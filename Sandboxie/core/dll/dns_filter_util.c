/*
 * Copyright 2022-2026 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define NOGDI
#include "dll.h"

#include <windows.h>
#include <wchar.h>
#include <string.h>
#include <windns.h>
#include <limits.h>

#include "common/my_wsa.h" // _htons

#include "dns_filter_util.h"
#include "dns_rebind.h"


static __inline BOOLEAN DNS_BuildSimpleQuery_CanWrite(int bufferSize, const BYTE* buffer, const BYTE* ptr, int needed)
{
    int used = (int)(ptr - buffer);
    if (used < 0 || used > bufferSize)
        return FALSE;
    return bufferSize - used >= needed;
}

//---------------------------------------------------------------------------
// DNS_GetTypeName
//---------------------------------------------------------------------------

const WCHAR* DNS_GetTypeName(WORD wType)
{
    switch (wType) {
        case DNS_TYPE_A:     return L"A";
        case DNS_TYPE_NS:    return L"NS";
        case DNS_TYPE_CNAME: return L"CNAME";
        case DNS_TYPE_SOA:   return L"SOA";
        case DNS_TYPE_PTR:   return L"PTR";
        case DNS_TYPE_MX:    return L"MX";
        case DNS_TYPE_TEXT:  return L"TXT";
        case DNS_TYPE_AAAA:  return L"AAAA";
        case DNS_TYPE_SRV:   return L"SRV";
        case DNS_TYPE_SVCB:  return L"SVCB";
        case DNS_TYPE_HTTPS: return L"HTTPS";
        case 255:            return L"ANY";
        default: {
            static WCHAR buffers[4][32];
            static volatile LONG bufferIndex = 0;
            LONG idx = InterlockedIncrement(&bufferIndex) & 3;
            Sbie_snwprintf(buffers[idx], 32, L"TYPE%d", wType);
            return buffers[idx];
        }
    }
}

//---------------------------------------------------------------------------
// DNS_IsTypeNegated
//---------------------------------------------------------------------------

BOOLEAN DNS_IsTypeNegated(const DNS_TYPE_FILTER* type_filter, USHORT query_type)
{
    if (!type_filter)
        return FALSE;

    if (type_filter->wildcard_negated)
        return TRUE;

    for (USHORT i = 0; i < type_filter->negated_count && i < MAX_DNS_TYPE_FILTERS; i++) {
        if (type_filter->negated_types[i] == query_type)
            return TRUE;
    }

    return FALSE;
}

//---------------------------------------------------------------------------
// DNS_IsTypeInFilterList
//---------------------------------------------------------------------------

BOOLEAN DNS_IsTypeInFilterList(const DNS_TYPE_FILTER* type_filter, USHORT query_type)
{
    if (!type_filter) {
        return TRUE;
    }

    for (USHORT i = 0; i < type_filter->type_count && i < MAX_DNS_TYPE_FILTERS; i++) {
        if (type_filter->allowed_types[i] == query_type) {
            return TRUE;
        }
    }

    if (DNS_IsTypeNegated(type_filter, query_type))
        return FALSE;

    if (type_filter->has_wildcard) {
        return TRUE;
    }

    return FALSE;
}

//---------------------------------------------------------------------------
// DNS_IsTypeInFilterListEx
//---------------------------------------------------------------------------

BOOLEAN DNS_IsTypeInFilterListEx(const DNS_TYPE_FILTER* type_filter, USHORT query_type, DNS_PASSTHROUGH_REASON* pReason)
{
    if (!type_filter) {
        return TRUE;
    }

    for (USHORT i = 0; i < type_filter->type_count && i < MAX_DNS_TYPE_FILTERS; i++) {
        if (type_filter->allowed_types[i] == query_type) {
            return TRUE;
        }
    }

    if (DNS_IsTypeNegated(type_filter, query_type)) {
        if (pReason) *pReason = DNS_PASSTHROUGH_TYPE_NEGATED;
        return FALSE;
    }

    if (type_filter->has_wildcard) {
        return TRUE;
    }

    if (pReason) *pReason = DNS_PASSTHROUGH_TYPE_NOT_FILTERED;
    return FALSE;
}

//---------------------------------------------------------------------------
// DNS_CanSynthesizeResponse
//---------------------------------------------------------------------------

BOOLEAN DNS_CanSynthesizeResponse(USHORT query_type)
{
    return (query_type == DNS_TYPE_A || query_type == DNS_TYPE_AAAA || query_type == 255);
}

//---------------------------------------------------------------------------
// DNS_IsSingleLabelDomain
//---------------------------------------------------------------------------

BOOLEAN DNS_IsSingleLabelDomain(const WCHAR* domain)
{
    if (!domain || !*domain)
        return FALSE;

    size_t len = wcslen(domain);
    while (len > 0 && domain[len - 1] == L'.')
        len--;

    if (len == 0)
        return FALSE;

    for (size_t i = 0; i < len; ++i) {
        if (domain[i] == L'.')
            return FALSE;
    }

    return TRUE;
}

//---------------------------------------------------------------------------
// DNS_IsValidDnsName
//
// Validates ASCII-only DNS names (A-labels). No Unicode conversion.
// Rules:
//   - Trailing dot allowed (root label); length limit is 253 excluding dot.
//   - Multi-label DNS names allowed; per-label length <= 63.
//   - Allows underscore for service labels (SRV/TXT).
//   - Single-label names are capped at 15 chars (NetBIOS-style).
//   - Punycode labels (xn--) are validated per RFC 3492 rules.
//---------------------------------------------------------------------------

static __inline WCHAR DNS_AsciiToLower(WCHAR ch)
{
    if (ch >= L'A' && ch <= L'Z')
        return (WCHAR)(ch + (L'a' - L'A'));
    return ch;
}

static __inline BOOLEAN DNS_IsPunycodePrefix(const WCHAR* label, size_t label_len)
{
    if (!label || label_len < 4)
        return FALSE;
    return (DNS_AsciiToLower(label[0]) == L'x' &&
            DNS_AsciiToLower(label[1]) == L'n' &&
            label[2] == L'-' &&
            label[3] == L'-');
}

static __inline int DNS_Punycode_DecodeDigit(WCHAR ch)
{
    ch = DNS_AsciiToLower(ch);
    if (ch >= L'a' && ch <= L'z')
        return (int)(ch - L'a');
    if (ch >= L'0' && ch <= L'9')
        return (int)(ch - L'0') + 26;
    return -1;
}

static ULONG DNS_Punycode_Adapt(ULONG delta, ULONG numpoints, BOOLEAN firsttime)
{
    const ULONG base = 36;
    const ULONG tmin = 1;
    const ULONG tmax = 26;
    const ULONG skew = 38;
    const ULONG damp = 700;

    delta = firsttime ? (delta / damp) : (delta / 2);
    delta += delta / numpoints;

    ULONG k = 0;
    while (delta > ((base - tmin) * tmax) / 2) {
        delta /= (base - tmin);
        k += base;
    }

    return k + (base - tmin + 1) * delta / (delta + skew);
}

static BOOLEAN DNS_IsValidPunycodeLabel(const WCHAR* label, size_t label_len)
{
    const ULONG base = 36;
    const ULONG tmin = 1;
    const ULONG tmax = 26;
    const ULONG initial_n = 128;
    const ULONG initial_bias = 72;

    if (!DNS_IsPunycodePrefix(label, label_len))
        return FALSE;

    if (label_len <= 4)
        return FALSE;

    const WCHAR* payload = label + 4;
    size_t payload_len = label_len - 4;

    for (size_t i = 0; i < payload_len; ++i) {
        WCHAR ch = payload[i];
        if (ch == L'-')
            continue;
        if (DNS_Punycode_DecodeDigit(ch) < 0)
            return FALSE;
    }

    size_t delim = (size_t)-1;
    for (size_t i = 0; i < payload_len; ++i) {
        if (payload[i] == L'-')
            delim = i;
    }

    ULONG out_len = 0;
    if (delim != (size_t)-1) {
        for (size_t j = 0; j < delim; ++j) {
            if (payload[j] >= 0x80)
                return FALSE;
        }
        out_len = (ULONG)delim;
    }

    ULONG n = initial_n;
    ULONG i = 0;
    ULONG bias = initial_bias;
    size_t in_idx = (delim == (size_t)-1) ? 0 : (delim + 1);

    while (in_idx < payload_len) {
        ULONG oldi = i;
        ULONG w = 1;

        for (ULONG k = base;; k += base) {
            if (in_idx >= payload_len)
                return FALSE;

            int digit = DNS_Punycode_DecodeDigit(payload[in_idx++]);
            if (digit < 0)
                return FALSE;

            if ((ULONG)digit > (ULONG_MAX - i) / w)
                return FALSE;
            i += (ULONG)digit * w;

            ULONG t = (k <= bias) ? tmin : (k >= bias + tmax) ? tmax : (k - bias);
            if ((ULONG)digit < t)
                break;

            if (w > ULONG_MAX / (base - t))
                return FALSE;
            w *= (base - t);
        }

        bias = DNS_Punycode_Adapt(i - oldi, out_len + 1, oldi == 0);

        if (i / (out_len + 1) > (ULONG_MAX - n))
            return FALSE;
        n += i / (out_len + 1);
        i %= (out_len + 1);

        if (n > 0x10FFFF || (n >= 0xD800 && n <= 0xDFFF))
            return FALSE;

        out_len++;
        if (out_len > 63)
            return FALSE;
        i++;
    }

    return out_len > 0;
}

BOOLEAN DNS_IsValidDnsName(const WCHAR* domain)
{
    if (!domain || !*domain)
        return FALSE;

    size_t len = wcslen(domain);
    while (len > 0 && domain[len - 1] == L'.')
        len--;

    if (len == 0 || len > 253)
        return FALSE;

    size_t label_len = 0;
    size_t label_start = 0;
    WCHAR label_first = 0;
    WCHAR label_last = 0;
    BOOLEAN label_has_underscore = FALSE;
    BOOLEAN has_dot = FALSE;

    for (size_t i = 0; i < len; ++i) {
        WCHAR ch = domain[i];
        if (ch == L'.') {
            has_dot = TRUE;
            if (label_len == 0 || label_len > 63)
                return FALSE;
            if (label_first == L'-' || label_last == L'-')
                return FALSE;
            if (DNS_IsPunycodePrefix(domain + label_start, label_len)) {
                if (label_has_underscore)
                    return FALSE;
                if (!DNS_IsValidPunycodeLabel(domain + label_start, label_len))
                    return FALSE;
            }
            label_len = 0;
            label_start = i + 1;
            label_first = 0;
            label_last = 0;
            label_has_underscore = FALSE;
            continue;
        }

        if (ch <= 0x20 || ch == 0x7F || ch == L'/' || ch == L'\\')
            return FALSE;

        if (!((ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z') ||
              (ch >= L'0' && ch <= L'9') || ch == L'-' || ch == L'_')) {
            return FALSE;
        }

        if (ch == L'_')
            label_has_underscore = TRUE;

        if (label_len == 0)
            label_first = ch;
        label_last = ch;
        label_len++;
        if (label_len > 63)
            return FALSE;
    }

    if (label_len == 0 || label_len > 63)
        return FALSE;
    if (label_first == L'-' || label_last == L'-')
        return FALSE;
    if (DNS_IsPunycodePrefix(domain + label_start, label_len)) {
        if (label_has_underscore)
            return FALSE;
        if (!DNS_IsValidPunycodeLabel(domain + label_start, label_len))
            return FALSE;
    }

    if (!has_dot && len > 15)
        return FALSE;

    return TRUE;
}

//---------------------------------------------------------------------------
// DNS_BuildSimpleQuery - Build DNS wire format query
//---------------------------------------------------------------------------
//
// RFC 1035: Standard DNS query (header + question section)
int DNS_BuildSimpleQuery(
    const WCHAR* domain,
    USHORT qtype,
    BYTE* buffer,
    int bufferSize)
{
    if (!domain || !buffer || bufferSize < 512)
        return 0;

    if (!DNS_IsValidDnsName(domain))
        return 0;

    char domainA[256];
    int len = WideCharToMultiByte(CP_UTF8, 0, domain, -1, domainA, (int)sizeof(domainA), NULL, NULL);
    if (len <= 0 || len > 255)
        return 0;

    BYTE* ptr = buffer;
    #define ENSURE_SPACE(n) do { if (!DNS_BuildSimpleQuery_CanWrite(bufferSize, buffer, ptr, (n))) return 0; } while (0)

    ENSURE_SPACE(12);

    USHORT txid = (USHORT)Dll_rand();
    if (txid == 0)
        txid = 1;
    *(USHORT*)ptr = _htons(txid);
    ptr += 2;

    *(USHORT*)ptr = _htons(0x0100);
    ptr += 2;

    *(USHORT*)ptr = _htons(1);  // Questions
    ptr += 2;

    *(USHORT*)ptr = 0;  // Answer RRs
    ptr += 2;
    *(USHORT*)ptr = 0;  // Authority RRs
    ptr += 2;
    *(USHORT*)ptr = 0;  // Additional RRs
    ptr += 2;

    char* namePtr = domainA;
    while (*namePtr) {
        char* labelStart = namePtr;
        int labelLen = 0;

        while (*namePtr && *namePtr != '.') {
            labelLen++;
            namePtr++;
        }

        if (labelLen == 0 || labelLen > 63)
            return 0;

        ENSURE_SPACE(1 + labelLen);

        *ptr++ = (BYTE)labelLen;
        memcpy(ptr, labelStart, labelLen);
        ptr += labelLen;

        if (*namePtr == '.')
            namePtr++;
    }

    ENSURE_SPACE(1);
    *ptr++ = 0;

    ENSURE_SPACE(4);

    *(USHORT*)ptr = _htons(qtype);
    ptr += 2;

    *(USHORT*)ptr = _htons(1);  // QClass (IN)
    ptr += 2;

    return (int)(ptr - buffer);
}

//---------------------------------------------------------------------------
// DNSAPI_BuildDnsRecordList
//---------------------------------------------------------------------------

PDNSAPI_DNS_RECORD DNSAPI_BuildDnsRecordList(
    const WCHAR* domainName,
    WORD wType,
    LIST* pEntries,
    DNS_CHARSET CharSet,
    const DOH_RESULT* pDohResult)
{
    if (!pEntries || !domainName)
        return NULL;

    PDNSAPI_DNS_RECORD pFirstRecord = NULL;
    PDNSAPI_DNS_RECORD pLastRecord = NULL;

    if (pDohResult && pDohResult->HasCname && pDohResult->CnameOwner[0] != L'\0' && pDohResult->CnameTarget[0] != L'\0') {
        SIZE_T ownerNameLen = 0, targetNameLen = 0;

        if (CharSet == DnsCharSetUnicode) {
            ownerNameLen = (wcslen(pDohResult->CnameOwner) + 1) * sizeof(WCHAR);
            targetNameLen = (wcslen(pDohResult->CnameTarget) + 1) * sizeof(WCHAR);
        } else if (CharSet == DnsCharSetAnsi) {
            int len1 = WideCharToMultiByte(CP_ACP, 0, pDohResult->CnameOwner, -1, NULL, 0, NULL, NULL);
            int len2 = WideCharToMultiByte(CP_ACP, 0, pDohResult->CnameTarget, -1, NULL, 0, NULL, NULL);
            if (len1 > 0 && len2 > 0) {
                ownerNameLen = len1;
                targetNameLen = len2;
            }
        } else if (CharSet == DnsCharSetUtf8) {
            int len1 = WideCharToMultiByte(CP_UTF8, 0, pDohResult->CnameOwner, -1, NULL, 0, NULL, NULL);
            int len2 = WideCharToMultiByte(CP_UTF8, 0, pDohResult->CnameTarget, -1, NULL, 0, NULL, NULL);
            if (len1 > 0 && len2 > 0) {
                ownerNameLen = len1;
                targetNameLen = len2;
            }
        }

        if (ownerNameLen > 0 && targetNameLen > 0) {
            PDNSAPI_DNS_RECORD pCnameRec = (PDNSAPI_DNS_RECORD)LocalAlloc(LPTR, sizeof(DNSAPI_DNS_RECORD));
            if (pCnameRec) {
                pCnameRec->pName = (PWSTR)LocalAlloc(LPTR, ownerNameLen);
                if (pCnameRec->pName) {
                    if (CharSet == DnsCharSetUnicode) {
                        wmemcpy(pCnameRec->pName, pDohResult->CnameOwner, wcslen(pDohResult->CnameOwner) + 1);
                    } else if (CharSet == DnsCharSetAnsi) {
                        WideCharToMultiByte(CP_ACP, 0, pDohResult->CnameOwner, -1, (LPSTR)pCnameRec->pName, (int)ownerNameLen, NULL, NULL);
                    } else if (CharSet == DnsCharSetUtf8) {
                        WideCharToMultiByte(CP_UTF8, 0, pDohResult->CnameOwner, -1, (LPSTR)pCnameRec->pName, (int)ownerNameLen, NULL, NULL);
                    }

                    pCnameRec->Data.CNAME.pNameHost = (PWSTR)LocalAlloc(LPTR, targetNameLen);
                    if (pCnameRec->Data.CNAME.pNameHost) {
                        if (CharSet == DnsCharSetUnicode) {
                            wmemcpy(pCnameRec->Data.CNAME.pNameHost, pDohResult->CnameTarget, wcslen(pDohResult->CnameTarget) + 1);
                        } else if (CharSet == DnsCharSetAnsi) {
                            WideCharToMultiByte(CP_ACP, 0, pDohResult->CnameTarget, -1, (LPSTR)pCnameRec->Data.CNAME.pNameHost, (int)targetNameLen, NULL, NULL);
                        } else if (CharSet == DnsCharSetUtf8) {
                            WideCharToMultiByte(CP_UTF8, 0, pDohResult->CnameTarget, -1, (LPSTR)pCnameRec->Data.CNAME.pNameHost, (int)targetNameLen, NULL, NULL);
                        }

                        pCnameRec->wType = DNS_TYPE_CNAME;
                        pCnameRec->wDataLength = (WORD)targetNameLen;
                        pCnameRec->Flags.DW = 0;
                        pCnameRec->Flags.S.Section = DNSREC_ANSWER;
                        pCnameRec->Flags.S.CharSet = CharSet;
                        pCnameRec->dwTtl = pDohResult->TTL;
                        pCnameRec->dwReserved = 0x53424945;
                        pCnameRec->pNext = NULL;

                        pFirstRecord = pCnameRec;
                        pLastRecord = pCnameRec;
                    } else {
                        LocalFree(pCnameRec->pName);
                        LocalFree(pCnameRec);
                    }
                } else {
                    LocalFree(pCnameRec);
                }
            }
        }
    }

    BOOLEAN is_any_query = (wType == 255);
    USHORT targetType = (wType == DNS_TYPE_AAAA) ? AF_INET6 : AF_INET;

    const WCHAR* recordDomainName = domainName;
    if (pDohResult && pDohResult->HasCname && pDohResult->CnameTarget[0] != L'\0') {
        recordDomainName = pDohResult->CnameTarget;
    }

    BOOLEAN has_ipv6 = FALSE;
    if (wType == DNS_TYPE_AAAA && !is_any_query && DNS_MapIpv4ToIpv6) {
        for (IP_ENTRY* entry = (IP_ENTRY*)List_Head(pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
            if (entry->Type == AF_INET6) {
                has_ipv6 = TRUE;
                break;
            }
        }
    }

    SIZE_T domainNameLen = 0;
    if (CharSet == DnsCharSetUnicode) {
        domainNameLen = (wcslen(recordDomainName) + 1) * sizeof(WCHAR);
    } else if (CharSet == DnsCharSetAnsi) {
        int len = WideCharToMultiByte(CP_ACP, 0, recordDomainName, -1, NULL, 0, NULL, NULL);
        if (len <= 0) return pFirstRecord;
        domainNameLen = len;
    } else if (CharSet == DnsCharSetUtf8) {
        int len = WideCharToMultiByte(CP_UTF8, 0, recordDomainName, -1, NULL, 0, NULL, NULL);
        if (len <= 0) return pFirstRecord;
        domainNameLen = len;
    } else {
        domainNameLen = (wcslen(recordDomainName) + 1) * sizeof(WCHAR);
        CharSet = DnsCharSetUnicode;
    }

    WCHAR filtered_msg[512];
    filtered_msg[0] = L'\0';

    for (IP_ENTRY* entry = (IP_ENTRY*)List_Head(pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        if (!is_any_query && entry->Type != targetType) {
            if (!(wType == DNS_TYPE_AAAA && DNS_MapIpv4ToIpv6 && !has_ipv6 && entry->Type == AF_INET))
                continue;
        }

        // Apply DNS rebind protection: omit filtered IPs entirely.
        // Only apply if FilterDnsApi is enabled (respects user's hook enablement choice).
        // Do NOT synthesize 0.0.0.0/:: placeholders, as that leaks into callers (e.g., ping 0.0.0.0).
        if (DNS_DnsApiHookEnabled && DNS_Rebind_ShouldFilterIpForDomain(domainName, &entry->IP, entry->Type)) {
            DNS_Rebind_AppendFilteredIpMsg(
                filtered_msg,
                (SIZE_T)(sizeof(filtered_msg) / sizeof(filtered_msg[0])),
                entry->Type,
                &entry->IP);
            continue;
        }

        PDNSAPI_DNS_RECORD pRecord = (PDNSAPI_DNS_RECORD)LocalAlloc(LPTR, sizeof(DNSAPI_DNS_RECORD));
        if (!pRecord) {
            PDNSAPI_DNS_RECORD pCur = pFirstRecord;
            while (pCur) {
                PDNSAPI_DNS_RECORD pNext = pCur->pNext;
                if (pCur->pName) LocalFree(pCur->pName);
                LocalFree(pCur);
                pCur = pNext;
            }
            return NULL;
        }

        memset(pRecord, 0, sizeof(DNSAPI_DNS_RECORD));

        pRecord->pName = (PWSTR)LocalAlloc(LPTR, domainNameLen);
        if (!pRecord->pName) {
            LocalFree(pRecord);
            PDNSAPI_DNS_RECORD pCur = pFirstRecord;
            while (pCur) {
                PDNSAPI_DNS_RECORD pNext = pCur->pNext;
                if (pCur->pName) LocalFree(pCur->pName);
                LocalFree(pCur);
                pCur = pNext;
            }
            return NULL;
        }

        if (CharSet == DnsCharSetUnicode) {
            wmemcpy(pRecord->pName, recordDomainName, wcslen(recordDomainName) + 1);
        } else if (CharSet == DnsCharSetAnsi) {
            WideCharToMultiByte(CP_ACP, 0, recordDomainName, -1, (LPSTR)pRecord->pName, (int)domainNameLen, NULL, NULL);
        } else if (CharSet == DnsCharSetUtf8) {
            WideCharToMultiByte(CP_UTF8, 0, recordDomainName, -1, (LPSTR)pRecord->pName, (int)domainNameLen, NULL, NULL);
        }

        if (is_any_query) {
            pRecord->wType = (entry->Type == AF_INET6) ? DNS_TYPE_AAAA : DNS_TYPE_A;
        } else {
            pRecord->wType = wType;
        }

        pRecord->Flags.DW = 0;
        pRecord->Flags.S.Section = DNSREC_ANSWER;
        pRecord->Flags.S.CharSet = CharSet;

        pRecord->dwTtl = 300;
        pRecord->dwReserved = 0x53424945;
        pRecord->pNext = NULL;

        if (entry->Type == AF_INET6) {
            pRecord->wDataLength = 16;
            memcpy(&pRecord->Data.AAAA.Ip6Address, entry->IP.Data, 16);
        } else if (wType == DNS_TYPE_AAAA && DNS_MapIpv4ToIpv6 && !has_ipv6) {
            pRecord->wDataLength = 16;
            DWORD* ipv6_data = (DWORD*)&pRecord->Data.AAAA.Ip6Address;
            ipv6_data[0] = 0;
            ipv6_data[1] = 0;
            ipv6_data[2] = 0xFFFF0000;
            ipv6_data[3] = entry->IP.Data32[3];
        } else {
            pRecord->wDataLength = 4;
            pRecord->Data.A.IpAddress = entry->IP.Data32[3];
        }

        if (!pFirstRecord) {
            pFirstRecord = pRecord;
            pLastRecord = pRecord;
        } else {
            pLastRecord->pNext = pRecord;
            pLastRecord = pRecord;
        }
    }

    if (filtered_msg[0] && DNS_TraceFlag && !DNS_ShouldSuppressLogTagged(domainName, DNS_REBIND_LOG_TAG_FILTER)) {
        DNS_TRACE_LOG(L"[DNS Rebind] Filtered IP(s) for domain %s%s", domainName, filtered_msg);
    }

    return pFirstRecord;
}
