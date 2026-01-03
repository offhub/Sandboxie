/*
 * Copyright 2022-2025 David Xanatos, xanasoft.com
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

#include "common/my_wsa.h" // _htons

#include "dns_filter_util.h"

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
// DNS_BuildSimpleQuery
//---------------------------------------------------------------------------

int DNS_BuildSimpleQuery(
    const WCHAR* domain,
    USHORT qtype,
    BYTE* buffer,
    int bufferSize)
{
    if (!domain || !buffer || bufferSize < 512)
        return 0;

    char domainA[256];
    int len = WideCharToMultiByte(CP_UTF8, 0, domain, -1, domainA, (int)sizeof(domainA), NULL, NULL);
    if (len <= 0 || len > 255)
        return 0;

    BYTE* ptr = buffer;

    *(USHORT*)ptr = 0x1234;
    ptr += 2;

    *(USHORT*)ptr = _htons(0x0100);
    ptr += 2;

    *(USHORT*)ptr = _htons(1);
    ptr += 2;

    *(USHORT*)ptr = 0;
    ptr += 2;
    *(USHORT*)ptr = 0;
    ptr += 2;
    *(USHORT*)ptr = 0;
    ptr += 2;

    char* namePtr = domainA;
    while (*namePtr) {
        char* labelStart = namePtr;
        int labelLen = 0;

        while (*namePtr && *namePtr != '.') {
            labelLen++;
            namePtr++;
        }

        *ptr++ = (BYTE)labelLen;
        memcpy(ptr, labelStart, labelLen);
        ptr += labelLen;

        if (*namePtr == '.')
            namePtr++;
    }

    *ptr++ = 0;

    *(USHORT*)ptr = _htons(qtype);
    ptr += 2;

    *(USHORT*)ptr = _htons(1);
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

    for (IP_ENTRY* entry = (IP_ENTRY*)List_Head(pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        if (!is_any_query && entry->Type != targetType) {
            if (!(wType == DNS_TYPE_AAAA && DNS_MapIpv4ToIpv6 && !has_ipv6 && entry->Type == AF_INET))
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

    return pFirstRecord;
}
