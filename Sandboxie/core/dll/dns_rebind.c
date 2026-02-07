/*
 * Copyright 2024-2026 David Xanatos, xanasoft.com
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

//---------------------------------------------------------------------------
// DNS Rebind Protection Implementation
//
// Prevents DNS rebinding attacks by filtering private/loopback IP addresses
// in DNS responses. Filtered A/AAAA answers are removed.
//---------------------------------------------------------------------------

#define NOGDI
#include "dll.h"

#include <windows.h>
#include <wchar.h>
#include <limits.h>
#include <windns.h>
#include "dns_rebind.h"
#include "dns_filter.h"
#include "dns_logging.h"
#include "dns_filter_util.h"
#include "dns_wire.h"
#include "dns_dnssec.h"
#include "dns_encrypted.h"  // For EncryptedDns_IsServerHostname()
#include "common/netfw.h"
#include "common/list.h"
#include "common/pattern.h"

// External from net.c
extern void WSA_DumpIP(ADDRESS_FAMILY af, IP_ADDRESS* pIP, wchar_t* pStr);

//---------------------------------------------------------------------------
// DNS_Rebind_AppendFilteredIpMsg
//---------------------------------------------------------------------------

_FX void DNS_Rebind_AppendFilteredIpMsg(
    WCHAR* msg,
    SIZE_T msg_cch,
    ADDRESS_FAMILY af,
    const IP_ADDRESS* pIP)
{
    if (!msg || msg_cch == 0 || !pIP)
        return;

    msg[msg_cch - 1] = L'\0';

    SIZE_T len = wcslen(msg);
    if (len >= msg_cch - 1)
        return;

    WCHAR ip_msg[128] = L"";
    WSA_DumpIP(af, (IP_ADDRESS*)pIP, ip_msg);

    SIZE_T avail = msg_cch - 1 - len;
    if (avail == 0)
        return;

    Sbie_snwprintf(msg + len, avail + 1, L"%s", ip_msg);
}

// DNSSEC Configuration moved to dns_dnssec.c/dns_dnssec.h

//---------------------------------------------------------------------------
// Configuration
//---------------------------------------------------------------------------

// Rebind protection enable patterns
// Supported formats:
//   - DnsRebindProtection=y|n
//   - DnsRebindProtection=<domain>:y|n
//   - DnsRebindProtection=<process>,y|n
//   - DnsRebindProtection=<process>,<domain>:y|n
// Notes:
//   - First parameter (optional) is process pattern and ends with ','
//     * if omitted: matches all processes
//   - Second parameter (optional) is domain pattern and ends with ':'
//     * if omitted: matches all domains
//   - Action flag (y|n) is the last/only token and is mandatory.
//     * If missing/empty/invalid, it is treated as 'n' (disabled).
//   - <domain> supports '*' and '?' wildcards (case-insensitive).
//   - More specific rules override less specific rules (exact domain beats '*.domain').
// Examples:
//   DnsRebindProtection=y                                 # Enable globally
//   DnsRebindProtection=nslookup.exe,n                    # Disable for a process
//   DnsRebindProtection=*.local:y                         # Enable for *.local
//   DnsRebindProtection=*.example.com:n                  # Disable for all *.example.com
//   DnsRebindProtection=host123.example.com:y            # Re-enable for one exact name
static LIST DNS_RebindPatterns;

//---------------------------------------------------------------------------
// External Dependencies
//---------------------------------------------------------------------------

extern BOOLEAN DNS_HasValidCertificate;
extern BOOLEAN DNS_TraceFlag;
extern BOOLEAN DNS_DebugFlag;
extern ULONGLONG GetTickCount64(void);

#if !defined(_DNSDEBUG)
#undef DNS_DebugFlag
#define DNS_DebugFlag 0
#endif

// From config.c
extern WCHAR* Config_MatchImageAndGetValue(WCHAR* setting, const WCHAR* imageName, ULONG* level);
extern BOOLEAN Config_MatchImage(const WCHAR* pat_str, ULONG pat_len, const WCHAR* test_str, ULONG depth);
extern const WCHAR* Dll_ImageName;

// System free helpers (resolved at runtime to avoid link dependencies)
typedef VOID (WINAPI *P_FreeAddrInfoW)(PADDRINFOW pAddrInfo);
typedef VOID (WINAPI *P_freeaddrinfo)(PADDRINFOA pAddrInfo);
typedef VOID (WINAPI *P_DnsRecordListFree)(PVOID pRecordList, INT FreeType);
typedef DNS_STATUS (WINAPI *P_DnsQuery_W)(
    PCWSTR              pszName,
    WORD                wType,
    DWORD               Options,
    PVOID               pExtra,
    PDNS_RECORD*        ppQueryResults,
    PVOID*              pReserved);

// Forward declaration for DNS wire-format parsing helper
static BOOLEAN DNS_Rebind_SkipDnsName(const BYTE* dns_data, int dns_len, int* pOffset);
static BOOLEAN DNS_Rebind_ParseWireForSanitize(
    BYTE* data,
    int data_len,
    const WCHAR* domain,
    BOOLEAN isTcp,
    BYTE** pDnsData,
    int* pDnsLen,
    DNS_WIRE_HEADER** pHeader,
    int* pQuestionOffset,
    USHORT* pAnswerCount,
    USHORT* pNsCount,
    USHORT* pAddCount,
    BOOLEAN* pHasLengthPrefix);

static P_DnsRecordListFree DNS_Rebind_GetDnsRecordListFree(void);
static P_DnsQuery_W DNS_Rebind_GetDnsQueryW(void);

static BOOLEAN DNS_Rebind_DnssecHasRrsigForType(const WCHAR* domain, WORD qtype)
{
    if (!domain || !*domain)
        return FALSE;

    if (EncryptedDns_IsEnabled()) {
        if (EncryptedDns_IsQueryActive())
        {
            if (!DNS_ShouldSuppressLogTagged(domain, DNS_REBIND_LOG_TAG_DEFAULT))
                DNS_DEBUG_LOG(L"[DNS Rebind] DNSSEC EncDns probe skipped for %s (query active)", domain);
            return FALSE;
        }
        if (EncryptedDns_CacheHasRrsig(domain, qtype))
            return TRUE;
        ENCRYPTED_DNS_RESULT encResult;
        if (!EncryptedDns_Query(domain, qtype, &encResult))
            return FALSE;
        if (encResult.RawResponseLen == 0)
            return FALSE;
        return DNS_Dnssec_ResponseHasRrsig(encResult.RawResponse, (int)encResult.RawResponseLen);
    }

    P_DnsQuery_W dnsQueryW = (P_DnsQuery_W)DNSAPI_GetSystemDnsQueryW();
    if (!dnsQueryW)
        dnsQueryW = DNS_Rebind_GetDnsQueryW();
    if (!dnsQueryW)
        return FALSE;

    PDNS_RECORD records = NULL;
    DNS_STATUS st = dnsQueryW(domain, qtype, DNS_QUERY_DNSSEC_OK, NULL, &records, NULL);
    if (st != 0 || !records)
        return FALSE;

    BOOLEAN has_rrsig = DNS_Dnssec_RecordListHasRrsig(records);
    P_DnsRecordListFree freeRec = (P_DnsRecordListFree)DNSAPI_GetSystemDnsRecordListFree();
    if (!freeRec)
        freeRec = DNS_Rebind_GetDnsRecordListFree();
    if (freeRec)
        freeRec(records, DnsFreeRecordList);
    else if (!DNS_ShouldSuppressLogTagged(domain, DNS_REBIND_LOG_TAG_DEFAULT))
        DNS_DEBUG_LOG(L"[DNS Rebind] DnsRecordListFree not available while probing %s", domain);

    return has_rrsig;
}

static BOOLEAN DNS_Rebind_DnssecShouldSkipWsaQuerySetW(const WCHAR* domain, LPWSAQUERYSETW lpqsResults)
{
    if (!domain || !lpqsResults)
        return FALSE;

    DNSSEC_MODE mode = DNS_DnssecGetMode(domain);
    if (mode != DNSSEC_MODE_ENABLED)
        return FALSE;

    BOOLEAN want_a = FALSE;
    BOOLEAN want_aaaa = FALSE;

    if (lpqsResults->dwNumberOfCsAddrs > 0 && lpqsResults->lpcsaBuffer) {
        for (DWORD i = 0; i < lpqsResults->dwNumberOfCsAddrs; ++i) {
            SOCKADDR* sa = lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr;
            if (!sa)
                continue;
            if (sa->sa_family == AF_INET)
                want_a = TRUE;
            else if (sa->sa_family == AF_INET6)
                want_aaaa = TRUE;
        }
    }

    if (lpqsResults->lpBlob && lpqsResults->lpBlob->pBlobData && lpqsResults->lpBlob->cbSize >= sizeof(HOSTENT)) {
        HOSTENT* hp = (HOSTENT*)lpqsResults->lpBlob->pBlobData;
        if (hp->h_addrtype == AF_INET)
            want_a = TRUE;
        else if (hp->h_addrtype == AF_INET6)
            want_aaaa = TRUE;
    }

    if (!want_a && !want_aaaa)
        want_a = TRUE;

    if (EncryptedDns_IsEnabled()) {
        if (want_a && EncryptedDns_CacheHasRrsig(domain, DNS_TYPE_A))
            return TRUE;
        if (want_aaaa && EncryptedDns_CacheHasRrsig(domain, DNS_TYPE_AAAA))
            return TRUE;
    }

    if (want_a && DNS_Rebind_DnssecHasRrsigForType(domain, DNS_TYPE_A))
        return TRUE;
    if (want_aaaa && DNS_Rebind_DnssecHasRrsigForType(domain, DNS_TYPE_AAAA))
        return TRUE;

    return FALSE;
}

// Generic function pointer resolver - reduces boilerplate for lazy-loading APIs
#define DEFINE_LAZY_PROC(type, name, dll, proc) \
    static type name(void) { \
        static type fn = NULL; \
        if (!fn) { \
            HMODULE h = GetModuleHandleW(dll); \
            if (!h) h = LoadLibraryW(dll); \
            if (h) fn = (type)GetProcAddress(h, proc); \
        } \
        return fn; \
    }

DEFINE_LAZY_PROC(P_FreeAddrInfoW, DNS_Rebind_GetFreeAddrInfoW, L"ws2_32.dll", "FreeAddrInfoW")
DEFINE_LAZY_PROC(P_freeaddrinfo, DNS_Rebind_GetFreeAddrInfoA, L"ws2_32.dll", "freeaddrinfo")
DEFINE_LAZY_PROC(P_DnsRecordListFree, DNS_Rebind_GetDnsRecordListFree, L"dnsapi.dll", "DnsRecordListFree")
DEFINE_LAZY_PROC(P_DnsQuery_W, DNS_Rebind_GetDnsQueryW, L"dnsapi.dll", "DnsQuery_W")

//---------------------------------------------------------------------------
// IP Address Conversion Helpers - centralized conversion to IP_ADDRESS format
//---------------------------------------------------------------------------

// Convert IPv4 address (in network byte order) to IP_ADDRESS
static __inline void DNS_Rebind_IPv4ToIpAddress(DWORD ipv4_net_order, IP_ADDRESS* pIP)
{
    memset(pIP, 0, sizeof(IP_ADDRESS));
    pIP->Data32[3] = ipv4_net_order;
}

// Convert IPv6 address (16 bytes) to IP_ADDRESS
static __inline void DNS_Rebind_IPv6ToIpAddress(const BYTE* ipv6_bytes, IP_ADDRESS* pIP)
{
    memset(pIP, 0, sizeof(IP_ADDRESS));
    memcpy(pIP->Data, ipv6_bytes, 16);
}

// Convert SOCKADDR to IP_ADDRESS, returns TRUE if conversion succeeded
static BOOLEAN DNS_Rebind_SockaddrToIpAddress(ADDRESS_FAMILY af, const void* sockaddr, IP_ADDRESS* pIP)
{
    if (!sockaddr || !pIP)
        return FALSE;

    if (af == AF_INET) {
        const SOCKADDR_IN* sa4 = (const SOCKADDR_IN*)sockaddr;
        DNS_Rebind_IPv4ToIpAddress(sa4->sin_addr.S_un.S_addr, pIP);
        return TRUE;
    }
    else if (af == AF_INET6) {
        const SOCKADDR_IN6_LH* sa6 = (const SOCKADDR_IN6_LH*)sockaddr;
        DNS_Rebind_IPv6ToIpAddress(sa6->sin6_addr.u.Byte, pIP);
        return TRUE;
    }

    return FALSE;
}

//---------------------------------------------------------------------------
// DNS_Rebind_SanitizeDnsWireResponseKeepLengthNodata
//---------------------------------------------------------------------------

_FX BOOLEAN DNS_Rebind_SanitizeDnsWireResponseKeepLengthNodata(
    BYTE* data,
    int data_len,
    const WCHAR* domain,
    BOOLEAN isTcp,
    ULONG* pFilteredA,
    ULONG* pFilteredAAAA)
{
    if (pFilteredA)
        *pFilteredA = 0;
    if (pFilteredAAAA)
        *pFilteredAAAA = 0;

    BYTE* dns_data = NULL;
    int dns_len = 0;
    DNS_WIRE_HEADER* header = NULL;
    int offset = 0;
    USHORT answer_count = 0;
    USHORT ns_count = 0;
    USHORT add_count = 0;
    BOOLEAN has_length_prefix = FALSE;

    if (!DNS_Rebind_ParseWireForSanitize(
            data, data_len, domain, isTcp,
            &dns_data, &dns_len, &header, &offset,
            &answer_count, &ns_count, &add_count,
            &has_length_prefix))
        return FALSE;

    (void)has_length_prefix;

    ULONG filteredA = 0;
    ULONG filteredAAAA = 0;

    typedef struct _DNS_REBIND_FILTERED_IP {
        ADDRESS_FAMILY af;
        IP_ADDRESS     ip;
    } DNS_REBIND_FILTERED_IP;

    DNS_REBIND_FILTERED_IP filtered_ips[16];
    ULONG filtered_ip_count = 0;

    int read_offset = offset;

    struct {
        USHORT count;
    } sections[3] = {
        { answer_count },
        { ns_count },
        { add_count },
    };

    // Pre-scan: find the first non-filtered A and AAAA IP to use as replacement.
    // When we filter a record in-place, duplicating a valid IP from the same response
    // is better than zeroing to 0.0.0.0/:: because clients won't see a bogus address.
    BYTE replacement_a[4];
    BOOLEAN has_replacement_a = FALSE;
    BYTE replacement_aaaa[16];
    BOOLEAN has_replacement_aaaa = FALSE;
    {
        int scan_off = offset;
        for (int sc = 0; sc < 3; ++sc) {
            for (USHORT si = 0; si < sections[sc].count; ++si) {
                if (!DNS_Rebind_SkipDnsName(dns_data, dns_len, &scan_off))
                    goto done_prescan;
                if (scan_off + 10 > dns_len)
                    goto done_prescan;
                USHORT st = _ntohs(*(USHORT*)(dns_data + scan_off));
                scan_off += 2; // TYPE
                scan_off += 2; // CLASS
                scan_off += 4; // TTL
                USHORT srdl = _ntohs(*(USHORT*)(dns_data + scan_off));
                scan_off += 2; // RDLENGTH
                if (scan_off + srdl > dns_len)
                    goto done_prescan;
                if (st == DNS_TYPE_A && srdl == 4 && !has_replacement_a) {
                    IP_ADDRESS sip;
                    DNS_Rebind_IPv4ToIpAddress(*(DWORD*)(dns_data + scan_off), &sip);
                    if (!DNS_Rebind_ShouldFilterIpForDomain(domain, &sip, AF_INET)) {
                        memcpy(replacement_a, dns_data + scan_off, 4);
                        has_replacement_a = TRUE;
                    }
                } else if (st == DNS_TYPE_AAAA && srdl == 16 && !has_replacement_aaaa) {
                    IP_ADDRESS sip;
                    DNS_Rebind_IPv6ToIpAddress(dns_data + scan_off, &sip);
                    if (!DNS_Rebind_ShouldFilterIpForDomain(domain, &sip, AF_INET6)) {
                        memcpy(replacement_aaaa, dns_data + scan_off, 16);
                        has_replacement_aaaa = TRUE;
                    }
                }
                scan_off += srdl;
            }
        }
    done_prescan:;
    }

    // Main pass: replace filtered RDATA in-place.
    // Uses a valid IP from the pre-scan (duplicate) when available, falls back to 0.0.0.0/::.
    for (int s = 0; s < 3; ++s) {
        for (USHORT i = 0; i < sections[s].count; ++i) {
            if (!DNS_Rebind_SkipDnsName(dns_data, dns_len, &read_offset))
                return FALSE;

            // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
            if (read_offset + 10 > dns_len)
                return FALSE;

            USHORT rr_type = _ntohs(*(USHORT*)(dns_data + read_offset));
            read_offset += 2;
            read_offset += 2; // CLASS
            read_offset += 4; // TTL
            USHORT rdlength = _ntohs(*(USHORT*)(dns_data + read_offset));
            read_offset += 2;

            if (read_offset + rdlength > dns_len)
                return FALSE;

            if (rr_type == DNS_TYPE_A && rdlength == 4) {
                IP_ADDRESS ip;
                DNS_Rebind_IPv4ToIpAddress(*(DWORD*)(dns_data + read_offset), &ip);
                if (DNS_Rebind_ShouldFilterIpForDomain(domain, &ip, AF_INET)) {
                    filteredA++;
                    // Replace filtered IP RDATA in-place.
                    // Prefer duplicating a valid IP so clients don't see 0.0.0.0.
                    // Critical for TCP payload-only buffers where the length prefix
                    // was already delivered and we cannot change the total size.
                    if (has_replacement_a)
                        memcpy(dns_data + read_offset, replacement_a, 4);
                    else
                        memset(dns_data + read_offset, 0, 4);
                    if (filtered_ip_count < (ULONG)(sizeof(filtered_ips) / sizeof(filtered_ips[0]))) {
                        filtered_ips[filtered_ip_count].af = AF_INET;
                        filtered_ips[filtered_ip_count].ip = ip;
                        filtered_ip_count++;
                    }
                }
            } else if (rr_type == DNS_TYPE_AAAA && rdlength == 16) {
                IP_ADDRESS ip;
                DNS_Rebind_IPv6ToIpAddress(dns_data + read_offset, &ip);
                if (DNS_Rebind_ShouldFilterIpForDomain(domain, &ip, AF_INET6)) {
                    filteredAAAA++;
                    // Replace filtered IP RDATA in-place (prefer valid IP duplicate).
                    if (has_replacement_aaaa)
                        memcpy(dns_data + read_offset, replacement_aaaa, 16);
                    else
                        memset(dns_data + read_offset, 0, 16);
                    if (filtered_ip_count < (ULONG)(sizeof(filtered_ips) / sizeof(filtered_ips[0]))) {
                        filtered_ips[filtered_ip_count].af = AF_INET6;
                        filtered_ips[filtered_ip_count].ip = ip;
                        filtered_ip_count++;
                    }
                }
            }

            read_offset += rdlength;
        }
    }

    if (pFilteredA)
        *pFilteredA = filteredA;
    if (pFilteredAAAA)
        *pFilteredAAAA = filteredAAAA;

    if (filteredA || filteredAAAA) {
        // Filtered IPs have been replaced in-place with 0.0.0.0/:: above.
        // The DNS wire format structure is preserved (record counts, offsets, RRSIG, OPT)
        // so the response remains parseable. TCP payload-only buffers require this
        // approach because the length prefix was already delivered to the client.

        if (!DNS_ShouldSuppressLogTagged(domain, DNS_REBIND_LOG_TAG_WIRE)) {
            WCHAR msg[1024];
            msg[0] = L'\0';
            for (ULONG i = 0; i < filtered_ip_count; ++i) {
                WCHAR ip_msg[128] = L"";
                WSA_DumpIP(filtered_ips[i].af, &filtered_ips[i].ip, ip_msg);

                size_t len = wcslen(msg);
                size_t avail = (sizeof(msg) / sizeof(msg[0])) - len;
                if (avail <= 2)
                    break;

                Sbie_snwprintf(msg + len, avail, L"%s", ip_msg);
            }
            DNS_TRACE_LOG(L"[DNS Rebind] Filtered IP(s) for domain %s%s", domain, msg);
            DNS_TRACE_LOG(L"[DNS Rebind] Filtered raw DNS response (kept length) for domain: %s (A=%lu, AAAA=%lu)",
                          domain, filteredA, filteredAAAA);
        }

        return TRUE;
    }

    return FALSE;
}

//---------------------------------------------------------------------------
// Rebind Pattern Entry
//---------------------------------------------------------------------------

typedef struct _REBIND_PATTERN {
    LIST_ELEM list_elem;
    WCHAR* process_pattern;     // Process name pattern (can be NULL = all)
    WCHAR* domain_pattern;      // Domain pattern (can be NULL = all)
    BOOLEAN enabled;            // TRUE if enabled, FALSE if disabled
} REBIND_PATTERN;

//---------------------------------------------------------------------------
// Rebind Filtered-IP Rule Entry
//---------------------------------------------------------------------------

typedef struct _REBIND_IP_RULE {
    LIST_ELEM list_elem;
    WCHAR* process_pattern;     // Process name pattern (can be NULL = all)
    WCHAR* domain_pattern;      // Domain pattern (can be NULL = all)
    WCHAR* ip_pattern;          // IP pattern string (for logging)
    BOOLEAN enabled;            // TRUE = filter, FALSE = allow/override
    USHORT af;                  // AF_INET or AF_INET6
    UCHAR prefix_len;           // CIDR prefix bits (0-32 or 0-128), or range specificity
    IP_ADDRESS ip;              // CIDR address, or range start (AF_INET stored in Data[12..15])
    BOOLEAN is_range;           // TRUE if ip..ip_end is used (inclusive range)
    IP_ADDRESS ip_end;          // Range end address (only valid when is_range=TRUE)
} REBIND_IP_RULE;

//---------------------------------------------------------------------------
// Module State
//---------------------------------------------------------------------------

// Indicates whether DnsRebindProtection has any enabled patterns.
// Used to suppress FilterDnsIP-related logging when protection is disabled.
static BOOLEAN DNS_Rebind_ProtectionEnabled = FALSE;

//---------------------------------------------------------------------------
// Simple wildcard pattern matcher (supports * and ? wildcards)
//---------------------------------------------------------------------------

static int DNS_Rebind_SpecificityScore(const WCHAR* pattern);
static BOOLEAN DNS_Rebind_ParseProtectionConfig(
    WCHAR* buf,
    WCHAR** pProcOut,
    WCHAR** pDomainOut,
    BOOLEAN* pEnabledOut);
static BOOLEAN DNS_Rebind_AddPattern(const WCHAR* process_pattern, const WCHAR* domain_pattern, BOOLEAN enabled);

static BOOLEAN DNS_Rebind_MatchWildcard(const WCHAR* pattern, const WCHAR* str) {
    if (!pattern || !str) return FALSE;

    if (_wcsicmp(pattern, L"@nodot@") == 0) {
        return DNS_IsSingleLabelDomain(str);
    }
    while (*pattern) {
        if (*pattern == L'*') {
            pattern++;
            if (!*pattern) return TRUE;
            while (*str) {
                if (DNS_Rebind_MatchWildcard(pattern, str)) return TRUE;
                str++;
            }
            return FALSE;
        } else if (*pattern == L'?') {
            if (!*str) return FALSE;
            pattern++; str++;
        } else {
            if (towlower(*pattern) != towlower(*str)) return FALSE;
            pattern++; str++;
        }
    }
    return *str == 0;
}

//---------------------------------------------------------------------------
// FilterDnsIP parsing helpers
//---------------------------------------------------------------------------

static WCHAR* DNS_Rebind_FindCharOutsideBrackets(WCHAR* s, WCHAR ch)
{
    int depth = 0;
    for (WCHAR* p = s; p && *p; ++p) {
        if (*p == L'[')
            depth++;
        else if (*p == L']' && depth > 0)
            depth--;
        else if (depth == 0 && *p == ch)
            return p;
    }
    return NULL;
}

static WCHAR* DNS_Rebind_FindLastCharOutsideBrackets(WCHAR* s, WCHAR ch)
{
    int depth = 0;
    WCHAR* last = NULL;
    for (WCHAR* p = s; p && *p; ++p) {
        if (*p == L'[')
            depth++;
        else if (*p == L']' && depth > 0)
            depth--;
        else if (depth == 0 && *p == ch)
            last = p;
    }
    return last;
}

static WCHAR* DNS_Rebind_TrimInPlace(WCHAR* s)
{
    if (!s)
        return s;

    while (*s == L' ' || *s == L'\t' || *s == L'\r' || *s == L'\n')
        ++s;

    size_t len = wcslen(s);
    while (len > 0) {
        WCHAR c = s[len - 1];
        if (c != L' ' && c != L'\t' && c != L'\r' && c != L'\n')
            break;
        s[len - 1] = 0;
        --len;
    }

    return s;
}

static BOOLEAN DNS_Rebind_ParseIpAddressString(const WCHAR* ip_string, USHORT* pAf, IP_ADDRESS* pIpOut)
{
    if (!ip_string || !ip_string[0] || !pAf || !pIpOut)
        return FALSE;

    WCHAR tmp[256];
    size_t in_len = wcslen(ip_string);
    if (in_len >= ARRAYSIZE(tmp))
        return FALSE;
    wmemcpy(tmp, ip_string, in_len + 1);

    WCHAR* s = DNS_Rebind_TrimInPlace(tmp);
    size_t len = wcslen(s);
    if (len == 0)
        return FALSE;

    // Strip optional outer [ ... ] for IPv6.
    if (s[0] == L'[' && len >= 2 && s[len - 1] == L']') {
        s[len - 1] = 0;
        s = s + 1;
        s = DNS_Rebind_TrimInPlace(s);
        len = wcslen(s);
        if (len == 0)
            return FALSE;
    }

    const WCHAR* addr = s;

    // Basic validation: check for invalid patterns like multiple consecutive dots
    // This catches malformed IPs like "224.0.0.0.1" that _inet_pton would partially parse
    const WCHAR* p = addr;
    WCHAR prev = 0;
    int dot_count = 0;
    BOOLEAN has_colon = FALSE;
    while (*p) {
        if (*p == L'.') {
            if (prev == L'.' || prev == 0)  // consecutive dots or leading dot
                return FALSE;
            dot_count++;
        } else if (*p == L':') {
            has_colon = TRUE;
        } else if ((*p < L'0' || *p > L'9') && (*p < L'a' || *p > L'f') && (*p < L'A' || *p > L'F')) {
            // Invalid character (not hex digit, dot, or colon)
            return FALSE;
        }
        prev = *p++;
    }
    // Trailing dot is invalid
    if (prev == L'.')
        return FALSE;
    // IPv4 should have exactly 3 dots
    if (!has_colon && dot_count != 3)
        return FALSE;

    IP_ADDRESS ip;
    memset(&ip, 0, sizeof(ip));
    USHORT af = 0;
    if (_inet_xton(addr, (ULONG)wcslen(addr), &ip, &af) != 1)
        return FALSE;

    if (af != AF_INET && af != AF_INET6)
        return FALSE;

    *pAf = af;
    *pIpOut = ip;
    return TRUE;
}

static BOOLEAN DNS_Rebind_ParseIpCidrPattern(const WCHAR* ip_pattern, USHORT* pAf, UCHAR* pPrefix, IP_ADDRESS* pIpOut)
{
    if (!ip_pattern || !ip_pattern[0] || !pAf || !pPrefix || !pIpOut)
        return FALSE;

    WCHAR tmp[256];
    size_t in_len = wcslen(ip_pattern);
    if (in_len >= ARRAYSIZE(tmp))
        return FALSE;
    wmemcpy(tmp, ip_pattern, in_len + 1);

    WCHAR* s = DNS_Rebind_TrimInPlace(tmp);
    if (!s || !s[0])
        return FALSE;

    UCHAR prefix = 0;
    BOOLEAN has_prefix = FALSE;
    WCHAR* slash = wcschr(s, L'/');
    if (slash) {
        *slash = 0;
        WCHAR* pfx = DNS_Rebind_TrimInPlace(slash + 1);
        if (!pfx || !pfx[0])
            return FALSE;
        int pfx_i = _wtoi(pfx);
        if (pfx_i < 0)
            return FALSE;
        prefix = (UCHAR)pfx_i;
        has_prefix = TRUE;
    }

    s = DNS_Rebind_TrimInPlace(s);
    if (!s || !s[0])
        return FALSE;

    IP_ADDRESS ip;
    USHORT af = 0;
    memset(&ip, 0, sizeof(ip));
    if (!DNS_Rebind_ParseIpAddressString(s, &af, &ip))
        return FALSE;

    if (af == AF_INET) {
        if (!has_prefix)
            prefix = 32;
        if (prefix > 32)
            return FALSE;
    } else if (af == AF_INET6) {
        if (!has_prefix)
            prefix = 128;
        if (prefix > 128)
            return FALSE;
    } else {
        return FALSE;
    }

    *pAf = af;
    *pPrefix = prefix;
    *pIpOut = ip;
    return TRUE;
}

static int DNS_Rebind_CommonPrefixBits(const BYTE* a, const BYTE* b, int bytes)
{
    if (!a || !b || bytes <= 0)
        return 0;

    int bits = 0;
    for (int i = 0; i < bytes; ++i) {
        BYTE x = (BYTE)(a[i] ^ b[i]);
        if (x == 0) {
            bits += 8;
            continue;
        }
        for (int bit = 7; bit >= 0; --bit) {
            if ((x & (1u << bit)) == 0)
                bits++;
            else
                return bits;
        }
    }
    return bits;
}

static BOOLEAN DNS_Rebind_ParseIpRangePattern(const WCHAR* ip_pattern, USHORT* pAf, IP_ADDRESS* pStartOut, IP_ADDRESS* pEndOut, UCHAR* pSpecificityOut)
{
    if (!ip_pattern || !ip_pattern[0] || !pAf || !pStartOut || !pEndOut || !pSpecificityOut)
        return FALSE;

    WCHAR tmp[256];
    size_t in_len = wcslen(ip_pattern);
    if (in_len >= ARRAYSIZE(tmp))
        return FALSE;
    wmemcpy(tmp, ip_pattern, in_len + 1);

    WCHAR* s = DNS_Rebind_TrimInPlace(tmp);
    if (!s || !s[0])
        return FALSE;

    // Range syntax: <start> - <end> (dash outside brackets)
    WCHAR* dash = DNS_Rebind_FindCharOutsideBrackets(s, L'-');
    if (!dash)
        return FALSE;

    *dash = 0;
    WCHAR* s_start = DNS_Rebind_TrimInPlace(s);
    WCHAR* s_end = DNS_Rebind_TrimInPlace(dash + 1);
    if (!s_start || !s_start[0] || !s_end || !s_end[0])
        return FALSE;

    IP_ADDRESS ip_start, ip_end;
    USHORT af_start = 0, af_end = 0;
    memset(&ip_start, 0, sizeof(ip_start));
    memset(&ip_end, 0, sizeof(ip_end));
    if (!DNS_Rebind_ParseIpAddressString(s_start, &af_start, &ip_start))
        return FALSE;
    if (!DNS_Rebind_ParseIpAddressString(s_end, &af_end, &ip_end))
        return FALSE;
    if (af_start != af_end)
        return FALSE;

    // Normalize ordering so start <= end (memcmp works for big-endian address bytes).
    int bytes = (af_start == AF_INET) ? 4 : 16;
    const BYTE* a = (af_start == AF_INET) ? &ip_start.Data[12] : (const BYTE*)ip_start.Data;
    const BYTE* b = (af_start == AF_INET) ? &ip_end.Data[12] : (const BYTE*)ip_end.Data;
    if (memcmp(a, b, (size_t)bytes) > 0) {
        IP_ADDRESS tmp_ip = ip_start;
        ip_start = ip_end;
        ip_end = tmp_ip;
    }

    // Specificity for scoring: common-prefix length between start/end.
    const BYTE* a2 = (af_start == AF_INET) ? &ip_start.Data[12] : (const BYTE*)ip_start.Data;
    const BYTE* b2 = (af_start == AF_INET) ? &ip_end.Data[12] : (const BYTE*)ip_end.Data;
    int common_bits = DNS_Rebind_CommonPrefixBits(a2, b2, bytes);
    if (common_bits < 0)
        common_bits = 0;
    if (af_start == AF_INET && common_bits > 32)
        common_bits = 32;
    if (af_start == AF_INET6 && common_bits > 128)
        common_bits = 128;

    *pAf = af_start;
    *pStartOut = ip_start;
    *pEndOut = ip_end;
    *pSpecificityOut = (UCHAR)common_bits;
    return TRUE;
}

static BOOLEAN DNS_Rebind_ParseIpSpec(const WCHAR* ip_pattern, USHORT* pAf, UCHAR* pPrefix, IP_ADDRESS* pIpStartOut, BOOLEAN* pIsRangeOut, IP_ADDRESS* pIpEndOut)
{
    if (!ip_pattern || !ip_pattern[0] || !pAf || !pPrefix || !pIpStartOut || !pIsRangeOut || !pIpEndOut)
        return FALSE;

    // Prefer explicit range parsing if a dash exists outside brackets.
    {
        USHORT af = 0;
        IP_ADDRESS start_ip, end_ip;
        UCHAR spec = 0;
        memset(&start_ip, 0, sizeof(start_ip));
        memset(&end_ip, 0, sizeof(end_ip));
        if (DNS_Rebind_ParseIpRangePattern(ip_pattern, &af, &start_ip, &end_ip, &spec)) {
            *pAf = af;
            *pPrefix = spec;
            *pIpStartOut = start_ip;
            *pIpEndOut = end_ip;
            *pIsRangeOut = TRUE;
            return TRUE;
        }
    }

    // Fall back to single IP/CIDR.
    {
        USHORT af = 0;
        UCHAR prefix = 0;
        IP_ADDRESS ip;
        memset(&ip, 0, sizeof(ip));
        if (!DNS_Rebind_ParseIpCidrPattern(ip_pattern, &af, &prefix, &ip))
            return FALSE;
        *pAf = af;
        *pPrefix = prefix;
        *pIpStartOut = ip;
        memset(pIpEndOut, 0, sizeof(*pIpEndOut));
        *pIsRangeOut = FALSE;
        return TRUE;
    }
}

static BOOLEAN DNS_Rebind_MatchPrefixBits(const BYTE* addr, const BYTE* rule, int bits, int bytes)
{
    if (!addr || !rule || bits < 0)
        return FALSE;
    if (bits == 0)
        return TRUE;

    int full_bytes = bits / 8;
    int rem_bits = bits % 8;

    if (full_bytes > bytes)
        return FALSE;

    if (full_bytes > 0 && memcmp(addr, rule, (size_t)full_bytes) != 0)
        return FALSE;

    if (rem_bits == 0)
        return TRUE;

    if (full_bytes >= bytes)
        return FALSE;

    BYTE mask = (BYTE)(0xFF << (8 - rem_bits));
    return (addr[full_bytes] & mask) == (rule[full_bytes] & mask);
}

static BOOLEAN DNS_Rebind_IsBytesInRangeInclusive(const BYTE* value, const BYTE* start, const BYTE* end, int bytes)
{
    if (!value || !start || !end || bytes <= 0)
        return FALSE;
    if (memcmp(value, start, (size_t)bytes) < 0)
        return FALSE;
    if (memcmp(value, end, (size_t)bytes) > 0)
        return FALSE;
    return TRUE;
}

static void DNS_Rebind_GetV4Candidates(const IP_ADDRESS* pIP, BYTE out1[4], BYTE out2[4])
{
    // IPv4 addresses are stored in bytes 12-15 of IP_ADDRESS.Data
    // Both candidates should be identical - just extract directly from bytes
    const BYTE* addr = (const BYTE*)pIP->Data;
    out1[0] = addr[12];
    out1[1] = addr[13];
    out1[2] = addr[14];
    out1[3] = addr[15];

    // out2 is identical to out1 (no byte order conversion needed)
    out2[0] = addr[12];
    out2[1] = addr[13];
    out2[2] = addr[14];
    out2[3] = addr[15];
}

static BOOLEAN DNS_Rebind_IsV4Like(const IP_ADDRESS* pIP)
{
    if (!pIP)
        return FALSE;
    const BYTE* a = (const BYTE*)pIP->Data;
    for (int i = 0; i < 10; ++i) {
        if (a[i] != 0)
            return FALSE;
    }
    // Accept IPv4-compatible (::w.x.y.z, deprecated) and IPv4-mapped (::ffff:w.x.y.z)
    if ((a[10] == 0 && a[11] == 0) || (a[10] == 0xFF && a[11] == 0xFF))
        return TRUE;
    return FALSE;
}

static BOOLEAN DNS_Rebind_IsV4Mapped(const IP_ADDRESS* pIP)
{
    if (!pIP)
        return FALSE;
    const BYTE* a = (const BYTE*)pIP->Data;
    for (int i = 0; i < 10; ++i) {
        if (a[i] != 0)
            return FALSE;
    }
    return (a[10] == 0xFF && a[11] == 0xFF);
}

static BOOLEAN DNS_Rebind_IsV4LikeWithHint(const IP_ADDRESS* pIP, ADDRESS_FAMILY af_hint)
{
    if (af_hint == AF_INET)
        return TRUE;
    if (af_hint == AF_INET6)
        return DNS_Rebind_IsV4Mapped(pIP);
    return DNS_Rebind_IsV4Like(pIP);
}

static BOOLEAN DNS_Rebind_IpRuleMatches(const REBIND_IP_RULE* rule, const WCHAR* domain, const IP_ADDRESS* pIP, ADDRESS_FAMILY af_hint)
{
    if (!rule || !pIP)
        return FALSE;

    if (rule->process_pattern && rule->process_pattern[0]) {
        const WCHAR* image_name = (Dll_ImageName && Dll_ImageName[0]) ? Dll_ImageName : L"";
        const WCHAR* pat = rule->process_pattern;
        BOOLEAN inv = FALSE;
        if (*pat == L'!') {
            inv = TRUE;
            ++pat;
        }
        BOOLEAN match = Config_MatchImage(pat, 0, image_name, 1);
        if (inv)
            match = !match;
        if (!match) {
            if (DNS_Rebind_ProtectionEnabled && !DNS_ShouldSuppressLogTagged(domain, DNS_REBIND_LOG_TAG_DEFAULT)) {
                DNS_TRACE_LOG(L"[DNS Rebind IP] Process mismatch: pat=%s, image=%s", rule->process_pattern, image_name);
            }
            return FALSE;
        }
    }

    if (rule->domain_pattern && rule->domain_pattern[0]) {
        if (!domain || !domain[0])
            return FALSE;
        if (!DNS_Rebind_MatchWildcard(rule->domain_pattern, domain))
            return FALSE;
    }

    if (rule->af == AF_INET) {
        if (!DNS_Rebind_IsV4LikeWithHint(pIP, af_hint))
            return FALSE;
        BYTE cand1[4], cand2[4];
        DNS_Rebind_GetV4Candidates(pIP, cand1, cand2);
        if (rule->is_range) {
            const BYTE* start4 = &rule->ip.Data[12];
            const BYTE* end4 = &rule->ip_end.Data[12];
            if (DNS_Rebind_IsBytesInRangeInclusive(cand1, start4, end4, 4))
                return TRUE;
            if (DNS_Rebind_IsBytesInRangeInclusive(cand2, start4, end4, 4))
                return TRUE;
            return FALSE;
        } else {
            const BYTE* rule4 = &rule->ip.Data[12];
            int bits = (int)rule->prefix_len;
            if (DNS_Rebind_MatchPrefixBits(cand1, rule4, bits, 4))
                return TRUE;
            if (DNS_Rebind_MatchPrefixBits(cand2, rule4, bits, 4))
                return TRUE;
            return FALSE;
        }
    }

    if (rule->af == AF_INET6) {
        if (af_hint == AF_INET)
            return FALSE;
        if (af_hint == AF_INET6 && DNS_Rebind_IsV4Mapped(pIP))
            return FALSE;
        if (rule->is_range) {
            return DNS_Rebind_IsBytesInRangeInclusive((const BYTE*)pIP->Data, (const BYTE*)rule->ip.Data, (const BYTE*)rule->ip_end.Data, 16);
        }
        return DNS_Rebind_MatchPrefixBits((const BYTE*)pIP->Data, (const BYTE*)rule->ip.Data, (int)rule->prefix_len, 16);
    }

    return FALSE;
}

static long DNS_Rebind_IpRuleScore(const REBIND_IP_RULE* rule)
{
    long score = 0;
    if (rule->process_pattern) {
        score += 1000000;
        score += DNS_Rebind_SpecificityScore(rule->process_pattern);
    }
    if (rule->domain_pattern) {
        score += 100000;
        score += DNS_Rebind_SpecificityScore(rule->domain_pattern);
    }
    score += (long)rule->prefix_len;
    return score;
}

static LIST DNS_RebindFilteredIpRules;

//---------------------------------------------------------------------------
// String Allocation Helpers
//---------------------------------------------------------------------------

static WCHAR* DNS_Rebind_DuplicateString(const WCHAR* s)
{
    if (!s || !s[0])
        return NULL;
    size_t len = wcslen(s);
    WCHAR* dup = (WCHAR*)Dll_Alloc((len + 1) * sizeof(WCHAR));
    if (dup)
        wmemcpy(dup, s, len + 1);
    return dup;
}

static void DNS_Rebind_FreeString(WCHAR* s)
{
    if (s)
        Dll_Free(s);
}

static BOOLEAN DNS_Rebind_AddFilteredIpRule(const WCHAR* process_pattern, const WCHAR* domain_pattern, const WCHAR* ip_pattern, BOOLEAN enabled)
{
    if (!ip_pattern || !ip_pattern[0])
        return FALSE;

    // Parse IP pattern first to fail early without allocating
    USHORT af = 0;
    UCHAR prefix = 0;
    IP_ADDRESS ip;
    memset(&ip, 0, sizeof(ip));
    BOOLEAN is_range = FALSE;
    IP_ADDRESS ip_end;
    memset(&ip_end, 0, sizeof(ip_end));
    if (!DNS_Rebind_ParseIpSpec(ip_pattern, &af, &prefix, &ip, &is_range, &ip_end))
        return FALSE;

    REBIND_IP_RULE* rule = (REBIND_IP_RULE*)Dll_Alloc(sizeof(REBIND_IP_RULE));
    if (!rule)
        return FALSE;
    memset(rule, 0, sizeof(*rule));

    rule->enabled = enabled;
    rule->af = af;
    rule->prefix_len = prefix;
    rule->ip = ip;
    rule->is_range = is_range;
    rule->ip_end = ip_end;
    rule->process_pattern = DNS_Rebind_DuplicateString(process_pattern);
    rule->domain_pattern = DNS_Rebind_DuplicateString(domain_pattern);
    rule->ip_pattern = DNS_Rebind_DuplicateString(ip_pattern);

    List_Insert_After(&DNS_RebindFilteredIpRules, NULL, rule);
    return TRUE;
}

static BOOLEAN DNS_Rebind_ParseFilteredIpRuleValue(WCHAR* buf, WCHAR** pProcOut, WCHAR** pDomainOut, WCHAR** pIpOut, BOOLEAN* pEnabledOut)
{
    if (!buf || !pProcOut || !pDomainOut || !pIpOut || !pEnabledOut)
        return FALSE;

    *pProcOut = NULL;
    *pDomainOut = NULL;
    *pIpOut = NULL;
    *pEnabledOut = TRUE;

    WCHAR* s = DNS_Rebind_TrimInPlace(buf);
    if (!s || !s[0])
        return FALSE;

    // Optional trailing action flag ';y|n' (preferred), ':y|n' or ',y|n' (outside brackets)
    BOOLEAN action_found = FALSE;

    // New syntax prefers ';y|n'
    WCHAR* last_semi = DNS_Rebind_FindLastCharOutsideBrackets(s, L';');
    if (last_semi) {
        WCHAR* flag = DNS_Rebind_TrimInPlace(last_semi + 1);
        if (flag && (flag[0] == L'y' || flag[0] == L'Y' || flag[0] == L'n' || flag[0] == L'N') && flag[1] == 0) {
            *pEnabledOut = (flag[0] == L'y' || flag[0] == L'Y');
            *last_semi = 0;
            s = DNS_Rebind_TrimInPlace(s);
            action_found = TRUE;
        }
    }

    WCHAR* last_colon = DNS_Rebind_FindLastCharOutsideBrackets(s, L':');
    if (!action_found && last_colon) {
        WCHAR* flag = DNS_Rebind_TrimInPlace(last_colon + 1);
        if (flag && (flag[0] == L'y' || flag[0] == L'Y' || flag[0] == L'n' || flag[0] == L'N') && flag[1] == 0) {
            *pEnabledOut = (flag[0] == L'y' || flag[0] == L'Y');
            *last_colon = 0;
            s = DNS_Rebind_TrimInPlace(s);
            action_found = TRUE;
        }
    }
    if (!action_found) {
        WCHAR* last_comma = DNS_Rebind_FindLastCharOutsideBrackets(s, L',');
        if (last_comma) {
            WCHAR* flag = DNS_Rebind_TrimInPlace(last_comma + 1);
            if (flag && (flag[0] == L'y' || flag[0] == L'Y' || flag[0] == L'n' || flag[0] == L'N') && flag[1] == 0) {
                *pEnabledOut = (flag[0] == L'y' || flag[0] == L'Y');
                *last_comma = 0;
                s = DNS_Rebind_TrimInPlace(s);
            }
        }
    }

    // Optional leading process pattern (process,rest)
    WCHAR* comma = DNS_Rebind_FindCharOutsideBrackets(s, L',');
    if (comma) {
        *comma = 0;
        WCHAR* proc = DNS_Rebind_TrimInPlace(s);
        WCHAR* rem = DNS_Rebind_TrimInPlace(comma + 1);
        if (proc && proc[0])
            *pProcOut = proc;
        s = rem;
    }

    if (!s || !s[0])
        return FALSE;

    // First try treating the remainder as a plain ip_pattern (supports raw IPv6 with colons).
    {
        USHORT af = 0;
        UCHAR prefix = 0;
        IP_ADDRESS ip_tmp;
        IP_ADDRESS ip_end_tmp;
        BOOLEAN is_range_tmp = FALSE;
        memset(&ip_tmp, 0, sizeof(ip_tmp));
        memset(&ip_end_tmp, 0, sizeof(ip_end_tmp));
        if (DNS_Rebind_ParseIpSpec(s, &af, &prefix, &ip_tmp, &is_range_tmp, &ip_end_tmp)) {
            WCHAR* ip = DNS_Rebind_TrimInPlace(s);
            if (ip && ip[0])
                *pIpOut = ip;
            return (*pIpOut != NULL);
        }
    }

    // Optional domain:ip_pattern split by first ':' outside brackets
    WCHAR* colon = DNS_Rebind_FindCharOutsideBrackets(s, L':');
    if (colon) {
        *colon = 0;
        WCHAR* dom = DNS_Rebind_TrimInPlace(s);
        WCHAR* ip = DNS_Rebind_TrimInPlace(colon + 1);
        if (dom && dom[0])
            *pDomainOut = dom;
        if (ip && ip[0])
            *pIpOut = ip;
    } else {
        WCHAR* ip = DNS_Rebind_TrimInPlace(s);
        if (ip && ip[0])
            *pIpOut = ip;
    }

    return (*pIpOut != NULL);
}

static void DNS_Rebind_LoadFilteredIpRulesFromSection(const WCHAR* section_name)
{
    if (!DNS_Rebind_ProtectionEnabled)
        return;

    static const WCHAR* kSettingNames[] = {
        L"FilterDnsIP"
    };

    const WCHAR* log_section = section_name;
    if (!log_section || !log_section[0]) {
        log_section = (Dll_BoxName && Dll_BoxName[0]) ? Dll_BoxName : L"<box>";
    }

    WCHAR conf_buf[256];
    for (int setting_index = 0; setting_index < ARRAYSIZE(kSettingNames); ++setting_index) {
        const WCHAR* setting_name = kSettingNames[setting_index];
        for (ULONG index = 0; ; ++index) {
            NTSTATUS status = SbieApi_QueryConf(section_name, setting_name, index, conf_buf, sizeof(conf_buf) - 16 * sizeof(WCHAR));
            if (!NT_SUCCESS(status))
                break;

            // Keep the full rule value intact (including optional [process,] prefix).
            const WCHAR* value = conf_buf;
            if (!value || !value[0])
                continue;

            // Debug: log each rule value read from config
            if (!DNS_IsSuppressLogEnabled()) {
                DNS_DEBUG_LOG(L"[DNS Rebind] %s read from [%s][%d]: %s",
                              setting_name,
                              log_section, index, value);
            }

            size_t value_len = wcslen(value);
            WCHAR* buf = (WCHAR*)Dll_Alloc((value_len + 1) * sizeof(WCHAR));
            if (!buf)
                continue;
            wmemcpy(buf, value, value_len + 1);

            WCHAR* proc_pat = NULL;
            WCHAR* dom_pat = NULL;
            WCHAR* ip_pat = NULL;
            BOOLEAN enabled = TRUE;

            if (DNS_Rebind_ParseFilteredIpRuleValue(buf, &proc_pat, &dom_pat, &ip_pat, &enabled)) {
                if (!DNS_Rebind_AddFilteredIpRule(proc_pat, dom_pat, ip_pat, enabled)) {
                    DNS_DEBUG_LOG(L"[DNS Rebind] %s add failed in [%s]: proc=%s, dom=%s, ip=%s",
                                  setting_name,
                                  log_section,
                                  proc_pat ? proc_pat : L"(all)",
                                  dom_pat ? dom_pat : L"(all)",
                                  ip_pat ? ip_pat : L"(null)");
                } else {
                    if (!DNS_IsSuppressLogEnabled()) {
                        DNS_DEBUG_LOG(L"[DNS Rebind] %s added from [%s]: proc=%s, dom=%s, ip=%s, enabled=%d",
                                      setting_name,
                                      log_section,
                                      proc_pat ? proc_pat : L"(all)",
                                      dom_pat ? dom_pat : L"(all)",
                                      ip_pat ? ip_pat : L"(null)",
                                      enabled ? 1 : 0);
                    }
                }
            } else {
                DNS_DEBUG_LOG(L"[DNS Rebind] %s parse failed in [%s]: %s", setting_name, log_section, value);
            }

            Dll_Free(buf);
        }
    }
}

static void DNS_Rebind_LoadProtectionFromSection(const WCHAR* section_name)
{
    WCHAR conf_buf[256];

    for (ULONG index = 0; ; ++index) {
        NTSTATUS status = SbieApi_QueryConf(section_name, L"DnsRebindProtection", index, conf_buf, sizeof(conf_buf) - 16 * sizeof(WCHAR));
        if (!NT_SUCCESS(status))
            break;

        if (!conf_buf[0])
            continue;

        WCHAR* buf = DNS_Rebind_DuplicateString(conf_buf);
        if (!buf)
            continue;

        WCHAR* process_pattern = NULL;
        WCHAR* domain_pattern = NULL;
        BOOLEAN enabled = FALSE;

        if (DNS_Rebind_ParseProtectionConfig(buf, &process_pattern, &domain_pattern, &enabled)) {
            DNS_Rebind_AddPattern(process_pattern, domain_pattern, enabled);
        }

        Dll_Free(buf);
    }
}

static BOOLEAN DNS_Rebind_IsFilteredIpByRuleList(const WCHAR* domain, const IP_ADDRESS* pIP, ADDRESS_FAMILY af_hint)
{
    if (!pIP)
        return FALSE;

    if (List_Count(&DNS_RebindFilteredIpRules) <= 0)
        return FALSE;

    REBIND_IP_RULE* best = NULL;
    long best_score = LONG_MIN;

    for (REBIND_IP_RULE* entry = (REBIND_IP_RULE*)List_Head(&DNS_RebindFilteredIpRules); entry; entry = (REBIND_IP_RULE*)List_Next(entry)) {
        if (!DNS_Rebind_IpRuleMatches(entry, domain, pIP, af_hint))
            continue;

        long score = DNS_Rebind_IpRuleScore(entry);
        
        // Format IP address for logging
        WCHAR msg[256] = L"";
        extern void WSA_DumpIP(ADDRESS_FAMILY af, IP_ADDRESS* pIP, wchar_t* pStr);
        ADDRESS_FAMILY af = af_hint;
        if (af != AF_INET && af != AF_INET6)
            af = DNS_Rebind_IsV4Like(pIP) ? AF_INET : AF_INET6;
        WSA_DumpIP(af, (IP_ADDRESS*)pIP, msg);
        
        if (DNS_Rebind_ProtectionEnabled && !DNS_ShouldSuppressLogTagged(domain, DNS_REBIND_LOG_TAG_DEFAULT)) {
            DNS_TRACE_LOG(L"[DNS Rebind IP] Rule matched: proc=%s, dom=%s, ip_pattern=%s, score=%ld, enabled=%d%s",
                          entry->process_pattern ? entry->process_pattern : L"(all)",
                          entry->domain_pattern ? entry->domain_pattern : L"(all)",
                          entry->ip_pattern ? entry->ip_pattern : L"(null)",
                          score, entry->enabled ? 1 : 0, msg);
        }
        if (score >= best_score) {
            best_score = score;
            best = entry;
        }
    }

    if (!best)
        return FALSE;
    return best->enabled;
}

//---------------------------------------------------------------------------
// Check if rebind protection is enabled for domain
// Supports pattern matching with wildcards
//---------------------------------------------------------------------------

static int DNS_Rebind_SpecificityScore(const WCHAR* pattern)
{
    if (!pattern || !pattern[0])
        return 0;

    int literal_count = 0;
    int wildcard_count = 0;
    for (const WCHAR* p = pattern; *p; ++p) {
        if (*p == L'*' || *p == L'?')
            wildcard_count++;
        else
            literal_count++;
    }

    // Prefer longer, more literal patterns. Penalize wildcards heavily so:
    //   "exact.domain" outranks "*.domain" outranks "*".
    // Ties are resolved by "last matching rule wins" in the caller.
    return (literal_count * 16) - (wildcard_count * 64) + (int)wcslen(pattern);
}

_FX BOOLEAN DNS_Rebind_IsEnabledForDomain(const WCHAR* domain)
{
    if (!DNS_Rebind_ProtectionEnabled)
        return FALSE;

    // Check if protection is enabled for this domain
    // Returns TRUE if rebind protection should be applied
    // 
    // IMPORTANT: NetworkDnsFilterExclude takes precedence (always skip rebind).
    // NetworkDnsFilter precedence is handled per-IP-family in DNS_Rebind_ShouldFilterIpForDomain().

    if (!domain) {
        DNS_DEBUG_LOG(L"[DNS Rebind Check] domain is NULL");
        return FALSE;
    }

    // Check if list is empty (no patterns configured)
    REBIND_PATTERN* first_pattern = (REBIND_PATTERN*)List_Head(&DNS_RebindPatterns);
    if (!first_pattern) {
        DNS_DEBUG_LOG(L"[DNS Rebind Check] No patterns configured for domain: %s", domain);
        return FALSE;
    }

    // Check if domain is excluded (NetworkDnsFilterExclude)
    // If it is, let the exclusion rule handle it (don't apply rebind protection)
    if (DNS_IsExcluded(domain)) {
        // Domain is excluded from DNS filtering - don't apply rebind protection
        return FALSE;
    }

    // Get current process image name for matching
    const WCHAR* image_name = Dll_ImageName;
    if (!image_name)
        image_name = L"";

    REBIND_PATTERN* entry = (REBIND_PATTERN*)List_Head(&DNS_RebindPatterns);

    REBIND_PATTERN* best = NULL;
    long best_score = LONG_MIN;

    while (entry) {
        // Check process pattern if present
        if (entry->process_pattern) {
            const WCHAR* pat = entry->process_pattern;
            BOOLEAN inv = FALSE;
            if (*pat == L'!') {
                inv = TRUE;
                ++pat;
            }
            BOOLEAN match = Config_MatchImage(pat, 0, image_name, 1);
            if (inv)
                match = !match;
            if (!match) {
                entry = (REBIND_PATTERN*)List_Next(entry);
                continue;
            }
        }

        // Check domain pattern if present
        if (entry->domain_pattern) {
            if (!DNS_Rebind_MatchWildcard(entry->domain_pattern, domain)) {
                entry = (REBIND_PATTERN*)List_Next(entry);
                continue;
            }
        }

        // Both matched (or were not specified). Compute specificity.
        // Priority order (highest to lowest):
        //   1) Has process pattern
        //   2) Has domain pattern
        //   3) Domain specificity (exact > wildcard, longer > shorter)
        //   4) Process specificity (exact > wildcard, longer > shorter)
        long score = 0;
        if (entry->process_pattern) {
            score += 1000000;
            score += DNS_Rebind_SpecificityScore(entry->process_pattern);
        }
        if (entry->domain_pattern) {
            score += 100000;
            score += DNS_Rebind_SpecificityScore(entry->domain_pattern);
        }

        // Global default (no process/domain) gets score 0.
        // If scores tie, prefer the later entry (last matching rule wins).
        if (score >= best_score) {
            best_score = score;
            best = entry;
        }

        entry = (REBIND_PATTERN*)List_Next(entry);
    }

    if (best) {
        if (best->enabled && !DNS_ShouldSuppressLogTagged(domain, DNS_REBIND_LOG_TAG_DEFAULT)) {
            DNS_DEBUG_LOG(L"[DNS Rebind Check] Domain %s matched best rule (score=%ld) enabled=%d proc=%s dom=%s",
                          domain,
                          best_score,
                          best->enabled,
                          best->process_pattern ? best->process_pattern : L"(all)",
                          best->domain_pattern ? best->domain_pattern : L"(all)");
        }
        return best->enabled;
    }
    return FALSE;
}

//---------------------------------------------------------------------------
// Shared helpers
//---------------------------------------------------------------------------

_FX BOOLEAN DNS_Rebind_ShouldFilterIpForDomain(const WCHAR* domain, const IP_ADDRESS* pIP, ADDRESS_FAMILY af_hint)
{
    if (!domain || !domain[0] || !pIP)
        return FALSE;

    // Auto-exclude encrypted DNS server hostnames (prevents chicken-and-egg problem
    // when WinHTTP needs to resolve DoH server hostname to connect)
    if (EncryptedDns_IsServerHostname(domain))
        return FALSE;

    if (!DNS_Rebind_IsEnabledForDomain(domain))
        return FALSE;

    // Determine qtype from address family hint (shared by DNSSEC and NetworkDnsFilter checks)
    USHORT qtype;
    if (af_hint == AF_INET)
        qtype = DNS_TYPE_A;
    else if (af_hint == AF_INET6)
        qtype = DNS_TYPE_AAAA;
    else
        qtype = DNS_Rebind_IsV4Like(pIP) ? DNS_TYPE_A : DNS_TYPE_AAAA;

    // DNSSEC skip: when DnssecEnabled=y and RRSIG records are present in the
    // EncDns cache or system DNS response for this domain/type, skip rebind
    // filtering. The RRSIG proves the response was DNSSEC-signed and validated.
    if (DNS_DnssecGetMode(domain) == DNSSEC_MODE_ENABLED) {
        if (EncryptedDns_IsEnabled() && EncryptedDns_CacheHasRrsig(domain, qtype)) {
            DNS_TRACE_LOG(L"[DNS Rebind] DNSSEC skip for %s (type %s) - EncDns cache RRSIG", domain, DNS_GetTypeName(qtype));
            return FALSE;
        }
        if (DNS_Rebind_DnssecHasRrsigForType(domain, qtype)) {
            DNS_TRACE_LOG(L"[DNS Rebind] DNSSEC skip for %s (type %s) - system DNS RRSIG", domain, DNS_GetTypeName(qtype));
            return FALSE;
        }
    }

    // If domain is filtered by NetworkDnsFilter for this IP family, don't apply rebind protection.
    // This keeps filter rules authoritative per address family.
    LIST* filter_entries = NULL;
    if (DNS_CheckFilter(domain, qtype, &filter_entries)) {
        return FALSE;
    }

    // Use rule-based filtering (templates.ini always loads default private IP ranges)
    return DNS_Rebind_IsFilteredIpByRuleList(domain, pIP, af_hint);
}

//---------------------------------------------------------------------------
// Passthrough sanitizers (system-DNS results)
//---------------------------------------------------------------------------

// Relative pointer helpers for HOSTENT blob (WSALookupService)
// Windows BLOB format uses offsets (not absolute pointers) from the base address.
#define DNS_REBIND_ABS_PTR(base, rel)    ((void*)(((BYTE*)(base)) + (uintptr_t)(rel)))
static __inline uintptr_t DNS_REBIND_GET_REL_FROM_PTR(void* p) { return (uintptr_t)(p); }

static BOOLEAN DNS_Rebind_ShouldFilterSockaddrForDomain(const WCHAR* domain, ADDRESS_FAMILY af, const void* sockaddrPtr)
{
    if (!sockaddrPtr)
        return FALSE;

    IP_ADDRESS ip;
    if (!DNS_Rebind_SockaddrToIpAddress(af, sockaddrPtr, &ip))
        return FALSE;

    if (domain && domain[0]) return DNS_Rebind_ShouldFilterIpForDomain(domain, &ip, af);
    return DNS_Rebind_IsFilteredIpByRuleList(NULL, &ip, af);
}

_FX void DNS_Rebind_SanitizeSockaddr(ADDRESS_FAMILY af, void* sockaddrPtr)
{
    // Deprecated in filter-only mode: no rewriting is performed.
    (void)af;
    (void)sockaddrPtr;
}

_FX void DNS_Rebind_SanitizeAddrInfoW(const WCHAR* domain, PADDRINFOW* ppResult)
{
    if (!domain || !ppResult || !*ppResult)
        return;

    if (!DNS_Rebind_IsEnabledForDomain(domain))
        return;

    ULONG filtered = 0;
    ULONG kept = 0;

    PADDRINFOW prev = NULL;
    PADDRINFOW cur = *ppResult;
    while (cur) {
        PADDRINFOW next = cur->ai_next;
        if (cur->ai_addr && DNS_Rebind_ShouldFilterSockaddrForDomain(domain, (ADDRESS_FAMILY)cur->ai_family, cur->ai_addr)) {
            if (prev)
                prev->ai_next = next;
            else
                *ppResult = next;
            cur->ai_next = NULL;
            P_FreeAddrInfoW freeW = DNS_Rebind_GetFreeAddrInfoW();
            if (freeW)
                freeW(cur);
            else if (!DNS_ShouldSuppressLogTagged(domain, DNS_REBIND_LOG_TAG_DEFAULT))
                DNS_DEBUG_LOG(L"[DNS Rebind] FreeAddrInfoW not available while filtering %s", domain);
            ++filtered;
        } else {
            ++kept;
            prev = cur;
        }
        cur = next;
    }

    if (filtered && !DNS_ShouldSuppressLogTagged(domain, DNS_REBIND_LOG_TAG_DEFAULT)) {
        DNS_TRACE_LOG(L"[DNS Rebind] Filtered ADDRINFOW results for domain: %s (filtered=%lu, kept=%lu)",
                      domain, filtered, kept);
    }
}

_FX void DNS_Rebind_SanitizeAddrInfoA(const WCHAR* domain, PADDRINFOA* ppResult)
{
    if (!domain || !ppResult || !*ppResult)
        return;

    if (!DNS_Rebind_IsEnabledForDomain(domain))
        return;

    ULONG filtered = 0;
    ULONG kept = 0;

    PADDRINFOA prev = NULL;
    PADDRINFOA cur = *ppResult;
    while (cur) {
        PADDRINFOA next = cur->ai_next;
        if (cur->ai_addr && DNS_Rebind_ShouldFilterSockaddrForDomain(domain, (ADDRESS_FAMILY)cur->ai_family, cur->ai_addr)) {
            if (prev)
                prev->ai_next = next;
            else
                *ppResult = next;
            cur->ai_next = NULL;
            P_freeaddrinfo freeA = DNS_Rebind_GetFreeAddrInfoA();
            if (freeA)
                freeA(cur);
            else if (!DNS_ShouldSuppressLogTagged(domain, DNS_REBIND_LOG_TAG_DEFAULT))
                DNS_DEBUG_LOG(L"[DNS Rebind] freeaddrinfo not available while filtering %s", domain);
            ++filtered;
        } else {
            ++kept;
            prev = cur;
        }
        cur = next;
    }

    if (filtered && !DNS_ShouldSuppressLogTagged(domain, DNS_REBIND_LOG_TAG_DEFAULT)) {
        DNS_TRACE_LOG(L"[DNS Rebind] Filtered ADDRINFOA results for domain: %s (filtered=%lu, kept=%lu)",
                      domain, filtered, kept);
    }
}

_FX void DNS_Rebind_SanitizeWSAQuerySetW(const WCHAR* domain, LPWSAQUERYSETW lpqsResults)
{
    if (!domain || !lpqsResults)
        return;

    if (!DNS_Rebind_IsEnabledForDomain(domain))
        return;

    // DNSSEC skip: when DnssecEnabled=y and RRSIG is present for this domain,
    // skip WSAQUERYSETW rebind sanitization entirely (trusted DNSSEC response).
    // This is an early-return optimization; the per-IP check in
    // DNS_Rebind_ShouldFilterIpForDomain also checks RRSIG.
    if (DNS_Rebind_DnssecShouldSkipWsaQuerySetW(domain, lpqsResults)) {
        DNS_TRACE_LOG(L"[DNS Rebind] Skipping WSAQUERYSETW sanitization for %s (DNSSEC RRSIG present)", domain);
        return;
    }

    ULONG filtered_csaddr = 0;
    ULONG kept_csaddr = 0;
    ULONG filtered_hostent = 0;
    ULONG kept_hostent = 0;

    // Sanitize CSADDR_INFO
    if (lpqsResults->dwNumberOfCsAddrs > 0 && lpqsResults->lpcsaBuffer) {
        DWORD out = 0;
        for (DWORD i = 0; i < lpqsResults->dwNumberOfCsAddrs; ++i) {
            SOCKADDR* sa = lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr;
            if (sa && DNS_Rebind_ShouldFilterSockaddrForDomain(domain, sa->sa_family, sa)) {
                ++filtered_csaddr;
                continue;
            }
            if (out != i)
                lpqsResults->lpcsaBuffer[out] = lpqsResults->lpcsaBuffer[i];
            ++out;
            ++kept_csaddr;
        }
        lpqsResults->dwNumberOfCsAddrs = out;
    }

    // Sanitize HOSTENT blob (best-effort; respect relative-pointer format)
    if (lpqsResults->lpBlob && lpqsResults->lpBlob->pBlobData && lpqsResults->lpBlob->cbSize >= sizeof(HOSTENT)) {
        HOSTENT* hp = (HOSTENT*)lpqsResults->lpBlob->pBlobData;
        if (hp->h_addrtype == AF_INET || hp->h_addrtype == AF_INET6) {
            if (hp->h_addr_list) {
                DWORD blobSize = lpqsResults->lpBlob->cbSize;
                uintptr_t addrListOffset = DNS_REBIND_GET_REL_FROM_PTR(hp->h_addr_list);
                if (addrListOffset < blobSize) {
                    PCHAR* addrArray = (PCHAR*)DNS_REBIND_ABS_PTR(hp, addrListOffset);
                    DWORD out = 0;
                    SIZE_T addrLen = (hp->h_addrtype == AF_INET) ? 4 : 16;
                    SIZE_T maxEntries = 0;

                    if (addrListOffset < blobSize) {
                        SIZE_T remaining = (SIZE_T)(blobSize - addrListOffset);
                        maxEntries = remaining / sizeof(PCHAR);
                    }

                    for (SIZE_T idx = 0; idx < maxEntries; ++idx) {
                        PCHAR entryPtr = addrArray[idx];
                        if (!entryPtr)
                            break;

                        uintptr_t ipOffset = DNS_REBIND_GET_REL_FROM_PTR(entryPtr);
                        if (ipOffset == 0 || ipOffset + addrLen > blobSize)
                            break;

                        PCHAR ptr = (PCHAR)DNS_REBIND_ABS_PTR(hp, ipOffset);
                        IP_ADDRESS ip;
                        if (hp->h_addrtype == AF_INET)
                            DNS_Rebind_IPv4ToIpAddress(*(DWORD*)ptr, &ip);
                        else
                            DNS_Rebind_IPv6ToIpAddress((const BYTE*)ptr, &ip);

                        if (DNS_Rebind_ShouldFilterIpForDomain(domain, &ip, hp->h_addrtype)) {
                            ++filtered_hostent;
                            continue;
                        }

                        addrArray[out++] = entryPtr;
                        ++kept_hostent;
                    }

                    if (out < maxEntries)
                        addrArray[out] = NULL;
                }
            }
        }
    }

    if ((filtered_csaddr || filtered_hostent) && !DNS_ShouldSuppressLogTagged(domain, DNS_REBIND_LOG_TAG_DEFAULT)) {
        DNS_TRACE_LOG(L"[DNS Rebind] Filtered WSAQUERYSETW for domain: %s (CSADDR filtered=%lu, kept=%lu; HOSTENT filtered=%lu, kept=%lu)",
                      domain, filtered_csaddr, kept_csaddr, filtered_hostent, kept_hostent);
    }
}

_FX void DNS_Rebind_SanitizeDnsRecordList(const WCHAR* domain, PDNS_RECORD* ppRecords)
{
    if (!domain || !ppRecords || !*ppRecords)
        return;

    if (!DNS_Rebind_IsEnabledForDomain(domain))
        return;

    ULONG filteredA = 0;
    ULONG filteredAAAA = 0;

    PDNS_RECORD prev = NULL;
    PDNS_RECORD rec = *ppRecords;
    while (rec) {
        PDNS_RECORD next = rec->pNext;
        BOOLEAN filtered = FALSE;

        if (rec->wType == DNS_TYPE_A) {
            IP_ADDRESS ip;
            DNS_Rebind_IPv4ToIpAddress(rec->Data.A.IpAddress, &ip);
            if (DNS_Rebind_ShouldFilterIpForDomain(domain, &ip, AF_INET)) {
                filtered = TRUE;
                ++filteredA;
            }
        }
        else if (rec->wType == DNS_TYPE_AAAA) {
            IP_ADDRESS ip;
            DNS_Rebind_IPv6ToIpAddress((const BYTE*)&rec->Data.AAAA.Ip6Address, &ip);
            if (DNS_Rebind_ShouldFilterIpForDomain(domain, &ip, AF_INET6)) {
                filtered = TRUE;
                ++filteredAAAA;
            }
        }

        if (filtered) {
            if (prev)
                prev->pNext = next;
            else
                *ppRecords = next;
            rec->pNext = NULL;
            P_DnsRecordListFree freeRec = DNS_Rebind_GetDnsRecordListFree();
            if (freeRec)
                freeRec(rec, DnsFreeRecordList);
            else if (!DNS_ShouldSuppressLogTagged(domain, DNS_REBIND_LOG_TAG_DEFAULT))
                DNS_DEBUG_LOG(L"[DNS Rebind] DnsRecordListFree not available while filtering %s", domain);
        } else {
            prev = rec;
        }

        rec = next;
    }

    if ((filteredA || filteredAAAA) && !DNS_ShouldSuppressLogTagged(domain, DNS_REBIND_LOG_TAG_DEFAULT)) {
        DNS_TRACE_LOG(L"[DNS Rebind] Filtered passthrough DNS_RECORDs for domain: %s (A=%lu, AAAA=%lu)",
                      domain, filteredA, filteredAAAA);
    }
}

//---------------------------------------------------------------------------
// DNS wire-format sanitizer (RFC 1035)
//---------------------------------------------------------------------------

static BOOLEAN DNS_Rebind_SkipDnsName(const BYTE* dns_data, int dns_len, int* pOffset)
{
    int offset = *pOffset;
    while (offset < dns_len) {
        BYTE label_len = dns_data[offset];
        if (label_len == 0) {
            offset++;
            *pOffset = offset;
            return TRUE;
        }
        if (DNS_IS_COMPRESSION_PTR(label_len)) {
            // Compression pointer is two bytes.
            offset += 2;
            *pOffset = offset;
            return (offset <= dns_len);
        }
        offset += 1 + label_len;
    }

    return FALSE;
}

static BOOLEAN DNS_Rebind_ParseWireForSanitize(
    BYTE* data,
    int data_len,
    const WCHAR* domain,
    BOOLEAN isTcp,
    BYTE** pDnsData,
    int* pDnsLen,
    DNS_WIRE_HEADER** pHeader,
    int* pQuestionOffset,
    USHORT* pAnswerCount,
    USHORT* pNsCount,
    USHORT* pAddCount,
    BOOLEAN* pHasLengthPrefix)
{
    if (!data || data_len < (int)sizeof(DNS_WIRE_HEADER) || !domain || !domain[0])
        return FALSE;

    if (!DNS_Rebind_IsEnabledForDomain(domain))
        return FALSE;

    BYTE* dns_data = data;
    int dns_len = data_len;
    BOOLEAN has_length_prefix = FALSE;
    if (isTcp && data_len > 2) {
        USHORT length_prefix = _ntohs(*(USHORT*)data);
        if (length_prefix == (USHORT)(data_len - 2)) {
            dns_data = data + 2;
            dns_len = data_len - 2;
            has_length_prefix = TRUE;
        } else {
            return FALSE;
        }
    }

    if (dns_len < (int)sizeof(DNS_WIRE_HEADER))
        return FALSE;

    DNS_WIRE_HEADER* header = (DNS_WIRE_HEADER*)dns_data;

    // Verify DNS response (QR=1)
    USHORT flags = _ntohs(header->Flags);
    if (((flags >> 15) & 0x1) != 1)
        return FALSE;

    // Only sanitize successful responses (rcode == 0)
    if ((flags & 0x000F) != 0)
        return FALSE;

    USHORT answer_count = _ntohs(header->AnswerRRs);
    USHORT ns_count = _ntohs(header->AuthorityRRs);
    USHORT add_count = _ntohs(header->AdditionalRRs);
    if (answer_count == 0 && ns_count == 0 && add_count == 0)
        return FALSE;

    int offset = (int)sizeof(DNS_WIRE_HEADER);

    // Skip question section (QNAME + QTYPE + QCLASS)
    USHORT question_count = _ntohs(header->Questions);
    for (USHORT q = 0; q < question_count; q++) {
        if (!DNS_Rebind_SkipDnsName(dns_data, dns_len, &offset))
            return FALSE;
        offset += 4;
        if (offset > dns_len)
            return FALSE;
    }

    if (pDnsData) *pDnsData = dns_data;
    if (pDnsLen) *pDnsLen = dns_len;
    if (pHeader) *pHeader = header;
    if (pQuestionOffset) *pQuestionOffset = offset;
    if (pAnswerCount) *pAnswerCount = answer_count;
    if (pNsCount) *pNsCount = ns_count;
    if (pAddCount) *pAddCount = add_count;
    if (pHasLengthPrefix) *pHasLengthPrefix = has_length_prefix;
    return TRUE;
}

_FX BOOLEAN DNS_Rebind_SanitizeDnsWireResponse(
    BYTE* data,
    int data_len,
    const WCHAR* domain,
    BOOLEAN isTcp,
    ULONG* pFilteredA,
    ULONG* pFilteredAAAA,
    int* pNewLen)
{
    if (pFilteredA)
        *pFilteredA = 0;
    if (pFilteredAAAA)
        *pFilteredAAAA = 0;
    if (pNewLen)
        *pNewLen = data_len;

    BYTE* dns_data = NULL;
    int dns_len = 0;
    DNS_WIRE_HEADER* header = NULL;
    int offset = 0;
    USHORT answer_count = 0;
    USHORT ns_count = 0;
    USHORT add_count = 0;
    BOOLEAN has_length_prefix = FALSE;

    if (!DNS_Rebind_ParseWireForSanitize(
            data, data_len, domain, isTcp,
            &dns_data, &dns_len, &header, &offset,
            &answer_count, &ns_count, &add_count,
            &has_length_prefix))
        return FALSE;

    ULONG filteredA = 0;
    ULONG filteredAAAA = 0;

    typedef struct _DNS_REBIND_FILTERED_IP {
        ADDRESS_FAMILY af;
        IP_ADDRESS     ip;
    } DNS_REBIND_FILTERED_IP;

    // Capture a few filtered IPs for logging (avoid unbounded log spam).
    DNS_REBIND_FILTERED_IP filtered_ips[16];
    ULONG filtered_ip_count = 0;
    USHORT kept_answers = 0;
    USHORT kept_ns = 0;
    USHORT kept_add = 0;

    int read_offset = offset;
    int write_offset = offset;

    // Sanitize A/AAAA RRs across all sections (Answer/Authority/Additional).
    // This prevents bypasses via glue records in Additional section.
    struct {
        USHORT count;
        USHORT* kept;
    } sections[3] = {
        { answer_count, &kept_answers },
        { ns_count, &kept_ns },
        { add_count, &kept_add },
    };

    for (int s = 0; s < 3; ++s) {
        for (USHORT i = 0; i < sections[s].count; ++i) {
            int rr_start = read_offset;
            if (!DNS_Rebind_SkipDnsName(dns_data, dns_len, &read_offset))
                return FALSE;

            // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
            if (read_offset + 10 > dns_len)
                return FALSE;

            USHORT rr_type = _ntohs(*(USHORT*)(dns_data + read_offset));
            read_offset += 2;
            read_offset += 2; // CLASS
            read_offset += 4; // TTL
            USHORT rdlength = _ntohs(*(USHORT*)(dns_data + read_offset));
            read_offset += 2;

            if (read_offset + rdlength > dns_len)
                return FALSE;

            BOOLEAN filtered = FALSE;
            if (rr_type == DNS_TYPE_A && rdlength == 4) {
                IP_ADDRESS ip;
                DNS_Rebind_IPv4ToIpAddress(*(DWORD*)(dns_data + read_offset), &ip);
                if (DNS_Rebind_ShouldFilterIpForDomain(domain, &ip, AF_INET)) {
                    filtered = TRUE;
                    filteredA++;

                    if (filtered_ip_count < (ULONG)(sizeof(filtered_ips) / sizeof(filtered_ips[0]))) {
                        filtered_ips[filtered_ip_count].af = AF_INET;
                        filtered_ips[filtered_ip_count].ip = ip;
                        filtered_ip_count++;
                    }
                }
            }
            else if (rr_type == DNS_TYPE_AAAA && rdlength == 16) {
                IP_ADDRESS ip;
                DNS_Rebind_IPv6ToIpAddress(dns_data + read_offset, &ip);
                if (DNS_Rebind_ShouldFilterIpForDomain(domain, &ip, AF_INET6)) {
                    filtered = TRUE;
                    filteredAAAA++;

                    if (filtered_ip_count < (ULONG)(sizeof(filtered_ips) / sizeof(filtered_ips[0]))) {
                        filtered_ips[filtered_ip_count].af = AF_INET6;
                        filtered_ips[filtered_ip_count].ip = ip;
                        filtered_ip_count++;
                    }
                }
            }

            int rr_end = read_offset + rdlength;
            int rr_len = rr_end - rr_start;

            if (!filtered) {
                if (write_offset != rr_start)
                    memmove(dns_data + write_offset, dns_data + rr_start, (size_t)rr_len);
                write_offset += rr_len;
                (*sections[s].kept)++;
            }

            read_offset = rr_end;
        }
    }

    int rr_end = read_offset;
    if ((filteredA || filteredAAAA) && write_offset != rr_end) {
        int tail_len = dns_len - rr_end;
        if (tail_len > 0)
            memmove(dns_data + write_offset, dns_data + rr_end, (size_t)tail_len);
        dns_len -= (rr_end - write_offset);
    }

    if (filteredA || filteredAAAA) {
        header->AnswerRRs = _htons(kept_answers);
        header->AuthorityRRs = _htons(kept_ns);
        header->AdditionalRRs = _htons(kept_add);

        if (pNewLen) {
            if (has_length_prefix) {
                *(USHORT*)data = _htons((USHORT)dns_len);
                *pNewLen = dns_len + 2;
            } else {
                *pNewLen = dns_len;
            }
        }
    }

    if (pFilteredA)
        *pFilteredA = filteredA;
    if (pFilteredAAAA)
        *pFilteredAAAA = filteredAAAA;

    if (filteredA || filteredAAAA) {
        // Use a distinct suppression tag for raw-wire responses, so a prior API
        // log for the same domain (e.g. -type=A) doesn't suppress raw ANY logs.
        if (!DNS_ShouldSuppressLogTagged(domain, DNS_REBIND_LOG_TAG_WIRE)) {
            // Align raw wire-format filtering logs with other APIs: log filtered IPs once per response.
            WCHAR msg[1024];
            msg[0] = L'\0';
            for (ULONG i = 0; i < filtered_ip_count; ++i) {
                WCHAR ip_msg[128] = L"";
                extern void WSA_DumpIP(ADDRESS_FAMILY af, IP_ADDRESS* pIP, wchar_t* pStr);
                WSA_DumpIP(filtered_ips[i].af, &filtered_ips[i].ip, ip_msg);

                size_t len = wcslen(msg);
                size_t avail = (sizeof(msg) / sizeof(msg[0])) - len;
                if (avail <= 2)
                    break;

                // WSA_DumpIP output already includes a leading delimiter (e.g. "; IPv4: ...").
                Sbie_snwprintf(msg + len, avail, L"%s", ip_msg);
            }
            DNS_TRACE_LOG(L"[DNS Rebind] Filtered IP(s) for domain %s%s", domain, msg);

            DNS_TRACE_LOG(L"[DNS Rebind] Filtered raw DNS response for domain: %s (A=%lu, AAAA=%lu)",
                          domain, filteredA, filteredAAAA);
        }
        return TRUE;
    }

    return FALSE;
}

//---------------------------------------------------------------------------
// DnsRebindProtection Config Parsing Helper
//---------------------------------------------------------------------------

// Parse a DnsRebindProtection config value into its components.
// Format: [process_pattern,][domain_pattern:]y|n
// Special token: @nodot@ matches single-label names (no dots, trailing dot ignored)
// Returns TRUE if parsing succeeded, FALSE otherwise.
static BOOLEAN DNS_Rebind_ParseProtectionConfig(
    WCHAR* buf,
    WCHAR** pProcOut,
    WCHAR** pDomainOut,
    BOOLEAN* pEnabledOut)
{
    if (!buf || !pProcOut || !pDomainOut || !pEnabledOut)
        return FALSE;

    *pProcOut = NULL;
    *pDomainOut = NULL;
    *pEnabledOut = FALSE;

    WCHAR* s = DNS_Rebind_TrimInPlace(buf);
    if (!s || !s[0])
        return FALSE;

    WCHAR* first_comma = wcschr(s, L',');
    WCHAR* first_colon = wcschr(s, L':');

    if (first_comma && (!first_colon || first_comma < first_colon)) {
        // Format: process,domain:flag or process,flag
        *first_comma = L'\0';
        WCHAR* proc = DNS_Rebind_TrimInPlace(s);
        if (proc && proc[0])
            *pProcOut = proc;

        WCHAR* remainder = DNS_Rebind_TrimInPlace(first_comma + 1);
        WCHAR* colon = wcschr(remainder, L':');
        if (colon) {
            // Format: domain:flag
            *colon = L'\0';
            WCHAR* dom = DNS_Rebind_TrimInPlace(remainder);
            WCHAR* flag = DNS_Rebind_TrimInPlace(colon + 1);
            if (dom && dom[0])
                *pDomainOut = dom;
            *pEnabledOut = (flag && (flag[0] == L'y' || flag[0] == L'Y'));
        } else {
            // Format: process,flag
            *pEnabledOut = (remainder && (remainder[0] == L'y' || remainder[0] == L'Y'));
        }
    } else if (first_colon) {
        // Format: domain:flag (no process)
        *first_colon = L'\0';
        WCHAR* dom = DNS_Rebind_TrimInPlace(s);
        WCHAR* flag = DNS_Rebind_TrimInPlace(first_colon + 1);
        if (dom && dom[0])
            *pDomainOut = dom;
        *pEnabledOut = (flag && (flag[0] == L'y' || flag[0] == L'Y'));
    } else {
        // Format: flag only (global setting)
        *pEnabledOut = (s[0] == L'y' || s[0] == L'Y');
    }

    return TRUE;
}

// Add a parsed rebind protection pattern to the list.
static BOOLEAN DNS_Rebind_AddPattern(const WCHAR* process_pattern, const WCHAR* domain_pattern, BOOLEAN enabled)
{
    REBIND_PATTERN* pattern = (REBIND_PATTERN*)Dll_Alloc(sizeof(REBIND_PATTERN));
    if (!pattern)
        return FALSE;

    memset(pattern, 0, sizeof(*pattern));
    pattern->enabled = enabled;
    pattern->process_pattern = DNS_Rebind_DuplicateString(process_pattern);
    pattern->domain_pattern = DNS_Rebind_DuplicateString(domain_pattern);

    List_Insert_After(&DNS_RebindPatterns, NULL, pattern);

    if (enabled) {
        DNS_TRACE_LOG(L"[DNS Rebind] Pattern %s: process=%s, domain=%s",
                      L"added",
                      pattern->process_pattern ? pattern->process_pattern : L"(all)",
                      pattern->domain_pattern ? pattern->domain_pattern : L"(all)");
    }

    return TRUE;
}

//---------------------------------------------------------------------------
// Initialize DNS rebind protection
//---------------------------------------------------------------------------

_FX BOOLEAN DNS_Rebind_Init(void)
{
    // Initialize pattern lists
    List_Init(&DNS_RebindPatterns);
    List_Init(&DNS_RebindFilteredIpRules);

    // Check if certificate is valid (requirement for DNS security features)
    if (!DNS_HasValidCertificate) {
        DNS_DEBUG_LOG(L"[DNS Rebind] Certificate required - disabled");
        return TRUE;  // Not an error - just disabled
    }

    // Load DNS Rebind Protection patterns from configuration (merge in order):
    //   1) Templates.ini [TemplateDnsRebindProtection]
    //   2) GlobalSettings
    //   3) Per-box settings
    // Later entries override earlier ones when specificity ties.
    DNS_Rebind_LoadProtectionFromSection(L"TemplateDnsRebindProtection");
    DNS_Rebind_LoadProtectionFromSection(L"GlobalSettings");
    DNS_Rebind_LoadProtectionFromSection(NULL);

    // Check if any patterns have protection enabled
    BOOLEAN has_enabled_pattern = FALSE;
    for (REBIND_PATTERN* p = (REBIND_PATTERN*)List_Head(&DNS_RebindPatterns); p; p = (REBIND_PATTERN*)List_Next(p)) {
        if (p->enabled) {
            has_enabled_pattern = TRUE;
            break;
        }
    }

    DNS_Rebind_ProtectionEnabled = has_enabled_pattern;

    if (has_enabled_pattern) {
        DNS_TRACE_LOG(L"[DNS Rebind] Protection loaded with %d pattern(s)",
                      List_Count(&DNS_RebindPatterns));

        // Load FilterDnsIP rules:
        //   1) Always load defaults from Templates.ini template section
        //   2) Then load GlobalSettings overrides (if present)
        //   3) Finally load per-box overrides
        // This lets users disable a template entry with "...,n".
        DNS_Rebind_LoadFilteredIpRulesFromSection(L"TemplateDnsRebindProtection");
        DNS_Rebind_LoadFilteredIpRulesFromSection(L"GlobalSettings");
        DNS_Rebind_LoadFilteredIpRulesFromSection(NULL);

        if (List_Count(&DNS_RebindFilteredIpRules) > 0) {
            DNS_TRACE_LOG(L"[DNS Rebind] FilterDnsIP loaded with %d rule(s)",
                          List_Count(&DNS_RebindFilteredIpRules));
        } else {
            DNS_DEBUG_LOG(L"[DNS Rebind] No FilterDnsIP configured - rebind filtering disabled");
        }
    } else {
        DNS_DEBUG_LOG(L"[DNS Rebind] No enabled patterns - disabled");
    }

    return TRUE;
}

