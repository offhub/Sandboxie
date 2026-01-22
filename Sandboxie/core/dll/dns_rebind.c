/*
 * Copyright 2024-2025 David Xanatos, xanasoft.com
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
#include "dns_wire.h"
#include "dns_encrypted.h"  // For EncryptedDns_IsServerHostname()
#include "common/netfw.h"
#include "common/list.h"
#include "common/pattern.h"

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
    UCHAR prefix_len;           // CIDR prefix bits (0-32 or 0-128)
    IP_ADDRESS ip;              // Address bytes (AF_INET stored in Data[12..15])
} REBIND_IP_RULE;

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

// Suppress duplicate rebind-check debug logs for the same domain
#define DNS_REBIND_LOG_SUPPRESS_SIZE 32
#define DNS_REBIND_LOG_SUPPRESS_MS   2000
typedef struct _DNS_REBIND_LOG_ENTRY {
    ULONG     hash;
    ULONGLONG tick;
    BOOLEAN   valid;
} DNS_REBIND_LOG_ENTRY;

static DNS_REBIND_LOG_ENTRY g_RebindLogCache[DNS_REBIND_LOG_SUPPRESS_SIZE];
static CRITICAL_SECTION g_RebindLogLock;
static BOOLEAN g_RebindLogInit = FALSE;

static ULONG DNS_Rebind_HashString(const WCHAR* str)
{
    ULONG hash = 2166136261u;
    if (!str)
        return hash;
    for (const WCHAR* p = str; *p; ++p) {
        hash ^= (ULONG)towlower(*p);
        hash *= 16777619u;
    }
    return hash;
}

static void DNS_Rebind_InitLogCache(void)
{
    if (!g_RebindLogInit) {
        InitializeCriticalSection(&g_RebindLogLock);
        memset(g_RebindLogCache, 0, sizeof(g_RebindLogCache));
        g_RebindLogInit = TRUE;
    }
}

static BOOLEAN DNS_Rebind_ShouldSuppressLog(const WCHAR* domain)
{
    if (!DNS_IsSuppressLogEnabled())
        return FALSE;

    if (!domain || !domain[0])
        return FALSE;

    DNS_Rebind_InitLogCache();

    ULONG h = DNS_Rebind_HashString(domain);
    ULONG idx = h % DNS_REBIND_LOG_SUPPRESS_SIZE;
    ULONGLONG now = GetTickCount64();

    EnterCriticalSection(&g_RebindLogLock);
    DNS_REBIND_LOG_ENTRY* entry = &g_RebindLogCache[idx];
    if (entry->valid && entry->hash == h && (now - entry->tick) < DNS_REBIND_LOG_SUPPRESS_MS) {
        LeaveCriticalSection(&g_RebindLogLock);
        return TRUE;
    }
    entry->valid = TRUE;
    entry->hash = h;
    entry->tick = now;
    LeaveCriticalSection(&g_RebindLogLock);
    return FALSE;
}

static BOOLEAN DNS_Rebind_MatchWildcard(const WCHAR* pattern, const WCHAR* str) {
    if (!pattern || !str) return FALSE;
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
// FilterDnsRebindIP parsing helpers
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

static BOOLEAN DNS_Rebind_ParseIpPattern(const WCHAR* ip_pattern, USHORT* pAf, UCHAR* pPrefix, IP_ADDRESS* pIpOut)
{
    if (!ip_pattern || !ip_pattern[0] || !pAf || !pPrefix || !pIpOut)
        return FALSE;

    WCHAR tmp[80];
    size_t in_len = wcslen(ip_pattern);
    if (in_len >= ARRAYSIZE(tmp))
        return FALSE;
    wmemcpy(tmp, ip_pattern, in_len + 1);

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

    // Trim whitespace after CIDR prefix removal
    s = DNS_Rebind_TrimInPlace(s);
    if (!s || !s[0])
        return FALSE;

    // Strip IPv6 bracket notation [ipv6addr] used in config format
    WCHAR stripped_ipv6[256] = {0};
    const WCHAR* addr = s;
    if (s[0] == L'[') {
        // IPv6 in brackets - find closing bracket
        WCHAR* closing = wcschr(s, L']');
        if (!closing || closing == s + 1)
            return FALSE;  // Mismatched brackets or empty
        // Copy content between brackets
        int len = (int)(closing - s - 1);
        if (len >= (int)sizeof(stripped_ipv6) / sizeof(WCHAR))
            return FALSE;  // Address too long
        wcsncpy(stripped_ipv6, s + 1, len);
        stripped_ipv6[len] = 0;
        addr = stripped_ipv6;
    }

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
    // Accept ::w.x.y.z (deprecated) and ::ffff:w.x.y.z
    if ((a[10] == 0 && a[11] == 0) || (a[10] == 0xFF && a[11] == 0xFF))
        return TRUE;
    return FALSE;
}

static BOOLEAN DNS_Rebind_IpRuleMatches(const REBIND_IP_RULE* rule, const WCHAR* domain, const IP_ADDRESS* pIP)
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
            if (!DNS_Rebind_ShouldSuppressLog(domain)) {
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
        if (!DNS_Rebind_IsV4Like(pIP))
            return FALSE;
        BYTE cand1[4], cand2[4];
        DNS_Rebind_GetV4Candidates(pIP, cand1, cand2);
        const BYTE* rule4 = &rule->ip.Data[12];
        int bits = (int)rule->prefix_len;
        if (DNS_Rebind_MatchPrefixBits(cand1, rule4, bits, 4))
            return TRUE;
        if (DNS_Rebind_MatchPrefixBits(cand2, rule4, bits, 4))
            return TRUE;
        return FALSE;
    }

    if (rule->af == AF_INET6) {
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
    if (!DNS_Rebind_ParseIpPattern(ip_pattern, &af, &prefix, &ip))
        return FALSE;

    REBIND_IP_RULE* rule = (REBIND_IP_RULE*)Dll_Alloc(sizeof(REBIND_IP_RULE));
    if (!rule)
        return FALSE;
    memset(rule, 0, sizeof(*rule));

    rule->enabled = enabled;
    rule->af = af;
    rule->prefix_len = prefix;
    rule->ip = ip;
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
        memset(&ip_tmp, 0, sizeof(ip_tmp));
        if (DNS_Rebind_ParseIpPattern(s, &af, &prefix, &ip_tmp)) {
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
    static const WCHAR* kSettingNames[] = {
        L"FilterDnsRebindIP"
    };

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
            DNS_TRACE_LOG(L"[DNS Rebind] FilterDnsRebindIP read from [%s][%d]: %s",
                          section_name ? section_name : L"<box>", index, value);

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
                    DNS_TRACE_LOG(L"[DNS Rebind] FilterDnsRebindIP add failed in [%s]: proc=%s, dom=%s, ip=%s",
                                  section_name ? section_name : L"<box>",
                                  proc_pat ? proc_pat : L"(all)",
                                  dom_pat ? dom_pat : L"(all)",
                                  ip_pat ? ip_pat : L"(null)");
                } else {
                    DNS_TRACE_LOG(L"[DNS Rebind] FilterDnsRebindIP added from [%s]: proc=%s, dom=%s, ip=%s, enabled=%d",
                                  section_name ? section_name : L"<box>",
                                  proc_pat ? proc_pat : L"(all)",
                                  dom_pat ? dom_pat : L"(all)",
                                  ip_pat ? ip_pat : L"(null)",
                                  enabled ? 1 : 0);
                }
            } else {
                DNS_TRACE_LOG(L"[DNS Rebind] FilterDnsRebindIP parse failed in [%s]: %s", section_name ? section_name : L"<box>", value);
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

static BOOLEAN DNS_Rebind_IsFilteredIpByRuleList(const WCHAR* domain, const IP_ADDRESS* pIP)
{
    if (!pIP)
        return FALSE;

    if (List_Count(&DNS_RebindFilteredIpRules) <= 0)
        return FALSE;

    REBIND_IP_RULE* best = NULL;
    long best_score = LONG_MIN;

    for (REBIND_IP_RULE* entry = (REBIND_IP_RULE*)List_Head(&DNS_RebindFilteredIpRules); entry; entry = (REBIND_IP_RULE*)List_Next(entry)) {
        if (!DNS_Rebind_IpRuleMatches(entry, domain, pIP))
            continue;

        long score = DNS_Rebind_IpRuleScore(entry);
        
        // Format IP address for logging
        WCHAR msg[256] = L"";
        extern void WSA_DumpIP(ADDRESS_FAMILY af, IP_ADDRESS* pIP, wchar_t* pStr);
        ADDRESS_FAMILY af = (pIP->Data32[0] == 0 && pIP->Data32[1] == 0 && pIP->Data[8] == 0 && pIP->Data[9] == 0 && 
                             (pIP->Data32[2] == 0 || (pIP->Data[10] == 0xFF && pIP->Data[11] == 0xFF))) ? AF_INET : AF_INET6;
        WSA_DumpIP(af, (IP_ADDRESS*)pIP, msg);
        
        if (!DNS_Rebind_ShouldSuppressLog(domain)) {
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
        if (!DNS_Rebind_ShouldSuppressLog(domain)) {
            DNS_DEBUG_LOG(L"[DNS Rebind Check] Domain %s matched best rule (score=%ld) enabled=%d proc=%s dom=%s",
                          domain,
                          best_score,
                          best->enabled,
                          best->process_pattern ? best->process_pattern : L"(all)",
                          best->domain_pattern ? best->domain_pattern : L"(all)");
        }
        return best->enabled;
    }

    if (!DNS_Rebind_ShouldSuppressLog(domain)) {
        DNS_DEBUG_LOG(L"[DNS Rebind Check] Domain %s - no match, disabled", domain);
    }
    return FALSE;
}

//---------------------------------------------------------------------------
// Shared helpers
//---------------------------------------------------------------------------

_FX BOOLEAN DNS_Rebind_ShouldFilterIpForDomain(const WCHAR* domain, const IP_ADDRESS* pIP)
{
    if (!domain || !domain[0] || !pIP)
        return FALSE;

    // Auto-exclude encrypted DNS server hostnames (prevents chicken-and-egg problem
    // when WinHTTP needs to resolve DoH server hostname to connect)
    if (EncryptedDns_IsServerHostname(domain))
        return FALSE;

    if (!DNS_Rebind_IsEnabledForDomain(domain))
        return FALSE;

    // If domain is filtered by NetworkDnsFilter for this IP family, don't apply rebind protection.
    // This keeps filter rules authoritative per address family.
    LIST* filter_entries = NULL;
    USHORT qtype = DNS_Rebind_IsV4Like(pIP) ? DNS_TYPE_A : DNS_TYPE_AAAA;
    if (DNS_CheckFilter(domain, qtype, &filter_entries)) {
        return FALSE;
    }

    // Use rule-based filtering (templates.ini always loads default private IP ranges)
    return DNS_Rebind_IsFilteredIpByRuleList(domain, pIP);
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

    if (domain && domain[0])
        return DNS_Rebind_ShouldFilterIpForDomain(domain, &ip);
    return DNS_Rebind_IsFilteredIpByRuleList(NULL, &ip);
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
            else if (!DNS_Rebind_ShouldSuppressLog(domain))
                DNS_DEBUG_LOG(L"[DNS Rebind] FreeAddrInfoW not available while filtering %s", domain);
            ++filtered;
        } else {
            ++kept;
            prev = cur;
        }
        cur = next;
    }

    if (filtered && !DNS_Rebind_ShouldSuppressLog(domain)) {
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
            else if (!DNS_Rebind_ShouldSuppressLog(domain))
                DNS_DEBUG_LOG(L"[DNS Rebind] freeaddrinfo not available while filtering %s", domain);
            ++filtered;
        } else {
            ++kept;
            prev = cur;
        }
        cur = next;
    }

    if (filtered && !DNS_Rebind_ShouldSuppressLog(domain)) {
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

                        if (DNS_Rebind_ShouldFilterIpForDomain(domain, &ip)) {
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

    if ((filtered_csaddr || filtered_hostent) && !DNS_Rebind_ShouldSuppressLog(domain)) {
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
            if (DNS_Rebind_ShouldFilterIpForDomain(domain, &ip)) {
                filtered = TRUE;
                ++filteredA;
            }
        }
        else if (rec->wType == DNS_TYPE_AAAA) {
            IP_ADDRESS ip;
            DNS_Rebind_IPv6ToIpAddress((const BYTE*)&rec->Data.AAAA.Ip6Address, &ip);
            if (DNS_Rebind_ShouldFilterIpForDomain(domain, &ip)) {
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
            else if (!DNS_Rebind_ShouldSuppressLog(domain))
                DNS_DEBUG_LOG(L"[DNS Rebind] DnsRecordListFree not available while filtering %s", domain);
        } else {
            prev = rec;
        }

        rec = next;
    }

    if ((filteredA || filteredAAAA) && !DNS_Rebind_ShouldSuppressLog(domain)) {
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

    if (!data || data_len < (int)sizeof(DNS_WIRE_HEADER) || !domain || !domain[0])
        return FALSE;

    if (!DNS_Rebind_IsEnabledForDomain(domain))
        return FALSE;

    // For TCP, require a complete 2-byte length prefix that matches the buffer.
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
    if (answer_count == 0)
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

    ULONG filteredA = 0;
    ULONG filteredAAAA = 0;
    USHORT kept_answers = 0;

    int answer_start = offset;
    int read_offset = offset;
    int write_offset = offset;

    for (USHORT a = 0; a < answer_count && read_offset < dns_len; a++) {
        int rr_start = read_offset;
        if (!DNS_Rebind_SkipDnsName(dns_data, dns_len, &read_offset))
            break;

        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
        if (read_offset + 10 > dns_len)
            break;

        USHORT rr_type = _ntohs(*(USHORT*)(dns_data + read_offset));
        read_offset += 2;
        read_offset += 2; // CLASS
        read_offset += 4; // TTL
        USHORT rdlength = _ntohs(*(USHORT*)(dns_data + read_offset));
        read_offset += 2;

        if (read_offset + rdlength > dns_len)
            break;

        BOOLEAN filtered = FALSE;
        if (rr_type == DNS_TYPE_A && rdlength == 4) {
            IP_ADDRESS ip;
            DNS_Rebind_IPv4ToIpAddress(*(DWORD*)(dns_data + read_offset), &ip);
            if (DNS_Rebind_ShouldFilterIpForDomain(domain, &ip)) {
                filtered = TRUE;
                filteredA++;
            }
        }
        else if (rr_type == DNS_TYPE_AAAA && rdlength == 16) {
            IP_ADDRESS ip;
            DNS_Rebind_IPv6ToIpAddress(dns_data + read_offset, &ip);
            if (DNS_Rebind_ShouldFilterIpForDomain(domain, &ip)) {
                filtered = TRUE;
                filteredAAAA++;
            }
        }

        int rr_end = read_offset + rdlength;
        int rr_len = rr_end - rr_start;

        if (!filtered) {
            if (write_offset != rr_start)
                memmove(dns_data + write_offset, dns_data + rr_start, (size_t)rr_len);
            write_offset += rr_len;
            kept_answers++;
        }

        read_offset = rr_end;
    }

    int answer_end = read_offset;
    if ((filteredA || filteredAAAA) && write_offset != answer_end) {
        int tail_len = dns_len - answer_end;
        if (tail_len > 0)
            memmove(dns_data + write_offset, dns_data + answer_end, (size_t)tail_len);
        dns_len -= (answer_end - write_offset);
    }

    if (filteredA || filteredAAAA) {
        header->AnswerRRs = _htons(kept_answers);
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
        if (!DNS_Rebind_ShouldSuppressLog(domain)) {
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

    DNS_TRACE_LOG(L"[DNS Rebind] Pattern %s: process=%s, domain=%s",
                  enabled ? L"added" : L"excluded",
                  pattern->process_pattern ? pattern->process_pattern : L"(all)",
                  pattern->domain_pattern ? pattern->domain_pattern : L"(all)");

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

    if (has_enabled_pattern) {
        DNS_TRACE_LOG(L"[DNS Rebind] Protection loaded with %d pattern(s)",
                      List_Count(&DNS_RebindPatterns));

        // Load FilterDnsRebindIP rules:
        //   1) Always load defaults from Templates.ini template section
        //   2) Then load GlobalSettings overrides (if present)
        //   3) Finally load per-box overrides
        // This lets users disable a template entry with "...,n".
        DNS_Rebind_LoadFilteredIpRulesFromSection(L"TemplateDnsRebindProtection");
        DNS_Rebind_LoadFilteredIpRulesFromSection(L"GlobalSettings");
        DNS_Rebind_LoadFilteredIpRulesFromSection(NULL);

        if (List_Count(&DNS_RebindFilteredIpRules) > 0) {
            DNS_TRACE_LOG(L"[DNS Rebind] FilterDnsRebindIP loaded with %d rule(s)",
                          List_Count(&DNS_RebindFilteredIpRules));
        } else {
            DNS_DEBUG_LOG(L"[DNS Rebind] No FilterDnsRebindIP configured - rebind filtering disabled");
        }
    } else {
        DNS_DEBUG_LOG(L"[DNS Rebind] No enabled patterns - disabled");
    }

    return TRUE;
}

