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

//---------------------------------------------------------------------------
// DNS Logging Module
//
// Centralized DNS logging functionality separated from dns_filter.c
// for better code organization and maintainability.
//---------------------------------------------------------------------------

#include "dll.h"
#include "dns_logging.h"
#include "dns_filter.h"
#include "dns_rebind.h"
#include <windows.h>
#include <wchar.h>
#include <windns.h>
#include "common/my_wsa.h"
#include "wsa_defs.h"
#include <SvcGuid.h>

// External timing function
ULONGLONG GetTickCount64();

// External functions from net.c/dns_filter.c
BOOLEAN WSA_GetIP(const SOCKADDR* addr, int addrlen, IP_ADDRESS* pIP);
void WSA_DumpIP(ADDRESS_FAMILY af, IP_ADDRESS* pIP, wchar_t* pStr);

// External function from dns_doh.c
BOOLEAN EncryptedDns_IsEnabled(void);

// DNS trace and debug flags (moved from dns_filter.c)
BOOLEAN DNS_TraceFlag = FALSE;
BOOLEAN DNS_DebugFlag = FALSE;

#if !defined(_DNSDEBUG)
// Release builds: compile out debug-only logging paths.
// Note: this is file-local and does NOT remove the exported DNS_DebugFlag variable.
#undef DNS_DebugFlag
#define DNS_DebugFlag 0
#endif

// External configuration function
extern BOOLEAN Config_GetSettingsForImageName_bool(const WCHAR* setting, BOOLEAN default_value);

//---------------------------------------------------------------------------
// DNS Log Suppression Cache
//
// Prevents duplicate logging when the same DNS query is resolved through
// multiple APIs (e.g., DnsQueryEx → WSALookupService, DnsQuery_A → DnsQuery_W)
// within a short time window (5 seconds).
//---------------------------------------------------------------------------

// Keep type-key suppression separate from tag-key suppression.
// This prevents tag entries (e.g., EDNS hostname checks) from being churned
// out of the cache by high-volume type-based suppression traffic.
#define DNS_SUPPRESS_CACHE_SIZE_TYPE 256
#define DNS_SUPPRESS_CACHE_SIZE_TAG  64
#define DNS_SUPPRESS_EXPIRY_MS 5000

typedef struct _DNS_SUPPRESS_ENTRY {
    WCHAR     domain[256];
    ULONG     key;
    ULONGLONG timestamp;
    ULONGLONG last_access;
    BOOLEAN   reported;
    BOOLEAN   valid;
} DNS_SUPPRESS_ENTRY;

static DNS_SUPPRESS_ENTRY g_DnsSuppressCacheType[DNS_SUPPRESS_CACHE_SIZE_TYPE];
static DNS_SUPPRESS_ENTRY g_DnsSuppressCacheTag[DNS_SUPPRESS_CACHE_SIZE_TAG];
static CRITICAL_SECTION g_DnsSuppressLock;
static BOOLEAN g_DnsSuppressInitialized = FALSE;
static volatile LONG g_DnsSuppressInitState = 0; // 0=uninitialized, 1=initializing, 2=initialized
static BOOLEAN g_SuppressDnsLogEnabled = TRUE;  // SuppressDnsLog setting (default: enabled)

// Initialize suppression cache
static void DNS_InitSuppressCache(void)
{
    LONG state = InterlockedCompareExchange(&g_DnsSuppressInitState, 0, 0);
    if (state == 2)
        return;

    if (InterlockedCompareExchange(&g_DnsSuppressInitState, 1, 0) == 0) {
        InitializeCriticalSection(&g_DnsSuppressLock);
        memset(g_DnsSuppressCacheType, 0, sizeof(g_DnsSuppressCacheType));
        memset(g_DnsSuppressCacheTag, 0, sizeof(g_DnsSuppressCacheTag));
        g_DnsSuppressInitialized = TRUE;
        InterlockedExchange(&g_DnsSuppressInitState, 2);
        return;
    }

    while ((state = InterlockedCompareExchange(&g_DnsSuppressInitState, 0, 0)) == 1) {
        Sleep(0);
    }
}

// Query SuppressDnsLog effective state
BOOLEAN DNS_IsSuppressLogEnabled(void)
{
    return g_SuppressDnsLogEnabled;
}

// Improved string hash (FNV-1a variant with per-process salt)
// More resistant to collision attacks than simple djb2
static ULONG g_HashSalt = 0;
static ULONG DNS_HashString(const WCHAR* str)
{
    // Initialize salt on first use (process-unique value)
    if (g_HashSalt == 0) {
        g_HashSalt = (ULONG)GetCurrentProcessId() ^ (ULONG)GetTickCount();
        if (g_HashSalt == 0) g_HashSalt = 0x811c9dc5;  // FNV offset basis
    }
    
    // FNV-1a hash with salt
    ULONG hash = 0x811c9dc5 ^ g_HashSalt;  // FNV offset basis XOR salt
    while (*str) {
        hash ^= (ULONG)(*str++);
        hash *= 0x01000193;  // FNV prime
    }
    return hash;
}

// Check if query was recently logged (returns TRUE if should suppress)
static void DNS_FormatTagForLog(WCHAR* out, SIZE_T out_cch, ULONG tag)
{
    if (!out || out_cch == 0)
        return;

    out[0] = L'\0';

    WCHAR c0 = (WCHAR)(tag & 0xFF);
    WCHAR c1 = (WCHAR)((tag >> 8) & 0xFF);
    WCHAR c2 = (WCHAR)((tag >> 16) & 0xFF);
    WCHAR c3 = (WCHAR)((tag >> 24) & 0xFF);

    BOOLEAN printable =
        (c0 >= 0x20 && c0 <= 0x7E) &&
        (c1 >= 0x20 && c1 <= 0x7E) &&
        (c2 >= 0x20 && c2 <= 0x7E) &&
        (c3 >= 0x20 && c3 <= 0x7E);

    if (printable) {
        Sbie_snwprintf(out, out_cch, L"%c%c%c%c (0x%08X)", c0, c1, c2, c3, tag);
    } else {
        Sbie_snwprintf(out, out_cch, L"0x%08X", tag);
    }
}

static BOOLEAN DNS_ShouldSuppressLogEx(const WCHAR* domain, ULONG key, BOOLEAN key_is_tag)
{
    if (!domain || (!DNS_TraceFlag && !DNS_DebugFlag) || !g_SuppressDnsLogEnabled)
        return FALSE;
    
    if (InterlockedCompareExchange(&g_DnsSuppressInitState, 0, 0) != 2)
        DNS_InitSuppressCache();
    if (InterlockedCompareExchange(&g_DnsSuppressInitState, 0, 0) != 2)
        return FALSE;
    
    ULONGLONG now = GetTickCount64();
    // Each cache has its own namespace, so we can keep the original key.
    ULONG stored_key = key;
    EnterCriticalSection(&g_DnsSuppressLock);

    DNS_SUPPRESS_ENTRY* cache = key_is_tag ? g_DnsSuppressCacheTag : g_DnsSuppressCacheType;
    ULONG cache_size = key_is_tag ? DNS_SUPPRESS_CACHE_SIZE_TAG : DNS_SUPPRESS_CACHE_SIZE_TYPE;

    // Two-pass suppression cache lookup:
    // Pass 1: Scan entire cache for a matching entry (must not stop early!)
    // Pass 2: If no match, find best slot to insert (expired > empty > LRU)
    //
    // BUG FIX: Previously, finding an expired entry would break the loop early,
    // causing us to miss matching entries at later slots. This resulted in
    // duplicate entries and failed suppression.

    // Pass 1: Look for existing matching entry
    for (ULONG i = 0; i < cache_size; ++i) {
        DNS_SUPPRESS_ENTRY* entry = &cache[i];

        if (entry->valid &&
            entry->key == stored_key &&
            (now - entry->timestamp) < DNS_SUPPRESS_EXPIRY_MS &&
            _wcsicmp(entry->domain, domain) == 0) {
            
            // Found matching entry - suppress this log
            BOOLEAN should_report = FALSE;
            ULONGLONG delta_ms = now - entry->timestamp;

            // Update access time for LRU eviction decisions.
            entry->last_access = now;

            if (!entry->reported) {
                entry->reported = TRUE;
                should_report = TRUE;
            }

            LeaveCriticalSection(&g_DnsSuppressLock);

            if (DNS_DebugFlag && should_report) {
                WCHAR debug_msg[512];
                if (key_is_tag) {
                    WCHAR tag_msg[32];
                    DNS_FormatTagForLog(tag_msg, (SIZE_T)(sizeof(tag_msg) / sizeof(tag_msg[0])), key);
                    Sbie_snwprintf(debug_msg, 512,
                        L"  DNS Log Suppressed: '%s' (tag=%s) - already logged %llu ms ago",
                        domain, tag_msg, delta_ms);
                } else {
                    Sbie_snwprintf(debug_msg, 512,
                        L"  DNS Log Suppressed: '%s' (Type: %s) - already logged %llu ms ago",
                        domain, DNS_GetTypeName((WORD)key), delta_ms);
                }
                SbieApi_MonitorPutMsg(MONITOR_DNS, debug_msg);
            }

            return TRUE;
        }
    }

    // Pass 2: No match found - find best slot to insert new entry
    // Priority: expired entry > empty slot > least recently accessed
    DNS_SUPPRESS_ENTRY* replace = NULL;
    ULONGLONG replace_tick = ~0ULL;
    for (ULONG i = 0; i < cache_size; ++i) {
        DNS_SUPPRESS_ENTRY* entry = &cache[i];

        if (!entry->valid) {
            // Empty slot - use it immediately
            replace = entry;
            break;
        }

        if ((now - entry->timestamp) >= DNS_SUPPRESS_EXPIRY_MS) {
            // Expired entry - use it immediately
            replace = entry;
            break;
        }

        // Track LRU for fallback
        if (entry->last_access < replace_tick) {
            replace_tick = entry->last_access;
            replace = entry;
        }
    }

    if (replace) {
        wcsncpy(replace->domain, domain, 255);
        replace->domain[255] = L'\0';
        replace->key = stored_key;
        replace->timestamp = now;
        replace->last_access = now;
        replace->reported = FALSE;
        replace->valid = TRUE;
    }

    LeaveCriticalSection(&g_DnsSuppressLock);
    return FALSE;
}

static BOOLEAN DNS_ShouldSuppressLog(const WCHAR* domain, WORD query_type)
{
    return DNS_ShouldSuppressLogEx(domain, (ULONG)query_type, FALSE);
}

BOOLEAN DNS_ShouldSuppressLogTagged(const WCHAR* domain, ULONG tag)
{
    return DNS_ShouldSuppressLogEx(domain, tag, TRUE);
}

// Public initialization function to load SuppressDnsLog setting
BOOLEAN DNS_LoadSuppressLogSetting(void)
{
    g_SuppressDnsLogEnabled = Config_GetSettingsForImageName_bool(L"SuppressDnsLog", TRUE);
    
    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"DNS Log Suppression: Configuration loaded - SuppressDnsLog=%s (TTL=%d ms, CacheType=%d, CacheTag=%d, ReportOnce=1)",
            g_SuppressDnsLogEnabled ? L"Enabled" : L"Disabled", DNS_SUPPRESS_EXPIRY_MS,
            DNS_SUPPRESS_CACHE_SIZE_TYPE, DNS_SUPPRESS_CACHE_SIZE_TAG);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    return g_SuppressDnsLogEnabled;
}

//---------------------------------------------------------------------------
// Helper Functions
//---------------------------------------------------------------------------

// Get reason string for passthrough logging
_FX const WCHAR* DNS_GetPassthroughReasonString(DNS_PASSTHROUGH_REASON reason)
{
    switch (reason) {
        case DNS_PASSTHROUGH_NO_MATCH:           return L"no filter match";
        case DNS_PASSTHROUGH_EXCLUDED:           return L"excluded";
        case DNS_PASSTHROUGH_NO_CERT:            return L"no certificate";
        case DNS_PASSTHROUGH_TYPE_NOT_FILTERED:  return L"type not filtered";
        case DNS_PASSTHROUGH_TYPE_NEGATED:       return L"type negated";
        case DNS_PASSTHROUGH_CONFIG_ERROR:       return L"config error";
        case DNS_PASSTHROUGH_UNSUPPORTED_TYPE:   return L"unsupported type (use encrypted DNS)";
        case DNS_PASSTHROUGH_NONE:
        default:                                 return NULL;
    }
}

// Check if an IPv6 address is IPv4-mapped (::ffff:a.b.c.d)
// Format: Bytes 0-9 must be 0x00, bytes 10-11 must be 0xFF
BOOLEAN DNS_IsIPv4Mapped(const IP_ADDRESS* pIP)
{
    return (pIP->Data32[0] == 0 && 
            pIP->Data32[1] == 0 && 
            pIP->Data[8] == 0 && 
            pIP->Data[9] == 0 &&
            pIP->Data[10] == 0xFF && 
            pIP->Data[11] == 0xFF);
}

//---------------------------------------------------------------------------
// General logging functions
//---------------------------------------------------------------------------

_FX void DNS_LogSimple(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* suffix)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s: %s (Type: %s)%s%s",
        prefix, domain, DNS_GetTypeName(wType),
        suffix ? L" - " : L"",
        suffix ? suffix : L"");
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
}

_FX void DNS_LogExclusion(const WCHAR* domain)
{
    if (!DNS_TraceFlag || !domain)
        return;

    if (DNS_ShouldSuppressLogTagged(domain, DNS_EXCL_LOG_TAG))
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"DNS Exclusion: Domain '%s' matched exclusion list, skipping filter", domain);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogIntercepted(const WCHAR* prefix, const WCHAR* domain, WORD wType, LIST* pEntries, BOOLEAN is_encdns)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    // Skip if we've already logged this query recently (suppression)
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    WCHAR msg[1024];
    Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s)",
        prefix, domain, DNS_GetTypeName(wType));
    
    if (pEntries) {
        BOOLEAN is_any_query = (wType == 255);
        USHORT targetType = (wType == DNS_TYPE_AAAA) ? AF_INET6 : AF_INET;
        
        IP_ENTRY* entry = (IP_ENTRY*)List_Head(pEntries);
        while (entry) {
            if (is_any_query || entry->Type == targetType) {
                WSA_DumpIP(entry->Type, &entry->IP, msg);
            }
            entry = (IP_ENTRY*)List_Next(entry);
        }
    }
    
    // EncDns-based resolution: MONITOR_OPEN (successful DNS query)
    // Filter-based interception: MONITOR_DENY (redirected/blocked query)
    ULONG monitorFlag = is_encdns ? MONITOR_OPEN : MONITOR_DENY;
    SbieApi_MonitorPutMsg(MONITOR_DNS | monitorFlag, msg);
}

_FX void DNS_LogBlocked(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* reason)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    // Skip if we've already logged this query recently (suppression)
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    WCHAR msg[1024];
    Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s) - %s",
        prefix, domain, DNS_GetTypeName(wType), reason);
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
}

_FX void DNS_LogInterceptedNoData(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* reason)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    // Skip if we've already logged this query recently (suppression)
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    WCHAR msg[1024];
    Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s) - %s",
        prefix, domain, DNS_GetTypeName(wType), reason);
    // NODATA for unsupported types uses MONITOR_DENY - we're blocking access to real data
    // (returning fake empty response, not passthrough)
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
}

_FX void DNS_LogPassthrough(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* reason)
{
    DNS_LogSimple(prefix, domain, wType, reason);
}

_FX void DNS_LogTypeFilterPassthrough(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* reason)
{
    if (!DNS_TraceFlag)
        return;

    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s Passthrough: %s (Type: %s) - Type filter: %s", 
        prefix, domain, DNS_GetTypeName(wType), reason);
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
}

_FX void DNS_LogPassthroughAnsi(const WCHAR* prefix, const CHAR* domainAnsi, WORD wType, const WCHAR* reason)
{
    if (!DNS_TraceFlag || !domainAnsi)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s: %S (Type: %s)%s%s",
        prefix, domainAnsi, DNS_GetTypeName(wType),
        reason ? L" - " : L"",
        reason ? reason : L"");
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
}

//---------------------------------------------------------------------------
// DNS_RECORD logging
//---------------------------------------------------------------------------

#define MAX_DNS_RECORDS_TO_LOG 20

_FX void DNS_LogDnsRecords(const WCHAR* prefix, const WCHAR* domain, WORD wType, PDNSAPI_DNS_RECORD pRecords, const WCHAR* suffix, BOOLEAN is_passthrough)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    // Skip if we've already logged this query recently (suppression applies to both passthrough and intercepted)
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    // Debug: Log entry to DNS_LogDnsRecords
    if (DNS_DebugFlag) {
        WCHAR debug_entry[256];
        Sbie_snwprintf(debug_entry, 256, L"  DNS_LogDnsRecords ENTRY: prefix=%s domain=%s wType=%s pRecords=%p passthrough=%d",
            prefix, domain, DNS_GetTypeName(wType), pRecords, is_passthrough);
        SbieApi_MonitorPutMsg(MONITOR_DNS, debug_entry);
    }
    
    WCHAR msg[1024];
    if (suffix) {
        Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s)%s",
            prefix, domain, DNS_GetTypeName(wType), suffix);
    } else {
        Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s) - Using filtered response",
            prefix, domain, DNS_GetTypeName(wType));
    }
    
    BOOLEAN is_any_query = (wType == 255);
    PDNSAPI_DNS_RECORD pRec = pRecords;
    int record_count = 0;
    
    // Debug: Count total records
    if (DNS_DebugFlag) {
        int total_records = 0;
        PDNSAPI_DNS_RECORD pCount = pRecords;
        while (pCount) {
            total_records++;
            pCount = pCount->pNext;
        }
        WCHAR debug_count[256];
        Sbie_snwprintf(debug_count, 256, L"  DNS_LogDnsRecords: Total records in chain: %d", total_records);
        SbieApi_MonitorPutMsg(MONITOR_DNS, debug_count);
    }
    
        // Import setting for passthrough filtering
        extern BOOLEAN DNS_MapIpv4ToIpv6;
    
    // For AAAA queries: check if native IPv6 exists first
    BOOLEAN has_native_ipv6 = FALSE;
    if (wType == DNS_TYPE_AAAA) {
        PDNSAPI_DNS_RECORD pCheckRec = pRecords;
        while (pCheckRec) {
            if (pCheckRec->wType == DNS_TYPE_AAAA) {
                IP_ADDRESS check_ip;
                memset(&check_ip, 0, sizeof(check_ip));
                memcpy(check_ip.Data, &pCheckRec->Data.AAAA.Ip6Address, 16);
                if (!DNS_IsIPv4Mapped(&check_ip)) {
                    has_native_ipv6 = TRUE;
                    break;
                }
            }
            pCheckRec = pCheckRec->pNext;
        }
    }
    
    while (pRec && record_count < MAX_DNS_RECORDS_TO_LOG) {
        BOOLEAN type_matches = (pRec->wType == wType) || is_any_query;
        BOOLEAN is_loggable_type = (pRec->wType == DNS_TYPE_A || pRec->wType == DNS_TYPE_AAAA);
        
        // Debug: Log each record being examined
        if (DNS_DebugFlag) {
            WCHAR debug_rec[256];
            Sbie_snwprintf(debug_rec, 256, L"  DNS_LogDnsRecords: Record #%d type=%s type_matches=%d loggable=%d",
                record_count, DNS_GetTypeName(pRec->wType), type_matches, is_loggable_type);
            SbieApi_MonitorPutMsg(MONITOR_DNS, debug_rec);
        }
        
        if (type_matches && is_loggable_type) {
                // Skip A records in AAAA passthrough queries when mapping is disabled
                if (is_passthrough && wType == DNS_TYPE_AAAA && pRec->wType == DNS_TYPE_A && !DNS_MapIpv4ToIpv6) {
                    pRec = pRec->pNext;
                    record_count++;
                    continue;
                }
            
            if (DNS_DebugFlag) {
                WCHAR debug_msg[256];
                Sbie_snwprintf(debug_msg, 256, L"  DNS_LogDnsRecords: Processing record type=%s for query type=%s",
                    DNS_GetTypeName(pRec->wType), DNS_GetTypeName(wType));
                SbieApi_MonitorPutMsg(MONITOR_DNS, debug_msg);
            }
            IP_ADDRESS ip;
            memset(&ip, 0, sizeof(ip));
            if (pRec->wType == DNS_TYPE_AAAA) {
                memcpy(ip.Data, &pRec->Data.AAAA.Ip6Address, 16);
                
                    // Skip IPv4-mapped addresses:
                    // - For passthrough AAAA queries when mapping disabled: always skip
                    // - For filtered responses: skip only if native IPv6 exists
                    BOOLEAN should_skip_mapped = FALSE;
                    BOOLEAN is_ipv4_mapped = DNS_IsIPv4Mapped(&ip);
                    
                    if (DNS_DebugFlag) {
                        WCHAR debug_ipv4mapped[512];
                        Sbie_snwprintf(debug_ipv4mapped, 512, 
                            L"    IPv6 bytes: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x - IsIPv4Mapped=%d",
                            ip.Data[0], ip.Data[1], ip.Data[2], ip.Data[3],
                            ip.Data[4], ip.Data[5], ip.Data[6], ip.Data[7],
                            ip.Data[8], ip.Data[9], ip.Data[10], ip.Data[11],
                            ip.Data[12], ip.Data[13], ip.Data[14], ip.Data[15],
                            is_ipv4_mapped);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, debug_ipv4mapped);
                    }
                    
                    if (is_ipv4_mapped) {
                        if (is_passthrough && wType == DNS_TYPE_AAAA && !DNS_MapIpv4ToIpv6) {
                            should_skip_mapped = TRUE;
                        } else if (has_native_ipv6) {
                            should_skip_mapped = TRUE;
                        }
                    }
                
                    if (should_skip_mapped) {
                    if (DNS_DebugFlag) {
                        WCHAR debug_msg[256];
                            Sbie_snwprintf(debug_msg, 256, L"    Skipping IPv4-mapped IPv6 (passthrough=%d mapping=%d native=%d)",
                                is_passthrough, DNS_MapIpv4ToIpv6, has_native_ipv6);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, debug_msg);
                    }
                } else {
                    WSA_DumpIP(AF_INET6, &ip, msg);
                }
            } else if (pRec->wType == DNS_TYPE_A) {
                ip.Data32[3] = pRec->Data.A.IpAddress;
                WSA_DumpIP(AF_INET, &ip, msg);
            }
        }
        pRec = pRec->pNext;
        record_count++;
    }
    
    SbieApi_MonitorPutMsg(is_passthrough ? (MONITOR_DNS | MONITOR_OPEN) : (MONITOR_DNS | MONITOR_DENY), msg);
}

//---------------------------------------------------------------------------
// DNS_LogDnsRecordsWithReason
//
// Logs DNS records with passthrough reason (for DnsQueryEx passthrough)
//---------------------------------------------------------------------------

_FX void DNS_LogDnsRecordsWithReason(const WCHAR* prefix, const WCHAR* domain, WORD wType,
                                     PDNSAPI_DNS_RECORD pRecords, DNS_PASSTHROUGH_REASON reason)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    // Skip if we've already logged this query recently (suppression applies to passthrough)
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    // Build suffix with reason
    const WCHAR* reasonStr = DNS_GetPassthroughReasonString(reason);
    WCHAR suffix[128];
    if (reasonStr && reasonStr[0] != L'\0') {
        Sbie_snwprintf(suffix, 128, L" [%s]", reasonStr);
    } else {
        suffix[0] = L'\0';
    }
    
    // Use the standard DNS_LogDnsRecords but with our reason suffix
    // We pass is_passthrough=TRUE to use MONITOR_OPEN flag
    WCHAR msg[1024];
    Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s)%s",
        prefix, domain, DNS_GetTypeName(wType), suffix);
    
    BOOLEAN is_any_query = (wType == 255);
    PDNSAPI_DNS_RECORD pRec = pRecords;
    int record_count = 0;
    
    extern BOOLEAN DNS_MapIpv4ToIpv6;
    
    // For AAAA queries: check if native IPv6 exists first
    BOOLEAN has_native_ipv6 = FALSE;
    if (wType == DNS_TYPE_AAAA) {
        PDNSAPI_DNS_RECORD pCheckRec = pRecords;
        while (pCheckRec) {
            if (pCheckRec->wType == DNS_TYPE_AAAA) {
                IP_ADDRESS check_ip;
                memset(&check_ip, 0, sizeof(check_ip));
                memcpy(check_ip.Data, &pCheckRec->Data.AAAA.Ip6Address, 16);
                if (!DNS_IsIPv4Mapped(&check_ip)) {
                    has_native_ipv6 = TRUE;
                    break;
                }
            }
            pCheckRec = pCheckRec->pNext;
        }
    }
    
    while (pRec && record_count < MAX_DNS_RECORDS_TO_LOG) {
        BOOLEAN type_matches = (pRec->wType == wType) || is_any_query;
        BOOLEAN is_loggable_type = (pRec->wType == DNS_TYPE_A || pRec->wType == DNS_TYPE_AAAA);
        
        if (type_matches && is_loggable_type) {
            // Skip A records in AAAA passthrough queries when mapping is disabled
            if (wType == DNS_TYPE_AAAA && pRec->wType == DNS_TYPE_A && !DNS_MapIpv4ToIpv6) {
                pRec = pRec->pNext;
                record_count++;
                continue;
            }
            
            IP_ADDRESS ip;
            memset(&ip, 0, sizeof(ip));
            if (pRec->wType == DNS_TYPE_AAAA) {
                memcpy(ip.Data, &pRec->Data.AAAA.Ip6Address, 16);
                
                // Check if IPv4-mapped and skip if conditions met
                BOOLEAN is_ipv4_mapped = DNS_IsIPv4Mapped(&ip);
                BOOLEAN should_skip_mapped = FALSE;
                
                if (is_ipv4_mapped) {
                    if (wType == DNS_TYPE_AAAA && !DNS_MapIpv4ToIpv6) {
                        should_skip_mapped = TRUE;
                    } else if (has_native_ipv6) {
                        should_skip_mapped = TRUE;
                    }
                }
                
                if (!should_skip_mapped) {
                    WSA_DumpIP(AF_INET6, &ip, msg);
                }
            } else if (pRec->wType == DNS_TYPE_A) {
                ip.Data32[3] = pRec->Data.A.IpAddress;
                WSA_DumpIP(AF_INET, &ip, msg);
            }
        }
        pRec = pRec->pNext;
        record_count++;
    }
    
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
}

//---------------------------------------------------------------------------
// DnsQuery-specific logging
//---------------------------------------------------------------------------

static const WCHAR* DNS_GetStatusMessage(DNS_STATUS status);

_FX void DNS_LogDnsQueryResultWithReason(const WCHAR* sourceTag, const WCHAR* domain, WORD wType,
                                         DNS_STATUS status, PDNSAPI_DNS_RECORD* ppQueryResults,
                                         DNS_PASSTHROUGH_REASON reason)
{
    if (!DNS_TraceFlag || !domain)
        return;

    // Skip if we've already logged this query recently (suppression)
    if (DNS_ShouldSuppressLog(domain, wType))
        return;

    WCHAR msg[1024];
    const WCHAR* reasonStr = DNS_GetPassthroughReasonString(reason);
    
    if (status == 0 && ppQueryResults && *ppQueryResults) {
        if (reasonStr) {
            Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s) [%s]",
                sourceTag, domain, DNS_GetTypeName(wType), reasonStr);
        } else {
            Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s)",
                sourceTag, domain, DNS_GetTypeName(wType));
        }
    } else {
        const WCHAR* statusMsg = DNS_GetStatusMessage(status);
        if (reasonStr) {
            if (statusMsg) {
                Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s) [%s] - %s",
                    sourceTag, domain, DNS_GetTypeName(wType), reasonStr, statusMsg);
            } else {
                Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s) [%s] - Status: %d",
                    sourceTag, domain, DNS_GetTypeName(wType), reasonStr, status);
            }
        } else {
            if (statusMsg) {
                Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s) - %s",
                    sourceTag, domain, DNS_GetTypeName(wType), statusMsg);
            } else {
                Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s) - Status: %d",
                    sourceTag, domain, DNS_GetTypeName(wType), status);
            }
        }
    }
    
    if (status == 0 && ppQueryResults && *ppQueryResults) {
        PDNSAPI_DNS_RECORD pRec = *ppQueryResults;
        BOOLEAN is_any_query = (wType == 255);
        int record_count = 0;
        
        while (pRec && record_count < MAX_DNS_RECORDS_TO_LOG) {
            // Log only records matching the requested query type (or all types for ANY queries)
            if ((is_any_query || pRec->wType == wType) && 
                (pRec->wType == DNS_TYPE_A || pRec->wType == DNS_TYPE_AAAA)) {
                
                // Skip unexpected A records in AAAA responses unless DnsMapIpv4ToIpv6 is enabled.
                extern BOOLEAN DNS_MapIpv4ToIpv6;
                if (wType == DNS_TYPE_AAAA && pRec->wType == DNS_TYPE_A && !DNS_MapIpv4ToIpv6) {
                    pRec = pRec->pNext;
                    continue;
                }
                
                IP_ADDRESS ip;
                memset(&ip, 0, sizeof(ip));
                if (pRec->wType == DNS_TYPE_AAAA) {
                    memcpy(ip.Data, &pRec->Data.AAAA.Ip6Address, 16);
                    
                    // Skip IPv4-mapped IPv6 for AAAA queries when mapping is disabled
                    // This matches the filtering behavior in DNS_LogDnsRecords for consistency
                    if (wType == DNS_TYPE_AAAA && !DNS_MapIpv4ToIpv6 && DNS_IsIPv4Mapped(&ip)) {
                        pRec = pRec->pNext;
                        continue;
                    }
                    
                    WSA_DumpIP(AF_INET6, &ip, msg);
                } else {
                    ip.Data32[3] = pRec->Data.A.IpAddress;
                    WSA_DumpIP(AF_INET, &ip, msg);
                }
                record_count++;
            }
            pRec = pRec->pNext;
        }
    }
    
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
}

_FX void DNS_LogDnsQueryResult(const WCHAR* sourceTag, const WCHAR* domain, WORD wType,
                               DNS_STATUS status, PDNSAPI_DNS_RECORD* ppQueryResults)
{
    DNS_LogDnsQueryResultWithReason(sourceTag, domain, wType, status, ppQueryResults, DNS_PASSTHROUGH_NONE);
}

_FX void DNS_LogDnsQueryExStatus(const WCHAR* prefix, const WCHAR* domain, WORD wType, DNS_STATUS status)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    // Skip if we've already logged this query recently (suppression)
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    WCHAR msg[512];
    
    if (status == DNS_REQUEST_PENDING) {
        Sbie_snwprintf(msg, 512, L"%s: %s (Type: %s) - Status: PENDING (async, will log completion)",
            prefix, domain, DNS_GetTypeName(wType));
    } else if (status != 0) {
        const WCHAR* statusMsg = DNS_GetStatusMessage(status);
        if (statusMsg) {
            Sbie_snwprintf(msg, 512, L"%s: %s (Type: %s) - %s",
                prefix, domain, DNS_GetTypeName(wType), statusMsg);
        } else {
            Sbie_snwprintf(msg, 512, L"%s: %s (Type: %s) - Error %d",
                prefix, domain, DNS_GetTypeName(wType), status);
        }
    } else {
        Sbie_snwprintf(msg, 512, L"%s: %s (Type: %s)",
            prefix, domain, DNS_GetTypeName(wType));
    }
    
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
}

_FX void DNS_LogDnsRecordsFromQueryResult(const WCHAR* prefix, const WCHAR* domain, WORD wType,
                                          DNS_STATUS status, PDNSAPI_DNS_RECORD pRecords)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    // Skip if we've already logged this query recently (suppression)
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    extern BOOLEAN DNS_MapIpv4ToIpv6;
    
    WCHAR msg[1024];
    Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s) - Status: %d",
        prefix, domain, DNS_GetTypeName(wType), status);
    
    if (status == 0 && pRecords) {
        PDNSAPI_DNS_RECORD pRec = pRecords;
        BOOLEAN is_any_query = (wType == 255);
        int record_count = 0;
        
        // For AAAA queries: check if native IPv6 exists first
        BOOLEAN has_native_ipv6 = FALSE;
        if (wType == DNS_TYPE_AAAA) {
            PDNSAPI_DNS_RECORD pCheckRec = pRecords;
            while (pCheckRec) {
                if (pCheckRec->wType == DNS_TYPE_AAAA) {
                    IP_ADDRESS check_ip;
                    memset(&check_ip, 0, sizeof(check_ip));
                    memcpy(check_ip.Data, &pCheckRec->Data.AAAA.Ip6Address, 16);
                    if (!DNS_IsIPv4Mapped(&check_ip)) {
                        has_native_ipv6 = TRUE;
                        break;
                    }
                }
                pCheckRec = pCheckRec->pNext;
            }
        }
        
        while (pRec && record_count < 10) {
            // Log only records matching the requested query type (or all types for ANY queries)
            if ((is_any_query || pRec->wType == wType) && 
                (pRec->wType == DNS_TYPE_A || pRec->wType == DNS_TYPE_AAAA)) {
                
                // Skip unexpected A records in AAAA responses unless DnsMapIpv4ToIpv6 is enabled
                if (wType == DNS_TYPE_AAAA && pRec->wType == DNS_TYPE_A && !DNS_MapIpv4ToIpv6) {
                    pRec = pRec->pNext;
                    continue;
                }
                
                IP_ADDRESS ip;
                memset(&ip, 0, sizeof(ip));
                if (pRec->wType == DNS_TYPE_AAAA) {
                    memcpy(ip.Data, &pRec->Data.AAAA.Ip6Address, 16);
                    
                    // Skip IPv4-mapped addresses when DnsMapIpv4ToIpv6 is disabled OR if native IPv6 exists
                    if (DNS_IsIPv4Mapped(&ip) && (!DNS_MapIpv4ToIpv6 || has_native_ipv6)) {
                        pRec = pRec->pNext;
                        continue;
                    }
                    
                    WSA_DumpIP(AF_INET6, &ip, msg);
                    record_count++;
                } else {
                    ip.Data32[3] = pRec->Data.A.IpAddress;
                    WSA_DumpIP(AF_INET, &ip, msg);
                    record_count++;
                }
            }
            pRec = pRec->pNext;
        }
    }
    
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
}

static const WCHAR* DNS_GetStatusMessage(DNS_STATUS status)
{
    switch (status) {
        case 0:                             return L"Success";
        case 9001:                          return L"DNS_ERROR_RCODE_FORMAT_ERROR: DNS server unable to interpret format";
        case 9002:                          return L"DNS_ERROR_RCODE_SERVER_FAILURE: DNS server failure";
        case 9003:                          return L"DNS_ERROR_RCODE_NAME_ERROR: Domain name does not exist";
        case 9004:                          return L"DNS_ERROR_RCODE_NOT_IMPLEMENTED: DNS request not supported by name server";
        case 9005:                          return L"DNS_ERROR_RCODE_REFUSED: DNS server refused query";
        case 9501:                          return L"DNS_INFO_NO_RECORDS: No records found for given DNS query";
        case 9502:                          return L"DNS_ERROR_BAD_PACKET: Bad DNS packet";
        case 9701:                          return L"DNS_ERROR_RECORD_DOES_NOT_EXIST: DNS record does not exist";
        case ERROR_TIMEOUT:                 return L"Timeout";
        case ERROR_INVALID_PARAMETER:       return L"Invalid parameter";
        default:                            return NULL;
    }
}

//---------------------------------------------------------------------------
// Raw socket logging
//---------------------------------------------------------------------------

_FX void DNS_LogRawSocketIntercepted(const WCHAR* protocol, const WCHAR* domain, WORD wType, 
                                      LIST* pEntries, const WCHAR* func_suffix)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    // Skip if we've already logged this query recently (suppression)
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    WCHAR msg[1024];
    Sbie_snwprintf(msg, 1024, L"%s DNS Intercepted: %s (Type: %s) - Using filtered response",
        protocol, domain, DNS_GetTypeName(wType));
    
    if (pEntries) {
        BOOLEAN is_any_query = (wType == 255);
        USHORT targetType = (wType == DNS_TYPE_AAAA) ? AF_INET6 : AF_INET;
        
        IP_ENTRY* entry = (IP_ENTRY*)List_Head(pEntries);
        while (entry) {
            if (is_any_query || entry->Type == targetType) {
                WSA_DumpIP(entry->Type, &entry->IP, msg);
            }
            entry = (IP_ENTRY*)List_Next(entry);
        }
    }
    
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
    
    if (DNS_DebugFlag && func_suffix) {
        WCHAR debug_msg[256];
        Sbie_snwprintf(debug_msg, 256, L"  Raw Socket Debug: Function=%s", func_suffix);
        SbieApi_MonitorPutMsg(MONITOR_DNS, debug_msg);
    }
}

_FX void DNS_LogRawSocketBlocked(const WCHAR* protocol, const WCHAR* domain, WORD wType, 
                                  const WCHAR* reason, const WCHAR* func_suffix)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    // Skip if we've already logged this query recently (suppression)
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s DNS Blocked: %s (Type: %s) - %s",
        protocol, domain, DNS_GetTypeName(wType), reason);
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
    
    if (DNS_DebugFlag && func_suffix) {
        WCHAR debug_msg[256];
        Sbie_snwprintf(debug_msg, 256, L"  Raw Socket Debug: Function=%s", func_suffix);
        SbieApi_MonitorPutMsg(MONITOR_DNS, debug_msg);
    }
}

_FX void DNS_LogRawSocketNoData(const WCHAR* protocol, const WCHAR* domain, WORD wType,
                                 const WCHAR* func_suffix)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    // Skip if we've already logged this query recently (suppression)
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s DNS Intercepted: %s (Type: %s) - No records for this type (NODATA)",
        protocol, domain, DNS_GetTypeName(wType));
    // NODATA for unsupported types uses MONITOR_DENY - we're blocking access to real data
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
    
    if (DNS_DebugFlag && func_suffix) {
        WCHAR debug_msg[256];
        Sbie_snwprintf(debug_msg, 256, L"  Raw Socket Debug: Function=%s", func_suffix);
        SbieApi_MonitorPutMsg(MONITOR_DNS, debug_msg);
    }
}

_FX void DNS_LogRawSocketDebug(const WCHAR* protocol, const WCHAR* domain, WORD wType,
                                int query_len, int response_len, const WCHAR* func_suffix, 
                                SOCKET s)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"  %s DNS Debug: %s (Type: %s) - QueryLen=%d, ResponseLen=%d, Func=%s, Socket=%p",
        protocol, domain ? domain : L"(unknown)", DNS_GetTypeName(wType),
        query_len, response_len, 
        func_suffix ? func_suffix : L"direct",
        (void*)(ULONG_PTR)s);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

//---------------------------------------------------------------------------
// WSALookupService logging
//---------------------------------------------------------------------------

_FX void WSA_FormatGuid(LPGUID lpGuid, WCHAR* buffer, SIZE_T bufferSize)
{
    if (!lpGuid || !buffer || bufferSize < 64)
        return;
    
    Sbie_snwprintf(buffer, bufferSize, L" (ClsId: %08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX)",
        lpGuid->Data1, lpGuid->Data2, lpGuid->Data3,
        lpGuid->Data4[0], lpGuid->Data4[1], lpGuid->Data4[2], lpGuid->Data4[3],
        lpGuid->Data4[4], lpGuid->Data4[5], lpGuid->Data4[6], lpGuid->Data4[7]);
}

_FX BOOLEAN WSA_IsIPv6Query(LPGUID lpServiceClassId)
{
    if (lpServiceClassId) {
        if (memcmp(lpServiceClassId, &(GUID)SVCID_DNS_TYPE_AAAA, sizeof(GUID)) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

_FX void WSA_LogIntercepted(const WCHAR* domain, LPGUID lpGuid, DWORD dwNameSpace, HANDLE handle, BOOLEAN is_blocked, LIST* pEntries, BOOLEAN is_encdns, ENCRYPTED_DNS_MODE protocol_used)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    WORD wType = WSA_IsIPv6Query(lpGuid) ? DNS_TYPE_AAAA : DNS_TYPE_A;
    
    // Skip if we've already logged this query recently (suppression)
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    WCHAR msg[1024];
    ULONG monitor_flags;
    if (is_blocked) {
        Sbie_snwprintf(msg, 1024, L"WSALookupService Blocked: %s (Type: %s) - Domain blocked (NXDOMAIN)",
            domain, DNS_GetTypeName(wType));
        monitor_flags = MONITOR_DNS | MONITOR_DENY;
    } else {
        // Use different terminology for EncDns vs filter-based responses:
        // - EncDns: "Resolved" (successful DNS resolution via encrypted DNS)
        // - Filter: "Filtered" (redirected/blocked by NetworkDnsFilter rules)
        if (is_encdns) {
            if (protocol_used != ENCRYPTED_DNS_MODE_AUTO) {
                Sbie_snwprintf(msg, 1024, L"WSALookupService EncDns(%s): %s (Type: %s)",
                    EncryptedDns_GetModeName(protocol_used), domain, DNS_GetTypeName(wType));
            } else {
                Sbie_snwprintf(msg, 1024, L"WSALookupService EncDns: %s (Type: %s)",
                    domain, DNS_GetTypeName(wType));
            }
            monitor_flags = MONITOR_DNS | MONITOR_OPEN;
        } else {
            Sbie_snwprintf(msg, 1024, L"WSALookupService Filtered: %s (Type: %s)",
                domain, DNS_GetTypeName(wType));
            monitor_flags = MONITOR_DNS | MONITOR_DENY;
        }
        
        if (pEntries) {
            IP_ENTRY* entry;
            for (entry = (IP_ENTRY*)List_Head(pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
                if ((wType == DNS_TYPE_AAAA && entry->Type == AF_INET6) ||
                    (wType == DNS_TYPE_A && entry->Type == AF_INET)) {
                    WCHAR ipStr[64];
                    if (entry->Type == AF_INET) {
                        DNS_FormatIPv4(ipStr, ARRAYSIZE(ipStr), &entry->IP.Data[12]);
                        wcscat_s(msg, 1024, L"; IPv4: ");
                    } else {
                        Sbie_snwprintf(ipStr, 64, L"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                            entry->IP.Data[0], entry->IP.Data[1], entry->IP.Data[2], entry->IP.Data[3],
                            entry->IP.Data[4], entry->IP.Data[5], entry->IP.Data[6], entry->IP.Data[7],
                            entry->IP.Data[8], entry->IP.Data[9], entry->IP.Data[10], entry->IP.Data[11],
                            entry->IP.Data[12], entry->IP.Data[13], entry->IP.Data[14], entry->IP.Data[15]);
                        wcscat_s(msg, 1024, L"; IPv6: ");
                    }
                    wcscat_s(msg, 1024, ipStr);
                }
            }
        }
    }
    SbieApi_MonitorPutMsg(monitor_flags, msg);
    
    if (DNS_DebugFlag) {
        WCHAR ClsId[64] = { 0 };
        if (lpGuid)
            WSA_FormatGuid(lpGuid, ClsId, ARRAYSIZE(ClsId));
        
        WCHAR debug_msg[512];
        Sbie_snwprintf(debug_msg, 512, L"  WSA Debug: NS=%d, ClsId=%s, Handle=%p, Blocked=%d",
            dwNameSpace, ClsId[0] ? ClsId : L"(none)", handle, is_blocked);
        SbieApi_MonitorPutMsg(MONITOR_DNS, debug_msg);
    }
}

_FX void WSA_LogPassthrough(const WCHAR* domain, LPGUID lpGuid, DWORD dwNameSpace, HANDLE handle, int errCode, WORD actualQueryType)
{
    if (!DNS_TraceFlag)
        return;
    
    WORD wType = actualQueryType;
    
    if (errCode != 0 || DNS_DebugFlag) {
        WCHAR msg[512];
        if (errCode != 0) {
            Sbie_snwprintf(msg, 512, L"WSALookupService Passthrough(SysDns): %s (NS: %d, Type: %s) - Error %d",
                domain ? domain : L"(unknown)", dwNameSpace, DNS_GetTypeName(wType), errCode);
            SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
        }
        
        if (DNS_DebugFlag) {
            WCHAR ClsId[64] = { 0 };
            if (lpGuid)
                WSA_FormatGuid(lpGuid, ClsId, ARRAYSIZE(ClsId));
            
            WCHAR debug_msg[512];
            Sbie_snwprintf(debug_msg, 512, L"  WSA Debug: NS=%d, ClsId=%s, Handle=%p, Error=%d",
                dwNameSpace, ClsId[0] ? ClsId : L"(none)", handle, errCode);
            SbieApi_MonitorPutMsg(MONITOR_DNS, debug_msg);
        }
    }
}

_FX void WSA_LogTypeFilterPassthrough(const WCHAR* domain, USHORT query_type, const WCHAR* reason)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"WSALookupService Passthrough(SysDns): %s (Type: %s) - %s",
        domain, DNS_GetTypeName(query_type), reason ? reason : L"forwarding to real DNS");
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
}

//---------------------------------------------------------------------------
// GetAddrInfo-specific logging (WinHTTP, curl, etc.)
//---------------------------------------------------------------------------

_FX const WCHAR* GAI_GetFamilyName(int family)
{
    switch (family) {
        case AF_INET:   return L"IPv4";
        case AF_INET6:  return L"IPv6";
        case AF_UNSPEC: return L"Any";
        default:        return L"Unknown";
    }
}

_FX void GAI_LogIntercepted(const WCHAR* funcName, const WCHAR* domain, int family, LIST* pEntries, BOOLEAN is_encdns)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    WORD wType = (family == AF_INET6) ? DNS_TYPE_AAAA : DNS_TYPE_A;
    
    // Skip if we've already logged this query recently (suppression)
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    WCHAR msg[1024];
    // Use different terminology for EncDns vs filter-based responses:
    // - EncDns: "Resolved" (successful DNS resolution via encrypted DNS)
    // - Filter: "Filtered" (redirected/blocked by NetworkDnsFilter rules)
    const WCHAR* action = is_encdns ? L"Resolved" : L"Filtered";
    Sbie_snwprintf(msg, 1024, L"%s %s: %s (%s)",
        funcName ? funcName : L"GetAddrInfo", action, domain, GAI_GetFamilyName(family));
    
    // Append IP addresses if available
    if (pEntries) {
        IP_ENTRY* entry;
        for (entry = (IP_ENTRY*)List_Head(pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
            BOOLEAN match = FALSE;
            if (family == AF_UNSPEC)
                match = TRUE;
            else if (family == AF_INET6 && entry->Type == AF_INET6)
                match = TRUE;
            else if (family == AF_INET && entry->Type == AF_INET)
                match = TRUE;
            
            if (match) {
                WCHAR ipStr[64];
                if (entry->Type == AF_INET) {
                    DNS_FormatIPv4(ipStr, ARRAYSIZE(ipStr), &entry->IP.Data[12]);
                    wcscat_s(msg, 1024, L"; IPv4: ");
                } else {
                    Sbie_snwprintf(ipStr, 64, L"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                        entry->IP.Data[0], entry->IP.Data[1], entry->IP.Data[2], entry->IP.Data[3],
                        entry->IP.Data[4], entry->IP.Data[5], entry->IP.Data[6], entry->IP.Data[7],
                        entry->IP.Data[8], entry->IP.Data[9], entry->IP.Data[10], entry->IP.Data[11],
                        entry->IP.Data[12], entry->IP.Data[13], entry->IP.Data[14], entry->IP.Data[15]);
                    wcscat_s(msg, 1024, L"; IPv6: ");
                }
                wcscat_s(msg, 1024, ipStr);
            }
        }
    }
    
    // EncDns-based resolution: MONITOR_OPEN (successful DNS query)
    // Filter-based interception: MONITOR_DENY (redirected/blocked query)
    ULONG monitorFlag = is_encdns ? MONITOR_OPEN : MONITOR_DENY;
    SbieApi_MonitorPutMsg(MONITOR_DNS | monitorFlag, msg);
}

_FX void GAI_LogBlocked(const WCHAR* funcName, const WCHAR* domain, int family)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    WORD wType = (family == AF_INET6) ? DNS_TYPE_AAAA : DNS_TYPE_A;
    
    // Skip if we've already logged this query recently (suppression)
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s Blocked: %s (%s) - Domain blocked (NXDOMAIN)",
        funcName ? funcName : L"GetAddrInfo", domain, GAI_GetFamilyName(family));
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
}

_FX void GAI_LogPassthrough(const WCHAR* funcName, const WCHAR* domain, int family, const WCHAR* reason)
{
    if (!DNS_TraceFlag)
        return;
    
    // For passthrough, only log if there's a specific reason or debug is enabled
    if (!reason && !DNS_DebugFlag)
        return;
    
    // Apply log suppression for passthrough logs (avoid duplicates from multiple APIs)
    WORD wType = (family == AF_INET6) ? DNS_TYPE_AAAA : 
                 (family == AF_INET) ? DNS_TYPE_A : DNS_TYPE_ANY;
    if (domain && DNS_ShouldSuppressLog(domain, wType))
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s Passthrough: %s (%s)%s%s",
        funcName ? funcName : L"GetAddrInfo", 
        domain ? domain : L"(null)", 
        GAI_GetFamilyName(family),
        reason ? L" - " : L"",
        reason ? reason : L"");
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
}

_FX void GAI_LogPassthroughWithEntries(const WCHAR* funcName, const WCHAR* domain, int family, LIST* pEntries, const WCHAR* reason)
{
    if (!DNS_TraceFlag)
        return;

    // For passthrough, only log if there's a specific reason or debug is enabled
    if (!reason && !DNS_DebugFlag)
        return;

    // Apply log suppression for passthrough logs (avoid duplicates from multiple APIs)
    WORD wType = (family == AF_INET6) ? DNS_TYPE_AAAA :
                 (family == AF_INET) ? DNS_TYPE_A : DNS_TYPE_ANY;
    if (domain && DNS_ShouldSuppressLog(domain, wType))
        return;

    WCHAR msg[1024];
    Sbie_snwprintf(msg, 1024, L"%s Passthrough: %s (%s)%s%s",
        funcName ? funcName : L"GetAddrInfo",
        domain ? domain : L"(null)",
        GAI_GetFamilyName(family),
        reason ? L" - " : L"",
        reason ? reason : L"");

    // Append IP addresses if available
    if (pEntries) {
        for (IP_ENTRY* entry = (IP_ENTRY*)List_Head(pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
            BOOLEAN match = FALSE;
            if (family == AF_UNSPEC)
                match = TRUE;
            else if (family == AF_INET6 && entry->Type == AF_INET6)
                match = TRUE;
            else if (family == AF_INET && entry->Type == AF_INET)
                match = TRUE;

            if (match) {
                WCHAR ipStr[64];
                if (entry->Type == AF_INET) {
                    DNS_FormatIPv4(ipStr, ARRAYSIZE(ipStr), &entry->IP.Data[12]);
                    wcscat_s(msg, ARRAYSIZE(msg), L"; IPv4: ");
                } else {
                    Sbie_snwprintf(ipStr, ARRAYSIZE(ipStr), L"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                        entry->IP.Data[0], entry->IP.Data[1], entry->IP.Data[2], entry->IP.Data[3],
                        entry->IP.Data[4], entry->IP.Data[5], entry->IP.Data[6], entry->IP.Data[7],
                        entry->IP.Data[8], entry->IP.Data[9], entry->IP.Data[10], entry->IP.Data[11],
                        entry->IP.Data[12], entry->IP.Data[13], entry->IP.Data[14], entry->IP.Data[15]);
                    wcscat_s(msg, ARRAYSIZE(msg), L"; IPv6: ");
                }
                wcscat_s(msg, ARRAYSIZE(msg), ipStr);
            }
        }
    }

    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
}

_FX void GAI_LogNoData(const WCHAR* funcName, const WCHAR* domain, int family)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    WORD wType = (family == AF_INET6) ? DNS_TYPE_AAAA : DNS_TYPE_A;
    
    // Skip if we've already logged this query recently (suppression)
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s Intercepted: %s (%s) - NODATA (no matching records)",
        funcName ? funcName : L"GetAddrInfo", domain, GAI_GetFamilyName(family));
    // NODATA uses MONITOR_DENY - we're blocking access to real data
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
}

_FX void GAI_LogDebugEntry(const WCHAR* funcName, const WCHAR* domain, const WCHAR* service, int family)
{
    if (!DNS_DebugFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"  %s Entry: domain=%s, service=%s, family=%s",
        funcName ? funcName : L"GetAddrInfo",
        domain ? domain : L"(null)",
        service ? service : L"(null)",
        GAI_GetFamilyName(family));
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void GAI_LogDebugEntryEx(const WCHAR* funcName, const WCHAR* domain, const WCHAR* service, int family, const void* pHints)
{
    if (!DNS_DebugFlag)
        return;
    if (!domain)
        return;
    
    WCHAR msg[512];
    // ADDRINFOW and ADDRINFOEXW share the same first 4 int-sized fields:
    //   ai_flags, ai_family, ai_socktype, ai_protocol
    typedef struct { int ai_flags; int ai_family; int ai_socktype; int ai_protocol; } HINTS_COMMON;
    const HINTS_COMMON* h = (const HINTS_COMMON*)pHints;
    
    if (h) {
        Sbie_snwprintf(msg, 512,
            L"  %s Entry: domain=%s, service=%s, family=%s, hints.ai_flags=0x%08X, hints.ai_socktype=%d, hints.ai_protocol=%d",
            funcName ? funcName : L"GetAddrInfo",
            domain, service ? service : L"(null)",
            GAI_GetFamilyName(family),
            h->ai_flags, h->ai_socktype, h->ai_protocol);
    } else {
        Sbie_snwprintf(msg, 512, L"  %s Entry: domain=%s, service=%s, family=Any, hints=(NULL)",
            funcName ? funcName : L"GetAddrInfo",
            domain, service ? service : L"(null)");
    }
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

//---------------------------------------------------------------------------
// Debug logging helpers
//---------------------------------------------------------------------------

_FX void DNS_LogDebug(const WCHAR* message)
{
    if (!DNS_DebugFlag || !message)
        return;
    SbieApi_MonitorPutMsg(MONITOR_DNS, message);
}

_FX void DNS_FormatIPv4(WCHAR* buffer, size_t bufSize, const BYTE* ipData)
{
    Sbie_snwprintf(buffer, bufSize, L"%d.%d.%d.%d",
        ipData[0], ipData[1], ipData[2], ipData[3]);
}

_FX void DNS_LogIPEntry(const IP_ENTRY* entry)
{
    if (!DNS_DebugFlag || !entry)
        return;
    
    WCHAR msg[128];
    if (entry->Type == AF_INET) {
        WCHAR ipStr[64];
        DNS_FormatIPv4(ipStr, 64, &entry->IP.Data[12]);
        Sbie_snwprintf(msg, 128, L"  Entry: Type=IPv4, IP=%s", ipStr);
    } else {
        Sbie_snwprintf(msg, 128, L"  Entry: Type=IPv6");
    }
    DNS_LogDebug(msg);
}

_FX void DNS_LogWSAFillStart(BOOLEAN isIPv6, SIZE_T ipCount, void* listHead)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"WSA_FillResponseStructure: isIPv6=%d, ipCount=%Iu, listHead=%p",
        isIPv6, ipCount, listHead);
    DNS_LogDebug(msg);
}

_FX void DNS_LogWSALookupCall(HANDLE hLookup, DWORD bufSize, BOOLEAN noMore, void* pEntries)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"WSALookupServiceNextW called: Hdl=%p, BufferSize=%d, NoMore=%d, pEntries=%p",
        hLookup, bufSize, noMore, pEntries);
    DNS_LogDebug(msg);
}

_FX void DNS_LogWSAFillFailure(HANDLE hLookup, DWORD error, DWORD bufSize)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"WSA_FillResponseStructure FAILED: Hdl=%p, Error=%d (0x%X), BufferSize=%d",
        hLookup, error, error, bufSize);
    DNS_LogDebug(msg);
}

_FX void DNS_LogQueryExPointers(const WCHAR* funcName, void* pQueryRequest, void* pQueryResults, DWORD version, void* queryName)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s: pQueryRequest=%p, pQueryResults=%p, Version=%d, QueryName=%p",
        funcName, pQueryRequest, pQueryResults, version, queryName);
    DNS_LogDebug(msg);
}

_FX void DNS_LogExclusionInit(const WCHAR* image_name, const WCHAR* value)
{
    if (!value || !DNS_TraceFlag || !DNS_DebugFlag)
        return;

    WCHAR msg[512];
    if (image_name && *image_name)
        Sbie_snwprintf(msg, 512, L"DNS Exclusion Init: Image='%s', Patterns='%s'", image_name, value);
    else
        Sbie_snwprintf(msg, 512, L"DNS Exclusion Init: Global, Patterns='%s'", value);

    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogExclusionInitDefault(const WCHAR* label, const WCHAR* value)
{
    if (!value || !DNS_TraceFlag || !DNS_DebugFlag)
        return;

    if (!label || !*label)
        return;

    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"DNS Exclusion Init: %s, Patterns='%s'", label, value);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

//---------------------------------------------------------------------------
// DnsQueryEx Debug Logging
//---------------------------------------------------------------------------

_FX void DNS_LogQueryExInvalidVersion(DWORD version)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"  DnsQueryEx: Invalid Version=%d (expected 1-3), passing through", version);
    DNS_LogDebug(msg);
}

_FX void DNS_LogQueryExVersion3(BOOLEAN isNetworkQueryRequired, DWORD networkIndex, DWORD cServers, void* pServers)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"  DnsQueryEx: VERSION3 detected - IsNetworkQueryRequired=%d, RequiredNetworkIndex=%u, cCustomServers=%u, pCustomServers=%p",
        isNetworkQueryRequired, networkIndex, cServers, pServers);
    DNS_LogDebug(msg);
}

_FX void DNS_LogQueryExEntry(const WCHAR* queryName, WORD queryType, DWORD version, ULONG64 options, DWORD interfaceIndex, BOOLEAN hasCallback)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"  DnsQueryEx Entry: QueryName=%s, Type=%s, Version=%d, Options=0x%llX, InterfaceIndex=%u, HasCallback=%d",
        queryName, DNS_GetTypeName(queryType), version, options, interfaceIndex, hasCallback);
    DNS_LogDebug(msg);
}

_FX void DNS_LogQueryExCorruptOptions(ULONG64 corruptOptions)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"  DnsQueryEx: CORRUPT QueryOptions detected: 0x%I64X (looks like user-mode pointer, treating as 0)", corruptOptions);
    DNS_LogDebug(msg);
}

_FX void DNS_LogQueryExStrippedFlags(const WCHAR* context, ULONG64 before, ULONG64 after)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"  DnsQueryEx: %s - stripped flags (0x%I64X -> 0x%I64X)", context, before, after);
    DNS_LogDebug(msg);
}

_FX void DNS_LogQueryExProactiveSanitize(ULONG64 original, ULONG64 sanitized)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"  DnsQueryEx: Proactive sanitization - QueryOptions reduced before call (0x%I64X -> 0x%I64X)", original, sanitized);
    DNS_LogDebug(msg);
}

_FX void DNS_LogQueryExErrorRetryReduction(const WCHAR* reason, ULONG64 before, ULONG64 after)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"  DnsQueryEx: %s, retrying with reduced QueryOptions (0x%I64X -> 0x%I64X)", reason, before, after);
    DNS_LogDebug(msg);
}

_FX void DNS_LogQueryExRetryInterface(DWORD originalIndex)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"  DnsQueryEx: ERROR_INVALID_PARAMETER with InterfaceIndex=%u, retrying with 0", originalIndex);
    DNS_LogDebug(msg);
}

_FX void DNS_LogQueryExDebugStatus(DNS_STATUS status, void* asyncCtx, void* pQueryResults, void* pQueryRecords, DWORD version)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"  DnsQueryEx Debug: status=%d, asyncCtx=%p, pQueryResults=%p, pQueryRecords=%p, Version=%d",
        status, asyncCtx, pQueryResults, pQueryRecords, version);
    DNS_LogDebug(msg);
}

//---------------------------------------------------------------------------
// WSALookupService Debug Logging
//---------------------------------------------------------------------------

_FX void DNS_LogWSADebugResponse(const WCHAR* domain, DWORD nameSpace, BOOLEAN isIPv6, HANDLE handle,
                                 DWORD addrCount, DWORD blobSize, void* csaBuffer, DWORD csaBufferCount)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    
    WCHAR msg[2048];
    Sbie_snwprintf(msg, ARRAYSIZE(msg), L"  WSA Debug Response: %s (NS: %d, Type: %s, Hdl: %p, AddrCount: %d, BlobSize: %d)",
        domain, nameSpace, isIPv6 ? L"IPv6" : L"IPv4", handle, addrCount, blobSize);
    
    // Log IP addresses if available
    if (csaBuffer && csaBufferCount > 0) {
        PCSADDR_INFO csaInfo = (PCSADDR_INFO)csaBuffer;
        for (DWORD i = 0; i < csaBufferCount; i++) {
            IP_ADDRESS ip;
            if (csaInfo[i].RemoteAddr.lpSockaddr &&
                WSA_GetIP(csaInfo[i].RemoteAddr.lpSockaddr,
                    csaInfo[i].RemoteAddr.iSockaddrLength, &ip))
                WSA_DumpIP(csaInfo[i].RemoteAddr.lpSockaddr->sa_family, &ip, msg);
        }
    }
    
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogWSADebugRequestEnd(HANDLE handle, BOOLEAN filtered)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    WCHAR msg[256];
    Sbie_snwprintf(msg, 256, L"  WSA Debug: %s Request End (Hdl: %p)", filtered ? L"" : L"Unfiltered", handle);
    DNS_LogDebug(msg);
}

//---------------------------------------------------------------------------
// WSALookupService Passthrough Result Logging
//---------------------------------------------------------------------------

_FX void DNS_LogWSAPassthroughResult(const WCHAR* domain, DWORD nameSpace, WORD queryType,
                                     void* lpqsResults)
{
    if (!DNS_TraceFlag)
        return;
    
    // Skip if we've already logged this query recently (suppression)
    if (domain && DNS_ShouldSuppressLog(domain, queryType))
        return;
    
    extern BOOLEAN DNS_MapIpv4ToIpv6;
    
    WCHAR msg[1024];
    // This logger is used for WSALookupServiceNextW results coming from the
    // real system provider (unfiltered path). It must not infer EncDns from
    // global configuration, otherwise excluded ":sys" domains get mislabeled.
    Sbie_snwprintf(msg, 1024, L"WSALookupService Passthrough(SysDns): %s (NS: %d, Type: %s)",
        domain, nameSpace, DNS_GetTypeName(queryType));
    
    // Log IP addresses from CSADDR_INFO array if available
    if (lpqsResults) {
        LPWSAQUERYSETW pResults = (LPWSAQUERYSETW)lpqsResults;
        if (pResults->lpcsaBuffer && pResults->dwNumberOfCsAddrs > 0) {
            for (DWORD i = 0; i < pResults->dwNumberOfCsAddrs && i < 10; i++) {
                PCSADDR_INFO csaInfo = &pResults->lpcsaBuffer[i];
                if (csaInfo->RemoteAddr.lpSockaddr) {
                    IP_ADDRESS ip;
                    if (WSA_GetIP(csaInfo->RemoteAddr.lpSockaddr,
                        csaInfo->RemoteAddr.iSockaddrLength, &ip)) {
                        
                        // Skip IPv4 addresses (AF_INET) in AAAA query results unless mapping is enabled
                        if (queryType == DNS_TYPE_AAAA && 
                            csaInfo->RemoteAddr.lpSockaddr->sa_family == AF_INET && 
                            !DNS_MapIpv4ToIpv6) {
                            continue;
                        }
                        
                        // Skip IPv4-mapped IPv6 in AAAA query results unless mapping is enabled
                        if (queryType == DNS_TYPE_AAAA && 
                            csaInfo->RemoteAddr.lpSockaddr->sa_family == AF_INET6) {
                            if (DNS_IsIPv4Mapped(&ip) && !DNS_MapIpv4ToIpv6) {
                                continue;
                            }
                        }
                        
                        WSA_DumpIP(csaInfo->RemoteAddr.lpSockaddr->sa_family, &ip, msg);
                    }
                }
            }
        }
    }
    
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
}

_FX void DNS_LogWSAPassthroughCSADDR(int index, ADDRESS_FAMILY got_af, ADDRESS_FAMILY expect_af, BOOLEAN match)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    
    WCHAR msg[256];
    Sbie_snwprintf(msg, 256, L"  CSADDR[%d]: got_af=%d expect_af=%d match=%d",
        index, got_af, expect_af, match);
    DNS_LogDebug(msg);
}

_FX void DNS_LogWSAPassthroughHOSTENT(ADDRESS_FAMILY h_addrtype, ADDRESS_FAMILY expect_af, BOOLEAN match)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    
    WCHAR msg[256];
    Sbie_snwprintf(msg, 256, L"  HOSTENT: h_addrtype=%d expect_af=%d match=%d",
        h_addrtype, expect_af, match);
    DNS_LogDebug(msg);
}

_FX void DNS_LogWSAPassthroughInvalidHostent(ADDRESS_FAMILY h_addrtype)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    
    WCHAR msg[256];
    Sbie_snwprintf(msg, 256, L"  HOSTENT: Skipping invalid h_addrtype=%d (not AF_INET or AF_INET6)",
        h_addrtype);
    DNS_LogDebug(msg);
}

//---------------------------------------------------------------------------
// Configuration/initialization logging functions
//---------------------------------------------------------------------------

_FX void DNS_LogConfigNoMatchingFilter(const WCHAR* domain)
{
    if (!DNS_TraceFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"NetworkDnsFilterType: No matching NetworkDnsFilter for domain='%s', ignoring", domain);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogConfigWildcardFound(const WCHAR* domain)
{
    if (!DNS_TraceFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"NetworkDnsFilterType: Wildcard '*' found for domain '%s' - will filter ALL types", domain);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogConfigNegatedWildcard(const WCHAR* domain)
{
    if (!DNS_TraceFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"NetworkDnsFilterType: Negated wildcard '!*' found for domain '%s' - will passthrough ALL types", domain);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogConfigNegatedType(const WCHAR* type, const WCHAR* domain)
{
    if (!DNS_TraceFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"NetworkDnsFilterType: Negated type '%s' for domain '%s' - will passthrough", type, domain);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogConfigInvalidType(const WCHAR* type, const WCHAR* domain)
{
    if (!DNS_TraceFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"NetworkDnsFilterType: Invalid type name '%s' for domain '%s'", type, domain);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogConfigTypeFilterApplied(const WCHAR* domain, const WCHAR* types_str, USHORT type_count, ULONG applied_count, BOOLEAN has_wildcard)
{
    if (!DNS_TraceFlag)
        return;
    
    WCHAR msg[512];
    if (has_wildcard) {
        Sbie_snwprintf(msg, 512, L"NetworkDnsFilterType: Domain='%s' types=[* (wildcard - all types)] applied to %d patterns",
            domain, applied_count);
    } else {
        Sbie_snwprintf(msg, 512, L"NetworkDnsFilterType: Domain='%s' types=[%s] (%d types) applied to %d patterns",
            domain, types_str, type_count, applied_count);
    }
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogConfigDnsTraceEnabled(void)
{
    WCHAR msg[256];
    Sbie_snwprintf(msg, 256, L"DNS Trace: DNS filtering activity logging enabled");
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogConfigFilterError(const WCHAR* domain)
{
    if (!DNS_TraceFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"DNS Filter: Error loading filter for domain '%s'", domain);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

//---------------------------------------------------------------------------
// Internal debug logging functions
//---------------------------------------------------------------------------

_FX void DNS_LogDebugCleanupStaleHandle(ULONGLONG age)
{
    if (!DNS_TraceFlag || !DNS_DebugFlag)
        return;
    
    WCHAR msg[256];
    Sbie_snwprintf(msg, 256, L"  WSA Debug: Cleaned up stale handle (Age: %llu ms)", age);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogDebugExclusionCheck(const WCHAR* domain, const WCHAR* image, ULONG count)
{
    if (!DNS_DebugFlag || !DNS_TraceFlag)
        return;
    
    // Suppress duplicate DNS_IsExcluded debug logs using DNS_EXCL_LOG_TAG
    if (DNS_ShouldSuppressLogTagged(domain, DNS_EXCL_LOG_TAG))
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"DNS_IsExcluded: Checking domain='%s', image='%s', ExclusionListCount=%d",
        domain, image ? image : L"(null)", count);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogDebugExclusionPerImageList(const WCHAR* image, ULONG pattern_count)
{
    if (!DNS_DebugFlag || !DNS_TraceFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"  DNS_IsExcluded: Checking per-image list for '%s' (%d patterns)",
        image, pattern_count);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogDebugExclusionGlobalList(ULONG pattern_count)
{
    if (!DNS_DebugFlag || !DNS_TraceFlag)
        return;
    
    // Suppress duplicate global list checking logs
    // Use a special marker string for suppression since this isn't domain-specific
    static WCHAR marker[] = L"__GLOBAL_LIST_CHECK__";
    if (DNS_ShouldSuppressLogTagged(marker, DNS_EXCL_LOG_TAG))
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"  DNS_IsExcluded: Checking global list (%d patterns)", pattern_count);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogDebugExclusionMatch(const WCHAR* domain, const WCHAR* pattern)
{
    if (!DNS_DebugFlag || !DNS_TraceFlag)
        return;
    
    // Suppress duplicate match logs for same domain
    if (DNS_ShouldSuppressLogTagged(domain, DNS_EXCL_LOG_TAG))
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"    DNS_IsExcluded: MATCH! Domain='%s' matched pattern='%s'",
        domain, pattern);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogRawSocketEncDnsRawResponse(const WCHAR* protocol, const WCHAR* domain, WORD wType,
                                          ENCRYPTED_DNS_MODE protocol_used, int response_len)
{
    if (!DNS_TraceFlag || !domain)
        return;

    // Skip if we've already logged this query recently (suppression)
    if (DNS_ShouldSuppressLog(domain, wType))
        return;

    WCHAR msg[512];
    if (protocol_used != ENCRYPTED_DNS_MODE_AUTO) {
        Sbie_snwprintf(msg, 512, L"%s DNS EncDns(%s): Raw response for %s (Type: %s, len: %d)",
            protocol ? protocol : L"Raw",
            EncryptedDns_GetModeName(protocol_used),
            domain,
            DNS_GetTypeName(wType),
            response_len);
    } else {
        Sbie_snwprintf(msg, 512, L"%s DNS EncDns: Raw response for %s (Type: %s, len: %d)",
            protocol ? protocol : L"Raw",
            domain,
            DNS_GetTypeName(wType),
            response_len);
    }

    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
}

_FX void DNS_LogDebugExclusionFromQueryEx(const WCHAR* sourceTag, const WCHAR* domain)
{
    if (!DNS_TraceFlag)
        return;

    if (domain && DNS_ShouldSuppressLogTagged(domain, DNS_EXCL_LOG_TAG))
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s Exclusion: Domain '%s' matched exclusion list, skipping filter", sourceTag, domain);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogDebugDnsApiRecordFree(PVOID pRecordList, INT FreeType, BOOLEAN isSbie)
{
    if (!DNS_TraceFlag)
        return;
    
    WCHAR msg[256];
    const WCHAR* freeTypeName = (FreeType == 0) ? L"DnsFreeFlat" : 
                                 (FreeType == 1) ? L"DnsFreeRecordList" : 
                                 (FreeType == 2) ? L"DnsFreeParsedMessageFields" : 
                                 L"Unknown";
    
    if (isSbie) {
        Sbie_snwprintf(msg, 256, L"DnsApi RecordListFree: Freeing SBIE record (List: %p, Type: %s)", pRecordList, freeTypeName);
    } else {
        Sbie_snwprintf(msg, 256, L"DnsApi RecordListFree: Calling real API (List: %p, Type: %s)", pRecordList, freeTypeName);
    }
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogDebugDnsApiRawResultFree(PVOID pQueryResults)
{
    if (!DNS_TraceFlag)
        return;
    
    WCHAR msg[256];
    Sbie_snwprintf(msg, 256, L"DnsApi QueryRawResultFree: Freeing result (ptr: %p)", pQueryResults);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}
