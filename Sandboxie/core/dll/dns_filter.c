/*
 * Copyright 2022 David Xanatos, xanasoft.com
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
// DNS Filter
//
// This module provides DNS query filtering for sandboxed applications through
// three separate interception layers:
//
// 1. WSALookupService API (ws2_32.dll) - Legacy WinSock DNS resolution
//    - Functions: WSALookupServiceBeginW, WSALookupServiceNextW, WSALookupServiceEnd
//    - Returns: WSAQUERYSETW with HOSTENT BLOB (relative pointers)
//    - Used by: Older applications, some games
//
// 2. DnsApi (dnsapi.dll) - Modern Windows DNS API
//    - Functions: DnsQuery_A, DnsQuery_W, DnsQueryEx, DnsQueryRaw
//    - Returns: DNS_RECORD linked list (absolute pointers)
//    - Used by: Modern browsers, system utilities, most contemporary apps
//
// 3. Raw Socket Interception (ws2_32.dll) - Direct UDP packet filtering
//    - Functions: sendto, WSASendTo (port 53 traffic)
//    - Parses: DNS wire format packets (RFC 1035)
//    - Used by: nslookup, dig, custom DNS clients bypassing high-level APIs
//    - Control: FilterRawDns (boolean) enables/disables raw socket hooking
//
// Configuration Settings:
//    NetworkDnsFilter=<domain>:<ip_addresses>
//      - Primary filter rule specification
//      - Format: [process,]domain[:ip1;ip2;...] or [process,]domain (block mode)
//      - Examples: 
//        * NetworkDnsFilter=*.example.com:0.0.0.0  (redirect to loopback)
//        * NetworkDnsFilter=example.org        (block all types)
//        * NetworkDnsFilter=chrome.exe,example.com:127.0.0.1
//
//    NetworkDnsFilterType=<domain>:<types>
//      - Type-based filtering specification
//      - Format: [process,]domain:type1;type2;... or [process,]domain:*
//      - Supported types: A, AAAA, MX, TXT, CNAME, etc. (named or numeric TYPE28)
//      - Supports negation prefix '!' for passthrough (e.g., !MX, !*, !A)
//
//      Filter Mode (domain:ip) Behavior:
//        - NO type filter set: A/AAAA/ANY intercepted, all other types BLOCKED
//        - Types in list: Intercepted if supported (A/AAAA), blocked if unsupported (MX/TXT/etc)
//        - Types NOT in list: PASSTHROUGH (only when type filter is explicitly set)
//        - Negated types (!type): Passthrough to real DNS (explicit passthrough)
//        - Wildcard (*): Filter ALL types (intercept supported, block unsupported)
//        - Negated wildcard (!*): Passthrough ALL types (explicit passthrough for all)
//
//      Block Mode (domain without IPs) Behavior:
//        - ALL types are blocked (returns NXDOMAIN per RFC 2308 - domain doesn't exist)
//        - NetworkDnsFilterType has no effect in block mode
//
//      Filter Mode (domain with IPs) DNS Response Behavior (RFC 2308):
//        - Supported types (A/AAAA) with matching IPs: NOERROR with answers
//        - Supported types with no matching IPs: NOERROR + NODATA (0 answers)
//        - Unsupported types (MX/TXT/CNAME/etc.): NOERROR + NODATA (domain exists, no records of this type)
//        - Passthrough types: Forward to real DNS (depends on NetworkDnsFilterType setting)
//
//      Examples:
//        * NetworkDnsFilter=example.com:1.0.0.1
//          (no NetworkDnsFilterType set)
//          → A/AAAA/ANY: Intercept (return 1.0.0.1)
//          → HTTPS/MX/TXT/CNAME: NOERROR + NODATA (unsupported types, domain exists)
//
//        * NetworkDnsFilter=example.com:1.0.0.1
//          NetworkDnsFilterType=example.com:A;AAAA;MX
//          → A/AAAA: Intercept (return 1.0.0.1)
//          → MX: NOERROR + NODATA (unsupported type, domain exists)
//          → CNAME/TXT/HTTPS: Passthrough (not in list)
//
//        * NetworkDnsFilter=example.com:1.0.0.1
//          NetworkDnsFilterType=example.com:A;AAAA;!MX
//          → A/AAAA: Intercept (return 1.0.0.1)
//          → MX: Passthrough (explicitly negated)
//          → CNAME/TXT/HTTPS: Passthrough (not in list)
//
//        * NetworkDnsFilter=example.com:1.0.0.1
//          NetworkDnsFilterType=example.com:*;!CNAME;!MX
//          → A/AAAA: Intercept (in wildcard, supported)
//          → MX/CNAME: Passthrough (explicitly negated)
//          → TXT/SRV/HTTPS: NOERROR + NODATA (in wildcard, unsupported, domain exists)
//
//        * NetworkDnsFilter=example.com:1.0.0.1
//          NetworkDnsFilterType=example.com:!*
//          → ALL types: Passthrough (complete filtering bypass)
//
//      IMPORTANT: Only A and AAAA (or ANY) records can be synthesized from IP addresses.
//                 - NO type filter: A/AAAA/ANY intercepted, all others return NOERROR + NODATA.
//                 - WITH type filter: Only listed types filtered; unlisted types PASSTHROUGH.
//                 - Unsupported types in filter list (without negation) return NOERROR + NODATA.
//
//    NetworkDnsFilterExclude=<patterns>
//      - Exclusion/whitelist patterns (higher priority than NetworkDnsFilter)
//      - Format: [process,]pattern1;pattern2;... (semicolon-separated)
//      - Supports wildcards: *.example.com, safe.*.example.com
//      - Examples:
//        * NetworkDnsFilterExclude=*.microsoft.com;*.windows.net
//        * NetworkDnsFilterExclude=chrome.exe,*.google.com
//
//    FilterRawDns=[process,]y|n
//      - Boolean: Enable/disable raw socket DNS interception (default: n)
//      - Per-process support: FilterRawDns=nslookup.exe,y
//      - NOTE: Only controls hook enablement; actual domain filtering uses
//              NetworkDnsFilter patterns
//
//    FilterDnsApi=[process,]y|n
//      - Boolean: Enable/disable DnsApi hooking (default: y)
//      - Per-process support: FilterDnsApi=chrome.exe,n
//      - When disabled: No DnsQuery_W/A/UTF8/Ex/Raw hooks installed
//      - Use case: Disable for specific apps that require native DNS behavior
//
//    DnsMapIpv4ToIpv6=[process,]y|n
//      - Boolean: Enable/disable IPv4-mapped IPv6 for AAAA queries (default: n)
//      - Per-process support: DnsMapIpv4ToIpv6=firefox.exe,y
//      - When disabled: AAAA queries return NOERROR + NODATA if no native IPv6 available
//      - When enabled: AAAA queries return IPv4-mapped IPv6 (::ffff:a.b.c.d) for IPv4-only entries
//      - Use case: Enable for apps that expect IPv6 responses for all AAAA queries
//
//    DnsTrace=y|n
//      - Enable DNS filtering activity logging to resource monitor
//
//    DnsDebug=[process,]y|n
//      - Boolean: Enable/disable verbose debug logging for troubleshooting (default: n)
//      - Per-process support: DnsDebug=test.exe,y
//      - Use case: Enable detailed logging for specific applications during debugging
//
//    SuppressDnsLog=[process,]y|n
//      - Boolean: Enable/disable duplicate log suppression (default: y)
//      - Per-process support: SuppressDnsLog=firefox.exe,n
//      - When enabled: Suppresses duplicate logs when same query resolved through multiple APIs
//      - Cache TTL: 5 seconds - queries re-logged if repeated after expiry
//      - Applies to: Passthrough, Intercepted, and Blocked logs
//      - Debug logging (DnsDebug=y) shows when suppression occurs
//      - Use case: Disable for debugging to see all API interactions
//
// Naming Convention:
//    WSA_*    - WSALookupService API specific functions
//    DNSAPI_* - DnsApi specific functions  
//    Socket_* - Raw socket interception functions (in socket_hooks.c)
//    DNS_*    - Shared infrastructure (filter lists, IP entries, config)
//
// IMPORTANT: HOSTENT structures in BLOB format use RELATIVE POINTERS (offsets)
//            not absolute pointers. All pointer-typed fields in HOSTENT contain
//            offset values from the HOSTENT base address. Consumer code must
//            convert these offsets to absolute pointers using ABS_PTR before
//            dereferencing. This is required by Windows BLOB specification for
//            relocatable data structures.
//---------------------------------------------------------------------------

#define NOGDI
#include "dll.h"

#include <windows.h>
#include <wchar.h>
#include <oleauto.h>
#include <SvcGuid.h>
#include <windns.h>
#include "common/my_wsa.h"
#include "common/netfw.h"
#include "common/map.h"
#include "wsa_defs.h"
#include "dnsapi_defs.h"
#include "socket_hooks.h"
#include "dns_filter.h"
#include "dns_logging.h"
#include "common/pattern.h"
#include "common/str_util.h"
#include "core/drv/api_defs.h"
#include "core/drv/verify.h"


//---------------------------------------------------------------------------
// Functions
//---------------------------------------------------------------------------

// WSALookupService API hooks (ws2_32.dll)
static int WSA_WSALookupServiceBeginW(
    LPWSAQUERYSETW  lpqsRestrictions,
    DWORD           dwControlFlags,
    LPHANDLE        lphLookup);

static int WSA_WSALookupServiceNextW(
    HANDLE          hLookup,
    DWORD           dwControlFlags,
    LPDWORD         lpdwBufferLength,
    LPWSAQUERYSETW  lpqsResults);

static int WSA_WSALookupServiceEnd(HANDLE hLookup);

// DnsApi hooks (dnsapi.dll)
static DNS_STATUS DNSAPI_DnsQuery_A(
    PCSTR           pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNSAPI_DNS_RECORD* ppQueryResults,
    PVOID*          pReserved);

static DNS_STATUS DNSAPI_DnsQuery_W(
    PCWSTR          pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNSAPI_DNS_RECORD* ppQueryResults,
    PVOID*          pReserved);

static DNS_STATUS DNSAPI_DnsQuery_UTF8(
    PCSTR           pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNSAPI_DNS_RECORD* ppQueryResults,
    PVOID*          pReserved);

static DNS_STATUS DNSAPI_DnsQueryEx(
    PDNS_QUERY_REQUEST  pQueryRequest,
    PDNS_QUERY_RESULT   pQueryResults,
    PDNS_QUERY_CANCEL   pCancelHandle);

static VOID DNSAPI_DnsRecordListFree(
    PVOID           pRecordList,
    INT             FreeType);

static DNS_STATUS DNSAPI_DnsQueryRaw(
    PDNS_QUERY_RAW_REQUEST  pQueryRequest,
    PDNS_QUERY_RAW_CANCEL   pCancelHandle);

static VOID DNSAPI_DnsQueryRawResultFree(
    PDNS_QUERY_RAW_RESULT   pQueryResults);

static DNS_STATUS DNSAPI_DnsCancelQuery(
    PDNS_QUERY_CANCEL       pCancelHandle);

static PDNSAPI_DNS_RECORD DNSAPI_BuildDnsRecordList(
    const WCHAR*    domainName,
    WORD            wType,
    LIST*           pEntries,
    DNS_CHARSET     CharSet);

// DNS Type Filter Helper Functions (internal use only)
static BOOLEAN DNS_ParseTypeName(const WCHAR* name, USHORT* type_out, BOOLEAN* is_negated);

// Shared utility functions (implemented in net.c)
BOOLEAN WSA_GetIP(const short* addr, int addrlen, IP_ADDRESS* pIP);
void WSA_DumpIP(ADDRESS_FAMILY af, IP_ADDRESS* pIP, wchar_t* pStr);

// DNS logging functions (implemented in dns_logging.c)
BOOLEAN DNS_IsIPv4Mapped(const IP_ADDRESS* pIP);

// Socket hooks functions (implemented in socket_hooks.c)
BOOLEAN Socket_ParseDnsQuery(
    const BYTE*    packet,
    int            len,
    WCHAR*         domainOut,
    int            domainOutSize,
    USHORT*        qtype);

int Socket_BuildDnsResponse(
    const BYTE*    query,
    int            query_len,
    struct _LIST*  pEntries,
    BOOLEAN        block,
    BYTE*          response,
    int            response_size,
    USHORT         qtype,
    struct _DNS_TYPE_FILTER* type_filter);

// Initialization functions
BOOLEAN DNSAPI_Init(HMODULE module);
static void DNS_InitFilterRules(void);

// External function declarations
ULONGLONG GetTickCount64();  // Windows Vista+ timing function

//---------------------------------------------------------------------------

// WSALookupService system function pointers
static P_WSALookupServiceBeginW __sys_WSALookupServiceBeginW = NULL;
static P_WSALookupServiceNextW __sys_WSALookupServiceNextW = NULL;
static P_WSALookupServiceEnd __sys_WSALookupServiceEnd = NULL;

// DnsApi system function pointers
static P_DnsQuery_A               __sys_DnsQuery_A               = NULL;
static P_DnsQuery_W               __sys_DnsQuery_W               = NULL;
static P_DnsQuery_UTF8            __sys_DnsQuery_UTF8            = NULL;

static P_DnsQueryEx               __sys_DnsQueryEx               = NULL;

static P_DnsRecordListFree        __sys_DnsRecordListFree        = NULL;
static P_DnsQueryRaw              __sys_DnsQueryRaw              = NULL;
static P_DnsQueryRawResultFree    __sys_DnsQueryRawResultFree    = NULL;
static P_DnsCancelQuery           __sys_DnsCancelQuery           = NULL;

typedef struct _DNSAPI_EX_FILTER_RESULT {
    DNS_STATUS Status;
    BOOLEAN    IsAsync;
    BOOLEAN    PassthroughLogged;  // TRUE if passthrough was already logged (negated type)
} DNSAPI_EX_FILTER_RESULT;

// Context structure for async DnsQueryEx callback wrapper
typedef struct _DNSAPI_ASYNC_CONTEXT {
    PDNS_QUERY_COMPLETION_ROUTINE    OriginalCallback;
    PVOID                            OriginalContext;
    WCHAR                            Domain[256];
    WORD                             QueryType;
} DNSAPI_ASYNC_CONTEXT;

// Context structure for DnsQueryRaw passthrough callback wrapper
typedef struct _DNSAPI_RAW_PASSTHROUGH_CONTEXT {
    DNS_QUERY_RAW_COMPLETION_ROUTINE  OriginalCallback;
    PVOID                             OriginalContext;
    WCHAR                             Domain[256];
    WORD                              QueryType;
} DNSAPI_RAW_PASSTHROUGH_CONTEXT;

// Callback wrapper signature with SAL annotations
static VOID WINAPI DNSAPI_RawPassthroughCallbackWrapper(
    _In_ PVOID                            pQueryContext,
    _In_ PDNS_QUERY_RAW_RESULT            pQueryResults);

static VOID WINAPI DNSAPI_AsyncCallbackWrapper(
    PVOID                            pQueryContext,
    PDNS_QUERY_RESULT                pQueryResults);



static BOOLEAN DNSAPI_FilterDnsQueryExForName(
    const WCHAR*                     pszName,
    WORD                             wType,
    ULONG64                          queryOptions,
    PDNS_QUERY_RESULT                pQueryResults,
    PDNS_QUERY_CANCEL                pCancelHandle,
    PDNS_QUERY_COMPLETION_ROUTINE    pCompletionCallback,
    PVOID                            pCompletionContext,
    const WCHAR*                     sourceTag,
    DNS_CHARSET                      CharSet,
    DNSAPI_EX_FILTER_RESULT*         pOutcome);


//---------------------------------------------------------------------------
// Variables
//---------------------------------------------------------------------------

extern POOL* Dll_Pool;

// Shared DNS filter infrastructure (exported for socket_hooks.c)
LIST       DNS_FilterList;      // Shared by WSA, DNSAPI, and raw socket implementations
BOOLEAN    DNS_FilterEnabled = FALSE;
static BOOLEAN DNS_DnsApiHookEnabled = TRUE;  // FilterDnsApi setting (default: enabled)
BOOLEAN    DNS_MapIpv4ToIpv6 = FALSE;         // DnsMapIpv4ToIpv6 setting (default: disabled)
BOOLEAN    DNS_HasValidCertificate = FALSE;  // Certificate validity for NetworkDnsFilter/FilterRawDns (exported)


#define MAX_DNS_FILTER_EX 32
typedef struct _DNS_EXCLUSION_LIST {
    WCHAR* image_name; // NULL for global
    WCHAR* patterns[MAX_DNS_FILTER_EX];
    ULONG  count;
} DNS_EXCLUSION_LIST;
static DNS_EXCLUSION_LIST DNS_ExclusionLists[MAX_DNS_FILTER_EX];
static ULONG DNS_ExclusionListCount = 0;
static BOOLEAN DNS_ExclusionsLoaded = FALSE;
static BOOLEAN DNS_DebugOptionsLoaded = FALSE;
static BOOLEAN DNS_DebugExclusionLogs = FALSE;

static void DNS_EnsureDebugOptionsLoaded(void);
static void DNS_LoadExclusionRules(void);
static DNS_EXCLUSION_LIST* DNS_GetOrCreateExclusionList(const WCHAR* image_name, size_t img_len);
static void DNS_ParseExclusionPatterns(DNS_EXCLUSION_LIST* excl, const WCHAR* value);
static BOOLEAN DNS_ListMatchesDomain(const DNS_EXCLUSION_LIST* excl, const WCHAR* domain);
static PATTERN* DNS_FindPatternInFilterList(const WCHAR* domain, ULONG level);
static BOOLEAN DNS_DomainMatchesFilter(const WCHAR* domain);
static BOOLEAN DNS_LoadFilterEntries(void);

// WSALookupService specific state tracking
typedef struct _WSA_LOOKUP {
    LIST* pEntries;          // THREAD SAFETY: Read-only after initialization; safe for concurrent reads
    BOOLEAN NoMore;
    WCHAR* DomainName;       // Request Domain
    GUID* ServiceClassId;    // Request Class ID
    DWORD Namespace;         // Request Namespace
    BOOLEAN Filtered;        // Filter flag
    WORD QueryType;          // Detected DNS query type (DNS_TYPE_A or DNS_TYPE_AAAA)
    ULONGLONG CreateTime;    // Handle creation time (GetTickCount64) for timeout tracking
} WSA_LOOKUP;

static HASH_MAP   WSA_LookupMap;


//---------------------------------------------------------------------------
// DNS_ExtractFilterAux
//
// Extract IP entries and type filter from DNS_FILTER_AUX structure
// Centralizes the extraction pattern used across all DNS filtering layers
// Exported for use by socket_hooks.c
//---------------------------------------------------------------------------

_FX void DNS_ExtractFilterAux(PVOID* aux, LIST** pEntries, DNS_TYPE_FILTER** type_filter)
{
    if (!aux || !*aux) {
        if (pEntries) *pEntries = NULL;
        if (type_filter) *type_filter = NULL;
        return;
    }
    
    DNS_FILTER_AUX* filter_aux = (DNS_FILTER_AUX*)(*aux);
    if (pEntries) *pEntries = filter_aux->ip_entries;
    if (type_filter) *type_filter = filter_aux->type_filter;
}

//---------------------------------------------------------------------------
// WSA_CleanupStaleHandles
//
// Periodically removes abandoned WSA_LOOKUP handles from the map.
// Handles older than 5 minutes are considered stale (app crashed/leaked handle).
// This prevents memory exhaustion from long-running sandboxed processes.
//---------------------------------------------------------------------------

_FX void WSA_CleanupStaleHandles(void)
{
    static ULONGLONG lastCleanup = 0;
    ULONGLONG now = GetTickCount64();
    ULONGLONG cleanupInterval = 60 * 1000;  // Run cleanup every 1 minute
    ULONGLONG handleTimeout = 5 * 60 * 1000;  // 5 minutes
    
    // Only run cleanup periodically to avoid overhead
    if (now - lastCleanup < cleanupInterval)
        return;
    
    lastCleanup = now;
    
    // Iterate through all handles and remove stale ones
    map_iter_t iter = map_iter();
    while (map_next(&WSA_LookupMap, &iter)) {
        WSA_LOOKUP* pLookup = (WSA_LOOKUP*)iter.value;
        if (!pLookup)
            continue;
        
        // Check if handle is older than timeout
        if (now - pLookup->CreateTime > handleTimeout) {
            // Cleanup memory before removing from map
            if (pLookup->DomainName)
                Dll_Free(pLookup->DomainName);
            if (pLookup->ServiceClassId)
                Dll_Free(pLookup->ServiceClassId);
            
            // Remove from map (also frees the handle allocated with Dll_Alloc)
            if (pLookup->Filtered && iter.key) {
                Dll_Free((void*)iter.key);  // Free the HANDLE allocated in WSALookupServiceBeginW
            }
            
            // Erase from map iterator
            map_erase(&WSA_LookupMap, &iter);
            
            // Debug log
            DNS_LogDebugCleanupStaleHandle(now - pLookup->CreateTime);
        }
    }
}

//---------------------------------------------------------------------------
// WSA_GetLookup
//
// Thread Safety: Uses map_get/map_insert pattern. While map_insert is not
//                fully atomic, the hash map implementation handles concurrent
//                inserts safely by returning the existing entry if another
//                thread inserted first. All fields are initialized after
//                successful insertion.
//---------------------------------------------------------------------------


_FX WSA_LOOKUP* WSA_GetLookup(HANDLE h, BOOLEAN bCanAdd)
{
    WSA_LOOKUP* pLookup = (WSA_LOOKUP*)map_get(&WSA_LookupMap, h);
    if (pLookup == NULL && bCanAdd) {
        // Note: map_insert returns existing entry if another thread inserted first
        // This provides race-safe behavior without explicit locking
        pLookup = (WSA_LOOKUP*)map_insert(&WSA_LookupMap, h, NULL, sizeof(WSA_LOOKUP));
        if (pLookup) {
            // Initialize fields - safe because map_insert zeroes new entries
            pLookup->pEntries = NULL;
            pLookup->NoMore = FALSE;
            pLookup->DomainName = NULL;
            pLookup->ServiceClassId = NULL;
            pLookup->Filtered = FALSE;
            pLookup->QueryType = DNS_TYPE_A;  // Default to A
            pLookup->CreateTime = GetTickCount64();  // Track creation time for timeout cleanup
        }
    }
    return pLookup;
}

//---------------------------------------------------------------------------
// Helper macros for alignment and relative pointers
//---------------------------------------------------------------------------

// Static assertion to ensure pointer size matches uintptr_t (required for offset storage)
// This validates our assumption that offsets can be safely stored in pointer-typed fields
#if defined(_WIN64)
static_assert(sizeof(void*) == sizeof(uintptr_t) && sizeof(void*) == 8, "64-bit pointer size mismatch");
#else
static_assert(sizeof(void*) == sizeof(uintptr_t) && sizeof(void*) == 4, "32-bit pointer size mismatch");
#endif

// Align pointer up to specified boundary (must be power of 2)
#define ALIGN_UP(ptr, align) (BYTE*)((((UINT_PTR)(ptr)) + ((align)-1)) & ~((UINT_PTR)((align)-1)))

// Relative pointer helpers for HOSTENT blob
// Windows BLOB format uses offsets (not absolute pointers) from the base address
// This is required for the HOSTENT structure to be relocatable in memory
#define REL_OFFSET(base, ptr) ((uintptr_t)((BYTE*)(ptr) - (BYTE*)(base)))
#define ABS_PTR(base, rel)    ((void*)(((BYTE*)(base)) + (uintptr_t)(rel)))

// Extract offset value from a pointer-typed field that actually contains a relative offset
// Use this when reading HOSTENT blob relative pointers stored in pointer-typed fields
// NOTE: This extracts the stored offset value, not a pointer - do not dereference the result
static inline uintptr_t GET_REL_FROM_PTR(void* p) {
    return (uintptr_t)(p);
}

// Debug buffer bounds checking (only in debug builds)
#ifdef _DEBUG
#define CHECK_BUFFER_SPACE(ptr, size, end) \
    do { if ((BYTE*)(ptr) + (size) > (BYTE*)(end)) { \
        SetLastError(WSAEFAULT); \
        return FALSE; \
    } } while(0)
#else
#define CHECK_BUFFER_SPACE(ptr, size, end) ((void)0)
#endif

//---------------------------------------------------------------------------
// WSA_FillResponseStructure
//
// Builds a complete WSAQUERYSETW structure with DNS results in a single buffer.
// Memory layout: WSAQUERYSETW | ServiceInstanceName | QueryString | CSADDR_INFO[] | 
//                SOCKADDR[] | BLOB | HOSTENT | h_name | h_aliases | h_addr_list | IPs
//
// IMPORTANT: The HOSTENT structure uses RELATIVE pointers (offsets from hostentBase)
//            as per Windows BLOB specification for relocatable data structures.
//
// Encoding: Domain names are converted from WCHAR to ANSI (CP_ACP) for HOSTENT
//           compatibility with Windows host resolution APIs.
//
// Thread Safety: This function reads from shared pLookup->pEntries list but does
//                not modify it. Concurrent calls are safe if the list is immutable
//                after initialization. Each call writes to caller-provided buffer.
//---------------------------------------------------------------------------

_FX BOOLEAN WSA_FillResponseStructure(
    WSA_LOOKUP* pLookup,
    LPWSAQUERYSETW lpqsResults,
    LPDWORD lpdwBufferLength)
{
    // Validate input parameters
    if (!pLookup || !pLookup->pEntries || !lpqsResults || !lpdwBufferLength)
        return FALSE;

    if (!pLookup->DomainName)
        return FALSE;

    BOOLEAN isIPv6Query = WSA_IsIPv6Query(pLookup->ServiceClassId);

    // Cache string length to avoid repeated wcslen calls
    SIZE_T domainChars = wcslen(pLookup->DomainName);
    
    // Convert domain name to narrow string (ANSI - CP_ACP) for HOSTENT
    // NOTE: Using CP_ACP encoding as Windows HOSTENT APIs expect ANSI strings
    // Pre-compute converted length for accurate size calculation
    int hostNameBytesNeeded = WideCharToMultiByte(CP_ACP, 0, pLookup->DomainName, (int)(domainChars + 1), NULL, 0, NULL, NULL);
    if (hostNameBytesNeeded <= 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    // Calc buffer size needed
    SIZE_T neededSize = sizeof(WSAQUERYSETW);
    SIZE_T domainNameLen = (domainChars + 1) * sizeof(WCHAR);
    neededSize += domainNameLen;  // for lpszServiceInstanceName
    neededSize += domainNameLen;  // for lpszQueryString

    // Calc IP size
    SIZE_T ipCount = 0;
    IP_ENTRY* entry;

    // Filter IP by type
    for (entry = (IP_ENTRY*)List_Head(pLookup->pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        if ((isIPv6Query && entry->Type == AF_INET6) ||
            (!isIPv6Query && entry->Type == AF_INET)) {
            ipCount++;
        }
    }
    
    // Debug: Log IP count and list contents
    DNS_LogWSAFillStart(isIPv6Query, ipCount, List_Head(pLookup->pEntries));
    
    // Log each entry in the list
    if (DNS_DebugFlag) {
        for (entry = (IP_ENTRY*)List_Head(pLookup->pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
            DNS_LogIPEntry(entry);
        }
    }

    if (ipCount == 0) {
        // No matching IPs for this query type
        // This is NOERROR + NODATA (domain exists, no records of this type)
        // Don't return FALSE here - let caller handle NODATA case
        // Note: Caller will check ipCount == 0 and return WSA_E_NO_MORE appropriately
        SetLastError(WSA_E_NO_MORE);
        return FALSE;
    }

    // Defensive: ensure ipCount fits in DWORD before casting (extremely large rule lists)
    if (ipCount > 0xFFFFFFFFUL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    SIZE_T csaddrSize = (SIZE_T)ipCount * sizeof(CSADDR_INFO);
    neededSize += csaddrSize;

    SIZE_T sockaddrSize = 0;
    for (entry = (IP_ENTRY*)List_Head(pLookup->pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        if ((isIPv6Query && entry->Type == AF_INET6) ||
            (!isIPv6Query && entry->Type == AF_INET)) {
            if (entry->Type == AF_INET)
                sockaddrSize += sizeof(SOCKADDR_IN) * 2;
            else if (entry->Type == AF_INET6)
                sockaddrSize += sizeof(SOCKADDR_IN6_LH) * 2;
        }
    }
    neededSize += sockaddrSize;

    // Add BLOB size for HOSTENT structure
    // NOTE: Windows BLOB format requires relative offsets (not absolute pointers) for relocatable data
    // HOSTENT structure + converted domain name + h_aliases NULL + h_addr_list entries + final NULL + IP addresses
    SIZE_T addrSize = isIPv6Query ? 16 : 4;  // IPv6 or IPv4 address size
    SIZE_T blobSize = sizeof(HOSTENT) + 
                      (SIZE_T)hostNameBytesNeeded +                    // Narrow string (ANSI)
                      (sizeof(void*) - 1) +                             // Worst-case padding before h_aliases
                      sizeof(PCHAR) +                                   // h_aliases NULL terminator
                      (sizeof(void*) - 1) +                             // Worst-case padding before h_addr_list
                      (ipCount * sizeof(PCHAR)) + sizeof(PCHAR) +       // h_addr_list array + NULL terminator
                      (ipCount * addrSize);                             // actual IP addresses
    
    // Account for alignment padding before BLOB structure
    neededSize = (neededSize + (sizeof(void*) - 1)) & ~(sizeof(void*) - 1);
    neededSize += sizeof(BLOB) + blobSize;

    // Check for overflow (DWORD is 32-bit unsigned)
    if (neededSize > 0xFFFFFFFF) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    // Buffer not enough, return error
    if (*lpdwBufferLength < (DWORD)neededSize) {
        *lpdwBufferLength = (DWORD)neededSize;
        SetLastError(WSAEFAULT);
        return FALSE;
    }

    memset(lpqsResults, 0, sizeof(WSAQUERYSETW));

    lpqsResults->dwSize = sizeof(WSAQUERYSETW);
    lpqsResults->dwNameSpace = pLookup->Namespace;
    lpqsResults->dwOutputFlags = 0;  // No special flags needed
    
    // Copy Service Class ID if available
    if (pLookup->ServiceClassId) {
        lpqsResults->lpServiceClassId = pLookup->ServiceClassId;
    }

    BYTE* currentPtr = (BYTE*)lpqsResults + sizeof(WSAQUERYSETW);
    
#ifdef _DEBUG
    // Debug: set buffer end for bounds checking
    BYTE* bufferEnd = (BYTE*)lpqsResults + *lpdwBufferLength;
#endif

    // Copy ServiceInstanceName (wide string)
    CHECK_BUFFER_SPACE(currentPtr, domainNameLen, bufferEnd);
    lpqsResults->lpszServiceInstanceName = (LPWSTR)currentPtr;
    wcscpy(lpqsResults->lpszServiceInstanceName, pLookup->DomainName);
    currentPtr += domainNameLen;

    // Copy QueryString (wide string)
    CHECK_BUFFER_SPACE(currentPtr, domainNameLen, bufferEnd);
    lpqsResults->lpszQueryString = (LPWSTR)currentPtr;
    wcscpy(lpqsResults->lpszQueryString, pLookup->DomainName);
    currentPtr += domainNameLen;

    // CSADDR_INFO array
    CHECK_BUFFER_SPACE(currentPtr, csaddrSize, bufferEnd);
    lpqsResults->dwNumberOfCsAddrs = (DWORD)ipCount;  // Safe: already verified ipCount fits in buffer
    lpqsResults->lpcsaBuffer = (PCSADDR_INFO)currentPtr;
    currentPtr += csaddrSize;

    SIZE_T i = 0;
    for (entry = (IP_ENTRY*)List_Head(pLookup->pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        if ((isIPv6Query && entry->Type != AF_INET6) ||
            (!isIPv6Query && entry->Type != AF_INET)) {
            continue;
        }

        PCSADDR_INFO csaInfo = &lpqsResults->lpcsaBuffer[i++];

        if (entry->Type == AF_INET) {
            CHECK_BUFFER_SPACE(currentPtr, sizeof(SOCKADDR_IN) * 2, bufferEnd);
            SOCKADDR_IN* remoteAddr = (SOCKADDR_IN*)currentPtr;
            currentPtr += sizeof(SOCKADDR_IN);
            memset(remoteAddr, 0, sizeof(SOCKADDR_IN));

            remoteAddr->sin_family = AF_INET;
            remoteAddr->sin_port = 0x3500;  // DNS port 53 in network byte order (big-endian)
            remoteAddr->sin_addr.S_un.S_addr = entry->IP.Data32[3];

            csaInfo->RemoteAddr.lpSockaddr = (LPSOCKADDR)remoteAddr;
            csaInfo->RemoteAddr.iSockaddrLength = sizeof(SOCKADDR_IN);

            SOCKADDR_IN* localAddr = (SOCKADDR_IN*)currentPtr;
            currentPtr += sizeof(SOCKADDR_IN);
            memset(localAddr, 0, sizeof(SOCKADDR_IN));

            localAddr->sin_family = AF_INET;
            localAddr->sin_port = 0;
            localAddr->sin_addr.S_un.S_addr = 0;

            csaInfo->LocalAddr.lpSockaddr = (LPSOCKADDR)localAddr;
            csaInfo->LocalAddr.iSockaddrLength = sizeof(SOCKADDR_IN);


            csaInfo->iSocketType = SOCK_DGRAM;
            csaInfo->iProtocol = IPPROTO_UDP;
        }
        else if (entry->Type == AF_INET6) {
            CHECK_BUFFER_SPACE(currentPtr, sizeof(SOCKADDR_IN6_LH) * 2, bufferEnd);
            SOCKADDR_IN6_LH* remoteAddr = (SOCKADDR_IN6_LH*)currentPtr;
            currentPtr += sizeof(SOCKADDR_IN6_LH);
            memset(remoteAddr, 0, sizeof(SOCKADDR_IN6_LH));

            remoteAddr->sin6_family = AF_INET6;
            remoteAddr->sin6_port = 0x3500;  // DNS port 53 in network byte order (big-endian)
            memcpy(remoteAddr->sin6_addr.u.Byte, entry->IP.Data, 16);

            csaInfo->RemoteAddr.lpSockaddr = (LPSOCKADDR)remoteAddr;
            csaInfo->RemoteAddr.iSockaddrLength = sizeof(SOCKADDR_IN6_LH);

            SOCKADDR_IN6_LH* localAddr = (SOCKADDR_IN6_LH*)currentPtr;
            currentPtr += sizeof(SOCKADDR_IN6_LH);
            memset(localAddr, 0, sizeof(SOCKADDR_IN6_LH));

            localAddr->sin6_family = AF_INET6;
            localAddr->sin6_port = 0;
            memset(localAddr->sin6_addr.u.Byte, 0, 16);

            csaInfo->LocalAddr.lpSockaddr = (LPSOCKADDR)localAddr;
            csaInfo->LocalAddr.iSockaddrLength = sizeof(SOCKADDR_IN6_LH);


            csaInfo->iSocketType = SOCK_RAW;
            // magic number returned by Windows
            csaInfo->iProtocol = 23;
        }
    }

    // Create BLOB with HOSTENT structure
    // Align currentPtr to pointer boundary before BLOB
    currentPtr = ALIGN_UP(currentPtr, sizeof(void*));
    
    CHECK_BUFFER_SPACE(currentPtr, sizeof(BLOB) + blobSize, bufferEnd);
    lpqsResults->lpBlob = (LPBLOB)currentPtr;
    memset(lpqsResults->lpBlob, 0, sizeof(BLOB));  // Zero BLOB structure
    currentPtr += sizeof(BLOB);

    lpqsResults->lpBlob->cbSize = (DWORD)blobSize;
    lpqsResults->lpBlob->pBlobData = currentPtr;

    HOSTENT* hostent = (HOSTENT*)currentPtr;
    memset(hostent, 0, sizeof(HOSTENT));  // Zero HOSTENT structure
    BYTE* hostentBase = currentPtr;
    currentPtr += sizeof(HOSTENT);

    // Set address type and length
    hostent->h_addrtype = isIPv6Query ? AF_INET6 : AF_INET;
    hostent->h_length = isIPv6Query ? 16 : 4;

    // Set h_name (relative offset - stored as pointer type but contains offset from base)
    // IMPORTANT: This is a RELATIVE OFFSET, not an absolute pointer
    hostent->h_name = (char*)(uintptr_t)REL_OFFSET(hostentBase, currentPtr);
    
    // Convert WCHAR domain name to narrow ANSI string for HOSTENT
    int converted = WideCharToMultiByte(CP_ACP, 0, pLookup->DomainName, (int)(domainChars + 1), 
                                        (LPSTR)currentPtr, hostNameBytesNeeded, NULL, NULL);
    if (converted <= 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    currentPtr += converted;

    // Align for h_aliases pointer array
    currentPtr = ALIGN_UP(currentPtr, sizeof(void*));
    
    // Set h_aliases (relative offset to NULL-terminated pointer array)
    hostent->h_aliases = (char**)(uintptr_t)REL_OFFSET(hostentBase, currentPtr);
    *(PCHAR*)currentPtr = 0;  // NULL terminator
    currentPtr += sizeof(PCHAR);

    // Align for h_addr_list pointer array
    currentPtr = ALIGN_UP(currentPtr, sizeof(void*));
    
    // Set h_addr_list (relative offset to pointer array)
    hostent->h_addr_list = (char**)(uintptr_t)REL_OFFSET(hostentBase, currentPtr);
    PCHAR* addrList = (PCHAR*)currentPtr;
    currentPtr += (ipCount + 1) * sizeof(PCHAR);  // Array of pointers + NULL terminator

    // Fill IP addresses
    SIZE_T addrIdx = 0;
    for (entry = (IP_ENTRY*)List_Head(pLookup->pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        if ((isIPv6Query && entry->Type != AF_INET6) ||
            (!isIPv6Query && entry->Type != AF_INET)) {
            continue;
        }

        // Set address pointer (relative offset from hostentBase - stored as pointer but contains offset)
        addrList[addrIdx] = (char*)(uintptr_t)REL_OFFSET(hostentBase, currentPtr);

        // Copy IP address
        if (isIPv6Query) {
            memcpy(currentPtr, entry->IP.Data, 16);
            currentPtr += 16;
        } else {
            *(DWORD*)currentPtr = entry->IP.Data32[3];
            currentPtr += 4;
        }
        addrIdx++;
    }
    addrList[addrIdx] = 0;  // NULL terminator

    // Final sanity check: ensure we didn't overrun the buffer (even in release builds)
    // This is a lightweight failsafe in case size calculations were wrong
    if ((BYTE*)currentPtr > ((BYTE*)lpqsResults + *lpdwBufferLength)) {
        SetLastError(WSAEFAULT);
        return FALSE;
    }

    return TRUE;
}

//---------------------------------------------------------------------------
// DNS_InitFilterRules
//
// Initializes shared DNS filter rules (called once, from whichever DLL loads first)
//---------------------------------------------------------------------------

static void DNS_EnsureDebugOptionsLoaded(void)
{
    if (DNS_DebugOptionsLoaded)
        return;

    DNS_DebugOptionsLoaded = TRUE;

    // Load DnsDebug setting with per-process support (like FilterDnsApi, DnsMapIpv4ToIpv6)
    DNS_DebugFlag = Config_GetSettingsForImageName_bool(L"DnsDebug", FALSE);
    DNS_DebugExclusionLogs = DNS_DebugFlag;  // Enable exclusion logs when debug is on
    
    // Load SuppressDnsLog setting (default: enabled for cleaner logs)
    extern BOOLEAN DNS_LoadSuppressLogSetting(void);
    DNS_LoadSuppressLogSetting();
}



static DNS_EXCLUSION_LIST* DNS_GetOrCreateExclusionList(const WCHAR* image_name, size_t img_len)
{
    if (image_name) {
        for (ULONG i = 0; i < DNS_ExclusionListCount; ++i) {
            if (DNS_ExclusionLists[i].image_name && _wcsicmp(DNS_ExclusionLists[i].image_name, image_name) == 0)
                return &DNS_ExclusionLists[i];
        }
    } else {
        for (ULONG i = 0; i < DNS_ExclusionListCount; ++i) {
            if (!DNS_ExclusionLists[i].image_name)
                return &DNS_ExclusionLists[i];
        }
    }

    if (DNS_ExclusionListCount >= MAX_DNS_FILTER_EX)
        return NULL;

    DNS_EXCLUSION_LIST* entry = &DNS_ExclusionLists[DNS_ExclusionListCount++];
    entry->count = 0;
    memset(entry->patterns, 0, sizeof(entry->patterns));

    if (image_name && img_len > 0) {
        entry->image_name = (WCHAR*)Dll_Alloc((img_len + 1) * sizeof(WCHAR));
        if (!entry->image_name) {
            --DNS_ExclusionListCount;
            return NULL;
        }
        wcsncpy(entry->image_name, image_name, img_len);
        entry->image_name[img_len] = 0;
    } else {
        entry->image_name = NULL;
    }

    return entry;
}

// Logging for exclusion initialization moved to dns_logging.c

static void DNS_ParseExclusionPatterns(DNS_EXCLUSION_LIST* excl, const WCHAR* value)
{
    if (!excl || !value || !*value)
        return;

    size_t vlen = wcslen(value);
    WCHAR* local_buf = (WCHAR*)Dll_Alloc((vlen + 1) * sizeof(WCHAR));
    if (!local_buf)
        return;

    wcscpy(local_buf, value);
    WCHAR* ptr = local_buf;
    while (ptr && *ptr && excl->count < MAX_DNS_FILTER_EX) {
        WCHAR* end = wcschr(ptr, L';');
        if (end)
            *end = L'\0';

        while (*ptr == L' ' || *ptr == L'\t')
            ++ptr;

        size_t len = wcslen(ptr);
        while (len > 0 && (ptr[len - 1] == L' ' || ptr[len - 1] == L'\t'))
            ptr[--len] = 0;

        if (len > 0) {
            WCHAR* pattern = (WCHAR*)Dll_Alloc((len + 1) * sizeof(WCHAR));
            if (!pattern)
                break;

            wcscpy(pattern, ptr);
            _wcslwr(pattern);
            excl->patterns[excl->count++] = pattern;
        }

        ptr = end ? end + 1 : NULL;
    }

    Dll_Free(local_buf);
}

static void DNS_LoadExclusionRules(void)
{
    DNS_EnsureDebugOptionsLoaded();

    if (DNS_ExclusionsLoaded)
        return;

    DNS_ExclusionsLoaded = TRUE;

    for (ULONG index = 0; ; ++index) {
        WCHAR ex_buf[256];
        NTSTATUS status = SbieApi_QueryConf(NULL, L"NetworkDnsFilterExclude", index, ex_buf, sizeof(ex_buf) - 16 * sizeof(WCHAR));
        if (!NT_SUCCESS(status))
            break;

        ULONG level = (ULONG)-1;
        const WCHAR* value = Config_MatchImageAndGetValue(ex_buf, Dll_ImageName, &level);
        if (!value)
            continue;

        const WCHAR* match_name = NULL;
        size_t match_len = 0;

        if (level != 2 && Dll_ImageName) {
            match_name = Dll_ImageName;
            match_len = wcslen(Dll_ImageName);
        }

        DNS_EXCLUSION_LIST* excl = DNS_GetOrCreateExclusionList(match_name, match_len);
        if (!excl)
            continue;

        DNS_LogExclusionInit(excl->image_name, value);
        DNS_ParseExclusionPatterns(excl, value);
    }
}

static BOOLEAN DNS_LoadFilterEntries(void)
{
    BOOLEAN loaded = FALSE;
    WCHAR conf_buf[256];

    for (ULONG index = 0; ; ++index) {
        NTSTATUS status = SbieApi_QueryConf(NULL, L"NetworkDnsFilter", index, conf_buf, sizeof(conf_buf) - 16 * sizeof(WCHAR));
        if (!NT_SUCCESS(status))
            break;

        ULONG level = (ULONG)-1;
        const WCHAR* value = Config_MatchImageAndGetValue(conf_buf, Dll_ImageName, &level);
        if (!value)
            continue;

        size_t vlen = wcslen(value);
        WCHAR* mutable_value = (WCHAR*)Dll_Alloc((vlen + 1) * sizeof(WCHAR));
        if (!mutable_value)
            continue;

        wcscpy(mutable_value, value);

        WCHAR* domain_ip = wcschr(mutable_value, L':');
        if (domain_ip)
            *domain_ip++ = L'\0';

        PATTERN* pat = Pattern_Create(Dll_Pool, mutable_value, TRUE, level);

        if (domain_ip) {
            LIST* entries = (LIST*)Dll_Alloc(sizeof(LIST));
            if (!entries) {
                Dll_Free(mutable_value);
                continue;
            }

            List_Init(entries);

            BOOLEAN HasV6 = FALSE;

            const WCHAR* ip_value = domain_ip;
            ULONG ip_len = wcslen(domain_ip);
            IP_ENTRY* last_entry = NULL;  // Track last entry for ordered insertion
            
            for (const WCHAR* ip_end = ip_value + ip_len; ip_value < ip_end;) {
                const WCHAR* ip_str1;
                ULONG ip_len1;
                ip_value = SbieDll_GetTagValue(ip_value, ip_end, &ip_str1, &ip_len1, L';');

                // Skip empty IP strings
                if (ip_len1 == 0)
                    continue;

                IP_ENTRY* entry = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
                if (entry && _inet_xton(ip_str1, ip_len1, &entry->IP, &entry->Type) == 1) {
                    // Validate that we actually got a non-zero IP (reject 0.0.0.0 unless explicitly specified)
                    BOOLEAN is_valid = FALSE;
                    if (entry->Type == AF_INET) {
                        is_valid = TRUE;  // Accept any IPv4, including 0.0.0.0 if user specified it
                    } else if (entry->Type == AF_INET6) {
                        is_valid = TRUE;  // Accept any IPv6
                        HasV6 = TRUE;
                    }
                    
                    if (is_valid) {
                        // Insert after last_entry to maintain order
                        List_Insert_After(entries, last_entry, entry);
                        last_entry = entry;
                    } else {
                        Dll_Free(entry);
                    }
                } else if (entry) {
                    Dll_Free(entry);
                }
            }

            if (!HasV6 && DNS_MapIpv4ToIpv6) {

                //
                // When DnsMapIpv4ToIpv6=y and no IPv6 entries exist, create IPv4-mapped IPv6 addresses
                // Format: ::ffff:a.b.c.d (RFC 4291 section 2.5.5.2)
                // This ensures IPv6 queries can resolve IPv4-only domains
                //

                for (IP_ENTRY* entry = (IP_ENTRY*)List_Head(entries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
                    if (entry->Type != AF_INET)
                        continue;

                    IP_ENTRY* entry6 = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
                    if (!entry6)
                        continue;

                    entry6->Type = AF_INET6;

                    // IPv4-mapped IPv6 address: ::FFFF:a.b.c.d (RFC 4291 section 2.5.5.2)
                    // Data layout: [0-9]=0x00, [10-11]=0xFF, [12-15]=IPv4
                    // Data32 layout: Data32[0]=0, Data32[1]=0, Data32[2]=0xFFFF0000, Data32[3]=IPv4
                    entry6->IP.Data32[0] = 0;
                    entry6->IP.Data32[1] = 0;
                    entry6->IP.Data32[2] = 0xFFFF0000;
                    entry6->IP.Data32[3] = entry->IP.Data32[3];  // Copy IPv4 address from Data32[3]

                    List_Insert_After(entries, NULL, entry6);
                }
            }

            // Create wrapper structure for auxiliary data
            DNS_FILTER_AUX* filter_aux = (DNS_FILTER_AUX*)Dll_Alloc(sizeof(DNS_FILTER_AUX));
            if (!filter_aux) {
                // Free entries if aux allocation fails
                IP_ENTRY* entry = (IP_ENTRY*)List_Head(entries);
                while (entry) {
                    IP_ENTRY* next = (IP_ENTRY*)List_Next(entry);
                    Dll_Free(entry);
                    entry = next;
                }
                Dll_Free(entries);
                Dll_Free(mutable_value);
                continue;
            }

            filter_aux->ip_entries = entries;
            filter_aux->type_filter = NULL;  // Will be set by DNS_LoadTypeFilterEntries

            PVOID* aux = Pattern_Aux(pat);
            *aux = filter_aux;
        } else {
            // Block mode (no IPs) - create aux with NULL ip_entries
            DNS_FILTER_AUX* filter_aux = (DNS_FILTER_AUX*)Dll_Alloc(sizeof(DNS_FILTER_AUX));
            if (!filter_aux) {
                Dll_Free(mutable_value);
                continue;
            }

            filter_aux->ip_entries = NULL;
            filter_aux->type_filter = NULL;

            PVOID* aux = Pattern_Aux(pat);
            *aux = filter_aux;
        }

        List_Insert_After(&DNS_FilterList, NULL, pat);
        Dll_Free(mutable_value);
        loaded = TRUE;
    }

    return loaded;
}

//---------------------------------------------------------------------------
// DNS_LoadTypeFilterEntries
//
// Loads NetworkDnsFilterType settings and attaches type filters to existing patterns
//---------------------------------------------------------------------------

static void DNS_LoadTypeFilterEntries(void)
{
    WCHAR conf_buf[256];

    for (ULONG index = 0; ; ++index) {
        NTSTATUS status = SbieApi_QueryConf(NULL, L"NetworkDnsFilterType", index, conf_buf, sizeof(conf_buf) - 16 * sizeof(WCHAR));
        if (!NT_SUCCESS(status))
            break;

        ULONG level = (ULONG)-1;
        const WCHAR* value = Config_MatchImageAndGetValue(conf_buf, Dll_ImageName, &level);
        if (!value)
            continue;

        size_t vlen = wcslen(value);
        WCHAR* mutable_value = (WCHAR*)Dll_Alloc((vlen + 1) * sizeof(WCHAR));
        if (!mutable_value)
            continue;

        wcscpy(mutable_value, value);

        // Split domain:types at colon
        WCHAR* domain_types = wcschr(mutable_value, L':');
        if (!domain_types) {
            Dll_Free(mutable_value);
            continue;  // Invalid format - need domain:types
        }

        *domain_types++ = L'\0';  // Null-terminate domain part
        WCHAR* domain = mutable_value;

        // Check if domain pattern is wildcard '*' - apply to ALL patterns
        BOOLEAN apply_to_all = (wcscmp(domain, L"*") == 0);
        
        // Convert domain to lowercase for matching
        _wcslwr(domain);
        
        // If domain contains wildcards or is *, we need to find all matching patterns
        // Otherwise, look for exact pattern match
        BOOLEAN has_wildcards = (wcschr(domain, L'*') != NULL || wcschr(domain, L'?') != NULL);
        
        // For exact match (no wildcards), verify pattern exists first
        PATTERN* found_pat = NULL;
        if (!apply_to_all && !has_wildcards) {
            // No wildcards - try to find exact pattern match
            found_pat = DNS_FindPatternInFilterList(domain, level);

            if (!found_pat) {
                // No matching NetworkDnsFilter entry - ignore this NetworkDnsFilterType
                DNS_LogConfigNoMatchingFilter(domain);
                Dll_Free(mutable_value);
                continue;
            }
        }

        // Parse type list (semicolon-separated)
        DNS_TYPE_FILTER* type_filter = (DNS_TYPE_FILTER*)Dll_Alloc(sizeof(DNS_TYPE_FILTER));
        if (!type_filter) {
            Dll_Free(mutable_value);
            continue;
        }

        memset(type_filter, 0, sizeof(DNS_TYPE_FILTER));

        WCHAR* type_ptr = domain_types;
        USHORT type_count = 0;
        USHORT negated_count = 0;
        BOOLEAN has_wildcard = FALSE;
        BOOLEAN wildcard_negated = FALSE;

        while (type_ptr && *type_ptr && 
               (type_count < MAX_DNS_TYPE_FILTERS - 1 || negated_count < MAX_DNS_TYPE_FILTERS - 1)) {
            // Find next semicolon or end of string
            WCHAR* semicolon = wcschr(type_ptr, L';');
            if (semicolon)
                *semicolon = L'\0';

            // Trim whitespace
            while (*type_ptr == L' ' || *type_ptr == L'\t')
                type_ptr++;

            size_t type_len = wcslen(type_ptr);
            while (type_len > 0 && (type_ptr[type_len - 1] == L' ' || type_ptr[type_len - 1] == L'\t'))
                type_ptr[--type_len] = L'\0';

            if (type_len > 0) {
                // Check for negated wildcard
                if (wcscmp(type_ptr, L"!*") == 0) {
                    wildcard_negated = TRUE;
                    DNS_LogConfigNegatedWildcard(domain);
                }
                // Check for wildcard
                else if (wcscmp(type_ptr, L"*") == 0) {
                    has_wildcard = TRUE;
                    DNS_LogConfigWildcardFound(domain);
                } else {
                    // Parse type name (with possible ! prefix)
                    USHORT parsed_type = 0;
                    BOOLEAN is_negated = FALSE;
                    if (DNS_ParseTypeName(type_ptr, &parsed_type, &is_negated)) {
                        if (is_negated) {
                            // Add to negated types list
                            if (negated_count < MAX_DNS_TYPE_FILTERS - 1) {
                                type_filter->negated_types[negated_count++] = parsed_type;
                                DNS_LogConfigNegatedType(type_ptr, domain);
                            }
                        } else {
                            // Add to allowed types list
                            if (type_count < MAX_DNS_TYPE_FILTERS - 1) {
                                type_filter->allowed_types[type_count++] = parsed_type;
                            }
                        }
                    } else {
                        DNS_LogConfigInvalidType(type_ptr, domain);
                    }
                }
            }

            type_ptr = semicolon ? semicolon + 1 : NULL;
        }

        type_filter->type_count = type_count;
        type_filter->negated_count = negated_count;
        type_filter->has_wildcard = has_wildcard;
        type_filter->wildcard_negated = wildcard_negated;
        type_filter->allowed_types[type_count] = 0;  // Null terminator
        type_filter->negated_types[negated_count] = 0;  // Null terminator

        // Attach type filter to matching pattern(s)
        // For wildcard domains (including '*'), iterate through all patterns and apply filter
        if (apply_to_all || has_wildcards) {
            // Create a pattern from the domain string for matching (if has wildcards)
            PATTERN* domain_pattern = NULL;
            if (has_wildcards && !apply_to_all) {
                domain_pattern = Pattern_Create(Dll_Pool, domain, TRUE, 0);
            }
            
            // Apply to ALL matching patterns in DNS_FilterList
            ULONG applied_count = 0;
            PATTERN* pat = (PATTERN*)List_Head(&DNS_FilterList);
            while (pat) {
                // Check if pattern matches the same image/level
                if (Pattern_Level(pat) == level) {
                    BOOLEAN should_apply = FALSE;
                    
                    if (apply_to_all) {
                        // Wildcard '*' applies to everything
                        should_apply = TRUE;
                    } else if (domain_pattern) {
                        // Check if domain pattern matches this filter pattern
                        const WCHAR* pat_src = Pattern_Source(pat);
                        if (pat_src && Pattern_Match(domain_pattern, pat_src, wcslen(pat_src))) {
                            should_apply = TRUE;
                        }
                    }
                    
                    if (should_apply) {
                        PVOID* aux = Pattern_Aux(pat);
                        if (aux && *aux) {
                            DNS_FILTER_AUX* filter_aux = (DNS_FILTER_AUX*)(*aux);
                            
                            // Create a copy of the type filter for each pattern
                            DNS_TYPE_FILTER* type_filter_copy = (DNS_TYPE_FILTER*)Dll_Alloc(sizeof(DNS_TYPE_FILTER));
                            if (type_filter_copy) {
                                memcpy(type_filter_copy, type_filter, sizeof(DNS_TYPE_FILTER));
                                
                                // Free old type filter if exists
                                if (filter_aux->type_filter) {
                                    Dll_Free(filter_aux->type_filter);
                                }
                                
                                filter_aux->type_filter = type_filter_copy;
                                applied_count++;
                            }
                        }
                    }
                }
                pat = (PATTERN*)List_Next(pat);
            }
            
            if (domain_pattern) {
                Pattern_Free(domain_pattern);
            }
            
            // Build types string for logging
            WCHAR types_str[256] = L"";
            if (!has_wildcard) {
                for (USHORT i = 0; i < type_count && i < 10; i++) {
                    WCHAR type_buf[32];
                    Sbie_snwprintf(type_buf, 32, L"%s%s", 
                        i > 0 ? L";" : L"",
                        DNS_GetTypeName(type_filter->allowed_types[i]));
                    wcscat(types_str, type_buf);
                }
            }
            DNS_LogConfigTypeFilterApplied(domain, types_str, type_count, applied_count, has_wildcard);
            
            // Free the original type filter (we created copies)
            Dll_Free(type_filter);
        } else if (found_pat) {
            // Exact match - apply to single pattern
            PVOID* aux = Pattern_Aux(found_pat);
            if (aux && *aux) {
                DNS_FILTER_AUX* filter_aux = (DNS_FILTER_AUX*)(*aux);
                
                // Free old type filter if exists
                if (filter_aux->type_filter) {
                    Dll_Free(filter_aux->type_filter);
                }
                
                filter_aux->type_filter = type_filter;

                // Build types string for logging
                WCHAR types_str[256] = L"";
                if (!has_wildcard) {
                    for (USHORT i = 0; i < type_count && i < 10; i++) {
                        WCHAR type_buf[32];
                        Sbie_snwprintf(type_buf, 32, L"%s%s", 
                            i > 0 ? L";" : L"",
                            DNS_GetTypeName(type_filter->allowed_types[i]));
                        wcscat(types_str, type_buf);
                    }
                }
                DNS_LogConfigTypeFilterApplied(domain, types_str, type_count, 1, has_wildcard);
            } else {
                Dll_Free(type_filter);
            }
        } else {
            // Should not happen - free type filter
            Dll_Free(type_filter);
        }
    }
}


_FX void DNS_InitFilterRules(void)
{
    // Load debug options first (needed by various initialization stages)
    DNS_EnsureDebugOptionsLoaded();
    
    // Load DnsApi hook setting
    DNS_DnsApiHookEnabled = Config_GetSettingsForImageName_bool(L"FilterDnsApi", TRUE);
    
    // Load DnsMapIpv4ToIpv6 setting (default: disabled)
    DNS_MapIpv4ToIpv6 = Config_GetSettingsForImageName_bool(L"DnsMapIpv4ToIpv6", FALSE);
    
    DNS_LoadExclusionRules();

    if (DNS_FilterList.count > 0)
        return;

    List_Init(&DNS_FilterList);
    DNS_LoadFilterEntries();
    
    // Load type filters (must be done after LoadFilterEntries)
    DNS_LoadTypeFilterEntries();

    // Check certificate for NetworkDnsFilter (certificate-only feature)
    BOOLEAN has_valid_certificate = FALSE;
    __declspec(align(8)) SCertInfo CertInfo = { 0 };
    if (NT_SUCCESS(SbieApi_QueryDrvInfo(-1, &CertInfo, sizeof(CertInfo))) && (CertInfo.active && CertInfo.opt_net)) {
        has_valid_certificate = TRUE;
    }

    // Store certificate status globally for filtering checks
    DNS_HasValidCertificate = has_valid_certificate;

    // Always enable infrastructure when filter rules exist (for logging and potential filtering)
    // Certificate will be checked at filtering time to determine if interception/blocking is allowed
    if (DNS_FilterList.count > 0) {
        DNS_FilterEnabled = TRUE;
        map_init(&WSA_LookupMap, Dll_Pool);
        
        if (!has_valid_certificate) {
            // Warn that filtering is disabled (will only log, not intercept/block)
            const WCHAR* strings[] = { L"NetworkDnsFilter" , NULL };
            SbieApi_LogMsgExt(-1, 6009, strings);
        }
    }

    // DnsTrace for logging (works regardless of certificate - logging only, no filtering)
    WCHAR wsTraceOptions[4];
    if (SbieApi_QueryConf(NULL, L"DnsTrace", 0, wsTraceOptions, sizeof(wsTraceOptions)) == STATUS_SUCCESS && wsTraceOptions[0] != L'\0') {
        DNS_TraceFlag = TRUE;
        // Initialize infrastructure for logging if not already done
        // This allows pure logging mode even without certificate or filter rules
        if (!DNS_FilterEnabled) {
            DNS_FilterEnabled = TRUE;
            map_init(&WSA_LookupMap, Dll_Pool);
        }
    }
}


//---------------------------------------------------------------------------
// DNS_GetTypeName
//
// Returns a human-readable name for a DNS query type
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
        case DNS_TYPE_SVCB:   return L"SVCB";
        case DNS_TYPE_HTTPS:   return L"HTTPS";
        case 255:            return L"ANY";  // Wildcard - requests all record types
        default: {
            // Use rotating buffers to reduce thread collision (not perfect but good enough)
            static WCHAR buffers[4][32];
            static volatile LONG bufferIndex = 0;
            LONG idx = InterlockedIncrement(&bufferIndex) & 3;  // Rotate through 4 buffers
            Sbie_snwprintf(buffers[idx], 32, L"TYPE%d", wType);
            return buffers[idx];
        }
    }
}

//

//---------------------------------------------------------------------------
// DNS_ParseTypeName
//
// Parses a DNS type name (e.g., "A", "AAAA", "CNAME") or numeric format (e.g., "TYPE28")
// Supports negation prefix '!' (e.g., "!A", "!MX")
// Returns TRUE if parsed successfully, FALSE otherwise
// Sets is_negated to TRUE if '!' prefix found
//---------------------------------------------------------------------------

static BOOLEAN DNS_ParseTypeName(const WCHAR* name, USHORT* type_out, BOOLEAN* is_negated)
{
    if (!name || !type_out)
        return FALSE;

    if (is_negated)
        *is_negated = FALSE;

    // Check for negation prefix '!'
    if (name[0] == L'!') {
        if (is_negated)
            *is_negated = TRUE;
        name++;  // Skip '!' prefix
    }

    // Try named types first
    if (_wcsicmp(name, L"A") == 0)           { *type_out = DNS_TYPE_A; return TRUE; }
    if (_wcsicmp(name, L"NS") == 0)          { *type_out = DNS_TYPE_NS; return TRUE; }
    if (_wcsicmp(name, L"CNAME") == 0)       { *type_out = DNS_TYPE_CNAME; return TRUE; }
    if (_wcsicmp(name, L"SOA") == 0)         { *type_out = DNS_TYPE_SOA; return TRUE; }
    if (_wcsicmp(name, L"PTR") == 0)         { *type_out = DNS_TYPE_PTR; return TRUE; }
    if (_wcsicmp(name, L"MX") == 0)          { *type_out = DNS_TYPE_MX; return TRUE; }
    if (_wcsicmp(name, L"TXT") == 0)         { *type_out = DNS_TYPE_TEXT; return TRUE; }
    if (_wcsicmp(name, L"AAAA") == 0)        { *type_out = DNS_TYPE_AAAA; return TRUE; }
    if (_wcsicmp(name, L"SVCB") == 0)         { *type_out = DNS_TYPE_SVCB; return TRUE; }
    if (_wcsicmp(name, L"HTTPS") == 0)         { *type_out = DNS_TYPE_HTTPS; return TRUE; }
    if (_wcsicmp(name, L"ANY") == 0)         { *type_out = 255; return TRUE; }

    // Try numeric format: "TYPE33" or just "33"
    if (_wcsnicmp(name, L"TYPE", 4) == 0) {
        name += 4;  // Skip "TYPE" prefix
    }

    // Parse numeric value
    WCHAR* endptr = NULL;
    long type_num = wcstol(name, &endptr, 10);
    if (endptr && *endptr == L'\0' && type_num >= 0 && type_num <= 65535) {
        *type_out = (USHORT)type_num;
        return TRUE;
    }

    return FALSE;
}

//---------------------------------------------------------------------------
// DNS_IsTypeNegated
//
// Helper function to check if a type is in the negated list
// Returns TRUE if type should be passed through (negated)
// Exported for use by socket_hooks.c
//---------------------------------------------------------------------------

BOOLEAN DNS_IsTypeNegated(const DNS_TYPE_FILTER* type_filter, USHORT query_type)
{
    if (!type_filter)
        return FALSE;

    // Check for !* (passthrough all)
    if (type_filter->wildcard_negated)
        return TRUE;

    // Check if type is in negated list
    for (USHORT i = 0; i < type_filter->negated_count && i < MAX_DNS_TYPE_FILTERS; i++) {
        if (type_filter->negated_types[i] == query_type)
            return TRUE;
    }

    return FALSE;
}

//---------------------------------------------------------------------------
// DNS_IsTypeInFilterList
//
// Checks if a DNS type should be filtered based on the type filter
// Returns TRUE if type should be filtered, FALSE if it should pass through
//
// Logic with negation support:
// - If type_filter is NULL: Filter ALL types (intercept A/AAAA/ANY, block others)
// - If type is in allowed list: Filter it (negation does NOT override explicit listing)
// - If type is negated (!type or !*): Passthrough
// - If type_filter has wildcard: Filter ALL types (except negated)
// - If type_filter is set: Filter types in list only, passthrough types NOT in list
//
// Explicit listing takes highest priority - negation only applies to unlisted types
//---------------------------------------------------------------------------

BOOLEAN DNS_IsTypeInFilterList(const DNS_TYPE_FILTER* type_filter, USHORT query_type)
{
    // No type filter specified - use default behavior
    // Filter ALL types (will be intercepted if A/AAAA/ANY, blocked if unsupported)
    if (!type_filter) {
        return TRUE;  // Filter all types by default
    }

    // Check if query type is EXPLICITLY in the allowed types list
    // Explicit listing overrides any negation (including !*)
    for (USHORT i = 0; i < type_filter->type_count && i < MAX_DNS_TYPE_FILTERS; i++) {
        if (type_filter->allowed_types[i] == query_type) {
            return TRUE;  // Type explicitly listed - filter it (ignore negation)
        }
    }

    // Type not in allowed list - check if it's negated (passthrough)
    if (DNS_IsTypeNegated(type_filter, query_type))
        return FALSE;  // Negated - passthrough

    // Wildcard specified - filter ALL unlisted types (except negated, already checked)
    if (type_filter->has_wildcard) {
        return TRUE;
    }

    // Type not in list - PASSTHROUGH (only when type filter is explicitly set)
    // When user sets a type filter, only listed types are filtered; unlisted types passthrough
    return FALSE;  // Passthrough to real DNS
}

//---------------------------------------------------------------------------
// DNS_CanSynthesizeResponse
//
// Checks if we can synthesize a DNS response for the given type
// Currently only A and AAAA records can be synthesized from IP addresses
//---------------------------------------------------------------------------

BOOLEAN DNS_CanSynthesizeResponse(USHORT query_type)
{
    // We can synthesize responses for A, AAAA, and ANY queries
    // ANY (type 255) queries can be satisfied by returning all A/AAAA records we have
    return (query_type == DNS_TYPE_A || query_type == DNS_TYPE_AAAA || query_type == 255);
}

// Returns TRUE if domain matches any exclusion string for current image or global
BOOLEAN DNS_IsExcluded(const WCHAR* domain)
{
    if (!domain)
        return FALSE;

    DNS_LoadExclusionRules();

    const WCHAR* image = Dll_ImageName;

    DNS_LogDebugExclusionCheck(domain, image, DNS_ExclusionListCount);

    if (image) {
        for (ULONG i = 0; i < DNS_ExclusionListCount; ++i) {
            DNS_EXCLUSION_LIST* excl = &DNS_ExclusionLists[i];
            if (!excl->image_name)
                continue;
            if (_wcsicmp(excl->image_name, image) != 0)
                continue;

            DNS_LogDebugExclusionPerImageList(excl->image_name, excl->count);

            if (DNS_ListMatchesDomain(excl, domain))
                return TRUE;
        }
    }

    for (ULONG i = 0; i < DNS_ExclusionListCount; ++i) {
        DNS_EXCLUSION_LIST* excl = &DNS_ExclusionLists[i];
        if (excl->image_name)
            continue;

        DNS_LogDebugExclusionGlobalList(excl->count);

        if (DNS_ListMatchesDomain(excl, domain))
            return TRUE;
    }

    return FALSE;
}

static BOOLEAN DNS_ListMatchesDomain(const DNS_EXCLUSION_LIST* excl, const WCHAR* domain)
{
    if (!excl || !domain)
        return FALSE;

    // Create a temporary pattern list for matching
    LIST temp_list;
    List_Init(&temp_list);
    
    // Add all patterns from exclusion list to temp pattern list
    for (ULONG j = 0; j < excl->count; ++j) {
        const WCHAR* pattern = excl->patterns[j];
        if (!pattern)
            continue;

        DNS_LogDebugExclusionTestPattern(j, pattern);

        // Use Pattern_MatchPathList for wildcard support
        PATTERN* pat = Pattern_Create(Dll_Pool, pattern, TRUE, 0);
        if (pat) {
            List_Insert_After(&temp_list, NULL, pat);
        }
    }
    
    // Match domain against pattern list
    size_t domain_len = wcslen(domain);
    WCHAR* domain_copy = (WCHAR*)Dll_AllocTemp((domain_len + 4) * sizeof(WCHAR));
    if (!domain_copy) {
        // Cleanup patterns
        PATTERN* pat = (PATTERN*)List_Head(&temp_list);
        while (pat) {
            PATTERN* next = (PATTERN*)List_Next(pat);
            Pattern_Free(pat);
            pat = next;
        }
        return FALSE;
    }
    
    wmemcpy(domain_copy, domain, domain_len);
    domain_copy[domain_len] = L'\0';
    
    PATTERN* found = NULL;
    int match_result = Pattern_MatchPathList(domain_copy, (ULONG)domain_len, &temp_list, NULL, NULL, NULL, &found);
    
    Dll_Free(domain_copy);
    
    // Cleanup patterns
    PATTERN* pat = (PATTERN*)List_Head(&temp_list);
    while (pat) {
        PATTERN* next = (PATTERN*)List_Next(pat);
        Pattern_Free(pat);
        pat = next;
    }
    
    if (match_result > 0 && found) {
        DNS_LogDebugExclusionMatch(domain, Pattern_Source(found));
        return TRUE;
    }

    return FALSE;
}

//---------------------------------------------------------------------------
// DNS_DomainMatchesFilter
//
// Helper to check if a domain matches any filter pattern (without type checking)
// Used for "Monitored" log detection in passthrough scenarios
// Returns TRUE if domain is in filter list, FALSE otherwise
//---------------------------------------------------------------------------

_FX BOOLEAN DNS_DomainMatchesFilter(const WCHAR* domain)
{
    if (!DNS_FilterEnabled || !domain)
        return FALSE;

    size_t path_len = wcslen(domain);
    if (path_len == 0)
        return FALSE;

    WCHAR* path_lwr = (WCHAR*)Dll_AllocTemp((path_len + 4) * sizeof(WCHAR));
    if (!path_lwr)
        return FALSE;

    wmemcpy(path_lwr, domain, path_len);
    path_lwr[path_len] = L'\0';
    _wcslwr(path_lwr);

    PATTERN* found;
    BOOLEAN matches = (Pattern_MatchPathList(path_lwr, (ULONG)path_len, &DNS_FilterList, NULL, NULL, NULL, &found) > 0);

    Dll_Free(path_lwr);
    return matches;
}

//---------------------------------------------------------------------------
// DNS_CheckFilter
//
// Simple filter check matching 1.16.8 pattern.
// Returns LIST* of IP entries if domain matches, NULL otherwise.
//---------------------------------------------------------------------------

_FX BOOLEAN DNS_CheckFilter(const WCHAR* pszName, WORD wType, LIST** ppEntries)
{
    if (!DNS_FilterEnabled || !pszName)
        return FALSE;

    // Check exclusion first
    if (DNS_IsExcluded(pszName))
        return FALSE;

    size_t path_len = wcslen(pszName);
    if (path_len == 0)
        return FALSE;

    WCHAR* path_lwr = (WCHAR*)Dll_AllocTemp((path_len + 4) * sizeof(WCHAR));
    if (!path_lwr)
        return FALSE;

    wmemcpy(path_lwr, pszName, path_len);
    path_lwr[path_len] = L'\0';
    _wcslwr(path_lwr);

    PATTERN* found;
    if (Pattern_MatchPathList(path_lwr, (ULONG)path_len, &DNS_FilterList, NULL, NULL, NULL, &found) <= 0) {
        Dll_Free(path_lwr);
        return FALSE;
    }

    Dll_Free(path_lwr);

    PVOID* aux = Pattern_Aux(found);
    if (!aux || !*aux)
        return FALSE;

    DNS_TYPE_FILTER* type_filter = NULL;
    DNS_ExtractFilterAux(aux, ppEntries, &type_filter);

    // If no IP entries (block mode), block it
    if (!*ppEntries)
        return TRUE;  // Return TRUE to indicate filtered (blocked)

    // Check type filter if specified
    if (type_filter && !DNS_IsTypeInFilterList(type_filter, wType))
        return FALSE;  // Type not in filter list, passthrough

    // Certificate required for actual filtering (interception/blocking)
    // Without certificate, logging already happened above, just pass through
    extern BOOLEAN DNS_HasValidCertificate;
    if (!DNS_HasValidCertificate) {
        return FALSE;  // Pass through to real DNS (no interception without cert)
    }

    return TRUE;
}

//---------------------------------------------------------------------------
// DNS_FindPatternInFilterList
//
// Helper function to find a pattern in DNS_FilterList using Pattern_MatchPathList.
// Supports wildcards and prioritizes by specificity (like NetworkDnsFilter).
// Returns the best matching pattern, or NULL if no match found.
//---------------------------------------------------------------------------

static PATTERN* DNS_FindPatternInFilterList(const WCHAR* domain, ULONG level)
{
    if (!domain || !DNS_FilterList.count)
        return NULL;

    size_t domain_len = wcslen(domain);
    if (domain_len == 0 || domain_len > 512)
        return NULL;

    // Create lowercase copy for matching
    WCHAR* domain_lwr = (WCHAR*)Dll_AllocTemp((domain_len + 4) * sizeof(WCHAR));
    if (!domain_lwr)
        return NULL;

    wmemcpy(domain_lwr, domain, domain_len);
    domain_lwr[domain_len] = L'\0';
    _wcslwr(domain_lwr);

    // Use Pattern_MatchPathList with level filtering
    PATTERN* found = NULL;
    ULONG match_level = level;
    int match_result = Pattern_MatchPathList(domain_lwr, (ULONG)domain_len, &DNS_FilterList, &match_level, NULL, NULL, &found);

    Dll_Free(domain_lwr);

    // Verify level matches (Pattern_MatchPathList returns best match, but we need exact level)
    if (match_result > 0 && found && Pattern_Level(found) == level) {
        return found;
    }

    return NULL;
}

//---------------------------------------------------------------------------
// WSA_InitNetDnsFilter
//---------------------------------------------------------------------------


_FX BOOLEAN WSA_InitNetDnsFilter(HMODULE module)
{
    P_WSALookupServiceBeginW WSALookupServiceBeginW;
    P_WSALookupServiceNextW WSALookupServiceNextW;
    P_WSALookupServiceEnd WSALookupServiceEnd;

    // Initialize shared filter rules (if not already done)
    DNS_InitFilterRules();

    // If neither filtering nor tracing is enabled (e.g. certificate missing with rules present
    // and DnsTrace not allowed), skip installing any WSALookupService or raw socket hooks.
    // This prevents crashes due to uninitialized lookup map usage in passthrough paths.
    // Crash scenario: DNS_FilterEnabled == FALSE, DNS_TraceFlag == FALSE, hooks installed,
    // WSA_WSALookupServiceBeginW uses WSA_GetLookup which depends on initialized map.
    if (!DNS_FilterEnabled && !DNS_TraceFlag) {
        return TRUE; // Nothing to do; leave original APIs untouched.
    }

    //
    // Setup WSALookupService hooks (ws2_32.dll)
    //

    WSALookupServiceBeginW = (P_WSALookupServiceBeginW)GetProcAddress(module, "WSALookupServiceBeginW");
    if (WSALookupServiceBeginW) {
        SBIEDLL_HOOK(WSA_, WSALookupServiceBeginW);
    }

    WSALookupServiceNextW = (P_WSALookupServiceNextW)GetProcAddress(module, "WSALookupServiceNextW");
    if (WSALookupServiceNextW) {
        SBIEDLL_HOOK(WSA_, WSALookupServiceNextW);
    }

    WSALookupServiceEnd = (P_WSALookupServiceEnd)GetProcAddress(module, "WSALookupServiceEnd");
    if (WSALookupServiceEnd) {
        SBIEDLL_HOOK(WSA_, WSALookupServiceEnd);
    }

    //
    // Setup raw socket hooks for nslookup and other direct DNS tools
    // Pass certificate status to enforce certificate requirement for FilterRawDns
    //
    Socket_InitHooks(module, DNS_HasValidCertificate);

    return TRUE;
}

//---------------------------------------------------------------------------
// DNS_GetDnsApiHookEnabled
//
// Query the FilterDnsApi setting to control DnsApi hooking
// Default: TRUE (enabled by default)
//---------------------------------------------------------------------------

static BOOLEAN DNS_GetDnsApiHookEnabled()
{
    // Query FilterDnsApi with per-process matching support
    // Default: TRUE (enabled by default for compatibility)
    return Config_GetSettingsForImageName_bool(L"FilterDnsApi", TRUE);
}

//---------------------------------------------------------------------------
// DNSAPI_Init
//
// Initializes DnsApi hooks (called when dnsapi.dll is loaded)
//---------------------------------------------------------------------------

_FX BOOLEAN DNSAPI_Init(HMODULE module)
{
    // Initialize shared filter rules (if not already done)
    DNS_InitFilterRules();

    // Check FilterDnsApi setting (default: enabled)
    DNS_DnsApiHookEnabled = DNS_GetDnsApiHookEnabled();
    
    if (!DNS_DnsApiHookEnabled) {
        // FilterDnsApi disabled - skip DnsApi hooking entirely
        return TRUE;
    }

    //
    // Setup DnsQuery hooks from dnsapi.dll
    // DnsQuery_W/A/UTF8 are available on Windows 2000+ (compatible with Win7/10/11)
    // DnsQueryEx is available on Windows Vista+ (compatible with Win7/10/11)
    // All functions use GetProcAddress to ensure compatibility across Windows versions
    //

    P_DnsQuery_W DnsQuery_W = (P_DnsQuery_W)GetProcAddress(module, "DnsQuery_W");
    if (DnsQuery_W) {
        SBIEDLL_HOOK(DNSAPI_, DnsQuery_W);
    }

    P_DnsQuery_A DnsQuery_A = (P_DnsQuery_A)GetProcAddress(module, "DnsQuery_A");
    if (DnsQuery_A) {
        SBIEDLL_HOOK(DNSAPI_, DnsQuery_A);
    }

    P_DnsQuery_UTF8 DnsQuery_UTF8 = (P_DnsQuery_UTF8)GetProcAddress(module, "DnsQuery_UTF8");
    if (DnsQuery_UTF8) {
        SBIEDLL_HOOK(DNSAPI_, DnsQuery_UTF8);
    }

    P_DnsQueryEx DnsQueryEx = (P_DnsQueryEx)GetProcAddress(module, "DnsQueryEx");
    if (DnsQueryEx) {
        SBIEDLL_HOOK(DNSAPI_, DnsQueryEx);
    }

    //
    // Other DNS API functions
    //

    P_DnsRecordListFree DnsRecordListFree = (P_DnsRecordListFree)GetProcAddress(module, "DnsRecordListFree");
    if (DnsRecordListFree) {
        SBIEDLL_HOOK(DNSAPI_, DnsRecordListFree);
    }

    P_DnsQueryRaw DnsQueryRaw = (P_DnsQueryRaw)GetProcAddress(module, "DnsQueryRaw");
    if (DnsQueryRaw) {
        SBIEDLL_HOOK(DNSAPI_, DnsQueryRaw);
    }

    P_DnsQueryRawResultFree DnsQueryRawResultFree = (P_DnsQueryRawResultFree)GetProcAddress(module, "DnsQueryRawResultFree");
    if (DnsQueryRawResultFree) {
        SBIEDLL_HOOK(DNSAPI_, DnsQueryRawResultFree);
    }

    P_DnsCancelQuery DnsCancelQuery = (P_DnsCancelQuery)GetProcAddress(module, "DnsCancelQuery");
    if (DnsCancelQuery) {
        SBIEDLL_HOOK(DNSAPI_, DnsCancelQuery);
    }

    return TRUE;
}


//---------------------------------------------------------------------------
// WSA_WSALookupServiceBeginW
//---------------------------------------------------------------------------


_FX int WSA_WSALookupServiceBeginW(
    LPWSAQUERYSETW  lpqsRestrictions,
    DWORD           dwControlFlags,
    LPHANDLE        lphLookup)
{
    // Periodically cleanup stale handles to prevent memory exhaustion
    if (DNS_FilterEnabled)
        WSA_CleanupStaleHandles();
    
    if (DNS_FilterEnabled && lpqsRestrictions && lpqsRestrictions->lpszServiceInstanceName) {
        ULONG path_len = wcslen(lpqsRestrictions->lpszServiceInstanceName);
        WCHAR* path_lwr = (WCHAR*)Dll_AllocTemp((path_len + 4) * sizeof(WCHAR));
        wmemcpy(path_lwr, lpqsRestrictions->lpszServiceInstanceName, path_len);
        path_lwr[path_len] = L'\0';
        _wcslwr(path_lwr);

        if (DNS_IsExcluded(path_lwr)) {
            DNS_LogExclusion(path_lwr);
            Dll_Free(path_lwr);
            return __sys_WSALookupServiceBeginW(lpqsRestrictions, dwControlFlags, lphLookup);
        }

        PATTERN* found;
        if (Pattern_MatchPathList(path_lwr, path_len, &DNS_FilterList, NULL, NULL, NULL, &found) > 0) {
            
            // Certificate required for actual filtering (interception/blocking)
            extern BOOLEAN DNS_HasValidCertificate;
            if (!DNS_HasValidCertificate) {
                // Domain matches filter but no cert - log as passthrough
                DNS_LogPassthrough(L"WSA", lpqsRestrictions->lpszServiceInstanceName, DNS_TYPE_A, L"No certificate - forwarding to real DNS");
                Dll_Free(path_lwr);
                return __sys_WSALookupServiceBeginW(lpqsRestrictions, dwControlFlags, lphLookup);
            }
            
            HANDLE fakeHandle = (HANDLE)Dll_Alloc(sizeof(ULONG_PTR));
            if (!fakeHandle) {
                Dll_Free(path_lwr);
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                return SOCKET_ERROR;
            }

            *lphLookup = fakeHandle;

            LIST* pEntries = NULL;  // Declare here so it's accessible for is_blocked check
            
            WSA_LOOKUP* pLookup = WSA_GetLookup(fakeHandle, TRUE);
            if (pLookup) {
                pLookup->Filtered = TRUE;

                pLookup->DomainName = Dll_Alloc((path_len + 1) * sizeof(WCHAR));
                if (pLookup->DomainName) {
                    wcscpy_s(pLookup->DomainName, path_len + 1, lpqsRestrictions->lpszServiceInstanceName);
                }
                else {
                    SbieApi_Log(2205, L"NetworkDnsFilter: Failed to allocate domain name");
                }

                pLookup->Namespace = lpqsRestrictions->dwNameSpace;

                if (lpqsRestrictions->lpServiceClassId) {
                    pLookup->ServiceClassId = Dll_Alloc(sizeof(GUID));
                    if (pLookup->ServiceClassId) {
                        memcpy(pLookup->ServiceClassId, lpqsRestrictions->lpServiceClassId, sizeof(GUID));
                    }
                    else {
                        SbieApi_Log(2205, L"NetworkDnsFilter: Failed to allocate service class ID");
                    }
                }

                PVOID* aux = Pattern_Aux(found);
                if (aux && *aux) {
                    DNS_TYPE_FILTER* type_filter = NULL;
                    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);
                    
                    // Determine query type from Service Class ID GUID
                    USHORT query_type = WSA_IsIPv6Query(lpqsRestrictions->lpServiceClassId) 
                        ? DNS_TYPE_AAAA 
                        : DNS_TYPE_A;
                    
                    // Store query type in lookup structure
                    pLookup->QueryType = query_type;
                    
                    // Block mode (no IPs) should block ALL query types
                    if (!pEntries) {
                        // In block mode, block everything (set NoMore to trigger error)
                        pLookup->NoMore = TRUE;
                        pLookup->pEntries = NULL;
                    } else {
                        // Filter mode (with IPs) - check if this type should be filtered
                        BOOLEAN should_filter = DNS_IsTypeInFilterList(type_filter, query_type);
                        
                        if (!should_filter) {
                            // Type not in filter list or negated - pass through to real DNS
                            // Check if negated to provide more specific log message
                            const WCHAR* reason = DNS_IsTypeNegated(type_filter, query_type)
                                ? L"Type filter: negated"
                                : L"Type not in filter list, forwarding to real DNS";
                            WSA_LogTypeFilterPassthrough(lpqsRestrictions->lpszServiceInstanceName, query_type, reason);
                            Dll_Free(fakeHandle);
                            Dll_Free(path_lwr);
                            return __sys_WSALookupServiceBeginW(lpqsRestrictions, dwControlFlags, lphLookup);
                        }
                        
                        pLookup->pEntries = pEntries;
                    }
                } else {
                    pLookup->NoMore = TRUE;
                }
            }

            // pEntries already extracted above - determine if blocked
            BOOLEAN is_blocked = (pEntries == NULL);
            
            WSA_LogIntercepted(lpqsRestrictions->lpszServiceInstanceName,
                lpqsRestrictions->lpServiceClassId,
                lpqsRestrictions->dwNameSpace,
                fakeHandle,
                is_blocked,
                pEntries);

            Dll_Free(path_lwr);
            return NO_ERROR;
        }

        Dll_Free(path_lwr);
    }

    int ret = __sys_WSALookupServiceBeginW(lpqsRestrictions, dwControlFlags, lphLookup);

    if (lpqsRestrictions && ret == NO_ERROR && lphLookup && *lphLookup) {
        // Determine query type for logging and storage
        WORD queryType = WSA_IsIPv6Query(lpqsRestrictions->lpServiceClassId) ? DNS_TYPE_AAAA : DNS_TYPE_A;
        
        // Store query type for passthrough queries so WSALookupServiceNextW can log correctly
        WSA_LOOKUP* pLookup = WSA_GetLookup(*lphLookup, TRUE);
        if (pLookup) {
            pLookup->QueryType = queryType;
            pLookup->Filtered = FALSE;  // Mark as passthrough
        }
        
        WSA_LogPassthrough(
            lpqsRestrictions->lpszServiceInstanceName,
            lpqsRestrictions->lpServiceClassId,
            lpqsRestrictions->dwNameSpace,
            *lphLookup,
            ret == SOCKET_ERROR ? GetLastError() : 0,
            queryType);
    } else if (lpqsRestrictions && ret == SOCKET_ERROR) {
        // Log errors even when we don't have a handle
        WORD queryType = WSA_IsIPv6Query(lpqsRestrictions->lpServiceClassId) ? DNS_TYPE_AAAA : DNS_TYPE_A;
        WSA_LogPassthrough(
            lpqsRestrictions->lpszServiceInstanceName,
            lpqsRestrictions->lpServiceClassId,
            lpqsRestrictions->dwNameSpace,
            NULL,
            GetLastError(),
            queryType);
    }

    return ret;
}


//---------------------------------------------------------------------------
// WSA_WSALookupServiceNextW
//---------------------------------------------------------------------------


_FX int WSA_WSALookupServiceNextW(
    HANDLE          hLookup,
    DWORD           dwControlFlags,
    LPDWORD         lpdwBufferLength,
    LPWSAQUERYSETW  lpqsResults)
{
    WSA_LOOKUP* pLookup = NULL;

    if (DNS_FilterEnabled) {
        pLookup = WSA_GetLookup(hLookup, FALSE);

        if (pLookup && pLookup->Filtered) {
            // Debug: Log entry to WSALookupServiceNextW
            DNS_LogWSALookupCall(hLookup, lpdwBufferLength ? *lpdwBufferLength : 0, 
                                 pLookup->NoMore, pLookup->pEntries);
            
            if (pLookup->NoMore || !pLookup->pEntries) {
                SetLastError(WSA_E_NO_MORE);
                return SOCKET_ERROR;
            }

            if (WSA_FillResponseStructure(pLookup, lpqsResults, lpdwBufferLength)) {
                pLookup->NoMore = TRUE;

                // Verbose debug logging only
                DNS_LogWSADebugResponse(pLookup->DomainName, lpqsResults->dwNameSpace,
                    WSA_IsIPv6Query(pLookup->ServiceClassId), hLookup,
                    lpqsResults->dwNumberOfCsAddrs,
                    lpqsResults->lpBlob ? lpqsResults->lpBlob->cbSize : 0,
                    lpqsResults->lpcsaBuffer, lpqsResults->dwNumberOfCsAddrs);

                return NO_ERROR;
            }
            else {
                // GetLastError already set in WSA_FillResponseStructure
                DWORD err = GetLastError();
                DNS_LogWSAFillFailure(hLookup, err, lpdwBufferLength ? *lpdwBufferLength : 0);
                return SOCKET_ERROR;
            }
        }

        if (pLookup && pLookup->NoMore) {

            SetLastError(WSA_E_NO_MORE);
            return SOCKET_ERROR;
        }
    }

    int ret = __sys_WSALookupServiceNextW(hLookup, dwControlFlags, lpdwBufferLength, lpqsResults);

    if (ret == NO_ERROR && pLookup && pLookup->pEntries) {

        //
        // This is a bit a simplified implementation, it assumes that all results are always of the same time
        // else it may truncate it early, also it can't return more results the have been found. 
        //

        if (lpqsResults->dwNumberOfCsAddrs > 0) {

            IP_ENTRY* entry = (IP_ENTRY*)List_Head(pLookup->pEntries);

            for (DWORD i = 0; i < lpqsResults->dwNumberOfCsAddrs; i++) {

                USHORT af = lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr->sa_family;
                for (; entry && entry->Type != af; entry = (IP_ENTRY*)List_Next(entry)); // skip to an entry of the right type
                if (!entry) { // no more entries clear remaining results
                    lpqsResults->dwNumberOfCsAddrs = i;
                    break;
                }

                if (af == AF_INET6)
                    memcpy(((SOCKADDR_IN6_LH*)lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr)->sin6_addr.u.Byte, entry->IP.Data, 16);
                else if (af == AF_INET)
                    ((SOCKADDR_IN*)lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr)->sin_addr.S_un.S_addr = entry->IP.Data32[3];

                entry = (IP_ENTRY*)List_Next(entry);
            }
        }

        if (lpqsResults->lpBlob != NULL) {

            IP_ENTRY* entry = (IP_ENTRY*)List_Head(pLookup->pEntries);

            HOSTENT* hp = (HOSTENT*)lpqsResults->lpBlob->pBlobData;
            if (hp->h_addrtype == AF_INET6 || hp->h_addrtype == AF_INET) {

                // Convert relative pointer to absolute using ABS_PTR helper
                // HOSTENT uses relative offsets (not absolute pointers) in BLOB format
                // NOTE: Windows BLOB spec requires relative offsets, but some providers may violate this
                // Extract offset from pointer-typed field (stored as offset value, not real pointer)
                uintptr_t addrListOffset = GET_REL_FROM_PTR(hp->h_addr_list);
                PCHAR* addrArray = (PCHAR*)ABS_PTR(hp, addrListOffset);
                
                for (PCHAR* Addr = addrArray; *Addr; Addr++) {

                    for (; entry && entry->Type != hp->h_addrtype; entry = (IP_ENTRY*)List_Next(entry)); // skip to an entry of the right type
                    if (!entry) { // no more entries, clear remaining results
                        *Addr = 0;
                        break;  // No point continuing - all remaining addresses will be NULL
                    }

                    // Convert relative offset to absolute pointer (extract offset, then convert)
                    uintptr_t ipOffset = GET_REL_FROM_PTR(*Addr);
                    PCHAR ptr = (PCHAR)ABS_PTR(hp, ipOffset);
                    if (hp->h_addrtype == AF_INET6)
                        memcpy(ptr, entry->IP.Data, 16);
                    else if (hp->h_addrtype == AF_INET)
                        *(DWORD*)ptr = entry->IP.Data32[3];

                    entry = (IP_ENTRY*)List_Next(entry);
                }
            }
        }

        pLookup->NoMore = TRUE;
    }

    if (DNS_TraceFlag && ret == NO_ERROR) {
        // Use query type from pLookup structure (stored in WSALookupServiceBeginW)
        USHORT query_type;
        if (pLookup) {
            query_type = pLookup->QueryType;
        } else {
            query_type = WSA_IsIPv6Query(lpqsResults->lpServiceClassId) ? DNS_TYPE_AAAA : DNS_TYPE_A;
        }
        
        DWORD ns = pLookup ? pLookup->Namespace : lpqsResults->dwNameSpace;
        
        // Log CSADDR_INFO results (includes filtering)
        DNS_LogWSAPassthroughResult(lpqsResults->lpszServiceInstanceName, ns, query_type, lpqsResults);
        
        // Also process HOSTENT blob if available (CSADDR_INFO and HOSTENT may contain different data)
        if (lpqsResults->lpBlob != NULL && (query_type == DNS_TYPE_A || query_type == DNS_TYPE_AAAA || query_type == 255)) {
            HOSTENT* hp = (HOSTENT*)lpqsResults->lpBlob->pBlobData;
            USHORT expected_af = (query_type == DNS_TYPE_AAAA) ? AF_INET6 : AF_INET;
            
            DNS_LogWSAPassthroughHOSTENT(hp->h_addrtype, expected_af, (hp->h_addrtype == expected_af ? 1 : 0));
            
            // Skip invalid/corrupt HOSTENT structures
            if (hp->h_addrtype != AF_INET6 && hp->h_addrtype != AF_INET) {
                DNS_LogWSAPassthroughInvalidHostent(hp->h_addrtype);
            }
            else if (hp->h_addr_list && (hp->h_addrtype == expected_af || query_type == 255)) {
                // Convert relative pointer to absolute
                uintptr_t addrListOffset = GET_REL_FROM_PTR(hp->h_addr_list);
                PCHAR* addrArray = (PCHAR*)ABS_PTR(hp, addrListOffset);
                
                WCHAR msg[2048];
                Sbie_snwprintf(msg, ARRAYSIZE(msg), L"WSALookupService Passthrough HOSTENT: %s",
                    lpqsResults->lpszServiceInstanceName);
                
                for (PCHAR* Addr = addrArray; *Addr; Addr++) {
                    uintptr_t ipOffset = GET_REL_FROM_PTR(*Addr);
                    PCHAR ptr = (PCHAR)ABS_PTR(hp, ipOffset);

                    IP_ADDRESS ip;
                    memset(&ip, 0, sizeof(ip));
                    if (hp->h_addrtype == AF_INET6)
                        memcpy(ip.Data, ptr, 16);
                    else if (hp->h_addrtype == AF_INET)
                        ip.Data32[3] = *(DWORD*)ptr;
                    
                    // Apply filtering for AAAA when mapping disabled
                    if (query_type == DNS_TYPE_AAAA && !DNS_MapIpv4ToIpv6) {
                        if (hp->h_addrtype == AF_INET) {
                            continue;  // Skip IPv4 entries
                        }
                        if (hp->h_addrtype == AF_INET6 && DNS_IsIPv4Mapped(&ip)) {
                            continue;  // Skip IPv4-mapped IPv6
                        }
                    }
                    
                    WSA_DumpIP(hp->h_addrtype, &ip, msg);
                }
                
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
        }
    }

    return ret;
}


//---------------------------------------------------------------------------
// WSA_WSALookupServiceEnd
//---------------------------------------------------------------------------


_FX int WSA_WSALookupServiceEnd(HANDLE hLookup)
{
    if (DNS_FilterEnabled) {
        WSA_LOOKUP* pLookup = WSA_GetLookup(hLookup, FALSE);

        if (pLookup && pLookup->Filtered) {
            if (pLookup->DomainName)
                Dll_Free(pLookup->DomainName);

            if (pLookup->ServiceClassId)
                Dll_Free(pLookup->ServiceClassId);

            map_remove(&WSA_LookupMap, hLookup);

            Dll_Free(hLookup);

            DNS_LogWSADebugRequestEnd(hLookup, TRUE);

            return NO_ERROR;
        }

        map_remove(&WSA_LookupMap, hLookup);
    }

    DNS_LogWSADebugRequestEnd(hLookup, FALSE);

    return __sys_WSALookupServiceEnd(hLookup);
}


//---------------------------------------------------------------------------
// DnsApi Implementation (dnsapi.dll)
//---------------------------------------------------------------------------

static BOOLEAN DNSAPI_FilterDnsQueryExForName(
    const WCHAR*                     pszName,
    WORD                             wType,
    ULONG64                          queryOptions,
    PDNS_QUERY_RESULT                pQueryResults,
    PDNS_QUERY_CANCEL                pCancelHandle,
    PDNS_QUERY_COMPLETION_ROUTINE    pCompletionCallback,
    PVOID                            pCompletionContext,
    const WCHAR*                     sourceTag,
    DNS_CHARSET                      CharSet,
    DNSAPI_EX_FILTER_RESULT*         pOutcome)
{
    if (!DNS_FilterEnabled || !pszName || !pQueryResults)
        return FALSE;

    size_t path_len = wcslen(pszName);
    if (path_len == 0)
        return FALSE;

    WCHAR* path_lwr = (WCHAR*)Dll_AllocTemp((path_len + 4) * sizeof(WCHAR));
    if (!path_lwr)
        return FALSE;

    wmemcpy(path_lwr, pszName, path_len);
    path_lwr[path_len] = L'\0';
    _wcslwr(path_lwr);

    if (DNS_IsExcluded(path_lwr)) {
        DNS_LogDebugExclusionFromQueryEx(sourceTag, path_lwr);
        Dll_Free(path_lwr);
        return FALSE;
    }

    PATTERN* found;
    if (Pattern_MatchPathList(path_lwr, path_len, &DNS_FilterList, NULL, NULL, NULL, &found) <= 0) {
        Dll_Free(path_lwr);
        return FALSE;
    }

    PVOID* aux = Pattern_Aux(found);
    if (!aux || !*aux) {
        Dll_Free(path_lwr);
        return FALSE;
    }

    // Certificate required for actual filtering (interception/blocking)
    extern BOOLEAN DNS_HasValidCertificate;
    if (!DNS_HasValidCertificate) {
        // Domain matches filter but no cert - log as passthrough
        DNS_LogPassthrough(sourceTag, pszName, wType, L"No certificate - forwarding to real DNS");
        Dll_Free(path_lwr);
        return FALSE;
    }

    LIST* pEntries = NULL;
    DNS_TYPE_FILTER* type_filter = NULL;
    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);

    // Block mode (no IPs) should block ALL query types
    if (!pEntries) {
        // In block mode, block everything regardless of type filter
        // (Don't check DNS_IsTypeInFilterList - block all types)
    } else {
        // Filter mode (with IPs) - check if this type should be filtered
        BOOLEAN should_filter = DNS_IsTypeInFilterList(type_filter, wType);
        
        if (!should_filter) {
            // Type not in filter list or negated - pass to real DNS
            // Check if negated to provide more specific log message
            if (type_filter && DNS_IsTypeNegated(type_filter, wType)) {
                DNS_LogTypeFilterPassthrough(sourceTag, pszName, wType, L"negated");
                if (pOutcome)
                    pOutcome->PassthroughLogged = TRUE;  // Indicate passthrough was already logged
            } else {
                DNS_LogPassthrough(sourceTag, pszName, wType, L"Type not in filter list, forwarding to real DNS");
                if (pOutcome)
                    pOutcome->PassthroughLogged = TRUE;  // Indicate passthrough was already logged
            }
            Dll_Free(path_lwr);
            return FALSE;
        }
    }

    // Type is in filter list (or block mode) - check if we can synthesize response or should block
    PDNSAPI_DNS_RECORD pRecords = NULL;
    DNS_STATUS status = 0;

    if (pEntries && DNS_CanSynthesizeResponse(wType)) {
        // Filter mode with supported type (A/AAAA): build response
        pRecords = DNSAPI_BuildDnsRecordList(pszName, wType, pEntries, CharSet);
        if (!pRecords)
            status = DNS_ERROR_RCODE_NAME_ERROR;
    } else if (!pEntries) {
        // Block mode: return NXDOMAIN (domain doesn't exist)
        status = DNS_ERROR_RCODE_NAME_ERROR;
    } else {
        // Filter mode but unsupported type (MX/CNAME/TXT/etc.)
        // Domain exists (we're filtering it), return NOERROR + NODATA (RFC 2308)
        status = 0;  // DNS_ERROR_RCODE = 0 = NOERROR, pRecords = NULL = NODATA
    }

    if (pQueryResults->Version == 0)
        pQueryResults->Version = DNS_QUERY_RESULTS_VERSION1;
    pQueryResults->QueryOptions = queryOptions;
    pQueryResults->pQueryRecords = pRecords;
    pQueryResults->Reserved = NULL;
    pQueryResults->QueryStatus = status;

    if (pCancelHandle)
        ZeroMemory(pCancelHandle, sizeof(DNS_QUERY_CANCEL));

    // Log the result
    if (status == 0 && pRecords) {
        WCHAR prefix[128];
        Sbie_snwprintf(prefix, 128, L"%s Intercepted", sourceTag);
        DNS_LogDnsRecords(prefix, pszName, wType, pRecords, NULL, FALSE);
    }
    else if (status == 0 && !pRecords) {
        // NOERROR + NODATA (unsupported type in intercept mode)
        WCHAR prefix[128];
        Sbie_snwprintf(prefix, 128, L"%s Intercepted", sourceTag);
        DNS_LogInterceptedNoData(prefix, pszName, wType, L"No records for this type (NODATA)");
    }
    else {
        // NXDOMAIN (block mode)
        WCHAR prefix[128];
        Sbie_snwprintf(prefix, 128, L"%s Blocked", sourceTag);
        DNS_LogBlocked(prefix, pszName, wType, L"Domain blocked (NXDOMAIN)");
    }

    if (pOutcome) {
        pOutcome->Status = status;
        pOutcome->IsAsync = (pCompletionCallback != NULL);
    }

    if (pCompletionCallback)
        pCompletionCallback(pQueryResults, pCompletionContext);

    Dll_Free(path_lwr);
    return TRUE;
}

//---------------------------------------------------------------------------
// DNSAPI_BuildDnsRecordList
//
// Builds a DNS_RECORD linked list from IP_ENTRY list.
// Memory is allocated using LocalAlloc for DnsFree compatibility.
//
// IMPORTANT: Different from HOSTENT BLOB format - uses absolute pointers
//            in a linked list structure. Caller must free with DnsRecordListFree.
//---------------------------------------------------------------------------

_FX PDNSAPI_DNS_RECORD DNSAPI_BuildDnsRecordList(
    const WCHAR* domainName,
    WORD wType,
    LIST* pEntries,
    DNS_CHARSET CharSet)
{
    if (!pEntries || !domainName)
        return NULL;

    PDNSAPI_DNS_RECORD pFirstRecord = NULL;
    PDNSAPI_DNS_RECORD pLastRecord = NULL;

    // For ANY queries (type 255), return both A and AAAA records
    BOOLEAN is_any_query = (wType == 255);
    USHORT targetType = (wType == DNS_TYPE_AAAA) ? AF_INET6 : AF_INET;
    
    // Check if IPv6 entries exist (needed for IPv4-mapped IPv6 creation)
    BOOLEAN has_ipv6 = FALSE;
    if (wType == DNS_TYPE_AAAA && !is_any_query && DNS_MapIpv4ToIpv6) {
        IP_ENTRY* entry;
        for (entry = (IP_ENTRY*)List_Head(pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
            if (entry->Type == AF_INET6) {
                has_ipv6 = TRUE;
                break;
            }
        }
    }
    
    // Calculate domain name length based on CharSet
    SIZE_T domainNameLen = 0;
    if (CharSet == DnsCharSetUnicode) {
        domainNameLen = (wcslen(domainName) + 1) * sizeof(WCHAR);
    } else if (CharSet == DnsCharSetAnsi) {
        int len = WideCharToMultiByte(CP_ACP, 0, domainName, -1, NULL, 0, NULL, NULL);
        if (len <= 0) return NULL;
        domainNameLen = len;
    } else if (CharSet == DnsCharSetUtf8) {
        int len = WideCharToMultiByte(CP_UTF8, 0, domainName, -1, NULL, 0, NULL, NULL);
        if (len <= 0) return NULL;
        domainNameLen = len;
    } else {
        // Default to Unicode if unknown
        domainNameLen = (wcslen(domainName) + 1) * sizeof(WCHAR);
        CharSet = DnsCharSetUnicode;
    }

    // Build linked list of DNS_RECORD structures
    IP_ENTRY* entry;
    for (entry = (IP_ENTRY*)List_Head(pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        // For ANY queries, include both IPv4 and IPv6; for specific types, filter by target type
        // Exception: If DnsMapIpv4ToIpv6=y and AAAA query without IPv6 entries, we'll create IPv4-mapped IPv6 below
        if (!is_any_query && entry->Type != targetType) {
            // For AAAA queries without IPv6, allow IPv4 entries (will be converted to IPv4-mapped IPv6)
            if (!(wType == DNS_TYPE_AAAA && DNS_MapIpv4ToIpv6 && !has_ipv6 && entry->Type == AF_INET))
                continue;
        }

        // Allocate DNS_RECORD using LocalAlloc (required for DnsFree compatibility)
        // LPTR = LMEM_FIXED | LMEM_ZEROINIT (allocate and zero-initialize)
        PDNSAPI_DNS_RECORD pRecord = (PDNSAPI_DNS_RECORD)LocalAlloc(LPTR, sizeof(DNSAPI_DNS_RECORD));
        if (!pRecord) {
            // Free already allocated records on failure - use LocalFree to match allocation
            PDNSAPI_DNS_RECORD pCur = pFirstRecord;
            while (pCur) {
                PDNSAPI_DNS_RECORD pNext = pCur->pNext;
                if (pCur->pName) LocalFree(pCur->pName);
                LocalFree(pCur);
                pCur = pNext;
            }
            return NULL;
        }

        // Verify structure is actually zero-initialized
        // (LPTR should do this, but be paranoid for Win7 compatibility)
        memset(pRecord, 0, sizeof(DNSAPI_DNS_RECORD));

        // Allocate and copy domain name (LPTR = zero-initialized)
        pRecord->pName = (PWSTR)LocalAlloc(LPTR, domainNameLen);
        if (!pRecord->pName) {
            LocalFree(pRecord);
            // Free already allocated records on failure - use LocalFree to match allocation
            PDNSAPI_DNS_RECORD pCur = pFirstRecord;
            while (pCur) {
                PDNSAPI_DNS_RECORD pNext = pCur->pNext;
                if (pCur->pName) LocalFree(pCur->pName);
                LocalFree(pCur);
                pCur = pNext;
            }
            return NULL;
        }
        
        // Copy domain name with conversion
        if (CharSet == DnsCharSetUnicode) {
            wmemcpy(pRecord->pName, domainName, wcslen(domainName) + 1);
        } else if (CharSet == DnsCharSetAnsi) {
            WideCharToMultiByte(CP_ACP, 0, domainName, -1, (LPSTR)pRecord->pName, (int)domainNameLen, NULL, NULL);
        } else if (CharSet == DnsCharSetUtf8) {
            WideCharToMultiByte(CP_UTF8, 0, domainName, -1, (LPSTR)pRecord->pName, (int)domainNameLen, NULL, NULL);
        }

        // Set record type and flags
        // For ANY queries, use actual record type (A for IPv4, AAAA for IPv6)
        // For specific queries, use the requested type
        if (is_any_query) {
            pRecord->wType = (entry->Type == AF_INET6) ? DNS_TYPE_AAAA : DNS_TYPE_A;
        } else {
            pRecord->wType = wType;
        }
        
        // Set Flags: Section = DNSREC_ANSWER (1), CharSet = Unicode (0), all other fields = 0
        // This ensures ipconfig displays "Section . . . . . . . : Answer" instead of "Question"
        pRecord->Flags.DW = 0;
        pRecord->Flags.S.Section = DNSREC_ANSWER;
        pRecord->Flags.S.CharSet = CharSet;
        
        pRecord->dwTtl = 300;  // 5 minutes TTL (default)
        pRecord->dwReserved = 0x53424945;  // 'SBIE' magic marker - identifies our synthesized records
        pRecord->pNext = NULL;

        // Copy IP address data based on entry type (not query type)
        if (entry->Type == AF_INET6) {
            pRecord->wDataLength = 16;
            memcpy(&pRecord->Data.AAAA.Ip6Address, entry->IP.Data, 16);
        } else if (wType == DNS_TYPE_AAAA && DNS_MapIpv4ToIpv6 && !has_ipv6) {
            // Create IPv4-mapped IPv6 address for AAAA query without IPv6 entries (when DnsMapIpv4ToIpv6=y)
            // Format: ::ffff:a.b.c.d (RFC 4291 section 2.5.5.2)
            pRecord->wDataLength = 16;
            DWORD* ipv6_data = (DWORD*)&pRecord->Data.AAAA.Ip6Address;
            ipv6_data[0] = 0;
            ipv6_data[1] = 0;
            ipv6_data[2] = 0xFFFF0000;  // ::ffff: prefix in network byte order
            ipv6_data[3] = entry->IP.Data32[3];  // IPv4 address at Data32[3]
        } else {
            pRecord->wDataLength = 4;
            pRecord->Data.A.IpAddress = entry->IP.Data32[3];
        }

        // Add to linked list
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

//---------------------------------------------------------------------------
// DNS_GetBlockedTag
//
// Helper to convert "X Intercepted" tag to "X Blocked" for consistent logging
//---------------------------------------------------------------------------

static const WCHAR* DNS_GetBlockedTag(const WCHAR* sourceTag, WCHAR* buffer, size_t bufferSize)
{
    const WCHAR* interceptedPos = wcsstr(sourceTag, L" Intercepted");
    if (interceptedPos) {
        size_t baseLen = interceptedPos - sourceTag;
        if (baseLen < bufferSize - 10) {  // Leave room for " Blocked" + null
            wmemcpy(buffer, sourceTag, baseLen);
            wcscpy(buffer + baseLen, L" Blocked");
            return buffer;
        }
    }
    return sourceTag;  // Fallback to original tag
}

//---------------------------------------------------------------------------
// DNS_GetBaseTag
//
// Helper to extract base tag from "X Intercepted" format (e.g., "DnsQuery_W")
// Used for passthrough logging to avoid "X Intercepted Passthrough" inconsistency
//---------------------------------------------------------------------------

static const WCHAR* DNS_GetBaseTag(const WCHAR* sourceTag, WCHAR* buffer, size_t bufferSize)
{
    const WCHAR* interceptedPos = wcsstr(sourceTag, L" Intercepted");
    if (interceptedPos) {
        size_t baseLen = interceptedPos - sourceTag;
        if (baseLen < bufferSize - 1) {
            wmemcpy(buffer, sourceTag, baseLen);
            buffer[baseLen] = L'\0';
            return buffer;
        }
    }
    return sourceTag;  // Fallback to original tag
}

//---------------------------------------------------------------------------
// DNS_LogDnsQueryResult
//
// Common logging for DnsQuery passthrough results - eliminates duplication
// Logs query result status and IP addresses (if successful)
// Note: Status 9501 (DNS_INFO_NO_RECORDS) is normal - means no records of this type exist
//---------------------------------------------------------------------------
// DNSAPI_FilterDnsQuery
//
// Common filtering logic for DnsQuery_W/A/UTF8 - eliminates code duplication
// Returns TRUE if query was intercepted (filtered/blocked), FALSE to passthrough
//---------------------------------------------------------------------------

static BOOLEAN DNSAPI_FilterDnsQuery(
    const WCHAR*            wName,
    WORD                    wType,
    LIST*                   pEntries,
    DNS_TYPE_FILTER*        type_filter,
    DNS_CHARSET             CharSet,
    const WCHAR*            sourceTag,
    PDNSAPI_DNS_RECORD*     ppQueryResults,
    DNS_STATUS*             pStatus,
    BOOLEAN*                pPassthroughLogged)  // OUT: TRUE if passthrough was already logged
{
    // Initialize output flag
    if (pPassthroughLogged)
        *pPassthroughLogged = FALSE;

    // Block mode (no IPs) should block ALL query types
    if (!pEntries) {
        WCHAR blockTag[128];
        DNS_LogBlocked(DNS_GetBlockedTag(sourceTag, blockTag, ARRAYSIZE(blockTag)), 
                       wName, wType, L"Domain blocked (NXDOMAIN)");
        *pStatus = DNS_ERROR_RCODE_NAME_ERROR;
        return TRUE;
    }

    // Filter mode (with IPs) - check if this type should be filtered
    BOOLEAN should_filter = DNS_IsTypeInFilterList(type_filter, wType);
    
    if (!should_filter) {
        // Type not in filter list or negated - pass to real DNS
        // Check if negated to provide more specific log message
        if (type_filter && DNS_IsTypeNegated(type_filter, wType)) {
            // Use base tag (strip "Intercepted") for passthrough logging
            WCHAR baseTag[128];
            DNS_LogTypeFilterPassthrough(DNS_GetBaseTag(sourceTag, baseTag, ARRAYSIZE(baseTag)), wName, wType, L"negated");
            if (pPassthroughLogged)
                *pPassthroughLogged = TRUE;  // Indicate we already logged the passthrough
        }
        // else: will be logged by caller (passthrough path) as "Type not in filter list"
        *pStatus = 0;
        return FALSE;
    }

    // Type is in filter list - check if we can synthesize or should block
    if (DNS_CanSynthesizeResponse(wType)) {
        // Filter mode with supported type: build DNS_RECORD linked list
        PDNSAPI_DNS_RECORD pRecords = DNSAPI_BuildDnsRecordList(wName, wType, pEntries, CharSet);
        
        if (pRecords) {
            *ppQueryResults = pRecords;
            DNS_LogDnsRecords(sourceTag, wName, wType, pRecords, NULL, FALSE);
            *pStatus = 0;
            return TRUE;
        } else {
            // No matching entries for this type (e.g., AAAA query but only IPv4 available)
            // Return NOERROR + NODATA (domain exists, no records of this type)
            DNS_LogInterceptedNoData(sourceTag, wName, wType, L"No records for this type (NODATA)");
            *ppQueryResults = NULL;
            *pStatus = 0;  // NOERROR
            return TRUE;
        }
    } else {
        // Unsupported type (MX/CNAME/TXT/etc.) in intercept mode
        // Domain exists (we're filtering it), return NOERROR + NODATA (RFC 2308)
        DNS_LogInterceptedNoData(sourceTag, wName, wType, L"No records for this type (NODATA)");
        *ppQueryResults = NULL;
        *pStatus = 0;  // NOERROR
        return TRUE;
    }
}

//---------------------------------------------------------------------------
// DNSAPI_DnsQuery_W
//
// Hook for DnsQuery_W - filters DNS queries using the same rules as
// WSALookupService but returns DNS_RECORD linked list format.
//---------------------------------------------------------------------------

_FX DNS_STATUS WINAPI DNSAPI_DnsQuery_W(
    PCWSTR          pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNSAPI_DNS_RECORD* ppQueryResults,
    PVOID*          pReserved)
{
    // Filter or block based on configuration
    if (DNS_FilterEnabled && pszName) {
        ULONG path_len = wcslen(pszName);
        WCHAR* path_lwr = (WCHAR*)Dll_AllocTemp((path_len + 4) * sizeof(WCHAR));
        wmemcpy(path_lwr, pszName, path_len);
        path_lwr[path_len] = L'\0';
        _wcslwr(path_lwr);

        if (DNS_IsExcluded(path_lwr)) {
            DNS_LogExclusion(path_lwr);
            Dll_Free(path_lwr);
            return __sys_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
        }

        PATTERN* found;
        if (Pattern_MatchPathList(path_lwr, path_len, &DNS_FilterList, NULL, NULL, NULL, &found) > 0) {
            PVOID* aux = Pattern_Aux(found);
            if (!aux || !*aux) {
                DNS_LogPassthrough(L"DnsQuery_W Passthrough", pszName, wType, L"No match, forwarding to real DNS");
                Dll_Free(path_lwr);
                return __sys_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
            }

            // Certificate required for actual filtering (interception/blocking)
            extern BOOLEAN DNS_HasValidCertificate;
            if (!DNS_HasValidCertificate) {
                // Domain matches filter but no cert - log as passthrough
                DNS_LogPassthrough(L"DnsQuery_W", pszName, wType, L"No certificate - forwarding to real DNS");
                Dll_Free(path_lwr);
                return __sys_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
            }

            LIST* pEntries = NULL;
            DNS_TYPE_FILTER* type_filter = NULL;
            DNS_ExtractFilterAux(aux, &pEntries, &type_filter);

            DNS_STATUS status;
            BOOLEAN passthroughLogged = FALSE;
            if (DNSAPI_FilterDnsQuery(pszName, wType, pEntries, type_filter, DnsCharSetUnicode,
                                      L"DnsQuery_W Intercepted", ppQueryResults, &status, &passthroughLogged)) {
                Dll_Free(path_lwr);
                return status;
            }

            // Not filtered by type - call real DNS and return unmodified result
            // Only log "Monitored" if passthrough wasn't already logged (e.g., for negated types)
            if (!passthroughLogged) {
                DNS_LogPassthrough(L"DnsQuery_W Monitored", pszName, wType, L"Type not in filter list, returning real DNS result");
            }
        }

        Dll_Free(path_lwr);
    }

    // Call original DnsQuery_W
    DNS_STATUS status = __sys_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);

    DNS_LogDnsQueryResult(L"DnsQuery_W Passthrough", pszName, wType, status, ppQueryResults);

    return status;
}

//---------------------------------------------------------------------------
// DNSAPI_DnsQuery_A
//
// Hook for DnsQuery_A (ANSI version) - converts to wide and calls DnsQuery_W hook
//---------------------------------------------------------------------------

_FX DNS_STATUS WINAPI DNSAPI_DnsQuery_A(
    PCSTR           pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNSAPI_DNS_RECORD* ppQueryResults,
    PVOID*          pReserved)
{
    // For filtering, convert to wide and use shared filter logic
    if (DNS_FilterEnabled && pszName) {
        int nameLen = MultiByteToWideChar(CP_ACP, 0, pszName, -1, NULL, 0);
        if (nameLen > 0 && nameLen < 512) {  // Sanity check
            // Use Dll_Alloc (not Dll_AllocTemp) so string persists for DNS_RECORD
            WCHAR* wName = (WCHAR*)Dll_Alloc(nameLen * sizeof(WCHAR));
            if (wName) {
                MultiByteToWideChar(CP_ACP, 0, pszName, -1, wName, nameLen);
                
                ULONG path_len = wcslen(wName);
                WCHAR* path_lwr = (WCHAR*)Dll_AllocTemp((path_len + 4) * sizeof(WCHAR));
                wmemcpy(path_lwr, wName, path_len);
                path_lwr[path_len] = L'\0';
                _wcslwr(path_lwr);

                if (DNS_IsExcluded(path_lwr)) {
                    DNS_LogExclusion(path_lwr);
                    Dll_Free(wName);
                    return __sys_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
                }

                PATTERN* found;
                if (Pattern_MatchPathList(path_lwr, path_len, &DNS_FilterList, NULL, NULL, NULL, &found) > 0) {
                    PVOID* aux = Pattern_Aux(found);
                    if (!aux || !*aux) {
                        Dll_Free(wName);
                        return __sys_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
                    }

                    // Certificate required for actual filtering (interception/blocking)
                    extern BOOLEAN DNS_HasValidCertificate;
                    if (!DNS_HasValidCertificate) {
                        // Domain matches filter but no cert - log as passthrough
                        DNS_LogPassthroughAnsi(L"DnsQuery_A", pszName, wType, L"No certificate - forwarding to real DNS");
                        Dll_Free(wName);
                        return __sys_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
                    }

                    LIST* pEntries = NULL;
                    DNS_TYPE_FILTER* type_filter = NULL;
                    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);

                    DNS_STATUS status;
                    BOOLEAN passthroughLogged = FALSE;
                    if (DNSAPI_FilterDnsQuery(wName, wType, pEntries, type_filter, DnsCharSetAnsi,
                                              L"DnsQuery_A Intercepted", ppQueryResults, &status, &passthroughLogged)) {
                        Dll_Free(wName);
                        return status;
                    }

                    // Not filtered by type - call real DNS and return unmodified result
                    // Only log "Monitored" if passthrough wasn't already logged (e.g., for negated types)
                    if (!passthroughLogged) {
                        DNS_LogPassthroughAnsi(L"DnsQuery_A Monitored", pszName, wType, L"Type not in filter list, returning real DNS result");
                    }
                }

                Dll_Free(wName);
            }
        }
    }

    // Call original DnsQuery_A
    DNS_STATUS status = __sys_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);

    // Convert ANSI domain to wide for logging
    if (DNS_TraceFlag && pszName) {
        int nameLen = MultiByteToWideChar(CP_ACP, 0, pszName, -1, NULL, 0);
        if (nameLen > 0 && nameLen < 512) {
            WCHAR* wName = (WCHAR*)Dll_AllocTemp(nameLen * sizeof(WCHAR));
            if (wName && MultiByteToWideChar(CP_ACP, 0, pszName, -1, wName, nameLen)) {
                DNS_LogDnsQueryResult(L"DnsQuery_A Passthrough", wName, wType, status, ppQueryResults);
            }
        }
    }

    return status;
}

//---------------------------------------------------------------------------
// DNSAPI_DnsQuery_UTF8
//
// Hook for DnsQuery_UTF8 - same logic as ANSI version but UTF-8 encoded input
//---------------------------------------------------------------------------

_FX DNS_STATUS WINAPI DNSAPI_DnsQuery_UTF8(
    PCSTR           pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNSAPI_DNS_RECORD* ppQueryResults,
    PVOID*          pReserved)
{
    if (DNS_FilterEnabled && pszName) {
        int nameLen = MultiByteToWideChar(CP_UTF8, 0, pszName, -1, NULL, 0);
        if (nameLen > 0 && nameLen < 512) {  // Sanity check
            // Use Dll_Alloc (not Dll_AllocTemp) so string persists for DNS_RECORD
            WCHAR* wName = (WCHAR*)Dll_Alloc(nameLen * sizeof(WCHAR));
            if (wName && MultiByteToWideChar(CP_UTF8, 0, pszName, -1, wName, nameLen)) {
                ULONG path_len = wcslen(wName);
                WCHAR* path_lwr = (WCHAR*)Dll_AllocTemp((path_len + 4) * sizeof(WCHAR));
                wmemcpy(path_lwr, wName, path_len);
                path_lwr[path_len] = L'\0';
                _wcslwr(path_lwr);

                if (DNS_IsExcluded(path_lwr)) {
                    DNS_LogExclusion(path_lwr);
                    Dll_Free(wName);
                    return __sys_DnsQuery_UTF8 ? __sys_DnsQuery_UTF8(pszName, wType, Options, pExtra, ppQueryResults, pReserved)
                                              : __sys_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
                }

                PATTERN* found;
                if (Pattern_MatchPathList(path_lwr, path_len, &DNS_FilterList, NULL, NULL, NULL, &found) > 0) {
                    PVOID* aux = Pattern_Aux(found);
                    if (!aux || !*aux) {
                        Dll_Free(wName);
                        return __sys_DnsQuery_UTF8 ? __sys_DnsQuery_UTF8(pszName, wType, Options, pExtra, ppQueryResults, pReserved)
                                                  : __sys_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
                    }

                    // Certificate required for actual filtering (interception/blocking)
                    extern BOOLEAN DNS_HasValidCertificate;
                    if (!DNS_HasValidCertificate) {
                        // Domain matches filter but no cert - log as passthrough
                        DNS_LogPassthroughAnsi(L"DnsQuery_UTF8", pszName, wType, L"No certificate - forwarding to real DNS");
                        Dll_Free(wName);
                        return __sys_DnsQuery_UTF8 ? __sys_DnsQuery_UTF8(pszName, wType, Options, pExtra, ppQueryResults, pReserved)
                                                  : __sys_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
                    }

                    LIST* pEntries = NULL;
                    DNS_TYPE_FILTER* type_filter = NULL;
                    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);

                    DNS_STATUS status;
                    BOOLEAN passthroughLogged = FALSE;
                    if (DNSAPI_FilterDnsQuery(wName, wType, pEntries, type_filter, DnsCharSetUtf8,
                                              L"DnsQuery_UTF8 Intercepted", ppQueryResults, &status, &passthroughLogged)) {
                        Dll_Free(wName);
                        return status;
                    }

                    // Not filtered by type - call real DNS and return unmodified result
                    // Only log "Monitored" if passthrough wasn't already logged (e.g., for negated types)
                    if (!passthroughLogged) {
                        DNS_LogPassthroughAnsi(L"DnsQuery_UTF8 Monitored", pszName, wType, L"Type not in filter list, returning real DNS result");
                    }
                }

                Dll_Free(wName);
            }
        }
    }

    DNS_STATUS status;
    if (__sys_DnsQuery_UTF8)
        status = __sys_DnsQuery_UTF8(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
    else
        status = __sys_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);

    // Convert UTF8 domain to wide for logging
    if (DNS_TraceFlag && pszName) {
        int nameLen = MultiByteToWideChar(CP_UTF8, 0, pszName, -1, NULL, 0);
        if (nameLen > 0 && nameLen < 512) {
            WCHAR* wName = (WCHAR*)Dll_AllocTemp(nameLen * sizeof(WCHAR));
            if (wName && MultiByteToWideChar(CP_UTF8, 0, pszName, -1, wName, nameLen)) {
                DNS_LogDnsQueryResult(L"DnsQuery_UTF8 Passthrough", wName, wType, status, ppQueryResults);
            }
        }
    }

    return status;
}

//---------------------------------------------------------------------------
// DNSAPI_AsyncCallbackWrapper
//
// Wrapper for async DnsQueryEx callbacks - logs final result before calling
// the original user callback
//---------------------------------------------------------------------------

_FX VOID WINAPI DNSAPI_AsyncCallbackWrapper(
    PVOID                            pQueryContext,
    PDNS_QUERY_RESULT                pQueryResults)
{
    DNSAPI_ASYNC_CONTEXT* ctx = (DNSAPI_ASYNC_CONTEXT*)pQueryContext;
    if (!ctx)
        return;

    // Log the final async result
    DNS_STATUS status = pQueryResults ? pQueryResults->QueryStatus : -1;
    DNS_LogDnsRecordsFromQueryResult(L"DnsQueryEx Async Result", ctx->Domain, ctx->QueryType,
                                     status, pQueryResults ? (PDNSAPI_DNS_RECORD)pQueryResults->pQueryRecords : NULL);

    // Call the original user callback
    if (ctx->OriginalCallback) {
        ctx->OriginalCallback(ctx->OriginalContext, pQueryResults);
    }

    // Free the context
    Dll_Free(ctx);
}

//---------------------------------------------------------------------------
// DNSAPI_RawPassthroughCallbackWrapper
//
// Wrapper for DnsQueryRaw passthrough callbacks - logs final result before
// calling the original user callback
//---------------------------------------------------------------------------

_FX VOID WINAPI DNSAPI_RawPassthroughCallbackWrapper(
    PVOID                            pQueryContext,
    PDNS_QUERY_RAW_RESULT            pQueryResults)
{
    DNSAPI_RAW_PASSTHROUGH_CONTEXT* ctx = (DNSAPI_RAW_PASSTHROUGH_CONTEXT*)pQueryContext;
    if (!ctx)
        return;

    // Log the final async result with IPs if available
    DNS_STATUS status = pQueryResults ? pQueryResults->queryStatus : -1;
    
    // Use queryRecords if Windows parsed them (preferred - structured data)
    // Otherwise fall back to status-only logging
    if (pQueryResults && pQueryResults->queryRecords) {
        DNS_LogDnsRecordsFromQueryResult(L"DnsQueryRaw Passthrough", ctx->Domain, 
            ctx->QueryType, status, (PDNSAPI_DNS_RECORD)pQueryResults->queryRecords);
    } else {
        DNS_LogDnsQueryExStatus(L"DnsQueryRaw Passthrough", ctx->Domain, ctx->QueryType, status);
    }

    // Call the original user callback
    if (ctx->OriginalCallback) {
        ctx->OriginalCallback(ctx->OriginalContext, pQueryResults);
    }

    // Free the context
    Dll_Free(ctx);
}

//---------------------------------------------------------------------------
// DNSAPI_DnsQueryEx
//---------------------------------------------------------------------------


_FX DNS_STATUS DNSAPI_DnsQueryEx(
    PDNS_QUERY_REQUEST  pQueryRequest,
    PDNS_QUERY_RESULT   pQueryResults,
    PDNS_QUERY_CANCEL   pCancelHandle)
{
    if (!pQueryRequest || !pQueryResults) {
        return __sys_DnsQueryEx(pQueryRequest, pQueryResults, pCancelHandle);
    }

    // Validate struct version and determine structure type
    // NOTE: VERSION3 uses DNS_QUERY_REQUEST3 (12 fields) which has the same first 8 fields as VERSION1/2
    // The additional VERSION3 fields (IsNetworkQueryRequired, RequiredNetworkIndex, cCustomServers, pCustomServers)
    // appear AFTER pQueryContext. We conditionally cast to the appropriate structure type.
    ULONG requestVersion = pQueryRequest->Version;
    PDNS_QUERY_REQUEST3 pQueryRequest3 = NULL;  // VERSION3 structure pointer (when Version==3)
    
    if (requestVersion < DNS_QUERY_REQUEST_VERSION1 || requestVersion > DNS_QUERY_REQUEST_VERSION3) {
        DNS_LogQueryExInvalidVersion(requestVersion);
        return __sys_DnsQueryEx(pQueryRequest, pQueryResults, pCancelHandle);
    }

    // Cast to appropriate structure type based on Version
    if (requestVersion == DNS_QUERY_REQUEST_VERSION3) {
        pQueryRequest3 = (PDNS_QUERY_REQUEST3)pQueryRequest;
        DNS_LogQueryExVersion3(pQueryRequest3->IsNetworkQueryRequired, pQueryRequest3->RequiredNetworkIndex,
            pQueryRequest3->cCustomServers, pQueryRequest3->pCustomServers);
    }
    // For VERSION1/2, continue using base PDNS_QUERY_REQUEST (8 fields)

    // Debug: Log entry parameters (including InterfaceIndex)
    ULONG originalInterfaceIndex = 0;
    if (DNS_DebugFlag && pQueryRequest->QueryName) {
        originalInterfaceIndex = (pQueryRequest->Version >= DNS_QUERY_REQUEST_VERSION1) ? pQueryRequest->InterfaceIndex : 0;
        DNS_LogQueryExEntry(pQueryRequest->QueryName, pQueryRequest->QueryType, pQueryRequest->Version,
            pQueryRequest->QueryOptions, originalInterfaceIndex,
            (pQueryRequest->Version >= DNS_QUERY_REQUEST_VERSION1 && pQueryRequest->pQueryCompletionCallback) ? TRUE : FALSE);
    } else {
        originalInterfaceIndex = (pQueryRequest->Version >= DNS_QUERY_REQUEST_VERSION1) ? pQueryRequest->InterfaceIndex : 0;
    }

    // Use centralized filtering logic
    DNSAPI_EX_FILTER_RESULT outcome = { 0 };
    BOOLEAN filterMatched = DNSAPI_FilterDnsQueryExForName(
            pQueryRequest->QueryName,
            pQueryRequest->QueryType,
            pQueryRequest->QueryOptions,
            pQueryResults,
            pCancelHandle,
            NULL,  // No completion callback (synchronous)
            NULL,  // No completion context
            L"DnsQueryEx",
            DnsCharSetUnicode,
            &outcome);
    
    if (filterMatched)
    {
        // Filter handled the request - return the status
        return outcome.Status;
    }
    else if (!outcome.PassthroughLogged && pQueryRequest->QueryName && DNS_DomainMatchesFilter(pQueryRequest->QueryName))
    {
        // Domain matched filter but type not in filter list - log as monitored passthrough
        // Only log if passthrough wasn't already logged (e.g., negated types already logged)
        // This creates parity with DnsQuery_W behavior
        DNS_LogPassthrough(L"DnsQueryEx Monitored", pQueryRequest->QueryName, 
                          pQueryRequest->QueryType, L"Type not in filter list, returning real DNS result");
    }

    // Check if this is an async call (has completion callback)
    // Note: At this point we only handle VERSION1/2 (VERSION3 already returned above)
    PDNS_QUERY_COMPLETION_ROUTINE originalCallback = NULL;
    PVOID originalContext = NULL;
    DNSAPI_ASYNC_CONTEXT* asyncCtx = NULL;

    if (pQueryRequest->Version >= DNS_QUERY_REQUEST_VERSION1 && 
        pQueryRequest->pQueryCompletionCallback) {
        
        originalCallback = pQueryRequest->pQueryCompletionCallback;
        originalContext = pQueryRequest->pQueryContext;

        // Create wrapper context to capture async result
        asyncCtx = (DNSAPI_ASYNC_CONTEXT*)Dll_Alloc(sizeof(DNSAPI_ASYNC_CONTEXT));
        if (asyncCtx) {
            asyncCtx->OriginalCallback = originalCallback;
            asyncCtx->OriginalContext = originalContext;
            asyncCtx->QueryType = pQueryRequest->QueryType;
            
            // Copy domain name for logging
            size_t domain_len = wcslen(pQueryRequest->QueryName);
            if (domain_len >= 255) domain_len = 255;
            wcsncpy(asyncCtx->Domain, pQueryRequest->QueryName, domain_len);
            asyncCtx->Domain[domain_len] = L'\0';

            // Replace callback with our wrapper
            pQueryRequest->pQueryCompletionCallback = DNSAPI_AsyncCallbackWrapper;
            pQueryRequest->pQueryContext = asyncCtx;
        }
    }

    // Sanitize QueryOptions to prevent ERROR_INVALID_PARAMETER from corrupt/unknown flags
    // Windows DnsQueryEx validates flags and rejects unknown bits with error 87
    // Strategy: Preserve ALL flags except the two known problematic ones
    #ifdef DNS_QUERY_ADDRCONFIG
    #undef DNS_QUERY_ADDRCONFIG
    #endif
    #define DNS_QUERY_ADDRCONFIG       0x2000  // Windows 7 and later: Skip query if no matching address config
    #ifdef DNS_QUERY_DUAL_ADDR
    #undef DNS_QUERY_DUAL_ADDR
    #endif
    #define DNS_QUERY_DUAL_ADDR        0x4000  // Windows 7 and later: Query both AAAA and A, map A to AAAA
    
    ULONG64 originalQueryOptions = pQueryRequest->QueryOptions;
    
    // Check for severely corrupt QueryOptions that look like pointer addresses
    // Windows DNS may use upper bits for internal/extended flags (exact meaning undocumented)
    // Only treat as corrupt if it matches canonical x64 user-mode pointer pattern
    // User-mode pointers on x64: 0x00007FF000000000 to 0x00007FFFFFFFFFFF
    // This requires bits 47-63 to be: 0000000000000000111111111111111 (canonical form)
    // Example corrupt value: 0x00007ffd7f9b0e14 (actual pointer - bits 47-63 = 0x0000FFFD)
    // Example valid value:   0x0A00800040026000 (extended flags - bits 47-63 = 0x000A0080)
    
    // Check if bits 47-63 match user-mode canonical pointer pattern (must be 0x0000_7F__ to 0x0000_7FFF)
    ULONG64 bits_47_63 = (originalQueryOptions >> 47) & 0x1FFFF;  // Extract bits 47-63 (17 bits)
    BOOLEAN looksLikePointer = (bits_47_63 >= 0x0FF80 && bits_47_63 <= 0x0FFFF);  // 0x00007F8... to 0x00007FFF...
    
    if (looksLikePointer) {
        DNS_LogQueryExCorruptOptions(originalQueryOptions);
        // Treat pointer-like values as 0 (safest default)
        originalQueryOptions = 0;
        pQueryRequest->QueryOptions = 0;
    }
    
    // Initial sanitization: Just preserve everything as-is
    // We'll selectively remove problematic flags later based on query type
    ULONG64 sanitizedQueryOptions = originalQueryOptions;
    
    // Additional sanitization for VERSION3 queries:
    // - DUAL_ADDR is not accepted for many types (e.g., HTTPS/SVCB), causes ERROR_INVALID_PARAMETER (87)
    // - A queries: Windows rejects DUAL_ADDR combined with ADDRCONFIG; be strict and remove both for A
    // - AAAA queries:
    //   * ADDRCONFIG: Always strip (causes error 9701 on systems without IPv6 addresses)
    //   * DUAL_ADDR: Strip when DnsMapIpv4ToIpv6=n, keep when DnsMapIpv4ToIpv6=y for IPv4-mapped IPv6
    if (requestVersion == DNS_QUERY_REQUEST_VERSION3) {
        if (pQueryRequest->QueryType == DNS_TYPE_A) {
            const ULONG64 PROBLEMATIC_FLAGS = DNS_QUERY_ADDRCONFIG | DNS_QUERY_DUAL_ADDR;
            if (sanitizedQueryOptions & PROBLEMATIC_FLAGS) {
                ULONG64 beforeStrip = sanitizedQueryOptions;
                sanitizedQueryOptions &= ~PROBLEMATIC_FLAGS;
                DNS_LogQueryExStrippedFlags(L"VERSION3 A query - stripped DUAL_ADDR/ADDRCONFIG flags",
                    beforeStrip, sanitizedQueryOptions);
            }
        } else if (pQueryRequest->QueryType == DNS_TYPE_AAAA) {
            // For AAAA queries:
            // - ADDRCONFIG: Always strip (causes error 9701 on systems without IPv6 addresses)
            // - DUAL_ADDR: Strip when DnsMapIpv4ToIpv6=n (native IPv6 only)
            //              Keep when DnsMapIpv4ToIpv6=y (allow IPv4-mapped IPv6 fallback)
            // These are independent flags with different purposes
            
            if (DNS_MapIpv4ToIpv6) {
                // DnsMapIpv4ToIpv6=y: Strip ADDRCONFIG only, keep DUAL_ADDR for IPv4-mapped IPv6
                if (sanitizedQueryOptions & DNS_QUERY_ADDRCONFIG) {
                    ULONG64 beforeStrip = sanitizedQueryOptions;
                    sanitizedQueryOptions &= ~DNS_QUERY_ADDRCONFIG;
                    DNS_LogQueryExStrippedFlags(L"VERSION3 AAAA query - stripped ADDRCONFIG (keeping DUAL_ADDR for DnsMapIpv4ToIpv6=y)",
                        beforeStrip, sanitizedQueryOptions);
                }
            } else {
                // DnsMapIpv4ToIpv6=n: Strip both ADDRCONFIG and DUAL_ADDR
                const ULONG64 PROBLEMATIC_FLAGS = DNS_QUERY_ADDRCONFIG | DNS_QUERY_DUAL_ADDR;
                if (sanitizedQueryOptions & PROBLEMATIC_FLAGS) {
                    ULONG64 beforeStrip = sanitizedQueryOptions;
                    sanitizedQueryOptions &= ~PROBLEMATIC_FLAGS;
                    DNS_LogQueryExStrippedFlags(L"VERSION3 AAAA query - stripped DUAL_ADDR/ADDRCONFIG (DnsMapIpv4ToIpv6=n)",
                        beforeStrip, sanitizedQueryOptions);
                }
            }
        } else {
            // For non-A/AAAA queries, strip DUAL_ADDR unconditionally (it is invalid outside A/AAAA scenarios)
            if (sanitizedQueryOptions & DNS_QUERY_DUAL_ADDR) {
                ULONG64 beforeStrip = sanitizedQueryOptions;
                sanitizedQueryOptions &= ~DNS_QUERY_DUAL_ADDR;
                DNS_LogQueryExStrippedFlags(L"VERSION3 non-A/AAAA query - stripped DUAL_ADDR flag",
                    beforeStrip, sanitizedQueryOptions);
            }
        }
    } else if (requestVersion == DNS_QUERY_REQUEST_VERSION1 || requestVersion == DNS_QUERY_REQUEST_VERSION2) {
        // Apply equivalent sanitization for VERSION1/2 requests
        if (pQueryRequest->QueryType == DNS_TYPE_A) {
            const ULONG64 PROBLEMATIC_FLAGS = DNS_QUERY_ADDRCONFIG | DNS_QUERY_DUAL_ADDR;
            if (sanitizedQueryOptions & PROBLEMATIC_FLAGS) {
                ULONG64 beforeStrip = sanitizedQueryOptions;
                sanitizedQueryOptions &= ~PROBLEMATIC_FLAGS;
                DNS_LogQueryExStrippedFlags(L"VERSION1/2 A query - stripped DUAL_ADDR/ADDRCONFIG flags",
                    beforeStrip, sanitizedQueryOptions);
            }
        } else if (pQueryRequest->QueryType == DNS_TYPE_AAAA) {
            // For AAAA queries:
            // - ADDRCONFIG: Always strip (causes error 9701 on systems without IPv6 addresses)
            // - DUAL_ADDR: Strip when DnsMapIpv4ToIpv6=n (native IPv6 only)
            //              Keep when DnsMapIpv4ToIpv6=y (allow IPv4-mapped IPv6 fallback)
            // These are independent flags with different purposes
            
            if (DNS_MapIpv4ToIpv6) {
                // DnsMapIpv4ToIpv6=y: Strip ADDRCONFIG only, keep DUAL_ADDR for IPv4-mapped IPv6
                if (sanitizedQueryOptions & DNS_QUERY_ADDRCONFIG) {
                    ULONG64 beforeStrip = sanitizedQueryOptions;
                    sanitizedQueryOptions &= ~DNS_QUERY_ADDRCONFIG;
                    DNS_LogQueryExStrippedFlags(L"VERSION1/2 AAAA query - stripped ADDRCONFIG (keeping DUAL_ADDR for DnsMapIpv4ToIpv6=y)",
                        beforeStrip, sanitizedQueryOptions);
                }
            } else {
                // DnsMapIpv4ToIpv6=n: Strip both ADDRCONFIG and DUAL_ADDR
                const ULONG64 PROBLEMATIC_FLAGS = DNS_QUERY_ADDRCONFIG | DNS_QUERY_DUAL_ADDR;
                if (sanitizedQueryOptions & PROBLEMATIC_FLAGS) {
                    ULONG64 beforeStrip = sanitizedQueryOptions;
                    sanitizedQueryOptions &= ~PROBLEMATIC_FLAGS;
                    DNS_LogQueryExStrippedFlags(L"VERSION1/2 AAAA query - stripped DUAL_ADDR/ADDRCONFIG (DnsMapIpv4ToIpv6=n)",
                        beforeStrip, sanitizedQueryOptions);
                }
            }
        } else {
            // For non-A/AAAA queries, strip DUAL_ADDR unconditionally
            if (sanitizedQueryOptions & DNS_QUERY_DUAL_ADDR) {
                ULONG64 beforeStrip = sanitizedQueryOptions;
                sanitizedQueryOptions &= ~DNS_QUERY_DUAL_ADDR;
                DNS_LogQueryExStrippedFlags(L"VERSION1/2 non-A/AAAA query - stripped DUAL_ADDR flag",
                    beforeStrip, sanitizedQueryOptions);
            }
        }
    }
    
    if (sanitizedQueryOptions != originalQueryOptions) {
        DNS_LogQueryExProactiveSanitize(originalQueryOptions, sanitizedQueryOptions);
        pQueryRequest->QueryOptions = sanitizedQueryOptions;
    }

    // No filter match - passthrough to real DNS (preserve caller's InterfaceIndex)
    DNS_STATUS status = __sys_DnsQueryEx(pQueryRequest, pQueryResults, pCancelHandle);
    
    // Restore original QueryOptions after call
    if (sanitizedQueryOptions != originalQueryOptions) {
        pQueryRequest->QueryOptions = originalQueryOptions;
    }

    // Prepare fallback options (computed lazily on first need) to avoid duplication
    ULONG64 fallbackOptions = 0;
    BOOLEAN fallbackPrepared = FALSE;

    // If the call failed with ERROR_INVALID_PARAMETER, retry once without DUAL_ADDR
    // and (for A queries) also without ADDRCONFIG. Use the most conservative flags.
    if (status == ERROR_INVALID_PARAMETER) {
        fallbackOptions = sanitizedQueryOptions;
        ULONG64 beforeFallback = fallbackOptions;
        // Always drop DUAL_ADDR on fallback
        fallbackOptions &= ~DNS_QUERY_DUAL_ADDR;
        // For A queries, also drop ADDRCONFIG
        if (pQueryRequest->QueryType == DNS_TYPE_A) {
            fallbackOptions &= ~DNS_QUERY_ADDRCONFIG;
        }
        fallbackPrepared = TRUE;

        if (fallbackOptions != beforeFallback) {
            DNS_LogQueryExErrorRetryReduction(L"ERROR_INVALID_PARAMETER", beforeFallback, fallbackOptions);
            ULONG64 savedOptions = pQueryRequest->QueryOptions; // currently originalQueryOptions
            pQueryRequest->QueryOptions = fallbackOptions;
            status = __sys_DnsQueryEx(pQueryRequest, pQueryResults, pCancelHandle);
            pQueryRequest->QueryOptions = savedOptions;
        }
    }

    // If still ERROR_INVALID_PARAMETER and caller specified an InterfaceIndex,
    // retry once with InterfaceIndex=0 as a compatibility fallback. Use sanitized/fallback options.
    if (status == ERROR_INVALID_PARAMETER &&
        originalInterfaceIndex != 0 &&
        pQueryRequest->Version >= DNS_QUERY_REQUEST_VERSION1)
    {
        DNS_LogQueryExRetryInterface(originalInterfaceIndex);

        // Prefer the stricter fallbackOptions if prepared; else use sanitizedQueryOptions
        ULONG64 optionsForRetry = fallbackPrepared ? fallbackOptions : sanitizedQueryOptions;

        ULONG savedInterfaceIndex = pQueryRequest->InterfaceIndex;
        ULONG64 savedOptions = pQueryRequest->QueryOptions; // currently originalQueryOptions
        pQueryRequest->InterfaceIndex = 0;
        pQueryRequest->QueryOptions = optionsForRetry;
        status = __sys_DnsQueryEx(pQueryRequest, pQueryResults, pCancelHandle);
        pQueryRequest->QueryOptions = savedOptions;
        pQueryRequest->InterfaceIndex = savedInterfaceIndex;
    }
    
    if (DNS_TraceFlag && pQueryRequest->QueryName) {
        // Debug: Log status and pQueryRecords pointer
        DNS_LogQueryExDebugStatus(status, asyncCtx, pQueryResults,
            pQueryResults ? pQueryResults->pQueryRecords : NULL, pQueryRequest->Version);
        
        if (status == DNS_REQUEST_PENDING && asyncCtx) {
            DNS_LogDnsQueryExStatus(L"DnsQueryEx Passthrough", pQueryRequest->QueryName, 
                                   pQueryRequest->QueryType, status);
        } else if (status == 0 && pQueryResults && pQueryResults->pQueryRecords) {
            // Sync call completed successfully - log with type filtering
            DNS_LogDnsRecords(L"DnsQueryEx Passthrough", pQueryRequest->QueryName, 
                            pQueryRequest->QueryType, (PDNSAPI_DNS_RECORD)pQueryResults->pQueryRecords, L"", TRUE);
        } else {
            // Error or no results - log based on status
            if (status != 0) {
                DNS_LogDnsQueryExStatus(L"DnsQueryEx Passthrough", pQueryRequest->QueryName,
                                       pQueryRequest->QueryType, status);
            } else {
                // Status 0 but no records - empty result (legitimate case)
                DNS_LogSimple(L"DnsQueryEx Passthrough", pQueryRequest->QueryName, 
                             pQueryRequest->QueryType, L" - No records");
            }
        }
    }

    // If async call failed immediately, clean up wrapper context
    if (asyncCtx && status != DNS_REQUEST_PENDING && status != 0) {
        // Restore original callback (call failed, so callback won't be invoked)
        pQueryRequest->pQueryCompletionCallback = originalCallback;
        pQueryRequest->pQueryContext = originalContext;
        Dll_Free(asyncCtx);
    }
    
    return status;
}

//---------------------------------------------------------------------------
// DNS_BuildSimpleQuery
//
// Helper to build a simple DNS query packet from domain name and type
// Used by DnsQueryRaw name/type mode when we need a query packet template
// Returns: Size of constructed packet, or 0 on error
//---------------------------------------------------------------------------

static int DNS_BuildSimpleQuery(
    const WCHAR*    domain,
    USHORT          qtype,
    BYTE*           buffer,
    int             bufferSize)
{
    if (!domain || !buffer || bufferSize < 512)
        return 0;

    // Convert wide domain to ASCII for DNS packet
    char domainA[256];
    int len = WideCharToMultiByte(CP_UTF8, 0, domain, -1, domainA, sizeof(domainA), NULL, NULL);
    if (len <= 0 || len > 255)
        return 0;

    // DNS header (12 bytes)
    BYTE* ptr = buffer;
    if (bufferSize < 512)
        return 0;

    // Transaction ID (random)
    *(USHORT*)ptr = 0x1234;  // Simple fixed ID for template
    ptr += 2;

    // Flags (0x0100 = standard query, recursion desired)
    *(USHORT*)ptr = _htons(0x0100);
    ptr += 2;

    // Question count = 1
    *(USHORT*)ptr = _htons(1);
    ptr += 2;

    // Answer/Authority/Additional counts = 0
    *(USHORT*)ptr = 0;
    ptr += 2;
    *(USHORT*)ptr = 0;
    ptr += 2;
    *(USHORT*)ptr = 0;
    ptr += 2;

    // Encode domain name in DNS label format
    char* namePtr = domainA;
    while (*namePtr) {
        char* labelStart = namePtr;
        int labelLen = 0;
        
        // Find label length (up to next dot or end)
        while (*namePtr && *namePtr != '.') {
            labelLen++;
            namePtr++;
        }

        // Write label length byte
        *ptr++ = (BYTE)labelLen;
        
        // Write label characters
        memcpy(ptr, labelStart, labelLen);
        ptr += labelLen;

        // Skip dot
        if (*namePtr == '.')
            namePtr++;
    }

    // Write terminating zero length byte
    *ptr++ = 0;

    // Write query type (2 bytes)
    *(USHORT*)ptr = _htons(qtype);
    ptr += 2;

    // Write query class (IN = 1, 2 bytes)
    *(USHORT*)ptr = _htons(1);
    ptr += 2;

    return (int)(ptr - buffer);
}

//---------------------------------------------------------------------------
// DNSAPI_DnsQueryRaw
//
// Hook for DnsQueryRaw - filters DNS queries using raw DNS packet format
// This API uses raw DNS wire format (RFC 1035) for both request and response
// Windows 10+ only - returns DNS_ERROR_CALL_NOT_IMPLEMENTED on older systems
//---------------------------------------------------------------------------

_FX DNS_STATUS WINAPI DNSAPI_DnsQueryRaw(
    PDNS_QUERY_RAW_REQUEST  pQueryRequest,
    PDNS_QUERY_RAW_CANCEL   pCancelHandle)
{
    if (!pQueryRequest) {
        return __sys_DnsQueryRaw(pQueryRequest, pCancelHandle);
    }

    // Parse domain name and query type
    // DnsQueryRaw supports two modes:
    // 1. Raw Packet Mode: dnsQueryRaw + dnsQueryRawSize (binary packet)
    // 2. Name/Type Mode: dnsQueryName + dnsQueryType (Windows builds packet)
    WCHAR domain[256] = { 0 };
    USHORT qtype = 0;
    BOOLEAN parsed = FALSE;
    
    if (DNS_FilterEnabled) {
        // Try Name/Type Mode first (simpler)
        if (pQueryRequest->dnsQueryName && pQueryRequest->dnsQueryType) {
            size_t nameLen = wcslen(pQueryRequest->dnsQueryName);
            if (nameLen > 0 && nameLen < 256) {
                wcscpy(domain, pQueryRequest->dnsQueryName);
                qtype = pQueryRequest->dnsQueryType;
                parsed = TRUE;
            }
        }
        // Try Raw Packet Mode
        else if (pQueryRequest->dnsQueryRaw && pQueryRequest->dnsQueryRawSize > 0) {
            if (Socket_ParseDnsQuery(pQueryRequest->dnsQueryRaw, pQueryRequest->dnsQueryRawSize, 
                                     domain, 256, &qtype)) {
                parsed = TRUE;
            }
        }
        
        if (parsed) {
            
            // Check if domain is excluded
            size_t domain_len = wcslen(domain);
            if (domain_len > 0) {
                WCHAR* domain_lwr = (WCHAR*)Dll_AllocTemp((domain_len + 4) * sizeof(WCHAR));
                if (domain_lwr) {
                    wmemcpy(domain_lwr, domain, domain_len);
                    domain_lwr[domain_len] = L'\0';
                    _wcslwr(domain_lwr);

                    if (DNS_IsExcluded(domain_lwr)) {
                        DNS_LogExclusion(domain_lwr);
                        Dll_Free(domain_lwr);
                        return __sys_DnsQueryRaw(pQueryRequest, pCancelHandle);
                    }

                    // Check if domain matches filter
                    PATTERN* found = NULL;
                    if (Pattern_MatchPathList(domain_lwr, (ULONG)domain_len, &DNS_FilterList, 
                                             NULL, NULL, NULL, &found) > 0) {
                        PVOID* aux = Pattern_Aux(found);
                        if (aux && *aux) {
                            // Certificate required for actual filtering (interception/blocking)
                            extern BOOLEAN DNS_HasValidCertificate;
                            if (!DNS_HasValidCertificate) {
                                // Domain matches filter but no cert - log as passthrough
                                DNS_LogPassthrough(L"DnsQueryRaw", domain, qtype, L"No certificate - forwarding to real DNS");
                                Dll_Free(domain_lwr);
                                
                                // Wrap callback to log completion status
                                if (pQueryRequest->queryCompletionCallback) {
                                    DNSAPI_RAW_PASSTHROUGH_CONTEXT* ctx = (DNSAPI_RAW_PASSTHROUGH_CONTEXT*)
                                        Dll_Alloc(sizeof(DNSAPI_RAW_PASSTHROUGH_CONTEXT));
                                    if (ctx) {
                                        ctx->OriginalCallback = pQueryRequest->queryCompletionCallback;
                                        ctx->OriginalContext = pQueryRequest->queryContext;
                                        wcscpy(ctx->Domain, domain);
                                        ctx->QueryType = qtype;
                                        
                                        // Replace with our wrapper
                                        pQueryRequest->queryCompletionCallback = DNSAPI_RawPassthroughCallbackWrapper;
                                        pQueryRequest->queryContext = ctx;
                                    }
                                }
                                
                                return __sys_DnsQueryRaw(pQueryRequest, pCancelHandle);
                            }

                            LIST* pEntries = NULL;
                            DNS_TYPE_FILTER* type_filter = NULL;
                            DNS_ExtractFilterAux(aux, &pEntries, &type_filter);

                            // Block mode (no IPs) - block ALL types
                            if (!pEntries) {
                                DNS_LogBlocked(L"DnsQueryRaw Blocked", domain, qtype, 
                                             L"Domain blocked (NXDOMAIN)");
                                Dll_Free(domain_lwr);
                                return DNS_ERROR_RCODE_NAME_ERROR;
                            }

                            // Check if type is negated (explicit passthrough)
                            BOOLEAN is_negated = DNS_IsTypeNegated(type_filter, qtype);
                            
                            if (is_negated) {
                                // Negated types always passthrough - use consistent logging format
                                DNS_LogTypeFilterPassthrough(L"DnsQueryRaw", domain, qtype, L"negated");
                                Dll_Free(domain_lwr);
                                
                                // Wrap callback to log completion status
                                if (pQueryRequest->queryCompletionCallback) {
                                    DNSAPI_RAW_PASSTHROUGH_CONTEXT* ctx = (DNSAPI_RAW_PASSTHROUGH_CONTEXT*)
                                        Dll_Alloc(sizeof(DNSAPI_RAW_PASSTHROUGH_CONTEXT));
                                    if (ctx) {
                                        ctx->OriginalCallback = pQueryRequest->queryCompletionCallback;
                                        ctx->OriginalContext = pQueryRequest->queryContext;
                                        wcscpy(ctx->Domain, domain);
                                        ctx->QueryType = qtype;
                                        
                                        // Replace with our wrapper
                                        pQueryRequest->queryCompletionCallback = DNSAPI_RawPassthroughCallbackWrapper;
                                        pQueryRequest->queryContext = ctx;
                                    }
                                }
                                
                                return __sys_DnsQueryRaw(pQueryRequest, pCancelHandle);
                            }

                            // Check if type is in filter list (non-negated)
                            BOOLEAN should_filter = DNS_IsTypeInFilterList(type_filter, qtype);
                            
                            if (!should_filter) {
                                // Type not in filter list - passthrough to real DNS (consistent with DnsQueryEx)
                                DNS_LogPassthrough(L"DnsQueryRaw Passthrough", domain, qtype, L"Type not in filter list, forwarding to real DNS");
                                Dll_Free(domain_lwr);
                                
                                // Wrap callback to log completion status
                                if (pQueryRequest->queryCompletionCallback) {
                                    DNSAPI_RAW_PASSTHROUGH_CONTEXT* ctx = (DNSAPI_RAW_PASSTHROUGH_CONTEXT*)
                                        Dll_Alloc(sizeof(DNSAPI_RAW_PASSTHROUGH_CONTEXT));
                                    if (ctx) {
                                        ctx->OriginalCallback = pQueryRequest->queryCompletionCallback;
                                        ctx->OriginalContext = pQueryRequest->queryContext;
                                        wcscpy(ctx->Domain, domain);
                                        ctx->QueryType = qtype;
                                        
                                        // Replace with our wrapper
                                        pQueryRequest->queryCompletionCallback = DNSAPI_RawPassthroughCallbackWrapper;
                                        pQueryRequest->queryContext = ctx;
                                    }
                                }
                                
                                return __sys_DnsQueryRaw(pQueryRequest, pCancelHandle);
                            }

                            // Check if we can synthesize or should block
                            if (DNS_CanSynthesizeResponse(qtype)) {
                                // Build raw DNS response packet
                                BYTE response[512];
                                BYTE tempQuery[512];
                                const BYTE* queryPtr = NULL;
                                int queryLen = 0;
                                int response_len = 0;

                                // Get query packet for response building
                                if (pQueryRequest->dnsQueryRaw && pQueryRequest->dnsQueryRawSize > 0) {
                                    // Raw packet mode - use the provided query
                                    queryPtr = pQueryRequest->dnsQueryRaw;
                                    queryLen = pQueryRequest->dnsQueryRawSize;
                                } else {
                                    // Name/type mode - build a temporary query packet
                                    queryLen = DNS_BuildSimpleQuery(domain, qtype, tempQuery, sizeof(tempQuery));
                                    if (queryLen > 0) {
                                        queryPtr = tempQuery;
                                    }
                                }

                                if (queryPtr && queryLen > 0) {
                                    response_len = Socket_BuildDnsResponse(
                                        queryPtr,
                                        queryLen,
                                        pEntries,
                                        FALSE,  // not block mode
                                        response,
                                        sizeof(response),
                                        qtype,
                                        type_filter);
                                }

                                if (response_len > 0) {
                                    // Allocate completion callback structure
                                    if (pQueryRequest->queryCompletionCallback) {
                                        // Async mode - need to allocate result and call callback
                                        PDNS_QUERY_RAW_RESULT pResult = (PDNS_QUERY_RAW_RESULT)
                                            LocalAlloc(LPTR, sizeof(DNS_QUERY_RAW_RESULT));
                                        
                                        if (pResult) {
                                            pResult->version = DNS_QUERY_RAW_RESULTS_VERSION1;
                                            pResult->queryStatus = 0;
                                            pResult->queryOptions = pQueryRequest->queryOptions;
                                            pResult->queryRawOptions = pQueryRequest->queryRawOptions;
                                            
                                            // Allocate and copy response packet
                                            pResult->queryRawResponse = (BYTE*)LocalAlloc(LPTR, response_len);
                                            if (pResult->queryRawResponse) {
                                                pResult->queryRawResponseSize = response_len;
                                                memcpy(pResult->queryRawResponse, response, response_len);
                                                
                                                DNS_LogIntercepted(L"DnsQueryRaw Intercepted", 
                                                                 domain, qtype, pEntries);
                                                
                                                // Call completion callback
                                                pQueryRequest->queryCompletionCallback(
                                                    pQueryRequest->queryContext,
                                                    pResult);
                                                
                                                Dll_Free(domain_lwr);
                                                return DNS_REQUEST_PENDING;
                                            }
                                            LocalFree(pResult);
                                        }
                                    }
                                    
                                    // Synchronous mode - but DnsQueryRaw doesn't support sync return
                                    // Always returns via callback, so we shouldn't reach here
                                    DNS_LogIntercepted(L"DnsQueryRaw Intercepted", domain, qtype, pEntries);
                                    Dll_Free(domain_lwr);
                                    return DNS_REQUEST_PENDING;
                                }
                            }
                            
                            // Cannot synthesize - return NOERROR + NODATA (domain exists, no records of this type)
                            // This is consistent with DnsQuery behavior for unsupported types
                            DNS_LogInterceptedNoData(L"DnsQueryRaw Intercepted", domain, qtype,
                                         L"No records for this type (NODATA)");
                            Dll_Free(domain_lwr);
                            
                            // Build NODATA response using the same mechanism
                            BYTE nodata_response[512];
                            BYTE tempQuery[512];
                            const BYTE* queryPtr = NULL;
                            int queryLen = 0;
                            
                            // Get query packet for NODATA response building
                            if (pQueryRequest->dnsQueryRaw && pQueryRequest->dnsQueryRawSize > 0) {
                                queryPtr = pQueryRequest->dnsQueryRaw;
                                queryLen = pQueryRequest->dnsQueryRawSize;
                            } else {
                                queryLen = DNS_BuildSimpleQuery(domain, qtype, tempQuery, sizeof(tempQuery));
                                if (queryLen > 0) {
                                    queryPtr = tempQuery;
                                }
                            }
                            
                            if (queryPtr && queryLen >= 12) {
                                // Build NODATA response by modifying the query header
                                // DNS header is 12 bytes: ID(2) + Flags(2) + QD(2) + AN(2) + NS(2) + AR(2)
                                memcpy(nodata_response, queryPtr, queryLen < 512 ? queryLen : 512);
                                
                                // Set response flags: QR=1 (response), OPCODE=0, AA=1, TC=0, RD=1, RA=1, RCODE=0 (NOERROR)
                                // Flags at offset 2-3: 0x8180 = 1000 0001 1000 0000 (big-endian)
                                nodata_response[2] = 0x81;  // QR=1, OPCODE=0, AA=1, TC=0, RD=1
                                nodata_response[3] = 0x80;  // RA=1, Z=0, RCODE=0 (NOERROR)
                                
                                // Set answer counts to 0 (NODATA means no answers)
                                nodata_response[6] = 0;   // ANCOUNT high byte
                                nodata_response[7] = 0;   // ANCOUNT low byte
                                nodata_response[8] = 0;   // NSCOUNT high byte
                                nodata_response[9] = 0;   // NSCOUNT low byte
                                nodata_response[10] = 0;  // ARCOUNT high byte
                                nodata_response[11] = 0;  // ARCOUNT low byte
                                
                                // Return via callback
                                if (pQueryRequest->queryCompletionCallback) {
                                    PDNS_QUERY_RAW_RESULT pResult = (PDNS_QUERY_RAW_RESULT)
                                        LocalAlloc(LPTR, sizeof(DNS_QUERY_RAW_RESULT));
                                    if (pResult) {
                                        pResult->version = DNS_QUERY_RAW_RESULTS_VERSION1;
                                        pResult->queryStatus = 0;  // NOERROR
                                        pResult->queryOptions = pQueryRequest->queryOptions;
                                        pResult->queryRawOptions = pQueryRequest->queryRawOptions;
                                        
                                        pResult->queryRawResponse = (BYTE*)LocalAlloc(LPTR, queryLen);
                                        if (pResult->queryRawResponse) {
                                            pResult->queryRawResponseSize = queryLen;
                                            memcpy(pResult->queryRawResponse, nodata_response, queryLen);
                                            
                                            pQueryRequest->queryCompletionCallback(
                                                pQueryRequest->queryContext, pResult);
                                            return DNS_REQUEST_PENDING;
                                        }
                                        LocalFree(pResult);
                                    }
                                }
                            }
                            
                            // Fallback: return status indicating no data (shouldn't reach here normally)
                            return 0;  // DNS_RCODE_NOERROR
                        }
                    }
                    
                    Dll_Free(domain_lwr);
                }
            }
        }
    }

    // No filter match - passthrough
    DNS_LogSimple(L"DnsQueryRaw Passthrough", domain, qtype, NULL);
    
    // Wrap callback to log completion status
    if (pQueryRequest->queryCompletionCallback) {
        DNSAPI_RAW_PASSTHROUGH_CONTEXT* ctx = (DNSAPI_RAW_PASSTHROUGH_CONTEXT*)
            Dll_Alloc(sizeof(DNSAPI_RAW_PASSTHROUGH_CONTEXT));
        if (ctx) {
            ctx->OriginalCallback = pQueryRequest->queryCompletionCallback;
            ctx->OriginalContext = pQueryRequest->queryContext;
            wcscpy(ctx->Domain, domain);
            ctx->QueryType = qtype;
            
            // Replace with our wrapper
            pQueryRequest->queryCompletionCallback = DNSAPI_RawPassthroughCallbackWrapper;
            pQueryRequest->queryContext = ctx;
        }
    }
    
    DNS_STATUS status = __sys_DnsQueryRaw(pQueryRequest, pCancelHandle);
    return status;
}

//---------------------------------------------------------------------------
// DNSAPI_DnsQueryRawResultFree
//
// Hook for DnsQueryRawResultFree - frees results from DnsQueryRaw
//---------------------------------------------------------------------------

_FX VOID WINAPI DNSAPI_DnsQueryRawResultFree(
    PDNS_QUERY_RAW_RESULT   pQueryResults)
{
    if (!pQueryResults)
        return;

    DNS_LogDebugDnsApiRawResultFree(pQueryResults);

    // Free the raw response buffer if present
    if (pQueryResults->queryRawResponse) {
        LocalFree(pQueryResults->queryRawResponse);
    }

    // Free DNS_RECORD list if present (our synthesized records have marker)
    if (pQueryResults->queryRecords) {
        DNSAPI_DnsRecordListFree(pQueryResults->queryRecords, 1);  // DnsFreeRecordList
    }

    // Free the result structure itself
    LocalFree(pQueryResults);
}

//---------------------------------------------------------------------------
// DNSAPI_DnsRecordListFree
//
// Hook for DnsRecordListFree - ensures proper cleanup of filtered records
// Detects our synthesized records (marked with 0x53424945 'SBIE' in dwReserved)
// and frees them with LocalFree instead of calling dnsapi.dll's internal free
//---------------------------------------------------------------------------

_FX VOID WINAPI DNSAPI_DnsRecordListFree(
    PVOID           pRecordList,
    INT             FreeType)
{
    if (!pRecordList)
        return;

    PDNSAPI_DNS_RECORD pRecord = (PDNSAPI_DNS_RECORD)pRecordList;
    
    // Check if this is our synthesized record by checking the magic marker
    // Our records have dwReserved = 0x53424945 ('SBIE')
    if (pRecord->dwReserved == 0x53424945) {
        // This is our synthesized record - free with LocalFree
        DNS_LogDebugDnsApiRecordFree(pRecordList, FreeType, TRUE);

        // Free all records in the linked list
        while (pRecord) {
            PDNSAPI_DNS_RECORD pNext = pRecord->pNext;
            
            // Free the domain name string
            if (pRecord->pName)
                LocalFree(pRecord->pName);
            
            // Free the record structure itself
            LocalFree(pRecord);
            
            pRecord = pNext;
        }
        return;
    }

    // Not our record - pass to real DnsRecordListFree
    DNS_LogDebugDnsApiRecordFree(pRecordList, FreeType, FALSE);

    __sys_DnsRecordListFree(pRecordList, FreeType);
}

//---------------------------------------------------------------------------
// DNSAPI_DnsCancelQuery
//
// Hook for DnsCancelQuery - allows cancellation of pending async queries
// This is a simple passthrough as cancellation doesn't need filtering
//---------------------------------------------------------------------------

_FX DNS_STATUS WINAPI DNSAPI_DnsCancelQuery(
    PDNS_QUERY_CANCEL       pCancelHandle)
{
    if (!__sys_DnsCancelQuery) {
        return DNS_ERROR_NOT_UNIQUE;  // Should not happen
    }

    // Simple passthrough - cancellation doesn't need filtering
    return __sys_DnsCancelQuery(pCancelHandle);
}

