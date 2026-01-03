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
// DNS Filtering / Encrypted DNS
//
// This module applies domain-based DNS policy for sandboxed processes.
// Multiple interception layers feed a shared pattern engine (NetworkDnsFilter)
// and can optionally use encrypted DNS for passthrough resolution.
//
// Interception layers:
//   1) GetAddrInfo hooks (ws2_32.dll)
//      - getaddrinfo / GetAddrInfoW / GetAddrInfoExW
//
//   2) WSALookupService hooks (ws2_32.dll)
//      - WSALookupServiceBeginW/NextW/End
//      - Returns: WSAQUERYSETW with HOSTENT BLOB (HOSTENT uses relative pointers)
//
//   3) DnsApi hooks (dnsapi.dll)
//      - DnsQuery_A/W/UTF8, DnsQueryEx, DnsQueryRaw (+ free/cancel helpers)
//
//   4) Raw socket DNS filtering (ws2_32.dll)
//      - Implemented in socket_hooks.c: filters direct DNS packets (UDP/TCP port 53)
//      - Controlled by: FilterRawDns (hook enable), policy is still driven by
//        NetworkDnsFilter patterns.
//
// Core policy settings (Sandboxie.ini):
//   NetworkDnsFilter=[process,]domain[:ip1;ip2;...]
//     - If no IPs: block mode (NXDOMAIN)
//     - With IPs: synthesize answers from configured IP list.
//       Only A/AAAA/ANY can be synthesized; other RR types return NOERROR+NODATA.
//
//   NetworkDnsFilterType=[process,]domain:type1;type2;...  |  [process,]domain:*
//     - Optional type gating for filter-mode (domain:ip). Supports negation '!'.
//     - If configured: unlisted types pass through to real DNS; listed but
//       unsupported types return NOERROR+NODATA.
//     - No effect in block-mode.
//
//   NetworkDnsFilterExclude=[process,][sys|enc:]pat1;pat2;...
//     - Higher priority allowlist. Excluded domains bypass NetworkDnsFilter.
//     - Optional resolution mode per pattern:
//         * sys: resolve via system DNS
//         * enc: resolve via EncryptedDnsServer (if configured)
//
// Hook enablement / behavior toggles:
//   FilterDnsApi=[process,]y|n     (default: y)
//   FilterRawDns=[process,]y|n     (default: n)
//   FilterWinHttp=[process,]y|n    (default: n)
//   FilterMsQuic=[process,]y|n[:block|allow] (default: n)
//   DnsMapIpv4ToIpv6=[process,]y|n (default: n)
//   DnsTrace=y|n                   (logging)
//   DnsDebug=[process,]y|n         (verbose logging)
//   SuppressDnsLog=[process,]y|n   (default: y)
//
// Encrypted DNS:
//   EncryptedDnsServer=[process,]url[;url2;...]
//     - Encrypted resolver(s) for passthrough/excluded domains.
//     - Requires a valid supporter certificate (DNS_HasValidCertificate).
//     - Supports multiple config lines and per-process overrides.
//     - URL schemes and advanced options are parsed by dns_encrypted.c/dns_doh.c
//       (e.g. https:// / httpx://, QUIC/AUTO modes, and query-string options).
//
// Naming Convention:
//    WSA_*    - WSALookupService API specific functions
//    DNSAPI_* - DnsApi specific functions  
//    Socket_* - Raw socket interception functions (in socket_hooks.c)
//    DNS_*    - Shared infrastructure (filter lists, IP entries, config)
//
// Modular File Organization:
//    dns_filter.c/h     - Shared infrastructure + DNSAPI/WSA hooks (this file)
//    winhttp_filter.c/h - WinHTTP connection filtering (FilterWinHttp)
//    winhttp_defs.h     - WinHTTP function pointer types and constants
//    dns_doh.c/h        - DNS-over-HTTPS (DoH) client implementation
//    dns_doq.c/h        - DNS-over-QUIC (DoQ) client implementation
//    dns_encrypted.c/h  - Shared encrypted DNS infrastructure
//    dns_logging.c/h    - Centralized DNS logging
//    dns_wire.h         - DNS wire format parsing utilities
//    msquic_filter.c/h  - MsQuic (QUIC/HTTP3) connection filtering
//    socket_hooks.c/h   - Raw socket DNS interception (FilterRawDns)
//    dnsapi_defs.h      - DnsApi type definitions
//    wsa_defs.h         - WSA type definitions
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
#include <winhttp.h>
#include "common/my_wsa.h"
#include "common/netfw.h"
#include "common/map.h"
#include "wsa_defs.h"
#include "dnsapi_defs.h"

// Additional getaddrinfo structures not defined in wsa_defs.h
// (wsa_defs.h already defines ADDRINFOW, PADDRINFOW, P_GetAddrInfoW, P_FreeAddrInfoW)

#ifndef WSAAPI
#define WSAAPI WINAPI
#endif

// Magic marker for our ADDRINFOW allocations
// We set bit 31 of ai_flags to mark structures allocated from our private heap
// This allows free functions to distinguish our allocations from system allocations
// Standard ai_flags values use lower bits (AI_PASSIVE=0x01, AI_CANONNAME=0x02, etc.)
#define AI_SBIE_MARKER  0x80000000

// ANSI version of addrinfo (not in wsa_defs.h)
typedef struct addrinfo {
    int                 ai_flags;
    int                 ai_family;
    int                 ai_socktype;
    int                 ai_protocol;
    size_t              ai_addrlen;
    char*               ai_canonname;
    struct sockaddr*    ai_addr;
    struct addrinfo*    ai_next;
} ADDRINFOA, *PADDRINFOA;

// Extended addrinfo for GetAddrInfoExW (not in wsa_defs.h)
typedef struct addrinfoexW {
    int                 ai_flags;
    int                 ai_family;
    int                 ai_socktype;
    int                 ai_protocol;
    size_t              ai_addrlen;
    PWSTR               ai_canonname;
    struct sockaddr*    ai_addr;
    void*               ai_blob;
    size_t              ai_bloblen;
    LPGUID              ai_provider;
    struct addrinfoexW* ai_next;
} ADDRINFOEXW, *PADDRINFOEXW, *LPADDRINFOEXW;

// Completion routine for async GetAddrInfoExW
typedef void (CALLBACK *LPLOOKUPSERVICE_COMPLETION_ROUTINE)(
    DWORD    dwError,
    DWORD    dwBytes,
    LPOVERLAPPED lpOverlapped);

// WSA error codes
#ifndef WSAHOST_NOT_FOUND
#define WSAHOST_NOT_FOUND    11001
#endif
#ifndef WSANO_DATA
#define WSANO_DATA           11004
#endif
#ifndef WSA_NOT_ENOUGH_MEMORY
#define WSA_NOT_ENOUGH_MEMORY 8
#endif

#include "socket_hooks.h"
#include "dns_filter.h"
#include "dns_filter_util.h"
#include "dns_logging.h"
#include "dns_doh.h"  // Includes dns_encrypted.h for EncryptedDns_* and ENCRYPTED_DNS_* types
#include "dns_wire.h" // For DNS_FlipHeaderToHost
#include "winhttp_filter.h"  // For WinHttp_Init
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

// getaddrinfo API hooks (ws2_32.dll)
static INT WSAAPI WSA_getaddrinfo(
    PCSTR           pNodeName,
    PCSTR           pServiceName,
    const ADDRINFOA* pHints,
    PADDRINFOA*     ppResult);

static INT WSAAPI WSA_GetAddrInfoW(
    PCWSTR          pNodeName,
    PCWSTR          pServiceName,
    const ADDRINFOW* pHints,
    PADDRINFOW*     ppResult);

static INT WSAAPI WSA_GetAddrInfoExW(
    PCWSTR          pName,
    PCWSTR          pServiceName,
    DWORD           dwNameSpace,
    LPGUID          lpNspId,
    const ADDRINFOEXW* hints,
    PADDRINFOEXW*   ppResult,
    struct timeval* timeout,
    LPOVERLAPPED    lpOverlapped,
    LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
    LPHANDLE        lpHandle);

static VOID WSAAPI WSA_freeaddrinfo(
    PADDRINFOA      pAddrInfo);

static VOID WSAAPI WSA_FreeAddrInfoW(
    PADDRINFOW      pAddrInfo);

static VOID WSAAPI WSA_FreeAddrInfoExW(
    PADDRINFOEXW    pAddrInfoEx);

// Helper function to check if an ADDRINFO structure is ours
// Returns TRUE if it has our magic marker (AI_SBIE_MARKER)
static BOOLEAN DNS_IsOurAddrInfo(int ai_flags);

// DNS Type Filter Helper Functions (internal use only)
static BOOLEAN DNS_ParseTypeName(const WCHAR* name, USHORT* type_out, BOOLEAN* is_negated);

// EncDns helper functions (forward declarations)
static BOOLEAN DNS_TryDoHQuery(const WCHAR* domain, USHORT qtype, LIST* pListOut, DOH_RESULT* pFullResult);
static void DNS_FreeIPEntryList(LIST* pList);
static BOOLEAN DNS_DoHQueryForFamily(const WCHAR* domain, int family, LIST* pListOut, ENCRYPTED_DNS_MODE* protocolUsedOut);
static int DNS_DoHBuildWSALookup(LPWSAQUERYSETW lpqsRestrictions, LPHANDLE lphLookup);
static BOOLEAN WSA_ConvertAddrInfoWToEx(PADDRINFOW pResultW, PADDRINFOEXW* ppResultEx);
static BOOLEAN DNS_DoHQueryForGetAddrInfoExW(PCWSTR pName, int family, const ADDRINFOEXW* hints, PCWSTR pServiceName, PADDRINFOEXW* ppResult, ENCRYPTED_DNS_MODE* protocolUsedOut);

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
static P_DnsExtractRecordsFromMessage_W __sys_DnsExtractRecordsFromMessage_W = NULL;

// Common function pointer type for narrow (ANSI/UTF-8) DnsQuery_* system calls.
typedef DNS_STATUS (WINAPI *DNSAPI_P_DnsQuery_NarrowSys)(
    PCSTR               pszName,
    WORD                wType,
    DWORD               Options,
    PVOID               pExtra,
    PDNSAPI_DNS_RECORD* ppQueryResults,
    PVOID*              pReserved);

// getaddrinfo API function pointer types (ws2_32.dll)
// Note: P_GetAddrInfoW and P_FreeAddrInfoW are already defined in wsa_defs.h

typedef INT (WSAAPI *P_getaddrinfo)(
    PCSTR           pNodeName,
    PCSTR           pServiceName,
    const ADDRINFOA* pHints,
    PADDRINFOA*     ppResult);

typedef INT (WSAAPI *P_GetAddrInfoExW)(
    PCWSTR          pName,
    PCWSTR          pServiceName,
    DWORD           dwNameSpace,
    LPGUID          lpNspId,
    const ADDRINFOEXW* hints,
    PADDRINFOEXW*   ppResult,
    struct timeval* timeout,
    LPOVERLAPPED    lpOverlapped,
    LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
    LPHANDLE        lpHandle);

typedef VOID (WSAAPI *P_freeaddrinfo)(PADDRINFOA pAddrInfo);
typedef VOID (WSAAPI *P_FreeAddrInfoExW)(PADDRINFOEXW pAddrInfoEx);

// WinHTTP function pointer type (winhttp.dll)
typedef HINTERNET (WINAPI *P_WinHttpConnect)(
    HINTERNET hSession,
    LPCWSTR pswzServerName,
    INTERNET_PORT nServerPort,
    DWORD dwReserved);

static P_getaddrinfo              __sys_getaddrinfo              = NULL;
static P_GetAddrInfoW             __sys_GetAddrInfoW             = NULL;
static P_GetAddrInfoExW           __sys_GetAddrInfoExW           = NULL;
static P_freeaddrinfo             __sys_freeaddrinfo             = NULL;
static P_FreeAddrInfoW            __sys_FreeAddrInfoW            = NULL;
static P_FreeAddrInfoExW          __sys_FreeAddrInfoExW          = NULL;
static P_WSASetLastError          __sys_WSASetLastError          = NULL;
static P_WinHttpConnect           __sys_WinHttpConnect           = NULL;

// Re-entrancy check helper: uses THREAD_DATA instead of __declspec(thread)
// to avoid TLS linker issues in this DLL project
static BOOLEAN WSA_GetInGetAddrInfoEx(void)
{
    THREAD_DATA *data = Dll_GetTlsData(NULL);
    return data ? data->dns_in_getaddrinfoex : FALSE;
}

static void WSA_SetInGetAddrInfoEx(BOOLEAN value)
{
    THREAD_DATA *data = Dll_GetTlsData(NULL);
    if (data)
        data->dns_in_getaddrinfoex = value;
}

static INT WSA_CallSysGetAddrInfoExW_WithReentrancyFlag(
    PCWSTR          pName,
    PCWSTR          pServiceName,
    DWORD           dwNameSpace,
    LPGUID          lpNspId,
    const ADDRINFOEXW* hints,
    PADDRINFOEXW*   ppResult,
    struct timeval* timeout,
    LPOVERLAPPED    lpOverlapped,
    LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
    LPHANDLE        lpHandle)
{
    WSA_SetInGetAddrInfoEx(TRUE);
    INT result = __sys_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                      hints, ppResult, timeout, lpOverlapped,
                                      lpCompletionRoutine, lpHandle);
    WSA_SetInGetAddrInfoEx(FALSE);
    return result;
}

// Magic marker for our synthesized ADDRINFO structures
// Used by FreeAddrInfo to identify and properly free our allocations
#define ADDRINFO_SBIE_MAGIC 0x53424945  // 'SBIE'

typedef struct _DNSAPI_EX_FILTER_RESULT {
    DNS_STATUS Status;
    BOOLEAN    IsAsync;
    BOOLEAN    PassthroughLogged;        // TRUE if passthrough was already logged (negated type)
    DNS_PASSTHROUGH_REASON PassthroughReason;  // Reason for passthrough (for logging)
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
    DNS_PASSTHROUGH_REASON            PassthroughReason;  // Reason for passthrough (for logging)
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
static BOOLEAN DNS_WinHttpHookEnabled = FALSE;  // FilterWinHttp setting (default: disabled)
BOOLEAN    DNS_MapIpv4ToIpv6 = FALSE;         // DnsMapIpv4ToIpv6 setting (default: disabled)
BOOLEAN    DNS_HasValidCertificate = FALSE;  // Certificate validity for NetworkDnsFilter/FilterRawDns (exported)


#define MAX_DNS_FILTER_EX 32
typedef struct _DNS_EXCLUSION_LIST {
    WCHAR* image_name; // NULL for global
    WCHAR* patterns[MAX_DNS_FILTER_EX];
    BYTE   modes[MAX_DNS_FILTER_EX]; // DNS_EXCLUDE_RESOLVE_MODE per pattern
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
static BOOLEAN DNS_ListMatchesDomain(const DNS_EXCLUSION_LIST* excl, const WCHAR* domain, DNS_EXCLUDE_RESOLVE_MODE* pModeOut);
static PATTERN* DNS_FindPatternInFilterList(const WCHAR* domain, ULONG level);
static BOOLEAN DNS_DomainMatchesFilter(const WCHAR* domain);
static BOOLEAN DNS_LoadFilterEntries(void);

static BOOLEAN DNS_IsExcludedEx(const WCHAR* domain, DNS_EXCLUDE_RESOLVE_MODE* pModeOut);

static void DNS_FormatEncDnsSourceTag(WCHAR* outTag, size_t outTagCch, const WCHAR* apiName, ENCRYPTED_DNS_MODE protocolUsed);

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
static CRITICAL_SECTION WSA_LookupMap_CritSec;
static BOOLEAN WSA_LookupMap_Initialized = FALSE;

// Re-entrancy detection counter for system's getaddrinfo (ANSI)
// When system calls getaddrinfo (ANSI), it internally calls GetAddrInfoW
// We need to passthrough in this case to avoid returning our private heap allocations
// that the system will try to free during ANSI conversion
// Using volatile to ensure thread-safe increments are visible
static volatile LONG WSA_SystemGetAddrInfoDepth = 0;

// Private heap for DNS filter allocations
// Using a private heap allows us to distinguish OUR allocations from system allocations
// HeapSize on this heap returns -1 for system allocations (which use process heap)
static HANDLE g_DnsFilterHeap = NULL;

static HANDLE DNS_GetFilterHeap(void)
{
    HANDLE hHeap = g_DnsFilterHeap;
    if (hHeap != NULL)
        return hHeap;
    
    // Create new heap - thread-safe lazy initialization
    hHeap = HeapCreate(0, 0, 0);
    if (hHeap) {
        // Use InterlockedCompareExchangePointer for 64-bit pointer safety
        // InterlockedCompareExchange((LONG*)) truncates 64-bit handles!
        HANDLE hExisting = InterlockedCompareExchangePointer(&g_DnsFilterHeap, hHeap, NULL);
        if (hExisting != NULL) {
            // Another thread already created the heap
            HeapDestroy(hHeap);
            hHeap = hExisting;
        }
    }
    return hHeap;
}


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
    
    if (!WSA_LookupMap_Initialized)
        return;
    
    EnterCriticalSection(&WSA_LookupMap_CritSec);
    
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
            
            // For filtered entries, we allocated a fake handle with Dll_Alloc.
            // iter.key points to the key storage inside the map node (which stores the handle VALUE).
            // We need to extract the actual handle value BEFORE map_erase invalidates the node.
            HANDLE fakeHandle = NULL;
            if (pLookup->Filtered && iter.key) {
                // The key is stored as sizeof(void*) bytes at iter.key
                // Dereference to get the actual handle value that was allocated
                fakeHandle = *(HANDLE*)iter.key;
            }
            
            // Erase from map iterator (this frees the node, invalidating iter.key)
            map_erase(&WSA_LookupMap, &iter);
            
            // Now free the fake handle AFTER map_erase (handle value was saved above)
            if (fakeHandle) {
                Dll_Free(fakeHandle);
            }
            
            // Debug log
            DNS_LogDebugCleanupStaleHandle(now - pLookup->CreateTime);
        }
    }
    
    LeaveCriticalSection(&WSA_LookupMap_CritSec);
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
    if (!WSA_LookupMap_Initialized)
        return NULL;
    
    EnterCriticalSection(&WSA_LookupMap_CritSec);
    
    WSA_LOOKUP* pLookup = (WSA_LOOKUP*)map_get(&WSA_LookupMap, h);
    if (pLookup == NULL && bCanAdd) {
        // Note: Critical section protects against concurrent insert/resize
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
    
    LeaveCriticalSection(&WSA_LookupMap_CritSec);
    return pLookup;
}

//---------------------------------------------------------------------------
// Helper macros for alignment and relative pointers
//---------------------------------------------------------------------------

static __forceinline BOOLEAN DNS_EntryMatchesQueryFamily(const IP_ENTRY* entry, BOOLEAN isIPv6Query)
{
    return entry && ((isIPv6Query && entry->Type == AF_INET6) || (!isIPv6Query && entry->Type == AF_INET));
}

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
#ifdef _DNSDEBUG
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

    // Calc IP size and sockaddr footprint in a single pass
    SIZE_T ipCount = 0;
    SIZE_T sockaddrSize = 0;
    IP_ENTRY* entry;

    for (entry = (IP_ENTRY*)List_Head(pLookup->pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        if (!DNS_EntryMatchesQueryFamily(entry, isIPv6Query))
            continue;
        ipCount++;
        sockaddrSize += (entry->Type == AF_INET) ? (sizeof(SOCKADDR_IN) * 2) : (sizeof(SOCKADDR_IN6_LH) * 2);
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
    
#ifdef _DNSDEBUG
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

    // Cache the selected entries so we don't traverse the LIST multiple times.
    // This keeps behavior identical but avoids repeated list walks when building CSADDR_INFO and HOSTENT.
    if (ipCount > (SIZE_MAX / sizeof(IP_ENTRY*))) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    IP_ENTRY** selectedEntries = (IP_ENTRY**)Dll_AllocTemp((ULONG)(ipCount * sizeof(IP_ENTRY*)));
    if (!selectedEntries) {
        SetLastError(WSA_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    SIZE_T i = 0;
    for (entry = (IP_ENTRY*)List_Head(pLookup->pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        if (!DNS_EntryMatchesQueryFamily(entry, isIPv6Query))
            continue;

        selectedEntries[i] = entry;
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
    for (SIZE_T j = 0; j < ipCount; j++) {
        entry = selectedEntries[j];
        if (!entry)
            continue;

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

    Dll_Free(selectedEntries);

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

static void DNS_FormatEncDnsSourceTag(WCHAR* outTag, size_t outTagCch, const WCHAR* apiName, ENCRYPTED_DNS_MODE protocolUsed)
{
    if (!outTag || outTagCch == 0 || !apiName) {
        return;
    }

    if (protocolUsed != ENCRYPTED_DNS_MODE_AUTO) {
        Sbie_snwprintf(outTag, outTagCch, L"%s EncDns(%s)", apiName, EncryptedDns_GetModeName(protocolUsed));
    } else {
        Sbie_snwprintf(outTag, outTagCch, L"%s EncDns", apiName);
    }
}

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

    DNS_EXCLUDE_RESOLVE_MODE default_mode = DNS_EXCLUDE_RESOLVE_SYS;

    while (*ptr == L' ' || *ptr == L'\t')
        ++ptr;

    // Optional global mode prefix: "enc:" or "sys:" applies to all patterns unless overridden.
    if (_wcsnicmp(ptr, L"enc:", 4) == 0) {
        default_mode = DNS_EXCLUDE_RESOLVE_ENC;
        ptr += 4;
    } else if (_wcsnicmp(ptr, L"sys:", 4) == 0) {
        default_mode = DNS_EXCLUDE_RESOLVE_SYS;
        ptr += 4;
    }

    while (*ptr == L' ' || *ptr == L'\t')
        ++ptr;
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
            DNS_EXCLUDE_RESOLVE_MODE mode = default_mode;

            // Optional per-pattern mode suffix: "pattern:enc" or "pattern:sys".
            // Backward compatible: only treats the LAST ':' as a mode separator when the suffix is enc/sys.
            WCHAR* last_colon = wcsrchr(ptr, L':');
            if (last_colon && last_colon != ptr && last_colon[1] != L'\0') {
                if (_wcsicmp(last_colon + 1, L"enc") == 0) {
                    mode = DNS_EXCLUDE_RESOLVE_ENC;
                    *last_colon = L'\0';
                    len = wcslen(ptr);
                } else if (_wcsicmp(last_colon + 1, L"sys") == 0) {
                    mode = DNS_EXCLUDE_RESOLVE_SYS;
                    *last_colon = L'\0';
                    len = wcslen(ptr);
                }
            }

            if (len == 0) {
                ptr = end ? end + 1 : NULL;
                continue;
            }

            WCHAR* pattern = (WCHAR*)Dll_Alloc((len + 1) * sizeof(WCHAR));
            if (!pattern)
                break;

            wcscpy(pattern, ptr);
            _wcslwr(pattern);
            excl->patterns[excl->count] = pattern;
            excl->modes[excl->count] = (BYTE)mode;
            excl->count++;
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
    
    // Load WinHTTP hook setting
    DNS_WinHttpHookEnabled = Config_GetSettingsForImageName_bool(L"FilterWinHttp", FALSE);
    
    // Load DnsMapIpv4ToIpv6 setting (default: disabled)
    DNS_MapIpv4ToIpv6 = Config_GetSettingsForImageName_bool(L"DnsMapIpv4ToIpv6", FALSE);

    if (DNS_FilterList.count > 0)
        return;

    List_Init(&DNS_FilterList);
    BOOLEAN hasFilters = DNS_LoadFilterEntries();
    
    // Only load exclusions and type filters if we have base filter rules
    // NetworkDnsFilterExclude and NetworkDnsFilterType have no effect without NetworkDnsFilter
    if (hasFilters) {
        DNS_LoadExclusionRules();
        DNS_LoadTypeFilterEntries();
    }

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
        if (!WSA_LookupMap_Initialized) {
            InitializeCriticalSection(&WSA_LookupMap_CritSec);
            map_init(&WSA_LookupMap, Dll_Pool);
            WSA_LookupMap_Initialized = TRUE;
        }
        
        if (!has_valid_certificate) {
            // Warn that filtering is disabled (will only log, not intercept/block)
            const WCHAR* strings[] = { L"NetworkDnsFilter" , NULL };
            SbieApi_LogMsgExt(-1, 6009, strings);
        }
    }

    // DnsTrace for logging (works regardless of certificate - logging only, no filtering)
    WCHAR wsTraceOptions[4];
    if (SbieApi_QueryConf(NULL, L"DnsTrace", 0, wsTraceOptions, sizeof(wsTraceOptions)) == STATUS_SUCCESS && wsTraceOptions[0] != L'\0') {
        // Respect explicit disable (e.g. DnsTrace=n/0) instead of treating any value as TRUE
        DNS_TraceFlag = Config_String2Bool(wsTraceOptions, FALSE);

        if (DNS_TraceFlag) {
            // Initialize infrastructure for logging if not already done
            // This allows pure logging mode even without certificate or filter rules
            if (!DNS_FilterEnabled) {
                DNS_FilterEnabled = TRUE;
                if (!WSA_LookupMap_Initialized) {
                    InitializeCriticalSection(&WSA_LookupMap_CritSec);
                    map_init(&WSA_LookupMap, Dll_Pool);
                    WSA_LookupMap_Initialized = TRUE;
                }
            }
        }
    }

    // Enable DNS filtering infrastructure when EncryptedDnsServer is configured
    // This ensures encrypted DNS works even without NetworkDnsFilter rules or DnsTrace
    if (EncryptedDns_IsEnabled()) {
        if (!DNS_FilterEnabled) {
            DNS_FilterEnabled = TRUE;
            if (!WSA_LookupMap_Initialized) {
                InitializeCriticalSection(&WSA_LookupMap_CritSec);
                map_init(&WSA_LookupMap, Dll_Pool);
                WSA_LookupMap_Initialized = TRUE;
            }
        }
    }
}


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

static BOOLEAN DNS_IsExcludedEx(const WCHAR* domain, DNS_EXCLUDE_RESOLVE_MODE* pModeOut)
{
    if (pModeOut)
        *pModeOut = DNS_EXCLUDE_RESOLVE_SYS;

    if (!domain)
        return FALSE;

    // Automatically exclude encrypted DNS server hostname to prevent re-entrancy loops
    // (WinHTTP resolves hostname internally, triggering DNS hooks)
    if (EncryptedDns_IsEnabled()) {
        const WCHAR* doh_hostname = EncryptedDns_GetServerHostname();
        if (doh_hostname && _wcsicmp(domain, doh_hostname) == 0) {
            if (DNS_DebugFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"[EncDns] Auto-excluded encrypted DNS server hostname: %s", domain);
                SbieApi_MonitorPutMsg(MONITOR_OTHER, msg);
            }
            if (pModeOut)
                *pModeOut = DNS_EXCLUDE_RESOLVE_SYS;
            return TRUE;
        }
    }

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

            if (DNS_ListMatchesDomain(excl, domain, pModeOut))
                return TRUE;
        }
    }

    for (ULONG i = 0; i < DNS_ExclusionListCount; ++i) {
        DNS_EXCLUSION_LIST* excl = &DNS_ExclusionLists[i];
        if (excl->image_name)
            continue;

        DNS_LogDebugExclusionGlobalList(excl->count);

        if (DNS_ListMatchesDomain(excl, domain, pModeOut))
            return TRUE;
    }

    return FALSE;
}

// Forward declaration (defined later)
static BOOLEAN DNS_IsIPAddress(const WCHAR* str);

// For IP literals, only allow exact (non-wildcard) patterns to match.
// This prevents catch-all wildcard rules (e.g., "*", "*.*") from matching IP-literal queries.
static BOOLEAN DNS_PatternIsExactNonWildcard(PATTERN* pat)
{
    if (!pat)
        return FALSE;

    const WCHAR* src = Pattern_Source(pat);
    if (!src)
        return FALSE;

    // Reject any wildcard patterns.
    if (wcschr(src, L'*') || wcschr(src, L'?'))
        return FALSE;

    // Defensive: ensure pattern engine also considers it exact.
    if (!Pattern_Exact(pat))
        return FALSE;

    if (Pattern_Wildcards(pat) != 0)
        return FALSE;

    return TRUE;
}

// Returns TRUE if domain matches any exclusion string for current image or global
BOOLEAN DNS_IsExcluded(const WCHAR* domain)
{
    return DNS_IsExcludedEx(domain, NULL);
}

BOOLEAN DNS_IsExcludedWithMode(const WCHAR* domain, DNS_EXCLUDE_RESOLVE_MODE* pModeOut)
{
    return DNS_IsExcludedEx(domain, pModeOut);
}

//---------------------------------------------------------------------------
// DNS_DomainMatchPatternList
//
// Match a DNS domain against a pattern list, handling FQDN conventions.
// Unlike Pattern_MatchPathList which adds backslashes for path matching,
// this function normalizes the trailing dot:
//   - If domain has trailing dot but pattern doesn't: try without dot
//   - If domain lacks trailing dot but pattern has one: try with dot
//
// Returns: match_len if matched, 0 if not matched
//---------------------------------------------------------------------------

_FX int WINAPI DNS_DomainMatchPatternList(
    WCHAR* domain_lwr, SIZE_T domain_len, LIST* pat_list, PATTERN** found_pat)
{
    if (!domain_lwr || !pat_list || domain_len == 0)
        return 0;

    int best_match_len = 0;
    PATTERN* best_found = NULL;
    
    // Check if domain has trailing dot (FQDN format)
    BOOLEAN has_trailing_dot = (domain_lwr[domain_len - 1] == L'.');
    
    // Prepare domain versions for matching:
    // - domain_without_dot: domain without trailing dot (for matching patterns without dot)
    // - domain_with_dot: domain with trailing dot (for matching patterns with dot)
    size_t len_without_dot = has_trailing_dot ? (domain_len - 1) : domain_len;

    // Special-case IP literals for NetworkDnsFilter matching: only exact IP rules apply.
    // Do NOT apply this to other pattern lists (e.g., NetworkDnsFilterExclude temp lists).
    BOOLEAN ip_literal_filter_match = FALSE;
    if (pat_list == &DNS_FilterList) {
        ip_literal_filter_match = DNS_IsIPAddress(domain_lwr);
    }

    PATTERN* pat = (PATTERN*)List_Head(pat_list);
    while (pat) {
        if (ip_literal_filter_match && !DNS_PatternIsExactNonWildcard(pat)) {
            pat = (PATTERN*)List_Next(pat);
            continue;
        }

        int match_len;
        
        // Try 1: Match domain WITHOUT trailing dot
        // This handles: pattern="*.in-addr.arpa" matching domain="1.0.168.192.in-addr.arpa."
        if (has_trailing_dot) {
            // Temporarily remove trailing dot
            domain_lwr[len_without_dot] = L'\0';
            match_len = Pattern_MatchX(pat, domain_lwr, (int)len_without_dot);
            domain_lwr[len_without_dot] = L'.';  // Restore
        } else {
            match_len = Pattern_MatchX(pat, domain_lwr, (int)domain_len);
        }
        
        if (match_len > best_match_len) {
            best_match_len = match_len;
            best_found = pat;
        }

        // Try 2: Match domain WITH trailing dot
        // This handles: pattern="*.in-addr.arpa." matching domain="1.0.168.192.in-addr.arpa"
        if (!has_trailing_dot) {
            // Temporarily add trailing dot
            domain_lwr[domain_len] = L'.';
            match_len = Pattern_MatchX(pat, domain_lwr, (int)domain_len + 1);
            domain_lwr[domain_len] = L'\0';  // Restore
            
            if (match_len > best_match_len) {
                best_match_len = match_len;
                best_found = pat;
            }
        }

        pat = (PATTERN*)List_Next(pat);
    }

    if (found_pat && best_match_len > 0) {
        *found_pat = best_found;
    }

    return best_match_len;
}

//---------------------------------------------------------------------------

static BOOLEAN DNS_ListMatchesDomain(const DNS_EXCLUSION_LIST* excl, const WCHAR* domain, DNS_EXCLUDE_RESOLVE_MODE* pModeOut)
{
    if (!excl || !domain)
        return FALSE;

    if (pModeOut)
        *pModeOut = DNS_EXCLUDE_RESOLVE_SYS;

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
            PVOID* aux = Pattern_Aux(pat);
            if (aux) {
                // Store 1-based index so NULL/0 means "no aux"
                *aux = (PVOID)(ULONG_PTR)(j + 1);
            }
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
    _wcslwr(domain_copy);  // DNS comparison is case-insensitive
    
    PATTERN* found = NULL;
    // Use DNS-specific matching that handles FQDN trailing dots properly
    int match_result = DNS_DomainMatchPatternList(domain_copy, domain_len, &temp_list, &found);
    
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

        if (pModeOut) {
            PVOID* aux = Pattern_Aux(found);
            ULONG idx = 0;
            if (aux && *aux) {
                idx = (ULONG)(ULONG_PTR)(*aux);
            }
            if (idx > 0) {
                idx--;
                if (idx < excl->count) {
                    *pModeOut = (DNS_EXCLUDE_RESOLVE_MODE)excl->modes[idx];
                }
            }
        }
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

    PATTERN* found = NULL;
    BOOLEAN matches = (DNS_DomainMatchPatternList(path_lwr, path_len, &DNS_FilterList, &found) > 0);

    Dll_Free(path_lwr);
    return matches;
}

//---------------------------------------------------------------------------
// DNS_CheckFilter
//
// Simple filter check.
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

    PATTERN* found = NULL;
    // Use DNS-specific matching that handles FQDN trailing dots properly
    if (DNS_DomainMatchPatternList(path_lwr, path_len, &DNS_FilterList, &found) <= 0) {
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
//
// Level parameter:
//   0 = exact image match only
//   1 = negated image match only  
//   2 = global default only
//   (ULONG)-1 = match any level (for runtime lookups that don't care about specificity)
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

    // IP literals should NOT match wildcard patterns (e.g., "*", "*.*").
    // Only exact (non-wildcard) patterns are eligible.
    if (DNS_IsIPAddress(domain_lwr)) {
        PATTERN* best_found = NULL;
        int best_match_len = 0;

        // Strip optional IPv6 brackets for matching against config rules.
        WCHAR saved_last = 0;
        WCHAR* ip_str = domain_lwr;
        int ip_len = (int)domain_len;
        if (domain_len >= 2 && domain_lwr[0] == L'[' && domain_lwr[domain_len - 1] == L']') {
            saved_last = domain_lwr[domain_len - 1];
            domain_lwr[domain_len - 1] = L'\0';
            ip_str = domain_lwr + 1;
            ip_len = (int)domain_len - 2;
        }

        PATTERN* pat = (PATTERN*)List_Head(&DNS_FilterList);
        while (pat) {
            if (!DNS_PatternIsExactNonWildcard(pat)) {
                pat = (PATTERN*)List_Next(pat);
                continue;
            }

            if (level != (ULONG)-1 && Pattern_Level(pat) != level) {
                pat = (PATTERN*)List_Next(pat);
                continue;
            }

            int match_len = Pattern_MatchX(pat, ip_str, ip_len);
            if (match_len > best_match_len) {
                best_match_len = match_len;
                best_found = pat;
            }

            pat = (PATTERN*)List_Next(pat);
        }

        if (saved_last)
            domain_lwr[domain_len - 1] = saved_last;

        Dll_Free(domain_lwr);
        return (best_match_len > 0) ? best_found : NULL;
    }

    PATTERN* found = NULL;
    int match_result;
    
    if (level == (ULONG)-1) {
        // Match any level - for runtime lookups (GetAddrInfo, DnsQuery, etc.)
        // Note: DNS_DomainMatchPatternList doesn't support level-based matching,
        // so for level-specific searches, we still need Pattern_MatchPathList.
        // However, DNS_DomainMatchPatternList handles FQDN trailing dots properly.
        match_result = DNS_DomainMatchPatternList(domain_lwr, domain_len, &DNS_FilterList, &found);
    } else {
        // Match specific level - for configuration loading (NetworkDnsFilterType)
        // This still requires the level parameter which DNS_DomainMatchPatternList doesn't support
        // For now, use Pattern_MatchPathList here since it's mainly for config loading
        ULONG match_level = level;
        match_result = Pattern_MatchPathList(domain_lwr, (ULONG)domain_len, &DNS_FilterList, &match_level, NULL, NULL, &found);
        
        // Verify level matches exactly
        if (match_result > 0 && found && Pattern_Level(found) != level) {
            found = NULL;
            match_result = 0;
        }
    }

    Dll_Free(domain_lwr);

    if (match_result > 0 && found) {
        return found;
    }

    return NULL;
}

//---------------------------------------------------------------------------
// DNS_WinHttpConnect
//
// Hook for WinHttpConnect() from winhttp.dll
// Validates server name against NetworkDnsFilter rules
// Returns NULL (connection failed) if domain is blocked, otherwise calls original
//---------------------------------------------------------------------------

static HINTERNET WINAPI DNS_WinHttpConnect(
    HINTERNET hSession,
    LPCWSTR pswzServerName,
    INTERNET_PORT nServerPort,
    DWORD dwReserved)
{
    // Quick path: if WinHTTP hook is disabled or no filter rules, use original
    if (!DNS_WinHttpHookEnabled || !DNS_FilterEnabled) {
        return __sys_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
    }

    // Validate domain against NetworkDnsFilter rules
    if (pswzServerName && wcslen(pswzServerName) > 0) {
        size_t domain_len = wcslen(pswzServerName);
        WCHAR* domain_lwr = (WCHAR*)Dll_AllocTemp((domain_len + 4) * sizeof(WCHAR));
        if (domain_lwr) {
            wmemcpy(domain_lwr, pswzServerName, domain_len);
            domain_lwr[domain_len] = L'\0';
            _wcslwr(domain_lwr);
            
            // Check exclusion first
            if (DNS_IsExcluded(domain_lwr)) {
                DNS_LogExclusion(domain_lwr);
                Dll_Free(domain_lwr);
                return __sys_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
            }
            
            // Exclude encrypted DNS server hostnames to prevent re-entrancy
            // Encrypted DNS uses WinHTTP internally, so we must bypass server connections
            if (EncryptedDns_IsServerHostname(domain_lwr)) {
                if (DNS_TraceFlag || DNS_DebugFlag) {
                    DNS_LogPassthrough(L"[WinHTTP]", pswzServerName, DNS_TYPE_ANY, L"EncDns server");
                }
                Dll_Free(domain_lwr);
                return __sys_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
            }
            
            // If an encrypted DNS query is already active, bypass to prevent re-entrancy
            // Encrypted DNS may trigger GetAddrInfoW which may trigger WinHttpConnect recursively
            if (EncryptedDns_IsQueryActive()) {
                if (DNS_TraceFlag || DNS_DebugFlag) {
                    DNS_LogPassthrough(L"[WinHTTP]", pswzServerName, DNS_TYPE_ANY, L"EncDns query active");
                }
                Dll_Free(domain_lwr);
                return __sys_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
            }
            
            PATTERN* found = NULL;
            
            // Use DNS-specific matching that handles FQDN trailing dots properly
            if (DNS_DomainMatchPatternList(domain_lwr, domain_len, &DNS_FilterList, &found) > 0) {
                // Domain matches NetworkDnsFilter
                
                // Check if certificate is valid for filtering
                if (!DNS_HasValidCertificate) {
                    DNS_LogPassthrough(L"[WinHTTP]", pswzServerName, DNS_TYPE_ANY, L"no certificate");
                    Dll_Free(domain_lwr);
                    return __sys_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
                }
                
                // Get IP entries for this domain (if any)
                PVOID* aux = Pattern_Aux(found);
                LIST* pEntries = NULL;
                DNS_TYPE_FILTER* type_filter = NULL;
                
                if (aux && *aux) {
                    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);
                }
                
                // If no IP entries, this is block mode - deny connection
                if (!pEntries) {
                    DNS_LogBlocked(L"[WinHTTP]", pswzServerName, DNS_TYPE_ANY, L"Domain blocked (NXDOMAIN)");
                    Dll_Free(domain_lwr);
                    SetLastError(ERROR_HOST_UNREACHABLE);
                    return NULL;
                }
                
                // Has IP entries - redirect mode
                // WinHTTP will perform DNS resolution internally via GetAddrInfoW
                // Our existing GetAddrInfoW hook will intercept and return the filtered IPs
                // Just allow the connection - the DNS hook handles the redirection
                DNS_LogPassthrough(L"[WinHTTP]", pswzServerName, DNS_TYPE_ANY, L"allowing (DNS hooks will redirect)");
                Dll_Free(domain_lwr);
                // Let WinHTTP proceed - it will call GetAddrInfoW which our hooks will intercept
                return __sys_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
            }
            
            // Domain not in filter - allow and log passthrough if tracing
            DNS_LogPassthrough(L"[WinHTTP]", pswzServerName, DNS_TYPE_ANY, L"not filtered");
            
            Dll_Free(domain_lwr);
        }
    }

    // Domain allowed or not blocked - call original function
    return __sys_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
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

    // Check if raw socket DNS hooks are requested via FilterRawDns setting
    extern BOOLEAN Socket_GetRawDnsFilterEnabled(BOOLEAN has_valid_certificate);
    BOOLEAN rawDnsEnabled = Socket_GetRawDnsFilterEnabled(TRUE); // Check setting only, ignore cert

    // Check if WinHTTP hooks are requested via FilterWinHttp setting
    // (This function will be defined later - forward declaration)
    BOOLEAN winHttpEnabled = (Config_GetSettingsForImageName_bool(L"FilterWinHttp", FALSE));

    // If none of the DNS features are enabled, skip all hooks
    // - DNS_FilterEnabled: NetworkDnsFilter rules exist
    // - DNS_TraceFlag: DnsTrace=y for logging
    // - rawDnsEnabled: FilterRawDns=y for raw socket filtering
    // - winHttpEnabled: FilterWinHttp=y for WinHTTP API filtering
    if (!DNS_FilterEnabled && !DNS_TraceFlag && !rawDnsEnabled && !winHttpEnabled) {
        return TRUE; // Nothing to do; leave original APIs untouched.
    }

    // Get WSASetLastError for error reporting in getaddrinfo hooks
    __sys_WSASetLastError = (P_WSASetLastError)GetProcAddress(module, "WSASetLastError");

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
    // Setup getaddrinfo hooks (ws2_32.dll)
    // These are used by WinHTTP, libcurl, and many modern applications
    //

    // Note: We use explicit casting to avoid conflicts with SDK definitions
    // The SBIEDLL_HOOK macro expects the local variable name to match the export name
    void* getaddrinfo = (void*)GetProcAddress(module, "getaddrinfo");
    if (getaddrinfo) {
        SBIEDLL_HOOK(WSA_, getaddrinfo);
    }

    P_GetAddrInfoW GetAddrInfoW = (P_GetAddrInfoW)GetProcAddress(module, "GetAddrInfoW");
    if (GetAddrInfoW) {
        SBIEDLL_HOOK(WSA_, GetAddrInfoW);
    }

    P_GetAddrInfoExW GetAddrInfoExW = (P_GetAddrInfoExW)GetProcAddress(module, "GetAddrInfoExW");
    if (GetAddrInfoExW) {
        SBIEDLL_HOOK(WSA_, GetAddrInfoExW);
    }

    void* freeaddrinfo = (void*)GetProcAddress(module, "freeaddrinfo");
    if (freeaddrinfo) {
        SBIEDLL_HOOK(WSA_, freeaddrinfo);
    }

    P_FreeAddrInfoW FreeAddrInfoW = (P_FreeAddrInfoW)GetProcAddress(module, "FreeAddrInfoW");
    if (FreeAddrInfoW) {
        SBIEDLL_HOOK(WSA_, FreeAddrInfoW);
    }

    P_FreeAddrInfoExW FreeAddrInfoExW = (P_FreeAddrInfoExW)GetProcAddress(module, "FreeAddrInfoExW");
    if (FreeAddrInfoExW) {
        SBIEDLL_HOOK(WSA_, FreeAddrInfoExW);
    }

    //
    // Setup raw socket hooks for nslookup and other direct DNS tools
    // Pass certificate status to enforce certificate requirement for FilterRawDns
    //
    Socket_InitHooks(module, DNS_HasValidCertificate);

    //
    // Initialize DoH (DNS-over-HTTPS) client
    // This is done here in addition to DNSAPI_Init to ensure DoH is available
    // when WSA APIs are used before dnsapi.dll is loaded
    //
    HMODULE hWinHttp = GetModuleHandleW(L"winhttp.dll");
    if (!hWinHttp) {
        hWinHttp = LoadLibraryW(L"winhttp.dll");
    }
    EncryptedDns_Init(hWinHttp, NULL);
    EncryptedDns_LoadConfig();

    return TRUE;
}

//---------------------------------------------------------------------------
// WINHTTP_Init
//
// Initializes WinHTTP hooks (called when winhttp.dll is loaded)
// Delegates to WinHttp_Init in winhttp_filter.c for modular organization.
// This function remains for backward compatibility with ldr.c.
//---------------------------------------------------------------------------

_FX BOOLEAN WINHTTP_Init(HMODULE module)
{
    // Initialize shared filter rules (if not already done)
    DNS_InitFilterRules();

    // Delegate to modular WinHTTP filter implementation
    return WinHttp_Init(module);
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

    // Load DnsExtractRecordsFromMessage_W for parsing raw DNS responses
    // This is used to convert encrypted DNS wire format responses to DNS_RECORD structures
    __sys_DnsExtractRecordsFromMessage_W = (P_DnsExtractRecordsFromMessage_W)
        GetProcAddress(module, "DnsExtractRecordsFromMessage_W");

    // Initialize encrypted DNS client
    HMODULE hWinHttp = GetModuleHandleW(L"winhttp.dll");
    if (!hWinHttp) {
        hWinHttp = LoadLibraryW(L"winhttp.dll");
    }
    
    // Always initialize encrypted DNS (even if hWinHttp is NULL)
    EncryptedDns_Init(hWinHttp, NULL);
    
    // Always try to load configuration
    EncryptedDns_LoadConfig();

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
    
    // Re-entrancy check: if we're inside GetAddrInfoExW, passthrough to avoid double-interception
    // GetAddrInfoExW internally may call WSALookupService on some Windows versions
    if (WSA_GetInGetAddrInfoEx()) {
        if (DNS_DebugFlag && lpqsRestrictions && lpqsRestrictions->lpszServiceInstanceName) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, ARRAYSIZE(msg),
                L"WSALookupService Bypass(SysDns): %s - reason: inside GetAddrInfoExW",
                lpqsRestrictions->lpszServiceInstanceName);
            DNS_LogDebug(msg);
        }
        return __sys_WSALookupServiceBeginW(lpqsRestrictions, dwControlFlags, lphLookup);
    }
    
    // Re-entrancy check: if we're inside system's getaddrinfo (ANSI), passthrough
    // The system's getaddrinfo calls GetAddrInfoW which may call WSALookupService
    // If we intercept here and call DoH, we'll block waiting for WinHTTP which
    // may deadlock if the DNS resolution thread pool is exhausted
    if (WSA_SystemGetAddrInfoDepth > 0) {
        if (DNS_DebugFlag && lpqsRestrictions && lpqsRestrictions->lpszServiceInstanceName) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, ARRAYSIZE(msg),
                L"WSALookupService Bypass(SysDns): %s - reason: inside system getaddrinfo",
                lpqsRestrictions->lpszServiceInstanceName);
            DNS_LogDebug(msg);
        }
        return __sys_WSALookupServiceBeginW(lpqsRestrictions, dwControlFlags, lphLookup);
    }
    
    if (DNS_FilterEnabled && lpqsRestrictions && lpqsRestrictions->lpszServiceInstanceName) {
        ULONG path_len = wcslen(lpqsRestrictions->lpszServiceInstanceName);
        WCHAR* path_lwr = (WCHAR*)Dll_AllocTemp((path_len + 4) * sizeof(WCHAR));
        wmemcpy(path_lwr, lpqsRestrictions->lpszServiceInstanceName, path_len);
        path_lwr[path_len] = L'\0';
        _wcslwr(path_lwr);

        {
            DNS_EXCLUDE_RESOLVE_MODE excludeMode = DNS_EXCLUDE_RESOLVE_SYS;
            if (DNS_IsExcludedEx(path_lwr, &excludeMode)) {
                DNS_LogExclusion(path_lwr);
                if (excludeMode == DNS_EXCLUDE_RESOLVE_SYS) {
                    // Excluded + sys: bypass filtering and EncDns - use system DNS directly
                    Dll_Free(path_lwr);
                    goto use_system_dns;
                }
                // Excluded + enc: bypass filtering but still allow EncDns passthrough logic
                Dll_Free(path_lwr);
                goto try_encdns_passthrough;
            }
        }

        PATTERN* found = NULL;
        if (DNS_DomainMatchPatternList(path_lwr, path_len, &DNS_FilterList, &found) > 0) {
            
            // Certificate required for actual filtering (interception/blocking)
            extern BOOLEAN DNS_HasValidCertificate;
            if (!DNS_HasValidCertificate) {
                // Domain matches filter but no cert - try EncDns first, then passthrough
                WORD queryType = WSA_IsIPv6Query(lpqsRestrictions->lpServiceClassId) ? DNS_TYPE_AAAA : DNS_TYPE_A;
                LIST doh_list;
                DOH_RESULT encdns_result;
                if (EncryptedDns_IsEnabled() && DNS_TryDoHQuery(path_lwr, queryType, &doh_list, &encdns_result)) {
                    HANDLE fakeHandle = (HANDLE)Dll_Alloc(sizeof(ULONG_PTR));
                    if (fakeHandle) {
                        *lphLookup = fakeHandle;
                        
                        WSA_LOOKUP* pLookup = WSA_GetLookup(fakeHandle, TRUE);
                        if (pLookup) {
                            pLookup->Filtered = TRUE;
                            pLookup->NoMore = FALSE;
                            pLookup->QueryType = queryType;
                            
                            pLookup->DomainName = Dll_Alloc((path_len + 1) * sizeof(WCHAR));
                            if (pLookup->DomainName) {
                                wcscpy_s(pLookup->DomainName, path_len + 1, lpqsRestrictions->lpszServiceInstanceName);
                            }
                            
                            pLookup->Namespace = lpqsRestrictions->dwNameSpace;
                            
                            if (lpqsRestrictions->lpServiceClassId) {
                                pLookup->ServiceClassId = Dll_Alloc(sizeof(GUID));
                                if (pLookup->ServiceClassId) {
                                    memcpy(pLookup->ServiceClassId, lpqsRestrictions->lpServiceClassId, sizeof(GUID));
                                }
                            }
                            
                            // Convert EncDns results to IP_ENTRY list
                            IP_ENTRY* entry;
                            LIST* pEntries = &doh_list;
                            
                            pLookup->pEntries = Dll_Alloc(sizeof(LIST));
                            if (pLookup->pEntries) {
                                List_Init(pLookup->pEntries);
                                
                                entry = (IP_ENTRY*)List_Head(pEntries);
                                while (entry) {
                                    IP_ENTRY* newEntry = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
                                    if (newEntry) {
                                        newEntry->Type = entry->Type;
                                        memcpy(&newEntry->IP, &entry->IP, sizeof(IP_ADDRESS));
                                        List_Insert_After(pLookup->pEntries, NULL, newEntry);
                                    }
                                    entry = (IP_ENTRY*)List_Next(entry);
                                }
                            }
                            
                            WSA_LogIntercepted(lpqsRestrictions->lpszServiceInstanceName,
                                lpqsRestrictions->lpServiceClassId,
                                lpqsRestrictions->dwNameSpace,
                                fakeHandle,
                                FALSE,  // not blocked
                                pLookup->pEntries,
                                TRUE,   // is_encdns = TRUE (EncDns resolution)
                                encdns_result.ProtocolUsed);
                            
                            Dll_Free(path_lwr);
                            DNS_FreeIPEntryList(&doh_list);
                            return NO_ERROR;
                        }
                        Dll_Free(fakeHandle);
                    }
                    DNS_FreeIPEntryList(&doh_list);
                }
                
                // EncDns query failed or returned no records
                if (EncryptedDns_IsEnabled()) {
                    // EncDns is enabled but query failed - return error instead of fallback to system DNS
                    Dll_Free(path_lwr);
                    SetLastError(WSAHOST_NOT_FOUND);
                    return SOCKET_ERROR;
                }
                
                // EncDns disabled - fall through to system DNS
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
                            // Type not in filter list or negated - try EncDns first, then passthrough to real DNS
                            EnterCriticalSection(&WSA_LookupMap_CritSec);
                            map_remove(&WSA_LookupMap, fakeHandle);
                            LeaveCriticalSection(&WSA_LookupMap_CritSec);
                            Dll_Free(fakeHandle);
                            
                            // Try EncDns for negated type passthrough queries
                            int encdns_result = DNS_DoHBuildWSALookup(lpqsRestrictions, lphLookup);
                            if (encdns_result == NO_ERROR) {
                                Dll_Free(path_lwr);
                                return NO_ERROR;
                            }
                            
                            // EncDns failed or disabled
                            Dll_Free(path_lwr);
                            if (EncryptedDns_IsEnabled()) {
                                // EncDns is enabled but failed - return error
                                return SOCKET_ERROR;
                            }
                            // EncDns disabled - passthrough to real DNS
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
                pEntries,
                FALSE,   // is_encdns = FALSE (filter-based)
                ENCRYPTED_DNS_MODE_AUTO);

            Dll_Free(path_lwr);
            return NO_ERROR;
        }

        Dll_Free(path_lwr);
    }

try_encdns_passthrough:
    // If EncDns is enabled, try EncDns for all passthrough queries (non-matching or no-cert)
    // This ensures all DNS traffic goes through secure channel when EncryptedDnsServer is configured
    if (lpqsRestrictions && lpqsRestrictions->lpszServiceInstanceName) {
        int encdns_result = DNS_DoHBuildWSALookup(lpqsRestrictions, lphLookup);
        if (encdns_result == NO_ERROR) {
            return NO_ERROR;
        }
        // EncDns failed or disabled - if EncDns is enabled, return error (no fallback)
        if (EncryptedDns_IsEnabled()) {
            return SOCKET_ERROR;
        }
    }

    // EncDns disabled - use system DNS
use_system_dns:
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
                Sbie_snwprintf(msg, ARRAYSIZE(msg), L"WSALookupService Passthrough(SysDns) HOSTENT: %s",
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
                
                SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
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
    if (DNS_FilterEnabled && WSA_LookupMap_Initialized) {
        WSA_LOOKUP* pLookup = WSA_GetLookup(hLookup, FALSE);

        if (pLookup && pLookup->Filtered) {
            if (pLookup->DomainName)
                Dll_Free(pLookup->DomainName);

            if (pLookup->ServiceClassId)
                Dll_Free(pLookup->ServiceClassId);

            EnterCriticalSection(&WSA_LookupMap_CritSec);
            map_remove(&WSA_LookupMap, hLookup);
            LeaveCriticalSection(&WSA_LookupMap_CritSec);

            Dll_Free(hLookup);

            DNS_LogWSADebugRequestEnd(hLookup, TRUE);

            return NO_ERROR;
        }

        EnterCriticalSection(&WSA_LookupMap_CritSec);
        map_remove(&WSA_LookupMap, hLookup);
        LeaveCriticalSection(&WSA_LookupMap_CritSec);
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

    PATTERN* found = NULL;
    BOOLEAN domainMatched = (DNS_DomainMatchPatternList(path_lwr, path_len, &DNS_FilterList, &found) > 0);
    
    // When EncryptedDnsServer is enabled and query type is unsupported (not A/AAAA),
    // let encrypted DNS handle it regardless of whether domain matches filter
    if (!domainMatched && EncryptedDns_IsEnabled() && !DNS_CanSynthesizeResponse(wType)) {
        // Domain doesn't match filter, but encrypted DNS should handle unsupported types
        if (pOutcome) {
            pOutcome->PassthroughLogged = TRUE;
            pOutcome->PassthroughReason = DNS_PASSTHROUGH_UNSUPPORTED_TYPE;
        }
        Dll_Free(path_lwr);
        return FALSE;  // Let encrypted DNS handle this query
    }
    
    if (!domainMatched) {
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
        // Domain matches filter but no cert - passthrough (caller will log with IPs)
        if (pOutcome) {
            pOutcome->PassthroughLogged = TRUE;  // Signal caller to skip redundant logging
            pOutcome->PassthroughReason = DNS_PASSTHROUGH_NO_CERT;
        }
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
        DNS_PASSTHROUGH_REASON typeReason = DNS_PASSTHROUGH_NONE;
        BOOLEAN should_filter = DNS_IsTypeInFilterListEx(type_filter, wType, &typeReason);
        
        if (!should_filter) {
            // Type not in filter list or negated - passthrough to real DNS
            // Caller will log the final result with IPs (suppression handles dedup)
            if (pOutcome) {
                pOutcome->PassthroughLogged = TRUE;  // Signal caller to skip redundant logging
                pOutcome->PassthroughReason = typeReason;
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
        pRecords = DNSAPI_BuildDnsRecordList(pszName, wType, pEntries, CharSet, NULL);
        // If no records built (e.g., AAAA query but only IPv4 available),
        // return NOERROR + NODATA (domain exists, no records of this type)
        // status stays 0 (NOERROR), pRecords stays NULL (NODATA)
    } else if (!pEntries) {
        // Block mode: return NXDOMAIN (domain doesn't exist)
        status = DNS_ERROR_RCODE_NAME_ERROR;
    } else {
        // Filter mode but unsupported type (MX/CNAME/TXT/etc.)
        // No encrypted DNS: Domain exists (we're filtering it), return NOERROR + NODATA (RFC 2308)
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
    BOOLEAN*                pPassthroughLogged,     // OUT: TRUE if passthrough was already logged
    DNS_PASSTHROUGH_REASON* pPassthroughReason)     // OUT: Reason for passthrough
{
    // Initialize output flags
    if (pPassthroughLogged)
        *pPassthroughLogged = FALSE;
    if (pPassthroughReason)
        *pPassthroughReason = DNS_PASSTHROUGH_NONE;

    // Block mode (no IPs) should block ALL query types
    if (!pEntries) {
        WCHAR blockTag[128];
        DNS_LogBlocked(DNS_GetBlockedTag(sourceTag, blockTag, ARRAYSIZE(blockTag)), 
                       wName, wType, L"Domain blocked (NXDOMAIN)");
        *ppQueryResults = NULL;  // CRITICAL: Must set to NULL to prevent caller using garbage pointer
        *pStatus = DNS_ERROR_RCODE_NAME_ERROR;
        return TRUE;
    }

    // Filter mode (with IPs) - check if this type should be filtered
    DNS_PASSTHROUGH_REASON typeReason = DNS_PASSTHROUGH_NONE;
    BOOLEAN should_filter = DNS_IsTypeInFilterListEx(type_filter, wType, &typeReason);

    if (!should_filter) {
        // Type not in filter list or negated - passthrough to real DNS
        if (pPassthroughReason)
            *pPassthroughReason = typeReason;
        return FALSE;
    }

    // Type is in filter list - synthesize response or return NOERROR+NODATA for unsupported types.
    PDNSAPI_DNS_RECORD pRecords = NULL;
    DNS_STATUS status = 0;

    if (DNS_CanSynthesizeResponse(wType)) {
        pRecords = DNSAPI_BuildDnsRecordList(wName, wType, pEntries, CharSet, NULL);
        // If no records built (e.g. AAAA requested but only IPv4 available and mapping disabled),
        // keep status=NOERROR and return NODATA.
    } else {
        // Unsupported type (MX/CNAME/TXT/etc.) in intercept mode: NOERROR + NODATA.
        status = 0;
    }

    if (ppQueryResults)
        *ppQueryResults = pRecords;
    if (pStatus)
        *pStatus = status;

    // Log the result (intercepted path)
    if (status == 0 && pRecords) {
        DNS_LogDnsRecords(sourceTag, wName, wType, pRecords, NULL, FALSE);
    } else if (status == 0 && !pRecords) {
        DNS_LogInterceptedNoData(sourceTag, wName, wType, L"No records for this type (NODATA)");
    } else {
        WCHAR blockTag[128];
        DNS_LogBlocked(DNS_GetBlockedTag(sourceTag, blockTag, ARRAYSIZE(blockTag)),
                       wName, wType, L"Domain blocked (NXDOMAIN)");
    }

    return TRUE;
}

//---------------------------------------------------------------------------
// DNSAPI_DnsQuery_NarrowCommon
//
// Common logic for DnsQuery_A and DnsQuery_UTF8 hooks.
//---------------------------------------------------------------------------

static DNS_STATUS DNSAPI_DnsQuery_NarrowCommon(
    PCSTR                      pszName,
    WORD                       wType,
    DWORD                      Options,
    PVOID                      pExtra,
    PDNSAPI_DNS_RECORD*        ppQueryResults,
    PVOID*                     pReserved,
    UINT                       codePage,
    DNS_CHARSET                recordCharSet,
    const WCHAR*               apiName,
    const WCHAR*               tagPassthrough,
    const WCHAR*               tagIntercepted,
    DNSAPI_P_DnsQuery_NarrowSys sysQuery,
    BOOLEAN                    includeDebugLogs)
{
    DNS_PASSTHROUGH_REASON passthroughReason = DNS_PASSTHROUGH_NONE;

    // Filtering stage
    if (DNS_FilterEnabled && pszName && sysQuery) {
        int nameLen = MultiByteToWideChar(codePage, 0, pszName, -1, NULL, 0);
        if (nameLen > 0 && nameLen < 512) {
            // Use Dll_Alloc (not Dll_AllocTemp) to match existing behavior
            WCHAR* wName = (WCHAR*)Dll_Alloc(nameLen * sizeof(WCHAR));
            if (wName) {
                MultiByteToWideChar(codePage, 0, pszName, -1, wName, nameLen);

                ULONG path_len = wcslen(wName);
                WCHAR* path_lwr = (WCHAR*)Dll_AllocTemp((path_len + 4) * sizeof(WCHAR));
                wmemcpy(path_lwr, wName, path_len);
                path_lwr[path_len] = L'\0';
                _wcslwr(path_lwr);

                {
                    DNS_EXCLUDE_RESOLVE_MODE excludeMode = DNS_EXCLUDE_RESOLVE_SYS;
                    if (DNS_IsExcludedEx(path_lwr, &excludeMode)) {
                        DNS_LogExclusion(path_lwr);
                        Dll_Free(path_lwr);
                        if (excludeMode == DNS_EXCLUDE_RESOLVE_SYS) {
                            DNS_STATUS ex_status = sysQuery(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
                            DNS_LogDnsQueryResultWithReason(tagPassthrough, wName, wType,
                                                           ex_status, ppQueryResults, DNS_PASSTHROUGH_EXCLUDED);
                            Dll_Free(wName);
                            return ex_status;
                        }
                        Dll_Free(wName);
                        // Excluded from filtering but forced to EncDns for passthrough.
                        goto passthrough_narrow;
                    }
                }

                PATTERN* found = NULL;
                if (DNS_DomainMatchPatternList(path_lwr, path_len, &DNS_FilterList, &found) > 0) {
                    PVOID* aux = Pattern_Aux(found);
                    if (!aux || !*aux) {
                        Dll_Free(path_lwr);
                        Dll_Free(wName);
                        return sysQuery(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
                    }

                    // Certificate required for actual filtering (interception/blocking)
                    extern BOOLEAN DNS_HasValidCertificate;
                    if (!DNS_HasValidCertificate) {
                        DNS_STATUS status = sysQuery(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
                        DNS_LogDnsQueryResultWithReason(tagPassthrough, wName, wType,
                                                       status, ppQueryResults, DNS_PASSTHROUGH_NO_CERT);
                        Dll_Free(path_lwr);
                        Dll_Free(wName);
                        return status;
                    }

                    LIST* pEntries = NULL;
                    DNS_TYPE_FILTER* type_filter = NULL;
                    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);

                    DNS_STATUS status;
                    BOOLEAN passthroughLogged = FALSE;
                    if (DNSAPI_FilterDnsQuery(wName, wType, pEntries, type_filter, recordCharSet,
                                              tagIntercepted, ppQueryResults, &status,
                                              &passthroughLogged, &passthroughReason)) {
                        Dll_Free(path_lwr);
                        Dll_Free(wName);
                        return status;
                    }

                    // Not filtered by type - passthrough to real DNS (logged with IPs and reason below)
                }

                Dll_Free(path_lwr);
                Dll_Free(wName);
            }
        }
    }

passthrough_narrow:
    // Passthrough stage (EncDns or system DNS)
    if (EncryptedDns_IsEnabled() && pszName) {
        int nameLen = MultiByteToWideChar(codePage, 0, pszName, -1, NULL, 0);
        if (nameLen > 0 && nameLen < 512) {
            WCHAR* wName = (WCHAR*)Dll_AllocTemp(nameLen * sizeof(WCHAR));
            if (wName && MultiByteToWideChar(codePage, 0, pszName, -1, wName, nameLen)) {
                // For A/AAAA queries, perform actual EncDns lookup
                if (wType == DNS_TYPE_A || wType == DNS_TYPE_AAAA) {
                    LIST doh_list;
                    DOH_RESULT encdns_result;
                    if (DNS_TryDoHQuery(wName, wType, &doh_list, &encdns_result)) {
                        PDNSAPI_DNS_RECORD pResult = DNSAPI_BuildDnsRecordList(wName, wType, &doh_list, recordCharSet, &encdns_result);
                        if (pResult) {
                            // Preserve existing per-API tag style:
                            // - DnsQuery_A: always includes mode in parentheses
                            // - DnsQuery_UTF8: uses DNS_FormatEncDnsSourceTag (AUTO may omit parens)
                            WCHAR sourceTag[64];
                            if (apiName && wcscmp(apiName, L"DnsQuery_A") == 0) {
                                Sbie_snwprintf(sourceTag, ARRAYSIZE(sourceTag), L"%s EncDns(%s)",
                                               apiName, EncryptedDns_GetModeName(encdns_result.ProtocolUsed));
                            } else {
                                DNS_FormatEncDnsSourceTag(sourceTag, ARRAYSIZE(sourceTag), apiName, encdns_result.ProtocolUsed);
                            }

                            DNS_LogDnsQueryResultWithReason(sourceTag, wName, wType,
                                                           DNS_RCODE_NOERROR, (PDNS_RECORDW*)&pResult, passthroughReason);
                            DNS_FreeIPEntryList(&doh_list);
                            *ppQueryResults = pResult;
                            return DNS_RCODE_NOERROR;
                        }
                        DNS_FreeIPEntryList(&doh_list);
                    }
                    // EncDns query failed - return error instead of fallback
                    {
                        WCHAR sourceTag[64];
                        DNS_FormatEncDnsSourceTag(sourceTag, ARRAYSIZE(sourceTag), apiName, encdns_result.ProtocolUsed);
                        DNS_LogDnsQueryResultWithReason(sourceTag, wName, wType,
                                                       DNS_ERROR_RCODE_NAME_ERROR, NULL, passthroughReason);
                    }
                    *ppQueryResults = NULL;
                    return DNS_ERROR_RCODE_NAME_ERROR;
                }

                // For non-A/AAAA queries (MX, TXT, SRV, etc.), query encrypted DNS and parse raw response
                DOH_RESULT encdns_result;
                if (EncryptedDns_Query(wName, wType, &encdns_result)) {
                    if (includeDebugLogs && DNS_DebugFlag) {
                        WCHAR msg[512];
                        Sbie_snwprintf(msg, 512, L"[EncDns] %s: RawResponseLen=%d, Success=%d, Status=%d, HasCname=%d, CnameTarget=%s",
                            apiName ? apiName : L"DnsQuery", encdns_result.RawResponseLen, encdns_result.Success,
                            encdns_result.Status, encdns_result.HasCname,
                            encdns_result.CnameTarget[0] ? encdns_result.CnameTarget : L"(none)");
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                    }

                    if (encdns_result.RawResponseLen > 0 && __sys_DnsExtractRecordsFromMessage_W && encdns_result.Success) {
                        // DnsExtractRecordsFromMessage_W expects HOST byte order, but DoH/DoQ returns NETWORK byte order
                        DNS_FlipHeaderToHost(encdns_result.RawResponse, encdns_result.RawResponseLen);

                        PDNS_RECORD pRecords = NULL;
                        DNS_STATUS extractStatus = __sys_DnsExtractRecordsFromMessage_W(
                            (PDNS_MESSAGE_BUFFER)encdns_result.RawResponse,
                            (WORD)encdns_result.RawResponseLen,
                            &pRecords);

                        if (includeDebugLogs && DNS_DebugFlag) {
                            WCHAR msg[512];
                            Sbie_snwprintf(msg, 512, L"[EncDns] %s: extractStatus=%d, pRecords=%p",
                                apiName ? apiName : L"DnsQuery", extractStatus, pRecords);
                            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                        }

                        if (extractStatus == 0 && pRecords) {
                            WCHAR sourceTag[64];
                            if (apiName && wcscmp(apiName, L"DnsQuery_A") == 0) {
                                Sbie_snwprintf(sourceTag, ARRAYSIZE(sourceTag), L"%s EncDns(%s)",
                                               apiName, EncryptedDns_GetModeName(encdns_result.ProtocolUsed));
                            } else {
                                DNS_FormatEncDnsSourceTag(sourceTag, ARRAYSIZE(sourceTag), apiName, encdns_result.ProtocolUsed);
                            }
                            DNS_LogDnsQueryResultWithReason(sourceTag, wName, wType,
                                                           DNS_RCODE_NOERROR, (PDNS_RECORDW*)&pRecords, passthroughReason);
                            *ppQueryResults = (PDNSAPI_DNS_RECORD)pRecords;
                            return DNS_RCODE_NOERROR;
                        }

                        if (extractStatus == 0) {
                            if (includeDebugLogs && DNS_DebugFlag) {
                                WCHAR msg[256];
                                Sbie_snwprintf(msg, 256, L"[EncDns] %s: extractStatus=0 but pRecords=NULL (type %d may not be extracted)",
                                    apiName ? apiName : L"DnsQuery", wType);
                                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                            }
                            {
                                WCHAR sourceTag[64];
                                DNS_FormatEncDnsSourceTag(sourceTag, ARRAYSIZE(sourceTag), apiName, encdns_result.ProtocolUsed);
                                DNS_LogDnsQueryResultWithReason(sourceTag, wName, wType,
                                                               DNS_INFO_NO_RECORDS, NULL, passthroughReason);
                            }
                            *ppQueryResults = NULL;
                            return DNS_INFO_NO_RECORDS;
                        }

                        if (includeDebugLogs && DNS_DebugFlag) {
                            WCHAR msg[256];
                            Sbie_snwprintf(msg, 256, L"[EncDns] %s: extraction failed with status=%d",
                                apiName ? apiName : L"DnsQuery", extractStatus);
                            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                        }

                        // Fallback: If extraction failed but we have CNAME data from EncDns parsing,
                        // manually build a CNAME record.
                        if (encdns_result.HasCname && encdns_result.CnameTarget[0] != L'\0' && wType == DNS_TYPE_CNAME) {
                            if (includeDebugLogs && DNS_DebugFlag) {
                                WCHAR msg[512];
                                Sbie_snwprintf(msg, 512, L"[EncDns] %s: Fallback - building CNAME record manually for %s -> %s",
                                    apiName ? apiName : L"DnsQuery", encdns_result.CnameOwner, encdns_result.CnameTarget);
                                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                            }

                            LIST empty_list;
                            List_Init(&empty_list);
                            PDNSAPI_DNS_RECORD pCnameResult = DNSAPI_BuildDnsRecordList(wName, wType, &empty_list, recordCharSet, &encdns_result);
                            if (pCnameResult) {
                                WCHAR sourceTag[64];
                                if (apiName && wcscmp(apiName, L"DnsQuery_A") == 0) {
                                    Sbie_snwprintf(sourceTag, ARRAYSIZE(sourceTag), L"%s EncDns(%s)",
                                                   apiName, EncryptedDns_GetModeName(encdns_result.ProtocolUsed));
                                } else {
                                    DNS_FormatEncDnsSourceTag(sourceTag, ARRAYSIZE(sourceTag), apiName, encdns_result.ProtocolUsed);
                                }
                                DNS_LogDnsQueryResultWithReason(sourceTag, wName, wType,
                                                               DNS_RCODE_NOERROR, (PDNS_RECORDW*)&pCnameResult, passthroughReason);
                                *ppQueryResults = pCnameResult;
                                return DNS_RCODE_NOERROR;
                            }
                        }
                    }

                    DNS_STATUS returnStatus = encdns_result.Status ? encdns_result.Status : DNS_INFO_NO_RECORDS;
                    {
                        WCHAR sourceTag[64];
                        DNS_FormatEncDnsSourceTag(sourceTag, ARRAYSIZE(sourceTag), apiName, encdns_result.ProtocolUsed);
                        DNS_LogDnsQueryResultWithReason(sourceTag, wName, wType,
                                                       returnStatus, NULL, passthroughReason);
                    }
                    *ppQueryResults = NULL;
                    return returnStatus;
                }

                // Query failed - return NXDOMAIN
                {
                    WCHAR sourceTag[64];
                    Sbie_snwprintf(sourceTag, ARRAYSIZE(sourceTag), L"%s EncDns", apiName ? apiName : L"DnsQuery");
                    DNS_LogDnsQueryResultWithReason(sourceTag, wName, wType,
                                                   DNS_ERROR_RCODE_NAME_ERROR, NULL, passthroughReason);
                }
                *ppQueryResults = NULL;
                return DNS_ERROR_RCODE_NAME_ERROR;
            }
        }
    }

    // System DNS passthrough
    if (!sysQuery) {
        if (ppQueryResults)
            *ppQueryResults = NULL;
        return DNS_ERROR_RCODE_SERVER_FAILURE;
    }

    DNS_STATUS status = sysQuery(pszName, wType, Options, pExtra, ppQueryResults, pReserved);

    // Convert narrow domain to wide for logging
    if (DNS_TraceFlag && pszName) {
        int nameLen = MultiByteToWideChar(codePage, 0, pszName, -1, NULL, 0);
        if (nameLen > 0 && nameLen < 512) {
            WCHAR* wName = (WCHAR*)Dll_AllocTemp(nameLen * sizeof(WCHAR));
            if (wName && MultiByteToWideChar(codePage, 0, pszName, -1, wName, nameLen)) {
                DNS_LogDnsQueryResultWithReason(tagPassthrough, wName, wType,
                                               status, ppQueryResults, passthroughReason);
            }
        }
    }

    return status;
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
    DNS_PASSTHROUGH_REASON passthroughReason = DNS_PASSTHROUGH_NONE;
    
    if (DNS_FilterEnabled && pszName) {
        ULONG path_len = wcslen(pszName);
        WCHAR* path_lwr = (WCHAR*)Dll_AllocTemp((path_len + 4) * sizeof(WCHAR));
        wmemcpy(path_lwr, pszName, path_len);
        path_lwr[path_len] = L'\0';
        _wcslwr(path_lwr);

        {
            DNS_EXCLUDE_RESOLVE_MODE excludeMode = DNS_EXCLUDE_RESOLVE_SYS;
            if (DNS_IsExcludedEx(path_lwr, &excludeMode)) {
                DNS_LogExclusion(path_lwr);
                Dll_Free(path_lwr);
                if (excludeMode == DNS_EXCLUDE_RESOLVE_SYS) {
                            DNS_STATUS ex_status = __sys_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
                            DNS_LogDnsQueryResultWithReason(L"DnsQuery_W Passthrough", pszName, wType,
                                                           ex_status, ppQueryResults, DNS_PASSTHROUGH_EXCLUDED);
                            return ex_status;
                }
                // Excluded from filtering but forced to EncDns for passthrough.
                goto passthrough_dnsquery_w;
            }
        }

        PATTERN* found = NULL;
        if (DNS_DomainMatchPatternList(path_lwr, path_len, &DNS_FilterList, &found) > 0) {
            PVOID* aux = Pattern_Aux(found);
            if (!aux || !*aux) {
                // Pattern matched but no aux data (config issue) - passthrough
                // Fall through to passthrough path which logs with IPs
            } else {
                // Certificate required for actual filtering (interception/blocking)
                extern BOOLEAN DNS_HasValidCertificate;
                if (!DNS_HasValidCertificate) {
                    // Domain matches filter but no cert - call real DNS and log result with IPs
                    Dll_Free(path_lwr);
                    DNS_STATUS status = __sys_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
                    DNS_LogDnsQueryResultWithReason(L"DnsQuery_W Passthrough", pszName, wType, 
                                                   status, ppQueryResults, DNS_PASSTHROUGH_NO_CERT);
                    return status;
                }

                LIST* pEntries = NULL;
                DNS_TYPE_FILTER* type_filter = NULL;
                DNS_ExtractFilterAux(aux, &pEntries, &type_filter);

                DNS_STATUS status;
                BOOLEAN passthroughLogged = FALSE;
                if (DNSAPI_FilterDnsQuery(pszName, wType, pEntries, type_filter, DnsCharSetUnicode,
                                          L"DnsQuery_W Intercepted", ppQueryResults, &status, 
                                          &passthroughLogged, &passthroughReason)) {
                    Dll_Free(path_lwr);
                    return status;
                }

                // Not filtered by type - passthrough to real DNS (logged with IPs and reason below)
            }
        }

        Dll_Free(path_lwr);
    }

passthrough_dnsquery_w:
    // Call original DnsQuery_W (or use EncDns exclusively if enabled)
    DNS_STATUS status;
    
    // Try encrypted DNS for all passthrough queries when enabled
    // When encrypted DNS is enabled, we should ONLY use it - no fallback to system DNS
    if (EncryptedDns_IsEnabled() && pszName) {
        // For A/AAAA queries, perform actual EncDns lookup
        if (wType == DNS_TYPE_A || wType == DNS_TYPE_AAAA) {
            LIST doh_list;
            DOH_RESULT encdns_result;
            if (DNS_TryDoHQuery(pszName, wType, &doh_list, &encdns_result)) {
                PDNSAPI_DNS_RECORD pResult = DNSAPI_BuildDnsRecordList(pszName, wType, &doh_list, DnsCharSetUnicode, &encdns_result);
                if (pResult) {
                    WCHAR sourceTag[64];
                    Sbie_snwprintf(sourceTag, ARRAYSIZE(sourceTag), L"DnsQuery_W EncDns(%s)",
                                   EncryptedDns_GetModeName(encdns_result.ProtocolUsed));
                    DNS_LogDnsQueryResultWithReason(sourceTag, pszName, wType,
                                                   DNS_RCODE_NOERROR, (PDNS_RECORDW*)&pResult, passthroughReason);
                    DNS_FreeIPEntryList(&doh_list);
                    *ppQueryResults = pResult;
                    return DNS_RCODE_NOERROR;
                }
                DNS_FreeIPEntryList(&doh_list);
            }
            // EncDns query failed or returned no records - return DNS error instead of fallback
            {
                WCHAR sourceTag[64];
                DNS_FormatEncDnsSourceTag(sourceTag, ARRAYSIZE(sourceTag), L"DnsQuery_W", encdns_result.ProtocolUsed);
                DNS_LogDnsQueryResultWithReason(sourceTag, pszName, wType,
                                               DNS_ERROR_RCODE_NAME_ERROR, NULL, passthroughReason);
            }
            *ppQueryResults = NULL;
            return DNS_ERROR_RCODE_NAME_ERROR;
        }
        
        // For non-A/AAAA queries (MX, TXT, SRV, etc.), query encrypted DNS and parse raw response
        DOH_RESULT encdns_result;
        if (EncryptedDns_Query(pszName, wType, &encdns_result)) {
            if (DNS_DebugFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"[EncDns] DnsQuery_W: RawResponseLen=%d, Success=%d, Status=%d, HasCname=%d, CnameTarget=%s", 
                    encdns_result.RawResponseLen, encdns_result.Success, encdns_result.Status, encdns_result.HasCname,
                    encdns_result.CnameTarget[0] ? encdns_result.CnameTarget : L"(none)");
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            
            // Check if we have raw response data and DnsExtractRecordsFromMessage_W is available
            if (encdns_result.RawResponseLen > 0 && __sys_DnsExtractRecordsFromMessage_W && encdns_result.Success) {
                // DnsExtractRecordsFromMessage_W expects HOST byte order, but DoH/DoQ returns NETWORK byte order
                // Flip header counts from network to host order before extraction
                DNS_FlipHeaderToHost(encdns_result.RawResponse, encdns_result.RawResponseLen);
                
                PDNS_RECORD pRecords = NULL;
                DNS_STATUS extractStatus = __sys_DnsExtractRecordsFromMessage_W(
                    (PDNS_MESSAGE_BUFFER)encdns_result.RawResponse,
                    (WORD)encdns_result.RawResponseLen,
                    &pRecords);

                if (DNS_DebugFlag) {
                    WCHAR msg[512];
                    Sbie_snwprintf(msg, 512, L"[EncDns] DnsQuery_W: extractStatus=%d, pRecords=%p", extractStatus, pRecords);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }

                if (extractStatus == 0 && pRecords) {
                    // Success - return extracted records
                    WCHAR sourceTag[64];
                    Sbie_snwprintf(sourceTag, ARRAYSIZE(sourceTag), L"DnsQuery_W EncDns(%s)",
                                   EncryptedDns_GetModeName(encdns_result.ProtocolUsed));
                    DNS_LogDnsQueryResultWithReason(sourceTag, pszName, wType,
                                                   DNS_RCODE_NOERROR, (PDNS_RECORDW*)&pRecords, passthroughReason);
                    *ppQueryResults = (PDNSAPI_DNS_RECORD)pRecords;
                    return DNS_RCODE_NOERROR;
                }
                
                // Extraction succeeded but no records - return NODATA (success with no records)
                if (extractStatus == 0) {
                    if (DNS_DebugFlag) {
                        WCHAR msg[256];
                        Sbie_snwprintf(msg, 256, L"[EncDns] DnsQuery_W: extractStatus=0 but pRecords=NULL (type %d may not be extracted)", wType);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                    }
                    {
                        WCHAR sourceTag[64];
                        DNS_FormatEncDnsSourceTag(sourceTag, ARRAYSIZE(sourceTag), L"DnsQuery_W", encdns_result.ProtocolUsed);
                        DNS_LogDnsQueryResultWithReason(sourceTag, pszName, wType,
                                                       DNS_INFO_NO_RECORDS, NULL, passthroughReason);
                    }
                    *ppQueryResults = NULL;
                    return DNS_INFO_NO_RECORDS;
                }
                
                // extractStatus != 0 - extraction failed
                if (DNS_DebugFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"[EncDns] DnsQuery_W: extraction failed with status=%d", extractStatus);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
                
                // Fallback: If extraction failed but we have CNAME data from EncDns parsing,
                // manually build a CNAME record. This handles cases where Windows API
                // cannot parse the DNS wire format (e.g., 9502 DNS_ERROR_BAD_PACKET).
                if (encdns_result.HasCname && encdns_result.CnameTarget[0] != L'\0' && wType == DNS_TYPE_CNAME) {
                    if (DNS_DebugFlag) {
                        WCHAR msg[512];
                        Sbie_snwprintf(msg, 512, L"[EncDns] DnsQuery_W: Fallback - building CNAME record manually for %s -> %s",
                            encdns_result.CnameOwner, encdns_result.CnameTarget);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                    }
                    
                    // Use DNSAPI_BuildDnsRecordList with empty IP list to build just the CNAME record
                    LIST empty_list;
                    List_Init(&empty_list);
                    PDNSAPI_DNS_RECORD pCnameResult = DNSAPI_BuildDnsRecordList(pszName, wType, &empty_list, DnsCharSetUnicode, &encdns_result);
                    if (pCnameResult) {
                        WCHAR sourceTag[64];
                        Sbie_snwprintf(sourceTag, ARRAYSIZE(sourceTag), L"DnsQuery_W EncDns(%s)",
                                       EncryptedDns_GetModeName(encdns_result.ProtocolUsed));
                        DNS_LogDnsQueryResultWithReason(sourceTag, pszName, wType,
                                                       DNS_RCODE_NOERROR, (PDNS_RECORDW*)&pCnameResult, passthroughReason);
                        *ppQueryResults = pCnameResult;
                        return DNS_RCODE_NOERROR;
                    }
                }
            }
            
            // Return status from DNS response
            DNS_STATUS returnStatus = encdns_result.Status ? encdns_result.Status : DNS_INFO_NO_RECORDS;
            {
                WCHAR sourceTag[64];
                DNS_FormatEncDnsSourceTag(sourceTag, ARRAYSIZE(sourceTag), L"DnsQuery_W", encdns_result.ProtocolUsed);
                DNS_LogDnsQueryResultWithReason(sourceTag, pszName, wType,
                                               returnStatus, NULL, passthroughReason);
            }
            *ppQueryResults = NULL;
            return returnStatus;
        }
        
        // Query failed - return NXDOMAIN
        DNS_LogDnsQueryResultWithReason(L"DnsQuery_W EncDns", pszName, wType,
                                       DNS_ERROR_RCODE_NAME_ERROR, NULL, passthroughReason);
        *ppQueryResults = NULL;
        return DNS_ERROR_RCODE_NAME_ERROR;
    }
    
    // EncDns disabled - use system DNS
    status = __sys_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);

    DNS_LogDnsQueryResultWithReason(L"DnsQuery_W Passthrough", pszName, wType, 
                                   status, ppQueryResults, passthroughReason);

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
    return DNSAPI_DnsQuery_NarrowCommon(
        pszName,
        wType,
        Options,
        pExtra,
        ppQueryResults,
        pReserved,
        CP_ACP,
        DnsCharSetAnsi,
        L"DnsQuery_A",
        L"DnsQuery_A Passthrough",
        L"DnsQuery_A Intercepted",
        (DNSAPI_P_DnsQuery_NarrowSys)__sys_DnsQuery_A,
        TRUE);
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
    DNSAPI_P_DnsQuery_NarrowSys sysQuery = (DNSAPI_P_DnsQuery_NarrowSys)(__sys_DnsQuery_UTF8 ? __sys_DnsQuery_UTF8 : __sys_DnsQuery_A);
    return DNSAPI_DnsQuery_NarrowCommon(
        pszName,
        wType,
        Options,
        pExtra,
        ppQueryResults,
        pReserved,
        CP_UTF8,
        DnsCharSetUtf8,
        L"DnsQuery_UTF8",
        L"DnsQuery_UTF8 Passthrough",
        L"DnsQuery_UTF8 Intercepted",
        sysQuery,
        FALSE);
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
        DNS_LogDnsRecordsWithReason(L"DnsQueryRaw Passthrough", ctx->Domain, 
            ctx->QueryType, (PDNSAPI_DNS_RECORD)pQueryResults->queryRecords, ctx->PassthroughReason);
    } else {
        // No structured records - log with reason in status format
        DNS_LogDnsQueryResultWithReason(L"DnsQueryRaw Passthrough", ctx->Domain, ctx->QueryType,
                                        status, NULL, ctx->PassthroughReason);
    }

    // Call the original user callback
    if (ctx->OriginalCallback) {
        ctx->OriginalCallback(ctx->OriginalContext, pQueryResults);
    }

    // Free the context
    Dll_Free(ctx);
}

//---------------------------------------------------------------------------
// DNSAPI_TryDoHForQueryEx
//
// Helper: Try EncDns for DnsQueryEx passthrough queries
// Returns TRUE if EncDns succeeded and pQueryResults filled
// For ALL query types, queries the encrypted DNS server
// Non-A/AAAA types are parsed from raw DNS response using DnsExtractRecordsFromMessage_W
//---------------------------------------------------------------------------

static BOOLEAN DNSAPI_TryDoHForQueryEx(
    const WCHAR* pszName,
    WORD wType,
    ULONG64 queryOptions,
    PDNS_QUERY_RESULT pQueryResults,
    DNS_CHARSET CharSet,
    ENCRYPTED_DNS_MODE* protocolUsedOut)
{
    if (!pszName || !pQueryResults) {
        return FALSE;
    }

    if (protocolUsedOut)
        *protocolUsedOut = ENCRYPTED_DNS_MODE_AUTO;

    // Check if encrypted DNS is enabled
    if (!EncryptedDns_IsEnabled()) {
        return FALSE;
    }

    // For A/AAAA types, use the existing IP-focused path
    if (wType == DNS_TYPE_A || wType == DNS_TYPE_AAAA) {
        LIST doh_list;
        DOH_RESULT encdns_result;
        if (!DNS_TryDoHQuery(pszName, wType, &doh_list, &encdns_result)) {
            return FALSE;
        }

        if (protocolUsedOut)
            *protocolUsedOut = encdns_result.ProtocolUsed;

        PDNSAPI_DNS_RECORD pRecords = DNSAPI_BuildDnsRecordList(pszName, wType, &doh_list, CharSet, &encdns_result);
        DNS_FreeIPEntryList(&doh_list);

        if (!pRecords) {
            // Empty result is still valid (NODATA)
            if (pQueryResults->Version == 0)
                pQueryResults->Version = DNS_QUERY_RESULTS_VERSION1;
            pQueryResults->QueryOptions = queryOptions;
            pQueryResults->pQueryRecords = NULL;
            pQueryResults->Reserved = NULL;
            pQueryResults->QueryStatus = 0;  // NOERROR with no records
            return TRUE;
        }

        // Fill query results
        if (pQueryResults->Version == 0)
            pQueryResults->Version = DNS_QUERY_RESULTS_VERSION1;
        pQueryResults->QueryOptions = queryOptions;
        pQueryResults->pQueryRecords = pRecords;
        pQueryResults->Reserved = NULL;
        pQueryResults->QueryStatus = 0;

        return TRUE;
    }

    // For non-A/AAAA types (TXT, MX, SRV, etc.), query encrypted DNS and parse raw response
    DOH_RESULT encdns_result;
    if (!EncryptedDns_Query(pszName, wType, &encdns_result)) {
        return FALSE;
    }

    if (protocolUsedOut)
        *protocolUsedOut = encdns_result.ProtocolUsed;

    // Check for DNS error status
    if (!encdns_result.Success) {
        if (pQueryResults->Version == 0)
            pQueryResults->Version = DNS_QUERY_RESULTS_VERSION1;
        pQueryResults->QueryOptions = queryOptions;
        pQueryResults->pQueryRecords = NULL;
        pQueryResults->Reserved = NULL;
        pQueryResults->QueryStatus = encdns_result.Status ? encdns_result.Status : DNS_ERROR_RCODE_NAME_ERROR;
        return TRUE;
    }

    // If we have raw response data and DnsExtractRecordsFromMessage_W is available, parse it
    if (encdns_result.RawResponseLen > 0 && __sys_DnsExtractRecordsFromMessage_W) {
        // DnsExtractRecordsFromMessage_W expects HOST byte order, but DoH/DoQ returns NETWORK byte order
        // Flip header counts from network to host order before extraction
        DNS_FlipHeaderToHost(encdns_result.RawResponse, encdns_result.RawResponseLen);
        
        PDNS_RECORD pRecords = NULL;
        DNS_STATUS status = __sys_DnsExtractRecordsFromMessage_W(
            (PDNS_MESSAGE_BUFFER)encdns_result.RawResponse,
            (WORD)encdns_result.RawResponseLen,
            &pRecords);

        if (status == 0 && pRecords) {
            // Success - return extracted records
            if (pQueryResults->Version == 0)
                pQueryResults->Version = DNS_QUERY_RESULTS_VERSION1;
            pQueryResults->QueryOptions = queryOptions;
            pQueryResults->pQueryRecords = pRecords;
            pQueryResults->Reserved = NULL;
            pQueryResults->QueryStatus = 0;
            return TRUE;
        }
        
        // Extraction failed - fallback to manually built CNAME record if available
        if (encdns_result.HasCname && encdns_result.CnameTarget[0] != L'\0' && wType == DNS_TYPE_CNAME) {
            LIST empty_list;
            List_Init(&empty_list);
            PDNSAPI_DNS_RECORD pCnameResult = DNSAPI_BuildDnsRecordList(pszName, wType, &empty_list, CharSet, &encdns_result);
            if (pCnameResult) {
                if (pQueryResults->Version == 0)
                    pQueryResults->Version = DNS_QUERY_RESULTS_VERSION1;
                pQueryResults->QueryOptions = queryOptions;
                pQueryResults->pQueryRecords = pCnameResult;
                pQueryResults->Reserved = NULL;
                pQueryResults->QueryStatus = 0;
                return TRUE;
            }
        }
        
        // Extraction failed and no fallback - return status from DNS response
        if (pQueryResults->Version == 0)
            pQueryResults->Version = DNS_QUERY_RESULTS_VERSION1;
        pQueryResults->QueryOptions = queryOptions;
        pQueryResults->pQueryRecords = NULL;
        pQueryResults->Reserved = NULL;
        pQueryResults->QueryStatus = encdns_result.Status;
        return TRUE;
    }

    // No raw response available (shouldn't happen) - return NODATA
    if (pQueryResults->Version == 0)
        pQueryResults->Version = DNS_QUERY_RESULTS_VERSION1;
    pQueryResults->QueryOptions = queryOptions;
    pQueryResults->pQueryRecords = NULL;
    pQueryResults->Reserved = NULL;
    pQueryResults->QueryStatus = encdns_result.Status ? encdns_result.Status : DNS_INFO_NO_RECORDS;
    return TRUE;
}

//---------------------------------------------------------------------------
// DNSAPI_DnsQueryEx
//---------------------------------------------------------------------------

static ULONG64 DNSAPI_SanitizeDnsQueryExQueryOptionsByType(
    ULONG requestVersion,
    WORD queryType,
    ULONG64 queryOptions,
    ULONG64 flagAddrConfig,
    ULONG64 flagDualAddr,
    BOOLEAN mapIpv4ToIpv6)
{
    if (requestVersion != DNS_QUERY_REQUEST_VERSION1 &&
        requestVersion != DNS_QUERY_REQUEST_VERSION2 &&
        requestVersion != DNS_QUERY_REQUEST_VERSION3)
    {
        return queryOptions;
    }

    const BOOLEAN isV3 = (requestVersion == DNS_QUERY_REQUEST_VERSION3);

    if (queryType == DNS_TYPE_A) {
        const ULONG64 PROBLEMATIC_FLAGS = flagAddrConfig | flagDualAddr;
        if (queryOptions & PROBLEMATIC_FLAGS) {
            ULONG64 beforeStrip = queryOptions;
            queryOptions &= ~PROBLEMATIC_FLAGS;
            DNS_LogQueryExStrippedFlags(
                isV3 ? L"VERSION3 A query - stripped DUAL_ADDR/ADDRCONFIG flags"
                     : L"VERSION1/2 A query - stripped DUAL_ADDR/ADDRCONFIG flags",
                beforeStrip,
                queryOptions);
        }
        return queryOptions;
    }

    if (queryType == DNS_TYPE_AAAA) {
        if (mapIpv4ToIpv6) {
            if (queryOptions & flagAddrConfig) {
                ULONG64 beforeStrip = queryOptions;
                queryOptions &= ~flagAddrConfig;
                DNS_LogQueryExStrippedFlags(
                    isV3 ? L"VERSION3 AAAA query - stripped ADDRCONFIG (keeping DUAL_ADDR for DnsMapIpv4ToIpv6=y)"
                         : L"VERSION1/2 AAAA query - stripped ADDRCONFIG (keeping DUAL_ADDR for DnsMapIpv4ToIpv6=y)",
                    beforeStrip,
                    queryOptions);
            }
            return queryOptions;
        }

        {
            const ULONG64 PROBLEMATIC_FLAGS = flagAddrConfig | flagDualAddr;
            if (queryOptions & PROBLEMATIC_FLAGS) {
                ULONG64 beforeStrip = queryOptions;
                queryOptions &= ~PROBLEMATIC_FLAGS;
                DNS_LogQueryExStrippedFlags(
                    isV3 ? L"VERSION3 AAAA query - stripped DUAL_ADDR/ADDRCONFIG (DnsMapIpv4ToIpv6=n)"
                         : L"VERSION1/2 AAAA query - stripped DUAL_ADDR/ADDRCONFIG (DnsMapIpv4ToIpv6=n)",
                    beforeStrip,
                    queryOptions);
            }
            return queryOptions;
        }
    }

    // For non-A/AAAA queries, strip DUAL_ADDR unconditionally (invalid outside A/AAAA scenarios).
    if (queryOptions & flagDualAddr) {
        ULONG64 beforeStrip = queryOptions;
        queryOptions &= ~flagDualAddr;
        DNS_LogQueryExStrippedFlags(
            isV3 ? L"VERSION3 non-A/AAAA query - stripped DUAL_ADDR flag"
                 : L"VERSION1/2 non-A/AAAA query - stripped DUAL_ADDR flag",
            beforeStrip,
            queryOptions);
    }
    return queryOptions;
}

static ULONG64 DNSAPI_BuildDnsQueryExFallbackOptions(
    WORD queryType,
    ULONG64 queryOptions,
    ULONG64 flagAddrConfig,
    ULONG64 flagDualAddr)
{
    // Fallback is intentionally conservative:
    // - Always drop DUAL_ADDR (frequently rejected by DnsQueryEx)
    // - For A queries, also drop ADDRCONFIG (can combine badly with other flags)
    queryOptions &= ~flagDualAddr;
    if (queryType == DNS_TYPE_A)
        queryOptions &= ~flagAddrConfig;
    return queryOptions;
}

static DNS_STATUS DNSAPI_CallSysDnsQueryExWithOverrides(
    PDNS_QUERY_REQUEST  pQueryRequest,
    PDNS_QUERY_RESULT   pQueryResults,
    PDNS_QUERY_CANCEL   pCancelHandle,
    BOOLEAN             overrideOptions,
    ULONG64             queryOptions,
    BOOLEAN             overrideInterfaceIndex,
    ULONG               interfaceIndex)
{
    ULONG64 savedOptions = 0;
    ULONG savedInterfaceIndex = 0;

    if (overrideOptions) {
        savedOptions = pQueryRequest->QueryOptions;
        pQueryRequest->QueryOptions = queryOptions;
    }

    if (overrideInterfaceIndex) {
        savedInterfaceIndex = pQueryRequest->InterfaceIndex;
        pQueryRequest->InterfaceIndex = interfaceIndex;
    }

    DNS_STATUS status = __sys_DnsQueryEx(pQueryRequest, pQueryResults, pCancelHandle);

    if (overrideInterfaceIndex) {
        pQueryRequest->InterfaceIndex = savedInterfaceIndex;
    }

    if (overrideOptions) {
        pQueryRequest->QueryOptions = savedOptions;
    }

    return status;
}


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
    
    // Not filtered - try EncDns for passthrough queries (but NOT for excluded domains)
    // Excluded domains should use system DNS directly
    if (pQueryRequest->QueryName) {
        size_t domain_len = wcslen(pQueryRequest->QueryName);
        WCHAR* domain_lwr = (WCHAR*)Dll_AllocTemp((domain_len + 4) * sizeof(WCHAR));
        if (domain_lwr) {
            wmemcpy(domain_lwr, pQueryRequest->QueryName, domain_len);
            domain_lwr[domain_len] = L'\0';
            _wcslwr(domain_lwr);
            
            DNS_EXCLUDE_RESOLVE_MODE excludeMode = DNS_EXCLUDE_RESOLVE_SYS;
            BOOLEAN is_excluded = DNS_IsExcludedEx(domain_lwr, &excludeMode);
            Dll_Free(domain_lwr);
            
            if (!is_excluded || excludeMode == DNS_EXCLUDE_RESOLVE_ENC) {
                // Not excluded (or excluded but forced to EncDns) - try EncDns
                ENCRYPTED_DNS_MODE protocolUsed = ENCRYPTED_DNS_MODE_AUTO;
                if (DNSAPI_TryDoHForQueryEx(pQueryRequest->QueryName, pQueryRequest->QueryType,
                                             pQueryRequest->QueryOptions, pQueryResults, DnsCharSetUnicode, &protocolUsed)) {
                    WCHAR prefix[64];
                    if (protocolUsed != ENCRYPTED_DNS_MODE_AUTO) {
                        Sbie_snwprintf(prefix, ARRAYSIZE(prefix), L"DnsQueryEx EncDns(%s)", EncryptedDns_GetModeName(protocolUsed));
                    } else {
                        wcscpy_s(prefix, ARRAYSIZE(prefix), L"DnsQueryEx EncDns");
                    }
                    DNS_LogDnsRecordsFromQueryResult(prefix, pQueryRequest->QueryName,
                                                    pQueryRequest->QueryType, 0, (PDNSAPI_DNS_RECORD)pQueryResults->pQueryRecords);
                    return 0;
                }
                // EncDns query failed or returned no records - return error when encrypted DNS is enabled
                if (EncryptedDns_IsEnabled()) {
                    WCHAR prefix[64];
                    DNS_FormatEncDnsSourceTag(prefix, ARRAYSIZE(prefix), L"DnsQueryEx", protocolUsed);
                    DNS_LogDnsQueryExStatus(prefix, pQueryRequest->QueryName,
                                           pQueryRequest->QueryType, DNS_ERROR_RCODE_NAME_ERROR);
                    if (pQueryResults) {
                        pQueryResults->QueryStatus = DNS_ERROR_RCODE_NAME_ERROR;
                        pQueryResults->pQueryRecords = NULL;
                    }
                    return DNS_ERROR_RCODE_NAME_ERROR;
                }
            }
        }
    }
    
    // If not filtered, passthrough logging with IPs happens after real DNS call below

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
    
    // Guard against obviously-corrupt QueryOptions that look like a stray pointer value.
    // Some callers (or uninitialized memory) can pass a pointer-sized value where flags are expected.
    // We only consider it "pointer-like" when it resembles a typical x64 user-mode canonical address
    // in the 0x00007F..-0x00007FFF.. range.
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
    
    // Additional sanitization based on query type and version:
    // - DUAL_ADDR is not accepted for many non-A/AAAA types (e.g., HTTPS/SVCB), causes ERROR_INVALID_PARAMETER (87)
    // - A queries: Windows rejects DUAL_ADDR combined with ADDRCONFIG; be strict and remove both for A
    // - AAAA queries:
    //   * ADDRCONFIG: Always strip
    //   * DUAL_ADDR: Strip when DnsMapIpv4ToIpv6=n, keep when DnsMapIpv4ToIpv6=y for IPv4-mapped IPv6
    sanitizedQueryOptions = DNSAPI_SanitizeDnsQueryExQueryOptionsByType(
        requestVersion,
        pQueryRequest->QueryType,
        sanitizedQueryOptions,
        DNS_QUERY_ADDRCONFIG,
        DNS_QUERY_DUAL_ADDR,
        DNS_MapIpv4ToIpv6);
    
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

    // If the call failed with ERROR_INVALID_PARAMETER, retry once with a conservative flag set.
    if (status == ERROR_INVALID_PARAMETER) {
        fallbackOptions = sanitizedQueryOptions;
        ULONG64 beforeFallback = fallbackOptions;
        fallbackOptions = DNSAPI_BuildDnsQueryExFallbackOptions(
            pQueryRequest->QueryType,
            fallbackOptions,
            DNS_QUERY_ADDRCONFIG,
            DNS_QUERY_DUAL_ADDR);
        fallbackPrepared = TRUE;

        if (fallbackOptions != beforeFallback) {
            DNS_LogQueryExErrorRetryReduction(L"ERROR_INVALID_PARAMETER", beforeFallback, fallbackOptions);
            status = DNSAPI_CallSysDnsQueryExWithOverrides(
                pQueryRequest,
                pQueryResults,
                pCancelHandle,
                TRUE,
                fallbackOptions,
                FALSE,
                0);
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

        status = DNSAPI_CallSysDnsQueryExWithOverrides(
            pQueryRequest,
            pQueryResults,
            pCancelHandle,
            TRUE,
            optionsForRetry,
            TRUE,
            0);
    }
    
    if (DNS_TraceFlag && pQueryRequest->QueryName) {
        // Debug: Log status and pQueryRecords pointer
        DNS_LogQueryExDebugStatus(status, asyncCtx, pQueryResults,
            pQueryResults ? pQueryResults->pQueryRecords : NULL, pQueryRequest->Version);
        
        if (status == DNS_REQUEST_PENDING && asyncCtx) {
            DNS_LogDnsQueryExStatus(L"DnsQueryEx Passthrough", pQueryRequest->QueryName, 
                                   pQueryRequest->QueryType, status);
        } else if (status == 0 && pQueryResults && pQueryResults->pQueryRecords) {
            // Sync call completed successfully - log with type filtering and reason
            DNS_LogDnsRecordsWithReason(L"DnsQueryEx Passthrough", pQueryRequest->QueryName, 
                            pQueryRequest->QueryType, (PDNSAPI_DNS_RECORD)pQueryResults->pQueryRecords, 
                            outcome.PassthroughReason);
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
// DNSAPI_GetQueryPacketForRaw
//
// Helper to obtain a DNS query packet for DnsQueryRaw handling.
// Prefers the caller-provided raw packet; otherwise builds a minimal template.
//---------------------------------------------------------------------------

static BOOLEAN DNSAPI_GetQueryPacketForRaw(
    const DNS_QUERY_RAW_REQUEST* pQueryRequest,
    const WCHAR* domain,
    USHORT qtype,
    BYTE* tempQuery,
    int tempQuerySize,
    const BYTE** queryPtr,
    int* queryLen)
{
    if (!pQueryRequest || !domain || !tempQuery || !queryPtr || !queryLen)
        return FALSE;

    *queryPtr = NULL;
    *queryLen = 0;

    if (pQueryRequest->dnsQueryRaw && pQueryRequest->dnsQueryRawSize > 0) {
        *queryPtr = pQueryRequest->dnsQueryRaw;
        *queryLen = (int)pQueryRequest->dnsQueryRawSize;
        return TRUE;
    }

    int built = DNS_BuildSimpleQuery(domain, qtype, tempQuery, tempQuerySize);
    if (built <= 0)
        return FALSE;

    *queryPtr = tempQuery;
    *queryLen = built;
    return TRUE;
}

//---------------------------------------------------------------------------
// DNSAPI_CompleteDnsQueryRaw
//
// Helper to complete a DnsQueryRaw request by invoking its completion callback
// with a caller-supplied raw response packet.
//---------------------------------------------------------------------------

static DNS_STATUS DNSAPI_CompleteDnsQueryRaw(
    PDNS_QUERY_RAW_REQUEST pQueryRequest,
    const BYTE* response,
    int response_len,
    DNS_STATUS queryStatus)
{
    if (!pQueryRequest || !pQueryRequest->queryCompletionCallback || !response || response_len <= 0)
        return 0;

    PDNS_QUERY_RAW_RESULT pResult = (PDNS_QUERY_RAW_RESULT)LocalAlloc(LPTR, sizeof(DNS_QUERY_RAW_RESULT));
    if (!pResult)
        return 0;

    pResult->version = DNS_QUERY_RAW_RESULTS_VERSION1;
    pResult->queryStatus = queryStatus;
    pResult->queryOptions = pQueryRequest->queryOptions;
    pResult->queryRawOptions = pQueryRequest->queryRawOptions;

    pResult->queryRawResponse = (BYTE*)LocalAlloc(LPTR, response_len);
    if (!pResult->queryRawResponse) {
        LocalFree(pResult);
        return 0;
    }

    pResult->queryRawResponseSize = response_len;
    memcpy(pResult->queryRawResponse, response, response_len);

    pQueryRequest->queryCompletionCallback(pQueryRequest->queryContext, pResult);
    return DNS_REQUEST_PENDING;
}

//---------------------------------------------------------------------------
// DNSAPI_TryDoHForDnsQueryRaw
//
// Attempt to satisfy a DnsQueryRaw request via EncryptedDnsServer (DoH).
// Returns TRUE if the request was completed via callback.
//---------------------------------------------------------------------------

static BOOLEAN DNSAPI_TryDoHForDnsQueryRaw(
    PDNS_QUERY_RAW_REQUEST pQueryRequest,
    const WCHAR* domain,
    USHORT qtype)
{
    if (!pQueryRequest || !domain || !*domain)
        return FALSE;

    if (!EncryptedDns_IsEnabled()) {
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"DnsQueryRaw EncDns: Encrypted DNS not enabled");
        }
        return FALSE;
    }

    // Avoid re-entrancy loops.
    if (EncryptedDns_IsQueryActive()) {
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"DnsQueryRaw EncDns: Re-entrancy detected, skipping");
        }
        return FALSE;
    }

    // DnsQueryRaw requires a completion callback - if not provided, we can't return results
    // (DnsQueryRaw is async-only, but some callers may not set callback properly)
    if (!pQueryRequest->queryCompletionCallback) {
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"DnsQueryRaw EncDns: No callback provided, cannot intercept");
        }
        return FALSE;
    }

    BYTE tempQuery[512];
    const BYTE* queryPtr = NULL;
    int queryLen = 0;
    if (!DNSAPI_GetQueryPacketForRaw(pQueryRequest, domain, qtype, tempQuery, sizeof(tempQuery), &queryPtr, &queryLen)) {
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"DnsQueryRaw EncDns: Failed to get query packet");
        }
        return FALSE;
    }

    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"DnsQueryRaw EncDns: Attempting query for %s (Type: %s)", domain, DNS_GetTypeName(qtype));
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // Query encrypted DNS directly (don't use DNS_TryDoHQuery which only returns A/AAAA)
    DOH_RESULT encdns_result;
    BOOLEAN doh_ok = EncryptedDns_Query(domain, qtype, &encdns_result);

    if (DNS_DebugFlag) {
        WCHAR msg[256];
        if (doh_ok && encdns_result.ProtocolUsed != ENCRYPTED_DNS_MODE_AUTO) {
            Sbie_snwprintf(msg, 256, L"DnsQueryRaw EncDns: EncryptedDns_Query returned TRUE for %s (used=%s)",
                domain, EncryptedDns_GetModeName(encdns_result.ProtocolUsed));
        } else {
            Sbie_snwprintf(msg, 256, L"DnsQueryRaw EncDns: EncryptedDns_Query returned %s for %s",
                doh_ok ? L"TRUE" : L"FALSE", domain);
        }
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    BYTE response[4096];
    int response_len = 0;
    DNS_STATUS status = 0;

    if (doh_ok && encdns_result.Success) {
        // For non-A/AAAA types (MX, TXT, CNAME, SRV, etc.), use raw wire format response
        // This ensures all DNS record types work through encrypted DNS
        if (qtype != DNS_TYPE_A && qtype != DNS_TYPE_AAAA) {
            if (encdns_result.RawResponseLen > 0 && encdns_result.RawResponseLen <= sizeof(response)) {
                // Copy raw DNS response directly (already in wire format)
                memcpy(response, encdns_result.RawResponse, encdns_result.RawResponseLen);
                response_len = (int)encdns_result.RawResponseLen;
                
                if (DNS_DebugFlag) {
                    WCHAR msg[512];
                    Sbie_snwprintf(msg, 512, L"DnsQueryRaw EncDns: Using raw response for %s (Type: %s, len: %d)",
                        domain, DNS_GetTypeName(qtype), response_len);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
            }
        } else {
            // For A/AAAA types, build IP list from encdns_result and use Socket_BuildDnsResponse
            LIST doh_list;
            List_Init(&doh_list);
            
            for (int i = 0; i < encdns_result.AnswerCount && i < 32; i++) {
                IP_ENTRY* entry = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
                if (entry) {
                    entry->Type = encdns_result.Answers[i].Type;
                    memcpy(&entry->IP, &encdns_result.Answers[i].IP, sizeof(IP_ADDRESS));
                    List_Insert_After(&doh_list, NULL, entry);
                }
            }
            
            response_len = Socket_BuildDnsResponse(
                queryPtr,
                queryLen,
                &doh_list,
                FALSE,
                response,
                sizeof(response),
                qtype,
                NULL);
                
            // Free the temporary IP list
            DNS_FreeIPEntryList(&doh_list);
        }
        status = 0;
    }

    if (response_len <= 0) {
        // EncDns is configured but we couldn't satisfy the request; return NXDOMAIN (no fallback).
        if (queryLen < 12)
            return FALSE;

        int copyLen = (queryLen < (int)sizeof(response)) ? queryLen : (int)sizeof(response);
        memcpy(response, queryPtr, copyLen);

        // Set response flags to NXDOMAIN (0x8183)
        response[2] = 0x81;
        response[3] = 0x83;

        // Zero AN/NS/AR counts
        response[6] = 0;
        response[7] = 0;
        response[8] = 0;
        response[9] = 0;
        response[10] = 0;
        response[11] = 0;

        response_len = copyLen;
        status = DNS_ERROR_RCODE_NAME_ERROR;

        {
            WCHAR sourceTag[64];
            DNS_FormatEncDnsSourceTag(sourceTag, ARRAYSIZE(sourceTag), L"DnsQueryRaw", encdns_result.ProtocolUsed);
            DNS_LogBlocked(sourceTag, domain, qtype, L"EncDns failed (no fallback)");
        }
    } else {
        USHORT answer_count = 0;
        if (response_len >= 8) {
            answer_count = _ntohs(*(USHORT*)(response + 6));
        }

        if (answer_count > 0) {
            // For logging, build temporary IP list from encdns_result
            LIST log_list;
            List_Init(&log_list);
            
            if (qtype == DNS_TYPE_A || qtype == DNS_TYPE_AAAA) {
                for (int i = 0; i < encdns_result.AnswerCount && i < 32; i++) {
                    IP_ENTRY* entry = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
                    if (entry) {
                        entry->Type = encdns_result.Answers[i].Type;
                        memcpy(&entry->IP, &encdns_result.Answers[i].IP, sizeof(IP_ADDRESS));
                        List_Insert_After(&log_list, NULL, entry);
                    }
                }
            }
            
            {
                WCHAR sourceTag[64];
                DNS_FormatEncDnsSourceTag(sourceTag, ARRAYSIZE(sourceTag), L"DnsQueryRaw", encdns_result.ProtocolUsed);
                DNS_LogIntercepted(sourceTag, domain, qtype, &log_list, TRUE);
            }
            DNS_FreeIPEntryList(&log_list);
        } else {
            WCHAR sourceTag[64];
            DNS_FormatEncDnsSourceTag(sourceTag, ARRAYSIZE(sourceTag), L"DnsQueryRaw", encdns_result.ProtocolUsed);
            DNS_LogInterceptedNoData(sourceTag, domain, qtype, L"NODATA");
        }
    }

    return (DNSAPI_CompleteDnsQueryRaw(pQueryRequest, response, response_len, status) == DNS_REQUEST_PENDING);
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

    if (!parsed) {
        return __sys_DnsQueryRaw(pQueryRequest, pCancelHandle);
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

                    {
                        DNS_EXCLUDE_RESOLVE_MODE excludeMode = DNS_EXCLUDE_RESOLVE_SYS;
                        if (DNS_IsExcludedEx(domain_lwr, &excludeMode)) {
                            DNS_LogExclusion(domain_lwr);
                            if (excludeMode == DNS_EXCLUDE_RESOLVE_ENC) {
                                Dll_Free(domain_lwr);
                                if (DNSAPI_TryDoHForDnsQueryRaw(pQueryRequest, domain, qtype))
                                    return DNS_REQUEST_PENDING;
                                // Fallback to system DNS: wrap callback to log completion status with IPs
                                if (pQueryRequest->queryCompletionCallback) {
                                    DNSAPI_RAW_PASSTHROUGH_CONTEXT* ctx = (DNSAPI_RAW_PASSTHROUGH_CONTEXT*)
                                        Dll_Alloc(sizeof(DNSAPI_RAW_PASSTHROUGH_CONTEXT));
                                    if (ctx) {
                                        ctx->OriginalCallback = pQueryRequest->queryCompletionCallback;
                                        ctx->OriginalContext = pQueryRequest->queryContext;
                                        wcsncpy(ctx->Domain, domain, 255);
                                        ctx->Domain[255] = L'\0';
                                        ctx->QueryType = qtype;
                                        ctx->PassthroughReason = DNS_PASSTHROUGH_EXCLUDED;

                                        pQueryRequest->queryCompletionCallback = DNSAPI_RawPassthroughCallbackWrapper;
                                        pQueryRequest->queryContext = ctx;
                                    }
                                }
                                return __sys_DnsQueryRaw(pQueryRequest, pCancelHandle);
                            }
                            // Excluded + sys: system DNS directly
                            Dll_Free(domain_lwr);
                            // Wrap callback to log completion status with IPs
                            if (pQueryRequest->queryCompletionCallback) {
                                DNSAPI_RAW_PASSTHROUGH_CONTEXT* ctx = (DNSAPI_RAW_PASSTHROUGH_CONTEXT*)
                                    Dll_Alloc(sizeof(DNSAPI_RAW_PASSTHROUGH_CONTEXT));
                                if (ctx) {
                                    ctx->OriginalCallback = pQueryRequest->queryCompletionCallback;
                                    ctx->OriginalContext = pQueryRequest->queryContext;
                                    wcsncpy(ctx->Domain, domain, 255);
                                    ctx->Domain[255] = L'\0';
                                    ctx->QueryType = qtype;
                                    ctx->PassthroughReason = DNS_PASSTHROUGH_EXCLUDED;

                                    pQueryRequest->queryCompletionCallback = DNSAPI_RawPassthroughCallbackWrapper;
                                    pQueryRequest->queryContext = ctx;
                                }
                            }
                            return __sys_DnsQueryRaw(pQueryRequest, pCancelHandle);
                        }
                    }

                    // Check if domain matches filter
                    PATTERN* found = NULL;
                    if (DNS_FilterEnabled && DNS_DomainMatchPatternList(domain_lwr, domain_len, &DNS_FilterList, 
                                             &found) > 0) {
                        PVOID* aux = Pattern_Aux(found);
                        if (aux && *aux) {
                            // Certificate required for actual filtering (interception/blocking)
                            extern BOOLEAN DNS_HasValidCertificate;
                            if (!DNS_HasValidCertificate) {
                                // Domain matches filter but no cert - passthrough (logged via callback with IPs)
                                Dll_Free(domain_lwr);

                                if (DNSAPI_TryDoHForDnsQueryRaw(pQueryRequest, domain, qtype))
                                    return DNS_REQUEST_PENDING;
                                
                                // Wrap callback to log completion status
                                if (pQueryRequest->queryCompletionCallback) {
                                    DNSAPI_RAW_PASSTHROUGH_CONTEXT* ctx = (DNSAPI_RAW_PASSTHROUGH_CONTEXT*)
                                        Dll_Alloc(sizeof(DNSAPI_RAW_PASSTHROUGH_CONTEXT));
                                    if (ctx) {
                                        ctx->OriginalCallback = pQueryRequest->queryCompletionCallback;
                                        ctx->OriginalContext = pQueryRequest->queryContext;
                                        wcsncpy(ctx->Domain, domain, 255);
                                        ctx->Domain[255] = L'\0';
                                        ctx->QueryType = qtype;
                                        ctx->PassthroughReason = DNS_PASSTHROUGH_NO_CERT;
                                        
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
                                // Negated types always passthrough - callback wrapper will log with IPs
                                Dll_Free(domain_lwr);

                                if (DNSAPI_TryDoHForDnsQueryRaw(pQueryRequest, domain, qtype))
                                    return DNS_REQUEST_PENDING;
                                
                                // Wrap callback to log completion status
                                if (pQueryRequest->queryCompletionCallback) {
                                    DNSAPI_RAW_PASSTHROUGH_CONTEXT* ctx = (DNSAPI_RAW_PASSTHROUGH_CONTEXT*)
                                        Dll_Alloc(sizeof(DNSAPI_RAW_PASSTHROUGH_CONTEXT));
                                    if (ctx) {
                                        ctx->OriginalCallback = pQueryRequest->queryCompletionCallback;
                                        ctx->OriginalContext = pQueryRequest->queryContext;
                                        wcsncpy(ctx->Domain, domain, 255);
                                        ctx->Domain[255] = L'\0';
                                        ctx->QueryType = qtype;
                                        ctx->PassthroughReason = DNS_PASSTHROUGH_TYPE_NEGATED;
                                        
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
                                // Type not in filter list - passthrough to real DNS
                                // Callback wrapper will log final result with IPs
                                Dll_Free(domain_lwr);

                                if (DNSAPI_TryDoHForDnsQueryRaw(pQueryRequest, domain, qtype))
                                    return DNS_REQUEST_PENDING;
                                
                                // Wrap callback to log completion status
                                if (pQueryRequest->queryCompletionCallback) {
                                    DNSAPI_RAW_PASSTHROUGH_CONTEXT* ctx = (DNSAPI_RAW_PASSTHROUGH_CONTEXT*)
                                        Dll_Alloc(sizeof(DNSAPI_RAW_PASSTHROUGH_CONTEXT));
                                    if (ctx) {
                                        ctx->OriginalCallback = pQueryRequest->queryCompletionCallback;
                                        ctx->OriginalContext = pQueryRequest->queryContext;
                                        wcsncpy(ctx->Domain, domain, 255);
                                        ctx->Domain[255] = L'\0';
                                        ctx->QueryType = qtype;
                                        ctx->PassthroughReason = DNS_PASSTHROUGH_TYPE_NOT_FILTERED;
                                        
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
                                    // Check if response has answers (not a NODATA response)
                                    // DNS header: ID(2) + Flags(2) + Questions(2) + AnswerRRs(2) + AuthorityRRs(2) + AdditionalRRs(2)
                                    // AnswerRRs is at offset 6, 2 bytes (network byte order)
                                    USHORT answer_count = 0;
                                    if (response_len >= 8) {
                                        answer_count = _ntohs(*(USHORT*)(response + 6));
                                    }
                                    
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
                                                
                                                // Log appropriately based on whether we have answers
                                                if (answer_count > 0) {
                                                    DNS_LogIntercepted(L"DnsQueryRaw Intercepted", 
                                                                     domain, qtype, pEntries, FALSE);
                                                } else {
                                                    DNS_LogInterceptedNoData(L"DnsQueryRaw Intercepted", domain, qtype,
                                                                 L"No records for this type (NODATA)");
                                                }
                                                
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
                                    if (answer_count > 0) {
                                        DNS_LogIntercepted(L"DnsQueryRaw Intercepted", domain, qtype, pEntries, FALSE);
                                    } else {
                                        DNS_LogInterceptedNoData(L"DnsQueryRaw Intercepted", domain, qtype,
                                                     L"No records for this type (NODATA)");
                                    }
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

    // No filter match - passthrough
    if (DNSAPI_TryDoHForDnsQueryRaw(pQueryRequest, domain, qtype))
        return DNS_REQUEST_PENDING;

    DNS_LogSimple(L"DnsQueryRaw Passthrough", domain, qtype, NULL);
    
    // Wrap callback to log completion status
    if (pQueryRequest->queryCompletionCallback) {
        DNSAPI_RAW_PASSTHROUGH_CONTEXT* ctx = (DNSAPI_RAW_PASSTHROUGH_CONTEXT*)
            Dll_Alloc(sizeof(DNSAPI_RAW_PASSTHROUGH_CONTEXT));
        if (ctx) {
            ctx->OriginalCallback = pQueryRequest->queryCompletionCallback;
            ctx->OriginalContext = pQueryRequest->queryContext;
            wcsncpy(ctx->Domain, domain, 255);
            ctx->Domain[255] = L'\0';
            ctx->QueryType = qtype;
            ctx->PassthroughReason = DNS_PASSTHROUGH_NO_MATCH;
            
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


//---------------------------------------------------------------------------
// WSA_BuildAddrInfoList
//
// Helper function to build ADDRINFOW linked list from IP entries
// Returns synthesized ADDRINFOW chain, or NULL on failure
// Caller must free with FreeAddrInfoW (our hook will detect and free properly)
//---------------------------------------------------------------------------

static PADDRINFOW WSA_BuildAddrInfoList(
    const WCHAR*    pNodeName,
    const WCHAR*    pServiceName,
    const ADDRINFOW* pHints,
    LIST*           pEntries)
{
    if (!pEntries || !List_Head(pEntries))
        return NULL;

    // Determine what address families to return based on hints
    int requestedFamily = AF_UNSPEC;
    int socktype = SOCK_STREAM;
    int protocol = IPPROTO_TCP;
    
    if (pHints) {
        requestedFamily = pHints->ai_family;
        if (pHints->ai_socktype)
            socktype = pHints->ai_socktype;
        if (pHints->ai_protocol)
            protocol = pHints->ai_protocol;
    }

    // Count matching entries
    int count = 0;
    for (IP_ENTRY* entry = (IP_ENTRY*)List_Head(pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        if (requestedFamily == AF_UNSPEC || 
            (requestedFamily == AF_INET && entry->Type == AF_INET) ||
            (requestedFamily == AF_INET6 && entry->Type == AF_INET6)) {
            count++;
        }
    }

    if (count == 0)
        return NULL;

    PADDRINFOW pHead = NULL;
    PADDRINFOW pTail = NULL;

    for (IP_ENTRY* entry = (IP_ENTRY*)List_Head(pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        if (requestedFamily != AF_UNSPEC && 
            !((requestedFamily == AF_INET && entry->Type == AF_INET) ||
              (requestedFamily == AF_INET6 && entry->Type == AF_INET6))) {
            continue;
        }

        // Calculate sizes for this entry
        SIZE_T addrSize = (entry->Type == AF_INET6) ? sizeof(SOCKADDR_IN6_LH) : sizeof(SOCKADDR_IN);
        SIZE_T nodeNameLen = pNodeName ? (wcslen(pNodeName) + 1) * sizeof(WCHAR) : 0;
        
        // Allocate ADDRINFOW + sockaddr + canonname in one block
        // FIX: Use private heap to distinguish OUR allocations from system allocations
        SIZE_T totalSize = sizeof(ADDRINFOW) + addrSize + nodeNameLen;
        HANDLE hHeap = DNS_GetFilterHeap();
        if (!hHeap) return NULL;
        BYTE* pBlock = (BYTE*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, totalSize);
        if (!pBlock) {
            // Free already allocated entries on failure
            while (pHead) {
                PADDRINFOW pNext = pHead->ai_next;
                HeapFree(hHeap, 0, pHead);
                pHead = pNext;
            }
            return NULL;
        }

        PADDRINFOW pInfo = (PADDRINFOW)pBlock;

        // Mark this as our allocation with magic marker in ai_flags (bit 31)
        // This allows free functions to distinguish our allocations from system allocations
        pInfo->ai_flags = AI_SBIE_MARKER;
        pInfo->ai_family = entry->Type;
        pInfo->ai_socktype = socktype;
        pInfo->ai_protocol = protocol;
        pInfo->ai_addrlen = addrSize;
        pInfo->ai_addr = (struct sockaddr*)(pBlock + sizeof(ADDRINFOW));
        pInfo->ai_next = NULL;

        // Fill in the sockaddr
        if (entry->Type == AF_INET6) {
            SOCKADDR_IN6_LH* pAddr6 = (SOCKADDR_IN6_LH*)pInfo->ai_addr;
            pAddr6->sin6_family = AF_INET6;
            pAddr6->sin6_port = 0;
            pAddr6->sin6_flowinfo = 0;
            pAddr6->sin6_scope_id = 0;
            memcpy(pAddr6->sin6_addr.u.Byte, entry->IP.Data, 16);
        } else if (entry->Type == AF_INET) {
            SOCKADDR_IN* pAddr4 = (SOCKADDR_IN*)pInfo->ai_addr;
            pAddr4->sin_family = AF_INET;
            pAddr4->sin_port = 0;
            pAddr4->sin_addr.S_un.S_addr = entry->IP.Data32[3];
        } else {
            // Invalid address family - skip this entry
            Dll_Free(pBlock);
            continue;
        }

        // Copy canonical name if provided
        if (pNodeName && nodeNameLen > 0) {
            pInfo->ai_canonname = (PWSTR)(pBlock + sizeof(ADDRINFOW) + addrSize);
            wcscpy(pInfo->ai_canonname, pNodeName);
        }

        // Link into list
        if (!pHead) {
            pHead = pInfo;
            pTail = pInfo;
        } else {
            pTail->ai_next = pInfo;
            pTail = pInfo;
        }
    }

    return pHead;
}

//---------------------------------------------------------------------------
// WSA_BuildIPEntryListFromAddrInfoW / ExW
//
// Helper functions to extract resolved IP addresses from system addrinfo results
// into a temporary IP_ENTRY list for logging.
//---------------------------------------------------------------------------

static void WSA_BuildIPEntryListFromAddrInfoW(PADDRINFOW pResult, LIST* pListOut)
{
    if (!pListOut)
        return;
    List_Init(pListOut);
    if (!pResult)
        return;

    for (PADDRINFOW p = pResult; p; p = p->ai_next) {
        if (!p->ai_addr)
            continue;

        if (p->ai_family == AF_INET && p->ai_addrlen >= sizeof(SOCKADDR_IN)) {
            SOCKADDR_IN* pAddr4 = (SOCKADDR_IN*)p->ai_addr;
            IP_ENTRY* entry = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
            if (!entry)
                continue;
            memset(entry, 0, sizeof(*entry));
            entry->Type = AF_INET;
            entry->IP.Data32[3] = pAddr4->sin_addr.S_un.S_addr;
            List_Insert_After(pListOut, NULL, entry);
        }
        else if (p->ai_family == AF_INET6 && p->ai_addrlen >= sizeof(SOCKADDR_IN6_LH)) {
            SOCKADDR_IN6_LH* pAddr6 = (SOCKADDR_IN6_LH*)p->ai_addr;
            IP_ENTRY* entry = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
            if (!entry)
                continue;
            memset(entry, 0, sizeof(*entry));
            entry->Type = AF_INET6;
            memcpy(entry->IP.Data, pAddr6->sin6_addr.u.Byte, 16);
            List_Insert_After(pListOut, NULL, entry);
        }
    }
}

static void WSA_BuildIPEntryListFromAddrInfoExW(PADDRINFOEXW pResult, LIST* pListOut)
{
    if (!pListOut)
        return;
    List_Init(pListOut);
    if (!pResult)
        return;

    for (PADDRINFOEXW p = pResult; p; p = p->ai_next) {
        if (!p->ai_addr)
            continue;

        if (p->ai_family == AF_INET && p->ai_addrlen >= sizeof(SOCKADDR_IN)) {
            SOCKADDR_IN* pAddr4 = (SOCKADDR_IN*)p->ai_addr;
            IP_ENTRY* entry = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
            if (!entry)
                continue;
            memset(entry, 0, sizeof(*entry));
            entry->Type = AF_INET;
            entry->IP.Data32[3] = pAddr4->sin_addr.S_un.S_addr;
            List_Insert_After(pListOut, NULL, entry);
        }
        else if (p->ai_family == AF_INET6 && p->ai_addrlen >= sizeof(SOCKADDR_IN6_LH)) {
            SOCKADDR_IN6_LH* pAddr6 = (SOCKADDR_IN6_LH*)p->ai_addr;
            IP_ENTRY* entry = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
            if (!entry)
                continue;
            memset(entry, 0, sizeof(*entry));
            entry->Type = AF_INET6;
            memcpy(entry->IP.Data, pAddr6->sin6_addr.u.Byte, 16);
            List_Insert_After(pListOut, NULL, entry);
        }
    }
}

//---------------------------------------------------------------------------
// WSA_IsSbieAddrInfoCore
//
// Core detection logic for all ADDRINFO variants.
// Checks if a structure was allocated by our hook using the magic marker.
//
// CRITICAL: Detection must be 100% reliable. False positive → LocalFree crash.
// False negative → system HeapFree crash.
//
// Parameters:
//   pBlock        - Pointer to the ADDRINFO structure
//   structSize    - Size of the specific structure (ADDRINFOW, ADDRINFOA, ADDRINFOEXW)
//   ai_addr       - The ai_addr field value
//   ai_addrlen    - The ai_addrlen field value
//   ai_family     - The ai_family field value
//   ai_canonname  - The ai_canonname field (as raw pointer for position check)
//   isWideChar    - TRUE if canonname is wide string (WCHAR*), FALSE for ANSI (char*)
//
// Returns TRUE if this is our allocation, FALSE otherwise.
//---------------------------------------------------------------------------

static BOOLEAN WSA_IsSbieAddrInfoCore(
    BYTE* pBlock,
    SIZE_T structSize,
    struct sockaddr* ai_addr,
    SIZE_T ai_addrlen,
    int ai_family,
    void* ai_canonname,
    BOOLEAN isWideChar)
{
    if (!pBlock)
        return FALSE;

    // Validate ai_addrlen is reasonable (IPv4 or IPv6 sockaddr size)
    if (ai_addrlen != sizeof(SOCKADDR_IN) && ai_addrlen != sizeof(SOCKADDR_IN6_LH))
        return FALSE;

    // First check: ai_addr MUST point exactly to structSize offset
    // This is how we allocate - sockaddr immediately follows the structure
    if ((BYTE*)ai_addr != pBlock + structSize)
        return FALSE;
    
    // Second check: validate sockaddr family matches ai_family
    if (ai_addr) {
        ADDRESS_FAMILY sockFamily = ai_addr->sa_family;
        if (sockFamily != ai_family)
            return FALSE;
    }
    
    // Calculate where magic marker should be
    SIZE_T canonLen = 0;
    if (ai_canonname) {
        // Canonname must point exactly to expected offset: structSize + ai_addrlen
        BYTE* expectedCanonPos = pBlock + structSize + ai_addrlen;
        if ((BYTE*)ai_canonname != expectedCanonPos)
            return FALSE;  // Canonname at wrong position - not ours
        
        // Calculate canonname length with bounded read
        __try {
            if (isWideChar) {
                SIZE_T len = wcsnlen((WCHAR*)ai_canonname, 256);
                if (len >= 256)
                    return FALSE;  // Suspiciously long
                canonLen = (len + 1) * sizeof(WCHAR);
            } else {
                SIZE_T len = strnlen((char*)ai_canonname, 256);
                if (len >= 256)
                    return FALSE;
                canonLen = len + 1;  // ANSI: 1 byte per char + null
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;  // Can't read canonname - not ours
        }
    }
    
    // Calculate total block size and magic location
    SIZE_T totalSize = structSize + ai_addrlen + canonLen + sizeof(ULONG);
    ULONG* pMagic = (ULONG*)(pBlock + totalSize - sizeof(ULONG));
    
    // Final check: read magic marker
    __try {
        if (*pMagic == ADDRINFO_SBIE_MAGIC)
            return TRUE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // Access violation reading magic - not ours
    }

    return FALSE;
}

//---------------------------------------------------------------------------
// WSA_IsSbieAddrInfoW / WSA_IsSbieAddrInfoA / WSA_IsSbieAddrInfoExW
//
// Type-safe wrappers around WSA_IsSbieAddrInfoCore
//---------------------------------------------------------------------------

static BOOLEAN WSA_IsSbieAddrInfoW(PADDRINFOW pAddrInfo)
{
    if (!pAddrInfo)
        return FALSE;
    return WSA_IsSbieAddrInfoCore(
        (BYTE*)pAddrInfo,
        sizeof(ADDRINFOW),
        pAddrInfo->ai_addr,
        pAddrInfo->ai_addrlen,
        pAddrInfo->ai_family,
        pAddrInfo->ai_canonname,
        TRUE);  // Wide string
}

static BOOLEAN WSA_IsSbieAddrInfoA(PADDRINFOA pAddrInfo)
{
    if (!pAddrInfo)
        return FALSE;
    return WSA_IsSbieAddrInfoCore(
        (BYTE*)pAddrInfo,
        sizeof(ADDRINFOA),
        pAddrInfo->ai_addr,
        pAddrInfo->ai_addrlen,
        pAddrInfo->ai_family,
        pAddrInfo->ai_canonname,
        FALSE);  // ANSI string
}

static BOOLEAN WSA_IsSbieAddrInfoExW(PADDRINFOEXW pAddrInfo)
{
    if (!pAddrInfo)
        return FALSE;
    
    // Additional check for ADDRINFOEXW: our allocations have these fields NULL/0
    if (pAddrInfo->ai_blob != NULL || pAddrInfo->ai_bloblen != 0 || pAddrInfo->ai_provider != NULL)
        return FALSE;
    
    return WSA_IsSbieAddrInfoCore(
        (BYTE*)pAddrInfo,
        sizeof(ADDRINFOEXW),
        pAddrInfo->ai_addr,
        pAddrInfo->ai_addrlen,
        pAddrInfo->ai_family,
        pAddrInfo->ai_canonname,
        TRUE);  // Wide string
}

//---------------------------------------------------------------------------
// WSA_ValidateAndFindFilter
//
// Helper function to validate domain name and locate matching filter entry
// Returns: PATTERN* if filter found (domain is filtered), NULL if passthrough
// Caller must free nameOut_Lwr when done
// Output parameters:
//   nameOut_Lwr: Lowercase version of domain (caller must Dll_Free)
//   ppAux: Pointer to filter aux data (for DNS_ExtractFilterAux)
//---------------------------------------------------------------------------

static PATTERN* WSA_ValidateAndFindFilter(
    PCWSTR          pNodeName,
    WCHAR**         nameOut_Lwr,
    PVOID**         ppAux)
{
    if (!pNodeName || !nameOut_Lwr || !ppAux) {
        return NULL;
    }

    // Validate domain name length
    SIZE_T nameLen = wcslen(pNodeName);
    if (nameLen == 0 || nameLen > 255) {
        return NULL;
    }

    // Allocate and convert to lowercase
    WCHAR* nameLwr = (WCHAR*)Dll_AllocTemp((ULONG)((nameLen + 1) * sizeof(WCHAR)));
    if (!nameLwr) {
        return NULL;
    }
    wmemcpy(nameLwr, pNodeName, nameLen);
    nameLwr[nameLen] = L'\0';
    _wcslwr(nameLwr);

    // Check exclusion list
    if (DNS_IsExcluded(nameLwr)) {
        Dll_Free(nameLwr);
        return NULL;
    }

    // Check if domain matches any filter
    PATTERN* found = DNS_FindPatternInFilterList(nameLwr, (ULONG)-1);
    if (!found) {
        Dll_Free(nameLwr);
        return NULL;
    }

    // Get aux data
    PVOID* aux = Pattern_Aux(found);
    if (!aux || !*aux) {
        Dll_Free(nameLwr);
        return NULL;
    }

    // Check certificate
    if (!DNS_HasValidCertificate) {
        Dll_Free(nameLwr);
        return NULL;
    }

    *nameOut_Lwr = nameLwr;
    *ppAux = aux;
    return found;
}

//---------------------------------------------------------------------------
// DNS_IsIPAddress
//
// Check if a string is an IP address (IPv4 or IPv6)
// Returns: TRUE if string is an IP address, FALSE if it's a hostname
//---------------------------------------------------------------------------

static BOOLEAN DNS_IsIPAddress(const WCHAR* str)
{
    if (!str || !*str) return FALSE;

    // Quick check for IPv4: must contain only digits and dots
    BOOLEAN hasDigit = FALSE, hasDot = FALSE, hasColon = FALSE, hasHex = FALSE;
    for (const WCHAR* p = str; *p; p++) {
        if (*p >= L'0' && *p <= L'9') {
            hasDigit = TRUE;
        } else if (*p == L'.') {
            hasDot = TRUE;
        } else if (*p == L':') {
            hasColon = TRUE;
        } else if ((*p >= L'a' && *p <= L'f') || (*p >= L'A' && *p <= L'F')) {
            hasHex = TRUE;
        } else if (*p != L'[' && *p != L']') {
            // Other characters mean it's likely a hostname
            return FALSE;
        }
    }

    // IPv4: digits and dots (e.g., 1.1.1.1)
    if (hasDigit && hasDot && !hasColon) return TRUE;
    
    // IPv6: colons and hex (e.g., 2001:db8::1 or [2001:db8::1])
    if (hasColon) return TRUE;
    
    return FALSE;
}

//---------------------------------------------------------------------------
// DNS_IsIPv4MappedIPv6Literal
//
// Detect common IPv4-mapped IPv6 literal forms used by tools like ping:
//   ::ffff:1.2.3.4
//   [::ffff:1.2.3.4]
//
// When callers use AF_UNSPEC, treating these as IPv4 better matches Windows
// behavior (unsandboxed ping prints "Pinging 1.2.3.4").
//---------------------------------------------------------------------------

static BOOLEAN DNS_IsIPv4MappedIPv6Literal(const WCHAR* str)
{
    if (!str || !*str)
        return FALSE;

    const WCHAR* s = str;
    if (*s == L'[') {
        size_t len = wcslen(s);
        if (len >= 2 && s[len - 1] == L']')
            s++;
    }

    // Require dotted-quad tail.
    if (!wcschr(s, L'.'))
        return FALSE;

    // Case-insensitive prefix check for "::ffff:".
    if (_wcsnicmp(s, L"::ffff:", 7) == 0)
        return TRUE;

    return FALSE;
}

//---------------------------------------------------------------------------
// DNS_TryDoHQuery
//
// Helper function to attempt EncDns query for passthrough domains
// Returns: TRUE if EncDns succeeded and pResult contains valid response
//          FALSE if EncDns disabled, failed, or no results
// 
// Used by: DnsQuery_A, DnsQuery_W, DnsQuery_UTF8, GetAddrInfoW
//
// Note: EncDns (EncryptedDnsServer) requires a valid certificate.
//---------------------------------------------------------------------------

static BOOLEAN DNS_TryDoHQuery(
    const WCHAR* domain,
    USHORT qtype,
    LIST* pListOut,  // Output: IP_ENTRY list
    DOH_RESULT* pFullResult)  // Output: Full EncDnsresult (including CNAME)
{
    if (!EncryptedDns_IsEnabled() || !domain || !pListOut) {
        return FALSE;
    }

    // Skip encrypted DNS for IP address queries (except PTR queries)
    // IP addresses should NOT need DNS resolution - synthesize a response directly
    // Examples: ping 1.1.1.1, tracert 8.8.8.8
    if (qtype != DNS_TYPE_PTR && DNS_IsIPAddress(domain)) {
        if (DNS_DebugFlag && (qtype == DNS_TYPE_A || qtype == DNS_TYPE_AAAA)) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[EncDns] IP address detected, synthesizing %s response: %s", 
                          qtype == DNS_TYPE_A ? L"A" : L"AAAA", domain);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        
        // Synthesize a response with the IP address itself
        List_Init(pListOut);
        if (pFullResult) {
            memset(pFullResult, 0, sizeof(DOH_RESULT));
            pFullResult->Success = TRUE;
            pFullResult->Status = 0;
            pFullResult->TTL = 300;  // 5 minute TTL for IP literals
        }
        
        // Parse the IP address
        IP_ADDRESS ip = { 0 };

        // Special-case ::ffff:a.b.c.d when caller asked for A.
        // Our generic parser treats any ':' as IPv6; for AF_UNSPEC we want
        // to behave like Windows tools and treat this as IPv4.
        if (qtype == DNS_TYPE_A && DNS_IsIPv4MappedIPv6Literal(domain)) {
            const WCHAR* s = domain;
            if (*s == L'[') {
                size_t len = wcslen(s);
                if (len >= 2 && s[len - 1] == L']')
                    s++;
            }

            const WCHAR* lastColon = wcsrchr(s, L':');
            if (lastColon && lastColon[1]) {
                struct in_addr v4;
                if (_inet_aton(lastColon + 1, &v4) == 1) {
                    memset(&ip, 0, sizeof(ip));
                    memcpy(&ip.Data[12], &v4, 4);

                    IP_ENTRY* pEntry = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
                    if (pEntry) {
                        pEntry->Type = AF_INET;
                        memcpy(&pEntry->IP, &ip, sizeof(IP_ADDRESS));
                        List_Insert_After(pListOut, NULL, pEntry);
                    }

                    if (pFullResult) {
                        pFullResult->AnswerCount = 1;
                        pFullResult->Answers[0].Type = AF_INET;
                        memcpy(&pFullResult->Answers[0].IP, &ip, sizeof(IP_ADDRESS));
                    }

                    return TRUE;
                }
            }

            return FALSE;
        }
        
        // Parse IP address (IPv4 or IPv6) using _inet_xton
        // This handles both plain IPs and IPv6 addresses with brackets [::1]
        USHORT addr_type = 0;
        if (_inet_xton(domain, (ULONG)wcslen(domain), &ip, &addr_type) == 1) {
            
            // Only return result if query type matches the parsed address type
            if ((qtype == DNS_TYPE_A && addr_type == AF_INET) ||
                (qtype == DNS_TYPE_AAAA && addr_type == AF_INET6)) {
                
                IP_ENTRY* pEntry = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
                if (pEntry) {
                    pEntry->Type = addr_type;  // Use actual parsed type
                    memcpy(&pEntry->IP, &ip, sizeof(IP_ADDRESS));
                    List_Insert_After(pListOut, NULL, pEntry);
                }
                
                if (pFullResult) {
                    pFullResult->AnswerCount = 1;
                    pFullResult->Answers[0].Type = addr_type;  // Use actual parsed type
                    memcpy(&pFullResult->Answers[0].IP, &ip, sizeof(IP_ADDRESS));
                }
                
                return TRUE;
            } else {
                // Query type doesn't match address type - return success with empty result
                return TRUE;
            }
        }
        
        return FALSE;  // Parsing failed, let system DNS handle it
    }

    // For non-A/AAAA queries, return success with empty result (NODATA)
    // This ensures EncDns-only mode doesn't leak non-address queries to system DNS
    // The caller will see an empty result, which is the correct response for
    // APIs like GetAddrInfo that only return addresses
    if (qtype != DNS_TYPE_A && qtype != DNS_TYPE_AAAA) {
        List_Init(pListOut);
        if (pFullResult) {
            memset(pFullResult, 0, sizeof(DOH_RESULT));
            pFullResult->Success = TRUE;
            pFullResult->Status = 0;  // NOERROR but no records
            pFullResult->AnswerCount = 0;
        }
        return TRUE;  // Success with empty result
    }

    DOH_RESULT encdns_result;
    memset(&encdns_result, 0, sizeof(encdns_result));
    // EncryptedDns_Query handles all error cases internally (backend unavailable, query timeout, etc.)
    // and returns FALSE on failure. This prevents crashes from uninitialized backends.
    if (!EncryptedDns_Query(domain, qtype, &encdns_result)) {
        return FALSE;
    }

    // Always return the full result (for logging) even on NXDOMAIN/NODATA.
    if (pFullResult) {
        memcpy(pFullResult, &encdns_result, sizeof(DOH_RESULT));
    }

    // Don't follow CNAME for passthrough queries - return EncDns response as-is
    // The EncDns server already resolved any CNAME and returned both CNAME and A records
    // Following CNAME here causes issues and duplication
    
    // Check for failure cases
    if (!encdns_result.Success || encdns_result.Status != 0) {
        return FALSE;
    }

    // Convert DOH_RESULT to IP_ENTRY list
    List_Init(pListOut);
    for (int i = 0; i < encdns_result.AnswerCount; i++) {
        IP_ENTRY* pEntry = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
        if (pEntry) {
            pEntry->Type = encdns_result.Answers[i].Type;
            memcpy(&pEntry->IP, &encdns_result.Answers[i].IP, sizeof(IP_ADDRESS));
            List_Insert_After(pListOut, NULL, pEntry);
        }
    }

    // Return TRUE even for empty result (NODATA/CNAME-only)
    // This is a valid DNS response - domain exists but has no records of requested type
    // Examples: AAAA query for a domain with only A records, or CNAME pointing to IPv4-only target
    return TRUE;
}

//---------------------------------------------------------------------------
// DNS_FreeIPEntryList
//
// Helper function to free IP_ENTRY list created by DNS_TryDoHQuery
//---------------------------------------------------------------------------

static void DNS_FreeIPEntryList(LIST* pList)
{
    if (!pList) return;
    
    IP_ENTRY* pEntry = (IP_ENTRY*)List_Head(pList);
    while (pEntry) {
        IP_ENTRY* pNext = (IP_ENTRY*)List_Next(pEntry);
        Dll_Free(pEntry);
        pEntry = pNext;
    }
}

//---------------------------------------------------------------------------
// DNS_DoHQueryForFamily
//
// Unified EncDns query helper for address-family-based lookups (GetAddrInfo style)
// Handles AF_UNSPEC by querying both A and AAAA, merging results.
//
// Parameters:
//   domain       - Domain name to query
//   family       - AF_INET, AF_INET6, or AF_UNSPEC
//   pListOut     - Output: Combined IP_ENTRY list (caller must free with DNS_FreeIPEntryList)
//
// Returns: TRUE if any records were returned, FALSE on failure
//
// Note: Encrypted DNS (EncryptedDnsServer) requires a valid certificate.
//       Gracefully handles backend unavailability (WinHTTP not loaded).
//---------------------------------------------------------------------------

static BOOLEAN DNS_DoHQueryForFamily(
    const WCHAR* domain,
    int family,
    LIST* pListOut,
    ENCRYPTED_DNS_MODE* protocolUsedOut)
{
    if (!EncryptedDns_IsEnabled() || !domain || !pListOut) {
        return FALSE;
    }

    if (protocolUsedOut)
        *protocolUsedOut = ENCRYPTED_DNS_MODE_AUTO;

    List_Init(pListOut);
    BOOLEAN hasResults = FALSE;

    // For IP addresses, determine type and avoid double queries
    if (family == AF_UNSPEC && DNS_IsIPAddress(domain)) {
        BOOLEAN isIPv6 = (wcschr(domain, L':') != NULL);
        BOOLEAN isMappedV4 = DNS_IsIPv4MappedIPv6Literal(domain);
        WORD qtype = (!isIPv6 || isMappedV4) ? DNS_TYPE_A : DNS_TYPE_AAAA;
        DOH_RESULT encdns_result;
        if (DNS_TryDoHQuery(domain, qtype, pListOut, &encdns_result)) {
            if (protocolUsedOut)
                *protocolUsedOut = encdns_result.ProtocolUsed;
            hasResults = TRUE;
        }
        return hasResults;
    }

    if (family == AF_UNSPEC) {
        // Query both A and AAAA records
        LIST doh_list_a;
        DOH_RESULT doh_result_a;
        if (DNS_TryDoHQuery(domain, DNS_TYPE_A, &doh_list_a, &doh_result_a)) {
            if (protocolUsedOut && *protocolUsedOut == ENCRYPTED_DNS_MODE_AUTO)
                *protocolUsedOut = doh_result_a.ProtocolUsed;
            // Move A records to combined list
            IP_ENTRY* pEntry = (IP_ENTRY*)List_Head(&doh_list_a);
            while (pEntry) {
                IP_ENTRY* pNext = (IP_ENTRY*)List_Next(pEntry);
                List_Remove(&doh_list_a, pEntry);
                List_Insert_After(pListOut, NULL, pEntry);
                pEntry = pNext;
            }
            hasResults = TRUE;
        }

        LIST doh_list_aaaa;
        DOH_RESULT doh_result_aaaa;
        if (DNS_TryDoHQuery(domain, DNS_TYPE_AAAA, &doh_list_aaaa, &doh_result_aaaa)) {
            if (protocolUsedOut && *protocolUsedOut == ENCRYPTED_DNS_MODE_AUTO)
                *protocolUsedOut = doh_result_aaaa.ProtocolUsed;
            // Append AAAA records to combined list
            IP_ENTRY* pEntry = (IP_ENTRY*)List_Head(&doh_list_aaaa);
            while (pEntry) {
                IP_ENTRY* pNext = (IP_ENTRY*)List_Next(pEntry);
                List_Remove(&doh_list_aaaa, pEntry);
                List_Insert_After(pListOut, NULL, pEntry);
                pEntry = pNext;
            }
            hasResults = TRUE;
        }
    }
    else {
        // Query specific family
        WORD qtype = (family == AF_INET6) ? DNS_TYPE_AAAA : DNS_TYPE_A;
        DOH_RESULT encdns_result;
        if (DNS_TryDoHQuery(domain, qtype, pListOut, &encdns_result)) {
            if (protocolUsedOut)
                *protocolUsedOut = encdns_result.ProtocolUsed;
            hasResults = TRUE;
        }
    }

    return hasResults;
}

//---------------------------------------------------------------------------
// DNS_DoHBuildWSALookup
//
// Unified EncDns helper for WSALookupService - creates a WSA_LOOKUP structure
// with EncDns results ready to be returned by WSALookupServiceNextW.
//
// Parameters:
//   lpqsRestrictions - Original WSA query parameters
//   lphLookup        - Output handle
//
// Returns: NO_ERROR on success, SOCKET_ERROR on failure (call GetLastError)
//
// Note: EncDns (EncryptedDnsServer) requires a valid certificate .
//       Returns SOCKET_ERROR gracefully if EncDns backend unavailable (no crash).
//---------------------------------------------------------------------------

static int DNS_DoHBuildWSALookup(
    LPWSAQUERYSETW lpqsRestrictions,
    LPHANDLE lphLookup)
{
    if (!EncryptedDns_IsEnabled() || !lpqsRestrictions || !lpqsRestrictions->lpszServiceInstanceName || !lphLookup) {
        return SOCKET_ERROR;
    }

    WORD queryType = WSA_IsIPv6Query(lpqsRestrictions->lpServiceClassId) ? DNS_TYPE_AAAA : DNS_TYPE_A;
    
    LIST doh_list;
    DOH_RESULT encdns_result;
    if (!DNS_TryDoHQuery(lpqsRestrictions->lpszServiceInstanceName, queryType, &doh_list, &encdns_result)) {
        SetLastError(WSAHOST_NOT_FOUND);
        return SOCKET_ERROR;
    }

    HANDLE fakeHandle = (HANDLE)Dll_Alloc(sizeof(ULONG_PTR));
    if (!fakeHandle) {
        DNS_FreeIPEntryList(&doh_list);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return SOCKET_ERROR;
    }

    *lphLookup = fakeHandle;
    
    WSA_LOOKUP* pLookup = WSA_GetLookup(fakeHandle, TRUE);
    if (!pLookup) {
        Dll_Free(fakeHandle);
        DNS_FreeIPEntryList(&doh_list);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return SOCKET_ERROR;
    }

    pLookup->Filtered = TRUE;
    pLookup->NoMore = FALSE;
    pLookup->QueryType = queryType;

    ULONG nameLen = (ULONG)wcslen(lpqsRestrictions->lpszServiceInstanceName);
    pLookup->DomainName = Dll_Alloc((nameLen + 1) * sizeof(WCHAR));
    if (pLookup->DomainName) {
        wcscpy_s(pLookup->DomainName, nameLen + 1, lpqsRestrictions->lpszServiceInstanceName);
    }

    pLookup->Namespace = lpqsRestrictions->dwNameSpace;

    if (lpqsRestrictions->lpServiceClassId) {
        pLookup->ServiceClassId = Dll_Alloc(sizeof(GUID));
        if (pLookup->ServiceClassId) {
            memcpy(pLookup->ServiceClassId, lpqsRestrictions->lpServiceClassId, sizeof(GUID));
        }
    }

    // Convert EncDns results to IP_ENTRY list in lookup structure
    pLookup->pEntries = Dll_Alloc(sizeof(LIST));
    if (pLookup->pEntries) {
        List_Init(pLookup->pEntries);
        
        IP_ENTRY* entry = (IP_ENTRY*)List_Head(&doh_list);
        while (entry) {
            IP_ENTRY* newEntry = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
            if (newEntry) {
                newEntry->Type = entry->Type;
                memcpy(&newEntry->IP, &entry->IP, sizeof(IP_ADDRESS));
                List_Insert_After(pLookup->pEntries, NULL, newEntry);
            }
            entry = (IP_ENTRY*)List_Next(entry);
        }
    }

    // Check if we have any IP entries matching the query type
    BOOLEAN has_matching_ips = FALSE;
    if (pLookup->pEntries) {
        IP_ENTRY* check_entry = (IP_ENTRY*)List_Head(pLookup->pEntries);
        BOOLEAN isIPv6Query = WSA_IsIPv6Query(lpqsRestrictions->lpServiceClassId);
        while (check_entry) {
            if ((isIPv6Query && check_entry->Type == AF_INET6) ||
                (!isIPv6Query && check_entry->Type == AF_INET)) {
                has_matching_ips = TRUE;
                break;
            }
            check_entry = (IP_ENTRY*)List_Next(check_entry);
        }
    }

    // If no matching IPs (CNAME-only or NODATA), mark as NoMore for proper WSA_E_NO_MORE handling
    if (!has_matching_ips) {
        pLookup->NoMore = TRUE;
    }

    WSA_LogIntercepted(lpqsRestrictions->lpszServiceInstanceName,
        lpqsRestrictions->lpServiceClassId,
        lpqsRestrictions->dwNameSpace,
        fakeHandle,
        FALSE,  // not blocked
        pLookup->pEntries,
        TRUE,   // is_encdns = TRUE (EncDns resolution)
        encdns_result.ProtocolUsed);

    DNS_FreeIPEntryList(&doh_list);
    return NO_ERROR;
}

//---------------------------------------------------------------------------
// WSA_ConvertAddrInfoWToEx
//
// Convert ADDRINFOW chain to ADDRINFOEXW chain for GetAddrInfoExW responses.
// Uses the DNS filter private heap for allocations.
//
// Parameters:
//   pResultW   - Input ADDRINFOW chain (will be freed after conversion)
//   ppResultEx - Output: ADDRINFOEXW chain
//
// Returns: TRUE on success, FALSE on failure (result freed on failure)
//---------------------------------------------------------------------------

static BOOLEAN WSA_ConvertAddrInfoWToEx(
    PADDRINFOW pResultW,
    PADDRINFOEXW* ppResultEx)
{
    if (!pResultW || !ppResultEx) {
        return FALSE;
    }

    PADDRINFOEXW pHead = NULL;
    PADDRINFOEXW pTail = NULL;
    HANDLE hHeap = DNS_GetFilterHeap();
    
    if (!hHeap) {
        WSA_FreeAddrInfoW(pResultW);
        return FALSE;
    }

    for (PADDRINFOW pW = pResultW; pW; pW = pW->ai_next) {
        SIZE_T canonLen = 0;
        if (pW->ai_canonname) {
            SIZE_T len = wcslen(pW->ai_canonname) + 1;
            if (len > 256) len = 256;  // DNS hostname limit (defensive cap)
            canonLen = len * sizeof(WCHAR);
        }
        SIZE_T blockSize = sizeof(ADDRINFOEXW) + pW->ai_addrlen + canonLen;
        
        BYTE* pBlock = (BYTE*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, blockSize);
        if (!pBlock) {
            // Cleanup on failure
            while (pHead) {
                PADDRINFOEXW pNext = pHead->ai_next;
                HeapFree(hHeap, 0, pHead);
                pHead = pNext;
            }
            WSA_FreeAddrInfoW(pResultW);
            return FALSE;
        }

        PADDRINFOEXW pEx = (PADDRINFOEXW)pBlock;
        pEx->ai_flags = pW->ai_flags;
        pEx->ai_family = pW->ai_family;
        pEx->ai_socktype = pW->ai_socktype;
        pEx->ai_protocol = pW->ai_protocol;
        pEx->ai_addrlen = pW->ai_addrlen;
        pEx->ai_addr = (struct sockaddr*)(pBlock + sizeof(ADDRINFOEXW));
        memcpy(pEx->ai_addr, pW->ai_addr, pW->ai_addrlen);
        pEx->ai_blob = NULL;
        pEx->ai_bloblen = 0;
        pEx->ai_provider = NULL;
        pEx->ai_next = NULL;

        if (pW->ai_canonname && canonLen > 0) {
            pEx->ai_canonname = (PWSTR)(pBlock + sizeof(ADDRINFOEXW) + pW->ai_addrlen);
            wcscpy(pEx->ai_canonname, pW->ai_canonname);
        }

        if (!pHead) {
            pHead = pEx;
            pTail = pEx;
        } else {
            pTail->ai_next = pEx;
            pTail = pEx;
        }
    }

    WSA_FreeAddrInfoW(pResultW);
    *ppResultEx = pHead;
    return TRUE;
}

//---------------------------------------------------------------------------
// DNS_DoHQueryForGetAddrInfoExW
//
// Unified EncDns query helper for GetAddrInfoExW - handles family-based queries
// and conversion to ADDRINFOEXW.
//
// Parameters:
//   pName      - Domain name
//   family     - AF_INET, AF_INET6, or AF_UNSPEC
//   hints      - Optional ADDRINFOEXW hints
//   pServiceName - Optional service name for port resolution
//   ppResult   - Output: ADDRINFOEXW chain
//
// Returns: TRUE on success, FALSE on failure
//---------------------------------------------------------------------------

static BOOLEAN DNS_DoHQueryForGetAddrInfoExW(
    PCWSTR pName,
    int family,
    const ADDRINFOEXW* hints,
    PCWSTR pServiceName,
    PADDRINFOEXW* ppResult,
    ENCRYPTED_DNS_MODE* protocolUsedOut)
{
    if (!EncryptedDns_IsEnabled() || !pName || !ppResult) {
        return FALSE;
    }

    if (protocolUsedOut)
        *protocolUsedOut = ENCRYPTED_DNS_MODE_AUTO;

    LIST doh_list;
    ENCRYPTED_DNS_MODE protocolUsed = ENCRYPTED_DNS_MODE_AUTO;
    if (!DNS_DoHQueryForFamily(pName, family, &doh_list, &protocolUsed)) {
        return FALSE;
    }

    if (protocolUsedOut)
        *protocolUsedOut = protocolUsed;

    // Build basic ADDRINFOW first
    ADDRINFOW hintsW = {0};
    if (hints) {
        hintsW.ai_flags = hints->ai_flags;
        hintsW.ai_family = hints->ai_family;
        hintsW.ai_socktype = hints->ai_socktype;
        hintsW.ai_protocol = hints->ai_protocol;
    }
    
    PADDRINFOW pResultW = WSA_BuildAddrInfoList(pName, pServiceName, &hintsW, &doh_list);
    DNS_FreeIPEntryList(&doh_list);
    
    if (!pResultW) {
        return FALSE;
    }

    // Convert to ADDRINFOEXW
    if (!WSA_ConvertAddrInfoWToEx(pResultW, ppResult)) {
        return FALSE;
    }

    return TRUE;
}

//---------------------------------------------------------------------------
// GAI_PrepareNameLwrForCheck
//
// Shared helper for GetAddrInfoW / GetAddrInfoExW:
// - Builds lowercase copy for matching
// - Evaluates exclusion (NetworkDnsFilterExclude)
// - Applies EncDns re-entrancy guards (server hostname / active query)
//
// Caller owns *nameLwrOut and must free it with Dll_Free on all paths.
//---------------------------------------------------------------------------

typedef enum _GAI_NAME_CHECK_RESULT {
    GAI_NAME_CHECK_OK = 0,
    GAI_NAME_CHECK_EXCLUDED_SYS,
    GAI_NAME_CHECK_PASSTHROUGH_SYS,
} GAI_NAME_CHECK_RESULT;

static GAI_NAME_CHECK_RESULT GAI_PrepareNameLwrForCheck(
    PCWSTR pName,
    int family,
    WCHAR** nameLwrOut,
    BOOLEAN* excludedFromFilteringOut,
    DNS_EXCLUDE_RESOLVE_MODE* excludeModeOut,
    const WCHAR** passthroughReasonOut)
{
    UNREFERENCED_PARAMETER(family);

    if (nameLwrOut)
        *nameLwrOut = NULL;
    if (excludedFromFilteringOut)
        *excludedFromFilteringOut = FALSE;
    if (excludeModeOut)
        *excludeModeOut = DNS_EXCLUDE_RESOLVE_SYS;
    if (passthroughReasonOut)
        *passthroughReasonOut = NULL;

    if (!pName || !nameLwrOut || !excludedFromFilteringOut || !excludeModeOut)
        return GAI_NAME_CHECK_PASSTHROUGH_SYS;

    SIZE_T nameLen = wcslen(pName);
    if (nameLen == 0 || nameLen > 255)
        return GAI_NAME_CHECK_PASSTHROUGH_SYS;

    WCHAR* nameLwr = (WCHAR*)Dll_AllocTemp((ULONG)((nameLen + 1) * sizeof(WCHAR)));
    if (!nameLwr)
        return GAI_NAME_CHECK_PASSTHROUGH_SYS;

    wmemcpy(nameLwr, pName, nameLen);
    nameLwr[nameLen] = L'\0';
    _wcslwr(nameLwr);

    *nameLwrOut = nameLwr;

    // Check if excluded - excluded domains bypass filtering; mode can still allow EncDns passthrough.
    *excludedFromFilteringOut = DNS_IsExcludedEx(nameLwr, excludeModeOut);
    if (*excludedFromFilteringOut && *excludeModeOut == DNS_EXCLUDE_RESOLVE_SYS) {
        if (passthroughReasonOut)
            *passthroughReasonOut = L"excluded from filtering";
        return GAI_NAME_CHECK_EXCLUDED_SYS;
    }

    // Exclude encrypted DNS server hostnames to prevent re-entrancy
    if (EncryptedDns_IsServerHostname(nameLwr)) {
        if (passthroughReasonOut)
            *passthroughReasonOut = L"encrypted DNS server";
        return GAI_NAME_CHECK_PASSTHROUGH_SYS;
    }

    // If an encrypted DNS query is already active, bypass to prevent re-entrancy from worker threads
    if (EncryptedDns_IsQueryActive()) {
        if (passthroughReasonOut)
            *passthroughReasonOut = L"encrypted DNS query active";
        return GAI_NAME_CHECK_PASSTHROUGH_SYS;
    }

    return GAI_NAME_CHECK_OK;
}

//---------------------------------------------------------------------------
// WSA_GetAddrInfoW
//
// Hook for GetAddrInfoW - filters DNS queries and synthesizes responses
// Used by WinHTTP, curl, and many modern applications
//---------------------------------------------------------------------------

_FX INT WSAAPI WSA_GetAddrInfoW(
    PCWSTR          pNodeName,
    PCWSTR          pServiceName,
    const ADDRINFOW* pHints,
    PADDRINFOW*     ppResult)
{
    int family = pHints ? pHints->ai_family : AF_UNSPEC;
    
    // Debug log entry
    GAI_LogDebugEntry(L"GetAddrInfoW", pNodeName, pServiceName, family);
    
    // Check if we're being called from within system's getaddrinfo (ANSI)
    // If so, passthrough to avoid returning our private heap allocations
    // that the system will try to free during ANSI conversion
    if (WSA_SystemGetAddrInfoDepth > 0) {
        return __sys_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }
    
    if (!DNS_FilterEnabled || !pNodeName || !ppResult) {
        return __sys_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }

    // Convert to lowercase for checking
    WCHAR* nameLwr = NULL;
    BOOLEAN excludedFromFiltering = FALSE;
    DNS_EXCLUDE_RESOLVE_MODE excludeMode = DNS_EXCLUDE_RESOLVE_SYS;
    const WCHAR* passthroughReason = NULL;
    GAI_NAME_CHECK_RESULT precheck = GAI_PrepareNameLwrForCheck(
        pNodeName, family, &nameLwr, &excludedFromFiltering, &excludeMode, &passthroughReason);

    if (precheck == GAI_NAME_CHECK_PASSTHROUGH_SYS) {
        if (passthroughReason)
            GAI_LogPassthrough(L"GetAddrInfoW", pNodeName, family, passthroughReason);
        if (nameLwr)
            Dll_Free(nameLwr);
        return __sys_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }

    if (precheck == GAI_NAME_CHECK_EXCLUDED_SYS) {
        if (nameLwr)
            Dll_Free(nameLwr);

        INT result = __sys_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
        if (result == 0 && ppResult && *ppResult) {
            LIST log_list;
            WSA_BuildIPEntryListFromAddrInfoW(*ppResult, &log_list);
            GAI_LogPassthroughWithEntries(L"GetAddrInfoW", pNodeName, family, &log_list,
                                          passthroughReason ? passthroughReason : L"excluded from filtering");
            DNS_FreeIPEntryList(&log_list);
        } else {
            GAI_LogPassthrough(L"GetAddrInfoW", pNodeName, family,
                               passthroughReason ? passthroughReason : L"excluded from filtering");
        }
        return result;
    }

    // Use shared validation helper
    PVOID* aux = NULL;
    PATTERN* found = NULL;
    if (!excludedFromFiltering) {
        found = DNS_FindPatternInFilterList(nameLwr, (ULONG)-1);
    }
    
    if (!found) {
        // No filter match - use encrypted DNS exclusively if enabled, otherwise system DNS
        if (EncryptedDns_IsEnabled()) {
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"[GetAddrInfoW] Encrypted DNS path: domain=%s, family=%d", 
                    pNodeName, family);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            
            LIST doh_list;
            ENCRYPTED_DNS_MODE protocolUsed = ENCRYPTED_DNS_MODE_AUTO;
            if (DNS_DoHQueryForFamily(pNodeName, family, &doh_list, &protocolUsed)) {
                PADDRINFOW pResult = WSA_BuildAddrInfoList(pNodeName, pServiceName, pHints, &doh_list);
                if (pResult) {
                    WCHAR sourceTag[64];
                    DNS_FormatEncDnsSourceTag(sourceTag, ARRAYSIZE(sourceTag), L"GetAddrInfoW", protocolUsed);
                    GAI_LogIntercepted(sourceTag, pNodeName, family, &doh_list, TRUE);
                    DNS_FreeIPEntryList(&doh_list);
                    Dll_Free(nameLwr);
                    *ppResult = pResult;
                    return 0;
                }
            }
            
            // EncDns query failed or returned no records - return error instead of fallback
            DNS_FreeIPEntryList(&doh_list);
            {
                WCHAR sourceTag[64];
                DNS_FormatEncDnsSourceTag(sourceTag, ARRAYSIZE(sourceTag), L"GetAddrInfoW", ENCRYPTED_DNS_MODE_AUTO);
                GAI_LogPassthrough(sourceTag, pNodeName, family, L"no EncDns records");
            }
            Dll_Free(nameLwr);
            return WSAHOST_NOT_FOUND;
        }
        
        // EncDns disabled - use system DNS
        GAI_LogPassthrough(L"GetAddrInfoW", pNodeName, family, L"no filter match");
        Dll_Free(nameLwr);
        return __sys_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }

    // Domain matches filter - check certificate
    extern BOOLEAN DNS_HasValidCertificate;
    if (!DNS_HasValidCertificate) {
        // Domain matches filter but no cert - use encrypted DNS exclusively if enabled, otherwise passthrough
        if (EncryptedDns_IsEnabled()) {
            LIST doh_list;
            ENCRYPTED_DNS_MODE protocolUsed = ENCRYPTED_DNS_MODE_AUTO;
            if (DNS_DoHQueryForFamily(pNodeName, family, &doh_list, &protocolUsed)) {
                PADDRINFOW pResult = WSA_BuildAddrInfoList(pNodeName, pServiceName, pHints, &doh_list);
                if (pResult) {
                    WCHAR baseTag[64];
                    WCHAR sourceTag[80];
                    DNS_FormatEncDnsSourceTag(baseTag, ARRAYSIZE(baseTag), L"GetAddrInfoW", protocolUsed);
                    Sbie_snwprintf(sourceTag, ARRAYSIZE(sourceTag), L"%s (no cert)", baseTag);
                    GAI_LogIntercepted(sourceTag, pNodeName, family, &doh_list, TRUE);
                    DNS_FreeIPEntryList(&doh_list);
                    Dll_Free(nameLwr);
                    *ppResult = pResult;
                    return 0;
                }
            }
            
            // EncDns query failed or returned no records - return error instead of fallback
            DNS_FreeIPEntryList(&doh_list);
            {
                WCHAR baseTag[64];
                WCHAR sourceTag[80];
                DNS_FormatEncDnsSourceTag(baseTag, ARRAYSIZE(baseTag), L"GetAddrInfoW", ENCRYPTED_DNS_MODE_AUTO);
                Sbie_snwprintf(sourceTag, ARRAYSIZE(sourceTag), L"%s (no cert)", baseTag);
                GAI_LogPassthrough(sourceTag, pNodeName, family, L"no EncDns records");
            }
            Dll_Free(nameLwr);
            return WSAHOST_NOT_FOUND;
        }
        
        // EncDns disabled - use system DNS
        GAI_LogPassthrough(L"GetAddrInfoW", pNodeName, family, L"no certificate");
        Dll_Free(nameLwr);
        return __sys_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }

    aux = Pattern_Aux(found);
    if (!aux || !*aux) {
        Dll_Free(nameLwr);
        return __sys_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }

    LIST* pEntries = NULL;
    DNS_TYPE_FILTER* type_filter = NULL;
    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);

    // Block mode (no IPs configured)
    if (!pEntries) {
        GAI_LogBlocked(L"GetAddrInfoW", pNodeName, family);
        Dll_Free(nameLwr);
        *ppResult = NULL;
        if (__sys_WSASetLastError)
            __sys_WSASetLastError(WSAHOST_NOT_FOUND);
        return WSAHOST_NOT_FOUND;
    }

    // Determine query type from hints
    WORD wType = DNS_TYPE_A;  // Default to A
    if (pHints) {
        if (pHints->ai_family == AF_INET6)
            wType = DNS_TYPE_AAAA;
        else if (pHints->ai_family == AF_UNSPEC)
            wType = DNS_TYPE_A;  // Will return both if available
    }

    // Check type filter
    if (type_filter && !DNS_IsTypeInFilterList(type_filter, wType)) {
        // Type not in filter list or negated - try encrypted DNS first, then passthrough
        if (EncryptedDns_IsEnabled()) {
            LIST doh_list;
            ENCRYPTED_DNS_MODE protocolUsed = ENCRYPTED_DNS_MODE_AUTO;
            if (DNS_DoHQueryForFamily(pNodeName, family, &doh_list, &protocolUsed)) {
                PADDRINFOW pResult = WSA_BuildAddrInfoList(pNodeName, pServiceName, pHints, &doh_list);
                if (pResult) {
                    WCHAR baseTag[64];
                    WCHAR sourceTag[92];
                    DNS_FormatEncDnsSourceTag(baseTag, ARRAYSIZE(baseTag), L"GetAddrInfoW", protocolUsed);
                    Sbie_snwprintf(sourceTag, ARRAYSIZE(sourceTag), L"%s (type passthrough)", baseTag);
                    GAI_LogIntercepted(sourceTag, pNodeName, family, &doh_list, TRUE);
                    DNS_FreeIPEntryList(&doh_list);
                    Dll_Free(nameLwr);
                    *ppResult = pResult;
                    return 0;
                }
            }
            
            // EncDns query failed or returned no records - return error instead of fallback
            DNS_FreeIPEntryList(&doh_list);
            {
                WCHAR baseTag[64];
                WCHAR sourceTag[92];
                DNS_FormatEncDnsSourceTag(baseTag, ARRAYSIZE(baseTag), L"GetAddrInfoW", ENCRYPTED_DNS_MODE_AUTO);
                Sbie_snwprintf(sourceTag, ARRAYSIZE(sourceTag), L"%s (type passthrough)", baseTag);
                GAI_LogPassthrough(sourceTag, pNodeName, family, L"no EncDns records");
            }
            Dll_Free(nameLwr);
            return WSAHOST_NOT_FOUND;
        }
        
        // EncDns disabled - passthrough to system DNS
        GAI_LogPassthrough(L"GetAddrInfoW", pNodeName, family, L"type not in filter");
        Dll_Free(nameLwr);
        return __sys_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }

    // Build synthesized response
    PADDRINFOW pResult = WSA_BuildAddrInfoList(pNodeName, pServiceName, pHints, pEntries);
    if (!pResult) {
        // No matching entries for requested family - return NODATA-like error
        GAI_LogNoData(L"GetAddrInfoW", pNodeName, family);
        Dll_Free(nameLwr);
        *ppResult = NULL;
        if (__sys_WSASetLastError)
            __sys_WSASetLastError(WSANO_DATA);
        return WSANO_DATA;
    }

    // Log successful interception
    if (pEntries) {
        GAI_LogIntercepted(L"GetAddrInfoW", pNodeName, family, pEntries, FALSE);
    }
    
    Dll_Free(nameLwr);
    *ppResult = pResult;
    return 0;  // Success
}

//---------------------------------------------------------------------------
// WSA_getaddrinfo
//
// Hook for getaddrinfo (ANSI version) - Just pass through to system
// The system's getaddrinfo will internally call GetAddrInfoW which we intercept
// This avoids heap ownership issues with Unicode->ANSI conversion
//---------------------------------------------------------------------------

_FX INT WSAAPI WSA_getaddrinfo(
    PCSTR           pNodeName,
    PCSTR           pServiceName,
    const ADDRINFOA* pHints,
    PADDRINFOA*     ppResult)
{
    // Increment re-entrancy counter before calling system
    // System's getaddrinfo will internally call GetAddrInfoW, which we hook
    // We need to passthrough in that case to avoid heap allocation mismatches
    InterlockedIncrement(&WSA_SystemGetAddrInfoDepth);
    
    INT result = __sys_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    
    InterlockedDecrement(&WSA_SystemGetAddrInfoDepth);
    
    return result;
}

//---------------------------------------------------------------------------
// WSA_GetAddrInfoExW
//
// Hook for GetAddrInfoExW - extended async version
// For async calls, we passthrough to system - DnsQueryEx hook handles filtering
// For sync calls, we intercept directly when a filter matches
//---------------------------------------------------------------------------

_FX INT WSAAPI WSA_GetAddrInfoExW(
    PCWSTR          pName,
    PCWSTR          pServiceName,
    DWORD           dwNameSpace,
    LPGUID          lpNspId,
    const ADDRINFOEXW* hints,
    PADDRINFOEXW*   ppResult,
    struct timeval* timeout,
    LPOVERLAPPED    lpOverlapped,
    LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
    LPHANDLE        lpHandle)
{
    int family = hints ? hints->ai_family : AF_UNSPEC;
    BOOLEAN isAsync = (lpOverlapped || lpCompletionRoutine) ? TRUE : FALSE;
    
    // Debug log entry
    GAI_LogDebugEntry(L"GetAddrInfoExW", pName, pServiceName, family);
    
    // Check basic preconditions - passthrough if not filterable
    if (!DNS_FilterEnabled || !pName || !ppResult) {
        if (isAsync) {
            // Set re-entrancy flag to prevent WSALookupService from double-intercepting
            return WSA_CallSysGetAddrInfoExW_WithReentrancyFlag(
                pName, pServiceName, dwNameSpace, lpNspId,
                hints, ppResult, timeout, lpOverlapped,
                lpCompletionRoutine, lpHandle);
        }
        return __sys_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                     hints, ppResult, timeout, lpOverlapped,
                                     lpCompletionRoutine, lpHandle);
    }

    // Convert to lowercase for checking
    SIZE_T nameLen = wcslen(pName);
    if (nameLen == 0 || nameLen > 255) {
        if (isAsync) {
            return WSA_CallSysGetAddrInfoExW_WithReentrancyFlag(
                pName, pServiceName, dwNameSpace, lpNspId,
                hints, ppResult, timeout, lpOverlapped,
                lpCompletionRoutine, lpHandle);
        }
        return __sys_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                     hints, ppResult, timeout, lpOverlapped,
                                     lpCompletionRoutine, lpHandle);
    }

    WCHAR* nameLwr = NULL;
    BOOLEAN excludedFromFiltering = FALSE;
    DNS_EXCLUDE_RESOLVE_MODE excludeMode = DNS_EXCLUDE_RESOLVE_SYS;
    const WCHAR* passthroughReason = NULL;
    GAI_NAME_CHECK_RESULT precheck = GAI_PrepareNameLwrForCheck(
        pName, family, &nameLwr, &excludedFromFiltering, &excludeMode, &passthroughReason);

    if (precheck == GAI_NAME_CHECK_PASSTHROUGH_SYS) {
        if (passthroughReason)
            GAI_LogPassthrough(L"GetAddrInfoExW", pName, family, passthroughReason);
        if (nameLwr)
            Dll_Free(nameLwr);

        if (isAsync) {
            return WSA_CallSysGetAddrInfoExW_WithReentrancyFlag(
                pName, pServiceName, dwNameSpace, lpNspId,
                hints, ppResult, timeout, lpOverlapped,
                lpCompletionRoutine, lpHandle);
        }

        return __sys_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                    hints, ppResult, timeout, lpOverlapped,
                                    lpCompletionRoutine, lpHandle);
    }

    if (precheck == GAI_NAME_CHECK_EXCLUDED_SYS) {
        if (nameLwr)
            Dll_Free(nameLwr);

        INT result;
        if (isAsync) {
            result = WSA_CallSysGetAddrInfoExW_WithReentrancyFlag(
                pName, pServiceName, dwNameSpace, lpNspId,
                hints, ppResult, timeout, lpOverlapped,
                lpCompletionRoutine, lpHandle);
        } else {
            result = __sys_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                          hints, ppResult, timeout, lpOverlapped,
                                          lpCompletionRoutine, lpHandle);
        }

        if (result == 0 && ppResult && *ppResult) {
            LIST log_list;
            WSA_BuildIPEntryListFromAddrInfoExW(*ppResult, &log_list);
            GAI_LogPassthroughWithEntries(L"GetAddrInfoExW", pName, family, &log_list,
                                          passthroughReason ? passthroughReason : L"excluded from filtering");
            DNS_FreeIPEntryList(&log_list);
        } else {
            GAI_LogPassthrough(L"GetAddrInfoExW", pName, family,
                               passthroughReason ? passthroughReason : L"excluded from filtering");
        }
        return result;
    }

    // Check if domain matches any filter
    PATTERN* found = NULL;
    if (!excludedFromFiltering) {
        found = DNS_FindPatternInFilterList(nameLwr, (ULONG)-1);
    }
    
    if (!found) {
        // No filter match - use encrypted DNS exclusively if enabled, otherwise system DNS
        if (EncryptedDns_IsEnabled()) {
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"[GetAddrInfoExW] Encrypted DNS path: domain=%s, family=%d", 
                    pName, family);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            
            PADDRINFOEXW pResultEx = NULL;
            ENCRYPTED_DNS_MODE protocolUsed = ENCRYPTED_DNS_MODE_AUTO;
            if (DNS_DoHQueryForGetAddrInfoExW(pName, family, hints, pServiceName, &pResultEx, &protocolUsed)) {
                LIST log_list;
                WSA_BuildIPEntryListFromAddrInfoExW(pResultEx, &log_list);
                WCHAR sourceTag[64];
                DNS_FormatEncDnsSourceTag(sourceTag, ARRAYSIZE(sourceTag), L"GetAddrInfoExW", protocolUsed);
                GAI_LogIntercepted(sourceTag, pName, family, &log_list, TRUE);
                DNS_FreeIPEntryList(&log_list);
                Dll_Free(nameLwr);
                *ppResult = pResultEx;
                if (lpHandle) *lpHandle = NULL;
                return 0;
            }
            
            // EncDns query failed or returned no records - return error instead of fallback
            {
                WCHAR sourceTag[64];
                DNS_FormatEncDnsSourceTag(sourceTag, ARRAYSIZE(sourceTag), L"GetAddrInfoExW", ENCRYPTED_DNS_MODE_AUTO);
                GAI_LogPassthrough(sourceTag, pName, family, L"no EncDns records");
            }
            Dll_Free(nameLwr);
            if (ppResult) *ppResult = NULL;
            if (lpHandle) *lpHandle = NULL;
            if (__sys_WSASetLastError)
                __sys_WSASetLastError(WSAHOST_NOT_FOUND);
            return WSAHOST_NOT_FOUND;
        }
        
        // EncDns disabled - passthrough to system DNS
        GAI_LogPassthrough(L"GetAddrInfoExW", pName, family, L"no filter match");
        Dll_Free(nameLwr);
        if (isAsync) {
            // Set re-entrancy flag to prevent WSALookupService from double-intercepting
            return WSA_CallSysGetAddrInfoExW_WithReentrancyFlag(
                pName, pServiceName, dwNameSpace, lpNspId,
                hints, ppResult, timeout, lpOverlapped,
                lpCompletionRoutine, lpHandle);
        }
        return __sys_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                     hints, ppResult, timeout, lpOverlapped,
                                     lpCompletionRoutine, lpHandle);
    }

    // Domain matches filter - check certificate
    extern BOOLEAN DNS_HasValidCertificate;
    if (!DNS_HasValidCertificate) {
        // Domain matches filter but no cert - use encrypted DNS exclusively if enabled, otherwise passthrough
        if (EncryptedDns_IsEnabled()) {
            PADDRINFOEXW pResultEx = NULL;
            ENCRYPTED_DNS_MODE protocolUsed = ENCRYPTED_DNS_MODE_AUTO;
            if (DNS_DoHQueryForGetAddrInfoExW(pName, family, hints, pServiceName, &pResultEx, &protocolUsed)) {
                LIST log_list;
                WSA_BuildIPEntryListFromAddrInfoExW(pResultEx, &log_list);
                WCHAR baseTag[64];
                WCHAR sourceTag[80];
                DNS_FormatEncDnsSourceTag(baseTag, ARRAYSIZE(baseTag), L"GetAddrInfoExW", protocolUsed);
                Sbie_snwprintf(sourceTag, ARRAYSIZE(sourceTag), L"%s (no cert)", baseTag);
                GAI_LogIntercepted(sourceTag, pName, family, &log_list, TRUE);
                DNS_FreeIPEntryList(&log_list);
                Dll_Free(nameLwr);
                *ppResult = pResultEx;
                if (lpHandle) *lpHandle = NULL;
                return 0;
            }
            
            // EncDns query failed or returned no records - return error instead of fallback
            {
                WCHAR baseTag[64];
                WCHAR sourceTag[80];
                DNS_FormatEncDnsSourceTag(baseTag, ARRAYSIZE(baseTag), L"GetAddrInfoExW", ENCRYPTED_DNS_MODE_AUTO);
                Sbie_snwprintf(sourceTag, ARRAYSIZE(sourceTag), L"%s (no cert)", baseTag);
                GAI_LogPassthrough(sourceTag, pName, family, L"no EncDns records");
            }
            Dll_Free(nameLwr);
            if (ppResult) *ppResult = NULL;
            if (lpHandle) *lpHandle = NULL;
            if (__sys_WSASetLastError)
                __sys_WSASetLastError(WSAHOST_NOT_FOUND);
            return WSAHOST_NOT_FOUND;
        }
        
        // EncDns disabled - passthrough to system DNS
        GAI_LogPassthrough(L"GetAddrInfoExW", pName, family, L"no certificate");
        Dll_Free(nameLwr);
        if (isAsync) {
            return WSA_CallSysGetAddrInfoExW_WithReentrancyFlag(
                pName, pServiceName, dwNameSpace, lpNspId,
                hints, ppResult, timeout, lpOverlapped,
                lpCompletionRoutine, lpHandle);
        }
        return __sys_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                     hints, ppResult, timeout, lpOverlapped,
                                     lpCompletionRoutine, lpHandle);
    }

    // Get aux data from filter pattern
    PVOID* aux = Pattern_Aux(found);
    if (!aux || !*aux) {
        Dll_Free(nameLwr);
        if (isAsync) {
            return WSA_CallSysGetAddrInfoExW_WithReentrancyFlag(
                pName, pServiceName, dwNameSpace, lpNspId,
                hints, ppResult, timeout, lpOverlapped,
                lpCompletionRoutine, lpHandle);
        }
        return __sys_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                     hints, ppResult, timeout, lpOverlapped,
                                     lpCompletionRoutine, lpHandle);
    }

    // --- Domain matches a filter with valid aux, we handle it directly (sync or async) ---
    Dll_Free(nameLwr);  // Free the lowercase copy, we have aux now
    
    LIST* pEntries = NULL;
    DNS_TYPE_FILTER* type_filter = NULL;
    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);

    // Determine query type from hints
    WORD wType = DNS_TYPE_A;  // Default to A
    if (hints) {
        if (hints->ai_family == AF_INET6)
            wType = DNS_TYPE_AAAA;
        else if (hints->ai_family == AF_UNSPEC)
            wType = DNS_TYPE_A;  // Will return both if available
    }

    // Check type filter (e.g., NetworkDnsFilter=example.com/A,AAAA)
    // If the requested type isn't allowed, try EncDns first, then passthrough to system (async or sync)
    if (type_filter && !DNS_IsTypeInFilterList(type_filter, wType)) {
        // Try encrypted DNS for negated type passthrough queries
        PADDRINFOEXW pResultEx = NULL;
        ENCRYPTED_DNS_MODE protocolUsed = ENCRYPTED_DNS_MODE_AUTO;
        if (DNS_DoHQueryForGetAddrInfoExW(pName, family, hints, pServiceName, &pResultEx, &protocolUsed)) {
            WCHAR baseTag[64];
            WCHAR sourceTag[92];
            DNS_FormatEncDnsSourceTag(baseTag, ARRAYSIZE(baseTag), L"GetAddrInfoExW", protocolUsed);
            Sbie_snwprintf(sourceTag, ARRAYSIZE(sourceTag), L"%s (type passthrough)", baseTag);
            GAI_LogPassthrough(sourceTag, pName, family, L"success");
            *ppResult = pResultEx;
            if (lpHandle) *lpHandle = NULL;
            return 0;
        }
        
        // Encrypted DNS failed or disabled
        if (EncryptedDns_IsEnabled()) {
            // Encrypted DNS enabled but failed - return error instead of fallback
            {
                WCHAR baseTag[64];
                WCHAR sourceTag[92];
                DNS_FormatEncDnsSourceTag(baseTag, ARRAYSIZE(baseTag), L"GetAddrInfoExW", ENCRYPTED_DNS_MODE_AUTO);
                Sbie_snwprintf(sourceTag, ARRAYSIZE(sourceTag), L"%s (type passthrough)", baseTag);
                GAI_LogPassthrough(sourceTag, pName, family, L"no EncDns records");
            }
            if (ppResult) *ppResult = NULL;
            if (lpHandle) *lpHandle = NULL;
            if (__sys_WSASetLastError)
                __sys_WSASetLastError(WSAHOST_NOT_FOUND);
            return WSAHOST_NOT_FOUND;
        }
        
        // EncDns disabled - passthrough to system DNS
        GAI_LogPassthrough(L"GetAddrInfoExW", pName, family, L"type not in filter");
        if (isAsync) {
            return WSA_CallSysGetAddrInfoExW_WithReentrancyFlag(
                pName, pServiceName, dwNameSpace, lpNspId,
                hints, ppResult, timeout, lpOverlapped,
                lpCompletionRoutine, lpHandle);
        }
        return __sys_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                     hints, ppResult, timeout, lpOverlapped,
                                     lpCompletionRoutine, lpHandle);
    }

    // Block mode - domain is blocked
    if (!pEntries) {
        GAI_LogBlocked(L"GetAddrInfoExW", pName, family);
        
        if (ppResult)
            *ppResult = NULL;
        if (lpHandle)
            *lpHandle = NULL;
        
        // Set error for both sync and async
        if (__sys_WSASetLastError)
            __sys_WSASetLastError(WSAHOST_NOT_FOUND);
        
        // For async calls that we're blocking synchronously:
        // Return error immediately - don't call completion routine
        // The application will see the error return value and handle it
        // (Completion routine is only called for truly async operations)
        
        // Return immediate error (not WSA_IO_PENDING) - operation never started
        return WSAHOST_NOT_FOUND;
    }

    // For GetAddrInfoExW, we need to build ADDRINFOEXW structures
    // For simplicity, we'll use the simpler ADDRINFOW version and adapt
    ADDRINFOW hintsW = {0};
    if (hints) {
        hintsW.ai_flags = hints->ai_flags;
        hintsW.ai_family = hints->ai_family;
        hintsW.ai_socktype = hints->ai_socktype;
        hintsW.ai_protocol = hints->ai_protocol;
    }

    // Build basic ADDRINFOW first
    PADDRINFOW pResultW = WSA_BuildAddrInfoList(pName, pServiceName, &hintsW, pEntries);
    if (!pResultW) {
        GAI_LogNoData(L"GetAddrInfoExW", pName, family);
        
        if (ppResult)
            *ppResult = NULL;
        if (lpHandle)
            *lpHandle = NULL;
        
        if (__sys_WSASetLastError)
            __sys_WSASetLastError(WSANO_DATA);
        
        // For async calls, return error immediately (don't call completion routine)
        // The application will see the error return value
        
        return WSANO_DATA;
    }

    // Convert ADDRINFOW to ADDRINFOEXW using helper
    PADDRINFOEXW pResultEx = NULL;
    if (!WSA_ConvertAddrInfoWToEx(pResultW, &pResultEx)) {
        // pResultW is freed by the helper on failure
        if (__sys_WSASetLastError)
            __sys_WSASetLastError(WSA_NOT_ENOUGH_MEMORY);
        return WSA_NOT_ENOUGH_MEMORY;
    }

    // Log successful interception
    if (pEntries) {
        GAI_LogIntercepted(L"GetAddrInfoExW", pName, family, pEntries, FALSE);
    }
    
    *ppResult = pResultEx;
    
    // For async calls that we complete synchronously:
    // According to GetAddrInfoExW behavior, if we complete immediately, we should:
    // 1. Return 0 (not WSA_IO_PENDING)
    // 2. NOT call the completion routine (only called for truly async operations)
    // 3. Results are immediately available in *ppResult
    // The application will see return value 0 and use *ppResult directly
    
    // Return immediate success (not WSA_IO_PENDING)
    // For both sync and async, the result is immediately available in *ppResult
    return 0;
}

//---------------------------------------------------------------------------
// DNS_IsOurAddrInfo
//
// Helper function to check if an ADDRINFO structure belongs to us
// Returns TRUE if it has our magic marker (AI_SBIE_MARKER in ai_flags)
//---------------------------------------------------------------------------

_FX BOOLEAN DNS_IsOurAddrInfo(int ai_flags)
{
    return (ai_flags & AI_SBIE_MARKER) != 0;
}

//---------------------------------------------------------------------------
// WSA_FreeAddrInfo_Common
//
// Shared implementation for freeaddrinfo/FreeAddrInfoW/FreeAddrInfoExW.
// Frees our synthesized addrinfo chains from the DNS private heap; otherwise
// forwards to the real system free function.
//---------------------------------------------------------------------------

typedef VOID (WSAAPI *P_freeaddrinfo_void)(PVOID pAddrInfo);

static VOID WSA_FreeAddrInfo_Common(PVOID pAddrInfo, P_freeaddrinfo_void sysFree, SIZE_T nextOffset)
{
    if (!pAddrInfo) {
        if (sysFree)
            sysFree(pAddrInfo);
        return;
    }

    // All addrinfo variants have ai_flags as the first field.
    if (!DNS_IsOurAddrInfo(*(int*)pAddrInfo)) {
        if (sysFree)
            sysFree(pAddrInfo);
        return;
    }

    HANDLE hHeap = DNS_GetFilterHeap();
    if (!hHeap) {
        if (sysFree)
            sysFree(pAddrInfo);
        return;
    }

    // CRITICAL: Our implementations allocate everything in ONE block!
    // Do NOT free embedded pointers (ai_addr/ai_canonname) separately.
    while (pAddrInfo) {
        PVOID pNext = *(PVOID*)((BYTE*)pAddrInfo + nextOffset);

        // Validate heap before freeing to catch corruption early
        if (!HeapValidate(hHeap, 0, pAddrInfo)) {
            break;
        }

        HeapFree(hHeap, 0, pAddrInfo);
        pAddrInfo = pNext;
    }
}

//---------------------------------------------------------------------------
// WSA_freeaddrinfo
//
// Hook for freeaddrinfo (ANSI) - frees ADDRINFOA structures
// FIX: Now uses HeapAlloc/HeapFree instead of LocalAlloc to match system allocator
//---------------------------------------------------------------------------

_FX VOID WSAAPI WSA_freeaddrinfo(PADDRINFOA pAddrInfo)
{
    WSA_FreeAddrInfo_Common(
        (PVOID)pAddrInfo,
        (P_freeaddrinfo_void)__sys_freeaddrinfo,
        (SIZE_T)FIELD_OFFSET(ADDRINFOA, ai_next));
}

//---------------------------------------------------------------------------
// WSA_FreeAddrInfoW
//
// Hook for FreeAddrInfoW - frees ADDRINFOW structures
// FIX: Uses private heap to distinguish our allocations from system allocations
//---------------------------------------------------------------------------

_FX VOID WSAAPI WSA_FreeAddrInfoW(PADDRINFOW pAddrInfo)
{
    WSA_FreeAddrInfo_Common(
        (PVOID)pAddrInfo,
        (P_freeaddrinfo_void)__sys_FreeAddrInfoW,
        (SIZE_T)FIELD_OFFSET(ADDRINFOW, ai_next));
}

//---------------------------------------------------------------------------
// WSA_FreeAddrInfoExW
//
// Hook for FreeAddrInfoExW - frees ADDRINFOEXW structures
// FIX: Uses private heap to distinguish our allocations from system allocations
//---------------------------------------------------------------------------

_FX VOID WSAAPI WSA_FreeAddrInfoExW(PADDRINFOEXW pAddrInfoEx)
{
    WSA_FreeAddrInfo_Common(
        (PVOID)pAddrInfoEx,
        (P_freeaddrinfo_void)__sys_FreeAddrInfoExW,
        (SIZE_T)FIELD_OFFSET(ADDRINFOEXW, ai_next));
}

//---------------------------------------------------------------------------
// DNS_Cleanup
//
// Cleanup DNS filter resources (called at DLL unload)
//---------------------------------------------------------------------------

_FX void DNS_Cleanup(void)
{
    EncryptedDns_Cleanup();
    
    // Destroy our private heap if it was created
    HANDLE hHeap = InterlockedExchangePointer(&g_DnsFilterHeap, NULL);
    if (hHeap) {
        HeapDestroy(hHeap);
    }
}
