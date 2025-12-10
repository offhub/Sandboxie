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
//        - NO NetworkDnsFilterType: A/AAAA/ANY intercepted, all other types return NODATA (blocked)
//        - Types in list: Intercepted if supported (A/AAAA), NODATA if unsupported (MX/TXT/etc)
//        - Types NOT in list: PASSTHROUGH to real DNS (only when NetworkDnsFilterType IS set)
//        - Negated types (!type): Passthrough to real DNS (explicit passthrough)
//        - Wildcard (*): Filter ALL types (intercept supported, NODATA for unsupported)
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
//                 - NO NetworkDnsFilterType: A/AAAA/ANY intercepted, all others return NOERROR + NODATA.
//                 - WITH NetworkDnsFilterType: Only listed types filtered; unlisted types PASSTHROUGH.
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
//    FilterWinHttp=[process,]y|n
//      - Boolean: Enable/disable WinHTTP API hooking (default: n)
//      - Per-process support: FilterWinHttp=updutil.exe,y
//      - When enabled: WinHttpConnect() calls are validated against NetworkDnsFilter rules
//      - Intercepts: Applications using WinHTTP for HTTP/HTTPS (e.g., UpdUtil, many updaters)
//      - Use case: Block malicious update services or telemetry URLs accessed via WinHTTP
//      - Note: Works independently from other DNS hooks; applies NetworkDnsFilter rules
//      - Examples:
//        * FilterWinHttp=y  (enable for all processes)
//        * FilterWinHttp=updutil.exe,y  (enable only for UpdUtil)
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
//    SecureDnsServer=[process,]<url>[;<url2>;...]
//      - DNS-over-HTTPS (DoH) server URLs for passthrough queries (default: disabled)
//      - Format: Semicolon-separated HTTPS URLs to RFC 8484 compliant DoH servers
//      - URL format: https://host[:port][/path] or httpx://host[:port][/path]
//        * https://  - Standard HTTPS with full certificate validation (signed cert)
//        * httpx:// - HTTPS with disabled certificate validation (self-signed cert)
//        * Port defaults to 443, path defaults to /dns-query
//      - Per-process support: SecureDnsServer=firefox.exe,https://1.1.1.1/dns-query
//        * Process-specific configs have HIGHER priority than global configs
//        * Only highest priority level is used (per-process overrides global completely)
//      - IPv6 servers: Use bracket notation https://[2606:4700:4700::1111]/dns-query
//      - Custom port support: https://dns.example.com:8443/dns-query
//      - Self-signed certificate support: httpx://internal-doh.local:8443/dns-query
//      - Supported providers: Cloudflare, Google, Quad9, any RFC 8484 server (signed or self-signed)
//      - Multi-server support:
//        * Multiple SecureDnsServer lines: Up to 8 config lines supported
//        * Each line can contain up to 16 semicolon-separated server URLs
//        * Round-robin load balancing across config lines AND servers within lines
//        * Failed servers enter 30-second cooldown (automatic failover)
//      - Examples:
//        * Single server (signed cert):
//          SecureDnsServer=https://cloudflare-dns.com/dns-query
//        * Multiple servers (same line, signed certs):
//          SecureDnsServer=https://1.1.1.1/dns-query;https://1.0.0.1/dns-query
//        * Multiple lines (round-robin across providers):
//          SecureDnsServer=https://1.1.1.1/dns-query;https://1.0.0.1/dns-query
//          SecureDnsServer=https://9.9.9.9/dns-query;https://149.112.112.112/dns-query
//        * Per-process configuration (OVERRIDES global):
//          SecureDnsServer=https://1.1.1.1/dns-query
//          SecureDnsServer=nslookup.exe,https://9.9.9.9/dns-query
//          (nslookup.exe uses ONLY 9.9.9.9, other processes use 1.1.1.1)
//        * IPv6 servers:
//          SecureDnsServer=https://[2606:4700:4700::1111]/dns-query
//          SecureDnsServer=https://[2001:4860:4860::8888]/dns-query
//        * Self-signed certificate (internal DoH server):
//          SecureDnsServer=httpx://internal-doh.corp:443/dns-query
//          SecureDnsServer=httpx://[fd12:3456::1]:8443/dns-query
//      - Behavior:
//        * Only applies to passthrough domains (excluded or no filter match)
//        * Bypasses system DNS resolver for enhanced privacy/security
//        * Supports A and AAAA queries only (consistent with NetworkDnsFilter)
//        * Response caching: 64-entry cache, 300-second default TTL
//        * Certificate validation via WinHTTP/WinINet (prevents MITM attacks on https://)
//        * Self-signed certs (httpx://) bypass validation for internal/test environments
//        * Supported APIs: GetAddrInfoW, DnsQuery_A/W/UTF8, DnsQueryEx (~95% coverage)
//      - Re-entrancy protection: DoH server hostname automatically excluded
//      - Use case: Prevent DNS leaks for non-filtered domains, bypass DNS-based blocking, internal DoH servers
//      - Security: httpx:// should only be used for internal DoH servers in trusted networks
//      - Note: Requires valid HTTPS connection; falls back to system DNS on error
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
#include "dns_logging.h"
#include "dns_doh.h"
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

static PDNSAPI_DNS_RECORD DNSAPI_BuildDnsRecordList(
    const WCHAR*    domainName,
    WORD            wType,
    LIST*           pEntries,
    DNS_CHARSET     CharSet,
    const DOH_RESULT* pDohResult);  // Optional: CNAME info from DoH

// DNS Type Filter Helper Functions (internal use only)
static BOOLEAN DNS_ParseTypeName(const WCHAR* name, USHORT* type_out, BOOLEAN* is_negated);

// DoH helper functions (forward declarations)
static BOOLEAN DNS_TryDoHQuery(const WCHAR* domain, USHORT qtype, LIST* pListOut, DOH_RESULT* pFullResult);
static void DNS_FreeIPEntryList(LIST* pList);
static BOOLEAN DNS_DoHQueryForFamily(const WCHAR* domain, int family, LIST* pListOut);
static int DNS_DoHBuildWSALookup(LPWSAQUERYSETW lpqsRestrictions, LPHANDLE lphLookup);
static BOOLEAN WSA_ConvertAddrInfoWToEx(PADDRINFOW pResultW, PADDRINFOEXW* ppResultEx);
static BOOLEAN DNS_DoHQueryForGetAddrInfoExW(PCWSTR pName, int family, const ADDRINFOEXW* hints, PCWSTR pServiceName, PADDRINFOEXW* ppResult);

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

    // Type not in list - PASSTHROUGH (only when NetworkDnsFilterType IS set)
    // When user sets NetworkDnsFilterType, only listed types are filtered; unlisted types passthrough
    return FALSE;  // Passthrough to real DNS
}

//---------------------------------------------------------------------------
// DNS_IsTypeInFilterListEx
//
// Extended version that also returns the passthrough reason
// Returns TRUE if type should be filtered, FALSE if it should pass through
// pReason is set when returning FALSE to indicate WHY it's passthrough
//---------------------------------------------------------------------------

BOOLEAN DNS_IsTypeInFilterListEx(const DNS_TYPE_FILTER* type_filter, USHORT query_type, DNS_PASSTHROUGH_REASON* pReason)
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
    if (DNS_IsTypeNegated(type_filter, query_type)) {
        if (pReason) *pReason = DNS_PASSTHROUGH_TYPE_NEGATED;
        return FALSE;  // Negated - passthrough
    }

    // Wildcard specified - filter ALL unlisted types (except negated, already checked)
    if (type_filter->has_wildcard) {
        return TRUE;
    }

    // Type not in list - PASSTHROUGH (only when NetworkDnsFilterType IS set)
    // When user sets NetworkDnsFilterType, only listed types are filtered; unlisted types passthrough
    if (pReason) *pReason = DNS_PASSTHROUGH_TYPE_NOT_FILTERED;
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

    // Automatically exclude DoH server hostname to prevent re-entrancy loops
    // (WinHTTP resolves hostname internally, triggering DNS hooks)
    if (DoH_IsEnabled()) {
        const WCHAR* doh_hostname = DoH_GetServerHostname();
        if (doh_hostname && _wcsicmp(domain, doh_hostname) == 0) {
            if (DNS_DebugFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"[DoH] Auto-excluded DoH server hostname: %s", domain);
                SbieApi_MonitorPutMsg(MONITOR_OTHER, msg);
            }
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

    PATTERN* found = NULL;
    int match_result;
    
    if (level == (ULONG)-1) {
        // Match any level - for runtime lookups (GetAddrInfo, DnsQuery, etc.)
        match_result = Pattern_MatchPathList(domain_lwr, (ULONG)domain_len, &DNS_FilterList, NULL, NULL, NULL, &found);
    } else {
        // Match specific level - for configuration loading (NetworkDnsFilterType)
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
            
            // Exclude DoH server hostnames to prevent re-entrancy
            // DoH uses WinHTTP internally, so we must bypass DoH server connections
            if (DoH_IsServerHostname(domain_lwr)) {
                if (DNS_TraceFlag || DNS_DebugFlag) {
                    DNS_LogPassthrough(L"WinHTTP", pswzServerName, DNS_TYPE_ANY, L"DoH server");
                }
                Dll_Free(domain_lwr);
                return __sys_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
            }
            
            // If a DoH query is already active, bypass to prevent re-entrancy
            // DoH may trigger GetAddrInfoW which may trigger WinHttpConnect recursively
            if (DoH_IsQueryActive()) {
                if (DNS_TraceFlag || DNS_DebugFlag) {
                    DNS_LogPassthrough(L"WinHTTP", pswzServerName, DNS_TYPE_ANY, L"DoH query active");
                }
                Dll_Free(domain_lwr);
                return __sys_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
            }
            
            PATTERN* found = NULL;
            
            // Use Pattern_MatchPathList for consistent wildcard matching with DNS_FilterList
            if (Pattern_MatchPathList(domain_lwr, (ULONG)domain_len, &DNS_FilterList, NULL, NULL, NULL, &found) > 0) {
                // Domain matches NetworkDnsFilter
                
                // Check if certificate is valid for filtering
                if (!DNS_HasValidCertificate) {
                    DNS_LogPassthrough(L"WinHTTP", pswzServerName, DNS_TYPE_ANY, L"no certificate");
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
                    DNS_LogBlocked(L"WinHTTP", pswzServerName, DNS_TYPE_ANY, L"Domain blocked (NXDOMAIN)");
                    Dll_Free(domain_lwr);
                    SetLastError(ERROR_HOST_UNREACHABLE);
                    return NULL;
                }
                
                // Has IP entries - redirect mode
                // WinHTTP will perform DNS resolution internally via GetAddrInfoW
                // Our existing GetAddrInfoW hook will intercept and return the filtered IPs
                // Just allow the connection - the DNS hook handles the redirection
                DNS_LogPassthrough(L"WinHTTP", pswzServerName, DNS_TYPE_ANY, L"allowing (DNS hooks will redirect)");
                Dll_Free(domain_lwr);
                // Let WinHTTP proceed - it will call GetAddrInfoW which our hooks will intercept
                return __sys_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
            }
            
            // Domain not in filter - allow and log passthrough if tracing
            DNS_LogPassthrough(L"WinHTTP", pswzServerName, DNS_TYPE_ANY, L"not filtered");
            
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
    DoH_Init(hWinHttp);
    DoH_LoadConfig();

    return TRUE;
}

//---------------------------------------------------------------------------
// WINHTTP_Init
//
// Initializes WinHTTP hooks (called when winhttp.dll is loaded)
// Hooks WinHttpConnect() to validate domains against NetworkDnsFilter rules
//---------------------------------------------------------------------------

_FX BOOLEAN WINHTTP_Init(HMODULE module)
{
    // Initialize shared filter rules (if not already done)
    DNS_InitFilterRules();

    // Check FilterWinHttp setting (default: disabled)
    BOOLEAN winHttpEnabled = Config_GetSettingsForImageName_bool(L"FilterWinHttp", FALSE);
    
    if (!winHttpEnabled) {
        // FilterWinHttp disabled - skip WinHTTP hooking entirely
        return TRUE;
    }

    // Only hook if filter rules exist
    if (!DNS_FilterEnabled) {
        return TRUE;
    }

    // Enable the WinHTTP hook for this process
    DNS_WinHttpHookEnabled = TRUE;

    //
    // Setup WinHttpConnect hook
    //

    P_WinHttpConnect WinHttpConnect = (P_WinHttpConnect)GetProcAddress(module, "WinHttpConnect");
    if (!WinHttpConnect) {
        // Function not found in module - log and skip
        SbieApi_Log(2205, L"WinHttpConnect not found in winhttp.dll");
        return TRUE;
    }
    
    SBIEDLL_HOOK(DNS_, WinHttpConnect);

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

    // Initialize DoH client
    // Note: We try to load configuration even without WinHTTP/WinINet
    // because SbieSvc can handle DoH queries out-of-process
    HMODULE hWinHttp = GetModuleHandleW(L"winhttp.dll");
    if (!hWinHttp) {
        hWinHttp = LoadLibraryW(L"winhttp.dll");
    }
    
    // Always initialize DoH (even if hWinHttp is NULL)
    // DoH_Init handles NULL gracefully and loads WinINet if available
    DoH_Init(hWinHttp);
    
    // Always try to load configuration
    // If in-process backends unavailable, SbieSvc will be used
    DoH_LoadConfig();

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
        return __sys_WSALookupServiceBeginW(lpqsRestrictions, dwControlFlags, lphLookup);
    }
    
    // Re-entrancy check: if we're inside system's getaddrinfo (ANSI), passthrough
    // The system's getaddrinfo calls GetAddrInfoW which may call WSALookupService
    // If we intercept here and call DoH, we'll block waiting for WinHTTP which
    // may deadlock if the DNS resolution thread pool is exhausted
    if (WSA_SystemGetAddrInfoDepth > 0) {
        return __sys_WSALookupServiceBeginW(lpqsRestrictions, dwControlFlags, lphLookup);
    }
    
    if (DNS_FilterEnabled && lpqsRestrictions && lpqsRestrictions->lpszServiceInstanceName) {
        ULONG path_len = wcslen(lpqsRestrictions->lpszServiceInstanceName);
        WCHAR* path_lwr = (WCHAR*)Dll_AllocTemp((path_len + 4) * sizeof(WCHAR));
        wmemcpy(path_lwr, lpqsRestrictions->lpszServiceInstanceName, path_len);
        path_lwr[path_len] = L'\0';
        _wcslwr(path_lwr);

        if (DNS_IsExcluded(path_lwr)) {
            DNS_LogExclusion(path_lwr);
            // Excluded domains bypass all filtering and DoH - use system DNS directly
            Dll_Free(path_lwr);
            return __sys_WSALookupServiceBeginW(lpqsRestrictions, dwControlFlags, lphLookup);
        }

        PATTERN* found;
        if (Pattern_MatchPathList(path_lwr, path_len, &DNS_FilterList, NULL, NULL, NULL, &found) > 0) {
            
            // Certificate required for actual filtering (interception/blocking)
            extern BOOLEAN DNS_HasValidCertificate;
            if (!DNS_HasValidCertificate) {
                // Domain matches filter but no cert - try DoH first, then passthrough
                WORD queryType = WSA_IsIPv6Query(lpqsRestrictions->lpServiceClassId) ? DNS_TYPE_AAAA : DNS_TYPE_A;
                LIST doh_list;
                DOH_RESULT doh_result;
                if (DoH_IsEnabled() && DNS_TryDoHQuery(path_lwr, queryType, &doh_list, &doh_result)) {
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
                            
                            // Convert DoH results to IP_ENTRY list
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
                                TRUE);  // is_doh = TRUE (DoH resolution)
                            
                            Dll_Free(path_lwr);
                            DNS_FreeIPEntryList(&doh_list);
                            return NO_ERROR;
                        }
                        Dll_Free(fakeHandle);
                    }
                    DNS_FreeIPEntryList(&doh_list);
                }
                
                // DoH query failed or returned no records
                if (DoH_IsEnabled()) {
                    // DoH is enabled but query failed - return error instead of fallback to system DNS
                    Dll_Free(path_lwr);
                    SetLastError(WSAHOST_NOT_FOUND);
                    return SOCKET_ERROR;
                }
                
                // DoH disabled - fall through to system DNS
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
                            // Type not in filter list or negated - try DoH first, then passthrough to real DNS
                            EnterCriticalSection(&WSA_LookupMap_CritSec);
                            map_remove(&WSA_LookupMap, fakeHandle);
                            LeaveCriticalSection(&WSA_LookupMap_CritSec);
                            Dll_Free(fakeHandle);
                            
                            // Try DoH for negated type passthrough queries
                            int doh_result = DNS_DoHBuildWSALookup(lpqsRestrictions, lphLookup);
                            if (doh_result == NO_ERROR) {
                                Dll_Free(path_lwr);
                                return NO_ERROR;
                            }
                            
                            // DoH failed or disabled
                            Dll_Free(path_lwr);
                            if (DoH_IsEnabled()) {
                                // DoH is enabled but failed - return error
                                return SOCKET_ERROR;
                            }
                            // DoH disabled - passthrough to real DNS
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
                FALSE);  // is_doh = FALSE (filter-based)

            Dll_Free(path_lwr);
            return NO_ERROR;
        }

        Dll_Free(path_lwr);
    }

    // If DoH is enabled, try DoH for all passthrough queries (non-matching or no-cert)
    // This ensures all DNS traffic goes through secure channel when SecureDnsServer is configured
    if (lpqsRestrictions && lpqsRestrictions->lpszServiceInstanceName) {
        int doh_result = DNS_DoHBuildWSALookup(lpqsRestrictions, lphLookup);
        if (doh_result == NO_ERROR) {
            return NO_ERROR;
        }
        // DoH failed or disabled - if DoH is enabled, return error (no fallback)
        if (DoH_IsEnabled()) {
            return SOCKET_ERROR;
        }
    }

    // DoH disabled - use system DNS
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
//
// If pDohResult is provided and contains CNAME info, prepends CNAME record
//---------------------------------------------------------------------------

_FX PDNSAPI_DNS_RECORD DNSAPI_BuildDnsRecordList(
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

    // If DoH result contains CNAME, prepend it first
    if (pDohResult && pDohResult->HasCname && pDohResult->CnameOwner[0] != L'\0' && pDohResult->CnameTarget[0] != L'\0') {
        SIZE_T ownerNameLen = 0, targetNameLen = 0;
        
        // Calculate lengths based on CharSet
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
            // Allocate CNAME record
            PDNSAPI_DNS_RECORD pCnameRec = (PDNSAPI_DNS_RECORD)LocalAlloc(LPTR, sizeof(DNSAPI_DNS_RECORD));
            if (pCnameRec) {
                pCnameRec->pName = (PWSTR)LocalAlloc(LPTR, ownerNameLen);
                if (pCnameRec->pName) {
                    // Copy owner name
                    if (CharSet == DnsCharSetUnicode) {
                        wmemcpy(pCnameRec->pName, pDohResult->CnameOwner, wcslen(pDohResult->CnameOwner) + 1);
                    } else if (CharSet == DnsCharSetAnsi) {
                        WideCharToMultiByte(CP_ACP, 0, pDohResult->CnameOwner, -1, (LPSTR)pCnameRec->pName, (int)ownerNameLen, NULL, NULL);
                    } else if (CharSet == DnsCharSetUtf8) {
                        WideCharToMultiByte(CP_UTF8, 0, pDohResult->CnameOwner, -1, (LPSTR)pCnameRec->pName, (int)ownerNameLen, NULL, NULL);
                    }
                    
                    // Allocate and copy CNAME target
                    pCnameRec->Data.CNAME.pNameHost = (PWSTR)LocalAlloc(LPTR, targetNameLen);
                    if (pCnameRec->Data.CNAME.pNameHost) {
                        if (CharSet == DnsCharSetUnicode) {
                            wmemcpy(pCnameRec->Data.CNAME.pNameHost, pDohResult->CnameTarget, wcslen(pDohResult->CnameTarget) + 1);
                        } else if (CharSet == DnsCharSetAnsi) {
                            WideCharToMultiByte(CP_ACP, 0, pDohResult->CnameTarget, -1, (LPSTR)pCnameRec->Data.CNAME.pNameHost, (int)targetNameLen, NULL, NULL);
                        } else if (CharSet == DnsCharSetUtf8) {
                            WideCharToMultiByte(CP_UTF8, 0, pDohResult->CnameTarget, -1, (LPSTR)pCnameRec->Data.CNAME.pNameHost, (int)targetNameLen, NULL, NULL);
                        }
                        
                        // Set CNAME record fields
                        pCnameRec->wType = DNS_TYPE_CNAME;
                        pCnameRec->wDataLength = (WORD)targetNameLen;
                        pCnameRec->Flags.DW = 0;
                        pCnameRec->Flags.S.Section = DNSREC_ANSWER;
                        pCnameRec->Flags.S.CharSet = CharSet;
                        pCnameRec->dwTtl = pDohResult->TTL;
                        pCnameRec->dwReserved = 0x53424945;  // 'SBIE' magic marker
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

    // For ANY queries (type 255), return both A and AAAA records
    BOOLEAN is_any_query = (wType == 255);
    USHORT targetType = (wType == DNS_TYPE_AAAA) ? AF_INET6 : AF_INET;
    
    // If CNAME is present, use CNAME target as domain name for A/AAAA records
    const WCHAR* recordDomainName = domainName;
    if (pDohResult && pDohResult->HasCname && pDohResult->CnameTarget[0] != L'\0') {
        recordDomainName = pDohResult->CnameTarget;
    }
    
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
    
    // Calculate domain name length based on CharSet (for A/AAAA records)
    SIZE_T domainNameLen = 0;
    if (CharSet == DnsCharSetUnicode) {
        domainNameLen = (wcslen(recordDomainName) + 1) * sizeof(WCHAR);
    } else if (CharSet == DnsCharSetAnsi) {
        int len = WideCharToMultiByte(CP_ACP, 0, recordDomainName, -1, NULL, 0, NULL, NULL);
        if (len <= 0) return pFirstRecord;  // Return CNAME record if present
        domainNameLen = len;
    } else if (CharSet == DnsCharSetUtf8) {
        int len = WideCharToMultiByte(CP_UTF8, 0, recordDomainName, -1, NULL, 0, NULL, NULL);
        if (len <= 0) return pFirstRecord;  // Return CNAME record if present
        domainNameLen = len;
    } else {
        // Default to Unicode if unknown
        domainNameLen = (wcslen(recordDomainName) + 1) * sizeof(WCHAR);
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
        
        // Copy domain name with conversion (use CNAME target if present)
        if (CharSet == DnsCharSetUnicode) {
            wmemcpy(pRecord->pName, recordDomainName, wcslen(recordDomainName) + 1);
        } else if (CharSet == DnsCharSetAnsi) {
            WideCharToMultiByte(CP_ACP, 0, recordDomainName, -1, (LPSTR)pRecord->pName, (int)domainNameLen, NULL, NULL);
        } else if (CharSet == DnsCharSetUtf8) {
            WideCharToMultiByte(CP_UTF8, 0, recordDomainName, -1, (LPSTR)pRecord->pName, (int)domainNameLen, NULL, NULL);
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
        // Caller will log final result with IPs (suppression handles dedup)
        if (pPassthroughLogged)
            *pPassthroughLogged = TRUE;  // Signal caller to skip redundant logging
        if (pPassthroughReason)
            *pPassthroughReason = typeReason;
        *pStatus = 0;
        return FALSE;
    }

    // Type is in filter list - check if we can synthesize or should block
    if (DNS_CanSynthesizeResponse(wType)) {
        // Filter mode with supported type: build DNS_RECORD linked list
        PDNSAPI_DNS_RECORD pRecords = DNSAPI_BuildDnsRecordList(wName, wType, pEntries, CharSet, NULL);
        
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
    DNS_PASSTHROUGH_REASON passthroughReason = DNS_PASSTHROUGH_NONE;
    
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

    // Call original DnsQuery_W (or use DoH exclusively if enabled)
    DNS_STATUS status;
    
    // Try DoH for all passthrough queries when DoH is enabled
    // When DoH is enabled, we should ONLY use DoH - no fallback to system DNS
    if (DoH_IsEnabled() && pszName) {
        // For A/AAAA queries, perform actual DoH lookup
        if (wType == DNS_TYPE_A || wType == DNS_TYPE_AAAA) {
            LIST doh_list;
            DOH_RESULT doh_result;
            if (DNS_TryDoHQuery(pszName, wType, &doh_list, &doh_result)) {
                PDNSAPI_DNS_RECORD pResult = DNSAPI_BuildDnsRecordList(pszName, wType, &doh_list, DnsCharSetUnicode, &doh_result);
                if (pResult) {
                    DNS_LogDnsQueryResultWithReason(L"DnsQuery_W DoH", pszName, wType,
                                                   DNS_RCODE_NOERROR, (PDNS_RECORDW*)&pResult, passthroughReason);
                    DNS_FreeIPEntryList(&doh_list);
                    *ppQueryResults = pResult;
                    return DNS_RCODE_NOERROR;
                }
                DNS_FreeIPEntryList(&doh_list);
            }
            // DoH query failed or returned no records - return DNS error instead of fallback
            DNS_LogDnsQueryResultWithReason(L"DnsQuery_W DoH", pszName, wType,
                                           DNS_ERROR_RCODE_NAME_ERROR, NULL, passthroughReason);
            *ppQueryResults = NULL;
            return DNS_ERROR_RCODE_NAME_ERROR;
        }
        
        // For non-A/AAAA queries (MX, TXT, SRV, etc.), return NODATA
        // This prevents leaking queries to system DNS when DoH mode is enabled
        // TODO: Future enhancement - implement raw DNS wire format DoH for all types
        DNS_LogDnsQueryResultWithReason(L"DnsQuery_W DoH (unsupported type)", pszName, wType,
                                       DNS_INFO_NO_RECORDS, NULL, passthroughReason);
        *ppQueryResults = NULL;
        return DNS_INFO_NO_RECORDS;  // NODATA - domain exists but no records of this type
    }
    
    // DoH disabled - use system DNS
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
    // Track reason for passthrough (will be used in final logging)
    DNS_PASSTHROUGH_REASON passthroughReason = DNS_PASSTHROUGH_NONE;
    
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
                        // Domain matches filter but no cert - call real DNS and log result with IPs
                        DNS_STATUS status = __sys_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
                        DNS_LogDnsQueryResultWithReason(L"DnsQuery_A Passthrough", wName, wType, 
                                                       status, ppQueryResults, DNS_PASSTHROUGH_NO_CERT);
                        Dll_Free(wName);
                        return status;
                    }

                    LIST* pEntries = NULL;
                    DNS_TYPE_FILTER* type_filter = NULL;
                    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);

                    DNS_STATUS status;
                    BOOLEAN passthroughLogged = FALSE;
                    if (DNSAPI_FilterDnsQuery(wName, wType, pEntries, type_filter, DnsCharSetAnsi,
                                              L"DnsQuery_A Intercepted", ppQueryResults, &status, 
                                              &passthroughLogged, &passthroughReason)) {
                        Dll_Free(wName);
                        return status;
                    }

                    // Not filtered by type - passthrough to real DNS (logged with IPs and reason below)
                }

                Dll_Free(wName);
            }
        }
    }

    // Call original DnsQuery_A (or try DoH first)
    DNS_STATUS status;
    
    // When DoH is enabled, we should ONLY use DoH - no fallback to system DNS
    if (DoH_IsEnabled() && pszName) {
        int nameLen = MultiByteToWideChar(CP_ACP, 0, pszName, -1, NULL, 0);
        if (nameLen > 0 && nameLen < 512) {
            WCHAR* wName = (WCHAR*)Dll_AllocTemp(nameLen * sizeof(WCHAR));
            if (wName && MultiByteToWideChar(CP_ACP, 0, pszName, -1, wName, nameLen)) {
                // For A/AAAA queries, perform actual DoH lookup
                if (wType == DNS_TYPE_A || wType == DNS_TYPE_AAAA) {
                    LIST doh_list;
                    DOH_RESULT doh_result;
                    if (DNS_TryDoHQuery(wName, wType, &doh_list, &doh_result)) {
                        PDNSAPI_DNS_RECORD pResult = DNSAPI_BuildDnsRecordList(wName, wType, &doh_list, DnsCharSetAnsi, &doh_result);
                        if (pResult) {
                            DNS_LogDnsQueryResultWithReason(L"DnsQuery_A DoH", wName, wType,
                                                           DNS_RCODE_NOERROR, (PDNS_RECORDW*)&pResult, passthroughReason);
                            DNS_FreeIPEntryList(&doh_list);
                            Dll_Free(wName);
                            *ppQueryResults = pResult;
                            return DNS_RCODE_NOERROR;
                        }
                        DNS_FreeIPEntryList(&doh_list);
                    }
                    // DoH query failed - return error instead of fallback
                    DNS_LogDnsQueryResultWithReason(L"DnsQuery_A DoH", wName, wType,
                                                   DNS_ERROR_RCODE_NAME_ERROR, NULL, passthroughReason);
                    Dll_Free(wName);
                    *ppQueryResults = NULL;
                    return DNS_ERROR_RCODE_NAME_ERROR;
                }
                
                // For non-A/AAAA queries, return NODATA
                DNS_LogDnsQueryResultWithReason(L"DnsQuery_A DoH (unsupported type)", wName, wType,
                                               DNS_INFO_NO_RECORDS, NULL, passthroughReason);
                Dll_Free(wName);
                *ppQueryResults = NULL;
                return DNS_INFO_NO_RECORDS;
            }
        }
    }
    
    status = __sys_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);

    // Convert ANSI domain to wide for logging
    if (DNS_TraceFlag && pszName) {
        int nameLen = MultiByteToWideChar(CP_ACP, 0, pszName, -1, NULL, 0);
        if (nameLen > 0 && nameLen < 512) {
            WCHAR* wName = (WCHAR*)Dll_AllocTemp(nameLen * sizeof(WCHAR));
            if (wName && MultiByteToWideChar(CP_ACP, 0, pszName, -1, wName, nameLen)) {
                DNS_LogDnsQueryResultWithReason(L"DnsQuery_A Passthrough", wName, wType, 
                                               status, ppQueryResults, passthroughReason);
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
    // Track reason for passthrough (will be used in final logging)
    DNS_PASSTHROUGH_REASON passthroughReason = DNS_PASSTHROUGH_NONE;
    
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
                        // Domain matches filter but no cert - call real DNS and log result with IPs
                        DNS_STATUS status = __sys_DnsQuery_UTF8 ? __sys_DnsQuery_UTF8(pszName, wType, Options, pExtra, ppQueryResults, pReserved)
                                                               : __sys_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
                        DNS_LogDnsQueryResultWithReason(L"DnsQuery_UTF8 Passthrough", wName, wType, 
                                                       status, ppQueryResults, DNS_PASSTHROUGH_NO_CERT);
                        Dll_Free(wName);
                        return status;
                    }

                    LIST* pEntries = NULL;
                    DNS_TYPE_FILTER* type_filter = NULL;
                    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);

                    DNS_STATUS status;
                    BOOLEAN passthroughLogged = FALSE;
                    if (DNSAPI_FilterDnsQuery(wName, wType, pEntries, type_filter, DnsCharSetUtf8,
                                              L"DnsQuery_UTF8 Intercepted", ppQueryResults, &status, 
                                              &passthroughLogged, &passthroughReason)) {
                        Dll_Free(wName);
                        return status;
                    }

                    // Not filtered by type - passthrough to real DNS (logged with IPs and reason below)
                }

                Dll_Free(wName);
            }
        }
    }

    // Call original DnsQuery_UTF8 (or try DoH first)
    DNS_STATUS status;
    
    // When DoH is enabled, we should ONLY use DoH - no fallback to system DNS
    if (DoH_IsEnabled() && pszName) {
        int nameLen = MultiByteToWideChar(CP_UTF8, 0, pszName, -1, NULL, 0);
        if (nameLen > 0 && nameLen < 512) {
            WCHAR* wName = (WCHAR*)Dll_AllocTemp(nameLen * sizeof(WCHAR));
            if (wName && MultiByteToWideChar(CP_UTF8, 0, pszName, -1, wName, nameLen)) {
                // For A/AAAA queries, perform actual DoH lookup
                if (wType == DNS_TYPE_A || wType == DNS_TYPE_AAAA) {
                    LIST doh_list;
                    DOH_RESULT doh_result;
                    if (DNS_TryDoHQuery(wName, wType, &doh_list, &doh_result)) {
                        PDNSAPI_DNS_RECORD pResult = DNSAPI_BuildDnsRecordList(wName, wType, &doh_list, DnsCharSetUtf8, &doh_result);
                        if (pResult) {
                            DNS_LogDnsQueryResultWithReason(L"DnsQuery_UTF8 DoH", wName, wType,
                                                           DNS_RCODE_NOERROR, (PDNS_RECORDW*)&pResult, passthroughReason);
                            DNS_FreeIPEntryList(&doh_list);
                            Dll_Free(wName);
                            *ppQueryResults = pResult;
                            return DNS_RCODE_NOERROR;
                        }
                        DNS_FreeIPEntryList(&doh_list);
                    }
                    // DoH query failed - return error instead of fallback
                    DNS_LogDnsQueryResultWithReason(L"DnsQuery_UTF8 DoH", wName, wType,
                                                   DNS_ERROR_RCODE_NAME_ERROR, NULL, passthroughReason);
                    Dll_Free(wName);
                    *ppQueryResults = NULL;
                    return DNS_ERROR_RCODE_NAME_ERROR;
                }
                
                // For non-A/AAAA queries, return NODATA
                DNS_LogDnsQueryResultWithReason(L"DnsQuery_UTF8 DoH (unsupported type)", wName, wType,
                                               DNS_INFO_NO_RECORDS, NULL, passthroughReason);
                Dll_Free(wName);
                *ppQueryResults = NULL;
                return DNS_INFO_NO_RECORDS;
            }
        }
    }
    
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
                DNS_LogDnsQueryResultWithReason(L"DnsQuery_UTF8 Passthrough", wName, wType, 
                                               status, ppQueryResults, passthroughReason);
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
// Helper: Try DoH for DnsQueryEx passthrough queries
// Returns TRUE if DoH succeeded and pQueryResults filled
// For non-A/AAAA types when DoH is enabled, returns NODATA result
//---------------------------------------------------------------------------

static BOOLEAN DNSAPI_TryDoHForQueryEx(
    const WCHAR* pszName,
    WORD wType,
    ULONG64 queryOptions,
    PDNS_QUERY_RESULT pQueryResults,
    DNS_CHARSET CharSet)
{
    if (!pszName || !pQueryResults) {
        return FALSE;
    }

    // For non-A/AAAA types when DoH is enabled, return success with empty result (NODATA)
    // This prevents leaking queries to system DNS
    if (wType != DNS_TYPE_A && wType != DNS_TYPE_AAAA) {
        if (DoH_IsEnabled()) {
            // Fill with empty NODATA result
            if (pQueryResults->Version == 0)
                pQueryResults->Version = DNS_QUERY_RESULTS_VERSION1;
            pQueryResults->QueryOptions = queryOptions;
            pQueryResults->pQueryRecords = NULL;
            pQueryResults->Reserved = NULL;
            pQueryResults->QueryStatus = DNS_INFO_NO_RECORDS;  // NODATA
            return TRUE;
        }
        return FALSE;
    }

    LIST doh_list;
    DOH_RESULT doh_result;
    if (!DNS_TryDoHQuery(pszName, wType, &doh_list, &doh_result)) {
        return FALSE;
    }

    PDNSAPI_DNS_RECORD pRecords = DNSAPI_BuildDnsRecordList(pszName, wType, &doh_list, CharSet, &doh_result);
    DNS_FreeIPEntryList(&doh_list);

    if (!pRecords) {
        return FALSE;
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
    
    // Not filtered - try DoH for passthrough queries (but NOT for excluded domains)
    // Excluded domains should use system DNS directly
    if (pQueryRequest->QueryName) {
        size_t domain_len = wcslen(pQueryRequest->QueryName);
        WCHAR* domain_lwr = (WCHAR*)Dll_AllocTemp((domain_len + 4) * sizeof(WCHAR));
        if (domain_lwr) {
            wmemcpy(domain_lwr, pQueryRequest->QueryName, domain_len);
            domain_lwr[domain_len] = L'\0';
            _wcslwr(domain_lwr);
            
            BOOLEAN is_excluded = DNS_IsExcluded(domain_lwr);
            Dll_Free(domain_lwr);
            
            if (!is_excluded) {
                // Not excluded - try DoH
                if (DNSAPI_TryDoHForQueryEx(pQueryRequest->QueryName, pQueryRequest->QueryType,
                                             pQueryRequest->QueryOptions, pQueryResults, DnsCharSetUnicode)) {
                    DNS_LogDnsRecordsFromQueryResult(L"DnsQueryEx DoH", pQueryRequest->QueryName,
                                                    pQueryRequest->QueryType, 0, (PDNSAPI_DNS_RECORD)pQueryResults->pQueryRecords);
                    return 0;
                }
                // DoH query failed or returned no records - return error when DoH is enabled
                if (DoH_IsEnabled()) {
                    DNS_LogDnsQueryExStatus(L"DnsQueryEx DoH", pQueryRequest->QueryName, 
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
                                // Domain matches filter but no cert - passthrough (logged via callback with IPs)
                                Dll_Free(domain_lwr);
                                
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
                                                                     domain, qtype, pEntries);
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
                                        DNS_LogIntercepted(L"DnsQueryRaw Intercepted", domain, qtype, pEntries);
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
// DNS_TryDoHQuery
//
// Helper function to attempt DoH query for passthrough domains
// Returns: TRUE if DoH succeeded and pResult contains valid response
//          FALSE if DoH disabled, failed, or no results
// 
// Used by: DnsQuery_A, DnsQuery_W, DnsQuery_UTF8, GetAddrInfoW
//---------------------------------------------------------------------------

static BOOLEAN DNS_TryDoHQuery(
    const WCHAR* domain,
    USHORT qtype,
    LIST* pListOut,  // Output: IP_ENTRY list
    DOH_RESULT* pFullResult)  // Output: Full DoH result (including CNAME)
{
    if (!DoH_IsEnabled() || !domain || !pListOut) {
        return FALSE;
    }

    // For non-A/AAAA queries, return success with empty result (NODATA)
    // This ensures DoH-only mode doesn't leak non-address queries to system DNS
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

    DOH_RESULT doh_result;
    if (!DoH_Query(domain, qtype, &doh_result)) {
        return FALSE;
    }

    // Don't follow CNAME for passthrough queries - return DoH response as-is
    // The DoH server already resolved any CNAME and returned both CNAME and A records
    // Following CNAME here causes issues and duplication
    
    // Check for failure cases
    if (!doh_result.Success || doh_result.Status != 0) {
        return FALSE;
    }

    // Return full result (including CNAME info)
    if (pFullResult) {
        memcpy(pFullResult, &doh_result, sizeof(DOH_RESULT));
    }

    // Convert DOH_RESULT to IP_ENTRY list
    List_Init(pListOut);
    for (int i = 0; i < doh_result.AnswerCount; i++) {
        IP_ENTRY* pEntry = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
        if (pEntry) {
            pEntry->Type = doh_result.Answers[i].Type;
            memcpy(&pEntry->IP, &doh_result.Answers[i].IP, sizeof(IP_ADDRESS));
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
// Unified DoH query helper for address-family-based lookups (GetAddrInfo style)
// Handles AF_UNSPEC by querying both A and AAAA, merging results.
//
// Parameters:
//   domain       - Domain name to query
//   family       - AF_INET, AF_INET6, or AF_UNSPEC
//   pListOut     - Output: Combined IP_ENTRY list (caller must free with DNS_FreeIPEntryList)
//
// Returns: TRUE if any records were returned, FALSE on failure
//---------------------------------------------------------------------------

static BOOLEAN DNS_DoHQueryForFamily(
    const WCHAR* domain,
    int family,
    LIST* pListOut)
{
    if (!DoH_IsEnabled() || !domain || !pListOut) {
        return FALSE;
    }

    List_Init(pListOut);
    BOOLEAN hasResults = FALSE;

    if (family == AF_UNSPEC) {
        // Query both A and AAAA records
        LIST doh_list_a;
        DOH_RESULT doh_result_a;
        if (DNS_TryDoHQuery(domain, DNS_TYPE_A, &doh_list_a, &doh_result_a)) {
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
        DOH_RESULT doh_result;
        if (DNS_TryDoHQuery(domain, qtype, pListOut, &doh_result)) {
            hasResults = TRUE;
        }
    }

    return hasResults;
}

//---------------------------------------------------------------------------
// DNS_DoHBuildWSALookup
//
// Unified DoH helper for WSALookupService - creates a WSA_LOOKUP structure
// with DoH results ready to be returned by WSALookupServiceNextW.
//
// Parameters:
//   lpqsRestrictions - Original WSA query parameters
//   lphLookup        - Output handle
//
// Returns: NO_ERROR on success, SOCKET_ERROR on failure (call GetLastError)
//---------------------------------------------------------------------------

static int DNS_DoHBuildWSALookup(
    LPWSAQUERYSETW lpqsRestrictions,
    LPHANDLE lphLookup)
{
    if (!DoH_IsEnabled() || !lpqsRestrictions || !lpqsRestrictions->lpszServiceInstanceName || !lphLookup) {
        return SOCKET_ERROR;
    }

    WORD queryType = WSA_IsIPv6Query(lpqsRestrictions->lpServiceClassId) ? DNS_TYPE_AAAA : DNS_TYPE_A;
    
    LIST doh_list;
    DOH_RESULT doh_result;
    if (!DNS_TryDoHQuery(lpqsRestrictions->lpszServiceInstanceName, queryType, &doh_list, &doh_result)) {
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

    // Convert DoH results to IP_ENTRY list in lookup structure
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
        TRUE);  // is_doh = TRUE (DoH resolution)

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
// Unified DoH query helper for GetAddrInfoExW - handles family-based queries
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
    PADDRINFOEXW* ppResult)
{
    if (!DoH_IsEnabled() || !pName || !ppResult) {
        return FALSE;
    }

    LIST doh_list;
    if (!DNS_DoHQueryForFamily(pName, family, &doh_list)) {
        return FALSE;
    }

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
    SIZE_T nameLen = wcslen(pNodeName);
    if (nameLen == 0 || nameLen > 255) {
        return __sys_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }
    
    WCHAR* nameLwr = (WCHAR*)Dll_AllocTemp((ULONG)((nameLen + 1) * sizeof(WCHAR)));
    if (!nameLwr) {
        return __sys_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }
    wmemcpy(nameLwr, pNodeName, nameLen);
    nameLwr[nameLen] = L'\0';
    _wcslwr(nameLwr);

    // Check if excluded - if so, bypass all filtering and DoH
    if (DNS_IsExcluded(nameLwr)) {
        GAI_LogPassthrough(L"GetAddrInfoW", pNodeName, family, L"excluded from filtering");
        Dll_Free(nameLwr);
        return __sys_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }

    // Exclude DoH server hostnames to prevent re-entrancy
    if (DoH_IsServerHostname(nameLwr)) {
        GAI_LogPassthrough(L"GetAddrInfoW", pNodeName, family, L"DoH server");
        Dll_Free(nameLwr);
        return __sys_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }

    // If a DoH query is already active, bypass to prevent re-entrancy from worker threads
    if (DoH_IsQueryActive()) {
        GAI_LogPassthrough(L"GetAddrInfoW", pNodeName, family, L"DoH query active");
        Dll_Free(nameLwr);
        return __sys_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }

    // Use shared validation helper
    PVOID* aux = NULL;
    PATTERN* found = DNS_FindPatternInFilterList(nameLwr, (ULONG)-1);
    
    if (!found) {
        // No filter match - use DoH exclusively if enabled, otherwise system DNS
        if (DoH_IsEnabled()) {
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"[GetAddrInfoW] DoH path: domain=%s, family=%d", 
                    pNodeName, family);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            
            LIST doh_list;
            if (DNS_DoHQueryForFamily(pNodeName, family, &doh_list)) {
                PADDRINFOW pResult = WSA_BuildAddrInfoList(pNodeName, pServiceName, pHints, &doh_list);
                if (pResult) {
                    GAI_LogIntercepted(L"GetAddrInfoW DoH", pNodeName, family, &doh_list, TRUE);
                    DNS_FreeIPEntryList(&doh_list);
                    Dll_Free(nameLwr);
                    *ppResult = pResult;
                    return 0;
                }
            }
            
            // DoH query failed or returned no records - return error instead of fallback
            DNS_FreeIPEntryList(&doh_list);
            GAI_LogPassthrough(L"GetAddrInfoW DoH", pNodeName, family, L"no DoH records");
            Dll_Free(nameLwr);
            return WSAHOST_NOT_FOUND;
        }
        
        // DoH disabled - use system DNS
        GAI_LogPassthrough(L"GetAddrInfoW", pNodeName, family, L"no filter match");
        Dll_Free(nameLwr);
        return __sys_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    }

    // Domain matches filter - check certificate
    extern BOOLEAN DNS_HasValidCertificate;
    if (!DNS_HasValidCertificate) {
        // Domain matches filter but no cert - use DoH exclusively if enabled, otherwise passthrough
        if (DoH_IsEnabled()) {
            LIST doh_list;
            if (DNS_DoHQueryForFamily(pNodeName, family, &doh_list)) {
                PADDRINFOW pResult = WSA_BuildAddrInfoList(pNodeName, pServiceName, pHints, &doh_list);
                if (pResult) {
                    GAI_LogIntercepted(L"GetAddrInfoW DoH (no cert)", pNodeName, family, &doh_list, TRUE);
                    DNS_FreeIPEntryList(&doh_list);
                    Dll_Free(nameLwr);
                    *ppResult = pResult;
                    return 0;
                }
            }
            
            // DoH query failed or returned no records - return error instead of fallback
            DNS_FreeIPEntryList(&doh_list);
            GAI_LogPassthrough(L"GetAddrInfoW DoH (no cert)", pNodeName, family, L"no DoH records");
            Dll_Free(nameLwr);
            return WSAHOST_NOT_FOUND;
        }
        
        // DoH disabled - use system DNS
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
        // Type not in filter list or negated - try DoH first, then passthrough
        if (DoH_IsEnabled()) {
            LIST doh_list;
            if (DNS_DoHQueryForFamily(pNodeName, family, &doh_list)) {
                PADDRINFOW pResult = WSA_BuildAddrInfoList(pNodeName, pServiceName, pHints, &doh_list);
                if (pResult) {
                    GAI_LogIntercepted(L"GetAddrInfoW DoH (type passthrough)", pNodeName, family, &doh_list, TRUE);
                    DNS_FreeIPEntryList(&doh_list);
                    Dll_Free(nameLwr);
                    *ppResult = pResult;
                    return 0;
                }
            }
            
            // DoH query failed or returned no records - return error instead of fallback
            DNS_FreeIPEntryList(&doh_list);
            GAI_LogPassthrough(L"GetAddrInfoW DoH (type passthrough)", pNodeName, family, L"no DoH records");
            Dll_Free(nameLwr);
            return WSAHOST_NOT_FOUND;
        }
        
        // DoH disabled - passthrough to system DNS
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
            WSA_SetInGetAddrInfoEx(TRUE);
            INT result = __sys_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                         hints, ppResult, timeout, lpOverlapped,
                                         lpCompletionRoutine, lpHandle);
            WSA_SetInGetAddrInfoEx(FALSE);
            return result;
        }
        return __sys_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                     hints, ppResult, timeout, lpOverlapped,
                                     lpCompletionRoutine, lpHandle);
    }

    // Use shared validation helper to check domain and find filter
    WCHAR* nameLwr = NULL;
    PVOID* aux = NULL;
    PATTERN* found = WSA_ValidateAndFindFilter(pName, &nameLwr, &aux);
    if (!found) {
        GAI_LogPassthrough(L"GetAddrInfoExW", pName, family, L"excluded or no filter match");
        if (nameLwr) Dll_Free(nameLwr);
        if (isAsync) {
            // Set re-entrancy flag to prevent WSALookupService from double-intercepting
            WSA_SetInGetAddrInfoEx(TRUE);
            INT result = __sys_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                         hints, ppResult, timeout, lpOverlapped,
                                         lpCompletionRoutine, lpHandle);
            WSA_SetInGetAddrInfoEx(FALSE);
            return result;
        }
        return __sys_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                     hints, ppResult, timeout, lpOverlapped,
                                     lpCompletionRoutine, lpHandle);
    }

    if (!nameLwr) {
        if (isAsync) {
            WSA_SetInGetAddrInfoEx(TRUE);
            INT result = __sys_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                         hints, ppResult, timeout, lpOverlapped,
                                         lpCompletionRoutine, lpHandle);
            WSA_SetInGetAddrInfoEx(FALSE);
            return result;
        }
        return __sys_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                     hints, ppResult, timeout, lpOverlapped,
                                     lpCompletionRoutine, lpHandle);
    }

    // --- Domain matches a filter, we handle it directly (sync or async) ---
    
    LIST* pEntries = NULL;
    DNS_TYPE_FILTER* type_filter = NULL;
    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);

    Dll_Free(nameLwr);

    // Determine query type from hints
    WORD wType = DNS_TYPE_A;  // Default to A
    if (hints) {
        if (hints->ai_family == AF_INET6)
            wType = DNS_TYPE_AAAA;
        else if (hints->ai_family == AF_UNSPEC)
            wType = DNS_TYPE_A;  // Will return both if available
    }

    // Check type filter (e.g., NetworkDnsFilter=example.com/A,AAAA)
    // If the requested type isn't allowed, try DoH first, then passthrough to system (async or sync)
    if (type_filter && !DNS_IsTypeInFilterList(type_filter, wType)) {
        // Try DoH for negated type passthrough queries
        PADDRINFOEXW pResultEx = NULL;
        if (DNS_DoHQueryForGetAddrInfoExW(pName, family, hints, pServiceName, &pResultEx)) {
            GAI_LogPassthrough(L"GetAddrInfoExW DoH (type passthrough)", pName, family, L"success");
            *ppResult = pResultEx;
            if (lpHandle) *lpHandle = NULL;
            return 0;
        }
        
        // DoH failed or disabled
        if (DoH_IsEnabled()) {
            // DoH enabled but failed - return error instead of fallback
            GAI_LogPassthrough(L"GetAddrInfoExW DoH (type passthrough)", pName, family, L"no DoH records");
            if (ppResult) *ppResult = NULL;
            if (lpHandle) *lpHandle = NULL;
            if (__sys_WSASetLastError)
                __sys_WSASetLastError(WSAHOST_NOT_FOUND);
            return WSAHOST_NOT_FOUND;
        }
        
        // DoH disabled - passthrough to system DNS
        GAI_LogPassthrough(L"GetAddrInfoExW", pName, family, L"type not in filter");
        if (isAsync) {
            WSA_SetInGetAddrInfoEx(TRUE);
            INT result = __sys_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId,
                                         hints, ppResult, timeout, lpOverlapped,
                                         lpCompletionRoutine, lpHandle);
            WSA_SetInGetAddrInfoEx(FALSE);
            return result;
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
// WSA_freeaddrinfo
//
// Hook for freeaddrinfo (ANSI) - frees ADDRINFOA structures
// FIX: Now uses HeapAlloc/HeapFree instead of LocalAlloc to match system allocator
//---------------------------------------------------------------------------

_FX VOID WSAAPI WSA_freeaddrinfo(PADDRINFOA pAddrInfo)
{
    if (!pAddrInfo) {
        if (__sys_freeaddrinfo)
            __sys_freeaddrinfo(pAddrInfo);
        return;
    }

    // Check for our magic marker using helper function
    // If not ours, pass to system free
    if (!DNS_IsOurAddrInfo(pAddrInfo->ai_flags)) {
        if (__sys_freeaddrinfo)
            __sys_freeaddrinfo(pAddrInfo);
        return;
    }

    // This is our allocation - free from our private heap
    // FIX: Use private heap to distinguish OUR allocations from system allocations
    HANDLE hHeap = DNS_GetFilterHeap();
    if (!hHeap) {
        // Private heap not initialized - pass to system
        if (__sys_freeaddrinfo)
            __sys_freeaddrinfo(pAddrInfo);
        return;
    }
    
    // CRITICAL: WSA_BuildAddrInfoList allocates everything in ONE block!
    // ADDRINFOW + sockaddr + canonname are all part of the same allocation
    // We must NOT try to free ai_addr or ai_canonname separately!
    
    BOOLEAN freedByUs = FALSE;
    
    // Free our allocations from private heap
    while (pAddrInfo) {
        PADDRINFOA pNext = pAddrInfo->ai_next;
        
        // Validate heap before freeing to catch corruption early
        // This prevents crashes in HeapFree if heap metadata is corrupted
        if (!HeapValidate(hHeap, 0, pAddrInfo)) {
            // Heap corruption detected - don't attempt to free
            // This could be double-free, buffer overflow, or use-after-free
            break;
        }
        
        // Just free the main block - ai_addr and ai_canonname are offsets within it!
        // DO NOT free embedded pointers separately - they're not separate allocations
        HeapFree(hHeap, 0, pAddrInfo);
        freedByUs = TRUE;
        pAddrInfo = pNext;
    }
}

//---------------------------------------------------------------------------
// WSA_FreeAddrInfoW
//
// Hook for FreeAddrInfoW - frees ADDRINFOW structures
// FIX: Uses private heap to distinguish our allocations from system allocations
//---------------------------------------------------------------------------

_FX VOID WSAAPI WSA_FreeAddrInfoW(PADDRINFOW pAddrInfo)
{
    if (!pAddrInfo) {
        if (__sys_FreeAddrInfoW)
            __sys_FreeAddrInfoW(pAddrInfo);
        return;
    }

    // Check for our magic marker using helper function
    // If not ours, pass to system free
    if (!DNS_IsOurAddrInfo(pAddrInfo->ai_flags)) {
        if (__sys_FreeAddrInfoW)
            __sys_FreeAddrInfoW(pAddrInfo);
        return;
    }

    // This is our allocation - free from our private heap
    // FIX: Use private heap to distinguish OUR allocations from system allocations
    HANDLE hHeap = DNS_GetFilterHeap();
    if (!hHeap) {
        // Private heap not initialized - pass to system
        if (__sys_FreeAddrInfoW)
            __sys_FreeAddrInfoW(pAddrInfo);
        return;
    }
    
    // CRITICAL: WSA_BuildAddrInfoList allocates everything in ONE block!
    // ADDRINFOW + sockaddr + canonname are all part of the same allocation
    // We must NOT try to free ai_addr or ai_canonname separately!
    
    BOOLEAN freedByUs = FALSE;
    
    // Free our allocations from private heap
    while (pAddrInfo) {
        PADDRINFOW pNext = pAddrInfo->ai_next;
        
        // Validate heap before freeing to catch corruption early
        // This prevents crashes in HeapFree if heap metadata is corrupted
        if (!HeapValidate(hHeap, 0, pAddrInfo)) {
            // Heap corruption detected - don't attempt to free
            // This could be double-free, buffer overflow, or use-after-free
            break;
        }
        
        // Just free the main block - ai_addr and ai_canonname are offsets within it!
        // DO NOT free embedded pointers separately - they're not separate allocations
        HeapFree(hHeap, 0, pAddrInfo);
        freedByUs = TRUE;
        pAddrInfo = pNext;
    }
}

//---------------------------------------------------------------------------
// WSA_FreeAddrInfoExW
//
// Hook for FreeAddrInfoExW - frees ADDRINFOEXW structures
// FIX: Uses private heap to distinguish our allocations from system allocations
//---------------------------------------------------------------------------

_FX VOID WSAAPI WSA_FreeAddrInfoExW(PADDRINFOEXW pAddrInfoEx)
{
    if (!pAddrInfoEx) {
        if (__sys_FreeAddrInfoExW)
            __sys_FreeAddrInfoExW(pAddrInfoEx);
        return;
    }

    // Check for our magic marker using helper function
    // If not ours, pass to system free
    if (!DNS_IsOurAddrInfo(pAddrInfoEx->ai_flags)) {
        if (__sys_FreeAddrInfoExW)
            __sys_FreeAddrInfoExW(pAddrInfoEx);
        return;
    }

    // This is our allocation - free from our private heap
    // FIX: Use private heap to distinguish OUR allocations from system allocations
    HANDLE hHeap = DNS_GetFilterHeap();
    if (!hHeap) {
        // Private heap not initialized - pass to system
        if (__sys_FreeAddrInfoExW)
            __sys_FreeAddrInfoExW(pAddrInfoEx);
        return;
    }
    
    // CRITICAL: Our implementation allocates everything in ONE block!
    // ADDRINFOEXW + sockaddr + canonname are all part of the same allocation
    // We must NOT try to free ai_addr or ai_canonname separately!
    
    BOOLEAN freedByUs = FALSE;
    
    // Free our allocations from private heap
    while (pAddrInfoEx) {
        PADDRINFOEXW pNext = pAddrInfoEx->ai_next;
        
        // Validate heap before freeing to catch corruption early
        // This prevents crashes in HeapFree if heap metadata is corrupted
        if (!HeapValidate(hHeap, 0, pAddrInfoEx)) {
            // Heap corruption detected - don't attempt to free
            // This could be double-free, buffer overflow, or use-after-free
            break;
        }
        
        // Just free the main block - ai_addr and ai_canonname are offsets within it!
        // DO NOT free embedded pointers separately - they're not separate allocations
        HeapFree(hHeap, 0, pAddrInfoEx);
        freedByUs = TRUE;
        pAddrInfoEx = pNext;
    }
}

//---------------------------------------------------------------------------
// DNS_Cleanup
//
// Cleanup DNS filter resources (called at DLL unload)
//---------------------------------------------------------------------------

_FX void DNS_Cleanup(void)
{
    DoH_Cleanup();
    
    // Destroy our private heap if it was created
    HANDLE hHeap = InterlockedExchangePointer(&g_DnsFilterHeap, NULL);
    if (hHeap) {
        HeapDestroy(hHeap);
    }
}
