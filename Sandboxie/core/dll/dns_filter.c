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
//      - Examples:
//        * NetworkDnsFilterType=*.example.com:A;AAAA  (filter only A/AAAA)
//        * NetworkDnsFilterType=*:*                   (filter all types)
//      - IMPORTANT: Unsupported types (MX, TXT, SRV, etc.) will be BLOCKED if 
//                   specified in the type list or when using wildcard (*).
//                   Only A and AAAA (or ANY) records can be synthesized from IP addresses.
//                   Don't set NetworkDnsFilterType if you don't want to block 
//                   unsupported record types.
//
//    NetworkDnsFilterExclude=<patterns>
//      - Exclusion/whitelist patterns (higher priority than NetworkDnsFilter)
//      - Format: [process,]pattern1;pattern2;... (semicolon-separated)
//      - Supports wildcards: *.example.com, safe.*.example.com
//      - Examples:
//        * NetworkDnsFilterExclude=*.microsoft.com;*.windows.net
//        * NetworkDnsFilterExclude=chrome.exe,*.google.com
//
//    FilterRawDns=y|n
//      - Boolean: Enable/disable raw socket DNS interception (default: n)
//      - Per-process support: FilterRawDns=nslookup.exe,y
//      - NOTE: Only controls hook enablement; actual domain filtering uses
//              NetworkDnsFilter patterns
//
//    DnsTrace=y|n
//      - Enable DNS filtering activity logging to resource monitor
//
//    DnsDebug=y|n
//      - Enable verbose debug logging for troubleshooting
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
#include "common/my_wsa.h"
#include "common/netfw.h"
#include "common/map.h"
#include "wsa_defs.h"
#include "dnsapi_defs.h"
#include "socket_hooks.h"
#include "dns_filter.h"
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

static VOID DNSAPI_DnsRecordListFree(
    PVOID           pRecordList,
    INT             FreeType);

static DNS_STATUS DNSAPI_DnsQuery_UTF8(
    PCSTR           pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNSAPI_DNS_RECORD* ppQueryResults,
    PVOID*          pReserved);

static DNS_STATUS DNSAPI_DnsQueryEx(
    PDNS_QUERY_REQUEST_W    pQueryRequest,
    PDNS_QUERY_RESULT       pQueryResults,
    PDNS_QUERY_CANCEL       pCancelHandle);

static DNS_STATUS DNSAPI_DnsQueryExW(
    PDNS_QUERY_REQUEST_W    pQueryRequest,
    PDNS_QUERY_RESULT       pQueryResults,
    PDNS_QUERY_CANCEL       pCancelHandle);

static DNS_STATUS DNSAPI_DnsQueryExA(
    PDNS_QUERY_REQUEST_A    pQueryRequest,
    PDNS_QUERY_RESULT       pQueryResults,
    PDNS_QUERY_CANCEL       pCancelHandle);

static DNS_STATUS DNSAPI_DnsQueryExUTF8(
    PDNS_QUERY_REQUEST_UTF8 pQueryRequest,
    PDNS_QUERY_RESULT       pQueryResults,
    PDNS_QUERY_CANCEL       pCancelHandle);

static DNS_STATUS DNSAPI_DnsQueryRaw(
    PDNS_QUERY_RAW_REQUEST  pRequest,
    PDNS_QUERY_RAW_CANCEL   pCancelHandle);

static DNS_STATUS DNSAPI_DnsQueryRawFilterAndRespond(
    PDNS_QUERY_RAW_REQUEST pRequest,
    const WCHAR* domainName,
    USHORT queryType,
    LIST* pEntries,
    DNS_TYPE_FILTER* type_filter,
    const BYTE* rawQuery,
    int rawQuerySize);

static PDNSAPI_DNS_RECORD DNSAPI_BuildDnsRecordList(
    const WCHAR*    domainName,
    WORD            wType,
    LIST*           pEntries,
    DNS_CHARSET     CharSet);

// DNS Type Filter Helper Functions (internal use only)
static BOOLEAN DNS_ParseTypeName(const WCHAR* name, USHORT* type_out);

// DNS Logging Helper Functions (internal use only)
static void DNS_LogDnsQueryResult(
    const WCHAR*            sourceTag,
    const WCHAR*            domain,
    WORD                    wType,
    DNS_STATUS              status,
    PDNSAPI_DNS_RECORD*     ppQueryResults);

// Shared utility functions (implemented in net.c)
BOOLEAN WSA_GetIP(const short* addr, int addrlen, IP_ADDRESS* pIP);
void WSA_DumpIP(ADDRESS_FAMILY af, IP_ADDRESS* pIP, wchar_t* pStr);

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

//---------------------------------------------------------------------------

// WSALookupService system function pointers
static P_WSALookupServiceBeginW __sys_WSALookupServiceBeginW = NULL;
static P_WSALookupServiceNextW __sys_WSALookupServiceNextW = NULL;
static P_WSALookupServiceEnd __sys_WSALookupServiceEnd = NULL;

// DnsApi system function pointers
static P_DnsQuery_A __sys_DnsQuery_A = NULL;
static P_DnsQuery_W __sys_DnsQuery_W = NULL;
static P_DnsRecordListFree __sys_DnsRecordListFree = NULL;
static P_DnsQuery_UTF8 __sys_DnsQuery_UTF8 = NULL;
static P_DnsQueryEx __sys_DnsQueryEx = NULL;
static P_DnsQueryExW __sys_DnsQueryExW = NULL;
static P_DnsQueryExA __sys_DnsQueryExA = NULL;
static P_DnsQueryExUTF8 __sys_DnsQueryExUTF8 = NULL;
static P_DnsQueryRaw __sys_DnsQueryRaw = NULL;
static P_DnsQueryRawResultFree __sys_DnsQueryRawResultFree = NULL;

// Windows version detection for DnsQueryEx workaround
// -1 = not checked, 0 = workaround not needed, 1 = workaround needed
static int DNS_NeedsDnsQueryExWorkaround = -1;

typedef struct _DNSAPI_EX_FILTER_RESULT {
    DNS_STATUS Status;
    BOOLEAN    IsAsync;
} DNSAPI_EX_FILTER_RESULT;

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

static BOOLEAN DNSAPI_HandleDnsQueryExRequestW(
    const WCHAR*             sourceTag,
    PDNS_QUERY_REQUEST_W     pQueryRequest,
    PDNS_QUERY_RESULT        pQueryResults,
    PDNS_QUERY_CANCEL        pCancelHandle,
    DNSAPI_EX_FILTER_RESULT* pOutcome);

static BOOLEAN DNSAPI_HandleDnsQueryExRequestMultiByte(
    const WCHAR*             sourceTag,
    PDNS_QUERY_REQUEST_A     pQueryRequest,
    PDNS_QUERY_RESULT        pQueryResults,
    PDNS_QUERY_CANCEL        pCancelHandle,
    UINT                     codePage,
    DNSAPI_EX_FILTER_RESULT* pOutcome);


//---------------------------------------------------------------------------
// Variables
//---------------------------------------------------------------------------

extern POOL* Dll_Pool;

// Shared DNS filter infrastructure (exported for socket_hooks.c)
LIST       DNS_FilterList;      // Shared by WSA, DNSAPI, and raw socket implementations
BOOLEAN    DNS_FilterEnabled = FALSE;
BOOLEAN    DNS_TraceFlag = FALSE;
BOOLEAN    DNS_DebugFlag = FALSE;  // Verbose debug logging (DnsDebug=y)


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
static void DNS_LogExclusionInit(const DNS_EXCLUSION_LIST* excl, const WCHAR* value);
static void DNS_ParseExclusionPatterns(DNS_EXCLUSION_LIST* excl, const WCHAR* value);
static BOOLEAN DNS_ListMatchesDomain(const DNS_EXCLUSION_LIST* excl, const WCHAR* domain);
static PATTERN* DNS_FindPatternInFilterList(const WCHAR* domain, ULONG level);
static BOOLEAN DNS_LoadFilterEntries(void);
static BOOLEAN WSA_IsIPv6Query(LPGUID lpServiceClassId);

// WSALookupService specific state tracking
typedef struct _WSA_LOOKUP {
    LIST* pEntries;          // THREAD SAFETY: Read-only after initialization; safe for concurrent reads
    BOOLEAN NoMore;
    WCHAR* DomainName;       // Request Domain
    GUID* ServiceClassId;    // Request Class ID
    DWORD Namespace;         // Request Namespace
    BOOLEAN Filtered;        // Filter flag
} WSA_LOOKUP;

static HASH_MAP   WSA_LookupMap;


//---------------------------------------------------------------------------
// DNS Logging Helpers
//---------------------------------------------------------------------------

// Log a simple DNS message with domain and type
static void DNS_LogSimple(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* suffix)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s: %s (Type: %s)%s%s",
        prefix, domain, DNS_GetTypeName(wType),
        suffix ? L" - " : L"",
        suffix ? suffix : L"");
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

// Log exclusion match (used in multiple places)
static void DNS_LogExclusion(const WCHAR* domain)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"DNS Exclusion: Domain '%s' matched exclusion list, skipping filter", domain);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

// Log DNS request with IP addresses (intercepted)
static void DNS_LogIntercepted(const WCHAR* prefix, const WCHAR* domain, WORD wType, LIST* pEntries)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    WCHAR msg[1024];
    Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s) - Using filtered response",
        prefix, domain, DNS_GetTypeName(wType));
    
    // Log IP addresses
    if (pEntries) {
        IP_ENTRY* entry = (IP_ENTRY*)List_Head(pEntries);
        while (entry) {
            WSA_DumpIP(entry->Type, &entry->IP, msg);
            entry = (IP_ENTRY*)List_Next(entry);
        }
    }
    
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
}

// Log DNS request blocked
static void DNS_LogBlocked(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* reason)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    WCHAR msg[1024];
    Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s) - %s",
        prefix, domain, DNS_GetTypeName(wType), reason);
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
}

// Log passthrough to real DNS
static void DNS_LogPassthrough(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* reason)
{
    DNS_LogSimple(prefix, domain, wType, reason);
}

// Log passthrough for ANSI domain names
static void DNS_LogPassthroughAnsi(const WCHAR* prefix, const CHAR* domainAnsi, WORD wType, const WCHAR* reason)
{
    if (!DNS_TraceFlag || !domainAnsi)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s: %S (Type: %s)%s%s",
        prefix, domainAnsi, DNS_GetTypeName(wType),
        reason ? L" - " : L"",
        reason ? reason : L"");
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

// Log DNS response from DNS_RECORD list (for DnsQuery_W)
static void DNS_LogDnsRecords(const WCHAR* prefix, const WCHAR* domain, WORD wType, PDNSAPI_DNS_RECORD pRecords)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    WCHAR msg[1024];
    Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s) - Using filtered response",
        prefix, domain, DNS_GetTypeName(wType));
    
    // Log IP addresses from DNS_RECORD
    PDNSAPI_DNS_RECORD pRec = pRecords;
    while (pRec) {
        IP_ADDRESS ip;
        if (pRec->wType == DNS_TYPE_AAAA) {
            memcpy(ip.Data, pRec->Data.AAAA.Ip6Address, 16);
            WSA_DumpIP(AF_INET6, &ip, msg);
        } else if (pRec->wType == DNS_TYPE_A) {
            ip.Data32[3] = pRec->Data.A.IpAddress;
            WSA_DumpIP(AF_INET, &ip, msg);
        }
        pRec = pRec->pNext;
    }
    
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
}

// Format GUID for logging (WSALookupService)
static void WSA_FormatGuid(LPGUID lpGuid, WCHAR* buffer, SIZE_T bufferSize)
{
    if (!lpGuid || !buffer || bufferSize < 64)
        return;
    
    Sbie_snwprintf(buffer, bufferSize, L" (ClsId: %08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX)",
        lpGuid->Data1, lpGuid->Data2, lpGuid->Data3,
        lpGuid->Data4[0], lpGuid->Data4[1], lpGuid->Data4[2], lpGuid->Data4[3],
        lpGuid->Data4[4], lpGuid->Data4[5], lpGuid->Data4[6], lpGuid->Data4[7]);
}

// Log WSALookupService intercepted request
static void WSA_LogIntercepted(const WCHAR* domain, LPGUID lpGuid, DWORD dwNameSpace, HANDLE handle)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    WCHAR ClsId[64] = { 0 };
    if (lpGuid)
        WSA_FormatGuid(lpGuid, ClsId, ARRAYSIZE(ClsId));
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"DNS Request Intercepted: %s%s (NS: %d, Type: %s, Hdl: %p) - Using filtered response",
        domain, ClsId, dwNameSpace,
        WSA_IsIPv6Query(lpGuid) ? L"IPv6" : L"IPv4", handle);
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
}

// Log WSALookupService passthrough request
static void WSA_LogPassthrough(const WCHAR* domain, LPGUID lpGuid, DWORD dwNameSpace, HANDLE handle, int errCode)
{
    if (!DNS_TraceFlag)
        return;
    
    WCHAR ClsId[64] = { 0 };
    if (lpGuid)
        WSA_FormatGuid(lpGuid, ClsId, ARRAYSIZE(ClsId));
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"DNS Request Begin: %s%s, NS: %d, Type: %s, Hdl: %p, Err: %d)",
        domain ? domain : L"Unnamed",
        ClsId, dwNameSpace, WSA_IsIPv6Query(lpGuid) ? L"IPv6" : L"IPv4",
        handle, errCode);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

//
// Debug logging helpers (conditional on DNS_DebugFlag)
//

// Generic debug logger
static void DNS_LogDebug(const WCHAR* message)
{
    if (!DNS_DebugFlag || !message)
        return;
    SbieApi_MonitorPutMsg(MONITOR_DNS, message);
}

// Format IPv4 address to string
static void DNS_FormatIPv4(WCHAR* buffer, size_t bufSize, const BYTE* ipData)
{
    Sbie_snwprintf(buffer, bufSize, L"%d.%d.%d.%d",
        ipData[12], ipData[13], ipData[14], ipData[15]);
}

// Log IP entry (IPv4 or IPv6) with indentation
static void DNS_LogIPEntry(const IP_ENTRY* entry)
{
    if (!DNS_DebugFlag || !entry)
        return;
    
    WCHAR msg[128];
    if (entry->Type == AF_INET) {
        WCHAR ipStr[64];
        DNS_FormatIPv4(ipStr, 64, entry->IP.Data);
        Sbie_snwprintf(msg, 128, L"  Entry: Type=IPv4, IP=%s", ipStr);
    } else {
        Sbie_snwprintf(msg, 128, L"  Entry: Type=IPv6");
    }
    DNS_LogDebug(msg);
}

// Log WSA fill response structure call
static void DNS_LogWSAFillStart(BOOLEAN isIPv6, SIZE_T ipCount, void* listHead)
{
    if (!DNS_DebugFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"WSA_FillResponseStructure: isIPv6=%d, ipCount=%Iu, listHead=%p",
        isIPv6, ipCount, listHead);
    DNS_LogDebug(msg);
}

// Log WSALookupServiceNextW call parameters
static void DNS_LogWSALookupCall(HANDLE hLookup, DWORD bufSize, BOOLEAN noMore, void* pEntries)
{
    if (!DNS_DebugFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"WSALookupServiceNextW called: Hdl=%p, BufferSize=%d, NoMore=%d, pEntries=%p",
        hLookup, bufSize, noMore, pEntries);
    DNS_LogDebug(msg);
}

// Log WSA fill response structure failure
static void DNS_LogWSAFillFailure(HANDLE hLookup, DWORD error, DWORD bufSize)
{
    if (!DNS_DebugFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"WSA_FillResponseStructure FAILED: Hdl=%p, Error=%d (0x%X), BufferSize=%d",
        hLookup, error, error, bufSize);
    DNS_LogDebug(msg);
}

// Log DnsQueryEx structure pointers
static void DNS_LogQueryExPointers(const WCHAR* funcName, void* pQueryRequest, void* pQueryResults, DWORD version, void* queryName)
{
    if (!DNS_DebugFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s: pQueryRequest=%p, pQueryResults=%p, Version=%d, QueryName=%p",
        funcName, pQueryRequest, pQueryResults, version, queryName);
    DNS_LogDebug(msg);
}

// Log WSALookupService type filter passthrough
static void WSA_LogTypeFilterPassthrough(const WCHAR* domain, USHORT query_type)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"WSALookupService Passthrough: %s (Type: %s) - Type not in filter list, forwarding to real DNS",
        domain, query_type == DNS_TYPE_AAAA ? L"AAAA" : L"A");
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
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
// WSA_GetLookup
//---------------------------------------------------------------------------


_FX WSA_LOOKUP* WSA_GetLookup(HANDLE h, BOOLEAN bCanAdd)
{
    WSA_LOOKUP* pLookup = (WSA_LOOKUP*)map_get(&WSA_LookupMap, h);
    if (pLookup == NULL && bCanAdd) {
        pLookup = (WSA_LOOKUP*)map_insert(&WSA_LookupMap, h, NULL, sizeof(WSA_LOOKUP));
        if (pLookup) {
            pLookup->pEntries = NULL;
            pLookup->NoMore = FALSE;
            pLookup->DomainName = NULL;
            pLookup->ServiceClassId = NULL;
            pLookup->Filtered = FALSE;
        }
    }
    return pLookup;
}

//---------------------------------------------------------------------------
// WSA_IsIPv6Query
//---------------------------------------------------------------------------

_FX BOOLEAN WSA_IsIPv6Query(LPGUID lpServiceClassId)
{
    if (lpServiceClassId) {
        if (memcmp(lpServiceClassId, &(GUID)SVCID_DNS_TYPE_AAAA, sizeof(GUID)) == 0) {
            return TRUE;
        }
    }
    return FALSE;
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

    WCHAR wsDebugOptions[4] = { 0 };
    if (SbieApi_QueryConf(NULL, L"DnsDebug", 0, wsDebugOptions, sizeof(wsDebugOptions)) == STATUS_SUCCESS && wsDebugOptions[0] != L'\0') {
        DNS_DebugFlag = Config_String2Bool(wsDebugOptions, FALSE);
        DNS_DebugExclusionLogs = DNS_DebugFlag;  // Enable exclusion logs when debug is on
    }
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

static void DNS_LogExclusionInit(const DNS_EXCLUSION_LIST* excl, const WCHAR* value)
{
    if (!value || !DNS_TraceFlag || !DNS_DebugExclusionLogs)
        return;

    WCHAR msg[512];
    if (excl->image_name)
        Sbie_snwprintf(msg, 512, L"DNS Exclusion Init: Image='%s', Patterns='%s'", excl->image_name, value);
    else
        Sbie_snwprintf(msg, 512, L"DNS Exclusion Init: Global, Patterns='%s'", value);

    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
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

        DNS_LogExclusionInit(excl, value);
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

            if (!HasV6) {

                //
                // When there are no IPv6 entries, create IPv4-mapped IPv6 addresses
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

                    // IPv4-mapped IPv6 address: first 80 bits zero, next 16 bits 0xFFFF, then IPv4 address
                    memset(entry6->IP.Data, 0, 10);
                    entry6->IP.Data[10] = 0xFF;
                    entry6->IP.Data[11] = 0xFF;
                    memcpy(&entry6->IP.Data[12], &entry->IP.Data32[3], 4);

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
                if (DNS_TraceFlag) {
                    WCHAR msg[512];
                    Sbie_snwprintf(msg, 512, L"NetworkDnsFilterType: No matching NetworkDnsFilter for domain='%s', ignoring", domain);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
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
        BOOLEAN has_wildcard = FALSE;

        while (type_ptr && *type_ptr && type_count < MAX_DNS_TYPE_FILTERS - 1) {
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
                // Check for wildcard
                if (wcscmp(type_ptr, L"*") == 0) {
                    has_wildcard = TRUE;
                    if (DNS_TraceFlag) {
                        WCHAR msg[512];
                        Sbie_snwprintf(msg, 512, L"NetworkDnsFilterType: Wildcard '*' found for domain '%s' - will filter ALL types", domain);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                    }
                } else {
                    USHORT type_val = 0;
                    if (DNS_ParseTypeName(type_ptr, &type_val)) {
                        type_filter->allowed_types[type_count++] = type_val;
                    } else {
                        if (DNS_TraceFlag) {
                            WCHAR msg[512];
                            Sbie_snwprintf(msg, 512, L"NetworkDnsFilterType: Invalid type name '%s' for domain '%s'", type_ptr, domain);
                            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                        }
                    }
                }
            }

            type_ptr = semicolon ? semicolon + 1 : NULL;
        }

        type_filter->type_count = type_count;
        type_filter->has_wildcard = has_wildcard;
        type_filter->allowed_types[type_count] = 0;  // Null terminator

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
            
            if (DNS_TraceFlag) {
                WCHAR msg[512];
                if (has_wildcard) {
                    Sbie_snwprintf(msg, 512, L"NetworkDnsFilterType: Domain='%s' types=[* (wildcard - all types)] applied to %d patterns",
                        domain, applied_count);
                } else {
                    WCHAR types_str[256] = L"";
                    for (USHORT i = 0; i < type_count && i < 10; i++) {
                        WCHAR type_buf[32];
                        Sbie_snwprintf(type_buf, 32, L"%s%s", 
                            i > 0 ? L";" : L"",
                            DNS_GetTypeName(type_filter->allowed_types[i]));
                        wcscat(types_str, type_buf);
                    }
                    Sbie_snwprintf(msg, 512, L"NetworkDnsFilterType: Domain='%s' types=[%s] (%d types) applied to %d patterns",
                        domain, types_str, type_count, applied_count);
                }
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            
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

                if (DNS_TraceFlag) {
                    WCHAR msg[512];
                    if (has_wildcard) {
                        Sbie_snwprintf(msg, 512, L"NetworkDnsFilterType: Domain='%s' types=[* (wildcard - all types)]",
                            domain);
                    } else {
                        WCHAR types_str[256] = L"";
                        for (USHORT i = 0; i < type_count && i < 10; i++) {
                            WCHAR type_buf[32];
                            Sbie_snwprintf(type_buf, 32, L"%s%s", 
                                i > 0 ? L";" : L"",
                                DNS_GetTypeName(type_filter->allowed_types[i]));
                            wcscat(types_str, type_buf);
                        }
                        Sbie_snwprintf(msg, 512, L"NetworkDnsFilterType: Domain='%s' types=[%s] (%d types)",
                            domain, types_str, type_count);
                    }
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
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
    DNS_LoadExclusionRules();

    if (DNS_FilterList.count > 0)
        return;

    List_Init(&DNS_FilterList);
    DNS_LoadFilterEntries();
    
    // Load type filters (must be done after LoadFilterEntries)
    DNS_LoadTypeFilterEntries();

    if (DNS_FilterList.count > 0) {

        DNS_FilterEnabled = TRUE;

        map_init(&WSA_LookupMap, Dll_Pool);

        __declspec(align(8)) SCertInfo CertInfo = { 0 };
        if (!NT_SUCCESS(SbieApi_QueryDrvInfo(-1, &CertInfo, sizeof(CertInfo))) || !(CertInfo.active && CertInfo.opt_net)) {

            const WCHAR* strings[] = { L"NetworkDnsFilter" , NULL };
            SbieApi_LogMsgExt(-1, 6009, strings);

            DNS_FilterEnabled = FALSE;
        }
    }

    // If there are any DnsTrace options set, then output this debug string
    WCHAR wsTraceOptions[4];
    if (SbieApi_QueryConf(NULL, L"DnsTrace", 0, wsTraceOptions, sizeof(wsTraceOptions)) == STATUS_SUCCESS && wsTraceOptions[0] != L'\0') {
        DNS_TraceFlag = TRUE;
        // Enable DNS filtering infrastructure even without filter rules to allow logging
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
        case DNS_TYPE_TXT:   return L"TXT";
        case DNS_TYPE_AAAA:  return L"AAAA";
        case DNS_TYPE_SRV:   return L"SRV";
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

//---------------------------------------------------------------------------
// DNS_ParseTypeName
//
// Parses a DNS type name (e.g., "A", "AAAA", "CNAME") or numeric format (e.g., "TYPE28")
// Returns TRUE if parsed successfully, FALSE otherwise
//---------------------------------------------------------------------------

static BOOLEAN DNS_ParseTypeName(const WCHAR* name, USHORT* type_out)
{
    if (!name || !type_out)
        return FALSE;

    // Try named types first
    if (_wcsicmp(name, L"A") == 0)           { *type_out = DNS_TYPE_A; return TRUE; }
    if (_wcsicmp(name, L"NS") == 0)          { *type_out = DNS_TYPE_NS; return TRUE; }
    if (_wcsicmp(name, L"CNAME") == 0)       { *type_out = DNS_TYPE_CNAME; return TRUE; }
    if (_wcsicmp(name, L"SOA") == 0)         { *type_out = DNS_TYPE_SOA; return TRUE; }
    if (_wcsicmp(name, L"PTR") == 0)         { *type_out = DNS_TYPE_PTR; return TRUE; }
    if (_wcsicmp(name, L"MX") == 0)          { *type_out = DNS_TYPE_MX; return TRUE; }
    if (_wcsicmp(name, L"TXT") == 0)         { *type_out = DNS_TYPE_TXT; return TRUE; }
    if (_wcsicmp(name, L"AAAA") == 0)        { *type_out = DNS_TYPE_AAAA; return TRUE; }
    if (_wcsicmp(name, L"SRV") == 0)         { *type_out = DNS_TYPE_SRV; return TRUE; }
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
// DNS_IsTypeInFilterList
//
// Checks if a DNS type should be filtered based on the type filter
// Returns TRUE if type should be filtered, FALSE if it should pass through
//
// Logic:
// - If type_filter is NULL: Use default (filter A/AAAA/ANY only)
// - If type_filter has wildcard: Filter ALL types
// - If type_filter is set: Filter only types in the allowed_types array
//---------------------------------------------------------------------------

BOOLEAN DNS_IsTypeInFilterList(const DNS_TYPE_FILTER* type_filter, USHORT query_type)
{
    // No type filter specified - use default behavior (filter A/AAAA/ANY)
    if (!type_filter) {
        return (query_type == DNS_TYPE_A || query_type == DNS_TYPE_AAAA || query_type == 255);
    }

    // Wildcard specified - filter ALL types
    if (type_filter->has_wildcard) {
        return TRUE;
    }

    // Check if query type is in the allowed types list
    for (USHORT i = 0; i < type_filter->type_count && i < MAX_DNS_TYPE_FILTERS; i++) {
        if (type_filter->allowed_types[i] == query_type) {
            return TRUE;  // Type is in filter list - should be filtered
        }
    }

    return FALSE;  // Type not in list - pass through to real DNS
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

    if (DNS_DebugExclusionLogs && DNS_TraceFlag) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"DNS_IsExcluded: Checking domain='%s', image='%s', ExclusionListCount=%d",
            domain, image ? image : L"(null)", DNS_ExclusionListCount);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    if (image) {
        for (ULONG i = 0; i < DNS_ExclusionListCount; ++i) {
            DNS_EXCLUSION_LIST* excl = &DNS_ExclusionLists[i];
            if (!excl->image_name)
                continue;
            if (_wcsicmp(excl->image_name, image) != 0)
                continue;

            if (DNS_DebugExclusionLogs && DNS_TraceFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"DNS_IsExcluded: Checking per-image list for '%s' (%d patterns)",
                    excl->image_name, excl->count);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }

            if (DNS_ListMatchesDomain(excl, domain))
                return TRUE;
        }
    }

    for (ULONG i = 0; i < DNS_ExclusionListCount; ++i) {
        DNS_EXCLUSION_LIST* excl = &DNS_ExclusionLists[i];
        if (excl->image_name)
            continue;

        if (DNS_DebugExclusionLogs && DNS_TraceFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"DNS_IsExcluded: Checking global list (%d patterns)", excl->count);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }

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

        if (DNS_DebugExclusionLogs && DNS_TraceFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"DNS_IsExcluded: Testing pattern[%d]='%s'", j, pattern);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }

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
        if (DNS_DebugExclusionLogs && DNS_TraceFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"DNS_IsExcluded: MATCH! Domain='%s' matched pattern='%s'",
                domain, Pattern_Source(found));
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        return TRUE;
    }

    return FALSE;
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
    //
    Socket_InitHooks(module);

    return TRUE;
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

    //
    // Setup DnsApi hooks (dnsapi.dll)
    //

    P_DnsQuery_A DnsQuery_A = (P_DnsQuery_A)GetProcAddress(module, "DnsQuery_A");
    if (DnsQuery_A) {
        SBIEDLL_HOOK(DNSAPI_, DnsQuery_A);
    }

    P_DnsQuery_W DnsQuery_W = (P_DnsQuery_W)GetProcAddress(module, "DnsQuery_W");
    if (DnsQuery_W) {
        SBIEDLL_HOOK(DNSAPI_, DnsQuery_W);
    }

    P_DnsRecordListFree DnsRecordListFree = (P_DnsRecordListFree)GetProcAddress(module, "DnsRecordListFree");
    if (DnsRecordListFree) {
        SBIEDLL_HOOK(DNSAPI_, DnsRecordListFree);
    }

    P_DnsQuery_UTF8 DnsQuery_UTF8 = (P_DnsQuery_UTF8)GetProcAddress(module, "DnsQuery_UTF8");
    if (DnsQuery_UTF8) {
        SBIEDLL_HOOK(DNSAPI_, DnsQuery_UTF8);
    }

    P_DnsQueryEx pDnsQueryEx = (P_DnsQueryEx)GetProcAddress(module, "DnsQueryEx");
    if (pDnsQueryEx) {
        *(ULONG_PTR*)&__sys_DnsQueryEx = (ULONG_PTR)
            SbieDll_Hook("DnsQueryEx", (void*)pDnsQueryEx, DNSAPI_DnsQueryEx, module);
        if (!__sys_DnsQueryEx)
            return FALSE;
    }

    P_DnsQueryExW pDnsQueryExW = (P_DnsQueryExW)GetProcAddress(module, "DnsQueryExW");
    if (pDnsQueryExW && (!pDnsQueryEx || pDnsQueryExW != pDnsQueryEx)) {
        *(ULONG_PTR*)&__sys_DnsQueryExW = (ULONG_PTR)
            SbieDll_Hook("DnsQueryExW", (void*)pDnsQueryExW, DNSAPI_DnsQueryExW, module);
        if (!__sys_DnsQueryExW)
            return FALSE;
    }

    P_DnsQueryExA pDnsQueryExA = (P_DnsQueryExA)GetProcAddress(module, "DnsQueryExA");
    if (pDnsQueryExA) {
        *(ULONG_PTR*)&__sys_DnsQueryExA = (ULONG_PTR)
            SbieDll_Hook("DnsQueryExA", (void*)pDnsQueryExA, DNSAPI_DnsQueryExA, module);
        if (!__sys_DnsQueryExA)
            return FALSE;
    }

    P_DnsQueryExUTF8 pDnsQueryExUTF8 = (P_DnsQueryExUTF8)GetProcAddress(module, "DnsQueryExUTF8");
    if (pDnsQueryExUTF8) {
        *(ULONG_PTR*)&__sys_DnsQueryExUTF8 = (ULONG_PTR)
            SbieDll_Hook("DnsQueryExUTF8", (void*)pDnsQueryExUTF8, DNSAPI_DnsQueryExUTF8, module);
        if (!__sys_DnsQueryExUTF8)
            return FALSE;
    }

    P_DnsQueryRaw pDnsQueryRaw = (P_DnsQueryRaw)GetProcAddress(module, "DnsQueryRaw");
    if (pDnsQueryRaw) {
        *(ULONG_PTR*)&__sys_DnsQueryRaw = (ULONG_PTR)
            SbieDll_Hook("DnsQueryRaw", (void*)pDnsQueryRaw, DNSAPI_DnsQueryRaw, module);
        if (!__sys_DnsQueryRaw)
            return FALSE;
    }

    P_DnsQueryRawResultFree pDnsQueryRawResultFree = (P_DnsQueryRawResultFree)GetProcAddress(module, "DnsQueryRawResultFree");
    if (pDnsQueryRawResultFree) {
        *(ULONG_PTR*)&__sys_DnsQueryRawResultFree = (ULONG_PTR)pDnsQueryRawResultFree;
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
            HANDLE fakeHandle = (HANDLE)Dll_Alloc(sizeof(ULONG_PTR));
            if (!fakeHandle) {
                Dll_Free(path_lwr);
                SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                return SOCKET_ERROR;
            }

            *lphLookup = fakeHandle;

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
                    LIST* pEntries = NULL;
                    DNS_TYPE_FILTER* type_filter = NULL;
                    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);
                    
                    // Determine query type from Service Class ID GUID
                    USHORT query_type = WSA_IsIPv6Query(lpqsRestrictions->lpServiceClassId) 
                        ? DNS_TYPE_AAAA 
                        : DNS_TYPE_A;
                    
                    // Block mode (no IPs) should block ALL query types
                    if (!pEntries) {
                        // In block mode, block everything (set NoMore to trigger error)
                        pLookup->NoMore = TRUE;
                        pLookup->pEntries = NULL;
                    } else {
                        // Filter mode (with IPs) - check if this type should be filtered
                        BOOLEAN should_filter = DNS_IsTypeInFilterList(type_filter, query_type);
                        
                        if (!should_filter) {
                            // Type not in filter list - pass through to real DNS
                            WSA_LogTypeFilterPassthrough(lpqsRestrictions->lpszServiceInstanceName, query_type);
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

            WSA_LogIntercepted(lpqsRestrictions->lpszServiceInstanceName,
                lpqsRestrictions->lpServiceClassId,
                lpqsRestrictions->dwNameSpace,
                fakeHandle);

            Dll_Free(path_lwr);
            return NO_ERROR;
        }

        Dll_Free(path_lwr);
    }

    int ret = __sys_WSALookupServiceBeginW(lpqsRestrictions, dwControlFlags, lphLookup);

    if (lpqsRestrictions) {
        WSA_LogPassthrough(
            lpqsRestrictions->lpszServiceInstanceName,
            lpqsRestrictions->lpServiceClassId,
            lpqsRestrictions->dwNameSpace,
            lphLookup ? *lphLookup : NULL,
            ret == SOCKET_ERROR ? GetLastError() : 0);
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

                if (DNS_TraceFlag) {
                    WCHAR msg[2048];
                    Sbie_snwprintf(msg, ARRAYSIZE(msg), L"DNS Filtered Response: %s (NS: %d, Type: %s, Hdl: %p, AddrCount: %d, BlobSize: %d)",
                        pLookup->DomainName, lpqsResults->dwNameSpace,
                        WSA_IsIPv6Query(pLookup->ServiceClassId) ? L"IPv6" : L"IPv4", hLookup,
                        lpqsResults->dwNumberOfCsAddrs,
                        lpqsResults->lpBlob ? lpqsResults->lpBlob->cbSize : 0);

                    for (DWORD i = 0; i < lpqsResults->dwNumberOfCsAddrs; i++) {
                        IP_ADDRESS ip;
                        if (lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr &&
                            WSA_GetIP(lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr,
                                lpqsResults->lpcsaBuffer[i].RemoteAddr.iSockaddrLength, &ip))
                            WSA_DumpIP(lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr->sa_family, &ip, msg);
                    }

                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }

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
        WCHAR msg[2048];
        // Use original query type from pLookup (if available), not from result structure
        // Result structure may have different ServiceClassId if DNS returns partial results
        USHORT query_type;
        if (pLookup && pLookup->ServiceClassId) {
            query_type = WSA_IsIPv6Query(pLookup->ServiceClassId) ? DNS_TYPE_AAAA : DNS_TYPE_A;
        } else {
            query_type = WSA_IsIPv6Query(lpqsResults->lpServiceClassId) ? DNS_TYPE_AAAA : DNS_TYPE_A;
        }
        Sbie_snwprintf(msg, ARRAYSIZE(msg), L"DNS Request Found: %s (Type: %s, NS: %d, Hdl: %p)",
            lpqsResults->lpszServiceInstanceName, DNS_GetTypeName(query_type), lpqsResults->dwNameSpace, hLookup);

        for (DWORD i = 0; i < lpqsResults->dwNumberOfCsAddrs; i++) {
            IP_ADDRESS ip;
            if (lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr &&
                WSA_GetIP(lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr, 
                    lpqsResults->lpcsaBuffer[i].RemoteAddr.iSockaddrLength, &ip))
                WSA_DumpIP(lpqsResults->lpcsaBuffer[i].RemoteAddr.lpSockaddr->sa_family, &ip, msg);
        }

        if (lpqsResults->lpBlob != NULL) {

            HOSTENT* hp = (HOSTENT*)lpqsResults->lpBlob->pBlobData;
            if (hp->h_addrtype != AF_INET6 && hp->h_addrtype != AF_INET) {
                WSA_DumpIP(hp->h_addrtype, NULL, msg);
            }
            else if (hp->h_addr_list) {
                // Convert relative pointer to absolute using ABS_PTR helper
                // Extract offset from pointer-typed field (stored as offset value, not real pointer)
                uintptr_t addrListOffset = GET_REL_FROM_PTR(hp->h_addr_list);
                PCHAR* addrArray = (PCHAR*)ABS_PTR(hp, addrListOffset);
                
                for (PCHAR* Addr = addrArray; *Addr; Addr++) {

                    // Convert relative offset to absolute pointer (extract offset, then convert)
                    uintptr_t ipOffset = GET_REL_FROM_PTR(*Addr);
                    PCHAR ptr = (PCHAR)ABS_PTR(hp, ipOffset);

                    IP_ADDRESS ip;
                    if (hp->h_addrtype == AF_INET6)
                        memcpy(ip.Data, ptr, 16);
                    else if (hp->h_addrtype == AF_INET)
                        ip.Data32[3] = *(DWORD*)ptr;
                    WSA_DumpIP(hp->h_addrtype, &ip, msg);
                }
            }
        }

        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
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

            if (DNS_TraceFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"DNS Filtered Request End (Hdl: %p)", hLookup);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }

            return NO_ERROR;
        }

        map_remove(&WSA_LookupMap, hLookup);
    }

    if (DNS_TraceFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"DNS Request End (Hdl: %p)", hLookup);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

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
        if (DNS_TraceFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, ARRAYSIZE(msg), L"%s Exclusion: Domain '%s' matched exclusion list, skipping filter", sourceTag, path_lwr);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
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
            // Type not in filter list - pass to real DNS
            DNS_LogPassthrough(sourceTag, pszName, wType, L"Type not in filter list, forwarding to real DNS");
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
    } else {
        // Block mode OR unsupported type (MX/CNAME/TXT/etc.): return NXDOMAIN
        status = DNS_ERROR_RCODE_NAME_ERROR;
    }

    if (pQueryResults->Version == 0)
        pQueryResults->Version = DNS_QUERY_RESULTS_VERSION1;
    pQueryResults->QueryOptions = queryOptions;
    pQueryResults->pQueryRecords = pRecords;
    pQueryResults->Reserved = NULL;
    pQueryResults->QueryStatus = status;

    if (pCancelHandle)
        ZeroMemory(pCancelHandle, sizeof(DNS_QUERY_CANCEL));

    if (DNS_TraceFlag) {
        WCHAR msg[1024];
        if (status == 0 && pRecords) {
            Sbie_snwprintf(msg, ARRAYSIZE(msg), L"%s Intercepted: %s (Type: %s) - Using filtered response",
                sourceTag, pszName, DNS_GetTypeName(wType));

            PDNSAPI_DNS_RECORD pRec = pRecords;
            while (pRec) {
                if (pRec->wType == DNS_TYPE_A || pRec->wType == DNS_TYPE_AAAA) {
                    IP_ADDRESS ip;
                    if (pRec->wType == DNS_TYPE_AAAA) {
                        memcpy(ip.Data, pRec->Data.AAAA.Ip6Address, 16);
                    } else {
                        ip.Data32[3] = pRec->Data.A.IpAddress;
                    }
                    WSA_DumpIP((pRec->wType == DNS_TYPE_AAAA) ? AF_INET6 : AF_INET, &ip, msg);
                }
                pRec = pRec->pNext;
            }

            SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
        }
        else {
            Sbie_snwprintf(msg, ARRAYSIZE(msg), L"%s Blocked: %s (Type: %s) - Returning NXDOMAIN",
                sourceTag, pszName, DNS_GetTypeName(wType));
            SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
        }
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
// DNS_CheckIfDnsQueryExWorkaroundNeeded
//
// Detects if current Windows version needs the DnsQueryEx synchronous bug workaround.
// Bug exists in: Windows 10 all builds, Server 2016 (1607), Server 2019 (1809)
// Bug fixed in: Windows 11 (22000+), Server 2022 (20348+)
//
// Returns: TRUE if workaround needed, FALSE if OS has fix
//---------------------------------------------------------------------------

static BOOLEAN DNS_CheckIfDnsQueryExWorkaroundNeeded(void)
{
    // Check cache first
    if (DNS_NeedsDnsQueryExWorkaround >= 0) {
        return (DNS_NeedsDnsQueryExWorkaround == 1);
    }

    // Get Windows version (RtlGetVersion always returns real version, unlike GetVersionEx)
    typedef LONG (WINAPI *P_RtlGetVersion)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        DNS_NeedsDnsQueryExWorkaround = 1;  // Assume workaround needed if can't detect
        return TRUE;
    }

    P_RtlGetVersion pRtlGetVersion = (P_RtlGetVersion)GetProcAddress(ntdll, "RtlGetVersion");
    if (!pRtlGetVersion) {
        DNS_NeedsDnsQueryExWorkaround = 1;  // Assume workaround needed if can't detect
        return TRUE;
    }

    RTL_OSVERSIONINFOW osvi;
    ZeroMemory(&osvi, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    
    if (pRtlGetVersion(&osvi) != 0) {
        DNS_NeedsDnsQueryExWorkaround = 1;  // Assume workaround needed if can't detect
        return TRUE;
    }

    // Windows 11 is version 10.0 build 22000+
    // Server 2022 is version 10.0 build 20348+
    // Windows 10 is version 10.0 build < 22000
    // Server 2016/2019 are version 10.0 build < 20348
    
    if (osvi.dwMajorVersion > 10) {
        // Future Windows versions (12+) - assume bug is fixed
        DNS_NeedsDnsQueryExWorkaround = 0;
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"DnsQueryEx workaround: Not needed (Windows %d.%d build %d)",
                osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
            DNS_LogDebug(msg);
        }
        return FALSE;
    }
    
    if (osvi.dwMajorVersion == 10 && osvi.dwMinorVersion == 0) {
        // Windows 11 (22000+) or Server 2022 (20348+) have the fix
        if (osvi.dwBuildNumber >= 22000 || osvi.dwBuildNumber >= 20348) {
            DNS_NeedsDnsQueryExWorkaround = 0;
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"DnsQueryEx workaround: Not needed (Windows 10.0 build %d - bug fixed)",
                    osvi.dwBuildNumber);
                DNS_LogDebug(msg);
            }
            return FALSE;
        }
        
        // Windows 10 or Server 2016/2019 - needs workaround
        DNS_NeedsDnsQueryExWorkaround = 1;
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"DnsQueryEx workaround: NEEDED (Windows 10.0 build %d - has bug)",
                osvi.dwBuildNumber);
            DNS_LogDebug(msg);
        }
        return TRUE;
    }
    
    // Older Windows (Vista, 7, 8, 8.1) - DnsQueryEx might not exist or behave differently
    // Apply workaround to be safe
    DNS_NeedsDnsQueryExWorkaround = 1;
    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"DnsQueryEx workaround: NEEDED (Windows %d.%d build %d - legacy OS)",
            osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
        DNS_LogDebug(msg);
    }
    return TRUE;
}

//---------------------------------------------------------------------------
// DNSAPI_ApplyWindows10DnsQueryExWorkaround
//
// Workaround for Windows 10 DnsQueryEx bug where queries without callbacks
// can return ERROR_IO_PENDING instead of completing synchronously, leaving
// async operations that crash when accessing freed stack memory.
// See: https://dblohm7.ca/blog/2022/05/06/dnsqueryex-needs-love/
//
// This function uses DnsQuery_W synchronously instead, which doesn't have
// the bug. Only called on Windows versions with the bug (Win10, Server 2016/2019).
//---------------------------------------------------------------------------

static BOOLEAN DNSAPI_ApplyWindows10DnsQueryExWorkaround(
    const WCHAR*             sourceTag,
    const WCHAR*             queryName,
    WORD                     queryType,
    ULONG64                  queryOptions,
    PDNS_QUERY_RESULT        pQueryResults,
    PDNS_QUERY_CANCEL        pCancelHandle,
    DNSAPI_EX_FILTER_RESULT* pOutcome)
{
    // Validate parameters
    if (!queryName || !pQueryResults) {
        return FALSE;
    }
    
    // Check if DnsQuery_W is available
    if (!__sys_DnsQuery_W) {
        return FALSE;  // Can't apply workaround, let caller use real DnsQueryEx
    }
    
    // Calculate masked options first (before debug logging)
    // Mask = 0x007E3FFF = bits 0-13 (standard flags) + bits 17-22 (multicast/encoding flags)
    DWORD dwOptions = (DWORD)(queryOptions & 0x007E3FFF);
    
    if (DNS_DebugFlag) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"%s: No callback provided, using DnsQuery_W to avoid Windows 10 bug", sourceTag);
        DNS_LogDebug(msg);
        Sbie_snwprintf(msg, 512, L"%s: queryOptions=0x%I64X, dwOptions=0x%08X, queryType=%d", 
            sourceTag, queryOptions, dwOptions, queryType);
        DNS_LogDebug(msg);
    }
    
    // Call DnsQuery_W synchronously (this always works correctly)
    // Note: DnsQuery_W uses DWORD for options, DnsQueryEx uses ULONG64
    // DnsQuery_W only supports a subset of options - unsupported options cause Error 87
    //
    // Analysis from logs: queryOptions like 0x800040006000 contain:
    //   High 32 bits (0x80004000xxxx): DnsQueryEx-specific extended flags (DoH/DoT/Async)
    //   Low 32 bits (0x00006000/0x26000): Mixed legacy + DnsQueryEx-specific flags
    //   Example: 0x6000 = DUAL_ADDR (0x4000) | ADDRCONFIG (0x2000)
    //
    // Flags shared by DnsQuery and DnsQueryEx (safe to pass - per Microsoft docs):
    // 0x00000001 DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE
    // 0x00000002 DNS_QUERY_USE_TCP_ONLY
    // 0x00000004 DNS_QUERY_NO_RECURSION
    // 0x00000008 DNS_QUERY_BYPASS_CACHE
    // 0x00000010 DNS_QUERY_NO_WIRE_QUERY
    // 0x00000020 DNS_QUERY_NO_LOCAL_NAME
    // 0x00000040 DNS_QUERY_NO_HOSTS_FILE
    // 0x00000080 DNS_QUERY_NO_NETBT
    // 0x00000100 DNS_QUERY_WIRE_ONLY
    // 0x00000200 DNS_QUERY_RETURN_MESSAGE
    // 0x00000400 DNS_QUERY_MULTICAST_ONLY (Vista+)
    // 0x00000800 DNS_QUERY_NO_MULTICAST
    // 0x00001000 DNS_QUERY_TREAT_AS_FQDN
    // 0x00002000 DNS_QUERY_ADDRCONFIG (Win7+)
    // 0x00020000 DNS_QUERY_MULTICAST_WAIT (Vista+)
    // 0x00040000 DNS_QUERY_MULTICAST_VERIFY (Vista+)
    // 0x00100000 DNS_QUERY_DONT_RESET_TTL_VALUES
    // 0x00200000 DNS_QUERY_DISABLE_IDN_ENCODING (Win8+)
    // 0x00800000 DNS_QUERY_APPEND_MULTILABEL
    //
    // DnsQueryEx-only flags (Windows 10+, MUST be stripped for DnsQuery_W):
    // 0x00004000  DNS_QUERY_DUAL_ADDR (Win7+ DnsQueryEx-specific, queries both A+AAAA)
    // 0x00008000+ DNS_QUERY_DOH, DNS_QUERY_DOT, etc.
    // 0x01000000+ High byte extended flags (async, validation, SNI, etc.)
    //
    // Safe mask strategy: Include ONLY legacy DnsQuery flags (bits 0-13, 17-22)
    // Exclude: bit 14 (DUAL_ADDR), bits 15-16 (reserved/DnsQueryEx), bits 23+ (extended)
    // 
    // Based on Microsoft official documentation (learn.microsoft.com/en-us/windows/win32/dns/dns-constants):
    // dwOptions already calculated above with mask 0x007E3FFF
    
    PDNSAPI_DNS_RECORD pRecords = NULL;
    DNS_STATUS status = __sys_DnsQuery_W(queryName, queryType, 
        dwOptions, NULL, &pRecords, NULL);
    
    // Populate DnsQueryEx result structure
    if (pQueryResults->Version == 0)
        pQueryResults->Version = DNS_QUERY_RESULTS_VERSION1;
    pQueryResults->QueryOptions = queryOptions;
    pQueryResults->pQueryRecords = pRecords;
    pQueryResults->Reserved = NULL;
    pQueryResults->QueryStatus = status;
    
    if (pCancelHandle)
        ZeroMemory(pCancelHandle, sizeof(DNS_QUERY_CANCEL));
    
    if (pOutcome) {
        pOutcome->Status = status;
        pOutcome->IsAsync = FALSE;  // We completed synchronously
    }
    
    // Log the workaround query result (same as normal passthrough logging)
    // Build tag with " Passthrough Result" suffix for consistency
    WCHAR logTag[128];
    Sbie_snwprintf(logTag, 128, L"%s Passthrough Result", sourceTag);
    PDNSAPI_DNS_RECORD* ppRecords = (status == 0) ? &pRecords : NULL;
    DNS_LogDnsQueryResult(logTag, queryName, queryType, status, ppRecords);
    
    return TRUE;  // We handled it
}

static BOOLEAN DNSAPI_HandleDnsQueryExRequestW(
    const WCHAR*             sourceTag,
    PDNS_QUERY_REQUEST_W     pQueryRequest,
    PDNS_QUERY_RESULT        pQueryResults,
    PDNS_QUERY_CANCEL        pCancelHandle,
    DNSAPI_EX_FILTER_RESULT* pOutcome)
{
    // CRITICAL: Apply Windows 10 workaround FIRST for all synchronous calls (no callback)
    // Only on Windows versions with the bug (Win10, Server 2016/2019).
    // Windows 11+ and Server 2022+ have the fix, so let async APIs work naturally.
    if (pQueryRequest && pQueryResults && pQueryRequest->QueryName && 
        pQueryRequest->Version >= DNS_QUERY_REQUEST_VERSION1 &&
        pQueryRequest->pQueryCompletionCallback == NULL &&
        DNS_CheckIfDnsQueryExWorkaroundNeeded()) {
        return DNSAPI_ApplyWindows10DnsQueryExWorkaround(
            sourceTag,
            pQueryRequest->QueryName,
            pQueryRequest->QueryType,
            pQueryRequest->QueryOptions,
            pQueryResults,
            pCancelHandle,
            pOutcome);
    }

    if (!DNS_FilterEnabled || !pQueryRequest || !pQueryResults)
        return FALSE;

    if (!pQueryRequest->QueryName)
        return FALSE;

    if (pQueryRequest->Version < DNS_QUERY_REQUEST_VERSION1)
        return FALSE;

    BOOLEAN result = DNSAPI_FilterDnsQueryExForName(
        pQueryRequest->QueryName,
        pQueryRequest->QueryType,
        pQueryRequest->QueryOptions,
        pQueryResults,
        pCancelHandle,
        pQueryRequest->pQueryCompletionCallback,
        pQueryRequest->pQueryContext,
        sourceTag,
        DnsCharSetUnicode,
        pOutcome);
    
    return result;
}

static BOOLEAN DNSAPI_HandleDnsQueryExRequestMultiByte(
    const WCHAR*             sourceTag,
    PDNS_QUERY_REQUEST_A     pQueryRequest,  // Can be PDNS_QUERY_REQUEST_A or PDNS_QUERY_REQUEST_UTF8
    PDNS_QUERY_RESULT        pQueryResults,
    PDNS_QUERY_CANCEL        pCancelHandle,
    UINT                     codePage,
    DNSAPI_EX_FILTER_RESULT* pOutcome)
{
    // Cast to ANSI structure (both ANSI and UTF8 have identical layouts)
    PDNS_QUERY_REQUEST_A pReq = (PDNS_QUERY_REQUEST_A)pQueryRequest;

    // CRITICAL: Apply Windows 10 workaround FIRST for all synchronous calls (no callback)
    // Only on Windows versions with the bug (Win10, Server 2016/2019).
    // Windows 11+ and Server 2022+ have the fix, so let async APIs work naturally.
    if (pReq && pQueryResults && pReq->QueryName && 
        pReq->Version >= DNS_QUERY_REQUEST_VERSION1 &&
        pReq->pQueryCompletionCallback == NULL &&
        DNS_CheckIfDnsQueryExWorkaroundNeeded()) {
        
        int nameLen = MultiByteToWideChar(codePage, 0, pReq->QueryName, -1, NULL, 0);
        if (nameLen > 0 && nameLen <= 512) {
            PWSTR wName = (PWSTR)Dll_Alloc(nameLen * sizeof(WCHAR));
            if (wName && MultiByteToWideChar(codePage, 0, pReq->QueryName, -1, wName, nameLen)) {
                BOOLEAN workaround_result = DNSAPI_ApplyWindows10DnsQueryExWorkaround(
                    sourceTag, wName, pReq->QueryType, pReq->QueryOptions,
                    pQueryResults, pCancelHandle, pOutcome);
                Dll_Free(wName);
                return workaround_result;
            }
            if (wName) Dll_Free(wName);
        }
    }

    if (!DNS_FilterEnabled || !pQueryRequest || !pQueryResults)
        return FALSE;
    
    if (!pReq->QueryName)
        return FALSE;

    if (pReq->Version < DNS_QUERY_REQUEST_VERSION1)
        return FALSE;

    int nameLen = MultiByteToWideChar(codePage, 0, pReq->QueryName, -1, NULL, 0);
    if (nameLen <= 0 || nameLen > 512)
        return FALSE;

    // Use Dll_Alloc instead of Dll_AllocTemp to avoid TLS cleanup issues with async operations
    PWSTR wName = (PWSTR)Dll_Alloc(nameLen * sizeof(WCHAR));
    if (!wName)
        return FALSE;

    if (!MultiByteToWideChar(codePage, 0, pReq->QueryName, -1, wName, nameLen)) {
        Dll_Free(wName);
        return FALSE;
    }

    DNS_CHARSET CharSet = (codePage == CP_UTF8) ? DnsCharSetUtf8 : DnsCharSetAnsi;

    BOOLEAN result = DNSAPI_FilterDnsQueryExForName(
        wName,
        pReq->QueryType,
        pReq->QueryOptions,
        pQueryResults,
        pCancelHandle,
        pReq->pQueryCompletionCallback,
        pReq->pQueryContext,
        sourceTag,
        CharSet,
        pOutcome);
    
    // Free the allocated wide string
    Dll_Free(wName);
    
    return result;
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
        if (!is_any_query && entry->Type != targetType)
            continue;

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
            memcpy(pRecord->Data.AAAA.Ip6Address, entry->IP.Data, 16);
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
// DNS_LogDnsQueryResult
//
// Common logging for DnsQuery passthrough results - eliminates duplication
// Logs query result status and IP addresses (if successful)
// Note: Status 9501 (DNS_INFO_NO_RECORDS) is normal - means no records of this type exist
//---------------------------------------------------------------------------

static void DNS_LogDnsQueryResult(
    const WCHAR*            sourceTag,
    const WCHAR*            domain,
    WORD                    wType,
    DNS_STATUS              status,
    PDNSAPI_DNS_RECORD*     ppQueryResults)
{
    if (!DNS_TraceFlag || !domain)
        return;

    WCHAR msg[1024];
    
    // Check what types were actually returned (for type mismatch detection)
    BOOLEAN hasA = FALSE, hasAAAA = FALSE;
    if (status == 0 && ppQueryResults && *ppQueryResults) {
        PDNSAPI_DNS_RECORD pRec = *ppQueryResults;
        while (pRec) {
            if (pRec->wType == DNS_TYPE_A) hasA = TRUE;
            if (pRec->wType == DNS_TYPE_AAAA) hasAAAA = TRUE;
            pRec = pRec->pNext;
        }
    }
    
    // Build status message - show returned type if different from requested
    if (status == 0 && ppQueryResults && *ppQueryResults) {
        WORD returnedType = (*ppQueryResults)->wType;
        if (returnedType != wType && (wType == DNS_TYPE_A || wType == DNS_TYPE_AAAA)) {
            // Type mismatch: requested AAAA but got A, or vice versa
            Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s, Status: %d, Returned: %s)",
                sourceTag, domain, DNS_GetTypeName(wType), status, DNS_GetTypeName(returnedType));
        } else {
            Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s, Status: %d)",
                sourceTag, domain, DNS_GetTypeName(wType), status);
        }
    } else {
        Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s, Status: %d)",
            sourceTag, domain, DNS_GetTypeName(wType), status);
    }
    
    // Log returned IP addresses if successful
    if (status == 0 && ppQueryResults && *ppQueryResults) {
        PDNSAPI_DNS_RECORD pRec = *ppQueryResults;
        while (pRec) {
            if (pRec->wType == DNS_TYPE_A || pRec->wType == DNS_TYPE_AAAA) {
                IP_ADDRESS ip;
                if (pRec->wType == DNS_TYPE_AAAA) {
                    memcpy(ip.Data, pRec->Data.AAAA.Ip6Address, 16);
                    WSA_DumpIP(AF_INET6, &ip, msg);
                } else {
                    ip.Data32[3] = pRec->Data.A.IpAddress;
                    WSA_DumpIP(AF_INET, &ip, msg);
                }
            }
            pRec = pRec->pNext;
        }
    }
    
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

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
    DNS_STATUS*             pStatus)
{
    // Block mode (no IPs) should block ALL query types
    if (!pEntries) {
        WCHAR blockTag[128];
        DNS_LogBlocked(DNS_GetBlockedTag(sourceTag, blockTag, ARRAYSIZE(blockTag)), 
                       wName, wType, L"Returning NXDOMAIN");
        *pStatus = DNS_ERROR_RCODE_NAME_ERROR;
        return TRUE;
    }

    // Filter mode (with IPs) - check if this type should be filtered
    BOOLEAN should_filter = DNS_IsTypeInFilterList(type_filter, wType);
    
    if (!should_filter) {
        // Type not in filter list - pass to real DNS
        *pStatus = 0;
        return FALSE;
    }

    // Type is in filter list - check if we can synthesize or should block
    if (DNS_CanSynthesizeResponse(wType)) {
        // Filter mode with supported type: build DNS_RECORD linked list
        PDNSAPI_DNS_RECORD pRecords = DNSAPI_BuildDnsRecordList(wName, wType, pEntries, CharSet);
        
        if (pRecords) {
            *ppQueryResults = pRecords;
            DNS_LogDnsRecords(sourceTag, wName, wType, pRecords);
            *pStatus = 0;
            return TRUE;
        } else {
            // No matching entries, return name error
            WCHAR blockTag[128];
            DNS_LogBlocked(DNS_GetBlockedTag(sourceTag, blockTag, ARRAYSIZE(blockTag)), 
                           wName, wType, L"Returning NXDOMAIN");
            *pStatus = DNS_ERROR_RCODE_NAME_ERROR;
            return TRUE;
        }
    } else {
        // Unsupported type (MX/CNAME/TXT/etc.): return NXDOMAIN
        WCHAR blockTag[128];
        DNS_LogBlocked(DNS_GetBlockedTag(sourceTag, blockTag, ARRAYSIZE(blockTag)), 
                       wName, wType, L"Returning NXDOMAIN");
        *pStatus = DNS_ERROR_RCODE_NAME_ERROR;
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
                DNS_LogPassthrough(L"DnsQuery_W Passthrough", pszName, wType, L"No filter configured, forwarding to real DNS");
                Dll_Free(path_lwr);
                return __sys_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
            }

            LIST* pEntries = NULL;
            DNS_TYPE_FILTER* type_filter = NULL;
            DNS_ExtractFilterAux(aux, &pEntries, &type_filter);

            DNS_STATUS status;
            if (DNSAPI_FilterDnsQuery(pszName, wType, pEntries, type_filter, DnsCharSetUnicode,
                                      L"DnsQuery_W Intercepted", ppQueryResults, &status)) {
                Dll_Free(path_lwr);
                return status;
            }

            // Not filtered - log passthrough and continue to real DNS
            DNS_LogPassthrough(L"DnsQuery_W Passthrough", pszName, wType, L"Type not in filter list, forwarding to real DNS");
        }

        Dll_Free(path_lwr);
    }

    // Call original DnsQuery_W
    DNS_STATUS status = __sys_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);

    DNS_LogDnsQueryResult(L"DnsQuery_W Passthrough Result", pszName, wType, status, ppQueryResults);

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

                    LIST* pEntries = NULL;
                    DNS_TYPE_FILTER* type_filter = NULL;
                    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);

                    DNS_STATUS status;
                    if (DNSAPI_FilterDnsQuery(wName, wType, pEntries, type_filter, DnsCharSetAnsi,
                                              L"DnsQuery_A Intercepted", ppQueryResults, &status)) {
                        Dll_Free(wName);
                        return status;
                    }

                    // Not filtered - log passthrough and continue to real DNS
                    DNS_LogPassthroughAnsi(L"DnsQuery_A Passthrough", pszName, wType, L"Type not in filter list, forwarding to real DNS");
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
                DNS_LogDnsQueryResult(L"DnsQuery_A Passthrough Result", wName, wType, status, ppQueryResults);
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

                    LIST* pEntries = NULL;
                    DNS_TYPE_FILTER* type_filter = NULL;
                    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);

                    DNS_STATUS status;
                    if (DNSAPI_FilterDnsQuery(wName, wType, pEntries, type_filter, DnsCharSetUtf8,
                                              L"DnsQuery_UTF8 Intercepted", ppQueryResults, &status)) {
                        Dll_Free(wName);
                        return status;
                    }

                    // Not filtered - log passthrough and continue to real DNS
                    DNS_LogPassthroughAnsi(L"DnsQuery_UTF8 Passthrough", pszName, wType, L"Type not in filter list, forwarding to real DNS");
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
                DNS_LogDnsQueryResult(L"DnsQuery_UTF8 Passthrough Result", wName, wType, status, ppQueryResults);
            }
        }
    }

    return status;
}

//---------------------------------------------------------------------------
// DnsQueryEx hooks (modern asynchronous API)
//---------------------------------------------------------------------------

_FX DNS_STATUS WINAPI DNSAPI_DnsQueryEx(
    PDNS_QUERY_REQUEST_W    pQueryRequest,
    PDNS_QUERY_RESULT       pQueryResults,
    PDNS_QUERY_CANCEL       pCancelHandle)
{
    DNSAPI_EX_FILTER_RESULT outcome;
    if (DNSAPI_HandleDnsQueryExRequestW(L"DnsQueryEx", pQueryRequest, pQueryResults, pCancelHandle, &outcome))
        return outcome.IsAsync ? DNS_REQUEST_PENDING : outcome.Status;

    DNS_STATUS status = DNS_ERROR_RCODE_NAME_ERROR;
    if (__sys_DnsQueryEx)
        status = __sys_DnsQueryEx(pQueryRequest, pQueryResults, pCancelHandle);
    else if (__sys_DnsQueryExW)
        status = __sys_DnsQueryExW(pQueryRequest, pQueryResults, pCancelHandle);

    // Log result with records from pQueryResults
    if (pQueryRequest && pQueryRequest->QueryName) {
        PDNSAPI_DNS_RECORD* ppRecords = (pQueryResults && pQueryResults->QueryStatus == 0) 
            ? &pQueryResults->pQueryRecords : NULL;
        DNS_LogDnsQueryResult(L"DnsQueryEx Passthrough Result", 
            pQueryRequest->QueryName, pQueryRequest->QueryType, status, ppRecords);
    }

    return status;
}

_FX DNS_STATUS WINAPI DNSAPI_DnsQueryExW(
    PDNS_QUERY_REQUEST_W    pQueryRequest,
    PDNS_QUERY_RESULT       pQueryResults,
    PDNS_QUERY_CANCEL       pCancelHandle)
{
    DNSAPI_EX_FILTER_RESULT outcome;
    if (DNSAPI_HandleDnsQueryExRequestW(L"DnsQueryExW", pQueryRequest, pQueryResults, pCancelHandle, &outcome))
        return outcome.IsAsync ? DNS_REQUEST_PENDING : outcome.Status;

    DNS_STATUS status = DNS_ERROR_RCODE_NAME_ERROR;
    if (__sys_DnsQueryExW)
        status = __sys_DnsQueryExW(pQueryRequest, pQueryResults, pCancelHandle);
    else if (__sys_DnsQueryEx)
        status = __sys_DnsQueryEx(pQueryRequest, pQueryResults, pCancelHandle);

    // Log result with records from pQueryResults
    if (pQueryRequest && pQueryRequest->QueryName) {
        PDNSAPI_DNS_RECORD* ppRecords = (pQueryResults && pQueryResults->QueryStatus == 0) 
            ? &pQueryResults->pQueryRecords : NULL;
        DNS_LogDnsQueryResult(L"DnsQueryExW Passthrough Result", 
            pQueryRequest->QueryName, pQueryRequest->QueryType, status, ppRecords);
    }

    return status;
}

_FX DNS_STATUS WINAPI DNSAPI_DnsQueryExA(
    PDNS_QUERY_REQUEST_A    pQueryRequest,
    PDNS_QUERY_RESULT       pQueryResults,
    PDNS_QUERY_CANCEL       pCancelHandle)
{
    if (DNS_DebugFlag && pQueryRequest) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"DnsQueryExA ENTRY: pQueryRequest=%p, QueryName=%p, Version=%d, Type=%d",
            pQueryRequest, pQueryRequest->QueryName, pQueryRequest->Version, pQueryRequest->QueryType);
        DNS_LogDebug(msg);
    }
    
    DNSAPI_EX_FILTER_RESULT outcome;
    if (DNSAPI_HandleDnsQueryExRequestMultiByte(L"DnsQueryExA", pQueryRequest, pQueryResults, pCancelHandle, CP_ACP, &outcome))
        return outcome.IsAsync ? DNS_REQUEST_PENDING : outcome.Status;

    if (DNS_DebugFlag && pQueryRequest) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"DnsQueryExA CALLING REAL API: pQueryRequest=%p", pQueryRequest);
        DNS_LogDebug(msg);
    }

    DNS_STATUS status = DNS_ERROR_RCODE_NAME_ERROR;
    if (__sys_DnsQueryExA)
        status = __sys_DnsQueryExA(pQueryRequest, pQueryResults, pCancelHandle);

    // Convert ANSI domain to wide for logging
    if (pQueryRequest && pQueryRequest->QueryName) {
        int nameLen = MultiByteToWideChar(CP_ACP, 0, pQueryRequest->QueryName, -1, NULL, 0);
        if (nameLen > 0 && nameLen < 512) {
            WCHAR* wName = (WCHAR*)Dll_AllocTemp(nameLen * sizeof(WCHAR));
            if (wName && MultiByteToWideChar(CP_ACP, 0, pQueryRequest->QueryName, -1, wName, nameLen)) {
                PDNSAPI_DNS_RECORD* ppRecords = (pQueryResults && pQueryResults->QueryStatus == 0) 
                    ? &pQueryResults->pQueryRecords : NULL;
                DNS_LogDnsQueryResult(L"DnsQueryExA Passthrough Result", 
                    wName, pQueryRequest->QueryType, status, ppRecords);
            }
        }
    }

    return status;
}

_FX DNS_STATUS WINAPI DNSAPI_DnsQueryExUTF8(
    PDNS_QUERY_REQUEST_UTF8 pQueryRequest,
    PDNS_QUERY_RESULT       pQueryResults,
    PDNS_QUERY_CANCEL       pCancelHandle)
{
    // Debug: Log the function call with raw pointer values
    DNS_LogQueryExPointers(L"DnsQueryExUTF8 ENTRY", pQueryRequest, pQueryResults,
        pQueryRequest ? pQueryRequest->Version : 0,
        pQueryRequest ? pQueryRequest->QueryName : NULL);
    
    DNSAPI_EX_FILTER_RESULT outcome;
    if (DNSAPI_HandleDnsQueryExRequestMultiByte(L"DnsQueryExUTF8", pQueryRequest, pQueryResults, pCancelHandle, CP_UTF8, &outcome))
        return outcome.IsAsync ? DNS_REQUEST_PENDING : outcome.Status;

    if (DNS_DebugFlag && pQueryRequest) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"DnsQueryExUTF8 CALLING REAL API: pQueryRequest=%p", pQueryRequest);
        DNS_LogDebug(msg);
    }

    DNS_STATUS status = DNS_ERROR_RCODE_NAME_ERROR;
    if (__sys_DnsQueryExUTF8)
        status = __sys_DnsQueryExUTF8(pQueryRequest, pQueryResults, pCancelHandle);

    // Convert UTF8 domain to wide for logging
    if (pQueryRequest && pQueryRequest->QueryName) {
        int nameLen = MultiByteToWideChar(CP_UTF8, 0, pQueryRequest->QueryName, -1, NULL, 0);
        if (nameLen > 0 && nameLen < 512) {
            WCHAR* wName = (WCHAR*)Dll_AllocTemp(nameLen * sizeof(WCHAR));
            if (wName && MultiByteToWideChar(CP_UTF8, 0, pQueryRequest->QueryName, -1, wName, nameLen)) {
                PDNSAPI_DNS_RECORD* ppRecords = (pQueryResults && pQueryResults->QueryStatus == 0) 
                    ? &pQueryResults->pQueryRecords : NULL;
                DNS_LogDnsQueryResult(L"DnsQueryExUTF8 Passthrough Result", 
                    wName, pQueryRequest->QueryType, status, ppRecords);
            }
        }
    }

    return status;
}

//---------------------------------------------------------------------------
// DNSAPI_DnsQueryRawFilterAndRespond
//
// Consolidated filtering logic for both Phase 1 and Phase 2
// Determines whether to block/filter, builds response, invokes callback
//---------------------------------------------------------------------------

static DNS_STATUS DNSAPI_DnsQueryRawFilterAndRespond(
    PDNS_QUERY_RAW_REQUEST pRequest,
    const WCHAR* domainName,
    USHORT queryType,
    LIST* pEntries,
    DNS_TYPE_FILTER* type_filter,
    const BYTE* rawQuery,
    int rawQuerySize)
{
    // Determine if should intercept this query
    BOOLEAN is_block_mode = !pEntries;  // Block mode = no IPs configured
    BOOLEAN type_in_filter = pEntries && DNS_IsTypeInFilterList(type_filter, queryType);
    BOOLEAN can_synthesize = DNS_CanSynthesizeResponse(queryType);
    
    // For raw packet mode: can filter any type (even if can't synthesize DNS_RECORD)
    // For name/type mode: can only filter types we can synthesize
    BOOLEAN can_filter_this_type = rawQuery ? TRUE : can_synthesize;

    // Check if we should intercept
    if (is_block_mode || type_in_filter) {
        // Build result structure
        PDNS_QUERY_RAW_RESULT pResult = (PDNS_QUERY_RAW_RESULT)Dll_Alloc(sizeof(DNS_QUERY_RAW_RESULT));
        if (pResult) {
            memset(pResult, 0, sizeof(DNS_QUERY_RAW_RESULT));
            pResult->version = pRequest->resultsVersion;
            pResult->queryOptions = pRequest->queryOptions;
            pResult->protocol = rawQuery ? pRequest->protocol : DNS_PROTOCOL_NO_WIRE;

            // Decide: Block (NXDOMAIN) or Filter (synthesized response)
            BOOLEAN should_block = is_block_mode || (type_in_filter && !can_filter_this_type);
            
            if (should_block) {
                // Block: return NXDOMAIN
                pResult->queryStatus = DNS_ERROR_RCODE_NAME_ERROR;
                pResult->queryRecords = NULL;
                
                // Build raw NXDOMAIN response if raw packet mode
                if (rawQuery && rawQuerySize > 0) {
                    BYTE responseBuffer[1024];
                    int responseSize = Socket_BuildDnsResponse(
                        rawQuery, rawQuerySize, NULL, TRUE,  // TRUE = block mode (NXDOMAIN)
                        responseBuffer, sizeof(responseBuffer),
                        queryType, type_filter);
                    
                    if (responseSize > 0) {
                        pResult->queryRawResponse = (BYTE*)Dll_Alloc(responseSize);
                        if (pResult->queryRawResponse) {
                            memcpy(pResult->queryRawResponse, responseBuffer, responseSize);
                            pResult->queryRawResponseSize = responseSize;
                        }
                    } else {
                        pResult->queryRawResponse = NULL;
                        pResult->queryRawResponseSize = 0;
                    }
                } else {
                    pResult->queryRawResponse = NULL;
                    pResult->queryRawResponseSize = 0;
                }

                if (DNS_TraceFlag) {
                    WCHAR msg[512];
                    Sbie_snwprintf(msg, 512, L"DnsQueryRaw Blocked%s: %s (Type: %s) - Returning NXDOMAIN",
                        rawQuery ? L" (raw)" : L"", domainName, DNS_GetTypeName(queryType));
                    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
                }
            } else {
                // Filter: synthesize response with configured IPs
                pResult->queryStatus = 0;  // Success
                
                // Build DNS_RECORD list if we can synthesize this type
                if (can_synthesize) {
                    pResult->queryRecords = DNSAPI_BuildDnsRecordList(domainName, queryType, pEntries, DnsCharSetUnicode);
                    if (!pResult->queryRecords) {
                        pResult->queryStatus = DNS_ERROR_RCODE_NAME_ERROR;
                    }
                } else {
                    // Can't build DNS_RECORD for this type (MX, CNAME, TYPE256, etc.)
                    pResult->queryRecords = NULL;
                }
                
                // Build raw packet if raw mode (works for any type)
                if (rawQuery && rawQuerySize > 0) {
                    BYTE responseBuffer[1024];
                    int responseSize = Socket_BuildDnsResponse(
                        rawQuery, rawQuerySize, pEntries, FALSE,  // FALSE = filter mode
                        responseBuffer, sizeof(responseBuffer),
                        queryType, type_filter);
                    
                    if (responseSize > 0) {
                        pResult->queryRawResponse = (BYTE*)Dll_Alloc(responseSize);
                        if (pResult->queryRawResponse) {
                            memcpy(pResult->queryRawResponse, responseBuffer, responseSize);
                            pResult->queryRawResponseSize = responseSize;
                            pResult->queryStatus = 0;  // Success if raw packet built
                        }
                    } else {
                        pResult->queryRawResponse = NULL;
                        pResult->queryRawResponseSize = 0;
                        // If can't build raw packet, return error
                        if (!pResult->queryRecords) {
                            pResult->queryStatus = DNS_ERROR_RCODE_NAME_ERROR;
                        }
                    }
                } else {
                    pResult->queryRawResponse = NULL;
                    pResult->queryRawResponseSize = 0;
                }

                if (DNS_TraceFlag) {
                    if (pResult->queryRecords) {
                        DNS_LogDnsRecords(rawQuery ? L"DnsQueryRaw Intercepted (raw)" : L"DnsQueryRaw Intercepted",
                            domainName, queryType, pResult->queryRecords);
                    } else if (rawQuery && pResult->queryRawResponse) {
                        WCHAR msg[512];
                        Sbie_snwprintf(msg, 512, L"DnsQueryRaw Filtered (raw): %s (Type: %s) - Returning filtered raw packet",
                            domainName, DNS_GetTypeName(queryType));
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                    }
                }
            }

            // Call callback inline (simulate async completion)
            pRequest->queryCompletionCallback(pRequest->queryContext, pResult);
            return DNS_REQUEST_PENDING;
        }
    }
    
    return 0;  // Not intercepted
}

//---------------------------------------------------------------------------
// DNSAPI_DnsQueryRaw
//
// Hook for DnsQueryRaw - Phase 1 implementation (name/type mode only)
// Supports filtering when dnsQueryName/dnsQueryType are provided.
// Raw packet mode (dnsQueryRaw) is passed through to real DNS (Phase 2 TODO).
//
// This API is always async and requires a callback - no synchronous mode exists.
//---------------------------------------------------------------------------

_FX DNS_STATUS WINAPI DNSAPI_DnsQueryRaw(
    PDNS_QUERY_RAW_REQUEST  pRequest,
    PDNS_QUERY_RAW_CANCEL   pCancelHandle)
{
    // Validate parameters
    if (!pRequest || pRequest->version != DNS_QUERY_RAW_REQUEST_VERSION1) {
        return DNS_ERROR_RCODE_NAME_ERROR;
    }

    // Callback is REQUIRED for DnsQueryRaw (always async)
    if (!pRequest->queryCompletionCallback) {
        return DNS_ERROR_RCODE_NAME_ERROR;
    }

    // Phase 1: Handle name/type mode (easy path)
    if (pRequest->dnsQueryName && pRequest->dnsQueryType) {
        if (DNS_FilterEnabled) {
            size_t name_len = wcslen(pRequest->dnsQueryName);
            if (name_len > 0 && name_len < 512) {
                WCHAR* name_lwr = (WCHAR*)Dll_AllocTemp((name_len + 4) * sizeof(WCHAR));
                if (name_lwr) {
                    wmemcpy(name_lwr, pRequest->dnsQueryName, name_len);
                    name_lwr[name_len] = L'\0';
                    _wcslwr(name_lwr);

                    // Check exclusions
                    if (DNS_IsExcluded(name_lwr)) {
                        if (DNS_TraceFlag) {
                            WCHAR msg[512];
                            Sbie_snwprintf(msg, 512, L"DnsQueryRaw: Domain '%s' excluded, forwarding to real DNS", name_lwr);
                            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                        }
                        Dll_Free(name_lwr);
                        if (__sys_DnsQueryRaw)
                            return __sys_DnsQueryRaw(pRequest, pCancelHandle);
                        return DNS_ERROR_RCODE_NAME_ERROR;
                    }

                    // Check filter list
                    PATTERN* found = NULL;
                    if (Pattern_MatchPathList(name_lwr, (ULONG)name_len, &DNS_FilterList, NULL, NULL, NULL, &found) > 0) {
                        PVOID* aux = Pattern_Aux(found);
                        if (aux && *aux) {
                            LIST* pEntries = NULL;
                            DNS_TYPE_FILTER* type_filter = NULL;
                            DNS_ExtractFilterAux(aux, &pEntries, &type_filter);

                            // Use helper for Phase 1 (name/type mode - no raw packet)
                            DNS_STATUS result = DNSAPI_DnsQueryRawFilterAndRespond(
                                pRequest, pRequest->dnsQueryName, pRequest->dnsQueryType,
                                pEntries, type_filter, NULL, 0);
                            
                            if (result == DNS_REQUEST_PENDING) {
                                Dll_Free(name_lwr);
                                return result;
                            }
                        }
                    }

                    Dll_Free(name_lwr);
                }
            }
        }
    }
    // Phase 2: Handle raw packet mode (dnsQueryRaw)
    else if (pRequest->dnsQueryRaw && pRequest->dnsQueryRawSize > 0) {
        if (DNS_FilterEnabled) {
            // Parse the raw DNS query packet to extract domain name and type
            WCHAR domainName[256] = {0};
            USHORT queryType = 0;
            
            if (Socket_ParseDnsQuery(pRequest->dnsQueryRaw, pRequest->dnsQueryRawSize, 
                                     domainName, 256, &queryType)) {
                // Convert to lowercase for matching
                _wcslwr(domainName);
                size_t name_len = wcslen(domainName);
                
                if (DNS_TraceFlag) {
                    WCHAR msg[512];
                    Sbie_snwprintf(msg, 512, L"DnsQueryRaw: Parsed raw packet - Domain='%s', Type=%s",
                        domainName, DNS_GetTypeName(queryType));
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
                
                // Check exclusions
                if (DNS_IsExcluded(domainName)) {
                    if (DNS_TraceFlag) {
                        WCHAR msg[512];
                        Sbie_snwprintf(msg, 512, L"DnsQueryRaw: Domain '%s' excluded, forwarding to real DNS", domainName);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                    }
                    if (__sys_DnsQueryRaw)
                        return __sys_DnsQueryRaw(pRequest, pCancelHandle);
                    return DNS_ERROR_RCODE_NAME_ERROR;
                }
                
                // Check filter list
                PATTERN* found = NULL;
                if (Pattern_MatchPathList(domainName, (ULONG)name_len, &DNS_FilterList, NULL, NULL, NULL, &found) > 0) {
                    PVOID* aux = Pattern_Aux(found);
                    if (aux && *aux) {
                        LIST* pEntries = NULL;
                        DNS_TYPE_FILTER* type_filter = NULL;
                        DNS_ExtractFilterAux(aux, &pEntries, &type_filter);
                        
                        DNS_STATUS result = DNSAPI_DnsQueryRawFilterAndRespond(
                            pRequest, domainName, queryType, pEntries, type_filter,
                            pRequest->dnsQueryRaw, pRequest->dnsQueryRawSize);
                        
                        if (result == DNS_REQUEST_PENDING) {
                            return result;
                        }
                    }
                }
            } else {
                // Failed to parse raw packet
                if (DNS_TraceFlag) {
                    SbieApi_MonitorPutMsg(MONITOR_DNS, L"DnsQueryRaw: Failed to parse raw packet, forwarding to real DNS");
                }
            }
        }
        
        // Passthrough for unparseable or unfiltered raw packets
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"DnsQueryRaw: Raw packet mode forwarding to real DNS");
        }
    }

    // Passthrough to real DnsQueryRaw
    if (DNS_TraceFlag && pRequest->dnsQueryName) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"DnsQueryRaw Passthrough: %s (Type: %s)",
            pRequest->dnsQueryName, DNS_GetTypeName(pRequest->dnsQueryType));
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    if (__sys_DnsQueryRaw)
        return __sys_DnsQueryRaw(pRequest, pCancelHandle);

    return DNS_ERROR_RCODE_NAME_ERROR;
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
        if (DNS_TraceFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"DnsApi RecordListFree: Freeing SBIE record (List: %p, Type: %d)", pRecordList, FreeType);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }

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
    if (DNS_TraceFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"DnsApi RecordListFree: Calling real API (List: %p, Type: %d)", pRecordList, FreeType);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    __sys_DnsRecordListFree(pRecordList, FreeType);
}

