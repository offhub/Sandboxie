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
//    - Functions: DnsQuery_A, DnsQuery_W
//    - Returns: DNS_RECORD linked list (absolute pointers)
//    - Used by: Modern browsers, system utilities, most contemporary apps
//
// 3. Raw Socket Interception (ws2_32.dll) - Direct UDP packet filtering
//    - Functions: sendto, WSASendTo (port 53 traffic)
//    - Parses: DNS wire format packets (RFC 1035)
//    - Used by: nslookup, dig, custom DNS clients
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

static PDNSAPI_DNS_RECORD DNSAPI_BuildDnsRecordList(
    const WCHAR*    domainName,
    WORD            wType,
    LIST*           pEntries);

// Shared utility functions (implemented in net.c)
BOOLEAN WSA_GetIP(const short* addr, int addrlen, IP_ADDRESS* pIP);
void WSA_DumpIP(ADDRESS_FAMILY af, IP_ADDRESS* pIP, wchar_t* pStr);

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
static BOOLEAN DNS_LoadFilterEntries(void);

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
    if (SbieApi_QueryConf(NULL, L"DnsDebug", 0, wsDebugOptions, sizeof(wsDebugOptions)) == STATUS_SUCCESS && wsDebugOptions[0] != L'\0')
        DNS_DebugExclusionLogs = Config_String2Bool(wsDebugOptions, FALSE);
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
        NTSTATUS status = SbieApi_QueryConf(NULL, L"NetworkDnsFilterEx", index, ex_buf, sizeof(ex_buf) - 16 * sizeof(WCHAR));
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
            for (const WCHAR* ip_end = ip_value + ip_len; ip_value < ip_end;) {
                const WCHAR* ip_str1;
                ULONG ip_len1;
                ip_value = SbieDll_GetTagValue(ip_value, ip_end, &ip_str1, &ip_len1, L';');

                IP_ENTRY* entry = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
                if (entry && _inet_xton(ip_str1, ip_len1, &entry->IP, &entry->Type) == 1) {
                    if (entry->Type == AF_INET6)
                        HasV6 = TRUE;
                    List_Insert_After(entries, NULL, entry);
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

            PVOID* aux = Pattern_Aux(pat);
            *aux = entries;
        }

        List_Insert_After(&DNS_FilterList, NULL, pat);
        Dll_Free(mutable_value);
        loaded = TRUE;
    }

    return loaded;
}


_FX void DNS_InitFilterRules(void)
{
    DNS_LoadExclusionRules();

    if (DNS_FilterList.count > 0)
        return;

    List_Init(&DNS_FilterList);
    DNS_LoadFilterEntries();

    if (DNS_FilterList.count > 0) {

        DNS_FilterEnabled = TRUE;

        map_init(&WSA_LookupMap, Dll_Pool);

        SCertInfo CertInfo = { 0 };
        if (!NT_SUCCESS(SbieApi_QueryDrvInfo(-1, &CertInfo, sizeof(CertInfo))) || !(CertInfo.active && CertInfo.opt_net)) {

            const WCHAR* strings[] = { L"NetworkDnsFilter" , NULL };
            SbieApi_LogMsgExt(-1, 6009, strings);

            DNS_FilterEnabled = FALSE;
        }
    }

    // If there are any DnsTrace options set, then output this debug string
    WCHAR wsTraceOptions[4];
    if (SbieApi_QueryConf(NULL, L"DnsTrace", 0, wsTraceOptions, sizeof(wsTraceOptions)) == STATUS_SUCCESS && wsTraceOptions[0] != L'\0')
        DNS_TraceFlag = TRUE;
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

    for (ULONG j = 0; j < excl->count; ++j) {
        const WCHAR* pattern = excl->patterns[j];
        if (!pattern)
            continue;

        if (DNS_DebugExclusionLogs && DNS_TraceFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"DNS_IsExcluded: Testing pattern[%d]='%s'", j, pattern);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }

        if (wcsstr(domain, pattern)) {
            if (DNS_DebugExclusionLogs && DNS_TraceFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"DNS_IsExcluded: MATCH! Domain='%s' matched pattern='%s'",
                    domain, pattern);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            return TRUE;
        }
    }

    return FALSE;
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
            if (DNS_TraceFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"DNS Exclusion: Domain '%s' matched exclusion list, skipping filter", path_lwr);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
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
                if (*aux)
                    pLookup->pEntries = (LIST*)*aux;
                else
                    pLookup->NoMore = TRUE;
            }

            if (DNS_TraceFlag) {
                WCHAR ClsId[64] = { 0 };
                if (lpqsRestrictions->lpServiceClassId) {
                    Sbie_snwprintf(ClsId, 64, L" (ClsId: %08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX)",
                        lpqsRestrictions->lpServiceClassId->Data1, lpqsRestrictions->lpServiceClassId->Data2, lpqsRestrictions->lpServiceClassId->Data3,
                        lpqsRestrictions->lpServiceClassId->Data4[0], lpqsRestrictions->lpServiceClassId->Data4[1], lpqsRestrictions->lpServiceClassId->Data4[2], lpqsRestrictions->lpServiceClassId->Data4[3],
                        lpqsRestrictions->lpServiceClassId->Data4[4], lpqsRestrictions->lpServiceClassId->Data4[5], lpqsRestrictions->lpServiceClassId->Data4[6], lpqsRestrictions->lpServiceClassId->Data4[7]);
                }

                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"DNS Request Intercepted: %s%s (NS: %d, Type: %s, Hdl: %p) - Using filtered response",
                    lpqsRestrictions->lpszServiceInstanceName, ClsId, lpqsRestrictions->dwNameSpace,
                    WSA_IsIPv6Query(lpqsRestrictions->lpServiceClassId) ? L"IPv6" : L"IPv4", fakeHandle);
                SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
            }

            Dll_Free(path_lwr);
            return NO_ERROR;
        }

        Dll_Free(path_lwr);
    }

    int ret = __sys_WSALookupServiceBeginW(lpqsRestrictions, dwControlFlags, lphLookup);

    if (DNS_TraceFlag && lpqsRestrictions) {
        WCHAR ClsId[64] = { 0 };
        if (lpqsRestrictions->lpServiceClassId) {
            Sbie_snwprintf(ClsId, 64, L" (ClsId: %08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX)",
                lpqsRestrictions->lpServiceClassId->Data1, lpqsRestrictions->lpServiceClassId->Data2, lpqsRestrictions->lpServiceClassId->Data3,
                lpqsRestrictions->lpServiceClassId->Data4[0], lpqsRestrictions->lpServiceClassId->Data4[1], lpqsRestrictions->lpServiceClassId->Data4[2], lpqsRestrictions->lpServiceClassId->Data4[3],
                lpqsRestrictions->lpServiceClassId->Data4[4], lpqsRestrictions->lpServiceClassId->Data4[5], lpqsRestrictions->lpServiceClassId->Data4[6], lpqsRestrictions->lpServiceClassId->Data4[7]);
        }

        WCHAR msg[512];
        BOOLEAN isIPv6 = WSA_IsIPv6Query(lpqsRestrictions->lpServiceClassId);
        Sbie_snwprintf(msg, 512, L"DNS Request Begin: %s%s, NS: %d, Type: %s, Hdl: %p, Err: %d)",
            lpqsRestrictions->lpszServiceInstanceName ? lpqsRestrictions->lpszServiceInstanceName : L"Unnamed",
            ClsId, lpqsRestrictions->dwNameSpace, isIPv6 ? L"IPv6" : L"IPv4",
            lphLookup ? *lphLookup : NULL, ret == SOCKET_ERROR ? GetLastError() : 0);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
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
            if (pLookup->NoMore || !pLookup->pEntries) {
                SetLastError(WSA_E_NO_MORE);
                return SOCKET_ERROR;
            }

            if (WSA_FillResponseStructure(pLookup, lpqsResults, lpdwBufferLength)) {
                pLookup->NoMore = TRUE;

                if (DNS_TraceFlag) {
                    WCHAR msg[2048];
                    Sbie_snwprintf(msg, ARRAYSIZE(msg), L"DNS Filtered Response: %s (NS: %d, Type: %s, Hdl: %p)",
                        pLookup->DomainName, lpqsResults->dwNameSpace,
                        WSA_IsIPv6Query(pLookup->ServiceClassId) ? L"IPv6" : L"IPv4", hLookup);

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
        Sbie_snwprintf(msg, ARRAYSIZE(msg), L"DNS Request Found: %s (NS: %d, Hdl: %p)",
            lpqsResults->lpszServiceInstanceName, lpqsResults->dwNameSpace, hLookup);

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
    DNSAPI_EX_FILTER_RESULT*         pOutcome)
{
    if (!DNS_FilterEnabled || !pszName || !pQueryResults)
        return FALSE;

    if (wType != DNS_TYPE_A && wType != DNS_TYPE_AAAA)
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
    LIST* pEntries = aux ? (LIST*)*aux : NULL;

    PDNSAPI_DNS_RECORD pRecords = NULL;
    DNS_STATUS status = 0;

    if (pEntries) {
        pRecords = DNSAPI_BuildDnsRecordList(pszName, wType, pEntries);
        if (!pRecords)
            status = DNS_ERROR_RCODE_NAME_ERROR;
    }
    else {
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
                sourceTag, pszName, (wType == DNS_TYPE_AAAA) ? L"AAAA" : L"A");

            PDNSAPI_DNS_RECORD pRec = pRecords;
            while (pRec) {
                if (pRec->wType == DNS_TYPE_A || pRec->wType == DNS_TYPE_AAAA) {
                    IP_ADDRESS ip;
                    if (pRec->wType == DNS_TYPE_AAAA)
                        memcpy(ip.Data, pRec->Data.AAAA.Ip6Address, 16);
                    else
                        ip.Data32[3] = pRec->Data.A.IpAddress;
                    WSA_DumpIP((pRec->wType == DNS_TYPE_AAAA) ? AF_INET6 : AF_INET, &ip, msg);
                }
                pRec = pRec->pNext;
            }

            SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
        }
        else {
            Sbie_snwprintf(msg, ARRAYSIZE(msg), L"%s Blocked: %s (Type: %s) - Returning NXDOMAIN",
                sourceTag, pszName, (wType == DNS_TYPE_AAAA) ? L"AAAA" : L"A");
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

static BOOLEAN DNSAPI_HandleDnsQueryExRequestW(
    const WCHAR*             sourceTag,
    PDNS_QUERY_REQUEST_W     pQueryRequest,
    PDNS_QUERY_RESULT        pQueryResults,
    PDNS_QUERY_CANCEL        pCancelHandle,
    DNSAPI_EX_FILTER_RESULT* pOutcome)
{
    if (!DNS_FilterEnabled || !pQueryRequest || !pQueryResults)
        return FALSE;

    if (pQueryRequest->QueryType != DNS_TYPE_A && pQueryRequest->QueryType != DNS_TYPE_AAAA)
        return FALSE;

    if (!pQueryRequest->QueryName)
        return FALSE;

    if (pQueryRequest->Version < DNS_QUERY_REQUEST_VERSION1)
        return FALSE;

    return DNSAPI_FilterDnsQueryExForName(
        pQueryRequest->QueryName,
        pQueryRequest->QueryType,
        pQueryRequest->QueryOptions,
        pQueryResults,
        pCancelHandle,
        pQueryRequest->pQueryCompletionCallback,
        pQueryRequest->pQueryContext,
        sourceTag,
        pOutcome);
}

static BOOLEAN DNSAPI_HandleDnsQueryExRequestMultiByte(
    const WCHAR*             sourceTag,
    PDNS_QUERY_REQUEST_A     pQueryRequest,
    PDNS_QUERY_RESULT        pQueryResults,
    PDNS_QUERY_CANCEL        pCancelHandle,
    UINT                     codePage,
    DNSAPI_EX_FILTER_RESULT* pOutcome)
{
    if (!DNS_FilterEnabled || !pQueryRequest || !pQueryResults)
        return FALSE;

    if (pQueryRequest->QueryType != DNS_TYPE_A && pQueryRequest->QueryType != DNS_TYPE_AAAA)
        return FALSE;

    if (!pQueryRequest->QueryName)
        return FALSE;

    if (pQueryRequest->Version < DNS_QUERY_REQUEST_VERSION1)
        return FALSE;

    int nameLen = MultiByteToWideChar(codePage, 0, pQueryRequest->QueryName, -1, NULL, 0);
    if (nameLen <= 0)
        return FALSE;

    PWSTR wName = (PWSTR)Dll_AllocTemp(nameLen * sizeof(WCHAR));
    if (!wName)
        return FALSE;

    if (!MultiByteToWideChar(codePage, 0, pQueryRequest->QueryName, -1, wName, nameLen))
        return FALSE;

    return DNSAPI_FilterDnsQueryExForName(
        wName,
        pQueryRequest->QueryType,
        pQueryRequest->QueryOptions,
        pQueryResults,
        pCancelHandle,
        pQueryRequest->pQueryCompletionCallback,
        pQueryRequest->pQueryContext,
        sourceTag,
        pOutcome);
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
    LIST* pEntries)
{
    if (!pEntries || !domainName)
        return NULL;

    PDNSAPI_DNS_RECORD pFirstRecord = NULL;
    PDNSAPI_DNS_RECORD pLastRecord = NULL;

    USHORT targetType = (wType == DNS_TYPE_AAAA) ? AF_INET6 : AF_INET;
    SIZE_T domainNameLen = (wcslen(domainName) + 1) * sizeof(WCHAR);

    // Build linked list of DNS_RECORD structures
    IP_ENTRY* entry;
    for (entry = (IP_ENTRY*)List_Head(pEntries); entry; entry = (IP_ENTRY*)List_Next(entry)) {
        if (entry->Type != targetType)
            continue;

        // Allocate DNS_RECORD using LocalAlloc (required for DnsFree compatibility)
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

        // Allocate and copy domain name
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
        wcscpy_s(pRecord->pName, domainNameLen / sizeof(WCHAR), domainName);

        // Set record type and flags
        pRecord->wType = wType;
        
        // Set Flags: Section = DNSREC_ANSWER (1), CharSet = Unicode (0), all other fields = 0
        // This ensures ipconfig displays "Section . . . . . . . : Answer" instead of "Question"
        // CharSet should be 0 (DnsCharSetUnicode) for wide string domain names
        pRecord->Flags.DW = 0;
        pRecord->Flags.S.Section = DNSREC_ANSWER;
        pRecord->Flags.S.CharSet = 0;  // DnsCharSetUnicode - matches Windows behavior for wide strings
        
        pRecord->dwTtl = 300;  // 5 minutes TTL (default)
        pRecord->pNext = NULL;

        // Copy IP address data
        if (wType == DNS_TYPE_AAAA) {
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
// DNSAPI_DnsQuery_W
//
// Hook for DnsQuery_W - filters DNS queries using the same rules as
// WSALookupService but returns DNS_RECORD linked list format.
//---------------------------------------------------------------------------

_FX DNS_STATUS DNSAPI_DnsQuery_W(
    PCWSTR          pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNSAPI_DNS_RECORD* ppQueryResults,
    PVOID*          pReserved)
{
    // Only filter A and AAAA queries
    if (DNS_FilterEnabled && pszName && (wType == DNS_TYPE_A || wType == DNS_TYPE_AAAA)) {
        ULONG path_len = wcslen(pszName);
        WCHAR* path_lwr = (WCHAR*)Dll_AllocTemp((path_len + 4) * sizeof(WCHAR));
        wmemcpy(path_lwr, pszName, path_len);
        path_lwr[path_len] = L'\0';
        _wcslwr(path_lwr);

        if (DNS_IsExcluded(path_lwr)) {
            if (DNS_TraceFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"DNS Exclusion: Domain '%s' matched exclusion list, skipping filter", path_lwr);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            Dll_Free(path_lwr);
            return __sys_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
        }

        PATTERN* found;
        if (Pattern_MatchPathList(path_lwr, path_len, &DNS_FilterList, NULL, NULL, NULL, &found) > 0) {
            PVOID* aux = Pattern_Aux(found);
            LIST* pEntries = (LIST*)*aux;

            if (pEntries) {
                // Build DNS_RECORD linked list
                PDNSAPI_DNS_RECORD pRecords = DNSAPI_BuildDnsRecordList(pszName, wType, pEntries);
                
                if (pRecords) {
                    *ppQueryResults = pRecords;
                    
                    if (DNS_TraceFlag) {
                        WCHAR msg[1024];
                        Sbie_snwprintf(msg, 1024, L"DnsApi Request Intercepted: %s (Type: %s) - Using filtered response",
                            pszName, (wType == DNS_TYPE_AAAA) ? L"AAAA" : L"A");
                        
                        // Log IP addresses
                        PDNSAPI_DNS_RECORD pRec = pRecords;
                        while (pRec) {
                            IP_ADDRESS ip;
                            if (wType == DNS_TYPE_AAAA) {
                                memcpy(ip.Data, pRec->Data.AAAA.Ip6Address, 16);
                            } else {
                                ip.Data32[3] = pRec->Data.A.IpAddress;
                            }
                            WSA_DumpIP((wType == DNS_TYPE_AAAA) ? AF_INET6 : AF_INET, &ip, msg);
                            pRec = pRec->pNext;
                        }
                        
                        SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
                    }
                    
                    Dll_Free(path_lwr);
                    return 0;  // DNS_STATUS success
                } else {
                    // No matching entries, return name error
                    Dll_Free(path_lwr);
                    return DNS_ERROR_RCODE_NAME_ERROR;
                }
            } else {
                // Pattern matched but no IPs configured - block with NXDOMAIN
                if (DNS_TraceFlag) {
                    WCHAR msg[1024];
                    Sbie_snwprintf(msg, 1024, L"DnsApi Request Blocked: %s (Type: %s) - No IP configured, returning NXDOMAIN",
                        pszName, (wType == DNS_TYPE_AAAA) ? L"AAAA" : L"A");
                    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
                }
                
                Dll_Free(path_lwr);
                return DNS_ERROR_RCODE_NAME_ERROR;
            }
        }

        Dll_Free(path_lwr);
    }

    // Call original DnsQuery_W
    DNS_STATUS status = __sys_DnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);

    if (DNS_TraceFlag && pszName) {
        WCHAR msg[1024];
        Sbie_snwprintf(msg, 1024, L"DnsApi Request: %s (Type: %d, Status: %d)",
            pszName, wType, status);
        
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

    return status;
}

//---------------------------------------------------------------------------
// DNSAPI_DnsQuery_A
//
// Hook for DnsQuery_A (ANSI version) - converts to wide and calls DnsQuery_W hook
//---------------------------------------------------------------------------

_FX DNS_STATUS DNSAPI_DnsQuery_A(
    PCSTR           pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNSAPI_DNS_RECORD* ppQueryResults,
    PVOID*          pReserved)
{
    // For filtering, convert to wide and use shared filter logic
    if (DNS_FilterEnabled && pszName && (wType == DNS_TYPE_A || wType == DNS_TYPE_AAAA)) {
        int nameLen = MultiByteToWideChar(CP_ACP, 0, pszName, -1, NULL, 0);
        if (nameLen > 0) {
            WCHAR* wName = (WCHAR*)Dll_AllocTemp(nameLen * sizeof(WCHAR));
            if (wName) {
                MultiByteToWideChar(CP_ACP, 0, pszName, -1, wName, nameLen);
                
                ULONG path_len = wcslen(wName);
                WCHAR* path_lwr = (WCHAR*)Dll_AllocTemp((path_len + 4) * sizeof(WCHAR));
                wmemcpy(path_lwr, wName, path_len);
                path_lwr[path_len] = L'\0';
                _wcslwr(path_lwr);

                if (DNS_IsExcluded(path_lwr)) {
                    if (DNS_TraceFlag) {
                        WCHAR msg[512];
                        Sbie_snwprintf(msg, 512, L"DNS Exclusion: Domain '%s' matched exclusion list, skipping filter", path_lwr);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                    }
                    // Note: path_lwr and wName are from Dll_AllocTemp - they auto-clear, no explicit free needed
                    return __sys_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
                }

                PATTERN* found;
                if (Pattern_MatchPathList(path_lwr, path_len, &DNS_FilterList, NULL, NULL, NULL, &found) > 0) {
                    PVOID* aux = Pattern_Aux(found);
                    LIST* pEntries = (LIST*)*aux;

                    if (pEntries) {
                        // Build DNS_RECORD linked list using wide domain name
                        PDNSAPI_DNS_RECORD pRecords = DNSAPI_BuildDnsRecordList(wName, wType, pEntries);
                        
                        if (pRecords) {
                            *ppQueryResults = pRecords;
                            
                            if (DNS_TraceFlag) {
                                WCHAR msg[1024];
                                Sbie_snwprintf(msg, 1024, L"DnsApi Request Intercepted (A): %S (Type: %s) - Using filtered response",
                                    pszName, (wType == DNS_TYPE_AAAA) ? L"AAAA" : L"A");
                                SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
                            }
                            
                            // Note: path_lwr and wName are from Dll_AllocTemp - they auto-clear, no explicit free needed
                            return 0;
                        } else {
                            // Note: path_lwr and wName are from Dll_AllocTemp - they auto-clear, no explicit free needed
                            return DNS_ERROR_RCODE_NAME_ERROR;
                        }
                    }
                }

                // Note: path_lwr and wName are from Dll_AllocTemp - they auto-clear, no explicit free needed
            }
        }
    }

    // Call original DnsQuery_A
    DNS_STATUS status = __sys_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);

    if (DNS_TraceFlag && pszName) {
        WCHAR msg[1024];
        Sbie_snwprintf(msg, 1024, L"DnsApi Request (A): %S (Type: %d, Status: %d)",
            pszName, wType, status);
        
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

    return status;
}

//---------------------------------------------------------------------------
// DNSAPI_DnsQuery_UTF8
//
// Hook for DnsQuery_UTF8 - same logic as ANSI version but UTF-8 encoded input
//---------------------------------------------------------------------------

_FX DNS_STATUS DNSAPI_DnsQuery_UTF8(
    PCSTR           pszName,
    WORD            wType,
    DWORD           Options,
    PVOID           pExtra,
    PDNSAPI_DNS_RECORD* ppQueryResults,
    PVOID*          pReserved)
{
    if (DNS_FilterEnabled && pszName && (wType == DNS_TYPE_A || wType == DNS_TYPE_AAAA)) {
        int nameLen = MultiByteToWideChar(CP_UTF8, 0, pszName, -1, NULL, 0);
        if (nameLen > 0) {
            WCHAR* wName = (WCHAR*)Dll_AllocTemp(nameLen * sizeof(WCHAR));
            if (wName && MultiByteToWideChar(CP_UTF8, 0, pszName, -1, wName, nameLen)) {
                ULONG path_len = wcslen(wName);
                WCHAR* path_lwr = (WCHAR*)Dll_AllocTemp((path_len + 4) * sizeof(WCHAR));
                wmemcpy(path_lwr, wName, path_len);
                path_lwr[path_len] = L'\0';
                _wcslwr(path_lwr);

                if (DNS_IsExcluded(path_lwr)) {
                    if (DNS_TraceFlag) {
                        WCHAR msg[512];
                        Sbie_snwprintf(msg, 512, L"DNS Exclusion: Domain '%s' matched exclusion list, skipping filter", path_lwr);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                    }
                    return __sys_DnsQuery_UTF8 ? __sys_DnsQuery_UTF8(pszName, wType, Options, pExtra, ppQueryResults, pReserved)
                                              : __sys_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
                }

                PATTERN* found;
                if (Pattern_MatchPathList(path_lwr, path_len, &DNS_FilterList, NULL, NULL, NULL, &found) > 0) {
                    PVOID* aux = Pattern_Aux(found);
                    LIST* pEntries = (LIST*)*aux;

                    if (pEntries) {
                        PDNSAPI_DNS_RECORD pRecords = DNSAPI_BuildDnsRecordList(wName, wType, pEntries);
                        if (pRecords) {
                            *ppQueryResults = pRecords;
                            if (DNS_TraceFlag) {
                                WCHAR msg[1024];
                                Sbie_snwprintf(msg, 1024, L"DnsApi Request Intercepted (UTF8): %S (Type: %s) - Using filtered response",
                                    pszName, (wType == DNS_TYPE_AAAA) ? L"AAAA" : L"A");
                                SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
                            }
                            return 0;
                        }
                        return DNS_ERROR_RCODE_NAME_ERROR;
                    }

                    if (DNS_TraceFlag) {
                        WCHAR msg[1024];
                        Sbie_snwprintf(msg, 1024, L"DnsApi Request Blocked (UTF8): %S (Type: %s) - Returning NXDOMAIN",
                            pszName, (wType == DNS_TYPE_AAAA) ? L"AAAA" : L"A");
                        SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
                    }
                    return DNS_ERROR_RCODE_NAME_ERROR;
                }
            }
        }
    }

    if (__sys_DnsQuery_UTF8)
        return __sys_DnsQuery_UTF8(pszName, wType, Options, pExtra, ppQueryResults, pReserved);

    return __sys_DnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
}

//---------------------------------------------------------------------------
// DnsQueryEx hooks (modern asynchronous API)
//---------------------------------------------------------------------------

_FX DNS_STATUS DNSAPI_DnsQueryEx(
    PDNS_QUERY_REQUEST_W    pQueryRequest,
    PDNS_QUERY_RESULT       pQueryResults,
    PDNS_QUERY_CANCEL       pCancelHandle)
{
    DNSAPI_EX_FILTER_RESULT outcome;
    if (DNSAPI_HandleDnsQueryExRequestW(L"DnsQueryEx", pQueryRequest, pQueryResults, pCancelHandle, &outcome))
        return outcome.IsAsync ? DNS_REQUEST_PENDING : outcome.Status;

    if (__sys_DnsQueryEx)
        return __sys_DnsQueryEx(pQueryRequest, pQueryResults, pCancelHandle);

    if (__sys_DnsQueryExW)
        return __sys_DnsQueryExW(pQueryRequest, pQueryResults, pCancelHandle);

    return DNS_ERROR_RCODE_NAME_ERROR;
}

_FX DNS_STATUS DNSAPI_DnsQueryExW(
    PDNS_QUERY_REQUEST_W    pQueryRequest,
    PDNS_QUERY_RESULT       pQueryResults,
    PDNS_QUERY_CANCEL       pCancelHandle)
{
    DNSAPI_EX_FILTER_RESULT outcome;
    if (DNSAPI_HandleDnsQueryExRequestW(L"DnsQueryExW", pQueryRequest, pQueryResults, pCancelHandle, &outcome))
        return outcome.IsAsync ? DNS_REQUEST_PENDING : outcome.Status;

    if (__sys_DnsQueryExW)
        return __sys_DnsQueryExW(pQueryRequest, pQueryResults, pCancelHandle);

    if (__sys_DnsQueryEx)
        return __sys_DnsQueryEx(pQueryRequest, pQueryResults, pCancelHandle);

    return DNS_ERROR_RCODE_NAME_ERROR;
}

_FX DNS_STATUS DNSAPI_DnsQueryExA(
    PDNS_QUERY_REQUEST_A    pQueryRequest,
    PDNS_QUERY_RESULT       pQueryResults,
    PDNS_QUERY_CANCEL       pCancelHandle)
{
    DNSAPI_EX_FILTER_RESULT outcome;
    if (DNSAPI_HandleDnsQueryExRequestMultiByte(L"DnsQueryExA", pQueryRequest, pQueryResults, pCancelHandle, CP_ACP, &outcome))
        return outcome.IsAsync ? DNS_REQUEST_PENDING : outcome.Status;

    if (__sys_DnsQueryExA)
        return __sys_DnsQueryExA(pQueryRequest, pQueryResults, pCancelHandle);

    return DNS_ERROR_RCODE_NAME_ERROR;
}

_FX DNS_STATUS DNSAPI_DnsQueryExUTF8(
    PDNS_QUERY_REQUEST_UTF8 pQueryRequest,
    PDNS_QUERY_RESULT       pQueryResults,
    PDNS_QUERY_CANCEL       pCancelHandle)
{
    DNSAPI_EX_FILTER_RESULT outcome;
    if (DNSAPI_HandleDnsQueryExRequestMultiByte(L"DnsQueryExUTF8", pQueryRequest, pQueryResults, pCancelHandle, CP_UTF8, &outcome))
        return outcome.IsAsync ? DNS_REQUEST_PENDING : outcome.Status;

    if (__sys_DnsQueryExUTF8)
        return __sys_DnsQueryExUTF8(pQueryRequest, pQueryResults, pCancelHandle);

    return DNS_ERROR_RCODE_NAME_ERROR;
}

//---------------------------------------------------------------------------
// DNSAPI_DnsRecordListFree
//
// Hook for DnsRecordListFree - ensures proper cleanup of filtered records
//---------------------------------------------------------------------------

_FX VOID DNSAPI_DnsRecordListFree(
    PVOID           pRecordList,
    INT             FreeType)
{
    if (DNS_TraceFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"DnsApi RecordListFree called (List: %p, Type: %d)", pRecordList, FreeType);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // Call original DnsRecordListFree
    __sys_DnsRecordListFree(pRecordList, FreeType);
}

