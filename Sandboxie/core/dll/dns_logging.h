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

#ifndef _DNS_LOGGING_H
#define _DNS_LOGGING_H

#include <windows.h>
#include <windns.h>
#include "dnsapi_defs.h"
#include "common/my_wsa.h"

//---------------------------------------------------------------------------
// DNS Logging Module
//
// Provides centralized logging functionality for DNS filtering operations.
// All DNS-related logging functions have been moved here to separate
// concerns and improve code organization.
//---------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------------
// External dependencies (must be provided by caller)
//---------------------------------------------------------------------------

// Forward declare types used in signatures to avoid heavy includes
typedef struct _IP_ADDRESS IP_ADDRESS;
struct _IP_ENTRY;

// DNS filter state flags (from dns_filter.c)
extern BOOLEAN DNS_TraceFlag;
extern BOOLEAN DNS_DebugFlag;

// DNS query type name resolver (from dns_filter.c)
const WCHAR* DNS_GetTypeName(WORD wType);

// Utility functions (from net.c)
void WSA_DumpIP(ADDRESS_FAMILY af, IP_ADDRESS* pIP, wchar_t* pStr);

//---------------------------------------------------------------------------
// General DNS logging functions
//---------------------------------------------------------------------------

// Log a simple DNS message with domain and type
void DNS_LogSimple(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* suffix);

// Log DNS domain matched exclusion list
void DNS_LogExclusion(const WCHAR* domain);

// Log DNS request with IP addresses (intercepted)
void DNS_LogIntercepted(const WCHAR* prefix, const WCHAR* domain, WORD wType, LIST* pEntries);

// Log DNS request blocked
void DNS_LogBlocked(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* reason);

// Log passthrough to real DNS
void DNS_LogPassthrough(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* reason);

// Log type filter passthrough (negated types)
void DNS_LogTypeFilterPassthrough(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* reason);

// Log passthrough for ANSI domain names
void DNS_LogPassthroughAnsi(const WCHAR* prefix, const CHAR* domainAnsi, WORD wType, const WCHAR* reason);

// Log DNS response from DNS_RECORD list
void DNS_LogDnsRecords(const WCHAR* prefix, const WCHAR* domain, WORD wType, 
                       PDNSAPI_DNS_RECORD pRecords, const WCHAR* suffix, BOOLEAN is_passthrough);

//---------------------------------------------------------------------------
// DnsQuery-specific logging
//---------------------------------------------------------------------------

// Log DnsQuery passthrough results
void DNS_LogDnsQueryResult(const WCHAR* sourceTag, const WCHAR* domain, WORD wType,
                           DNS_STATUS status, PDNSAPI_DNS_RECORD* ppQueryResults);

// Log DnsQueryEx status (PENDING, error, no records)
void DNS_LogDnsQueryExStatus(const WCHAR* prefix, const WCHAR* domain, WORD wType, DNS_STATUS status);

// Log DNS_RECORD results with IP addresses (async callbacks)
void DNS_LogDnsRecordsFromQueryResult(const WCHAR* prefix, const WCHAR* domain, WORD wType,
                                      DNS_STATUS status, PDNSAPI_DNS_RECORD pRecords);

//---------------------------------------------------------------------------
// Raw socket DNS logging (used by socket_hooks.c)
//---------------------------------------------------------------------------

void DNS_LogRawSocketIntercepted(const WCHAR* protocol, const WCHAR* domain, WORD wType,
                                  LIST* pEntries, const WCHAR* func_suffix);

void DNS_LogRawSocketBlocked(const WCHAR* protocol, const WCHAR* domain, WORD wType,
                             const WCHAR* reason, const WCHAR* func_suffix);

void DNS_LogRawSocketDebug(const WCHAR* protocol, const WCHAR* domain, WORD wType,
                           int query_len, int response_len, const WCHAR* func_suffix, 
                           SOCKET s);

//---------------------------------------------------------------------------
// WSALookupService-specific logging
//---------------------------------------------------------------------------

void WSA_LogIntercepted(const WCHAR* domain, LPGUID lpGuid, DWORD dwNameSpace, 
                       HANDLE handle, BOOLEAN is_blocked, LIST* pEntries);

void WSA_LogPassthrough(const WCHAR* domain, LPGUID lpGuid, DWORD dwNameSpace, 
                       HANDLE handle, int errCode, WORD actualQueryType);

void WSA_LogTypeFilterPassthrough(const WCHAR* domain, USHORT query_type);

void WSA_FormatGuid(LPGUID lpGuid, WCHAR* buffer, SIZE_T bufferSize);

BOOLEAN WSA_IsIPv6Query(LPGUID lpServiceClassId);

//---------------------------------------------------------------------------
// Debug logging helpers
//---------------------------------------------------------------------------

void DNS_LogDebug(const WCHAR* message);

void DNS_FormatIPv4(WCHAR* buffer, size_t bufSize, const BYTE* ipData);

void DNS_LogIPEntry(const struct _IP_ENTRY* entry);

void DNS_LogWSAFillStart(BOOLEAN isIPv6, SIZE_T ipCount, void* listHead);

void DNS_LogWSALookupCall(HANDLE hLookup, DWORD bufSize, BOOLEAN noMore, void* pEntries);

void DNS_LogWSAFillFailure(HANDLE hLookup, DWORD error, DWORD bufSize);

void DNS_LogQueryExPointers(const WCHAR* funcName, void* pQueryRequest, void* pQueryResults,
                            DWORD version, void* queryName);

// Exclusion initialization logging (avoid dependency on internal struct)
void DNS_LogExclusionInit(const WCHAR* image_name, const WCHAR* value);

// Configuration/initialization logging (replaces direct SbieApi_MonitorPutMsg calls)
void DNS_LogConfigNoMatchingFilter(const WCHAR* domain);
void DNS_LogConfigWildcardFound(const WCHAR* domain);
void DNS_LogConfigNegatedWildcard(const WCHAR* domain);
void DNS_LogConfigNegatedType(const WCHAR* type, const WCHAR* domain);
void DNS_LogConfigInvalidType(const WCHAR* type, const WCHAR* domain);
void DNS_LogConfigTypeFilterApplied(const WCHAR* domain, const WCHAR* types_str, USHORT type_count, ULONG applied_count, BOOLEAN has_wildcard);
void DNS_LogConfigDnsTraceEnabled(void);
void DNS_LogConfigFilterError(const WCHAR* domain);

// Internal debug logging
void DNS_LogDebugCleanupStaleHandle(ULONGLONG age);
void DNS_LogDebugExclusionCheck(const WCHAR* domain, const WCHAR* image, ULONG count);
void DNS_LogDebugExclusionPerImageList(const WCHAR* image, ULONG pattern_count);
void DNS_LogDebugExclusionGlobalList(ULONG pattern_count);
void DNS_LogDebugExclusionTestPattern(ULONG index, const WCHAR* pattern);
void DNS_LogDebugExclusionMatch(const WCHAR* domain, const WCHAR* pattern);
void DNS_LogDebugExclusionFromQueryEx(const WCHAR* sourceTag, const WCHAR* domain);
void DNS_LogDebugDnsApiRecordFree(PVOID pRecordList, INT FreeType, BOOLEAN isSbie);
void DNS_LogDebugDnsApiRawResultFree(PVOID pQueryResults);

// DnsQueryEx debug logging helpers
void DNS_LogQueryExInvalidVersion(DWORD version);
void DNS_LogQueryExVersion3(BOOLEAN isNetworkQueryRequired, DWORD networkIndex, DWORD cServers, void* pServers);
void DNS_LogQueryExEntry(const WCHAR* queryName, WORD queryType, DWORD version, ULONG64 options, DWORD interfaceIndex, BOOLEAN hasCallback);
void DNS_LogQueryExCorruptOptions(ULONG64 corruptOptions);
void DNS_LogQueryExStrippedFlags(const WCHAR* context, ULONG64 before, ULONG64 after);
void DNS_LogQueryExProactiveSanitize(ULONG64 original, ULONG64 sanitized);  // Pre-call sanitization
void DNS_LogQueryExErrorRetryReduction(const WCHAR* reason, ULONG64 before, ULONG64 after);  // On-error retry
void DNS_LogQueryExRetryInterface(DWORD originalIndex);
void DNS_LogQueryExDebugStatus(DNS_STATUS status, void* asyncCtx, void* pQueryResults, void* pQueryRecords, DWORD version);

// WSALookupService debug logging
void DNS_LogWSADebugResponse(const WCHAR* domain, DWORD nameSpace, BOOLEAN isIPv6, HANDLE handle,
                             DWORD addrCount, DWORD blobSize, void* csaBuffer, DWORD csaBufferCount);
void DNS_LogWSADebugRequestEnd(HANDLE handle, BOOLEAN filtered);

// WSALookupService passthrough result logging
void DNS_LogWSAPassthroughResult(const WCHAR* domain, DWORD nameSpace, WORD queryType, 
                                  void* lpqsResults);
void DNS_LogWSAPassthroughCSADDR(int index, ADDRESS_FAMILY got_af, ADDRESS_FAMILY expect_af, BOOLEAN match);
void DNS_LogWSAPassthroughHOSTENT(ADDRESS_FAMILY h_addrtype, ADDRESS_FAMILY expect_af, BOOLEAN match);
void DNS_LogWSAPassthroughInvalidHostent(ADDRESS_FAMILY h_addrtype);

#ifdef __cplusplus
}
#endif

#endif // _DNS_LOGGING_H
