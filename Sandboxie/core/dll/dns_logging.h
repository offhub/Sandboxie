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

#ifndef _DNS_LOGGING_H
#define _DNS_LOGGING_H

#include <windows.h>
#include <windns.h>
#include "dnsapi_defs.h"
#include "dns_encrypted.h"
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
// Debug Logging Macros
//
// Use these macros for conditional logging to reduce code verbosity.
// DNS_TRACE_LOG: For tracing DNS operations (DnsTrace=y)
// DNS_DEBUG_LOG: For detailed debug output (DnsDebug=y)
//---------------------------------------------------------------------------

// Trace logging: Format and output message if DNS_TraceFlag is set
// Usage: DNS_TRACE_LOG(L"[Prefix] Domain %s resolved", domain);
#define DNS_TRACE_LOG(fmt, ...) \
    do { \
        if (DNS_TraceFlag) { \
            WCHAR _dns_log_buf[512]; \
            Sbie_snwprintf(_dns_log_buf, 512, fmt, ##__VA_ARGS__); \
            SbieApi_MonitorPutMsg(MONITOR_DNS, _dns_log_buf); \
        } \
    } while (0)

// Debug logging:
// - Debug builds: enabled when DNS_DebugFlag is set
// - Release builds: compiled out (no flag checks, no formatting cost)
#if defined(_DNSDEBUG)
#define DNS_DEBUG_LOG(fmt, ...) \
    do { \
        if (DNS_DebugFlag) { \
            WCHAR _dns_log_buf[512]; \
            Sbie_snwprintf(_dns_log_buf, 512, fmt, ##__VA_ARGS__); \
            SbieApi_MonitorPutMsg(MONITOR_DNS, _dns_log_buf); \
        } \
    } while (0)
#else
#define DNS_DEBUG_LOG(fmt, ...) \
    do { (void)0; } while (0)
#endif

// Combined trace/debug logging:
// - Debug builds: logs if either trace or debug is enabled
// - Release builds: logs only when trace is enabled (debug compiled out)
#if defined(_DNSDEBUG)
#define DNS_LOG_IF_ENABLED(fmt, ...) \
    do { \
        if (DNS_TraceFlag || DNS_DebugFlag) { \
            WCHAR _dns_log_buf[512]; \
            Sbie_snwprintf(_dns_log_buf, 512, fmt, ##__VA_ARGS__); \
            SbieApi_MonitorPutMsg(MONITOR_DNS, _dns_log_buf); \
        } \
    } while (0)
#else
#define DNS_LOG_IF_ENABLED(fmt, ...) \
    do { \
        if (DNS_TraceFlag) { \
            WCHAR _dns_log_buf[512]; \
            Sbie_snwprintf(_dns_log_buf, 512, fmt, ##__VA_ARGS__); \
            SbieApi_MonitorPutMsg(MONITOR_DNS, _dns_log_buf); \
        } \
    } while (0)
#endif

//---------------------------------------------------------------------------
// DNS Logging Configuration
//---------------------------------------------------------------------------

// Load SuppressDnsLog setting (called during initialization)
BOOLEAN DNS_LoadSuppressLogSetting(void);

// Query SuppressDnsLog effective state
BOOLEAN DNS_IsSuppressLogEnabled(void);

// Suppress duplicate domain-tagged trace logs using the shared DNS suppression cache.
// This is used by modules outside dns_logging.c (e.g., DNS rebind protection) so
// they share the same TTL/cache as core DNS query logging.
BOOLEAN DNS_ShouldSuppressLogTagged(const WCHAR* domain, ULONG tag);

//---------------------------------------------------------------------------
// Passthrough Reason Codes
//
// Used to indicate why a DNS query was passed through to real DNS
//---------------------------------------------------------------------------

typedef enum _DNS_PASSTHROUGH_REASON {
    DNS_PASSTHROUGH_NONE = 0,           // No specific reason (normal passthrough)
    DNS_PASSTHROUGH_NO_MATCH,           // Domain not in filter list
    DNS_PASSTHROUGH_EXCLUDED,           // Domain matched exclusion list
    DNS_PASSTHROUGH_NO_CERT,            // Domain matched but no valid certificate
    DNS_PASSTHROUGH_TYPE_NOT_FILTERED,  // Type not in filter list
    DNS_PASSTHROUGH_TYPE_NEGATED,       // Type explicitly negated in filter
    DNS_PASSTHROUGH_CONFIG_ERROR,       // Configuration error (no aux data)
    DNS_PASSTHROUGH_UNSUPPORTED_TYPE,   // Type not A/AAAA (let encrypted DNS handle)
} DNS_PASSTHROUGH_REASON;

// Get reason string for passthrough logging
const WCHAR* DNS_GetPassthroughReasonString(DNS_PASSTHROUGH_REASON reason);

//---------------------------------------------------------------------------
// General DNS logging functions
//---------------------------------------------------------------------------

// Log a simple DNS message with domain and type
void DNS_LogSimple(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* suffix);

// Log DNS domain matched exclusion list
void DNS_LogExclusion(const WCHAR* domain);

// Log DNS request with IP addresses (intercepted)
// is_encdns: TRUE = EncDns resolution (MONITOR_OPEN), FALSE = filter interception (MONITOR_DENY)
void DNS_LogIntercepted(const WCHAR* prefix, const WCHAR* domain, WORD wType, LIST* pEntries, BOOLEAN is_encdns);

// Log DNS request blocked
void DNS_LogBlocked(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* reason);

// Log DNS intercepted with NODATA (domain exists, no records for this type)
void DNS_LogInterceptedNoData(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* reason);

// Log passthrough to real DNS
void DNS_LogPassthrough(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* reason);

// Log type filter passthrough (negated types)
void DNS_LogTypeFilterPassthrough(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* reason);

// Log passthrough for ANSI domain names
void DNS_LogPassthroughAnsi(const WCHAR* prefix, const CHAR* domainAnsi, WORD wType, const WCHAR* reason);

// Log DNS response from DNS_RECORD list
void DNS_LogDnsRecords(const WCHAR* prefix, const WCHAR* domain, WORD wType, 
                       PDNSAPI_DNS_RECORD pRecords, const WCHAR* suffix, BOOLEAN is_passthrough);

// Log DNS response from DNS_RECORD list with passthrough reason
void DNS_LogDnsRecordsWithReason(const WCHAR* prefix, const WCHAR* domain, WORD wType,
                                 PDNSAPI_DNS_RECORD pRecords, DNS_PASSTHROUGH_REASON reason);

//---------------------------------------------------------------------------
// DnsQuery-specific logging
//---------------------------------------------------------------------------

// Log DnsQuery passthrough results (without reason)
void DNS_LogDnsQueryResult(const WCHAR* sourceTag, const WCHAR* domain, WORD wType,
                           DNS_STATUS status, PDNSAPI_DNS_RECORD* ppQueryResults);

// Log DnsQuery passthrough results with reason
void DNS_LogDnsQueryResultWithReason(const WCHAR* sourceTag, const WCHAR* domain, WORD wType,
                                     DNS_STATUS status, PDNSAPI_DNS_RECORD* ppQueryResults,
                                     DNS_PASSTHROUGH_REASON reason);

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

void DNS_LogRawSocketNoData(const WCHAR* protocol, const WCHAR* domain, WORD wType,
                            const WCHAR* func_suffix);

// Log when EncDns returns a raw wire-format response used by raw socket DNS interception.
// This is especially relevant for non-A/AAAA query types (e.g., ANY, TXT, MX) where we
// return the raw response bytes from the encrypted DNS backend.
void DNS_LogRawSocketEncDnsRawResponse(const WCHAR* protocol, const WCHAR* domain, WORD wType,
                                      ENCRYPTED_DNS_MODE protocol_used, int response_len);

void DNS_LogRawSocketDebug(const WCHAR* protocol, const WCHAR* domain, WORD wType,
                           int query_len, int response_len, const WCHAR* func_suffix, 
                           SOCKET s);

//---------------------------------------------------------------------------
// WSALookupService-specific logging
//---------------------------------------------------------------------------

// Log WSALookupService result - for both EncDns and filter-based responses
// is_encdns: TRUE for EncDns-based resolution (shows "Resolved", MONITOR_OPEN)
//         FALSE for filter-based response (shows "Filtered", MONITOR_DENY)
void WSA_LogIntercepted(const WCHAR* domain, LPGUID lpGuid, DWORD dwNameSpace, 
                       HANDLE handle, BOOLEAN is_blocked, LIST* pEntries, BOOLEAN is_encdns, ENCRYPTED_DNS_MODE protocol_used);

void WSA_LogPassthrough(const WCHAR* domain, LPGUID lpGuid, DWORD dwNameSpace, 
                       HANDLE handle, int errCode, WORD actualQueryType);

void WSA_LogTypeFilterPassthrough(const WCHAR* domain, USHORT query_type, const WCHAR* reason);

void WSA_FormatGuid(LPGUID lpGuid, WCHAR* buffer, SIZE_T bufferSize);

BOOLEAN WSA_IsIPv6Query(LPGUID lpServiceClassId);

//---------------------------------------------------------------------------
// GetAddrInfo-specific logging (WinHTTP, curl, etc.)
//---------------------------------------------------------------------------

// Log GetAddrInfo* query result - for both EncDns and filter-based responses
// is_encdns: TRUE for EncDns-based resolution (shows "Resolved", MONITOR_OPEN)
//         FALSE for filter-based response (shows "Filtered", MONITOR_DENY)
void GAI_LogIntercepted(const WCHAR* funcName, const WCHAR* domain, int family, LIST* pEntries, BOOLEAN is_encdns);

// Log GetAddrInfo* blocked (NXDOMAIN)
void GAI_LogBlocked(const WCHAR* funcName, const WCHAR* domain, int family);

// Log GetAddrInfo* passthrough to system DNS
void GAI_LogPassthrough(const WCHAR* funcName, const WCHAR* domain, int family, const WCHAR* reason);

// Log GetAddrInfo* passthrough with resolved IPs (system DNS)
void GAI_LogPassthroughWithEntries(const WCHAR* funcName, const WCHAR* domain, int family, LIST* pEntries, const WCHAR* reason);

// Log GetAddrInfo* NODATA response (domain exists but no records for requested type)
void GAI_LogNoData(const WCHAR* funcName, const WCHAR* domain, int family);

// Debug: Log GetAddrInfo* function entry
void GAI_LogDebugEntry(const WCHAR* funcName, const WCHAR* domain, const WCHAR* service, int family);

// Debug: Log GetAddrInfo* function entry with hints details (flags, socktype, protocol)
// pHints should point to an ADDRINFOW or compatible struct (first 4 int fields match ADDRINFOEXW).
void GAI_LogDebugEntryEx(const WCHAR* funcName, const WCHAR* domain, const WCHAR* service, int family, const void* pHints);

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
void DNS_LogExclusionInitDefault(const WCHAR* label, const WCHAR* value);

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
