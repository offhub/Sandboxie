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
// DNS Logging Module
//
// Centralized DNS logging functionality separated from dns_filter.c
// for better code organization and maintainability.
//---------------------------------------------------------------------------

#include "dll.h"
#include "dns_logging.h"
#include "dns_filter.h"
#include <SvcGuid.h>

// External timing function
ULONGLONG GetTickCount64();

// Suppression state (moved from dns_filter.c)
static BOOLEAN DNS_SuppressLogEnabled = TRUE;
static ULONGLONG DNS_SuppressLogWindowMs = 1000;

#define DNS_DUPLOG_CACHE_SIZE 64
typedef struct _DNS_RECENT_LOG_ENTRY {
    WCHAR       domain[256];
    USHORT      type;
    ULONGLONG   tick;
} DNS_RECENT_LOG_ENTRY;
static DNS_RECENT_LOG_ENTRY DNS_RecentLogs[DNS_DUPLOG_CACHE_SIZE];
static BOOLEAN DNS_RecentLogsInitialized = FALSE;

//---------------------------------------------------------------------------
// Suppression functions
//---------------------------------------------------------------------------

_FX void DNS_InitSuppressLogSettings(BOOLEAN enabled, ULONGLONG windowMs)
{
    DNS_SuppressLogEnabled = enabled;
    DNS_SuppressLogWindowMs = windowMs;
}

_FX void DNS_GetSuppressLogSettings(BOOLEAN* enabled, ULONGLONG* windowMs)
{
    if (enabled) *enabled = DNS_SuppressLogEnabled;
    if (windowMs) *windowMs = DNS_SuppressLogWindowMs;
}

_FX BOOLEAN DNS_ShouldSuppressLog(const WCHAR* domain, USHORT wType)
{
    if (!DNS_TraceFlag || !domain || !*domain)
        return FALSE;
    
    if (!DNS_SuppressLogEnabled)
        return FALSE;

    WCHAR norm[256];
    size_t len = wcslen(domain);
    if (len >= ARRAYSIZE(norm)) len = ARRAYSIZE(norm) - 1;
    wmemcpy(norm, domain, len);
    norm[len] = L'\0';
    _wcslwr(norm);

    if (!DNS_RecentLogsInitialized) {
        memset(DNS_RecentLogs, 0, sizeof(DNS_RecentLogs));
        DNS_RecentLogsInitialized = TRUE;
    }

    ULONGLONG now = GetTickCount64();
    ULONGLONG window = DNS_SuppressLogWindowMs;

    int insertIndex = -1;
    ULONGLONG oldestTick = (ULONGLONG)-1;
    
    for (int i = 0; i < DNS_DUPLOG_CACHE_SIZE; ++i) {
        DNS_RECENT_LOG_ENTRY* e = &DNS_RecentLogs[i];
        
        if (e->tick != 0 && (now - e->tick) <= window) {
            if (e->type == wType && _wcsicmp(e->domain, norm) == 0) {
                return TRUE;
            }
        } else {
            if (insertIndex == -1 || e->tick < oldestTick) {
                oldestTick = e->tick;
                insertIndex = i;
            }
        }
    }
    
    if (insertIndex == -1) {
        insertIndex = 0;
        oldestTick = DNS_RecentLogs[0].tick;
        for (int i = 1; i < DNS_DUPLOG_CACHE_SIZE; ++i) {
            if (DNS_RecentLogs[i].tick < oldestTick) {
                oldestTick = DNS_RecentLogs[i].tick;
                insertIndex = i;
            }
        }
    }
    
    wcsncpy(DNS_RecentLogs[insertIndex].domain, norm, ARRAYSIZE(DNS_RecentLogs[insertIndex].domain) - 1);
    DNS_RecentLogs[insertIndex].domain[ARRAYSIZE(DNS_RecentLogs[insertIndex].domain) - 1] = L'\0';
    DNS_RecentLogs[insertIndex].type = wType;
    DNS_RecentLogs[insertIndex].tick = now;
    return FALSE;
}

//---------------------------------------------------------------------------
// General logging functions
//---------------------------------------------------------------------------

_FX void DNS_LogSimple(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* suffix)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s: %s (Type: %s)%s%s",
        prefix, domain, DNS_GetTypeName(wType),
        suffix ? L" - " : L"",
        suffix ? suffix : L"");
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogExclusion(const WCHAR* domain)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"DNS Exclusion: Domain '%s' matched exclusion list, skipping filter", domain);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogIntercepted(const WCHAR* prefix, const WCHAR* domain, WORD wType, LIST* pEntries)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    WCHAR msg[1024];
    Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s) - Using filtered response",
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
    
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
}

_FX void DNS_LogBlocked(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* reason)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    WCHAR msg[1024];
    Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s) - %s",
        prefix, domain, DNS_GetTypeName(wType), reason);
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
}

_FX void DNS_LogPassthrough(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* reason)
{
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    DNS_LogSimple(prefix, domain, wType, reason);
}

_FX void DNS_LogTypeFilterPassthrough(const WCHAR* prefix, const WCHAR* domain, WORD wType, const WCHAR* reason)
{
    if (!DNS_TraceFlag)
        return;

    if (DNS_ShouldSuppressLog(domain, wType))
        return;

    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s Passthrough: %s (Type: %s) - Type filter: %s", 
        prefix, domain, DNS_GetTypeName(wType), reason);
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_TRACE, msg);
}

_FX void DNS_LogPassthroughAnsi(const WCHAR* prefix, const CHAR* domainAnsi, WORD wType, const WCHAR* reason)
{
    if (!DNS_TraceFlag || !domainAnsi)
        return;
    
    WCHAR domain[256];
    int nameLen = MultiByteToWideChar(CP_ACP, 0, domainAnsi, -1, domain, ARRAYSIZE(domain));
    if (nameLen > 0 && nameLen < (int)ARRAYSIZE(domain)) {
        if (DNS_ShouldSuppressLog(domain, wType))
            return;
    }
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s: %S (Type: %s)%s%s",
        prefix, domainAnsi, DNS_GetTypeName(wType),
        reason ? L" - " : L"",
        reason ? reason : L"");
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

//---------------------------------------------------------------------------
// DNS_RECORD logging
//---------------------------------------------------------------------------

#define MAX_DNS_RECORDS_TO_LOG 20

_FX void DNS_LogDnsRecords(const WCHAR* prefix, const WCHAR* domain, WORD wType, PDNSAPI_DNS_RECORD pRecords, const WCHAR* suffix, BOOLEAN is_passthrough)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
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
    while (pRec && record_count < MAX_DNS_RECORDS_TO_LOG) {
        BOOLEAN type_matches = (pRec->wType == wType) || is_any_query;
        BOOLEAN is_loggable_type = (pRec->wType == DNS_TYPE_A || pRec->wType == DNS_TYPE_AAAA);
        
        if (type_matches && is_loggable_type) {
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
                
                BOOLEAN is_ipv4_mapped = (ip.Data32[0] == 0 && ip.Data32[1] == 0 && ip.Data32[2] == 0xFFFF0000);
                if (!is_ipv4_mapped) {
                    WSA_DumpIP(AF_INET6, &ip, msg);
                } else if (DNS_DebugFlag) {
                    WCHAR debug_msg[256];
                    Sbie_snwprintf(debug_msg, 256, L"    Skipping IPv4-mapped IPv6 address for AAAA query");
                    SbieApi_MonitorPutMsg(MONITOR_DNS, debug_msg);
                }
            } else if (pRec->wType == DNS_TYPE_A) {
                ip.Data32[3] = pRec->Data.A.IpAddress;
                WSA_DumpIP(AF_INET, &ip, msg);
            }
        }
        pRec = pRec->pNext;
        record_count++;
    }
    
    SbieApi_MonitorPutMsg(is_passthrough ? MONITOR_DNS : (MONITOR_DNS | MONITOR_DENY), msg);
}

//---------------------------------------------------------------------------
// DnsQuery-specific logging
//---------------------------------------------------------------------------

static const WCHAR* DNS_GetStatusMessage(DNS_STATUS status);

_FX void DNS_LogDnsQueryResult(const WCHAR* sourceTag, const WCHAR* domain, WORD wType,
                               DNS_STATUS status, PDNSAPI_DNS_RECORD* ppQueryResults)
{
    if (!DNS_TraceFlag || !domain)
        return;

    if (DNS_ShouldSuppressLog(domain, wType))
        return;

    WCHAR msg[1024];
    
    if (status == 0 && ppQueryResults && *ppQueryResults) {
        Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s)",
            sourceTag, domain, DNS_GetTypeName(wType));
    } else {
        const WCHAR* statusMsg = DNS_GetStatusMessage(status);
        if (statusMsg) {
            Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s) - %s",
                sourceTag, domain, DNS_GetTypeName(wType), statusMsg);
        } else {
            Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s) - Status: %d",
                sourceTag, domain, DNS_GetTypeName(wType), status);
        }
    }
    
    if (status == 0 && ppQueryResults && *ppQueryResults) {
        PDNSAPI_DNS_RECORD pRec = *ppQueryResults;
        BOOLEAN is_any_query = (wType == 255);
        int record_count = 0;
        
        while (pRec && record_count < MAX_DNS_RECORDS_TO_LOG) {
            if ((is_any_query || pRec->wType == wType) && 
                (pRec->wType == DNS_TYPE_A || pRec->wType == DNS_TYPE_AAAA)) {
                
                IP_ADDRESS ip;
                memset(&ip, 0, sizeof(ip));
                if (pRec->wType == DNS_TYPE_AAAA) {
                    memcpy(ip.Data, &pRec->Data.AAAA.Ip6Address, 16);
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
    
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogDnsQueryExStatus(const WCHAR* prefix, const WCHAR* domain, WORD wType, DNS_STATUS status)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
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
    
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

_FX void DNS_LogDnsRecordsFromQueryResult(const WCHAR* prefix, const WCHAR* domain, WORD wType,
                                          DNS_STATUS status, PDNSAPI_DNS_RECORD pRecords)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    WCHAR msg[1024];
    Sbie_snwprintf(msg, 1024, L"%s: %s (Type: %s) - Status: %d",
        prefix, domain, DNS_GetTypeName(wType), status);
    
    if (status == 0 && pRecords) {
        PDNSAPI_DNS_RECORD pRec = pRecords;
        BOOLEAN is_any_query = (wType == 255);
        int record_count = 0;
        
        while (pRec && record_count < 10) {
            if ((is_any_query || pRec->wType == wType) && 
                (pRec->wType == DNS_TYPE_A || pRec->wType == DNS_TYPE_AAAA)) {
                
                IP_ADDRESS ip;
                memset(&ip, 0, sizeof(ip));
                if (pRec->wType == DNS_TYPE_AAAA) {
                    memcpy(ip.Data, &pRec->Data.AAAA.Ip6Address, 16);
                    
                    BOOLEAN is_ipv4_mapped = (ip.Data32[0] == 0 && ip.Data32[1] == 0 && ip.Data32[2] == 0xFFFF0000);
                    if (!is_ipv4_mapped) {
                        WSA_DumpIP(AF_INET6, &ip, msg);
                        record_count++;
                    }
                } else {
                    ip.Data32[3] = pRec->Data.A.IpAddress;
                    WSA_DumpIP(AF_INET, &ip, msg);
                    record_count++;
                }
            }
            pRec = pRec->pNext;
        }
    }
    
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

static const WCHAR* DNS_GetStatusMessage(DNS_STATUS status)
{
    switch (status) {
        case 0:                             return L"Success";
        case 9001:                          return L"RCODE_FORMAT_ERROR: DNS server unable to interpret format";
        case 9002:                          return L"RCODE_SERVER_FAILURE: DNS server internal error";
        case 9003:                          return L"RCODE_NAME_ERROR: Domain name does not exist";
        case 9004:                          return L"RCODE_NOT_IMPLEMENTED: DNS server does not support this query type";
        case 9005:                          return L"RCODE_REFUSED: DNS server refused query";
        case 9501:                          return L"No records found (domain exists but no records of this type)";
        case 9502:                          return L"NO_DNS_DATA: Valid name but no data of requested type";
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

_FX void DNS_LogRawSocketDebug(const WCHAR* protocol, const WCHAR* domain, WORD wType,
                                int query_len, int response_len, const WCHAR* func_suffix, 
                                SOCKET s)
{
    if (!DNS_DebugFlag)
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

_FX void WSA_LogIntercepted(const WCHAR* domain, LPGUID lpGuid, DWORD dwNameSpace, HANDLE handle, BOOLEAN is_blocked, LIST* pEntries)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    WORD wType = WSA_IsIPv6Query(lpGuid) ? DNS_TYPE_AAAA : DNS_TYPE_A;
    
    if (DNS_ShouldSuppressLog(domain, wType))
        return;
    
    WCHAR msg[1024];
    if (is_blocked) {
        Sbie_snwprintf(msg, 1024, L"WSALookupService Blocked: %s (Type: %s) - Returning NXDOMAIN",
            domain, DNS_GetTypeName(wType));
    } else {
        Sbie_snwprintf(msg, 1024, L"WSALookupService Intercepted: %s (Type: %s) - Using filtered response",
            domain, DNS_GetTypeName(wType));
        
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
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
    
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
    
    if (domain && DNS_ShouldSuppressLog(domain, wType))
        return;
    
    if (errCode != 0 || DNS_DebugFlag) {
        WCHAR msg[512];
        if (errCode != 0) {
            Sbie_snwprintf(msg, 512, L"WSALookupService Passthrough: %s (Type: %s) - Error %d",
                domain ? domain : L"(unknown)", DNS_GetTypeName(wType), errCode);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
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

_FX void WSA_LogTypeFilterPassthrough(const WCHAR* domain, USHORT query_type)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    if (DNS_ShouldSuppressLog(domain, query_type))
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"WSALookupService Passthrough: %s (Type: %s) - Type not in filter list, forwarding to real DNS",
        domain, query_type == DNS_TYPE_AAAA ? L"AAAA" : L"A");
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
    if (!DNS_DebugFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"WSA_FillResponseStructure: isIPv6=%d, ipCount=%Iu, listHead=%p",
        isIPv6, ipCount, listHead);
    DNS_LogDebug(msg);
}

_FX void DNS_LogWSALookupCall(HANDLE hLookup, DWORD bufSize, BOOLEAN noMore, void* pEntries)
{
    if (!DNS_DebugFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"WSALookupServiceNextW called: Hdl=%p, BufferSize=%d, NoMore=%d, pEntries=%p",
        hLookup, bufSize, noMore, pEntries);
    DNS_LogDebug(msg);
}

_FX void DNS_LogWSAFillFailure(HANDLE hLookup, DWORD error, DWORD bufSize)
{
    if (!DNS_DebugFlag)
        return;
    
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"WSA_FillResponseStructure FAILED: Hdl=%p, Error=%d (0x%X), BufferSize=%d",
        hLookup, error, error, bufSize);
    DNS_LogDebug(msg);
}

_FX void DNS_LogQueryExPointers(const WCHAR* funcName, void* pQueryRequest, void* pQueryResults, DWORD version, void* queryName)
{
    if (!DNS_DebugFlag)
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

