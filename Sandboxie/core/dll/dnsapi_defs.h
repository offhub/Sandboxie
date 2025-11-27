/*
 * Copyright 2022-2025 David Xanatos, xanasoft.com
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
// DnsApi Definitions
//---------------------------------------------------------------------------

#ifndef _DNSAPI_DEFS_H
#define _DNSAPI_DEFS_H

// windns.h is included in dns_filter.c before this header
// All DNS types come from Windows SDK - we only add function pointers

//---------------------------------------------------------------------------
// Type Aliases for compatibility
//---------------------------------------------------------------------------

typedef DNS_RECORD DNSAPI_DNS_RECORD, *PDNSAPI_DNS_RECORD;

// Windows SDK doesn't define pointer typedefs for DnsQueryRaw types - add them
typedef DNS_QUERY_RAW_REQUEST *PDNS_QUERY_RAW_REQUEST;
typedef DNS_QUERY_RAW_RESULT *PDNS_QUERY_RAW_RESULT;
typedef DNS_QUERY_RAW_CANCEL *PDNS_QUERY_RAW_CANCEL;

// Callback function pointer typedef for DnsQueryRaw (matches Windows SDK)
typedef VOID (CALLBACK *DNS_QUERY_RAW_COMPLETION_ROUTINE)(
    VOID*                   queryContext,
    DNS_QUERY_RAW_RESULT*   queryResults);

typedef DNS_QUERY_RAW_COMPLETION_ROUTINE *PDNS_QUERY_RAW_COMPLETION_ROUTINE;

//---------------------------------------------------------------------------
// DnsQuery Function Pointers
//
// Note: DnsQueryEx has no W/A/UTF8 variants in windns.h header - only the
// neutral DnsQueryEx(). However, dnsapi.dll exports separate entry points:
// - DnsQueryExW (real implementation, takes WCHAR)
// - DnsQueryExA (wrapper: converts ANSI → WCHAR, calls W)
// - DnsQueryExUTF8 (wrapper: converts UTF8 → WCHAR, calls W)
//
// We hook all three exports to be safe, though hooking only DnsQueryExW
// would catch most calls since A/UTF8 just convert and forward to W.
//---------------------------------------------------------------------------

typedef DNS_STATUS (WINAPI *P_DnsQuery_A)(
    PCSTR               pszName,
    WORD                wType,
    DWORD               Options,
    PVOID               pExtra,
    PDNS_RECORD*        ppQueryResults,
    PVOID*              pReserved);

typedef DNS_STATUS (WINAPI *P_DnsQuery_W)(
    PCWSTR              pszName,
    WORD                wType,
    DWORD               Options,
    PVOID               pExtra,
    PDNS_RECORD*        ppQueryResults,
    PVOID*              pReserved);

typedef DNS_STATUS (WINAPI *P_DnsQuery_UTF8)(
    PCSTR               pszName,
    WORD                wType,
    DWORD               Options,
    PVOID               pExtra,
    PDNS_RECORD*        ppQueryResults,
    PVOID*              pReserved);

typedef DNS_STATUS (WINAPI *P_DnsQueryEx)(
    PDNS_QUERY_REQUEST  pQueryRequest,
    PDNS_QUERY_RESULT   pQueryResults,
    PDNS_QUERY_CANCEL   pCancelHandle);

typedef VOID (WINAPI *P_DnsRecordListFree)(
    PVOID               pRecordList,
    INT                 FreeType);

typedef DNS_STATUS (WINAPI *P_DnsQueryRaw)(
    PDNS_QUERY_RAW_REQUEST  pRequest,
    PDNS_QUERY_RAW_CANCEL   pCancelHandle);

typedef VOID (WINAPI *P_DnsQueryRawResultFree)(
    PDNS_QUERY_RAW_RESULT   pResult);

typedef DNS_STATUS (WINAPI *P_DnsCancelQuery)(
    PDNS_QUERY_CANCEL       pCancelHandle);

#endif /* _DNSAPI_DEFS_H */
