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

#ifndef _DNSAPI_FILTER_H
#define _DNSAPI_FILTER_H

//---------------------------------------------------------------------------
// DnsApi Filter Documentation
//
// The DNSAPI_Init function (in dns_filter.c) provides DNS query filtering
// for the Windows DnsApi (dnsapi.dll).
//
// This header provides type definitions for DnsApi filtering. The actual
// implementation remains in dns_filter.c due to tight coupling with shared
// filter infrastructure (filter lists, system function pointers, lookup maps).
//
// Hooked Functions:
//   - DnsQuery_A, DnsQuery_W, DnsQuery_UTF8 (standard DNS query APIs)
//   - DnsQueryEx (async DNS query API, Windows Vista+)
//   - DnsQueryRaw (raw DNS wire format API, Windows 10+)
//   - DnsRecordListFree, DnsQueryRawResultFree, DnsCancelQuery (cleanup hooks)
//
// Configuration:
//   FilterDnsApi=[process,]y|n
//     - Boolean: Enable/disable DnsApi hooking (default: y)
//     - Per-process support: FilterDnsApi=chrome.exe,n
//     - When disabled: No DnsQuery* hooks installed
//
// Integration:
//   - Uses DNS_CheckFilter() from dns_filter.c for domain matching
//   - Uses encrypted DNS from dns_encrypted.c for passthrough queries
//   - Tracing via DnsTrace=y and DnsDebug=y settings
//
// See also:
//   - dnsapi_defs.h: DnsApi type definitions (DNS_RECORD, etc.)
//   - dns_filter.c: DNSAPI_Init and hook implementations
//   - dns_filter.h: Shared DNS filter infrastructure exports
//---------------------------------------------------------------------------

#include <windows.h>
#include <windns.h>

#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------------
// Type Definitions for DnsApi Wire Format Parsing
//---------------------------------------------------------------------------

// Function pointer type for DnsExtractRecordsFromMessage_W
// Used internally by dns_filter.c to parse raw DNS wire format responses
// from encrypted DNS (DoH/DoQ) back into DNS_RECORD structures
typedef DNS_STATUS (WINAPI *P_DnsExtractRecordsFromMessage_W)(
    PDNS_MESSAGE_BUFFER pDnsBuffer,
    WORD wMessageLength,
    PDNS_RECORD* ppRecord,
    PBYTE* ppExtra
);

#ifdef __cplusplus
}
#endif

#endif // _DNSAPI_FILTER_H
