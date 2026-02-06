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

#ifndef DNS_FILTER_UTIL_H
#define DNS_FILTER_UTIL_H

#include <windows.h>
#include <windns.h>

#include "dns_filter.h"
#include "dnsapi_defs.h"
#include "dns_doh.h"   // DOH_RESULT
#include "dns_logging.h" // DNS_PASSTHROUGH_REASON

#ifdef __cplusplus
extern "C" {
#endif

// Internal helper for DnsQueryRaw passthrough (moved out of dns_filter.c)
// If has_do_flag=TRUE, appends EDNS OPT record with DO flag (for DNSSEC)
int DNS_BuildSimpleQuery(
    const WCHAR* domain,
    USHORT qtype,
    BYTE* buffer,
    int bufferSize,
    BOOLEAN has_do_flag);

// Builds a DNS_RECORD linked list from IP_ENTRY list.
PDNSAPI_DNS_RECORD DNSAPI_BuildDnsRecordList(
    const WCHAR* domainName,
    WORD wType,
    LIST* pEntries,
    DNS_CHARSET CharSet,
    const DOH_RESULT* pDohResult);

// Extended type-filter decision helper (used internally by dns_filter.c)
BOOLEAN DNS_IsTypeInFilterListEx(
    const DNS_TYPE_FILTER* type_filter,
    USHORT query_type,
    DNS_PASSTHROUGH_REASON* pReason);

// Returns TRUE if domain is a single-label name (no dots, trailing dot ignored)
BOOLEAN DNS_IsSingleLabelDomain(const WCHAR* domain);

#ifdef __cplusplus
}
#endif

#endif // DNS_FILTER_UTIL_H
