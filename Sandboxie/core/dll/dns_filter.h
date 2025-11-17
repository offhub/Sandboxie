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

#ifndef DNS_FILTER_H
#define DNS_FILTER_H

#include <windows.h>
#include "common/list.h"
#include "common/netfw.h"

#ifdef __cplusplus
extern "C" {
#endif

extern LIST    DNS_FilterList;
extern BOOLEAN DNS_FilterEnabled;
extern BOOLEAN DNS_TraceFlag;

typedef struct _IP_ENTRY
{
    LIST_ELEM list_elem;
    USHORT    Type;
    IP_ADDRESS IP;
} IP_ENTRY;

// DNS Type Filter - specifies which DNS record types to filter for a pattern
// If NULL, default behavior applies (filter A/AAAA/ANY only)
#define MAX_DNS_TYPE_FILTERS 32
typedef struct _DNS_TYPE_FILTER
{
    USHORT allowed_types[MAX_DNS_TYPE_FILTERS];  // Array of DNS types to filter (0-terminated)
    USHORT type_count;                            // Number of types in array
} DNS_TYPE_FILTER;

// Auxiliary data stored with each DNS filter pattern
// Contains both IP entries and optional type filter
typedef struct _DNS_FILTER_AUX
{
    LIST* ip_entries;                    // List of IP_ENTRY (NULL for block mode)
    DNS_TYPE_FILTER* type_filter;        // Type filter (NULL = default A/AAAA/ANY)
} DNS_FILTER_AUX;

BOOLEAN WSA_InitNetDnsFilter(HMODULE module);
BOOLEAN DNSAPI_Init(HMODULE module);
BOOLEAN DNS_IsExcluded(const WCHAR* domain);

// DNS Type Filter Helper Functions (used by socket_hooks.c)
BOOLEAN DNS_IsTypeInFilterList(const DNS_TYPE_FILTER* type_filter, USHORT query_type);
BOOLEAN DNS_CanSynthesizeResponse(USHORT query_type);
const WCHAR* DNS_GetTypeName(WORD wType);

#ifdef __cplusplus
}
#endif

#endif // DNS_FILTER_H