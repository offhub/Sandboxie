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

BOOLEAN WSA_InitNetDnsFilter(HMODULE module);
BOOLEAN DNSAPI_Init(HMODULE module);
BOOLEAN DNS_IsExcluded(const WCHAR* domain);

#ifdef __cplusplus
}
#endif

#endif // DNS_FILTER_H