/*
 * Copyright 2024-2026 David Xanatos, xanasoft.com
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

#ifndef _WINHTTP_FILTER_H
#define _WINHTTP_FILTER_H

//---------------------------------------------------------------------------
// WinHTTP Connection Filter
//
// This module provides filtering for WinHTTP API calls (winhttp.dll),
// intercepting WinHttpConnect() to validate domains against NetworkDnsFilter
// rules before allowing connections.
//
// Configuration:
//   FilterWinHttp=[process,]y|n
//     - Boolean: Enable/disable WinHTTP API hooking (default: n)
//     - Per-process support: FilterWinHttp=updutil.exe,y
//     - When enabled: WinHttpConnect() calls are validated against NetworkDnsFilter rules
//     - Use case: Block malicious update services or telemetry URLs accessed via WinHTTP
//
// Integration:
//   - Uses DNS_CheckFilter() from dns_filter.c for domain matching
//   - Block mode: Returns NULL handle with ERROR_INTERNET_NAME_NOT_RESOLVED
//   - Passthrough: Connection proceeds normally
//   - Tracing: Uses DnsTrace=y (DNS_TraceFlag) for logging
//---------------------------------------------------------------------------

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------------
// Public API
//---------------------------------------------------------------------------

// Initialize WinHTTP filter hooks (called when winhttp.dll is loaded)
// Returns TRUE on success, FALSE on failure
BOOLEAN WinHttp_Init(HMODULE module);

#ifdef __cplusplus
}
#endif

#endif // _WINHTTP_FILTER_H
