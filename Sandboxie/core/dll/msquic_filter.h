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

#ifndef _MSQUIC_FILTER_H
#define _MSQUIC_FILTER_H

//---------------------------------------------------------------------------
// MsQuic (QUIC Protocol) Connection Filter
//
// This module provides filtering for MsQuic (Microsoft QUIC) connections,
// intercepting QUIC/HTTP3 traffic that bypasses traditional TCP-based
// DNS and connection filtering.
//
// QUIC Protocol Overview:
//   - QUIC (RFC 9000) is a UDP-based transport protocol providing:
//     * Encrypted transport (TLS 1.3 integrated)
//     * Multiplexed streams within single connection
//     * Fast connection establishment (0-RTT)
//     * Connection migration across networks
//   - HTTP/3 uses QUIC as its transport layer
//   - MsQuic is Microsoft's cross-platform QUIC implementation
//
// Why Filter MsQuic:
//   - QUIC traffic bypasses traditional TCP hooks (connect, send, recv)
//   - Applications using HTTP/3 (Chrome, Edge, Firefox) use QUIC
//   - DNS-over-QUIC (DoQ) bypasses DNS filtering on port 53
//   - Without filtering, sandboxed apps can make unrestricted QUIC connections
//
// Interception Strategy:
//   - Hook MsQuicOpenVersion() - the entry point that returns API table
//   - Return modified API table with hooked ConnectionStart()
//   - ConnectionStart() receives ServerName (hostname) and ServerPort
//   - Apply NetworkDnsFilter rules to block/allow connections
//
// Configuration:
//   FilterMsQuic=[process,]y|n[:block|allow]
//     - Enable/disable MsQuic filtering (default: n)
//     - Per-process support: FilterMsQuic=chrome.exe,y
//     - When enabled: Intercepts ConnectionStart() calls
//     - Uses existing NetworkDnsFilter rules for domain filtering
//     - Mode suffix (only when enabled):
//         * block (default): block all matches (even if NetworkDnsFilter rule has IPs)
//         * allow: allow matches in filter:ip mode (legacy/compat behavior)
//       Example: FilterMsQuic=chrome.exe,y:allow
//
// Integration with DNS Filter:
//   - Uses DNS_CheckFilter() from dns_filter.c for domain matching
//   - Block mode: Returns QUIC_STATUS_PERMISSION_DENIED
//   - Filter mode (with IPs): depends on FilterMsQuic mode (cannot redirect/pin IPs in QUIC)
//   - Passthrough: Connection proceeds normally
//
// Tracing:
//   - MsQuic logs are written under the DNS monitor category
//   - Allow/Block/Passthrough logs use DnsTrace=y (DNS_TraceFlag)
//   - Verbose initialization/debug logs use DnsDebug=y (DNS_DebugFlag)
//
// Limitations:
//   - Cannot redirect QUIC connections to different IPs (unlike DNS filtering)
//   - Can only block or allow connections
//   - IP-based rules in NetworkDnsFilter become block rules for QUIC
//
// Example Configuration:
//   NetworkDnsFilter=*.ads.example.com
//   FilterMsQuic=y:block
//   
//   Result: QUIC connections to *.ads.example.com are blocked
//---------------------------------------------------------------------------

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------------
// Public Functions
//---------------------------------------------------------------------------

// DoQ exclusion: Prevent filtering DoQ's own MsQuic usage
void MsQuic_SetDoqInitializing(BOOLEAN initializing);

// Get original (unhooked) MsQuicOpenVersion function pointer
// Returns NULL if MsQuic hooks not initialized
// DoQ uses this to call the real MsQuic API without going through instrumentation
void* MsQuic_GetOriginalOpenVersion(void);

// Initialize MsQuic filter hooks
// Called when msquic.dll is loaded
// Returns TRUE on success, FALSE on failure
BOOLEAN MsQuic_Init(HMODULE module);

// Check if MsQuic filtering is enabled for current process
BOOLEAN MsQuic_IsFilterEnabled(void);

#ifdef __cplusplus
}
#endif

#endif /* _MSQUIC_FILTER_H */
