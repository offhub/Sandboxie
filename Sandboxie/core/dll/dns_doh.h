/*
 * Copyright 2024-2025 David Xanatos, xanasoft.com
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

#ifndef _DNS_DOH_H
#define _DNS_DOH_H

#include <windows.h>
#include <windns.h>
#include "common/netfw.h"  // For IP_ADDRESS type
#include "dns_encrypted.h" // For unified ENCRYPTED_DNS_* types and DOH_* aliases

//---------------------------------------------------------------------------
// Encrypted DNS Client (DoH/DoH2/DoH3/DoQ/DoT)
//
// This module implements encrypted DNS functionality to provide secure DNS
// resolution for passthrough queries. Supports multiple protocols:
//
//   - DoH  (DNS over HTTPS, HTTP/1.1 or HTTP/2) - RFC 8484, TCP 443
//   - DoH2 (DNS over HTTPS, HTTP/2 only) - RFC 8484, TCP 443
//   - DoH3 (DNS over HTTPS, HTTP/3 only, QUIC) - RFC 8484, UDP 443
//   - DoQ  (DNS over QUIC, native) - RFC 9250, UDP 853
//   - DoT  (DNS over TLS, raw) - RFC 7858, TCP 853 (reserved)
//   - Auto (tries DoQ → DoH3 → DoH2 → DoH with fallback and backoff)
//
// Configuration:
//   EncryptedDnsServer=<url>[?mode=<protocol>]
//     - Full server URL (e.g., https://cloudflare-dns.com/dns-query)
//     - Mode parameter selects protocol: ?mode=auto|doh|doh2|doh3|doq|dot
//       * If mode is set (except mode=auto), only that protocol is attempted.
//     - StrictBindIP QUIC control: ?strict=0|1 (default: 1)
//       * When StrictBindIP is active, QUIC protocols (DoQ/DoH3) are normally skipped/blocked.
//       * Use ?strict=0 on a server URL to allow QUIC even when StrictBindIP is enabled.
//     - Default mode by scheme:
//         * https:// / httpx://  → HTTP-only fallback (DoH3 → DoH2 → DoH)
//         * auto:// / autox://  → full AUTO (DoQ → DoH3 → DoH2 → DoH)
//     - Default port by protocol: DoH/DoH2/DoH3: 443, DoQ/DoT: 853
//     - Default path: /dns-query is applied only for DoH-based modes when no path is provided
//     - Supported providers: Cloudflare, Google, Quad9, AdGuard, etc.
//     - Requires a valid certificate
//
// URL Schemes:
//   - https://  - HTTP-only mode (DoH3 → DoH2 → DoH)
//   - httpx://  - HTTP-only mode with self-signed certificate allowed
//   - quic://   - DoQ only (DNS over QUIC, signed certificate)
//   - quicx://  - DoQ only (self-signed certificate allowed)
//   - auto://   - AUTO mode with all protocols (DoQ → DoH3 → DoH2 → DoH, skips QUIC if StrictBindIP)
//   - autox://  - AUTO mode with self-signed certificate
//
// AUTO Mode Fallback:
//   When mode=auto (or auto:// scheme), tries protocols in order with fallback:
//   1. DoQ  (fastest, if MsQuic available and StrictBindIP disabled)
//   2. DoH3 (HTTP/3 over QUIC, if Windows 11 and StrictBindIP disabled)
//   3. DoH2 (HTTP/2, standard HTTPS)
//   4. DoH  (HTTP/1.1 or HTTP/2, final fallback)
//   Failed protocols enter incremental backoff (30s, 60s, 120s, 300s max).
//   StrictBindIP automatically skips DoQ and DoH3 (QUIC incompatible).
//
// Implementation Details:
//   - DoH/DoH2: Uses WinHTTP for HTTPS requests (wire format)
//   - DoH3: Uses WinHTTP on Windows 11 22H2+, not available on Windows 10
//   - DoQ: Uses MsQuic for native QUIC DNS (wire format)
//   - Re-entrancy protection: Prevents infinite loops
//   - Response caching: 300-second default TTL (respects DNS TTL when available)
//   - Supports A and AAAA queries only (consistent with NetworkDnsFilter)
//
// Security:
//   - Certificate validation via WinHTTP/MsQuic
//   - Domain validation against NetworkDnsFilter before query
//   - Prevents interception attacks (original domain in SNI)
//
// Integration Status:
//   ✅ Supported APIs:
//      - GetAddrInfoW (most common, used by browsers/curl/WinHTTP)
//      - DnsQuery_A/W/UTF8 (Windows DNS API - command-line tools, legacy apps)
//      - DnsQueryEx (Modern async DNS API - Windows 10+)
//      - DnsQueryRaw (Raw DNS wire format API - Windows 10+)
//      - Raw UDP/TCP sockets (port 53): Full support via sendto/WSASendTo interception
//
// Examples:
//   EncryptedDnsServer=https://cloudflare-dns.com/dns-query  (auto mode, tries DoQ first)
//   EncryptedDnsServer=https://1.1.1.1/dns-query?mode=doh2   (HTTP/2 only)
//   EncryptedDnsServer=https://dns.google/dns-query?mode=doh3 (HTTP/3 only)
//   EncryptedDnsServer=quic://dns.adguard-dns.com:853         (DoQ only)
//   EncryptedDnsServer=https://[2001:db8::1]/dns-query        (IPv6, auto mode)
//
// Note: This file provides backward-compatible API names (DoH_*).
//       For new code, consider using the unified dns_encrypted.h header.
//---------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------------
// DoH Error Types and Constants
//
// All error types and constants are now defined in dns_encrypted.h
// Use DOH_ERROR_* (aliased to ENCRYPTED_DNS_ERROR_*) for compatibility
// Use DOH_* constants (aliased to ENCRYPTED_DNS_*) for compatibility
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
// Public API
//---------------------------------------------------------------------------

// Initialize encrypted DNS client (call once at DLL startup)
// Returns TRUE on success, FALSE on failure
BOOLEAN EncryptedDns_Init(HMODULE hWinHttp, HMODULE hMsQuic);

// Cleanup encrypted DNS client (call at DLL shutdown)
void EncryptedDns_Cleanup(void);

// Load EncryptedDnsServer configuration from registry
// Returns TRUE if encrypted DNS is enabled (URL configured), FALSE otherwise
BOOLEAN EncryptedDns_LoadConfig(void);

// Query encrypted DNS server for domain (passthrough queries only)
// Returns TRUE if query succeeded, FALSE on error
// Result is written to pResult parameter
BOOLEAN EncryptedDns_Query(
    const WCHAR* domain,
    USHORT qtype,
    DOH_RESULT* pResult
);

// Check if encrypted DNS is enabled (EncryptedDnsServer configured)
BOOLEAN EncryptedDns_IsEnabled(void);

// Get encrypted DNS server hostname (for exclusion from filtering)
// Returns hostname without protocol/path (e.g., "cloudflare-dns.com")
// Returns NULL if encrypted DNS is not enabled
const WCHAR* EncryptedDns_GetServerHostname(void);

// Check if hostname is a configured encrypted DNS server (case-insensitive)
// Returns TRUE if hostname matches any configured server
// Used to exclude servers from DNS filtering to prevent re-entrancy
BOOLEAN EncryptedDns_IsServerHostname(const WCHAR* hostname);

//---------------------------------------------------------------------------
// Encrypted DNS Backend Public API (called from dns_encrypted.c)
//
// Note: These entry points keep the historical DoH_* naming, but the shared
// query path may dispatch to DoQ (MsQuic) or other encrypted-DNS modes based
// on EncryptedDnsServer configuration.
//---------------------------------------------------------------------------

// Initialize DoH module with WinHTTP
// Returns TRUE if DoH is available, FALSE otherwise
BOOLEAN DoH_Init(HMODULE hWinHttp);

// Cleanup DoH module and release resources
void DoH_Cleanup(void);

// Load EncryptedDnsServer configuration
// Returns TRUE if servers configured, FALSE otherwise
BOOLEAN DoH_LoadConfig(void);

// Encrypted DNS query implementation (DoH/DoH2/DoH3/DoQ)
// Returns TRUE on success, FALSE on error
BOOLEAN DoH_Query(const WCHAR* domain, USHORT qtype, ENCRYPTED_DNS_RESULT* pResult);

// Check if DoH is enabled (configuration loaded)
BOOLEAN DoH_IsEnabled(void);

// Get server hostname (for exclusion from filtering)
const WCHAR* DoH_GetServerHostname(void);

// Get server URL (for logging)
const WCHAR* DoH_GetServerUrl(void);

// Check if hostname is a configured DoH server
BOOLEAN DoH_IsServerHostname(const WCHAR* hostname);

// Check if any DoH query is currently active
BOOLEAN DoH_IsQueryActive(void);

// Mark server as failed (for shared error handling)
void DoH_MarkServerFailed(void* server, ULONGLONG now);

// OS version accessors (for HTTP/3 support detection)
DWORD DoH_GetOsMajorVersion(void);
DWORD DoH_GetOsMinorVersion(void);
DWORD DoH_GetOsBuildNumber(void);

// Check if any encrypted DNS query is currently active (for re-entrancy prevention)
// Returns TRUE if query is in progress on any thread
BOOLEAN EncryptedDns_IsQueryActive(void);

// Get configured encrypted DNS server URL (for logging)
const WCHAR* EncryptedDns_GetServerUrl(void);

// Get human-readable error string for error type
// Returns static string describing the error (never NULL)
const WCHAR* EncryptedDns_GetErrorString(DOH_ERROR_TYPE type);

// Unified error handler for query failures
// Returns TRUE if caller should try next server, FALSE if should fail immediately
BOOLEAN EncryptedDns_HandleQueryError(DOH_ERROR_TYPE type, void* server, 
    const WCHAR* domain, ULONGLONG now);

#ifdef __cplusplus
}
#endif

#endif // _DNS_DOH_H
