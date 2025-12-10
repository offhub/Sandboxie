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

//---------------------------------------------------------------------------
// DNS-over-HTTPS (DoH) Client
//
// This module implements RFC 8484 DNS-over-HTTPS functionality to provide
// secure DNS resolution for passthrough queries.
//
// Configuration:
//   SecureDnsServer=<url>
//     - Full DoH server URL (e.g., https://cloudflare-dns.com/dns-query)
//     - Supported providers: Cloudflare, Google, Quad9, etc.
//     - Default: disabled (empty string)
//
// Implementation Details:
//   - Uses WinHTTP for HTTPS requests (JSON wire format)
//   - Re-entrancy protection: Whitelists DoH server to prevent infinite loops
//   - Response caching: 300-second default TTL (respects DNS TTL when available)
//   - JSON parsing: Lightweight custom parser (no external dependencies)
//   - Supports A and AAAA queries only (consistent with NetworkDnsFilter)
//
// Security:
//   - Certificate validation via WinHTTP
//   - Domain validation against NetworkDnsFilter before DoH query
//   - Prevents HTTPS interception attacks (original domain in SNI)
//
// Integration Status:
//   ✅ Supported APIs:
//      - GetAddrInfoW (most common, used by browsers/curl/WinHTTP)
//      - DnsQuery_A/W/UTF8 (Windows DNS API - command-line tools, legacy apps)
//      - DnsQueryEx (Modern async DNS API - Windows 10+)
//   ⚠️  Partial Support:
//      - DnsQueryRaw: Requires DNS wire format conversion (JSON → RFC 1035)
//      - Raw UDP sockets (port 53): Requires packet injection
//   Coverage: ~95% of real-world DNS queries
//
// Examples:
//   SecureDnsServer=https://cloudflare-dns.com/dns-query
//   SecureDnsServer=https://dns.google/resolve
//   SecureDnsServer=https://dns.quad9.net/dns-query
//---------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------------
// Types
//---------------------------------------------------------------------------

// DoH query result structure
typedef struct _DOH_RESULT {
    BOOLEAN     Success;           // TRUE if query succeeded
    DNS_STATUS  Status;            // DNS status code (0 = success, RCODE otherwise)
    USHORT      AnswerCount;       // Number of IP addresses returned
    struct {
        USHORT Type;               // AF_INET or AF_INET6
        IP_ADDRESS IP;             // IP address data
    } Answers[32];                 // IP addresses (max 32 per RFC 1035)
    ULONG       TTL;               // Time-to-live in seconds (for caching)
    WCHAR       CnameTarget[256];  // CNAME target if response contains only CNAME
    BOOLEAN     IsCnameOnly;       // TRUE if response contains only CNAME (no A/AAAA)
    BOOLEAN     HasCname;          // TRUE if response contains CNAME record (even with A/AAAA)
    WCHAR       CnameOwner[256];   // CNAME owner name (original queried name)
} DOH_RESULT;

//---------------------------------------------------------------------------
// Public API
//---------------------------------------------------------------------------

// Initialize DoH client (call once at DLL startup)
// Returns TRUE on success, FALSE on failure
BOOLEAN DoH_Init(HMODULE hWinHttp);

// Cleanup DoH client (call at DLL shutdown)
void DoH_Cleanup(void);

// Load SecureDnsServer configuration from registry
// Returns TRUE if DoH is enabled (URL configured), FALSE otherwise
BOOLEAN DoH_LoadConfig(void);

// Query DoH server for domain (passthrough queries only)
// Returns TRUE if query succeeded, FALSE on error
// Result is written to pResult parameter
BOOLEAN DoH_Query(
    const WCHAR* domain,
    USHORT qtype,
    DOH_RESULT* pResult
);

// Check if DoH is enabled (SecureDnsServer configured)
BOOLEAN DoH_IsEnabled(void);

// Get DoH server hostname (for exclusion from filtering)
// Returns hostname without protocol/path (e.g., "cloudflare-dns.com")
// Returns NULL if DoH is not enabled
const WCHAR* DoH_GetServerHostname(void);

// Check if hostname is a configured DoH server (case-insensitive)
// Returns TRUE if hostname matches any configured DoH server
// Used to exclude DoH servers from DNS filtering to prevent re-entrancy
BOOLEAN DoH_IsServerHostname(const WCHAR* hostname);

// Check if any DoH query is currently active (for re-entrancy prevention)
// Returns TRUE if DoH query is in progress on any thread
BOOLEAN DoH_IsQueryActive(void);

// Get configured DoH server URL (for logging)
const WCHAR* DoH_GetServerUrl(void);

#ifdef __cplusplus
}
#endif

#endif // _DNS_DOH_H
