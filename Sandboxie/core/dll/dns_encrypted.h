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

#ifndef _DNS_ENCRYPTED_H
#define _DNS_ENCRYPTED_H

#include <windows.h>
#include <windns.h>
#include "common/netfw.h"  // For IP_ADDRESS type

//---------------------------------------------------------------------------
// Encrypted DNS Client (DoH/DoH2/DoH3/DoQ/DoT)
//
// This module implements encrypted DNS functionality to provide secure DNS
// resolution for passthrough queries, supporting multiple protocols:
//
// Supported Protocols:
//   - DoH  (DNS over HTTPS, HTTP/1.1/2, RFC 8484) - TCP 443 - via WinHTTP
//   - DoH2 (DNS over HTTPS, HTTP/2 only, RFC 8484) - TCP 443 - via WinHTTP
//   - DoH3 (DNS over HTTPS, HTTP/3 only, RFC 8484) - UDP 443 - via WinHTTP
//   - DoQ  (DNS over QUIC, native, RFC 9250) - UDP 853 - via MsQuic
//   - DoT  (DNS over TLS, raw, RFC 7858) - TCP 853 - (future)
//
// Configuration:
//   EncryptedDnsServer=<url>[?mode=<protocol>]
//     - Full server URL (e.g., https://cloudflare-dns.com/dns-query for DoH, quic://dns.example.com for DoQ)
//     - URL schemes:
//         https://  - HTTP-only mode (DoH3 → DoH2 → DoH, skips DoH3 if StrictBindIP)
//         httpx://  - HTTP-only mode with self-signed certificate allowed
//         quic://   - DoQ only (signed certificate)
//         quicx://  - DoQ only (self-signed certificate)
//         auto://   - AUTO mode with all protocols (DoQ → DoH3 → DoH2 → DoH, skips QUIC if StrictBindIP)
//         autox://  - AUTO mode with self-signed certificate
//     - Mode parameter selects protocol:
//         ?mode=auto  - AUTO mode (default for auto:// schemes)
//         ?mode=doh   - DNS over HTTPS (HTTP/1.1 or HTTP/2)
//         ?mode=doh2  - DNS over HTTPS, HTTP/2 only
//         ?mode=doh3  - DNS over HTTPS, HTTP/3 only (QUIC via WinHTTP, default for https://)
//         ?mode=doq   - DNS over QUIC (native, via MsQuic)
//         ?mode=dot   - DNS over TLS (reserved, not yet implemented)
//     - Default port by protocol:
//         DoH/DoH2/DoH3: 443 (HTTPS default)
//         DoQ/DoT: 853 (encrypted DNS default per RFC 7858/9250)
//     - Default path: /dns-query is applied only for DoH-based modes when no path is provided
//     - Supported providers: Cloudflare, Google, Quad9, etc.
//     - Default: disabled (empty string)
//     - Requires a valid certificate
//     - StrictBindIP: Automatically skips DoQ and DoH3 (QUIC incompatible)
//
// Implementation Details:
//   - DoH/DoH2/DoH3: Uses WinHTTP for HTTPS requests (wire format)
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
//   EncryptedDnsServer=https://cloudflare-dns.com/dns-query
//   EncryptedDnsServer=https://1.1.1.1/dns-query?mode=doh2
//   EncryptedDnsServer=https://dns.google/dns-query?mode=doh3
//   EncryptedDnsServer=quic://dns.adguard-dns.com?mode=doq
//   EncryptedDnsServer=https://[2001:db8::1]/dns-query (RFC 3849 documentation IPv6)
//---------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------------
// Protocol Mode Enumeration
//
// Specifies which encrypted DNS protocol to use for queries.
// Each mode has different transport characteristics and requirements.
//
// AUTO mode behavior:
//   Tries protocols in order with fallback on failure:
//   1. DoQ  (DNS over QUIC, native) - if MsQuic available
//   2. DoH3 (HTTP/3 over QUIC) - if WinHTTP supports or MsQuic available
//   3. DoH2 (HTTP/2) - standard HTTPS
//   4. DoH  (HTTP/1.1 or HTTP/2) - fallback
//   Failed protocols enter backoff period before retry.
//---------------------------------------------------------------------------

typedef enum _ENCRYPTED_DNS_MODE {
    ENCRYPTED_DNS_MODE_DOH = 0,     // DNS over HTTPS (HTTP/1.1 or HTTP/2) - RFC 8484, TCP 443
    ENCRYPTED_DNS_MODE_DOH2,        // DNS over HTTPS, HTTP/2 only - RFC 8484, TCP 443
    ENCRYPTED_DNS_MODE_DOH3,        // DNS over HTTPS, HTTP/3 only (QUIC) - RFC 8484, UDP 443
    ENCRYPTED_DNS_MODE_DOQ,         // DNS over QUIC (native) - RFC 9250, UDP 853
    ENCRYPTED_DNS_MODE_DOT,         // DNS over TLS (raw) - RFC 7858, TCP 853 (reserved)
    ENCRYPTED_DNS_MODE_AUTO,        // Auto: try DoQ → DoH3 → DoH2 → DoH with fallback
} ENCRYPTED_DNS_MODE;

//---------------------------------------------------------------------------
// Default Ports by Protocol (per RFCs)
//
// DoH/DoH2/DoH3: 443 (HTTPS default, RFC 8484)
// DoQ: 853 (RFC 9250 Section 3.1)
// DoT: 853 (RFC 7858 Section 3.1)
//---------------------------------------------------------------------------

#define ENCRYPTED_DNS_DEFAULT_PORT_DOH      443     // HTTPS default
#define ENCRYPTED_DNS_DEFAULT_PORT_DOH2     443     // HTTPS default
#define ENCRYPTED_DNS_DEFAULT_PORT_DOH3     443     // HTTPS default (QUIC uses same port)
#define ENCRYPTED_DNS_DEFAULT_PORT_DOQ      853     // RFC 9250 Section 3.1
#define ENCRYPTED_DNS_DEFAULT_PORT_DOT      853     // RFC 7858 Section 3.1

//---------------------------------------------------------------------------
// Encrypted DNS Error Types
//
// Unified error codes for encrypted DNS operations, enabling centralized 
// error handling and consistent logging across all protocols.
//---------------------------------------------------------------------------

typedef enum _ENCRYPTED_DNS_ERROR_TYPE {
    ENCRYPTED_DNS_ERROR_NONE = 0,               // No error
    ENCRYPTED_DNS_ERROR_NOT_CONFIGURED,         // EncryptedDnsServer not set
    ENCRYPTED_DNS_ERROR_BACKEND_UNAVAILABLE,    // Backend (WinHTTP/MsQuic) failed to load
    ENCRYPTED_DNS_ERROR_CONNECT_FAILED,         // Connection to server failed
    ENCRYPTED_DNS_ERROR_REQUEST_FAILED,         // Request creation failed
    ENCRYPTED_DNS_ERROR_SEND_FAILED,            // Failed to send request
    ENCRYPTED_DNS_ERROR_RECEIVE_FAILED,         // Failed to receive response
    ENCRYPTED_DNS_ERROR_TIMEOUT,                // Request timed out
    ENCRYPTED_DNS_ERROR_HTTP_STATUS,            // Non-200 HTTP status code (DoH only)
    ENCRYPTED_DNS_ERROR_PARSE_FAILED,           // Failed to parse DNS response
    ENCRYPTED_DNS_ERROR_REENTRANT,              // Re-entrancy detected
    ENCRYPTED_DNS_ERROR_SEMAPHORE_TIMEOUT,      // Semaphore wait timeout (server overloaded)
    ENCRYPTED_DNS_ERROR_ALL_SERVERS_FAILED,     // All configured servers failed
    ENCRYPTED_DNS_ERROR_PROTOCOL_MISMATCH,      // Required protocol not available
    ENCRYPTED_DNS_ERROR_PROTOCOL_NOT_SUPPORTED, // Protocol not supported (e.g., DoT not implemented)
    ENCRYPTED_DNS_ERROR_QUIC_INIT_FAILED,       // MsQuic initialization failed (DoQ)
    ENCRYPTED_DNS_ERROR_QUIC_STREAM_FAILED,     // QUIC stream operation failed (DoQ)
} ENCRYPTED_DNS_ERROR_TYPE;

//---------------------------------------------------------------------------
// Encrypted DNS Constants
//
// Named constants for magic numbers used throughout implementation.
//---------------------------------------------------------------------------

// Timeouts (milliseconds)
// AUTO mode uses shorter timeouts for faster fallback to next protocol when failures occur.
// Since AUTO mode tries DoQ → DoH3 → DoH2 → DoH, quick failures allow rapid fallback.
// Reduced from 5s to 2s to prevent user-visible delays when protocol doesn't work.
#define ENCRYPTED_DNS_HTTP_TIMEOUT_MS         2000    // HTTP request timeout (reduced for faster fallback)
#define ENCRYPTED_DNS_QUIC_TIMEOUT_MS         2000    // QUIC request timeout (reduced for faster fallback)
#define ENCRYPTED_DNS_SEMAPHORE_TIMEOUT_MS    2000    // Semaphore wait timeout (reduced for fail-fast behavior)
#define ENCRYPTED_DNS_REENTRANT_WAIT_MS       50      // Per-iteration wait for re-entrancy
#define ENCRYPTED_DNS_REENTRANT_MAX_ATTEMPTS  10      // Max re-entrancy wait iterations

// Cache settings
#define ENCRYPTED_DNS_CACHE_SIZE              64      // Number of cache entries
#define ENCRYPTED_DNS_DEFAULT_TTL             300     // Default TTL in seconds (5 min)
#define ENCRYPTED_DNS_MIN_TTL                 60      // Minimum TTL for fallback responses

// Negative caching (failed queries)
// Keep this short to avoid "sticky" outages, but long enough to prevent query storms.
// When BindAdapter/BindAdapterIP is configured and the adapter is down, use an even
// shorter TTL and purge failures on adapter-up transitions.
#define ENCRYPTED_DNS_FAILED_TTL              10      // seconds
#define ENCRYPTED_DNS_BIND_DOWN_TTL           2       // seconds

// Server limits
#define ENCRYPTED_DNS_MAX_SERVERS_PER_LINE    16      // Max servers per config line
#define ENCRYPTED_DNS_MAX_CONFIG_LINES        8       // Max config lines (EncryptedDnsServer)
#define ENCRYPTED_DNS_SERVER_FAIL_COOLDOWN    30000   // Server cooldown in ms (30 sec)

// Connection pool
#define ENCRYPTED_DNS_MAX_POOL_CONNECTIONS    16      // Max pooled connections

// Pending queries
#define ENCRYPTED_DNS_MAX_PENDING_QUERIES     32      // Max concurrent pending queries
#define ENCRYPTED_DNS_MAX_CONCURRENT_QUERIES  8       // Semaphore limit

// DNS response limits
#define ENCRYPTED_DNS_MAX_ANSWERS             32      // Max IP addresses per response
#define ENCRYPTED_DNS_DOMAIN_MAX_LEN          256     // Max domain name length

// HTTP/3 backoff periods (seconds)
#define ENCRYPTED_DNS_HTTP3_BACKOFF_1         30      // 1st failure: 30 seconds
#define ENCRYPTED_DNS_HTTP3_BACKOFF_2         60      // 2nd failure: 1 minute
#define ENCRYPTED_DNS_HTTP3_BACKOFF_3         120     // 3rd failure: 2 minutes
#define ENCRYPTED_DNS_HTTP3_BACKOFF_MAX       300     // 4th+ failure: 5 minutes max

// WinHTTP error codes for user-friendly messages
#define WINHTTP_ERROR_CANNOT_CONNECT        12029
#define WINHTTP_ERROR_TIMEOUT               12002
#define WINHTTP_ERROR_CONNECTION_RESET      12030

// QUIC ALPN tokens (RFC 9250 Section 4)
#define DOQ_ALPN_TOKEN                      "doq"
#define DOQ_ALPN_TOKEN_LEN                  3

//---------------------------------------------------------------------------
// Types
//---------------------------------------------------------------------------

// Maximum raw DNS response size for non-A/AAAA queries
#define ENCRYPTED_DNS_MAX_RAW_RESPONSE      8192

// Encrypted DNS query result structure
typedef struct _ENCRYPTED_DNS_RESULT {
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
    ENCRYPTED_DNS_MODE ProtocolUsed; // Protocol actually used (DoH/DoH2/DoH3/DoQ/DoT/AUTO)
    // Raw DNS response for non-A/AAAA queries (TXT, MX, SRV, etc.)
    BYTE        RawResponse[ENCRYPTED_DNS_MAX_RAW_RESPONSE]; // Raw DNS wire format response
    DWORD       RawResponseLen;    // Length of raw response data (0 if not used)
} ENCRYPTED_DNS_RESULT;

//---------------------------------------------------------------------------
// Legacy Type Aliases (for backward compatibility during migration)
//---------------------------------------------------------------------------

// Error type alias
typedef ENCRYPTED_DNS_ERROR_TYPE DOH_ERROR_TYPE;
#define DOH_ERROR_NONE                  ENCRYPTED_DNS_ERROR_NONE
#define DOH_ERROR_NOT_CONFIGURED        ENCRYPTED_DNS_ERROR_NOT_CONFIGURED
#define DOH_ERROR_BACKEND_UNAVAILABLE   ENCRYPTED_DNS_ERROR_BACKEND_UNAVAILABLE
#define DOH_ERROR_CONNECT_FAILED        ENCRYPTED_DNS_ERROR_CONNECT_FAILED
#define DOH_ERROR_REQUEST_FAILED        ENCRYPTED_DNS_ERROR_REQUEST_FAILED
#define DOH_ERROR_SEND_FAILED           ENCRYPTED_DNS_ERROR_SEND_FAILED
#define DOH_ERROR_RECEIVE_FAILED        ENCRYPTED_DNS_ERROR_RECEIVE_FAILED
#define DOH_ERROR_TIMEOUT               ENCRYPTED_DNS_ERROR_TIMEOUT
#define DOH_ERROR_HTTP_STATUS           ENCRYPTED_DNS_ERROR_HTTP_STATUS
#define DOH_ERROR_PARSE_FAILED          ENCRYPTED_DNS_ERROR_PARSE_FAILED
#define DOH_ERROR_REENTRANT             ENCRYPTED_DNS_ERROR_REENTRANT
#define DOH_ERROR_SEMAPHORE_TIMEOUT     ENCRYPTED_DNS_ERROR_SEMAPHORE_TIMEOUT
#define DOH_ERROR_ALL_SERVERS_FAILED    ENCRYPTED_DNS_ERROR_ALL_SERVERS_FAILED
#define DOH_ERROR_PROTOCOL_MISMATCH     ENCRYPTED_DNS_ERROR_PROTOCOL_MISMATCH

// Result type alias
typedef ENCRYPTED_DNS_RESULT DOH_RESULT;

// Constant aliases
#define DOH_HTTP_TIMEOUT_MS             ENCRYPTED_DNS_HTTP_TIMEOUT_MS
#define DOH_SEMAPHORE_TIMEOUT_MS        ENCRYPTED_DNS_SEMAPHORE_TIMEOUT_MS
#define DOH_REENTRANT_WAIT_MS           ENCRYPTED_DNS_REENTRANT_WAIT_MS
#define DOH_REENTRANT_MAX_ATTEMPTS      ENCRYPTED_DNS_REENTRANT_MAX_ATTEMPTS
#define DOH_CACHE_SIZE                  ENCRYPTED_DNS_CACHE_SIZE
#define DOH_DEFAULT_TTL                 ENCRYPTED_DNS_DEFAULT_TTL
#define DOH_MIN_TTL                     ENCRYPTED_DNS_MIN_TTL
#define DOH_MAX_SERVERS_PER_LINE        ENCRYPTED_DNS_MAX_SERVERS_PER_LINE
#define DOH_MAX_CONFIG_LINES            ENCRYPTED_DNS_MAX_CONFIG_LINES
#define DOH_SERVER_FAIL_COOLDOWN        ENCRYPTED_DNS_SERVER_FAIL_COOLDOWN
#define DOH_MAX_POOL_CONNECTIONS        ENCRYPTED_DNS_MAX_POOL_CONNECTIONS
#define DOH_MAX_PENDING_QUERIES         ENCRYPTED_DNS_MAX_PENDING_QUERIES
#define DOH_MAX_CONCURRENT_QUERIES      ENCRYPTED_DNS_MAX_CONCURRENT_QUERIES
#define DOH_MAX_ANSWERS                 ENCRYPTED_DNS_MAX_ANSWERS
#define DOH_DOMAIN_MAX_LEN              ENCRYPTED_DNS_DOMAIN_MAX_LEN
#define DOH_HTTP3_BACKOFF_1             ENCRYPTED_DNS_HTTP3_BACKOFF_1
#define DOH_HTTP3_BACKOFF_2             ENCRYPTED_DNS_HTTP3_BACKOFF_2
#define DOH_HTTP3_BACKOFF_3             ENCRYPTED_DNS_HTTP3_BACKOFF_3
#define DOH_HTTP3_BACKOFF_MAX           ENCRYPTED_DNS_HTTP3_BACKOFF_MAX

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
    ENCRYPTED_DNS_RESULT* pResult
);

// Check if encrypted DNS is enabled (EncryptedDnsServer configured)
BOOLEAN EncryptedDns_IsEnabled(void);

// Get server hostname (for exclusion from filtering)
// Returns hostname without protocol/path (e.g., "cloudflare-dns.com")
// Returns NULL if not enabled
const WCHAR* EncryptedDns_GetServerHostname(void);

// Check if hostname is a configured server (case-insensitive)
// Returns TRUE if hostname matches any configured server
// Used to exclude servers from DNS filtering to prevent re-entrancy
BOOLEAN EncryptedDns_IsServerHostname(const WCHAR* hostname);

// Check if any query is currently active (for re-entrancy prevention)
// Returns TRUE if query is in progress on any thread
BOOLEAN EncryptedDns_IsQueryActive(void);

// Get configured server URL (for logging)
const WCHAR* EncryptedDns_GetServerUrl(void);

// Get human-readable error string for error type
// Returns static string describing the error (never NULL)
const WCHAR* EncryptedDns_GetErrorString(ENCRYPTED_DNS_ERROR_TYPE type);

// Unified error handler for query failures
// Returns TRUE if caller should try next server, FALSE if should fail immediately
BOOLEAN EncryptedDns_HandleQueryError(ENCRYPTED_DNS_ERROR_TYPE type, void* server, 
    const WCHAR* domain, ULONGLONG now);

// Get protocol mode name string (for logging)
const WCHAR* EncryptedDns_GetModeName(ENCRYPTED_DNS_MODE mode);

// Get default port for protocol mode
USHORT EncryptedDns_GetDefaultPort(ENCRYPTED_DNS_MODE mode);

#ifdef __cplusplus
}
#endif

#endif // _DNS_ENCRYPTED_H
