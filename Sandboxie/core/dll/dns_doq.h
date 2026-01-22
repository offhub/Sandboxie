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

#ifndef _DNS_DOQ_H
#define _DNS_DOQ_H

#include <windows.h>
#include <windns.h>
#include "dns_encrypted.h"

//---------------------------------------------------------------------------
// DNS over QUIC (DoQ) Client - RFC 9250
//
// This module implements native DNS over QUIC (DoQ) as specified in RFC 9250.
// Unlike DoH3 which tunnels HTTP/3 over QUIC, DoQ uses QUIC streams directly
// for DNS message transport with minimal overhead.
//
// Protocol Overview (RFC 9250):
//   - Transport: QUIC (RFC 9000) over UDP
//   - Default Port: 853 (same as DoT, per RFC 9250 Section 3.1)
//   - ALPN Token: "doq" (RFC 9250 Section 4)
//   - Message Format: DNS wire format (RFC 1035) prefixed with 2-byte length
//   - One query per QUIC stream (unidirectional streams not used)
//   - Connection reuse: Multiple queries over same QUIC connection
//
// Implementation via MsQuic:
//   - MsQuic is Microsoft's cross-platform QUIC implementation
//   - Not included in Windows system32, must be injected via InjectDll
//   - Uses QUIC API v2 for modern features
//   - Automatic connection pooling for efficiency
//
// Message Framing (RFC 9250 Section 4.2):
//   - Each DNS message is preceded by a 2-byte length field (big-endian)
//   - Length prefix is NOT part of the DNS message itself
//   - Each query uses a separate bidirectional QUIC stream
//   - Client initiates stream, sends query, receives response, closes stream
//
// Flow:
//   1. Open QUIC connection to DoQ server (port 853)
//   2. Create bidirectional stream
//   3. Send: [2-byte length][DNS query in wire format]
//   4. Receive: [2-byte length][DNS response in wire format]
//   5. Close stream (connection remains open for reuse)
//
// Error Handling (RFC 9250 Section 5):
//   - DOQ_NO_ERROR (0x0): Clean close
//   - DOQ_INTERNAL_ERROR (0x1): Implementation error
//   - DOQ_PROTOCOL_ERROR (0x2): Protocol violation
//   - DOQ_REQUEST_CANCELLED (0x3): Request cancelled
//   - DOQ_EXCESSIVE_LOAD (0x4): Server overloaded
//   - DOQ_UNSPECIFIED_ERROR (0x5): Generic error
//
// Supported Providers:
//   - AdGuard: quic://dns.adguard-dns.com
//   - NextDNS: quic://dns.nextdns.io
//   - Any RFC 9250 compliant server
//---------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------------
// DoQ Error Codes (RFC 9250 Section 5)
//---------------------------------------------------------------------------

#define DOQ_ERROR_NO_ERROR              0x0     // Clean close
#define DOQ_ERROR_INTERNAL_ERROR        0x1     // Implementation error
#define DOQ_ERROR_PROTOCOL_ERROR        0x2     // Protocol violation
#define DOQ_ERROR_REQUEST_CANCELLED     0x3     // Request cancelled
#define DOQ_ERROR_EXCESSIVE_LOAD        0x4     // Server overloaded
#define DOQ_ERROR_UNSPECIFIED_ERROR     0x5     // Generic error

//---------------------------------------------------------------------------
// DoQ Constants
//---------------------------------------------------------------------------

// Default port per RFC 9250 Section 3.1
#define DOQ_DEFAULT_PORT                853

// ALPN token per RFC 9250 Section 4
#define DOQ_ALPN_STRING                 "doq"
#define DOQ_ALPN_LENGTH                 3

// Timeouts
// AUTO mode uses shorter timeouts for faster fallback to next protocol when DoQ fails.
// Standalone DoQ mode uses these same shorter timeouts for reasonable responsiveness.
// Since AUTO mode tries DoQ → DoH3 → DoH2 → DoH, quick failures allow rapid fallback.
// Reduced from 5s to 2s to prevent user-visible delays when protocol doesn't work.
#define DOQ_CONNECT_TIMEOUT_MS          2000    // Connection timeout (reduced for faster fallback)
#define DOQ_QUERY_TIMEOUT_MS            2000    // Query timeout (reduced for faster fallback)
#define DOQ_IDLE_TIMEOUT_MS             30000   // Connection idle timeout

// Message size limits
#define DOQ_MAX_MESSAGE_SIZE            65535   // Max DNS message size
#define DOQ_LENGTH_PREFIX_SIZE          2       // Length prefix size in bytes

// Connection pool
#define DOQ_MAX_CONNECTIONS             8       // Max pooled connections

//---------------------------------------------------------------------------
// DoQ Connection State
//---------------------------------------------------------------------------

typedef enum _DOQ_CONNECTION_STATE {
    DOQ_STATE_DISCONNECTED = 0,     // Not connected
    DOQ_STATE_CONNECTING,           // Connection in progress
    DOQ_STATE_CONNECTED,            // Connected and ready
    DOQ_STATE_ERROR,                // Connection failed
} DOQ_CONNECTION_STATE;

//---------------------------------------------------------------------------
// DoQ Server Information
//---------------------------------------------------------------------------

typedef struct _DOQ_SERVER {
    WCHAR Host[ENCRYPTED_DNS_DOMAIN_MAX_LEN];   // Server hostname
    USHORT Port;                                // Server port (default: 853)
    BOOLEAN SelfSigned;                         // Allow self-signed certs
    ULONGLONG FailedUntil;                      // Failure cooldown timestamp
} DOQ_SERVER;

//---------------------------------------------------------------------------
// Public API
//---------------------------------------------------------------------------

// Initialize DoQ module with MsQuic
// hMsQuic: Handle to msquic.dll (required, must be injected via InjectDll)
// Returns TRUE if DoQ is available, FALSE otherwise
BOOLEAN DoQ_Init(HMODULE hMsQuic);

// Cleanup DoQ module and release resources
void DoQ_Cleanup(void);

// Check if DoQ is available (MsQuic loaded successfully)
BOOLEAN DoQ_IsAvailable(void);

// Perform DoQ query to specified server
// server: Target DoQ server
// domain: Domain name to query
// qtype: DNS query type (A, AAAA, etc.)
// pResult: Output result structure
// Returns TRUE on success, FALSE on error
BOOLEAN DoQ_Query(
    const DOQ_SERVER* server,
    const WCHAR* domain,
    USHORT qtype,
    ENCRYPTED_DNS_RESULT* pResult
);

// Close all DoQ connections (for cleanup or reconnection)
void DoQ_CloseAllConnections(void);

// Get DoQ error string for logging
const WCHAR* DoQ_GetErrorString(UINT64 errorCode);

#ifdef __cplusplus
}
#endif

#endif // _DNS_DOQ_H
