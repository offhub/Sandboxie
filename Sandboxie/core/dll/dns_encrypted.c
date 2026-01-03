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

//---------------------------------------------------------------------------
// Encrypted DNS Client - Shared Implementation
//
// This module contains protocol-agnostic encrypted DNS functionality shared
// between DoH (dns_doh.c) and DoQ (dns_doq.c) implementations:
//
//   - Initialization and cleanup coordination
//   - Configuration loading and management
//   - Server selection and failover logic
//   - Protocol helper functions (mode detection, port defaults, etc.)
//   - Public API functions
//
// Protocol-specific implementations are in:
//   - dns_doh.c: WinHTTP-based DoH/DoH2/DoH3 implementation
//   - dns_doq.c: MsQuic-based DoQ implementation
//---------------------------------------------------------------------------

#define NOGDI
#include "dll.h"
#include "dns_encrypted.h"
#include "dns_doh.h"
#include "dns_doq.h"
#include "dns_logging.h"

#include <windows.h>
#include <wchar.h>

//---------------------------------------------------------------------------
// External Functions and Variables
//---------------------------------------------------------------------------

extern ULONGLONG GetTickCount64(void);
extern BOOLEAN DNS_TraceFlag;
extern BOOLEAN DNS_DebugFlag;
extern BOOLEAN DNS_HasValidCertificate;
extern BOOLEAN WSA_IsBindIPLoopback(void);

#if !defined(_DNSDEBUG)
// Release builds: compile out debug-only logging paths.
#undef DNS_DebugFlag
#define DNS_DebugFlag 0
#endif

// External from config.c
extern WCHAR* Config_MatchImageAndGetValue(WCHAR* setting, const WCHAR* imageName, ULONG* level);
extern const WCHAR* Dll_ImageName;

//---------------------------------------------------------------------------
// Encrypted DNS Protocol Helper Functions
//---------------------------------------------------------------------------

// Get human-readable name for a protocol mode
_FX const WCHAR* EncryptedDns_GetModeName(ENCRYPTED_DNS_MODE mode)
{
    switch (mode) {
        case ENCRYPTED_DNS_MODE_DOH:  return L"DoH";
        case ENCRYPTED_DNS_MODE_DOH2: return L"DoH2";
        case ENCRYPTED_DNS_MODE_DOH3: return L"DoH3";
        case ENCRYPTED_DNS_MODE_DOQ:  return L"DoQ";
        case ENCRYPTED_DNS_MODE_DOT:  return L"DoT";
        case ENCRYPTED_DNS_MODE_AUTO: return L"Auto";
        default:                      return L"Unknown";
    }
}

// Get default port for a protocol mode
_FX USHORT EncryptedDns_GetDefaultPort(ENCRYPTED_DNS_MODE mode)
{
    switch (mode) {
        case ENCRYPTED_DNS_MODE_DOH:
        case ENCRYPTED_DNS_MODE_DOH2:
        case ENCRYPTED_DNS_MODE_DOH3:
        case ENCRYPTED_DNS_MODE_AUTO: // AUTO uses HTTPS port for HTTP-based protocols
            return ENCRYPTED_DNS_DEFAULT_PORT_DOH;  // 443
        case ENCRYPTED_DNS_MODE_DOQ:
            return ENCRYPTED_DNS_DEFAULT_PORT_DOQ;  // 853
        case ENCRYPTED_DNS_MODE_DOT:
            return ENCRYPTED_DNS_DEFAULT_PORT_DOT;  // 853
        default:
            return ENCRYPTED_DNS_DEFAULT_PORT_DOH;  // Default to 443
    }
}

// Check if a protocol mode uses HTTP (WinHTTP backend)
_FX BOOLEAN EncryptedDns_IsHttpBased(ENCRYPTED_DNS_MODE mode)
{
    return (mode == ENCRYPTED_DNS_MODE_DOH || 
            mode == ENCRYPTED_DNS_MODE_DOH2 || 
            mode == ENCRYPTED_DNS_MODE_DOH3);
}

// Check if a protocol mode uses QUIC (MsQuic backend)
_FX BOOLEAN EncryptedDns_IsQuicBased(ENCRYPTED_DNS_MODE mode)
{
    return (mode == ENCRYPTED_DNS_MODE_DOQ);
}

// Check if a protocol mode uses raw TLS (DoT)
_FX BOOLEAN EncryptedDns_IsTlsBased(ENCRYPTED_DNS_MODE mode)
{
    return (mode == ENCRYPTED_DNS_MODE_DOT);
}

// Check if WinHTTP supports HTTP/3 (Windows 11 22H2+ required)
// On Windows 10, HTTP/3 is not supported by WinHTTP - use MsQuic instead
_FX BOOLEAN EncryptedDns_WinHttpSupportsHttp3(void)
{
    // Get OS version from DoH module (it captures this during LoadConfig)
    extern DWORD DoH_GetOsMajorVersion(void);
    extern DWORD DoH_GetOsMinorVersion(void);
    extern DWORD DoH_GetOsBuildNumber(void);
    
    DWORD major = DoH_GetOsMajorVersion();
    DWORD minor = DoH_GetOsMinorVersion();
    DWORD build = DoH_GetOsBuildNumber();
    
    // Windows 11 (build 22000+) with 22H2 update (build 22621+) supports HTTP/3
    // Windows version: 10.0.22000+ (major=10, minor=0, build=22000+)
    // Windows 11 = 10.0.22000+, Windows 10 = 10.0.19041, etc.
    if (major == 10 && minor == 0) {
        // Windows 10/11 - check build number
        // Windows 11 starts at build 22000, HTTP/3 available in 22H2 (22621+)
        return (build >= 22000);
    }
    // Future Windows versions (11+)
    return (major > 10);
}

// Get next protocol to try in AUTO mode fallback chain
// Returns ENCRYPTED_DNS_MODE_DOH as final fallback (always available)
// Order: DoQ → DoH3 → DoH2 → DoH
_FX ENCRYPTED_DNS_MODE EncryptedDns_GetNextAutoProtocol(ENCRYPTED_DNS_MODE current)
{
    switch (current) {
        case ENCRYPTED_DNS_MODE_DOQ:
            return ENCRYPTED_DNS_MODE_DOH3;
        case ENCRYPTED_DNS_MODE_DOH3:
            return ENCRYPTED_DNS_MODE_DOH2;
        case ENCRYPTED_DNS_MODE_DOH2:
            return ENCRYPTED_DNS_MODE_DOH;
        case ENCRYPTED_DNS_MODE_DOH:
        default:
            return ENCRYPTED_DNS_MODE_DOH; // Final fallback, no more options
    }
}

// Calculate backoff time in milliseconds based on failure count
// Uses incremental backoff: 30s, 60s, 120s, 300s max
_FX ULONG EncryptedDns_GetBackoffMs(ULONG failCount)
{
    if (failCount <= 1) return 30000;       // 30 seconds
    if (failCount == 2) return 60000;       // 1 minute
    if (failCount == 3) return 120000;      // 2 minutes
    return 300000;                          // 5 minutes max
}

//---------------------------------------------------------------------------
// Public API Implementation
//
// These functions delegate to protocol-specific implementations in
// dns_doh.c and dns_doq.c as appropriate.
//---------------------------------------------------------------------------

_FX BOOLEAN EncryptedDns_Init(HMODULE hWinHttp, HMODULE hMsQuic)
{
    // Always initialize DoH (initializes connection pool even if WinHTTP not loaded yet)
    // WinHTTP functions are loaded lazily in DoH_LoadBackends on first query
    DoH_Init(hWinHttp);
    
    // Initialize DoQ if MsQuic is available
    if (hMsQuic) {
        DoQ_Init(hMsQuic);
    }
    
    return TRUE;
}

_FX void EncryptedDns_Cleanup(void)
{
    // Cleanup protocol implementations
    DoH_Cleanup();
    DoQ_Cleanup();
}

_FX BOOLEAN EncryptedDns_LoadConfig(void)
{
    // Configuration is loaded by DoH module (dns_doh.c)
    // since it manages the multi-server configuration structure
    return DoH_LoadConfig();
}

_FX BOOLEAN EncryptedDns_Query(const WCHAR* domain, USHORT qtype, ENCRYPTED_DNS_RESULT* pResult)
{
    // Query is handled by DoH module (dns_doh.c)
    // which implements the main query logic, protocol selection,
    // and dispatches to DoQ as needed in AUTO mode
    return DoH_Query(domain, qtype, pResult);
}

_FX BOOLEAN EncryptedDns_IsEnabled(void)
{
    // Check if configuration is loaded
    return DoH_IsEnabled();
}

_FX const WCHAR* EncryptedDns_GetServerHostname(void)
{
    // Get server hostname from DoH configuration
    return DoH_GetServerHostname();
}

_FX const WCHAR* EncryptedDns_GetServerUrl(void)
{
    // Get server URL from DoH configuration
    return DoH_GetServerUrl();
}

_FX BOOLEAN EncryptedDns_IsServerHostname(const WCHAR* hostname)
{
    // Check against DoH configuration
    return DoH_IsServerHostname(hostname);
}

_FX BOOLEAN EncryptedDns_IsQueryActive(void)
{
    // Check if any query is active
    return DoH_IsQueryActive();
}

_FX const WCHAR* EncryptedDns_GetErrorString(ENCRYPTED_DNS_ERROR_TYPE type)
{
    switch (type) {
        case ENCRYPTED_DNS_ERROR_NONE:
            return L"No error";
        case ENCRYPTED_DNS_ERROR_NOT_CONFIGURED:
            return L"EncryptedDnsServer not configured";
        case ENCRYPTED_DNS_ERROR_BACKEND_UNAVAILABLE:
            return L"HTTP/QUIC backend unavailable";
        case ENCRYPTED_DNS_ERROR_CONNECT_FAILED:
            return L"Connection to server failed";
        case ENCRYPTED_DNS_ERROR_REQUEST_FAILED:
            return L"Request creation failed";
        case ENCRYPTED_DNS_ERROR_SEND_FAILED:
            return L"Failed to send request";
        case ENCRYPTED_DNS_ERROR_RECEIVE_FAILED:
            return L"Failed to receive response";
        case ENCRYPTED_DNS_ERROR_TIMEOUT:
            return L"Request timed out";
        case ENCRYPTED_DNS_ERROR_HTTP_STATUS:
            return L"HTTP error status code";
        case ENCRYPTED_DNS_ERROR_PARSE_FAILED:
            return L"Failed to parse DNS response";
        case ENCRYPTED_DNS_ERROR_REENTRANT:
            return L"Re-entrancy detected";
        case ENCRYPTED_DNS_ERROR_SEMAPHORE_TIMEOUT:
            return L"Semaphore timeout (server overloaded)";
        case ENCRYPTED_DNS_ERROR_ALL_SERVERS_FAILED:
            return L"All configured servers failed";
        case ENCRYPTED_DNS_ERROR_PROTOCOL_MISMATCH:
            return L"Required protocol not available";
        case ENCRYPTED_DNS_ERROR_PROTOCOL_NOT_SUPPORTED:
            return L"Protocol not supported";
        case ENCRYPTED_DNS_ERROR_QUIC_INIT_FAILED:
            return L"QUIC initialization failed";
        case ENCRYPTED_DNS_ERROR_QUIC_STREAM_FAILED:
            return L"QUIC stream operation failed";
        default:
            return L"Unknown error";
    }
}

_FX BOOLEAN EncryptedDns_HandleQueryError(ENCRYPTED_DNS_ERROR_TYPE type, void* server, 
    const WCHAR* domain, ULONGLONG now)
{
    // Log the error with contextual information
    if (DNS_TraceFlag) {
        WCHAR msg[512];
        if (domain) {
            Sbie_snwprintf(msg, 512, L"[EncDns] Error for %s: %s",
                domain, EncryptedDns_GetErrorString(type));
        } else {
            Sbie_snwprintf(msg, 512, L"[EncDns] Error: %s", 
                EncryptedDns_GetErrorString(type));
        }
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        
        // Provide helpful diagnostic hints for common issues
        switch (type) {
            case ENCRYPTED_DNS_ERROR_CONNECT_FAILED:
            case ENCRYPTED_DNS_ERROR_SEND_FAILED:
            case ENCRYPTED_DNS_ERROR_RECEIVE_FAILED:
            case ENCRYPTED_DNS_ERROR_TIMEOUT:
                SbieApi_MonitorPutMsg(MONITOR_DNS, 
                    L"[EncDns] Hint: Check firewall settings and ensure server is accessible. "
                    L"If NetworkAccess rules block outbound traffic, add exception for encrypted DNS server.");
                break;
            case ENCRYPTED_DNS_ERROR_ALL_SERVERS_FAILED:
                SbieApi_MonitorPutMsg(MONITOR_DNS, 
                    L"[EncDns] Check: 1) NetworkAccess firewall rules allow server "
                    L"2) Server URL is correct 3) Network connectivity");
                break;
            case ENCRYPTED_DNS_ERROR_QUIC_INIT_FAILED:
                SbieApi_MonitorPutMsg(MONITOR_DNS,
                    L"[EncDns] Hint: MsQuic not available or failed to initialize. "
                    L"DoQ requires MsQuic to be injected via InjectDll.");
                break;
            default:
                break;
        }
    }

    // Determine action based on error type
    switch (type) {
        // Server-specific failures - try next server
        case ENCRYPTED_DNS_ERROR_CONNECT_FAILED:
        case ENCRYPTED_DNS_ERROR_SEND_FAILED:
        case ENCRYPTED_DNS_ERROR_RECEIVE_FAILED:
        case ENCRYPTED_DNS_ERROR_HTTP_STATUS:
        case ENCRYPTED_DNS_ERROR_PROTOCOL_MISMATCH:
        case ENCRYPTED_DNS_ERROR_PARSE_FAILED:
        case ENCRYPTED_DNS_ERROR_QUIC_STREAM_FAILED:
            // Server failure - mark failed and try next
            if (server) {
                DoH_MarkServerFailed(server, now);
            }
            return TRUE;  // Try next server
            
        // Protocol-specific timeouts - don't mark entire server as failed
        // (DoQ timeout on UDP 853 doesn't mean DoH on TCP 443 won't work)
        case ENCRYPTED_DNS_ERROR_TIMEOUT:
            return TRUE;  // Try next protocol without server-wide penalty
            
        // Request failures - might be transient, try next
        case ENCRYPTED_DNS_ERROR_REQUEST_FAILED:
            return TRUE;  // Try next server without marking failed
            
        // Fatal errors - don't retry
        case ENCRYPTED_DNS_ERROR_NOT_CONFIGURED:
        case ENCRYPTED_DNS_ERROR_BACKEND_UNAVAILABLE:
        case ENCRYPTED_DNS_ERROR_REENTRANT:
        case ENCRYPTED_DNS_ERROR_SEMAPHORE_TIMEOUT:
        case ENCRYPTED_DNS_ERROR_ALL_SERVERS_FAILED:
        case ENCRYPTED_DNS_ERROR_PROTOCOL_NOT_SUPPORTED:
        case ENCRYPTED_DNS_ERROR_QUIC_INIT_FAILED:
            return FALSE;  // Fail immediately
            
        // No error or unknown - don't retry
        case ENCRYPTED_DNS_ERROR_NONE:
        default:
            return FALSE;
    }
}
