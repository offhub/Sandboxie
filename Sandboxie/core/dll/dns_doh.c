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
// DNS-over-HTTPS (DoH) Client Implementation
//
// RFC 8484 compliant DoH client using WinHTTP for secure DNS resolution.
// Uses DNS wire format (application/dns-message) per RFC 8484 Section 6.
//
// Design Goals:
//   - Minimal dependencies (WinHTTP only - no external JSON libraries)
//   - Re-entrancy safe: Dual protection via per-thread TLS flag + global query counter
//     (Prevents infinite loops when DoH server queries DNS, WinHTTP uses internal threads)
//   - Response caching (64-entry cache, 300-second default TTL)
//   - Thread-safe initialization with proper synchronization (interlocked atomics)
//   - RFC 8484 compliant: DNS wire format (application/dns-message) via POST
//   - Graceful fallback: Returns synthetic NOERROR+NODATA when DoH unavailable
//
// Concurrency Control (Browser Fix):
//   - Pending query coalescing: Multiple threads requesting same domain wait on single HTTP request
//   - Semaphore limits concurrent DoH queries to 2 (prevents DoH server hammering)
//   - 5-second HTTP timeouts prevent indefinite blocking
//   - Prevents browser freeze when multiple DNS Resolver threads query simultaneously
//
// Backend:
//   - Uses WinHTTP exclusively
//   - If WinHTTP.dll cannot be loaded, DoH is disabled (graceful failure)
//
// DNS Wire Format (RFC 1035):
//   - POST request with application/dns-message Content-Type
//   - Binary DNS query in request body (12-byte header + QNAME + QTYPE + QCLASS)
//   - Binary DNS response in response body (parsed directly from wire format)
//   - Supports all DoH providers (Cloudflare, Google, Quad9, etc.)
//
// Supported Query Types:
//   - DNS_TYPE_A (IPv4): Parsed from wire format Answer section
//   - DNS_TYPE_AAAA (IPv6): Parsed from wire format Answer section
//   - Other types: Pass through to system DNS (only A/AAAA synthesized from DoH)
//
// Configuration:
//   - Requires valid certificate(DNS_HasValidCertificate)
//   - Multi-server support: Up to 8 config lines × 16 servers per line
//   - Round-robin load balancing across config lines AND servers within lines
//   - Failed server cooldown: 30 seconds (automatic failover)
//   - Per-process support: EncryptedDnsServer=[process,]url format
//     * Process-specific configs have HIGHER priority than global configs
//     * Only the highest priority level is used (process-specific overrides global)
//     * Example: nslookup.exe will ONLY use its specific servers, not global ones
//   - Custom ports: https://host[:port][/path] (port defaults to 443; default path /dns-query only for DoH-based modes)
//   - IPv6 support: Use bracket notation https://[2606:4700:4700::1111]/dns-query
//   - URL Schemes:
//     * https://  - HTTP-only mode (DoH3 → DoH2 → DoH, skips DoH3 if StrictBindIP)
//     * httpx://  - HTTP-only mode with self-signed certificate allowed
//     * quic://   - DoQ only (DNS over QUIC)
//     * quicx://  - DoQ only with self-signed certificate
//     * auto://   - AUTO mode with all protocols (DoQ → DoH3 → DoH2 → DoH, skips QUIC if StrictBindIP)
//     * autox://  - AUTO mode with self-signed certificate
//   - Protocol selection: Add ?mode=auto|doh|doh2|doh3|doq|dot
//   - OCSP control: Add ?ocsp=0 to disable OCSP revocation checking, ?ocsp=1 to enable (default: disabled)
//   - User-Agent control: Add ?agent=0 to disable User-Agent (default), ?agent=1 to enable "Sandboxie-DoH/1.0"
//
// Supported Providers:
//   - Cloudflare: https://1.1.1.1/dns-query, https://cloudflare-dns.com/dns-query
//   - Google: https://8.8.8.8/dns-query, https://dns.google/dns-query
//   - Quad9: https://9.9.9.9/dns-query, https://dns.quad9.net/dns-query
//   - Any RFC 8484 compliant server (signed or self-signed cert via httpx://)
//---------------------------------------------------------------------------

#define NOGDI
#include "dll.h"
#include "dns_doh.h"
#include "dns_doq.h"
#include "dns_filter.h"
#include "dns_logging.h"
#include "winhttp_defs.h"  // WinHTTP function pointers and constants

#include <windows.h>
#include <winhttp.h>
#include <wchar.h>
#include <shlwapi.h>  // For UrlEscapeW

// URL escape flags (may not be defined in all SDK versions)
#ifndef URL_ESCAPE_SEGMENT
#define URL_ESCAPE_SEGMENT 0x00000004  // Escape unsafe URL characters
#endif

//---------------------------------------------------------------------------
// DNS Wire Format Structures (RFC 1035)
//---------------------------------------------------------------------------

#pragma pack(push, 1)
typedef struct _DOH_DNS_HEADER {
    USHORT TransactionID;
    USHORT Flags;
    USHORT Questions;
    USHORT AnswerRRs;
    USHORT AuthorityRRs;
    USHORT AdditionalRRs;
} DOH_DNS_HEADER;
#pragma pack(pop)

// DNS wire format constants
#define DOH_DNS_QCLASS_IN 0x0001  // Internet class
#define DOH_DNS_TYPE_A    0x0001  // IPv4
#define DOH_DNS_TYPE_AAAA 0x001C  // IPv6

//---------------------------------------------------------------------------
// HTTP Backend Selection
//---------------------------------------------------------------------------

typedef enum _DOH_HTTP_BACKEND {
    DOH_BACKEND_NONE = 0,       // Not initialized
    DOH_BACKEND_WINHTTP,        // WinHTTP
    DOH_BACKEND_FAILED          // Backend failed to load, don't retry
} DOH_HTTP_BACKEND;

//---------------------------------------------------------------------------
// WinHTTP Function Pointers and Constants
//
// Moved to winhttp_defs.h for shared use across modules.
// See winhttp_defs.h for P_WinHttpOpen, P_WinHttpConnect, P_WinHttpOpenRequest,
// P_WinHttpSendRequest, P_WinHttpReceiveResponse, P_WinHttpQueryHeaders,
// P_WinHttpReadData, P_WinHttpCloseHandle, P_WinHttpSetOption,
// P_WinHttpSetTimeouts, P_WinHttpQueryOption typedefs and WINHTTP_* constants.
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
// Multi-Server Support Structures
// Supports up to 8 config lines (EncryptedDnsServer settings), each with up to 16 servers
// Round-robin load balancing across both lines and servers within lines
// Failed servers enter 30-second cooldown before retry
// Note: DOH_MAX_SERVERS_PER_LINE, DOH_MAX_CONFIG_LINES, DOH_SERVER_FAIL_COOLDOWN 
//       are defined in dns_doh.h
//---------------------------------------------------------------------------

// Protocol backoff tracking for AUTO mode
// Each protocol can fail independently and enter backoff
typedef struct _DOH_PROTOCOL_BACKOFF {
    ULONGLONG BackoffUntil;     // GetTickCount64() tick when protocol can retry (0 = available)
    ULONG FailCount;            // Number of consecutive failures (for incremental backoff)
} DOH_PROTOCOL_BACKOFF;

typedef struct _DOH_SERVER {
    WCHAR Url[512];             // Full URL for logging/debugging
    WCHAR Host[DOH_DOMAIN_MAX_LEN]; // Hostname extracted from URL
    WCHAR Path[DOH_DOMAIN_MAX_LEN]; // Request path (default: /dns-query for DoH/AUTO; empty for DoQ/DoT)
    INTERNET_PORT Port;         // Port from URL (default based on mode)
    INTERNET_PORT PortDoQ;      // Port for DoQ (853 by default, used in AUTO mode)
    ULONGLONG FailedUntil;      // GetTickCount64() tick when server can retry (0 = available)
    BOOLEAN SelfSigned;         // TRUE if httpx:// (self-signed cert), FALSE if https:// (signed cert)
    BOOLEAN DisableOCSP;        // TRUE to disable OCSP revocation checking
    BOOLEAN EnableAgent;        // TRUE to send User-Agent header (default: FALSE for privacy)
    CHAR Http3Mode;             // 0=HTTP/2 only (default), 1=HTTP/3 only, -1=auto (prefer HTTP/3, fallback to HTTP/2)
    ULONGLONG Http3FallbackUntil; // GetTickCount64() tick until HTTP/3 is skipped (incremental backoff)
    ULONG Http3FailCount;       // Number of consecutive HTTP/3 failures (for incremental backoff)
    ENCRYPTED_DNS_MODE ProtocolMode; // Protocol mode: DoH, DoH2, DoH3, DoQ, DoT, AUTO
    BOOLEAN HttpOnlyAuto;        // TRUE if AUTO should skip DoQ (https:// / httpx:// default)
    BOOLEAN ProtocolLocked;      // TRUE if configuration requires ONLY ProtocolMode (quic:// or explicit ?mode=... except auto)
    BOOLEAN StrictBindIpQuicDisable; // TRUE to disable QUIC protocols under StrictBindIP (default); set ?strict=0 to allow QUIC even with StrictBindIP
    
    // AUTO mode protocol backoff tracking
    // Each protocol has independent failure tracking for fallback chain: DoQ → DoH3 → DoH2 → DoH
    DOH_PROTOCOL_BACKOFF AutoBackoff[5]; // Indexed by ENCRYPTED_DNS_MODE (0=DoH, 1=DoH2, 2=DoH3, 3=DoQ, 4=DoT)
} DOH_SERVER;

typedef struct _DOH_CONFIG_LINE {
    DOH_SERVER Servers[DOH_MAX_SERVERS_PER_LINE];
    ULONG ServerCount;          // Number of servers in this config line (1-16)
    ULONG CurrentServer;        // Round-robin index within this line
    ULONG Level;                // Config match level (0=global, 1=process, higher=more specific)
} DOH_CONFIG_LINE;

//---------------------------------------------------------------------------
// Global State - All access must be synchronized
//---------------------------------------------------------------------------

// Initialization state (interlocked access - prevents race during startup)
static volatile LONG g_DohInitStarted = 0;
static volatile LONG g_DohInitComplete = 0;

// Configuration (protected by g_DohConfigLock after loaded)
// g_DohConfigLines: Array of config lines (from multiple EncryptedDnsServer settings)
// g_DohConfigLineCount: Total number of loaded config lines (max 8)
// g_DohCurrentConfigLine: Round-robin pointer across config lines for load balancing
static DOH_CONFIG_LINE g_DohConfigLines[DOH_MAX_CONFIG_LINES];
static ULONG g_DohConfigLineCount = 0;
static ULONG g_DohCurrentConfigLine = 0;
static volatile LONG g_DohConfigured = 0;
static CRITICAL_SECTION g_DohConfigLock;
static volatile LONG g_DohConfigLockValid = 0;

// OS version for WinHTTP settings (Windows version detection)
static DWORD g_OsMajorVersion = 0;
static DWORD g_OsMinorVersion = 0;
static DWORD g_OsBuildNumber = 0;

// Connection pool for persistent HTTP connections (prevents connection spam)
// Cache connections per server to reuse them across multiple DNS queries
// Key: server:port (e.g., "cloudflare-dns.com:443")
// Value: HINTERNET connection handle
// NOTE: WinHTTP connection handles are NOT thread-safe for concurrent requests.
//       The InUse flag prevents multiple threads from using the same handle simultaneously.
// Note: DOH_MAX_POOL_CONNECTIONS defined in dns_doh.h

typedef struct _DOH_CONNECTION_POOL {
    WCHAR ServerKey[512];       // "host:port" for lookup/deduplication
    HINTERNET hConnect;         // Cached connection handle
    ULONGLONG LastUsed;         // GetTickCount64() for LRU eviction
    volatile LONG InUse;        // 1 if currently in use by a thread, 0 if available
    DWORD ProtocolMask;         // WINHTTP_PROTOCOL_FLAG_* mask used when creating/reusing this connection
} DOH_CONNECTION_POOL;

static DOH_CONNECTION_POOL g_DohConnPool[DOH_MAX_POOL_CONNECTIONS];
static ULONG g_DohConnPoolCount = 0;
static CRITICAL_SECTION g_DohConnPoolLock;
static volatile LONG g_DohConnPoolLockValid = 0;

// Connection pool statistics (for performance monitoring)
static volatile LONG g_DohConnPoolHits = 0;     // Reused existing connection
static volatile LONG g_DohConnPoolMisses = 0;   // Created new connection
static volatile LONG g_DohConnPoolEvictions = 0; // Evicted LRU connection

// Backend state (protected by g_DohLock)
// Session handle for persistent HTTP connections
static CRITICAL_SECTION g_DohLock;
static volatile LONG g_DohLockValid = 0;
static DOH_HTTP_BACKEND g_DohBackend = DOH_BACKEND_NONE;
static HINTERNET g_hWinHttpSession = NULL;

// WinHTTP function pointers
static P_WinHttpOpen __sys_WinHttpOpen = NULL;
static P_WinHttpConnect __sys_WinHttpConnect = NULL;
static P_WinHttpOpenRequest __sys_WinHttpOpenRequest = NULL;
static P_WinHttpSendRequest __sys_WinHttpSendRequest = NULL;
static P_WinHttpReceiveResponse __sys_WinHttpReceiveResponse = NULL;
static P_WinHttpQueryHeaders __sys_WinHttpQueryHeaders = NULL;
static P_WinHttpQueryOption __sys_WinHttpQueryOption = NULL;
static P_WinHttpReadData __sys_WinHttpReadData = NULL;
static P_WinHttpCloseHandle __sys_WinHttpCloseHandle = NULL;
static P_WinHttpSetOption __sys_WinHttpSetOption = NULL;
static P_WinHttpSetTimeouts __sys_WinHttpSetTimeouts = NULL;

// UrlEscape function pointer from Shlwapi.dll
typedef HRESULT (WINAPI *P_UrlEscapeW)(
    LPCWSTR pszUrl,
    LPWSTR pszEscaped,
    LPDWORD pcchEscaped,
    DWORD dwFlags
);
static P_UrlEscapeW __sys_UrlEscapeW = NULL;

// Cache state - Stores resolved DoH responses to reduce network round-trips
// Each entry caches A/AAAA queries by domain+type with 300-second TTL
// Cache size: 64 entries maximum (typical for light DNS usage)
// Thread safety: Protected by g_DohCacheLock critical section
// Note: DOH_CACHE_SIZE and DOH_DEFAULT_TTL are defined in dns_doh.h

typedef struct _DOH_CACHE_ENTRY {
    WCHAR domain[DOH_DOMAIN_MAX_LEN];
    USHORT qtype;
    ULONGLONG expiry;           // Tick count when entry expires
    DOH_RESULT result;          // Cached DoH response (status, IPs, TTL)
    BOOLEAN is_failure;          // TRUE if this is a cached failure (negative cache)
    BOOLEAN is_bind_failure;     // TRUE if failure caused by BindAdapter/BindAdapterIP being down
    BOOLEAN valid;              // Entry is populated and not expired
} DOH_CACHE_ENTRY;

static DOH_CACHE_ENTRY g_DohCache[DOH_CACHE_SIZE];
static CRITICAL_SECTION g_DohCacheLock;
static volatile LONG g_DohCacheLockValid = 0;

// Global re-entrancy protection (for multi-threaded HTTP libraries)
// Problem: When user queries a domain, we make a DoH query to resolve the DoH server's hostname.
// If system tries to resolve the DoH server again from within the DoH query, we get infinite loop.
// Solution: Use global counter (g_DohActiveQueries) to detect cross-thread re-entrancy from WinHTTP
//           internal threads. Combined with per-thread TLS flag (dns_in_doh_query) for same-thread loops.
static volatile LONG g_DohActiveQueries = 0;

// Log suppression flag for StrictBindIP downgrade messages
// When StrictBindIP is active, QUIC protocols are disabled.
// We log this once at parse-time and runtime to avoid spam.
BOOLEAN g_LoggedStrictBindIPDowngrade = FALSE;

// Log suppression for StrictBindIP blocking protocol-locked QUIC modes.
// When user explicitly requests a QUIC-only mode (quic://, mode=doq, mode=doh3)
// we do NOT downgrade; this message explains why queries fail in that case.
static BOOLEAN g_LoggedStrictBindIPBlockedLocked = FALSE;

// Log suppression for StrictBindIP override (?strict=0).
// When StrictBindIP is active, QUIC protocols are usually skipped/blocked.
// If a server URL explicitly sets ?strict=0, we log once to make it obvious
// that QUIC is allowed despite StrictBindIP.
static BOOLEAN g_LoggedStrictBindIPStrictOverride = FALSE;

//---------------------------------------------------------------------------
// Pending Query Coalescing - Prevent multiple threads from hammering DoH server
//
// Problem: Some browsers use multiple DNS Resolver threads that query different domains simultaneously.
//          Each thread makes its own DoH HTTP request, causing many concurrent WinHTTP calls.
//          This hammers the DoH server and all threads block waiting for HTTP responses.
//
// Solution: Track pending queries by domain+type. When a thread requests a domain that's already
//           being queried, it WAITS on an event instead of making a duplicate HTTP request.
//           When the first query completes, it signals the event and all waiters read from cache.
//
// Concurrency: Use a semaphore to limit concurrent DoH requests (max 2) to avoid overwhelming
//              the DoH server. This is in ADDITION to coalescing - different domains still wait.
// Note: DOH_MAX_PENDING_QUERIES, DOH_MAX_CONCURRENT_QUERIES defined in dns_doh.h
//---------------------------------------------------------------------------

typedef struct _DOH_PENDING_QUERY {
    WCHAR Domain[DOH_DOMAIN_MAX_LEN];  // Domain being queried
    USHORT QType;               // Query type (A/AAAA)
    HANDLE Event;               // Event signaled when query completes
    volatile LONG WaiterCount;  // Number of threads waiting on this query
    volatile LONG Completed;    // 1 if query completed (success or failure)
    BOOLEAN Valid;              // Entry is active
} DOH_PENDING_QUERY;

static DOH_PENDING_QUERY g_DohPendingQueries[DOH_MAX_PENDING_QUERIES];
static CRITICAL_SECTION g_DohPendingLock;
static volatile LONG g_DohPendingLockValid = 0;
static HANDLE g_DohQuerySemaphore = NULL;  // Limits concurrent DoH requests

//---------------------------------------------------------------------------
// External Functions
//---------------------------------------------------------------------------

extern ULONGLONG GetTickCount64(void);
extern BOOLEAN DNS_TraceFlag;
extern BOOLEAN DNS_DebugFlag;

#if !defined(_DNSDEBUG)
// Release builds: compile out debug-only logging paths.
// This keeps hot paths free of DNS_DebugFlag checks.
#undef DNS_DebugFlag
#define DNS_DebugFlag 0
#endif

// Encrypted DNS protocol helpers (from dns_encrypted.c)
extern const WCHAR* EncryptedDns_GetModeName(ENCRYPTED_DNS_MODE mode);
extern USHORT EncryptedDns_GetDefaultPort(ENCRYPTED_DNS_MODE mode);
extern BOOLEAN EncryptedDns_IsHttpBased(ENCRYPTED_DNS_MODE mode);
extern BOOLEAN EncryptedDns_IsQuicBased(ENCRYPTED_DNS_MODE mode);
extern BOOLEAN EncryptedDns_IsTlsBased(ENCRYPTED_DNS_MODE mode);
extern BOOLEAN EncryptedDns_WinHttpSupportsHttp3(void);
extern ENCRYPTED_DNS_MODE EncryptedDns_GetNextAutoProtocol(ENCRYPTED_DNS_MODE current);
extern ULONG EncryptedDns_GetBackoffMs(ULONG failCount);

//---------------------------------------------------------------------------
// Re-entrancy Protection (per-thread via TLS)
//---------------------------------------------------------------------------

static BOOLEAN EncDns_GetInQuery(void)
{
    THREAD_DATA *data = Dll_GetTlsData(NULL);
    return data ? data->dns_in_doh_query : FALSE;
}

static void EncDns_SetInQuery(BOOLEAN value)
{
    THREAD_DATA *data = Dll_GetTlsData(NULL);
    if (data)
        data->dns_in_doh_query = value;
}

//---------------------------------------------------------------------------
// OS Version Accessors (for EncryptedDns_WinHttpSupportsHttp3)
//---------------------------------------------------------------------------

_FX DWORD DoH_GetOsMajorVersion(void)
{
    return g_OsMajorVersion;
}

_FX DWORD DoH_GetOsMinorVersion(void)
{
    return g_OsMinorVersion;
}

_FX DWORD DoH_GetOsBuildNumber(void)
{
    return g_OsBuildNumber;
}

//---------------------------------------------------------------------------
// Protocol Selection Result Structure (for DoH_SelectProtocolMode)
//---------------------------------------------------------------------------

typedef struct _DOH_PROTOCOL_SELECTION {
    DWORD   ProtocolMask;           // WINHTTP_PROTOCOL_FLAG_HTTP2/HTTP3 mask
    BOOLEAN Http3Enabled;           // TRUE if HTTP/3 is enabled for this request
    BOOLEAN CanUseHttp3;            // TRUE if system supports HTTP/3
    BOOLEAN CanUseEnableProtocol;   // TRUE if WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL supported
    const WCHAR* DecisionReason;    // Human-readable reason for logging
} DOH_PROTOCOL_SELECTION;

//---------------------------------------------------------------------------
// Forward Declarations
//---------------------------------------------------------------------------

static BOOLEAN EncDns_ParseUrlToServer(const WCHAR* url, DOH_SERVER* server);
static BOOLEAN EncDns_LoadBackends(void);
static BOOLEAN EncDns_Request(const WCHAR* domain, USHORT qtype, BYTE* response, DWORD response_size, DWORD* bytes_read, ENCRYPTED_DNS_MODE* protocol_used_out);
static BOOLEAN EncDns_RequestToServer(DOH_SERVER* server, const WCHAR* domain, USHORT qtype, BYTE* response, DWORD response_size, DWORD* bytes_read, ENCRYPTED_DNS_MODE* protocol_used_out);
static BOOLEAN DoH_HttpRequest_WinHttp(DOH_SERVER* server, const WCHAR* domain, USHORT qtype, BYTE* response, DWORD response_size, DWORD* bytes_read, ENCRYPTED_DNS_MODE* protocol_used_out);

// Helper functions for DoH_HttpRequest_WinHttp decomposition
static BOOLEAN DoH_SelectProtocolMode(DOH_SERVER* server, ULONGLONG now, DOH_PROTOCOL_SELECTION* result);
static void DoH_ConfigureSecurityOptions(HINTERNET hRequest, DOH_SERVER* server);
static void DoH_ValidateProtocolUsed(HINTERNET hRequest, DOH_SERVER* server, 
    DOH_PROTOCOL_SELECTION* proto, BOOLEAN* result, DWORD* bytes_read, ULONGLONG now, DWORD* proto_used_out);
static BOOLEAN EncDns_ParseDnsResponse(const BYTE* response, int responseLen, DOH_RESULT* pResult);
static BOOLEAN DoH_ParseJsonResponse(const WCHAR* json, DOH_RESULT* pResult);
static BOOLEAN EncDns_CacheLookup(const WCHAR* domain, USHORT qtype, DOH_RESULT* pResult);
static void EncDns_CacheStore(const WCHAR* domain, USHORT qtype, const DOH_RESULT* pResult, BOOLEAN is_failure, BOOLEAN is_bind_failure);
static DOH_SERVER* EncDns_SelectServer(ULONGLONG now);

static void EncDns_CachePurgeFailures(BOOLEAN only_bind_failures);
static void EncDns_ResetAllServerFailures(void);
static void EncDns_CheckBindAdapterRecovery(void);

//---------------------------------------------------------------------------
// DoH_LogWinHttpProxyInfo (diagnostic)
//---------------------------------------------------------------------------

static void DoH_LogWinHttpProxyInfo(HINTERNET hInternet, const WCHAR* context)
{
    if ((!DNS_TraceFlag && !DNS_DebugFlag) || !hInternet || !__sys_WinHttpQueryOption)
        return;

    DWORD size = 0;
    __sys_WinHttpQueryOption(hInternet, WINHTTP_OPTION_PROXY, NULL, &size);
    DWORD err = GetLastError();
    if (err != ERROR_INSUFFICIENT_BUFFER || size == 0 || size > (64 * 1024))
        return;

    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf)
        return;

    if (__sys_WinHttpQueryOption(hInternet, WINHTTP_OPTION_PROXY, buf, &size)) {
        WINHTTP_PROXY_INFO* pi = (WINHTTP_PROXY_INFO*)buf;

        const WCHAR* access = L"unknown";
        switch (pi->dwAccessType) {
        case WINHTTP_ACCESS_TYPE_NO_PROXY:        access = L"no-proxy"; break;
        case WINHTTP_ACCESS_TYPE_DEFAULT_PROXY:   access = L"default"; break;
        case WINHTTP_ACCESS_TYPE_NAMED_PROXY:     access = L"named"; break;
        case WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY: access = L"auto"; break;
        default: break;
        }

        WCHAR proxy[256];
        WCHAR bypass[256];
        proxy[0] = L'\0';
        bypass[0] = L'\0';

        if (pi->lpszProxy && pi->lpszProxy[0]) {
            wcsncpy(proxy, pi->lpszProxy, 255);
            proxy[255] = L'\0';
        }
        if (pi->lpszProxyBypass && pi->lpszProxyBypass[0]) {
            wcsncpy(bypass, pi->lpszProxyBypass, 255);
            bypass[255] = L'\0';
        }

        if (DNS_TraceFlag) {
            WCHAR msg[768];
            Sbie_snwprintf(msg, 768, L"[DoH] WinHTTP proxy (%s): access=%s proxy='%s' bypass='%s'",
                context ? context : L"?",
                access,
                proxy[0] ? proxy : L"(none)",
                bypass[0] ? bypass : L"(none)");
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    }

    HeapFree(GetProcessHeap(), 0, buf);
}

//---------------------------------------------------------------------------
// Connection Pool Management - Prevent connection spam
//---------------------------------------------------------------------------

static void DoH_InitConnPool(void)
{
    if (InterlockedCompareExchange(&g_DohConnPoolLockValid, 1, 0) == 0) {
        InitializeCriticalSection(&g_DohConnPoolLock);
        g_DohConnPoolCount = 0;
        memset(g_DohConnPool, 0, sizeof(g_DohConnPool));
    }
}

static void DoH_CloseConnPool(void)
{
    if (InterlockedCompareExchange(&g_DohConnPoolLockValid, 0, 1) == 1) {
        EnterCriticalSection(&g_DohConnPoolLock);
        
        for (ULONG i = 0; i < g_DohConnPoolCount; i++) {
            if (g_DohConnPool[i].hConnect && __sys_WinHttpCloseHandle) {
                __sys_WinHttpCloseHandle(g_DohConnPool[i].hConnect);
            }
        }
        
        g_DohConnPoolCount = 0;
        memset(g_DohConnPool, 0, sizeof(g_DohConnPool));
        
        LeaveCriticalSection(&g_DohConnPoolLock);
        DeleteCriticalSection(&g_DohConnPoolLock);
    }
}

// Get or create cached connection for server
// Returns HINTERNET connection handle (valid until cleanup)
// Sets *pbIsPooled to TRUE if returned handle is in pool, FALSE if temporary
// Thread-safe: Holds pool lock during entire operation to prevent concurrent creation
static HINTERNET DoH_GetPooledConnection(const WCHAR* host, INTERNET_PORT port, DWORD protocolMask, BOOLEAN* pbIsPooled)
{
    if (!InterlockedCompareExchange(&g_DohConnPoolLockValid, 0, 0))
        return NULL;

    if (pbIsPooled)
        *pbIsPooled = FALSE;

    EnterCriticalSection(&g_DohConnPoolLock);

    // Build server key for lookup (include protocol mode)
    WCHAR serverKey[512];
    const WCHAR* protoTag = L"h2";
    if ((protocolMask & WINHTTP_PROTOCOL_MASK) == WINHTTP_PROTOCOL_FLAG_HTTP3) {
        protoTag = L"h3";
    } else if ((protocolMask & WINHTTP_PROTOCOL_MASK) == (WINHTTP_PROTOCOL_FLAG_HTTP2 | WINHTTP_PROTOCOL_FLAG_HTTP3)) {
        protoTag = L"h23";
    } else {
        protoTag = L"h2";
    }

    if (port == INTERNET_DEFAULT_HTTPS_PORT) {
        Sbie_snwprintf(serverKey, sizeof(serverKey) / sizeof(WCHAR), L"%s|%s", host, protoTag);
    } else {
        Sbie_snwprintf(serverKey, sizeof(serverKey) / sizeof(WCHAR), L"%s:%d|%s", host, port, protoTag);
    }
    _wcslwr(serverKey);  // Normalize to lowercase for comparison

    // Search for existing connection that is NOT currently in use
    // WinHTTP connection handles are NOT thread-safe for concurrent requests
    for (ULONG i = 0; i < g_DohConnPoolCount; i++) {
        if (_wcsicmp(g_DohConnPool[i].ServerKey, serverKey) == 0 && g_DohConnPool[i].ProtocolMask == protocolMask) {
            // Found matching connection - try to acquire it atomically
            if (InterlockedCompareExchange(&g_DohConnPool[i].InUse, 1, 0) == 0) {
                // Successfully acquired! Mark as in use, update LRU
                g_DohConnPool[i].LastUsed = GetTickCount64();
                HINTERNET hConn = g_DohConnPool[i].hConnect;
                if (pbIsPooled)
                    *pbIsPooled = TRUE;
                InterlockedIncrement(&g_DohConnPoolHits);
                LeaveCriticalSection(&g_DohConnPoolLock);
                
                if (DNS_DebugFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"[DoH] Reusing pooled connection to %s:%d (%s) (pool: %d/%d, hits: %d)",
                        host, port, protoTag, g_DohConnPoolCount, DOH_MAX_POOL_CONNECTIONS, g_DohConnPoolHits);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
                return hConn;
            }
            // Connection found but currently in use by another thread - skip it
        }
    }

    // No available connection - create new one after releasing lock to avoid blocking other threads
    HINTERNET hConnect = NULL;
    BOOLEAN created = FALSE;
    HINTERNET hSession = NULL;
    
    // Capture session handle before releasing lock
    if (!g_hWinHttpSession || !__sys_WinHttpConnect) {
        // Log why we're failing early
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DoH] GetPooledConnection failed: session=0x%p, func=0x%p", 
            g_hWinHttpSession, __sys_WinHttpConnect);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        LeaveCriticalSection(&g_DohConnPoolLock);
        return NULL;
    }
    hSession = g_hWinHttpSession;
    
    // Release lock before blocking network call to reduce contention
    LeaveCriticalSection(&g_DohConnPoolLock);
    
    // Create connection without holding lock (may block on network)
    hConnect = __sys_WinHttpConnect(hSession, host, port, 0);
    created = (hConnect != NULL);
    
    if (!created) {
        // Always log WinHttpConnect failures - this is a critical issue
        DWORD lastError = GetLastError();
        WCHAR msg[320];
        Sbie_snwprintf(msg, 320, L"[DoH] WinHttpConnect failed for %s:%d (error %lu, session=0x%p, func=0x%p)", 
            host, port, lastError, hSession, __sys_WinHttpConnect);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    // Re-acquire lock to insert into pool
    EnterCriticalSection(&g_DohConnPoolLock);

    if (created) {
        InterlockedIncrement(&g_DohConnPoolMisses);
        if (g_DohConnPoolCount < DOH_MAX_POOL_CONNECTIONS) {
            DOH_CONNECTION_POOL* pool = &g_DohConnPool[g_DohConnPoolCount++];
            wcscpy(pool->ServerKey, serverKey);
            pool->hConnect = hConnect;
            pool->LastUsed = GetTickCount64();
            pool->InUse = 1;  // Mark as in use immediately
            pool->ProtocolMask = protocolMask;
            if (pbIsPooled)
                *pbIsPooled = TRUE;

            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"[DoH] Created and cached connection to %s:%d (%s) (pool: %d/%d, misses: %d)",
                    host, port, protoTag, g_DohConnPoolCount, DOH_MAX_POOL_CONNECTIONS, g_DohConnPoolMisses);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
        } else {
            // Pool full - find LRU entry that is NOT in use
            ULONG lruIdx = 0;
            ULONGLONG oldestTime = ULLONG_MAX;
            BOOLEAN foundAvailable = FALSE;

            for (ULONG i = 0; i < DOH_MAX_POOL_CONNECTIONS; i++) {
                if (g_DohConnPool[i].InUse == 0 && g_DohConnPool[i].LastUsed < oldestTime) {
                    lruIdx = i;
                    oldestTime = g_DohConnPool[i].LastUsed;
                    foundAvailable = TRUE;
                }
            }

            if (foundAvailable) {
                InterlockedIncrement(&g_DohConnPoolEvictions);
                // Close old connection
                if (g_DohConnPool[lruIdx].hConnect && __sys_WinHttpCloseHandle) {
                    __sys_WinHttpCloseHandle(g_DohConnPool[lruIdx].hConnect);
                }

                // Replace with new connection
                wcscpy(g_DohConnPool[lruIdx].ServerKey, serverKey);
                g_DohConnPool[lruIdx].hConnect = hConnect;
                g_DohConnPool[lruIdx].LastUsed = GetTickCount64();
                g_DohConnPool[lruIdx].InUse = 1;  // Mark as in use
                g_DohConnPool[lruIdx].ProtocolMask = protocolMask;
                if (pbIsPooled)
                    *pbIsPooled = TRUE;

                if (DNS_DebugFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"[DoH] Evicted LRU connection, cached to %s (pool: %d/%d, evictions: %d)",
                        host, g_DohConnPoolCount, DOH_MAX_POOL_CONNECTIONS, g_DohConnPoolEvictions);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
            } else {
                // All connections in pool are in use - don't cache this one, just use it temporarily
                if (DNS_DebugFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"[DoH] Pool full and all in use, using temporary connection to %s",
                        host);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
                // hConnect will be returned but not cached - caller will close it after use
            }
        }
    }

    LeaveCriticalSection(&g_DohConnPoolLock);
    return hConnect;
}

//---------------------------------------------------------------------------
// DoH_ReleasePooledConnection - Release connection back to pool after use
// Thread-safe: Can be called concurrently from multiple threads
//---------------------------------------------------------------------------

static void DoH_ReleasePooledConnection(HINTERNET hConnect, BOOLEAN shouldClose)
{
    if (!hConnect || !InterlockedCompareExchange(&g_DohConnPoolLockValid, 0, 0))
        return;

    EnterCriticalSection(&g_DohConnPoolLock);

    // Find the connection in the pool and mark as available
    for (ULONG i = 0; i < g_DohConnPoolCount; i++) {
        if (g_DohConnPool[i].hConnect == hConnect) {
            if (shouldClose) {
                // Close and remove from pool
                if (__sys_WinHttpCloseHandle) {
                    __sys_WinHttpCloseHandle(g_DohConnPool[i].hConnect);
                }
                
                // Shift remaining entries down
                for (ULONG j = i; j < g_DohConnPoolCount - 1; j++) {
                    g_DohConnPool[j] = g_DohConnPool[j + 1];
                }
                g_DohConnPoolCount--;
            } else {
                // Mark as available for reuse
                InterlockedExchange(&g_DohConnPool[i].InUse, 0);
            }
            LeaveCriticalSection(&g_DohConnPoolLock);
            return;
        }
    }

    // Connection not found in pool - it's a temporary connection, close it
    LeaveCriticalSection(&g_DohConnPoolLock);
    
    if (shouldClose && __sys_WinHttpCloseHandle) {
        __sys_WinHttpCloseHandle(hConnect);
    }
}

//---------------------------------------------------------------------------
// Pending Query Coalescing - Prevent parallel HTTP requests for same domain
//
// When multiple threads request the same domain simultaneously:
// 1. First thread creates pending entry and performs HTTP request
// 2. Other threads find pending entry and wait on its event
// 3. First thread completes, signals event, stores result in cache
// 4. Waiting threads wake up and read from cache
//---------------------------------------------------------------------------

// Find or create pending query entry for domain+type
// Returns: Pointer to existing pending query (caller should wait on event)
//          NULL if no pending query found (caller should create one and perform request)
static DOH_PENDING_QUERY* EncDns_FindPendingQuery(const WCHAR* domain, USHORT qtype)
{
    if (!InterlockedCompareExchange(&g_DohPendingLockValid, 0, 0))
        return NULL;

    EnterCriticalSection(&g_DohPendingLock);

    // Search for existing pending query
    for (ULONG i = 0; i < DOH_MAX_PENDING_QUERIES; i++) {
        if (g_DohPendingQueries[i].Valid && 
            g_DohPendingQueries[i].QType == qtype &&
            _wcsicmp(g_DohPendingQueries[i].Domain, domain) == 0) {
            // Found! Increment waiter count
            InterlockedIncrement(&g_DohPendingQueries[i].WaiterCount);
            LeaveCriticalSection(&g_DohPendingLock);
            return &g_DohPendingQueries[i];
        }
    }

    LeaveCriticalSection(&g_DohPendingLock);
    return NULL;
}

// Create new pending query entry (caller will perform HTTP request)
// Returns: Pointer to new pending query, or NULL if table full
static DOH_PENDING_QUERY* EncDns_CreatePendingQuery(const WCHAR* domain, USHORT qtype)
{
    if (!InterlockedCompareExchange(&g_DohPendingLockValid, 0, 0))
        return NULL;

    EnterCriticalSection(&g_DohPendingLock);

    // Find empty slot
    for (ULONG i = 0; i < DOH_MAX_PENDING_QUERIES; i++) {
        if (!g_DohPendingQueries[i].Valid) {
            // Create event for waiters (manual reset, initially unsignaled)
            HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            if (!hEvent) {
                LeaveCriticalSection(&g_DohPendingLock);
                return NULL;
            }

            wcsncpy(g_DohPendingQueries[i].Domain, domain, 255);
            g_DohPendingQueries[i].Domain[255] = L'\0';
            g_DohPendingQueries[i].QType = qtype;
            g_DohPendingQueries[i].Event = hEvent;
            g_DohPendingQueries[i].WaiterCount = 0;
            g_DohPendingQueries[i].Completed = 0;
            g_DohPendingQueries[i].Valid = TRUE;

            if (DNS_DebugFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"[EncDns] Created pending query for %s (type %d)", domain, qtype);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }

            LeaveCriticalSection(&g_DohPendingLock);
            return &g_DohPendingQueries[i];
        }
    }

    if (DNS_DebugFlag) {
        SbieApi_MonitorPutMsg(MONITOR_DNS, L"[EncDns] Pending query table full");
    }

    LeaveCriticalSection(&g_DohPendingLock);
    return NULL;
}

// Complete pending query and signal all waiters
static void EncDns_CompletePendingQuery(DOH_PENDING_QUERY* pending)
{
    if (!pending)
        return;

    // Mark as completed and signal event
    InterlockedExchange(&pending->Completed, 1);
    if (pending->Event) {
        SetEvent(pending->Event);
    }

    if (DNS_DebugFlag) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"[EncDns] Completed pending query for %s (waiters: %d)", 
            pending->Domain, pending->WaiterCount);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
}

// Remove pending query entry (called by last thread to leave)
static void EncDns_RemovePendingQuery(DOH_PENDING_QUERY* pending)
{
    if (!pending || !InterlockedCompareExchange(&g_DohPendingLockValid, 0, 0))
        return;

    EnterCriticalSection(&g_DohPendingLock);

    // Check if a new waiter attached to this query while we were waiting for the lock.
    // If WaiterCount >= 0, it means there are active waiters (or a new waiter just arrived),
    // so we must NOT remove the entry yet. The last waiter to leave will remove it.
    if (pending->WaiterCount >= 0) {
        LeaveCriticalSection(&g_DohPendingLock);
        return;
    }

    // Close event handle
    if (pending->Event) {
        CloseHandle(pending->Event);
        pending->Event = NULL;
    }

    // Clear entry
    memset(pending, 0, sizeof(DOH_PENDING_QUERY));

    LeaveCriticalSection(&g_DohPendingLock);
}

// Decrement waiter count and clean up if last waiter
static void EncDns_ReleaseWaiter(DOH_PENDING_QUERY* pending)
{
    if (!pending)
        return;

    LONG count = InterlockedDecrement(&pending->WaiterCount);
    
    // If we're the last waiter and query is completed, clean up
    // Note: The original querier doesn't decrement WaiterCount, so when it reaches -1
    // all waiters have left and we can clean up
    if (count < 0 && pending->Completed) {
        EncDns_RemovePendingQuery(pending);
    }
}

//---------------------------------------------------------------------------
// EncDns_ParseUrlToServer - Parse encrypted DNS server URL into server structure
//
// Supported URL schemes:
//   https://  - HTTP-only mode (DoH3 → DoH2 → DoH)
//   httpx://  - HTTP-only mode with self-signed certificate allowed
//   quic://   - DoQ only (DNS over QUIC, signed certificate)
//   quicx://  - DoQ only (self-signed certificate allowed)
//   auto://   - AUTO mode with all protocols (DoQ → DoH3 → DoH2 → DoH, skips QUIC if StrictBindIP)
//   autox://  - AUTO mode with self-signed certificate
//
// Query parameters:
//   ?mode=auto|doh|doh2|doh3|doq|dot  - Protocol mode (overrides scheme detection)
//   ?ocsp=0|1     - OCSP revocation checking (0=disable, 1=enable)
//   ?agent=0|1    - User-Agent header (0=disable, 1=enable)
//   ?strict=0|1   - QUIC under StrictBindIP (default: 1). If 0, do NOT skip/downgrade QUIC protocols when StrictBindIP is active.
//
// Default ports by mode:
//   DoH/DoH2/DoH3: 443 (HTTPS)
//   DoQ/DoT: 853 (RFC 9250/7858)
//
// AUTO mode behavior:
//   - Default order: DoQ → DoH3 → DoH2 → DoH
//   - Skips DoQ and DoH3 if StrictBindIP is active (QUIC UDP listener always binds to dual-mode wildcard address)
//   - Skips DoH3 if OS doesn't support HTTP/3 (Windows 10)
//   - Skips DoQ if msquic.dll not available
//---------------------------------------------------------------------------

static BOOLEAN EncDns_ParseUrlToServer(const WCHAR* url, DOH_SERVER* server)
{
    const WCHAR* p = url;
    const WCHAR* host_start;
    const WCHAR* path_start;
    SIZE_T host_len;
    BOOLEAN self_signed = FALSE;
    BOOLEAN explicit_port = FALSE;
    ENCRYPTED_DNS_MODE detected_mode = ENCRYPTED_DNS_MODE_DOH;

    if (!url || !*url || !server)
        return FALSE;

    memset(server, 0, sizeof(DOH_SERVER));

    // Initialize default values
    server->DisableOCSP = FALSE;  // Default: OCSP enabled
    server->EnableAgent = FALSE;  // Default: No User-Agent (privacy)
    server->Http3Mode = 0;        // Default: HTTP/2 only (for DoH)
    server->Http3FallbackUntil = 0;
    server->Http3FailCount = 0;
    server->ProtocolMode = ENCRYPTED_DNS_MODE_AUTO;  // Will be determined later
    server->HttpOnlyAuto = FALSE;
    server->ProtocolLocked = FALSE;
    server->StrictBindIpQuicDisable = TRUE;

    // Check URL scheme and detect initial mode
    // https:// and httpx:// use HTTP-only mode (DoH3 → DoH2 → DoH, skips DoH3 if StrictBindIP)
    // quic:// and quicx:// force DoQ mode explicitly
    // auto:// and autox:// request AUTO mode with all protocols (DoQ → DoH3 → DoH2 → DoH)
    if (wcsncmp(p, L"https://", 8) == 0) {
        p += 8;
        self_signed = FALSE;
        detected_mode = ENCRYPTED_DNS_MODE_AUTO;  // HTTP-only fallback: DoH3 → DoH2 → DoH (skip DoQ)
        server->HttpOnlyAuto = TRUE;
    } else if (wcsncmp(p, L"httpx://", 8) == 0) {
        p += 8;
        self_signed = TRUE;
        detected_mode = ENCRYPTED_DNS_MODE_AUTO;  // HTTP-only fallback: DoH3 → DoH2 → DoH (skip DoQ)
        server->HttpOnlyAuto = TRUE;
    } else if (wcsncmp(p, L"quic://", 7) == 0) {
        p += 7;
        self_signed = FALSE;
        detected_mode = ENCRYPTED_DNS_MODE_DOQ;   // Explicit DoQ mode
        server->ProtocolLocked = TRUE;            // quic:// means DoQ only
    } else if (wcsncmp(p, L"quicx://", 8) == 0) {
        p += 8;
        self_signed = TRUE;
        detected_mode = ENCRYPTED_DNS_MODE_DOQ;   // Explicit DoQ mode
        server->ProtocolLocked = TRUE;            // quicx:// means DoQ only
    } else if (wcsncmp(p, L"auto://", 7) == 0) {
        p += 7;
        self_signed = FALSE;
        detected_mode = ENCRYPTED_DNS_MODE_AUTO;  // AUTO mode: DoQ → DoH3 → DoH2 → DoH
    } else if (wcsncmp(p, L"autox://", 8) == 0) {
        p += 8;
        self_signed = TRUE;
        detected_mode = ENCRYPTED_DNS_MODE_AUTO;  // AUTO mode: DoQ → DoH3 → DoH2 → DoH
    } else {
        if (DNS_TraceFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"[EncDns] Invalid URL scheme: %s", url);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        return FALSE;
    }
    server->SelfSigned = self_signed;

    // Extract hostname (handle IPv6 bracket notation: [IPv6]:port)
    host_start = p;
    if (*p == L'[') {
        // IPv6 address in brackets: https://[2606:4700:4700::1111]:443/dns-query
        p++;  // Skip opening bracket
        host_start = p;
        while (*p && *p != L']') {
            p++;
        }
        if (*p != L']') {
            if (DNS_TraceFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[EncDns] Invalid IPv6 URL (missing closing bracket)");
            }
            return FALSE;
        }
        host_len = p - host_start;
        p++;  // Skip closing bracket
    } else {
        // Regular hostname or IPv4: https://1.1.1.1:443/dns-query
        while (*p && *p != L':' && *p != L'/' && *p != L'?') {
            p++;
        }
        host_len = p - host_start;
    }
    
    if (host_len == 0 || host_len >= 256) {
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[EncDns] Invalid hostname length");
        }
        return FALSE;
    }
    wcsncpy(server->Host, host_start, host_len);
    server->Host[host_len] = L'\0';

    // Extract port (optional) - will be adjusted later if not specified
    if (*p == L':') {
        p++;
        server->Port = (INTERNET_PORT)wcstoul(p, (WCHAR**)&p, 10);
        if (server->Port != 0) {
            explicit_port = TRUE;
        }
    }

    // Extract path and query parameters
    // URL can be: https://host, https://host/, https://host/path, https://host/path?query, https://host?query
    const WCHAR* query_start = NULL;
    const WCHAR* path_end = p;
    
    // Find where path ends (either at '?' for query start, or end of string)
    while (*path_end && *path_end != L'?') {
        path_end++;
    }
    
    // Determine the path.
    // IMPORTANT: Only DoH-based modes need a default request path (/dns-query).
    // DoQ/DoT do not use HTTP paths, so we must not append /dns-query for them.
    BOOLEAN path_provided = FALSE;
    SIZE_T path_len = 0;
    if (*p == L'/') {
        // Path is explicitly provided (e.g., /dns-query or /)
        path_provided = TRUE;
        path_start = p;
        path_len = path_end - p;
    } else {
        // No explicit path (e.g., https://host, https://host?mode=doh2, quic://host)
        path_start = L"";
        path_len = 0;
    }
    
    if (path_len >= 256) {
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[EncDns] Path too long");
        }
        return FALSE;
    }
    wcsncpy(server->Path, path_start, path_len);
    server->Path[path_len] = L'\0';
    
    // Check for query parameters
    if (*path_end == L'?') {
        query_start = path_end + 1;  // Skip '?'
    }

    // Parse query parameters if present
    // Use -1 as sentinel to detect if mode was explicitly set by parameters
    ENCRYPTED_DNS_MODE mode_from_param = (ENCRYPTED_DNS_MODE)-1;
    if (query_start && *query_start) {
        WCHAR query_buf[512];
        if (wcslen(query_start) < 512) {
            wcscpy(query_buf, query_start);
            
            // Parse mode parameter (new unified protocol selection)
            // ?mode=auto|doh|doh2|doh3|doq|dot
            WCHAR* mode_param = wcsstr(query_buf, L"mode=");
            if (mode_param) {
                mode_param += 5;  // Skip "mode="
                if (wcsncmp(mode_param, L"auto", 4) == 0) {
                    mode_from_param = ENCRYPTED_DNS_MODE_AUTO;
                } else if (wcsncmp(mode_param, L"doh3", 4) == 0) {
                    mode_from_param = ENCRYPTED_DNS_MODE_DOH3;
                } else if (wcsncmp(mode_param, L"doh2", 4) == 0) {
                    mode_from_param = ENCRYPTED_DNS_MODE_DOH2;
                } else if (wcsncmp(mode_param, L"doq", 3) == 0) {
                    mode_from_param = ENCRYPTED_DNS_MODE_DOQ;
                } else if (wcsncmp(mode_param, L"dot", 3) == 0) {
                    mode_from_param = ENCRYPTED_DNS_MODE_DOT;
                } else if (wcsncmp(mode_param, L"doh", 3) == 0) {
                    mode_from_param = ENCRYPTED_DNS_MODE_DOH;
                }
                // mode_from_param will override detected_mode after all parsing
            }
            
            // Parse OCSP parameter (ocsp=0 to disable, ocsp=1 to explicitly enable)
            WCHAR* ocsp_param = wcsstr(query_buf, L"ocsp=");
            if (ocsp_param) {
                ocsp_param += 5;  // Skip "ocsp="
                if (*ocsp_param == L'0') {
                    server->DisableOCSP = TRUE;
                } else if (*ocsp_param == L'1') {
                    server->DisableOCSP = FALSE;
                }
            } else {
                // No explicit OCSP setting in URL - use default (OCSP disabled for better performance)
                server->DisableOCSP = TRUE;
            }
            
            // Parse agent parameter (agent=0 to disable, agent=1 to enable User-Agent)
            WCHAR* agent_param = wcsstr(query_buf, L"agent=");
            if (agent_param) {
                agent_param += 6;  // Skip "agent="
                if (*agent_param == L'1') {
                    server->EnableAgent = TRUE;
                } else if (*agent_param == L'0') {
                    server->EnableAgent = FALSE;
                }
            }
            // Default: EnableAgent = FALSE (no User-Agent for privacy)

            // Parse strict parameter (?strict=0 to allow QUIC even when StrictBindIP is active)
            // Default: strict=1 (enforced) when not provided.
            WCHAR* strict_param = wcsstr(query_buf, L"strict=");
            if (strict_param) {
                strict_param += 7;  // Skip "strict="
                if (*strict_param == L'0') {
                    server->StrictBindIpQuicDisable = FALSE;
                } else if (*strict_param == L'1') {
                    server->StrictBindIpQuicDisable = TRUE;
                }
            }

            // Legacy ?http3= parameter support removed.
        }
    } else {
        // No query parameters - use default (OCSP disabled for better performance)
        server->DisableOCSP = TRUE;
    }

    // Determine final protocol mode
    // If mode= parameter was specified, it overrides the scheme detection
    // mode_from_param == -1 means no mode parameter was specified
    if (mode_from_param != (ENCRYPTED_DNS_MODE)-1) {
        detected_mode = mode_from_param;
        // Explicit mode overrides scheme behavior.
        server->HttpOnlyAuto = FALSE;
        // Explicit mode locks protocol selection unless the user explicitly asked for AUTO.
        server->ProtocolLocked = (detected_mode != ENCRYPTED_DNS_MODE_AUTO);
    }
    server->ProtocolMode = detected_mode;

    // Apply default path for HTTP-based modes only.
    // - DoH/DoH2/DoH3/AUTO: if no path (or "/"), default to "/dns-query"
    // - DoQ/DoT: keep empty path when not provided
    {
        BOOLEAN http_based_mode = (
            server->ProtocolMode == ENCRYPTED_DNS_MODE_DOH ||
            server->ProtocolMode == ENCRYPTED_DNS_MODE_DOH2 ||
            server->ProtocolMode == ENCRYPTED_DNS_MODE_DOH3 ||
            server->ProtocolMode == ENCRYPTED_DNS_MODE_AUTO);

        if (http_based_mode) {
            if (!path_provided || (server->Path[0] == L'/' && server->Path[1] == L'\0')) {
                wcscpy(server->Path, L"/dns-query");
            }
        }
    }
    
    // Check if QUIC-based protocols should be skipped due to StrictBindIP.
    // Practical note: Even though WinHTTP's DoH3 behavior may vary by OS/build,
    // we treat DoH3 as QUIC-based here and skip it under StrictBindIP.
    extern BOOLEAN WSA_ShouldDisableQuicProtocols(void);
    BOOLEAN strictBindIpActive = WSA_ShouldDisableQuicProtocols();
    BOOLEAN strictBindIpQuicIncompatible = (server->StrictBindIpQuicDisable && strictBindIpActive);
    
    if (strictBindIpQuicIncompatible) {
        // Downgrade QUIC-based protocols to TCP alternatives only when the configuration
        // allows fallback. For quic:// and explicit ?mode=doq/doh3, we must NOT downgrade.
        if (!server->ProtocolLocked) {
            switch (server->ProtocolMode) {
                case ENCRYPTED_DNS_MODE_DOQ:
                case ENCRYPTED_DNS_MODE_DOH3:
                    // DoQ/DoH3 → DoH2 (fallback to HTTP/2 over TCP)
                    server->ProtocolMode = ENCRYPTED_DNS_MODE_DOH2;
                    if (DNS_TraceFlag && !g_LoggedStrictBindIPDowngrade) {
                        SbieApi_MonitorPutMsg(MONITOR_DNS,
                            L"[EncDns] StrictBindIP detected - downgrading QUIC protocol to DoH2 (TCP)");
                        g_LoggedStrictBindIPDowngrade = TRUE;
                    }
                    break;
                case ENCRYPTED_DNS_MODE_AUTO:
                    // AUTO: runtime logic will skip DoQ and DoH3
                    if (DNS_TraceFlag && !g_LoggedStrictBindIPDowngrade) {
                        SbieApi_MonitorPutMsg(MONITOR_DNS,
                            L"[EncDns] StrictBindIP detected - AUTO mode will skip QUIC protocols (DoQ/DoH3)");
                        g_LoggedStrictBindIPDowngrade = TRUE;
                    }
                    break;
                default:
                    break;
            }
        }
    }
    
    // Map protocol mode to Http3Mode for backward compatibility
    switch (server->ProtocolMode) {
        case ENCRYPTED_DNS_MODE_DOH3:
            server->Http3Mode = 1;  // HTTP/3 only
            break;
        case ENCRYPTED_DNS_MODE_DOH2:
            server->Http3Mode = 0;  // HTTP/2 only
            break;
        case ENCRYPTED_DNS_MODE_DOH:
            server->Http3Mode = 0;  // Default to HTTP/2
            break;
        case ENCRYPTED_DNS_MODE_AUTO:
            server->Http3Mode = -1; // Auto mode will try all protocols
            break;
        case ENCRYPTED_DNS_MODE_DOQ:
        case ENCRYPTED_DNS_MODE_DOT:
            // Not HTTP-based, Http3Mode irrelevant
            server->Http3Mode = 0;
            break;
        default:
            break;
    }

    // Set default port if not explicitly specified
    if (!explicit_port) {
        server->Port = EncryptedDns_GetDefaultPort(server->ProtocolMode);
    }
    
    // Set DoQ port for AUTO mode fallback (always 853 unless explicitly set via quic:// scheme)
    // In AUTO mode, we try DoQ on port 853 even if the main URL is https:// on 443
    server->PortDoQ = ENCRYPTED_DNS_DEFAULT_PORT_DOQ;  // 853

    // One-time trace when StrictBindIP is active but ?strict=0 explicitly allows QUIC.
    // Log after ports are finalized so the message shows meaningful ports.
    if (strictBindIpActive && !server->StrictBindIpQuicDisable) {
        if ((DNS_TraceFlag || DNS_DebugFlag) && !g_LoggedStrictBindIPStrictOverride) {
            WCHAR msg[512];
            if (server->PortDoQ && server->PortDoQ != server->Port) {
                Sbie_snwprintf(msg, 512,
                    L"[EncDns] StrictBindIP active but overridden by ?strict=0 (QUIC allowed). Server=%s:%u (DoQ port %u)",
                    server->Host, (ULONG)server->Port, (ULONG)server->PortDoQ);
            } else {
                Sbie_snwprintf(msg, 512,
                    L"[EncDns] StrictBindIP active but overridden by ?strict=0 (QUIC allowed). Server=%s:%u",
                    server->Host, (ULONG)server->Port);
            }
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            g_LoggedStrictBindIPStrictOverride = TRUE;
        }
    }

    // Store full URL
    if (wcslen(url) < 512) {
        wcscpy(server->Url, url);
    }

    if (DNS_DebugFlag) {
        WCHAR msg[768];
        const WCHAR* modeStr = EncryptedDns_GetModeName(server->ProtocolMode);
        if (server->ProtocolMode == ENCRYPTED_DNS_MODE_AUTO) {
            // Auto mode uses both DoH (port 443) and DoQ (port 853)
            Sbie_snwprintf(msg, 768, L"[EncDns] Parsed URL - Host: %s, PortDoH: %d, PortDoQ: %d, Path: %s, Mode: %s, CertMode: %s, OCSP: %s, Agent: %s",
                server->Host, server->Port, server->PortDoQ, server->Path, 
                modeStr,
                self_signed ? L"self-signed" : L"signed",
                server->DisableOCSP ? L"disabled" : L"enabled",
                server->EnableAgent ? L"enabled" : L"disabled");
        } else {
            Sbie_snwprintf(msg, 768, L"[EncDns] Parsed URL - Host: %s, Port: %d, Path: %s, Mode: %s, CertMode: %s, OCSP: %s, Agent: %s",
                server->Host, server->Port, server->Path, 
                modeStr,
                self_signed ? L"self-signed" : L"signed",
                server->DisableOCSP ? L"disabled" : L"enabled",
                server->EnableAgent ? L"enabled" : L"disabled");
        }
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    return TRUE;
}

//---------------------------------------------------------------------------
// DoH_LoadWinHttpFunctions - Load WinHTTP function pointers
//---------------------------------------------------------------------------

static BOOLEAN DoH_LoadWinHttpFunctions(HMODULE hModule)
{
    if (!hModule)
        return FALSE;

    __sys_WinHttpOpen = (P_WinHttpOpen)GetProcAddress(hModule, "WinHttpOpen");
    __sys_WinHttpConnect = (P_WinHttpConnect)GetProcAddress(hModule, "WinHttpConnect");
    __sys_WinHttpOpenRequest = (P_WinHttpOpenRequest)GetProcAddress(hModule, "WinHttpOpenRequest");
    __sys_WinHttpSendRequest = (P_WinHttpSendRequest)GetProcAddress(hModule, "WinHttpSendRequest");
    __sys_WinHttpReceiveResponse = (P_WinHttpReceiveResponse)GetProcAddress(hModule, "WinHttpReceiveResponse");
    __sys_WinHttpQueryHeaders = (P_WinHttpQueryHeaders)GetProcAddress(hModule, "WinHttpQueryHeaders");
    __sys_WinHttpQueryOption = (P_WinHttpQueryOption)GetProcAddress(hModule, "WinHttpQueryOption");
    __sys_WinHttpReadData = (P_WinHttpReadData)GetProcAddress(hModule, "WinHttpReadData");
    __sys_WinHttpCloseHandle = (P_WinHttpCloseHandle)GetProcAddress(hModule, "WinHttpCloseHandle");
    __sys_WinHttpSetOption = (P_WinHttpSetOption)GetProcAddress(hModule, "WinHttpSetOption");
    __sys_WinHttpSetTimeouts = (P_WinHttpSetTimeouts)GetProcAddress(hModule, "WinHttpSetTimeouts");

    return __sys_WinHttpOpen && __sys_WinHttpConnect && __sys_WinHttpOpenRequest &&
           __sys_WinHttpSendRequest && __sys_WinHttpReceiveResponse && 
           __sys_WinHttpQueryHeaders && __sys_WinHttpReadData && __sys_WinHttpCloseHandle;
}

//---------------------------------------------------------------------------
// DoH_LoadUrlEscapeFunction - Load UrlEscapeW from Shlwapi.dll
// This is used for RFC 8484 URL parameter encoding
//---------------------------------------------------------------------------

static BOOLEAN DoH_LoadUrlEscapeFunction(void)
{
    if (__sys_UrlEscapeW)
        return TRUE;  // Already loaded

    HMODULE hShlwapi = GetModuleHandleW(L"shlwapi.dll");
    if (!hShlwapi) {
        hShlwapi = LoadLibraryW(L"shlwapi.dll");
        if (!hShlwapi)
            return FALSE;
    }

    __sys_UrlEscapeW = (P_UrlEscapeW)GetProcAddress(hShlwapi, "UrlEscapeW");
    return __sys_UrlEscapeW != NULL;
}

//---------------------------------------------------------------------------
// DoH_HasWinHttpFunctions - Check if WinHTTP functions are loaded
//---------------------------------------------------------------------------

static BOOLEAN DoH_HasWinHttpFunctions(void)
{
    return __sys_WinHttpOpen && __sys_WinHttpConnect && __sys_WinHttpOpenRequest &&
           __sys_WinHttpSendRequest && __sys_WinHttpReceiveResponse && 
           __sys_WinHttpQueryHeaders && __sys_WinHttpReadData && __sys_WinHttpCloseHandle;
}

//---------------------------------------------------------------------------
// EncDns_LoadBackends - Load encrypted DNS backends
//
// Thread-safe: Uses interlocked operations and critical sections
//---------------------------------------------------------------------------

static BOOLEAN EncDns_LoadBackends(void)
{
    HMODULE hModule;
    BOOLEAN hasWinHttp = FALSE;

    // Fast path: already initialized
    if (InterlockedCompareExchange(&g_DohInitComplete, 0, 0) != 0) {
        return g_DohBackend != DOH_BACKEND_NONE && g_DohBackend != DOH_BACKEND_FAILED;
    }

    // Try to become the initializer
    if (InterlockedCompareExchange(&g_DohInitStarted, 1, 0) != 0) {
        // Another thread is initializing, wait for completion
        while (InterlockedCompareExchange(&g_DohInitComplete, 0, 0) == 0) {
            Sleep(1);
        }
        return g_DohBackend != DOH_BACKEND_NONE && g_DohBackend != DOH_BACKEND_FAILED;
    }

    // We are the initializer - initialize critical sections first
    if (InterlockedCompareExchange(&g_DohLockValid, 1, 0) == 0) {
        InitializeCriticalSection(&g_DohLock);
    }
    if (InterlockedCompareExchange(&g_DohCacheLockValid, 1, 0) == 0) {
        InitializeCriticalSection(&g_DohCacheLock);
        memset(g_DohCache, 0, sizeof(g_DohCache));
    }
    
    // Initialize connection pool (may not have been done if DoH_Init was skipped)
    // This handles the case where WinHTTP wasn't loaded at EncryptedDns_Init time
    DoH_InitConnPool();
    if (InterlockedCompareExchange(&g_DohPendingLockValid, 1, 0) == 0) {
        InitializeCriticalSection(&g_DohPendingLock);
        memset(g_DohPendingQueries, 0, sizeof(g_DohPendingQueries));
        // Create semaphore to limit concurrent DoH queries (max 2)
        if (!g_DohQuerySemaphore) {
            g_DohQuerySemaphore = CreateSemaphoreW(NULL, DOH_MAX_CONCURRENT_QUERIES, DOH_MAX_CONCURRENT_QUERIES, NULL);
        }
    }

    EnterCriticalSection(&g_DohLock);

    // Load UrlEscapeW for RFC 8484 URL parameter encoding
    DoH_LoadUrlEscapeFunction();

    // Try to load WinHTTP (the only supported backend)
    // Priority 1: Check if WinHTTP already loaded
    hModule = GetModuleHandleW(L"winhttp.dll");
    if (hModule && DoH_LoadWinHttpFunctions(hModule)) {
        hasWinHttp = TRUE;
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] WinHTTP.dll already loaded");
        }
    }

    // Priority 2: Try to load WinHTTP (if not already loaded)
    if (!hasWinHttp) {
        hModule = LoadLibraryW(L"winhttp.dll");
        if (hModule && DoH_LoadWinHttpFunctions(hModule)) {
            hasWinHttp = TRUE;
            if (DNS_TraceFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Loaded WinHTTP.dll");
            }
        }
    }

    // Set backend based on what's available
    if (hasWinHttp) {
        g_DohBackend = DOH_BACKEND_WINHTTP;
    } else {
        g_DohBackend = DOH_BACKEND_FAILED;
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] WinHTTP not available - DoH disabled");
        }
        // Don't mark init complete - allow retry later when backend might be available
        LeaveCriticalSection(&g_DohLock);
        InterlockedExchange(&g_DohInitStarted, 0);
        return FALSE;
    }

    LeaveCriticalSection(&g_DohLock);

    // Mark initialization complete only when successful
    InterlockedExchange(&g_DohInitComplete, 1);

    if (DNS_TraceFlag && hasWinHttp) {
        SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Initialized with WinHTTP backend");
    }

    return hasWinHttp;
}

//---------------------------------------------------------------------------
// DoH_EnsureSession - Ensure HTTP session is created
//---------------------------------------------------------------------------

static BOOLEAN DoH_EnsureSession(void)
{
    BOOLEAN result = FALSE;
    DWORD accessType;

    if (!InterlockedCompareExchange(&g_DohLockValid, 0, 0))
        return FALSE;

    EnterCriticalSection(&g_DohLock);

    if (g_DohBackend == DOH_BACKEND_WINHTTP) {
        if (!g_hWinHttpSession && DoH_HasWinHttpFunctions()) {
            // Use automatic proxy on Windows 8.1+ (6.3+)
            // Windows 8 (6.2) has issues with WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
            accessType = (g_OsMajorVersion > 6 || (g_OsMajorVersion == 6 && g_OsMinorVersion >= 3)) ? 
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY : WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
            
            // Use NULL User-Agent by default for privacy
            // Per-request User-Agent can be added via ?agent=1 parameter
            g_hWinHttpSession = __sys_WinHttpOpen(
                NULL,  // No User-Agent by default (privacy)
                accessType,
                WINHTTP_NO_PROXY_NAME,
                WINHTTP_NO_PROXY_BYPASS,
                0
            );
            if (g_hWinHttpSession) {
                result = TRUE;
                
                // Configure TLS protocols based on OS version
                // TLS 1.3 only available on Windows 11+ (build 22000)
                if (__sys_WinHttpSetOption) {
                    DWORD secureProtocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;  // Always enable TLS 1.2
                    
                    if (Dll_OsBuild >= 22000) {
                        // Windows 11+: Add TLS 1.3 support
                        secureProtocols |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
                    }
                    if (g_OsMajorVersion == 6 && g_OsMinorVersion == 1) {
                        // Windows 7 (6.1): Also enable TLS 1.1 as fallback
                        secureProtocols |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1;
                    }
                    
                    __sys_WinHttpSetOption(g_hWinHttpSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &secureProtocols, sizeof(secureProtocols));
                }

                // Windows 10 1903+ (build 18362): Disable WinHTTP's secure protocol fallback.
                // This prevents silent protocol downgrades during TLS negotiation.
                if (Dll_OsBuild >= 18362 && __sys_WinHttpSetOption) {
                    BOOL disableFallback = TRUE;
                    if (!__sys_WinHttpSetOption(g_hWinHttpSession, WINHTTP_OPTION_DISABLE_SECURE_PROTOCOL_FALLBACK, &disableFallback, sizeof(disableFallback))) {
                        if (DNS_DebugFlag) {
                            DWORD lastError = GetLastError();
                            WCHAR msg[256];
                            Sbie_snwprintf(msg, 256, L"[DoH] Warning: Failed to set WINHTTP_OPTION_DISABLE_SECURE_PROTOCOL_FALLBACK (err=%lu)", lastError);
                            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                        }
                    }
                }
                
                // Windows 8+ features (version 6.2+)
                if ((g_OsMajorVersion > 6 || (g_OsMajorVersion == 6 && g_OsMinorVersion >= 2)) && __sys_WinHttpSetOption) {
                    // Enable decompression (gzip/deflate)
                    DWORD decompressionFlags = WINHTTP_DECOMPRESSION_FLAG_GZIP | WINHTTP_DECOMPRESSION_FLAG_DEFLATE;
                    __sys_WinHttpSetOption(g_hWinHttpSession, WINHTTP_OPTION_DECOMPRESSION, &decompressionFlags, sizeof(decompressionFlags));
                }
                
                // Configure HTTP protocol version (consolidated - set once based on highest capability)
                if (__sys_WinHttpSetOption) {
                    DWORD protocols = 0;
                    
                    if (Dll_OsBuild >= 26100) {
                        // Windows 11 24H2+: Allow HTTP/3 at session-level; select per-request.
                        protocols = WINHTTP_PROTOCOL_FLAG_HTTP2 | WINHTTP_PROTOCOL_FLAG_HTTP3;
                        
                        // Short HTTP/3 handshake timeout for fast fallback when QUIC is blocked
                        // QUIC uses UDP which is often blocked by firewalls; 500ms allows quick fallback to HTTP/2
                        DWORD http3Timeout = 500;  // 500ms for QUIC handshake
                        __sys_WinHttpSetOption(g_hWinHttpSession, WINHTTP_OPTION_HTTP3_HANDSHAKE_TIMEOUT, &http3Timeout, sizeof(http3Timeout));
                        
                        if (DNS_TraceFlag) {
                            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] HTTP/3 available (selected per-request)");
                        }
                    } else if (Dll_OsBuild >= 10240) {
                        // Windows 10+: HTTP/2 only
                        protocols = WINHTTP_PROTOCOL_FLAG_HTTP2;
                        
                        if (DNS_TraceFlag) {
                            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] HTTP/2 protocol enabled");
                        }
                    }
                    
                    if (protocols != 0) {
                        __sys_WinHttpSetOption(g_hWinHttpSession, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &protocols, sizeof(protocols));
                    }
                }
                
                // Windows 10 1809+ features (build 17763)
                if (Dll_OsBuild >= 17763 && __sys_WinHttpSetOption) {
                    // Enable IPv6 fast fallback (Happy Eyeballs v2) (RFC 8305)
                    DWORD ipv6FastFallback = TRUE;
                    __sys_WinHttpSetOption(g_hWinHttpSession, WINHTTP_OPTION_IPV6_FAST_FALLBACK, &ipv6FastFallback, sizeof(ipv6FastFallback));
                    
                    // Disable stream queue for better HTTP/2 performance
                    DWORD disableStreamQueue = TRUE;
                    __sys_WinHttpSetOption(g_hWinHttpSession, WINHTTP_OPTION_DISABLE_STREAM_QUEUE, &disableStreamQueue, sizeof(disableStreamQueue));
                }
                
                // Windows 10 1809+ (build 17763): TLS False Start for TLS 1.2
                // TLS False Start only benefits TLS 1.2 handshakes (TLS 1.3 has 0-RTT built-in)
                // Enable on Windows 10 1809+ but before Windows 11 where TLS 1.3 is primary
                if (Dll_OsBuild >= 17763 && Dll_OsBuild < 22000 && __sys_WinHttpSetOption) {
                    DWORD tlsFalseStart = TRUE;
                    __sys_WinHttpSetOption(g_hWinHttpSession, WINHTTP_OPTION_TLS_FALSE_START, &tlsFalseStart, sizeof(tlsFalseStart));
                }
                
                // Windows 11+ features (build 22000)
                if (Dll_OsBuild >= 22000 && __sys_WinHttpSetOption) {
                    // Disable global pooling for better sandbox isolation
                    DWORD disableGlobalPooling = TRUE;
                    __sys_WinHttpSetOption(g_hWinHttpSession, WINHTTP_OPTION_DISABLE_GLOBAL_POOLING, &disableGlobalPooling, sizeof(disableGlobalPooling));
                    
                    // Enable TCP Fast Open (RFC 7413) - helps cold-start latency
                    DWORD tcpFastOpen = TRUE;
                    __sys_WinHttpSetOption(g_hWinHttpSession, WINHTTP_OPTION_TCP_FAST_OPEN, &tcpFastOpen, sizeof(tcpFastOpen));
                }
                
                if (DNS_TraceFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"[DoH] WinHTTP session created (Build: %d, Proxy: %s)", 
                        Dll_OsBuild,
                        (accessType == WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY) ? L"auto" : L"default");
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
            } else {
                DWORD lastError = GetLastError();
                g_DohBackend = DOH_BACKEND_FAILED;
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"[DoH] WinHTTP session creation failed (error %d)", lastError);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
        } else if (g_hWinHttpSession) {
            result = TRUE;
        }
    }

    LeaveCriticalSection(&g_DohLock);
    return result;
}

//---------------------------------------------------------------------------
// EncryptedDns_Init
//
// Initialize encrypted DNS client module.
// This function always succeeds and returns TRUE.
// Actual backend loading is deferred until first query (lazy initialization).
//
// Parameters:
//   hWinHttp - Optional WinHTTP module handle (NULL = will load on demand)
//
// Returns: Always TRUE (initialization cannot fail)
//---------------------------------------------------------------------------

_FX BOOLEAN DoH_Init(HMODULE hWinHttp)
{
    if (hWinHttp) {
        DoH_LoadWinHttpFunctions(hWinHttp);
    }
    DoH_InitConnPool();  // Initialize connection pool
    return TRUE;
}

//---------------------------------------------------------------------------
// DoH_Cleanup
//
// Cleanup DoH module and release all resources.
// Closes WinHTTP session, connection pool, and all critical sections.
// Safe to call even if DoH was never fully initialized.
//
// Thread Safety: Uses interlocked operations for cleanup state checks
// Resources Released:
//   - Connection pool (all cached HINTERNET handles)
//   - WinHTTP session handle
//   - Cache entries
//   - Pending query semaphore
//   - All critical sections (g_DohLock, g_DohCacheLock, g_DohConfigLock)
//---------------------------------------------------------------------------

_FX void DoH_Cleanup(void)
{
    // Close connection pool first (before closing sessions)
    DoH_CloseConnPool();

    if (InterlockedCompareExchange(&g_DohLockValid, 0, 0)) {
        EnterCriticalSection(&g_DohLock);
        
        if (g_hWinHttpSession && __sys_WinHttpCloseHandle) {
            __sys_WinHttpCloseHandle(g_hWinHttpSession);
            g_hWinHttpSession = NULL;
        }
        g_DohBackend = DOH_BACKEND_NONE;
        
        LeaveCriticalSection(&g_DohLock);
        DeleteCriticalSection(&g_DohLock);
        InterlockedExchange(&g_DohLockValid, 0);
    }

    if (InterlockedCompareExchange(&g_DohCacheLockValid, 0, 0)) {
        DeleteCriticalSection(&g_DohCacheLock);
        InterlockedExchange(&g_DohCacheLockValid, 0);
    }

    // Clean up pending query resources
    if (InterlockedCompareExchange(&g_DohPendingLockValid, 0, 0)) {
        EnterCriticalSection(&g_DohPendingLock);
        
        // Close all pending query event handles
        for (ULONG i = 0; i < DOH_MAX_PENDING_QUERIES; i++) {
            if (g_DohPendingQueries[i].Event) {
                CloseHandle(g_DohPendingQueries[i].Event);
                g_DohPendingQueries[i].Event = NULL;
            }
            g_DohPendingQueries[i].Valid = FALSE;
        }
        
        LeaveCriticalSection(&g_DohPendingLock);
        DeleteCriticalSection(&g_DohPendingLock);
        InterlockedExchange(&g_DohPendingLockValid, 0);
    }
    
    // Close semaphore
    if (g_DohQuerySemaphore) {
        CloseHandle(g_DohQuerySemaphore);
        g_DohQuerySemaphore = NULL;
    }

    if (InterlockedCompareExchange(&g_DohConfigLockValid, 0, 0)) {
        DeleteCriticalSection(&g_DohConfigLock);
        InterlockedExchange(&g_DohConfigLockValid, 0);
    }

    g_DohConfigLineCount = 0;
    g_DohCurrentConfigLine = 0;
    InterlockedExchange(&g_DohConfigured, 0);
    InterlockedExchange(&g_DohInitComplete, 0);
    InterlockedExchange(&g_DohInitStarted, 0);
}

//---------------------------------------------------------------------------
// DoH_LoadConfig
//
// Loads EncryptedDnsServer configuration from sandbox settings.
// Requires valid certificate (DNS_HasValidCertificate).
// Returns TRUE if any encrypted DNS servers were configured, FALSE otherwise.
//
// Thread Safety: Uses critical section to protect config structure
// Re-entrancy: Safe to call multiple times (early return if already configured)
//---------------------------------------------------------------------------

_FX BOOLEAN DoH_LoadConfig(void)
{
    WCHAR conf_buf[1024];
    ULONG config_lines_found = 0;
    ULONG highest_level = (ULONG)-1;  // Track highest priority config level
    RTL_OSVERSIONINFOW osvi;

    if (InterlockedCompareExchange(&g_DohConfigured, 0, 0) != 0)
        return TRUE;

    // Check certificate validation - encrypted DNS requires a valid certificate
    extern BOOLEAN DNS_HasValidCertificate;
    if (!DNS_HasValidCertificate) {
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[EncDns] Disabled - no valid certificate");
        }
        return FALSE;
    }

    // Get OS version for WinHTTP/MsQuic backend selection
    // Use RtlGetVersion instead of GetVersionExW to get real OS version (not manifest version)
    // GetVersionExW returns 6.2 on Windows 10 without proper manifest, causing false Windows 7 detection
    typedef NTSTATUS (WINAPI *P_RtlGetVersion)(RTL_OSVERSIONINFOW*);
    P_RtlGetVersion pRtlGetVersion = (P_RtlGetVersion)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    osvi.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    if (pRtlGetVersion && pRtlGetVersion(&osvi) == 0) {
        g_OsMajorVersion = osvi.dwMajorVersion;
        g_OsMinorVersion = osvi.dwMinorVersion;
        g_OsBuildNumber = osvi.dwBuildNumber;
    }

    // Initialize config lock
    if (InterlockedCompareExchange(&g_DohConfigLockValid, 1, 0) == 0) {
        InitializeCriticalSection(&g_DohConfigLock);
        memset(g_DohConfigLines, 0, sizeof(g_DohConfigLines));
    }

    EnterCriticalSection(&g_DohConfigLock);

    // Read EncryptedDnsServer configuration only (SecureDnsServer no longer supported)
    // Iterate through all config lines
    for (ULONG index = 0; index < DOH_MAX_CONFIG_LINES; ++index) {
        NTSTATUS status = SbieApi_QueryConf(NULL, L"EncryptedDnsServer", index, conf_buf, sizeof(conf_buf) - 16 * sizeof(WCHAR));
        if (!NT_SUCCESS(status))
            break;

        // Check for per-process match
        ULONG level = (ULONG)-1;
        const WCHAR* value = Config_MatchImageAndGetValue(conf_buf, Dll_ImageName, &level);
        if (!value)
            continue;

        if (DNS_DebugFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"[EncDns] Config line %d (level=%d): %s", config_lines_found, level, value);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }

        // Parse semicolon-separated servers in this config line
        DOH_CONFIG_LINE* config_line = &g_DohConfigLines[config_lines_found];
        config_line->ServerCount = 0;
        config_line->CurrentServer = 0;
        config_line->Level = level;  // Store config match level for priority filtering

        const WCHAR* server_start = value;
        while (*server_start && config_line->ServerCount < DOH_MAX_SERVERS_PER_LINE) {
            // Skip leading whitespace
            while (*server_start == L' ' || *server_start == L'\t')
                server_start++;

            if (!*server_start)
                break;

            // Find end of this server URL (semicolon or end of string)
            const WCHAR* server_end = server_start;
            while (*server_end && *server_end != L';')
                server_end++;

            // Copy server URL to temporary buffer
            SIZE_T url_len = server_end - server_start;
            if (url_len > 0 && url_len < 512) {
                WCHAR url_buf[512];
                wcsncpy(url_buf, server_start, url_len);
                url_buf[url_len] = L'\0';

                // Trim trailing whitespace
                while (url_len > 0 && (url_buf[url_len - 1] == L' ' || url_buf[url_len - 1] == L'\t')) {
                    url_buf[--url_len] = L'\0';
                }

                if (url_len > 0 && EncDns_ParseUrlToServer(url_buf, &config_line->Servers[config_line->ServerCount])) {
                    config_line->ServerCount++;
                }
            }

            // Move to next server
            if (*server_end == L';')
                server_start = server_end + 1;
            else
                break;
        }

        if (config_line->ServerCount > 0) {
            // Track highest priority level (lower level number = higher priority)
            if (level < highest_level) {
                highest_level = level;
            }
            config_lines_found++;
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"[EncDns] Config line %d has %d server(s) at level %d", 
                    config_lines_found - 1, config_line->ServerCount, level);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
        }
    }

    // Filter to only use highest priority config lines (lowest level number)
    // Example: If nslookup.exe has level=1 config and global level=2, use only level=1
    ULONG final_count = 0;
    for (ULONG i = 0; i < config_lines_found; i++) {
        if (g_DohConfigLines[i].Level == highest_level) {
            if (i != final_count) {
                // Compact array - move higher priority configs to front
                g_DohConfigLines[final_count] = g_DohConfigLines[i];
            }
            final_count++;
        }
    }

    g_DohConfigLineCount = final_count;
    g_DohCurrentConfigLine = 0;

    if (DNS_DebugFlag && final_count > 0) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[EncDns] Using %d config line(s) at priority level %d", 
            final_count, highest_level);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    LeaveCriticalSection(&g_DohConfigLock);

    if (config_lines_found > 0) {
        InterlockedExchange(&g_DohConfigured, 1);
        
        // Check if bind IP is configured to loopback - remote encrypted DNS will fail
        // Loopback interfaces cannot route to internet DNS servers (like 1.1.1.1)
        // However, local proxies (listening on 0.0.0.0 or 127.0.0.1) will still work
        if (WSA_IsBindIPLoopback()) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, 
                L"[EncDns] WARNING: Sandbox uses loopback BindAdapter/BindAdapterIP (127.x.x.x or ::1). "
                L"Remote encrypted DNS servers (e.g., 1.1.1.1) will fail, but local proxies listening on 127.0.0.1 or 0.0.0.0 will work.");
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        
        return TRUE;
    }

    return FALSE;
}

//---------------------------------------------------------------------------
// DoH_IsEnabled
//---------------------------------------------------------------------------

_FX BOOLEAN DoH_IsEnabled(void)
{
    return InterlockedCompareExchange(&g_DohConfigured, 0, 0) != 0;
}

//---------------------------------------------------------------------------
// DoH_GetServerUrl - Returns first server's URL for compatibility
//---------------------------------------------------------------------------

_FX const WCHAR* DoH_GetServerUrl(void)
{
    if (!InterlockedCompareExchange(&g_DohConfigLockValid, 0, 0))
        return NULL;

    if (g_DohConfigLineCount > 0 && g_DohConfigLines[0].ServerCount > 0)
        return g_DohConfigLines[0].Servers[0].Url;
    
    return NULL;
}

//---------------------------------------------------------------------------
// DoH_GetServerHostname - Returns first server's hostname for compatibility
//---------------------------------------------------------------------------

_FX const WCHAR* DoH_GetServerHostname(void)
{
    if (!InterlockedCompareExchange(&g_DohConfigLockValid, 0, 0))
        return NULL;

    if (g_DohConfigLineCount > 0 && g_DohConfigLines[0].ServerCount > 0) {
        const WCHAR* host = g_DohConfigLines[0].Servers[0].Host;
        if (host[0] != L'\0')
            return host;
    }
    
    return NULL;
}

//---------------------------------------------------------------------------
// DoH_IsServerHostname - Check if hostname matches any configured encrypted DNS server
//
// Purpose: Re-entrancy prevention - if user queries a domain and we resolve
// the encrypted DNS server's hostname internally, it would cause infinite loop.
// Solution: Exclude encrypted DNS server hostnames from filtering so they bypass
// the filter and use system DNS instead, preventing recursive queries.
//
// Returns: TRUE if hostname matches any encrypted DNS server (should be excluded from filtering)
//          FALSE otherwise (proceed with normal filtering)
//---------------------------------------------------------------------------

_FX BOOLEAN DoH_IsServerHostname(const WCHAR* hostname)
{
    if (!hostname || !*hostname)
        return FALSE;

    if (!InterlockedCompareExchange(&g_DohConfigLockValid, 0, 0))
        return FALSE;

    if (!InterlockedCompareExchange(&g_DohConfigured, 0, 0))
        return FALSE;

    EnterCriticalSection(&g_DohConfigLock);

    // Check all configured servers
    for (ULONG i = 0; i < g_DohConfigLineCount; i++) {
        DOH_CONFIG_LINE* line = &g_DohConfigLines[i];
        for (ULONG s = 0; s < line->ServerCount; s++) {
            if (_wcsicmp(hostname, line->Servers[s].Host) == 0) {
                if (DNS_DebugFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"[EncDns] Server hostname match: %s", hostname);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
                LeaveCriticalSection(&g_DohConfigLock);
                return TRUE;
            }
        }
    }

    if (DNS_DebugFlag) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"[EncDns] No server hostname match for: %s (checked %u lines)", hostname, g_DohConfigLineCount);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    LeaveCriticalSection(&g_DohConfigLock);
    return FALSE;
}

//---------------------------------------------------------------------------
// DoH_IsQueryActive - Check if any encrypted DNS query is currently active (re-entrancy detection)
//
// Returns: TRUE if an encrypted DNS query is active (either on current thread or globally)
//          FALSE if safe to start new query
//
// Checks both:
//   1. Per-thread TLS flag (dns_in_doh_query): Detects same-thread recursion
//   2. Global counter (g_DohActiveQueries): Detects cross-thread recursion from WinHTTP internal threads
//
// If TRUE, caller should skip encrypted DNS and fall back to system DNS to prevent loops
//---------------------------------------------------------------------------

_FX BOOLEAN DoH_IsQueryActive(void)
{
    // Check both TLS flag and global counter
    if (EncDns_GetInQuery())
        return TRUE;
    if (InterlockedCompareExchange(&g_DohActiveQueries, 0, 0) > 0)
        return TRUE;
    return FALSE;
}

//---------------------------------------------------------------------------
// EncDns_SelectServer - Select a server using round-robin with failure awareness
//---------------------------------------------------------------------------

static DOH_SERVER* EncDns_SelectServer(ULONGLONG now)
{
    ULONG start_line, start_server;
    ULONG attempts = 0;
    ULONG max_attempts;

    if (!InterlockedCompareExchange(&g_DohConfigLockValid, 0, 0))
        return NULL;

    if (g_DohConfigLineCount == 0)
        return NULL;

    EnterCriticalSection(&g_DohConfigLock);

    start_line = g_DohCurrentConfigLine;
    
    // Calculate maximum attempts (total servers across all lines)
    max_attempts = 0;
    for (ULONG i = 0; i < g_DohConfigLineCount; i++) {
        max_attempts += g_DohConfigLines[i].ServerCount;
    }

    // Try to find a working server
    while (attempts < max_attempts) {
        ULONG current_line_idx = g_DohCurrentConfigLine;
        DOH_CONFIG_LINE* line = &g_DohConfigLines[current_line_idx];
        
        if (line->ServerCount > 0) {
            start_server = line->CurrentServer;
            
            // Try servers in this line
            for (ULONG s = 0; s < line->ServerCount; s++) {
                ULONG server_idx = (start_server + s) % line->ServerCount;
                DOH_SERVER* server = &line->Servers[server_idx];
                
                // Check if server is in cooldown
                if (server->FailedUntil == 0 || now >= server->FailedUntil) {
                    // Update within-line round-robin counter
                    line->CurrentServer = (server_idx + 1) % line->ServerCount;
                    // Advance to next config line for next query (round-robin across lines)
                    g_DohCurrentConfigLine = (current_line_idx + 1) % g_DohConfigLineCount;
                    LeaveCriticalSection(&g_DohConfigLock);
                    return server;
                }
                attempts++;
            }
        }
        
        // No available server in this line, try next line
        current_line_idx = (current_line_idx + 1) % g_DohConfigLineCount;
        
        // Avoid infinite loop if we've checked all lines
        if (current_line_idx == start_line && attempts > 0)
            break;
            
        // Update the line pointer for next iteration
        g_DohCurrentConfigLine = current_line_idx;
    }

    // All servers are in cooldown - return first one anyway (reset will happen on retry)
    if (g_DohConfigLines[0].ServerCount > 0) {
        LeaveCriticalSection(&g_DohConfigLock);
        return &g_DohConfigLines[0].Servers[0];
    }

    LeaveCriticalSection(&g_DohConfigLock);
    return NULL;
}

//---------------------------------------------------------------------------
// DoH_MarkServerFailed - Mark a server as failed for cooldown period
//---------------------------------------------------------------------------

_FX void DoH_MarkServerFailed(void* pServer, ULONGLONG now)
{
    DOH_SERVER* server = (DOH_SERVER*)pServer;
    if (!server)
        return;

    if (!InterlockedCompareExchange(&g_DohConfigLockValid, 0, 0))
        return;

    EnterCriticalSection(&g_DohConfigLock);
    
    server->FailedUntil = now + DOH_SERVER_FAIL_COOLDOWN;
    
    if (DNS_TraceFlag) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"[DoH] Server %s marked failed, retry after %d seconds",
            server->Host, DOH_SERVER_FAIL_COOLDOWN / 1000);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // Move to next server in this config line
    for (ULONG i = 0; i < g_DohConfigLineCount; i++) {
        DOH_CONFIG_LINE* line = &g_DohConfigLines[i];
        for (ULONG s = 0; s < line->ServerCount; s++) {
            if (&line->Servers[s] == server && line->ServerCount > 1) {
                line->CurrentServer = (s + 1) % line->ServerCount;
                break;
            }
        }
    }

    LeaveCriticalSection(&g_DohConfigLock);
}

//---------------------------------------------------------------------------
// DoH_MarkHttp3Failed - Apply incremental backoff for HTTP/3 failures
//
// When HTTP/3 (QUIC) fails, we apply incremental backoff to avoid constantly
// retrying HTTP/3 which can delay browsing. Backoff periods:
//   1st failure: 30 seconds
//   2nd failure: 60 seconds  
//   3rd failure: 120 seconds
//   4th+ failure: 300 seconds (5 minutes max)
//
// This allows occasional retry in case network conditions change (e.g., 
// firewall rules updated, different network, etc.)
//---------------------------------------------------------------------------

static void DoH_MarkHttp3Failed(DOH_SERVER* server, ULONGLONG now)
{
    if (!server || server->Http3Mode != -1)
        return;

    if (!InterlockedCompareExchange(&g_DohConfigLockValid, 0, 0))
        return;

    EnterCriticalSection(&g_DohConfigLock);
    
    // Increment fail count and calculate backoff
    server->Http3FailCount++;
    
    ULONG backoff_seconds;
    switch (server->Http3FailCount) {
        case 1:  backoff_seconds = 30;  break;   // 30 seconds
        case 2:  backoff_seconds = 60;  break;   // 1 minute
        case 3:  backoff_seconds = 120; break;   // 2 minutes
        default: backoff_seconds = 300; break;   // 5 minutes max
    }
    
    server->Http3FallbackUntil = now + (backoff_seconds * 1000);
    
    if (DNS_TraceFlag) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"[DoH] HTTP/3 failed for %s (attempt %d), falling back to HTTP/2 for %d seconds",
            server->Host, server->Http3FailCount, backoff_seconds);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    LeaveCriticalSection(&g_DohConfigLock);
}

//---------------------------------------------------------------------------
// DoH_ResetHttp3Failures - Reset HTTP/3 backoff on successful connection
//---------------------------------------------------------------------------

static void DoH_ResetHttp3Failures(DOH_SERVER* server)
{
    if (!server || server->Http3Mode != -1)
        return;

    if (server->Http3FailCount == 0 && server->Http3FallbackUntil == 0)
        return;  // Already reset, no need to lock

    if (!InterlockedCompareExchange(&g_DohConfigLockValid, 0, 0))
        return;

    EnterCriticalSection(&g_DohConfigLock);
    
    if (server->Http3FailCount > 0 || server->Http3FallbackUntil > 0) {
        server->Http3FailCount = 0;
        server->Http3FallbackUntil = 0;
        
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoH] HTTP/3 backoff reset for %s", server->Host);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    }

    LeaveCriticalSection(&g_DohConfigLock);
}

//---------------------------------------------------------------------------
// EncDns_CacheLookup
//---------------------------------------------------------------------------

static BOOLEAN EncDns_CacheLookup(const WCHAR* domain, USHORT qtype, DOH_RESULT* pResult)
{
    ULONGLONG now;
    int i;

    if (!InterlockedCompareExchange(&g_DohCacheLockValid, 0, 0))
        return FALSE;

    now = GetTickCount64();

    EnterCriticalSection(&g_DohCacheLock);

    for (i = 0; i < DOH_CACHE_SIZE; i++) {
        if (g_DohCache[i].valid &&
            g_DohCache[i].qtype == qtype &&
            _wcsicmp(g_DohCache[i].domain, domain) == 0) {
            
            if (now < g_DohCache[i].expiry) {
                memcpy(pResult, &g_DohCache[i].result, sizeof(DOH_RESULT));
                LeaveCriticalSection(&g_DohCacheLock);
                
                if (DNS_DebugFlag) {
                    WCHAR msg[512];
                    if (!g_DohCache[i].is_failure && pResult->ProtocolUsed != ENCRYPTED_DNS_MODE_AUTO) {
                        Sbie_snwprintf(msg, 512, L"[EncDns] Cache HIT: %s (Type: %d, used=%s)",
                            domain, qtype, EncryptedDns_GetModeName(pResult->ProtocolUsed));
                    } else {
                        Sbie_snwprintf(msg, 512, L"[EncDns] Cache HIT: %s (Type: %d)", domain, qtype);
                    }
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
                return TRUE;
            } else {
                g_DohCache[i].valid = FALSE;
            }
        }
    }

    LeaveCriticalSection(&g_DohCacheLock);

    if (DNS_DebugFlag) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"[EncDns] Cache MISS: %s (Type: %d)", domain, qtype);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    return FALSE;
}

//---------------------------------------------------------------------------
// DoH_EncodeDnsName
//
// Encodes a domain name into DNS wire format (RFC 1035 Section 3.1).
// Converts "www.google.com" to: 03 77 77 77 06 67 6F 6F 67 6C 65 03 63 6F 6D 00
// Each label is prefixed with its length byte, terminated with 0x00.
//
// Parameters:
//   domain     - Domain name in Unicode (e.g., L"www.google.com")
//   buffer     - Output buffer for encoded name
//   bufferSize - Size of output buffer
//
// Returns: Number of bytes written, or -1 on error
//---------------------------------------------------------------------------

static int DoH_EncodeDnsName(const WCHAR* domain, BYTE* buffer, int bufferSize)
{
    char ansi_domain[256];
    int pos = 0;
    int label_start = 0;
    int i, j;

    if (!domain || !buffer || bufferSize < 2)
        return -1;

    // Convert Unicode to ANSI (DNS names are ASCII)
    for (i = 0; i < 255 && domain[i]; i++) {
        if (domain[i] > 127) {
            // Invalid character for DNS name
            return -1;
        }
        ansi_domain[i] = (char)domain[i];
    }

    // Check if domain was truncated
    if (domain[i] != 0) {
        return -1;
    }

    ansi_domain[i] = '\0';

    // Encode labels
    while (ansi_domain[label_start]) {
        // Find end of label (next dot or end of string)
        int label_end = label_start;
        while (ansi_domain[label_end] && ansi_domain[label_end] != '.')
            label_end++;

        int label_len = label_end - label_start;
        
        // Check label length (max 63 bytes per RFC 1035)
        if (label_len == 0 || label_len > 63)
            return -1;

        // Check buffer space (length byte + label + null terminator)
        if (pos + 1 + label_len + 1 > bufferSize)
            return -1;

        // Write length byte
        buffer[pos++] = (BYTE)label_len;

        // Write label characters
        for (j = 0; j < label_len; j++) {
            buffer[pos++] = (BYTE)ansi_domain[label_start + j];
        }

        // Move to next label
        if (ansi_domain[label_end] == '.')
            label_start = label_end + 1;
        else
            break;
    }

    // Write terminating null byte
    buffer[pos++] = 0x00;

    return pos;
}

//---------------------------------------------------------------------------
// DoH_BuildDnsQuery
//
// Builds a DNS query in wire format (RFC 1035).
// Creates binary DNS packet: 12-byte header + question section.
//
// Parameters:
//   domain      - Domain name to query (e.g., L"www.google.com")
//   qtype       - Query type (1=A, 28=AAAA)
//   buffer      - Output buffer for DNS query packet
//   bufferSize  - Size of output buffer
//   queryLen    - [OUT] Length of generated query
//
// Returns: TRUE on success, FALSE on error
//---------------------------------------------------------------------------

static BOOLEAN DoH_BuildDnsQuery(
    const WCHAR* domain,
    USHORT qtype,
    BYTE* buffer,
    int bufferSize,
    int* queryLen)
{
    DOH_DNS_HEADER* header;
    int nameLen;
    BYTE* p;

    if (!domain || !buffer || !queryLen || bufferSize < 512)
        return FALSE;

    *queryLen = 0;

    // Build DNS header
    header = (DOH_DNS_HEADER*)buffer;
    memset(header, 0, sizeof(DOH_DNS_HEADER));

    // Transaction ID (use random value)
    header->TransactionID = (USHORT)(GetTickCount64() & 0xFFFF);

    // Flags: Standard query with recursion desired
    // QR=0 (query), Opcode=0 (standard), RD=1 (recursion desired)
    header->Flags = _htons(0x0100);  // 0000000100000000 in binary

    // Counts
    header->Questions = _htons(1);   // 1 question
    header->AnswerRRs = 0;
    header->AuthorityRRs = 0;
    header->AdditionalRRs = 0;

    // Encode domain name after header
    p = buffer + sizeof(DOH_DNS_HEADER);
    nameLen = DoH_EncodeDnsName(domain, p, bufferSize - sizeof(DOH_DNS_HEADER) - 4);
    
    if (nameLen <= 0)
        return FALSE;

    p += nameLen;

    // Add QTYPE (2 bytes)
    *(USHORT*)p = _htons(qtype);
    p += 2;

    // Add QCLASS (2 bytes) - always IN (Internet)
    *(USHORT*)p = _htons(1);  // QCLASS_IN = 1
    p += 2;

    *queryLen = (int)(p - buffer);

    if (DNS_DebugFlag) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"[EncDns] Built DNS query: %s (Type: %d, Length: %d bytes)",
            domain, qtype, *queryLen);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    return TRUE;
}

//---------------------------------------------------------------------------
// DoH_DecodeDnsName
//
// Decodes a DNS name from wire format to Unicode string.
// Handles DNS name compression (RFC 1035 Section 4.1.4).
//
// Parameters:
//   packet     - Full DNS packet (needed for compression pointer resolution)
//   packetLen  - Length of packet
//   offset     - Starting offset of name in packet
//   nameOut    - Output buffer for decoded name
//   nameOutSize- Size of output buffer
//
// Returns: Number of bytes consumed from packet, or -1 on error
//---------------------------------------------------------------------------

static int DoH_DecodeDnsName(
    const BYTE* packet,
    int packetLen,
    int offset,
    WCHAR* nameOut,
    int nameOutSize)
{
    int originalOffset = offset;
    int outPos = 0;
    BOOLEAN firstLabel = TRUE;
    int jumpCount = 0;
    BOOLEAN jumped = FALSE;
    int savedOffset = -1;

    if (!packet || !nameOut || nameOutSize < 1)
        return -1;

    if (offset < 0 || offset >= packetLen)
        return -1;

    while (offset < packetLen) {
        BYTE labelLen = packet[offset];

        // End of name
        if (labelLen == 0) {
            offset++;
            break;
        }

        // DNS name compression pointer (top 2 bits set)
        if ((labelLen & 0xC0) == 0xC0) {
            if (offset + 1 >= packetLen)
                return -1;

            // Loop detection
            if (++jumpCount > 10)
                return -1;

            // Calculate pointer target
            USHORT ptrOffset = ((labelLen & 0x3F) << 8) | packet[offset + 1];

            // Validate pointer
            if (ptrOffset >= packetLen || ptrOffset >= offset)
                return -1;

            // Save position on first jump
            if (!jumped) {
                savedOffset = offset + 2;
                jumped = TRUE;
            }

            offset = ptrOffset;
            continue;
        }

        // Validate label length
        if (labelLen > 63 || offset + 1 + labelLen > packetLen)
            return -1;

        // Add dot separator
        if (!firstLabel) {
            if (outPos + 1 >= nameOutSize)
                return -1;
            nameOut[outPos++] = L'.';
        }
        firstLabel = FALSE;

        // Copy label
        offset++;
        for (int i = 0; i < labelLen; i++) {
            if (outPos + 1 >= nameOutSize)
                return -1;
            nameOut[outPos++] = (WCHAR)packet[offset++];
        }
    }

    nameOut[outPos] = L'\0';

    // Return bytes consumed
    if (jumped && savedOffset > 0)
        return savedOffset - originalOffset;
    return offset - originalOffset;
}

//---------------------------------------------------------------------------
// EncDns_CacheStore
//---------------------------------------------------------------------------

static void EncDns_CacheStore(const WCHAR* domain, USHORT qtype, const DOH_RESULT* pResult, BOOLEAN is_failure, BOOLEAN is_bind_failure)
{
    ULONGLONG now;
    int i;
    int oldest_idx = 0;
    ULONGLONG oldest_expiry = (ULONGLONG)-1;
    BOOLEAN found_empty = FALSE;

    if (!InterlockedCompareExchange(&g_DohCacheLockValid, 0, 0))
        return;

    now = GetTickCount64();

    EnterCriticalSection(&g_DohCacheLock);

    // Two-pass eviction: 1) Find empty or expired, 2) Fall back to LRU
    for (i = 0; i < DOH_CACHE_SIZE; i++) {
        if (!g_DohCache[i].valid) {
            oldest_idx = i;
            found_empty = TRUE;
            break;
        }
        // Prefer expired entries over valid ones
        if (now >= g_DohCache[i].expiry) {
            if (!found_empty || g_DohCache[i].expiry < oldest_expiry) {
                oldest_expiry = g_DohCache[i].expiry;
                oldest_idx = i;
                found_empty = TRUE;  // Mark as found to avoid checking valid entries
            }
        }
    }

    // If no empty/expired entries, fall back to LRU (oldest non-expired entry)
    if (!found_empty) {
        oldest_expiry = (ULONGLONG)-1;
        for (i = 0; i < DOH_CACHE_SIZE; i++) {
            if (g_DohCache[i].expiry < oldest_expiry) {
                oldest_expiry = g_DohCache[i].expiry;
                oldest_idx = i;
            }
        }
    }

    wcsncpy(g_DohCache[oldest_idx].domain, domain, 255);
    g_DohCache[oldest_idx].domain[255] = L'\0';
    g_DohCache[oldest_idx].qtype = qtype;
    g_DohCache[oldest_idx].expiry = now + (pResult->TTL * 1000);
    memcpy(&g_DohCache[oldest_idx].result, pResult, sizeof(DOH_RESULT));
    g_DohCache[oldest_idx].is_failure = is_failure;
    g_DohCache[oldest_idx].is_bind_failure = is_bind_failure;
    g_DohCache[oldest_idx].valid = TRUE;

    LeaveCriticalSection(&g_DohCacheLock);

    if (DNS_DebugFlag) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"[EncDns] Cached: %s (Type: %d, TTL: %d)", domain, qtype, pResult->TTL);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
}

static void EncDns_CachePurgeFailures(BOOLEAN only_bind_failures)
{
    if (!InterlockedCompareExchange(&g_DohCacheLockValid, 0, 0))
        return;

    EnterCriticalSection(&g_DohCacheLock);
    for (int i = 0; i < DOH_CACHE_SIZE; i++) {
        if (!g_DohCache[i].valid)
            continue;
        if (!g_DohCache[i].is_failure)
            continue;
        if (only_bind_failures && !g_DohCache[i].is_bind_failure)
            continue;
        g_DohCache[i].valid = FALSE;
    }
    LeaveCriticalSection(&g_DohCacheLock);
}

static void EncDns_ResetAllServerFailures(void)
{
    if (!InterlockedCompareExchange(&g_DohConfigLockValid, 0, 0))
        return;

    EnterCriticalSection(&g_DohConfigLock);
    for (ULONG line = 0; line < g_DohConfigLineCount; line++) {
        DOH_CONFIG_LINE* cfg = &g_DohConfigLines[line];
        for (ULONG s = 0; s < cfg->ServerCount; s++) {
            DOH_SERVER* server = &cfg->Servers[s];
            server->FailedUntil = 0;
            server->Http3FallbackUntil = 0;
            server->Http3FailCount = 0;
            for (int i = 0; i < 5; i++) {
                server->AutoBackoff[i].BackoffUntil = 0;
                server->AutoBackoff[i].FailCount = 0;
            }
        }
    }
    LeaveCriticalSection(&g_DohConfigLock);
}

// Detect BindAdapter/BindAdapterIP down->up transitions and repair sticky state.
static void EncDns_CheckBindAdapterRecovery(void)
{
    static volatile LONG s_inited = 0;
    static BOOLEAN s_lastValid = TRUE;

    if (!WSA_IsBindIPEnabled())
        return;

    BOOLEAN nowValid = WSA_IsBindIPValid();
    if (InterlockedCompareExchange(&s_inited, 1, 0) == 0) {
        s_lastValid = nowValid;
        return;
    }

    if (!s_lastValid && nowValid) {
        EncDns_CachePurgeFailures(FALSE);
        EncDns_ResetAllServerFailures();
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS,
                L"[EncDns] BindAdapter/BindAdapterIP is UP again - cleared failed-query cache and reset server fail/backoff state");
        }
    }

    s_lastValid = nowValid;
}

//---------------------------------------------------------------------------
// DoH_IsIPAddress
//
// Detects if a hostname is an IP address (IPv4 or IPv6).
// IPv6: Checks for bracket notation [address]
// IPv4: Validates structure (digits and exactly 3 dots)
//
// Returns: TRUE if hostname appears to be an IP address, FALSE otherwise
//---------------------------------------------------------------------------

static BOOLEAN DoH_IsIPAddress(const WCHAR* hostname)
{
    const WCHAR* p;
    int dotCount;
    
    if (!hostname || !hostname[0])
        return FALSE;
    
    // Check for IPv6 in brackets
    if (hostname[0] == L'[') {
        p = hostname;
        while (*p && *p != L']') p++;
        return *p == L']';
    }
    
    // Check if entire string consists only of digits and dots
    // (basic IPv4 detection - will have false positives like "1.2.3" but catches most cases)
    p = hostname;
    dotCount = 0;
    
    while (*p) {
        if (*p == L'.') {
            dotCount++;
        }
        else if (*p < L'0' || *p > L'9') {
            return FALSE; // Non-digit, non-dot character found
        }
        p++;
    }
    
    // Must have exactly 3 dots for IPv4 (e.g., 1.1.1.1)
    return dotCount == 3;
}

//---------------------------------------------------------------------------
// DoH_EscapeDomainName - URL-encode domain name for RFC 8484 compliance
//
// RFC 8484 requires proper URL encoding of query parameters.
// UrlEscapeW handles percent-encoding and special character conversion.
//
// Returns: Pointer to escaped domain (buffer), or original domain if encoding fails
//---------------------------------------------------------------------------

static const WCHAR* DoH_EscapeDomainName(const WCHAR* domain, WCHAR* buffer, DWORD bufsize)
{
    if (!domain || !buffer || bufsize == 0)
        return domain;

    // Try to use UrlEscapeW if available
    if (__sys_UrlEscapeW) {
        DWORD escaped_len = bufsize;
        HRESULT hr = __sys_UrlEscapeW(domain, buffer, &escaped_len, 
                                       URL_ESCAPE_SEGMENT);  // Escape for URL segment (domain names)
        if (SUCCEEDED(hr)) {
            return buffer;
        }
    }

    // Fallback: Copy as-is (most domain names are ASCII and don't need encoding)
    wcsncpy(buffer, domain, bufsize - 1);
    buffer[bufsize - 1] = L'\0';
    return buffer;
}

//---------------------------------------------------------------------------
// DoH_GetTypeString
//---------------------------------------------------------------------------

static const WCHAR* DoH_GetTypeString(USHORT qtype, WCHAR* buffer, DWORD bufsize)
{
    switch (qtype) {
        case 1:   return L"A";
        case 28:  return L"AAAA";
        case 5:   return L"CNAME";
        case 15:  return L"MX";
        case 16:  return L"TXT";
        case 2:   return L"NS";
        case 6:   return L"SOA";
        case 12:  return L"PTR";
        case 33:  return L"SRV";
        case 255: return L"ANY";
        case 257: return L"CAA";
		case 658: return L"HTTPS";
        default:
            Sbie_snwprintf(buffer, bufsize, L"TYPE%d", qtype);
            return buffer;
    }
}

//---------------------------------------------------------------------------
// DoH_SelectProtocolMode
//
// Determines protocol selection (HTTP/2 vs HTTP/3) based on server config,
// OS capabilities, and backoff state.
//
// Parameters:
//   server - DoH server configuration
//   now    - Current tick count (for backoff checking)
//   result - [OUT] Protocol selection result
//
// Returns: TRUE if protocol selection succeeded, FALSE if HTTP/3 required but unavailable
//---------------------------------------------------------------------------

static BOOLEAN DoH_SelectProtocolMode(DOH_SERVER* server, ULONGLONG now, DOH_PROTOCOL_SELECTION* result)
{
    if (!result)
        return FALSE;

    // Advanced protocol controls via WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL exist on Win10 1607+ (build 14393).
    result->CanUseEnableProtocol = (Dll_OsBuild >= 14393 && __sys_WinHttpSetOption && g_hWinHttpSession);
    result->CanUseHttp3 = (Dll_OsBuild >= 26100 && result->CanUseEnableProtocol);

    // Default to HTTP/2
    result->ProtocolMask = WINHTTP_PROTOCOL_FLAG_HTTP2;
    result->Http3Enabled = FALSE;
    result->DecisionReason = L"http2";

    if (server->Http3Mode == 1) {
        // HTTP/3 only: do not allow HTTP/2 fallback
        if (!result->CanUseHttp3) {
            if (DNS_TraceFlag) {
                WCHAR msg[256];
                const WCHAR* modeName = EncryptedDns_GetModeName(server->ProtocolMode);
                Sbie_snwprintf(msg, 256, L"[EncDns] mode=%s requires HTTP/3 for %s:%d, but HTTP/3 not supported on this OS/build",
                    modeName, server->Host, server->Port);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            return FALSE;
        }
        result->ProtocolMask = WINHTTP_PROTOCOL_FLAG_HTTP3;
        result->Http3Enabled = TRUE;
        result->DecisionReason = L"http3-only";
    } else if (server->Http3Mode == -1) {
        // Auto: prefer HTTP/3, but respect backoff cooldown
        if (result->CanUseHttp3 && (server->Http3FallbackUntil == 0 || now >= server->Http3FallbackUntil)) {
            result->ProtocolMask = (WINHTTP_PROTOCOL_FLAG_HTTP2 | WINHTTP_PROTOCOL_FLAG_HTTP3);
            result->Http3Enabled = TRUE;
            result->DecisionReason = L"auto";
        } else {
            result->ProtocolMask = WINHTTP_PROTOCOL_FLAG_HTTP2;
            result->Http3Enabled = FALSE;
            result->DecisionReason = (server->Http3FallbackUntil > 0 && now < server->Http3FallbackUntil) ? L"auto-cooldown" : L"auto-no-http3";
        }
    } else {
        // Default: HTTP/2 only
        if (result->CanUseEnableProtocol) {
            result->ProtocolMask = WINHTTP_PROTOCOL_FLAG_HTTP2;
            result->Http3Enabled = FALSE;
            result->DecisionReason = L"http2";
        } else {
            // WinHTTP advanced protocol selection is unavailable; fall back to legacy HTTP (1.1 and prior).
            result->ProtocolMask = 0;
            result->Http3Enabled = FALSE;
            result->DecisionReason = L"http11";
        }
    }

    return TRUE;
}

//---------------------------------------------------------------------------
// Helpers: readable protocol strings for logging
//---------------------------------------------------------------------------

static const WCHAR* DoH_GetHttpProtocolString(DWORD protoFlags)
{
    if ((protoFlags & WINHTTP_PROTOCOL_FLAG_HTTP3) != 0)
        return L"HTTP/3";
    if ((protoFlags & WINHTTP_PROTOCOL_FLAG_HTTP2) != 0)
        return L"HTTP/2";
    if (protoFlags == 0)
        return L"HTTP/1.1";
    return L"HTTP";
}

static const WCHAR* DoH_GetHttpProtocolMaskString(DWORD protoMask)
{
    if (protoMask == (WINHTTP_PROTOCOL_FLAG_HTTP2 | WINHTTP_PROTOCOL_FLAG_HTTP3))
        return L"HTTP/2+HTTP/3";
    return DoH_GetHttpProtocolString(protoMask);
}

//---------------------------------------------------------------------------
// Helpers: map WinHTTP protocol used flags to Encrypted DNS mode
//---------------------------------------------------------------------------

static ENCRYPTED_DNS_MODE EncDns_MapWinHttpProtoUsedToMode(DWORD protoUsed)
{
    if ((protoUsed & WINHTTP_PROTOCOL_FLAG_HTTP3) != 0)
        return ENCRYPTED_DNS_MODE_DOH3;
    if ((protoUsed & WINHTTP_PROTOCOL_FLAG_HTTP2) != 0)
        return ENCRYPTED_DNS_MODE_DOH2;
    return ENCRYPTED_DNS_MODE_DOH;
}

//---------------------------------------------------------------------------
// DoH_ConfigureSecurityOptions
//
// Configures WinHTTP security options including certificate validation,
// OCSP revocation checking, and timeouts.
//
// Parameters:
//   hRequest - WinHTTP request handle
//   server   - DoH server configuration
//---------------------------------------------------------------------------

static void DoH_ConfigureSecurityOptions(HINTERNET hRequest, DOH_SERVER* server)
{
    if (!__sys_WinHttpSetOption || !hRequest)
        return;

    DWORD security_flags = 0;
    
    // If using self-signed certificate (httpx://), disable certificate validation
    if (server->SelfSigned) {
        security_flags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | 
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID | 
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    }
    
    // Windows 7 (6.1) and earlier don't correctly validate certificate CN for IP addresses
    // Ignore CN validation when connecting to IP-based DoH servers on Windows 7/Vista only
    if (g_OsMajorVersion > 0 && g_OsMajorVersion <= 6 && DoH_IsIPAddress(server->Host)) {
        security_flags |= SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoH] Windows %d: Ignoring certificate CN for IP address", g_OsMajorVersion);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    }
    
    if (security_flags != 0) {
        if (!__sys_WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &security_flags, sizeof(security_flags))) {
            if (DNS_TraceFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Warning: Failed to set WinHTTP security flags");
            }
        }
    }
    
    // Control OCSP revocation checking
    // WinHTTP doesn't check revocation by default, so we only need to enable it explicitly if requested
    if (!server->DisableOCSP) {
        // Enable SSL revocation checking (only when ocsp=1)
        DWORD enable_revocation = WINHTTP_ENABLE_SSL_REVOCATION;
        if (!__sys_WinHttpSetOption(hRequest, WINHTTP_OPTION_ENABLE_FEATURE, &enable_revocation, sizeof(enable_revocation))) {
            if (DNS_DebugFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Warning: Failed to enable WinHTTP SSL revocation checking");
            }
        }
    }

    // Set HTTP timeouts to prevent indefinite blocking (5 seconds for DNS queries)
    if (__sys_WinHttpSetTimeouts) {
        // WinHttpSetTimeouts(hRequest, resolve, connect, send, receive) - all in milliseconds
        if (!__sys_WinHttpSetTimeouts(hRequest, 
                DOH_HTTP_TIMEOUT_MS,  // DNS name resolution timeout
                DOH_HTTP_TIMEOUT_MS,  // Connection timeout
                DOH_HTTP_TIMEOUT_MS,  // Send timeout
                DOH_HTTP_TIMEOUT_MS)) // Receive timeout
        {
            if (DNS_DebugFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Warning: Failed to set WinHTTP timeouts");
            }
        }
    }
}

//---------------------------------------------------------------------------
// DoH_ValidateProtocolUsed
//
// Validates that the correct HTTP protocol was used and handles fallback
// detection for HTTP/3 auto mode.
//
// Parameters:
//   hRequest   - WinHTTP request handle
//   server     - DoH server configuration
//   proto      - Protocol selection used for this request
//   result     - [IN/OUT] Request result (may be set to FALSE on validation failure)
//   bytes_read - [IN/OUT] Bytes read (may be reset to 0 on validation failure)
//   now        - Current tick count for backoff tracking
//---------------------------------------------------------------------------

static void DoH_ValidateProtocolUsed(HINTERNET hRequest, DOH_SERVER* server, 
    DOH_PROTOCOL_SELECTION* proto, BOOLEAN* result, DWORD* bytes_read, ULONGLONG now, DWORD* proto_used_out)
{
    if (!hRequest || !__sys_WinHttpQueryOption || !server || !proto || !result || !bytes_read)
        return;

    DWORD protoUsed = 0xFFFFFFFF;
    DWORD protoUsedSize = sizeof(protoUsed);

    if (!__sys_WinHttpQueryOption(hRequest, WINHTTP_OPTION_HTTP_PROTOCOL_USED, &protoUsed, &protoUsedSize)) {
        if (DNS_DebugFlag) {
            DWORD lastError = GetLastError();
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoH] WinHttpQueryOption(WINHTTP_OPTION_HTTP_PROTOCOL_USED) failed (err=%lu)", lastError);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        return;
    }

    if (proto_used_out)
        *proto_used_out = protoUsed;

    // Auto mode: detect silent fallback from HTTP/3 to HTTP/2
    if (*result && server->Http3Mode == -1 && proto->Http3Enabled) {
        if ((protoUsed & WINHTTP_PROTOCOL_FLAG_HTTP3) != 0) {
            if (DNS_TraceFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"[DoH] HTTP protocol used for %s:%d: HTTP/3", server->Host, server->Port);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            DoH_ResetHttp3Failures(server);
        } else if ((protoUsed & WINHTTP_PROTOCOL_FLAG_HTTP2) != 0) {
            if (DNS_TraceFlag) {
                WCHAR msg[384];
                Sbie_snwprintf(msg, 384, L"[DoH] HTTP/3 failed (silent fallback) for %s:%d -> used HTTP/2 (likely UDP/443 blocked)",
                    server->Host, server->Port);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            DoH_MarkHttp3Failed(server, now);
        } else {
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"[DoH] HTTP protocol used for %s:%d: 0x%lx", server->Host, server->Port, protoUsed);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
        }
    }

    // DoH3-only mode: treat HTTP/2/1.1 fallback as failure
    if (*result && server->ProtocolMode == ENCRYPTED_DNS_MODE_DOH3 && server->Http3Mode == 1) {
        if ((protoUsed & WINHTTP_PROTOCOL_FLAG_HTTP3) == 0) {
            if (DNS_TraceFlag) {
                WCHAR msg[384];
                const WCHAR* modeName = EncryptedDns_GetModeName(server->ProtocolMode);
                const WCHAR* usedProtoStr = DoH_GetHttpProtocolString(protoUsed);
                if (protoUsed == 0) {
                    Sbie_snwprintf(msg, 384, L"[EncDns] mode=%s requires HTTP/3 for %s:%d, but %s was used (proto=0x0 -> likely HTTP/1.1 over TLS/TCP or proxy); treating as failure",
                        modeName, server->Host, server->Port, usedProtoStr);
                } else {
                    Sbie_snwprintf(msg, 384, L"[EncDns] mode=%s requires HTTP/3 for %s:%d, but %s was used (proto=0x%lx); treating as failure",
                        modeName, server->Host, server->Port, usedProtoStr, protoUsed);
                }
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }

            DoH_LogWinHttpProxyInfo(hRequest, L"request");
            DoH_LogWinHttpProxyInfo(g_hWinHttpSession, L"session");

            *result = FALSE;
            *bytes_read = 0;
        }
    }

    // DoH2-only mode: treat HTTP/1.1 fallback as failure
    // Note: DoH (non-2) allows HTTP/1.1, so we must not fail those.
    if (*result && server->ProtocolMode == ENCRYPTED_DNS_MODE_DOH2 && server->Http3Mode == 0 && proto->ProtocolMask == WINHTTP_PROTOCOL_FLAG_HTTP2) {
        if ((protoUsed & WINHTTP_PROTOCOL_FLAG_HTTP2) == 0) {
            if (DNS_TraceFlag) {
                WCHAR msg[384];
                const WCHAR* modeName = EncryptedDns_GetModeName(server->ProtocolMode);
                const WCHAR* usedProtoStr = DoH_GetHttpProtocolString(protoUsed);
                if (protoUsed == 0) {
                    Sbie_snwprintf(msg, 384, L"[EncDns] mode=%s requires HTTP/2 for %s:%d, but %s was used (proto=0x0 -> likely HTTP/1.1 over TLS/TCP or proxy); treating as failure",
                        modeName, server->Host, server->Port, usedProtoStr);
                } else {
                    Sbie_snwprintf(msg, 384, L"[EncDns] mode=%s requires HTTP/2 for %s:%d, but %s was used (proto=0x%lx); treating as failure",
                        modeName, server->Host, server->Port, usedProtoStr, protoUsed);
                }
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }

            DoH_LogWinHttpProxyInfo(hRequest, L"request");
            DoH_LogWinHttpProxyInfo(g_hWinHttpSession, L"session");

            *result = FALSE;
            *bytes_read = 0;
        }
    }
}

//---------------------------------------------------------------------------
// DoH_HttpRequest_WinHttp
//
// Sends DNS query using WinHTTP with DNS wire format (RFC 8484 Section 4.1).
// Uses POST method with Content-Type: application/dns-message.
//
// Parameters:
//   server       - DoH server configuration
//   domain       - Domain name to query
//   qtype        - Query type (1=A, 28=AAAA)
//   response     - [OUT] Buffer for binary DNS response
//   response_size- Size of response buffer
//   bytes_read   - [OUT] Number of bytes read
//
// Returns: TRUE on success (HTTP 200 with valid response), FALSE on error
//---------------------------------------------------------------------------

static BOOLEAN DoH_HttpRequest_WinHttp(DOH_SERVER* server, const WCHAR* domain, USHORT qtype, BYTE* response, DWORD response_size, DWORD* bytes_read, ENCRYPTED_DNS_MODE* protocol_used_out)
{
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    DWORD status_code = 0;
    DWORD status_size = sizeof(DWORD);
    BOOLEAN result = FALSE;
    BYTE query_buffer[512];
    int query_len = 0;
    DWORD total_read = 0;
    DWORD chunk_read = 0;
    BOOLEAN isPooled = FALSE;
    DWORD protoUsed = 0;

    *bytes_read = 0;

    if (protocol_used_out)
        *protocol_used_out = ENCRYPTED_DNS_MODE_AUTO;

    if (!server || !DoH_HasWinHttpFunctions())
        return FALSE;

    // Build DNS query in wire format
    if (!DoH_BuildDnsQuery(domain, qtype, query_buffer, sizeof(query_buffer), &query_len)) {
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Failed to build DNS query");
        }
        return FALSE;
    }

    if (!InterlockedCompareExchange(&g_DohLockValid, 0, 0))
        return FALSE;

    EnterCriticalSection(&g_DohLock);
    
    if (!g_hWinHttpSession) {
        LeaveCriticalSection(&g_DohLock);
        if (!DoH_EnsureSession())
            return FALSE;
        EnterCriticalSection(&g_DohLock);
    }

    // Protocol selection using helper function
    ULONGLONG now = GetTickCount64();
    DOH_PROTOCOL_SELECTION protoSelect;
    
    if (!DoH_SelectProtocolMode(server, now, &protoSelect)) {
        LeaveCriticalSection(&g_DohLock);
        return FALSE;
    }

    // Configure protocol selection at session level for compatibility with existing pooling.
    if (protoSelect.CanUseEnableProtocol) {
        __sys_WinHttpSetOption(g_hWinHttpSession, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &protoSelect.ProtocolMask, sizeof(protoSelect.ProtocolMask));
        if (protoSelect.Http3Enabled) {
            DWORD http3Timeout = 500;
            __sys_WinHttpSetOption(g_hWinHttpSession, WINHTTP_OPTION_HTTP3_HANDSHAKE_TIMEOUT, &http3Timeout, sizeof(http3Timeout));
        }
    }

    if (DNS_TraceFlag) {
        const WCHAR* modeName = EncryptedDns_GetModeName(server->ProtocolMode);
        const WCHAR* protoStr = DoH_GetHttpProtocolMaskString(protoSelect.ProtocolMask);
        WCHAR msg[320];
        if (server->Http3Mode == -1 && server->Http3FallbackUntil > 0 && now < server->Http3FallbackUntil) {
            ULONG remaining = (ULONG)((server->Http3FallbackUntil - now) / 1000);
            Sbie_snwprintf(msg, 320, L"[EncDns] Protocol decision for %s:%d: mode=%s selected=%s (%s, cooldown %us)",
                server->Host, server->Port, modeName, protoStr, protoSelect.DecisionReason, remaining);
        } else {
            Sbie_snwprintf(msg, 320, L"[EncDns] Protocol decision for %s:%d: mode=%s selected=%s (%s)",
                server->Host, server->Port, modeName, protoStr, protoSelect.DecisionReason);
        }
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // Use pooled connection to prevent connection spam (keyed by protocol mask)
    hConnect = DoH_GetPooledConnection(server->Host, server->Port, protoSelect.ProtocolMask, &isPooled);
    LeaveCriticalSection(&g_DohLock);

    if (!hConnect) {
        // Log additional context for debugging connection failures
        WCHAR msg[320];
        Sbie_snwprintf(msg, 320, L"[DoH] Connection failed for %s:%d (proto=%s, pooled=%d)",
            server->Host, server->Port, 
            (protoSelect.ProtocolMask == WINHTTP_PROTOCOL_FLAG_HTTP3) ? L"h3" : L"h2",
            (int)isPooled);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        
        ULONGLONG errorNow = GetTickCount64();
        EncryptedDns_HandleQueryError(DOH_ERROR_CONNECT_FAILED, server, domain, errorNow);
        goto cleanup;
    }

    // Use POST method for DNS wire format
    hRequest = __sys_WinHttpOpenRequest(hConnect, L"POST", server->Path, NULL, 
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        ULONGLONG errorNow = GetTickCount64();
        EncryptedDns_HandleQueryError(DOH_ERROR_REQUEST_FAILED, server, domain, errorNow);
        goto cleanup;
    }

    // Protocol selection is primarily configured at session level above for pooling,
    // but enforce per-request settings where possible.
    if (__sys_WinHttpSetOption && hRequest) {
        // Ensure the request is constrained to the intended modern protocol set.
        if (protoSelect.CanUseEnableProtocol) {
            __sys_WinHttpSetOption(hRequest, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &protoSelect.ProtocolMask, sizeof(protoSelect.ProtocolMask));

            // Windows 10 1903+ (build 18362): optionally disallow legacy protocol fallback.
            if (Dll_OsBuild >= 18362) {
                BOOL requireModernProtocol = (server->Http3Mode != -1) ? TRUE : FALSE;
                __sys_WinHttpSetOption(hRequest, WINHTTP_OPTION_HTTP_PROTOCOL_REQUIRED, &requireModernProtocol, sizeof(requireModernProtocol));
            }

            if (protoSelect.Http3Enabled) {
                DWORD http3Timeout = 500;
                __sys_WinHttpSetOption(hRequest, WINHTTP_OPTION_HTTP3_HANDSHAKE_TIMEOUT, &http3Timeout, sizeof(http3Timeout));
            }
        }
    }

    // Configure security options (certificate validation, OCSP, timeouts)
    DoH_ConfigureSecurityOptions(hRequest, server);

    // Build request headers - include User-Agent only if explicitly enabled
    WCHAR headers[512];
    if (server->EnableAgent) {
        wcscpy(headers, L"Content-Type: application/dns-message\r\nAccept: application/dns-message\r\nConnection: Keep-Alive\r\nUser-Agent: Sandboxie-DoH/1.0\r\n");
    } else {
        wcscpy(headers, L"Content-Type: application/dns-message\r\nAccept: application/dns-message\r\nConnection: Keep-Alive\r\n");
    }

    // Send DNS query with wire format headers
    if (!__sys_WinHttpSendRequest(hRequest, 
            headers, 
            (DWORD)-1, query_buffer, query_len, query_len, 0)) {
        ULONGLONG errorNow = GetTickCount64();
        EncryptedDns_HandleQueryError(DOH_ERROR_SEND_FAILED, server, domain, errorNow);
        goto cleanup;
    }

    if (!__sys_WinHttpReceiveResponse(hRequest, NULL)) {
        ULONGLONG errorNow = GetTickCount64();
        EncryptedDns_HandleQueryError(DOH_ERROR_RECEIVE_FAILED, server, domain, errorNow);
        goto cleanup;
    }

    if (!__sys_WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_size, WINHTTP_NO_HEADER_INDEX)) {
        goto cleanup;
    }

    if (status_code != 200) {
        ULONGLONG errorNow = GetTickCount64();
        EncryptedDns_HandleQueryError(DOH_ERROR_HTTP_STATUS, server, domain, errorNow);
        goto cleanup;
    }

    // Read binary DNS response
    while (__sys_WinHttpReadData(hRequest, response + total_read, 
            response_size - total_read, &chunk_read) && chunk_read > 0) {
        total_read += chunk_read;
        if (total_read >= response_size) {
            ULONGLONG errorNow = GetTickCount64();
            EncryptedDns_HandleQueryError(DOH_ERROR_PARSE_FAILED, server, domain, errorNow);
            goto cleanup;
        }
    }

    if (total_read > 0) {
        *bytes_read = total_read;
        result = TRUE;

        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoH] WinHTTP received %d bytes for %s", total_read, domain);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    }

cleanup:
    // Validate that the correct HTTP protocol was used and handle fallback detection
    DoH_ValidateProtocolUsed(hRequest, server, &protoSelect, &result, bytes_read, now, &protoUsed);

    if (result && protocol_used_out && protoUsed != 0xFFFFFFFF) {
        *protocol_used_out = EncDns_MapWinHttpProtoUsedToMode(protoUsed);
    }

    if (hRequest)
        __sys_WinHttpCloseHandle(hRequest);
    
    // Release connection back to pool (or close if temporary)
    DoH_ReleasePooledConnection(hConnect, !isPooled);

    // Track explicit HTTP/3 attempt failures (auto mode only).
    if (!result && server->Http3Mode == -1 && protoSelect.Http3Enabled) {
        DoH_MarkHttp3Failed(server, now);
    }

    return result;
}

//---------------------------------------------------------------------------
// EncDns_TryProtocol - Try a specific protocol for a query
// 
// Helper function that attempts a query using a specific protocol mode.
// Returns TRUE on success, FALSE on failure.
//---------------------------------------------------------------------------

static BOOLEAN EncDns_TryProtocol(DOH_SERVER* server, ENCRYPTED_DNS_MODE mode,
    const WCHAR* domain, USHORT qtype, BYTE* response, DWORD response_size, DWORD* bytes_read, ENCRYPTED_DNS_MODE* protocol_used_out)
{
    // Note: DoQ_Query and DoQ_IsAvailable are declared in dns_doq.h
    // DoQ uses DOQ_SERVER struct and ENCRYPTED_DNS_RESULT, not raw response buffers
    // This integration requires conversion between the two interfaces
    
    if (protocol_used_out)
        *protocol_used_out = ENCRYPTED_DNS_MODE_AUTO;

    switch (mode) {
        case ENCRYPTED_DNS_MODE_DOQ:
            // DNS over QUIC (DoQ) - RFC 9250
            // Use MsQuic backend, port 853
            // Note: DoQ_Query uses DOQ_SERVER and ENCRYPTED_DNS_RESULT interfaces
            // which differ from the raw buffer interface used here.
            // DoQ integration requires building DOQ_SERVER and converting results.

            // StrictBindIP is incompatible with QUIC (wildcard UDP sockets).
            // In AUTO mode we skip QUIC higher up; here we only emit an explicit
            // trace when the configuration is protocol-locked to QUIC and thus cannot fallback.
            {
                extern BOOLEAN WSA_ShouldDisableQuicProtocols(void);
                if ((server ? server->StrictBindIpQuicDisable : TRUE) && WSA_ShouldDisableQuicProtocols()) {
                    if (server && server->ProtocolLocked && (DNS_TraceFlag || DNS_DebugFlag) && !g_LoggedStrictBindIPBlockedLocked) {
                        WCHAR msg[512];
                        Sbie_snwprintf(msg, 512,
                            L"[EncDns] StrictBindIP active - QUIC protocols disabled; DoQ-only requested (quic:// or ?mode=doq). Server=%s:%u",
                            server->Host, (ULONG)server->PortDoQ);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                        g_LoggedStrictBindIPBlockedLocked = TRUE;
                    }
                    return FALSE;
                }
            }
            if (DNS_DebugFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[EncDns] Checking DoQ availability...");
            }
            
            if (!DoQ_IsAvailable()) {
                if (DNS_DebugFlag) {
                    SbieApi_MonitorPutMsg(MONITOR_DNS, L"[EncDns] DoQ unavailable (MsQuic not loaded) - skipping");
                }
                // In AUTO mode, this is not a failure - just skip DoQ and try next protocol
                // Don't return FALSE here - let caller try other protocols
                // Mark protocol as failed for backoff tracking
                if (server && server->ProtocolMode == ENCRYPTED_DNS_MODE_AUTO) {
                    ULONGLONG now = GetTickCount64();
                    server->AutoBackoff[ENCRYPTED_DNS_MODE_DOQ].FailCount++;
                    // Calculate backoff: 30s, 60s, 120s, 300s max
                    ULONG backoffMs = (server->AutoBackoff[ENCRYPTED_DNS_MODE_DOQ].FailCount == 1) ? 30000 :
                                      (server->AutoBackoff[ENCRYPTED_DNS_MODE_DOQ].FailCount == 2) ? 60000 :
                                      (server->AutoBackoff[ENCRYPTED_DNS_MODE_DOQ].FailCount == 3) ? 120000 : 300000;
                    server->AutoBackoff[ENCRYPTED_DNS_MODE_DOQ].BackoffUntil = now + backoffMs;
                }
                return FALSE;  // Skip this protocol, caller will try next
            }
            
            if (DNS_DebugFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[EncDns] DoQ is available, proceeding...");
            }
            {
                DOQ_SERVER doqServer = { 0 };
                ENCRYPTED_DNS_RESULT doqResult = { 0 };
                
                // Build DOQ_SERVER from DOH_SERVER
                wcsncpy(doqServer.Host, server->Host, ENCRYPTED_DNS_DOMAIN_MAX_LEN - 1);
                doqServer.Port = server->PortDoQ;
                doqServer.SelfSigned = server->SelfSigned;
                doqServer.FailedUntil = 0;
                
                if (DNS_DebugFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"[EncDns] Trying DoQ to %s:%d", server->Host, server->PortDoQ);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
                
                // Call DoQ_Query which returns parsed result
                if (!DoQ_Query(&doqServer, domain, qtype, &doqResult)) {
                    if (DNS_DebugFlag) {
                        SbieApi_MonitorPutMsg(MONITOR_DNS, L"[EncDns] DoQ query failed");
                    }
                    return FALSE;
                }

                if (protocol_used_out)
                    *protocol_used_out = ENCRYPTED_DNS_MODE_DOQ;
                
                // Use raw DNS response if available (supports all record types: A, AAAA, CNAME, TXT, MX, etc.)
                if (doqResult.RawResponseLen > 0 && doqResult.RawResponseLen <= response_size) {
                    memcpy(response, doqResult.RawResponse, doqResult.RawResponseLen);
                    *bytes_read = doqResult.RawResponseLen;
                    return TRUE;
                }
                
                // Fallback: Convert ENCRYPTED_DNS_RESULT to DNS wire format (A/AAAA only)
                // Build minimal DNS response: Header + Question + Answer(s)
                BYTE* ptr = response;
                DOH_DNS_HEADER* header = (DOH_DNS_HEADER*)ptr;
                ptr += sizeof(DOH_DNS_HEADER);
                
                // DNS Header
                header->TransactionID = 0x1234;  // Arbitrary ID
                header->Flags = _htons(0x8180);  // Response, recursion desired/available, no error
                if (!doqResult.Success || doqResult.Status != 0) {
                    // Set RCODE from DNS status
                    USHORT flags = _ntohs(header->Flags);
                    flags = (flags & 0xFFF0) | (doqResult.Status & 0x000F);
                    header->Flags = _htons(flags);
                }
                header->Questions = _htons(1);
                header->AnswerRRs = _htons(doqResult.AnswerCount);
                header->AuthorityRRs = 0;
                header->AdditionalRRs = 0;
                
                // Question section (domain name + qtype + qclass)
                // Encode domain name in DNS format
                const WCHAR* label = domain;
                while (*label) {
                    const WCHAR* dot = wcschr(label, L'.');
                    size_t len = dot ? (dot - label) : wcslen(label);
                    if (len > 63 || (ptr - response) + len + 1 > response_size) {
                        return FALSE;  // Label too long or buffer full
                    }
                    *ptr++ = (BYTE)len;
                    for (size_t i = 0; i < len; i++) {
                        *ptr++ = (BYTE)label[i];
                    }
                    if (!dot) break;
                    label = dot + 1;
                }
                *ptr++ = 0;  // End of domain name
                
                // QTYPE and QCLASS
                *(USHORT*)ptr = _htons(qtype);
                ptr += 2;
                *(USHORT*)ptr = _htons(1);  // IN class
                ptr += 2;
                
                // Answer section
                for (USHORT i = 0; i < doqResult.AnswerCount; i++) {
                    // Name (compression pointer to question)
                    *ptr++ = 0xC0;
                    *ptr++ = 0x0C;  // Points to offset 12 (after header)
                    
                    // Type
                    *(USHORT*)ptr = _htons(doqResult.Answers[i].Type == AF_INET ? 1 : 28);
                    ptr += 2;
                    
                    // Class (IN)
                    *(USHORT*)ptr = _htons(1);
                    ptr += 2;
                    
                    // TTL
                    *(DWORD*)ptr = _htonl(doqResult.TTL);
                    ptr += 4;
                    
                    // RDLENGTH and RDATA
                    if (doqResult.Answers[i].Type == AF_INET) {
                        *(USHORT*)ptr = _htons(4);
                        ptr += 2;
                        memcpy(ptr, &doqResult.Answers[i].IP.Data32[3], 4);
                        ptr += 4;
                    } else {  // AF_INET6
                        *(USHORT*)ptr = _htons(16);
                        ptr += 2;
                        memcpy(ptr, doqResult.Answers[i].IP.Data, 16);
                        ptr += 16;
                    }
                }
                
                *bytes_read = (DWORD)(ptr - response);
                return TRUE;
            }
            
        case ENCRYPTED_DNS_MODE_DOH3:
            // DNS over HTTPS with HTTP/3 (QUIC)
            // On Windows 11 22H2+: Use WinHTTP with HTTP/3 flag
            // On Windows 10: Use MsQuic for HTTP/3 over QUIC (not yet implemented)

            // StrictBindIP is incompatible with QUIC-style wildcard UDP sockets.
            // When DoH3 is selected directly, we must fail (no implicit downgrade).
            {
                extern BOOLEAN WSA_ShouldDisableQuicProtocols(void);
                if ((server ? server->StrictBindIpQuicDisable : TRUE) && WSA_ShouldDisableQuicProtocols()) {
                    if (server && server->ProtocolLocked && (DNS_TraceFlag || DNS_DebugFlag) && !g_LoggedStrictBindIPBlockedLocked) {
                        WCHAR msg[512];
                        Sbie_snwprintf(msg, 512,
                            L"[EncDns] StrictBindIP active - QUIC protocols disabled; DoH3-only requested (?mode=doh3). Server=%s:%u",
                            server->Host, (ULONG)server->Port);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                        g_LoggedStrictBindIPBlockedLocked = TRUE;
                    }
                    return FALSE;
                }
            }
            
            if (EncryptedDns_WinHttpSupportsHttp3()) {
                if (DNS_DebugFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"[EncDns] Trying DoH3 (WinHTTP) to %s:%d", server->Host, server->Port);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
                // Temporarily set Http3Mode to force HTTP/3
                CHAR savedHttp3Mode = server->Http3Mode;
                server->Http3Mode = 1;  // HTTP/3 only
                BOOLEAN result = DoH_HttpRequest_WinHttp(server, domain, qtype, response, response_size, bytes_read, protocol_used_out);
                server->Http3Mode = savedHttp3Mode;
                return result;
            } else {
                // Pre-Windows 11: Try MsQuic-based HTTP/3 (DoQ with HTTP/3 framing)
                // Note: This is a simplified approach - true HTTP/3 over MsQuic would need
                // full HTTP/3 framing. For now, fallback to next protocol.
                if (DNS_DebugFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"[EncDns] DoH3 unavailable (requires Windows 11 build 22000+, current: %d.%d.%d)",
                        g_OsMajorVersion, g_OsMinorVersion, g_OsBuildNumber);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
                return FALSE;
            }
            
        case ENCRYPTED_DNS_MODE_DOH2:
            // DNS over HTTPS with HTTP/2 only
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"[EncDns] Trying DoH2 to %s:%d", server->Host, server->Port);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            {
                CHAR savedHttp3Mode = server->Http3Mode;
                server->Http3Mode = 0;  // HTTP/2 only
                BOOLEAN result = DoH_HttpRequest_WinHttp(server, domain, qtype, response, response_size, bytes_read, protocol_used_out);
                server->Http3Mode = savedHttp3Mode;
                return result;
            }
            
        case ENCRYPTED_DNS_MODE_DOH:
            // DNS over HTTPS (HTTP/1.1 or HTTP/2, auto-negotiated)
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"[EncDns] Trying DoH to %s:%d", server->Host, server->Port);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            return DoH_HttpRequest_WinHttp(server, domain, qtype, response, response_size, bytes_read, protocol_used_out);
            
        case ENCRYPTED_DNS_MODE_DOT:
            // DNS over TLS - not yet implemented
            if (DNS_TraceFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[EncDns] DoT (DNS over TLS) not yet implemented");
            }
            return FALSE;
            
        default:
            return FALSE;
    }
}

//---------------------------------------------------------------------------
// EncDns_RequestToServer - Make request to a specific server
// 
// Dispatches to the appropriate backend based on protocol mode:
//   - DoH/DoH2/DoH3: Uses WinHTTP (HTTP-based)
//   - DoQ: Uses MsQuic (QUIC-based, RFC 9250)
//   - DoT: Not yet implemented
//   - AUTO: Tries DoQ → DoH3 → DoH2 → DoH with fallback and backoff
//---------------------------------------------------------------------------

static BOOLEAN EncDns_RequestToServer(DOH_SERVER* server, const WCHAR* domain, USHORT qtype, BYTE* response, DWORD response_size, DWORD* bytes_read, ENCRYPTED_DNS_MODE* protocol_used_out)
{
    ULONGLONG now;
    ENCRYPTED_DNS_MODE tryMode;
    
    if (!server)
        return FALSE;

    if (!InterlockedCompareExchange(&g_DohLockValid, 0, 0))
        return FALSE;

    now = GetTickCount64();

    if (protocol_used_out)
        *protocol_used_out = ENCRYPTED_DNS_MODE_AUTO;

    // One-time trace when StrictBindIP is active but ?strict=0 explicitly allows QUIC.
    // This is placed here (runtime) because network binding policy may not be initialized
    // yet at configuration-parse time.
    {
        extern BOOLEAN WSA_ShouldDisableQuicProtocols(void);
        if (!server->StrictBindIpQuicDisable && WSA_ShouldDisableQuicProtocols()) {
            if ((DNS_TraceFlag || DNS_DebugFlag) && !g_LoggedStrictBindIPStrictOverride) {
                WCHAR msg[512];
                if (server->PortDoQ && server->PortDoQ != server->Port) {
                    Sbie_snwprintf(msg, 512,
                        L"[EncDns] StrictBindIP active but overridden by ?strict=0 (QUIC allowed). Server=%s:%u (DoQ port %u)",
                        server->Host, (ULONG)server->Port, (ULONG)server->PortDoQ);
                } else {
                    Sbie_snwprintf(msg, 512,
                        L"[EncDns] StrictBindIP active but overridden by ?strict=0 (QUIC allowed). Server=%s:%u",
                        server->Host, (ULONG)server->Port);
                }
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                g_LoggedStrictBindIPStrictOverride = TRUE;
            }
        }
    }
    
    // Handle AUTO mode with fallback chain: DoQ → DoH3 → DoH2 → DoH
    if (server->ProtocolMode == ENCRYPTED_DNS_MODE_AUTO) {
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[EncDns] AUTO mode for %s - trying protocols in order", domain);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        
        // Check if QUIC protocols should be skipped (StrictBindIP)
        extern BOOLEAN WSA_ShouldDisableQuicProtocols(void);
        BOOLEAN strictBindIpQuicIncompatible = (server->StrictBindIpQuicDisable && WSA_ShouldDisableQuicProtocols());
        
        // Log suppression: reuse parse-time flag for consistent logging
        extern BOOLEAN g_LoggedStrictBindIPDowngrade;
        
        // Try each protocol in order, skipping those in backoff.
        // - https:// / httpx:// default: HTTP-only fallback DoH3 → DoH2 → DoH (skip DoQ)
        // - auto:// / autox:// and explicit mode=auto: full fallback DoQ → DoH3 → DoH2 → DoH
        const ENCRYPTED_DNS_MODE* protocols = NULL;
        int protocolCount = 0;
        static const ENCRYPTED_DNS_MODE protocols_http_only[] = {
            ENCRYPTED_DNS_MODE_DOH3,
            ENCRYPTED_DNS_MODE_DOH2,
            ENCRYPTED_DNS_MODE_DOH
        };
        static const ENCRYPTED_DNS_MODE protocols_full_auto[] = {
            ENCRYPTED_DNS_MODE_DOQ,
            ENCRYPTED_DNS_MODE_DOH3,
            ENCRYPTED_DNS_MODE_DOH2,
            ENCRYPTED_DNS_MODE_DOH
        };

        if (server->HttpOnlyAuto) {
            protocols = protocols_http_only;
            protocolCount = (int)(sizeof(protocols_http_only) / sizeof(protocols_http_only[0]));
        } else {
            protocols = protocols_full_auto;
            protocolCount = (int)(sizeof(protocols_full_auto) / sizeof(protocols_full_auto[0]));
        }

        for (int i = 0; i < protocolCount; i++) {
            tryMode = protocols[i];
            
            // Skip QUIC-based protocols (DoQ and DoH3) if StrictBindIP is active
            if (strictBindIpQuicIncompatible && (tryMode == ENCRYPTED_DNS_MODE_DOQ || tryMode == ENCRYPTED_DNS_MODE_DOH3)) {
                if (DNS_DebugFlag && !g_LoggedStrictBindIPDowngrade) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"[EncDns] Skipping QUIC protocols (StrictBindIP active - incompatible)");
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                    g_LoggedStrictBindIPDowngrade = TRUE;
                }
                continue;
            }
            
            // Check if this protocol is in backoff
            if (server->AutoBackoff[tryMode].BackoffUntil > now) {
                if (DNS_DebugFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"[EncDns] Skipping %s (in backoff for %llu ms)", 
                        EncryptedDns_GetModeName(tryMode),
                        server->AutoBackoff[tryMode].BackoffUntil - now);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
                continue;
            }
            
            if (DNS_DebugFlag) {
                USHORT actualPort = (tryMode == ENCRYPTED_DNS_MODE_DOQ) ? 
                    EncryptedDns_GetDefaultPort(tryMode) : server->Port;
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"[EncDns] Attempting %s for %s (%s:%d)", 
                    EncryptedDns_GetModeName(tryMode), domain, server->Host, actualPort);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            
            // Try this protocol
            ENCRYPTED_DNS_MODE used = ENCRYPTED_DNS_MODE_AUTO;
            if (EncDns_TryProtocol(server, tryMode, domain, qtype, response, response_size, bytes_read, &used)) {
                // Success - clear backoff for this protocol
                EnterCriticalSection(&g_DohConfigLock);
                server->AutoBackoff[tryMode].BackoffUntil = 0;
                server->AutoBackoff[tryMode].FailCount = 0;
                LeaveCriticalSection(&g_DohConfigLock);

                if (protocol_used_out)
                    *protocol_used_out = used;
                
                if (DNS_DebugFlag && tryMode != ENCRYPTED_DNS_MODE_DOQ) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"[EncDns] Success with %s (not primary DoQ)", 
                        EncryptedDns_GetModeName(tryMode));
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
                return TRUE;
            }
            
            // Failed - update backoff for this protocol
            EnterCriticalSection(&g_DohConfigLock);
            server->AutoBackoff[tryMode].FailCount++;
            server->AutoBackoff[tryMode].BackoffUntil = now + 
                EncryptedDns_GetBackoffMs(server->AutoBackoff[tryMode].FailCount);
            LeaveCriticalSection(&g_DohConfigLock);
            
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"[EncDns] %s failed, backoff %lu ms", 
                    EncryptedDns_GetModeName(tryMode),
                    EncryptedDns_GetBackoffMs(server->AutoBackoff[tryMode].FailCount));
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
        }
        
        // All protocols failed
        return FALSE;
    }
    
    // Non-AUTO mode: dispatch directly to the specified protocol
    {
        ENCRYPTED_DNS_MODE used = ENCRYPTED_DNS_MODE_AUTO;
        BOOLEAN ok = EncDns_TryProtocol(server, server->ProtocolMode, domain, qtype, response, response_size, bytes_read, &used);
        if (ok && protocol_used_out)
            *protocol_used_out = used;
        return ok;
    }
}

//---------------------------------------------------------------------------
// EncDns_Request - Make request with multi-server failover
//---------------------------------------------------------------------------

static BOOLEAN EncDns_Request(const WCHAR* domain, USHORT qtype, BYTE* response, DWORD response_size, DWORD* bytes_read, ENCRYPTED_DNS_MODE* protocol_used_out)
{
    ULONGLONG now = GetTickCount64();
    ULONG attempts = 0;
    ULONG max_attempts;
    DOH_SERVER* first_server = NULL;
    DOH_SERVER* server;

    if (protocol_used_out)
        *protocol_used_out = ENCRYPTED_DNS_MODE_AUTO;

    if (!InterlockedCompareExchange(&g_DohConfigLockValid, 0, 0))
        return FALSE;

    // Calculate maximum attempts
    max_attempts = 0;
    for (ULONG i = 0; i < g_DohConfigLineCount; i++) {
        max_attempts += g_DohConfigLines[i].ServerCount;
    }

    if (max_attempts == 0)
        return FALSE;

    // Try servers with failover
    while (attempts < max_attempts) {
        server = EncDns_SelectServer(now);
        if (!server)
            break;

        // Prevent infinite loop
        if (first_server == NULL) {
            first_server = server;
        } else if (server == first_server && attempts > 0) {
            // We've cycled back to the first server - all servers failed
            break;
        }

        // Note: In AUTO mode, individual protocols log their actual ports
        if (DNS_DebugFlag && server->ProtocolMode != ENCRYPTED_DNS_MODE_AUTO) {
            WCHAR msg[512];
            const WCHAR* modeName = EncryptedDns_GetModeName(server->ProtocolMode);
            Sbie_snwprintf(msg, 512, L"[EncDns] Trying server %s:%d (mode: %s)", server->Host, server->Port, modeName);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }

        ENCRYPTED_DNS_MODE used = ENCRYPTED_DNS_MODE_AUTO;
        if (EncDns_RequestToServer(server, domain, qtype, response, response_size, bytes_read, &used)) {
            if (protocol_used_out)
                *protocol_used_out = used;
            // Clear failure state on success
            if (server->FailedUntil > 0) {
                EnterCriticalSection(&g_DohConfigLock);
                server->FailedUntil = 0;
                LeaveCriticalSection(&g_DohConfigLock);
            }
            // Round-robin advancement already happened in EncDns_SelectServer
            return TRUE;
        }

        // Mark server as failed (EncryptedDns_HandleQueryError already called in lower layer)
        DoH_MarkServerFailed(server, now);
        attempts++;
    }

    // All servers failed
    EncryptedDns_HandleQueryError(DOH_ERROR_ALL_SERVERS_FAILED, NULL, domain, now);

    return FALSE;
}

//---------------------------------------------------------------------------
// EncDns_ParseDnsResponse
//
// Parses DNS wire format response (RFC 1035).
// Extracts IP addresses from answer section, handles name compression.
//
// Parameters:
//   response   - Binary DNS response packet
//   responseLen- Length of response
//   pResult    - [OUT] Parsed result with IP addresses and TTL
//
// Returns: TRUE on successful parse, FALSE on error
//---------------------------------------------------------------------------

static BOOLEAN EncDns_ParseDnsResponse(const BYTE* response, int responseLen, DOH_RESULT* pResult)
{
    DOH_DNS_HEADER* header;
    int offset;
    USHORT answerCount;
    USHORT questionCount;
    USHORT flags;
    USHORT qr;
    USHORT rcode;
    int i;
    WCHAR tempName[256];
    USHORT rtype, rclass, rdlength;
    ULONG ttl;
    int nameLen;
    BYTE* ip;
    USHORT* ip6;
    BOOLEAN hasCname = FALSE;  // Track if we saw any CNAME records

    if (!response || responseLen < sizeof(DOH_DNS_HEADER) || !pResult)
        return FALSE;

    ENCRYPTED_DNS_MODE savedProtocolUsed = pResult->ProtocolUsed;
    memset(pResult, 0, sizeof(DOH_RESULT));
    pResult->ProtocolUsed = savedProtocolUsed;
    pResult->TTL = DOH_DEFAULT_TTL;

    // Store raw DNS response for non-A/AAAA queries (TXT, MX, SRV, etc.)
    // This allows callers to parse any DNS record type from the wire format
    if (responseLen > 0 && responseLen <= ENCRYPTED_DNS_MAX_RAW_RESPONSE) {
        memcpy(pResult->RawResponse, response, responseLen);
        pResult->RawResponseLen = (DWORD)responseLen;
    }

    header = (DOH_DNS_HEADER*)response;

    // Check if this is a response (QR bit = 1)
    flags = _ntohs(header->Flags);
    qr = (flags >> 15) & 0x1;
    if (qr != 1)
        return FALSE;

    // Extract response code (RCODE - last 4 bits of flags)
    rcode = flags & 0x000F;
    pResult->Status = (DNS_STATUS)rcode;

    // If DNS error, return success but with no answers
    if (rcode != 0) {
        pResult->Success = TRUE;
        pResult->AnswerCount = 0;
        
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[EncDns] DNS response code: %d", rcode);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        
        return TRUE;
    }

    questionCount = _ntohs(header->Questions);
    answerCount = _ntohs(header->AnswerRRs);

    if (answerCount == 0) {
        pResult->Success = TRUE;
        pResult->AnswerCount = 0;
        return TRUE;
    }

    // Skip question section
    offset = sizeof(DOH_DNS_HEADER);
    for (i = 0; i < questionCount; i++) {
        nameLen = DoH_DecodeDnsName(response, responseLen, offset, tempName, 256);
        if (nameLen <= 0)
            return FALSE;
        
        offset += nameLen;
        
        // Skip QTYPE (2) + QCLASS (2)
        if (offset + 4 > responseLen)
            return FALSE;
        offset += 4;
    }

    // Parse answer section
    BOOLEAN hasSoa = FALSE;
    for (i = 0; i < answerCount && pResult->AnswerCount < 32; i++) {
        // Parse name (may use compression)
        nameLen = DoH_DecodeDnsName(response, responseLen, offset, tempName, 256);
        if (nameLen <= 0)
            return FALSE;
        
        offset += nameLen;

        // Check space for TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2)
        if (offset + 10 > responseLen)
            return FALSE;

        rtype = _ntohs(*(USHORT*)(response + offset));
        offset += 2;

        rclass = _ntohs(*(USHORT*)(response + offset));
        offset += 2;

        ttl = _ntohl(*(ULONG*)(response + offset));
        offset += 4;

        rdlength = _ntohs(*(USHORT*)(response + offset));
        offset += 2;

        // Check space for RDATA
        if (offset + rdlength > responseLen) {
            return FALSE;
        }

        // Store minimum TTL
        if (i == 0 || ttl < pResult->TTL) {
            pResult->TTL = ttl;
        }

        // Parse RDATA based on type
        if (rtype == DOH_DNS_TYPE_A && rclass == 1 && rdlength == 4) {
            // IPv4 address - store in Data32[3] (last 4 bytes) per codebase convention
            pResult->Answers[pResult->AnswerCount].Type = AF_INET;
            memset(&pResult->Answers[pResult->AnswerCount].IP, 0, sizeof(IP_ADDRESS));
            pResult->Answers[pResult->AnswerCount].IP.Data32[3] = *(DWORD*)(response + offset);
            pResult->AnswerCount++;
            
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                ip = (BYTE*)(response + offset);
                Sbie_snwprintf(msg, 256, L"[EncDns] Parsed A record: %d.%d.%d.%d (TTL: %d)",
                    ip[0], ip[1], ip[2], ip[3], ttl);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
        }
        else if (rtype == DOH_DNS_TYPE_AAAA && rclass == 1 && rdlength == 16) {
            // IPv6 address
            pResult->Answers[pResult->AnswerCount].Type = AF_INET6;
            memcpy(pResult->Answers[pResult->AnswerCount].IP.Data, response + offset, 16);
            pResult->AnswerCount++;
            
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                ip6 = (USHORT*)(response + offset);
                Sbie_snwprintf(msg, 256, L"[EncDns] Parsed AAAA record: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x (TTL: %d)",
                    _ntohs(ip6[0]), _ntohs(ip6[1]), _ntohs(ip6[2]), _ntohs(ip6[3]),
                    _ntohs(ip6[4]), _ntohs(ip6[5]), _ntohs(ip6[6]), _ntohs(ip6[7]), ttl);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
        }
        else if (rtype == 5 && rclass == 1) {
            // CNAME record - store for DNS response building
            hasCname = TRUE;
            
            // Decode the CNAME target
            WCHAR cnameTarget[256];
            int cnameLen = DoH_DecodeDnsName(response, responseLen, offset, cnameTarget, 256);
            if (cnameLen > 0 && pResult->CnameTarget[0] == L'\0') {
                // Store CNAME info (owner name and target)
                wcsncpy(pResult->CnameOwner, tempName, 255);
                pResult->CnameOwner[255] = L'\0';
                wcsncpy(pResult->CnameTarget, cnameTarget, 255);
                pResult->CnameTarget[255] = L'\0';
                pResult->HasCname = TRUE;
            }
            
            if (DNS_DebugFlag) {
                if (cnameLen > 0) {
                    WCHAR msg[512];
                    Sbie_snwprintf(msg, 512, L"[EncDns] Found CNAME: %s -> %s (TTL: %d)",
                        tempName, cnameTarget, ttl);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
            }
        }
        else if (rtype == 6 && rclass == 1) {
            // SOA record - indicates authoritative "no records of this type"
            // Don't follow CNAME if we see SOA (NODATA response per RFC 2308)
            hasSoa = TRUE;
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"[EncDns] Found SOA record (NODATA) - TTL: %d", ttl);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            // Clear CNAME target if present - SOA means CNAME target has no records
            pResult->CnameTarget[0] = L'\0';
        }

        // Skip RDATA
        offset += rdlength;
    }

    // If we only got CNAME records (no A/AAAA, no SOA), mark it for CNAME following
    if (pResult->AnswerCount == 0 && hasCname && !hasSoa && pResult->CnameTarget[0] != L'\0') {
        pResult->IsCnameOnly = TRUE;
        pResult->Success = TRUE;  // Still a valid response, just needs CNAME following
        
        if (DNS_DebugFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"[EncDns] CNAME-only response, target: %s", pResult->CnameTarget);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        
        return TRUE;
    }

    pResult->Success = TRUE;

    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[EncDns] Parsed %d answers from DNS response", pResult->AnswerCount);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    return TRUE;
}

//---------------------------------------------------------------------------
// DoH_ParseJsonResponse (DEPRECATED - kept for compatibility)
//
// Parses JSON response from RFC 8484 DoH server using simple string parsing.
// JSON format (application/dns-json): {"Status": N, "Answer": [{...}, {...}]}
//
// Extracts:
//   - "Status" field: DNS response code (0=NOERROR, 3=NXDOMAIN, etc.)
//   - "Answer" array: DNS records with "data" field containing IP addresses
//     * IPv4: Parsed via inet_pton to SOCKADDR_IN IP format
//     * IPv6: Parsed via inet_pton to SOCKADDR_IN6 IP format
//     * Max 32 answers per response
//
// Returns: TRUE on successful parse (valid JSON structure)
//          FALSE on parse error (malformed JSON)
// Note: Status != 0 indicates error response (DNS failure); Success=TRUE with AnswerCount=0
//---------------------------------------------------------------------------

static BOOLEAN DoH_ParseJsonResponse(const WCHAR* json, DOH_RESULT* pResult)
{
    const WCHAR* p;
    WCHAR ip_str[64];

    if (!json || !pResult)
        return FALSE;

    ENCRYPTED_DNS_MODE savedProtocolUsed = pResult->ProtocolUsed;
    memset(pResult, 0, sizeof(DOH_RESULT));
    pResult->ProtocolUsed = savedProtocolUsed;
    pResult->TTL = DOH_DEFAULT_TTL;

    p = wcsstr(json, L"\"Status\"");
    if (p) {
        p = wcschr(p, L':');
        if (p) {
            p++;
            while (*p == L' ') p++;
            pResult->Status = (DNS_STATUS)wcstoul(p, NULL, 10);
        }
    }

    if (pResult->Status != 0) {
        pResult->Success = TRUE;
        return TRUE;
    }

    p = wcsstr(json, L"\"Answer\"");
    if (!p) {
        pResult->Success = TRUE;
        pResult->AnswerCount = 0;
        return TRUE;
    }

    p = wcschr(p, L'[');
    if (!p)
        return FALSE;
    p++;

    while (*p && *p != L']' && pResult->AnswerCount < 32) {
        const WCHAR* data_field = wcsstr(p, L"\"data\"");
        const WCHAR* next_obj = wcschr(p, L'}');
        
        if (!data_field || (next_obj && data_field > next_obj)) {
            p = next_obj ? next_obj + 1 : NULL;
            if (!p) break;
            continue;
        }

        const WCHAR* value_start = wcschr(data_field, L':');
        if (!value_start) break;
        value_start++;
        while (*value_start == L' ') value_start++;
        if (*value_start != L'"') {
            p = next_obj ? next_obj + 1 : NULL;
            if (!p) break;
            continue;
        }
        value_start++;

        const WCHAR* value_end = wcschr(value_start, L'"');
        if (!value_end || (value_end - value_start) >= 64) break;

        wcsncpy(ip_str, value_start, value_end - value_start);
        ip_str[value_end - value_start] = L'\0';

        USHORT* pType = &pResult->Answers[pResult->AnswerCount].Type;
        IP_ADDRESS* pIP = &pResult->Answers[pResult->AnswerCount].IP;
        
        if (wcschr(ip_str, L':')) {
            if (_inet_pton(AF_INET6, ip_str, pIP->Data) == 1) {
                *pType = AF_INET6;
                pResult->AnswerCount++;
            }
        } else if (wcschr(ip_str, L'.')) {
            BYTE temp[4];
            if (_inet_pton(AF_INET, ip_str, temp) == 1) {
                memcpy(&pIP->Data32[3], temp, 4);
                *pType = AF_INET;
                pResult->AnswerCount++;
                
                if (DNS_DebugFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"[DoH] Parsed IPv4: %s", ip_str);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
            }
        }

        p = value_end ? wcschr(value_end, L'}') : NULL;
        if (!p) break;
        p++;
    }

    pResult->Success = TRUE;
    return TRUE;
}

//---------------------------------------------------------------------------
// DoH_Query - Perform encrypted DNS query (DoH/DoH2/DoH3/DoQ)
//
// Input:
//   - domain: Domain name to resolve (e.g., "google.com")
//   - qtype: DNS query type (DNS_TYPE_A, DNS_TYPE_AAAA)
//   - pResult: Output structure to receive response
//
// Process:
//   1. Check if encrypted DNS is enabled (EncryptedDnsServer configured)
//   2. Check for re-entrancy (TLS flag + global counter)
//   3. Try cache lookup (avoid network round-trip for recent queries)
//   4. Check for pending query (same domain - coalesce with existing request)
//   5. Acquire semaphore (limit concurrent queries to prevent server hammering)
//   6. Select server using round-robin with failure detection
//   7. Make HTTPS request with proper URL parameters
//   8. Parse response and extract IP addresses
//   9. Cache successful response (300s TTL)
//  10. Signal pending waiters, release semaphore
//  11. Return synthetic NOERROR+NODATA on any error (graceful fallback)
//
// Return: TRUE if query completed (success or graceful error)
//         FALSE if critical error (should not happen in normal operation)
//
// Note: Always returns pResult->Success=TRUE for graceful failure semantics
//---------------------------------------------------------------------------

_FX BOOLEAN DoH_Query(const WCHAR* domain, USHORT qtype, DOH_RESULT* pResult)
{
    BYTE response[8192];
    DWORD bytes_read = 0;
    DOH_PENDING_QUERY* pending = NULL;
    BOOLEAN isQuerier = FALSE;  // TRUE if we're the thread making the HTTP request
    DWORD waitResult;

    if (!domain || !pResult)
        return FALSE;

    memset(pResult, 0, sizeof(DOH_RESULT));
    pResult->ProtocolUsed = ENCRYPTED_DNS_MODE_AUTO;

    if (!DoH_IsEnabled())
        return FALSE;

    if (!EncDns_LoadBackends()) {
        pResult->Success = TRUE;
        pResult->Status = 0;
        pResult->AnswerCount = 0;
        pResult->TTL = ENCRYPTED_DNS_FAILED_TTL;
        EncDns_CacheStore(domain, qtype, pResult, TRUE, FALSE);
        return TRUE;
    }

    if (InterlockedCompareExchange(&g_DohLockValid, 0, 0)) {
        EnterCriticalSection(&g_DohLock);
        DOH_HTTP_BACKEND backend = g_DohBackend;
        LeaveCriticalSection(&g_DohLock);
        
        if (backend == DOH_BACKEND_FAILED) {
            pResult->Success = TRUE;
            pResult->Status = 0;
            pResult->AnswerCount = 0;
            pResult->TTL = ENCRYPTED_DNS_FAILED_TTL;
            EncDns_CacheStore(domain, qtype, pResult, TRUE, FALSE);
            return TRUE;
        }
    }

    // Check same-thread re-entrancy first (prevents infinite loops on same thread)
    if (EncDns_GetInQuery()) {
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[EncDns] Re-entrancy detected (TLS)");
        }
        return FALSE;
    }

    // BindAdapter/BindAdapterIP recovery handling:
    // - on down->up transition: clear cached failures and reset server fail/backoff state
    // This must run before cache lookup so cached failures don't block recovery.
    EncDns_CheckBindAdapterRecovery();

    // Check cache BEFORE doing any pending query logic
    if (EncDns_CacheLookup(domain, qtype, pResult))
        return TRUE;

    // While BindAdapter/BindAdapterIP is down, avoid attempting EncDns connections
    // and short-cache the failure to prevent query storms.
    if (WSA_IsBindIPEnabled() && !WSA_IsBindIPValid()) {
        pResult->Success = TRUE;
        pResult->Status = 0;
        pResult->AnswerCount = 0;
        pResult->TTL = ENCRYPTED_DNS_BIND_DOWN_TTL;
        EncDns_CacheStore(domain, qtype, pResult, TRUE, TRUE);
        return TRUE;
    }

    //
    // Pending Query Coalescing:
    // Check if another thread is already querying this domain+type.
    // If so, wait for it instead of making a duplicate HTTP request.
    //
    pending = EncDns_FindPendingQuery(domain, qtype);
    if (pending) {
        // Another thread is already querying this domain - wait for it
        if (DNS_DebugFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"[EncDns] Waiting for pending query: %s (type %d)", domain, qtype);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }

        // Wait for the query to complete (with timeout)
        waitResult = WaitForSingleObject(pending->Event, DOH_HTTP_TIMEOUT_MS);
        
        // Decrement waiter count (may trigger cleanup)
        EncDns_ReleaseWaiter(pending);

        if (waitResult == WAIT_OBJECT_0) {
            // Query completed - read from cache
            if (EncDns_CacheLookup(domain, qtype, pResult)) {
                return TRUE;
            }
        }

        // Timeout or cache miss - fall through to graceful failure
        pResult->Success = TRUE;
        pResult->Status = 0;
        pResult->AnswerCount = 0;
        pResult->TTL = ENCRYPTED_DNS_FAILED_TTL;
        EncDns_CacheStore(domain, qtype, pResult, TRUE, FALSE);
        return TRUE;
    }

    //
    // No pending query found - we'll be the querier.
    // Create pending entry so other threads can wait on us.
    //
    pending = EncDns_CreatePendingQuery(domain, qtype);
    isQuerier = TRUE;

    //
    // Semaphore: Limit concurrent DoH requests to prevent server hammering.
    // Wait for semaphore slot before making HTTP request.
    //
    if (g_DohQuerySemaphore) {
        waitResult = WaitForSingleObject(g_DohQuerySemaphore, DOH_SEMAPHORE_TIMEOUT_MS);
        if (waitResult != WAIT_OBJECT_0) {
            // Timeout waiting for semaphore - too many concurrent queries
            // This indicates DoH server is slow or there are >2 concurrent queries
            if (DNS_TraceFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"[EncDns] Semaphore timeout for %s - encrypted DNS backend overloaded or slow (falling back to empty response)", domain);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            pResult->Success = TRUE;
            pResult->Status = 0;
            pResult->AnswerCount = 0;
            pResult->TTL = ENCRYPTED_DNS_FAILED_TTL;
            EncDns_CacheStore(domain, qtype, pResult, TRUE, FALSE);
            if (pending) {
                EncDns_CompletePendingQuery(pending);
                EncDns_ReleaseWaiter(pending);
            }
            return TRUE;
        }
    }

    // Check global counter for cross-thread re-entrancy (WinHTTP uses internal threads)
    if (InterlockedCompareExchange(&g_DohActiveQueries, 0, 0) > 0) {
        if (DNS_DebugFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"[EncDns] Re-entrancy detected (global), waiting for active query: %s", domain);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        
        // Wait up to 500ms for active query to complete (50ms x 10 attempts)
        for (int i = 0; i < 10; i++) {
            Sleep(50);
            
            // Check cache again - another thread may have completed the query
            if (EncDns_CacheLookup(domain, qtype, pResult)) {
                if (g_DohQuerySemaphore) ReleaseSemaphore(g_DohQuerySemaphore, 1, NULL);
                if (pending) {
                    EncDns_CompletePendingQuery(pending);
                    EncDns_ReleaseWaiter(pending);
                }
                return TRUE;
            }
            
            // Check if query finished
            if (InterlockedCompareExchange(&g_DohActiveQueries, 0, 0) == 0)
                break;
        }
        
        // Check cache one final time after waiting
        if (EncDns_CacheLookup(domain, qtype, pResult)) {
            if (g_DohQuerySemaphore) ReleaseSemaphore(g_DohQuerySemaphore, 1, NULL);
            if (pending) {
                EncDns_CompletePendingQuery(pending);
                EncDns_ReleaseWaiter(pending);
            }
            return TRUE;
        }
    }

    EncDns_SetInQuery(TRUE);
    InterlockedIncrement(&g_DohActiveQueries);

    if (DNS_TraceFlag) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"[EncDns] Query: %s (Type: %s)", domain, DNS_GetTypeName(qtype));
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    ENCRYPTED_DNS_MODE protocolUsed = ENCRYPTED_DNS_MODE_AUTO;
    if (!EncDns_Request(domain, qtype, response, sizeof(response), &bytes_read, &protocolUsed)) {
        InterlockedDecrement(&g_DohActiveQueries);
        EncDns_SetInQuery(FALSE);
        if (g_DohQuerySemaphore) ReleaseSemaphore(g_DohQuerySemaphore, 1, NULL);
        pResult->Success = TRUE;
        pResult->Status = 0;
        pResult->AnswerCount = 0;
        pResult->TTL = ENCRYPTED_DNS_FAILED_TTL;
        EncDns_CacheStore(domain, qtype, pResult, TRUE, FALSE);
        if (pending) {
            EncDns_CompletePendingQuery(pending);
            EncDns_ReleaseWaiter(pending);
        }
        return TRUE;
    }

    pResult->ProtocolUsed = protocolUsed;

    // Parse binary DNS wire format response
    if (!EncDns_ParseDnsResponse(response, (int)bytes_read, pResult)) {
        InterlockedDecrement(&g_DohActiveQueries);
        EncDns_SetInQuery(FALSE);
        if (g_DohQuerySemaphore) ReleaseSemaphore(g_DohQuerySemaphore, 1, NULL);
        pResult->Success = TRUE;
        pResult->Status = 0;
        pResult->AnswerCount = 0;
        pResult->TTL = ENCRYPTED_DNS_FAILED_TTL;
        EncDns_CacheStore(domain, qtype, pResult, TRUE, FALSE);
        if (pending) {
            EncDns_CompletePendingQuery(pending);
            EncDns_ReleaseWaiter(pending);
        }
        return TRUE;
    }

    InterlockedDecrement(&g_DohActiveQueries);
    EncDns_SetInQuery(FALSE);

    // Cache the result so waiters can read it
    EncDns_CacheStore(domain, qtype, pResult, FALSE, FALSE);

    // Release semaphore and signal pending waiters
    if (g_DohQuerySemaphore) ReleaseSemaphore(g_DohQuerySemaphore, 1, NULL);
    if (pending) {
        EncDns_CompletePendingQuery(pending);
        EncDns_ReleaseWaiter(pending);
    }

    return TRUE;
}
