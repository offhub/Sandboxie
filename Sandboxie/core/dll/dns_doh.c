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
// RFC 8484 compliant DoH client using WinHTTP/WinINet for secure DNS resolution.
// Uses DNS wire format (application/dns-message) per RFC 8484 Section 6.
//
// Wire Format vs JSON:
//   - Wire format (application/dns-message): MANDATORY per RFC 8484, all servers support it
//   - JSON format (application/dns-json): OPTIONAL, deprecated by many providers (Quad9 dropped it)
//   - Wire format is more compact, faster, and universally compatible
//
// Design Goals:
//   - Minimal dependencies (WinHTTP preferred, WinINet fallback)
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
// Backend Priority:
//   1. If WinHTTP.dll already loaded - use WinHTTP
//   2. If WinINet.dll already loaded - use WinINet  
//   3. Try to load WinHTTP.dll - use if successful
//   4. Try to load WinINet.dll - use if successful
//   5. Both failed - mark as DOH_BACKEND_FAILED (skip retries, graceful failure)
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
//   - Multi-server support: Up to 8 config lines × 16 servers per line
//   - Round-robin load balancing across config lines AND servers within lines
//   - Failed server cooldown: 30 seconds (automatic failover)
//   - Per-process support: SecureDnsServer=[process,]url format
//     * Process-specific configs have HIGHER priority than global configs
//     * Only the highest priority level is used (process-specific overrides global)
//     * Example: nslookup.exe will ONLY use its specific servers, not global ones
//   - Custom ports: https://host[:port][/path] (port defaults to 443, path to /dns-query)
//   - IPv6 support: Use bracket notation https://[2606:4700:4700::1111]/dns-query
//   - Certificate validation:
//     * https://  - Validate server certificate (standard, default)
//     * httpx:// - Bypass certificate validation for self-signed certs
//
// Supported Providers:
//   - Cloudflare: https://1.1.1.1/dns-query, https://cloudflare-dns.com/dns-query
//   - Google: https://8.8.8.8/dns-query, https://dns.google/resolve
//   - Quad9: https://9.9.9.9/dns-query, https://dns.quad9.net/dns-query
//   - Any RFC 8484 compliant server (signed or self-signed cert via httpx://)
//---------------------------------------------------------------------------

#define NOGDI
#include "dll.h"
#include "dns_doh.h"
#include "dns_filter.h"
#include "dns_logging.h"

#include <windows.h>
#include <winhttp.h>
#include <wininet.h>
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
    DOH_BACKEND_WINHTTP,        // WinHTTP (preferred)
    DOH_BACKEND_WININET,        // WinINet (fallback)
    DOH_BACKEND_FAILED          // Both backends failed, don't retry
} DOH_HTTP_BACKEND;

//---------------------------------------------------------------------------
// WinHTTP Function Pointers
//---------------------------------------------------------------------------

typedef HINTERNET (WINAPI *P_WinHttpOpen)(
    LPCWSTR pszAgentW,
    DWORD dwAccessType,
    LPCWSTR pszProxyW,
    LPCWSTR pszProxyBypassW,
    DWORD dwFlags
);

typedef HINTERNET (WINAPI *P_WinHttpConnect)(
    HINTERNET hSession,
    LPCWSTR pswzServerName,
    INTERNET_PORT nServerPort,
    DWORD dwReserved
);

typedef HINTERNET (WINAPI *P_WinHttpOpenRequest)(
    HINTERNET hConnect,
    LPCWSTR pwszVerb,
    LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion,
    LPCWSTR pwszReferrer,
    LPCWSTR *ppwszAcceptTypes,
    DWORD dwFlags
);

typedef BOOL (WINAPI *P_WinHttpSendRequest)(
    HINTERNET hRequest,
    LPCWSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength,
    DWORD dwTotalLength,
    DWORD_PTR dwContext
);

typedef BOOL (WINAPI *P_WinHttpReceiveResponse)(
    HINTERNET hRequest,
    LPVOID lpReserved
);

typedef BOOL (WINAPI *P_WinHttpQueryHeaders)(
    HINTERNET hRequest,
    DWORD dwInfoLevel,
    LPCWSTR pwszName,
    LPVOID lpBuffer,
    LPDWORD lpdwBufferLength,
    LPDWORD lpdwIndex
);

typedef BOOL (WINAPI *P_WinHttpReadData)(
    HINTERNET hRequest,
    LPVOID lpBuffer,
    DWORD dwNumberOfBytesToRead,
    LPDWORD lpdwNumberOfBytesRead
);

typedef BOOL (WINAPI *P_WinHttpCloseHandle)(
    HINTERNET hInternet
);

typedef BOOL (WINAPI *P_WinHttpSetOption)(
    HINTERNET hInternet,
    DWORD dwOption,
    LPVOID lpBuffer,
    DWORD dwBufferLength
);

typedef BOOL (WINAPI *P_WinHttpSetTimeouts)(
    HINTERNET hInternet,
    int nResolveTimeout,
    int nConnectTimeout,
    int nSendTimeout,
    int nReceiveTimeout
);

//---------------------------------------------------------------------------
// WinINet Function Pointers
//---------------------------------------------------------------------------

typedef HINTERNET (WINAPI *P_InternetOpenW)(
    LPCWSTR lpszAgent,
    DWORD dwAccessType,
    LPCWSTR lpszProxy,
    LPCWSTR lpszProxyBypass,
    DWORD dwFlags
);

typedef HINTERNET (WINAPI *P_InternetOpenUrlW)(
    HINTERNET hInternet,
    LPCWSTR lpszUrl,
    LPCWSTR lpszHeaders,
    DWORD dwHeadersLength,
    DWORD dwFlags,
    DWORD_PTR dwContext
);

typedef HINTERNET (WINAPI *P_InternetConnectW)(
    HINTERNET hInternet,
    LPCWSTR lpszServerName,
    INTERNET_PORT nServerPort,
    LPCWSTR lpszUserName,
    LPCWSTR lpszPassword,
    DWORD dwService,
    DWORD dwFlags,
    DWORD_PTR dwContext
);

typedef HINTERNET (WINAPI *P_HttpOpenRequestW)(
    HINTERNET hConnect,
    LPCWSTR lpszVerb,
    LPCWSTR lpszObjectName,
    LPCWSTR lpszVersion,
    LPCWSTR lpszReferrer,
    LPCWSTR *lplpszAcceptTypes,
    DWORD dwFlags,
    DWORD_PTR dwContext
);

typedef BOOL (WINAPI *P_HttpSendRequestW)(
    HINTERNET hRequest,
    LPCWSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength
);

typedef BOOL (WINAPI *P_InternetReadFile)(
    HINTERNET hFile,
    LPVOID lpBuffer,
    DWORD dwNumberOfBytesToRead,
    LPDWORD lpdwNumberOfBytesRead
);

typedef BOOL (WINAPI *P_InternetCloseHandle)(
    HINTERNET hInternet
);

typedef BOOL (WINAPI *P_HttpQueryInfoW)(
    HINTERNET hRequest,
    DWORD dwInfoLevel,
    LPVOID lpBuffer,
    LPDWORD lpdwBufferLength,
    LPDWORD lpdwIndex
);

typedef BOOL (WINAPI *P_InternetSetOptionW)(
    HINTERNET hInternet,
    DWORD dwOption,
    LPVOID lpBuffer,
    DWORD dwBufferLength
);

//---------------------------------------------------------------------------
// Constants
//---------------------------------------------------------------------------

#ifndef INTERNET_OPEN_TYPE_PRECONFIG
#define INTERNET_OPEN_TYPE_PRECONFIG 0
#endif

#ifndef INTERNET_FLAG_SECURE
#define INTERNET_FLAG_SECURE 0x00800000
#endif

#ifndef INTERNET_FLAG_NO_CACHE_WRITE
#define INTERNET_FLAG_NO_CACHE_WRITE 0x04000000
#endif

#ifndef INTERNET_FLAG_RELOAD
#define INTERNET_FLAG_RELOAD 0x80000000
#endif

#ifndef INTERNET_SERVICE_HTTP
#define INTERNET_SERVICE_HTTP 3
#endif

#ifndef HTTP_QUERY_STATUS_CODE
#define HTTP_QUERY_STATUS_CODE 19
#endif

#ifndef HTTP_QUERY_FLAG_NUMBER
#define HTTP_QUERY_FLAG_NUMBER 0x20000000
#endif

#ifndef WINHTTP_ACCESS_TYPE_DEFAULT_PROXY
#define WINHTTP_ACCESS_TYPE_DEFAULT_PROXY 0
#endif

#ifndef WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY 4
#endif

#ifndef WINHTTP_NO_PROXY_NAME
#define WINHTTP_NO_PROXY_NAME NULL
#endif

#ifndef WINHTTP_NO_PROXY_BYPASS
#define WINHTTP_NO_PROXY_BYPASS NULL
#endif

#ifndef WINHTTP_FLAG_SECURE
#define WINHTTP_FLAG_SECURE 0x00800000
#endif

#ifndef WINHTTP_QUERY_STATUS_CODE
#define WINHTTP_QUERY_STATUS_CODE 19
#endif

#ifndef WINHTTP_QUERY_FLAG_NUMBER
#define WINHTTP_QUERY_FLAG_NUMBER 0x20000000
#endif

#ifndef WINHTTP_OPTION_DECOMPRESSION
#define WINHTTP_OPTION_DECOMPRESSION 118
#endif

#ifndef WINHTTP_DECOMPRESSION_FLAG_GZIP
#define WINHTTP_DECOMPRESSION_FLAG_GZIP 0x00000001
#endif

#ifndef WINHTTP_DECOMPRESSION_FLAG_DEFLATE
#define WINHTTP_DECOMPRESSION_FLAG_DEFLATE 0x00000002
#endif

#ifndef INTERNET_DEFAULT_HTTPS_PORT
#define INTERNET_DEFAULT_HTTPS_PORT 443
#endif

#ifndef INTERNET_OPTION_SECURITY_FLAGS
#define INTERNET_OPTION_SECURITY_FLAGS 31
#endif

#ifndef WINHTTP_OPTION_SECURITY_FLAGS
#define WINHTTP_OPTION_SECURITY_FLAGS 31
#endif

#ifndef SECURITY_FLAG_IGNORE_UNKNOWN_CA
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA 0x00000100
#endif

#ifndef SECURITY_FLAG_IGNORE_CERT_CN_INVALID
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID 0x00001000
#endif

#ifndef SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID 0x00002000
#endif

#ifndef INTERNET_OPTION_CONNECT_TIMEOUT
#define INTERNET_OPTION_CONNECT_TIMEOUT 2
#endif

#ifndef INTERNET_OPTION_SEND_TIMEOUT
#define INTERNET_OPTION_SEND_TIMEOUT 5
#endif

#ifndef INTERNET_OPTION_RECEIVE_TIMEOUT
#define INTERNET_OPTION_RECEIVE_TIMEOUT 6
#endif

//---------------------------------------------------------------------------
// Multi-Server Support Structures
// Supports up to 8 config lines (SecureDnsServer settings), each with up to 16 servers
// Round-robin load balancing across both lines and servers within lines
// Failed servers enter 30-second cooldown before retry

#define DOH_MAX_SERVERS 16
#define DOH_MAX_CONFIG_LINES 8
#define DOH_SERVER_FAIL_COOLDOWN_MS 30000  // Skip failed server for 30 seconds

typedef struct _DOH_SERVER {
    WCHAR Url[512];             // Full URL for logging/debugging
    WCHAR Host[256];            // Hostname extracted from URL
    WCHAR Path[256];            // Request path (default: /dns-query)
    INTERNET_PORT Port;         // Port from URL (default: 443)
    ULONGLONG FailedUntil;      // GetTickCount64() tick when server can retry (0 = available)
    BOOLEAN SelfSigned;         // TRUE if httpx:// (self-signed cert), FALSE if https:// (signed cert)
} DOH_SERVER;

typedef struct _DOH_CONFIG_LINE {
    DOH_SERVER Servers[DOH_MAX_SERVERS];
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
// g_DohConfigLines: Array of config lines (from multiple SecureDnsServer settings)
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

// Connection pool for persistent HTTP connections (prevents connection spam)
// Cache connections per server to reuse them across multiple DNS queries
// Key: server:port (e.g., "cloudflare-dns.com:443")
// Value: HINTERNET connection handle
// NOTE: WinHTTP/WinINet connection handles are NOT thread-safe for concurrent requests.
//       The InUse flag prevents multiple threads from using the same handle simultaneously.
#define DOH_MAX_CONNECTIONS 16
typedef struct _DOH_CONNECTION_POOL {
    WCHAR ServerKey[512];       // "host:port" for lookup/deduplication
    HINTERNET hConnect;         // Cached connection handle
    ULONGLONG LastUsed;         // GetTickCount64() for LRU eviction
    BOOLEAN BackendWinHttp;     // TRUE if WinHTTP, FALSE if WinINet
    volatile LONG InUse;        // 1 if currently in use by a thread, 0 if available
} DOH_CONNECTION_POOL;

static DOH_CONNECTION_POOL g_DohConnPool[DOH_MAX_CONNECTIONS];
static ULONG g_DohConnPoolCount = 0;
static CRITICAL_SECTION g_DohConnPoolLock;
static volatile LONG g_DohConnPoolLockValid = 0;

// Backend state (protected by g_DohLock)
// Tracks which HTTP backend (WinHTTP/WinINet) is initialized
// Session handles for persistent HTTP connections
static CRITICAL_SECTION g_DohLock;
static volatile LONG g_DohLockValid = 0;
static DOH_HTTP_BACKEND g_DohBackend = DOH_BACKEND_NONE;
static HINTERNET g_hWinHttpSession = NULL;
static HINTERNET g_hWinINetSession = NULL;

// WinHTTP function pointers
static P_WinHttpOpen __sys_WinHttpOpen = NULL;
static P_WinHttpConnect __sys_WinHttpConnect = NULL;
static P_WinHttpOpenRequest __sys_WinHttpOpenRequest = NULL;
static P_WinHttpSendRequest __sys_WinHttpSendRequest = NULL;
static P_WinHttpReceiveResponse __sys_WinHttpReceiveResponse = NULL;
static P_WinHttpQueryHeaders __sys_WinHttpQueryHeaders = NULL;
static P_WinHttpReadData __sys_WinHttpReadData = NULL;
static P_WinHttpCloseHandle __sys_WinHttpCloseHandle = NULL;
static P_WinHttpSetOption __sys_WinHttpSetOption = NULL;
static P_WinHttpSetTimeouts __sys_WinHttpSetTimeouts = NULL;

// WinINet function pointers
static P_InternetOpenW __sys_InternetOpenW = NULL;
static P_InternetConnectW __sys_InternetConnectW = NULL;
static P_InternetOpenUrlW __sys_InternetOpenUrlW = NULL;
static P_HttpOpenRequestW __sys_HttpOpenRequestW = NULL;
static P_HttpSendRequestW __sys_HttpSendRequestW = NULL;
static P_InternetReadFile __sys_InternetReadFile = NULL;
static P_InternetCloseHandle __sys_InternetCloseHandle = NULL;
static P_HttpQueryInfoW __sys_HttpQueryInfoW = NULL;
static P_InternetSetOptionW __sys_InternetSetOptionW = NULL;

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
#define DOH_CACHE_SIZE 64
#define DOH_DEFAULT_TTL 300

typedef struct _DOH_CACHE_ENTRY {
    WCHAR domain[256];
    USHORT qtype;
    ULONGLONG expiry;           // Tick count when entry expires
    DOH_RESULT result;          // Cached DoH response (status, IPs, TTL)
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
//---------------------------------------------------------------------------

#define DOH_MAX_PENDING_QUERIES 32
#define DOH_MAX_CONCURRENT_QUERIES 2
#define DOH_QUERY_TIMEOUT_MS 5000  // 5 second timeout for HTTP requests

typedef struct _DOH_PENDING_QUERY {
    WCHAR Domain[256];          // Domain being queried
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

//---------------------------------------------------------------------------
// Re-entrancy Protection (per-thread via TLS)
//---------------------------------------------------------------------------

static BOOLEAN DoH_GetInDoHQuery(void)
{
    THREAD_DATA *data = Dll_GetTlsData(NULL);
    return data ? data->dns_in_doh_query : FALSE;
}

static void DoH_SetInDoHQuery(BOOLEAN value)
{
    THREAD_DATA *data = Dll_GetTlsData(NULL);
    if (data)
        data->dns_in_doh_query = value;
}

//---------------------------------------------------------------------------
// Forward Declarations
//---------------------------------------------------------------------------

static BOOLEAN DoH_ParseUrlToServer(const WCHAR* url, DOH_SERVER* server);
static BOOLEAN DoH_LoadBackends(void);
static BOOLEAN DoH_HttpRequest(const WCHAR* domain, USHORT qtype, BYTE* response, DWORD response_size, DWORD* bytes_read);
static BOOLEAN DoH_HttpRequestToServer(DOH_SERVER* server, const WCHAR* domain, USHORT qtype, BYTE* response, DWORD response_size, DWORD* bytes_read);
static BOOLEAN DoH_HttpRequest_WinHttp(DOH_SERVER* server, const WCHAR* domain, USHORT qtype, BYTE* response, DWORD response_size, DWORD* bytes_read);
static BOOLEAN DoH_HttpRequest_WinINet(DOH_SERVER* server, const WCHAR* domain, USHORT qtype, BYTE* response, DWORD response_size, DWORD* bytes_read);
static BOOLEAN DoH_ParseDnsResponse(const BYTE* response, int responseLen, DOH_RESULT* pResult);
static BOOLEAN DoH_ParseJsonResponse(const WCHAR* json, DOH_RESULT* pResult);
static BOOLEAN DoH_CacheLookup(const WCHAR* domain, USHORT qtype, DOH_RESULT* pResult);
static void DoH_CacheStore(const WCHAR* domain, USHORT qtype, const DOH_RESULT* pResult);
static DOH_SERVER* DoH_SelectServer(ULONGLONG now);
static void DoH_MarkServerFailed(DOH_SERVER* server, ULONGLONG now);

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
            if (g_DohConnPool[i].hConnect) {
                if (g_DohConnPool[i].BackendWinHttp && __sys_WinHttpCloseHandle) {
                    __sys_WinHttpCloseHandle(g_DohConnPool[i].hConnect);
                } else if (!g_DohConnPool[i].BackendWinHttp && __sys_InternetCloseHandle) {
                    __sys_InternetCloseHandle(g_DohConnPool[i].hConnect);
                }
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
// Thread-safe: Holds pool lock during entire operation to prevent concurrent creation
static HINTERNET DoH_GetPooledConnection(const WCHAR* host, INTERNET_PORT port, BOOLEAN bWinHttp)
{
    if (!InterlockedCompareExchange(&g_DohConnPoolLockValid, 0, 0))
        return NULL;

    EnterCriticalSection(&g_DohConnPoolLock);

    // Build server key for lookup
    WCHAR serverKey[512];
    if (port == INTERNET_DEFAULT_HTTPS_PORT) {
        Sbie_snwprintf(serverKey, sizeof(serverKey) / sizeof(WCHAR), L"%s", host);
    } else {
        Sbie_snwprintf(serverKey, sizeof(serverKey) / sizeof(WCHAR), L"%s:%d", host, port);
    }
    _wcslwr(serverKey);  // Normalize to lowercase for comparison

    // Search for existing connection that is NOT currently in use
    // WinHTTP/WinINet connection handles are NOT thread-safe for concurrent requests
    for (ULONG i = 0; i < g_DohConnPoolCount; i++) {
        if (_wcsicmp(g_DohConnPool[i].ServerKey, serverKey) == 0 &&
            g_DohConnPool[i].BackendWinHttp == bWinHttp) {
            // Found matching connection - try to acquire it atomically
            if (InterlockedCompareExchange(&g_DohConnPool[i].InUse, 1, 0) == 0) {
                // Successfully acquired! Mark as in use, update LRU
                g_DohConnPool[i].LastUsed = GetTickCount64();
                HINTERNET hConn = g_DohConnPool[i].hConnect;
                LeaveCriticalSection(&g_DohConnPoolLock);
                
                if (DNS_DebugFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"[DoH] Reusing pooled connection to %s (pool: %d/%d)",
                        host, g_DohConnPoolCount, DOH_MAX_CONNECTIONS);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
                return hConn;
            }
            // Connection found but currently in use by another thread - skip it
        }
    }

    // No available connection - create new one while holding lock to prevent concurrent creation
    HINTERNET hConnect = NULL;
    BOOLEAN created = FALSE;
    
    if (bWinHttp) {
        if (!g_hWinHttpSession || !__sys_WinHttpConnect) {
            LeaveCriticalSection(&g_DohConnPoolLock);
            return NULL;
        }
        hConnect = __sys_WinHttpConnect(g_hWinHttpSession, host, port, 0);
        created = (hConnect != NULL);
    } else {
        if (!g_hWinINetSession || !__sys_InternetConnectW) {
            LeaveCriticalSection(&g_DohConnPoolLock);
            return NULL;
        }
        hConnect = __sys_InternetConnectW(g_hWinINetSession, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        created = (hConnect != NULL);
    }

    if (created) {
        if (g_DohConnPoolCount < DOH_MAX_CONNECTIONS) {
            DOH_CONNECTION_POOL* pool = &g_DohConnPool[g_DohConnPoolCount++];
            wcscpy(pool->ServerKey, serverKey);
            pool->hConnect = hConnect;
            pool->LastUsed = GetTickCount64();
            pool->BackendWinHttp = bWinHttp;
            pool->InUse = 1;  // Mark as in use immediately

            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"[DoH] Created and cached connection to %s (pool: %d/%d)",
                    host, g_DohConnPoolCount, DOH_MAX_CONNECTIONS);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
        } else {
            // Pool full - find LRU entry that is NOT in use
            ULONG lruIdx = 0;
            ULONGLONG oldestTime = ULLONG_MAX;
            BOOLEAN foundAvailable = FALSE;

            for (ULONG i = 0; i < DOH_MAX_CONNECTIONS; i++) {
                if (g_DohConnPool[i].InUse == 0 && g_DohConnPool[i].LastUsed < oldestTime) {
                    lruIdx = i;
                    oldestTime = g_DohConnPool[i].LastUsed;
                    foundAvailable = TRUE;
                }
            }

            if (foundAvailable) {
                // Close old connection
                if (g_DohConnPool[lruIdx].hConnect) {
                    if (g_DohConnPool[lruIdx].BackendWinHttp && __sys_WinHttpCloseHandle) {
                        __sys_WinHttpCloseHandle(g_DohConnPool[lruIdx].hConnect);
                    } else if (!g_DohConnPool[lruIdx].BackendWinHttp && __sys_InternetCloseHandle) {
                        __sys_InternetCloseHandle(g_DohConnPool[lruIdx].hConnect);
                    }
                }

                // Replace with new connection
                wcscpy(g_DohConnPool[lruIdx].ServerKey, serverKey);
                g_DohConnPool[lruIdx].hConnect = hConnect;
                g_DohConnPool[lruIdx].LastUsed = GetTickCount64();
                g_DohConnPool[lruIdx].BackendWinHttp = bWinHttp;
                g_DohConnPool[lruIdx].InUse = 1;  // Mark as in use

                if (DNS_DebugFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"[DoH] Evicted LRU connection, cached to %s (pool: %d/%d)",
                        host, g_DohConnPoolCount, DOH_MAX_CONNECTIONS);
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
                if (g_DohConnPool[i].BackendWinHttp && __sys_WinHttpCloseHandle) {
                    __sys_WinHttpCloseHandle(g_DohConnPool[i].hConnect);
                } else if (!g_DohConnPool[i].BackendWinHttp && __sys_InternetCloseHandle) {
                    __sys_InternetCloseHandle(g_DohConnPool[i].hConnect);
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
    
    if (shouldClose) {
        // Try to determine backend and close appropriately
        // Since we don't know the backend type, try both (one will fail safely)
        if (__sys_WinHttpCloseHandle) {
            __sys_WinHttpCloseHandle(hConnect);
        }
        if (__sys_InternetCloseHandle) {
            __sys_InternetCloseHandle(hConnect);
        }
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
static DOH_PENDING_QUERY* DoH_FindPendingQuery(const WCHAR* domain, USHORT qtype)
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
static DOH_PENDING_QUERY* DoH_CreatePendingQuery(const WCHAR* domain, USHORT qtype)
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
                Sbie_snwprintf(msg, 512, L"[DoH] Created pending query for %s (type %d)", domain, qtype);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }

            LeaveCriticalSection(&g_DohPendingLock);
            return &g_DohPendingQueries[i];
        }
    }

    if (DNS_DebugFlag) {
        SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Pending query table full");
    }

    LeaveCriticalSection(&g_DohPendingLock);
    return NULL;
}

// Complete pending query and signal all waiters
static void DoH_CompletePendingQuery(DOH_PENDING_QUERY* pending)
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
        Sbie_snwprintf(msg, 512, L"[DoH] Completed pending query for %s (waiters: %d)", 
            pending->Domain, pending->WaiterCount);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
}

// Remove pending query entry (called by last thread to leave)
static void DoH_RemovePendingQuery(DOH_PENDING_QUERY* pending)
{
    if (!pending || !InterlockedCompareExchange(&g_DohPendingLockValid, 0, 0))
        return;

    EnterCriticalSection(&g_DohPendingLock);

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
static void DoH_ReleaseWaiter(DOH_PENDING_QUERY* pending)
{
    if (!pending)
        return;

    LONG count = InterlockedDecrement(&pending->WaiterCount);
    
    // If we're the last waiter and query is completed, clean up
    // Note: The original querier doesn't decrement WaiterCount, so when it reaches -1
    // all waiters have left and we can clean up
    if (count < 0 && pending->Completed) {
        DoH_RemovePendingQuery(pending);
    }
}

//---------------------------------------------------------------------------
// DoH_ParseUrlToServer - Parse DoH server URL into server structure
//---------------------------------------------------------------------------

static BOOLEAN DoH_ParseUrlToServer(const WCHAR* url, DOH_SERVER* server)
{
    const WCHAR* p = url;
    const WCHAR* host_start;
    const WCHAR* path_start;
    SIZE_T host_len;
    BOOLEAN self_signed = FALSE;

    if (!url || !*url || !server)
        return FALSE;

    memset(server, 0, sizeof(DOH_SERVER));

    // Check for https:// (signed cert) or httpx:// (self-signed cert) prefix
    if (wcsncmp(p, L"https://", 8) == 0) {
        p += 8;
        self_signed = FALSE;
    } else if (wcsncmp(p, L"httpx://", 8) == 0) {
        p += 8;
        self_signed = TRUE;
    } else {
        if (DNS_TraceFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"[DoH] Invalid URL (must start with https:// or httpx://): %s", url);
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
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Invalid IPv6 URL (missing closing bracket)");
            }
            return FALSE;
        }
        host_len = p - host_start;
        p++;  // Skip closing bracket
    } else {
        // Regular hostname or IPv4: https://1.1.1.1:443/dns-query
        while (*p && *p != L':' && *p != L'/') {
            p++;
        }
        host_len = p - host_start;
    }
    
    if (host_len == 0 || host_len >= 256) {
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Invalid hostname length");
        }
        return FALSE;
    }
    wcsncpy(server->Host, host_start, host_len);
    server->Host[host_len] = L'\0';

    // Extract port (optional)
    if (*p == L':') {
        p++;
        server->Port = (INTERNET_PORT)wcstoul(p, (WCHAR**)&p, 10);
        if (server->Port == 0) {
            server->Port = INTERNET_DEFAULT_HTTPS_PORT;
        }
    } else {
        server->Port = INTERNET_DEFAULT_HTTPS_PORT;
    }

    // Extract path
    if (*p == L'/') {
        path_start = p;
    } else {
        path_start = L"/dns-query";
    }
    
    if (wcslen(path_start) >= 256) {
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Path too long");
        }
        return FALSE;
    }
    wcscpy(server->Path, path_start);

    // Store full URL
    if (wcslen(url) < 512) {
        wcscpy(server->Url, url);
    }

    if (DNS_DebugFlag) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"[DoH] Parsed URL - Host: %s, Port: %d, Path: %s, CertMode: %s",
            server->Host, server->Port, server->Path, self_signed ? L"self-signed" : L"signed");
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
    __sys_WinHttpReadData = (P_WinHttpReadData)GetProcAddress(hModule, "WinHttpReadData");
    __sys_WinHttpCloseHandle = (P_WinHttpCloseHandle)GetProcAddress(hModule, "WinHttpCloseHandle");
    __sys_WinHttpSetOption = (P_WinHttpSetOption)GetProcAddress(hModule, "WinHttpSetOption");
    __sys_WinHttpSetTimeouts = (P_WinHttpSetTimeouts)GetProcAddress(hModule, "WinHttpSetTimeouts");

    return __sys_WinHttpOpen && __sys_WinHttpConnect && __sys_WinHttpOpenRequest &&
           __sys_WinHttpSendRequest && __sys_WinHttpReceiveResponse && 
           __sys_WinHttpQueryHeaders && __sys_WinHttpReadData && __sys_WinHttpCloseHandle;
}

//---------------------------------------------------------------------------
// DoH_LoadWinINetFunctions - Load WinINet function pointers
//---------------------------------------------------------------------------

static BOOLEAN DoH_LoadWinINetFunctions(HMODULE hModule)
{
    if (!hModule)
        return FALSE;

    __sys_InternetOpenW = (P_InternetOpenW)GetProcAddress(hModule, "InternetOpenW");
    __sys_InternetConnectW = (P_InternetConnectW)GetProcAddress(hModule, "InternetConnectW");
    __sys_InternetOpenUrlW = (P_InternetOpenUrlW)GetProcAddress(hModule, "InternetOpenUrlW");
    __sys_HttpOpenRequestW = (P_HttpOpenRequestW)GetProcAddress(hModule, "HttpOpenRequestW");
    __sys_HttpSendRequestW = (P_HttpSendRequestW)GetProcAddress(hModule, "HttpSendRequestW");
    __sys_InternetReadFile = (P_InternetReadFile)GetProcAddress(hModule, "InternetReadFile");
    __sys_InternetCloseHandle = (P_InternetCloseHandle)GetProcAddress(hModule, "InternetCloseHandle");
    __sys_HttpQueryInfoW = (P_HttpQueryInfoW)GetProcAddress(hModule, "HttpQueryInfoW");
    __sys_InternetSetOptionW = (P_InternetSetOptionW)GetProcAddress(hModule, "InternetSetOptionW");

    return __sys_InternetOpenW && __sys_InternetConnectW && __sys_HttpOpenRequestW &&
           __sys_HttpSendRequestW && __sys_InternetReadFile && __sys_InternetCloseHandle && 
           __sys_HttpQueryInfoW;
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
// DoH_HasWinINetFunctions - Check if WinINet functions are loaded
//---------------------------------------------------------------------------

static BOOLEAN DoH_HasWinINetFunctions(void)
{
    return __sys_InternetOpenW && __sys_InternetConnectW && __sys_HttpOpenRequestW &&
           __sys_HttpSendRequestW && __sys_InternetReadFile && __sys_InternetCloseHandle && 
           __sys_HttpQueryInfoW;
}

//---------------------------------------------------------------------------
// DoH_LoadBackends - Load HTTP backends following priority order
//
// Priority:
//   1. Check if WinHTTP already loaded - use it
//   2. Check if WinINet already loaded - use it
//   3. Try to load WinHTTP - use if successful
//   4. Try to load WinINet - use if successful
//   5. Both failed - mark as failed
//
// Thread-safe: Uses interlocked operations and critical sections
//---------------------------------------------------------------------------

static BOOLEAN DoH_LoadBackends(void)
{
    HMODULE hModule;
    BOOLEAN hasWinHttp = FALSE;
    BOOLEAN hasWinINet = FALSE;

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

    // Priority 1: Check if WinHTTP already loaded
    hModule = GetModuleHandleW(L"winhttp.dll");
    if (hModule && DoH_LoadWinHttpFunctions(hModule)) {
        hasWinHttp = TRUE;
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] WinHTTP.dll already loaded");
        }
    }

    // Priority 2: Check if WinINet already loaded (only if WinHTTP not available)
    if (!hasWinHttp) {
        hModule = GetModuleHandleW(L"wininet.dll");
        if (hModule && DoH_LoadWinINetFunctions(hModule)) {
            hasWinINet = TRUE;
            if (DNS_TraceFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] WinINet.dll already loaded");
            }
        }
    }

    // Priority 3: Try to load WinHTTP
    if (!hasWinHttp && !hasWinINet) {
        hModule = LoadLibraryW(L"winhttp.dll");
        if (hModule && DoH_LoadWinHttpFunctions(hModule)) {
            hasWinHttp = TRUE;
            if (DNS_TraceFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Loaded WinHTTP.dll");
            }
        }
    }

    // Priority 4: Try to load WinINet
    if (!hasWinHttp && !hasWinINet) {
        hModule = LoadLibraryW(L"wininet.dll");
        if (hModule && DoH_LoadWinINetFunctions(hModule)) {
            hasWinINet = TRUE;
            if (DNS_TraceFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Loaded WinINet.dll");
            }
        }
    }

    // Set backend based on what's available
    if (hasWinHttp) {
        g_DohBackend = DOH_BACKEND_WINHTTP;
    } else if (hasWinINet) {
        g_DohBackend = DOH_BACKEND_WININET;
    } else {
        g_DohBackend = DOH_BACKEND_FAILED;
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] No HTTP backend available");
        }
    }

    LeaveCriticalSection(&g_DohLock);

    // Mark initialization complete
    InterlockedExchange(&g_DohInitComplete, 1);

    if (DNS_TraceFlag && (hasWinHttp || hasWinINet)) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DoH] Initialized with %s backend",
            hasWinHttp ? L"WinHTTP" : L"WinINet");
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    return hasWinHttp || hasWinINet;
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

    switch (g_DohBackend) {
    case DOH_BACKEND_WINHTTP:
        if (!g_hWinHttpSession && DoH_HasWinHttpFunctions()) {
            // Use automatic proxy on Windows 8+ (like WebUtils.cpp)
            accessType = (g_OsMajorVersion >= 8) ? 
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY : WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
            
            g_hWinHttpSession = __sys_WinHttpOpen(
                L"Sandboxie DoH Client/1.0",
                accessType,
                WINHTTP_NO_PROXY_NAME,
                WINHTTP_NO_PROXY_BYPASS,
                0
            );
            if (g_hWinHttpSession) {
                result = TRUE;
                
                // Enable decompression on Windows 8+ (like WebUtils.cpp)
                if (g_OsMajorVersion >= 8 && __sys_WinHttpSetOption) {
                    DWORD options = WINHTTP_DECOMPRESSION_FLAG_GZIP | WINHTTP_DECOMPRESSION_FLAG_DEFLATE;
                    __sys_WinHttpSetOption(g_hWinHttpSession, WINHTTP_OPTION_DECOMPRESSION, &options, sizeof(options));
                }
                
                if (DNS_TraceFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"[DoH] WinHTTP session created (proxy type: %s)", 
                        (g_OsMajorVersion >= 8) ? L"automatic" : L"default");
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
            } else {
                // WinHTTP failed, try WinINet fallback
                HMODULE hWinINet = GetModuleHandleW(L"wininet.dll");
                if (!hWinINet) hWinINet = LoadLibraryW(L"wininet.dll");
                if (hWinINet && DoH_LoadWinINetFunctions(hWinINet)) {
                    g_DohBackend = DOH_BACKEND_WININET;
                    if (DNS_TraceFlag) {
                        SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] WinHTTP failed, switching to WinINet");
                    }
                    LeaveCriticalSection(&g_DohLock);
                    return DoH_EnsureSession();
                } else {
                    g_DohBackend = DOH_BACKEND_FAILED;
                    SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] All backends failed");
                }
            }
        } else if (g_hWinHttpSession) {
            result = TRUE;
        }
        break;

    case DOH_BACKEND_WININET:
        if (!g_hWinINetSession && DoH_HasWinINetFunctions()) {
            g_hWinINetSession = __sys_InternetOpenW(
                L"Sandboxie DoH Client/1.0",
                INTERNET_OPEN_TYPE_PRECONFIG,
                NULL, NULL, 0
            );
            if (g_hWinINetSession) {
                result = TRUE;
                if (DNS_TraceFlag) {
                    SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] WinINet session created");
                }
            } else {
                g_DohBackend = DOH_BACKEND_FAILED;
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] WinINet session failed");
            }
        } else if (g_hWinINetSession) {
            result = TRUE;
        }
        break;

    default:
        break;
    }

    LeaveCriticalSection(&g_DohLock);
    return result;
}

//---------------------------------------------------------------------------
// DoH_Init
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
        if (g_hWinINetSession && __sys_InternetCloseHandle) {
            __sys_InternetCloseHandle(g_hWinINetSession);
            g_hWinINetSession = NULL;
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
//---------------------------------------------------------------------------

_FX BOOLEAN DoH_LoadConfig(void)
{
    WCHAR conf_buf[1024];
    ULONG config_lines_found = 0;
    ULONG highest_level = (ULONG)-1;  // Track highest priority config level
    OSVERSIONINFOW osvi;

    if (InterlockedCompareExchange(&g_DohConfigured, 0, 0) != 0)
        return TRUE;

    // Get OS version for WinHTTP settings
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);
    if (GetVersionExW(&osvi)) {
        g_OsMajorVersion = osvi.dwMajorVersion;
    }

    // Initialize config lock
    if (InterlockedCompareExchange(&g_DohConfigLockValid, 1, 0) == 0) {
        InitializeCriticalSection(&g_DohConfigLock);
        memset(g_DohConfigLines, 0, sizeof(g_DohConfigLines));
    }

    EnterCriticalSection(&g_DohConfigLock);

    // Iterate through all SecureDnsServer config lines
    for (ULONG index = 0; index < DOH_MAX_CONFIG_LINES; ++index) {
        NTSTATUS status = SbieApi_QueryConf(NULL, L"SecureDnsServer", index, conf_buf, sizeof(conf_buf) - 16 * sizeof(WCHAR));
        if (!NT_SUCCESS(status))
            break;

        // Check for per-process match
        ULONG level = (ULONG)-1;
        const WCHAR* value = Config_MatchImageAndGetValue(conf_buf, Dll_ImageName, &level);
        if (!value)
            continue;

        if (DNS_DebugFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"[DoH] Config line %d (level=%d): %s", config_lines_found, level, value);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }

        // Parse semicolon-separated servers in this config line
        DOH_CONFIG_LINE* config_line = &g_DohConfigLines[config_lines_found];
        config_line->ServerCount = 0;
        config_line->CurrentServer = 0;
        config_line->Level = level;  // Store config match level for priority filtering

        const WCHAR* server_start = value;
        while (*server_start && config_line->ServerCount < DOH_MAX_SERVERS) {
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

                if (url_len > 0 && DoH_ParseUrlToServer(url_buf, &config_line->Servers[config_line->ServerCount])) {
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
                Sbie_snwprintf(msg, 256, L"[DoH] Config line %d has %d server(s) at level %d", 
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
        Sbie_snwprintf(msg, 256, L"[DoH] Using %d config line(s) at priority level %d", 
            final_count, highest_level);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    LeaveCriticalSection(&g_DohConfigLock);

    if (config_lines_found > 0) {
        InterlockedExchange(&g_DohConfigured, 1);
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
// DoH_IsServerHostname - Check if hostname matches any configured DoH server
//
// Purpose: Re-entrancy prevention - if user queries a domain and we resolve
// the DoH server's hostname internally, it would cause infinite loop.
// Solution: Exclude DoH server hostnames from filtering so they bypass
// the filter and use system DNS instead, preventing recursive DoH queries.
//
// Returns: TRUE if hostname matches any DoH server (should be excluded from filtering)
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
                LeaveCriticalSection(&g_DohConfigLock);
                return TRUE;
            }
        }
    }

    LeaveCriticalSection(&g_DohConfigLock);
    return FALSE;
}

//---------------------------------------------------------------------------
// DoH_IsQueryActive - Check if any DoH query is currently active (re-entrancy detection)
//
// Returns: TRUE if a DoH query is active (either on current thread or globally)
//          FALSE if safe to start new DoH query
//
// Checks both:
//   1. Per-thread TLS flag (dns_in_doh_query): Detects same-thread recursion
//   2. Global counter (g_DohActiveQueries): Detects cross-thread recursion from WinHTTP internal threads
//
// If TRUE, caller should skip DoH and fall back to system DNS to prevent loops
//---------------------------------------------------------------------------

_FX BOOLEAN DoH_IsQueryActive(void)
{
    // Check both TLS flag and global counter
    if (DoH_GetInDoHQuery())
        return TRUE;
    if (InterlockedCompareExchange(&g_DohActiveQueries, 0, 0) > 0)
        return TRUE;
    return FALSE;
}

//---------------------------------------------------------------------------
// DoH_SelectServer - Select a server using round-robin with failure awareness
//---------------------------------------------------------------------------

static DOH_SERVER* DoH_SelectServer(ULONGLONG now)
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
        DOH_CONFIG_LINE* line = &g_DohConfigLines[g_DohCurrentConfigLine];
        
        if (line->ServerCount > 0) {
            start_server = line->CurrentServer;
            
            // Try servers in this line
            for (ULONG s = 0; s < line->ServerCount; s++) {
                ULONG server_idx = (start_server + s) % line->ServerCount;
                DOH_SERVER* server = &line->Servers[server_idx];
                
                // Check if server is in cooldown
                if (server->FailedUntil == 0 || now >= server->FailedUntil) {
                    // Update within-line round-robin counter only
                    line->CurrentServer = (server_idx + 1) % line->ServerCount;
                    LeaveCriticalSection(&g_DohConfigLock);
                    return server;
                }
                attempts++;
            }
        }
        
        // Move to next config line (round-robin across lines)
        g_DohCurrentConfigLine = (g_DohCurrentConfigLine + 1) % g_DohConfigLineCount;
        
        // Avoid infinite loop if we've checked all lines
        if (g_DohCurrentConfigLine == start_line && attempts > 0)
            break;
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
// DoH_AdvanceLineRoundRobin - Advance to next config line after successful query
//---------------------------------------------------------------------------

static void DoH_AdvanceLineRoundRobin(DOH_SERVER* server)
{
    ULONG i;
    
    if (!server)
        return;

    if (!InterlockedCompareExchange(&g_DohConfigLockValid, 0, 0))
        return;

    EnterCriticalSection(&g_DohConfigLock);
    
    // Find which line this server belongs to
    for (i = 0; i < g_DohConfigLineCount; i++) {
        DOH_CONFIG_LINE* line = &g_DohConfigLines[i];
        ULONG s;
        
        for (s = 0; s < line->ServerCount; s++) {
            if (&line->Servers[s] == server) {
                // Found it - advance line counter only if we're on this line
                if (g_DohCurrentConfigLine == i) {
                    g_DohCurrentConfigLine = (g_DohCurrentConfigLine + 1) % g_DohConfigLineCount;
                }
                LeaveCriticalSection(&g_DohConfigLock);
                return;
            }
        }
    }
    
    LeaveCriticalSection(&g_DohConfigLock);
}

//---------------------------------------------------------------------------
// DoH_MarkServerFailed - Mark a server as failed for cooldown period
//---------------------------------------------------------------------------

static void DoH_MarkServerFailed(DOH_SERVER* server, ULONGLONG now)
{
    if (!server)
        return;

    if (!InterlockedCompareExchange(&g_DohConfigLockValid, 0, 0))
        return;

    EnterCriticalSection(&g_DohConfigLock);
    
    server->FailedUntil = now + DOH_SERVER_FAIL_COOLDOWN_MS;
    
    if (DNS_TraceFlag) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"[DoH] Server %s marked failed, retry after %d seconds",
            server->Host, DOH_SERVER_FAIL_COOLDOWN_MS / 1000);
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
// DoH_CacheLookup
//---------------------------------------------------------------------------

static BOOLEAN DoH_CacheLookup(const WCHAR* domain, USHORT qtype, DOH_RESULT* pResult)
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
                    Sbie_snwprintf(msg, 512, L"[DoH] Cache HIT: %s (Type: %d)", domain, qtype);
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
        Sbie_snwprintf(msg, 512, L"[DoH] Cache MISS: %s (Type: %d)", domain, qtype);
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
        Sbie_snwprintf(msg, 512, L"[DoH] Built DNS query: %s (Type: %d, Length: %d bytes)",
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
// DoH_CacheStore
//---------------------------------------------------------------------------

static void DoH_CacheStore(const WCHAR* domain, USHORT qtype, const DOH_RESULT* pResult)
{
    ULONGLONG now;
    int i;
    int oldest_idx = 0;
    ULONGLONG oldest_expiry = (ULONGLONG)-1;

    if (!InterlockedCompareExchange(&g_DohCacheLockValid, 0, 0))
        return;

    now = GetTickCount64();

    EnterCriticalSection(&g_DohCacheLock);

    for (i = 0; i < DOH_CACHE_SIZE; i++) {
        if (!g_DohCache[i].valid) {
            oldest_idx = i;
            break;
        }
        if (g_DohCache[i].expiry < oldest_expiry) {
            oldest_expiry = g_DohCache[i].expiry;
            oldest_idx = i;
        }
    }

    wcsncpy(g_DohCache[oldest_idx].domain, domain, 255);
    g_DohCache[oldest_idx].domain[255] = L'\0';
    g_DohCache[oldest_idx].qtype = qtype;
    g_DohCache[oldest_idx].expiry = now + (pResult->TTL * 1000);
    memcpy(&g_DohCache[oldest_idx].result, pResult, sizeof(DOH_RESULT));
    g_DohCache[oldest_idx].valid = TRUE;

    LeaveCriticalSection(&g_DohCacheLock);

    if (DNS_DebugFlag) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"[DoH] Cached: %s (Type: %d, TTL: %d)", domain, qtype, pResult->TTL);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
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
        default:
            Sbie_snwprintf(buffer, bufsize, L"TYPE%d", qtype);
            return buffer;
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

static BOOLEAN DoH_HttpRequest_WinHttp(DOH_SERVER* server, const WCHAR* domain, USHORT qtype, BYTE* response, DWORD response_size, DWORD* bytes_read)
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

    *bytes_read = 0;

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

    // Use pooled connection to prevent connection spam
    hConnect = DoH_GetPooledConnection(server->Host, server->Port, TRUE);
    LeaveCriticalSection(&g_DohLock);

    if (!hConnect) {
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] WinHttpConnect/pooled connection failed");
        }
        goto cleanup;
    }

    // Use POST method for DNS wire format
    hRequest = __sys_WinHttpOpenRequest(hConnect, L"POST", server->Path, NULL, 
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] WinHttpOpenRequest failed");
        }
        goto cleanup;
    }

    // If using self-signed certificate (httpx://), disable certificate validation
    if (server->SelfSigned && __sys_WinHttpSetOption) {
        DWORD security_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | 
                              SECURITY_FLAG_IGNORE_CERT_CN_INVALID | 
                              SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        if (!__sys_WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &security_flags, sizeof(security_flags))) {
            if (DNS_TraceFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Warning: Failed to disable certificate validation for self-signed cert");
            }
        }
    }

    // Set HTTP timeouts to prevent indefinite blocking (5 seconds for DNS queries)
    if (__sys_WinHttpSetTimeouts) {
        // WinHttpSetTimeouts(hRequest, resolve, connect, send, receive) - all in milliseconds
        if (!__sys_WinHttpSetTimeouts(hRequest, 
                DOH_QUERY_TIMEOUT_MS,  // DNS name resolution timeout
                DOH_QUERY_TIMEOUT_MS,  // Connection timeout
                DOH_QUERY_TIMEOUT_MS,  // Send timeout
                DOH_QUERY_TIMEOUT_MS)) // Receive timeout
        {
            if (DNS_DebugFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Warning: Failed to set WinHTTP timeouts");
            }
        }
    }

    // Send DNS query with wire format headers (includes Connection: Keep-Alive for connection reuse)
    if (!__sys_WinHttpSendRequest(hRequest, 
            L"Content-Type: application/dns-message\r\nAccept: application/dns-message\r\nConnection: Keep-Alive\r\n", 
            (DWORD)-1, query_buffer, query_len, query_len, 0)) {
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] WinHttpSendRequest failed");
        }
        goto cleanup;
    }

    if (!__sys_WinHttpReceiveResponse(hRequest, NULL)) {
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] WinHttpReceiveResponse failed");
        }
        goto cleanup;
    }

    if (!__sys_WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_size, WINHTTP_NO_HEADER_INDEX)) {
        goto cleanup;
    }

    if (status_code != 200) {
        if (DNS_TraceFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoH] HTTP %d for %s", status_code, domain);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        goto cleanup;
    }

    // Read binary DNS response
    while (__sys_WinHttpReadData(hRequest, response + total_read, 
            response_size - total_read, &chunk_read) && chunk_read > 0) {
        total_read += chunk_read;
        if (total_read >= response_size) {
            if (DNS_TraceFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Response too large");
            }
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
    if (hRequest)
        __sys_WinHttpCloseHandle(hRequest);
    
    // Release connection back to pool (or close if temporary)
    DoH_ReleasePooledConnection(hConnect, FALSE);

    return result;
}

//---------------------------------------------------------------------------
// DoH_HttpRequest_WinINet
//
// Sends DNS query using WinINet with DNS wire format (RFC 8484 Section 4.1).
// Uses HttpOpenRequest/HttpSendRequest for POST with binary body.
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

static BOOLEAN DoH_HttpRequest_WinINet(DOH_SERVER* server, const WCHAR* domain, USHORT qtype, BYTE* response, DWORD response_size, DWORD* bytes_read)
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

    *bytes_read = 0;

    if (!server || !DoH_HasWinINetFunctions())
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
    
    if (!g_hWinINetSession) {
        g_hWinINetSession = __sys_InternetOpenW(
            L"Sandboxie DoH Client/1.0",
            INTERNET_OPEN_TYPE_PRECONFIG,
            NULL, NULL, 0
        );
        if (!g_hWinINetSession) {
            LeaveCriticalSection(&g_DohLock);
            if (DNS_TraceFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] InternetOpenW failed");
            }
            return FALSE;
        }
    }

    // Use pooled connection to prevent connection spam
    hConnect = DoH_GetPooledConnection(server->Host, server->Port, FALSE);
    
    LeaveCriticalSection(&g_DohLock);

    if (!hConnect) {
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] InternetConnectW/pooled connection failed");
        }
        return FALSE;
    }

    // Use POST method for DNS wire format
    hRequest = __sys_HttpOpenRequestW(hConnect, L"POST", server->Path, NULL, NULL, NULL,
        INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD, 0);
    
    if (!hRequest) {
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] HttpOpenRequestW failed");
        }
        DoH_ReleasePooledConnection(hConnect, FALSE);
        return FALSE;
    }

    // If using self-signed certificate (httpx://), disable certificate validation
    if (server->SelfSigned && __sys_InternetSetOptionW) {
        DWORD security_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | 
                              SECURITY_FLAG_IGNORE_CERT_CN_INVALID | 
                              SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        if (!__sys_InternetSetOptionW(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &security_flags, sizeof(security_flags))) {
            if (DNS_TraceFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Warning: Failed to disable certificate validation for self-signed cert (WinINet)");
            }
        }
    }

    // Set HTTP timeouts to prevent indefinite blocking (5 seconds for DNS queries)
    // This is critical to prevent browser freeze when DoH server is slow/unresponsive
    if (__sys_InternetSetOptionW) {
        DWORD timeout_ms = DOH_QUERY_TIMEOUT_MS;
        __sys_InternetSetOptionW(hRequest, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout_ms, sizeof(timeout_ms));
        __sys_InternetSetOptionW(hRequest, INTERNET_OPTION_SEND_TIMEOUT, &timeout_ms, sizeof(timeout_ms));
        __sys_InternetSetOptionW(hRequest, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout_ms, sizeof(timeout_ms));
    }

    // Send DNS query with wire format headers (includes Connection: Keep-Alive for connection reuse)
    if (!__sys_HttpSendRequestW(hRequest,
            L"Content-Type: application/dns-message\r\nAccept: application/dns-message\r\nConnection: Keep-Alive\r\n",
            (DWORD)-1, query_buffer, query_len)) {
        if (DNS_TraceFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoH] HttpSendRequestW failed, error %d", GetLastError());
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        goto cleanup;
    }

    if (!__sys_HttpQueryInfoW(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
            &status_code, &status_size, NULL)) {
        goto cleanup;
    }

    if (status_code != 200) {
        if (DNS_TraceFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoH] HTTP %d for %s", status_code, domain);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        goto cleanup;
    }

    // Read binary DNS response
    while (__sys_InternetReadFile(hRequest, response + total_read, 
            response_size - total_read, &chunk_read) && chunk_read > 0) {
        total_read += chunk_read;
        if (total_read >= response_size) {
            if (DNS_TraceFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Response too large");
            }
            goto cleanup;
        }
    }

    if (total_read > 0) {
        *bytes_read = total_read;
        result = TRUE;

        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoH] WinINet received %d bytes for %s", total_read, domain);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    }

cleanup:
    if (hRequest)
        __sys_InternetCloseHandle(hRequest);
    
    // Release connection back to pool (or close if temporary)
    DoH_ReleasePooledConnection(hConnect, FALSE);

    return result;
}

//---------------------------------------------------------------------------
// DoH_HttpRequestToServer - Make request to a specific server
//---------------------------------------------------------------------------

static BOOLEAN DoH_HttpRequestToServer(DOH_SERVER* server, const WCHAR* domain, USHORT qtype, BYTE* response, DWORD response_size, DWORD* bytes_read)
{
    DOH_HTTP_BACKEND backend;

    if (!server)
        return FALSE;

    if (!InterlockedCompareExchange(&g_DohLockValid, 0, 0))
        return FALSE;

    EnterCriticalSection(&g_DohLock);
    backend = g_DohBackend;
    LeaveCriticalSection(&g_DohLock);

    if (backend == DOH_BACKEND_FAILED)
        return FALSE;

    if (backend == DOH_BACKEND_WINHTTP) {
        if (DoH_HttpRequest_WinHttp(server, domain, qtype, response, response_size, bytes_read))
            return TRUE;
        
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] WinHTTP failed, trying WinINet");
        }
        
        if (DoH_HttpRequest_WinINet(server, domain, qtype, response, response_size, bytes_read)) {
            EnterCriticalSection(&g_DohLock);
            g_DohBackend = DOH_BACKEND_WININET;
            LeaveCriticalSection(&g_DohLock);
            return TRUE;
        }
    }
    else if (backend == DOH_BACKEND_WININET) {
        if (DoH_HttpRequest_WinINet(server, domain, qtype, response, response_size, bytes_read))
            return TRUE;
    }
    else {
        if (DoH_HttpRequest_WinHttp(server, domain, qtype, response, response_size, bytes_read)) {
            EnterCriticalSection(&g_DohLock);
            g_DohBackend = DOH_BACKEND_WINHTTP;
            LeaveCriticalSection(&g_DohLock);
            return TRUE;
        }
        if (DoH_HttpRequest_WinINet(server, domain, qtype, response, response_size, bytes_read)) {
            EnterCriticalSection(&g_DohLock);
            g_DohBackend = DOH_BACKEND_WININET;
            LeaveCriticalSection(&g_DohLock);
            return TRUE;
        }
    }

    return FALSE;
}

//---------------------------------------------------------------------------
// DoH_HttpRequest - Make request with multi-server failover
//---------------------------------------------------------------------------

static BOOLEAN DoH_HttpRequest(const WCHAR* domain, USHORT qtype, BYTE* response, DWORD response_size, DWORD* bytes_read)
{
    ULONGLONG now = GetTickCount64();
    ULONG attempts = 0;
    ULONG max_attempts;
    DOH_SERVER* first_server = NULL;
    DOH_SERVER* server;

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
        server = DoH_SelectServer(now);
        if (!server)
            break;

        // Prevent infinite loop
        if (first_server == NULL) {
            first_server = server;
        } else if (server == first_server && attempts > 0) {
            // We've cycled back to the first server - all servers failed
            break;
        }

        if (DNS_DebugFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"[DoH] Trying server %s:%d", server->Host, server->Port);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }

        if (DoH_HttpRequestToServer(server, domain, qtype, response, response_size, bytes_read)) {
            // Clear failure state on success
            if (server->FailedUntil > 0) {
                EnterCriticalSection(&g_DohConfigLock);
                server->FailedUntil = 0;
                LeaveCriticalSection(&g_DohConfigLock);
            }
            // Advance line round-robin for next query
            DoH_AdvanceLineRoundRobin(server);
            return TRUE;
        }

        // Mark server as failed
        DoH_MarkServerFailed(server, now);
        attempts++;
    }

    // All servers failed
    if (DNS_TraceFlag) {
        SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] All servers failed");
    }

    return FALSE;
}

//---------------------------------------------------------------------------
// DoH_ParseDnsResponse
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

static BOOLEAN DoH_ParseDnsResponse(const BYTE* response, int responseLen, DOH_RESULT* pResult)
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

    memset(pResult, 0, sizeof(DOH_RESULT));
    pResult->TTL = DOH_DEFAULT_TTL;

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
            Sbie_snwprintf(msg, 256, L"[DoH] DNS response code: %d", rcode);
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
                Sbie_snwprintf(msg, 256, L"[DoH] Parsed A record: %d.%d.%d.%d (TTL: %d)",
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
                Sbie_snwprintf(msg, 256, L"[DoH] Parsed AAAA record: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x (TTL: %d)",
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
                    Sbie_snwprintf(msg, 512, L"[DoH] Found CNAME: %s -> %s (TTL: %d)",
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
                Sbie_snwprintf(msg, 256, L"[DoH] Found SOA record (NODATA) - TTL: %d", ttl);
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
            Sbie_snwprintf(msg, 512, L"[DoH] CNAME-only response, target: %s", pResult->CnameTarget);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        
        return TRUE;
    }

    pResult->Success = TRUE;

    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DoH] Parsed %d answers from DNS response", pResult->AnswerCount);
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

    memset(pResult, 0, sizeof(DOH_RESULT));
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
// DoH_Query - Perform DNS query via DoH (DNS-over-HTTPS)
//
// Input:
//   - domain: Domain name to resolve (e.g., "google.com")
//   - qtype: DNS query type (DNS_TYPE_A, DNS_TYPE_AAAA)
//   - pResult: Output structure to receive response
//
// Process:
//   1. Check if DoH is enabled (SecureDnsServer configured)
//   2. Check for re-entrancy (TLS flag + global counter)
//   3. Try cache lookup (avoid network round-trip for recent queries)
//   4. Check for pending query (same domain - coalesce with existing request)
//   5. Acquire semaphore (limit concurrent DoH requests to prevent server hammering)
//   6. Select server using round-robin with failure detection
//   7. Make HTTPS request with proper DoH URL parameters
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

    if (!DoH_IsEnabled())
        return FALSE;

    if (!DoH_LoadBackends()) {
        pResult->Success = TRUE;
        pResult->Status = 0;
        pResult->AnswerCount = 0;
        pResult->TTL = 60;
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
            pResult->TTL = 60;
            return TRUE;
        }
    }

    // Check same-thread re-entrancy first (prevents infinite loops on same thread)
    if (DoH_GetInDoHQuery()) {
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Re-entrancy detected (TLS)");
        }
        return FALSE;
    }

    // Check cache BEFORE doing any pending query logic
    if (DoH_CacheLookup(domain, qtype, pResult))
        return TRUE;

    //
    // Pending Query Coalescing:
    // Check if another thread is already querying this domain+type.
    // If so, wait for it instead of making a duplicate HTTP request.
    //
    pending = DoH_FindPendingQuery(domain, qtype);
    if (pending) {
        // Another thread is already querying this domain - wait for it
        if (DNS_DebugFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"[DoH] Waiting for pending query: %s (type %d)", domain, qtype);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }

        // Wait for the query to complete (with timeout)
        waitResult = WaitForSingleObject(pending->Event, DOH_QUERY_TIMEOUT_MS);
        
        // Decrement waiter count (may trigger cleanup)
        DoH_ReleaseWaiter(pending);

        if (waitResult == WAIT_OBJECT_0) {
            // Query completed - read from cache
            if (DoH_CacheLookup(domain, qtype, pResult)) {
                return TRUE;
            }
        }

        // Timeout or cache miss - fall through to graceful failure
        pResult->Success = TRUE;
        pResult->Status = 0;
        pResult->AnswerCount = 0;
        pResult->TTL = 60;
        return TRUE;
    }

    //
    // No pending query found - we'll be the querier.
    // Create pending entry so other threads can wait on us.
    //
    pending = DoH_CreatePendingQuery(domain, qtype);
    isQuerier = TRUE;

    //
    // Semaphore: Limit concurrent DoH requests to prevent server hammering.
    // Wait for semaphore slot before making HTTP request.
    //
    if (g_DohQuerySemaphore) {
        waitResult = WaitForSingleObject(g_DohQuerySemaphore, DOH_QUERY_TIMEOUT_MS);
        if (waitResult != WAIT_OBJECT_0) {
            // Timeout waiting for semaphore - too many concurrent queries
            if (DNS_DebugFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoH] Semaphore timeout - too many concurrent queries");
            }
            if (pending) {
                DoH_CompletePendingQuery(pending);
                DoH_ReleaseWaiter(pending);
            }
            pResult->Success = TRUE;
            pResult->Status = 0;
            pResult->AnswerCount = 0;
            pResult->TTL = 60;
            return TRUE;
        }
    }

    // Check global counter for cross-thread re-entrancy (WinHTTP uses internal threads)
    if (InterlockedCompareExchange(&g_DohActiveQueries, 0, 0) > 0) {
        if (DNS_DebugFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"[DoH] Re-entrancy detected (global), waiting for active query: %s", domain);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        
        // Wait up to 500ms for active query to complete (50ms x 10 attempts)
        for (int i = 0; i < 10; i++) {
            Sleep(50);
            
            // Check cache again - another thread may have completed the query
            if (DoH_CacheLookup(domain, qtype, pResult)) {
                if (g_DohQuerySemaphore) ReleaseSemaphore(g_DohQuerySemaphore, 1, NULL);
                if (pending) {
                    DoH_CompletePendingQuery(pending);
                    DoH_ReleaseWaiter(pending);
                }
                return TRUE;
            }
            
            // Check if query finished
            if (InterlockedCompareExchange(&g_DohActiveQueries, 0, 0) == 0)
                break;
        }
        
        // Check cache one final time after waiting
        if (DoH_CacheLookup(domain, qtype, pResult)) {
            if (g_DohQuerySemaphore) ReleaseSemaphore(g_DohQuerySemaphore, 1, NULL);
            if (pending) {
                DoH_CompletePendingQuery(pending);
                DoH_ReleaseWaiter(pending);
            }
            return TRUE;
        }
    }

    DoH_SetInDoHQuery(TRUE);
    InterlockedIncrement(&g_DohActiveQueries);

    if (DNS_TraceFlag) {
        WCHAR msg[512];
        Sbie_snwprintf(msg, 512, L"[DoH] Query: %s (Type: %s)", domain, DNS_GetTypeName(qtype));
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    if (!DoH_HttpRequest(domain, qtype, response, sizeof(response), &bytes_read)) {
        InterlockedDecrement(&g_DohActiveQueries);
        DoH_SetInDoHQuery(FALSE);
        if (g_DohQuerySemaphore) ReleaseSemaphore(g_DohQuerySemaphore, 1, NULL);
        if (pending) {
            DoH_CompletePendingQuery(pending);
            DoH_ReleaseWaiter(pending);
        }
        pResult->Success = TRUE;
        pResult->Status = 0;
        pResult->AnswerCount = 0;
        pResult->TTL = 60;
        return TRUE;
    }

    // Parse binary DNS wire format response
    if (!DoH_ParseDnsResponse(response, (int)bytes_read, pResult)) {
        InterlockedDecrement(&g_DohActiveQueries);
        DoH_SetInDoHQuery(FALSE);
        if (g_DohQuerySemaphore) ReleaseSemaphore(g_DohQuerySemaphore, 1, NULL);
        if (pending) {
            DoH_CompletePendingQuery(pending);
            DoH_ReleaseWaiter(pending);
        }
        pResult->Success = TRUE;
        pResult->Status = 0;
        pResult->AnswerCount = 0;
        pResult->TTL = 60;
        return TRUE;
    }

    InterlockedDecrement(&g_DohActiveQueries);
    DoH_SetInDoHQuery(FALSE);

    // Cache the result so waiters can read it
    DoH_CacheStore(domain, qtype, pResult);

    // Release semaphore and signal pending waiters
    if (g_DohQuerySemaphore) ReleaseSemaphore(g_DohQuerySemaphore, 1, NULL);
    if (pending) {
        DoH_CompletePendingQuery(pending);
        DoH_ReleaseWaiter(pending);
    }

    return TRUE;
}
