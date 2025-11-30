/*
 * Copyright 2022 David Xanatos, xanasoft.com
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
// Socket Hooks - Raw DNS Query Interception
//
// This module intercepts raw UDP socket operations to filter DNS queries
// sent directly to port 53, catching tools like nslookup.exe that bypass
// high-level DNS APIs.
//
// DNS Wire Format Parser:
//   - Parses DNS query packets (RFC 1035)
//   - Extracts domain names from question section
//   - Matches against NetworkDnsFilter rules using hierarchical wildcard matching
//   - Blocks filtered queries by returning NXDOMAIN or configured IP
//
// Hierarchical Wildcard Matching:
//   - Tries exact match first: "www.sub.example.com"
//   - Falls back through wildcard levels: "*.sub.example.com" → "*.example.com" → "*.com"
//   - Finally tries catch-all: "*"
//   - Most specific match wins
//
// Configuration Examples:
//   NetworkDnsFilter=*.example.com,1.1.1.1    # Redirect all example.com subdomains
//   NetworkDnsFilter=*.ads.com                # Block all ads.com subdomains (NXDOMAIN)
//   NetworkDnsFilter=*,0.0.0.0                # Block everything else
//
// IPv4-to-IPv6 Mapping (DnsMapIpv4ToIpv6 setting, default: off):
//   - When enabled: AAAA queries automatically use IPv4-mapped IPv6 (::ffff:a.b.c.d) if only IPv4 configured
//   - When disabled: AAAA queries return NXDOMAIN if no native IPv6 addresses available
//   - Native IPv6 addresses always preferred when available
//---------------------------------------------------------------------------

#define NOGDI
#include "dll.h"

#include <windows.h>
#include <wchar.h>
#include "common/my_wsa.h"
#include "wsa_defs.h"
#include "common/pattern.h"
#include "common/netfw.h"
#include "socket_hooks.h"
#include "dns_filter.h"
#include "dns_logging.h"

//---------------------------------------------------------------------------
// WSABUF Definition
//---------------------------------------------------------------------------

typedef struct _WSABUF_REAL {
    ULONG len;
    CHAR FAR *buf;
} WSABUF_REAL, *LPWSABUF_REAL;

//---------------------------------------------------------------------------
// DNS Packet Structure (RFC 1035)
// Using custom structure names to avoid conflicts with Windows SDK definitions
//---------------------------------------------------------------------------

#pragma pack(push, 1)
typedef struct _DNS_WIRE_HEADER {
    USHORT TransactionID;
    USHORT Flags;
    USHORT Questions;
    USHORT AnswerRRs;
    USHORT AuthorityRRs;
    USHORT AdditionalRRs;
} DNS_WIRE_HEADER;
#pragma pack(pop)

// DNS Header Flags (network byte order - big endian)
#define DNS_FLAG_QR_QUERY    0x0000   // Query (0 = query, 1 = response)
#define DNS_FLAG_OPCODE_STD  0x0000   // Standard query
#define DNS_QTYPE_A          0x0100   // Type A (IPv4) - network byte order
#define DNS_QTYPE_AAAA       0x1C00   // Type AAAA (IPv6) - network byte order

// DNS Response structures
#pragma pack(push, 1)
typedef struct _DNS_QUESTION {
    USHORT qtype;
    USHORT qclass;
} DNS_QUESTION;

typedef struct _DNS_RR {
    USHORT name;        // Compressed name pointer
    USHORT type;
    USHORT rr_class;
    DWORD ttl;
    USHORT rdlength;
    // Data follows
} DNS_RR;
#pragma pack(pop)

// DNS_TYPE_A and DNS_TYPE_AAAA are already defined in windns.h
// (windns.h is included via dns_logging.h -> dnsapi_defs.h)
#ifndef DNS_TYPE_A
#define DNS_TYPE_A     1
#endif

#ifndef DNS_TYPE_AAAA
#define DNS_TYPE_AAAA  28
#endif

#define DNS_RESPONSE_SIZE 512  // Maximum DNS response size (RFC 1035)

//---------------------------------------------------------------------------
// Socket Option Constants (for getsockopt)
//---------------------------------------------------------------------------

#ifndef SOL_SOCKET
#define SOL_SOCKET 0xffff
#endif

#ifndef SO_TYPE
#define SO_TYPE 0x1008
#endif

#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif

#ifndef SOCK_DGRAM
#define SOCK_DGRAM 2
#endif

//---------------------------------------------------------------------------
// Fake Response Queue for Direct DNS Response Injection
// Per-Socket FIFO Architecture - O(1) enqueue/dequeue, reduced lock contention
//---------------------------------------------------------------------------

// Resource limits to prevent abuse
#define MAX_FAKE_RESPONSES_PER_SOCKET 10
#define FAKE_RESPONSE_TIMEOUT_MS 10000

typedef struct _FAKE_RESPONSE {
    char length_prefix[2];      // TCP DNS length prefix (2 bytes, network byte order)
    char response[512];         // DNS payload
    int response_len;           // Length of DNS payload
    int consumed;               // Bytes already returned (includes length prefix for TCP)
    int total_len;              // Total bytes to return (2 + response_len for TCP, response_len for UDP)
    BOOLEAN is_tcp;             // TRUE if this is a TCP response (has length prefix)
    BOOLEAN skip_length_prefix; // TRUE if we should skip sending the length prefix (nslookup without -vc)
    struct sockaddr_in from_addr;
    DWORD timestamp;
    struct _FAKE_RESPONSE* next;
} FAKE_RESPONSE;

// Per-socket response queue (FIFO with head/tail pointers)
typedef struct _SOCKET_RESPONSE_QUEUE {
    SOCKET socket;                      // Socket handle (for hash table validation)
    CRITICAL_SECTION lock;              // Per-socket lock (reduces contention)
    FAKE_RESPONSE* head;                // FIFO head (oldest response)
    FAKE_RESPONSE* tail;                // FIFO tail (newest response)
    ULONG response_count;               // Number of queued responses
    DWORD last_access;                  // Timestamp for cleanup
    struct _SOCKET_RESPONSE_QUEUE* next; // Collision chain (for hash table)
} SOCKET_RESPONSE_QUEUE;

// Hash table for per-socket queues
#define RESPONSE_QUEUE_TABLE_SIZE 256
static SOCKET_RESPONSE_QUEUE* g_ResponseQueueTable[RESPONSE_QUEUE_TABLE_SIZE];
static CRITICAL_SECTION g_ResponseTableLock;  // Only for queue creation/deletion

static BOOLEAN DNS_RawSocketFilterEnabled = FALSE;  // Raw socket filtering enabled (default: FALSE)
static BOOLEAN DNS_DebugFlag = FALSE;  // Verbose debug logging (requires DnsTrace + DnsDebug)

//---------------------------------------------------------------------------
// DNS Connection Tracking
//---------------------------------------------------------------------------

// Track sockets connected to DNS servers (port 53)
static BOOLEAN Socket_IsDnsSocket(SOCKET s);
void Socket_MarkDnsSocket(SOCKET s, BOOLEAN isDns);  // Non-static: called from net.c
static BOOLEAN Socket_IsTcpSocket(SOCKET s);  // Helper to detect TCP vs UDP sockets

// Simple hash table for tracking DNS sockets
#define DNS_SOCKET_TABLE_SIZE 256
static SOCKET g_DnsSockets[DNS_SOCKET_TABLE_SIZE];
static BOOLEAN g_DnsSocketFlags[DNS_SOCKET_TABLE_SIZE];

// Store DNS server addresses for getpeername() support
// Stores the address the socket connected to (for local-response spoofing)
// Use byte array large enough for IPv6 (128 bytes is more than enough for sockaddr_in6)
#define DNS_SERVER_ADDR_SIZE 128
static BYTE g_DnsServerAddrs[DNS_SOCKET_TABLE_SIZE][DNS_SERVER_ADDR_SIZE];
static int g_DnsServerAddrLens[DNS_SOCKET_TABLE_SIZE];

//---------------------------------------------------------------------------
// System Function Pointers
//---------------------------------------------------------------------------

static P_sendto __sys_sendto = NULL;
static P_WSASend __sys_WSASend = NULL;
static P_WSASendTo __sys_WSASendTo = NULL;
static P_send __sys_send = NULL;
static P_connect __sys_connect = NULL;
static P_WSAConnect __sys_WSAConnect = NULL;
static P_recv __sys_recv = NULL;
static P_recvfrom __sys_recvfrom = NULL;
static P_getpeername __sys_getpeername = NULL;

// select/poll support for TCP DNS local-response mode (P_select is defined in wsa_defs.h)
static P_select __sys_select = NULL;

// getsockopt function pointer (not hooked, used for socket type detection)
typedef int (WINAPI *P_getsockopt)(SOCKET s, int level, int optname, char* optval, int* optlen);
static P_getsockopt __sys_getsockopt = NULL;

//---------------------------------------------------------------------------
// Forward Declarations
//---------------------------------------------------------------------------

// External utility functions (from dns_filter.c / net.c)
void WSA_DumpIP(ADDRESS_FAMILY af, IP_ADDRESS* pIP, wchar_t* pStr);

BOOLEAN Socket_GetRawDnsFilterEnabled(BOOLEAN has_valid_certificate);  // Non-static: called from net.c

static int Socket_connect(
    SOCKET         s,
    const void     *name,
    int            namelen);

static int Socket_WSAConnect(
    SOCKET         s,
    const void     *name,
    int            namelen,
    LPWSABUF       lpCallerData,
    LPWSABUF       lpCalleeData,
    LPQOS          lpSQOS,
    LPQOS          lpGQOS);

static int Socket_send(
    SOCKET      s,
    const char* buf,
    int         len,
    int         flags);

static int Socket_sendto(
    SOCKET         s,
    const char     *buf,
    int            len,
    int            flags,
    const void     *to,
    int            tolen);

static int Socket_WSASend(
    SOCKET                             s,
    LPWSABUF                           lpBuffers,
    DWORD                              dwBufferCount,
    LPDWORD                            lpNumberOfBytesSent,
    DWORD                              dwFlags,
    LPWSAOVERLAPPED                    lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

static int Socket_WSASendTo(
    SOCKET                             s,
    LPWSABUF                           lpBuffers,
    DWORD                              dwBufferCount,
    LPDWORD                            lpNumberOfBytesSent,
    DWORD                              dwFlags,
    const void                         *lpTo,
    int                                iTolen,
    LPWSAOVERLAPPED                    lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

BOOLEAN Socket_ParseDnsQuery(
    const BYTE*    packet,
    int            len,
    WCHAR*         domainOut,
    int            domainOutSize,
    USHORT*        qtype);

static int Socket_DecodeDnsName(
    const BYTE*    packet,
    int            packetLen,
    int            offset,
    WCHAR*         nameOut,
    int            nameOutSize);

static int Socket_recv(
    SOCKET   s,
    char     *buf,
    int      len,
    int      flags);

static int Socket_recvfrom(
    SOCKET   s,
    char     *buf,
    int      len,
    int      flags,
    void     *from,
    int      *fromlen);

static int Socket_select(
    int            nfds,
    void           *readfds,
    void           *writefds,
    void           *exceptfds,
    const void     *timeout);

static int Socket_getpeername(
    SOCKET         s,
    void           *name,
    int            *namelen);

// DNS filtering helpers
static int Socket_MatchDomainHierarchical(
    const WCHAR*   domain_lwr,
    ULONG          domain_len,
    PATTERN**      found);

// Fake response helpers
int Socket_BuildDnsResponse(
    const BYTE*    query,
    int            query_len,
    struct _LIST*  pEntries,
    BOOLEAN        block,
    BYTE*          response,
    int            response_size,
    USHORT         qtype,
    struct _DNS_TYPE_FILTER* type_filter);

static BOOLEAN Socket_ValidateDnsResponse(
    const BYTE*    response,
    int            len);

static void Socket_AddFakeResponse(
    SOCKET         s,
    const BYTE*    response,
    int            response_len,
    const void*    to);

static BOOLEAN Socket_HasFakeResponse(SOCKET s);

static int Socket_GetFakeResponse(
    SOCKET   s,
    char     *buf,
    int      len,
    void     *from,
    int      *fromlen);

//---------------------------------------------------------------------------
// Raw Socket DNS Logging Helpers
//---------------------------------------------------------------------------

// Log raw DNS query with domain and type
static void Socket_LogDnsQuery(const WCHAR* prefix, const WCHAR* domain, USHORT qtype_host, const WCHAR* suffix, SOCKET s)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    // qtype_host is already in host byte order from Socket_ParseDnsQuery
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s: %s (Type: %s, %s, Socket: %p)",
        prefix, domain, DNS_GetTypeName(qtype_host), suffix, (void*)(ULONG_PTR)s);
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

// Log intercepted DNS with IP addresses and response info
static void Socket_LogInterceptedResponse(const WCHAR* protocol, const WCHAR* domain, USHORT qtype_host,
    int query_len, const BYTE* response, int response_len, SOCKET s, LIST* pEntries, const WCHAR* func_suffix)
{
    if (!DNS_TraceFlag || !domain || !response)
        return;
    
    // qtype_host is already in host byte order from Socket_ParseDnsQuery
    
    // Check actual response flags to determine if it's NXDOMAIN or success
    DNS_WIRE_HEADER* resp_hdr = (DNS_WIRE_HEADER*)response;
    USHORT resp_flags = _ntohs(resp_hdr->Flags);
    USHORT rcode = resp_flags & 0x000F;  // Response code in lower 4 bits
    BOOLEAN is_nxdomain = (rcode == 3);  // RCODE 3 = NXDOMAIN
    
    if (!is_nxdomain && pEntries) {
        // Use unified logging format
        DNS_LogRawSocketIntercepted(protocol, domain, qtype_host, pEntries, func_suffix);
        
        // Log verbose details to DnsDebug
        DNS_LogRawSocketDebug(protocol, domain, qtype_host, query_len, response_len, func_suffix, s);
    } else {
        // Blocked (no IPs or unsupported type)
        DNS_LogRawSocketBlocked(protocol, domain, qtype_host, 
            L"Returning NXDOMAIN", func_suffix);
        
        // Log verbose details to DnsDebug
        DNS_LogRawSocketDebug(protocol, domain, qtype_host, query_len, response_len, func_suffix, s);
    }
}

// Log filter mode passthrough
static void Socket_LogFilterPassthrough(const WCHAR* protocol, const WCHAR* domain, USHORT qtype_host, const WCHAR* func_name)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    // qtype_host is already in host byte order from Socket_ParseDnsQuery
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s DNS: %s%s (Type: %s) - Filter mode, non-address query, forwarding to real DNS",
        protocol, func_name ? func_name : L"", domain, DNS_GetTypeName(qtype_host));
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
}

// Log forwarded to real DNS
static void Socket_LogForwarded(const WCHAR* protocol, const WCHAR* domain, USHORT qtype_host, const WCHAR* func_name, SOCKET s)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    // Detect actual protocol if socket is valid
    const WCHAR* actual_protocol = protocol;
    if (s != INVALID_SOCKET && Socket_IsDnsSocket(s)) {
        BOOLEAN isTcp = Socket_IsTcpSocket(s);
        actual_protocol = isTcp ? L"TCP" : L"UDP";
    }
    
    // qtype_host is already in host byte order from Socket_ParseDnsQuery
    WCHAR msg[512];
    Sbie_snwprintf(msg, 512, L"%s DNS Passthrough: %s (Type: %s) - Forwarding to real DNS",
        actual_protocol, domain, DNS_GetTypeName(qtype_host));
    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    
    // Verbose debug info
    if (DNS_DebugFlag && func_name) {
        WCHAR debug_msg[256];
        Sbie_snwprintf(debug_msg, 256, L"  Raw Socket Debug: Function=%s, Socket=%p",
            func_name, (void*)(ULONG_PTR)s);
        SbieApi_MonitorPutMsg(MONITOR_DNS, debug_msg);
    }
}

//---------------------------------------------------------------------------
// Socket_HandleDnsQuery
//
// Centralized DNS query handling for all send operations (TCP/UDP)
// Extracts filter aux, builds DNS response, handles errors
//
// Returns: response_len (>0 = intercepted, 0 = pass through, -1 = error)
//---------------------------------------------------------------------------

static int Socket_HandleDnsQuery(
    PVOID* aux,
    const BYTE* dns_payload,
    int dns_payload_len,
    USHORT qtype,
    BYTE* response,
    int response_size,
    const WCHAR* error_prefix)
{
    // Extract filter configuration
    LIST* pEntries = NULL;
    DNS_TYPE_FILTER* type_filter = NULL;
    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);
    
    // Build DNS response
    int response_len = Socket_BuildDnsResponse(
        dns_payload, dns_payload_len, pEntries, pEntries == NULL, 
        response, response_size, qtype, type_filter);
    
    // Handle errors
    if (response_len < 0 && DNS_TraceFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"%s: Error building response, dropping query", error_prefix);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    return response_len;
}

//---------------------------------------------------------------------------
// Socket_GetRawDnsFilterEnabled
//
// Query the FilterRawDns setting to control raw socket DNS filtering
// Default: Enabled if valid certificate, disabled otherwise (certificate-based default)
//---------------------------------------------------------------------------

_FX BOOLEAN Socket_GetRawDnsFilterEnabled(BOOLEAN has_valid_certificate)
{
    // Query FilterRawDns with per-process matching support
    // Default: Certificate-based (enabled with valid cert, disabled without cert)
    return Config_GetSettingsForImageName_bool(L"FilterRawDns", has_valid_certificate);
}

//---------------------------------------------------------------------------
// Socket_InitHooks
//---------------------------------------------------------------------------

_FX BOOLEAN Socket_InitHooks(HMODULE module, BOOLEAN has_valid_certificate)
{
    P_connect connect;
    P_WSAConnect WSAConnect;
    P_send send;
    P_sendto sendto;
    P_WSASend WSASend;
    P_WSASendTo WSASendTo;
    P_recv recv;
    P_recvfrom recvfrom;

    // Initialize getsockopt early (needed for Socket_IsTcpSocket even if hooking is disabled)
    if (!__sys_getsockopt) {
        __sys_getsockopt = (P_getsockopt)GetProcAddress(module, "getsockopt");
    }

    // Load FilterRawDns setting (default: enabled with valid cert, disabled without cert)
    DNS_RawSocketFilterEnabled = Socket_GetRawDnsFilterEnabled(has_valid_certificate);

    // Certificate validation logic has been moved to filtering time (in send hooks)
    // Here we only control whether hooks are installed at all
    // Install hooks when:
    // - FilterRawDns=y (explicit enable) OR
    // - DnsTrace=y (logging mode)
    // This allows logging to work without certificate, while filtering requires certificate
    extern LIST DNS_FilterList;
    extern BOOLEAN DNS_TraceFlag;
    
    // If FilterRawDns explicitly disabled by user, skip hooking
    // But allow hooks if DnsTrace is enabled even when FilterRawDns=n (logging-only mode)
    if (!DNS_RawSocketFilterEnabled && !DNS_TraceFlag) {
        return TRUE;
    }

    // Load DnsDebug setting for verbose logging (only effective if DnsTrace is also set)
    WCHAR wsDebugOptions[4] = { 0 };
    if (SbieApi_QueryConf(NULL, L"DnsDebug", 0, wsDebugOptions, sizeof(wsDebugOptions)) == STATUS_SUCCESS && wsDebugOptions[0] != L'\0')
        DNS_DebugFlag = Config_String2Bool(wsDebugOptions, FALSE);

    // Initialize per-socket response queue table
    InitializeCriticalSection(&g_ResponseTableLock);
    for (int i = 0; i < RESPONSE_QUEUE_TABLE_SIZE; i++) {
        g_ResponseQueueTable[i] = NULL;
    }

    // Initialize DNS socket tracking table
    for (int i = 0; i < DNS_SOCKET_TABLE_SIZE; i++) {
        g_DnsSockets[i] = INVALID_SOCKET;
        g_DnsSocketFlags[i] = FALSE;
        g_DnsServerAddrLens[i] = 0;
        memset(g_DnsServerAddrs[i], 0, DNS_SERVER_ADDR_SIZE);
    }

    // Hook connect (to track DNS connections)
    connect = (P_connect)GetProcAddress(module, "connect");
    if (connect) {
        SBIEDLL_HOOK(Socket_, connect);
    }

    // Hook WSAConnect (overlapped connect - used by .NET)
    WSAConnect = (P_WSAConnect)GetProcAddress(module, "WSAConnect");
    if (WSAConnect) {
        SBIEDLL_HOOK(Socket_, WSAConnect);
    }

    // Hook send (for connected DNS sockets)
    send = (P_send)GetProcAddress(module, "send");
    if (send) {
        SBIEDLL_HOOK(Socket_, send);
    }

    // Hook sendto (standard UDP send)
    sendto = (P_sendto)GetProcAddress(module, "sendto");
    if (sendto) {
        SBIEDLL_HOOK(Socket_, sendto);
    }

    // Hook WSASend (overlapped TCP send - used by .NET)
    WSASend = (P_WSASend)GetProcAddress(module, "WSASend");
    if (WSASend) {
        SBIEDLL_HOOK(Socket_, WSASend);
    }

    // Hook WSASendTo (overlapped UDP send)
    WSASendTo = (P_WSASendTo)GetProcAddress(module, "WSASendTo");
    if (WSASendTo) {
        SBIEDLL_HOOK(Socket_, WSASendTo);
    }

    // Hook recv (to return fake DNS responses)
    recv = (P_recv)GetProcAddress(module, "recv");
    if (recv) {
        SBIEDLL_HOOK(Socket_, recv);
    }

    // Hook recvfrom (to return fake DNS responses)
    recvfrom = (P_recvfrom)GetProcAddress(module, "recvfrom");
    if (recvfrom) {
        SBIEDLL_HOOK(Socket_, recvfrom);
    }

    // Hook select (to make DNS sockets with fake responses appear readable)
    __sys_select = (P_select)GetProcAddress(module, "select");
    if (__sys_select) {
        P_select select = __sys_select;
        SBIEDLL_HOOK(Socket_, select);
    }

    // Hook getpeername (to return DNS server address for sockets answered locally)
    __sys_getpeername = (P_getpeername)GetProcAddress(module, "getpeername");
    if (__sys_getpeername) {
        P_getpeername getpeername = __sys_getpeername;
        SBIEDLL_HOOK(Socket_, getpeername);
    }

    return TRUE;
}

//---------------------------------------------------------------------------
// Socket_IsDnsSocket
//
// Check if a socket is marked as a DNS connection
//---------------------------------------------------------------------------

_FX BOOLEAN Socket_IsDnsSocket(SOCKET s)
{
    ULONG index = ((ULONG_PTR)s) % DNS_SOCKET_TABLE_SIZE;
    return (g_DnsSockets[index] == s && g_DnsSocketFlags[index]);
}

//---------------------------------------------------------------------------
// Socket_MarkDnsSocket
//
// Mark a socket as DNS connection (or unmark it)
//---------------------------------------------------------------------------

_FX void Socket_MarkDnsSocket(SOCKET s, BOOLEAN isDns)
{
    ULONG index = ((ULONG_PTR)s) % DNS_SOCKET_TABLE_SIZE;
    g_DnsSockets[index] = s;
    g_DnsSocketFlags[index] = isDns;
}

//---------------------------------------------------------------------------
// Socket_IsTcpSocket
//
// Check if a socket is TCP (SOCK_STREAM) or UDP (SOCK_DGRAM)
// Uses getsockopt(SO_TYPE) to query the actual socket type
//
// Returns: TRUE if TCP, FALSE if UDP or error
//---------------------------------------------------------------------------

_FX BOOLEAN Socket_IsTcpSocket(SOCKET s)
{
    // Load getsockopt on first use (lazy initialization)
    if (!__sys_getsockopt) {
        HMODULE ws2_32 = GetModuleHandleA("ws2_32.dll");
        if (ws2_32) {
            __sys_getsockopt = (P_getsockopt)GetProcAddress(ws2_32, "getsockopt");
        }
        if (!__sys_getsockopt) {
            return FALSE;  // Can't detect type, assume UDP
        }
    }
    
    int sockType = 0;
    int optLen = sizeof(sockType);
    
    // Query socket type using getsockopt
    if (__sys_getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&sockType, &optLen) == 0) {
        return (sockType == SOCK_STREAM);  // TRUE for TCP, FALSE for UDP
    }
    
    // If query fails, assume UDP (safer default for DNS)
    return FALSE;
}

//---------------------------------------------------------------------------
// Socket_connect
//
// Hook for connect() - track connections to DNS servers (port 53)
//---------------------------------------------------------------------------

_FX int Socket_connect(
    SOCKET         s,
    const void     *name,
    int            namelen)
{
    // DEBUG: Log connect calls when verbose debug is enabled
    if (DNS_FilterEnabled && DNS_RawSocketFilterEnabled && DNS_DebugFlag && name) {
        USHORT destPort = 0;
        USHORT addrFamily = ((struct sockaddr*)name)->sa_family;
        BOOLEAN isTcp = Socket_IsTcpSocket(s);
        const WCHAR* protocol = isTcp ? L"TCP" : L"UDP";

        if (addrFamily == AF_INET && namelen >= sizeof(struct sockaddr_in)) {
            destPort = _ntohs(((struct sockaddr_in*)name)->sin_port);
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"%s: connect() called, AF_INET, port=%d, socket=%p",
                protocol, destPort, (void*)(ULONG_PTR)s);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        else if (addrFamily == AF_INET6 && namelen >= sizeof(struct sockaddr_in6)) {
            destPort = _ntohs(((struct sockaddr_in6*)name)->sin6_port);
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"%s: connect() called, AF_INET6, port=%d, socket=%p",
                protocol, destPort, (void*)(ULONG_PTR)s);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    }
    
    // Check if connecting to DNS port 53
    if (DNS_FilterEnabled && DNS_RawSocketFilterEnabled && name) {
        USHORT destPort = 0;
        USHORT addrFamily = ((struct sockaddr*)name)->sa_family;

        if (addrFamily == AF_INET && namelen >= sizeof(struct sockaddr_in)) {
            destPort = _ntohs(((struct sockaddr_in*)name)->sin_port);
        }
        else if (addrFamily == AF_INET6 && namelen >= sizeof(struct sockaddr_in6)) {
            destPort = _ntohs(((struct sockaddr_in6*)name)->sin6_port);
        }

        // Mark socket as DNS if connecting to port 53
        if (destPort == 53) {
            Socket_MarkDnsSocket(s, TRUE);
            
            // Store DNS server address for getpeername() support
            ULONG index = ((ULONG_PTR)s) % DNS_SOCKET_TABLE_SIZE;
            if (addrFamily == AF_INET && namelen <= DNS_SERVER_ADDR_SIZE) {
                memcpy(g_DnsServerAddrs[index], name, namelen);
                g_DnsServerAddrLens[index] = namelen;
            } else if (addrFamily == AF_INET6 && namelen <= DNS_SERVER_ADDR_SIZE) {
                memcpy(g_DnsServerAddrs[index], name, namelen);
                g_DnsServerAddrLens[index] = namelen;
            }
            
            // Log DNS connection detection with protocol type
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                BOOLEAN isTcp = Socket_IsTcpSocket(s);
                Sbie_snwprintf(msg, 256, L"  %s DNS Debug: Connection detected to port 53, socket=%p marked as DNS",
                    isTcp ? L"TCP" : L"UDP", (void*)(ULONG_PTR)s);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
        } else {
            Socket_MarkDnsSocket(s, FALSE);
        }
    }

    // Call original connect
    return __sys_connect(s, name, namelen);
}

//---------------------------------------------------------------------------
// Socket_WSAConnect
//
// Hook for WSAConnect() - overlapped version of connect, used by .NET
//---------------------------------------------------------------------------

_FX int Socket_WSAConnect(
    SOCKET         s,
    const void     *name,
    int            namelen,
    LPWSABUF       lpCallerData,
    LPWSABUF       lpCalleeData,
    LPQOS          lpSQOS,
    LPQOS          lpGQOS)
{
    // DEBUG: Log WSAConnect calls when verbose debug is enabled
    if (DNS_FilterEnabled && DNS_RawSocketFilterEnabled && DNS_DebugFlag && name) {
        USHORT destPort = 0;
        USHORT addrFamily = ((struct sockaddr*)name)->sa_family;
        BOOLEAN isTcp = Socket_IsTcpSocket(s);
        const WCHAR* protocol = isTcp ? L"TCP" : L"UDP";

        if (addrFamily == AF_INET && namelen >= sizeof(struct sockaddr_in)) {
            destPort = _ntohs(((struct sockaddr_in*)name)->sin_port);
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"%s: WSAConnect() called, AF_INET, port=%d, socket=%p",
                protocol, destPort, (void*)(ULONG_PTR)s);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        else if (addrFamily == AF_INET6 && namelen >= sizeof(struct sockaddr_in6)) {
            destPort = _ntohs(((struct sockaddr_in6*)name)->sin6_port);
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"%s: WSAConnect() called, AF_INET6, port=%d, socket=%p",
                protocol, destPort, (void*)(ULONG_PTR)s);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    }
    
    // Check if connecting to DNS port 53
    if (DNS_FilterEnabled && DNS_RawSocketFilterEnabled && name) {
        USHORT destPort = 0;
        USHORT addrFamily = ((struct sockaddr*)name)->sa_family;

        if (addrFamily == AF_INET && namelen >= sizeof(struct sockaddr_in)) {
            destPort = _ntohs(((struct sockaddr_in*)name)->sin_port);
        }
        else if (addrFamily == AF_INET6 && namelen >= sizeof(struct sockaddr_in6)) {
            destPort = _ntohs(((struct sockaddr_in6*)name)->sin6_port);
        }

        // Mark socket as DNS if connecting to port 53
        if (destPort == 53) {
            Socket_MarkDnsSocket(s, TRUE);
            
            // Store DNS server address for getpeername() support
            ULONG index = ((ULONG_PTR)s) % DNS_SOCKET_TABLE_SIZE;
            if (addrFamily == AF_INET && namelen <= DNS_SERVER_ADDR_SIZE) {
                memcpy(g_DnsServerAddrs[index], name, namelen);
                g_DnsServerAddrLens[index] = namelen;
            } else if (addrFamily == AF_INET6 && namelen <= DNS_SERVER_ADDR_SIZE) {
                memcpy(g_DnsServerAddrs[index], name, namelen);
                g_DnsServerAddrLens[index] = namelen;
            }
            
            // Log DNS connection detection with protocol type
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                BOOLEAN isTcp = Socket_IsTcpSocket(s);
                Sbie_snwprintf(msg, 256, L"  %s DNS Debug: WSAConnect detected port 53, socket=%p marked as DNS",
                    isTcp ? L"TCP" : L"UDP", (void*)(ULONG_PTR)s);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
        } else {
            Socket_MarkDnsSocket(s, FALSE);
        }
    }

    // Call original WSAConnect
    return __sys_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
}

//---------------------------------------------------------------------------
// Socket_send
//
// Hook for send() - intercepts DNS packets on connected sockets
//---------------------------------------------------------------------------

_FX int Socket_send(
    SOCKET      s,
    const char* buf,
    int         len,
    int         flags)
{
    // DEBUG: Log ALL send() calls when verbose debug is enabled
    if (DNS_FilterEnabled && DNS_RawSocketFilterEnabled && DNS_DebugFlag && buf && len > 0) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"GLOBAL: send() socket=%p, len=%d, isDns=%d",
            (void*)(ULONG_PTR)s, len, Socket_IsDnsSocket(s) ? 1 : 0);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    // Debug: Log send() calls on DNS sockets
    if (DNS_DebugFlag && Socket_IsDnsSocket(s)) {
        BOOLEAN isTcp = Socket_IsTcpSocket(s);
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"%s DNS: send() called on DNS socket=%p, len=%d",
            isTcp ? L"TCP" : L"UDP", (void*)(ULONG_PTR)s, len);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // Only inspect if this is a DNS socket and filtering is enabled
    // Minimum check: at least enough for DNS header (with or without TCP length prefix)
    if (DNS_FilterEnabled && DNS_RawSocketFilterEnabled && Socket_IsDnsSocket(s) && buf && len >= sizeof(DNS_WIRE_HEADER)) {
        
        // TCP DNS packets MAY have a 2-byte length prefix before the DNS payload
        // However, many implementations send the length and payload in separate send() calls
        // So we need to handle three cases:
        // 1. Length prefix + DNS payload together (len >= DNS_WIRE_HEADER + 2)
        // 2. DNS payload only (len >= DNS_WIRE_HEADER, starts with valid DNS header)
        // 3. Length prefix only (len == 2) - ignore this case
        
        const BYTE* dns_payload = (const BYTE*)buf;
        int dns_payload_len = len;
        BOOLEAN has_length_prefix = FALSE;
        
        // Check for TCP DNS length prefix (2 bytes in network byte order)
        // Be careful: DNS transaction ID could be misinterpreted as length prefix!
        // Only treat as length prefix if:
        // 1. Length matches exactly (tcp_length + 2 == len)
        // 2. The remaining bytes look like a valid DNS header
        // 3. Length is within reasonable DNS bounds (12 to 512 bytes)
        // 4. QR bit is 0 (query, not response)
        if (len >= 2 + sizeof(DNS_WIRE_HEADER)) {
            USHORT tcp_length = _ntohs(*(USHORT*)buf);
            // If the length prefix matches (payload = total - 2), this is TCP DNS format
            if (tcp_length + 2 == len && 
                tcp_length >= sizeof(DNS_WIRE_HEADER) && 
                tcp_length <= 512) {  // Reasonable DNS max size
                
                // Additional validation: check if bytes after prefix look like DNS header
                DNS_WIRE_HEADER* potential_header = (DNS_WIRE_HEADER*)(buf + 2);
                USHORT flags = _ntohs(potential_header->Flags);
                USHORT qr = (flags >> 15) & 0x1;
                
                // If this looks like a query (QR=0) and has questions, treat as TCP DNS with length prefix
                if (qr == 0 && _ntohs(potential_header->Questions) > 0) {
                    dns_payload = (const BYTE*)buf + 2;  // Skip length prefix
                    dns_payload_len = tcp_length;
                    has_length_prefix = TRUE;
                    
                    if (DNS_DebugFlag) {
                        WCHAR msg[256];
                        Sbie_snwprintf(msg, 256, L"TCP DNS: Detected length prefix, payload=%d bytes",
                            tcp_length);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                    }
                }
            }
        }
        
        // If len == 2, this might be just the length prefix sent separately - skip it
        if (len == 2) {
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"TCP DNS: Skipping length-only send (len=2)");
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            return __sys_send(s, buf, len, flags);
        }
        
        WCHAR domainName[256];
        USHORT qtype = 0;

        // Parse DNS query packet (now pointing to actual DNS data)
        if (Socket_ParseDnsQuery(dns_payload, dns_payload_len, domainName, 256, &qtype)) {
            
            // Check if domain matches filter rules with hierarchical fallback
            // Try: exact match → *.subdomain.example.com → *.example.com → *.com → *
            ULONG domain_len = wcslen(domainName);
            WCHAR* domain_lwr = (WCHAR*)Dll_AllocTemp((domain_len + 4) * sizeof(WCHAR));
            wmemcpy(domain_lwr, domainName, domain_len);
            domain_lwr[domain_len] = L'\0';
            _wcslwr(domain_lwr);

            PATTERN* found = NULL;
            int match_result = Socket_MatchDomainHierarchical(domain_lwr, domain_len, &found);
            
            if (match_result > 0) {
                
                // Get auxiliary data containing IP list and type filter
                PVOID* aux = Pattern_Aux(found);
                if (!aux || !*aux) {
                    // No aux data - shouldn't happen, but be safe
                    Dll_Free(domain_lwr);
                    return __sys_send(s, buf, len, flags);
                }

                // Certificate required for actual filtering (interception/blocking)
                extern BOOLEAN DNS_HasValidCertificate;
                if (!DNS_HasValidCertificate) {
                    // Domain matches filter but no cert - log as passthrough
                    Socket_LogForwarded(L"TCP", domainName, qtype, L"send", s);
                    Dll_Free(domain_lwr);
                    return __sys_send(s, buf, len, flags);
                }

                // Build fake DNS response using centralized helper
                BYTE response[DNS_RESPONSE_SIZE];
                int response_len = Socket_HandleDnsQuery(
                    aux, dns_payload, dns_payload_len, qtype, response, DNS_RESPONSE_SIZE, L"TCP DNS");
                
                // response_len == 0 means "pass through to real DNS" (filter mode, non-filtered query)
                // response_len < 0 means error
                // response_len > 0 means we have a fake response to queue
                
                if (response_len < 0) {
                    // Error already logged by Socket_HandleDnsQuery
                    return len;  // Return success to prevent real send
                }
                
                if (response_len == 0) {
                    // Filter mode + non-A/AAAA query: Pass through to real DNS
                    Socket_LogFilterPassthrough(L"TCP", domainName, qtype, NULL);
                    // Fall through to call __sys_send - let real DNS handle it
                }
                else if (response_len > 0) {
                    // Validate the response before queuing
                    if (!Socket_ValidateDnsResponse(response, response_len)) {
                        if (DNS_TraceFlag) {
                            SbieApi_MonitorPutMsg(MONITOR_DNS, L"TCP DNS: Built response failed validation, dropping");
                        }
                        return len;  // Still return success to prevent real send
                    }
                    
                    // Get pEntries for logging (extract again since we need it)
                    LIST* pEntries = NULL;
                    DNS_TYPE_FILTER* type_filter = NULL;
                    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);
                    
                    // For TCP DNS: Queue ONLY the DNS payload (no length prefix)
                    // TCP local-response strategy:
                    // 1. Client completes the normal TCP handshake to the DNS server (connect/WSAConnect succeeds)
                    // 2. Client sends: [2-byte length][DNS query]
                    // 3. We intercept send() and keep the payload local (no upstream send)
                    // 4. We queue a fake response (DNS payload only, no length prefix)
                    // 5. Client reads the TCP length prefix → we report the fake length as if it came from the server
                    // 6. Client reads the DNS payload → we return our fake response
                    
                    if (DNS_DebugFlag) {
                        WCHAR msg[256];
                        Sbie_snwprintf(msg, 256, L"  TCP DNS Debug: Queueing fake response (answered locally, DNS payload only), len=%d bytes",
                            response_len);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                    }
                    
                    // Queue fake response for recv/recvfrom to return
                    Socket_AddFakeResponse(s, response, response_len, NULL);
                    
                    // Local-response: Return success WITHOUT actually sending upstream
                    // The socket will appear to have sent data, but nothing goes to the network
                    // When client calls recv(), we'll return our fake response
                    
                    // Log the interception with detailed diagnostics
                    Socket_LogInterceptedResponse(L"TCP", domainName, qtype, len, response, response_len, s, pEntries, NULL);
                    
                    // Return success - client thinks data was sent
                    return len;
                } // end else if (response_len > 0)
                
                // If response_len == 0, we fall through here to call __sys_send
            }
            else {
                // Domain not in filter list - trace allowed queries
                Socket_LogForwarded(L"TCP", domainName, qtype, L"send", s);
            }
        }
    }

    // Call original send
    return __sys_send(s, buf, len, flags);
}

//---------------------------------------------------------------------------
// Socket_WSASend
//
// Hook for WSASend() - overlapped version of send for connected sockets
// This is what .NET TcpClient uses internally
//---------------------------------------------------------------------------

_FX int Socket_WSASend(
    SOCKET                             s,
    LPWSABUF                           lpBuffers,
    DWORD                              dwBufferCount,
    LPDWORD                            lpNumberOfBytesSent,
    DWORD                              dwFlags,
    LPWSAOVERLAPPED                    lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    // DEBUG: Log ALL WSASend() calls when verbose debug is enabled
    if (DNS_FilterEnabled && DNS_RawSocketFilterEnabled && DNS_DebugFlag && lpBuffers && dwBufferCount > 0) {
        LPWSABUF_REAL buffers = (LPWSABUF_REAL)lpBuffers;
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"GLOBAL: WSASend() socket=%p, len=%d, isDns=%d",
            (void*)(ULONG_PTR)s, buffers[0].len, Socket_IsDnsSocket(s) ? 1 : 0);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    // Debug: Log WSASend() calls on DNS sockets
    if (DNS_DebugFlag && Socket_IsDnsSocket(s)) {
        BOOLEAN isTcp = Socket_IsTcpSocket(s);
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"%s DNS: WSASend() called on DNS socket=%p, buffers=%d",
            isTcp ? L"TCP" : L"UDP", (void*)(ULONG_PTR)s, dwBufferCount);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // Only inspect if this is a DNS socket and filtering is enabled
    if (DNS_FilterEnabled && DNS_RawSocketFilterEnabled && Socket_IsDnsSocket(s) && lpBuffers && dwBufferCount > 0) {
        
        // Cast to actual WSABUF structure
        LPWSABUF_REAL buffers = (LPWSABUF_REAL)lpBuffers;
        
        // Check if first buffer has enough data for DNS header
        if (buffers[0].len >= sizeof(DNS_WIRE_HEADER)) {
            const BYTE* buf = (const BYTE*)buffers[0].buf;
            int len = buffers[0].len;
            
            const BYTE* dns_payload = buf;
            int dns_payload_len = len;
            BOOLEAN has_length_prefix = FALSE;
            
            // Check for TCP DNS length prefix (with validation to avoid false positives)
            if (len >= 2 + sizeof(DNS_WIRE_HEADER)) {
                USHORT tcp_length = _ntohs(*(USHORT*)buf);
                if (tcp_length + 2 == len && 
                    tcp_length >= sizeof(DNS_WIRE_HEADER) && 
                    tcp_length <= 512) {  // Reasonable DNS max size
                    
                    // Validate: check if bytes after prefix look like DNS header
                    DNS_WIRE_HEADER* potential_header = (DNS_WIRE_HEADER*)(buf + 2);
                    USHORT flags = _ntohs(potential_header->Flags);
                    USHORT qr = (flags >> 15) & 0x1;
                    
                    // If this looks like a query (QR=0) and has questions, treat as TCP DNS with length prefix
                    if (qr == 0 && _ntohs(potential_header->Questions) > 0) {
                        dns_payload = buf + 2;
                        dns_payload_len = tcp_length;
                        has_length_prefix = TRUE;
                        
                        if (DNS_DebugFlag) {
                            WCHAR msg[256];
                            Sbie_snwprintf(msg, 256, L"TCP DNS: WSASend detected length prefix, payload=%d bytes",
                                dns_payload_len);
                            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                        }
                    }
                }
            }
            
            // Skip length-only sends
            if (len == 2) {
                if (DNS_DebugFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"TCP DNS: WSASend skipping length-only send (len=2)");
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
                return __sys_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
            }
            
            WCHAR domainName[256];
            USHORT qtype = 0;

            // Parse DNS query packet
            if (Socket_ParseDnsQuery(dns_payload, dns_payload_len, domainName, 256, &qtype)) {
                
                // Check if domain matches filter rules
                ULONG domain_len = wcslen(domainName);
                WCHAR* domain_lwr = (WCHAR*)Dll_AllocTemp((domain_len + 4) * sizeof(WCHAR));
                wmemcpy(domain_lwr, domainName, domain_len);
                domain_lwr[domain_len] = L'\0';
                _wcslwr(domain_lwr);

                PATTERN* found = NULL;
                int match_result = Socket_MatchDomainHierarchical(domain_lwr, domain_len, &found);
                
                if (match_result > 0) {
                    
                    // Get auxiliary data containing IP list and type filter
                    PVOID* aux = Pattern_Aux(found);
                    if (!aux || !*aux) {
                        Dll_Free(domain_lwr);
                        return __sys_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
                    }

                    // Certificate required for actual filtering (interception/blocking)
                    extern BOOLEAN DNS_HasValidCertificate;
                    if (!DNS_HasValidCertificate) {
                        // Domain matches filter but no cert - log as passthrough
                        Socket_LogForwarded(L"TCP", domainName, qtype, L"WSASend", s);
                        Dll_Free(domain_lwr);
                        return __sys_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
                    }

                    // Build fake DNS response using centralized helper
                    BYTE response[DNS_RESPONSE_SIZE];
                    int response_len = Socket_HandleDnsQuery(
                        aux, dns_payload, dns_payload_len, qtype, response, DNS_RESPONSE_SIZE, L"TCP DNS: WSASend");
                    
                    // response_len == 0 means "pass through to real DNS" (filter mode, non-filtered query)
                    // response_len < 0 means error
                    // response_len > 0 means we have a fake response to queue
                    
                    if (response_len < 0) {
                        // Error already logged by Socket_HandleDnsQuery
                        if (lpNumberOfBytesSent) *lpNumberOfBytesSent = buffers[0].len;
                        return 0;  // Return success to prevent real send
                    }
                    
                    if (response_len == 0) {
                        // Filter mode + non-A/AAAA query: Pass through to real DNS
                        Socket_LogFilterPassthrough(L"TCP", domainName, qtype, L"WSASend ");
                        // Fall through to call __sys_WSASend - let real DNS handle it
                    }
                    else if (response_len > 0) {
                        // Validate the response before queuing
                        if (!Socket_ValidateDnsResponse(response, response_len)) {
                            if (DNS_TraceFlag) {
                                SbieApi_MonitorPutMsg(MONITOR_DNS, L"TCP DNS: WSASend built response failed validation, dropping");
                            }
                            if (lpNumberOfBytesSent) *lpNumberOfBytesSent = buffers[0].len;
                            return 0;  // Return success to prevent real send
                        }
                        
                        // Get pEntries for logging
                        LIST* pEntries = NULL;
                        DNS_TYPE_FILTER* type_filter = NULL;
                        DNS_ExtractFilterAux(aux, &pEntries, &type_filter);
                        
                        // For TCP DNS: Queue ONLY the DNS payload (no length prefix)
                        // TCP local-response strategy (same as send()):
                        // 1. Client finishes the normal TCP handshake with the DNS server
                        // 2. Client issues WSASend() with [2-byte length][DNS query]
                        // 3. We intercept the payload and keep it local (nothing forwarded upstream)
                        // 4. We queue a fabricated DNS payload (length prefix handled at recv time)
                        // 5. Later recv()/WSARecv() calls read the fake length prefix and payload from our queue
                        
                        if (DNS_DebugFlag) {
                            WCHAR msg[256];
                            Sbie_snwprintf(msg, 256, L"  TCP DNS Debug: WSASend queueing fake response (answered locally, DNS payload only), len=%d bytes",
                                response_len);
                            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                        }
                        
                        // Queue fake response for recv to return
                        Socket_AddFakeResponse(s, response, response_len, NULL);
                        
                        // Log the DNS query activity
                        Socket_LogInterceptedResponse(L"TCP", domainName, qtype, len, response, response_len, s, pEntries, L"WSASend");
                        
                        // Set bytes sent and return success WITHOUT actually sending
                        if (lpNumberOfBytesSent) {
                            *lpNumberOfBytesSent = len;
                        }
                        return 0;  // Success (answered locally)
                    } // end else if (response_len > 0)
                    
                    // If response_len == 0, we fall through here to call __sys_WSASend
                }
                else {
                    // Domain not in filter list - trace allowed queries
                    Socket_LogForwarded(L"TCP", domainName, qtype, L"WSASend", s);
                }
            }
        }
    }

    // Call original WSASend
    return __sys_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

//---------------------------------------------------------------------------
// Socket_sendto
//
// Hook for sendto() - intercepts UDP packets to port 53 (DNS)
//---------------------------------------------------------------------------

_FX int Socket_sendto(
    SOCKET         s,
    const char     *buf,
    int            len,
    int            flags,
    const void     *to,
    int            tolen)
{
    // Only inspect if DNS filtering is enabled and we have a valid destination
    if (DNS_FilterEnabled && DNS_RawSocketFilterEnabled && to && buf && len >= sizeof(DNS_WIRE_HEADER)) {
        
        // Check if destination is DNS port 53
        USHORT destPort = 0;
        USHORT addrFamily = ((struct sockaddr*)to)->sa_family;

        if (addrFamily == AF_INET && tolen >= sizeof(struct sockaddr_in)) {
            destPort = _ntohs(((struct sockaddr_in*)to)->sin_port);
        } 
        else if (addrFamily == AF_INET6 && tolen >= sizeof(struct sockaddr_in6)) {
            destPort = _ntohs(((struct sockaddr_in6*)to)->sin6_port);
        }

        // Port 53 = DNS
        if (destPort == 53) {
            WCHAR domainName[256];
            USHORT qtype = 0;

            // Parse DNS query packet
            if (Socket_ParseDnsQuery((const BYTE*)buf, len, domainName, 256, &qtype)) {
                
                // Check if domain matches filter rules
                ULONG domain_len = wcslen(domainName);
                WCHAR* domain_lwr = (WCHAR*)Dll_AllocTemp((domain_len + 4) * sizeof(WCHAR));
                wmemcpy(domain_lwr, domainName, domain_len);
                domain_lwr[domain_len] = L'\0';
                _wcslwr(domain_lwr);

                PATTERN* found = NULL;
                int match_result = Socket_MatchDomainHierarchical(domain_lwr, domain_len, &found);
                
                if (match_result > 0) {
                    
                    // Get auxiliary data containing IP list and type filter
                    PVOID* aux = Pattern_Aux(found);
                    if (!aux || !*aux) {
                        Dll_Free(domain_lwr);
                        return __sys_sendto(s, buf, len, flags, to, tolen);
                    }

                    // Certificate required for actual filtering (interception/blocking)
                    extern BOOLEAN DNS_HasValidCertificate;
                    if (!DNS_HasValidCertificate) {
                        // Domain matches filter but no cert - log as passthrough
                        Socket_LogForwarded(L"UDP", domainName, qtype, L"sendto", s);
                        Dll_Free(domain_lwr);
                        return __sys_sendto(s, buf, len, flags, to, tolen);
                    }

                    // Build fake DNS response using centralized helper
                    BYTE response[DNS_RESPONSE_SIZE];
                    int response_len = Socket_HandleDnsQuery(
                        aux, (const BYTE*)buf, len, qtype, response, DNS_RESPONSE_SIZE, L"UDP DNS: sendto");
                    
                    // response_len == 0 means "pass through to real DNS" (filter mode, non-filtered query)
                    // response_len < 0 means error
                    // response_len > 0 means we have a fake response to queue
                    
                    if (response_len < 0) {
                        // Error already logged by Socket_HandleDnsQuery
                        return len;  // Return success to prevent real send
                    }
                    
                    if (response_len == 0) {
                        // Filter mode + non-A/AAAA query: Pass through to real DNS
                        Socket_LogFilterPassthrough(L"UDP", domainName, qtype, L"sendto ");
                        // Fall through to call __sys_sendto - let real DNS handle it
                    }
                    else if (response_len > 0) {
                        // Validate the response before queuing
                        if (!Socket_ValidateDnsResponse(response, response_len)) {
                            if (DNS_TraceFlag) {
                                SbieApi_MonitorPutMsg(MONITOR_DNS, L"UDP DNS: sendto built response failed validation, dropping");
                            }
                            return len;  // Return success to prevent real send
                        }
                        
                        // Get pEntries for logging
                        LIST* pEntries = NULL;
                        DNS_TYPE_FILTER* type_filter = NULL;
                        DNS_ExtractFilterAux(aux, &pEntries, &type_filter);
                        
                        // Queue fake response for recv/recvfrom to return
                        Socket_AddFakeResponse(s, response, response_len, to);
                        
                        // Log the interception
                        Socket_LogInterceptedResponse(L"UDP", domainName, qtype, len, response, response_len, s, pEntries, L"sendto");
                        
                        // Return success without actually sending (UDP answered locally)
                        return len;
                    } // end else if (response_len > 0)
                    
                    // If response_len == 0, we fall through here to call __sys_sendto
                }
                else {
                    // Domain not in filter list - trace allowed queries
                    Socket_LogForwarded(L"UDP", domainName, qtype, L"sendto", s);
                }
            }
        }
    }

    // Call original sendto
    return __sys_sendto(s, buf, len, flags, to, tolen);
}

//---------------------------------------------------------------------------
// Socket_WSASendTo
//
// Hook for WSASendTo() - overlapped version of sendto
//---------------------------------------------------------------------------

_FX int Socket_WSASendTo(
    SOCKET                             s,
    LPWSABUF                           lpBuffers,
    DWORD                              dwBufferCount,
    LPDWORD                            lpNumberOfBytesSent,
    DWORD                              dwFlags,
    const void                         *lpTo,
    int                                iTolen,
    LPWSAOVERLAPPED                    lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    // Only inspect if DNS filtering is enabled and we have buffers
    if (DNS_FilterEnabled && DNS_RawSocketFilterEnabled && lpTo && lpBuffers && dwBufferCount > 0) {
        
        // Cast to actual WSABUF structure
        LPWSABUF_REAL buffers = (LPWSABUF_REAL)lpBuffers;
        
        // Check if destination is DNS port 53
        USHORT destPort = 0;
        USHORT addrFamily = ((struct sockaddr*)lpTo)->sa_family;

        if (addrFamily == AF_INET && iTolen >= sizeof(struct sockaddr_in)) {
            destPort = _ntohs(((struct sockaddr_in*)lpTo)->sin_port);
        } 
        else if (addrFamily == AF_INET6 && iTolen >= sizeof(struct sockaddr_in6)) {
            destPort = _ntohs(((struct sockaddr_in6*)lpTo)->sin6_port);
        }

        // Port 53 = DNS
        if (destPort == 53 && buffers[0].len >= sizeof(DNS_WIRE_HEADER)) {
            WCHAR domainName[256];
            USHORT qtype = 0;

            // Parse DNS query packet from first buffer
            if (Socket_ParseDnsQuery((const BYTE*)buffers[0].buf, buffers[0].len, domainName, 256, &qtype)) {
                
                // Check if domain matches filter rules
                ULONG domain_len = wcslen(domainName);
                WCHAR* domain_lwr = (WCHAR*)Dll_AllocTemp((domain_len + 4) * sizeof(WCHAR));
                wmemcpy(domain_lwr, domainName, domain_len);
                domain_lwr[domain_len] = L'\0';
                _wcslwr(domain_lwr);

                PATTERN* found = NULL;
                int match_result = Socket_MatchDomainHierarchical(domain_lwr, domain_len, &found);
                
                if (match_result > 0) {
                    
                    // Get auxiliary data containing IP list and type filter
                    PVOID* aux = Pattern_Aux(found);
                    if (!aux || !*aux) {
                        Dll_Free(domain_lwr);
                        return __sys_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
                    }

                    // Certificate required for actual filtering (interception/blocking)
                    extern BOOLEAN DNS_HasValidCertificate;
                    if (!DNS_HasValidCertificate) {
                        // Domain matches filter but no cert - log as passthrough
                        Socket_LogForwarded(L"UDP", domainName, qtype, L"WSASendTo", s);
                        Dll_Free(domain_lwr);
                        return __sys_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
                    }

                    // Build fake DNS response using centralized helper
                    BYTE response[DNS_RESPONSE_SIZE];
                    int response_len = Socket_HandleDnsQuery(
                        aux, (const BYTE*)buffers[0].buf, buffers[0].len, qtype, response, DNS_RESPONSE_SIZE, L"UDP DNS: WSASendTo");
                    
                    // response_len == 0 means "pass through to real DNS" (filter mode, non-filtered query)
                    // response_len < 0 means error
                    // response_len > 0 means we have a fake response to queue
                    
                    if (response_len < 0) {
                        // Error already logged by Socket_HandleDnsQuery
                        if (lpNumberOfBytesSent) *lpNumberOfBytesSent = buffers[0].len;
                        return 0;  // Return success to prevent real send
                    }
                    
                    if (response_len == 0) {
                        // Filter mode + non-A/AAAA query: Pass through to real DNS
                        Socket_LogFilterPassthrough(L"UDP", domainName, qtype, L"WSASendTo ");
                        // Fall through to call __sys_WSASendTo - let real DNS handle it
                    }
                    else if (response_len > 0) {
                        // Validate the response before queuing
                        if (!Socket_ValidateDnsResponse(response, response_len)) {
                            if (DNS_TraceFlag) {
                                SbieApi_MonitorPutMsg(MONITOR_DNS, L"UDP DNS: WSASendTo built response failed validation, dropping");
                            }
                            if (lpNumberOfBytesSent) *lpNumberOfBytesSent = buffers[0].len;
                            return 0;  // Return success to prevent real send
                        }
                        
                        // Get pEntries for logging
                        LIST* pEntries = NULL;
                        DNS_TYPE_FILTER* type_filter = NULL;
                        DNS_ExtractFilterAux(aux, &pEntries, &type_filter);
                        
                        // Queue fake response for recv/recvfrom to return
                        Socket_AddFakeResponse(s, response, response_len, lpTo);
                        
                        // Log the interception
                        Socket_LogInterceptedResponse(L"UDP", domainName, qtype, buffers[0].len, response, response_len, s, pEntries, L"WSASendTo");
                        
                        // Set bytes sent and return success (answered locally)
                        if (lpNumberOfBytesSent) {
                            *lpNumberOfBytesSent = buffers[0].len;
                        }
                        return 0;  // Success
                    } // end else if (response_len > 0)
                    
                    // If response_len == 0, we fall through here to call __sys_WSASendTo
                }
                else {
                    // Domain not in filter list - trace allowed queries
                    Socket_LogForwarded(L"UDP", domainName, qtype, L"WSASendTo", s);
                }
            }
        }
    }

    // Call original WSASendTo
    return __sys_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
}

//---------------------------------------------------------------------------
// Socket_ParseDnsQuery
//
// Parses a DNS query packet and extracts the domain name.
//
// Returns: TRUE if successfully parsed, FALSE otherwise
//---------------------------------------------------------------------------

_FX BOOLEAN Socket_ParseDnsQuery(
    const BYTE*    packet,
    int            len,
    WCHAR*         domainOut,
    int            domainOutSize,
    USHORT*        qtype)
{
    if (!packet || len < sizeof(DNS_WIRE_HEADER) || !domainOut || domainOutSize < 1)
        return FALSE;

    DNS_WIRE_HEADER* header = (DNS_WIRE_HEADER*)packet;

    // Verify this is a DNS query (QR bit = 0)
    // Flags are in network byte order (big-endian)
    USHORT flags = _ntohs(header->Flags);
    USHORT qr = (flags >> 15) & 0x1;  // Query/Response bit
    
    if (qr != 0) {
        // This is a response, not a query
        return FALSE;
    }

    // Check if we have at least one question
    USHORT questionCount = _ntohs(header->Questions);
    if (questionCount < 1) {
        return FALSE;
    }

    // Parse the first question (domain name starts after header)
    int offset = sizeof(DNS_WIRE_HEADER);
    int nameLen = Socket_DecodeDnsName(packet, len, offset, domainOut, domainOutSize);
    
    if (nameLen <= 0) {
        return FALSE;
    }

    // Update offset to point after the name
    offset += nameLen;

    // Read QTYPE (2 bytes) and QCLASS (2 bytes) after the name
    if (offset + 4 > len) {
        return FALSE;
    }

    // DNS packets use network byte order (big-endian), convert to host byte order
    USHORT queryType = _ntohs(*(USHORT*)(packet + offset));
    if (qtype) {
        *qtype = queryType;
    }

    return TRUE;
}

//---------------------------------------------------------------------------
// Socket_DecodeDnsName
//
// Decodes a DNS name from wire format to Unicode string.
// DNS names use length-prefixed labels (e.g., 3www6google3com0)
//
// Returns: Number of bytes consumed from packet, or -1 on error
//---------------------------------------------------------------------------

_FX int Socket_DecodeDnsName(
    const BYTE*    packet,
    int            packetLen,
    int            offset,
    WCHAR*         nameOut,
    int            nameOutSize)
{
    if (!packet || !nameOut || nameOutSize < 1)
        return -1;
    
    // Input validation: check bounds
    if (offset < 0 || offset >= packetLen)
        return -1;

    int originalOffset = offset;
    int outPos = 0;
    BOOLEAN firstLabel = TRUE;

    while (offset < packetLen) {
        BYTE labelLen = packet[offset];

        // End of name (zero-length label)
        if (labelLen == 0) {
            offset++;
            break;
        }

        // Check for DNS name compression (pointer - top 2 bits set)
        if ((labelLen & 0xC0) == 0xC0) {
            // Name compression not fully supported in this simple parser
            // Just terminate here to avoid infinite loops
            offset += 2;
            break;
        }

        // Check if label length is valid
        if (labelLen > 63 || offset + 1 + labelLen > packetLen) {
            return -1;
        }

        // Add dot separator between labels (except for first label)
        if (!firstLabel) {
            if (outPos + 1 >= nameOutSize)
                return -1;
            nameOut[outPos++] = L'.';
        }
        firstLabel = FALSE;

        // Copy label characters (convert from ANSI to Unicode)
        offset++;
        for (int i = 0; i < labelLen; i++) {
            if (outPos + 1 >= nameOutSize)
                return -1;
            
            BYTE ch = packet[offset++];
            
            // Convert ANSI to Unicode (simple ASCII conversion)
            // DNS labels should be ASCII-compatible
            nameOut[outPos++] = (WCHAR)ch;
        }
    }

    // Null-terminate
    nameOut[outPos] = L'\0';

    // Return number of bytes consumed
    return offset - originalOffset;
}

//---------------------------------------------------------------------------
// Pattern_MatchWildcard
//
// Simple glob-style wildcard matcher: '*' matches any sequence, '?' matches one char
// Returns TRUE if str matches pattern, FALSE otherwise
//---------------------------------------------------------------------------
static BOOLEAN Pattern_MatchWildcard(const WCHAR* pattern, const WCHAR* str) {
    if (!pattern || !str) return FALSE;
    while (*pattern) {
        if (*pattern == L'*') {
            pattern++;
            if (!*pattern) return TRUE; // Trailing * matches all
            while (*str) {
                if (Pattern_MatchWildcard(pattern, str)) return TRUE;
                str++;
            }
            return FALSE;
        } else if (*pattern == L'?') {
            if (!*str) return FALSE;
            pattern++; str++;
        } else {
            if (towlower(*pattern) != towlower(*str)) return FALSE;
            pattern++; str++;
        }
    }
    return *str == 0;
}

//---------------------------------------------------------------------------
// Socket_MatchDomainHierarchical
//
// Matches domain against DNS filter list with hierarchical subdomain fallback.
// Tries exact match first, then walks up subdomain levels with wildcards,
// finally tries catch-all wildcard "*".
//
// Example for "www.sub.example.com":
//   1. Try exact: "www.sub.example.com"
//   2. Try "*.sub.example.com"
//   3. Try "*.example.com"
//   4. Try "*.com"
//   5. Try "*"
//
// Returns: >0 if match found, 0 if no match, <0 on error
//---------------------------------------------------------------------------

_FX int Socket_MatchDomainHierarchical(
    const WCHAR*   domain_lwr,
    ULONG          domain_len,
    PATTERN**      found)
{
    if (!domain_lwr || domain_len == 0 || !found)
        return 0;

    *found = NULL;
    
    // Check if domain is excluded from filtering
    if (DNS_IsExcluded(domain_lwr)) {
        if (DNS_TraceFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"DNS Exclusion (Socket): Domain '%s' matched exclusion list, skipping filter", domain_lwr);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        return 0;  // Return no match - allow normal DNS resolution
    }
    
    int best_level = -1;
    int best_is_exact = 0;
    PATTERN* best_pattern = NULL;
    int match_result = 0;

    // Create local mutable copy for Pattern_MatchPathList (which expects non-const WCHAR*)
    WCHAR* domain_copy = (WCHAR*)Dll_AllocTemp((domain_len + 1) * sizeof(WCHAR));
    if (!domain_copy)
        return 0;
    wmemcpy(domain_copy, domain_lwr, domain_len);
    domain_copy[domain_len] = L'\0';

    // 1. Check for exact match (no '*' or '?')
    PATTERN* pat = (PATTERN*)List_Head(&DNS_FilterList);
    while (pat) {
        const WCHAR* pat_text = Pattern_Source(pat);
        if (!pat_text) { pat = (PATTERN*)List_Next(pat); continue; }
        ULONG pat_len = wcslen(pat_text);
        if (!wcschr(pat_text, L'*') && !wcschr(pat_text, L'?')) {
            if (DNS_DebugFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"  DNS Debug Hierarchical: Comparing domain '%s' to pattern '%s' (len: %lu vs %lu)", domain_lwr, pat_text, domain_len, pat_len);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            if (pat_len == domain_len && _wcsnicmp(pat_text, domain_lwr, domain_len) == 0) {
                // Exact match found, return immediately
                *found = pat;
                if (DNS_DebugFlag) {
                    WCHAR msg[512];
                    Sbie_snwprintf(msg, 512, L"  DNS Debug Hierarchical: Domain '%s' matched exact pattern '%s'", domain_lwr, pat_text);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
                Dll_Free(domain_copy);
                return 1;
            }
        }
        pat = (PATTERN*)List_Next(pat);
    }

    // 2. Check for wildcard matches (mid-pattern wildcards supported)
    pat = (PATTERN*)List_Head(&DNS_FilterList);
    int best_wildcard_len = -1;
    int best_wildcard_count = 1000;
    PATTERN* best_wildcard_pattern = NULL;
    while (pat) {
        const WCHAR* pat_text = Pattern_Source(pat);
        if (!pat_text) { pat = (PATTERN*)List_Next(pat); continue; }
        ULONG pat_len = wcslen(pat_text);
        // Skip global wildcard '*' for now
        if (pat_len == 1 && pat_text[0] == L'*') { pat = (PATTERN*)List_Next(pat); continue; }
        // Only consider patterns with '*' or '?'
        if (wcschr(pat_text, L'*') || wcschr(pat_text, L'?')) {
            if (Pattern_MatchWildcard(pat_text, domain_lwr)) {
                // Prefer the most specific: longest pattern, then fewest wildcards
                int wildcard_count = 0;
                for (const WCHAR* p = pat_text; *p; ++p) if (*p == L'*') wildcard_count++;
                if ((int)pat_len > best_wildcard_len || ((int)pat_len == best_wildcard_len && wildcard_count < best_wildcard_count)) {
                    best_wildcard_pattern = pat;
                    best_wildcard_len = (int)pat_len;
                    best_wildcard_count = wildcard_count;
                }
            }
        }
        pat = (PATTERN*)List_Next(pat);
    }
    if (best_wildcard_pattern) {
        *found = best_wildcard_pattern;
        if (DNS_DebugFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"  DNS Debug Hierarchical: Domain '%s' matched pattern '%s' (mid-wildcard support)", domain_lwr, Pattern_Source(best_wildcard_pattern));
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        Dll_Free(domain_copy);
        return 2;
    }

    // 3. Check for catch-all wildcard "*" (least specific, last resort)
    pat = (PATTERN*)List_Head(&DNS_FilterList);
    while (pat) {
        const WCHAR* pat_text = Pattern_Source(pat);
        if (pat_text && wcslen(pat_text) == 1 && pat_text[0] == L'*') {
            *found = pat;
            if (DNS_DebugFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"  DNS Debug Hierarchical: Domain '%s' matched catch-all pattern '*'", domain_lwr);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            Dll_Free(domain_copy);
            return 3;
        }
        pat = (PATTERN*)List_Next(pat);
    }

    Dll_Free(domain_copy);
    return 0;
}

//---------------------------------------------------------------------------
// Socket_BuildDnsResponse
//
// Builds a fake DNS response packet with configured IP addresses or NXDOMAIN
//
// Returns: Length of response packet, 0 for pass-through, or -1 on error
//---------------------------------------------------------------------------

_FX int Socket_BuildDnsResponse(
    const BYTE*    query,
    int            query_len,
    struct _LIST*  pEntries,
    BOOLEAN        block,
    BYTE*          response,
    int            response_size,
    USHORT         qtype,
    struct _DNS_TYPE_FILTER* type_filter)
{
    if (!query || !response || query_len < sizeof(DNS_WIRE_HEADER) || response_size < 512)
        return -1;

    // qtype is now in host byte order (Socket_ParseDnsQuery converts it)
    USHORT qtype_host = qtype;
    
    // Block mode (no IPs) should block ALL query types
    if (!pEntries) {
        // In block mode, intercept everything regardless of type filter
        block = TRUE;
    } else {
        // Filter mode (with IPs) - check if this type should be filtered
        BOOLEAN should_filter = DNS_IsTypeInFilterList(type_filter, qtype_host);
        
        if (!should_filter) {
            // Type not in filter list - pass to real DNS
            return 0;
        }
        
        // Type is in filter list - check if we can synthesize
        BOOLEAN can_synthesize = DNS_CanSynthesizeResponse(qtype_host);
        
        if (!can_synthesize) {
            // Filter mode but unsupported type (MX/CNAME/etc.) - return NXDOMAIN
            block = TRUE;
        }
    }

    // Copy query to response buffer (up to response_size)
    int copy_len = (query_len < response_size) ? query_len : response_size;
    memcpy(response, query, copy_len);

    DNS_WIRE_HEADER* resp_header = (DNS_WIRE_HEADER*)response;
    
    // Set response flags
    if (block || !pEntries) {
        // NXDOMAIN response (domain doesn't exist OR type blocked)
        resp_header->Flags = _htons(0x8183);  // Response, NXDOMAIN
        resp_header->AnswerRRs = _htons(0);
    } else {
        // Success response
        resp_header->Flags = _htons(0x8180);  // Response, No error, Recursion available
        
        // Count how many IPs we have matching the query type
        // For ANY queries (type 255), return all A + AAAA records
        USHORT answer_count = 0;
        BOOLEAN has_ipv4 = FALSE;
        BOOLEAN has_ipv6 = FALSE;
        BOOLEAN is_any_query = (qtype_host == 255);
        
        if (pEntries) {
            IP_ENTRY* entry = (IP_ENTRY*)List_Head(pEntries);
            while (entry) {
                if ((qtype_host == DNS_TYPE_A || is_any_query) && entry->Type == AF_INET) {
                    answer_count++;
                    has_ipv4 = TRUE;
                } else if ((qtype_host == DNS_TYPE_AAAA || is_any_query) && entry->Type == AF_INET6) {
                    answer_count++;
                    has_ipv6 = TRUE;
                } else if (qtype_host == DNS_TYPE_AAAA && entry->Type == AF_INET && DNS_MapIpv4ToIpv6) {
                    // AAAA query but only IPv4 available - we'll map it (if DnsMapIpv4ToIpv6=y)
                    has_ipv4 = TRUE;
                }
                entry = (IP_ENTRY*)List_Next(entry);
            }
            
            // Fallback: if DnsMapIpv4ToIpv6=y and AAAA query but no IPv6, use IPv4-mapped IPv6
            if (qtype_host == DNS_TYPE_AAAA && DNS_MapIpv4ToIpv6 && !has_ipv6 && has_ipv4) {
                // Count IPv4 addresses to map
                entry = (IP_ENTRY*)List_Head(pEntries);
                while (entry) {
                    if (entry->Type == AF_INET) {
                        answer_count++;
                    }
                    entry = (IP_ENTRY*)List_Next(entry);
                }
            }
        }
        
        resp_header->AnswerRRs = _htons(answer_count);
    }

    // If blocking or no IPs, return just the header
    if (block || !pEntries) {
        return copy_len;
    }

    // Add answer records
    int offset = copy_len;
    IP_ENTRY* entry = (IP_ENTRY*)List_Head(pEntries);
    BOOLEAN is_any_query = (qtype_host == 255);  // Check if this is ANY query
    
    // Check if we need IPv4-to-IPv6 mapping (AAAA query with no IPv6 addresses)
    BOOLEAN need_ipv4_mapping = FALSE;
    BOOLEAN has_native_ipv6 = FALSE;
    
    if (qtype_host == DNS_TYPE_AAAA && DNS_MapIpv4ToIpv6) {
        // Check if we have any native IPv6 addresses
        IP_ENTRY* check = (IP_ENTRY*)List_Head(pEntries);
        while (check) {
            if (check->Type == AF_INET6) {
                has_native_ipv6 = TRUE;
                break;
            }
            check = (IP_ENTRY*)List_Next(check);
        }
        need_ipv4_mapping = !has_native_ipv6;
    }
    
    while (entry) {
        BOOLEAN match = FALSE;
        int rdata_len = 0;
        USHORT record_type = 0;  // Actual type for this record (A or AAAA)
        BYTE ipv6_mapped[16];  // For IPv4-mapped IPv6 addresses
        
        if ((qtype_host == DNS_TYPE_A || is_any_query) && entry->Type == AF_INET) {
            match = TRUE;
            rdata_len = 4;  // IPv4 address
            record_type = DNS_TYPE_A;
        } else if ((qtype_host == DNS_TYPE_AAAA || is_any_query) && entry->Type == AF_INET6) {
            match = TRUE;
            rdata_len = 16;  // IPv6 address
            record_type = DNS_TYPE_AAAA;
        } else if (qtype_host == DNS_TYPE_AAAA && entry->Type == AF_INET && need_ipv4_mapping) {
            // AAAA query but only IPv4 available - create IPv4-mapped IPv6 address (when DnsMapIpv4ToIpv6=y)
            // Format: ::ffff:a.b.c.d (RFC 4291 section 2.5.5.2)
            match = TRUE;
            rdata_len = 16;
            record_type = DNS_TYPE_AAAA;
            
            // Build IPv4-mapped IPv6: first 10 bytes = 0, next 2 bytes = 0xff, last 4 bytes = IPv4
            memset(ipv6_mapped, 0, 10);
            ipv6_mapped[10] = 0xff;
            ipv6_mapped[11] = 0xff;
            memcpy(ipv6_mapped + 12, &entry->IP.Data32[3], 4);
        }
        
        if (match) {
            // Check if we have enough space BEFORE writing (bounds check)
            // Need: sizeof(DNS_RR) + rdata_len bytes, must fit within response_size
            if (offset + (int)sizeof(DNS_RR) + rdata_len > response_size) {
                // Not enough space - stop adding records
                break;
            }
            
            // Build DNS resource record
            DNS_RR* rr = (DNS_RR*)(response + offset);
            
            // Compressed name pointer (0xC00C points to offset 12 - first question name)
            rr->name = _htons(0xC00C);
            rr->type = _htons(record_type);  // Use actual record type (A or AAAA), not query type
            rr->rr_class = _htons(1);  // IN (Internet)
            rr->ttl = _htonl(300);     // 5 minutes TTL
            rr->rdlength = _htons(rdata_len);
            
            offset += sizeof(DNS_RR);
            
            // Copy IP address data
            if (record_type == DNS_TYPE_A && entry->Type == AF_INET) {
                // IPv4: use Data32[3] for the last 32-bit word
                memcpy(response + offset, &entry->IP.Data32[3], 4);
                offset += 4;
            } else if (record_type == DNS_TYPE_AAAA && entry->Type == AF_INET6) {
                // IPv6: use Data array (16 bytes)
                memcpy(response + offset, entry->IP.Data, 16);
                offset += 16;
            } else if (record_type == DNS_TYPE_AAAA && entry->Type == AF_INET && need_ipv4_mapping) {
                // IPv4-mapped IPv6
                memcpy(response + offset, ipv6_mapped, 16);
                offset += 16;
            }
        }
        
        entry = (IP_ENTRY*)List_Next(entry);
    }

    return offset;
}

//---------------------------------------------------------------------------
// Socket_ValidateDnsResponse
//
// Validates a DNS response packet for basic sanity
// Prevents malformed responses from being queued
//
// Returns: TRUE if valid, FALSE otherwise
//---------------------------------------------------------------------------

_FX BOOLEAN Socket_ValidateDnsResponse(
    const BYTE*    response,
    int            len)
{
    if (!response || len < sizeof(DNS_WIRE_HEADER))
        return FALSE;
    
    DNS_WIRE_HEADER* header = (DNS_WIRE_HEADER*)response;
    
    // Basic sanity checks
    USHORT questions = _ntohs(header->Questions);
    USHORT answers = _ntohs(header->AnswerRRs);
    USHORT authority = _ntohs(header->AuthorityRRs);
    USHORT additional = _ntohs(header->AdditionalRRs);
    
    // Reasonable limits (prevent obviously malformed packets)
    if (questions > 10 || answers > 50 || authority > 50 || additional > 50)
        return FALSE;
    
    // Response should have QR bit set (bit 15 of flags)
    USHORT flags = _ntohs(header->Flags);
    USHORT qr = (flags >> 15) & 0x1;
    if (qr != 1)  // Should be 1 for responses
        return FALSE;
    
    return TRUE;
}

//---------------------------------------------------------------------------
// Socket_GetQueueIndex
//
// Hash function for socket handle to queue table index
//---------------------------------------------------------------------------

_FX ULONG Socket_GetQueueIndex(SOCKET s)
{
    return ((ULONG_PTR)s) % RESPONSE_QUEUE_TABLE_SIZE;
}

//---------------------------------------------------------------------------
// Socket_GetResponseQueue
//
// Get or create response queue for a socket (O(1) average case)
//---------------------------------------------------------------------------

_FX SOCKET_RESPONSE_QUEUE* Socket_GetResponseQueue(SOCKET s, BOOLEAN create)
{
    ULONG index = Socket_GetQueueIndex(s);
    
    // Fast path: search collision chain (lock-free read)
    SOCKET_RESPONSE_QUEUE* queue = g_ResponseQueueTable[index];
    while (queue) {
        if (queue->socket == s) {
            return queue;
        }
        queue = queue->next;
    }
    
    if (!create) return NULL;
    
    // Slow path: create new queue (need table lock)
    EnterCriticalSection(&g_ResponseTableLock);
    
    // Double-check (another thread might have created it)
    queue = g_ResponseQueueTable[index];
    while (queue) {
        if (queue->socket == s) {
            LeaveCriticalSection(&g_ResponseTableLock);
            return queue;
        }
        queue = queue->next;
    }
    
    // Allocate new queue
    queue = (SOCKET_RESPONSE_QUEUE*)Dll_Alloc(sizeof(SOCKET_RESPONSE_QUEUE));
    if (queue) {
        queue->socket = s;
        InitializeCriticalSection(&queue->lock);
        queue->head = NULL;
        queue->tail = NULL;
        queue->response_count = 0;
        queue->last_access = GetTickCount();
        
        // Add to head of collision chain
        queue->next = g_ResponseQueueTable[index];
        g_ResponseQueueTable[index] = queue;
    }
    
    LeaveCriticalSection(&g_ResponseTableLock);
    return queue;
}

//---------------------------------------------------------------------------
// Socket_CleanupResponseQueue
//
// Remove and free a response queue (called when socket closes or times out)
//---------------------------------------------------------------------------

_FX void Socket_CleanupResponseQueue(SOCKET s)
{
    ULONG index = Socket_GetQueueIndex(s);
    
    EnterCriticalSection(&g_ResponseTableLock);
    
    SOCKET_RESPONSE_QUEUE** pprev = &g_ResponseQueueTable[index];
    SOCKET_RESPONSE_QUEUE* queue = g_ResponseQueueTable[index];
    
    while (queue) {
        if (queue->socket == s) {
            // Remove from collision chain
            *pprev = queue->next;
            
            // Free all pending responses
            EnterCriticalSection(&queue->lock);
            FAKE_RESPONSE* resp = queue->head;
            while (resp) {
                FAKE_RESPONSE* next = resp->next;
                Dll_Free(resp);
                resp = next;
            }
            LeaveCriticalSection(&queue->lock);
            
            // Free queue
            DeleteCriticalSection(&queue->lock);
            Dll_Free(queue);
            break;
        }
        
        pprev = &queue->next;
        queue = queue->next;
    }
    
    LeaveCriticalSection(&g_ResponseTableLock);
}

//---------------------------------------------------------------------------
// Socket_AddFakeResponse
//
// Adds a fake DNS response to the per-socket FIFO queue (O(1))
//---------------------------------------------------------------------------

_FX void Socket_AddFakeResponse(
    SOCKET         s,
    const BYTE*    response,
    int            response_len,
    const void*    to)
{
    if (!response || response_len <= 0 || response_len > 512)
        return;

    // Get or create queue for this socket
    SOCKET_RESPONSE_QUEUE* queue = Socket_GetResponseQueue(s, TRUE);
    if (!queue) return;

    // Allocate new response entry
    FAKE_RESPONSE* new_resp = (FAKE_RESPONSE*)Dll_Alloc(sizeof(FAKE_RESPONSE));
    if (!new_resp) {
        return;
    }

    // Fill in response data
    memcpy(new_resp->response, response, response_len);
    new_resp->response_len = response_len;
    new_resp->consumed = 0;
    new_resp->timestamp = GetTickCount();
    new_resp->next = NULL;  // FIFO: new items go to tail
    
    // Detect TCP vs UDP: if 'to' is NULL, this is TCP (connected socket)
    new_resp->is_tcp = (to == NULL);
    
    if (new_resp->is_tcp) {
        // TCP: Add 2-byte length prefix before DNS payload
        USHORT tcp_len = _htons(response_len);
        memcpy(new_resp->length_prefix, &tcp_len, 2);
        new_resp->total_len = 2 + response_len;  // Length prefix + payload
        new_resp->skip_length_prefix = FALSE;    // Will be determined on first recv()
    } else {
        // UDP: No length prefix, just payload
        new_resp->total_len = response_len;
        new_resp->skip_length_prefix = FALSE;    // N/A for UDP
    }
    
    // Set source address with port 0 (Win11 compatibility - OS handles port assignment)
    if (to) {
        memcpy(&new_resp->from_addr, to, sizeof(struct sockaddr_in));
        new_resp->from_addr.sin_port = 0;
    } else {
        memset(&new_resp->from_addr, 0, sizeof(struct sockaddr_in));
        new_resp->from_addr.sin_family = AF_INET;
        new_resp->from_addr.sin_port = 0;
    }

    // Add to FIFO tail (per-socket lock, not global)
    EnterCriticalSection(&queue->lock);
    
    // Clean up old responses (>FAKE_RESPONSE_TIMEOUT_MS old) before adding new one
    DWORD now = GetTickCount();
    FAKE_RESPONSE** pprev = &queue->head;
    FAKE_RESPONSE* cur = queue->head;
    
    while (cur) {
        FAKE_RESPONSE* next = cur->next;
        
        if (now - cur->timestamp > FAKE_RESPONSE_TIMEOUT_MS) {
            // Remove old entry
            *pprev = next;
            if (queue->tail == cur) {
                queue->tail = NULL;  // Queue now empty
            }
            queue->response_count--;
            Dll_Free(cur);
        } else {
            pprev = &cur->next;
        }
        
        cur = next;
    }
    
    // Enforce maximum response limit to prevent resource exhaustion
    if (queue->response_count >= MAX_FAKE_RESPONSES_PER_SOCKET) {
        // Remove oldest response to make room
        FAKE_RESPONSE* oldest = queue->head;
        if (oldest) {
            queue->head = oldest->next;
            if (!queue->head) {
                queue->tail = NULL;
            }
            queue->response_count--;
            Dll_Free(oldest);
            
            if (DNS_TraceFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"DNS Filter: Queue limit reached for socket=%p, dropped oldest response",
                    (void*)(ULONG_PTR)s);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
        }
    }
    
    // Append to tail (FIFO)
    if (queue->tail) {
        queue->tail->next = new_resp;
        queue->tail = new_resp;
    } else {
        // Queue was empty
        queue->head = new_resp;
        queue->tail = new_resp;
    }
    
    queue->response_count++;
    queue->last_access = now;
    
    LeaveCriticalSection(&queue->lock);
}

//---------------------------------------------------------------------------
// Socket_HasFakeResponse
//
// Check if a pending fake response exists for this socket (O(1))
//---------------------------------------------------------------------------

_FX BOOLEAN Socket_HasFakeResponse(SOCKET s)
{
    SOCKET_RESPONSE_QUEUE* queue = Socket_GetResponseQueue(s, FALSE);
    if (!queue) return FALSE;
    
    // Lock-free read of head pointer (safe for NULL check on most architectures)
    // For absolute safety, we could use per-queue lock, but this is fast path
    return (queue->head != NULL);
}

//---------------------------------------------------------------------------
// Socket_GetFakeResponse
//
// Retrieve and consume a fake DNS response from the queue (with TCP stream fragmentation)
// Returns data incrementally, matching the requested buffer size
// For TCP: 
//   - If first recv() requests 2 bytes: Return length prefix, then payload in subsequent calls
//   - If first recv() requests large buffer: Skip length prefix, return payload only (nslookup without -vc)
// For UDP: Returns only DNS payload
//---------------------------------------------------------------------------

_FX int Socket_GetFakeResponse(
    SOCKET   s,
    char     *buf,
    int      len,
    void     *from,
    int      *fromlen)
{
    SOCKET_RESPONSE_QUEUE* queue = Socket_GetResponseQueue(s, FALSE);
    if (!queue) return -1;
    
    int bytes_copied = -1;

    EnterCriticalSection(&queue->lock);

    FAKE_RESPONSE* cur = queue->head;  // FIFO: always process head
    
    if (cur) {
        // On first recv() for TCP, determine if we should skip length prefix
        if (cur->is_tcp && cur->consumed == 0) {
            if (len == 2) {
                // App is explicitly reading 2 bytes - it expects length prefix
                cur->skip_length_prefix = FALSE;
            } else if (len >= cur->response_len) {
                // App is reading with large buffer - skip length prefix (nslookup without -vc)
                cur->skip_length_prefix = TRUE;
                cur->total_len = cur->response_len;  // Adjust total length to skip prefix
                
                if (DNS_DebugFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"TCP DNS: Large recv(%d), skipping length prefix, returning raw DNS payload",
                        len);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
            }
        }
        
        // Calculate remaining bytes in this response
        int remaining = cur->total_len - cur->consumed;
        
        if (remaining > 0) {
            // Copy min(requested, remaining) bytes from current offset
            int copy_len = (remaining < len) ? remaining : len;
            
            // Determine source buffer based on current offset and skip_length_prefix flag
            if (cur->is_tcp && !cur->skip_length_prefix && cur->consumed < 2) {
                // Still reading from length prefix
                int prefix_remaining = 2 - cur->consumed;
                int from_prefix = (copy_len < prefix_remaining) ? copy_len : prefix_remaining;
                
                // Copy from length prefix
                memcpy(buf, cur->length_prefix + cur->consumed, from_prefix);
                
                // If we need more data and length prefix is exhausted, continue with payload
                if (copy_len > from_prefix) {
                    int from_payload = copy_len - from_prefix;
                    memcpy(buf + from_prefix, cur->response, from_payload);
                }
            } else {
                // Reading from DNS payload
                int payload_offset;
                if (cur->is_tcp && !cur->skip_length_prefix) {
                    payload_offset = cur->consumed - 2;  // Already consumed length prefix
                } else {
                    payload_offset = cur->consumed;  // No length prefix or skipped
                }
                memcpy(buf, cur->response + payload_offset, copy_len);
            }
            
            bytes_copied = copy_len;
            
            // Advance consumed offset
            cur->consumed += copy_len;
            
            // Copy source address if requested (for UDP, or TCP if app asks for it)
            if (from && fromlen) {
                int addr_copy_len = (*fromlen < sizeof(struct sockaddr_in)) ? *fromlen : sizeof(struct sockaddr_in);
                memcpy(from, &cur->from_addr, addr_copy_len);
                *fromlen = sizeof(struct sockaddr_in);
            }
            
            // If fully consumed, remove from head (FIFO dequeue)
            if (cur->consumed >= cur->total_len) {
                queue->head = cur->next;
                if (!queue->head) {
                    queue->tail = NULL;  // Queue now empty
                }
                queue->response_count--;
                
                if (DNS_DebugFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"%s DNS: Fake response fully consumed (%d bytes total, %s), socket=%p removed",
                        cur->is_tcp ? L"TCP" : L"UDP", cur->total_len, 
                        (cur->is_tcp && cur->skip_length_prefix) ? L"no length prefix" : L"with length prefix",
                        (void*)(ULONG_PTR)s);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
                
                Dll_Free(cur);
            }
        }
    }

    LeaveCriticalSection(&queue->lock);

    return bytes_copied;
}

//---------------------------------------------------------------------------
// Socket_recv
//
// Hook for recv() - returns fake DNS responses if available
// Fragmentation is handled automatically by Socket_GetFakeResponse
//---------------------------------------------------------------------------

_FX int Socket_recv(
    SOCKET   s,
    char     *buf,
    int      len,
    int      flags)
{
    // DEBUG: Log ALL recv() calls when verbose debug is enabled
    if (DNS_FilterEnabled && DNS_RawSocketFilterEnabled && DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"GLOBAL RECV: socket=%p, len=%d, isDns=%d, hasFake=%d",
            (void*)(ULONG_PTR)s, len, Socket_IsDnsSocket(s) ? 1 : 0, Socket_HasFakeResponse(s) ? 1 : 0);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // Check for pending fake response
    if (Socket_HasFakeResponse(s)) {
        // Return data from fake response (handles fragmentation automatically)
        int result = Socket_GetFakeResponse(s, buf, len, NULL, NULL);
        if (result > 0) {
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"  TCP DNS Debug: Returned %d bytes from fake response, socket=%p",
                    result, (void*)(ULONG_PTR)s);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            return result;
        }
    }

    // No fake response - pass through to real recv
    return __sys_recv(s, buf, len, flags);
}

//---------------------------------------------------------------------------
// Socket_recvfrom
//
// Hook for recvfrom() - returns fake DNS responses if available
//---------------------------------------------------------------------------

_FX int Socket_recvfrom(
    SOCKET   s,
    char     *buf,
    int      len,
    int      flags,
    void     *from,
    int      *fromlen)
{
    // Check for pending fake response
    if (Socket_HasFakeResponse(s)) {
        int result = Socket_GetFakeResponse(s, buf, len, from, fromlen);
        if (result > 0) {
            // Verbose debug logging only
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"  Raw Socket Debug: Delivered fake response (recvfrom), socket=%p, len=%d",
                    (void*)(ULONG_PTR)s, result);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            return result;
        }
    }

    // No fake response - pass through to real recvfrom
    return __sys_recvfrom(s, buf, len, flags, from, fromlen);
}

//---------------------------------------------------------------------------
// Socket_select
//
// Hook for select() - makes DNS sockets with fake responses appear readable
// This is critical for nslookup and other tools that use select() to wait
// for data before calling recv().
//---------------------------------------------------------------------------

_FX int Socket_select(
    int            nfds,
    void           *readfds,
    void           *writefds,
    void           *exceptfds,
    const void     *timeout)
{
    // Cast void* parameters to proper types
    fd_set *readfds_typed = (fd_set*)readfds;
    fd_set *writefds_typed = (fd_set*)writefds;
    fd_set *exceptfds_typed = (fd_set*)exceptfds;
    const struct timeval *timeout_typed = (const struct timeval*)timeout;
    
    // If DNS filtering is not enabled, pass through
    if (!DNS_FilterEnabled || !DNS_RawSocketFilterEnabled || !readfds_typed) {
        return __sys_select(nfds, readfds, writefds, exceptfds, timeout);
    }

    // Check if any of the sockets in readfds have fake responses queued
    BOOLEAN has_fake = FALSE;
    
    // fd_set is a bitmap of sockets - we need to check each one
    // Note: fd_set structure varies, but we can iterate through sockets
    for (int i = 0; i < (int)readfds_typed->fd_count; i++) {
        SOCKET s = readfds_typed->fd_array[i];
        if (Socket_HasFakeResponse(s)) {
            has_fake = TRUE;
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"TCP DNS: select() found socket=%p with fake response, making it readable",
                    (void*)(ULONG_PTR)s);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            break;
        }
    }

    // If we have fake responses, return immediately to unblock the caller
    if (has_fake) {
        // Call select with zero timeout to get current state
        struct timeval zero_timeout = {0, 0};
        int result = __sys_select(nfds, readfds, writefds, exceptfds, &zero_timeout);
        
        // Now add our fake-response sockets to readfds
        for (int i = 0; i < (int)readfds_typed->fd_count; i++) {
            SOCKET s = readfds_typed->fd_array[i];
            if (Socket_HasFakeResponse(s)) {
                // Socket is already in the set, just ensure it's marked
                // fd_set operations are done via FD_SET macro, but we already have it in the array
                if (DNS_DebugFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"TCP DNS: select() marking socket=%p as readable (has fake response)",
                        (void*)(ULONG_PTR)s);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
            }
        }
        
        // Return > 0 to indicate sockets are ready
        return (result >= 0) ? (result > 0 ? result : 1) : result;
    }

    // No fake responses - call original select
    return __sys_select(nfds, readfds, writefds, exceptfds, timeout);
}

//---------------------------------------------------------------------------
// Socket_getpeername
//
// Hook for getpeername() - returns stored DNS server address for locally-answered sockets
// This allows applications to inspect the "peer" address even though we intercept
// the connection and never actually connect to the DNS server
//---------------------------------------------------------------------------

_FX int Socket_getpeername(
    SOCKET         s,
    void           *name,
    int            *namelen)
{
    // Check if this is a DNS socket with a stored server address
    if (DNS_FilterEnabled && DNS_RawSocketFilterEnabled && Socket_IsDnsSocket(s) && name && namelen) {
        ULONG index = ((ULONG_PTR)s) % DNS_SOCKET_TABLE_SIZE;
        
        // If we have a stored DNS server address, return it
        if (g_DnsServerAddrLens[index] > 0) {
            int copy_len = (*namelen < g_DnsServerAddrLens[index]) ? *namelen : g_DnsServerAddrLens[index];
            memcpy(name, g_DnsServerAddrs[index], copy_len);
            *namelen = g_DnsServerAddrLens[index];
            
            if (DNS_TraceFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"TCP DNS: getpeername() returned stored DNS server address for socket=%p",
                    (void*)(ULONG_PTR)s);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            
            return 0;  // Success
        }
    }
    
    // Not a DNS socket or no stored address - pass through to real getpeername
    return __sys_getpeername(s, name, namelen);
}

