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
//   - Matches against NetworkDnsFilter rules
//   - Blocks filtered queries by returning WSAEACCES
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

//---------------------------------------------------------------------------
// WSABUF Definition
//---------------------------------------------------------------------------

typedef struct _WSABUF_REAL {
    ULONG len;
    CHAR FAR *buf;
} WSABUF_REAL, *LPWSABUF_REAL;

//---------------------------------------------------------------------------
// DNS Packet Structure (RFC 1035)
//---------------------------------------------------------------------------

#pragma pack(push, 1)
typedef struct _DNS_HEADER {
    USHORT TransactionID;
    USHORT Flags;
    USHORT Questions;
    USHORT AnswerRRs;
    USHORT AuthorityRRs;
    USHORT AdditionalRRs;
} DNS_HEADER;
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

#define DNS_TYPE_A     1
#define DNS_TYPE_AAAA  28

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

//---------------------------------------------------------------------------
// External Variables (from dns_filter.c)
//---------------------------------------------------------------------------

extern LIST DNS_FilterList;          // Shared DNS filter list
extern BOOLEAN DNS_FilterEnabled;    // DNS filtering enabled flag
extern BOOLEAN DNS_TraceFlag;        // DNS trace logging flag

//---------------------------------------------------------------------------
// Local Variables
//---------------------------------------------------------------------------

static BOOLEAN DNS_RawSocketFilterEnabled = FALSE;  // Raw socket filtering enabled (default: FALSE)
static BOOLEAN DNS_DebugFlag = FALSE;  // Verbose debug logging (requires DnsTrace + DnsDebug)

//---------------------------------------------------------------------------
// IP Entry Structure (from dns_filter.c)
//---------------------------------------------------------------------------

typedef struct _IP_ENTRY {
    LIST_ELEM list_elem;
    USHORT Type;
    IP_ADDRESS IP;
} IP_ENTRY;

//---------------------------------------------------------------------------
// DNS Connection Tracking
//---------------------------------------------------------------------------

// Track sockets connected to DNS servers (port 53)
static BOOLEAN Socket_IsDnsSocket(SOCKET s);
void Socket_MarkDnsSocket(SOCKET s, BOOLEAN isDns);  // Non-static: called from net.c

// Simple hash table for tracking DNS sockets
#define DNS_SOCKET_TABLE_SIZE 256
static SOCKET g_DnsSockets[DNS_SOCKET_TABLE_SIZE];
static BOOLEAN g_DnsSocketFlags[DNS_SOCKET_TABLE_SIZE];

// Store DNS server addresses for getpeername() support
// Stores the address the socket connected to (for zero-network spoofing)
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

// select/poll support for zero-network TCP DNS (P_select is defined in wsa_defs.h)
static P_select __sys_select = NULL;

//---------------------------------------------------------------------------
// Forward Declarations
//---------------------------------------------------------------------------

// External utility functions (from dns_filter.c / net.c)
void WSA_DumpIP(ADDRESS_FAMILY af, IP_ADDRESS* pIP, wchar_t* pStr);

BOOLEAN Socket_GetRawDnsFilterEnabled();  // Non-static: called from net.c

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

static BOOLEAN Socket_ParseDnsQuery(
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

// Fake response helpers
static int Socket_BuildDnsResponse(
    const BYTE*    query,
    int            query_len,
    LIST*          pEntries,
    BOOLEAN        block,
    BYTE*          response,
    int            response_size,
    USHORT         qtype);

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
// Socket_GetRawDnsFilterEnabled
//
// Query the FilterRawDns setting to control raw socket DNS filtering
// Default: FALSE (disabled by default)
//---------------------------------------------------------------------------

_FX BOOLEAN Socket_GetRawDnsFilterEnabled()
{
    // Query FilterRawDns with per-process matching support
    // Default: FALSE (disabled by default)
    return Config_GetSettingsForImageName_bool(L"FilterRawDns", FALSE);
}

//---------------------------------------------------------------------------
// Socket_InitHooks
//---------------------------------------------------------------------------

_FX BOOLEAN Socket_InitHooks(HMODULE module)
{
    P_connect connect;
    P_WSAConnect WSAConnect;
    P_send send;
    P_sendto sendto;
    P_WSASend WSASend;
    P_WSASendTo WSASendTo;
    P_recv recv;
    P_recvfrom recvfrom;

    // Load FilterRawDns setting
    DNS_RawSocketFilterEnabled = Socket_GetRawDnsFilterEnabled();

    // If raw DNS filtering is disabled, skip hooking entirely
    if (!DNS_RawSocketFilterEnabled) {
        return TRUE;
    }

    // Load DnsDebug setting for verbose logging (only effective if DnsTrace is also set)
    WCHAR wsDebugOptions[4];
    if (SbieApi_QueryConf(NULL, L"DnsDebug", 0, wsDebugOptions, sizeof(wsDebugOptions)) == STATUS_SUCCESS && wsDebugOptions[0] != L'\0')
        DNS_DebugFlag = TRUE;

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

    // Hook getpeername (to return DNS server address for zero-network sockets)
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

        if (addrFamily == AF_INET && namelen >= sizeof(struct sockaddr_in)) {
            destPort = _ntohs(((struct sockaddr_in*)name)->sin_port);
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"TCP: connect() called, AF_INET, port=%d, socket=%p",
                destPort, (void*)(ULONG_PTR)s);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        else if (addrFamily == AF_INET6 && namelen >= sizeof(struct sockaddr_in6)) {
            destPort = _ntohs(((struct sockaddr_in6*)name)->sin6_port);
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"TCP: connect() called, AF_INET6, port=%d, socket=%p",
                destPort, (void*)(ULONG_PTR)s);
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
            
            // Log DNS connection detection
            if (DNS_TraceFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"TCP DNS: Connection detected to port 53, socket=%p marked as DNS",
                    (void*)(ULONG_PTR)s);
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

        if (addrFamily == AF_INET && namelen >= sizeof(struct sockaddr_in)) {
            destPort = _ntohs(((struct sockaddr_in*)name)->sin_port);
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"TCP: WSAConnect() called, AF_INET, port=%d, socket=%p",
                destPort, (void*)(ULONG_PTR)s);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        else if (addrFamily == AF_INET6 && namelen >= sizeof(struct sockaddr_in6)) {
            destPort = _ntohs(((struct sockaddr_in6*)name)->sin6_port);
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"TCP: WSAConnect() called, AF_INET6, port=%d, socket=%p",
                destPort, (void*)(ULONG_PTR)s);
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
            
            // Log DNS connection detection
            if (DNS_TraceFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"TCP DNS: WSAConnect detected port 53, socket=%p marked as DNS",
                    (void*)(ULONG_PTR)s);
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
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"TCP DNS: send() called on DNS socket=%p, len=%d",
            (void*)(ULONG_PTR)s, len);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // Only inspect if this is a DNS socket and filtering is enabled
    // Minimum check: at least enough for DNS header (with or without TCP length prefix)
    if (DNS_FilterEnabled && DNS_RawSocketFilterEnabled && Socket_IsDnsSocket(s) && buf && len >= sizeof(DNS_HEADER)) {
        
        // TCP DNS packets MAY have a 2-byte length prefix before the DNS payload
        // However, many implementations send the length and payload in separate send() calls
        // So we need to handle three cases:
        // 1. Length prefix + DNS payload together (len >= DNS_HEADER + 2)
        // 2. DNS payload only (len >= DNS_HEADER, starts with valid DNS header)
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
        if (len >= 2 + sizeof(DNS_HEADER)) {
            USHORT tcp_length = _ntohs(*(USHORT*)buf);
            // If the length prefix matches (payload = total - 2), this is TCP DNS format
            if (tcp_length + 2 == len && 
                tcp_length >= sizeof(DNS_HEADER) && 
                tcp_length <= 512) {  // Reasonable DNS max size
                
                // Additional validation: check if bytes after prefix look like DNS header
                DNS_HEADER* potential_header = (DNS_HEADER*)(buf + 2);
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
            
            // Check if domain matches filter rules
            ULONG domain_len = wcslen(domainName);
            WCHAR* domain_lwr = (WCHAR*)Dll_AllocTemp((domain_len + 4) * sizeof(WCHAR));
            wmemcpy(domain_lwr, domainName, domain_len);
            domain_lwr[domain_len] = L'\0';
            _wcslwr(domain_lwr);

            PATTERN* found = NULL;
            if (Pattern_MatchPathList(domain_lwr, domain_len, &DNS_FilterList, NULL, NULL, NULL, &found) > 0) {
                
                // Check if an IP address is defined for this domain
                PVOID* aux = Pattern_Aux(found);
                BOOLEAN hasIP = (aux && *aux != NULL);
                LIST* pEntries = hasIP ? (LIST*)*aux : NULL;
                
                // Build fake DNS response
                BYTE response[512];
                int response_len = Socket_BuildDnsResponse(
                    dns_payload, dns_payload_len, pEntries, !hasIP, response, 512, qtype);
                
                if (response_len > 0) {
                    // Validate the response before queuing
                    if (!Socket_ValidateDnsResponse(response, response_len)) {
                        if (DNS_TraceFlag) {
                            SbieApi_MonitorPutMsg(MONITOR_DNS, L"TCP DNS: Built response failed validation, dropping");
                        }
                        return len;  // Still return success to prevent real send
                    }
                    
                    // For TCP DNS: Queue ONLY the DNS payload (no length prefix)
                    // TCP zero-network strategy:
                    // 1. Client sends: [2-byte length][DNS query]
                    // 2. We intercept send() and DON'T send to server (zero-network)
                    // 3. We queue fake response (DNS payload only, no length prefix)
                    // 4. Client reads length prefix → we return success with fake length
                    // 5. Client reads DNS payload → we return our fake response
                    
                    if (DNS_TraceFlag) {
                        WCHAR msg[256];
                        Sbie_snwprintf(msg, 256, L"TCP DNS: Queueing fake response (ZERO-NETWORK, DNS payload only), len=%d bytes",
                            response_len);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                    }
                    
                    // Queue fake response for recv/recvfrom to return
                    Socket_AddFakeResponse(s, response, response_len, NULL);
                    
                    // ZERO-NETWORK: Return success WITHOUT actually sending
                    // The socket will appear to have sent data, but nothing goes to the network
                    // When client calls recv(), we'll return our fake response
                    
                    // Log the interception with detailed diagnostics
                    if (DNS_TraceFlag) {
                        WCHAR msg[512];
                        if (hasIP) {
                            Sbie_snwprintf(msg, 512, L"TCP DNS: %s (Type: %s) - ZERO-NETWORK (len=%d), FAKE RESPONSE QUEUED (len=%d), socket=%p",
                                domainName,
                                (qtype == 0x1C00) ? L"AAAA" : (qtype == 0x0100) ? L"A" : L"OTHER",
                                len, response_len, (void*)(ULONG_PTR)s);
                            
                            // Log IP addresses
                            if (pEntries) {
                                IP_ENTRY* entry = (IP_ENTRY*)List_Head(pEntries);
                                while (entry) {
                                    WSA_DumpIP(entry->Type, &entry->IP, msg);
                                    entry = (IP_ENTRY*)List_Next(entry);
                                }
                            }
                            
                            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                        } else {
                            Sbie_snwprintf(msg, 512, L"TCP DNS: %s (Type: %s) - ZERO-NETWORK (len=%d), NXDOMAIN QUEUED (len=%d), socket=%p",
                                domainName,
                                (qtype == 0x1C00) ? L"AAAA" : (qtype == 0x0100) ? L"A" : L"OTHER",
                                len, response_len, (void*)(ULONG_PTR)s);
                            SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
                        }
                    }
                    
                    // Return success - client thinks data was sent
                    return len;
                }
            }
            else {
                // Domain not in filter list - trace allowed queries
                if (DNS_TraceFlag) {
                    WCHAR msg[512];
                    Sbie_snwprintf(msg, 512, L"Raw DNS Query Forwarded to Real Server (send): %s (Type: %s, Port: 53, Socket: %p)",
                        domainName,
                        (qtype == 0x1C00) ? L"AAAA" : (qtype == 0x0100) ? L"A" : L"OTHER",
                        (void*)(ULONG_PTR)s);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
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
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"TCP DNS: WSASend() called on DNS socket=%p, buffers=%d",
            (void*)(ULONG_PTR)s, dwBufferCount);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // Only inspect if this is a DNS socket and filtering is enabled
    if (DNS_FilterEnabled && DNS_RawSocketFilterEnabled && Socket_IsDnsSocket(s) && lpBuffers && dwBufferCount > 0) {
        
        // Cast to actual WSABUF structure
        LPWSABUF_REAL buffers = (LPWSABUF_REAL)lpBuffers;
        
        // Check if first buffer has enough data for DNS header
        if (buffers[0].len >= sizeof(DNS_HEADER)) {
            const BYTE* buf = (const BYTE*)buffers[0].buf;
            int len = buffers[0].len;
            
            const BYTE* dns_payload = buf;
            int dns_payload_len = len;
            BOOLEAN has_length_prefix = FALSE;
            
            // Check for TCP DNS length prefix (with validation to avoid false positives)
            if (len >= 2 + sizeof(DNS_HEADER)) {
                USHORT tcp_length = _ntohs(*(USHORT*)buf);
                if (tcp_length + 2 == len && 
                    tcp_length >= sizeof(DNS_HEADER) && 
                    tcp_length <= 512) {  // Reasonable DNS max size
                    
                    // Validate: check if bytes after prefix look like DNS header
                    DNS_HEADER* potential_header = (DNS_HEADER*)(buf + 2);
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
                if (Pattern_MatchPathList(domain_lwr, domain_len, &DNS_FilterList, NULL, NULL, NULL, &found) > 0) {
                    
                    // Check if an IP address is defined for this domain
                    PVOID* aux = Pattern_Aux(found);
                    BOOLEAN hasIP = (aux && *aux != NULL);
                    LIST* pEntries = hasIP ? (LIST*)*aux : NULL;
                    
                    // Build fake DNS response
                    BYTE response[512];
                    int response_len = Socket_BuildDnsResponse(
                        dns_payload, dns_payload_len, pEntries, !hasIP, response, 512, qtype);
                    
                    if (response_len > 0) {
                        // Validate the response before queuing
                        if (!Socket_ValidateDnsResponse(response, response_len)) {
                            if (DNS_TraceFlag) {
                                SbieApi_MonitorPutMsg(MONITOR_DNS, L"TCP DNS: WSASend built response failed validation, dropping");
                            }
                            if (lpNumberOfBytesSent) *lpNumberOfBytesSent = buffers[0].len;
                            return 0;  // Return success to prevent real send
                        }
                        
                        // For TCP DNS: Queue ONLY the DNS payload (no length prefix)
                        // TCP zero-network strategy (same as send())
                        
                        if (DNS_TraceFlag) {
                            WCHAR msg[256];
                            Sbie_snwprintf(msg, 256, L"TCP DNS: WSASend queueing fake response (ZERO-NETWORK, DNS payload only), len=%d bytes",
                                response_len);
                            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                        }
                        
                        // Queue fake response for recv to return
                        Socket_AddFakeResponse(s, response, response_len, NULL);
                        
                        // Log the DNS query activity
                        if (DNS_TraceFlag) {
                            WCHAR msg[512];
                            if (hasIP) {
                                Sbie_snwprintf(msg, 512, L"TCP DNS: %s (Type: %s) - ZERO-NETWORK (len=%d), FAKE RESPONSE QUEUED (len=%d) (WSASend)",
                                    domainName,
                                    (qtype == 0x1C00) ? L"AAAA" : (qtype == 0x0100) ? L"A" : L"OTHER",
                                    len, response_len);
                                
                                // Log IP addresses
                                if (pEntries) {
                                    IP_ENTRY* entry = (IP_ENTRY*)List_Head(pEntries);
                                    while (entry) {
                                        WSA_DumpIP(entry->Type, &entry->IP, msg);
                                        entry = (IP_ENTRY*)List_Next(entry);
                                    }
                                }
                            } else {
                                Sbie_snwprintf(msg, 512, L"TCP DNS: %s (Type: %s) - ZERO-NETWORK, NXDOMAIN queued (WSASend)",
                                    domainName,
                                    (qtype == 0x1C00) ? L"AAAA" : (qtype == 0x0100) ? L"A" : L"OTHER");
                            }
                            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                        }
                        
                        // Set bytes sent and return success WITHOUT actually sending
                        if (lpNumberOfBytesSent) {
                            *lpNumberOfBytesSent = len;
                        }
                        return 0;  // Success (zero-network)
                    }
                }
                else {
                    // Domain not in filter list - trace allowed queries
                    if (DNS_TraceFlag) {
                        WCHAR msg[512];
                        Sbie_snwprintf(msg, 512, L"TCP DNS: Forwarded to Real Server (WSASend): %s (Type: %s, Socket: %p)",
                            domainName,
                            (qtype == 0x1C00) ? L"AAAA" : (qtype == 0x0100) ? L"A" : L"OTHER",
                            (void*)(ULONG_PTR)s);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                    }
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
    if (DNS_FilterEnabled && DNS_RawSocketFilterEnabled && to && buf && len >= sizeof(DNS_HEADER)) {
        
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
                if (Pattern_MatchPathList(domain_lwr, domain_len, &DNS_FilterList, NULL, NULL, NULL, &found) > 0) {
                    
                    // Check if an IP address is defined for this domain
                    PVOID* aux = Pattern_Aux(found);
                    BOOLEAN hasIP = (aux && *aux != NULL);
                    LIST* pEntries = hasIP ? (LIST*)*aux : NULL;
                    
                    // Build fake DNS response
                    BYTE response[512];
                    int response_len = Socket_BuildDnsResponse(
                        (const BYTE*)buf, len, pEntries, !hasIP, response, 512, qtype);
                    
                    if (response_len > 0) {
                        // Validate the response before queuing
                        if (!Socket_ValidateDnsResponse(response, response_len)) {
                            if (DNS_TraceFlag) {
                                SbieApi_MonitorPutMsg(MONITOR_DNS, L"UDP DNS: sendto built response failed validation, dropping");
                            }
                            return len;  // Return success to prevent real send
                        }
                        
                        // Queue fake response for recv/recvfrom to return
                        Socket_AddFakeResponse(s, response, response_len, to);
                        
                        // Log the interception
                        if (DNS_TraceFlag) {
                            WCHAR msg[512];
                            if (hasIP) {
                                Sbie_snwprintf(msg, 512, L"DNS Filter MODIFIED (sendto): %s (Type: %s) - ZERO NETWORK, fake response queued",
                                    domainName,
                                    (qtype == 0x1C00) ? L"AAAA" : (qtype == 0x0100) ? L"A" : L"OTHER");
                                
                                // Log IP addresses
                                if (pEntries) {
                                    IP_ENTRY* entry = (IP_ENTRY*)List_Head(pEntries);
                                    while (entry) {
                                        WSA_DumpIP(entry->Type, &entry->IP, msg);
                                        entry = (IP_ENTRY*)List_Next(entry);
                                    }
                                }
                                
                                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                            } else {
                                Sbie_snwprintf(msg, 512, L"DNS Filter BLOCKED (sendto): %s (Type: %s) - ZERO NETWORK, NXDOMAIN returned",
                                    domainName,
                                    (qtype == 0x1C00) ? L"AAAA" : (qtype == 0x0100) ? L"A" : L"OTHER");
                                SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
                            }
                        }
                        
                        // Return success without actually sending (UDP zero-network)
                        return len;
                    }
                }
                else {
                    // Domain not in filter list - trace allowed queries
                    if (DNS_TraceFlag) {
                        WCHAR msg[512];
                        Sbie_snwprintf(msg, 512, L"Raw DNS Query Forwarded to Real Server (sendto): %s (Type: %s, Port: 53, Socket: %p)",
                            domainName,
                            (qtype == 0x1C00) ? L"AAAA" : (qtype == 0x0100) ? L"A" : L"OTHER",
                            (void*)(ULONG_PTR)s);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                    }
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
        if (destPort == 53 && buffers[0].len >= sizeof(DNS_HEADER)) {
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
                if (Pattern_MatchPathList(domain_lwr, domain_len, &DNS_FilterList, NULL, NULL, NULL, &found) > 0) {
                    
                    // Check if an IP address is defined for this domain
                    PVOID* aux = Pattern_Aux(found);
                    BOOLEAN hasIP = (aux && *aux != NULL);
                    LIST* pEntries = hasIP ? (LIST*)*aux : NULL;
                    
                    // Build fake DNS response
                    BYTE response[512];
                    int response_len = Socket_BuildDnsResponse(
                        (const BYTE*)buffers[0].buf, buffers[0].len, pEntries, !hasIP, response, 512, qtype);
                    
                    if (response_len > 0) {
                        // Validate the response before queuing
                        if (!Socket_ValidateDnsResponse(response, response_len)) {
                            if (DNS_TraceFlag) {
                                SbieApi_MonitorPutMsg(MONITOR_DNS, L"UDP DNS: WSASendTo built response failed validation, dropping");
                            }
                            if (lpNumberOfBytesSent) *lpNumberOfBytesSent = buffers[0].len;
                            return 0;  // Return success to prevent real send
                        }
                        
                        // Queue fake response for recv/recvfrom to return
                        Socket_AddFakeResponse(s, response, response_len, lpTo);
                        
                        // Log the interception
                        if (DNS_TraceFlag) {
                            WCHAR msg[512];
                            if (hasIP) {
                                Sbie_snwprintf(msg, 512, L"Raw DNS Query MODIFIED (WSASendTo): %s (Type: %s, Port: 53, Socket: %p) - Injected fake response",
                                    domainName,
                                    (qtype == 0x1C00) ? L"AAAA" : (qtype == 0x0100) ? L"A" : L"OTHER",
                                    (void*)(ULONG_PTR)s);
                                
                                // Log IP addresses
                                if (pEntries) {
                                    IP_ENTRY* entry = (IP_ENTRY*)List_Head(pEntries);
                                    while (entry) {
                                        WSA_DumpIP(entry->Type, &entry->IP, msg);
                                        entry = (IP_ENTRY*)List_Next(entry);
                                    }
                                }
                                
                                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                            } else {
                                Sbie_snwprintf(msg, 512, L"Raw DNS Query Blocked (WSASendTo): %s (Type: %s, Port: 53, Socket: %p) - Returned NXDOMAIN",
                                    domainName,
                                    (qtype == 0x1C00) ? L"AAAA" : (qtype == 0x0100) ? L"A" : L"OTHER",
                                    (void*)(ULONG_PTR)s);
                                SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
                            }
                        }
                        
                        // Set bytes sent and return success
                        if (lpNumberOfBytesSent) {
                            *lpNumberOfBytesSent = buffers[0].len;
                        }
                        return 0;  // Success
                    }
                }
                else {
                    // Domain not in filter list - trace allowed queries
                    if (DNS_TraceFlag) {
                        WCHAR msg[512];
                        Sbie_snwprintf(msg, 512, L"Raw DNS Query Forwarded to Real Server (WSASendTo): %s (Type: %s, Port: 53, Socket: %p)",
                            domainName,
                            (qtype == 0x1C00) ? L"AAAA" : (qtype == 0x0100) ? L"A" : L"OTHER",
                            (void*)(ULONG_PTR)s);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                    }
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
    if (!packet || len < sizeof(DNS_HEADER) || !domainOut || domainOutSize < 1)
        return FALSE;

    DNS_HEADER* header = (DNS_HEADER*)packet;

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
    int offset = sizeof(DNS_HEADER);
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

    USHORT queryType = *(USHORT*)(packet + offset);
    // queryType is already in network byte order - store as-is for comparison
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
// Socket_BuildDnsResponse
//
// Builds a fake DNS response packet with configured IP addresses
//
// Returns: Length of response packet, or -1 on error
//---------------------------------------------------------------------------

_FX int Socket_BuildDnsResponse(
    const BYTE*    query,
    int            query_len,
    LIST*          pEntries,
    BOOLEAN        block,
    BYTE*          response,
    int            response_size,
    USHORT         qtype)
{
    if (!query || !response || query_len < sizeof(DNS_HEADER) || response_size < 512)
        return -1;

    // Copy query to response buffer (up to response_size)
    int copy_len = (query_len < response_size) ? query_len : response_size;
    memcpy(response, query, copy_len);

    DNS_HEADER* resp_header = (DNS_HEADER*)response;
    
    // Set response flags
    if (block) {
        // NXDOMAIN response (domain doesn't exist)
        resp_header->Flags = _htons(0x8183);  // Response, NXDOMAIN
        resp_header->AnswerRRs = _htons(0);
    } else {
        // Success response
        resp_header->Flags = _htons(0x8180);  // Response, No error, Recursion available
        
        // Count how many IPs we have matching the query type
        USHORT answer_count = 0;
        if (pEntries) {
            IP_ENTRY* entry = (IP_ENTRY*)List_Head(pEntries);
            while (entry) {
                // Convert qtype from network byte order for comparison
                USHORT qtype_host = _ntohs(qtype);
                
                if ((qtype_host == DNS_TYPE_A && entry->Type == AF_INET) ||
                    (qtype_host == DNS_TYPE_AAAA && entry->Type == AF_INET6)) {
                    answer_count++;
                }
                entry = (IP_ENTRY*)List_Next(entry);
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
    
    while (entry && offset + (int)sizeof(DNS_RR) + 16 < response_size) {
        USHORT qtype_host = _ntohs(qtype);
        BOOLEAN match = FALSE;
        int rdata_len = 0;
        
        if (qtype_host == DNS_TYPE_A && entry->Type == AF_INET) {
            match = TRUE;
            rdata_len = 4;  // IPv4 address
        } else if (qtype_host == DNS_TYPE_AAAA && entry->Type == AF_INET6) {
            match = TRUE;
            rdata_len = 16;  // IPv6 address
        }
        
        if (match) {
            // Build DNS resource record
            DNS_RR* rr = (DNS_RR*)(response + offset);
            
            // Compressed name pointer (0xC00C points to offset 12 - first question name)
            rr->name = _htons(0xC00C);
            rr->type = _htons(qtype_host);
            rr->rr_class = _htons(1);  // IN (Internet)
            rr->ttl = _htonl(300);     // 5 minutes TTL
            rr->rdlength = _htons(rdata_len);
            
            offset += sizeof(DNS_RR);
            
            // Copy IP address data
            if (entry->Type == AF_INET) {
                // IPv4: use Data32[3] for the last 32-bit word
                memcpy(response + offset, &entry->IP.Data32[3], 4);
                offset += 4;
            } else {
                // IPv6: use Data array (16 bytes)
                memcpy(response + offset, entry->IP.Data, 16);
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
    if (!response || len < sizeof(DNS_HEADER))
        return FALSE;
    
    DNS_HEADER* header = (DNS_HEADER*)response;
    
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
    
    // Set source address to DNS port 53
    if (to) {
        memcpy(&new_resp->from_addr, to, sizeof(struct sockaddr_in));
        new_resp->from_addr.sin_port = _htons(53);
    } else {
        memset(&new_resp->from_addr, 0, sizeof(struct sockaddr_in));
        new_resp->from_addr.sin_family = AF_INET;
        new_resp->from_addr.sin_port = _htons(53);
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
                Sbie_snwprintf(msg, 256, L"TCP DNS: Returned %d bytes from fake response, socket=%p",
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
            if (DNS_TraceFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"DNS Filter: Delivered fake response (recvfrom)");
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
// Hook for getpeername() - returns stored DNS server address for zero-network sockets
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
