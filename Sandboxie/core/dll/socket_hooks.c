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

//---------------------------------------------------------------------------
// Socket Hooks - Raw DNS Query Interception
//
// This module intercepts raw UDP socket operations to filter DNS queries
// sent directly to DNS ports (default: 53), catching tools like nslookup.exe
// that bypass high-level DNS APIs.
//
// Custom Port Support:
//   FilterRawDns=[process,]y|n[:port1[;port2;...]]
//   - Default (no ports): monitors port 53 only
//   - Custom ports: monitors only specified ports
//   - Examples:
//     FilterRawDns=y                         (port 53)
//     FilterRawDns=nslookup.exe,y:5353;9953  (nslookup, ports 5353+9953)
//     FilterRawDns=y:53;5353;9953            (all apps, ports 53+5353+9953)
//
// DNS Wire Format Parser:
//   - Parses DNS query packets (RFC 1035)
//   - Extracts domain names from question section
//   - Matches against NetworkDnsFilter rules using hierarchical wildcard matching
//   - Returns filtered responses per RFC 2308 semantics
//
// Hierarchical Wildcard Matching:
//   - Tries exact match first: "www.sub.example.com"
//   - Falls back through wildcard levels: "*.sub.example.com" → "*.example.com" → "*.com"
//   - Finally tries catch-all: "*"
//   - Most specific match wins
//
// Configuration Examples:
//   NetworkDnsFilter=*.example.com:192.0.2.1    # Redirect all example.com subdomains (RFC 5737)
//   NetworkDnsFilter=*.ads.test                 # Block all ads.test subdomains (NXDOMAIN)
//   NetworkDnsFilter=*                          # Block everything else (catch-all)
//
// DNS Response Behavior (RFC 2308):
//   Block Mode (no IPs configured):
//     - ALL types: NXDOMAIN (RCODE 3) - domain does not exist
//   Intercept Mode (with IPs):
//     - Supported types (A/AAAA) with matching IPs: NOERROR with answers
//     - Supported types with no matching IPs: NOERROR + NODATA (0 answers)
//     - Unsupported types (MX/TXT/etc.): NOERROR + NODATA (domain exists, no records of this type)
//
// IPv4-to-IPv6 Mapping (DnsMapIpv4ToIpv6 setting, default: off):
//   - When enabled: AAAA queries automatically use IPv4-mapped IPv6 (::ffff:a.b.c.d) if only IPv4 configured
//   - When disabled: AAAA queries return NOERROR + NODATA if no native IPv6 addresses available
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
#include "dns_wire.h"
#include "dns_doh.h"  // Includes dns_encrypted.h for EncryptedDns_* and ENCRYPTED_DNS_* types
#include "dns_rebind.h"
#include "dns_dnssec.h"

//---------------------------------------------------------------------------
// Forward Declarations of Socket Types (used locally, not from winsock2.h)
// These are minimal definitions needed for socket filtering operations
//---------------------------------------------------------------------------

// sockaddr_storage - For IPv4/IPv6 address storage (RFC 3493)
// Sized to hold both IPv4 (sockaddr_in) and IPv6 (sockaddr_in6) addresses
typedef struct sockaddr_storage {
    ADDRESS_FAMILY ss_family;
    CHAR __ss_pad1[6];          // Padding
    __int64 __ss_align;         // Force alignment
    CHAR __ss_pad2[112];        // Remaining padding (total 128 bytes)
} SOCKADDR_STORAGE, *PSOCKADDR_STORAGE;

// WSABUF structure for scatter/gather operations
typedef struct _WSABUF_REAL {
    ULONG len;
    CHAR FAR *buf;
} WSABUF_REAL, *LPWSABUF_REAL;

// WSAMSG structure for WSARecvMsg compatibility
// Note: Duplicate definition removed - see line 343-349 for the correct definition

//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
// DNS wire format structures (shared with dns_wire.h)
//---------------------------------------------------------------------------

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

// Maximum DNS response size - increased from 512 to support EDNS0
// RFC 6891 allows up to 4096 bytes for EDNS0-capable resolvers
// Note: Stack allocation of 4096 bytes is safe for most architectures
// (default Windows stack is 1MB, typical recursion depth is shallow)
#define DNS_RESPONSE_SIZE 4096

// Smaller response buffer for simple queries without EDNS0
// Most DNS responses fit in 512 bytes (original RFC 1035 limit)
#define DNS_SIMPLE_RESPONSE_SIZE 512

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
// WSAEnumNetworkEvents Constants and Structures
// (moved here because Socket_InjectFdRead uses them before Socket_WSAEnumNetworkEvents)
//---------------------------------------------------------------------------

#ifndef FD_READ_BIT
#define FD_READ_BIT      0
#define FD_READ          (1 << FD_READ_BIT)
#endif

#ifndef FD_CLOSE_BIT
#define FD_CLOSE_BIT     5
#define FD_CLOSE         (1 << FD_CLOSE_BIT)
#endif

#ifndef FD_MAX_EVENTS
#define FD_MAX_EVENTS    10
#endif

typedef struct _WSANETWORKEVENTS_COMPAT {
    long lNetworkEvents;
    int  iErrorCode[FD_MAX_EVENTS];
} WSANETWORKEVENTS_COMPAT;

//---------------------------------------------------------------------------
// Fake Response Queue for Direct DNS Response Injection
// Per-Socket FIFO Architecture - O(1) enqueue/dequeue, reduced lock contention
//---------------------------------------------------------------------------

// Resource limits to prevent abuse
#define MAX_FAKE_RESPONSES_PER_SOCKET 10
#define FAKE_RESPONSE_TIMEOUT_MS 10000

typedef struct _FAKE_RESPONSE {
    char length_prefix[2];      // TCP DNS length prefix (2 bytes, network byte order)
    char response[DNS_RESPONSE_SIZE];  // DNS payload (4096 bytes for EDNS0 support)
    int response_len;           // Length of DNS payload
    int consumed;               // Bytes already returned (includes length prefix for TCP)
    int total_len;              // Total bytes to return (2 + response_len for TCP, response_len for UDP)
    BOOLEAN is_tcp;             // TRUE if this is a TCP response (has length prefix)
    BOOLEAN skip_length_prefix; // TRUE if we should skip sending the length prefix (nslookup without -vc)
    SOCKADDR_STORAGE from_addr; // Use sockaddr_storage to support both IPv4 and IPv6
    int from_addr_len;          // Actual length of the address (sizeof(sockaddr_in) or sockaddr_in6)
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
// TCP DNS Reassembly Buffer
// 
// Some applications (like Cygwin dig) send TCP DNS messages in fragments:
//   - First WSASendTo: 2-byte length prefix only
//   - Second WSASendTo: DNS query payload
// We need to reassemble these fragments to properly intercept the query.
//---------------------------------------------------------------------------

// Increased from 520 to 4098 to support EDNS0 (RFC 6891) and prevent filter bypass
// via oversized packets. Format: 2-byte length prefix + up to 4096 byte DNS payload
#define TCP_REASSEMBLY_BUFFER_SIZE 4098
#define TCP_REASSEMBLY_TIMEOUT_MS 5000  // Drop incomplete messages after 5 seconds

typedef struct _TCP_REASSEMBLY_BUFFER {
    SOCKET socket;                          // Socket this buffer belongs to
    BYTE buffer[TCP_REASSEMBLY_BUFFER_SIZE];// Accumulated data
    int bytes_received;                     // Total bytes accumulated
    int expected_length;                    // Expected total length (from 2-byte prefix, -1 if unknown)
    DWORD timestamp;                        // When first fragment was received
    BOOLEAN active;                         // TRUE if buffer is in use
} TCP_REASSEMBLY_BUFFER;

// Simple table for TCP reassembly buffers (keyed by socket hash)
#define TCP_REASSEMBLY_TABLE_SIZE 64
static TCP_REASSEMBLY_BUFFER g_TcpReassemblyTable[TCP_REASSEMBLY_TABLE_SIZE];
static CRITICAL_SECTION g_TcpReassemblyLock;

static BOOLEAN DNS_RawSocketFilterEnabled = FALSE;  // Raw socket filtering enabled (default: FALSE)
static BOOLEAN DNS_RawSocketHooksEnabled = FALSE;   // Hooks/logging enabled (FilterRawDns or DnsTrace)

// Custom DNS port list for FilterRawDns
// Supports up to 16 custom ports (e.g., FilterRawDns=y:53;5353;9953)
// When no ports configured, defaults to port 53 only.
#define DNS_MAX_CUSTOM_PORTS 16
static USHORT DNS_CustomPorts[DNS_MAX_CUSTOM_PORTS];
static int DNS_CustomPortCount = 0;  // 0 = use default (port 53 only)

// Use global DNS_DebugFlag from dns_logging.c for consistent debug logging across modules
extern BOOLEAN DNS_DebugFlag;

// Encrypted DNS function declarations (from dns_encrypted.c)
extern BOOLEAN EncryptedDns_IsEnabled(void);

#if !defined(_DNSDEBUG)
// Release builds: compile out debug-only logging paths.
#undef DNS_DebugFlag
#define DNS_DebugFlag 0
#endif

//---------------------------------------------------------------------------
// DNS Connection Tracking
//---------------------------------------------------------------------------

// Track sockets connected to DNS servers (port 53)
static BOOLEAN Socket_IsDnsSocket(SOCKET s);
void Socket_MarkDnsSocket(SOCKET s, BOOLEAN isDns);  // Non-static: called from net.c
static BOOLEAN Socket_IsTcpSocket(SOCKET s);  // Helper to detect TCP vs UDP sockets

// DNSSEC support helpers (implemented in dns_dnssec.c)

// Simple hash table for tracking DNS sockets
#define DNS_SOCKET_TABLE_SIZE 256
static SOCKET g_DnsSockets[DNS_SOCKET_TABLE_SIZE];
static BOOLEAN g_DnsSocketFlags[DNS_SOCKET_TABLE_SIZE];
static CRITICAL_SECTION g_DnsSocketTableLock;  // Protects socket table access

// Store DNS server addresses for getpeername() support
// Stores the address the socket connected to (for local-response spoofing)
// Use byte array large enough for IPv6 (128 bytes is more than enough for sockaddr_in6)
#define DNS_SERVER_ADDR_SIZE 128
static BYTE g_DnsServerAddrs[DNS_SOCKET_TABLE_SIZE][DNS_SERVER_ADDR_SIZE];
static int g_DnsServerAddrLens[DNS_SOCKET_TABLE_SIZE];

// Tracking for pending passthrough DNS queries (for logging response IPs)
// When a query is forwarded to real DNS, we store domain/type so we can log the response
#define PENDING_QUERY_DOMAIN_SIZE 256
typedef struct _PENDING_DNS_QUERY {
    WCHAR Domain[PENDING_QUERY_DOMAIN_SIZE];
    USHORT QueryType;
    BOOLEAN IsTcp;
    BOOLEAN Valid;  // TRUE if there's a pending query to log
    DNS_PASSTHROUGH_REASON PassthroughReason;  // Reason for passthrough (for logging)
} PENDING_DNS_QUERY;
static PENDING_DNS_QUERY g_PendingQueries[DNS_SOCKET_TABLE_SIZE];

// Socket-to-Event mapping for async DNS queries
// When app calls WSAEventSelect/WSAEnumNetworkEvents, store the event handle
// so we can signal it proactively when a DNS response arrives
#define SOCKET_EVENT_MAPPING_SIZE 256
typedef struct _SOCKET_EVENT_MAPPING {
    SOCKET socket;
    HANDLE hEvent;
    DWORD timestamp;  // For cleanup of stale entries
} SOCKET_EVENT_MAPPING;
static SOCKET_EVENT_MAPPING g_SocketEventMappings[SOCKET_EVENT_MAPPING_SIZE];
static CRITICAL_SECTION g_SocketEventMappingsLock;

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
static P_WSARecv __sys_WSARecv = NULL;
static P_WSARecvFrom __sys_WSARecvFrom = NULL;
static P_getpeername __sys_getpeername = NULL;

// select/poll support for TCP DNS local-response mode (P_select is defined in wsa_defs.h)
static P_select __sys_select = NULL;
static P_WSAPoll __sys_WSAPoll = NULL;

// WSAEnumNetworkEvents for Cygwin async I/O (needs to inject FD_READ for fake responses)
static P_WSAEnumNetworkEvents __sys_WSAEnumNetworkEvents = NULL;

// WSAMSG structure for WSARecvMsg (matches ws2def.h, using WSABUF_REAL)
// Using void* for name pointer to avoid LPSOCKADDR dependency
typedef struct _WSAMSG_COMPAT {
    void*            name;              // LPSOCKADDR - Remote address
    INT              namelen;           // Remote address length
    LPWSABUF_REAL    lpBuffers;         // Data buffer array
    ULONG            dwBufferCount;     // Number of elements in array
    WSABUF_REAL      Control;           // Control buffer
    ULONG            dwFlags;           // Flags
} WSAMSG_COMPAT, *LPWSAMSG_COMPAT;

// WSARecvMsg function pointer type
typedef INT (PASCAL FAR *LPFN_WSARECVMSG)(
    SOCKET s,
    LPWSAMSG_COMPAT lpMsg,
    LPDWORD lpdwNumberOfBytesRecvd,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

// Store the real WSARecvMsg function pointer (set by Socket_GetWSARecvMsgWrapper)
static LPFN_WSARECVMSG __sys_WSARecvMsg = NULL;

// getsockopt function pointer (not hooked, used for socket type detection)
typedef int (WINAPI *P_getsockopt)(SOCKET s, int level, int optname, char* optval, int* optlen);
static P_getsockopt __sys_getsockopt = NULL;

//---------------------------------------------------------------------------
// Forward Declarations
//---------------------------------------------------------------------------

// External utility functions (from dns_filter.c / net.c)
void WSA_DumpIP(ADDRESS_FAMILY af, IP_ADDRESS* pIP, wchar_t* pStr);

_FX BOOLEAN Socket_ValidateDnsResponse(
    const BYTE*    response,
    int            len);

_FX void Socket_AddFakeResponse(
    SOCKET         s,
    const BYTE*    response,
    int            response_len,
    const void*    to);

static void Socket_LogInterceptedResponse(const WCHAR* protocol, const WCHAR* domain, USHORT qtype_host,
    int query_len, const BYTE* response, int response_len, SOCKET s, LIST* pEntries, const WCHAR* func_suffix);

//---------------------------------------------------------------------------
// Socket_TryHandleIpLiteralDnsQuery
//
// If the DNS QNAME is a literal IP address (e.g. "1.1.1.1" or "[::1]"),
// it should NOT be treated as a filterable DNS domain name. This helper
// synthesizes a local A/AAAA response (IP->IP) or NOERROR+NODATA on family
// mismatch, and queues it as a fake response.
//---------------------------------------------------------------------------

static BOOLEAN Socket_TryHandleIpLiteralDnsQuery(
    SOCKET s,
    const BYTE* dns_payload,
    int dns_payload_len,
    const void* to,
    const WCHAR* protocol,
    const WCHAR* func_name,
    const WCHAR* domainName,
    USHORT qtype)
{
    if (!dns_payload || dns_payload_len < (int)sizeof(DNS_WIRE_HEADER) || !domainName)
        return FALSE;

    if (!(qtype == DNS_TYPE_A || qtype == DNS_TYPE_AAAA))
        return FALSE;

    IP_ADDRESS ip;
    USHORT addr_type = 0;
    memset(&ip, 0, sizeof(ip));
    if (_inet_xton(domainName, (ULONG)wcslen(domainName), &ip, &addr_type) != 1)
        return FALSE;

    LIST ip_list;
    List_Init(&ip_list);

    if ((qtype == DNS_TYPE_A && addr_type == AF_INET) ||
        (qtype == DNS_TYPE_AAAA && addr_type == AF_INET6)) {
        IP_ENTRY* pEntry = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
        if (pEntry) {
            pEntry->Type = addr_type;
            memcpy(&pEntry->IP, &ip, sizeof(IP_ADDRESS));
            List_Insert_After(&ip_list, NULL, pEntry);
        }
    }

    BYTE edns_buffer[256];
    int edns_len = Socket_ExtractEdnsRecord(dns_payload, dns_payload_len, edns_buffer, sizeof(edns_buffer));
    
    // Extract DO flag from EDNS for DNSSEC support
    // OPT record layout in edns_buffer: [0]=root, [1-2]=TYPE, [3-4]=UDP size,
    // [5]=ExtRCODE, [6]=Version, [7-8]=Flags(DO+Z), [9-10]=RDLEN
    USHORT edns_flags = 0;
    if (edns_len >= 11) {
        edns_flags = (edns_buffer[7] << 8) | edns_buffer[8];  // DO+Z flags at offset 7-8
    }
    BOOLEAN do_flag = (edns_flags & DNS_EDNS_FLAG_DO) != 0;
    
    // Determine DNSSEC mode
    DNSSEC_MODE dnssec_mode = DNSSEC_MODE_DISABLED;  // Default
    if (do_flag) {
        dnssec_mode = DNS_DnssecGetMode(domainName);
    }
    
    BYTE response[DNS_RESPONSE_SIZE];
    int response_len = Socket_BuildDnsResponse(
        dns_payload,
        dns_payload_len,
        &ip_list,
        FALSE,  // not block mode
        response,
        DNS_RESPONSE_SIZE,
        qtype,
        NULL,
        domainName,
        edns_len > 0 ? edns_buffer : NULL,
        edns_len,
        dnssec_mode);

    // Free temporary IP list
    IP_ENTRY* pFree = (IP_ENTRY*)List_Head(&ip_list);
    while (pFree) {
        IP_ENTRY* pNext = (IP_ENTRY*)List_Next(pFree);
        Dll_Free(pFree);
        pFree = pNext;
    }

    if (response_len <= 0)
        return FALSE;

    if (!Socket_ValidateDnsResponse(response, response_len))
        return FALSE;

    Socket_AddFakeResponse(s, response, response_len, to);
    Socket_LogInterceptedResponse(protocol, domainName, qtype, dns_payload_len,
        response, response_len, s, NULL, func_name);
    return TRUE;
}

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

static int Socket_WSARecv(
    SOCKET                             s,
    LPWSABUF                           lpBuffers,
    DWORD                              dwBufferCount,
    LPDWORD                            lpNumberOfBytesRecvd,
    LPDWORD                            lpFlags,
    LPWSAOVERLAPPED                    lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

static int Socket_WSARecvFrom(
    SOCKET                             s,
    LPWSABUF                           lpBuffers,
    DWORD                              dwBufferCount,
    LPDWORD                            lpNumberOfBytesRecvd,
    LPDWORD                            lpFlags,
    void                               *lpFrom,
    LPINT                              lpFromlen,
    LPWSAOVERLAPPED                    lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

static int Socket_select(
    int            nfds,
    void           *readfds,
    void           *writefds,
    void           *exceptfds,
    const void     *timeout);

static int Socket_WSAPoll(
    WSAPOLLFD_COMPAT *fdArray,
    ULONG            nfds,
    INT              timeout);

static int Socket_getpeername(
    SOCKET         s,
    void           *name,
    int            *namelen);

static int Socket_WSAEnumNetworkEvents(
    SOCKET         s,
    HANDLE         hEventObject,
    void           *lpNetworkEvents);

static INT PASCAL FAR Socket_WSARecvMsg(
    SOCKET         s,
    LPWSAMSG_COMPAT lpMsg,
    LPDWORD        lpdwNumberOfBytesRecvd,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

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
    struct _DNS_TYPE_FILTER* type_filter,
    const WCHAR*   domain,
    const BYTE*    edns_record,
    int            edns_record_len,
    DNSSEC_MODE    dnssec_mode);

static BOOLEAN Socket_HasFakeResponse(SOCKET s);

static int Socket_GetFakeResponse(
    SOCKET   s,
    char     *buf,
    int      len,
    void     *from,
    int      *fromlen);

//---------------------------------------------------------------------------
// Pending Query Tracking (for logging passthrough response IPs)
//---------------------------------------------------------------------------

// Store a pending passthrough query for a socket (called when forwarding to real DNS)
// Thread-safe: Protected by g_DnsSocketTableLock to prevent race conditions
static void Socket_SetPendingQuery(SOCKET s, const WCHAR* domain, USHORT qtype, BOOLEAN isTcp, DNS_PASSTHROUGH_REASON reason)
{
    if (!DNS_TraceFlag || !domain)
        return;
    
    ULONG index = ((ULONG_PTR)s) % DNS_SOCKET_TABLE_SIZE;
    
    EnterCriticalSection(&g_DnsSocketTableLock);
    
    // Check for hash collision (different socket in same slot)
    if (g_DnsSockets[index] != s && g_DnsSockets[index] != INVALID_SOCKET) {
        // Collision - clear old entry
        g_PendingQueries[index].Valid = FALSE;
    }
    
    size_t domain_len = wcslen(domain);
    if (domain_len >= PENDING_QUERY_DOMAIN_SIZE)
        domain_len = PENDING_QUERY_DOMAIN_SIZE - 1;
    
    wcsncpy(g_PendingQueries[index].Domain, domain, domain_len);
    g_PendingQueries[index].Domain[domain_len] = L'\0';
    g_PendingQueries[index].QueryType = qtype;
    g_PendingQueries[index].IsTcp = isTcp;
    g_PendingQueries[index].PassthroughReason = reason;
    g_PendingQueries[index].Valid = TRUE;
    
    LeaveCriticalSection(&g_DnsSocketTableLock);
}

// Get pending query for a socket (called when receiving DNS response)
// Returns TRUE if there was a pending query, fills in domain and qtype
// If clearQuery is TRUE, the pending query is cleared (one-shot behavior)
// Thread-safe: Protected by g_DnsSocketTableLock to prevent race conditions
static BOOLEAN Socket_GetPendingQuery(SOCKET s, WCHAR* domain, int domain_size, USHORT* qtype, BOOLEAN* isTcp, DNS_PASSTHROUGH_REASON* reason, BOOLEAN clearQuery)
{
    ULONG index = ((ULONG_PTR)s) % DNS_SOCKET_TABLE_SIZE;
    BOOLEAN result = FALSE;
    
    EnterCriticalSection(&g_DnsSocketTableLock);
    
    // Check if this is the right socket and has a pending query
    if (g_DnsSockets[index] != s || !g_PendingQueries[index].Valid) {
        LeaveCriticalSection(&g_DnsSocketTableLock);
        return FALSE;
    }
    
    if (domain && domain_size > 0) {
        wcsncpy(domain, g_PendingQueries[index].Domain, domain_size - 1);
        domain[domain_size - 1] = L'\0';
    }
    
    if (qtype) {
        *qtype = g_PendingQueries[index].QueryType;
    }
    
    if (isTcp) {
        *isTcp = g_PendingQueries[index].IsTcp;
    }
    
    if (reason) {
        *reason = g_PendingQueries[index].PassthroughReason;
    }
    
    // Clear the pending query if requested (one-shot - don't log again on subsequent reads)
    if (clearQuery) {
        g_PendingQueries[index].Valid = FALSE;
    }
    
    result = TRUE;
    
    LeaveCriticalSection(&g_DnsSocketTableLock);
    return result;
}

// Clear pending query for a socket (e.g., when socket closes or gets intercepted response)
// Thread-safe: Protected by g_DnsSocketTableLock to prevent race conditions
static void Socket_ClearPendingQuery(SOCKET s)
{
    ULONG index = ((ULONG_PTR)s) % DNS_SOCKET_TABLE_SIZE;
    
    EnterCriticalSection(&g_DnsSocketTableLock);
    g_PendingQueries[index].Valid = FALSE;
    LeaveCriticalSection(&g_DnsSocketTableLock);
}

//---------------------------------------------------------------------------
// DNS Response Parsing (for logging passthrough IPs)
//---------------------------------------------------------------------------

// Parse DNS response and log IPs (for passthrough queries)
// Called when recv returns with DNS response data
// Returns TRUE if a response was successfully parsed and logged
// Returns FALSE if data is too small or invalid (caller should NOT clear pending query)
static BOOLEAN Socket_ParseAndLogDnsResponse(
    SOCKET s,
    const BYTE* data,
    int data_len,
    const WCHAR* domain,
    USHORT qtype,
    BOOLEAN isTcp,
    DNS_PASSTHROUGH_REASON reason)
{
    if (!DNS_TraceFlag || !data || data_len < (int)sizeof(DNS_WIRE_HEADER))
        return FALSE;
    
    // For TCP, skip the 2-byte length prefix if present
    const BYTE* dns_data = data;
    int dns_len = data_len;
    
    if (isTcp && data_len > 2) {
        // Check if first 2 bytes look like a length prefix (value close to remaining data)
        USHORT length_prefix = _ntohs(*(USHORT*)data);
        if (length_prefix == (USHORT)(data_len - 2)) {
            dns_data = data + 2;
            dns_len = data_len - 2;
        }
    }
    
    if (dns_len < (int)sizeof(DNS_WIRE_HEADER))
        return FALSE;
    
    DNS_WIRE_HEADER* header = (DNS_WIRE_HEADER*)dns_data;
    
    // Verify this is a DNS response (QR bit = 1)
    USHORT flags = _ntohs(header->Flags);
    USHORT qr = (flags >> 15) & 0x1;
    
    if (qr != 1) {
        // Not a response
        return FALSE;
    }
    
    // Get reason string
    const WCHAR* reason_str = DNS_GetPassthroughReasonString(reason);
    
    // Check response code
    USHORT rcode = flags & 0x000F;
    if (rcode != 0) {
        // Error response (NXDOMAIN, SERVFAIL, etc.) - log without IPs
        const WCHAR* protocol = isTcp ? L"TCP DNS" : L"UDP DNS";
        WCHAR msg[512];
        
        const WCHAR* rcode_str = L"Error";
        switch (rcode) {
            case 1: rcode_str = L"Format Error"; break;
            case 2: rcode_str = L"Server Failure"; break;
            case 3: rcode_str = L"NXDOMAIN"; break;
            case 4: rcode_str = L"Not Implemented"; break;
            case 5: rcode_str = L"Refused"; break;
        }
        
        if (reason != DNS_PASSTHROUGH_NONE && reason_str[0] != L'\0') {
            Sbie_snwprintf(msg, 512, L"%s Passthrough: %s (Type: %s) [%s] - %s",
                protocol, domain, DNS_GetTypeName(qtype), reason_str, rcode_str);
        } else {
            Sbie_snwprintf(msg, 512, L"%s Passthrough: %s (Type: %s) - %s",
                protocol, domain, DNS_GetTypeName(qtype), rcode_str);
        }
        SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
        return TRUE;
    }
    
    // Parse answer section for IPs
    USHORT answer_count = _ntohs(header->AnswerRRs);
    
    if (answer_count == 0) {
        // No answers (NODATA)
        const WCHAR* protocol = isTcp ? L"TCP DNS" : L"UDP DNS";
        WCHAR msg[512];
        if (reason != DNS_PASSTHROUGH_NONE && reason_str[0] != L'\0') {
            Sbie_snwprintf(msg, 512, L"%s Passthrough: %s (Type: %s) [%s] - No records",
                protocol, domain, DNS_GetTypeName(qtype), reason_str);
        } else {
            Sbie_snwprintf(msg, 512, L"%s Passthrough: %s (Type: %s) - No records",
                protocol, domain, DNS_GetTypeName(qtype));
        }
        SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
        return TRUE;
    }
    
    // Build log message with IPs
    const WCHAR* protocol = isTcp ? L"TCP DNS" : L"UDP DNS";
    WCHAR msg[1024];
    if (reason != DNS_PASSTHROUGH_NONE && reason_str[0] != L'\0') {
        Sbie_snwprintf(msg, 1024, L"%s Passthrough: %s (Type: %s) [%s]",
            protocol, domain, DNS_GetTypeName(qtype), reason_str);
    } else {
        Sbie_snwprintf(msg, 1024, L"%s Passthrough: %s (Type: %s)",
            protocol, domain, DNS_GetTypeName(qtype));
    }
    
    // Skip to answer section (past header and question)
    int offset = sizeof(DNS_WIRE_HEADER);
    
    // Skip question section (name + QTYPE + QCLASS)
    USHORT question_count = _ntohs(header->Questions);
    for (USHORT q = 0; q < question_count && offset < dns_len; q++) {
        // Skip domain name
        while (offset < dns_len) {
            BYTE label_len = dns_data[offset];
            if (label_len == 0) {
                offset++;
                break;
            }
            if ((label_len & 0xC0) == 0xC0) {
                offset += 2;  // Compression pointer
                break;
            }
            offset += 1 + label_len;
        }
        offset += 4;  // QTYPE + QCLASS
    }
    
    // Parse answer records
    int ip_count = 0;
    for (USHORT a = 0; a < answer_count && offset < dns_len && ip_count < 10; a++) {
        // Skip domain name (likely compressed)
        while (offset < dns_len) {
            BYTE label_len = dns_data[offset];
            if (label_len == 0) {
                offset++;
                break;
            }
            if ((label_len & 0xC0) == 0xC0) {
                offset += 2;  // Compression pointer
                break;
            }
            offset += 1 + label_len;
        }
        
        // Read TYPE, CLASS, TTL, RDLENGTH
        if (offset + 10 > dns_len)
            break;
        
        USHORT rr_type = _ntohs(*(USHORT*)(dns_data + offset));
        offset += 2;
        // Skip CLASS
        offset += 2;
        // Skip TTL
        offset += 4;
        USHORT rdlength = _ntohs(*(USHORT*)(dns_data + offset));
        offset += 2;
        
        // Check if we have enough data for RDATA
        if (offset + rdlength > dns_len)
            break;
        
        // Log A and AAAA records
        if (rr_type == DNS_TYPE_A && rdlength == 4) {
            IP_ADDRESS ip;
            memset(&ip, 0, sizeof(ip));
            ip.Data32[3] = *(DWORD*)(dns_data + offset);
            WSA_DumpIP(AF_INET, &ip, msg);
            ip_count++;
        } else if (rr_type == DNS_TYPE_AAAA && rdlength == 16) {
            IP_ADDRESS ip;
            memset(&ip, 0, sizeof(ip));
            memcpy(ip.Data, dns_data + offset, 16);
            WSA_DumpIP(AF_INET6, &ip, msg);
            ip_count++;
        }
        
        offset += rdlength;
    }
    
    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
    return TRUE;
}

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
    
    // Check actual response flags to determine if it's NXDOMAIN, NOERROR, etc.
    DNS_WIRE_HEADER* resp_hdr = (DNS_WIRE_HEADER*)response;
    USHORT resp_flags = _ntohs(resp_hdr->Flags);
    USHORT rcode = resp_flags & 0x000F;  // Response code in lower 4 bits
    USHORT answer_count = _ntohs(resp_hdr->AnswerRRs);
    
    BOOLEAN is_nxdomain = (rcode == 3);  // RCODE 3 = NXDOMAIN
    BOOLEAN is_nodata = (rcode == 0 && answer_count == 0);  // NOERROR but no answers
    
    if (!is_nxdomain && !is_nodata && pEntries) {
        // Success with IPs - use unified logging format
        DNS_LogRawSocketIntercepted(protocol, domain, qtype_host, pEntries, func_suffix);
        
        // Log verbose details to DnsDebug
        DNS_LogRawSocketDebug(protocol, domain, qtype_host, query_len, response_len, func_suffix, s);
    } else if (is_nodata) {
        // NOERROR + NODATA (domain exists, no records of this type)
        // This happens for unsupported types like CNAME, MX, TXT in filter mode
        DNS_LogRawSocketNoData(protocol, domain, qtype_host, func_suffix);
        
        // Log verbose details to DnsDebug
        DNS_LogRawSocketDebug(protocol, domain, qtype_host, query_len, response_len, func_suffix, s);
    } else {
        // NXDOMAIN (blocked domain)
        DNS_LogRawSocketBlocked(protocol, domain, qtype_host, 
            L"Domain blocked (NXDOMAIN)", func_suffix);
        
        // Log verbose details to DnsDebug
        DNS_LogRawSocketDebug(protocol, domain, qtype_host, query_len, response_len, func_suffix, s);
    }
}

// Log filter mode passthrough and track pending query for response logging
static void Socket_LogFilterPassthrough(const WCHAR* protocol, const WCHAR* domain, USHORT qtype_host, const WCHAR* func_name, SOCKET s, DNS_PASSTHROUGH_REASON reason)
{
    if (!domain)
        return;
    
    // Detect actual protocol if socket is valid
    BOOLEAN isTcp = FALSE;
    if (s != INVALID_SOCKET && Socket_IsDnsSocket(s)) {
        isTcp = Socket_IsTcpSocket(s);
    } else if (wcscmp(protocol, L"TCP") == 0) {
        isTcp = TRUE;
    }
    
    // Track this pending query so we can log the response IPs when recv returns
    Socket_SetPendingQuery(s, domain, qtype_host, isTcp, reason);
    
    // Skip the initial passthrough message - we'll log the full result with IPs later
    if (DNS_DebugFlag && func_name) {
        WCHAR debug_msg[256];
        Sbie_snwprintf(debug_msg, 256, L"  %s DNS Debug: %s filter passthrough for %s (%s), awaiting response on socket=%p",
            protocol, func_name, domain, DNS_GetTypeName(qtype_host), (void*)(ULONG_PTR)s);
        SbieApi_MonitorPutMsg(MONITOR_DNS, debug_msg);
    }
}

// Log forwarded to real DNS and track pending query for response logging
static void Socket_LogForwarded(const WCHAR* protocol, const WCHAR* domain, USHORT qtype_host, const WCHAR* func_name, SOCKET s, DNS_PASSTHROUGH_REASON reason)
{
    if (!domain)
        return;
    
    // Detect actual protocol if socket is valid
    BOOLEAN isTcp = FALSE;
    const WCHAR* actual_protocol = protocol;
    if (s != INVALID_SOCKET && Socket_IsDnsSocket(s)) {
        isTcp = Socket_IsTcpSocket(s);
        actual_protocol = isTcp ? L"TCP" : L"UDP";
    } else if (wcscmp(protocol, L"TCP") == 0) {
        isTcp = TRUE;
    }
    
    // Track this pending query so we can log the response IPs when recv returns
    // This replaces the initial "Forwarding to real DNS" message with a full result message
    Socket_SetPendingQuery(s, domain, qtype_host, isTcp, reason);
    
    // Skip the "Forwarding to real DNS" message - we'll log the full result with IPs later
    // Only log debug info if enabled
    if (DNS_DebugFlag && func_name) {
        WCHAR debug_msg[256];
        Sbie_snwprintf(debug_msg, 256, L"  Raw Socket Debug: %s DNS query for %s (%s), awaiting response on socket=%p",
            actual_protocol, domain, DNS_GetTypeName(qtype_host), (void*)(ULONG_PTR)s);
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
    const WCHAR* error_prefix,
    const WCHAR* domain)
{
    // Extract filter configuration
    LIST* pEntries = NULL;
    DNS_TYPE_FILTER* type_filter = NULL;
    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);
    
    BYTE edns_buffer[256];
    int edns_len = Socket_ExtractEdnsRecord(dns_payload, dns_payload_len, edns_buffer, sizeof(edns_buffer));
    
    // Extract DO flag from EDNS for DNSSEC support
    // OPT record layout in edns_buffer: [0]=root, [1-2]=TYPE, [3-4]=UDP size,
    // [5]=ExtRCODE, [6]=Version, [7-8]=Flags(DO+Z), [9-10]=RDLEN
    USHORT edns_flags = 0;
    if (edns_len >= 11) {
        edns_flags = (edns_buffer[7] << 8) | edns_buffer[8];  // DO+Z flags at offset 7-8
    }
    BOOLEAN do_flag = (edns_flags & DNS_EDNS_FLAG_DO) != 0;
    
    // Determine DNSSEC mode
    DNSSEC_MODE dnssec_mode = DNSSEC_MODE_DISABLED;  // Default
    if (do_flag && domain) {
        dnssec_mode = DNS_DnssecGetMode(domain);
        // Note: DNSSEC_MODE_ENABLED (y mode) has no effect here since
        // we already synthesized responses (not using raw encrypted DNS)
    }
    
    // Build DNS response
    int response_len = Socket_BuildDnsResponse(
        dns_payload, dns_payload_len, pEntries, pEntries == NULL, 
        response, response_size, qtype, type_filter, domain,
        edns_len > 0 ? edns_buffer : NULL, edns_len, dnssec_mode);
    
    // Handle errors
    if (response_len < 0 && DNS_TraceFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"%s: Error building response, dropping query", error_prefix);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    return response_len;
}

//---------------------------------------------------------------------------
// Socket_BuildDoHResponse
//
// Build a DNS wire format response from DoH query results.
// Used for raw socket DNS interception when EncryptedDnsServer is configured.
//
// Parameters:
//   query         - Original DNS query packet
//   query_len     - Length of query packet
//   domain        - Domain name being queried
//   qtype         - Query type (DNS_TYPE_A, DNS_TYPE_AAAA, etc.)
//   response      - Buffer for DNS response
//   response_size - Size of response buffer
//   protocol      - Protocol name for logging ("TCP" or "UDP")
//
// Returns: Length of response packet, 0 for passthrough, -1 on error
//---------------------------------------------------------------------------

static int Socket_BuildDoHResponse(
    const BYTE* query,
    int query_len,
    const WCHAR* domain,
    USHORT qtype,
    BYTE* response,
    int response_size,
    const WCHAR* protocol)
{
    // Respect exclusion mode:
    // - SYS: excluded domains should use system DNS directly (no EncDns for raw sockets)
    // - ENC: excluded domains still use EncDns for passthrough
    DNS_EXCLUDE_RESOLVE_MODE excludeMode = DNS_EXCLUDE_RESOLVE_SYS;
    if (DNS_IsExcludedWithMode(domain, &excludeMode) && excludeMode == DNS_EXCLUDE_RESOLVE_SYS) {
        if (DNS_TraceFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"%s DNS: Domain excluded (sys), passthrough: %s (Type: %s)",
                protocol ? protocol : L"Raw", domain, DNS_GetTypeName(qtype));
            SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
        }
        return 0;
    }

    // Check if encrypted DNS is enabled
    if (!EncryptedDns_IsEnabled()) {
        return 0;  // Passthrough - encrypted DNS not configured
    }
    
    // Prevent re-entrancy - if encrypted DNS query is already active, don't trigger another
    // This prevents infinite loops when FilterWinHttp=y intercepts encrypted DNS's WinHTTP calls
    if (EncryptedDns_IsQueryActive()) {
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"Raw DNS: Skipping encrypted DNS for %s - query already active (re-entrancy protection)", domain);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        return 0;  // Passthrough to avoid re-entrancy
    }
    
    // Query encrypted DNS server
    DOH_RESULT doh_result;
    if (!EncryptedDns_Query(domain, qtype, &doh_result)) {
        // Encrypted DNS query failed - if enabled, return NXDOMAIN instead of passthrough
        // This ensures all DNS traffic goes through encrypted DNS when configured
        if (EncryptedDns_IsEnabled()) {
            // Return NXDOMAIN response (domain doesn't exist)
            if (response_size < sizeof(DNS_WIRE_HEADER)) {
                return -1;  // Buffer too small
            }
            
            // Copy query header and set response flags
            if (query_len >= sizeof(DNS_WIRE_HEADER)) {
                memcpy(response, query, sizeof(DNS_WIRE_HEADER));
                DNS_WIRE_HEADER* resp_hdr = (DNS_WIRE_HEADER*)response;
                resp_hdr->Flags = _htons(0x8183);  // Response, NXDOMAIN (RCODE=3)
                resp_hdr->AnswerRRs = 0;
                resp_hdr->AuthorityRRs = 0;
                resp_hdr->AdditionalRRs = 0;
                
                if (DNS_TraceFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"Raw DNS EncDns: Query failed for %s - returning NXDOMAIN (no fallback)", domain);
                    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
                }
                
                return sizeof(DNS_WIRE_HEADER);  // Return minimal NXDOMAIN response
            }
            return -1;
        }
        return 0;  // Encrypted DNS disabled - passthrough to system DNS
    }
    
    if (!doh_result.Success) {
        // Encrypted DNS returned error - same handling as query failure
        if (EncryptedDns_IsEnabled()) {
            if (response_size < sizeof(DNS_WIRE_HEADER) || query_len < sizeof(DNS_WIRE_HEADER)) {
                return -1;
            }
            memcpy(response, query, sizeof(DNS_WIRE_HEADER));
            DNS_WIRE_HEADER* resp_hdr = (DNS_WIRE_HEADER*)response;
            resp_hdr->Flags = _htons(0x8183);  // Response, NXDOMAIN
            resp_hdr->AnswerRRs = 0;
            resp_hdr->AuthorityRRs = 0;
            resp_hdr->AdditionalRRs = 0;
            return sizeof(DNS_WIRE_HEADER);
        }
        return 0;  // Encrypted DNS disabled - passthrough
    }
    
    // For non-A/AAAA types (MX, TXT, CNAME, SRV, etc.), use raw wire format response
    // This ensures all DNS record types work through encrypted DNS
    if (qtype != DNS_TYPE_A && qtype != DNS_TYPE_AAAA) {
        if (doh_result.RawResponseLen > 0 && (int)doh_result.RawResponseLen <= response_size) {
            // Copy raw DNS response directly (already in wire format)
            memcpy(response, doh_result.RawResponse, doh_result.RawResponseLen);

            // Apply DNS rebind protection to the raw wire response
            // This is critical for ANY queries or other types that might carry 
            // filtered IPs in the Answer/Additional sections.
            ULONG filteredA = 0;
            ULONG filteredAAAA = 0;
            int new_len = 0;
            
            if (DNS_Rebind_SanitizeDnsWireResponse(response, (int)doh_result.RawResponseLen, domain, FALSE, &filteredA, &filteredAAAA, &new_len)) {
                // Update length after filtering
                doh_result.RawResponseLen = (DWORD)new_len;
            }

            // IMPORTANT: Preserve the original transaction ID from the intercepted query.
            // EncDns builds its own query (and therefore its own TransactionID) when calling
            // the DoH/DoQ backend. Raw-socket clients (e.g. nslookup -novc) match responses
            // by TransactionID and will discard a valid response if the ID does not match,
            // resulting in a timeout even though we injected bytes back to the socket.
            if (query && query_len >= (int)sizeof(DNS_WIRE_HEADER) &&
                doh_result.RawResponseLen >= sizeof(DNS_WIRE_HEADER)) {
                ((DNS_WIRE_HEADER*)response)->TransactionID = ((DNS_WIRE_HEADER*)query)->TransactionID;
            }
            
            DNS_LogRawSocketEncDnsRawResponse(protocol ? protocol : L"Raw", domain, qtype,
                                             doh_result.ProtocolUsed, (int)doh_result.RawResponseLen);
            
            return (int)doh_result.RawResponseLen;
        }
        // No raw response available - return NODATA (domain exists, no records of this type)
        if (response_size >= sizeof(DNS_WIRE_HEADER) && query_len >= sizeof(DNS_WIRE_HEADER)) {
            memcpy(response, query, sizeof(DNS_WIRE_HEADER));
            DNS_WIRE_HEADER* resp_hdr = (DNS_WIRE_HEADER*)response;
            resp_hdr->Flags = _htons(0x8180);  // Response, NOERROR (NODATA)
            resp_hdr->AnswerRRs = 0;
            resp_hdr->AuthorityRRs = 0;
            resp_hdr->AdditionalRRs = 0;
            return sizeof(DNS_WIRE_HEADER);
        }
        return -1;
    }
    
    // For A/AAAA types, build response from IP entries
    // Build LIST of IP entries from DoH result (to reuse Socket_BuildDnsResponse)
    LIST ip_list;
    List_Init(&ip_list);
    
    for (int i = 0; i < doh_result.AnswerCount && i < 32; i++) {
        IP_ENTRY* entry = (IP_ENTRY*)Dll_Alloc(sizeof(IP_ENTRY));
        if (entry) {
            entry->Type = doh_result.Answers[i].Type;
            memcpy(&entry->IP, &doh_result.Answers[i].IP, sizeof(IP_ADDRESS));
            List_Insert_After(&ip_list, NULL, entry);
        }
    }
    
    BYTE edns_buffer[256];
    int edns_len = Socket_ExtractEdnsRecord(query, query_len, edns_buffer, sizeof(edns_buffer));
    
    // Extract DO flag from EDNS for DNSSEC support
    // OPT record layout in edns_buffer: [0]=root, [1-2]=TYPE, [3-4]=UDP size,
    // [5]=ExtRCODE, [6]=Version, [7-8]=Flags(DO+Z), [9-10]=RDLEN
    USHORT edns_flags = 0;
    if (edns_len >= 11) {
        edns_flags = (edns_buffer[7] << 8) | edns_buffer[8];  // DO+Z flags at offset 7-8
    }
    BOOLEAN do_flag = (edns_flags & DNS_EDNS_FLAG_DO) != 0;
    
    // Determine DNSSEC mode for this domain (independent of app's EDNS/DO flag)
    DNSSEC_MODE dnssec_mode = DNSSEC_MODE_DISABLED;  // Default
    if (domain) {
        dnssec_mode = DNS_DnssecGetMode(domain);
    }
    
    // Mode ENABLED (y) = always use raw response when RRSIG present, skip rebind
    // Our EncDns/DoH query always includes EDNS+DO, so DNSSEC-signed domains return RRSIG
    // regardless of whether the app requested EDNS+DO
    if (dnssec_mode == DNSSEC_MODE_ENABLED && doh_result.RawResponseLen > 0) {
        if (DNS_Dnssec_ResponseHasRrsig(doh_result.RawResponse, (int)doh_result.RawResponseLen)) {
            if ((int)doh_result.RawResponseLen <= response_size) {
                memcpy(response, doh_result.RawResponse, doh_result.RawResponseLen);
                
                // Preserve original transaction ID from query
                if (query_len >= (int)sizeof(DNS_WIRE_HEADER)) {
                    ((DNS_WIRE_HEADER*)response)->TransactionID = ((DNS_WIRE_HEADER*)query)->TransactionID;
                }
                
                // Free the IP list
                IP_ENTRY* entry_free = (IP_ENTRY*)List_Head(&ip_list);
                while (entry_free) {
                    IP_ENTRY* next_free = (IP_ENTRY*)List_Next(entry_free);
                    Dll_Free(entry_free);
                    entry_free = next_free;
                }
                
                if (DNS_TraceFlag) {
                    WCHAR msg[512];
                    Sbie_snwprintf(msg, 512, L"%s DNS EncDns: DNSSEC pass-through for %s (DnssecEnabled=y, RRSIG present, raw len=%d, app_DO=%d)",
                        protocol ? protocol : L"Raw", domain, (int)doh_result.RawResponseLen, do_flag ? 1 : 0);
                    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
                }
                
                return (int)doh_result.RawResponseLen;
            }
        }
        // No RRSIG in raw response: domain doesn't support DNSSEC, fall through to synthetic response
    }
    
    // Mode FILTER (f) = use raw response only when app sent EDNS+DO (respect app's DNSSEC choice)
    // Always apply IP filtering (rebind protection) even with RRSIG present
    if (dnssec_mode == DNSSEC_MODE_FILTER && do_flag && doh_result.RawResponseLen > 0) {
        if ((int)doh_result.RawResponseLen <= response_size) {
            memcpy(response, doh_result.RawResponse, doh_result.RawResponseLen);
            
            // Preserve original transaction ID from query
            if (query_len >= (int)sizeof(DNS_WIRE_HEADER)) {
                ((DNS_WIRE_HEADER*)response)->TransactionID = ((DNS_WIRE_HEADER*)query)->TransactionID;
            }
            
            // Apply IP filtering in-place (replaces filtered IPs with valid duplicate, preserves RRSIG)
            ULONG filteredA = 0, filteredAAAA = 0;
            DNS_Rebind_SanitizeDnsWireResponseKeepLengthNodata(
                response, (int)doh_result.RawResponseLen, domain, FALSE,
                &filteredA, &filteredAAAA);
            
            // Free the IP list
            IP_ENTRY* entry_free = (IP_ENTRY*)List_Head(&ip_list);
            while (entry_free) {
                IP_ENTRY* next_free = (IP_ENTRY*)List_Next(entry_free);
                Dll_Free(entry_free);
                entry_free = next_free;
            }
            
            if (DNS_TraceFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"%s DNS EncDns: DNSSEC filter-mode for %s (raw len=%d, filtered A=%lu AAAA=%lu)",
                    protocol ? protocol : L"Raw", domain, (int)doh_result.RawResponseLen, filteredA, filteredAAAA);
                SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
            }
            
            return (int)doh_result.RawResponseLen;
        }
    }
    
    // Build DNS response using existing function
    int response_len = Socket_BuildDnsResponse(
        query, query_len, &ip_list, FALSE, response, response_size, qtype, NULL, domain,
        edns_len > 0 ? edns_buffer : NULL, edns_len, dnssec_mode);
    
    // Free the IP list
    IP_ENTRY* entry = (IP_ENTRY*)List_Head(&ip_list);
    while (entry) {
        IP_ENTRY* next = (IP_ENTRY*)List_Next(entry);
        Dll_Free(entry);
        entry = next;
    }
    
    if (response_len > 0 && DNS_TraceFlag) {
        WCHAR msg[512];
        DNS_WIRE_HEADER* resp_hdr = (DNS_WIRE_HEADER*)response;
        USHORT answer_rrs = (response_len >= sizeof(DNS_WIRE_HEADER)) ? _ntohs(resp_hdr->AnswerRRs) : 0;
        if (doh_result.ProtocolUsed != ENCRYPTED_DNS_MODE_AUTO) {
            Sbie_snwprintf(msg, 512, L"%s DNS EncDns(%s): Built response for %s (Type: %s, IPs: %d, response_len: %d, AnswerRRs: %d)",
                protocol ? protocol : L"Raw", EncryptedDns_GetModeName(doh_result.ProtocolUsed),
                domain, DNS_GetTypeName(qtype), doh_result.AnswerCount, response_len, answer_rrs);
        } else {
            Sbie_snwprintf(msg, 512, L"%s DNS EncDns: Built response for %s (Type: %s, IPs: %d, response_len: %d, AnswerRRs: %d)",
                protocol ? protocol : L"Raw", domain, DNS_GetTypeName(qtype), doh_result.AnswerCount, response_len, answer_rrs);
        }
        SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
    }
    
    return response_len;
}

//---------------------------------------------------------------------------
// Socket_IsDnsPort
//
// Check if a destination port matches the configured DNS port list.
// If custom ports are configured via FilterRawDns=y:port1;port2;...,
// only those ports are matched. Otherwise defaults to port 53.
//---------------------------------------------------------------------------

static BOOLEAN Socket_IsDnsPort(USHORT port)
{
    if (DNS_CustomPortCount > 0) {
        for (int i = 0; i < DNS_CustomPortCount; i++) {
            if (DNS_CustomPorts[i] == port)
                return TRUE;
        }
        return FALSE;
    }
    // Default: standard DNS port only
    return (port == 53);
}

//---------------------------------------------------------------------------
// Socket_ParseFilterRawDnsPorts
//
// Parse custom port list from FilterRawDns value after the colon.
// Format: "y:port1;port2;..." or "y" (no ports = default to 53)
// Stores parsed ports in DNS_CustomPorts array.
//---------------------------------------------------------------------------

static void Socket_ParseFilterRawDnsPorts(const WCHAR* port_str)
{
    if (!port_str || !port_str[0])
        return;

    DNS_CustomPortCount = 0;

    const WCHAR* p = port_str;
    while (*p && DNS_CustomPortCount < DNS_MAX_CUSTOM_PORTS) {
        // Skip separators
        while (*p == L';' || *p == L' ')
            p++;
        if (!*p)
            break;

        // Parse port number
        USHORT port = 0;
        while (*p >= L'0' && *p <= L'9') {
            port = port * 10 + (USHORT)(*p - L'0');
            p++;
        }

        if (port > 0 && port <= 65535) {
            // Check for duplicates
            BOOLEAN dup = FALSE;
            for (int i = 0; i < DNS_CustomPortCount; i++) {
                if (DNS_CustomPorts[i] == port) { dup = TRUE; break; }
            }
            if (!dup) {
                DNS_CustomPorts[DNS_CustomPortCount++] = port;
            }
        }

        // Skip to next separator
        while (*p && *p != L';')
            p++;
    }
}

//---------------------------------------------------------------------------
// Socket_GetRawDnsFilterEnabled
//
// Query the FilterRawDns setting to control raw socket DNS filtering.
// Syntax: FilterRawDns=[process,]y|n[:port1[;port2;...]]
//   - y: Enable filtering (default port 53 if no ports specified)
//   - n: Disable filtering (ports ignored)
//   - :port1;port2: Custom ports to monitor (only when enabled)
//
// Default: Disabled (user must explicitly enable with FilterRawDns=y)
// Note: Logging is still allowed without certificate when DnsTrace=y
//---------------------------------------------------------------------------

extern const WCHAR* Dll_ImageName;

_FX BOOLEAN Socket_GetRawDnsFilterEnabled(BOOLEAN has_valid_certificate)
{
    WCHAR value[256];
    SbieDll_GetSettingsForName(NULL, Dll_ImageName, L"FilterRawDns", value, sizeof(value), NULL);

    if (!value[0])
        return FALSE;

    // Check for y/n prefix
    WCHAR ch = value[0];
    BOOLEAN enabled = (ch == L'y' || ch == L'Y');

    // Parse optional port list after colon (only when first call sets it up)
    if (enabled && DNS_CustomPortCount == 0) {
        const WCHAR* colon = wcschr(value, L':');
        if (colon) {
            Socket_ParseFilterRawDnsPorts(colon + 1);
            if (DNS_CustomPortCount > 0) {
                DNS_TRACE_LOG(L"[FilterRawDns] Custom ports configured: %d port(s)", DNS_CustomPortCount);
                for (int i = 0; i < DNS_CustomPortCount; i++) {
                    DNS_DEBUG_LOG(L"[FilterRawDns] Port[%d]: %d", i, DNS_CustomPorts[i]);
                }
            }
        }
    }

    return enabled;
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
    P_WSARecv WSARecv;
    P_WSARecvFrom WSARecvFrom;

    // Initialize getsockopt early (needed for Socket_IsTcpSocket even if hooking is disabled)
    if (!__sys_getsockopt) {
        __sys_getsockopt = (P_getsockopt)GetProcAddress(module, "getsockopt");
    }

    // Load FilterRawDns setting (default: disabled, user must explicitly enable)
    // FilterRawDns controls both hooks and filtering:
    //   - When enabled: installs hooks, applies NetworkDnsFilter rules AND rebind protection
    //   - When disabled: no hooks, no filtering, no rebind protection
    DNS_RawSocketFilterEnabled = Socket_GetRawDnsFilterEnabled(has_valid_certificate); // filtering only (requires cert)
    DNS_RawSocketHooksEnabled   = Socket_GetRawDnsFilterEnabled(TRUE);                 // hooks enabled when FilterRawDns=y (ignoring cert)

    // Also enable raw socket hooks when EncryptedDnsServer is configured.
    // This allows EncryptedDns passthrough for tools like nslookup even when FilterRawDns=n.
    // Note: Rebind protection still requires FilterRawDns=y (controlled by DNS_RawSocketFilterEnabled).
    if (!DNS_RawSocketHooksEnabled && EncryptedDns_IsEnabled()) {
        DNS_RawSocketHooksEnabled = TRUE;
    }

    // Certificate validation logic has been moved to filtering time (in send hooks)
    // Here we only control whether hooks are installed at all
    // Install hooks when FilterRawDns=y (explicit enable)
    // If no certificate, hooks are installed but filtering is disabled (logging only)
    extern LIST DNS_FilterList;

    // Load DnsDebug setting for verbose logging (supports per-process: DnsDebug=program.exe,y)
#if defined(_DNSDEBUG)
    DNS_DebugFlag = Config_GetSettingsForImageName_bool(L"DnsDebug", FALSE);
#endif

    // CRITICAL: Always initialize critical sections BEFORE early return
    // These are used by hooks that may be installed via other paths (e.g., WSARecvMsg)
    // even when FilterRawDns=n. Failure to initialize causes crashes when DnsTrace=y.
    InitializeCriticalSection(&g_ResponseTableLock);
    InitializeCriticalSection(&g_TcpReassemblyLock);
    InitializeCriticalSection(&g_DnsSocketTableLock);
    InitializeCriticalSection(&g_SocketEventMappingsLock);
    
    // Initialize per-socket response queue table
    for (int i = 0; i < RESPONSE_QUEUE_TABLE_SIZE; i++) {
        g_ResponseQueueTable[i] = NULL;
    }
    
    // Initialize TCP reassembly table
    for (int i = 0; i < TCP_REASSEMBLY_TABLE_SIZE; i++) {
        g_TcpReassemblyTable[i].active = FALSE;
        g_TcpReassemblyTable[i].bytes_received = 0;
        g_TcpReassemblyTable[i].expected_length = -1;
    }

    // Initialize DNS socket tracking table
    for (int i = 0; i < DNS_SOCKET_TABLE_SIZE; i++) {
        g_DnsSockets[i] = INVALID_SOCKET;
        g_DnsSocketFlags[i] = FALSE;
        g_DnsServerAddrLens[i] = 0;
        memset(g_DnsServerAddrs[i], 0, DNS_SERVER_ADDR_SIZE);
        g_PendingQueries[i].Valid = FALSE;
        g_PendingQueries[i].Domain[0] = L'\0';
        g_PendingQueries[i].QueryType = 0;
        g_PendingQueries[i].IsTcp = FALSE;
        g_PendingQueries[i].PassthroughReason = DNS_PASSTHROUGH_NONE;
    }
    
    // Initialize socket-to-event mappings table
    for (int i = 0; i < SOCKET_EVENT_MAPPING_SIZE; i++) {
        g_SocketEventMappings[i].socket = INVALID_SOCKET;
        g_SocketEventMappings[i].hEvent = NULL;
        g_SocketEventMappings[i].timestamp = 0;
    }
    
    // If neither filtering nor logging are enabled, skip hooking
    if (!DNS_RawSocketHooksEnabled) {
        return TRUE;
    }

    // Hook connect (to track DNS connections)
    connect = (P_connect)GetProcAddress(module, "connect");
    if (connect) {
        SBIEDLL_HOOK(Socket_, connect);
    }

    // Hook WSAConnect (overlapped connect - used by .NET)
    // NOTE: Also hooked in net.c for firewall/proxy - hooks chain correctly
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

    // Hook WSASendTo (overlapped UDP send + TCP via connected sockets)
    // NOTE: Also hooked in net.c for firewall/BindIP - hooks chain correctly
    // This hook handles TCP DNS reassembly which net.c doesn't do
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

    // Hook WSARecv (overlapped TCP recv - used by dig, .NET, and other modern apps)
    WSARecv = (P_WSARecv)GetProcAddress(module, "WSARecv");
    if (WSARecv) {
        SBIEDLL_HOOK(Socket_, WSARecv);
    }

    // Hook WSARecvFrom (overlapped UDP recv)
    // NOTE: Also hooked in net.c for firewall/BindIP - hooks chain correctly
    WSARecvFrom = (P_WSARecvFrom)GetProcAddress(module, "WSARecvFrom");
    if (WSARecvFrom) {
        SBIEDLL_HOOK(Socket_, WSARecvFrom);
    }

    // Hook select (to make DNS sockets with fake responses appear readable)
    __sys_select = (P_select)GetProcAddress(module, "select");
    if (__sys_select) {
        P_select select = __sys_select;
        SBIEDLL_HOOK(Socket_, select);
    }

    // Hook WSAPoll (modern alternative to select, used by dig and other tools)
    __sys_WSAPoll = (P_WSAPoll)GetProcAddress(module, "WSAPoll");
    if (__sys_WSAPoll) {
        P_WSAPoll WSAPoll = __sys_WSAPoll;
        SBIEDLL_HOOK(Socket_, WSAPoll);
    }

    // Hook getpeername (to return DNS server address for sockets answered locally)
    __sys_getpeername = (P_getpeername)GetProcAddress(module, "getpeername");
    if (__sys_getpeername) {
        P_getpeername getpeername = __sys_getpeername;
        SBIEDLL_HOOK(Socket_, getpeername);
    }

    // Hook WSAEnumNetworkEvents (for Cygwin async I/O - inject FD_READ for fake responses)
    // NOTE: Also hooked in net.c for proxy hack - hooks chain correctly
    __sys_WSAEnumNetworkEvents = (P_WSAEnumNetworkEvents)GetProcAddress(module, "WSAEnumNetworkEvents");
    if (__sys_WSAEnumNetworkEvents) {
        P_WSAEnumNetworkEvents WSAEnumNetworkEvents = __sys_WSAEnumNetworkEvents;
        SBIEDLL_HOOK(Socket_, WSAEnumNetworkEvents);
    }

    // Note: WSAIoctl is hooked in net.c (WSA_WSAIoctl) which also handles WSARecvMsg interception
    // for our DNS filtering. We just need to store the WSARecvMsg function pointer when we get it.

    return TRUE;
}

//---------------------------------------------------------------------------
// Socket_IsDnsSocket
//
// Check if a socket is marked as a DNS connection
// Thread-safe: uses critical section to prevent race conditions
//---------------------------------------------------------------------------

_FX BOOLEAN Socket_IsDnsSocket(SOCKET s)
{
    ULONG index = ((ULONG_PTR)s) % DNS_SOCKET_TABLE_SIZE;
    EnterCriticalSection(&g_DnsSocketTableLock);
    BOOLEAN result = (g_DnsSockets[index] == s && g_DnsSocketFlags[index]);
    LeaveCriticalSection(&g_DnsSocketTableLock);
    return result;
}

//---------------------------------------------------------------------------
// Socket_MarkDnsSocket
//
// Mark a socket as DNS connection (or unmark it)
// Thread-safe: uses critical section to prevent race conditions
//---------------------------------------------------------------------------

_FX void Socket_MarkDnsSocket(SOCKET s, BOOLEAN isDns)
{
    ULONG index = ((ULONG_PTR)s) % DNS_SOCKET_TABLE_SIZE;
    EnterCriticalSection(&g_DnsSocketTableLock);
    g_DnsSockets[index] = s;
    g_DnsSocketFlags[index] = isDns;
    LeaveCriticalSection(&g_DnsSocketTableLock);
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
// TCP DNS Reassembly Functions
//
// Accumulate partial TCP sends until we have a complete DNS message.
// Some applications (like Cygwin dig) send in fragments:
//   - First WSASendTo: 2-byte length prefix only
//   - Second WSASendTo: DNS query payload
//---------------------------------------------------------------------------

_FX TCP_REASSEMBLY_BUFFER* Socket_GetReassemblyBuffer(SOCKET s, BOOLEAN create)
{
    ULONG index = ((ULONG_PTR)s) % TCP_REASSEMBLY_TABLE_SIZE;
    DWORD now = GetTickCount();
    
    EnterCriticalSection(&g_TcpReassemblyLock);
    
    TCP_REASSEMBLY_BUFFER* buf = &g_TcpReassemblyTable[index];
    
    if (buf->active && buf->socket == s) {
        // Check for timeout
        if (now - buf->timestamp > TCP_REASSEMBLY_TIMEOUT_MS) {
            // Stale buffer - reset it
            buf->active = FALSE;
            buf->bytes_received = 0;
            buf->expected_length = -1;
            
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"TCP DNS: Reassembly buffer timed out for socket=%p, discarding %d bytes",
                    (void*)(ULONG_PTR)s, buf->bytes_received);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
        }
    }
    
    if (!buf->active && create) {
        // Create new buffer
        buf->socket = s;
        buf->bytes_received = 0;
        buf->expected_length = -1;
        buf->timestamp = now;
        buf->active = TRUE;
    }
    
    if (!buf->active || buf->socket != s) {
        LeaveCriticalSection(&g_TcpReassemblyLock);
        return NULL;  // No buffer found
    }
    
    LeaveCriticalSection(&g_TcpReassemblyLock);
    return buf;
}

_FX void Socket_ClearReassemblyBuffer(SOCKET s)
{
    ULONG index = ((ULONG_PTR)s) % TCP_REASSEMBLY_TABLE_SIZE;
    
    EnterCriticalSection(&g_TcpReassemblyLock);
    
    TCP_REASSEMBLY_BUFFER* buf = &g_TcpReassemblyTable[index];
    if (buf->active && buf->socket == s) {
        buf->active = FALSE;
        buf->bytes_received = 0;
        buf->expected_length = -1;
    }
    
    LeaveCriticalSection(&g_TcpReassemblyLock);
}

// Returns:
//   0 = Need more data (continue accumulating)
//   1 = Complete message available (buffer contains full DNS message)
//  -1 = Error (invalid data, buffer overflow, etc.)
_FX int Socket_AddToReassemblyBuffer(SOCKET s, const BYTE* data, int len, BYTE** outBuffer, int* outLen)
{
    if (len <= 0 || !data) return -1;
    
    TCP_REASSEMBLY_BUFFER* buf = Socket_GetReassemblyBuffer(s, TRUE);
    if (!buf) return -1;
    
    EnterCriticalSection(&g_TcpReassemblyLock);
    
    // Check for buffer overflow
    if (buf->bytes_received + len > TCP_REASSEMBLY_BUFFER_SIZE) {
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"TCP DNS: Reassembly buffer overflow for socket=%p, have=%d, adding=%d",
                (void*)(ULONG_PTR)s, buf->bytes_received, len);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        buf->active = FALSE;
        LeaveCriticalSection(&g_TcpReassemblyLock);
        return -1;
    }
    
    // Append data
    memcpy(buf->buffer + buf->bytes_received, data, len);
    buf->bytes_received += len;
    
    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"TCP DNS: Reassembly buffer now has %d bytes for socket=%p",
            buf->bytes_received, (void*)(ULONG_PTR)s);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    // Check if we have the length prefix yet
    if (buf->bytes_received >= 2 && buf->expected_length < 0) {
        // Parse 2-byte length prefix (network byte order)
        USHORT tcp_length = (buf->buffer[0] << 8) | buf->buffer[1];
        buf->expected_length = 2 + tcp_length;  // Total = prefix + payload
        
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"TCP DNS: Length prefix parsed, expecting %d total bytes, have %d",
                buf->expected_length, buf->bytes_received);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        
        // Validate expected length
        if (buf->expected_length > TCP_REASSEMBLY_BUFFER_SIZE) {
            buf->active = FALSE;
            LeaveCriticalSection(&g_TcpReassemblyLock);
            return -1;  // Message too large
        }
    }
    
    // Check if message is complete
    if (buf->expected_length > 0 && buf->bytes_received >= buf->expected_length) {
        // Message complete!
        if (outBuffer) *outBuffer = buf->buffer;
        if (outLen) *outLen = buf->bytes_received;
        
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"TCP DNS: Reassembly complete, %d bytes total for socket=%p",
                buf->bytes_received, (void*)(ULONG_PTR)s);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        
        LeaveCriticalSection(&g_TcpReassemblyLock);
        return 1;  // Complete message
    }
    
    LeaveCriticalSection(&g_TcpReassemblyLock);
    return 0;  // Need more data
}

// Send the complete reassembled TCP DNS data to the server
// This is called when we need to passthrough a DNS query that was reassembled
// 
// IMPORTANT: We must support both synchronous and overlapped I/O modes.
// If overlapped parameters are provided, we pass them through to preserve async semantics.
// Returns: 0 on success, SOCKET_ERROR on failure (or WSA_IO_PENDING for async)
_FX int Socket_SendReassembledData(
    SOCKET s, 
    LPDWORD lpNumberOfBytesSent,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    ULONG index = ((ULONG_PTR)s) % TCP_REASSEMBLY_TABLE_SIZE;
    int result = SOCKET_ERROR;
    
    EnterCriticalSection(&g_TcpReassemblyLock);
    
    TCP_REASSEMBLY_BUFFER* buf = &g_TcpReassemblyTable[index];
    if (buf->active && buf->socket == s && buf->bytes_received > 0) {
        // Create a WSABUF for the reassembled data
        WSABUF_REAL wsabuf;
        wsabuf.len = buf->bytes_received;
        wsabuf.buf = (char*)buf->buffer;
        
        DWORD bytesSent = 0;
        
        // Pass through overlapped parameters to preserve async I/O semantics
        // This fixes the bug where we were forcing synchronous sends and breaking
        // applications that use overlapped I/O (like Cygwin dig with async sockets)
        result = __sys_WSASendTo(s, (LPWSABUF)&wsabuf, 1, &bytesSent, 0, NULL, 0, 
                                  lpOverlapped, lpCompletionRoutine);
        
        if (result == 0 && lpNumberOfBytesSent) {
            *lpNumberOfBytesSent = bytesSent;
        }
        
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"TCP DNS: Sent reassembled data (%d bytes) to server, result=%d, overlapped=%s",
                buf->bytes_received, result, lpOverlapped ? L"yes" : L"no");
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        
        // Clear the buffer after sending
        buf->active = FALSE;
        buf->bytes_received = 0;
        buf->expected_length = -1;
    }
    
    LeaveCriticalSection(&g_TcpReassemblyLock);
    return result;
}

//---------------------------------------------------------------------------
// Socket_TrackDnsConnection
//
// Common helper to track DNS connections (port 53) for connect/WSAConnect
// Stores the DNS server address for getpeername() spoofing
//
// Returns: TRUE if this is a DNS connection, FALSE otherwise
//---------------------------------------------------------------------------

static BOOLEAN Socket_TrackDnsConnection(SOCKET s, const void* name, int namelen, const WCHAR* func_name)
{
    if (!DNS_FilterEnabled || !DNS_RawSocketHooksEnabled || !name)
        return FALSE;
    
    USHORT destPort = 0;
    USHORT addrFamily = ((struct sockaddr*)name)->sa_family;

    if (addrFamily == AF_INET && namelen >= sizeof(struct sockaddr_in)) {
        destPort = _ntohs(((struct sockaddr_in*)name)->sin_port);
    }
    else if (addrFamily == AF_INET6 && namelen >= sizeof(struct sockaddr_in6)) {
        destPort = _ntohs(((struct sockaddr_in6*)name)->sin6_port);
    }

    // Mark socket as DNS if connecting to a DNS port
    if (Socket_IsDnsPort(destPort)) {
        Socket_MarkDnsSocket(s, TRUE);
        
        // Store DNS server address for getpeername() support (thread-safe)
        ULONG index = ((ULONG_PTR)s) % DNS_SOCKET_TABLE_SIZE;
        EnterCriticalSection(&g_DnsSocketTableLock);
        if (namelen <= DNS_SERVER_ADDR_SIZE) {
            memcpy(g_DnsServerAddrs[index], name, namelen);
            g_DnsServerAddrLens[index] = namelen;
        }
        LeaveCriticalSection(&g_DnsSocketTableLock);
        
        // Log DNS connection detection with protocol type
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            BOOLEAN isTcp = Socket_IsTcpSocket(s);
            Sbie_snwprintf(msg, 256, L"  %s DNS Debug: %s detected port %d, socket=%p marked as DNS",
                isTcp ? L"TCP" : L"UDP", func_name, destPort, (void*)(ULONG_PTR)s);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        return TRUE;
    } else {
        Socket_MarkDnsSocket(s, FALSE);
        return FALSE;
    }
}

//---------------------------------------------------------------------------
// Socket_TrackDnsConnectionEx
//
// Exported wrapper for Socket_TrackDnsConnection - called from net.c
//---------------------------------------------------------------------------

_FX BOOLEAN Socket_TrackDnsConnectionEx(SOCKET s, const void* name, int namelen)
{
    return Socket_TrackDnsConnection(s, name, namelen, L"WSAConnect");
}

//---------------------------------------------------------------------------
// Socket_DetectTcpLengthPrefix
//
// Detects TCP DNS length prefix and extracts the actual DNS payload.
// TCP DNS format: [2-byte length prefix][DNS payload]
//
// Returns: TRUE if length prefix detected, FALSE otherwise
// On success, *out_payload and *out_payload_len point to the DNS data
//---------------------------------------------------------------------------

static BOOLEAN Socket_DetectTcpLengthPrefix(
    const BYTE* buf,
    int len,
    const BYTE** out_payload,
    int* out_payload_len)
{
    if (!buf || len < 2 + sizeof(DNS_WIRE_HEADER) || !out_payload || !out_payload_len)
        return FALSE;
    
    // Check for TCP DNS length prefix (2 bytes in network byte order)
    // Be careful: DNS transaction ID could be misinterpreted as length prefix!
    // Only treat as length prefix if:
    // 1. Length matches exactly (tcp_length + 2 == len)
    // 2. The remaining bytes look like a valid DNS header
    // 3. Length is within reasonable DNS bounds (12 bytes minimum, up to 65535 per RFC 1035)
    //    Note: We use 4096 as practical upper bound (EDNS0 common size per RFC 6891)
    // 4. QR bit is 0 (query, not response)
    
    USHORT tcp_length = _ntohs(*(USHORT*)buf);
    
    // Removed 512-byte limit that allowed filter bypass via EDNS0 padding
    // TCP DNS supports up to 65535 bytes, we accept up to 4096 (common EDNS0 size)
    if (tcp_length + 2 == len && 
        tcp_length >= sizeof(DNS_WIRE_HEADER) && 
        tcp_length <= 4096) {
        
        // Validate: check if bytes after prefix look like DNS header
        DNS_WIRE_HEADER* potential_header = (DNS_WIRE_HEADER*)(buf + 2);
        USHORT flags = _ntohs(potential_header->Flags);
        USHORT qr = (flags >> 15) & 0x1;
        
        // If this looks like a query (QR=0) and has questions, treat as TCP DNS with length prefix
        if (qr == 0 && _ntohs(potential_header->Questions) > 0) {
            *out_payload = buf + 2;
            *out_payload_len = tcp_length;
            
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"TCP DNS: Detected length prefix, payload=%d bytes", tcp_length);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            return TRUE;
        }
    }
    
    return FALSE;
}

//---------------------------------------------------------------------------
// DNS Query Processing Result
//---------------------------------------------------------------------------

typedef enum _DNS_PROCESS_RESULT {
    DNS_PROCESS_PASSTHROUGH = 0,    // No match or passthrough - call real function
    DNS_PROCESS_INTERCEPTED = 1,    // Intercepted - fake response queued, return success
    DNS_PROCESS_ERROR = -1          // Error - return success without sending
} DNS_PROCESS_RESULT;

//---------------------------------------------------------------------------
// Socket_ProcessDnsQuery
//
// Centralized DNS query processing for all send hooks.
// Handles domain matching, certificate check, response building, and queuing.
//
// Parameters:
//   s              - Socket handle
//   dns_payload    - DNS query packet (without TCP length prefix)
//   dns_payload_len- Length of DNS query
//   to             - Destination address (NULL for TCP connected sockets)
//   protocol       - "TCP" or "UDP" for logging
//   func_name      - Function name for logging (e.g., "send", "WSASendTo")
//
// Returns: DNS_PROCESS_RESULT indicating action taken
//---------------------------------------------------------------------------

static DNS_PROCESS_RESULT Socket_ProcessDnsQuery(
    SOCKET s,
    const BYTE* dns_payload,
    int dns_payload_len,
    const void* to,
    const WCHAR* protocol,
    const WCHAR* func_name)
{
    WCHAR domainName[256];
    USHORT qtype = 0;

    // Parse DNS query packet
    if (!Socket_ParseDnsQuery(dns_payload, dns_payload_len, domainName, 256, &qtype)) {
        return DNS_PROCESS_PASSTHROUGH;  // Not a valid DNS query
    }

    // Literal IP QNAMEs are not filterable DNS domains.
    if (Socket_TryHandleIpLiteralDnsQuery(s, dns_payload, dns_payload_len, to, protocol, func_name, domainName, qtype)) {
        return DNS_PROCESS_INTERCEPTED;
    }
    
    // Prepare lowercase domain for matching
    ULONG domain_len = wcslen(domainName);
    WCHAR* domain_lwr = (WCHAR*)Dll_AllocTemp((domain_len + 4) * sizeof(WCHAR));
    if (!domain_lwr)
        return DNS_PROCESS_PASSTHROUGH;
    
    wmemcpy(domain_lwr, domainName, domain_len);
    domain_lwr[domain_len] = L'\0';
    _wcslwr(domain_lwr);

    // Check if domain matches filter rules
    PATTERN* found = NULL;
    int match_result = Socket_MatchDomainHierarchical(domain_lwr, domain_len, &found);
    
    if (match_result <= 0) {
        // Domain not in filter list - try encrypted DNS if configured, otherwise passthrough
        if (EncryptedDns_IsEnabled()) {
            BYTE response[DNS_RESPONSE_SIZE];
            int response_len = Socket_BuildDoHResponse(dns_payload, dns_payload_len, domain_lwr, qtype, response, DNS_RESPONSE_SIZE, protocol);
            if (response_len > 0) {
                // Encrypted DNS succeeded - queue the response
                // Socket_AddFakeResponse handles TCP length prefix automatically
                Socket_AddFakeResponse(s, response, response_len, to);
                Dll_Free(domain_lwr);
                return DNS_PROCESS_INTERCEPTED;
            }
        }
        // Encrypted DNS not configured or failed - passthrough
        Socket_LogForwarded(protocol, domainName, qtype, func_name, s, DNS_PASSTHROUGH_NO_MATCH);
        Dll_Free(domain_lwr);
        return DNS_PROCESS_PASSTHROUGH;
    }
    
    // Get auxiliary data containing IP list and type filter
    PVOID* aux = Pattern_Aux(found);
    if (!aux || !*aux) {
        // Even though we have no IPs/filter data, we still need to track this query
        // so that rebind protection can be applied to the server's response.
        // This happens when a domain matches a filter pattern but has no configured IPs.
        Socket_LogForwarded(protocol, domainName, qtype, func_name, s, DNS_PASSTHROUGH_CONFIG_ERROR);
        Dll_Free(domain_lwr);
        return DNS_PROCESS_PASSTHROUGH;
    }

    // Certificate required for actual filtering (interception/blocking)
    extern BOOLEAN DNS_HasValidCertificate;
    if (!DNS_HasValidCertificate) {
        // No certificate - try encrypted DNS if configured, otherwise passthrough
        if (EncryptedDns_IsEnabled()) {
            BYTE response[DNS_RESPONSE_SIZE];
            int response_len = Socket_BuildDoHResponse(dns_payload, dns_payload_len, domain_lwr, qtype, response, DNS_RESPONSE_SIZE, protocol);
            if (response_len > 0) {
                // Socket_AddFakeResponse handles TCP length prefix automatically
                Socket_AddFakeResponse(s, response, response_len, to);
                Dll_Free(domain_lwr);
                return DNS_PROCESS_INTERCEPTED;
            }
        }
        Socket_LogForwarded(protocol, domainName, qtype, func_name, s, DNS_PASSTHROUGH_NO_CERT);
        Dll_Free(domain_lwr);
        return DNS_PROCESS_PASSTHROUGH;
    }

    // Extract type filter early to check for negated types
    LIST* pEntries = NULL;
    DNS_TYPE_FILTER* type_filter = NULL;
    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);
    
    // Check if type is negated (explicit passthrough)
    BOOLEAN is_negated = DNS_IsTypeNegated(type_filter, qtype);
    if (is_negated) {
        // Type is negated (!type or !*) - try encrypted DNS if configured, otherwise passthrough
        if (EncryptedDns_IsEnabled()) {
            BYTE response[DNS_RESPONSE_SIZE];
            int response_len = Socket_BuildDoHResponse(dns_payload, dns_payload_len, domain_lwr, qtype, response, DNS_RESPONSE_SIZE, protocol);
            if (response_len > 0) {
                // Socket_AddFakeResponse handles TCP length prefix automatically
                Socket_AddFakeResponse(s, response, response_len, to);
                Dll_Free(domain_lwr);
                return DNS_PROCESS_INTERCEPTED;
            }
        }
        Socket_LogFilterPassthrough(protocol, domainName, qtype, func_name, s, DNS_PASSTHROUGH_TYPE_NEGATED);
        Dll_Free(domain_lwr);
        return DNS_PROCESS_PASSTHROUGH;
    }

    // Build fake DNS response
    BYTE response[DNS_RESPONSE_SIZE];
    int response_len = Socket_HandleDnsQuery(
        aux, dns_payload, dns_payload_len, qtype, response, DNS_RESPONSE_SIZE, 
        protocol, domainName);
    
    Dll_Free(domain_lwr);
    
    if (response_len < 0) {
        // Error building response
        return DNS_PROCESS_ERROR;
    }
    
    if (response_len == 0) {
        // Type not in filter list (when filter is set) - passthrough without negation log
        Socket_LogFilterPassthrough(protocol, domainName, qtype, func_name, s, DNS_PASSTHROUGH_TYPE_NOT_FILTERED);
        return DNS_PROCESS_PASSTHROUGH;
    }
    
    // Validate the response before queuing
    if (!Socket_ValidateDnsResponse(response, response_len)) {
        if (DNS_TraceFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"%s DNS: %s built response failed validation, dropping",
                protocol, func_name ? func_name : L"");
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        return DNS_PROCESS_ERROR;
    }
    
    // pEntries and type_filter already extracted above
    
    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"  %s DNS Debug: %s queueing fake response, len=%d bytes",
            protocol, func_name ? func_name : L"", response_len);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    // Queue fake response
    Socket_AddFakeResponse(s, response, response_len, to);
    
    // Log the interception
    Socket_LogInterceptedResponse(protocol, domainName, qtype, dns_payload_len, 
        response, response_len, s, pEntries, func_name);
    
    return DNS_PROCESS_INTERCEPTED;
}

static BOOLEAN Socket_GetDestPortFromSockaddr(const void* addr, int addrlen, USHORT* out_port)
{
    if (!addr || !out_port)
        return FALSE;

    USHORT addrFamily = ((struct sockaddr*)addr)->sa_family;

    if (addrFamily == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        *out_port = _ntohs(((struct sockaddr_in*)addr)->sin_port);
        return TRUE;
    }

    if (addrFamily == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
        *out_port = _ntohs(((struct sockaddr_in6*)addr)->sin6_port);
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN Socket_HandleUdpDnsSend(
    SOCKET s,
    const BYTE* buf,
    int len,
    const void* to,
    int tolen,
    const WCHAR* func_name,
    BOOLEAN log_mark,
    BOOLEAN track_pending,
    DNS_PROCESS_RESULT* out_result)
{
    if (!buf || len < (int)sizeof(DNS_WIRE_HEADER) || !to || !func_name)
        return FALSE;

    USHORT destPort = 0;
    if (!Socket_GetDestPortFromSockaddr(to, tolen, &destPort))
        return FALSE;

    if (!Socket_IsDnsPort(destPort))
        return FALSE;

    if (!Socket_IsDnsSocket(s)) {
        Socket_MarkDnsSocket(s, TRUE);
        if (log_mark && DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"UDP DNS: Marking socket=%p as DNS socket (via %s to port %d)",
                (void*)(ULONG_PTR)s, func_name, destPort);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    }

    if (track_pending) {
        WCHAR domainName[256];
        USHORT qtype = 0;
        if (Socket_ParseDnsQuery(buf, len, domainName, 256, &qtype)) {
            Socket_SetPendingQuery(s, domainName, qtype, FALSE, DNS_PASSTHROUGH_NONE);
        }
    }

    if (DNS_FilterEnabled && DNS_RawSocketFilterEnabled) {
        DNS_PROCESS_RESULT result = Socket_ProcessDnsQuery(s, buf, len, to, L"UDP", func_name);
        if (out_result) {
            *out_result = result;
        }
    } else if (out_result) {
        *out_result = DNS_PROCESS_PASSTHROUGH;
    }

    return TRUE;
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
    // // DEBUG: Log connect calls when verbose debug is enabled
    // if (DNS_FilterEnabled && DNS_RawSocketHooksEnabled && DNS_DebugFlag && name) {
    //     USHORT destPort = 0;
    //     USHORT addrFamily = ((struct sockaddr*)name)->sa_family;
    //     BOOLEAN isTcp = Socket_IsTcpSocket(s);
    //     const WCHAR* protocol = isTcp ? L"TCP" : L"UDP";

    //     if (addrFamily == AF_INET && namelen >= sizeof(struct sockaddr_in)) {
    //         destPort = _ntohs(((struct sockaddr_in*)name)->sin_port);
    //     }
    //     else if (addrFamily == AF_INET6 && namelen >= sizeof(struct sockaddr_in6)) {
    //         destPort = _ntohs(((struct sockaddr_in6*)name)->sin6_port);
    //     }
        
    //     WCHAR msg[256];
    //     Sbie_snwprintf(msg, 256, L"%s: connect() called, AF_%s, port=%d, socket=%p",
    //         protocol, addrFamily == AF_INET ? L"INET" : L"INET6", destPort, (void*)(ULONG_PTR)s);
    //     SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    // }
    
    // Track DNS connection (port 53)
    Socket_TrackDnsConnection(s, name, namelen, L"connect");

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
    // // DEBUG: Log WSAConnect calls when verbose debug is enabled
    // if (DNS_FilterEnabled && DNS_RawSocketHooksEnabled && DNS_DebugFlag && name) {
    //     USHORT destPort = 0;
    //     USHORT addrFamily = ((struct sockaddr*)name)->sa_family;
    //     BOOLEAN isTcp = Socket_IsTcpSocket(s);
    //     const WCHAR* protocol = isTcp ? L"TCP" : L"UDP";

    //     if (addrFamily == AF_INET && namelen >= sizeof(struct sockaddr_in)) {
    //         destPort = _ntohs(((struct sockaddr_in*)name)->sin_port);
    //     }
    //     else if (addrFamily == AF_INET6 && namelen >= sizeof(struct sockaddr_in6)) {
    //         destPort = _ntohs(((struct sockaddr_in6*)name)->sin6_port);
    //     }
        
    //     WCHAR msg[256];
    //     Sbie_snwprintf(msg, 256, L"%s: WSAConnect() called, AF_%s, port=%d, socket=%p",
    //         protocol, addrFamily == AF_INET ? L"INET" : L"INET6", destPort, (void*)(ULONG_PTR)s);
    //     SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    // }
    
    // Track DNS connection (port 53)
    Socket_TrackDnsConnection(s, name, namelen, L"WSAConnect");

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
    // DEBUG: Log send() calls on DNS sockets only
    if (DNS_FilterEnabled && DNS_RawSocketHooksEnabled && DNS_DebugFlag && buf && len > 0 && Socket_IsDnsSocket(s)) {
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

    // Inspect DNS sockets when filtering or EncDns passthrough is enabled.
    if (DNS_RawSocketHooksEnabled && (DNS_FilterEnabled || EncryptedDns_IsEnabled()) &&
        Socket_IsDnsSocket(s) && buf && len >= sizeof(DNS_WIRE_HEADER)) {
        
        BOOLEAN isTcp = Socket_IsTcpSocket(s);

        // Skip length-only sends (TCP DNS fragments)
        if (isTcp && len == 2) {
            if (DNS_DebugFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"TCP DNS: Skipping length-only send (len=2)");
            }
            return __sys_send(s, buf, len, flags);
        }
        
        // Detect TCP length prefix and extract DNS payload
        const BYTE* dns_payload = (const BYTE*)buf;
        int dns_payload_len = len;
        
        if (isTcp && Socket_DetectTcpLengthPrefix((const BYTE*)buf, len, &dns_payload, &dns_payload_len)) {
            // Length prefix detected - dns_payload now points to actual DNS data
        }
        
        // Process DNS query
        DNS_PROCESS_RESULT result = Socket_ProcessDnsQuery(s, dns_payload, dns_payload_len, NULL, isTcp ? L"TCP" : L"UDP", L"send");
        
        if (result == DNS_PROCESS_INTERCEPTED || result == DNS_PROCESS_ERROR) {
            return len;  // Return success (intercepted or error - don't send)
        }
        // DNS_PROCESS_PASSTHROUGH: fall through to real send
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
    // Cast to actual WSABUF structure
    LPWSABUF_REAL buffers = (lpBuffers && dwBufferCount > 0) ? (LPWSABUF_REAL)lpBuffers : NULL;
    
    // DEBUG: Log WSASend() calls on DNS sockets only
    if (DNS_FilterEnabled && DNS_RawSocketHooksEnabled && DNS_DebugFlag && buffers && Socket_IsDnsSocket(s)) {
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

    // Inspect DNS sockets when filtering or EncDns passthrough is enabled.
    if (DNS_RawSocketHooksEnabled && (DNS_FilterEnabled || EncryptedDns_IsEnabled()) &&
        Socket_IsDnsSocket(s) && buffers && buffers[0].len >= sizeof(DNS_WIRE_HEADER)) {
        
        BOOLEAN isTcp = Socket_IsTcpSocket(s);
        int len = buffers[0].len;
        
        // Skip length-only sends (TCP DNS fragments)
        if (isTcp && len == 2) {
            if (DNS_DebugFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"TCP DNS: WSASend skipping length-only send (len=2)");
            }
            return __sys_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
        }
        
        // Detect TCP length prefix and extract DNS payload
        const BYTE* dns_payload = (const BYTE*)buffers[0].buf;
        int dns_payload_len = len;
        
        if (isTcp && Socket_DetectTcpLengthPrefix((const BYTE*)buffers[0].buf, len, &dns_payload, &dns_payload_len)) {
            // Length prefix detected - dns_payload now points to actual DNS data
        }
        
        // Process DNS query
        DNS_PROCESS_RESULT result = Socket_ProcessDnsQuery(s, dns_payload, dns_payload_len, NULL, isTcp ? L"TCP" : L"UDP", L"WSASend");
        
        if (result == DNS_PROCESS_INTERCEPTED || result == DNS_PROCESS_ERROR) {
            if (lpNumberOfBytesSent) *lpNumberOfBytesSent = len;
            return 0;  // Return success (intercepted or error - don't send)
        }
        // DNS_PROCESS_PASSTHROUGH: fall through to real WSASend
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
    // Track DNS queries (for response sanitization/logging) whenever raw socket hooks are installed.
    // Interception/blocking still requires DNS filtering to be enabled.
    if (DNS_RawSocketHooksEnabled && to && buf && len >= sizeof(DNS_WIRE_HEADER)) {
        DNS_PROCESS_RESULT result = DNS_PROCESS_PASSTHROUGH;
        if (Socket_HandleUdpDnsSend(s, (const BYTE*)buf, len, to, tolen, L"sendto", TRUE, TRUE, &result)) {
            if (DNS_FilterEnabled && DNS_RawSocketFilterEnabled &&
                (result == DNS_PROCESS_INTERCEPTED || result == DNS_PROCESS_ERROR)) {
                return len;  // Return success (intercepted or error - don't send)
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
// Also handles Cygwin TCP sockets which call WSASendTo with lpTo=NULL for connected sockets
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
    // Cast to actual WSABUF structure (used in multiple code paths)
    LPWSABUF_REAL buffers = (lpBuffers && dwBufferCount > 0) ? (LPWSABUF_REAL)lpBuffers : NULL;
    
    // Calculate total length across all buffers
    ULONG totalLen = 0;
    if (buffers) {
        for (DWORD i = 0; i < dwBufferCount; i++) {
            totalLen += buffers[i].len;
        }
    }
    
    // DEBUG: Log WSASendTo() calls on DNS sockets only
    if (DNS_FilterEnabled && DNS_RawSocketHooksEnabled && DNS_DebugFlag && buffers && Socket_IsDnsSocket(s)) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"GLOBAL: WSASendTo() socket=%p, bufCount=%d, buf[0].len=%d, totalLen=%d, lpTo=%s, isDns=%d",
            (void*)(ULONG_PTR)s, dwBufferCount, buffers[0].len, totalLen, lpTo ? L"set" : L"NULL", Socket_IsDnsSocket(s) ? 1 : 0);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    // =========================================================================
    // CASE 1: Connected socket (lpTo == NULL) - handle like WSASend
    // This is what Cygwin uses for TCP DNS via WSASendTo on connected sockets
    // =========================================================================
    if (DNS_FilterEnabled && DNS_RawSocketHooksEnabled && !lpTo && Socket_IsDnsSocket(s) && buffers) {
        
        // Handle UDP connected sockets separately (no length prefix, no reassembly)
        if (!Socket_IsTcpSocket(s)) {
            // Concatenate buffers if needed
            BYTE* udp_payload = NULL;
            BYTE* temp_buf = NULL;
            
            if (dwBufferCount == 1) {
                udp_payload = (BYTE*)buffers[0].buf;
            } else {
                temp_buf = (BYTE*)Dll_AllocTemp(totalLen);
                if (temp_buf) {
                    int offset = 0;
                    for (DWORD i = 0; i < dwBufferCount; i++) {
                        memcpy(temp_buf + offset, buffers[i].buf, buffers[i].len);
                        offset += buffers[i].len;
                    }
                    udp_payload = temp_buf;
                }
            }
            
            if (udp_payload) {
                DNS_PROCESS_RESULT result = Socket_ProcessDnsQuery(s, udp_payload, totalLen, NULL, L"UDP", L"WSASendTo(conn)");
                
                if (temp_buf) Dll_Free(temp_buf);
                
                if (result == DNS_PROCESS_INTERCEPTED || result == DNS_PROCESS_ERROR) {
                    if (lpNumberOfBytesSent) *lpNumberOfBytesSent = totalLen;
                    return 0;  // Return success (intercepted or error - don't send)
                }
            }
            // Passthrough to original WSASendTo
            return __sys_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
        }

        // Cygwin may send [2-byte length prefix][DNS payload] in separate WSABUF entries
        // Check if we have multiple buffers with first being 2 bytes (length prefix)
        const BYTE* dns_payload = NULL;
        int dns_payload_len = 0;
        BOOLEAN has_length_prefix = FALSE;
        BOOLEAN used_reassembly = FALSE;  // Track if we used reassembly (affects passthrough)
        
        if (dwBufferCount >= 2 && buffers[0].len == 2 && buffers[1].len >= sizeof(DNS_WIRE_HEADER)) {
            // Multiple buffers: [0]=length prefix, [1]=DNS payload
            USHORT tcp_length = _ntohs(*(USHORT*)buffers[0].buf);
            if (tcp_length == buffers[1].len) {
                dns_payload = (const BYTE*)buffers[1].buf;
                dns_payload_len = buffers[1].len;
                has_length_prefix = TRUE;
                
                if (DNS_DebugFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"TCP DNS: WSASendTo multi-buffer: [0]=%d bytes (len prefix), [1]=%d bytes (payload)",
                        buffers[0].len, buffers[1].len);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
            }
        }
        
        // Single buffer case: use helper to detect TCP length prefix
        if (!dns_payload && buffers[0].len >= sizeof(DNS_WIRE_HEADER)) {
            dns_payload = (const BYTE*)buffers[0].buf;
            dns_payload_len = buffers[0].len;
            
            // Try to detect and extract TCP DNS length prefix
            if (Socket_DetectTcpLengthPrefix((const BYTE*)buffers[0].buf, buffers[0].len, &dns_payload, &dns_payload_len)) {
                has_length_prefix = TRUE;
            }
        }
        
        // TCP Reassembly: Handle fragmented sends (length prefix sent separately from payload)
        // Some applications (like Cygwin dig) send:
        //   - First WSASendTo: 2-byte length prefix only
        //   - Second WSASendTo: DNS query payload
        //
        // IMPORTANT: For TCP DNS interception, we must NOT send any fragments to the server.
        // We accumulate fragments, and only when complete, either:
        //   - Intercept: return success without calling __sys_WSASendTo (fake the send)
        //   - Passthrough: call __sys_WSASendTo with all accumulated data
        //
        // To properly passthrough, we'd need to resend all fragments, which is complex.
        // For now, we only intercept fully - if domain matches filter, intercept; otherwise error.
        if (!dns_payload) {
            // Concatenate all buffer data into a single block for reassembly
            BYTE* concat_buf = (BYTE*)Dll_AllocTemp(totalLen);
            if (concat_buf) {
                int offset = 0;
                for (DWORD i = 0; i < dwBufferCount; i++) {
                    memcpy(concat_buf + offset, buffers[i].buf, buffers[i].len);
                    offset += buffers[i].len;
                }
                
                // Add to reassembly buffer
                BYTE* reassembled_data = NULL;
                int reassembled_len = 0;
                int reassembly_result = Socket_AddToReassemblyBuffer(s, concat_buf, totalLen, &reassembled_data, &reassembled_len);
                
                Dll_Free(concat_buf);
                
                if (reassembly_result == 0) {
                    // Need more data - fake success without actually sending
                    // We can't pass through partial data because if the full message
                    // is intercepted, the server would receive incomplete data.
                    if (DNS_DebugFlag) {
                        WCHAR msg[256];
                        Sbie_snwprintf(msg, 256, L"TCP DNS: WSASendTo reassembly incomplete, buffering %d bytes (not sending)", totalLen);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                    }
                    // Report success - data was "sent" (actually buffered)
                    if (lpNumberOfBytesSent) *lpNumberOfBytesSent = totalLen;
                    return 0;  // Fake success
                }
                else if (reassembly_result == 1 && reassembled_data && reassembled_len >= 2 + sizeof(DNS_WIRE_HEADER)) {
                    // Complete message! Parse it.
                    USHORT tcp_length = (reassembled_data[0] << 8) | reassembled_data[1];
                    if (tcp_length + 2 == reassembled_len && tcp_length >= sizeof(DNS_WIRE_HEADER)) {
                        dns_payload = reassembled_data + 2;  // Skip length prefix
                        dns_payload_len = tcp_length;
                        has_length_prefix = TRUE;
                        used_reassembly = TRUE;  // Mark that we used reassembly
                        
                        if (DNS_DebugFlag) {
                            WCHAR msg[256];
                            Sbie_snwprintf(msg, 256, L"TCP DNS: Reassembly complete! %d bytes total, payload=%d bytes",
                                reassembled_len, dns_payload_len);
                            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                        }
                        
                        // NOTE: dns_payload points into reassembly buffer
                        // Process immediately below, buffer will be cleared after successful interception
                    }
                }
                // If reassembly_result == -1 (error), dns_payload remains NULL
                // Fall through to check if we have a valid payload
            }
        }
        
        // If we have a valid DNS payload, process it
        if (dns_payload && dns_payload_len >= sizeof(DNS_WIRE_HEADER)) {
            WCHAR domainName[256];
            USHORT qtype = 0;

            // Parse DNS query packet
            if (Socket_ParseDnsQuery(dns_payload, dns_payload_len, domainName, 256, &qtype)) {

                // Literal IP QNAMEs are not filterable DNS domains.
                // Handle here because this TCP WSASendTo(conn) path does not go through Socket_ProcessDnsQuery.
                if (Socket_TryHandleIpLiteralDnsQuery(s, dns_payload, dns_payload_len, NULL, L"TCP", L"WSASendTo(conn)", domainName, qtype)) {
                    if (used_reassembly) {
                        Socket_ClearReassemblyBuffer(s);
                    }
                    if (lpNumberOfBytesSent) {
                        *lpNumberOfBytesSent = totalLen;
                    }
                    return 0;  // Answered locally
                }
                
                // Modify EDNS DO flag based on DnssecEnabled mode for TCP passthrough
                // This ensures the real DNS server returns (or omits) RRSIG as appropriate:
                //   y mode (ENABLED):  set DO flag -> server returns RRSIG records
                //   n mode (DISABLED): clear DO flag -> server omits RRSIG records
                //   f mode (FILTER):   leave unchanged -> respect app's EDNS choice
                {
                    DNSSEC_MODE tcp_dnssec_mode = DNS_DnssecGetMode(domainName);
                    if (tcp_dnssec_mode == DNSSEC_MODE_ENABLED) {
                        BOOLEAN modified = DNS_Dnssec_ModifyEdnsDOFlag((BYTE*)dns_payload, dns_payload_len, TRUE);
                        if (DNS_DebugFlag) {
                            WCHAR msg[256];
                            Sbie_snwprintf(msg, 256, L"TCP DNS: DnssecEnabled=y, %s DO flag for %s",
                                modified ? L"set" : L"no EDNS to set", domainName);
                            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                        }
                    } else if (tcp_dnssec_mode == DNSSEC_MODE_DISABLED) {
                        BOOLEAN modified = DNS_Dnssec_ModifyEdnsDOFlag((BYTE*)dns_payload, dns_payload_len, FALSE);
                        if (DNS_DebugFlag) {
                            WCHAR msg[256];
                            Sbie_snwprintf(msg, 256, L"TCP DNS: DnssecEnabled=n, %s DO flag for %s",
                                modified ? L"cleared" : L"no EDNS to clear", domainName);
                            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                        }
                    }
                }
                
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
                        // Even though we have no IPs/filter data, we still need to track this query
                        // so that rebind protection can be applied to the server's response.
                        // This happens when a domain matches a filter pattern but has no configured IPs.
                        BYTE response[DNS_RESPONSE_SIZE];
                        int response_len = Socket_BuildDoHResponse(
                            dns_payload, dns_payload_len, domain_lwr, qtype, response, DNS_RESPONSE_SIZE, L"TCP");
                        if (response_len > 0) {
                            if (Socket_ValidateDnsResponse(response, response_len)) {
                                if (DNS_DebugFlag) {
                                    WCHAR msg[256];
                                    Sbie_snwprintf(msg, 256, L"  TCP DNS Debug: WSASendTo(conn) queueing EncDns response, len=%d bytes",
                                        response_len);
                                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                                }
                                Socket_AddFakeResponse(s, response, response_len, NULL);
                                if (used_reassembly) {
                                    Socket_ClearReassemblyBuffer(s);
                                }
                                if (lpNumberOfBytesSent) {
                                    *lpNumberOfBytesSent = totalLen;
                                }
                                Dll_Free(domain_lwr);
                                return 0;
                            }
                        }
                        Socket_LogForwarded(L"TCP", domainName, qtype, L"WSASendTo(conn)", s, DNS_PASSTHROUGH_CONFIG_ERROR);
                        Dll_Free(domain_lwr);
                        // If we used reassembly, send the complete reassembled data
                        if (used_reassembly) {
                            return Socket_SendReassembledData(s, lpNumberOfBytesSent, lpOverlapped, lpCompletionRoutine);
                        }
                        return __sys_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
                    }

                    // Certificate required for actual filtering (interception/blocking)
                    extern BOOLEAN DNS_HasValidCertificate;
                    if (!DNS_HasValidCertificate) {
                        BYTE response[DNS_RESPONSE_SIZE];
                        int response_len = Socket_BuildDoHResponse(
                            dns_payload, dns_payload_len, domain_lwr, qtype, response, DNS_RESPONSE_SIZE, L"TCP");
                        if (response_len > 0) {
                            if (Socket_ValidateDnsResponse(response, response_len)) {
                                if (DNS_DebugFlag) {
                                    WCHAR msg[256];
                                    Sbie_snwprintf(msg, 256, L"  TCP DNS Debug: WSASendTo(conn) queueing EncDns response, len=%d bytes",
                                        response_len);
                                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                                }
                                Socket_AddFakeResponse(s, response, response_len, NULL);
                                if (used_reassembly) {
                                    Socket_ClearReassemblyBuffer(s);
                                }
                                if (lpNumberOfBytesSent) {
                                    *lpNumberOfBytesSent = totalLen;
                                }
                                Dll_Free(domain_lwr);
                                return 0;
                            }
                        }
                        Socket_LogForwarded(L"TCP", domainName, qtype, L"WSASendTo(conn)", s, DNS_PASSTHROUGH_NO_CERT);
                        Dll_Free(domain_lwr);
                        // If we used reassembly, send the complete reassembled data
                        if (used_reassembly) {
                            return Socket_SendReassembledData(s, lpNumberOfBytesSent, lpOverlapped, lpCompletionRoutine);
                        }
                        return __sys_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
                    }

                    // Build fake DNS response
                    BYTE response[DNS_RESPONSE_SIZE];
                    int response_len = Socket_HandleDnsQuery(
                        aux, dns_payload, dns_payload_len, qtype, response, DNS_RESPONSE_SIZE, L"TCP DNS: WSASendTo(conn)", domainName);
                    
                    if (response_len < 0) {
                        if (lpNumberOfBytesSent) *lpNumberOfBytesSent = totalLen;
                        Dll_Free(domain_lwr);
                        return 0;
                    }
                    
                    if (response_len == 0) {
                        BYTE response[DNS_RESPONSE_SIZE];
                        int encdns_len = Socket_BuildDoHResponse(
                            dns_payload, dns_payload_len, domain_lwr, qtype, response, DNS_RESPONSE_SIZE, L"TCP");
                        if (encdns_len > 0) {
                            if (Socket_ValidateDnsResponse(response, encdns_len)) {
                                if (DNS_DebugFlag) {
                                    WCHAR msg[256];
                                    Sbie_snwprintf(msg, 256, L"  TCP DNS Debug: WSASendTo(conn) queueing EncDns response, len=%d bytes",
                                        encdns_len);
                                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                                }
                                Socket_AddFakeResponse(s, response, encdns_len, NULL);
                                if (used_reassembly) {
                                    Socket_ClearReassemblyBuffer(s);
                                }
                                if (lpNumberOfBytesSent) {
                                    *lpNumberOfBytesSent = totalLen;
                                }
                                Dll_Free(domain_lwr);
                                return 0;
                            }
                        }
                        Socket_LogFilterPassthrough(L"TCP", domainName, qtype, L"WSASendTo(conn)", s, DNS_PASSTHROUGH_TYPE_NOT_FILTERED);
                        // Need to passthrough - if we used reassembly, send the complete reassembled data
                        if (used_reassembly) {
                            Dll_Free(domain_lwr);
                            return Socket_SendReassembledData(s, lpNumberOfBytesSent, lpOverlapped, lpCompletionRoutine);
                        }
                        Dll_Free(domain_lwr);
                        // Fall through to call __sys_WSASendTo at end of function
                    }
                    else if (response_len > 0) {
                        if (!Socket_ValidateDnsResponse(response, response_len)) {
                            if (DNS_TraceFlag) {
                                SbieApi_MonitorPutMsg(MONITOR_DNS, L"TCP DNS: WSASendTo(conn) response failed validation");
                            }
                            if (lpNumberOfBytesSent) *lpNumberOfBytesSent = totalLen;
                            Dll_Free(domain_lwr);
                            return 0;
                        }
                        
                        LIST* pEntries = NULL;
                        DNS_TYPE_FILTER* type_filter = NULL;
                        DNS_ExtractFilterAux(aux, &pEntries, &type_filter);
                        
                        if (DNS_DebugFlag) {
                            WCHAR msg[256];
                            Sbie_snwprintf(msg, 256, L"  TCP DNS Debug: WSASendTo(conn) queueing fake response, len=%d bytes",
                                response_len);
                            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                        }
                        
                        Socket_AddFakeResponse(s, response, response_len, NULL);
                        Socket_LogInterceptedResponse(L"TCP", domainName, qtype, totalLen, response, response_len, s, pEntries, L"WSASendTo(conn)");
                        
                        // Clear reassembly buffer after successful interception
                        Socket_ClearReassemblyBuffer(s);
                        
                        if (lpNumberOfBytesSent) {
                            *lpNumberOfBytesSent = totalLen;
                        }
                        Dll_Free(domain_lwr);
                        return 0;  // Success (answered locally)
                    }
                    
                    // If response_len == 0, we already freed domain_lwr above
                }
                else {
                    BYTE response[DNS_RESPONSE_SIZE];
                    int response_len = Socket_BuildDoHResponse(
                        dns_payload, dns_payload_len, domain_lwr, qtype, response, DNS_RESPONSE_SIZE, L"TCP");
                    if (response_len > 0) {
                        if (Socket_ValidateDnsResponse(response, response_len)) {
                            if (DNS_DebugFlag) {
                                WCHAR msg[256];
                                Sbie_snwprintf(msg, 256, L"  TCP DNS Debug: WSASendTo(conn) queueing EncDns response, len=%d bytes",
                                    response_len);
                                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                            }
                            Socket_AddFakeResponse(s, response, response_len, NULL);
                            if (used_reassembly) {
                                Socket_ClearReassemblyBuffer(s);
                            }
                            if (lpNumberOfBytesSent) {
                                *lpNumberOfBytesSent = totalLen;
                            }
                            Dll_Free(domain_lwr);
                            return 0;
                        }
                    }
                    Socket_LogForwarded(L"TCP", domainName, qtype, L"WSASendTo(conn)", s, DNS_PASSTHROUGH_NO_MATCH);
                    Dll_Free(domain_lwr);
                    // Need to passthrough - if we used reassembly, send the complete reassembled data
                    if (used_reassembly) {
                        return Socket_SendReassembledData(s, lpNumberOfBytesSent, lpOverlapped, lpCompletionRoutine);
                    }
                }
            }
        }
    }
    
    // =========================================================================
    // CASE 2: UDP with destination address (lpTo != NULL)
    // =========================================================================
    if (DNS_RawSocketHooksEnabled && lpTo && buffers) {
        DNS_PROCESS_RESULT result = DNS_PROCESS_PASSTHROUGH;
        if (Socket_HandleUdpDnsSend(s, (const BYTE*)buffers[0].buf, buffers[0].len, lpTo, iTolen,
            L"WSASendTo", TRUE, TRUE, &result)) {
            if (DNS_FilterEnabled && DNS_RawSocketFilterEnabled &&
                (result == DNS_PROCESS_INTERCEPTED || result == DNS_PROCESS_ERROR)) {
                if (lpNumberOfBytesSent) *lpNumberOfBytesSent = buffers[0].len;
                return 0;  // Return success (intercepted or error - don't send)
            }
        }
    }

    // Call original WSASendTo
    return __sys_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
}

//---------------------------------------------------------------------------
// Socket_ProcessWSASendTo
//
// Exported wrapper for DNS interception in WSASendTo - called from net.c
// Processes UDP DNS queries (port 53) and TCP DNS on connected sockets
//
// Returns: 0 = passthrough (call real function), >0 = intercepted, <0 = error
//---------------------------------------------------------------------------

_FX int Socket_ProcessWSASendTo(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, const void* lpTo, int iTolen)
{
    if (!DNS_FilterEnabled || !DNS_RawSocketFilterEnabled)
        return 0;  // Passthrough
    
    LPWSABUF_REAL buffers = (lpBuffers && dwBufferCount > 0) ? (LPWSABUF_REAL)lpBuffers : NULL;
    if (!buffers)
        return 0;  // Passthrough
    
    // CASE 1: Connected socket (lpTo == NULL) - TCP DNS
    if (!lpTo && Socket_IsDnsSocket(s)) {
        // This case is complex (TCP reassembly) - handled by internal hook
        // For now, passthrough and let the internal hook handle it
        return 0;
    }
    
    // CASE 2: UDP with destination address (lpTo != NULL)
    if (lpTo && buffers[0].len >= sizeof(DNS_WIRE_HEADER)) {
        DNS_PROCESS_RESULT result = DNS_PROCESS_PASSTHROUGH;
        if (Socket_HandleUdpDnsSend(s, (const BYTE*)buffers[0].buf, buffers[0].len, lpTo, iTolen,
            L"WSASendTo", FALSE, FALSE, &result)) {
            if (result == DNS_PROCESS_INTERCEPTED || result == DNS_PROCESS_ERROR) {
                if (lpNumberOfBytesSent) *lpNumberOfBytesSent = buffers[0].len;
                return 1;  // Intercepted
            }
        }
    }
    
    return 0;  // Passthrough
}

//---------------------------------------------------------------------------
// Socket_ProcessWSARecvFrom
//
// Exported wrapper for fake DNS response injection - called from net.c
// Returns fake DNS responses if available
//
// Returns: 0 = no fake response, >0 = bytes returned
//---------------------------------------------------------------------------

_FX int Socket_ProcessWSARecvFrom(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
    void* lpFrom, LPINT lpFromlen)
{
    if (!DNS_FilterEnabled || !DNS_RawSocketFilterEnabled)
        return 0;
    
    if (!Socket_IsDnsSocket(s) || !Socket_HasFakeResponse(s))
        return 0;
    
    LPWSABUF_REAL buffers = (lpBuffers && dwBufferCount > 0) ? (LPWSABUF_REAL)lpBuffers : NULL;
    if (!buffers || buffers[0].len == 0)
        return 0;
    
    int received = Socket_GetFakeResponse(s, buffers[0].buf, buffers[0].len, lpFrom, lpFromlen);
    if (received > 0) {
        if (lpNumberOfBytesRecvd) *lpNumberOfBytesRecvd = received;
        if (lpFlags) *lpFlags = 0;
        return received;
    }
    
    return 0;
}

//---------------------------------------------------------------------------
// Socket_InjectFdRead
//
// Exported wrapper for FD_READ injection - called from net.c
// Injects FD_READ event when fake responses are queued
//
// Returns: TRUE if FD_READ was injected
//---------------------------------------------------------------------------

_FX BOOLEAN Socket_InjectFdRead(SOCKET s, void* lpNetworkEvents)
{
    if (!DNS_FilterEnabled || !DNS_RawSocketFilterEnabled)
        return FALSE;
    
    if (!Socket_IsDnsSocket(s) || !Socket_HasFakeResponse(s))
        return FALSE;
    
    // Inject FD_READ event
    WSANETWORKEVENTS_COMPAT* events = (WSANETWORKEVENTS_COMPAT*)lpNetworkEvents;
    if (events) {
        events->lNetworkEvents |= FD_READ;
        events->iErrorCode[FD_READ_BIT] = 0;
        return TRUE;
    }
    
    return FALSE;
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
    int jumpCount = 0;           // Loop detection for compression pointers
    BOOLEAN jumped = FALSE;      // Track if we've followed a pointer
    int savedOffset = -1;        // Save original offset when following pointer

    while (offset < packetLen) {
        BYTE labelLen = packet[offset];

        // End of name (zero-length label)
        if (labelLen == 0) {
            offset++;
            break;
        }

        // Check for DNS name compression (pointer - top 2 bits set)
        if ((labelLen & 0xC0) == 0xC0) {
            // Follow compression pointers with loop detection
            // DNS compression pointer format: 11xxxxxx xxxxxxxx (14-bit offset)
            if (offset + 1 >= packetLen)
                return -1;  // Incomplete pointer
            
            // Loop detection: max 10 jumps to prevent infinite loops from malicious packets
            if (++jumpCount > 10)
                return -1;  // Too many jumps - possible attack
            
            // Calculate pointer target offset
            USHORT ptrOffset = ((labelLen & 0x3F) << 8) | packet[offset + 1];
            
            // Pointer must point backwards (or at least not past current position)
            // and must be within packet bounds
            if (ptrOffset >= packetLen || ptrOffset >= offset)
                return -1;  // Invalid pointer target
            
            // Save our position (only on first jump) so we can calculate bytes consumed
            if (!jumped) {
                savedOffset = offset + 2;  // Position after the pointer
                jumped = TRUE;
            }
            
            // Follow the pointer
            offset = ptrOffset;
            continue;
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

    // Return number of bytes consumed from the original position
    // If we followed a compression pointer, return the saved offset (position after pointer)
    // Otherwise return current offset
    if (jumped && savedOffset > 0) {
        return savedOffset - originalOffset;
    }
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
// Level-aware matching (fixes per-image config leakage):
//   Patterns have levels: 0 = exact image match, 1 = negated match, 2 = global
//   Lower level = higher priority. Once we find a match at level N, we ignore
//   patterns with level > N. This ensures process-specific rules take precedence.
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
    
    // Track best match with level-aware priority (like Pattern_MatchPathList)
    // Level: 0 = exact image match (highest priority), 1 = negated, 2 = global (lowest)
    ULONG best_level = (ULONG)-1;  // Start with worst possible level
    int best_match_type = 0;       // 1 = exact, 2 = wildcard, 3 = catch-all
    int best_wildcard_len = -1;
    int best_wildcard_count = 1000;
    PATTERN* best_pattern = NULL;

    // Create local mutable copy for Pattern_MatchPathList (which expects non-const WCHAR*)
    WCHAR* domain_copy = (WCHAR*)Dll_AllocTemp((domain_len + 1) * sizeof(WCHAR));
    if (!domain_copy)
        return 0;
    wmemcpy(domain_copy, domain_lwr, domain_len);
    domain_copy[domain_len] = L'\0';

    // Single pass through all patterns, tracking best match with level priority
    PATTERN* pat = (PATTERN*)List_Head(&DNS_FilterList);
    while (pat) {
        const WCHAR* pat_text = Pattern_Source(pat);
        if (!pat_text) { pat = (PATTERN*)List_Next(pat); continue; }
        
        ULONG pat_level = Pattern_Level(pat);
        ULONG pat_len = wcslen(pat_text);
        
        // Skip patterns with weaker (higher) level than our current best
        if (pat_level > best_level) {
            pat = (PATTERN*)List_Next(pat);
            continue;
        }
        
        BOOLEAN is_exact = (!wcschr(pat_text, L'*') && !wcschr(pat_text, L'?'));
        BOOLEAN is_catchall = (pat_len == 1 && pat_text[0] == L'*');
        
        // Check for exact match (no wildcards)
        if (is_exact) {
            if (pat_len == domain_len && _wcsnicmp(pat_text, domain_lwr, domain_len) == 0) {
                // Exact match - check if better than current best
                if (pat_level < best_level || 
                    (pat_level == best_level && best_match_type != 1)) {
                    best_pattern = pat;
                    best_level = pat_level;
                    best_match_type = 1;  // Exact match
                    
                    if (DNS_DebugFlag) {
                        WCHAR msg[512];
                        Sbie_snwprintf(msg, 512, L"  DNS Debug Hierarchical: Domain '%s' matched exact pattern '%s' (level=%lu)", 
                            domain_lwr, pat_text, pat_level);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                    }
                    
                    // If we found an exact match at level 0, we can't do better
                    if (pat_level == 0) {
                        Dll_Free(domain_copy);
                        *found = best_pattern;
                        return 1;
                    }
                }
            }
        }
        // Check for catch-all wildcard "*" (lowest priority within same level)
        else if (is_catchall) {
            // Only use catch-all if no better match at this or better level
            if (pat_level < best_level || 
                (pat_level == best_level && best_match_type == 0)) {
                best_pattern = pat;
                best_level = pat_level;
                best_match_type = 3;  // Catch-all
                
                if (DNS_DebugFlag) {
                    WCHAR msg[512];
                    Sbie_snwprintf(msg, 512, L"  DNS Debug Hierarchical: Domain '%s' candidate catch-all '*' (level=%lu)", 
                        domain_lwr, pat_level);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
            }
        }
        // Check for wildcard match (middle priority)
        else if (Pattern_MatchWildcard(pat_text, domain_lwr)) {
            // Count wildcards for specificity comparison
            int wildcard_count = 0;
            for (const WCHAR* p = pat_text; *p; ++p) if (*p == L'*') wildcard_count++;
            
            // Better match if: better level, or same level but more specific pattern
            BOOLEAN is_better = FALSE;
            if (pat_level < best_level) {
                is_better = TRUE;
            } else if (pat_level == best_level) {
                // At same level: prefer exact > wildcard > catch-all
                // Among wildcards: prefer longest, then fewest wildcards
                if (best_match_type == 0 || best_match_type == 3) {
                    is_better = TRUE;
                } else if (best_match_type == 2) {
                    if ((int)pat_len > best_wildcard_len || 
                        ((int)pat_len == best_wildcard_len && wildcard_count < best_wildcard_count)) {
                        is_better = TRUE;
                    }
                }
            }
            
            if (is_better) {
                best_pattern = pat;
                best_level = pat_level;
                best_match_type = 2;  // Wildcard match
                best_wildcard_len = (int)pat_len;
                best_wildcard_count = wildcard_count;
                
                if (DNS_DebugFlag) {
                    WCHAR msg[512];
                    Sbie_snwprintf(msg, 512, L"  DNS Debug Hierarchical: Domain '%s' matched pattern '%s' (level=%lu, len=%lu)", 
                        domain_lwr, pat_text, pat_level, pat_len);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
            }
        }
        
        pat = (PATTERN*)List_Next(pat);
    }
    
    Dll_Free(domain_copy);
    
    if (best_pattern) {
        *found = best_pattern;
        if (DNS_DebugFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"  DNS Debug Hierarchical: Final match for '%s' is '%s' (type=%d, level=%lu)", 
                domain_lwr, Pattern_Source(best_pattern), best_match_type, best_level);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        return best_match_type;
    }
    
    return 0;
}

//---------------------------------------------------------------------------
// Socket_ExtractEdnsRecord
//
// Extracts the EDNS OPT record from a DNS query packet, if present.
// The OPT record appears in the Additional section of DNS messages.
// It uses TYPE=41 and has special semantics per RFC 6891.
//
// Parameters:
//   query        - DNS query packet
//   query_len    - Length of DNS query packet
//   edns_buffer  - Output buffer to store the extracted OPT record
//   edns_size    - Size of edns_buffer
//
// Returns: Length of extracted EDNS record, or 0 if not found/invalid
//---------------------------------------------------------------------------

_FX int Socket_ExtractEdnsRecord(const BYTE* query, int query_len, BYTE* edns_buffer, int edns_size)
{
    if (!query || query_len < sizeof(DNS_WIRE_HEADER) || !edns_buffer || edns_size < DNS_OPT_RECORD_HEADER_SIZE)
        return 0;

    DNS_WIRE_HEADER* hdr = (DNS_WIRE_HEADER*)query;
    
    // Get the number of Additional RRs (OPT record should be in Additional section)
    USHORT additional_count = _ntohs(hdr->AdditionalRRs);
    if (additional_count == 0)
        return 0;  // No additional records, no EDNS

    // Skip to the Additional section
    // We need to skip: Questions + Answers + Authority sections
    int offset = sizeof(DNS_WIRE_HEADER);
    
    USHORT questions = _ntohs(hdr->Questions);
    USHORT answers = _ntohs(hdr->AnswerRRs);
    USHORT authority = _ntohs(hdr->AuthorityRRs);
    
    // Skip questions section
    for (USHORT i = 0; i < questions && offset < query_len; i++) {
        // Skip domain name
        while (offset < query_len) {
            BYTE label_len = query[offset];
            if (label_len == 0) {
                offset++;
                break;
            }
            if ((label_len & 0xC0) == 0xC0) {
                offset += 2;
                break;
            }
            offset += 1 + label_len;
        }
        // Skip QTYPE and QCLASS (4 bytes)
        offset += 4;
    }
    
    // Skip answer and authority sections
    for (USHORT i = 0; i < (answers + authority) && offset < query_len; i++) {
        // Skip domain name
        while (offset < query_len) {
            BYTE label_len = query[offset];
            if (label_len == 0) {
                offset++;
                break;
            }
            if ((label_len & 0xC0) == 0xC0) {
                offset += 2;
                break;
            }
            offset += 1 + label_len;
        }
        // Skip TYPE, CLASS, TTL, RDLENGTH (10 bytes)
        if (offset + 10 > query_len)
            return 0;
        offset += 10;
        
        // Skip RDATA
        USHORT rdlength = _ntohs(*(USHORT*)(query + offset - 2));
        offset += rdlength;
    }
    
    // Now we're in the Additional section - look for OPT record (TYPE=41, root label=0)
    for (USHORT i = 0; i < additional_count && offset < query_len; i++) {
        int record_start = offset;
        
        // Check for root label (single 0 byte) followed by TYPE=41
        if (offset + 3 <= query_len && query[offset] == 0) {  // root label
            offset++;
            USHORT type = _ntohs(*(USHORT*)(query + offset));
            offset += 2;
            
            if (type == DNS_TYPE_OPT) {
                // Found OPT record! Now copy it to the output buffer
                // We need: root_label (1) + type (2) + udp_payload (2) + extended_flags (4) + rdlength (2) + rdata (variable)
                
                // Read the rest of the OPT record
                if (offset + 8 > query_len)
                    return 0;
                    
                USHORT udp_payload = *(USHORT*)(query + offset);
                offset += 2;
                DWORD extended_flags = *(DWORD*)(query + offset);
                offset += 4;
                USHORT rdlength = _ntohs(*(USHORT*)(query + offset));
                offset += 2;
                
                // Check if we have space for the complete record (including rdata)
                int total_size = 1 + 2 + 2 + 4 + 2 + rdlength;
                if (total_size > edns_size || offset + rdlength > query_len)
                    return 0;
                
                // Copy the record to output buffer
                int out_offset = 0;
                edns_buffer[out_offset++] = 0;  // root label
                *(USHORT*)(edns_buffer + out_offset) = _htons(DNS_TYPE_OPT);
                out_offset += 2;
                *(USHORT*)(edns_buffer + out_offset) = udp_payload;  // Already in network byte order
                out_offset += 2;
                *(DWORD*)(edns_buffer + out_offset) = extended_flags;  // Already in network byte order
                out_offset += 4;
                *(USHORT*)(edns_buffer + out_offset) = *(USHORT*)(query + offset - 2);  // Already in network byte order
                out_offset += 2;
                
                // Copy rdata
                if (rdlength > 0) {
                    memcpy(edns_buffer + out_offset, query + offset, rdlength);
                    out_offset += rdlength;
                }
                
                return out_offset;
            }
        } else {
            // Skip this record (it's not OPT, so skip the domain name and record data)
            offset = record_start;
            
            // Skip domain name
            while (offset < query_len) {
                BYTE label_len = query[offset];
                if (label_len == 0) {
                    offset++;
                    break;
                }
                if ((label_len & 0xC0) == 0xC0) {
                    offset += 2;
                    break;
                }
                offset += 1 + label_len;
            }
            
            // Skip TYPE, CLASS, TTL, RDLENGTH (10 bytes)
            if (offset + 10 > query_len)
                return 0;
            offset += 10;
            
            // Skip RDATA
            USHORT rdlength = _ntohs(*(USHORT*)(query + offset - 2));
            offset += rdlength;
        }
    }
    
    return 0;  // No OPT record found
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
    struct _DNS_TYPE_FILTER* type_filter,
    const WCHAR*   domain,
    const BYTE*    edns_record,
    int            edns_record_len,
    DNSSEC_MODE    dnssec_mode)
{
    if (!query || !response || query_len < sizeof(DNS_WIRE_HEADER) || response_size < 512)
        return -1;

    // qtype is now in host byte order (Socket_ParseDnsQuery converts it)
    USHORT qtype_host = qtype;
    
    // Track if we're returning NODATA (domain exists, no records) vs NXDOMAIN (domain doesn't exist)
    BOOLEAN return_nodata = FALSE;
    
    // Block mode (no IPs) should block ALL query types with NXDOMAIN
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
            // Filter mode but unsupported type (MX/CNAME/etc.)
            // Domain exists (we're filtering it), but no records of this type
            // RFC 2308: Return NOERROR + NODATA (not NXDOMAIN)
            block = TRUE;
            return_nodata = TRUE;
        }
    }

    // Calculate where the question section ends (header + question name + QTYPE + QCLASS)
    // We only want to copy the header and question section, NOT any additional records (like OPT/EDNS0)
    int question_end = sizeof(DNS_WIRE_HEADER);
    
    // Skip past the question name (length-prefixed labels ending with 0)
    while (question_end < query_len) {
        BYTE label_len = query[question_end];
        if (label_len == 0) {
            question_end++;  // Skip the null terminator
            break;
        }
        if ((label_len & 0xC0) == 0xC0) {
            // Compression pointer (2 bytes) - shouldn't appear in questions but handle it
            question_end += 2;
            break;
        }
        question_end += 1 + label_len;  // Skip length byte + label
    }
    
    // Add QTYPE (2 bytes) and QCLASS (2 bytes)
    question_end += 4;
    
    // Validate bounds
    if (question_end > query_len || question_end > response_size) {
        return -1;  // Malformed query
    }

    // Copy only the DNS header and question section (not additional records like OPT)
    int copy_len = question_end;
    memcpy(response, query, copy_len);

    DNS_WIRE_HEADER* resp_header = (DNS_WIRE_HEADER*)response;
    
    // Clear Authority and Additional RR counts (we're not including them)
    resp_header->AuthorityRRs = _htons(0);
    resp_header->AdditionalRRs = _htons(0);
    
    // Set response flags
    if (block) {
        if (return_nodata) {
            // NOERROR + NODATA (domain exists, no records of this type)
            resp_header->Flags = _htons(0x8180);  // Response, No error
            resp_header->AnswerRRs = _htons(0);
        } else {
            // NXDOMAIN (domain doesn't exist - block mode)
            resp_header->Flags = _htons(0x8183);  // Response, NXDOMAIN
            resp_header->AnswerRRs = _htons(0);
        }
    } else if (!pEntries) {
        // Fallback: no entries at all (shouldn't reach here, but handle gracefully)
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

    // If blocking (or no IPs), return just the header (NXDOMAIN or NOERROR + NODATA)
    if (block || !pEntries) {
        // Even in block mode, preserve EDNS record if present (for DNSSEC support)
        int offset = copy_len;
        if (edns_record && edns_record_len > 0 && offset + edns_record_len <= response_size) {
            memcpy(response + offset, edns_record, edns_record_len);
            offset += edns_record_len;
            resp_header->AdditionalRRs = _htons(1);
        }
        return offset;
    }

    // Add answer records
    int offset = copy_len;
    IP_ENTRY* entry = (IP_ENTRY*)List_Head(pEntries);
    BOOLEAN is_any_query = (qtype_host == 255);  // Check if this is ANY query

    // Actual number of answer RRs emitted (may differ from pre-count due to rebind filtering).
    USHORT built_answers = 0;
    
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

    WCHAR filtered_msg[512];
    filtered_msg[0] = L'\0';
    
    while (entry) {
        BOOLEAN match = FALSE;
        int rdata_len = 0;
        USHORT record_type = 0;  // Actual type for this record (A or AAAA)
        BYTE ipv6_mapped[16];  // For IPv4-mapped IPv6 addresses

        // Apply DNS rebind protection: omit filtered IPs entirely.
        // BUT: Skip rebind filtering if BOTH:
        //   1. DnssecEnabled=y (DNSSEC_MODE_ENABLED) 
        //   2. AND DO flag present in query (client wants DNSSEC signatures)
        // In that case, preserve all IPs for signature validation.
        BOOLEAN skip_rebind = FALSE;
        if (dnssec_mode == DNSSEC_MODE_ENABLED && edns_record && edns_record_len >= 11) {
            // Check for DO flag in EDNS record (offset 6-7, bit 0x8000)
            USHORT edns_flags = (edns_record[6] << 8) | edns_record[7];
            if ((edns_flags & 0x8000) != 0) {
                skip_rebind = TRUE;  // DO flag present - preserve IPs for DNSSEC
            }
        }
        
        if (!skip_rebind && domain && DNS_Rebind_ShouldFilterIpForDomain(domain, &entry->IP)) {
            DNS_Rebind_AppendFilteredIpMsg(
                filtered_msg,
                (SIZE_T)(sizeof(filtered_msg) / sizeof(filtered_msg[0])),
                entry->Type,
                &entry->IP);
            entry = (IP_ENTRY*)List_Next(entry);
            continue;
        }
        
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
            
            // Copy IP address data (apply DNS rebind protection if needed)
            if (record_type == DNS_TYPE_A && entry->Type == AF_INET) {
                // IPv4: stored in Data32[3] (last 4 bytes) per codebase convention
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

            built_answers++;
        }
        
        entry = (IP_ENTRY*)List_Next(entry);
    }

    // Fix up AnswerRRs to reflect the actual number of RRs emitted.
    resp_header->AnswerRRs = _htons(built_answers);

    if (domain && filtered_msg[0] && DNS_TraceFlag && !DNS_ShouldSuppressLogTagged(domain, DNS_REBIND_LOG_TAG_FILTER)) {
        DNS_TRACE_LOG(L"[DNS Rebind] Filtered IP(s) for domain %s%s", domain, filtered_msg);
    }

    // Append EDNS OPT record based on DNSSEC mode
    // - DNSSEC_MODE_ENABLED (y): Reached when raw response has no RRSIG (non-DNSSEC domain)
    // - DNSSEC_MODE_FILTER (f): Append EDNS with DO flag (tampering evidence)
    // - DNSSEC_MODE_DISABLED (n): Don't append EDNS (DNSSEC disabled signal)
    if (edns_record && edns_record_len > 0 && dnssec_mode != DNSSEC_MODE_DISABLED) {
        // Check if we have space for the EDNS record
        if (offset + edns_record_len <= response_size) {
            memcpy(response + offset, edns_record, edns_record_len);
            offset += edns_record_len;
            
            // Update AdditionalRRs count to include the OPT record
            resp_header->AdditionalRRs = _htons(1);
        }
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
    if (!response || response_len <= 0 || response_len > DNS_RESPONSE_SIZE)
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
    
    // Detect TCP vs UDP: if 'to' is NULL, this is a connected socket
    // Use Socket_IsTcpSocket to distinguish TCP from UDP connected sockets
    if (to == NULL) {
        new_resp->is_tcp = Socket_IsTcpSocket(s);
    } else {
        new_resp->is_tcp = FALSE; // sendto with destination is always UDP (or connectionless)
    }
    
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
    
    // Set source address - preserve the original DNS server address including port 53
    // DIG validates that responses come from the same address:port as the query destination
    // Now properly supports both IPv4 and IPv6 using sockaddr_storage
    if (to) {
        const struct sockaddr* addr = (const struct sockaddr*)to;
        if (addr->sa_family == AF_INET6) {
            // IPv6 address
            memcpy(&new_resp->from_addr, to, sizeof(SOCKADDR_IN6_LH));
            new_resp->from_addr_len = sizeof(SOCKADDR_IN6_LH);
            
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"DNS: Fake response queued (IPv6), socket=%p",
                    (void*)(ULONG_PTR)s);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
        } else {
            // IPv4 address (AF_INET)
            memcpy(&new_resp->from_addr, to, sizeof(SOCKADDR_IN));
            new_resp->from_addr_len = sizeof(SOCKADDR_IN);
            
            if (DNS_DebugFlag) {
                SOCKADDR_IN* addr4 = (SOCKADDR_IN*)to;
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"DNS: Fake response queued, from_addr=%d.%d.%d.%d:%d, socket=%p",
                    (addr4->sin_addr.s_addr) & 0xFF,
                    (addr4->sin_addr.s_addr >> 8) & 0xFF,
                    (addr4->sin_addr.s_addr >> 16) & 0xFF,
                    (addr4->sin_addr.s_addr >> 24) & 0xFF,
                    _ntohs(addr4->sin_port),
                    (void*)(ULONG_PTR)s);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
        }
    } else {
        // No destination address provided - use default IPv4
        memset(&new_resp->from_addr, 0, sizeof(SOCKADDR_STORAGE));
        SOCKADDR_IN* addr4 = (SOCKADDR_IN*)&new_resp->from_addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = _htons(53);  // DNS port in network byte order
        new_resp->from_addr_len = sizeof(SOCKADDR_IN);
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
    
    // PROACTIVE EVENT SIGNALING FIX: Signal the event immediately so async apps notice the response
    // This fixes the timing issue where nslookup calls WSAEnumNetworkEvents BEFORE the async
    // EncDns response arrives. By proactively signaling, we ensure the event wakes up immediately.
    {
        ULONG index = ((ULONG_PTR)s) % SOCKET_EVENT_MAPPING_SIZE;
        EnterCriticalSection(&g_SocketEventMappingsLock);
        
        if (g_SocketEventMappings[index].socket == s && g_SocketEventMappings[index].hEvent != NULL) {
            // Found an event associated with this socket - signal it immediately
            SetEvent(g_SocketEventMappings[index].hEvent);
            
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"DNS: Proactively signaled event=%p for socket=%p (response queued)",
                    g_SocketEventMappings[index].hEvent, (void*)(ULONG_PTR)s);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
        }
        
        LeaveCriticalSection(&g_SocketEventMappingsLock);
    }
}

//---------------------------------------------------------------------------
// Socket_RecordEventForSocket
//
// Record the event handle associated with a socket (called from WSAEnumNetworkEvents)
// This enables proactive event signaling when responses are queued
//---------------------------------------------------------------------------

static void Socket_RecordEventForSocket(SOCKET s, HANDLE hEvent)
{
    if (hEvent == NULL) return;
    
    ULONG index = ((ULONG_PTR)s) % SOCKET_EVENT_MAPPING_SIZE;
    EnterCriticalSection(&g_SocketEventMappingsLock);
    
    g_SocketEventMappings[index].socket = s;
    g_SocketEventMappings[index].hEvent = hEvent;
    g_SocketEventMappings[index].timestamp = GetTickCount();
    
    LeaveCriticalSection(&g_SocketEventMappingsLock);
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
            // Now properly supports IPv6 using stored from_addr_len
            if (from && fromlen) {
                int addr_copy_len = (*fromlen < cur->from_addr_len) ? *fromlen : cur->from_addr_len;
                memcpy(from, &cur->from_addr, addr_copy_len);
                *fromlen = cur->from_addr_len;
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
                    const WCHAR* prefix_info;
                    if (!cur->is_tcp) {
                        prefix_info = L"UDP payload only";
                    } else if (cur->skip_length_prefix) {
                        prefix_info = L"no length prefix";
                    } else {
                        prefix_info = L"with length prefix";
                    }
                    Sbie_snwprintf(msg, 256, L"%s DNS: Fake response fully consumed (%d bytes total, %s), socket=%p removed",
                        cur->is_tcp ? L"TCP" : L"UDP", cur->total_len, prefix_info,
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
// Socket_ApplyRebindProtection
//
// Apply DNS rebind protection to a passthrough DNS response buffer.
// Updates *io_len in-place when sanitized.
//---------------------------------------------------------------------------

static void Socket_ApplyRebindProtection(SOCKET s, BYTE* buf, int* io_len)
{
    if (!buf || !io_len || *io_len <= 0)
        return;

    // Only apply if FilterRawDns is enabled (respects user's hook enablement choice)
    if (!DNS_RawSocketFilterEnabled || !Socket_IsDnsSocket(s))
        return;

    WCHAR domain[256];
    USHORT qtype;
    BOOLEAN isTcp;
    DNS_PASSTHROUGH_REASON reason;

    if (Socket_GetPendingQuery(s, domain, 256, &qtype, &isTcp, &reason, FALSE)) {
        ULONG filteredA = 0;
        ULONG filteredAAAA = 0;
        (void)qtype;
        (void)reason;

        int new_len = *io_len;
        BOOLEAN sanitized = FALSE;

        // For TCP: check if buffer contains [len][payload] or just payload
        // - If length_prefix == *io_len - 2: buffer has both, pass isTcp=TRUE
        // - Otherwise: payload-only, pass isTcp=FALSE (no length prefix in current buffer)
        // IMPORTANT: Must detect length prefix BEFORE RRSIG check so we pass correct
        // data pointer to DNS_Dnssec_ResponseHasRrsig (TCP buffers start with 2-byte length)
        BOOLEAN has_length_prefix = FALSE;
        if (isTcp && *io_len > 2) {
            USHORT length_prefix = _ntohs(*(USHORT*)buf);
            has_length_prefix = (length_prefix == (USHORT)(*io_len - 2));
        }

        // Check DNSSEC mode and response content:
        // Only skip rebind filtering if BOTH:
        //   1. DnssecEnabled=y (DNSSEC_MODE_ENABLED)
        //   2. AND response contains RRSIG records (actual DNSSEC data to preserve)
        // For TCP with length prefix, skip the 2-byte prefix to get actual DNS payload
        DNSSEC_MODE dnssec_mode = DNS_DnssecGetMode(domain);
        if (dnssec_mode == DNSSEC_MODE_ENABLED) {
            const BYTE* dns_payload = has_length_prefix ? buf + 2 : buf;
            int dns_payload_len = has_length_prefix ? *io_len - 2 : *io_len;
            if (DNS_Dnssec_ResponseHasRrsig(dns_payload, dns_payload_len)) {
                // y mode + RRSIG present: Pass through raw response untouched
                // Preserving RRSIG signatures requires unmodified response
                return;
            }
        }

        if (isTcp && !has_length_prefix) {
            // Payload-only TCP response: keep length to avoid mismatched length prefix already delivered.
            sanitized = DNS_Rebind_SanitizeDnsWireResponseKeepLengthNodata(buf, *io_len, domain, FALSE,
                &filteredA, &filteredAAAA);
            new_len = *io_len;
        } else {
            // Full buffer (UDP or TCP with length prefix): remove RRs and update length prefix if present.
            sanitized = DNS_Rebind_SanitizeDnsWireResponse(buf, *io_len, domain,
                (isTcp && has_length_prefix),
                &filteredA, &filteredAAAA, &new_len);
        }

        if (sanitized && new_len > 0 && new_len <= *io_len)
            *io_len = new_len;
    }
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
	BOOLEAN isDns = Socket_IsDnsSocket(s);
	BOOLEAN hasFake = Socket_HasFakeResponse(s);
    if (DNS_FilterEnabled && DNS_RawSocketHooksEnabled && DNS_DebugFlag && (isDns || hasFake)) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"GLOBAL: recv() socket=%p, len=%d, isDns=%d, hasFake=%d",
            (void*)(ULONG_PTR)s, len, isDns ? 1 : 0, hasFake ? 1 : 0);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // Check for pending fake response
    if (hasFake) {
        // Return data from fake response (handles fragmentation automatically)
        int result = Socket_GetFakeResponse(s, buf, len, NULL, NULL);
        if (result > 0) {
            if (DNS_DebugFlag) {
                const WCHAR* protocol = Socket_IsTcpSocket(s) ? L"TCP" : L"UDP";
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"  %s DNS Debug: Returned %d bytes from fake response, socket=%p",
                    protocol, result, (void*)(ULONG_PTR)s);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            return result;
        }
    }

    // No fake response - pass through to real recv
    int result = __sys_recv(s, buf, len, flags);
    
    // Apply DNS rebind protection to passthrough DNS responses (TCP and connected UDP)
    if (result > 0) {
        int new_len = result;
        Socket_ApplyRebindProtection(s, (BYTE*)buf, &new_len);
        if (new_len > 0 && new_len <= result)
            result = new_len;
    }

    // Check if there's a pending passthrough query to log
    if (result > 0 && DNS_TraceFlag) {
        WCHAR domain[256];
        USHORT qtype;
        BOOLEAN isTcp;
        DNS_PASSTHROUGH_REASON reason;
        // Peek at the pending query without clearing it
        if (Socket_GetPendingQuery(s, domain, 256, &qtype, &isTcp, &reason, FALSE)) {
            // Try to parse and log the DNS response
            // For TCP DNS, the first recv may only get the 2-byte length prefix
            // Only clear the pending query if we successfully parsed and logged
            if (Socket_ParseAndLogDnsResponse(s, (const BYTE*)buf, result, domain, qtype, isTcp, reason)) {
                // Successfully logged - clear the pending query
                Socket_ClearPendingQuery(s);
            }
            // If parse failed (e.g., only got length prefix), leave pending query for next recv
        }
    }
    
    return result;
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
    int result = __sys_recvfrom(s, buf, len, flags, from, fromlen);

    // Apply DNS rebind protection to passthrough DNS responses (UDP)
    if (result > 0) {
        int new_len = result;
        Socket_ApplyRebindProtection(s, (BYTE*)buf, &new_len);
        if (new_len > 0 && new_len <= result)
            result = new_len;
    }
    
    // Check if there's a pending passthrough query to log
    if (result > 0 && DNS_TraceFlag) {
        WCHAR domain[256];
        USHORT qtype;
        BOOLEAN isTcp;
        DNS_PASSTHROUGH_REASON reason;
        // Peek at the pending query without clearing it
        if (Socket_GetPendingQuery(s, domain, 256, &qtype, &isTcp, &reason, FALSE)) {
            // Try to parse and log the DNS response
            // Only clear the pending query if we successfully parsed and logged
            if (Socket_ParseAndLogDnsResponse(s, (const BYTE*)buf, result, domain, qtype, isTcp, reason)) {
                Socket_ClearPendingQuery(s);
            }
        }
    }
    
    return result;
}

//---------------------------------------------------------------------------
// Socket_WSARecv
//
// Hook for WSARecv() - returns fake DNS responses for TCP sockets
// This is what dig and .NET applications use for connected sockets
//---------------------------------------------------------------------------

_FX int Socket_WSARecv(
    SOCKET                             s,
    LPWSABUF                           lpBuffers,
    DWORD                              dwBufferCount,
    LPDWORD                            lpNumberOfBytesRecvd,
    LPDWORD                            lpFlags,
    LPWSAOVERLAPPED                    lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    // Cast to actual WSABUF structure
    LPWSABUF_REAL buffers = (LPWSABUF_REAL)lpBuffers;
    
    // DEBUG: Log WSARecv() calls on DNS sockets or with fake responses
    BOOLEAN isDns = Socket_IsDnsSocket(s);
    BOOLEAN hasFake = Socket_HasFakeResponse(s);
    if (DNS_FilterEnabled && DNS_RawSocketHooksEnabled && DNS_DebugFlag && lpBuffers && dwBufferCount > 0 && (isDns || hasFake)) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"GLOBAL: WSARecv() socket=%p, first.len=%d, isDns=%d, hasFake=%d",
            (void*)(ULONG_PTR)s, buffers[0].len, isDns ? 1 : 0, hasFake ? 1 : 0);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // Check for pending fake response on DNS sockets
    if (hasFake && lpBuffers && dwBufferCount > 0) {
        // Get fake response data into first buffer
        int result = Socket_GetFakeResponse(s, buffers[0].buf, buffers[0].len, NULL, NULL);
        if (result > 0) {
            if (lpNumberOfBytesRecvd) {
                *lpNumberOfBytesRecvd = result;
            }
            if (lpFlags) {
                *lpFlags = 0;  // Clear any pending flags
            }
            
            if (DNS_DebugFlag) {
                const WCHAR* protocol = Socket_IsTcpSocket(s) ? L"TCP" : L"UDP";
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"  %s DNS Debug: WSARecv returned %d bytes from fake response, socket=%p",
                    protocol, result, (void*)(ULONG_PTR)s);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            
            // For synchronous WSARecv (lpOverlapped == NULL), return 0 for success
            // For overlapped WSARecv, we also return 0 but the caller expects the data immediately
            return 0;  // Success
        }
    }

    // No fake response - pass through to real WSARecv
    int ret = __sys_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
    
    // Apply DNS rebind protection to passthrough DNS responses (synchronous only)
    if (ret == 0 && lpOverlapped == NULL && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0 &&
        lpBuffers && dwBufferCount > 0) {
        int new_len = (int)*lpNumberOfBytesRecvd;
        Socket_ApplyRebindProtection(s, (BYTE*)buffers[0].buf, &new_len);
        if (new_len > 0 && new_len <= (int)*lpNumberOfBytesRecvd)
            *lpNumberOfBytesRecvd = (DWORD)new_len;
    }

    // Check if there's a pending passthrough query to log (synchronous only)
    if (ret == 0 && lpOverlapped == NULL && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0 && 
        DNS_TraceFlag && lpBuffers && dwBufferCount > 0) {
        WCHAR domain[256];
        USHORT qtype;
        BOOLEAN isTcp;
        DNS_PASSTHROUGH_REASON reason;
        // Peek at the pending query without clearing it
        if (Socket_GetPendingQuery(s, domain, 256, &qtype, &isTcp, &reason, FALSE)) {
            // Try to parse and log the DNS response
            // Only clear the pending query if we successfully parsed and logged
            if (Socket_ParseAndLogDnsResponse(s, (const BYTE*)buffers[0].buf, (int)*lpNumberOfBytesRecvd, domain, qtype, isTcp, reason)) {
                Socket_ClearPendingQuery(s);
            }
        }
    }
    
    return ret;
}

//---------------------------------------------------------------------------
// Socket_WSARecvFrom
//
// Hook for WSARecvFrom() - returns fake DNS responses for UDP sockets
// This is what dig uses for UDP DNS queries
//---------------------------------------------------------------------------

_FX int Socket_WSARecvFrom(
    SOCKET                             s,
    LPWSABUF                           lpBuffers,
    DWORD                              dwBufferCount,
    LPDWORD                            lpNumberOfBytesRecvd,
    LPDWORD                            lpFlags,
    void                               *lpFrom,
    LPINT                              lpFromlen,
    LPWSAOVERLAPPED                    lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    // Cast to actual WSABUF structure
    LPWSABUF_REAL buffers = (LPWSABUF_REAL)lpBuffers;
    
    // DEBUG: Log WSARecvFrom() calls only if there's a fake response queued
    BOOLEAN hasFake = Socket_HasFakeResponse(s);
    if (DNS_FilterEnabled && DNS_RawSocketHooksEnabled && DNS_DebugFlag && lpBuffers && dwBufferCount > 0 && hasFake) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"GLOBAL: WSARecvFrom() socket=%p, first.len=%d, hasFake=%d",
            (void*)(ULONG_PTR)s, buffers[0].len, hasFake ? 1 : 0);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // Check for pending fake response
    if (hasFake && lpBuffers && dwBufferCount > 0) {
        // Get fake response data into first buffer
        int fromlen_val = lpFromlen ? *lpFromlen : 0;
        int result = Socket_GetFakeResponse(s, buffers[0].buf, buffers[0].len, lpFrom, &fromlen_val);
        if (result > 0) {
            if (lpNumberOfBytesRecvd) {
                *lpNumberOfBytesRecvd = result;
            }
            if (lpFlags) {
                *lpFlags = 0;  // Clear any pending flags
            }
            if (lpFromlen) {
                *lpFromlen = fromlen_val;
            }
            
            if (DNS_DebugFlag) {
                const WCHAR* protocol = Socket_IsTcpSocket(s) ? L"TCP" : L"UDP";
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"  %s DNS Debug: WSARecvFrom returned %d bytes from fake response, socket=%p",
                    protocol, result, (void*)(ULONG_PTR)s);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            
            return 0;  // Success
        }
    }
    
    // FIX for UDP DNS + EncDns timeout:
    // When EncDns is enabled and processing async queries (DoQ, DoH), responses may not be queued
    // immediately when WSARecvFrom is called. If this is a DNS socket with no immediate response,
    // poll briefly for a response to arrive (typically within 500-1000ms for DoQ/DoH).
    // This prevents timeouts when nslookup calls WSARecvFrom before async EncDns completes.
    if (!hasFake && Socket_IsDnsSocket(s) && EncryptedDns_IsEnabled() && 
        lpBuffers && dwBufferCount > 0 && !lpOverlapped) {
        // Synchronous recv on DNS socket with EncDns enabled - poll for async response
        DWORD pollRetries = 20;  // ~1 second total (50ms per retry)
        while (pollRetries-- > 0) {
            if (Socket_HasFakeResponse(s)) {
                int fromlen_val = lpFromlen ? *lpFromlen : 0;
                int result = Socket_GetFakeResponse(s, buffers[0].buf, buffers[0].len, lpFrom, &fromlen_val);
                if (result > 0) {
                    if (lpNumberOfBytesRecvd) *lpNumberOfBytesRecvd = result;
                    if (lpFlags) *lpFlags = 0;
                    if (lpFromlen) *lpFromlen = fromlen_val;
                    
                    if (DNS_DebugFlag) {
                        const WCHAR* protocol = Socket_IsTcpSocket(s) ? L"TCP" : L"UDP";
                        WCHAR msg[256];
                        Sbie_snwprintf(msg, 256, L"  %s DNS Debug: WSARecvFrom got delayed EncDns response after poll, socket=%p",
                            protocol, (void*)(ULONG_PTR)s);
                        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                    }
                    return 0;  // Success
                }
            }
            Sleep(50);  // Small sleep before next retry
        }
    }

    // No fake response - pass through to real WSARecvFrom
    int ret = __sys_WSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);

    // Apply DNS rebind protection to passthrough DNS responses (UDP, synchronous only)
    if (ret == 0 && lpOverlapped == NULL && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0 &&
        lpBuffers && dwBufferCount > 0)
    {
        int new_len = (int)*lpNumberOfBytesRecvd;
        Socket_ApplyRebindProtection(s, (BYTE*)buffers[0].buf, &new_len);
        if (new_len > 0 && new_len <= (int)*lpNumberOfBytesRecvd)
            *lpNumberOfBytesRecvd = (DWORD)new_len;
    }
    
    // Check if there's a pending passthrough query to log (synchronous only)
    if (ret == 0 && lpOverlapped == NULL && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0 && 
        DNS_TraceFlag && lpBuffers && dwBufferCount > 0) {
        WCHAR domain[256];
        USHORT qtype;
        BOOLEAN isTcp;
        DNS_PASSTHROUGH_REASON reason;
        // Peek at the pending query without clearing it
        if (Socket_GetPendingQuery(s, domain, 256, &qtype, &isTcp, &reason, FALSE)) {
            // Try to parse and log the DNS response
            // Only clear the pending query if we successfully parsed and logged
            if (Socket_ParseAndLogDnsResponse(s, (const BYTE*)buffers[0].buf, (int)*lpNumberOfBytesRecvd, domain, qtype, isTcp, reason)) {
                Socket_ClearPendingQuery(s);
            }
        }
    }
    
    return ret;
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
    if (!DNS_FilterEnabled || !DNS_RawSocketHooksEnabled || !readfds_typed) {
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
                const WCHAR* protocol = Socket_IsTcpSocket(s) ? L"TCP" : L"UDP";
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"%s DNS: select() found socket=%p with fake response, making it readable",
                    protocol, (void*)(ULONG_PTR)s);
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
                    const WCHAR* protocol = Socket_IsTcpSocket(s) ? L"TCP" : L"UDP";
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"%s DNS: select() marking socket=%p as readable (has fake response)",
                        protocol, (void*)(ULONG_PTR)s);
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
// Socket_WSAPoll
//
// Hook for WSAPoll() - makes DNS sockets with fake responses appear readable
// WSAPoll is the modern alternative to select(), used by dig and other tools
// Poll constants: POLLIN=0x0100, POLLRDNORM=0x0100, POLLOUT=0x0010
//---------------------------------------------------------------------------

#define POLLIN_COMPAT      0x0100
#define POLLRDNORM_COMPAT  0x0100
#define POLLOUT_COMPAT     0x0010

_FX int Socket_WSAPoll(
    WSAPOLLFD_COMPAT *fdArray,
    ULONG            nfds,
    INT              timeout)
{
    // If DNS filtering is not enabled or no array, pass through
    if (!DNS_FilterEnabled || !DNS_RawSocketHooksEnabled || !fdArray || nfds == 0) {
        return __sys_WSAPoll(fdArray, nfds, timeout);
    }

    // Check if any of the sockets have fake responses queued
    BOOLEAN has_fake = FALSE;
    ULONG fake_count = 0;
    
    for (ULONG i = 0; i < nfds; i++) {
        // Only check sockets waiting for read events
        if ((fdArray[i].events & (POLLIN_COMPAT | POLLRDNORM_COMPAT)) && 
            Socket_HasFakeResponse(fdArray[i].fd)) {
            has_fake = TRUE;
            fake_count++;
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"DNS: WSAPoll() found socket=%p with fake response, making it readable",
                    (void*)(ULONG_PTR)fdArray[i].fd);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
        }
    }

    // If we have fake responses, set the appropriate revents and return immediately
    if (has_fake) {
        // First, call WSAPoll with zero timeout to get current state of other sockets
        int result = __sys_WSAPoll(fdArray, nfds, 0);
        
        // Now set POLLIN for sockets with fake responses
        for (ULONG i = 0; i < nfds; i++) {
            if ((fdArray[i].events & (POLLIN_COMPAT | POLLRDNORM_COMPAT)) && 
                Socket_HasFakeResponse(fdArray[i].fd)) {
                // Mark socket as readable
                fdArray[i].revents |= (fdArray[i].events & (POLLIN_COMPAT | POLLRDNORM_COMPAT));
                if (DNS_DebugFlag) {
                    WCHAR msg[256];
                    Sbie_snwprintf(msg, 256, L"DNS: WSAPoll() marking socket=%p as readable (revents=0x%04X)",
                        (void*)(ULONG_PTR)fdArray[i].fd, fdArray[i].revents);
                    SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
                }
            }
        }
        
        // Return the count of ready sockets (at least the ones with fake responses)
        int ready = (result > 0) ? result : 0;
        ready += fake_count;
        return (ready > 0) ? ready : 1;  // At least 1 socket is ready
    }

    // No fake responses - call original WSAPoll
    return __sys_WSAPoll(fdArray, nfds, timeout);
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
    if (DNS_FilterEnabled && DNS_RawSocketHooksEnabled && Socket_IsDnsSocket(s) && name && namelen) {
        ULONG index = ((ULONG_PTR)s) % DNS_SOCKET_TABLE_SIZE;
        
        // Thread-safe access to DNS server address storage
        EnterCriticalSection(&g_DnsSocketTableLock);
        
        // If we have a stored DNS server address, return it
        if (g_DnsServerAddrLens[index] > 0) {
            int copy_len = (*namelen < g_DnsServerAddrLens[index]) ? *namelen : g_DnsServerAddrLens[index];
            memcpy(name, g_DnsServerAddrs[index], copy_len);
            *namelen = g_DnsServerAddrLens[index];
            
            LeaveCriticalSection(&g_DnsSocketTableLock);
            
            if (DNS_TraceFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"TCP DNS: getpeername() returned stored DNS server address for socket=%p",
                    (void*)(ULONG_PTR)s);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            
            return 0;  // Success
        }
        
        LeaveCriticalSection(&g_DnsSocketTableLock);
    }
    
    // Not a DNS socket or no stored address - pass through to real getpeername
    return __sys_getpeername(s, name, namelen);
}

//---------------------------------------------------------------------------
// Socket_WSAEnumNetworkEvents
//
// Hook for WSAEnumNetworkEvents() - injects FD_READ when fake responses are queued
// This is critical for Cygwin applications that use WSAEventSelect + WSAWaitForMultipleEvents
// for async I/O. Without this hook, they would wait forever for FD_READ from the network.
// NOTE: WSANETWORKEVENTS_COMPAT and FD_* defines are at the top of this file.
//---------------------------------------------------------------------------

_FX int Socket_WSAEnumNetworkEvents(
    SOCKET         s,
    HANDLE         hEventObject,
    void           *lpNetworkEvents)
{
    // Record the event handle for this socket so we can signal it proactively when responses arrive
    if (hEventObject != NULL && DNS_FilterEnabled && DNS_RawSocketHooksEnabled) {
        Socket_RecordEventForSocket(s, hEventObject);
    }
    
    // Call the original function first
    int result = __sys_WSAEnumNetworkEvents(s, hEventObject, lpNetworkEvents);
    
    // If the call succeeded and we have a fake response queued, inject FD_READ
    if (result == 0 && DNS_FilterEnabled && DNS_RawSocketHooksEnabled && 
        Socket_HasFakeResponse(s) && lpNetworkEvents) {
        
        WSANETWORKEVENTS_COMPAT* events = (WSANETWORKEVENTS_COMPAT*)lpNetworkEvents;
        
        // Inject FD_READ event to signal data is available
        if (!(events->lNetworkEvents & FD_READ)) {
            events->lNetworkEvents |= FD_READ;
            events->iErrorCode[FD_READ_BIT] = 0;  // No error
            
            // CRITICAL: The call to WSAEnumNetworkEvents above RESET the event handle.
            // Cygwin uses WSAWaitForMultipleEvents to wait on this event handle.
            // If we don't re-signal it, the wait loop will block forever even though
            // we injected FD_READ into the network events.
            // We must re-signal the event handle so the wait loop wakes up.
            if (hEventObject != NULL) {
                SetEvent(hEventObject);
            }
            
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"DNS: WSAEnumNetworkEvents() injected FD_READ for socket=%p (fake response queued), re-signaled event=%p",
                    (void*)(ULONG_PTR)s, hEventObject);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
        }
    }
    
    return result;
}

//---------------------------------------------------------------------------
// Socket_WSARecvMsg
//
// Our wrapper for WSARecvMsg that checks for fake DNS responses.
// This is called by Cygwin when receiving UDP data via recvmsg().
//---------------------------------------------------------------------------

_FX INT PASCAL FAR Socket_WSARecvMsg(
    SOCKET         s,
    LPWSAMSG_COMPAT lpMsg,
    LPDWORD        lpdwNumberOfBytesRecvd,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    // Cast WSABUF to our version
    LPWSABUF_REAL buffers = (LPWSABUF_REAL)lpMsg->lpBuffers;
    
    // DEBUG: Log WSARecvMsg() calls only if there's a fake response queued
    BOOLEAN hasFake = Socket_HasFakeResponse(s);
    if (DNS_FilterEnabled && DNS_RawSocketHooksEnabled && DNS_DebugFlag && 
        lpMsg && lpMsg->lpBuffers && lpMsg->dwBufferCount > 0 && hasFake) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"GLOBAL: WSARecvMsg() socket=%p, first.len=%d, hasFake=%d",
            (void*)(ULONG_PTR)s, buffers[0].len, hasFake ? 1 : 0);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // Check for pending fake response
    if (hasFake && lpMsg && lpMsg->lpBuffers && lpMsg->dwBufferCount > 0) {
        // Get fake response data into first buffer
        int fromlen_val = lpMsg->namelen;
        int result = Socket_GetFakeResponse(s, buffers[0].buf, buffers[0].len, 
                                             lpMsg->name, &fromlen_val);
        if (result > 0) {
            if (lpdwNumberOfBytesRecvd) {
                *lpdwNumberOfBytesRecvd = result;
            }
            // Update the name length
            lpMsg->namelen = fromlen_val;
            // Clear control data (no ancillary data for our fake response)
            lpMsg->Control.len = 0;
            // Clear flags
            lpMsg->dwFlags = 0;
            
            if (DNS_DebugFlag) {
                const WCHAR* protocol = Socket_IsTcpSocket(s) ? L"TCP" : L"UDP";
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"  %s DNS Debug: WSARecvMsg returned %d bytes from fake response, socket=%p",
                    protocol, result, (void*)(ULONG_PTR)s);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            
            return 0;  // Success
        }
    }

    // No fake response - pass through to real WSARecvMsg
    if (__sys_WSARecvMsg) {
        int ret = __sys_WSARecvMsg(s, lpMsg, lpdwNumberOfBytesRecvd, lpOverlapped, lpCompletionRoutine);
        
        // Apply DNS rebind protection to passthrough DNS responses (synchronous only)
        if (ret == 0 && lpOverlapped == NULL && lpdwNumberOfBytesRecvd && *lpdwNumberOfBytesRecvd > 0 &&
            lpMsg && lpMsg->lpBuffers && lpMsg->dwBufferCount > 0) {
            int new_len = (int)*lpdwNumberOfBytesRecvd;
            Socket_ApplyRebindProtection(s, (BYTE*)buffers[0].buf, &new_len);
            if (new_len > 0 && new_len <= (int)*lpdwNumberOfBytesRecvd)
                *lpdwNumberOfBytesRecvd = (DWORD)new_len;
        }

        // Check if there's a pending passthrough query to log (synchronous only)
        if (ret == 0 && lpOverlapped == NULL && lpdwNumberOfBytesRecvd && *lpdwNumberOfBytesRecvd > 0 && 
            DNS_TraceFlag && lpMsg && lpMsg->lpBuffers && lpMsg->dwBufferCount > 0) {
            WCHAR domain[256];
            USHORT qtype;
            BOOLEAN isTcp;
            DNS_PASSTHROUGH_REASON reason;
            // Peek at the pending query without clearing it
            if (Socket_GetPendingQuery(s, domain, 256, &qtype, &isTcp, &reason, FALSE)) {
                // Try to parse and log the DNS response
                // Only clear the pending query if we successfully parsed and logged
                if (Socket_ParseAndLogDnsResponse(s, (const BYTE*)buffers[0].buf, (int)*lpdwNumberOfBytesRecvd, domain, qtype, isTcp, reason)) {
                    Socket_ClearPendingQuery(s);
                }
            }
        }
        
        return ret;
    }
    
    // WSARecvMsg not available - shouldn't happen but return error
    // Note: We can't call WSASetLastError here as we don't have access to it,
    // but if __sys_WSARecvMsg is NULL, something is very wrong anyway.
    return SOCKET_ERROR;
}

//---------------------------------------------------------------------------
// Socket_GetWSARecvMsgWrapper
//
// Returns our WSARecvMsg wrapper function pointer and stores the real
// WSARecvMsg function pointer. Called from WSA_WSAIoctl in net.c when
// an application requests the WSARecvMsg extension function.
//---------------------------------------------------------------------------

_FX void* Socket_GetWSARecvMsgWrapper(void* realWSARecvMsg)
{
    // Store the real WSARecvMsg function pointer
    __sys_WSARecvMsg = (LPFN_WSARECVMSG)realWSARecvMsg;
    
    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"DNS: Socket_GetWSARecvMsgWrapper() storing real=%p, returning wrapper=%p",
            realWSARecvMsg, (void*)Socket_WSARecvMsg);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    // Return our wrapper function
    return (void*)Socket_WSARecvMsg;
}
