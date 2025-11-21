/*
 * Copyright 2022-2025 David Xanatos, xanasoft.com
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
// DnsApi Definitions
//
// This header provides type definitions and constants for Windows DNS API
// (dnsapi.dll) used by Sandboxie's DNS filtering implementation.
//
// Structures and constants are based on Windows SDK windns.h to ensure
// binary compatibility with the system DNS API.
//---------------------------------------------------------------------------

#ifndef _DNSAPI_DEFS_H
#define _DNSAPI_DEFS_H

//---------------------------------------------------------------------------
// Version & helper constants (backfilled for older SDKs)
//---------------------------------------------------------------------------

#ifndef DNS_QUERY_REQUEST_VERSION1
#define DNS_QUERY_REQUEST_VERSION1    1
#endif

#ifndef DNS_QUERY_RESULTS_VERSION1
#define DNS_QUERY_RESULTS_VERSION1    1
#endif

#ifndef DNS_REQUEST_PENDING
#define DNS_REQUEST_PENDING           ERROR_IO_PENDING
#endif

//---------------------------------------------------------------------------
// DNS Status Codes
//---------------------------------------------------------------------------

typedef LONG DNS_STATUS;

//---------------------------------------------------------------------------
// DNS Query Types
//---------------------------------------------------------------------------

#ifndef DNS_TYPE_A
#define DNS_TYPE_A      1   // IPv4 address record
#endif

#ifndef DNS_TYPE_NS
#define DNS_TYPE_NS     2   // Name server record
#endif

#ifndef DNS_TYPE_CNAME
#define DNS_TYPE_CNAME  5   // Canonical name record
#endif

#ifndef DNS_TYPE_SOA
#define DNS_TYPE_SOA    6   // Start of authority record
#endif

#ifndef DNS_TYPE_PTR
#define DNS_TYPE_PTR    12  // Pointer record
#endif

#ifndef DNS_TYPE_MX
#define DNS_TYPE_MX     15  // Mail exchange record
#endif

#ifndef DNS_TYPE_TXT
#define DNS_TYPE_TXT    16  // Text record
#endif

#ifndef DNS_TYPE_AAAA
#define DNS_TYPE_AAAA   28  // IPv6 address record
#endif

#ifndef DNS_TYPE_SRV
#define DNS_TYPE_SRV    33  // Service locator record
#endif

#ifndef DNS_TYPE_ALL
#define DNS_TYPE_ALL    255 // Wildcard (ANY) - requests all record types
#endif

//---------------------------------------------------------------------------
// DNS Record Section Types
//---------------------------------------------------------------------------

#ifndef DNSREC_QUESTION
#define DNSREC_QUESTION   0  // Question section
#define DNSREC_ANSWER     1  // Answer section
#define DNSREC_AUTHORITY  2  // Authority section
#define DNSREC_ADDITIONAL 3  // Additional section
#endif

//---------------------------------------------------------------------------
// DNS Query Options
//
// Flags shared by both DnsQuery and DnsQueryEx (safe for DnsQuery_W workaround):
// These flags are compatible with legacy DnsQuery API and can be passed through
// when converting DnsQueryEx calls to DnsQuery_W on Windows 10 (bug workaround).
//---------------------------------------------------------------------------

#ifndef DNS_QUERY_STANDARD
#define DNS_QUERY_STANDARD                    0x00000000
#endif

#ifndef DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE
#define DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE   0x00000001
#endif

#ifndef DNS_QUERY_USE_TCP_ONLY
#define DNS_QUERY_USE_TCP_ONLY                0x00000002
#endif

#ifndef DNS_QUERY_NO_RECURSION
#define DNS_QUERY_NO_RECURSION                0x00000004
#endif

#ifndef DNS_QUERY_BYPASS_CACHE
#define DNS_QUERY_BYPASS_CACHE                0x00000008
#endif

#ifndef DNS_QUERY_NO_WIRE_QUERY
#define DNS_QUERY_NO_WIRE_QUERY               0x00000010
#endif

#ifndef DNS_QUERY_NO_LOCAL_NAME
#define DNS_QUERY_NO_LOCAL_NAME               0x00000020
#endif

#ifndef DNS_QUERY_NO_HOSTS_FILE
#define DNS_QUERY_NO_HOSTS_FILE               0x00000040
#endif

#ifndef DNS_QUERY_NO_NETBT
#define DNS_QUERY_NO_NETBT                    0x00000080
#endif

#ifndef DNS_QUERY_WIRE_ONLY
#define DNS_QUERY_WIRE_ONLY                   0x00000100  // Legacy flag
#endif

#ifndef DNS_QUERY_RETURN_MESSAGE
#define DNS_QUERY_RETURN_MESSAGE              0x00000200
#endif

#ifndef DNS_QUERY_TREAT_AS_FQDN
#define DNS_QUERY_TREAT_AS_FQDN               0x00001000
#endif

#ifndef DNS_QUERY_DONT_RESET_TTL_VALUES
#define DNS_QUERY_DONT_RESET_TTL_VALUES       0x00002000
#endif

#ifndef DNS_QUERY_DISABLE_IDN_ENCODING
#define DNS_QUERY_DISABLE_IDN_ENCODING        0x00004000
#endif

#ifndef DNS_QUERY_MULTICAST_ONLY
#define DNS_QUERY_MULTICAST_ONLY              0x00000400
#endif

#ifndef DNS_QUERY_NO_MULTICAST
#define DNS_QUERY_NO_MULTICAST                0x00000800
#endif

#ifndef DNS_QUERY_ADDRCONFIG
#define DNS_QUERY_ADDRCONFIG                  0x00002000  // Windows 7+
#endif

#ifndef DNS_QUERY_DUAL_ADDR
#define DNS_QUERY_DUAL_ADDR                   0x00004000  // Windows 7+ DnsQueryEx only
#endif

#ifndef DNS_QUERY_MULTICAST_WAIT
#define DNS_QUERY_MULTICAST_WAIT              0x00020000
#endif

#ifndef DNS_QUERY_MULTICAST_VERIFY
#define DNS_QUERY_MULTICAST_VERIFY            0x00040000
#endif

#ifndef DNS_QUERY_DONT_RESET_TTL_VALUES
#define DNS_QUERY_DONT_RESET_TTL_VALUES       0x00100000
#endif

#ifndef DNS_QUERY_DISABLE_IDN_ENCODING
#define DNS_QUERY_DISABLE_IDN_ENCODING        0x00200000
#endif

#ifndef DNS_QUERY_APPEND_MULTILABEL
#define DNS_QUERY_APPEND_MULTILABEL           0x00800000
#endif

// Safe mask for DnsQuery_W compatibility (bits 0-13, 17-22)
// Excludes DnsQueryEx-specific flags: bit 14 (DUAL_ADDR), bits 15-16, bits 23+
// Based on Microsoft documentation: learn.microsoft.com/en-us/windows/win32/dns/dns-constants
#ifndef DNS_QUERY_W_SAFE_MASK
#define DNS_QUERY_W_SAFE_MASK                 0x007E3FFF
#endif

//---------------------------------------------------------------------------
// DNS Error Codes
//---------------------------------------------------------------------------

#ifndef DNS_ERROR_RCODE_NAME_ERROR
#define DNS_ERROR_RCODE_NAME_ERROR  9003  // Name does not exist
#endif

//---------------------------------------------------------------------------
// DNS Character Set
//---------------------------------------------------------------------------

typedef enum _DNS_CHARSET
{
    DnsCharSetUnknown,
    DnsCharSetUnicode,
    DnsCharSetUtf8,
    DnsCharSetAnsi,
} DNS_CHARSET;

//---------------------------------------------------------------------------
// DNS_RECORD_FLAGS Structure
//
// Bitfield structure for the Flags union in DNS_RECORD.
// Matches Windows dnsapi.h DNS_RECORD_FLAGS layout.
//---------------------------------------------------------------------------

typedef struct _DNS_RECORD_FLAGS {
    DWORD Section : 2;      // Record section (DNSREC_QUESTION/ANSWER/AUTHORITY/ADDITIONAL)
    DWORD Delete : 1;       // Record marked for deletion
    DWORD CharSet : 2;      // Character set (DnsCharSetUnicode/Utf8/Ansi)
    DWORD Unused : 3;       // Reserved/unused bits
    DWORD Reserved : 24;    // Reserved for future use
} DNS_RECORD_FLAGS;

//---------------------------------------------------------------------------
// DNS_RECORD Structure
//
// Simplified DNS_RECORD structure matching Windows dnsapi.h layout.
// Only includes fields needed for A and AAAA record types.
//
// IMPORTANT: Uses ABSOLUTE pointers (unlike HOSTENT BLOB which uses relative offsets)
//            Memory must be allocated with LocalAlloc for DnsRecordListFree compatibility
//
// NOTE: Structure MUST match exact layout from Windows SDK windns.h
//       Different Windows versions may have different layouts!
//---------------------------------------------------------------------------

#pragma pack(push, 8)  // Force 8-byte alignment for x64 compatibility
struct _DnsRecordW {
    struct _DnsRecordW* pNext;      // Pointer to next record in linked list
    PWSTR               pName;      // Domain name (wide string)
    WORD                wType;      // Record type (DNS_TYPE_A or DNS_TYPE_AAAA)
    WORD                wDataLength; // Length of record data
    union {
        DWORD               DW;     // Access flags as DWORD
        DNS_RECORD_FLAGS    S;      // Access flags as bitfield structure
    } Flags;
    DWORD               dwTtl;      // Time to live in seconds
    DWORD               dwReserved; // Reserved for system use
    union {
        struct {
            DWORD       IpAddress;  // IPv4 address (network byte order)
        } A;
        struct {
            BYTE        Ip6Address[16];  // IPv6 address (16 bytes)
        } AAAA;
        // Pad to match real DNS_RECORD structure size
        // Real Windows DNS_RECORD has larger Data union (24+ bytes for MX/SOA/SRV/etc)
        // We only use A/AAAA but need matching size for Win7 dnsapi.dll validation
        // Note: DNS_TSIG_DATAW is ~56 bytes, so 24 bytes is not enough.
        // Using 64 bytes to be safe and cover all known record types.
        BYTE            Padding[64];
    } Data;
};
#pragma pack(pop)

//---------------------------------------------------------------------------
// Type Aliases
//---------------------------------------------------------------------------

typedef struct _DnsRecordW DNSAPI_DNS_RECORD, *PDNSAPI_DNS_RECORD;

//---------------------------------------------------------------------------
// Modern DNS Query Structures (Windows 8+)
//---------------------------------------------------------------------------

typedef struct _DNS_QUERY_RESULT {
    ULONG               Version;
    DNS_STATUS          QueryStatus;
    ULONG64             QueryOptions;
    PDNSAPI_DNS_RECORD  pQueryRecords;
    PVOID               Reserved;
} DNS_QUERY_RESULT, *PDNS_QUERY_RESULT;

typedef VOID (WINAPI *PDNS_QUERY_COMPLETION_ROUTINE)(
    PDNS_QUERY_RESULT   pQueryResults,
    PVOID               pQueryContext);

typedef struct _DNS_QUERY_REQUEST_W {
    ULONG                           Version;
    PWSTR                           QueryName;
    WORD                            QueryType;
    WORD                            _Padding1;  // Explicit padding for alignment
    ULONG                           _Padding2;  // Align to 8 bytes before QueryOptions
    ULONG64                         QueryOptions;
    PVOID                           pDnsServerList;
    ULONG                           InterfaceIndex;
    ULONG                           _Padding3;  // Align to 8 bytes before callback pointer
    PDNS_QUERY_COMPLETION_ROUTINE   pQueryCompletionCallback;
    PVOID                           pQueryContext;
} DNS_QUERY_REQUEST_W, *PDNS_QUERY_REQUEST_W;

typedef struct _DNS_QUERY_REQUEST_A {
    ULONG                           Version;
    PSTR                            QueryName;
    WORD                            QueryType;
    WORD                            _Padding1;  // Explicit padding for alignment
    ULONG                           _Padding2;  // Align to 8 bytes before QueryOptions
    ULONG64                         QueryOptions;
    PVOID                           pDnsServerList;
    ULONG                           InterfaceIndex;
    ULONG                           _Padding3;  // Align to 8 bytes before callback pointer
    PDNS_QUERY_COMPLETION_ROUTINE   pQueryCompletionCallback;
    PVOID                           pQueryContext;
} DNS_QUERY_REQUEST_A, *PDNS_QUERY_REQUEST_A;

typedef struct _DNS_QUERY_REQUEST_UTF8 {
    ULONG                           Version;
    PSTR                            QueryName;
    WORD                            QueryType;
    WORD                            _Padding1;  // Explicit padding for alignment
    ULONG                           _Padding2;  // Align to 8 bytes before QueryOptions
    ULONG64                         QueryOptions;
    PVOID                           pDnsServerList;
    ULONG                           InterfaceIndex;
    ULONG                           _Padding3;  // Align to 8 bytes before callback pointer
    PDNS_QUERY_COMPLETION_ROUTINE   pQueryCompletionCallback;
    PVOID                           pQueryContext;
} DNS_QUERY_REQUEST_UTF8, *PDNS_QUERY_REQUEST_UTF8;

typedef struct _DNS_QUERY_CANCEL {
    BYTE Reserved[32];
} DNS_QUERY_CANCEL, *PDNS_QUERY_CANCEL;

//---------------------------------------------------------------------------
// Function Pointer Types
//
// These match the Windows dnsapi.dll export signatures for hooking.
//---------------------------------------------------------------------------

typedef DNS_STATUS (WINAPI *P_DnsQuery_A)(
    PCSTR               pszName,
    WORD                wType,
    DWORD               Options,
    PVOID               pExtra,
    PDNSAPI_DNS_RECORD* ppQueryResults,
    PVOID*              pReserved);

typedef DNS_STATUS (WINAPI *P_DnsQuery_W)(
    PCWSTR              pszName,
    WORD                wType,
    DWORD               Options,
    PVOID               pExtra,
    PDNSAPI_DNS_RECORD* ppQueryResults,
    PVOID*              pReserved);

typedef VOID (WINAPI *P_DnsRecordListFree)(
    PVOID               pRecordList,
    INT                 FreeType);

typedef DNS_STATUS (WINAPI *P_DnsQuery_UTF8)(
    PCSTR               pszName,
    WORD                wType,
    DWORD               Options,
    PVOID               pExtra,
    PDNSAPI_DNS_RECORD* ppQueryResults,
    PVOID*              pReserved);

typedef DNS_STATUS (WINAPI *P_DnsQueryExW)(
    PDNS_QUERY_REQUEST_W    pQueryRequest,
    PDNS_QUERY_RESULT       pQueryResults,
    PDNS_QUERY_CANCEL       pCancelHandle);

typedef DNS_STATUS (WINAPI *P_DnsQueryExA)(
    PDNS_QUERY_REQUEST_A    pQueryRequest,
    PDNS_QUERY_RESULT       pQueryResults,
    PDNS_QUERY_CANCEL       pCancelHandle);

typedef DNS_STATUS (WINAPI *P_DnsQueryExUTF8)(
    PDNS_QUERY_REQUEST_UTF8 pQueryRequest,
    PDNS_QUERY_RESULT       pQueryResults,
    PDNS_QUERY_CANCEL       pCancelHandle);

// Some builds export a generic DnsQueryEx without suffix; treat it as wide.
typedef DNS_STATUS (WINAPI *P_DnsQueryEx)(
    PDNS_QUERY_REQUEST_W    pQueryRequest,
    PDNS_QUERY_RESULT       pQueryResults,
    PDNS_QUERY_CANCEL       pCancelHandle);

//---------------------------------------------------------------------------
// DnsQueryRaw Structures (Windows 10+)
//---------------------------------------------------------------------------

#ifndef DNS_QUERY_RAW_REQUEST_VERSION1
#define DNS_QUERY_RAW_REQUEST_VERSION1    1
#endif

#ifndef DNS_QUERY_RAW_RESULTS_VERSION1
#define DNS_QUERY_RAW_RESULTS_VERSION1    1
#endif

#ifndef DNS_ADDR_MAX_SOCKADDR_LENGTH
#define DNS_ADDR_MAX_SOCKADDR_LENGTH      32
#endif

// DNS Protocol constants
#define DNS_PROTOCOL_UNSPECIFIED  0
#define DNS_PROTOCOL_UDP          1
#define DNS_PROTOCOL_TCP          2
#define DNS_PROTOCOL_DOH          3
#define DNS_PROTOCOL_DOT          4
#define DNS_PROTOCOL_NO_WIRE      5

typedef VOID (WINAPI *PDNS_QUERY_RAW_COMPLETION_ROUTINE)(
    PVOID                       pQueryContext,
    PVOID                       pQueryResults);  // Actually PDNS_QUERY_RAW_RESULT

typedef struct _DNS_QUERY_RAW_REQUEST {
    ULONG                               version;
    ULONG                               resultsVersion;
    ULONG                               dnsQueryRawSize;
    BYTE*                               dnsQueryRaw;
    PWSTR                               dnsQueryName;
    USHORT                              dnsQueryType;
    ULONG64                             queryOptions;
    ULONG                               interfaceIndex;
    PDNS_QUERY_RAW_COMPLETION_ROUTINE   queryCompletionCallback;
    PVOID                               queryContext;
    ULONG64                             queryRawOptions;
    ULONG                               customServersSize;
    PVOID                               customServers;  // DNS_CUSTOM_SERVER*
    ULONG                               protocol;
    CHAR                                maxSa[DNS_ADDR_MAX_SOCKADDR_LENGTH];
} DNS_QUERY_RAW_REQUEST, *PDNS_QUERY_RAW_REQUEST;

typedef struct _DNS_QUERY_RAW_RESULT {
    ULONG                   version;
    DNS_STATUS              queryStatus;
    ULONG64                 queryOptions;
    ULONG64                 queryRawOptions;
    ULONG64                 responseFlags;
    ULONG                   queryRawResponseSize;
    BYTE*                   queryRawResponse;
    PDNSAPI_DNS_RECORD      queryRecords;
    ULONG                   protocol;
    CHAR                    maxSa[DNS_ADDR_MAX_SOCKADDR_LENGTH];
} DNS_QUERY_RAW_RESULT, *PDNS_QUERY_RAW_RESULT;

typedef struct _DNS_QUERY_RAW_CANCEL {
    BYTE Reserved[32];
} DNS_QUERY_RAW_CANCEL, *PDNS_QUERY_RAW_CANCEL;

typedef DNS_STATUS (WINAPI *P_DnsQueryRaw)(
    PDNS_QUERY_RAW_REQUEST  pRequest,
    PDNS_QUERY_RAW_CANCEL   pCancelHandle);

typedef VOID (WINAPI *P_DnsQueryRawResultFree)(
    PDNS_QUERY_RAW_RESULT   pResult);

#endif // _DNSAPI_DEFS_H
