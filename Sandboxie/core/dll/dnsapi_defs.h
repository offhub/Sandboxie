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
//---------------------------------------------------------------------------

#ifndef DNS_QUERY_STANDARD
#define DNS_QUERY_STANDARD          0x00000000
#endif

#ifndef DNS_QUERY_BYPASS_CACHE
#define DNS_QUERY_BYPASS_CACHE      0x00000008
#endif

//---------------------------------------------------------------------------
// DNS Error Codes
//---------------------------------------------------------------------------

#ifndef DNS_ERROR_RCODE_NAME_ERROR
#define DNS_ERROR_RCODE_NAME_ERROR  9003  // Name does not exist
#endif

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
//---------------------------------------------------------------------------

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
    } Data;
};

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
    ULONG64                         QueryOptions;
    PVOID                           pDnsServerList;
    ULONG                           InterfaceIndex;
    PDNS_QUERY_COMPLETION_ROUTINE   pQueryCompletionCallback;
    PVOID                           pQueryContext;
} DNS_QUERY_REQUEST_W, *PDNS_QUERY_REQUEST_W;

typedef struct _DNS_QUERY_REQUEST_A {
    ULONG                           Version;
    PSTR                            QueryName;
    WORD                            QueryType;
    ULONG64                         QueryOptions;
    PVOID                           pDnsServerList;
    ULONG                           InterfaceIndex;
    PDNS_QUERY_COMPLETION_ROUTINE   pQueryCompletionCallback;
    PVOID                           pQueryContext;
} DNS_QUERY_REQUEST_A, *PDNS_QUERY_REQUEST_A;

typedef struct _DNS_QUERY_REQUEST_UTF8 {
    ULONG                           Version;
    PSTR                            QueryName;
    WORD                            QueryType;
    ULONG64                         QueryOptions;
    PVOID                           pDnsServerList;
    ULONG                           InterfaceIndex;
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

#endif // _DNSAPI_DEFS_H
