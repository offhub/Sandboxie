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
// DNS Wire Format Definitions (RFC 1035)
//
// Shared header for DNS wire format structures used by:
//   - socket_hooks.c (raw socket DNS interception)
//   - dns_doh.c (DNS-over-HTTPS client)
//
// All structures use network byte order (big-endian) as per RFC 1035.
// Use _ntohs()/_htons() for 16-bit fields and _ntohl()/_htonl() for 32-bit.
//---------------------------------------------------------------------------

#ifndef _DNS_WIRE_H
#define _DNS_WIRE_H

#include <windows.h>
#include "common/my_wsa.h"

//---------------------------------------------------------------------------
// Byte Order Conversion
//
// Use _ntohl(), _ntohs(), _htonl(), _htons() inline functions from
// common/my_wsa.h.
//---------------------------------------------------------------------------
// DNS Message Header (RFC 1035 Section 4.1.1)
//
// The header is 12 bytes and contains:
//   - Transaction ID (16 bits): Used to match responses to queries
//   - Flags (16 bits): QR, Opcode, AA, TC, RD, RA, Z, RCODE
//   - Question Count (16 bits): Number of entries in question section
//   - Answer Count (16 bits): Number of RRs in answer section
//   - Authority Count (16 bits): Number of RRs in authority section
//   - Additional Count (16 bits): Number of RRs in additional section
//---------------------------------------------------------------------------

#pragma pack(push, 1)
typedef struct _DNS_WIRE_HEADER {
    USHORT TransactionID;   // Query/response transaction ID
    USHORT Flags;           // DNS header flags (see DNS_FLAG_* constants)
    USHORT Questions;       // Number of questions
    USHORT AnswerRRs;       // Number of answer resource records
    USHORT AuthorityRRs;    // Number of authority resource records
    USHORT AdditionalRRs;   // Number of additional resource records
} DNS_WIRE_HEADER, *PDNS_WIRE_HEADER;
#pragma pack(pop)

//---------------------------------------------------------------------------
// DNS_FlipHeaderToHost - Convert DNS header counts from network to host order
//
// DnsExtractRecordsFromMessage_W expects DNS messages in HOST byte order,
// but DoQ/DoH responses are in NETWORK byte order (big-endian).
// This function flips the 16-bit count fields to host order.
// 
// Note: Modifies the buffer in-place. Flags are NOT flipped because they
// are defined as individual bytes in Windows SDK (same as RFC 1035).
//---------------------------------------------------------------------------

static __inline void DNS_FlipHeaderToHost(BYTE* pBuffer, DWORD bufferLen)
{
    if (pBuffer && bufferLen >= sizeof(DNS_WIRE_HEADER)) {
        PDNS_WIRE_HEADER hdr = (PDNS_WIRE_HEADER)pBuffer;
        hdr->TransactionID = _ntohs(hdr->TransactionID);
        hdr->Questions = _ntohs(hdr->Questions);
        hdr->AnswerRRs = _ntohs(hdr->AnswerRRs);
        hdr->AuthorityRRs = _ntohs(hdr->AuthorityRRs);
        hdr->AdditionalRRs = _ntohs(hdr->AdditionalRRs);
        // Flags are NOT flipped - Windows SDK defines flags as individual bytes
    }
}

//---------------------------------------------------------------------------
// DNS Header Flags (RFC 1035 Section 4.1.1)
//
// Bit layout (network byte order):
//   0     - QR (Query/Response): 0=Query, 1=Response
//   1-4   - Opcode: 0=QUERY, 1=IQUERY, 2=STATUS
//   5     - AA (Authoritative Answer)
//   6     - TC (Truncation)
//   7     - RD (Recursion Desired)
//   8     - RA (Recursion Available)
//   9-11  - Z (Reserved, must be zero)
//   12-15 - RCODE (Response Code)
//---------------------------------------------------------------------------

// Query/Response flag
#define DNS_FLAG_QR_QUERY       0x0000  // This is a query
#define DNS_FLAG_QR_RESPONSE    0x8000  // This is a response

// Opcode (4 bits, shifted to position 11-14)
#define DNS_FLAG_OPCODE_MASK    0x7800
#define DNS_FLAG_OPCODE_QUERY   0x0000  // Standard query
#define DNS_FLAG_OPCODE_IQUERY  0x0800  // Inverse query (obsolete)
#define DNS_FLAG_OPCODE_STATUS  0x1000  // Server status request

// Other flags
#define DNS_FLAG_AA             0x0400  // Authoritative Answer
#define DNS_FLAG_TC             0x0200  // Truncation
#define DNS_FLAG_RD             0x0100  // Recursion Desired
#define DNS_FLAG_RA             0x0080  // Recursion Available
#define DNS_FLAG_Z_MASK         0x0070  // Reserved (must be zero)

// Response Code (RCODE, 4 bits)
#define DNS_FLAG_RCODE_MASK     0x000F
#define DNS_RCODE_NOERROR       0       // No error
#define DNS_RCODE_FORMERR       1       // Format error
#define DNS_RCODE_SERVFAIL      2       // Server failure
#define DNS_RCODE_NXDOMAIN      3       // Non-existent domain
#define DNS_RCODE_NOTIMP        4       // Not implemented
#define DNS_RCODE_REFUSED       5       // Query refused

//---------------------------------------------------------------------------
// DNS Question Section (RFC 1035 Section 4.1.2)
//
// Question format (after variable-length QNAME):
//   QTYPE  (16 bits): Query type (A, AAAA, MX, etc.)
//   QCLASS (16 bits): Query class (usually IN = 1)
//
// Note: Windows SDK WinDNS.h also defines DNS_WIRE_QUESTION with different
// field names (QuestionType/QuestionClass vs qtype/qclass). We use our own
// SBIE_DNS_WIRE_QUESTION to avoid conflicts.
//---------------------------------------------------------------------------

#pragma pack(push, 1)
typedef struct _SBIE_DNS_WIRE_QUESTION {
    USHORT qtype;   // Query type (DNS_TYPE_A, DNS_TYPE_AAAA, etc.)
    USHORT qclass;  // Query class (DNS_CLASS_IN)
} SBIE_DNS_WIRE_QUESTION, *PSBIE_DNS_WIRE_QUESTION;
#pragma pack(pop)

//---------------------------------------------------------------------------
// DNS Resource Record (RFC 1035 Section 4.1.3)
//
// RR format (after variable-length NAME or compression pointer):
//   TYPE     (16 bits): RR type
//   CLASS    (16 bits): RR class
//   TTL      (32 bits): Time to live in seconds
//   RDLENGTH (16 bits): Length of RDATA
//   RDATA    (variable): Resource record data
//---------------------------------------------------------------------------

#pragma pack(push, 1)
typedef struct _DNS_WIRE_RR {
    USHORT type;        // RR type
    USHORT rr_class;    // RR class
    DWORD  ttl;         // Time to live (seconds)
    USHORT rdlength;    // Length of RDATA that follows
    // RDATA follows (variable length based on rdlength)
} DNS_WIRE_RR, *PDNS_WIRE_RR;
#pragma pack(pop)

// Size of DNS_WIRE_RR structure (for pointer arithmetic)
// Note: RDATA is NOT included in this constant
#define DNS_WIRE_RR_HEADER_SIZE  10

//---------------------------------------------------------------------------
// EDNS OPT Pseudo-Record (RFC 6891 Section 6)
//
// The OPT pseudo-RR uses TYPE=41 and has special field meanings:
//   NAME      (variable): Root label (single 0 byte) - always present
//   TYPE      (16 bits):  41 (OPT)
//   UDP_SIZE  (16 bits):  Advertised UDP payload size (in CLASS field position)
//   EXTENDED_RCODE (8 bits): High bits of RCODE (in TTL field high byte)
//   VERSION   (8 bits):   EDNS version (in TTL field, should be 0)
//   FLAGS     (16 bits):  EDNS flags (in TTL field low 2 bytes)
//   RDLENGTH  (16 bits):  Length of RDATA (options)
//   RDATA     (variable): EDNS options
//
// Flags (in network byte order in TTL field):
//   Bit 15 (0x8000): DO bit - DNSSEC OK
//   Bits 14-0: Reserved (must be zero)
//---------------------------------------------------------------------------

#pragma pack(push, 1)
typedef struct _DNS_OPT_RECORD {
    BYTE   root_label;      // Root domain label (always 0x00)
    USHORT type;            // Type = 41 (OPT)
    USHORT udp_payload;     // UDP payload size (in network byte order)
    DWORD  extended_flags;  // Extended RCODE (8 bits) + Version (8 bits) + Flags (16 bits)
    USHORT rdlength;        // Length of options data that follows
} DNS_OPT_RECORD, *PDNS_OPT_RECORD;
#pragma pack(pop)

// Size of OPT record header (without options data)
#define DNS_OPT_RECORD_HEADER_SIZE  11

// EDNS flags (stored in network byte order in the low 16 bits of extended_flags)
#define DNS_EDNS_FLAG_DO            0x8000  // DNSSEC OK flag

//---------------------------------------------------------------------------
// DNS Query/Record Types (RFC 1035, RFC 3596, RFC 9460)
//
// Note: These are also defined in windns.h as DNS_TYPE_*.
// We define them here for use in raw packet handling where
// windns.h might not be included.
//---------------------------------------------------------------------------

#ifndef DNS_TYPE_A
#define DNS_TYPE_A          1       // IPv4 address
#endif

#ifndef DNS_TYPE_NS
#define DNS_TYPE_NS         2       // Nameserver
#endif

#ifndef DNS_TYPE_CNAME
#define DNS_TYPE_CNAME      5       // Canonical name
#endif

#ifndef DNS_TYPE_SOA
#define DNS_TYPE_SOA        6       // Start of Authority
#endif

#ifndef DNS_TYPE_PTR
#define DNS_TYPE_PTR        12      // Pointer (reverse lookup)
#endif

#ifndef DNS_TYPE_MX
#define DNS_TYPE_MX         15      // Mail exchanger
#endif

#ifndef DNS_TYPE_TEXT
#define DNS_TYPE_TEXT       16      // Text record
#endif

#ifndef DNS_TYPE_AAAA
#define DNS_TYPE_AAAA       28      // IPv6 address (RFC 3596)
#endif

#ifndef DNS_TYPE_SRV
#define DNS_TYPE_SRV        33      // Service locator
#endif

#ifndef DNS_TYPE_SVCB
#define DNS_TYPE_SVCB       64      // Service Binding (RFC 9460)
#endif

#ifndef DNS_TYPE_HTTPS
#define DNS_TYPE_HTTPS      65      // HTTPS Binding (RFC 9460)
#endif

#ifndef DNS_TYPE_ANY
#define DNS_TYPE_ANY        255     // Request all record types
#endif

#ifndef DNS_TYPE_OPT
#define DNS_TYPE_OPT        41      // EDNS pseudo-RR (RFC 6891)
#endif

//---------------------------------------------------------------------------
// DNS Query Classes (RFC 1035 Section 3.2.4)
//---------------------------------------------------------------------------

#ifndef DNS_CLASS_IN
#define DNS_CLASS_IN        1       // Internet class
#endif

#ifndef DNS_CLASS_ANY
#define DNS_CLASS_ANY       255     // Any class
#endif

//---------------------------------------------------------------------------
// DNS Response Size Limits
//---------------------------------------------------------------------------

// Traditional DNS response limit (RFC 1035)
#define DNS_MAX_UDP_PAYLOAD     512

// EDNS0 maximum (RFC 6891)
// Practical limit for DoH and modern DNS
#define DNS_MAX_EDNS0_PAYLOAD   4096

// Our buffer size for DNS responses
#define DNS_RESPONSE_BUFFER_SIZE DNS_MAX_EDNS0_PAYLOAD

//---------------------------------------------------------------------------
// DNS Name Compression (RFC 1035 Section 4.1.4)
//
// Names can be compressed using pointers. A pointer is identified by
// the first two bits being set (11xxxxxx), followed by a 14-bit offset.
//---------------------------------------------------------------------------

#define DNS_COMPRESSION_MASK    0xC0    // First byte of pointer (11xxxxxx)
#define DNS_COMPRESSION_OFFSET  0x3FFF  // 14-bit offset mask

// Check if a label byte is a compression pointer
#define DNS_IS_COMPRESSION_PTR(byte)  (((byte) & DNS_COMPRESSION_MASK) == DNS_COMPRESSION_MASK)

// Get offset from compression pointer (2 bytes)
#define DNS_GET_COMPRESSION_OFFSET(ptr) \
    ((((USHORT)(ptr)[0] & 0x3F) << 8) | (USHORT)(ptr)[1])

//---------------------------------------------------------------------------
// Common Response Flag Combinations
//---------------------------------------------------------------------------

// Standard response with no error
#define DNS_RESPONSE_NOERROR    (_htons(DNS_FLAG_QR_RESPONSE | DNS_FLAG_AA | DNS_FLAG_RA))

// Standard response with NXDOMAIN (domain doesn't exist)
#define DNS_RESPONSE_NXDOMAIN   (_htons(DNS_FLAG_QR_RESPONSE | DNS_FLAG_AA | DNS_FLAG_RA | DNS_RCODE_NXDOMAIN))

// Server failure response
#define DNS_RESPONSE_SERVFAIL   (_htons(DNS_FLAG_QR_RESPONSE | DNS_FLAG_RA | DNS_RCODE_SERVFAIL))

// Refused response
#define DNS_RESPONSE_REFUSED    (_htons(DNS_FLAG_QR_RESPONSE | DNS_FLAG_RA | DNS_RCODE_REFUSED))

//---------------------------------------------------------------------------
// Helper Macros for DNS Packet Processing
//---------------------------------------------------------------------------

// Get RCODE from flags (after converting from network byte order)
#define DNS_GET_RCODE(flags)    ((flags) & DNS_FLAG_RCODE_MASK)

// Check if packet is a response
#define DNS_IS_RESPONSE(flags)  (((flags) & DNS_FLAG_QR_RESPONSE) != 0)

// Check if packet is a query
#define DNS_IS_QUERY(flags)     (((flags) & DNS_FLAG_QR_RESPONSE) == 0)

#endif // _DNS_WIRE_H
