/*
 * Copyright 2024-2026 David Xanatos, xanasoft.com
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

#ifndef _DNS_REBIND_H
#define _DNS_REBIND_H

#include <windows.h>
#include <windns.h>
#include "common/my_wsa.h"
#include "wsa_defs.h"
#include "common/netfw.h"

//---------------------------------------------------------------------------
// DNS Log Suppression Tags (shared with dns_logging.c suppression cache)
//---------------------------------------------------------------------------

// FourCC-like tags for DNS_ShouldSuppressLogTagged(domain, tag)
// Use readable ASCII identifiers.
#define DNS_REBIND_LOG_TAG_DEFAULT 0x444E4252u /* 'RBND' */
#define DNS_REBIND_LOG_TAG_FILTER  0x50494252u /* 'RBIP' */
#define DNS_REBIND_LOG_TAG_WIRE    0x45524957u /* 'WIRE' */
#define DNS_EXCL_LOG_TAG           0x4C435845u /* 'EXCL' */
#define DNS_ENCDNS_LOG_TAG         0x534E4345u /* 'ECNS' - EncDns cache/pending/re-entrancy */

// Helper: append a WSA_DumpIP-formatted fragment (includes its own delimiter) to a caller buffer.
// Used to aggregate multiple filtered IPs into a single log line.
void DNS_Rebind_AppendFilteredIpMsg(
	WCHAR* msg,
	SIZE_T msg_cch,
	ADDRESS_FAMILY af,
	const IP_ADDRESS* pIP);

//---------------------------------------------------------------------------
// DNSSEC Support (moved to dns_dnssec.h)
//---------------------------------------------------------------------------

#include "dns_dnssec.h"

// ANSI version of addrinfo (not in wsa_defs.h). Keep local to core/dll code.
// Note: This intentionally avoids pulling in winsock2.h.
typedef struct addrinfo {
	int                 ai_flags;
	int                 ai_family;
	int                 ai_socktype;
	int                 ai_protocol;
	size_t              ai_addrlen;
	char*               ai_canonname;
	struct sockaddr*    ai_addr;
	struct addrinfo*    ai_next;
} ADDRINFOA, *PADDRINFOA;

//---------------------------------------------------------------------------
// DNS Rebind Protection
//
// Filters DNS responses that contain private/loopback IP addresses,
// preventing DNS rebinding attacks. Filtered A/AAAA answers are removed,
// leaving only valid/public addresses.
//
// Configuration (more specific overrides less specific):
//   - DnsRebindProtection=y|n
//   - DnsRebindProtection=<domain>:y|n
//   - DnsRebindProtection=<process>,y|n
//   - DnsRebindProtection=<process>,<domain>:y|n
//     * process is the optional first parameter and ends with ',' (default: all processes)
//     * domain is the optional second parameter and ends with ':' (default: all domains)
//     * action (y|n) is the last/only token; missing/invalid is treated as 'n'
//     * <domain> supports '*' and '?' wildcards (case-insensitive)
//     * Special token: @nodot@ matches single-label names (no dots, trailing dot ignored)
//     * Examples:
//         DnsRebindProtection=*.local:y
//         DnsRebindProtection=*.example.com:n
//         DnsRebindProtection=host123.example.com:y
//     * Requires valid certificate (DNS_HasValidCertificate)
//
// Filtered IP Rules:
//   - FilterDnsIP=[process,][domain:]ip_pattern[;y|n]
//     * action defaults to 'y' (filter)
//     * action delimiter is ';' (preferred)
//     * for backward compatibility, action also accepts ':y|n' and ',y|n'
//     * ip_pattern supports:
//         - IPv4/IPv6 with optional CIDR prefix (e.g. 10.0.0.0/8, fc00::/7)
//         - IPv4/IPv6 inclusive ranges using '-' (e.g. 10.0.0.10-10.0.0.99, 2001:db8::1-2001:db8::ffff)
//     * process and domain support '*' and '?' wildcards (case-insensitive)
//     * more specific rules override less specific rules
//     * defaults are provided by [TemplateDnsRebindProtection] in Templates.ini
//
// Notes:
//   - Default FilterDnsIP rules should be provided by Templates.ini.
//
// Priority/Integration:
//   NetworkDnsFilterExclude and NetworkDnsFilter rules take precedence.
//   Priority order (highest to lowest):
//     1. NetworkDnsFilterExclude - Excluded domains bypass all filtering
//     2. NetworkDnsFilter - Filtered/blocked domains use filter rules
//     3. DnsRebindProtection - Only applies to unfiltered domains
//   This ensures:
//     - Excluded domains use configured resolver (not rebind protected)
//     - Blocked domains stay blocked (NXDOMAIN)
//     - Filtered domains use configured IPs (not modified)
//     - Only unfiltered private IPs are removed from answers
//
// Default Filtered IP Ranges:
//   See Templates.ini [TemplateDnsRebindProtection] for the canonical list.
//---------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------------
// Public API
//---------------------------------------------------------------------------

// Initialize DNS rebind protection (called during DNS filter startup)
// Returns TRUE on success, FALSE on failure
BOOLEAN DNS_Rebind_Init(void);

// Check if a domain has rebind protection enabled
// Returns TRUE if protection is enabled for this domain, FALSE otherwise
BOOLEAN DNS_Rebind_IsEnabledForDomain(const WCHAR* domain);

// Convenience helper: TRUE if rebind protection is enabled for domain AND the IP is filtered.
// Useful for call sites that already have an IP_ADDRESS and want a single decision.
// af_hint: Use AF_INET/AF_INET6 when known, AF_UNSPEC to fall back to address heuristics.
BOOLEAN DNS_Rebind_ShouldFilterIpForDomain(const WCHAR* domain, const IP_ADDRESS* pIP, ADDRESS_FAMILY af_hint);

//---------------------------------------------------------------------------
// Passthrough sanitizers (system-DNS results)
//
// These helpers mutate returned DNS results in-place so that private/loopback
// addresses are filtered out when rebind protection is enabled.
//---------------------------------------------------------------------------

// Sanitizes a SOCKADDR_IN / SOCKADDR_IN6_LH in-place (no domain check).
// In filter-only mode this does not rewrite; call sites should remove entries.
void DNS_Rebind_SanitizeSockaddr(ADDRESS_FAMILY af, void* sockaddrPtr);

// Sanitizes an ADDRINFOW chain in-place (checks domain enablement).
// Removes filtered nodes and updates *ppResult.
void DNS_Rebind_SanitizeAddrInfoW(const WCHAR* domain, PADDRINFOW* ppResult);

// Sanitizes an ADDRINFOA chain in-place (checks domain enablement).
// Removes filtered nodes and updates *ppResult.
void DNS_Rebind_SanitizeAddrInfoA(const WCHAR* domain, PADDRINFOA* ppResult);

// Sanitizes a WSAQUERYSETW result blob in-place (checks domain enablement).
void DNS_Rebind_SanitizeWSAQuerySetW(const WCHAR* domain, LPWSAQUERYSETW lpqsResults);

// Sanitizes a DNS_RECORD linked list in-place (checks domain enablement).
// Removes filtered records and updates *ppRecords.
void DNS_Rebind_SanitizeDnsRecordList(const WCHAR* domain, PDNS_RECORD* ppRecords);

// In-place sanitizer for DNS wire-format responses (RFC 1035).
// Filters out A/AAAA answers when rebind protection is enabled.
// Supports DNS-over-TCP framing when isTcp=TRUE and the buffer contains a complete 2-byte length prefix.
// Returns TRUE if any record was filtered.
BOOLEAN DNS_Rebind_SanitizeDnsWireResponse(
	BYTE* data,
	int data_len,
	const WCHAR* domain,
	BOOLEAN isTcp,
	ULONG* pFilteredA,
	ULONG* pFilteredAAAA,
	int* pNewLen);

// Length-preserving sanitizer for DNS wire-format responses (RFC 1035).
// When a TCP length prefix was already delivered separately, this keeps the
// original message length while converting the response to NOERROR+NODATA:
//   - Sets Answer/Authority/Additional counts to 0
//   - Zeroes RR bytes after the question section
// Supports DNS-over-TCP framing when isTcp=TRUE and the buffer contains a complete 2-byte length prefix.
// Returns TRUE if any record was filtered.
BOOLEAN DNS_Rebind_SanitizeDnsWireResponseKeepLengthNodata(
	BYTE* data,
	int data_len,
	const WCHAR* domain,
	BOOLEAN isTcp,
	ULONG* pFilteredA,
	ULONG* pFilteredAAAA);

#ifdef __cplusplus
}
#endif

#endif // _DNS_REBIND_H
