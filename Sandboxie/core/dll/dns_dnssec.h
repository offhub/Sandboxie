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

#ifndef _DNS_DNSSEC_H
#define _DNS_DNSSEC_H

#include <windows.h>
#include <windns.h>
#include "dns_wire.h"
#include "dns_rebind.h"

//---------------------------------------------------------------------------
// DNSSEC Support (DnssecEnabled Configuration)
//
// Per-domain/per-process control of DNSSEC behavior. Determines how DNS
// responses are handled when DNSSEC records (RRSIG) are present.
//
// Four modes:
//   y (ENABLED)  - Always query with EDNS+DO flag. If response contains RRSIG,
//                  pass through raw response and skip DnsRebindProtection.
//                  For domains that don't support DNSSEC (no RRSIG in response),
//                  fall through to normal synthetic response path.
//                  [+DNSSEC, *DnsRebindProtection (skip if RRSIG present)]
//
//   p (PERMISSIVE) - Always query with EDNS+DO flag, but always apply
//                    DnsRebindProtection even if RRSIG is present. Preserves
//                    DNSSEC records (like FILTER) while forcing DNSSEC queries.
//                    [+DNSSEC, +DnsRebindProtection (always)]
//
//   f (FILTER)   - (DEFAULT) Don't force EDNS+DO, but if the app requests it
//                  (DNS_QUERY_DNSSEC_OK flag), preserve it. When the app requests
//                  DNSSEC and RRSIG is present in the EncDns raw response, parse
//                  the raw response to preserve RRSIG/DNSSEC records. Always apply
//                  DnsRebindProtection including when RRSIG is present.
//                  For DnsQuery/DnsQueryEx APIs, preserves DNSSEC records from
//                  EncDns/system DNS while applying rebind protection.
//                  [*DNSSEC (if app requests), +DnsRebindProtection (always)]
//
//   n (DISABLED) - Never use EDNS+DO. Strip EDNS OPT from outgoing queries
//                  if the app adds it. Always apply DnsRebindProtection.
//                  Strip RRSIG/DNSSEC records from DNS responses.
//                  [-DNSSEC, +DnsRebindProtection (always)]
//
// Configuration formats (same scoring system as DnsRebindProtection):
//   DnssecEnabled=y|p|f|n                          # Global default
//   DnssecEnabled=<domain>:y|p|f|n                  # Per-domain
//   DnssecEnabled=<process>,y|p|f|n                 # Per-process
//   DnssecEnabled=<process>,<domain>:y|p|f|n        # Per-process + per-domain
//
// Scoring (most specific match wins):
//   - process pattern adds 1000000 + specificity(process)
//   - domain pattern adds 100000 + specificity(domain)
//   - specificity = (literal_chars * 16) - (wildcards * 64) + length
//   - On tie, later entry wins (last matching rule)
//
// Examples:
//   DnssecEnabled=y                               # Enable globally
//   DnssecEnabled=nslookup.exe,n                  # Disable for nslookup
//   DnssecEnabled=example.com:p                   # Force DNSSEC but keep filtering
//   DnssecEnabled=*.local:n                       # Disable for *.local
//   DnssecEnabled=cloudflare.com:y                # Enable for cloudflare.com
//---------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------------
// DNSSEC Mode Enum
//---------------------------------------------------------------------------

typedef enum _DNSSEC_MODE {
    DNSSEC_MODE_ENABLED  = 0,  // y mode - pass through raw encrypted DNS (RRSIG preserved, DNSSEC enabled)
    DNSSEC_MODE_FILTER   = 1,  // f mode - filter + keep EDNS with broken RRSIG (tampering evidence)
    DNSSEC_MODE_DISABLED = 2,  // n mode - filter + no EDNS advertised (DNSSEC disabled signal)
    DNSSEC_MODE_PERMISSIVE = 3 // p mode - force DNSSEC queries, keep filtering enabled
} DNSSEC_MODE;

// Map DNSSEC mode to config char for logging (y/p/f/n or '?')
WCHAR DNS_Dnssec_ModeToChar(DNSSEC_MODE mode);

//---------------------------------------------------------------------------
// Configuration API
//---------------------------------------------------------------------------

// Get DNSSEC mode for a domain (pattern-based lookup with scoring)
// Uses the same scoring system as DnsRebindProtection for consistency.
DNSSEC_MODE DNS_DnssecGetMode(const WCHAR* domain);

// Initialize DNSSEC patterns from configuration (called during DNS filter startup)
void DNS_Dnssec_InitPatterns(void);

//---------------------------------------------------------------------------
// DNS Wire Format DNSSEC Helpers
//---------------------------------------------------------------------------

// Check if a DNS wire-format response contains RRSIG records (TYPE=46)
// in any section (Answer, Authority, or Additional).
// Returns: TRUE if RRSIG records found, FALSE otherwise
BOOLEAN DNS_Dnssec_ResponseHasRrsig(const BYTE* data, int data_len);

// Modify the EDNS DO flag in a DNS query in-place.
// Finds the OPT record (TYPE=41) in the Additional section and sets
// or clears the DO flag (bit 15 of the EDNS flags field).
// Used by TCP passthrough to control DNSSEC behavior:
//   y mode: set_do=TRUE  (server returns RRSIG)
//   n mode: set_do=FALSE (server omits RRSIG)
// Returns: TRUE if OPT record was found and modified, FALSE if no EDNS present
BOOLEAN DNS_Dnssec_ModifyEdnsDOFlag(BYTE* query, int query_len, BOOLEAN set_do);

//---------------------------------------------------------------------------
// DNS_RECORD-Level DNSSEC Helpers (for DnsQuery/DnsQueryEx APIs)
//---------------------------------------------------------------------------

// Check if a DNS_RECORD linked list contains RRSIG records (wType=46)
// Returns: TRUE if RRSIG records found, FALSE otherwise
BOOLEAN DNS_Dnssec_RecordListHasRrsig(const void* pRecordList);

// Strip DNSSEC-related records (RRSIG=46, DNSKEY=48, DS=43, NSEC=47, NSEC3=50,
// NSEC3PARAM=51, CDNSKEY=60, CDS=59) from a DNS_RECORD linked list.
// Used in DISABLED mode to remove DNSSEC data from responses.
// Frees stripped records via DnsRecordListFree.
// pRecordList: pointer to PDNS_RECORD (modified in-place)
void DNS_Dnssec_StripDnssecRecords(void* pRecordList);

// Get the DnsQuery Options flag adjustment for DNSSEC mode.
// Returns DNS_QUERY_DNSSEC_OK (0x01000000) that should be OR'd into Options
// when mode is ENABLED or PERMISSIVE, or 0 otherwise.
// For DISABLED mode, returns a flag to strip (caller should AND with ~result).
// mode_out: 0 = no change, 1 = add DNSSEC_OK flag, -1 = strip DNSSEC_OK flag
void DNS_Dnssec_GetQueryFlags(DNSSEC_MODE mode, int* mode_out);

//---------------------------------------------------------------------------
// DNSSEC Composite Helpers (reduce code duplication in dns_filter.c)
//---------------------------------------------------------------------------

// Post-process a DNS_RECORD list with DNSSEC-aware rebind protection and stripping.
//   ENABLED mode  + RRSIG present: skip rebind, keep DNSSEC records
//   ENABLED mode  + no RRSIG:      apply rebind, keep DNSSEC records
//   PERMISSIVE mode:                apply rebind, keep DNSSEC records
//   FILTER mode:                    apply rebind, keep DNSSEC records
//   DISABLED mode:                  apply rebind, strip DNSSEC records
// Returns TRUE if rebind was skipped (ENABLED + RRSIG).
BOOLEAN DNS_Dnssec_PostProcessRecordList(
    const WCHAR* domain,
    PDNS_RECORD* ppRecords,
    DNSSEC_MODE mode);

// Adjust DnsQuery Options DWORD based on DNSSEC mode.
//   ENABLED:    add DNS_QUERY_DNSSEC_OK
//   PERMISSIVE: add DNS_QUERY_DNSSEC_OK
//   FILTER:     no change (preserve app's choice)
//   DISABLED:   remove DNS_QUERY_DNSSEC_OK
DWORD DNS_Dnssec_AdjustQueryOptions(DNSSEC_MODE mode, DWORD options);

// Same as above but for ULONG64 (DnsQueryEx uses 64-bit options).
ULONG64 DNS_Dnssec_AdjustQueryOptions64(DNSSEC_MODE mode, ULONG64 options);

#ifdef __cplusplus
}
#endif

#endif // _DNS_DNSSEC_H
