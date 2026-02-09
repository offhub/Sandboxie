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

//---------------------------------------------------------------------------
// DNSSEC Configuration and Wire-Format Helpers
//
// This module provides:
//   1. DnssecEnabled configuration parsing and pattern-based mode lookup
//      (uses the same scoring system as DnsRebindProtection)
//   2. DNS wire-format helpers for DNSSEC:
//      - RRSIG detection in responses
//      - EDNS DO flag modification in queries
//---------------------------------------------------------------------------

#define NOGDI
#include "dll.h"
#include <windows.h>
#include <wchar.h>
#include <limits.h>
#include <windns.h>
#include "dns_dnssec.h"
#include "dns_wire.h"
#include "dns_logging.h"
#include "dns_rebind.h"
#include "common/list.h"

//---------------------------------------------------------------------------
// External Dependencies
//---------------------------------------------------------------------------

extern BOOLEAN DNS_TraceFlag;
extern BOOLEAN DNS_DebugFlag;
extern BOOLEAN DNS_HasValidCertificate;

#if !defined(_DNSDEBUG)
#undef DNS_DebugFlag
#define DNS_DebugFlag 0
#endif

extern BOOLEAN Config_MatchImage(const WCHAR* pat_str, ULONG pat_len, const WCHAR* test_str, ULONG depth);
extern const WCHAR* Dll_ImageName;

//---------------------------------------------------------------------------
// DNSSEC Pattern Structure
//---------------------------------------------------------------------------

typedef struct _DNSSEC_PATTERN {
    LIST_ELEM list_elem;
    WCHAR* process_pattern;  // NULL = match all processes
    WCHAR* domain_pattern;   // NULL = match all domains
    DNSSEC_MODE mode;
} DNSSEC_PATTERN;

// DNSSEC patterns list
static LIST DNS_DnssecPatterns;

//---------------------------------------------------------------------------
// Wildcard Matching (shared logic with DnsRebindProtection)
//---------------------------------------------------------------------------

// Forward declaration for single-label domain check
extern BOOLEAN DNS_IsSingleLabelDomain(const WCHAR* domain);

static BOOLEAN DNS_Dnssec_MatchWildcard(const WCHAR* pattern, const WCHAR* str)
{
    if (!pattern || !str) return FALSE;

    if (_wcsicmp(pattern, L"@nodot@") == 0) {
        return DNS_IsSingleLabelDomain(str);
    }
    while (*pattern) {
        if (*pattern == L'*') {
            pattern++;
            if (!*pattern) return TRUE;
            while (*str) {
                if (DNS_Dnssec_MatchWildcard(pattern, str)) return TRUE;
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
// Specificity Scoring (same algorithm as DnsRebindProtection)
//
// Prefer longer, more literal patterns. Penalize wildcards heavily so:
//   "exact.domain" outranks "*.domain" outranks "*".
// Ties are resolved by "last matching rule wins" in the caller.
//---------------------------------------------------------------------------

static int DNS_Dnssec_SpecificityScore(const WCHAR* pattern)
{
    if (!pattern || !pattern[0])
        return 0;

    int literal_count = 0;
    int wildcard_count = 0;
    for (const WCHAR* p = pattern; *p; ++p) {
        if (*p == L'*' || *p == L'?')
            wildcard_count++;
        else
            literal_count++;
    }

    return (literal_count * 16) - (wildcard_count * 64) + (int)wcslen(pattern);
}

//---------------------------------------------------------------------------
// DNS_DnssecGetMode
//
// Pattern-based DNSSEC mode lookup using the same scoring system as
// DnsRebindProtection for consistency:
//   - process pattern adds 1000000 + specificity(process)
//   - domain pattern adds 100000 + specificity(domain)
//   - global default (no process/domain) gets score 0
//   - ties resolved by last matching rule wins
//---------------------------------------------------------------------------

_FX DNSSEC_MODE DNS_DnssecGetMode(const WCHAR* domain)
{
    DNSSEC_MODE best_mode = DNSSEC_MODE_FILTER;  // Default: f mode (preserve app's EDNS choice, always apply rebind protection)
    long best_score = LONG_MIN;

    const WCHAR* process_name = Dll_ImageName;

    DNSSEC_PATTERN* pattern = (DNSSEC_PATTERN*)List_Head(&DNS_DnssecPatterns);
    while (pattern) {
        // Check process match
        BOOLEAN process_match = FALSE;
        if (!pattern->process_pattern) {
            process_match = TRUE;  // NULL = match all processes
        } else if (process_name) {
            // Support negation with '!' prefix (same as DnsRebindProtection)
            const WCHAR* pat = pattern->process_pattern;
            BOOLEAN inv = FALSE;
            if (*pat == L'!') {
                inv = TRUE;
                ++pat;
            }
            BOOLEAN match = Config_MatchImage(pat, 0, process_name, 1);
            if (inv)
                match = !match;
            process_match = match;
        }

        if (!process_match) {
            pattern = (DNSSEC_PATTERN*)List_Next(pattern);
            continue;
        }

        // Check domain match
        BOOLEAN domain_match = FALSE;
        if (!pattern->domain_pattern) {
            domain_match = TRUE;  // NULL = match all domains
        } else if (domain) {
            domain_match = DNS_Dnssec_MatchWildcard(pattern->domain_pattern, domain);
        }

        if (!domain_match) {
            pattern = (DNSSEC_PATTERN*)List_Next(pattern);
            continue;
        }

        // Both matched. Compute specificity score (same as DnsRebindProtection).
        long score = 0;
        if (pattern->process_pattern) {
            score += 1000000;
            score += DNS_Dnssec_SpecificityScore(pattern->process_pattern);
        }
        if (pattern->domain_pattern) {
            score += 100000;
            score += DNS_Dnssec_SpecificityScore(pattern->domain_pattern);
        }

        // On tie, prefer later entry (last matching rule wins).
        if (score >= best_score) {
            best_score = score;
            best_mode = pattern->mode;
        }

        pattern = (DNSSEC_PATTERN*)List_Next(pattern);
    }

    return best_mode;
}

//---------------------------------------------------------------------------
// DNS_Dnssec_ParseConfig
//---------------------------------------------------------------------------

static BOOLEAN DNS_Dnssec_ParseConfig(const WCHAR* str, WCHAR** out_process, WCHAR** out_domain, DNSSEC_MODE* out_mode)
{
    // Parse format: [process,][domain:]mode
    // mode = y|p|f|n
    if (!str || !*str)
        return FALSE;

    *out_process = NULL;
    *out_domain = NULL;
    *out_mode = DNSSEC_MODE_DISABLED;

    WCHAR* buf = Dll_Alloc((wcslen(str) + 1) * sizeof(WCHAR));
    wcscpy(buf, str);

    WCHAR* ptr = buf;
    WCHAR* comma = wcschr(ptr, L',');
    WCHAR* colon = wcschr(ptr, L':');

    // Determine structure
    if (comma && (!colon || comma < colon)) {
        // Has process pattern: "process,rest"
        *comma = L'\0';
        *out_process = Dll_Alloc((wcslen(ptr) + 1) * sizeof(WCHAR));
        wcscpy(*out_process, ptr);
        ptr = comma + 1;
        colon = wcschr(ptr, L':');
    }

    if (colon) {
        // Has domain pattern: "domain:mode"
        *colon = L'\0';
        *out_domain = Dll_Alloc((wcslen(ptr) + 1) * sizeof(WCHAR));
        wcscpy(*out_domain, ptr);
        ptr = colon + 1;
    }

    // Parse mode flag
    while (*ptr == L' ') ptr++;  // Skip whitespace
    if (*ptr == L'y' || *ptr == L'Y') {
        *out_mode = DNSSEC_MODE_ENABLED;
    } else if (*ptr == L'p' || *ptr == L'P') {
        *out_mode = DNSSEC_MODE_PERMISSIVE;
    } else if (*ptr == L'f' || *ptr == L'F') {
        *out_mode = DNSSEC_MODE_FILTER;
    } else if (*ptr == L'n' || *ptr == L'N') {
        *out_mode = DNSSEC_MODE_DISABLED;
    } else {
        if (*out_process) Dll_Free(*out_process);
        if (*out_domain) Dll_Free(*out_domain);
        Dll_Free(buf);
        return FALSE;
    }

    Dll_Free(buf);
    return TRUE;
}

//---------------------------------------------------------------------------
// DNS_Dnssec_ModeToChar
//---------------------------------------------------------------------------

_FX WCHAR DNS_Dnssec_ModeToChar(DNSSEC_MODE mode)
{
    switch (mode) {
        case DNSSEC_MODE_ENABLED:
            return L'y';
        case DNSSEC_MODE_PERMISSIVE:
            return L'p';
        case DNSSEC_MODE_FILTER:
            return L'f';
        case DNSSEC_MODE_DISABLED:
            return L'n';
        default:
            return L'?';
    }
}

//---------------------------------------------------------------------------
// DNS_Dnssec_InitPatterns
//---------------------------------------------------------------------------

_FX void DNS_Dnssec_InitPatterns(void)
{
    ULONG index = 0;
    ULONG count = 0;

    List_Init(&DNS_DnssecPatterns);

    // Check if certificate is valid (requirement for DNS security features)
    if (!DNS_HasValidCertificate) {
        DNS_DEBUG_LOG(L"[DNSSEC] Certificate required - disabled");
        return;
    }

    // Load all DnssecEnabled settings
    while (1) {
        WCHAR conf_buf[2048];
        NTSTATUS status = SbieApi_QueryConf(
            NULL, L"DnssecEnabled", index, conf_buf, sizeof(conf_buf) - 16 * sizeof(WCHAR));

        if (!NT_SUCCESS(status))
            break;

        index++;

        WCHAR* process_pattern = NULL;
        WCHAR* domain_pattern = NULL;
        DNSSEC_MODE mode = DNSSEC_MODE_DISABLED;

        if (!DNS_Dnssec_ParseConfig(conf_buf, &process_pattern, &domain_pattern, &mode)) {
            if (DNS_TraceFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"[DNSSEC] Parse error: %s", conf_buf);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            continue;
        }

        DNSSEC_PATTERN* pattern = Dll_Alloc(sizeof(DNSSEC_PATTERN));
        pattern->process_pattern = process_pattern;
        pattern->domain_pattern = domain_pattern;
        pattern->mode = mode;

        List_Insert_After(&DNS_DnssecPatterns, NULL, pattern);
        count++;

        if (DNS_TraceFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"[DNSSEC] Pattern: proc=%s domain=%s mode=%c",
                process_pattern ? process_pattern : L"*",
                domain_pattern ? domain_pattern : L"*",
                DNS_Dnssec_ModeToChar(mode));
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    }

    if (DNS_TraceFlag && count > 0) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DNSSEC] Loaded %d pattern(s)", count);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
}

//---------------------------------------------------------------------------
// DNS_Dnssec_ResponseHasRrsig
//
// Checks if a DNS wire response contains RRSIG records (TYPE=46)
// in any section (Answer, Authority, Additional).
//---------------------------------------------------------------------------

_FX BOOLEAN DNS_Dnssec_ResponseHasRrsig(const BYTE* data, int data_len)
{
    if (!data || data_len < (int)sizeof(DNS_WIRE_HEADER))
        return FALSE;

    DNS_WIRE_HEADER* header = (DNS_WIRE_HEADER*)data;
    USHORT question_count = _ntohs(header->Questions);
    USHORT answer_count = _ntohs(header->AnswerRRs);
    USHORT auth_count = _ntohs(header->AuthorityRRs);
    USHORT add_count = _ntohs(header->AdditionalRRs);

    int offset = sizeof(DNS_WIRE_HEADER);

    // Skip question section
    for (USHORT i = 0; i < question_count && offset < data_len; i++) {
        while (offset < data_len) {
            BYTE len = data[offset];
            offset++;

            if (len == 0)
                break;

            if ((len & 0xC0) == 0xC0) {
                offset++;
                break;
            }

            offset += len;
        }

        offset += 4;  // QTYPE + QCLASS
    }

    // Check ANSWER, AUTHORITY, and ADDITIONAL sections for RRSIG
    USHORT total_rrs = answer_count + auth_count + add_count;

    for (USHORT i = 0; i < total_rrs && offset < data_len - 10; i++) {
        // Skip name
        while (offset < data_len) {
            BYTE len = data[offset];
            offset++;

            if (len == 0)
                break;

            if ((len & 0xC0) == 0xC0) {
                offset++;
                break;
            }

            offset += len;
        }

        if (offset + 10 > data_len)
            return FALSE;

        USHORT rr_type = _ntohs(*(USHORT*)(data + offset));

        // DNS_TYPE_RRSIG = 46
        if (rr_type == 46)
            return TRUE;

        offset += 2;  // TYPE
        offset += 2;  // CLASS
        offset += 4;  // TTL

        USHORT rdlen = _ntohs(*(USHORT*)(data + offset));
        offset += 2;
        offset += rdlen;  // RDATA
    }

    return FALSE;
}

//---------------------------------------------------------------------------
// DNS_Dnssec_ModifyEdnsDOFlag
//
// Finds the EDNS OPT record in a DNS query and sets or clears the DO flag
// in-place. Used by TCP passthrough to control DNSSEC:
//   y mode: set_do=TRUE  -> server returns RRSIG
//   n mode: set_do=FALSE -> server omits RRSIG
//---------------------------------------------------------------------------

_FX BOOLEAN DNS_Dnssec_ModifyEdnsDOFlag(BYTE* query, int query_len, BOOLEAN set_do)
{
    if (!query || query_len < (int)sizeof(DNS_WIRE_HEADER))
        return FALSE;

    DNS_WIRE_HEADER* hdr = (DNS_WIRE_HEADER*)query;
    USHORT additional_count = _ntohs(hdr->AdditionalRRs);
    if (additional_count == 0)
        return FALSE;

    int offset = sizeof(DNS_WIRE_HEADER);
    USHORT questions = _ntohs(hdr->Questions);
    USHORT answers = _ntohs(hdr->AnswerRRs);
    USHORT authority = _ntohs(hdr->AuthorityRRs);

    // Skip questions section
    for (USHORT i = 0; i < questions && offset < query_len; i++) {
        while (offset < query_len) {
            BYTE label_len = query[offset];
            if (label_len == 0) { offset++; break; }
            if ((label_len & 0xC0) == 0xC0) { offset += 2; break; }
            offset += 1 + label_len;
        }
        offset += 4;  // QTYPE + QCLASS
    }

    // Skip answer and authority sections
    for (USHORT i = 0; i < (answers + authority) && offset < query_len; i++) {
        while (offset < query_len) {
            BYTE label_len = query[offset];
            if (label_len == 0) { offset++; break; }
            if ((label_len & 0xC0) == 0xC0) { offset += 2; break; }
            offset += 1 + label_len;
        }
        if (offset + 10 > query_len) return FALSE;
        USHORT rdlength = _ntohs(*(USHORT*)(query + offset + 8));
        offset += 10 + rdlength;
    }

    // Scan additional section for OPT record (TYPE=41)
    for (USHORT i = 0; i < additional_count && offset < query_len; i++) {
        int record_start = offset;

        // Check for root label (single 0 byte) + TYPE=41
        if (offset + 3 <= query_len && query[offset] == 0) {
            USHORT type = _ntohs(*(USHORT*)(query + offset + 1));
            if (type == DNS_TYPE_OPT) {
                // OPT record layout after root label(1) + TYPE(2):
                //   [+0..+1] UDP payload size
                //   [+2]     Extended RCODE
                //   [+3]     Version
                //   [+4..+5] Flags (DO flag at bit 15)
                //   [+6..+7] RDLEN
                int flags_offset = offset + 1 + 2 + 2 + 2;  // root + TYPE + UDP_size + ExtRCODE+Version
                if (flags_offset + 2 > query_len) return FALSE;

                USHORT flags = (query[flags_offset] << 8) | query[flags_offset + 1];
                if (set_do)
                    flags |= DNS_EDNS_FLAG_DO;
                else
                    flags &= ~DNS_EDNS_FLAG_DO;
                query[flags_offset] = (BYTE)(flags >> 8);
                query[flags_offset + 1] = (BYTE)(flags & 0xFF);
                return TRUE;
            }
        }

        // Not OPT record - skip it
        offset = record_start;
        while (offset < query_len) {
            BYTE label_len = query[offset];
            if (label_len == 0) { offset++; break; }
            if ((label_len & 0xC0) == 0xC0) { offset += 2; break; }
            offset += 1 + label_len;
        }
        if (offset + 10 > query_len) return FALSE;
        USHORT rdlength = _ntohs(*(USHORT*)(query + offset + 8));
        offset += 10 + rdlength;
    }

    return FALSE;  // No OPT record found
}

//---------------------------------------------------------------------------
// DNS_RECORD-Level DNSSEC Helpers
//
// These functions operate on DNS_RECORD linked lists (used by DnsQuery_W/A/UTF8
// and DnsQueryEx APIs) rather than wire-format packets.
//---------------------------------------------------------------------------

// DNSSEC-related DNS record types (most are already defined in windns.h from Windows SDK)
// DNS_TYPE_RRSIG      46  (defined in SDK)
// DNS_TYPE_DNSKEY     48  (defined in SDK)
// DNS_TYPE_DS         43  (defined in SDK)
// DNS_TYPE_NSEC       47  (defined in SDK)
// DNS_TYPE_NSEC3      50  (defined in SDK)
// DNS_TYPE_NSEC3PARAM 51  (defined in SDK)

// Newer DNSSEC types (RFC 7344) - not in all SDK versions, define locally
#ifndef DNS_TYPE_CDNSKEY
#define DNS_TYPE_CDNSKEY    60
#endif
#ifndef DNS_TYPE_CDS
#define DNS_TYPE_CDS        59
#endif

static BOOLEAN DNS_Dnssec_IsDnssecType(USHORT wType)
{
    switch (wType) {
        case DNS_TYPE_RRSIG:
        case DNS_TYPE_DNSKEY:
        case DNS_TYPE_DS:
        case DNS_TYPE_NSEC:
        case DNS_TYPE_NSEC3:
        case DNS_TYPE_NSEC3PARAM:
        case DNS_TYPE_CDNSKEY:
        case DNS_TYPE_CDS:
            return TRUE;
        default:
            return FALSE;
    }
}

//---------------------------------------------------------------------------
// DNS_Dnssec_RecordListHasRrsig
//
// Check if a DNS_RECORD linked list contains RRSIG records.
// Works with both PDNS_RECORD and PDNSAPI_DNS_RECORD (same layout).
//---------------------------------------------------------------------------

_FX BOOLEAN DNS_Dnssec_RecordListHasRrsig(const void* pRecordList)
{
    const DNS_RECORD* pRecord = (const DNS_RECORD*)pRecordList;
    while (pRecord) {
        if (pRecord->wType == DNS_TYPE_RRSIG) {
            return TRUE;
        }
        pRecord = pRecord->pNext;
    }
    return FALSE;
}

//---------------------------------------------------------------------------
// DNS_Dnssec_StripDnssecRecords
//
// Remove DNSSEC-related records from a DNS_RECORD linked list in-place.
// Used in DISABLED mode to strip RRSIG, DNSKEY, DS, NSEC, etc.
// 
// Note: We don't free individual records because DnsRecordListFree
// expects contiguous allocation. Instead we unlink them from the list.
// The caller is responsible for freeing the entire list later.
//---------------------------------------------------------------------------

_FX void DNS_Dnssec_StripDnssecRecords(void* ppRecordList)
{
    if (!ppRecordList) return;
    
    PDNS_RECORD* ppHead = (PDNS_RECORD*)ppRecordList;
    PDNS_RECORD pRecord = *ppHead;
    PDNS_RECORD pPrev = NULL;
    ULONG stripped = 0;
    
    while (pRecord) {
        PDNS_RECORD pNext = pRecord->pNext;
        
        if (DNS_Dnssec_IsDnssecType(pRecord->wType)) {
            // Unlink this record from the list
            if (pPrev) {
                pPrev->pNext = pNext;
            } else {
                *ppHead = pNext;
            }
            // Don't update pPrev - it stays the same
            stripped++;
        } else {
            pPrev = pRecord;
        }
        
        pRecord = pNext;
    }
    
    if (stripped > 0 && DNS_TraceFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DNSSEC] Stripped %lu DNSSEC records (DnssecEnabled=n)", stripped);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
}

//---------------------------------------------------------------------------
// DNS_Dnssec_GetQueryFlags
//
// Determine how to adjust DnsQuery Options flags based on DNSSEC mode:
//   y (ENABLED):    mode_out = 1  -> caller should add DNS_QUERY_DNSSEC_OK
//   p (PERMISSIVE): mode_out = 1  -> caller should add DNS_QUERY_DNSSEC_OK
//   f (FILTER):     mode_out = 0  -> no change (preserve app's choice)
//   n (DISABLED):   mode_out = -1 -> caller should strip DNS_QUERY_DNSSEC_OK
//---------------------------------------------------------------------------

_FX void DNS_Dnssec_GetQueryFlags(DNSSEC_MODE mode, int* mode_out)
{
    if (!mode_out) return;
    
    switch (mode) {
        case DNSSEC_MODE_ENABLED:
            *mode_out = 1;   // Force DNSSEC
            break;
        case DNSSEC_MODE_PERMISSIVE:
            *mode_out = 1;   // Force DNSSEC
            break;
        case DNSSEC_MODE_FILTER:
            *mode_out = 0;   // Preserve app's choice
            break;
        case DNSSEC_MODE_DISABLED:
            *mode_out = -1;  // Strip DNSSEC
            break;
        default:
            *mode_out = 0;
            break;
    }
}

//---------------------------------------------------------------------------
// DNS_Dnssec_PostProcessRecordList
//
// Combined DNSSEC-aware rebind protection + DISABLED-mode strip.
// Eliminates repeated if-ENABLED-skip-rebind / if-DISABLED-strip blocks
// scattered across dns_filter.c.
//
// Returns TRUE if rebind was skipped (ENABLED mode with RRSIG present).
//---------------------------------------------------------------------------

_FX BOOLEAN DNS_Dnssec_PostProcessRecordList(
    const WCHAR* domain,
    PDNS_RECORD* ppRecords,
    DNSSEC_MODE mode)
{
    if (!ppRecords || !*ppRecords)
        return FALSE;

    BOOLEAN skip_rebind = FALSE;
    if (mode == DNSSEC_MODE_ENABLED) {
        skip_rebind = DNS_Dnssec_RecordListHasRrsig(*ppRecords);
    }
    if (!skip_rebind) {
        DNS_Rebind_SanitizeDnsRecordList(domain, ppRecords);
    }
    if (mode == DNSSEC_MODE_DISABLED) {
        DNS_Dnssec_StripDnssecRecords(ppRecords);
    }
    return skip_rebind;
}

//---------------------------------------------------------------------------
// DNS_Dnssec_AdjustQueryOptions / AdjustQueryOptions64
//
// Apply DNSSEC mode to DnsQuery Options flags in one call.
// Replaces the repeated GetQueryFlags + if/else flag adjustment pattern.
//---------------------------------------------------------------------------

_FX DWORD DNS_Dnssec_AdjustQueryOptions(DNSSEC_MODE mode, DWORD options)
{
    int flag = 0;
    DNS_Dnssec_GetQueryFlags(mode, &flag);
    if (flag > 0)
        options |= DNS_QUERY_DNSSEC_OK;
    else if (flag < 0)
        options &= ~DNS_QUERY_DNSSEC_OK;
    return options;
}

_FX ULONG64 DNS_Dnssec_AdjustQueryOptions64(DNSSEC_MODE mode, ULONG64 options)
{
    int flag = 0;
    DNS_Dnssec_GetQueryFlags(mode, &flag);
    if (flag > 0)
        options |= DNS_QUERY_DNSSEC_OK;
    else if (flag < 0)
        options &= ~(ULONG64)DNS_QUERY_DNSSEC_OK;
    return options;
}
