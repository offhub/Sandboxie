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
// WinHTTP Connection Filter Implementation
//
// This module intercepts WinHTTP API calls to filter HTTP/HTTPS connections
// based on NetworkDnsFilter rules.
//
// Hook Strategy:
//   - Hook WinHttpConnect() to validate server names against DNS filter rules
//   - Block mode: Returns NULL with ERROR_HOST_UNREACHABLE
//   - Filter mode: Allows connection (DNS hooks redirect via GetAddrInfoW)
//
// Configuration:
//   FilterWinHttp=[process,]y|n (default: n)
//     - Enable/disable WinHTTP filtering per-process
//     - Example: FilterWinHttp=updutil.exe,y
//
// Integration:
//   - Uses DNS_CheckFilter() and DNS_IsExcluded() from dns_filter.c
//   - Uses encrypted DNS server exclusion from dns_encrypted.c
//   - Tracing via DNS_TraceFlag (DnsTrace=y)
//---------------------------------------------------------------------------

#define NOGDI
#include "dll.h"

#include <windows.h>
#include <winhttp.h>
#include <wchar.h>
#include "winhttp_filter.h"
#include "winhttp_defs.h"
#include "dns_filter.h"
#include "dns_logging.h"
#include "dns_encrypted.h"
#include "common/pattern.h"

//---------------------------------------------------------------------------
// Configuration
//---------------------------------------------------------------------------

// WinHTTP hook enabled state (from FilterWinHttp setting)
static BOOLEAN WinHttp_FilterEnabled = FALSE;

// Original function pointer
static P_WinHttpConnect __sys_WinHttpConnect = NULL;

//---------------------------------------------------------------------------
// External Dependencies
//---------------------------------------------------------------------------

// From dns_filter.c
extern LIST DNS_FilterList;
extern BOOLEAN DNS_FilterEnabled;
extern BOOLEAN DNS_HasValidCertificate;
extern BOOLEAN DNS_TraceFlag;
extern BOOLEAN DNS_DebugFlag;

#if !defined(_DNSDEBUG)
// Release builds: compile out debug-only logging paths.
#undef DNS_DebugFlag
#define DNS_DebugFlag 0
#endif

// From dns_filter.c
extern void DNS_ExtractFilterAux(PVOID* aux, LIST** pEntries, DNS_TYPE_FILTER** type_filter);

// From dll.c
extern void* Dll_AllocTemp(ULONG size);
extern void Dll_Free(void* ptr);

// From config.c
extern BOOLEAN Config_GetSettingsForImageName_bool(const WCHAR* setting, BOOLEAN default_value);

//---------------------------------------------------------------------------
// Forward Declarations
//---------------------------------------------------------------------------

static HINTERNET WINAPI WinHttp_WinHttpConnect(
    HINTERNET hSession,
    LPCWSTR pswzServerName,
    INTERNET_PORT nServerPort,
    DWORD dwReserved);

//---------------------------------------------------------------------------
// WinHttp_Init
//
// Initializes WinHTTP hooks (called when winhttp.dll is loaded)
// Hooks WinHttpConnect() to validate domains against NetworkDnsFilter rules
//---------------------------------------------------------------------------

_FX BOOLEAN WinHttp_Init(HMODULE module)
{
    // Check FilterWinHttp setting (default: disabled)
    BOOLEAN winHttpEnabled = Config_GetSettingsForImageName_bool(L"FilterWinHttp", FALSE);
    
    if (!winHttpEnabled) {
        // FilterWinHttp disabled - skip WinHTTP hooking entirely
        return TRUE;
    }

    // Only hook if filter rules exist
    if (!DNS_FilterEnabled) {
        return TRUE;
    }

    // Enable the WinHTTP filter for this process
    WinHttp_FilterEnabled = TRUE;

    //
    // Setup WinHttpConnect hook
    //

    P_WinHttpConnect WinHttpConnect = (P_WinHttpConnect)GetProcAddress(module, "WinHttpConnect");
    if (!WinHttpConnect) {
        // Function not found in module - log and skip
        SbieApi_Log(2205, L"WinHttpConnect not found in winhttp.dll");
        return TRUE;
    }
    
    SBIEDLL_HOOK(WinHttp_, WinHttpConnect);

    return TRUE;
}

//---------------------------------------------------------------------------
// WinHttp_WinHttpConnect
//
// Hook for WinHttpConnect() from winhttp.dll
// Validates server name against NetworkDnsFilter rules
// Returns NULL (connection failed) if domain is blocked, otherwise calls original
//---------------------------------------------------------------------------

static HINTERNET WINAPI WinHttp_WinHttpConnect(
    HINTERNET hSession,
    LPCWSTR pswzServerName,
    INTERNET_PORT nServerPort,
    DWORD dwReserved)
{
    // Quick path: if WinHTTP hook is disabled or no filter rules, use original
    if (!WinHttp_FilterEnabled || !DNS_FilterEnabled) {
        return __sys_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
    }

    // Validate domain against NetworkDnsFilter rules
    if (pswzServerName && wcslen(pswzServerName) > 0) {
        size_t domain_len = wcslen(pswzServerName);
        WCHAR* domain_lwr = (WCHAR*)Dll_AllocTemp((domain_len + 4) * sizeof(WCHAR));
        if (domain_lwr) {
            wmemcpy(domain_lwr, pswzServerName, domain_len);
            domain_lwr[domain_len] = L'\0';
            _wcslwr(domain_lwr);
            
            // Check exclusion first
            if (DNS_IsExcluded(domain_lwr)) {
                DNS_LogExclusion(domain_lwr);
                Dll_Free(domain_lwr);
                return __sys_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
            }
            
            // Exclude encrypted DNS server hostnames to prevent re-entrancy
            // Encrypted DNS uses WinHTTP internally, so we must bypass server connections
            if (EncryptedDns_IsServerHostname(domain_lwr)) {
                if (DNS_TraceFlag || DNS_DebugFlag) {
                    DNS_LogPassthrough(L"[WinHTTP]", pswzServerName, DNS_TYPE_ANY, L"EncDns server");
                }
                Dll_Free(domain_lwr);
                return __sys_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
            }
            
            // If an encrypted DNS query is already active, bypass to prevent re-entrancy
            // Encrypted DNS may trigger GetAddrInfoW which may trigger WinHttpConnect recursively
            if (EncryptedDns_IsQueryActive()) {
                if (DNS_TraceFlag || DNS_DebugFlag) {
                    DNS_LogPassthrough(L"[WinHTTP]", pswzServerName, DNS_TYPE_ANY, L"EncDns query active");
                }
                Dll_Free(domain_lwr);
                return __sys_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
            }
            
            PATTERN* found = NULL;
            
            // Use DNS-specific matching that handles FQDN trailing dots properly
            if (DNS_DomainMatchPatternList(domain_lwr, domain_len, &DNS_FilterList, &found) > 0) {
                // Domain matches NetworkDnsFilter
                
                // Check if certificate is valid for filtering
                if (!DNS_HasValidCertificate) {
                    DNS_LogPassthrough(L"[WinHTTP]", pswzServerName, DNS_TYPE_ANY, L"no certificate");
                    Dll_Free(domain_lwr);
                    return __sys_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
                }
                
                // Get IP entries for this domain (if any)
                PVOID* aux = Pattern_Aux(found);
                LIST* pEntries = NULL;
                DNS_TYPE_FILTER* type_filter = NULL;
                
                if (aux && *aux) {
                    DNS_ExtractFilterAux(aux, &pEntries, &type_filter);
                }
                
                // If no IP entries, this is block mode - deny connection
                if (!pEntries) {
                    DNS_LogBlocked(L"[WinHTTP]", pswzServerName, DNS_TYPE_ANY, L"Domain blocked (NXDOMAIN)");
                    Dll_Free(domain_lwr);
                    SetLastError(ERROR_HOST_UNREACHABLE);
                    return NULL;
                }
                
                // Has IP entries - redirect mode
                // WinHTTP will perform DNS resolution internally via GetAddrInfoW
                // Our existing GetAddrInfoW hook will intercept and return the filtered IPs
                // Just allow the connection - the DNS hook handles the redirection
                DNS_LogPassthrough(L"[WinHTTP]", pswzServerName, DNS_TYPE_ANY, L"allowing (DNS hooks will redirect)");
                Dll_Free(domain_lwr);
                // Let WinHTTP proceed - it will call GetAddrInfoW which our hooks will intercept
                return __sys_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
            }
            
            // Domain not in filter - allow and log passthrough if tracing
            DNS_LogPassthrough(L"[WinHTTP]", pswzServerName, DNS_TYPE_ANY, L"not filtered");
            
            Dll_Free(domain_lwr);
        }
    }

    // Domain allowed or not blocked - call original function
    return __sys_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
}
