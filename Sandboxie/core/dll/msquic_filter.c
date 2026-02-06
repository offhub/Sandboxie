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
// MsQuic (QUIC Protocol) Connection Filter Implementation
//
// This module intercepts MsQuic API calls to filter QUIC/HTTP3 connections
// based on NetworkDnsFilter rules.
//
// Hook Strategy:
//   1. Hook MsQuicOpenVersion() export from msquic.dll
//   2. When app calls MsQuicOpenVersion(), we call the real function
//   3. We copy the returned API table and replace ConnectionStart pointer
//   4. Return our modified API table to the application
//   5. When app calls ConnectionStart(), our hook checks the hostname
//   6. Block or allow based on NetworkDnsFilter rules
//
// Thread Safety:
//   - API table copies are allocated per-call and tracked
//   - MsQuicClose() hook frees the corresponding table copy
//   - Critical section protects the table tracking list
//---------------------------------------------------------------------------

#define NOGDI
#include "dll.h"

#include <windows.h>
#include <wchar.h>
#include "msquic_defs.h"
#include "msquic_filter.h"
#include "dns_filter.h"
#include "dns_logging.h"
#include "dns_encrypted.h"  // For EncryptedDns_IsQueryActive()

#if !defined(_DNSDEBUG)
// Release builds: compile out debug-only logging paths.
#undef DNS_DebugFlag
#define DNS_DebugFlag 0
#endif

//---------------------------------------------------------------------------
// Configuration
//---------------------------------------------------------------------------

// Maximum number of concurrent API table instances to track
#define MSQUIC_MAX_API_TABLES   64

//---------------------------------------------------------------------------
// Variables
//---------------------------------------------------------------------------

// Configuration flag
static BOOLEAN MsQuic_FilterEnabled = FALSE;

typedef enum _MSQUIC_FILTER_MODE {
    MSQUIC_FILTER_BLOCK_ALL = 0,        // Block if NetworkDnsFilter matches (even if rule has IPs)
    MSQUIC_FILTER_ALLOW_FILTER_IP = 1,  // Allow if rule has IPs (legacy/compat behavior)
} MSQUIC_FILTER_MODE;

static MSQUIC_FILTER_MODE MsQuic_FilterMode = MSQUIC_FILTER_BLOCK_ALL;

// Original function pointers
static P_MsQuicOpenVersion __sys_MsQuicOpenVersion = NULL;
static P_MsQuicClose __sys_MsQuicClose = NULL;

// Tracking structure for modified API tables
typedef struct _MSQUIC_TABLE_ENTRY {
    const QUIC_API_TABLE* OriginalTable;   // Original table from MsQuic
    QUIC_API_TABLE* ModifiedTable;         // Our modified copy
    QUIC_CONNECTION_START_FN RealConnectionStart;  // Original ConnectionStart
} MSQUIC_TABLE_ENTRY;

static MSQUIC_TABLE_ENTRY MsQuic_Tables[MSQUIC_MAX_API_TABLES];
static CRITICAL_SECTION MsQuic_TableLock;
static BOOLEAN MsQuic_Initialized = FALSE;

//---------------------------------------------------------------------------
// Forward Declarations
//---------------------------------------------------------------------------

static QUIC_STATUS QUIC_API MsQuic_MsQuicOpenVersion(
    UINT32 Version,
    const void** QuicApi);

static void QUIC_API MsQuic_MsQuicClose(
    const void* QuicApi);

static QUIC_STATUS QUIC_API MsQuic_ConnectionStart(
    HQUIC Connection,
    HQUIC Configuration,
    QUIC_ADDRESS_FAMILY Family,
    const char* ServerName,
    UINT16 ServerPort);


// DoQ exclusion helper functions
static BOOLEAN MsQuic_GetDoqInitializing(void);
static void MsQuic_SetDoqInitializingInternal(BOOLEAN initializing);

//---------------------------------------------------------------------------
// Helper Functions
//---------------------------------------------------------------------------

// Find table entry by modified table pointer
static MSQUIC_TABLE_ENTRY* MsQuic_FindTableByModified(const QUIC_API_TABLE* ModifiedTable)
{
    for (int i = 0; i < MSQUIC_MAX_API_TABLES; i++) {
        if (MsQuic_Tables[i].ModifiedTable == ModifiedTable) {
            return &MsQuic_Tables[i];
        }
    }
    return NULL;
}

// Find table entry by original table pointer
static MSQUIC_TABLE_ENTRY* MsQuic_FindTableByOriginal(const QUIC_API_TABLE* OriginalTable)
{
    for (int i = 0; i < MSQUIC_MAX_API_TABLES; i++) {
        if (MsQuic_Tables[i].OriginalTable == OriginalTable) {
            return &MsQuic_Tables[i];
        }
    }
    return NULL;
}

// Allocate a new table entry
static MSQUIC_TABLE_ENTRY* MsQuic_AllocTableEntry(void)
{
    for (int i = 0; i < MSQUIC_MAX_API_TABLES; i++) {
        if (MsQuic_Tables[i].OriginalTable == NULL) {
            return &MsQuic_Tables[i];
        }
    }
    return NULL;
}

// Free a table entry
static void MsQuic_FreeTableEntry(MSQUIC_TABLE_ENTRY* Entry)
{
    if (Entry->ModifiedTable) {
        Dll_Free(Entry->ModifiedTable);
        Entry->ModifiedTable = NULL;
    }
    Entry->OriginalTable = NULL;
    Entry->RealConnectionStart = NULL;
}

//---------------------------------------------------------------------------
// DoQ Exclusion Helper Functions (using Sandboxie TLS)
//---------------------------------------------------------------------------

static BOOLEAN MsQuic_GetDoqInitializing(void)
{
    THREAD_DATA *data = Dll_GetTlsData(NULL);
    return data ? data->msquic_doq_initializing : FALSE;
}

static void MsQuic_SetDoqInitializingInternal(BOOLEAN initializing)
{
    THREAD_DATA *data = Dll_GetTlsData(NULL);
    if (data)
        data->msquic_doq_initializing = initializing;
}

//---------------------------------------------------------------------------
// MsQuic_GetOriginalOpenVersion - Public function to get unhooked pointer
//
// Returns the original (unhooked) MsQuicOpenVersion function pointer.
// DoQ uses this to call the real MsQuic API without going through
// instrumentation stubs that expect to be called from hooked locations.
//---------------------------------------------------------------------------

_FX void* MsQuic_GetOriginalOpenVersion(void)
{
    return (void*)__sys_MsQuicOpenVersion;
}

//---------------------------------------------------------------------------
// MsQuic_MsQuicOpenVersion - Hook for MsQuicOpenVersion
//
// This is the main entry point for MsQuic. We intercept it to:
// 1. Call the real MsQuicOpenVersion
// 2. Create a copy of the API table
// 3. Replace ConnectionStart with our hook
// 4. Return our modified table
//---------------------------------------------------------------------------

static QUIC_STATUS QUIC_API MsQuic_MsQuicOpenVersion(
    UINT32 Version,
    const void** QuicApi)
{
    QUIC_STATUS Status;
    const QUIC_API_TABLE* OriginalTable;
    QUIC_API_TABLE* ModifiedTable;
    MSQUIC_TABLE_ENTRY* Entry;

    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[MsQuic] MsQuicOpenVersion called (Version=%u, Filter=%s, DoQ=%s)", 
            Version, MsQuic_FilterEnabled ? L"enabled" : L"disabled",
            MsQuic_GetDoqInitializing() ? L"initializing" : L"not-doq");
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // DoQ exclusion: Don't filter DoQ's own MsQuic usage
    if (MsQuic_GetDoqInitializing()) {
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[MsQuic] Bypassing filter for DoQ initialization");
        }
        return __sys_MsQuicOpenVersion ? __sys_MsQuicOpenVersion(Version, QuicApi) : QUIC_STATUS_NOT_SUPPORTED;
    }

    // Call real function
    Status = __sys_MsQuicOpenVersion(Version, (const void**)&OriginalTable);
    if (QUIC_FAILED(Status) || OriginalTable == NULL) {
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[MsQuic] MsQuicOpenVersion failed: Status=0x%08X, Table=%p", 
                Status, OriginalTable);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        *QuicApi = OriginalTable;
        return Status;
    }

    // If filtering is disabled, just return original
    if (!MsQuic_FilterEnabled) {
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[MsQuic] Filtering disabled, returning original API table");
        }
        *QuicApi = OriginalTable;
        return Status;
    }

    EnterCriticalSection(&MsQuic_TableLock);

    // Check if we already have an entry for this original table
    Entry = MsQuic_FindTableByOriginal(OriginalTable);
    if (Entry) {
        // Reuse existing modified table
        *QuicApi = Entry->ModifiedTable;
        LeaveCriticalSection(&MsQuic_TableLock);
        return Status;
    }

    // Allocate new entry
    Entry = MsQuic_AllocTableEntry();
    if (!Entry) {
        // No space, return original
        *QuicApi = OriginalTable;
        LeaveCriticalSection(&MsQuic_TableLock);
        
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[MsQuic] Warning: Table tracking limit reached");
        }
        return Status;
    }

    // Allocate and copy the API table
    ModifiedTable = (QUIC_API_TABLE*)Dll_Alloc(sizeof(QUIC_API_TABLE));
    if (!ModifiedTable) {
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[MsQuic] Failed to allocate modified API table");
        }
        *QuicApi = OriginalTable;
        LeaveCriticalSection(&MsQuic_TableLock);
        return Status;
    }

    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[MsQuic] Allocated modified table %p, copying from original %p", 
            ModifiedTable, OriginalTable);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // Copy the original table
    memcpy(ModifiedTable, OriginalTable, sizeof(QUIC_API_TABLE));

    // Store original ConnectionStart and replace with our hook
    Entry->OriginalTable = OriginalTable;
    Entry->ModifiedTable = ModifiedTable;
    Entry->RealConnectionStart = OriginalTable->ConnectionStart;
    
    ModifiedTable->ConnectionStart = MsQuic_ConnectionStart;

    *QuicApi = ModifiedTable;
    
    LeaveCriticalSection(&MsQuic_TableLock);

    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[MsQuic] API table hooked successfully: Original=%p, Modified=%p, Hook=%p", 
            OriginalTable, ModifiedTable, MsQuic_ConnectionStart);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    return Status;
}

//---------------------------------------------------------------------------
// MsQuic_MsQuicClose - Hook for MsQuicClose
//
// Clean up our modified API table when the application is done with it.
//---------------------------------------------------------------------------

static void QUIC_API MsQuic_MsQuicClose(const void* QuicApi)
{
    MSQUIC_TABLE_ENTRY* Entry = NULL;
    const QUIC_API_TABLE* OriginalTable = NULL;

    EnterCriticalSection(&MsQuic_TableLock);

    // Check if this is one of our modified tables
    Entry = MsQuic_FindTableByModified((const QUIC_API_TABLE*)QuicApi);
    if (Entry) {
        OriginalTable = Entry->OriginalTable;
        MsQuic_FreeTableEntry(Entry);
        
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[MsQuic] API table released");
        }
    } else {
        // Not our table, pass through as-is
        OriginalTable = (const QUIC_API_TABLE*)QuicApi;
    }

    LeaveCriticalSection(&MsQuic_TableLock);

    // Call real close with original table
    if (OriginalTable) {
        __sys_MsQuicClose(OriginalTable);
    }
}

//---------------------------------------------------------------------------
// MsQuic_ConnectionStart - Hook for QUIC_API_TABLE::ConnectionStart
//
// This is where we filter QUIC connections based on ServerName (hostname).
// We use the same NetworkDnsFilter rules as DNS filtering.
//---------------------------------------------------------------------------

static QUIC_STATUS QUIC_API MsQuic_ConnectionStart(
    HQUIC Connection,
    HQUIC Configuration,
    QUIC_ADDRESS_FAMILY Family,
    const char* ServerName,
    UINT16 ServerPort)
{
    QUIC_CONNECTION_START_FN RealConnectionStart = NULL;
    WCHAR ServerNameW[QUIC_MAX_SNI_LENGTH + 1];
    LIST* pEntries = NULL;
    BOOLEAN shouldBlock = FALSE;

    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[MsQuic] ConnectionStart hook called: ServerName='%S', Port=%u", 
            ServerName ? ServerName : "(null)", ServerPort);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // Find the real ConnectionStart function
    // We need to search through all tables since we don't know which one this connection belongs to
    EnterCriticalSection(&MsQuic_TableLock);
    for (int i = 0; i < MSQUIC_MAX_API_TABLES; i++) {
        if (MsQuic_Tables[i].RealConnectionStart) {
            RealConnectionStart = MsQuic_Tables[i].RealConnectionStart;
            break;
        }
    }
    LeaveCriticalSection(&MsQuic_TableLock);

    if (!RealConnectionStart) {
        // This shouldn't happen, but handle it gracefully
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    // If no server name, just pass through
    if (!ServerName || ServerName[0] == '\0') {
        return RealConnectionStart(Connection, Configuration, Family, ServerName, ServerPort);
    }

    // Convert server name to wide string first (needed for hostname checks)
    int len = MultiByteToWideChar(CP_UTF8, 0, ServerName, -1, ServerNameW, QUIC_MAX_SNI_LENGTH);
    if (len <= 0) {
        // Conversion failed, allow connection
        return RealConnectionStart(Connection, Configuration, Family, ServerName, ServerPort);
    }
    ServerNameW[QUIC_MAX_SNI_LENGTH] = L'\0';

    // If this is an encrypted DNS query (DoH/DoQ client making connection), bypass filter
    // This prevents the encrypted DNS client from being blocked by its own filter rules
    if (EncryptedDns_IsQueryActive()) {
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[MsQuic] Bypass filter: encrypted DNS client active");
        }
        return RealConnectionStart(Connection, Configuration, Family, ServerName, ServerPort);
    }

    // Check if this is an encrypted DNS server hostname (same exclusion as DoH uses)
    // This allows DoQ connections to the configured DNS server even when FilterMsQuic is enabled
    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[MsQuic] Checking server hostname: '%s' (UTF-8: '%S') port %u", ServerNameW, ServerName, ServerPort);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    BOOLEAN isServerHostname = EncryptedDns_IsServerHostname(ServerNameW);
    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[MsQuic] EncryptedDns_IsServerHostname('%s') returned: %s", 
            ServerNameW, isServerHostname ? L"TRUE" : L"FALSE");
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    if (isServerHostname) {
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[MsQuic] Bypass filter: encrypted DNS server %s:%u", ServerNameW, ServerPort);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        return RealConnectionStart(Connection, Configuration, Family, ServerName, ServerPort);
    } else {
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[MsQuic] Server hostname not recognized: %s:%u", ServerNameW, ServerPort);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    }

    // Check exclusion list first (DNS_IsExcluded)
    if (DNS_IsExcluded(ServerNameW)) {
        DNS_TRACE_LOG(L"[MsQuic] Excluded: %s:%u", ServerNameW, ServerPort);
        return RealConnectionStart(Connection, Configuration, Family, ServerName, ServerPort);
    }

    // Check if domain matches a filter rule
    // DNS_TYPE_A (1) is used since QUIC is IP-based
    if (DNS_CheckFilter(ServerNameW, 1 /* DNS_TYPE_A */, &pEntries)) {
        // Domain matched a filter rule
        if (pEntries == NULL) {
            // Block mode - no IPs configured means block
            shouldBlock = TRUE;
            
            if (DNS_TraceFlag) {
                WCHAR msg[512];
                Sbie_snwprintf(msg, 512, L"[MsQuic] Blocked: %s:%u (block mode)", ServerNameW, ServerPort);
                SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
            }
        } else {
            // Filter mode with IPs - for QUIC we cannot redirect/pin IPs.
            // Default is to block (security-correct). Allow mode keeps legacy/compat behavior.
            if (MsQuic_FilterMode == MSQUIC_FILTER_ALLOW_FILTER_IP) {
                if (DNS_TraceFlag) {
                    WCHAR msg[512];
                    Sbie_snwprintf(msg, 512, L"[MsQuic] Allowed: %s:%u (filter:ip allow mode)", ServerNameW, ServerPort);
                    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
                }
            } else {
                shouldBlock = TRUE;
                if (DNS_TraceFlag) {
                    WCHAR msg[512];
                    Sbie_snwprintf(msg, 512, L"[MsQuic] Blocked: %s:%u (filter:ip block mode)", ServerNameW, ServerPort);
                    SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_DENY, msg);
                }
            }
        }
    } else {
        // No filter match - passthrough
        if (DNS_TraceFlag) {
            WCHAR msg[512];
            Sbie_snwprintf(msg, 512, L"[MsQuic] Passthrough: %s:%u", ServerNameW, ServerPort);
            SbieApi_MonitorPutMsg(MONITOR_DNS | MONITOR_OPEN, msg);
        }
    }

    if (shouldBlock) {
        // Return permission denied - connection will fail
        return QUIC_STATUS_PERMISSION_DENIED;
    }

    // Allow connection
    return RealConnectionStart(Connection, Configuration, Family, ServerName, ServerPort);
}

//---------------------------------------------------------------------------
// MsQuic_IsFilterEnabled
//---------------------------------------------------------------------------

_FX BOOLEAN MsQuic_IsFilterEnabled(void)
{
    return MsQuic_FilterEnabled;
}

//---------------------------------------------------------------------------
// MsQuic_Init
//---------------------------------------------------------------------------

_FX BOOLEAN MsQuic_Init(HMODULE module)
{
    P_MsQuicOpenVersion MsQuicOpenVersion;
    P_MsQuicClose MsQuicClose;

    WCHAR wsMsQuicOptions[64];

    // Default behavior when enabled: block all matches (even if rule has IPs)
    MsQuic_FilterMode = MSQUIC_FILTER_BLOCK_ALL;

    // Load configuration
    wsMsQuicOptions[0] = L'\0';
    SbieDll_GetSettingsForName(NULL, Dll_ImageName, L"FilterMsQuic", wsMsQuicOptions, sizeof(wsMsQuicOptions), L"");
    MsQuic_FilterEnabled = Config_String2Bool(wsMsQuicOptions, FALSE);

    // Optional mode suffix: y|n:block|allow
    if (MsQuic_FilterEnabled) {
        WCHAR* colon = wcschr(wsMsQuicOptions, L':');
        if (colon) {
            WCHAR* mode = colon + 1;
            while (*mode == L' ' || *mode == L'\t') mode++;
            if (_wcsnicmp(mode, L"allow", 5) == 0) {
                MsQuic_FilterMode = MSQUIC_FILTER_ALLOW_FILTER_IP;
            } else {
                // Default/unknown => block
                MsQuic_FilterMode = MSQUIC_FILTER_BLOCK_ALL;
            }
        }
    }

    // If filtering is disabled, skip hook installation
    if (!MsQuic_FilterEnabled) {
        return TRUE;
    }

    // Initialize critical section and table tracking
    if (!MsQuic_Initialized) {
        InitializeCriticalSection(&MsQuic_TableLock);
        memset(MsQuic_Tables, 0, sizeof(MsQuic_Tables));
        MsQuic_Initialized = TRUE;
    }

    // Get function pointers
    MsQuicOpenVersion = (P_MsQuicOpenVersion)GetProcAddress(module, "MsQuicOpenVersion");
    MsQuicClose = (P_MsQuicClose)GetProcAddress(module, "MsQuicClose");

    // Hook MsQuicOpenVersion (required)
    if (MsQuicOpenVersion) {
        SBIEDLL_HOOK(MsQuic_, MsQuicOpenVersion);
    } else {
        // MsQuicOpenVersion not found - this DLL might be a different version
        return TRUE;
    }

    // Hook MsQuicClose (for cleanup)
    if (MsQuicClose) {
        SBIEDLL_HOOK(MsQuic_, MsQuicClose);
    }

    if (DNS_DebugFlag) {
        if (MsQuic_FilterMode == MSQUIC_FILTER_ALLOW_FILTER_IP)
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[MsQuic] Filter initialized (allow filter:ip)");
        else
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[MsQuic] Filter initialized (block all matches)");
    }

    // Note: DoQ module initializes itself independently when needed
    // Removed recursive DoQ_Init() call to prevent initialization deadlock

    return TRUE;
}

//---------------------------------------------------------------------------
// Public Functions
//---------------------------------------------------------------------------

// Mark DoQ initialization phase (excludes DoQ from its own filtering)
void MsQuic_SetDoqInitializing(BOOLEAN initializing)
{
    MsQuic_SetDoqInitializingInternal(initializing);
}
