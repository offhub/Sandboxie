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
// DNS over QUIC (DoQ) Client Implementation - RFC 9250
//
// This module implements native DNS over QUIC (DoQ) as specified in RFC 9250.
// DoQ uses QUIC streams directly for DNS message transport with minimal overhead.
//
// Implementation via MsQuic:
//   - MsQuic is Microsoft's cross-platform QUIC implementation
//   - Not included in Windows system32, must be injected via InjectDll
//   - Uses QUIC API v2 for modern features
//   - Automatic connection pooling for efficiency
//
// Message Flow (RFC 9250 Section 4.2):
//   1. Open QUIC connection to DoQ server (port 853)
//   2. Create bidirectional stream
//   3. Send: [2-byte length][DNS query in wire format]
//   4. Receive: [2-byte length][DNS response in wire format]
//   5. Close stream (connection remains open for reuse)
//
// Thread Safety:
//   - Connection pool protected by critical section
//   - Individual queries use separate streams on same connection
//   - Event-based synchronization for async QUIC operations
//---------------------------------------------------------------------------

#define NOGDI
#include "dll.h"

#include <windows.h>
#include <wchar.h>
#include <limits.h>
#include "msquic_defs.h"
#include "dns_doq.h"
#include "dns_encrypted.h"
#include "dns_logging.h"
#include "dns_wire.h"
#include "msquic_filter.h"  // For MsQuic_SetDoqInitializing and MsQuic_GetOriginalOpenVersion

//---------------------------------------------------------------------------
// Extended MsQuic Types (needed for DoQ but not in msquic_defs.h)
//---------------------------------------------------------------------------

// Stream event types
typedef enum QUIC_STREAM_EVENT_TYPE {
    QUIC_STREAM_EVENT_START_COMPLETE            = 0,
    QUIC_STREAM_EVENT_RECEIVE                   = 1,
    QUIC_STREAM_EVENT_SEND_COMPLETE             = 2,
    QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN        = 3,
    QUIC_STREAM_EVENT_PEER_SEND_ABORTED         = 4,
    QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED      = 5,
    QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE    = 6,
    QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE         = 7,
    QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE    = 8,
    QUIC_STREAM_EVENT_PEER_ACCEPTED             = 9,
} QUIC_STREAM_EVENT_TYPE;

// Stream open flags
typedef enum QUIC_STREAM_OPEN_FLAGS {
    QUIC_STREAM_OPEN_FLAG_NONE                  = 0x0000,
    QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL        = 0x0001,
    QUIC_STREAM_OPEN_FLAG_0_RTT                 = 0x0002,
} QUIC_STREAM_OPEN_FLAGS;

// Stream start flags
typedef enum QUIC_STREAM_START_FLAGS {
    QUIC_STREAM_START_FLAG_NONE                 = 0x0000,
    QUIC_STREAM_START_FLAG_IMMEDIATE            = 0x0001,
    QUIC_STREAM_START_FLAG_FAIL_BLOCKED         = 0x0002,
    QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL     = 0x0004,
} QUIC_STREAM_START_FLAGS;

// Stream shutdown flags
typedef enum QUIC_STREAM_SHUTDOWN_FLAGS {
    QUIC_STREAM_SHUTDOWN_FLAG_NONE              = 0x0000,
    QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL          = 0x0001,
    QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND        = 0x0002,
    QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE     = 0x0004,
    QUIC_STREAM_SHUTDOWN_FLAG_ABORT             = 0x0006,
    QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE         = 0x0008,
} QUIC_STREAM_SHUTDOWN_FLAGS;

// Send flags
typedef enum QUIC_SEND_FLAGS {
    QUIC_SEND_FLAG_NONE                         = 0x0000,
    QUIC_SEND_FLAG_ALLOW_0_RTT                  = 0x0001,
    QUIC_SEND_FLAG_START                        = 0x0002,
    QUIC_SEND_FLAG_FIN                          = 0x0004,
    QUIC_SEND_FLAG_DGRAM_PRIORITY               = 0x0008,
    QUIC_SEND_FLAG_DELAY_SEND                   = 0x0010,
} QUIC_SEND_FLAGS;

// Receive flags (must be defined before QUIC_STREAM_EVENT which uses it)
typedef enum QUIC_RECEIVE_FLAGS {
    QUIC_RECEIVE_FLAG_NONE                      = 0x0000,
    QUIC_RECEIVE_FLAG_0_RTT                     = 0x0001,
    QUIC_RECEIVE_FLAG_FIN                       = 0x0002,
} QUIC_RECEIVE_FLAGS;

// Stream event structure
typedef struct QUIC_STREAM_EVENT {
    QUIC_STREAM_EVENT_TYPE Type;
    union {
        struct {
            QUIC_STATUS Status;
            QUIC_UINT62 ID;
            BOOLEAN PeerAccepted;
        } START_COMPLETE;
        struct {
            QUIC_UINT62 AbsoluteOffset;
            QUIC_UINT62 TotalBufferLength;
            const QUIC_BUFFER* Buffers;
            UINT32 BufferCount;
            QUIC_RECEIVE_FLAGS Flags;
        } RECEIVE;
        struct {
            BOOLEAN Canceled;
            void* ClientContext;
        } SEND_COMPLETE;
        struct {
            QUIC_UINT62 ErrorCode;
        } PEER_SEND_ABORTED;
        struct {
            QUIC_UINT62 ErrorCode;
        } PEER_RECEIVE_ABORTED;
        struct {
            BOOLEAN Graceful;
        } SEND_SHUTDOWN_COMPLETE;
        struct {
            BOOLEAN ConnectionShutdown;
            BOOLEAN AppCloseInProgress;
            QUIC_STATUS ConnectionCloseStatus;
            QUIC_UINT62 ConnectionErrorCode;
        } SHUTDOWN_COMPLETE;
        struct {
            UINT64 ByteCount;
        } IDEAL_SEND_BUFFER_SIZE;
    };
} QUIC_STREAM_EVENT;

// Stream callback handler
typedef
QUIC_STATUS
(QUIC_API QUIC_STREAM_CALLBACK)(
    HQUIC Stream,
    void* Context,
    QUIC_STREAM_EVENT* Event
    );
typedef QUIC_STREAM_CALLBACK *QUIC_STREAM_CALLBACK_HANDLER;

// Real stream function types
typedef
QUIC_STATUS
(QUIC_API * QUIC_STREAM_OPEN_FN_REAL)(
    HQUIC Connection,
    QUIC_STREAM_OPEN_FLAGS Flags,
    QUIC_STREAM_CALLBACK_HANDLER Handler,
    void* Context,
    HQUIC* Stream
    );

typedef
void
(QUIC_API * QUIC_STREAM_CLOSE_FN_REAL)(
    HQUIC Stream
    );

typedef
QUIC_STATUS
(QUIC_API * QUIC_STREAM_START_FN_REAL)(
    HQUIC Stream,
    QUIC_STREAM_START_FLAGS Flags
    );

typedef
void
(QUIC_API * QUIC_STREAM_SHUTDOWN_FN_REAL)(
    HQUIC Stream,
    QUIC_STREAM_SHUTDOWN_FLAGS Flags,
    QUIC_UINT62 ErrorCode
    );

typedef
QUIC_STATUS
(QUIC_API * QUIC_STREAM_SEND_FN_REAL)(
    HQUIC Stream,
    const QUIC_BUFFER* Buffers,
    UINT32 BufferCount,
    QUIC_SEND_FLAGS Flags,
    void* ClientSendContext
    );

typedef
void
(QUIC_API * QUIC_STREAM_RECEIVE_COMPLETE_FN_REAL)(
    HQUIC Stream,
    UINT64 BufferLength
    );

//---------------------------------------------------------------------------
// Credential Configuration
//---------------------------------------------------------------------------

typedef enum QUIC_CREDENTIAL_TYPE {
    QUIC_CREDENTIAL_TYPE_NONE,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12,
} QUIC_CREDENTIAL_TYPE;

typedef enum QUIC_CREDENTIAL_FLAGS {
    QUIC_CREDENTIAL_FLAG_NONE                           = 0x00000000,
    QUIC_CREDENTIAL_FLAG_CLIENT                         = 0x00000001,
    QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS              = 0x00000002,
    QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION      = 0x00000004,
    QUIC_CREDENTIAL_FLAG_ENABLE_OCSP                    = 0x00000008,
    QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED  = 0x00000010,
    QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION   = 0x00000020,
    QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION  = 0x00000040,
    QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION = 0x00000080,
    QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT      = 0x00000100,
    QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN         = 0x00000200,
    QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x00000400,
    QUIC_CREDENTIAL_FLAG_IGNORE_NO_REVOCATION_CHECK     = 0x00000800,
    QUIC_CREDENTIAL_FLAG_IGNORE_REVOCATION_OFFLINE      = 0x00001000,
    QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES      = 0x00002000,
    QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES      = 0x00004000,
    QUIC_CREDENTIAL_FLAG_USE_SUPPLIED_CREDENTIALS       = 0x00008000,
    QUIC_CREDENTIAL_FLAG_USE_SYSTEM_MAPPER              = 0x00010000,
    QUIC_CREDENTIAL_FLAG_CACHE_ONLY_URL_RETRIEVAL       = 0x00020000,
    QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CACHE_ONLY    = 0x00040000,
    QUIC_CREDENTIAL_FLAG_INPROC_PEER_CERTIFICATE        = 0x00080000,
    QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE        = 0x00100000,
} QUIC_CREDENTIAL_FLAGS;

typedef struct QUIC_CREDENTIAL_CONFIG {
    QUIC_CREDENTIAL_TYPE Type;
    QUIC_CREDENTIAL_FLAGS Flags;
    void* Certificate;          // Based on Type
    const char* Principal;
    void* Reserved;
    void* AsyncHandler;
    void* AllowedCipherSuites;
    const char* CaCertificateFile;
} QUIC_CREDENTIAL_CONFIG;

//---------------------------------------------------------------------------
// Settings
//---------------------------------------------------------------------------

typedef struct QUIC_SETTINGS {
    union {
        UINT64 IsSetFlags;
        struct {
            UINT64 MaxBytesPerKey                       : 1;
            UINT64 HandshakeIdleTimeoutMs               : 1;
            UINT64 IdleTimeoutMs                        : 1;
            UINT64 MtuDiscoverySearchCompleteTimeoutUs  : 1;
            UINT64 TlsClientMaxSendBuffer               : 1;
            UINT64 TlsServerMaxSendBuffer               : 1;
            UINT64 StreamRecvWindowDefault              : 1;
            UINT64 StreamRecvBufferDefault              : 1;
            UINT64 ConnFlowControlWindow                : 1;
            UINT64 MaxWorkerQueueDelayUs                : 1;
            UINT64 MaxStatelessOperations               : 1;
            UINT64 InitialWindowPackets                 : 1;
            UINT64 SendIdleTimeoutMs                    : 1;
            UINT64 InitialRttMs                         : 1;
            UINT64 MaxAckDelayMs                        : 1;
            UINT64 DisconnectTimeoutMs                  : 1;
            UINT64 KeepAliveIntervalMs                  : 1;
            UINT64 CongestionControlAlgorithm           : 1;
            UINT64 PeerBidiStreamCount                  : 1;
            UINT64 PeerUnidiStreamCount                 : 1;
            UINT64 MaxBindingStatelessOperations        : 1;
            UINT64 StatelessOperationExpirationMs       : 1;
            UINT64 MinimumMtu                           : 1;
            UINT64 MaximumMtu                           : 1;
            UINT64 SendBufferingEnabled                 : 1;
            UINT64 PacingEnabled                        : 1;
            UINT64 MigrationEnabled                     : 1;
            UINT64 DatagramReceiveEnabled               : 1;
            UINT64 ServerResumptionLevel                : 1;
            UINT64 MaxOperationsPerDrain                : 1;
            UINT64 MtuDiscoveryMissingProbeCount        : 1;
            UINT64 DestCidUpdateIdleTimeoutMs           : 1;
            UINT64 GreaseQuicBitEnabled                 : 1;
            UINT64 EcnEnabled                           : 1;
            UINT64 HyStartEnabled                       : 1;
            UINT64 StreamRecvWindowBidiLocalDefault     : 1;
            UINT64 StreamRecvWindowBidiRemoteDefault    : 1;
            UINT64 StreamRecvWindowUnidiDefault         : 1;
            UINT64 RESERVED                             : 26;
        } IsSet;
    };
    UINT64 MaxBytesPerKey;
    UINT64 HandshakeIdleTimeoutMs;
    UINT64 IdleTimeoutMs;
    UINT64 MtuDiscoverySearchCompleteTimeoutUs;
    UINT32 TlsClientMaxSendBuffer;
    UINT32 TlsServerMaxSendBuffer;
    UINT32 StreamRecvWindowDefault;
    UINT32 StreamRecvBufferDefault;
    UINT32 ConnFlowControlWindow;
    UINT32 MaxWorkerQueueDelayUs;
    UINT32 MaxStatelessOperations;
    UINT32 InitialWindowPackets;
    UINT32 SendIdleTimeoutMs;
    UINT32 InitialRttMs;
    UINT32 MaxAckDelayMs;
    UINT32 DisconnectTimeoutMs;
    UINT32 KeepAliveIntervalMs;
    UINT16 CongestionControlAlgorithm;
    UINT16 PeerBidiStreamCount;
    UINT16 PeerUnidiStreamCount;
    UINT16 MaxBindingStatelessOperations;
    UINT16 StatelessOperationExpirationMs;
    UINT16 MinimumMtu;
    UINT16 MaximumMtu;
    UINT8 SendBufferingEnabled : 1;
    UINT8 PacingEnabled : 1;
    UINT8 MigrationEnabled : 1;
    UINT8 DatagramReceiveEnabled : 1;
    UINT8 ServerResumptionLevel : 2;
    UINT8 GreaseQuicBitEnabled : 1;
    UINT8 EcnEnabled : 1;
    UINT8 MaxOperationsPerDrain;
    UINT8 MtuDiscoveryMissingProbeCount;
    UINT32 DestCidUpdateIdleTimeoutMs;
    UINT8 HyStartEnabled : 1;
    UINT8 RESERVED2 : 7;
    UINT32 StreamRecvWindowBidiLocalDefault;
    UINT32 StreamRecvWindowBidiRemoteDefault;
    UINT32 StreamRecvWindowUnidiDefault;
} QUIC_SETTINGS;

//---------------------------------------------------------------------------
// DoQ Query Context
//---------------------------------------------------------------------------

typedef struct _DOQ_QUERY_CONTEXT {
    // Synchronization
    HANDLE CompletionEvent;         // Signaled when query completes
    
    // Query data
    BYTE QueryBuffer[DOQ_MAX_MESSAGE_SIZE + DOQ_LENGTH_PREFIX_SIZE];
    UINT32 QueryLength;
    
    // Response data
    BYTE ResponseBuffer[DOQ_MAX_MESSAGE_SIZE + DOQ_LENGTH_PREFIX_SIZE];
    UINT32 ResponseLength;
    UINT32 ResponseOffset;          // Current write offset
    
    // Status
    QUIC_STATUS Status;
    BOOLEAN Completed;
    BOOLEAN SendComplete;
    BOOLEAN RecvComplete;
    
    // Result
    ENCRYPTED_DNS_RESULT* pResult;
} DOQ_QUERY_CONTEXT;

//---------------------------------------------------------------------------
// DoQ Connection Pool Entry
//---------------------------------------------------------------------------

typedef struct _DOQ_CONNECTION {
    WCHAR Host[ENCRYPTED_DNS_DOMAIN_MAX_LEN];
    USHORT Port;
    HQUIC Connection;
    HQUIC Configuration;
    DOQ_CONNECTION_STATE State;
    ULONGLONG LastUsed;
    HANDLE ConnectEvent;            // Signaled when connection completes
    QUIC_STATUS ConnectStatus;
    volatile LONG RefCount;
} DOQ_CONNECTION;

//---------------------------------------------------------------------------
// Global State
//---------------------------------------------------------------------------

// MsQuic initialization
static volatile LONG g_DoqInitialized = 0;
static HMODULE g_hMsQuic = NULL;
static const QUIC_API_TABLE* g_pQuicApi = NULL;

// Registration and configuration
static HQUIC g_hRegistration = NULL;
static CRITICAL_SECTION g_DoqLock;
static volatile LONG g_DoqLockValid = 0;

// Connection pool
static DOQ_CONNECTION g_DoqConnPool[DOQ_MAX_CONNECTIONS];
static ULONG g_DoqConnPoolCount = 0;

// ALPN buffer for DoQ
// Note: QUIC_BUFFER expects the raw ALPN string, not length-prefixed
static const UINT8 g_DoqAlpn[] = "doq";
static const QUIC_BUFFER g_DoqAlpnBuffer = { 3, (UINT8*)g_DoqAlpn };

// External dependencies
extern BOOLEAN DNS_TraceFlag;
extern BOOLEAN DNS_DebugFlag;
extern ULONGLONG GetTickCount64(void);

#if !defined(_DNSDEBUG)
// Release builds: compile out debug-only logging paths.
#undef DNS_DebugFlag
#define DNS_DebugFlag 0
#endif

//---------------------------------------------------------------------------
// Forward Declarations
//---------------------------------------------------------------------------

static QUIC_STATUS QUIC_API DoQ_ConnectionCallback(HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event);
static QUIC_STATUS QUIC_API DoQ_StreamCallback(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event);
static DOQ_CONNECTION* DoQ_GetOrCreateConnection(const DOQ_SERVER* server);
static void DoQ_ReleaseConnection(DOQ_CONNECTION* conn);
static BOOLEAN DoQ_ParseResponse(const BYTE* response, UINT32 length, ENCRYPTED_DNS_RESULT* pResult);

static BOOLEAN DoQ_IsExecutableAddress(const void* p)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (!p)
        return FALSE;
    if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi))
        return FALSE;
    if (mbi.State != MEM_COMMIT)
        return FALSE;
    if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        return TRUE;
    return FALSE;
}

//---------------------------------------------------------------------------
// DoQ_Init - Initialize DoQ module
//---------------------------------------------------------------------------

_FX BOOLEAN DoQ_Init(HMODULE hMsQuic)
{
    QUIC_STATUS status;
    QUIC_REGISTRATION_CONFIG regConfig = { 0 };
    BOOLEAN bDynamicallyLoaded = FALSE;

    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DoQ] Init called with hMsQuic=%p", hMsQuic);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // Use interlocked operation to prevent concurrent initialization
    LONG oldState = InterlockedCompareExchange(&g_DoqInitialized, -1, 0);
    if (oldState != 0) {
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] Init skipped - already initialized or in progress (state=%ld)", oldState);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        // Either already initialized (1) or initialization in progress (-1)
        // Wait briefly if in progress, then return current state
        while (InterlockedCompareExchange(&g_DoqInitialized, 0, 0) == -1) {
            Sleep(10);
        }
        return InterlockedCompareExchange(&g_DoqInitialized, 0, 0) == 1;
    }

    if (DNS_DebugFlag) {
        SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Acquired initialization lock, proceeding...");
    }

    // We got the initialization lock (set to -1)
    // If no module provided, try to load msquic.dll from system
    if (!hMsQuic) {
        hMsQuic = GetModuleHandleW(L"msquic.dll");
        if (!hMsQuic) {
            hMsQuic = LoadLibraryW(L"msquic.dll");
            bDynamicallyLoaded = TRUE;
        }
        if (!hMsQuic) {
            DWORD dwError = GetLastError();
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"[DoQ] msquic.dll not found (error: %d)", dwError);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            InterlockedExchange(&g_DoqInitialized, 0);  // Failed
            if (DNS_DebugFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Init exiting early - msquic.dll load failed");
            }
            return FALSE;
        }
        if (DNS_DebugFlag && bDynamicallyLoaded) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Loaded msquic.dll dynamically");
        }
    }

    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DoQ] Getting MsQuicOpenVersion from msquic.dll handle=%p", hMsQuic);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // Get MsQuicOpenVersion function pointer
    // Priority 1: Try MsQuic_GetOriginalOpenVersion() - returns original unhooked pointer
    //   This works when FilterMsQuic is enabled and hooks are installed
    // Priority 2: Fall back to GetProcAddress() if filter not initialized
    //   This works when FilterMsQuic=n (disabled) or when called before MsQuic_Init()
    //   NOTE: GetProcAddress will return hooked stub if ApiTrace is enabled, which will crash
    P_MsQuicOpenVersion pMsQuicOpenVersion = (P_MsQuicOpenVersion)MsQuic_GetOriginalOpenVersion();
    if (!pMsQuicOpenVersion) {
        // MsQuic filter not initialized (FilterMsQuic=n), use GetProcAddress as fallback
        pMsQuicOpenVersion = (P_MsQuicOpenVersion)GetProcAddress(hMsQuic, "MsQuicOpenVersion");
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] MsQuic filter not active, using GetProcAddress: %p", pMsQuicOpenVersion);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    } else {
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] Using original MsQuicOpenVersion from filter: %p", pMsQuicOpenVersion);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    }
    
    if (!pMsQuicOpenVersion) {
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] MsQuicOpenVersion not found (error: %d)", GetLastError());
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        InterlockedExchange(&g_DoqInitialized, 0);  // Failed
        return FALSE;
    }

    if (!DoQ_IsExecutableAddress((const void*)pMsQuicOpenVersion)) {
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] MsQuicOpenVersion resolved to non-executable address: %p", pMsQuicOpenVersion);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        InterlockedExchange(&g_DoqInitialized, 0);
        return FALSE;
    }

    // Initialize critical section
    if (InterlockedCompareExchange(&g_DoqLockValid, 1, 0) == 0) {
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Initializing critical section");
        }
        InitializeCriticalSection(&g_DoqLock);
        memset(g_DoqConnPool, 0, sizeof(g_DoqConnPool));
    }

    if (DNS_DebugFlag) {
        SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Entering critical section for initialization");
    }
    EnterCriticalSection(&g_DoqLock);

    // Get QUIC API table
    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DoQ] Calling MsQuicOpenVersion (Version=%u)", QUIC_API_VERSION_2);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    // Mark DoQ initialization to exclude from MsQuic filtering
    MsQuic_SetDoqInitializing(TRUE);
    status = pMsQuicOpenVersion(QUIC_API_VERSION_2, (const void**)&g_pQuicApi);
    MsQuic_SetDoqInitializing(FALSE);
    if (QUIC_FAILED(status) || !g_pQuicApi) {
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] MsQuicOpenVersion failed: status=0x%08X, g_pQuicApi=%p", status, g_pQuicApi);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        LeaveCriticalSection(&g_DoqLock);
        InterlockedExchange(&g_DoqInitialized, 0);  // Failed
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Init exiting early - MsQuicOpenVersion failed");
        }
        return FALSE;
    } else {
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] MsQuicOpenVersion succeeded: API table=%p, ConnectionStart=%p", 
                g_pQuicApi, g_pQuicApi ? g_pQuicApi->ConnectionStart : NULL);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    }

    // Open registration
    regConfig.AppName = "SandboxieDoQ";
    regConfig.ExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY;
    
    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DoQ] Calling RegistrationOpen with API table %p", g_pQuicApi);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    status = g_pQuicApi->RegistrationOpen(&regConfig, &g_hRegistration);
    if (QUIC_FAILED(status)) {
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] RegistrationOpen failed: status=0x%08X", status);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        g_pQuicApi = NULL;
        LeaveCriticalSection(&g_DoqLock);
        InterlockedExchange(&g_DoqInitialized, 0);  // Failed
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Init exiting early - RegistrationOpen failed");
        }
        return FALSE;
    } else {
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] RegistrationOpen succeeded: handle=%p", g_hRegistration);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    }

    g_hMsQuic = hMsQuic;
    InterlockedExchange(&g_DoqInitialized, 1);

    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DoQ] Initialization completed successfully - state set to 1, g_pQuicApi=%p", g_pQuicApi);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    if (DNS_TraceFlag) {
        SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Initialized with MsQuic");
    }

    LeaveCriticalSection(&g_DoqLock);
    
    if (DNS_DebugFlag) {
        SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Init function returning TRUE");
    }
    
    return TRUE;
}

//---------------------------------------------------------------------------
// DoQ_Cleanup - Cleanup DoQ module
//---------------------------------------------------------------------------

_FX void DoQ_Cleanup(void)
{
    if (InterlockedCompareExchange(&g_DoqInitialized, 0, 1) != 1)
        return;  // Not initialized

    if (InterlockedCompareExchange(&g_DoqLockValid, 0, 0) == 0)
        return;

    EnterCriticalSection(&g_DoqLock);

    // Close all connections
    for (ULONG i = 0; i < g_DoqConnPoolCount; i++) {
        if (g_DoqConnPool[i].Configuration && g_pQuicApi) {
            g_pQuicApi->ConfigurationClose(g_DoqConnPool[i].Configuration);
        }
        if (g_DoqConnPool[i].Connection && g_pQuicApi) {
            g_pQuicApi->ConnectionClose(g_DoqConnPool[i].Connection);
        }
        if (g_DoqConnPool[i].ConnectEvent) {
            CloseHandle(g_DoqConnPool[i].ConnectEvent);
        }
    }
    g_DoqConnPoolCount = 0;
    memset(g_DoqConnPool, 0, sizeof(g_DoqConnPool));

    // Close registration
    if (g_hRegistration && g_pQuicApi) {
        g_pQuicApi->RegistrationClose(g_hRegistration);
        g_hRegistration = NULL;
    }

    g_pQuicApi = NULL;
    g_hMsQuic = NULL;

    LeaveCriticalSection(&g_DoqLock);
    DeleteCriticalSection(&g_DoqLock);
    InterlockedExchange(&g_DoqLockValid, 0);

    if (DNS_TraceFlag) {
        SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Cleanup complete");
    }
}

//---------------------------------------------------------------------------
// DoQ_IsAvailable - Check if DoQ is available
//---------------------------------------------------------------------------

_FX BOOLEAN DoQ_IsAvailable(void)
{
    LONG state = InterlockedCompareExchange(&g_DoqInitialized, 0, 0);
    
    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DoQ] IsAvailable: initial state=%ld, g_pQuicApi=%p", state, g_pQuicApi);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    // If not initialized yet (0), try to initialize with dynamic loading
    if (state == 0) {
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Not initialized, attempting initialization...");
        }
        DoQ_Init(NULL);  // Will attempt to load msquic.dll
        state = InterlockedCompareExchange(&g_DoqInitialized, 0, 0);
        
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] After init attempt: state=%ld, g_pQuicApi=%p", state, g_pQuicApi);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    }
    
    // If initialization in progress (-1), wait briefly
    if (state == -1) {
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Initialization in progress, waiting...");
        }
        for (int i = 0; i < 50 && state == -1; i++) {
            Sleep(10);
            state = InterlockedCompareExchange(&g_DoqInitialized, 0, 0);
        }
    }
    
    BOOLEAN result = state == 1 && g_pQuicApi != NULL;
    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DoQ] IsAvailable result: %s (state=%ld, g_pQuicApi=%p)", 
            result ? L"TRUE" : L"FALSE", state, g_pQuicApi);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    return result;
}

//---------------------------------------------------------------------------
// DoQ_ConnectionCallback - QUIC connection event handler
//---------------------------------------------------------------------------

static QUIC_STATUS QUIC_API DoQ_ConnectionCallback(
    HQUIC Connection,
    void* Context,
    QUIC_CONNECTION_EVENT* Event)
{
    DOQ_CONNECTION* conn = (DOQ_CONNECTION*)Context;

    if (DNS_DebugFlag) {
        const WCHAR* eventName = L"UNKNOWN";
        switch (Event->Type) {
            case 0: eventName = L"CONNECTED"; break;
            case 1: eventName = L"SHUTDOWN_INITIATED_BY_TRANSPORT"; break;
            case 2: eventName = L"SHUTDOWN_INITIATED_BY_PEER"; break;
            case 3: eventName = L"SHUTDOWN_COMPLETE"; break;
            case 4: eventName = L"LOCAL_ADDRESS_CHANGED"; break;
            case 5: eventName = L"PEER_ADDRESS_CHANGED"; break;
            case 6: eventName = L"PEER_STREAM_STARTED"; break;
            case 7: eventName = L"STREAMS_AVAILABLE"; break;
            case 8: eventName = L"PEER_NEEDS_STREAMS"; break;
            case 9: eventName = L"IDEAL_PROCESSOR_CHANGED"; break;
            case 10: eventName = L"DATAGRAM_STATE_CHANGED"; break;
            case 11: eventName = L"DATAGRAM_RECEIVED"; break;
            case 12: eventName = L"DATAGRAM_SEND_STATE_CHANGED"; break;
            case 13: eventName = L"RESUMED"; break;
            case 14: eventName = L"RESUMPTION_TICKET_RECEIVED"; break;
            case 15: eventName = L"PEER_CERTIFICATE_RECEIVED"; break;
        }
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DoQ] Connection callback: %s (%d) for %s:%d", 
            eventName, Event->Type, conn ? conn->Host : L"(null)", conn ? conn->Port : 0);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] Connected to %s:%d", conn->Host, conn->Port);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        conn->State = DOQ_STATE_CONNECTED;
        conn->ConnectStatus = QUIC_STATUS_SUCCESS;
        if (conn->ConnectEvent) {
            SetEvent(conn->ConnectEvent);
        }
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        if (DNS_DebugFlag || DNS_TraceFlag) {
            WCHAR msg[256];
            QUIC_STATUS status = Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status;
            
            // Provide detailed messages for common MsQuic status results
            if (status == 0x80410007) {  // QUIC_STATUS_ALPN_NEG_FAILURE
                Sbie_snwprintf(msg, 256, L"[DoQ] Connection failed: ALPN negotiation failed (0x%08X). Server may not support DoQ on this port.", status);
            } else if (status == CERT_E_UNTRUSTEDROOT) {  // QUIC_STATUS_CERT_UNTRUSTED_ROOT
                Sbie_snwprintf(msg, 256, L"[DoQ] Connection failed: Certificate untrusted (0x%08X)", status);
            } else if (status == CERT_E_EXPIRED) {  // QUIC_STATUS_CERT_EXPIRED
                Sbie_snwprintf(msg, 256, L"[DoQ] Connection failed: Certificate expired (0x%08X)", status);
            } else if (status == 0x80410005) {  // QUIC_STATUS_CONNECTION_IDLE
                Sbie_snwprintf(msg, 256, L"[DoQ] Connection shutdown: Connection idle timeout (0x%08X)", status);
            } else if (status == 0x80410006) {  // QUIC_STATUS_CONNECTION_TIMEOUT
                Sbie_snwprintf(msg, 256, L"[DoQ] Connection shutdown: Connection timeout (0x%08X)", status);
            } else {
                Sbie_snwprintf(msg, 256, L"[DoQ] Connection shutdown by transport: 0x%08X", status);
            }
            
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        conn->State = DOQ_STATE_ERROR;
        conn->ConnectStatus = Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status;
        if (conn->ConnectEvent) {
            SetEvent(conn->ConnectEvent);
        }
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] Connection shutdown by peer: 0x%llX", 
                Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        conn->State = DOQ_STATE_ERROR;
        if (conn->ConnectEvent) {
            SetEvent(conn->ConnectEvent);
        }
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Connection shutdown complete");
        }
        conn->State = DOQ_STATE_DISCONNECTED;
        break;

    case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
        // For now, accept certificate (can add validation later)
        break;

    default:
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

//---------------------------------------------------------------------------
// DoQ_StreamCallback - QUIC stream event handler
//---------------------------------------------------------------------------

static QUIC_STATUS QUIC_API DoQ_StreamCallback(
    HQUIC Stream,
    void* Context,
    QUIC_STREAM_EVENT* Event)
{
    DOQ_QUERY_CONTEXT* ctx = (DOQ_QUERY_CONTEXT*)Context;
    QUIC_STREAM_RECEIVE_COMPLETE_FN_REAL StreamReceiveComplete = NULL;

    switch (Event->Type) {
    case QUIC_STREAM_EVENT_START_COMPLETE:
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] Stream started: status=0x%08X", 
                Event->START_COMPLETE.Status);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        if (QUIC_FAILED(Event->START_COMPLETE.Status)) {
            ctx->Status = Event->START_COMPLETE.Status;
            ctx->Completed = TRUE;
            SetEvent(ctx->CompletionEvent);
        }
        break;

    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Send complete");
        }
        ctx->SendComplete = TRUE;
        break;

    case QUIC_STREAM_EVENT_RECEIVE:
        // Copy received data to response buffer
        for (UINT32 i = 0; i < Event->RECEIVE.BufferCount; i++) {
            const QUIC_BUFFER* buf = &Event->RECEIVE.Buffers[i];
            UINT32 copyLen = buf->Length;
            if (ctx->ResponseOffset + copyLen > sizeof(ctx->ResponseBuffer)) {
                copyLen = sizeof(ctx->ResponseBuffer) - ctx->ResponseOffset;
            }
            if (copyLen > 0) {
                memcpy(ctx->ResponseBuffer + ctx->ResponseOffset, buf->Buffer, copyLen);
                ctx->ResponseOffset += copyLen;
            }
        }

        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] Received %llu bytes (total: %u)", 
                Event->RECEIVE.TotalBufferLength, ctx->ResponseOffset);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        
        // Get StreamReceiveComplete from API table
        if (g_pQuicApi) {
            StreamReceiveComplete = (QUIC_STREAM_RECEIVE_COMPLETE_FN_REAL)g_pQuicApi->StreamReceiveComplete;
            if (StreamReceiveComplete) {
                StreamReceiveComplete(Stream, Event->RECEIVE.TotalBufferLength);
            }
        }

        // Check for FIN flag (end of response)
        if (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) {
            if (DNS_DebugFlag) {
                SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Received FIN flag, response complete");
            }
            ctx->RecvComplete = TRUE;
            ctx->ResponseLength = ctx->ResponseOffset;
            ctx->Status = QUIC_STATUS_SUCCESS;
            ctx->Completed = TRUE;
            SetEvent(ctx->CompletionEvent);
        }
        break;

    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Peer send shutdown");
        }
        ctx->RecvComplete = TRUE;
        ctx->ResponseLength = ctx->ResponseOffset;
        ctx->Status = QUIC_STATUS_SUCCESS;
        ctx->Completed = TRUE;
        SetEvent(ctx->CompletionEvent);
        break;

    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] Peer send aborted: 0x%llX", 
                Event->PEER_SEND_ABORTED.ErrorCode);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        ctx->Status = QUIC_STATUS_ABORTED;
        ctx->Completed = TRUE;
        SetEvent(ctx->CompletionEvent);
        break;

    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        if (DNS_DebugFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Stream shutdown complete");
        }
        if (!ctx->Completed) {
            ctx->Status = ctx->RecvComplete ? QUIC_STATUS_SUCCESS : QUIC_STATUS_ABORTED;
            ctx->Completed = TRUE;
            SetEvent(ctx->CompletionEvent);
        }
        break;

    default:
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

//---------------------------------------------------------------------------
// DoQ_GetOrCreateConnection - Get or create connection to DoQ server
//---------------------------------------------------------------------------

static DOQ_CONNECTION* DoQ_GetOrCreateConnection(const DOQ_SERVER* server)
{
    DOQ_CONNECTION* conn = NULL;
    QUIC_STATUS status;
    QUIC_SETTINGS settings = { 0 };
    QUIC_CREDENTIAL_CONFIG credConfig = { 0 };
    char hostA[256];
    int len;

    if (!g_pQuicApi || !g_hRegistration)
        return NULL;

    EnterCriticalSection(&g_DoqLock);

    // Look for existing connection
    for (ULONG i = 0; i < g_DoqConnPoolCount; i++) {
        if (_wcsicmp(g_DoqConnPool[i].Host, server->Host) == 0 &&
            g_DoqConnPool[i].Port == server->Port &&
            g_DoqConnPool[i].State == DOQ_STATE_CONNECTED) {
            
            conn = &g_DoqConnPool[i];
            InterlockedIncrement(&conn->RefCount);
            conn->LastUsed = GetTickCount64();
            
            if (DNS_DebugFlag) {
                WCHAR msg[256];
                Sbie_snwprintf(msg, 256, L"[DoQ] Reusing connection to %s:%d", server->Host, server->Port);
                SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
            }
            
            LeaveCriticalSection(&g_DoqLock);
            return conn;
        }
    }

    // Need to create new connection
    if (g_DoqConnPoolCount >= DOQ_MAX_CONNECTIONS) {
        // Pool full - find oldest unused connection
        ULONG oldest = 0;
        ULONGLONG oldestTime = ULLONG_MAX;
        for (ULONG i = 0; i < DOQ_MAX_CONNECTIONS; i++) {
            if (g_DoqConnPool[i].RefCount == 0 && g_DoqConnPool[i].LastUsed < oldestTime) {
                oldest = i;
                oldestTime = g_DoqConnPool[i].LastUsed;
            }
        }
        
        // Close oldest connection
        conn = &g_DoqConnPool[oldest];
        if (conn->Configuration) {
            g_pQuicApi->ConfigurationClose(conn->Configuration);
        }
        if (conn->Connection) {
            g_pQuicApi->ConnectionClose(conn->Connection);
        }
        if (conn->ConnectEvent) {
            CloseHandle(conn->ConnectEvent);
        }
        memset(conn, 0, sizeof(DOQ_CONNECTION));
    } else {
        conn = &g_DoqConnPool[g_DoqConnPoolCount++];
    }

    // Initialize connection entry
    wcsncpy(conn->Host, server->Host, ENCRYPTED_DNS_DOMAIN_MAX_LEN - 1);
    conn->Port = server->Port;
    conn->State = DOQ_STATE_CONNECTING;
    conn->RefCount = 1;
    conn->ConnectEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    // Configure settings
    settings.IdleTimeoutMs = DOQ_IDLE_TIMEOUT_MS;
    settings.IsSet.IdleTimeoutMs = TRUE;
    settings.PeerBidiStreamCount = 100;  // Allow multiple concurrent queries
    settings.IsSet.PeerBidiStreamCount = TRUE;

    // Open configuration with DoQ ALPN
    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DoQ] Opening configuration for %s:%u with ALPN='doq' (%d bytes)", server->Host, server->Port, g_DoqAlpnBuffer.Length);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    status = g_pQuicApi->ConfigurationOpen(
        g_hRegistration,
        &g_DoqAlpnBuffer,
        1,
        &settings,
        sizeof(settings),
        NULL,
        &conn->Configuration);

    if (QUIC_FAILED(status)) {
        if (DNS_TraceFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] ConfigurationOpen failed: 0x%08X", status);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        conn->State = DOQ_STATE_ERROR;
        LeaveCriticalSection(&g_DoqLock);
        return NULL;
    }

    // Load TLS credentials (client mode)
    credConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    credConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    if (server->SelfSigned) {
        credConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Using self-signed mode (no cert validation)");
        }
    }

    if (DNS_TraceFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DoQ] Loading credentials (Type=%d, Flags=0x%08X)", credConfig.Type, credConfig.Flags);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    status = g_pQuicApi->ConfigurationLoadCredential(conn->Configuration, &credConfig);
    if (QUIC_FAILED(status)) {
        if (DNS_TraceFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] ConfigurationLoadCredential failed: 0x%08X", status);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        g_pQuicApi->ConfigurationClose(conn->Configuration);
        conn->Configuration = NULL;
        conn->State = DOQ_STATE_ERROR;
        LeaveCriticalSection(&g_DoqLock);
        return NULL;
    }
    
    if (DNS_TraceFlag) {
        SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Credentials loaded successfully");
    }

    // Open connection
    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DoQ] Calling ConnectionOpen for %s:%u", server->Host, server->Port);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    status = g_pQuicApi->ConnectionOpen(
        g_hRegistration,
        DoQ_ConnectionCallback,
        conn,
        &conn->Connection);

    if (QUIC_FAILED(status)) {
        if (DNS_TraceFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] ConnectionOpen failed: 0x%08X", status);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        g_pQuicApi->ConfigurationClose(conn->Configuration);
        conn->Configuration = NULL;
        conn->State = DOQ_STATE_ERROR;
        LeaveCriticalSection(&g_DoqLock);
        return NULL;
    } else {
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] ConnectionOpen succeeded for %s:%u", server->Host, server->Port);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    }

    // Convert hostname to ANSI
    len = WideCharToMultiByte(CP_UTF8, 0, server->Host, -1, hostA, sizeof(hostA), NULL, NULL);
    if (len == 0) {
        g_pQuicApi->ConnectionClose(conn->Connection);
        g_pQuicApi->ConfigurationClose(conn->Configuration);
        conn->Connection = NULL;
        conn->Configuration = NULL;
        conn->State = DOQ_STATE_ERROR;
        LeaveCriticalSection(&g_DoqLock);
        return NULL;
    }

    // Start connection
    // Note: DoQ is automatically disabled when StrictBindIP is active (see WSA_ShouldDisableQuicProtocols)
    // so this code only runs when QUIC is compatible with the bind configuration
    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DoQ] Calling ConnectionStart: %s:%u", server->Host, server->Port);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    status = g_pQuicApi->ConnectionStart(
        conn->Connection,
        conn->Configuration,
        QUIC_ADDRESS_FAMILY_UNSPEC,  // Let MsQuic use dual-stack
        hostA,
        server->Port);

    if (QUIC_FAILED(status)) {
        if (DNS_TraceFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] ConnectionStart failed: 0x%08X", status);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        g_pQuicApi->ConnectionClose(conn->Connection);
        g_pQuicApi->ConfigurationClose(conn->Configuration);
        conn->Connection = NULL;
        conn->Configuration = NULL;
        conn->State = DOQ_STATE_ERROR;
        LeaveCriticalSection(&g_DoqLock);
        return NULL;
    } else {
        if (DNS_DebugFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] ConnectionStart returned success (0x%08X), waiting for completion", status);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    }

    LeaveCriticalSection(&g_DoqLock);

    // Wait for connection to complete
    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DoQ] Waiting for connection completion (timeout: %d ms)", DOQ_CONNECT_TIMEOUT_MS);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }
    
    DWORD waitResult = WaitForSingleObject(conn->ConnectEvent, DOQ_CONNECT_TIMEOUT_MS);
    if (waitResult != WAIT_OBJECT_0 || conn->State != DOQ_STATE_CONNECTED) {
        if (DNS_TraceFlag || DNS_DebugFlag) {
            WCHAR msg[256];
            const WCHAR* waitResultStr = (waitResult == WAIT_OBJECT_0) ? L"SIGNALED" : 
                                        (waitResult == WAIT_TIMEOUT) ? L"TIMEOUT" : L"FAILED";
            const WCHAR* stateStr = (conn->State == DOQ_STATE_CONNECTED) ? L"CONNECTED" :
                                   (conn->State == DOQ_STATE_CONNECTING) ? L"CONNECTING" :
                                   (conn->State == DOQ_STATE_ERROR) ? L"ERROR" : L"UNKNOWN";
            Sbie_snwprintf(msg, 256, L"[DoQ] Connection to %s:%d failed - WaitResult: %s, State: %s, ConnectStatus: 0x%08X", 
                server->Host, server->Port, waitResultStr, stateStr, conn->ConnectStatus);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        EnterCriticalSection(&g_DoqLock);
        g_pQuicApi->ConnectionClose(conn->Connection);
        g_pQuicApi->ConfigurationClose(conn->Configuration);
        conn->Connection = NULL;
        conn->Configuration = NULL;
        conn->State = DOQ_STATE_ERROR;
        LeaveCriticalSection(&g_DoqLock);
        return NULL;
    }

    if (DNS_TraceFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DoQ] Connected to %s:%d", server->Host, server->Port);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    return conn;
}

//---------------------------------------------------------------------------
// DoQ_ReleaseConnection - Release connection reference
//---------------------------------------------------------------------------

static void DoQ_ReleaseConnection(DOQ_CONNECTION* conn)
{
    if (conn) {
        InterlockedDecrement(&conn->RefCount);
    }
}

//---------------------------------------------------------------------------
// DoQ_BuildDnsQuery - Build DNS wire format query with length prefix and optional EDNS
//---------------------------------------------------------------------------
//
// RFC 1035: Standard DNS query (header + question section)
// RFC 6891: EDNS (OPT record in additional section with DO flag for DNSSEC)
//
// Parameters:
//   has_do_flag: If TRUE, appends EDNS OPT record with DO flag (DNSSEC OK)
//                This signals to upstream server to include RRSIG records
//

static UINT32 DoQ_BuildDnsQuery(const WCHAR* domain, USHORT qtype, BYTE* buffer, UINT32 bufferSize, BOOLEAN has_do_flag)
{
    DNS_WIRE_HEADER* header;
    BYTE* p;
    const WCHAR* label_start;
    UINT32 queryLen;
    static USHORT s_TransactionId = 0;
    UINT32 required_size = DOQ_LENGTH_PREFIX_SIZE + 12 + 4 + 256;

    // Reserve space for EDNS OPT record if needed (1 + 2 + 2 + 4 + 2 = 11 bytes)
    if (has_do_flag)
        required_size += 11;

    if (bufferSize < required_size)
        return 0;

    // Leave space for length prefix
    p = buffer + DOQ_LENGTH_PREFIX_SIZE;
    header = (DNS_WIRE_HEADER*)p;

    // Fill header
    memset(header, 0, sizeof(DNS_WIRE_HEADER));
    header->TransactionID = _htons((USHORT)InterlockedIncrement((LONG*)&s_TransactionId));
    header->Flags = _htons(DNS_FLAG_RD);  // Recursion desired
    header->Questions = _htons(1);
    header->AdditionalRRs = _htons(has_do_flag ? 1 : 0);  // 1 additional record (OPT) if EDNS needed

    p += sizeof(DNS_WIRE_HEADER);

    // Encode domain name (label format)
    label_start = domain;
    while (*label_start) {
        const WCHAR* dot = wcschr(label_start, L'.');
        SIZE_T label_len = dot ? (dot - label_start) : wcslen(label_start);
        
        if (label_len > 63 || label_len == 0) {
            // Invalid label
            if (label_len == 0 && *label_start == L'.') {
                label_start++;
                continue;
            }
            return 0;
        }
        
        *p++ = (BYTE)label_len;
        for (SIZE_T i = 0; i < label_len; i++) {
            *p++ = (BYTE)label_start[i];
        }
        
        if (dot) {
            label_start = dot + 1;
        } else {
            break;
        }
    }
    *p++ = 0;  // Root label

    // QTYPE and QCLASS
    *(USHORT*)p = _htons(qtype);
    p += 2;
    *(USHORT*)p = _htons(1);  // IN class
    p += 2;

    // Append EDNS OPT record if DO flag requested
    if (has_do_flag) {
        *p++ = 0;                          // ROOT name for OPT
        *(USHORT*)p = _htons(41);          // TYPE = OPT
        p += 2;
        *(USHORT*)p = _htons(4096);        // UDP payload size
        p += 2;
        *(UINT32*)p = _htonl(0x00008000); // EDNS version 0, DO flag (bit 15 of flags field) set
        p += 4;
        *(USHORT*)p = _htons(0);           // RDLEN = 0 (no RDATA options)
        p += 2;
    }

    // Calculate total query length (excluding length prefix)
    queryLen = (UINT32)(p - (buffer + DOQ_LENGTH_PREFIX_SIZE));

    // Write length prefix (big-endian)
    buffer[0] = (BYTE)(queryLen >> 8);
    buffer[1] = (BYTE)(queryLen & 0xFF);

    return DOQ_LENGTH_PREFIX_SIZE + queryLen;
}

//---------------------------------------------------------------------------
// DoQ_ParseResponse - Parse DNS wire format response
//---------------------------------------------------------------------------

static BOOLEAN DoQ_ParseResponse(const BYTE* response, UINT32 length, ENCRYPTED_DNS_RESULT* pResult)
{
    const DNS_WIRE_HEADER* header;
    USHORT flags, qdcount, ancount;
    UINT32 offset;
    const BYTE* rawResponse;  // Pointer to raw DNS data (after length prefix)
    UINT32 rawLength;         // Length of raw DNS data

    if (!pResult)
        return FALSE;

    memset(pResult, 0, sizeof(ENCRYPTED_DNS_RESULT));

    // Skip length prefix if present (RFC 9250: 2-byte big-endian length prefix)
    rawResponse = response;
    rawLength = length;
    if (length >= 2) {
        USHORT prefixLen = ((USHORT)response[0] << 8) | response[1];
        if ((UINT32)(prefixLen + 2) <= length) {
            rawResponse = response + 2;
            rawLength = length - 2;
        }
    }

    // Store raw DNS response for non-A/AAAA queries (TXT, MX, SRV, CNAME, etc.)
    // This allows callers to parse any DNS record type from the wire format
    if (rawLength > 0 && rawLength <= ENCRYPTED_DNS_MAX_RAW_RESPONSE) {
        memcpy(pResult->RawResponse, rawResponse, rawLength);
        pResult->RawResponseLen = rawLength;
    }

    if (rawLength < sizeof(DNS_WIRE_HEADER))
        return FALSE;

    header = (const DNS_WIRE_HEADER*)rawResponse;
    flags = _ntohs(header->Flags);
    qdcount = _ntohs(header->Questions);
    ancount = _ntohs(header->AnswerRRs);

    // Check response flag
    if (!DNS_IS_RESPONSE(flags))
        return FALSE;

    // Get RCODE
    pResult->Status = DNS_GET_RCODE(flags);
    pResult->Success = TRUE;

    if (pResult->Status != 0) {
        // Non-zero RCODE (NXDOMAIN, SERVFAIL, etc.)
        return TRUE;
    }

    // Skip question section
    offset = sizeof(DNS_WIRE_HEADER);
    for (USHORT i = 0; i < qdcount && offset < rawLength; i++) {
        // Skip name
        while (offset < rawLength) {
            BYTE labelLen = rawResponse[offset];
            if (labelLen == 0) {
                offset++;
                break;
            } else if ((labelLen & 0xC0) == 0xC0) {
                offset += 2;  // Compression pointer
                break;
            } else {
                offset += 1 + labelLen;
            }
        }
        offset += 4;  // QTYPE + QCLASS
    }

    // Parse answer section
    pResult->AnswerCount = 0;
    for (USHORT i = 0; i < ancount && offset < rawLength && pResult->AnswerCount < 32; i++) {
        USHORT rtype, rclass, rdlength;
        ULONG ttl;

        // Skip name
        while (offset < rawLength) {
            BYTE labelLen = rawResponse[offset];
            if (labelLen == 0) {
                offset++;
                break;
            } else if ((labelLen & 0xC0) == 0xC0) {
                offset += 2;
                break;
            } else {
                offset += 1 + labelLen;
            }
        }

        if (offset + 10 > rawLength)
            break;

        rtype = _ntohs(*(USHORT*)(rawResponse + offset));
        offset += 2;
        rclass = _ntohs(*(USHORT*)(rawResponse + offset));
        offset += 2;
        ttl = _ntohl(*(ULONG*)(rawResponse + offset));
        offset += 4;
        rdlength = _ntohs(*(USHORT*)(rawResponse + offset));
        offset += 2;

        if (offset + rdlength > rawLength)
            break;

        // Store TTL (use minimum from all answers)
        if (pResult->TTL == 0 || ttl < pResult->TTL) {
            pResult->TTL = ttl;
        }

        // Parse A record
        if (rtype == DNS_TYPE_A && rdlength == 4 && rclass == 1) {
            pResult->Answers[pResult->AnswerCount].Type = AF_INET;
            memset(&pResult->Answers[pResult->AnswerCount].IP, 0, sizeof(IP_ADDRESS));
            pResult->Answers[pResult->AnswerCount].IP.Data32[3] = *(DWORD*)(rawResponse + offset);
            pResult->AnswerCount++;
        }
        // Parse AAAA record
        else if (rtype == DNS_TYPE_AAAA && rdlength == 16 && rclass == 1) {
            pResult->Answers[pResult->AnswerCount].Type = AF_INET6;
            memcpy(pResult->Answers[pResult->AnswerCount].IP.Data, rawResponse + offset, 16);
            pResult->AnswerCount++;
        }

        offset += rdlength;
    }

    // Set minimum TTL if none found
    if (pResult->TTL == 0) {
        pResult->TTL = ENCRYPTED_DNS_DEFAULT_TTL;
    }

    return TRUE;
}

//---------------------------------------------------------------------------
// DoQ_Query - Perform DoQ query
//---------------------------------------------------------------------------

_FX BOOLEAN DoQ_Query(
    const DOQ_SERVER* server,
    const WCHAR* domain,
    USHORT qtype,
    ENCRYPTED_DNS_RESULT* pResult)
{
    DOQ_CONNECTION* conn = NULL;
    HQUIC hStream = NULL;
    DOQ_QUERY_CONTEXT ctx = { 0 };
    QUIC_STATUS status;
    QUIC_BUFFER sendBuffer;
    BOOLEAN result = FALSE;
    QUIC_STREAM_OPEN_FN_REAL StreamOpen;
    QUIC_STREAM_START_FN_REAL StreamStart;
    QUIC_STREAM_SEND_FN_REAL StreamSend;
    QUIC_STREAM_SHUTDOWN_FN_REAL StreamShutdown;
    QUIC_STREAM_CLOSE_FN_REAL StreamClose;

    if (!DoQ_IsAvailable() || !server || !domain || !pResult) {
        return FALSE;
    }

    memset(pResult, 0, sizeof(ENCRYPTED_DNS_RESULT));

    // Get function pointers (cast void* to actual types)
    StreamOpen = (QUIC_STREAM_OPEN_FN_REAL)g_pQuicApi->StreamOpen;
    StreamStart = (QUIC_STREAM_START_FN_REAL)g_pQuicApi->StreamStart;
    StreamSend = (QUIC_STREAM_SEND_FN_REAL)g_pQuicApi->StreamSend;
    StreamShutdown = (QUIC_STREAM_SHUTDOWN_FN_REAL)g_pQuicApi->StreamShutdown;
    StreamClose = (QUIC_STREAM_CLOSE_FN_REAL)g_pQuicApi->StreamClose;

    if (!StreamOpen || !StreamStart || !StreamSend || !StreamShutdown || !StreamClose) {
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Stream functions not available");
        }
        return FALSE;
    }

    // Get or create connection
    conn = DoQ_GetOrCreateConnection(server);
    if (!conn || conn->State != DOQ_STATE_CONNECTED) {
        return FALSE;
    }

    // Initialize query context
    ctx.CompletionEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ctx.CompletionEvent) {
        DoQ_ReleaseConnection(conn);
        return FALSE;
    }
    ctx.pResult = pResult;

    // Build DNS query with length prefix and EDNS DO flag (requests RRSIG for DNSSEC-signed domains)
    ctx.QueryLength = DoQ_BuildDnsQuery(domain, qtype, ctx.QueryBuffer, sizeof(ctx.QueryBuffer), TRUE);
    if (ctx.QueryLength == 0) {
        CloseHandle(ctx.CompletionEvent);
        DoQ_ReleaseConnection(conn);
        return FALSE;
    }

    // Open bidirectional stream
    status = StreamOpen(
        conn->Connection,
        QUIC_STREAM_OPEN_FLAG_NONE,
        DoQ_StreamCallback,
        &ctx,
        &hStream);

    if (QUIC_FAILED(status)) {
        if (DNS_TraceFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] StreamOpen failed: 0x%08X", status);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        CloseHandle(ctx.CompletionEvent);
        DoQ_ReleaseConnection(conn);
        return FALSE;
    }

    // Start stream
    status = StreamStart(hStream, QUIC_STREAM_START_FLAG_NONE);
    if (QUIC_FAILED(status)) {
        if (DNS_TraceFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] StreamStart failed: 0x%08X", status);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        StreamClose(hStream);
        CloseHandle(ctx.CompletionEvent);
        DoQ_ReleaseConnection(conn);
        return FALSE;
    }

    // Send query with FIN flag (one query per stream per RFC 9250)
    sendBuffer.Length = ctx.QueryLength;
    sendBuffer.Buffer = ctx.QueryBuffer;
    
    status = StreamSend(
        hStream,
        &sendBuffer,
        1,
        QUIC_SEND_FLAG_FIN,
        NULL);

    if (QUIC_FAILED(status)) {
        if (DNS_TraceFlag) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] StreamSend failed: 0x%08X", status);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
        StreamShutdown(hStream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        StreamClose(hStream);
        CloseHandle(ctx.CompletionEvent);
        DoQ_ReleaseConnection(conn);
        return FALSE;
    }

    if (DNS_DebugFlag) {
        WCHAR msg[256];
        Sbie_snwprintf(msg, 256, L"[DoQ] Sent query for %s (type %d), %u bytes", 
            domain, qtype, ctx.QueryLength);
        SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
    }

    // Wait for response
    DWORD waitResult = WaitForSingleObject(ctx.CompletionEvent, DOQ_QUERY_TIMEOUT_MS);
    
    if (waitResult != WAIT_OBJECT_0 || !ctx.Completed) {
        if (DNS_TraceFlag) {
            SbieApi_MonitorPutMsg(MONITOR_DNS, L"[DoQ] Query timeout");
        }
        StreamShutdown(hStream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    } else if (QUIC_SUCCEEDED(ctx.Status) && ctx.ResponseLength > 0) {
        // Parse response
        result = DoQ_ParseResponse(ctx.ResponseBuffer, ctx.ResponseLength, pResult);
        
        if (DNS_TraceFlag && result) {
            WCHAR msg[256];
            Sbie_snwprintf(msg, 256, L"[DoQ] Query for %s: %d answer(s), TTL=%u", 
                domain, pResult->AnswerCount, pResult->TTL);
            SbieApi_MonitorPutMsg(MONITOR_DNS, msg);
        }
    }

    // Cleanup
    StreamClose(hStream);
    CloseHandle(ctx.CompletionEvent);
    DoQ_ReleaseConnection(conn);

    return result;
}

//---------------------------------------------------------------------------
// DoQ_CloseAllConnections - Close all connections
//---------------------------------------------------------------------------

_FX void DoQ_CloseAllConnections(void)
{
    if (!InterlockedCompareExchange(&g_DoqLockValid, 0, 0))
        return;

    EnterCriticalSection(&g_DoqLock);

    for (ULONG i = 0; i < g_DoqConnPoolCount; i++) {
        if (g_DoqConnPool[i].Configuration && g_pQuicApi) {
            g_pQuicApi->ConfigurationClose(g_DoqConnPool[i].Configuration);
        }
        if (g_DoqConnPool[i].Connection && g_pQuicApi) {
            g_pQuicApi->ConnectionShutdown(
                g_DoqConnPool[i].Connection,
                QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                DOQ_ERROR_NO_ERROR);
            g_pQuicApi->ConnectionClose(g_DoqConnPool[i].Connection);
        }
        if (g_DoqConnPool[i].ConnectEvent) {
            CloseHandle(g_DoqConnPool[i].ConnectEvent);
        }
    }
    g_DoqConnPoolCount = 0;
    memset(g_DoqConnPool, 0, sizeof(g_DoqConnPool));

    LeaveCriticalSection(&g_DoqLock);
}

//---------------------------------------------------------------------------
// DoQ_GetErrorString - Get error string for DoQ error code
//---------------------------------------------------------------------------

_FX const WCHAR* DoQ_GetErrorString(UINT64 errorCode)
{
    switch (errorCode) {
        case DOQ_ERROR_NO_ERROR:
            return L"No error";
        case DOQ_ERROR_INTERNAL_ERROR:
            return L"Internal error";
        case DOQ_ERROR_PROTOCOL_ERROR:
            return L"Protocol error";
        case DOQ_ERROR_REQUEST_CANCELLED:
            return L"Request cancelled";
        case DOQ_ERROR_EXCESSIVE_LOAD:
            return L"Excessive load";
        case DOQ_ERROR_UNSPECIFIED_ERROR:
            return L"Unspecified error";
        default:
            return L"Unknown error";
    }
}
