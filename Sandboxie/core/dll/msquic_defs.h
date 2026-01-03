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
// MsQuic Type Definitions
//
// Minimal type definitions for hooking MsQuic API functions.
// Based on Microsoft MsQuic library (https://github.com/microsoft/msquic)
//
// MsQuic is Microsoft's implementation of the QUIC transport protocol (RFC 9000).
// QUIC provides encrypted, multiplexed transport over UDP, commonly used for
// HTTP/3 connections.
//
// This header provides only the types needed for connection filtering:
//   - MsQuicOpenVersion: Entry point to get API function table
//   - ConnectionStart: Initiates connection to remote server
//   - ConnectionOpen: Creates new connection handle
//
// For full MsQuic documentation, see: https://github.com/microsoft/msquic/tree/main/docs
//---------------------------------------------------------------------------

#ifndef _MSQUIC_DEFS_H
#define _MSQUIC_DEFS_H

#include <windows.h>

// MsQuic uses QUIC_API for its public C API calling convention.
// On Windows user mode (including x86), QUIC_API is __cdecl.
// Using WINAPI (__stdcall) here breaks x86 by corrupting the stack.
#ifndef QUIC_API
#define QUIC_API __cdecl
#endif

//---------------------------------------------------------------------------
// Basic Types (from msquic.h)
//---------------------------------------------------------------------------

// MsQuic handle type - opaque pointer to MsQuic objects
typedef struct QUIC_HANDLE *HQUIC;

// MsQuic status type - compatible with NTSTATUS/HRESULT
typedef LONG QUIC_STATUS;

// Success status
#define QUIC_STATUS_SUCCESS             ((QUIC_STATUS)0)
#define QUIC_STATUS_PENDING             ((QUIC_STATUS)0x703E5)

// Error codes
#define QUIC_STATUS_NOT_SUPPORTED       ((QUIC_STATUS)0xC0000BBB)
#define QUIC_STATUS_INVALID_PARAMETER   ((QUIC_STATUS)0xC0000BCD)
#define QUIC_STATUS_PERMISSION_DENIED   ((QUIC_STATUS)0xC0000022)
#define QUIC_STATUS_ABORTED             ((QUIC_STATUS)0xC0000120)

// Check if status is successful
#define QUIC_SUCCEEDED(Status)          ((QUIC_STATUS)(Status) >= 0)
#define QUIC_FAILED(Status)             ((QUIC_STATUS)(Status) < 0)

// 62-bit integer for QUIC protocol values
typedef UINT64 QUIC_UINT62;

// Address family constants
#define QUIC_ADDRESS_FAMILY_UNSPEC      0
#define QUIC_ADDRESS_FAMILY_INET        2
#define QUIC_ADDRESS_FAMILY_INET6       23

// QUIC address family type
typedef USHORT QUIC_ADDRESS_FAMILY;

// Maximum lengths
#define QUIC_MAX_SNI_LENGTH             65535
#define QUIC_MAX_ALPN_LENGTH            255

//---------------------------------------------------------------------------
// Buffer Structure
//---------------------------------------------------------------------------

typedef struct QUIC_BUFFER {
    UINT32 Length;
    UINT8* Buffer;
} QUIC_BUFFER;

//---------------------------------------------------------------------------
// Registration Configuration
//---------------------------------------------------------------------------

typedef enum QUIC_EXECUTION_PROFILE {
    QUIC_EXECUTION_PROFILE_LOW_LATENCY,
    QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT,
    QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER,
    QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME,
} QUIC_EXECUTION_PROFILE;

typedef struct QUIC_REGISTRATION_CONFIG {
    const char* AppName;
    QUIC_EXECUTION_PROFILE ExecutionProfile;
} QUIC_REGISTRATION_CONFIG;

//---------------------------------------------------------------------------
// Connection Shutdown Flags
//---------------------------------------------------------------------------

typedef enum QUIC_CONNECTION_SHUTDOWN_FLAGS {
    QUIC_CONNECTION_SHUTDOWN_FLAG_NONE      = 0x0000,
    QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT    = 0x0001,
} QUIC_CONNECTION_SHUTDOWN_FLAGS;

//---------------------------------------------------------------------------
// Connection Event Types and Structures
//---------------------------------------------------------------------------

typedef enum QUIC_CONNECTION_EVENT_TYPE {
    QUIC_CONNECTION_EVENT_CONNECTED                         = 0,
    QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT   = 1,
    QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER        = 2,
    QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE                 = 3,
    QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED             = 4,
    QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED              = 5,
    QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED               = 6,
    QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE                 = 7,
    QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS                = 8,
    QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED           = 9,
    QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED            = 10,
    QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED                 = 11,
    QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED       = 12,
    QUIC_CONNECTION_EVENT_RESUMED                           = 13,
    QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED        = 14,
    QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED         = 15,
} QUIC_CONNECTION_EVENT_TYPE;

typedef struct QUIC_CONNECTION_EVENT {
    QUIC_CONNECTION_EVENT_TYPE Type;
    union {
        struct {
            BOOLEAN SessionResumed;
            UINT8 NegotiatedAlpnLength;
            const UINT8* NegotiatedAlpn;
        } CONNECTED;
        struct {
            QUIC_STATUS Status;
            QUIC_UINT62 ErrorCode;
        } SHUTDOWN_INITIATED_BY_TRANSPORT;
        struct {
            QUIC_UINT62 ErrorCode;
        } SHUTDOWN_INITIATED_BY_PEER;
        struct {
            BOOLEAN HandshakeCompleted;
            BOOLEAN PeerAcknowledgedShutdown;
            BOOLEAN AppCloseInProgress;
        } SHUTDOWN_COMPLETE;
        // Other event types omitted - not needed for filtering
    };
} QUIC_CONNECTION_EVENT;

//---------------------------------------------------------------------------
// Callback Function Types
//---------------------------------------------------------------------------

typedef
QUIC_STATUS
(QUIC_API QUIC_CONNECTION_CALLBACK)(
    HQUIC Connection,
    void* Context,
    QUIC_CONNECTION_EVENT* Event
    );

typedef QUIC_CONNECTION_CALLBACK *QUIC_CONNECTION_CALLBACK_HANDLER;

//---------------------------------------------------------------------------
// API Function Pointer Types
//---------------------------------------------------------------------------

// SetContext - Associates application context with handle
typedef
void
(QUIC_API * QUIC_SET_CONTEXT_FN)(
    HQUIC Handle,
    void* Context
    );

// GetContext - Retrieves application context from handle
typedef
void*
(QUIC_API * QUIC_GET_CONTEXT_FN)(
    HQUIC Handle
    );

// SetCallbackHandler - Sets event handler for handle
typedef
void
(QUIC_API * QUIC_SET_CALLBACK_HANDLER_FN)(
    HQUIC Handle,
    void* Handler,
    void* Context
    );

// SetParam - Sets parameter on handle
typedef
QUIC_STATUS
(QUIC_API * QUIC_SET_PARAM_FN)(
    HQUIC Handle,
    UINT32 Param,
    UINT32 BufferLength,
    const void* Buffer
    );

// GetParam - Gets parameter from handle
typedef
QUIC_STATUS
(QUIC_API * QUIC_GET_PARAM_FN)(
    HQUIC Handle,
    UINT32 Param,
    UINT32* BufferLength,
    void* Buffer
    );

// RegistrationOpen - Opens new registration
typedef
QUIC_STATUS
(QUIC_API * QUIC_REGISTRATION_OPEN_FN)(
    const QUIC_REGISTRATION_CONFIG* Config,
    HQUIC* Registration
    );

// RegistrationClose - Closes registration
typedef
void
(QUIC_API * QUIC_REGISTRATION_CLOSE_FN)(
    HQUIC Registration
    );

// RegistrationShutdown - Shuts down all connections in registration
typedef
void
(QUIC_API * QUIC_REGISTRATION_SHUTDOWN_FN)(
    HQUIC Registration,
    QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
    QUIC_UINT62 ErrorCode
    );

// ConfigurationOpen - Opens new configuration
typedef
QUIC_STATUS
(QUIC_API * QUIC_CONFIGURATION_OPEN_FN)(
    HQUIC Registration,
    const QUIC_BUFFER* AlpnBuffers,
    UINT32 AlpnBufferCount,
    const void* Settings,
    UINT32 SettingsSize,
    void* Context,
    HQUIC* Configuration
    );

// ConfigurationClose - Closes configuration
typedef
void
(QUIC_API * QUIC_CONFIGURATION_CLOSE_FN)(
    HQUIC Configuration
    );

// ConfigurationLoadCredential - Loads TLS credentials
typedef
QUIC_STATUS
(QUIC_API * QUIC_CONFIGURATION_LOAD_CREDENTIAL_FN)(
    HQUIC Configuration,
    const void* CredConfig
    );

// ListenerOpen - Opens new listener
typedef
QUIC_STATUS
(QUIC_API * QUIC_LISTENER_OPEN_FN)(
    HQUIC Registration,
    void* Handler,
    void* Context,
    HQUIC* Listener
    );

// ListenerClose - Closes listener
typedef
void
(QUIC_API * QUIC_LISTENER_CLOSE_FN)(
    HQUIC Listener
    );

// ListenerStart - Starts listener
typedef
QUIC_STATUS
(QUIC_API * QUIC_LISTENER_START_FN)(
    HQUIC Listener,
    const QUIC_BUFFER* AlpnBuffers,
    UINT32 AlpnBufferCount,
    const void* LocalAddress
    );

// ListenerStop - Stops listener
typedef
void
(QUIC_API * QUIC_LISTENER_STOP_FN)(
    HQUIC Listener
    );

// ConnectionOpen - Opens new connection
typedef
QUIC_STATUS
(QUIC_API * QUIC_CONNECTION_OPEN_FN)(
    HQUIC Registration,
    QUIC_CONNECTION_CALLBACK_HANDLER Handler,
    void* Context,
    HQUIC* Connection
    );

// ConnectionClose - Closes connection
typedef
void
(QUIC_API * QUIC_CONNECTION_CLOSE_FN)(
    HQUIC Connection
    );

// ConnectionShutdown - Shuts down connection
typedef
void
(QUIC_API * QUIC_CONNECTION_SHUTDOWN_FN)(
    HQUIC Connection,
    QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
    QUIC_UINT62 ErrorCode
    );

// ConnectionStart - Starts connection to remote server (KEY FUNCTION FOR FILTERING)
typedef
QUIC_STATUS
(QUIC_API * QUIC_CONNECTION_START_FN)(
    HQUIC Connection,
    HQUIC Configuration,
    QUIC_ADDRESS_FAMILY Family,
    const char* ServerName,      // The target hostname - what we want to filter
    UINT16 ServerPort            // The target port
    );

// ConnectionSetConfiguration - Sets configuration on accepted connection
typedef
QUIC_STATUS
(QUIC_API * QUIC_CONNECTION_SET_CONFIGURATION_FN)(
    HQUIC Connection,
    HQUIC Configuration
    );

// ConnectionSendResumptionTicket - Sends resumption ticket
typedef
QUIC_STATUS
(QUIC_API * QUIC_CONNECTION_SEND_RESUMPTION_FN)(
    HQUIC Connection,
    UINT32 Flags,
    UINT16 DataLength,
    const UINT8* ResumptionData
    );

// Stream functions (minimal, for table completeness)
typedef void* QUIC_STREAM_OPEN_FN;
typedef void* QUIC_STREAM_CLOSE_FN;
typedef void* QUIC_STREAM_START_FN;
typedef void* QUIC_STREAM_SHUTDOWN_FN;
typedef void* QUIC_STREAM_SEND_FN;
typedef void* QUIC_STREAM_RECEIVE_COMPLETE_FN;
typedef void* QUIC_STREAM_RECEIVE_SET_ENABLED_FN;
typedef void* QUIC_DATAGRAM_SEND_FN;

//---------------------------------------------------------------------------
// API Function Table (QUIC_API_TABLE)
//
// This is the main interface returned by MsQuicOpenVersion.
// Applications get this table and call functions through it.
// We hook MsQuicOpenVersion to return a modified table with our hooks.
//---------------------------------------------------------------------------

typedef struct QUIC_API_TABLE {

    QUIC_SET_CONTEXT_FN                 SetContext;
    QUIC_GET_CONTEXT_FN                 GetContext;
    QUIC_SET_CALLBACK_HANDLER_FN        SetCallbackHandler;

    QUIC_SET_PARAM_FN                   SetParam;
    QUIC_GET_PARAM_FN                   GetParam;

    QUIC_REGISTRATION_OPEN_FN           RegistrationOpen;
    QUIC_REGISTRATION_CLOSE_FN          RegistrationClose;
    QUIC_REGISTRATION_SHUTDOWN_FN       RegistrationShutdown;

    QUIC_CONFIGURATION_OPEN_FN          ConfigurationOpen;
    QUIC_CONFIGURATION_CLOSE_FN         ConfigurationClose;
    QUIC_CONFIGURATION_LOAD_CREDENTIAL_FN
                                        ConfigurationLoadCredential;

    QUIC_LISTENER_OPEN_FN               ListenerOpen;
    QUIC_LISTENER_CLOSE_FN              ListenerClose;
    QUIC_LISTENER_START_FN              ListenerStart;
    QUIC_LISTENER_STOP_FN               ListenerStop;

    QUIC_CONNECTION_OPEN_FN             ConnectionOpen;
    QUIC_CONNECTION_CLOSE_FN            ConnectionClose;
    QUIC_CONNECTION_SHUTDOWN_FN         ConnectionShutdown;
    QUIC_CONNECTION_START_FN            ConnectionStart;      // <-- Key hook point
    QUIC_CONNECTION_SET_CONFIGURATION_FN
                                        ConnectionSetConfiguration;
    QUIC_CONNECTION_SEND_RESUMPTION_FN  ConnectionSendResumptionTicket;

    QUIC_STREAM_OPEN_FN                 StreamOpen;
    QUIC_STREAM_CLOSE_FN                StreamClose;
    QUIC_STREAM_START_FN                StreamStart;
    QUIC_STREAM_SHUTDOWN_FN             StreamShutdown;
    QUIC_STREAM_SEND_FN                 StreamSend;
    QUIC_STREAM_RECEIVE_COMPLETE_FN     StreamReceiveComplete;
    QUIC_STREAM_RECEIVE_SET_ENABLED_FN  StreamReceiveSetEnabled;

    QUIC_DATAGRAM_SEND_FN               DatagramSend;

    // v2.2+ fields
    void*                               ConnectionResumptionTicketValidationComplete;
    void*                               ConnectionCertificateValidationComplete;

    // v2.5+ fields
    void*                               ConnectionOpenInPartition;

} QUIC_API_TABLE;

//---------------------------------------------------------------------------
// MsQuic Entry Point Function Types
//---------------------------------------------------------------------------

// MsQuicOpenVersion - Main entry point to get API table
typedef
QUIC_STATUS
(QUIC_API *P_MsQuicOpenVersion)(
    UINT32 Version,
    const void** QuicApi     // Returns QUIC_API_TABLE*
    );

// MsQuicClose - Releases API table reference
typedef
void
(QUIC_API *P_MsQuicClose)(
    const void* QuicApi
    );

// API version constants
#define QUIC_API_VERSION_2      2

#endif /* _MSQUIC_DEFS_H */
