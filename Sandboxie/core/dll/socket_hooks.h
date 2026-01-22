/*
 * Copyright 2022 David Xanatos, xanasoft.com
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

#ifndef _SOCKET_HOOKS_H
#define _SOCKET_HOOKS_H

//---------------------------------------------------------------------------
// Socket Hooks - Raw DNS Query Interception
//
// This module intercepts raw UDP socket sends to port 53 (DNS) to filter
// DNS queries made by tools that bypass high-level APIs like nslookup.exe
//---------------------------------------------------------------------------

#include <windows.h>

//---------------------------------------------------------------------------
// Forward Declarations (for use in function prototypes)
//---------------------------------------------------------------------------

// Forward declare LIST and DNS_TYPE_FILTER structures
// Full definitions are in common/list.h and dns_filter.h respectively
struct _LIST;
struct _DNS_TYPE_FILTER;

//---------------------------------------------------------------------------
// Function Prototypes
//---------------------------------------------------------------------------

// Initialize socket hooks (called from WSA_InitNetDnsFilter)
BOOLEAN Socket_InitHooks(HMODULE module, BOOLEAN has_valid_certificate);

// Check if FilterRawDns setting is enabled (for external use)
BOOLEAN Socket_GetRawDnsFilterEnabled(BOOLEAN has_valid_certificate);

// Mark a socket as DNS connection (for external use by ConnectEx hook)
void Socket_MarkDnsSocket(SOCKET s, BOOLEAN isDns);

// Track DNS connection (port 53) - called internally and may be useful for external hooks
// Returns TRUE if this is a DNS connection
BOOLEAN Socket_TrackDnsConnectionEx(SOCKET s, const void* name, int namelen);

// Process DNS query in WSASendTo - available for external use if needed
// Returns: 0 = passthrough, >0 = intercepted (return value), <0 = error
int Socket_ProcessWSASendTo(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, const void* lpTo, int iTolen);

// Process DNS response in WSARecvFrom - available for external use if needed
// Returns: 0 = no fake response, >0 = fake response returned
int Socket_ProcessWSARecvFrom(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
    void* lpFrom, LPINT lpFromlen);

// Inject FD_READ in WSAEnumNetworkEvents - available for external use if needed
// Returns TRUE if FD_READ was injected
BOOLEAN Socket_InjectFdRead(SOCKET s, void* lpNetworkEvents);

// DNS packet parsing/building functions (for DnsQueryRaw Phase 2)
BOOLEAN Socket_ParseDnsQuery(
    const BYTE*    packet,
    int            len,
    WCHAR*         domainOut,
    int            domainOutSize,
    USHORT*        qtype);

int Socket_BuildDnsResponse(
    const BYTE*    query,
    int            query_len,
    struct _LIST*  pEntries,
    BOOLEAN        block,
    BYTE*          response,
    int            response_size,
    USHORT         qtype,
    struct _DNS_TYPE_FILTER* type_filter,
    const WCHAR*   domain);

// WSARecvMsg interception for Cygwin UDP recv support
// Called by WSA_WSAIoctl in net.c when WSARecvMsg extension is requested
// Returns: Wrapper function pointer to use instead of real WSARecvMsg
//          Also stores the real WSARecvMsg pointer for later use
void* Socket_GetWSARecvMsgWrapper(void* realWSARecvMsg);

#endif // _SOCKET_HOOKS_H
