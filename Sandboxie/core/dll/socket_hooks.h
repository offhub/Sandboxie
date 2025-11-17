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
// Function Prototypes
//---------------------------------------------------------------------------

// Initialize socket hooks (called from WSA_InitNetDnsFilter)
BOOLEAN Socket_InitHooks(HMODULE module);

// Check if FilterRawDns setting is enabled (for external use)
BOOLEAN Socket_GetRawDnsFilterEnabled();

// Mark a socket as DNS connection (for external use by ConnectEx hook)
void Socket_MarkDnsSocket(SOCKET s, BOOLEAN isDns);

#endif // _SOCKET_HOOKS_H
