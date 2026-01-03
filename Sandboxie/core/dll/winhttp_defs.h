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
// WinHTTP Type Definitions
//
// This header contains WinHTTP function pointer types and constants used
// for API hooking. Separated from dns_doh.c for cleaner organization.
//---------------------------------------------------------------------------

#ifndef _WINHTTP_DEFS_H
#define _WINHTTP_DEFS_H

#include <windows.h>
#include <winhttp.h>

//---------------------------------------------------------------------------
// WinHTTP Function Pointer Types
//---------------------------------------------------------------------------

typedef HINTERNET (WINAPI *P_WinHttpOpen)(
    LPCWSTR pszAgentW,
    DWORD dwAccessType,
    LPCWSTR pszProxyW,
    LPCWSTR pszProxyBypassW,
    DWORD dwFlags
);

typedef HINTERNET (WINAPI *P_WinHttpConnect)(
    HINTERNET hSession,
    LPCWSTR pswzServerName,
    INTERNET_PORT nServerPort,
    DWORD dwReserved
);

typedef HINTERNET (WINAPI *P_WinHttpOpenRequest)(
    HINTERNET hConnect,
    LPCWSTR pwszVerb,
    LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion,
    LPCWSTR pwszReferrer,
    LPCWSTR *ppwszAcceptTypes,
    DWORD dwFlags
);

typedef BOOL (WINAPI *P_WinHttpSendRequest)(
    HINTERNET hRequest,
    LPCWSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength,
    DWORD dwTotalLength,
    DWORD_PTR dwContext
);

typedef BOOL (WINAPI *P_WinHttpReceiveResponse)(
    HINTERNET hRequest,
    LPVOID lpReserved
);

typedef BOOL (WINAPI *P_WinHttpQueryHeaders)(
    HINTERNET hRequest,
    DWORD dwInfoLevel,
    LPCWSTR pwszName,
    LPVOID lpBuffer,
    LPDWORD lpdwBufferLength,
    LPDWORD lpdwIndex
);

typedef BOOL (WINAPI *P_WinHttpReadData)(
    HINTERNET hRequest,
    LPVOID lpBuffer,
    DWORD dwNumberOfBytesToRead,
    LPDWORD lpdwNumberOfBytesRead
);

typedef BOOL (WINAPI *P_WinHttpCloseHandle)(
    HINTERNET hInternet
);

typedef BOOL (WINAPI *P_WinHttpSetOption)(
    HINTERNET hInternet,
    DWORD dwOption,
    LPVOID lpBuffer,
    DWORD dwBufferLength
);

typedef BOOL (WINAPI *P_WinHttpSetTimeouts)(
    HINTERNET hInternet,
    int nResolveTimeout,
    int nConnectTimeout,
    int nSendTimeout,
    int nReceiveTimeout
);

typedef BOOL (WINAPI *P_WinHttpQueryOption)(
    HINTERNET hInternet,
    DWORD dwOption,
    LPVOID lpBuffer,
    LPDWORD lpdwBufferLength
);

//---------------------------------------------------------------------------
// WinHTTP Constants (may not be defined in older SDK versions)
//---------------------------------------------------------------------------

#ifndef WINHTTP_ACCESS_TYPE_DEFAULT_PROXY
#define WINHTTP_ACCESS_TYPE_DEFAULT_PROXY 0
#endif

#ifndef WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY 4
#endif

#ifndef WINHTTP_NO_PROXY_NAME
#define WINHTTP_NO_PROXY_NAME NULL
#endif

#ifndef WINHTTP_NO_PROXY_BYPASS
#define WINHTTP_NO_PROXY_BYPASS NULL
#endif

#ifndef WINHTTP_FLAG_SECURE
#define WINHTTP_FLAG_SECURE 0x00800000
#endif

#ifndef WINHTTP_QUERY_STATUS_CODE
#define WINHTTP_QUERY_STATUS_CODE 19
#endif

#ifndef WINHTTP_QUERY_FLAG_NUMBER
#define WINHTTP_QUERY_FLAG_NUMBER 0x20000000
#endif

#ifndef WINHTTP_OPTION_DECOMPRESSION
#define WINHTTP_OPTION_DECOMPRESSION 118
#endif

#ifndef WINHTTP_DECOMPRESSION_FLAG_GZIP
#define WINHTTP_DECOMPRESSION_FLAG_GZIP 0x00000001
#endif

#ifndef WINHTTP_DECOMPRESSION_FLAG_DEFLATE
#define WINHTTP_DECOMPRESSION_FLAG_DEFLATE 0x00000002
#endif

#ifndef INTERNET_DEFAULT_HTTPS_PORT
#define INTERNET_DEFAULT_HTTPS_PORT 443
#endif

#ifndef INTERNET_OPTION_SECURITY_FLAGS
#define INTERNET_OPTION_SECURITY_FLAGS 31
#endif

#ifndef WINHTTP_OPTION_SECURITY_FLAGS
#define WINHTTP_OPTION_SECURITY_FLAGS 31
#endif

#ifndef SECURITY_FLAG_IGNORE_UNKNOWN_CA
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA 0x00000100
#endif

#ifndef SECURITY_FLAG_IGNORE_CERT_CN_INVALID
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID 0x00001000
#endif

#ifndef SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID 0x00002000
#endif

#ifndef SECURITY_FLAG_IGNORE_REVOCATION
#define SECURITY_FLAG_IGNORE_REVOCATION 0x00000080
#endif

#ifndef WINHTTP_OPTION_ENABLE_FEATURE
#define WINHTTP_OPTION_ENABLE_FEATURE 79
#endif

#ifndef WINHTTP_ENABLE_SSL_REVOCATION
#define WINHTTP_ENABLE_SSL_REVOCATION 0x00000001
#endif

#ifndef INTERNET_OPTION_CONNECT_TIMEOUT
#define INTERNET_OPTION_CONNECT_TIMEOUT 2
#endif

#ifndef INTERNET_OPTION_SEND_TIMEOUT
#define INTERNET_OPTION_SEND_TIMEOUT 5
#endif

#ifndef INTERNET_OPTION_RECEIVE_TIMEOUT
#define INTERNET_OPTION_RECEIVE_TIMEOUT 6
#endif

// HTTP/2 protocol support (Windows 10 1607+)
#ifndef WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL
#define WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL 133
#endif

#ifndef WINHTTP_OPTION_HTTP_PROTOCOL_USED
#define WINHTTP_OPTION_HTTP_PROTOCOL_USED 134
#endif

#ifndef WINHTTP_PROTOCOL_FLAG_HTTP2
#define WINHTTP_PROTOCOL_FLAG_HTTP2 0x1
#endif

#ifndef WINHTTP_PROTOCOL_FLAG_HTTP3
#define WINHTTP_PROTOCOL_FLAG_HTTP3 0x2
#endif

// Additional WinHTTP options for advanced features
#ifndef WINHTTP_OPTION_SECURE_PROTOCOLS
#define WINHTTP_OPTION_SECURE_PROTOCOLS 84
#endif

#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1   0x00000080
#endif

#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 0x00000200
#endif

#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 0x00000800
#endif

#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 0x00002000
#endif

#ifndef WINHTTP_OPTION_IPV6_FAST_FALLBACK
#define WINHTTP_OPTION_IPV6_FAST_FALLBACK 140
#endif

#ifndef WINHTTP_OPTION_DISABLE_STREAM_QUEUE
#define WINHTTP_OPTION_DISABLE_STREAM_QUEUE 139
#endif

#ifndef WINHTTP_OPTION_DISABLE_GLOBAL_POOLING
#define WINHTTP_OPTION_DISABLE_GLOBAL_POOLING 195
#endif

#ifndef WINHTTP_OPTION_TLS_FALSE_START
#define WINHTTP_OPTION_TLS_FALSE_START 154
#endif

#ifndef WINHTTP_OPTION_TCP_FAST_OPEN
#define WINHTTP_OPTION_TCP_FAST_OPEN 153
#endif

#ifndef WINHTTP_OPTION_HTTP3_HANDSHAKE_TIMEOUT
#define WINHTTP_OPTION_HTTP3_HANDSHAKE_TIMEOUT 189
#endif

#ifndef WINHTTP_OPTION_PROXY
#define WINHTTP_OPTION_PROXY 38
#endif

#ifndef WINHTTP_OPTION_DISABLE_SECURE_PROTOCOL_FALLBACK
#define WINHTTP_OPTION_DISABLE_SECURE_PROTOCOL_FALLBACK 144
#endif

#ifndef WINHTTP_OPTION_HTTP_PROTOCOL_REQUIRED
#define WINHTTP_OPTION_HTTP_PROTOCOL_REQUIRED 145
#endif

//---------------------------------------------------------------------------
// WinHTTP Error Codes (for user-friendly error messages)
//---------------------------------------------------------------------------

#ifndef WINHTTP_ERROR_CANNOT_CONNECT
#define WINHTTP_ERROR_CANNOT_CONNECT 12029
#endif

#ifndef WINHTTP_ERROR_TIMEOUT
#define WINHTTP_ERROR_TIMEOUT 12002
#endif

#ifndef WINHTTP_ERROR_CONNECTION_RESET
#define WINHTTP_ERROR_CONNECTION_RESET 12030
#endif

#endif /* _WINHTTP_DEFS_H */
