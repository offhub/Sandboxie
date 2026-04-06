/*
 * Copyright 2025-2026 David Xanatos, xanasoft.com
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
// Trust Hooks - Code Signing Verification Bypass
//
// Implements forced code-signing trust for sandboxed processes. When a file
// path matches a VerifyTrustFile rule, WinVerifyTrust calls are intercepted
// and made to succeed regardless of the actual signature state.
//
// Hooks installed from crypt32.dll (via Trust_Crypt_Init):
//   - CertVerifyCertificateChainPolicy
//   - CryptQueryObject
//   - CryptMsgGetParam
//   - CryptMsgClose
//
// Hooks installed from wintrust.dll (via Trust_Init):
//   - WinVerifyTrust
//   - WinVerifyTrustEx
//   - WTHelperProvDataFromStateData
//   - WTHelperGetProvSignerFromChain
//   - WTHelperGetProvCertFromChain
//   - WTHelperCertCheckValidSignature
//
// Configuration (Sandboxie.ini):
//   VerifyTrustFile=[process,]path_or_wildcard
//     - One or more entries; matching file paths get forced-trust.
//     - Wildcards (* and ?) are matched against full path and filename.
//
// Entry points:
//   Trust_Crypt_Init(HMODULE) - installs crypt32.dll hooks, called by Crypt_Init
//   Trust_Init(HMODULE)       - installs wintrust.dll hooks, public entry point
//---------------------------------------------------------------------------


//---------------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------------


#include "dll.h"

#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <stdarg.h>
#include <wctype.h>


//---------------------------------------------------------------------------
// Macros
//---------------------------------------------------------------------------


#define CRYPT_TRUST_RULE_MAX   32
#define CRYPT_TRUST_RULE_LEN   260
#define CRYPT_PROXY_MSG_MAX    16
#define CRYPT_FORCED_STATE_MAX 32
#define CRYPT_STRUCT_FIELD_END(type, field) \
    (FIELD_OFFSET(type, field) + sizeof(((type *)0)->field))

#if defined(_DEBUG) || defined(_CRYPTDEBUG)
#define CRYPT_REDACT(p)  ((void *)(ULONG_PTR)(p))
#else
#define CRYPT_REDACT(p)  ((void *)((ULONG_PTR)(p) & 0xFFFF))
#endif


//---------------------------------------------------------------------------
// Forward Declarations
//---------------------------------------------------------------------------


static void Crypt_InitTrustRules(void);
static BOOLEAN Crypt_HasTrustRules(void);
static LONG Crypt_GetForceChainPolicyDepth(void);
static void Crypt_EnterForceChainPolicy(void);
static void Crypt_LeaveForceChainPolicy(void);
static void *Crypt_GetCallerAddress(void);
static void Crypt_Trace(const WCHAR *fmt, ...);
static BOOLEAN Crypt_GetWinTrustUnionChoice(
    const WINTRUST_DATA *pWinTrustData, DWORD *pUnionChoice);
static BOOLEAN Crypt_GetWinTrustStateAction(
    const WINTRUST_DATA *pWinTrustData, DWORD *pStateAction);
static BOOLEAN Crypt_GetWinTrustStateHandle(
    const WINTRUST_DATA *pWinTrustData, HANDLE *pStateHandle);
static BOOLEAN Crypt_SetWinTrustStateHandle(
    WINTRUST_DATA *pWinTrustData, HANDLE hStateHandle);
static BOOLEAN Crypt_GetProviderWinTrustData(
    const CRYPT_PROVIDER_DATA *pProvData,
    const WINTRUST_DATA **ppWinTrustData);
static BOOLEAN Crypt_HasProviderSignerErrorField(
    const CRYPT_PROVIDER_SGNR *pProvSigner);
static BOOLEAN Crypt_GetProviderSignerCertChain(
    const CRYPT_PROVIDER_SGNR *pProvSigner,
    CRYPT_PROVIDER_CERT **ppCertChain, DWORD *pcCertChain);
static BOOLEAN Crypt_SetProviderSignerCertChain(
    CRYPT_PROVIDER_SGNR *pProvSigner,
    CRYPT_PROVIDER_CERT *pCertChain, DWORD cCertChain);
static const WCHAR *Crypt_GetWinTrustFilePath(
    const WINTRUST_DATA *pWinTrustData);
static BOOLEAN Crypt_ShouldForceTrustForPath(const WCHAR *path);
static BOOLEAN Crypt_ShouldForceTrustForData(const WINTRUST_DATA *pWinTrustData);
static void Crypt_FreeQueryObjectContext(DWORD contentType, const void *pvContext);
static LONG Crypt_WinVerifyTrust(
    HWND hwnd, GUID *pgActionID, WINTRUST_DATA *pWinTrustData);
static LONG Crypt_WinVerifyTrustEx(
    HWND hwnd, GUID *pgActionID, WINTRUST_DATA *pWinTrustData);
static CRYPT_PROVIDER_DATA *Crypt_WTHelperProvDataFromStateData(
    HANDLE hStateData);
static CRYPT_PROVIDER_SGNR *Crypt_WTHelperGetProvSignerFromChain(
    CRYPT_PROVIDER_DATA *pProvData,
    DWORD idxSigner, BOOL fCounterSigner, DWORD idxCounterSigner);
static CRYPT_PROVIDER_CERT *Crypt_WTHelperGetProvCertFromChain(
    CRYPT_PROVIDER_SGNR *pSgnr, DWORD idxCert);
static HRESULT Crypt_WTHelperCertCheckValidSignature(
    CRYPT_PROVIDER_DATA *pProvData);
static void Crypt_InitFakeProviderState(void);
static void Crypt_SanitizeForcedProviderData(
    CRYPT_PROVIDER_DATA *pProvData, HANDLE hStateData, BOOLEAN trace);
static void Crypt_RestoreForcedProviderData(CRYPT_PROVIDER_DATA *pProvData);
static HANDLE Crypt_GetFakeStateHandle(void);
static BOOLEAN Crypt_RememberForcedTrustState(HANDLE hStateData);
static void Crypt_ForgetForcedTrustState(HANDLE hStateData);
static BOOLEAN Crypt_IsForcedTrustState(HANDLE hStateData);

#if defined(_DEBUG) || defined(_CRYPTDEBUG)
static DWORD Crypt_SearchPathW(
    LPCWSTR lpPath, LPCWSTR lpFileName, LPCWSTR lpExtension,
    DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart);
#endif


//---------------------------------------------------------------------------
// Function Pointer Types
//---------------------------------------------------------------------------


typedef LONG (WINAPI *P_WinVerifyTrust)(HWND, GUID *, WINTRUST_DATA *);
static P_WinVerifyTrust __sys_WinVerifyTrust = NULL;

typedef LONG (WINAPI *P_WinVerifyTrustEx)(HWND, GUID *, WINTRUST_DATA *);
static P_WinVerifyTrustEx __sys_WinVerifyTrustEx = NULL;

typedef CRYPT_PROVIDER_DATA * (WINAPI *P_WTHelperProvDataFromStateData)(HANDLE);
static P_WTHelperProvDataFromStateData __sys_WTHelperProvDataFromStateData = NULL;

typedef CRYPT_PROVIDER_SGNR * (WINAPI *P_WTHelperGetProvSignerFromChain)(
    CRYPT_PROVIDER_DATA *, DWORD, BOOL, DWORD);
static P_WTHelperGetProvSignerFromChain __sys_WTHelperGetProvSignerFromChain = NULL;

typedef CRYPT_PROVIDER_CERT * (WINAPI *P_WTHelperGetProvCertFromChain)(
    CRYPT_PROVIDER_SGNR *, DWORD);
static P_WTHelperGetProvCertFromChain __sys_WTHelperGetProvCertFromChain = NULL;

typedef HRESULT (WINAPI *P_WTHelperCertCheckValidSignature)(CRYPT_PROVIDER_DATA *);
static P_WTHelperCertCheckValidSignature __sys_WTHelperCertCheckValidSignature = NULL;

typedef BOOL (*P_CertVerifyCertificateChainPolicy)(
    LPCSTR pszPolicyOID,
    PCCERT_CHAIN_CONTEXT pChainContext,
    PCERT_CHAIN_POLICY_PARA pPolicyPara,
    PCERT_CHAIN_POLICY_STATUS pPolicyStatus);
static P_CertVerifyCertificateChainPolicy __sys_CertVerifyCertificateChainPolicy = NULL;

typedef BOOL (WINAPI *P_CryptQueryObject)(
    DWORD dwObjectType, const void *pvObject,
    DWORD dwExpectedContentTypeFlags, DWORD dwExpectedFormatTypeFlags,
    DWORD dwFlags, DWORD *pdwMsgAndCertEncodingType, DWORD *pdwContentType,
    DWORD *pdwFormatType, HCERTSTORE *phCertStore,
    HCRYPTMSG *phMsg, const void **ppvContext);
static P_CryptQueryObject __sys_CryptQueryObject = NULL;

typedef BOOL (WINAPI *P_CryptMsgGetParam)(
    HCRYPTMSG hCryptMsg, DWORD dwParamType, DWORD dwIndex,
    void *pvData, DWORD *pcbData);
static P_CryptMsgGetParam __sys_CryptMsgGetParam = NULL;

typedef BOOL (WINAPI *P_CryptMsgClose)(HCRYPTMSG hCryptMsg);
static P_CryptMsgClose __sys_CryptMsgClose = NULL;

#if defined(_DEBUG) || defined(_CRYPTDEBUG)
typedef DWORD (WINAPI *P_SearchPathW)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPWSTR, LPWSTR *);
static P_SearchPathW __sys_SearchPathW = NULL;
#endif


//---------------------------------------------------------------------------
// Variables
//---------------------------------------------------------------------------


static volatile LONG Crypt_TrustRuleInit = 0;
static ULONG Crypt_TrustRuleCount = 0;
static WCHAR Crypt_TrustRules[CRYPT_TRUST_RULE_MAX][CRYPT_TRUST_RULE_LEN] = { 0 };
static const WCHAR Crypt_TraceTag[] = L"[Crypt] ";
static volatile ULONG_PTR Crypt_ProxyMsgHandles[CRYPT_PROXY_MSG_MAX] = { 0 };
static ULONG_PTR Crypt_FakeStateMarker = 0xC47A1001;
static ULONG_PTR Crypt_ForcedTrustStates[CRYPT_FORCED_STATE_MAX] = { 0 };
static CRYPT_PROVIDER_DATA Crypt_FakeProviderData = { 0 };
static CRYPT_PROVIDER_SGNR Crypt_FakeProviderSigner = { 0 };
static CRYPT_PROVIDER_CERT Crypt_FakeProviderCert = { 0 };
static PVOID Crypt_FakeCertContextPtr = NULL;


//---------------------------------------------------------------------------
// Crypt_GetForceChainPolicyDepth
//---------------------------------------------------------------------------


static LONG Crypt_GetForceChainPolicyDepth(void)
{
    THREAD_DATA *data = Dll_GetTlsData(NULL);

    if (!data)
        return 0;

    return (LONG)data->crypt_force_chain_policy_depth;
}


//---------------------------------------------------------------------------
// Crypt_EnterForceChainPolicy
//---------------------------------------------------------------------------


static void Crypt_EnterForceChainPolicy(void)
{
    THREAD_DATA *data = Dll_GetTlsData(NULL);

    if (data)
        ++data->crypt_force_chain_policy_depth;
}


//---------------------------------------------------------------------------
// Crypt_LeaveForceChainPolicy
//---------------------------------------------------------------------------


static void Crypt_LeaveForceChainPolicy(void)
{
    THREAD_DATA *data = Dll_GetTlsData(NULL);

    if (data && data->crypt_force_chain_policy_depth > 0)
        --data->crypt_force_chain_policy_depth;
}


//---------------------------------------------------------------------------
// Crypt_RememberProxyMsgHandle
//---------------------------------------------------------------------------


static BOOLEAN Crypt_RememberProxyMsgHandle(HCRYPTMSG hCryptMsg)
{
    ULONG i;
    ULONG_PTR value;

    if (!hCryptMsg)
        return FALSE;

    value = (ULONG_PTR)hCryptMsg;

    for (i = 0; i < sizeof(Crypt_ProxyMsgHandles) / sizeof(Crypt_ProxyMsgHandles[0]); ++i) {
        ULONG_PTR current = (ULONG_PTR)InterlockedCompareExchangePointer(
            (PVOID volatile *)&Crypt_ProxyMsgHandles[i], NULL, NULL);

        if (InterlockedCompareExchangePointer(
                (PVOID volatile *)&Crypt_ProxyMsgHandles[i],
                (PVOID)value, NULL) == NULL)
            return TRUE;
        if (current == value)
            return TRUE;
    }

    return FALSE;
}


//---------------------------------------------------------------------------
// Crypt_ForgetProxyMsgHandle
//---------------------------------------------------------------------------


static void Crypt_ForgetProxyMsgHandle(HCRYPTMSG hCryptMsg)
{
    ULONG i;
    ULONG_PTR value;

    if (!hCryptMsg)
        return;

    value = (ULONG_PTR)hCryptMsg;

    for (i = 0; i < sizeof(Crypt_ProxyMsgHandles) / sizeof(Crypt_ProxyMsgHandles[0]); ++i) {
        if ((ULONG_PTR)InterlockedCompareExchangePointer(
                (PVOID volatile *)&Crypt_ProxyMsgHandles[i], NULL, NULL) == value) {
            InterlockedExchangePointer((PVOID volatile *)&Crypt_ProxyMsgHandles[i], NULL);
            return;
        }
    }
}


//---------------------------------------------------------------------------
// Crypt_IsProxyMsgHandle
//---------------------------------------------------------------------------


static BOOLEAN Crypt_IsProxyMsgHandle(HCRYPTMSG hCryptMsg)
{
    ULONG i;
    ULONG_PTR value;

    if (!hCryptMsg)
        return FALSE;

    value = (ULONG_PTR)hCryptMsg;

    for (i = 0; i < sizeof(Crypt_ProxyMsgHandles) / sizeof(Crypt_ProxyMsgHandles[0]); ++i) {
        if ((ULONG_PTR)InterlockedCompareExchangePointer(
            (PVOID volatile *)&Crypt_ProxyMsgHandles[i], NULL, NULL) == value)
            return TRUE;
    }

    return FALSE;
}


//---------------------------------------------------------------------------
// Crypt_RedactUsers
//---------------------------------------------------------------------------


#if !defined(_DEBUG) && !defined(_CRYPTDEBUG)
static void Crypt_RedactUsers(WCHAR *msg, size_t msg_count)
{
    static const WCHAR repl[] = L"user";
    const ULONG repl_len = 4;
    WCHAR *p = msg;

    while (*p) {
        if (p[0] == L'\\'
                && (p[1] == L'U' || p[1] == L'u')
                && (p[2] == L's' || p[2] == L'S')
                && (p[3] == L'e' || p[3] == L'E')
                && (p[4] == L'r' || p[4] == L'R')
                && (p[5] == L's' || p[5] == L'S')
                && p[6] == L'\\') {
            WCHAR *ustart = p + 7;
            WCHAR *uend = ustart;
            while (*uend && *uend != L'\\')
                ++uend;
            if (uend > ustart) {
                ULONG old_len = (ULONG)(uend - ustart);
                ULONG i;
                for (i = 0; i < repl_len; ++i)
                    ustart[i] = repl[i];
                if (old_len >= repl_len) {
                    WCHAR *dst = ustart + repl_len;
                    WCHAR *src = uend;
                    while (*src)
                        *dst++ = *src++;
                    *dst = L'\0';
                } else {
                    WCHAR *dst = ustart + repl_len;
                    WCHAR *src = uend;
                    size_t tail = 0, avail;
                    const WCHAR *s = src;
                    while (*s++)
                        ++tail;
                    avail = msg_count - (size_t)(dst - msg) - 1;
                    if (tail > avail)
                        tail = avail;
                    {
                        WCHAR *de = dst + tail;
                        const WCHAR *se = src + tail;
                        *de = L'\0';
                        while (se > src) {
                            --se;
                            --de;
                            *de = *se;
                        }
                    }
                }
                p = ustart + repl_len;
                continue;
            }
        }
        ++p;
    }
}
#endif


//---------------------------------------------------------------------------
// Crypt_Trace
//---------------------------------------------------------------------------


static void Crypt_Trace(const WCHAR *fmt, ...)
{
    WCHAR msg[1024];
    size_t msg_count = sizeof(msg) / sizeof(msg[0]);
    static const WCHAR fmt_fail[] = L"trace format failed";
    va_list args;
    int rc;
    ULONG i;

    extern int (__cdecl *P_vsnwprintf)(wchar_t *_Buffer, size_t Count, const wchar_t * const, va_list Args);

    if (!P_vsnwprintf)
        return;

    for (i = 0; i < msg_count; ++i)
        msg[i] = L'\0';

    for (i = 0; i < sizeof(Crypt_TraceTag) / sizeof(Crypt_TraceTag[0]) - 1; ++i)
        msg[i] = Crypt_TraceTag[i];

    va_start(args, fmt);
    rc = P_vsnwprintf(msg + (sizeof(Crypt_TraceTag) / sizeof(Crypt_TraceTag[0]) - 1),
        msg_count - (sizeof(Crypt_TraceTag) / sizeof(Crypt_TraceTag[0])), fmt, args);
    va_end(args);

    if (rc < 0) {
        size_t dst = sizeof(Crypt_TraceTag) / sizeof(Crypt_TraceTag[0]) - 1;
        size_t src = 0;
        while (dst + 1 < msg_count && fmt_fail[src])
            msg[dst++] = fmt_fail[src++];
        msg[dst] = L'\0';
    }

    msg[msg_count - 1] = L'\0';
#if !defined(_DEBUG) && !defined(_CRYPTDEBUG)
    Crypt_RedactUsers(msg, msg_count);
#endif
    SbieApi_MonitorPutMsg(MONITOR_OTHER | MONITOR_TRACE, msg);
}


//---------------------------------------------------------------------------
// Crypt_HasTrustRules
//---------------------------------------------------------------------------


static BOOLEAN Crypt_HasTrustRules(void)
{
    Crypt_InitTrustRules();
    return (Crypt_TrustRuleCount > 0);
}


//---------------------------------------------------------------------------
// Crypt_GetWinTrustUnionChoice
//---------------------------------------------------------------------------


static BOOLEAN Crypt_GetWinTrustUnionChoice(
    const WINTRUST_DATA *pWinTrustData, DWORD *pUnionChoice)
{
    if (!pWinTrustData || !pUnionChoice
            || pWinTrustData->cbStruct < CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, dwUnionChoice))
        return FALSE;

    *pUnionChoice = pWinTrustData->dwUnionChoice;
    return TRUE;
}


//---------------------------------------------------------------------------
// Crypt_GetWinTrustStateAction
//---------------------------------------------------------------------------


static BOOLEAN Crypt_GetWinTrustStateAction(
    const WINTRUST_DATA *pWinTrustData, DWORD *pStateAction)
{
    if (!pWinTrustData || !pStateAction
            || pWinTrustData->cbStruct < CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, dwStateAction))
        return FALSE;

    *pStateAction = pWinTrustData->dwStateAction;
    return TRUE;
}


//---------------------------------------------------------------------------
// Crypt_GetWinTrustStateHandle
//---------------------------------------------------------------------------


static BOOLEAN Crypt_GetWinTrustStateHandle(
    const WINTRUST_DATA *pWinTrustData, HANDLE *pStateHandle)
{
    if (!pWinTrustData || !pStateHandle
            || pWinTrustData->cbStruct < CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, hWVTStateData))
        return FALSE;

    *pStateHandle = pWinTrustData->hWVTStateData;
    return TRUE;
}


//---------------------------------------------------------------------------
// Crypt_SetWinTrustStateHandle
//---------------------------------------------------------------------------


static BOOLEAN Crypt_SetWinTrustStateHandle(
    WINTRUST_DATA *pWinTrustData, HANDLE hStateHandle)
{
    if (!pWinTrustData
            || pWinTrustData->cbStruct < CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, hWVTStateData))
        return FALSE;

    pWinTrustData->hWVTStateData = hStateHandle;
    return TRUE;
}


//---------------------------------------------------------------------------
// Crypt_GetProviderWinTrustData
//---------------------------------------------------------------------------


static BOOLEAN Crypt_GetProviderWinTrustData(
    const CRYPT_PROVIDER_DATA *pProvData,
    const WINTRUST_DATA **ppWinTrustData)
{
    if (!pProvData || !ppWinTrustData
            || pProvData->cbStruct < CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, pWintrustData))
        return FALSE;

    *ppWinTrustData = pProvData->pWintrustData;
    return TRUE;
}


//---------------------------------------------------------------------------
// Crypt_HasProviderSignerErrorField
//---------------------------------------------------------------------------


static BOOLEAN Crypt_HasProviderSignerErrorField(
    const CRYPT_PROVIDER_SGNR *pProvSigner)
{
    if (!pProvSigner
            || pProvSigner->cbStruct < CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_SGNR, dwError))
        return FALSE;

    return TRUE;
}


//---------------------------------------------------------------------------
// Crypt_GetProviderSignerCertChain
//---------------------------------------------------------------------------


static BOOLEAN Crypt_GetProviderSignerCertChain(
    const CRYPT_PROVIDER_SGNR *pProvSigner,
    CRYPT_PROVIDER_CERT **ppCertChain, DWORD *pcCertChain)
{
    if (!pProvSigner || !ppCertChain || !pcCertChain
            || pProvSigner->cbStruct < CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_SGNR, pasCertChain)
            || pProvSigner->cbStruct < CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_SGNR, csCertChain))
        return FALSE;

    *ppCertChain = pProvSigner->pasCertChain;
    *pcCertChain = pProvSigner->csCertChain;
    return TRUE;
}


//---------------------------------------------------------------------------
// Crypt_SetProviderSignerCertChain
//---------------------------------------------------------------------------


static BOOLEAN Crypt_SetProviderSignerCertChain(
    CRYPT_PROVIDER_SGNR *pProvSigner,
    CRYPT_PROVIDER_CERT *pCertChain, DWORD cCertChain)
{
    if (!pProvSigner
            || pProvSigner->cbStruct < CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_SGNR, pasCertChain)
            || pProvSigner->cbStruct < CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_SGNR, csCertChain))
        return FALSE;

    pProvSigner->pasCertChain = pCertChain;
    pProvSigner->csCertChain = cCertChain;
    return TRUE;
}


//---------------------------------------------------------------------------
// Crypt_GetWinTrustFilePath
//---------------------------------------------------------------------------


static const WCHAR *Crypt_GetWinTrustFilePath(
    const WINTRUST_DATA *pWinTrustData)
{
    DWORD union_choice;
    WINTRUST_FILE_INFO *pFile;

    if (!Crypt_GetWinTrustUnionChoice(pWinTrustData, &union_choice)
            || union_choice != WTD_CHOICE_FILE)
        return NULL;

    if (pWinTrustData->cbStruct < CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, pFile)
            || !pWinTrustData->pFile)
        return NULL;

    pFile = pWinTrustData->pFile;

    if (pFile->cbStruct < CRYPT_STRUCT_FIELD_END(WINTRUST_FILE_INFO, pcwszFilePath))
        return NULL;

    return pFile->pcwszFilePath;
}


//---------------------------------------------------------------------------
// Crypt_WildcardMatchNoCase
//---------------------------------------------------------------------------


static BOOLEAN Crypt_WildcardMatchNoCase(const WCHAR *pattern, const WCHAR *text)
{
    const WCHAR *star = NULL;
    const WCHAR *star_text = NULL;

    if (!pattern || !text)
        return FALSE;

    while (*text) {
        WCHAR pc = *pattern;
        WCHAR tc = *text;

        if (pc == L'*') {
            star = ++pattern;
            star_text = text;
            continue;
        }

        if (pc == L'?' || towlower(pc) == towlower(tc)) {
            ++pattern;
            ++text;
            continue;
        }

        if (star) {
            pattern = star;
            text = ++star_text;
            continue;
        }

        return FALSE;
    }

    while (*pattern == L'*')
        ++pattern;

    return (*pattern == L'\0');
}


//---------------------------------------------------------------------------
// Crypt_MatchTrustFixPath
//---------------------------------------------------------------------------


static BOOLEAN Crypt_MatchTrustFixPath(const WCHAR *rule, const WCHAR *path)
{
    const WCHAR *base;

    if (!rule || !*rule || !path || !*path)
        return FALSE;

    base = wcsrchr(path, L'\\');
    if (!base)
        base = path;
    else
        ++base;

    return Crypt_WildcardMatchNoCase(rule, path)
        || Crypt_WildcardMatchNoCase(rule, base);
}


//---------------------------------------------------------------------------
// Crypt_InitTrustRules
//---------------------------------------------------------------------------


static void Crypt_InitTrustRules(void)
{
    WCHAR conf_buf[2048];
    ULONG index;
    ULONG count;
    LONG init_state;

    init_state = InterlockedCompareExchange(&Crypt_TrustRuleInit, 1, 0);
    if (init_state == 2)
        return;
    if (init_state == 1) {
        while (InterlockedCompareExchange(&Crypt_TrustRuleInit, 2, 2) != 2)
            SwitchToThread();
        return;
    }

    count = 0;
    index = 0;

    while (count < CRYPT_TRUST_RULE_MAX) {
        WCHAR *value;
        NTSTATUS status = SbieApi_QueryConf(
            NULL, L"VerifyTrustFile", index,
            conf_buf, sizeof(conf_buf) - 16 * sizeof(WCHAR));
        if (!NT_SUCCESS(status))
            break;
        ++index;

        value = Config_MatchImageAndGetValue(conf_buf, Dll_ImageName, NULL);
        if (value && *value) {
            wcsncpy(Crypt_TrustRules[count], value, CRYPT_TRUST_RULE_LEN - 1);
            Crypt_TrustRules[count][CRYPT_TRUST_RULE_LEN - 1] = L'\0';
            ++count;
        }
    }

    Crypt_TrustRuleCount = count;
    InterlockedExchange(&Crypt_TrustRuleInit, 2);
}


//---------------------------------------------------------------------------
// Crypt_ShouldForceTrustForPath
//---------------------------------------------------------------------------


static BOOLEAN Crypt_ShouldForceTrustForPath(const WCHAR *path)
{
    ULONG i;

    if (!path || !*path)
        return FALSE;

    Crypt_InitTrustRules();

    for (i = 0; i < Crypt_TrustRuleCount; ++i) {
        if (Crypt_MatchTrustFixPath(Crypt_TrustRules[i], path))
            return TRUE;
    }

    return FALSE;
}


//---------------------------------------------------------------------------
// Crypt_ShouldForceTrustForData
//---------------------------------------------------------------------------


static BOOLEAN Crypt_ShouldForceTrustForData(const WINTRUST_DATA *pWinTrustData)
{
    return Crypt_ShouldForceTrustForPath(
        Crypt_GetWinTrustFilePath(pWinTrustData));
}


//---------------------------------------------------------------------------
// Crypt_FreeQueryObjectContext
//---------------------------------------------------------------------------


static void Crypt_FreeQueryObjectContext(DWORD contentType, const void *pvContext)
{
    HMODULE hCrypt32;

    if (!pvContext)
        return;

    hCrypt32 = GetModuleHandleW(L"crypt32.dll");

    switch (contentType) {
    case CERT_QUERY_CONTENT_CERT:
    case CERT_QUERY_CONTENT_SERIALIZED_CERT:
    case CERT_QUERY_CONTENT_CERT_PAIR:
        if (hCrypt32) {
            typedef BOOL (WINAPI *P_CertFreeCertificateContext)(PCCERT_CONTEXT);
            P_CertFreeCertificateContext pfnCertFreeCertificateContext =
                (P_CertFreeCertificateContext)GetProcAddress(hCrypt32, "CertFreeCertificateContext");
            if (pfnCertFreeCertificateContext)
                pfnCertFreeCertificateContext((PCCERT_CONTEXT)pvContext);
        }
        break;

    case CERT_QUERY_CONTENT_CTL:
    case CERT_QUERY_CONTENT_SERIALIZED_CTL:
        if (hCrypt32) {
            typedef BOOL (WINAPI *P_CertFreeCTLContext)(PCCTL_CONTEXT);
            P_CertFreeCTLContext pfnCertFreeCTLContext =
                (P_CertFreeCTLContext)GetProcAddress(hCrypt32, "CertFreeCTLContext");
            if (pfnCertFreeCTLContext)
                pfnCertFreeCTLContext((PCCTL_CONTEXT)pvContext);
        }
        break;

    case CERT_QUERY_CONTENT_CRL:
    case CERT_QUERY_CONTENT_SERIALIZED_CRL:
        if (hCrypt32) {
            typedef BOOL (WINAPI *P_CertFreeCRLContext)(PCCRL_CONTEXT);
            P_CertFreeCRLContext pfnCertFreeCRLContext =
                (P_CertFreeCRLContext)GetProcAddress(hCrypt32, "CertFreeCRLContext");
            if (pfnCertFreeCRLContext)
                pfnCertFreeCRLContext((PCCRL_CONTEXT)pvContext);
        }
        break;

    case CERT_QUERY_CONTENT_PKCS7_SIGNED:
    case CERT_QUERY_CONTENT_PKCS7_UNSIGNED:
    case CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED:
        LocalFree((HLOCAL)pvContext);
        break;

    default:
        break;
    }
}


//---------------------------------------------------------------------------
// Crypt_IsAddressInSbieDll
//---------------------------------------------------------------------------


static BOOLEAN Crypt_IsAddressInSbieDll(const void *addr)
{
    MEMORY_BASIC_INFORMATION mbi_addr;
    MEMORY_BASIC_INFORMATION mbi_self;

    if (!addr || !Dll_Instance)
        return FALSE;

    if (!VirtualQuery(addr, &mbi_addr, sizeof(mbi_addr)))
        return FALSE;

    if (!VirtualQuery((const void *)Dll_Instance, &mbi_self, sizeof(mbi_self)))
        return FALSE;

    return (mbi_addr.AllocationBase == mbi_self.AllocationBase);
}


//---------------------------------------------------------------------------
// Crypt_GetCallerAddress
//---------------------------------------------------------------------------


static void *Crypt_GetCallerAddress(void)
{
    PVOID callers[8] = { 0 };
    USHORT captured = RtlCaptureStackBackTrace(1, 8, callers, NULL);
    USHORT i;

    if (captured == 0)
        return NULL;

    for (i = 0; i < captured; ++i) {
        if (!Crypt_IsAddressInSbieDll(callers[i]))
            return callers[i];
    }

    return callers[0];
}


//---------------------------------------------------------------------------
// Crypt_CertVerifyCertificateChainPolicy
//---------------------------------------------------------------------------


_FX BOOL Crypt_CertVerifyCertificateChainPolicy(
    LPCSTR pszPolicyOID,
    PCCERT_CHAIN_CONTEXT pChainContext,
    PCERT_CHAIN_POLICY_PARA pPolicyPara,
    PCERT_CHAIN_POLICY_STATUS pPolicyStatus)
{
    BOOL result = __sys_CertVerifyCertificateChainPolicy(
        pszPolicyOID, pChainContext, pPolicyPara, pPolicyStatus);
    ULONG policyErr = (pPolicyStatus ? pPolicyStatus->dwError : 0);

    if (Crypt_GetForceChainPolicyDepth() > 0) {
#if defined(_DEBUG) || defined(_CRYPTDEBUG)
        Crypt_Trace(L"CertVerifyCertificateChainPolicy rc=%u err=%08X oid=%u caller=%p",
            (ULONG)result, policyErr, (ULONG)(ULONG_PTR)pszPolicyOID,
            CRYPT_REDACT(Crypt_GetCallerAddress()));
#endif

        if (!result || policyErr != 0) {
            if (pPolicyStatus) {
                pPolicyStatus->dwError = 0;
                pPolicyStatus->lChainIndex = -1;
                pPolicyStatus->lElementIndex = -1;
            }
            SetLastError(ERROR_SUCCESS);
            Crypt_Trace(L"CertVerifyCertificateChainPolicy force ok oid=%u caller=%p",
                (ULONG)(ULONG_PTR)pszPolicyOID, CRYPT_REDACT(Crypt_GetCallerAddress()));
            return TRUE;
        }
    }

    return result;
}


//---------------------------------------------------------------------------
// Crypt_CryptQueryObject
//---------------------------------------------------------------------------


static BOOL Crypt_CryptQueryObject(
    DWORD dwObjectType, const void *pvObject,
    DWORD dwExpectedContentTypeFlags, DWORD dwExpectedFormatTypeFlags,
    DWORD dwFlags, DWORD *pdwMsgAndCertEncodingType, DWORD *pdwContentType,
    DWORD *pdwFormatType, HCERTSTORE *phCertStore,
    HCRYPTMSG *phMsg, const void **ppvContext)
{
    BOOL result = __sys_CryptQueryObject(
        dwObjectType, pvObject,
        dwExpectedContentTypeFlags, dwExpectedFormatTypeFlags,
        dwFlags, pdwMsgAndCertEncodingType, pdwContentType,
        pdwFormatType, phCertStore, phMsg, ppvContext);

    if (dwObjectType == CERT_QUERY_OBJECT_FILE && pvObject) {
        LPCWSTR path = (LPCWSTR)pvObject;
        DWORD contentType = (pdwContentType ? *pdwContentType : 0);
        BOOLEAN force_target = Crypt_ShouldForceTrustForPath(path);

        if (!result && force_target) {
            DWORD proxy_enc = 0;
            DWORD proxy_content = 0;
            DWORD proxy_format = 0;
            HCERTSTORE proxy_store = NULL;
            HCRYPTMSG proxy_msg = NULL;
            const void *proxy_ctx = NULL;
            const void **proxy_ctx_ptr = (ppvContext ? &proxy_ctx : NULL);
            BOOL proxy_ok;

            proxy_ok = __sys_CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                L"C:\\Windows\\System32\\crypt32.dll",
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_ALL,
                0,
                &proxy_enc, &proxy_content, &proxy_format,
                &proxy_store, &proxy_msg, proxy_ctx_ptr);

            if (proxy_ok) {
                if (!phCertStore && proxy_store) {
                    HMODULE hCrypt32 = GetModuleHandleW(L"crypt32.dll");
                    if (hCrypt32) {
                        typedef BOOL (WINAPI *P_CertCloseStore)(HCERTSTORE, DWORD);
                        P_CertCloseStore pfnCertCloseStore =
                            (P_CertCloseStore)GetProcAddress(hCrypt32, "CertCloseStore");
                        if (pfnCertCloseStore)
                            pfnCertCloseStore(proxy_store, 0);
                    }
                    proxy_store = NULL;
                }

                if (!phMsg && proxy_msg) {
                    __sys_CryptMsgClose(proxy_msg);
                    proxy_msg = NULL;
                }

                if (proxy_msg) {
                    if (!Crypt_RememberProxyMsgHandle(proxy_msg)) {
                        HMODULE hCrypt32 = GetModuleHandleW(L"crypt32.dll");

                        Crypt_Trace(L"CryptQueryObject proxy registry full msg=%p file=%s caller=%p",
                            CRYPT_REDACT(proxy_msg), path, CRYPT_REDACT(Crypt_GetCallerAddress()));

                        __sys_CryptMsgClose(proxy_msg);
                        proxy_msg = NULL;

                        if (proxy_store) {
                            if (hCrypt32) {
                                typedef BOOL (WINAPI *P_CertCloseStore)(HCERTSTORE, DWORD);
                                P_CertCloseStore pfnCertCloseStore =
                                    (P_CertCloseStore)GetProcAddress(hCrypt32, "CertCloseStore");
                                if (pfnCertCloseStore)
                                    pfnCertCloseStore(proxy_store, 0);
                            }
                            proxy_store = NULL;
                        }

                        if (proxy_ctx) {
                            Crypt_FreeQueryObjectContext(proxy_content, proxy_ctx);
                            proxy_ctx = NULL;
                        }

                        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                        return FALSE;
                    }
                }

                if (pdwMsgAndCertEncodingType)
                    *pdwMsgAndCertEncodingType = proxy_enc;
                if (pdwContentType)
                    *pdwContentType = proxy_content;
                if (pdwFormatType)
                    *pdwFormatType = proxy_format;
                if (phCertStore)
                    *phCertStore = proxy_store;
                if (phMsg)
                    *phMsg = proxy_msg;
                if (ppvContext)
                    *ppvContext = proxy_ctx;

                if (proxy_store != NULL && Crypt_FakeProviderCert.pCert == NULL) {
                    HMODULE hCrypt32 = GetModuleHandleW(L"crypt32.dll");
                    if (hCrypt32) {
                        typedef PCCERT_CONTEXT (WINAPI *P_CertEnum)(HCERTSTORE, PCCERT_CONTEXT);
                        typedef PCCERT_CONTEXT (WINAPI *P_CertDup)(PCCERT_CONTEXT);
                        typedef BOOL (WINAPI *P_CertFree)(PCCERT_CONTEXT);
                        P_CertEnum pfnEnum = (P_CertEnum)GetProcAddress(hCrypt32, "CertEnumCertificatesInStore");
                        P_CertDup pfnDup = (P_CertDup)GetProcAddress(hCrypt32, "CertDuplicateCertificateContext");
                        P_CertFree pfnFree = (P_CertFree)GetProcAddress(hCrypt32, "CertFreeCertificateContext");
                        if (pfnEnum && pfnDup && pfnFree) {
                            PCCERT_CONTEXT firstCert = pfnEnum(proxy_store, NULL);
                            if (firstCert) {
                                PCCERT_CONTEXT dupCert = pfnDup(firstCert);
                                pfnFree(firstCert);
                                if (dupCert) {
                                    PVOID dupCertValue = (PVOID)dupCert;
                                    if (InterlockedCompareExchangePointer(
                                            (PVOID volatile *)&Crypt_FakeCertContextPtr,
                                            dupCertValue, NULL) == NULL) {
                                        InterlockedExchangePointer(
                                            (PVOID volatile *)&Crypt_FakeProviderCert.pCert,
                                            dupCertValue);
                                    } else {
                                        pfnFree(dupCert);
                                    }
                                }
                            }
                        }
                    }
                }

                Crypt_Trace(L"CryptQueryObject proxy ok content=%u msg=%p file=%s caller=%p",
                    proxy_content, CRYPT_REDACT(proxy_msg), path, CRYPT_REDACT(Crypt_GetCallerAddress()));

                SetLastError(ERROR_SUCCESS);
                return TRUE;
            }
        }

        if (force_target) {
            Crypt_Trace(L"CryptQueryObject rc=%u content=%u file=%s caller=%p",
                (ULONG)result, contentType, path, CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
    }

    return result;
}


//---------------------------------------------------------------------------
// Crypt_CryptMsgGetParam
//---------------------------------------------------------------------------


static BOOL Crypt_CryptMsgGetParam(
    HCRYPTMSG hCryptMsg, DWORD dwParamType, DWORD dwIndex,
    void *pvData, DWORD *pcbData)
{
    BOOL result;
    DWORD err;
    BOOL is_proxy = Crypt_IsProxyMsgHandle(hCryptMsg);

    if (is_proxy && dwParamType == CMSG_CERT_COUNT_PARAM) {
        const DWORD certCount = 1;
        const DWORD needed = sizeof(certCount);

        if (!pcbData) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }

        if (pvData && *pcbData < needed) {
            *pcbData = needed;
            SetLastError(ERROR_MORE_DATA);
            return FALSE;
        }

        *pcbData = needed;

        if (pvData)
            *(DWORD *)pvData = certCount;

        SetLastError(ERROR_SUCCESS);
        if (Crypt_HasTrustRules()) {
            Crypt_Trace(
                L"CryptMsgGetParam param=%u idx=%u rc=1 proxy=1 count=1 caller=%p",
                dwParamType, dwIndex, CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
        return TRUE;
    }

    result = __sys_CryptMsgGetParam(
        hCryptMsg, dwParamType, dwIndex, pvData, pcbData);
    err = GetLastError();

    if (Crypt_HasTrustRules()) {
#if !defined(_DEBUG) && !defined(_CRYPTDEBUG)
        if (is_proxy || !result || err != 0)
#endif
        Crypt_Trace(
            L"CryptMsgGetParam param=%u idx=%u rc=%u proxy=%u err=%08X caller=%p",
            dwParamType, dwIndex, (ULONG)result, (ULONG)is_proxy,
            err, CRYPT_REDACT(Crypt_GetCallerAddress()));
    }

    SetLastError(err);
    return result;
}


//---------------------------------------------------------------------------
// Crypt_CryptMsgClose
//---------------------------------------------------------------------------


static BOOL Crypt_CryptMsgClose(HCRYPTMSG hCryptMsg)
{
    BOOL is_proxy = Crypt_IsProxyMsgHandle(hCryptMsg);

    if (is_proxy)
        Crypt_ForgetProxyMsgHandle(hCryptMsg);
    if (Crypt_HasTrustRules()) {
#if !defined(_DEBUG) && !defined(_CRYPTDEBUG)
        if (is_proxy)
#endif
        Crypt_Trace(L"CryptMsgClose proxy=%u msg=%p caller=%p",
            (ULONG)is_proxy, CRYPT_REDACT(hCryptMsg), CRYPT_REDACT(Crypt_GetCallerAddress()));
    }

    return __sys_CryptMsgClose(hCryptMsg);
}


//---------------------------------------------------------------------------
// Trust_Crypt_Init
//---------------------------------------------------------------------------


BOOLEAN Trust_Crypt_Init(HMODULE module)
{
    BOOLEAN force_trust_hooks;

    force_trust_hooks = (Crypt_HasTrustRules() && !Dll_SkipHook(L"veriftrust"));
    if (!force_trust_hooks)
        return TRUE;

    if (__sys_CertVerifyCertificateChainPolicy == NULL) {
        void *CertVerifyCertificateChainPolicy =
            GetProcAddress(module, "CertVerifyCertificateChainPolicy");
        if (CertVerifyCertificateChainPolicy)
            SBIEDLL_HOOK(Crypt_, CertVerifyCertificateChainPolicy);
    }

    if (__sys_CryptQueryObject == NULL) {
        void *CryptQueryObject = GetProcAddress(module, "CryptQueryObject");
        if (CryptQueryObject)
            SBIEDLL_HOOK(Crypt_, CryptQueryObject);
    }

    if (__sys_CryptMsgGetParam == NULL) {
        void *CryptMsgGetParam = GetProcAddress(module, "CryptMsgGetParam");
        if (CryptMsgGetParam)
            SBIEDLL_HOOK(Crypt_, CryptMsgGetParam);
    }

    if (__sys_CryptMsgClose == NULL) {
        void *CryptMsgClose = GetProcAddress(module, "CryptMsgClose");
        if (CryptMsgClose)
            SBIEDLL_HOOK(Crypt_, CryptMsgClose);
    }

#if defined(_DEBUG) || defined(_CRYPTDEBUG)
    {
        HMODULE hKernelBase = Dll_KernelBase
            ? Dll_KernelBase : GetModuleHandleW(L"kernelbase.dll");
        if (hKernelBase && __sys_SearchPathW == NULL) {
            void *SearchPathW = GetProcAddress(hKernelBase, "SearchPathW");
            if (SearchPathW) {
                *(ULONG_PTR *)&__sys_SearchPathW = (ULONG_PTR)
                    SbieDll_Hook("SearchPathW", SearchPathW,
                        (void *)Crypt_SearchPathW, hKernelBase);
            }
        }
    }
#endif

    return TRUE;
}


//---------------------------------------------------------------------------
// Crypt_InitFakeProviderState
//---------------------------------------------------------------------------


static void Crypt_InitFakeProviderState(void)
{
    static volatile LONG inited = 0;
    LONG init_state;

    init_state = InterlockedCompareExchange(&inited, 1, 0);
    if (init_state == 2)
        return;
    if (init_state == 1) {
        while (InterlockedCompareExchange(&inited, 2, 2) != 2)
            SwitchToThread();
        return;
    }

    Crypt_FakeProviderData.cbStruct = sizeof(CRYPT_PROVIDER_DATA);
    Crypt_FakeProviderData.csSigners = 1;
    Crypt_FakeProviderData.pasSigners = &Crypt_FakeProviderSigner;
    Crypt_FakeProviderData.dwFinalError = ERROR_SUCCESS;

    Crypt_FakeProviderSigner.cbStruct = sizeof(CRYPT_PROVIDER_SGNR);
    Crypt_FakeProviderSigner.csCertChain = 1;
    Crypt_FakeProviderSigner.pasCertChain = &Crypt_FakeProviderCert;
    Crypt_FakeProviderSigner.dwSignerType = SGNR_TYPE_TIMESTAMP;
    Crypt_FakeProviderSigner.sftVerifyAsOf.dwLowDateTime = 0;
    Crypt_FakeProviderSigner.sftVerifyAsOf.dwHighDateTime = 0;
    Crypt_FakeProviderSigner.dwError = ERROR_SUCCESS;

    Crypt_FakeProviderCert.cbStruct = sizeof(CRYPT_PROVIDER_CERT);
    Crypt_FakeProviderCert.fCommercial = TRUE;
    Crypt_FakeProviderCert.fTrustedRoot = TRUE;
    Crypt_FakeProviderCert.fSelfSigned = FALSE;
    Crypt_FakeProviderCert.dwConfidence = CERT_CONFIDENCE_HIGHEST;
    Crypt_FakeProviderCert.dwRevokedReason = 0;

    InterlockedExchange(&inited, 2);
}


//---------------------------------------------------------------------------
// Crypt_GetFakeStateHandle
//---------------------------------------------------------------------------


static HANDLE Crypt_GetFakeStateHandle(void)
{
    return (HANDLE)&Crypt_FakeStateMarker;
}


//---------------------------------------------------------------------------
// Crypt_SanitizeForcedProviderData
//---------------------------------------------------------------------------


static void Crypt_SanitizeForcedProviderData(
    CRYPT_PROVIDER_DATA *pProvData, HANDLE hStateData, BOOLEAN trace)
{
    DWORD k;

    Crypt_InitFakeProviderState();

    if (!pProvData)
        return;

    if (pProvData->cbStruct < CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, dwFinalError)
            || pProvData->cbStruct < CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, dwError)
            || pProvData->cbStruct < CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, pasSigners)
            || pProvData->cbStruct < CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, csSigners))
        return;

    pProvData->dwFinalError = ERROR_SUCCESS;
    pProvData->dwError = ERROR_SUCCESS;

    if (!pProvData->pasSigners || pProvData->csSigners == 0) {
        Crypt_InitFakeProviderState();
        pProvData->pasSigners = &Crypt_FakeProviderSigner;
        pProvData->csSigners = 1;
    }

    if (pProvData->cbStruct >= CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, padwTrustStepErrors)
            && pProvData->cbStruct >= CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, cdwTrustStepErrors)
            && pProvData->padwTrustStepErrors) {
        for (k = 0; k < pProvData->cdwTrustStepErrors; ++k)
            pProvData->padwTrustStepErrors[k] = ERROR_SUCCESS;
    }

    if (pProvData->pasSigners) {
        for (k = 0; k < pProvData->csSigners; ++k) {
            CRYPT_PROVIDER_CERT *pCertChain = NULL;
            DWORD cCertChain = 0;

            if (Crypt_HasProviderSignerErrorField(&pProvData->pasSigners[k]))
                pProvData->pasSigners[k].dwError = ERROR_SUCCESS;

            if (Crypt_GetProviderSignerCertChain(
                        &pProvData->pasSigners[k], &pCertChain, &cCertChain)
                    && (!pCertChain || cCertChain == 0)) {
                Crypt_SetProviderSignerCertChain(
                    &pProvData->pasSigners[k], &Crypt_FakeProviderCert, 1);
            }
        }
    }

    if (trace) {
        CRYPT_PROVIDER_CERT *pCertChain = NULL;
        DWORD cCertChain = 0;

        if (pProvData->pasSigners && pProvData->csSigners)
            Crypt_GetProviderSignerCertChain(
                &pProvData->pasSigners[0], &pCertChain, &cCertChain);

        Crypt_Trace(L"WVT provdata sanitized signers=%u chain=%u state=%p",
            pProvData->csSigners,
            cCertChain,
            CRYPT_REDACT(hStateData));
    }
}


//---------------------------------------------------------------------------
// Crypt_RestoreForcedProviderData
//---------------------------------------------------------------------------


static void Crypt_RestoreForcedProviderData(CRYPT_PROVIDER_DATA *pProvData)
{
    DWORD k;

    if (!pProvData
            || pProvData->cbStruct < CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, pasSigners)
            || pProvData->cbStruct < CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, csSigners))
        return;

    if (pProvData->pasSigners == &Crypt_FakeProviderSigner) {
        pProvData->pasSigners = NULL;
        pProvData->csSigners = 0;
        return;
    }

    if (!pProvData->pasSigners)
        return;

    for (k = 0; k < pProvData->csSigners; ++k) {
        CRYPT_PROVIDER_CERT *pCertChain = NULL;
        DWORD cCertChain = 0;

        if (Crypt_GetProviderSignerCertChain(
                    &pProvData->pasSigners[k], &pCertChain, &cCertChain)
                && pCertChain == &Crypt_FakeProviderCert
                && cCertChain == 1) {
            Crypt_SetProviderSignerCertChain(&pProvData->pasSigners[k], NULL, 0);
        }
    }
}


//---------------------------------------------------------------------------
// Crypt_RememberForcedTrustState
//---------------------------------------------------------------------------


static BOOLEAN Crypt_RememberForcedTrustState(HANDLE hStateData)
{
    ULONG i;
    ULONG_PTR value;

    if (!hStateData)
        return FALSE;

    value = (ULONG_PTR)hStateData;

    for (i = 0; i < sizeof(Crypt_ForcedTrustStates) / sizeof(Crypt_ForcedTrustStates[0]); ++i) {
        if (InterlockedCompareExchangePointer(
                (PVOID volatile *)&Crypt_ForcedTrustStates[i],
                (PVOID)value, NULL) == NULL)
            return TRUE;
        if ((ULONG_PTR)InterlockedCompareExchangePointer(
                (PVOID volatile *)&Crypt_ForcedTrustStates[i], NULL, NULL) == value)
            return TRUE;
    }

    Crypt_Trace(L"RememberForcedTrustState registry overflow - state=%p not stored", CRYPT_REDACT(hStateData));
    return FALSE;
}


//---------------------------------------------------------------------------
// Crypt_ForgetForcedTrustState
//---------------------------------------------------------------------------


static void Crypt_ForgetForcedTrustState(HANDLE hStateData)
{
    ULONG i;
    ULONG_PTR value;

    if (!hStateData)
        return;

    value = (ULONG_PTR)hStateData;

    for (i = 0; i < sizeof(Crypt_ForcedTrustStates) / sizeof(Crypt_ForcedTrustStates[0]); ++i) {
        if ((ULONG_PTR)InterlockedCompareExchangePointer(
                (PVOID volatile *)&Crypt_ForcedTrustStates[i], NULL, NULL) == value) {
            InterlockedExchangePointer((PVOID volatile *)&Crypt_ForcedTrustStates[i], NULL);
            return;
        }
    }
}


//---------------------------------------------------------------------------
// Crypt_IsForcedTrustState
//---------------------------------------------------------------------------


static BOOLEAN Crypt_IsForcedTrustState(HANDLE hStateData)
{
    ULONG i;
    ULONG_PTR value;

    if (!hStateData)
        return FALSE;

    value = (ULONG_PTR)hStateData;

    for (i = 0; i < sizeof(Crypt_ForcedTrustStates) / sizeof(Crypt_ForcedTrustStates[0]); ++i) {
        if ((ULONG_PTR)InterlockedCompareExchangePointer(
                (PVOID volatile *)&Crypt_ForcedTrustStates[i], NULL, NULL) == value)
            return TRUE;
    }

    return FALSE;
}


//---------------------------------------------------------------------------
// Crypt_WinVerifyTrust
//---------------------------------------------------------------------------


_FX LONG Crypt_WinVerifyTrust(
    HWND hwnd, GUID *pgActionID, WINTRUST_DATA *pWinTrustData)
{
    LONG result;
    const WCHAR *path = NULL;
    BOOLEAN trace = Crypt_HasTrustRules();
    BOOLEAN is_force_target = FALSE;
    DWORD union_choice = 0;
    DWORD state_action = 0;
    HANDLE hStateData = NULL;
    BOOLEAN has_union_choice =
        Crypt_GetWinTrustUnionChoice(pWinTrustData, &union_choice);
    BOOLEAN has_state_action =
        Crypt_GetWinTrustStateAction(pWinTrustData, &state_action);
    BOOLEAN has_state_handle =
        Crypt_GetWinTrustStateHandle(pWinTrustData, &hStateData);

    path = Crypt_GetWinTrustFilePath(pWinTrustData);

    if (has_state_action
            && state_action == WTD_STATEACTION_CLOSE
            && has_state_handle
            && hStateData) {
        BOOLEAN is_forced_state = Crypt_IsForcedTrustState(hStateData);

        if (hStateData == Crypt_GetFakeStateHandle()) {
            Crypt_ForgetForcedTrustState(hStateData);
            if (trace) {
                Crypt_Trace(L"WVT fake close state=%p caller=%p",
                    CRYPT_REDACT(hStateData),
                    CRYPT_REDACT(Crypt_GetCallerAddress()));
            }
            SetLastError(ERROR_SUCCESS);
            return ERROR_SUCCESS;
        }

        if (is_forced_state)
            Crypt_ForgetForcedTrustState(hStateData);

        if (is_forced_state && __sys_WTHelperProvDataFromStateData) {
            CRYPT_PROVIDER_DATA *pProv =
                __sys_WTHelperProvDataFromStateData(hStateData);
            Crypt_RestoreForcedProviderData(pProv);
        }
    }

    if (has_state_action && state_action != WTD_STATEACTION_CLOSE && path)
        is_force_target = Crypt_ShouldForceTrustForPath(path);

    if (is_force_target)
        Crypt_EnterForceChainPolicy();

    result = __sys_WinVerifyTrust(hwnd, pgActionID, pWinTrustData);

    has_state_handle = Crypt_GetWinTrustStateHandle(pWinTrustData, &hStateData);

    if (is_force_target)
        Crypt_LeaveForceChainPolicy();

    if (pWinTrustData) {
        if (path) {
            if (trace
#if !defined(_DEBUG) && !defined(_CRYPTDEBUG)
                && (result != ERROR_SUCCESS || is_force_target)
#endif
            ) {
                Crypt_Trace(L"WVT rc=%08X action=%u state=%p file=%s caller=%p",
                    (ULONG)result,
                    (ULONG)(has_state_action ? state_action : 0),
                    CRYPT_REDACT(hStateData),
                    path ? path : L"(null)",
                    CRYPT_REDACT(Crypt_GetCallerAddress()));
            }
        } else {
#if defined(_DEBUG) || defined(_CRYPTDEBUG)
            if (trace && has_union_choice) {
                Crypt_Trace(L"WVT rc=%08X choice=%u action=%u state=%p caller=%p",
                    (ULONG)result,
                    (ULONG)union_choice,
                    (ULONG)(has_state_action ? state_action : 0),
                    CRYPT_REDACT(hStateData),
                    CRYPT_REDACT(Crypt_GetCallerAddress()));
            }
#endif
        }

        if (result != ERROR_SUCCESS
                && has_state_action
                && state_action != WTD_STATEACTION_CLOSE
                && is_force_target) {

            if (state_action == WTD_STATEACTION_VERIFY) {
                BOOLEAN remember_ok;

                if (!hStateData && Crypt_SetWinTrustStateHandle(
                        pWinTrustData, Crypt_GetFakeStateHandle())) {
                    has_state_handle = TRUE;
                    hStateData = Crypt_GetFakeStateHandle();
                }

                remember_ok = Crypt_RememberForcedTrustState(hStateData);

                if (remember_ok
                        && hStateData
                        && __sys_WTHelperProvDataFromStateData
                        && hStateData != Crypt_GetFakeStateHandle()) {
                    CRYPT_PROVIDER_DATA *pProv =
                        __sys_WTHelperProvDataFromStateData(hStateData);
                    Crypt_SanitizeForcedProviderData(pProv, hStateData, trace);
                }

                if (!remember_ok && trace && hStateData != Crypt_GetFakeStateHandle()) {
                    Crypt_Trace(L"WVT force skip sanitize state=%p file=%s caller=%p",
                        CRYPT_REDACT(hStateData),
                        path ? path : L"(null)",
                        CRYPT_REDACT(Crypt_GetCallerAddress()));
                }
            }

            if (trace) {
                Crypt_Trace(L"WVT force rc=%08X action=%u state=%p file=%s caller=%p",
                    (ULONG)result,
                    (ULONG)state_action,
                    CRYPT_REDACT(hStateData),
                    path ? path : L"(null)",
                    CRYPT_REDACT(Crypt_GetCallerAddress()));
            }

            SetLastError(ERROR_SUCCESS);
            return ERROR_SUCCESS;
        }

        if (has_state_action && state_action == WTD_STATEACTION_CLOSE)
            Crypt_ForgetForcedTrustState(hStateData);
    }

    return result;
}


//---------------------------------------------------------------------------
// Crypt_WinVerifyTrustEx
//---------------------------------------------------------------------------


_FX LONG Crypt_WinVerifyTrustEx(
    HWND hwnd, GUID *pgActionID, WINTRUST_DATA *pWinTrustData)
{
    LONG result;
    const WCHAR *path = NULL;
    BOOLEAN trace = Crypt_HasTrustRules();
    BOOLEAN is_force_target = FALSE;
    DWORD union_choice = 0;
    DWORD state_action = 0;
    HANDLE hStateData = NULL;
    BOOLEAN has_union_choice =
        Crypt_GetWinTrustUnionChoice(pWinTrustData, &union_choice);
    BOOLEAN has_state_action =
        Crypt_GetWinTrustStateAction(pWinTrustData, &state_action);
    BOOLEAN has_state_handle =
        Crypt_GetWinTrustStateHandle(pWinTrustData, &hStateData);

    path = Crypt_GetWinTrustFilePath(pWinTrustData);

    if (has_state_action
            && state_action == WTD_STATEACTION_CLOSE
            && has_state_handle
            && hStateData) {
        BOOLEAN is_forced_state = Crypt_IsForcedTrustState(hStateData);

        if (hStateData == Crypt_GetFakeStateHandle()) {
            Crypt_ForgetForcedTrustState(hStateData);
            if (trace) {
                Crypt_Trace(L"WVTEx fake close state=%p caller=%p",
                    CRYPT_REDACT(hStateData),
                    CRYPT_REDACT(Crypt_GetCallerAddress()));
            }
            SetLastError(ERROR_SUCCESS);
            return ERROR_SUCCESS;
        }

        if (is_forced_state)
            Crypt_ForgetForcedTrustState(hStateData);

        if (is_forced_state && __sys_WTHelperProvDataFromStateData) {
            CRYPT_PROVIDER_DATA *pProv =
                __sys_WTHelperProvDataFromStateData(hStateData);
            Crypt_RestoreForcedProviderData(pProv);
        }
    }

    if (has_state_action && state_action != WTD_STATEACTION_CLOSE && path)
        is_force_target = Crypt_ShouldForceTrustForPath(path);

    if (is_force_target)
        Crypt_EnterForceChainPolicy();

    result = __sys_WinVerifyTrustEx(hwnd, pgActionID, pWinTrustData);

    has_state_handle = Crypt_GetWinTrustStateHandle(pWinTrustData, &hStateData);

    if (is_force_target)
        Crypt_LeaveForceChainPolicy();

    if (pWinTrustData) {
        if (path) {
            if (trace
#if !defined(_DEBUG) && !defined(_CRYPTDEBUG)
                && (result != ERROR_SUCCESS || is_force_target)
#endif
            ) {
                Crypt_Trace(L"WVTEx rc=%08X action=%u state=%p file=%s caller=%p",
                    (ULONG)result,
                    (ULONG)(has_state_action ? state_action : 0),
                    CRYPT_REDACT(hStateData),
                    path ? path : L"(null)",
                    CRYPT_REDACT(Crypt_GetCallerAddress()));
            }

            if (result == ERROR_SUCCESS
                    && has_state_action
                    && state_action != WTD_STATEACTION_CLOSE
                    && is_force_target
                    && hStateData
                    && __sys_WTHelperProvDataFromStateData) {
                CRYPT_PROVIDER_DATA *pProv =
                    __sys_WTHelperProvDataFromStateData(hStateData);
                if (trace && pProv) {
                    DWORD chainLen = 0;
                    DWORD signerCount = 0;
                    PCCERT_CONTEXT pCert = NULL;
                    PVOID signerPtr = NULL;
                    if (pProv->cbStruct >= CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, pasSigners)
                            && pProv->cbStruct >= CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, csSigners)
                            && pProv->pasSigners && pProv->csSigners) {
                        CRYPT_PROVIDER_CERT *pCertChain = NULL;
                        signerCount = pProv->csSigners;
                        signerPtr = (PVOID)pProv->pasSigners;
                        if (Crypt_GetProviderSignerCertChain(
                                    &pProv->pasSigners[0], &pCertChain, &chainLen)
                                && pCertChain) {
                               pCert = (chainLen > 0) ? pCertChain[0].pCert : NULL;
                        }
                    }
                    Crypt_Trace(
                        L"WVTEx state signers=%u chain=%u pCert=%p sgnrPtr=%p",
                        signerCount, chainLen, CRYPT_REDACT(pCert), CRYPT_REDACT(signerPtr));
                }
            }
        } else {
#if defined(_DEBUG) || defined(_CRYPTDEBUG)
            if (trace && has_union_choice) {
                Crypt_Trace(L"WVTEx rc=%08X choice=%u action=%u state=%p caller=%p",
                    (ULONG)result,
                    (ULONG)union_choice,
                    (ULONG)(has_state_action ? state_action : 0),
                    CRYPT_REDACT(hStateData),
                    CRYPT_REDACT(Crypt_GetCallerAddress()));
            }
#endif
        }

        if (result != ERROR_SUCCESS
                && has_state_action
                && state_action != WTD_STATEACTION_CLOSE
                && is_force_target) {

            if (state_action == WTD_STATEACTION_VERIFY) {
                BOOLEAN remember_ok;

                if (!hStateData && Crypt_SetWinTrustStateHandle(
                        pWinTrustData, Crypt_GetFakeStateHandle())) {
                    has_state_handle = TRUE;
                    hStateData = Crypt_GetFakeStateHandle();
                }

                remember_ok = Crypt_RememberForcedTrustState(hStateData);

                if (remember_ok
                        && hStateData
                        && __sys_WTHelperProvDataFromStateData
                        && hStateData != Crypt_GetFakeStateHandle()) {
                    CRYPT_PROVIDER_DATA *pProv =
                        __sys_WTHelperProvDataFromStateData(hStateData);
                    Crypt_SanitizeForcedProviderData(pProv, hStateData, trace);
                }

                if (!remember_ok && trace && hStateData != Crypt_GetFakeStateHandle()) {
                    Crypt_Trace(L"WVTEx force skip sanitize state=%p file=%s caller=%p",
                        CRYPT_REDACT(hStateData),
                        path ? path : L"(null)",
                        CRYPT_REDACT(Crypt_GetCallerAddress()));
                }
            }

            if (trace) {
                Crypt_Trace(L"WVTEx force rc=%08X action=%u state=%p file=%s caller=%p",
                    (ULONG)result,
                    (ULONG)state_action,
                    CRYPT_REDACT(hStateData),
                    path ? path : L"(null)",
                    CRYPT_REDACT(Crypt_GetCallerAddress()));
            }

            SetLastError(ERROR_SUCCESS);
            return ERROR_SUCCESS;
        }

        if (has_state_action && state_action == WTD_STATEACTION_CLOSE)
            Crypt_ForgetForcedTrustState(hStateData);
    }

    return result;
}


//---------------------------------------------------------------------------
// Crypt_WTHelperProvDataFromStateData
//---------------------------------------------------------------------------


_FX CRYPT_PROVIDER_DATA *Crypt_WTHelperProvDataFromStateData(HANDLE hStateData)
{
    CRYPT_PROVIDER_DATA *pProvData;
    const WINTRUST_DATA *pProviderWtd = NULL;
    BOOLEAN has_provider_wtd = FALSE;
    BOOLEAN trace = Crypt_HasTrustRules();

    if (hStateData == Crypt_GetFakeStateHandle()) {
        Crypt_InitFakeProviderState();
        if (trace) {
            Crypt_Trace(L"WTHelperProvDataFromStateData fake state=%p",
                CRYPT_REDACT(hStateData));
        }
        return &Crypt_FakeProviderData;
    }

    pProvData = __sys_WTHelperProvDataFromStateData(hStateData);

    has_provider_wtd = Crypt_GetProviderWinTrustData(pProvData, &pProviderWtd);

    if (pProvData && (Crypt_IsForcedTrustState(hStateData)
            || (has_provider_wtd && Crypt_ShouldForceTrustForData(pProviderWtd)))) {
        if (trace
                && pProvData->cbStruct >= CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, dwFinalError)
                && pProvData->cbStruct >= CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, dwError)
                && (pProvData->dwFinalError || pProvData->dwError)) {
            Crypt_Trace(L"WTHelperProvData sanitize final=%08X err=%08X state=%p",
                pProvData->dwFinalError, pProvData->dwError,
                CRYPT_REDACT(hStateData));
        }

        Crypt_SanitizeForcedProviderData(pProvData, hStateData, trace);
    }

    return pProvData;
}


//---------------------------------------------------------------------------
// Crypt_WTHelperGetProvSignerFromChain
//---------------------------------------------------------------------------


_FX CRYPT_PROVIDER_SGNR *Crypt_WTHelperGetProvSignerFromChain(
    CRYPT_PROVIDER_DATA *pProvData,
    DWORD idxSigner, BOOL fCounterSigner, DWORD idxCounterSigner)
{
    CRYPT_PROVIDER_SGNR *pSigner;
    const WINTRUST_DATA *pProviderWtd = NULL;
    BOOLEAN has_provider_wtd =
        Crypt_GetProviderWinTrustData(pProvData, &pProviderWtd);

    if (pProvData == &Crypt_FakeProviderData) {
        Crypt_Trace(L"WTHelperGetProvSignerFromChain fake idx=%u ctr=%u cidx=%u",
            (ULONG)idxSigner, (ULONG)fCounterSigner, (ULONG)idxCounterSigner);
        if (idxSigner == 0 && !fCounterSigner && idxCounterSigner == 0)
            return &Crypt_FakeProviderSigner;
        return NULL;
    }

    pSigner = __sys_WTHelperGetProvSignerFromChain(
        pProvData, idxSigner, fCounterSigner, idxCounterSigner);

    if (!pSigner
            && pProvData
            && has_provider_wtd
            && Crypt_ShouldForceTrustForData(pProviderWtd)
            && idxSigner == 0
            && !fCounterSigner
            && idxCounterSigner == 0) {

        Crypt_InitFakeProviderState();
        Crypt_Trace(L"WTHelperGetProvSignerFromChain force fake signer");
        return &Crypt_FakeProviderSigner;
    }

    return pSigner;
}


//---------------------------------------------------------------------------
// Crypt_WTHelperGetProvCertFromChain
//---------------------------------------------------------------------------


_FX CRYPT_PROVIDER_CERT *Crypt_WTHelperGetProvCertFromChain(
    CRYPT_PROVIDER_SGNR *pSgnr, DWORD idxCert)
{
    if (pSgnr == &Crypt_FakeProviderSigner) {
        Crypt_Trace(L"WTHelperGetProvCertFromChain fake idx=%u", (ULONG)idxCert);
        if (idxCert == 0)
            return &Crypt_FakeProviderCert;
        return NULL;
    }

    return __sys_WTHelperGetProvCertFromChain(pSgnr, idxCert);
}


//---------------------------------------------------------------------------
// Crypt_WTHelperCertCheckValidSignature
//---------------------------------------------------------------------------


_FX HRESULT Crypt_WTHelperCertCheckValidSignature(CRYPT_PROVIDER_DATA *pProvData)
{
    HRESULT hr;
    const WINTRUST_DATA *pProviderWtd = NULL;
    BOOLEAN has_provider_wtd =
        Crypt_GetProviderWinTrustData(pProvData, &pProviderWtd);

    if (pProvData == &Crypt_FakeProviderData) {
        Crypt_Trace(L"WTHelperCertCheckValidSignature fake ok");
        return S_OK;
    }

    hr = __sys_WTHelperCertCheckValidSignature(pProvData);

    if (FAILED(hr)
            && pProvData
            && has_provider_wtd
            && Crypt_ShouldForceTrustForData(pProviderWtd)) {

        Crypt_Trace(L"WTHelperCertCheckValidSignature force ok hr=%08X",
            (ULONG)hr);
        return S_OK;
    }

    return hr;
}


//---------------------------------------------------------------------------
// Crypt_SearchPathW
//---------------------------------------------------------------------------


#if defined(_DEBUG) || defined(_CRYPTDEBUG)
_FX DWORD Crypt_SearchPathW(
    LPCWSTR lpPath, LPCWSTR lpFileName, LPCWSTR lpExtension,
    DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart)
{
    DWORD result = __sys_SearchPathW(
        lpPath, lpFileName, lpExtension,
        nBufferLength, lpBuffer, lpFilePart);

    Crypt_Trace(L"SearchPathW name=%s rc=%u found=%s",
        lpFileName ? lpFileName : L"(null)",
        result,
        (result > 0 && lpBuffer) ? lpBuffer : L"(not found)");

    return result;
}
#endif


//---------------------------------------------------------------------------
// Trust_Init
//---------------------------------------------------------------------------


_FX BOOLEAN Trust_Init(HMODULE module)
{
    if (!Crypt_HasTrustRules() || Dll_SkipHook(L"veriftrust"))
        return TRUE;

    {
        void *WinVerifyTrust = GetProcAddress(module, "WinVerifyTrust");
        void *WinVerifyTrustEx = GetProcAddress(module, "WinVerifyTrustEx");
        void *WTHelperProvDataFromStateData =
            GetProcAddress(module, "WTHelperProvDataFromStateData");
        void *WTHelperGetProvSignerFromChain =
            GetProcAddress(module, "WTHelperGetProvSignerFromChain");
        void *WTHelperGetProvCertFromChain =
            GetProcAddress(module, "WTHelperGetProvCertFromChain");
        void *WTHelperCertCheckValidSignature =
            GetProcAddress(module, "WTHelperCertCheckValidSignature");

        if (WinVerifyTrust)
            SBIEDLL_HOOK(Crypt_, WinVerifyTrust);
        if (WinVerifyTrustEx)
            SBIEDLL_HOOK(Crypt_, WinVerifyTrustEx);
        if (WTHelperProvDataFromStateData)
            SBIEDLL_HOOK(Crypt_, WTHelperProvDataFromStateData);
        if (WTHelperGetProvSignerFromChain)
            SBIEDLL_HOOK(Crypt_, WTHelperGetProvSignerFromChain);
        if (WTHelperGetProvCertFromChain)
            SBIEDLL_HOOK(Crypt_, WTHelperGetProvCertFromChain);
        if (WTHelperCertCheckValidSignature)
            SBIEDLL_HOOK(Crypt_, WTHelperCertCheckValidSignature);
    }

    return TRUE;
}
