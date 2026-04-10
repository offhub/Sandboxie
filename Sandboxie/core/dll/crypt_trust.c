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
// Trust Hooks - Code Signing Verification
//
// Implements VerifyTrustFile policy handling for sandboxed processes.
// Matching file paths are processed in one of three modes:
//   - :fake    -> force WinVerifyTrust success and sanitize provider state.
//   - :catalog -> prefer catalog-based verification/query paths.
//   - :skip    -> exclude this path from any fake or catalog action, even
//                 if a broader wildcard rule would otherwise match it.
//
// If no suffix is provided in VerifyTrustFile, :fake is used for backward
// compatibility.
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
//   VerifyTrustFile=[process,]path_or_wildcard[:fake|:catalog|:skip]
//     - One or more entries; mode is applied per matching path.
//     - Wildcards (* and ?) are matched against full path and filename.
//     - Exact rules (no wildcards) take priority over wildcard rules.
//     - A :skip rule suppresses any matching fake or catalog action.
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
#include <mscat.h>
#include <stdarg.h>
#include <wctype.h>


//---------------------------------------------------------------------------
// Macros
//---------------------------------------------------------------------------


#define CRYPT_TRUST_RULE_MAX   32
#define CRYPT_TRUST_RULE_LEN   260
#define CRYPT_PROXY_MSG_MAX    16
#define CRYPT_FORCED_STATE_MAX 32
#define CRYPT_CATALOG_CACHE_MAX 64
#define CRYPT_CATALOG_PATH_MAX  1024
#define CRYPT_CATALOG_CACHE_FILE_MAX_BYTES (256 * 1024)
#define CRYPT_CATALOG_CACHE_MUTEX_NAME_MAX 128
#define CRYPT_CATALOG_CACHE_FILE_NAME L"CatalogPaths.dat"
#define CRYPT_CATALOG_CACHE_TMP_NAME  L"CatalogPaths.tmp"
#define CRYPT_CATALOG_CACHE_BAK_NAME  L"CatalogPaths.bak"
#define CRYPT_TRUST_MODE_NONE    0
#define CRYPT_TRUST_MODE_FAKE    1
#define CRYPT_TRUST_MODE_CATALOG 2
#define CRYPT_TRUST_MODE_SKIP    3
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
static ULONG Crypt_ParseTrustRuleMode(
    const WCHAR *value, WCHAR *rule_buf, size_t rule_buf_count);
static ULONG Crypt_GetTrustModeForPath(const WCHAR *path);
static BOOLEAN Crypt_MatchTrustFixPath(const WCHAR *rule, const WCHAR *path);
static const WCHAR *Crypt_SkipDosPathPrefix(const WCHAR *path);
static BOOLEAN Crypt_NormalizePathForCache(
    const WCHAR *path, WCHAR *path_buf, size_t path_buf_count);
static void Crypt_ClearCatalogCache(void);
static BOOLEAN Crypt_FindCatalogCachePathInMemory(
    const WCHAR *memberPath, WCHAR *catalogPath, size_t catalogPathCount);
static BOOLEAN Crypt_FindCatalogCachePath(
    const WCHAR *memberPath, WCHAR *catalogPath, size_t catalogPathCount);
static void Crypt_RememberCatalogCachePathInMemory(
    const WCHAR *memberPath, const WCHAR *catalogPath);
static void Crypt_RememberCatalogCachePath(
    const WCHAR *memberPath, const WCHAR *catalogPath);
static void Crypt_ForgetCatalogCachePathInMemory(const WCHAR *memberPath);
static void Crypt_ForgetCatalogCachePath(const WCHAR *memberPath);
static void Crypt_LockCatalogCache(void);
static void Crypt_UnlockCatalogCache(void);
static void Crypt_InitCatalogCacheMutexName(void);
static HANDLE Crypt_LockCatalogCacheFile(void);
static BOOLEAN Crypt_OpenBoxDataFileRead(const WCHAR *name, HANDLE *phFile);
static BOOLEAN Crypt_LoadCatalogCacheFileLocked(const WCHAR *name);
static BOOLEAN Crypt_BuildCatalogCacheSnapshot(WCHAR **ppData, ULONG *pcchData);
static BOOLEAN Crypt_SaveCatalogCacheFileLocked(void);
static BOOLEAN Crypt_WarmCatalogCacheForPath(
    const WCHAR *trace_tag, BOOLEAN trace, const WCHAR *filePath);
static BOOLEAN Crypt_ComputeFileSha256(HANDLE hFile, BYTE *hashOut, DWORD *cbHashOut);
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
static void Crypt_CopyWinTrustData(
    WINTRUST_DATA *dst, const WINTRUST_DATA *src);
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
static ULONG Crypt_GetTrustModeForData(const WINTRUST_DATA *pWinTrustData);
static BOOLEAN Crypt_CopyPathSafe(
    const WCHAR *path, WCHAR *path_buf, size_t path_buf_count);
static void Crypt_NormalizePathSeparators(WCHAR *path);
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
static BOOLEAN Crypt_HasFakeProviderCert(void);
static void Crypt_TrySeedFakeProviderCert(HCERTSTORE hCertStore);
static void Crypt_EnsureFakeProviderCert(void);
static void Crypt_RefreshFakeProviderState(void);
static void Crypt_UpdateFakeSignerInfo(void);
static void Crypt_UpdateFakeProviderStatePointers(void);
static void Crypt_SanitizeForcedProviderData(
    CRYPT_PROVIDER_DATA *pProvData, HANDLE hStateData, BOOLEAN trace, BOOLEAN catalog_hint);
static void Crypt_SetProviderDataCatalogSignature(
    CRYPT_PROVIDER_DATA *pProvData, HANDLE hStateData, BOOLEAN force_mark);
static BOOLEAN Crypt_HasCatalogBinding(HANDLE hStateData);
static void Crypt_RestoreForcedProviderData(CRYPT_PROVIDER_DATA *pProvData);
static HANDLE Crypt_GetFakeStateHandle(void);
static BOOLEAN Crypt_RememberForcedTrustState(HANDLE hStateData);
static void Crypt_ForgetForcedTrustState(HANDLE hStateData);
static BOOLEAN Crypt_IsForcedTrustState(HANDLE hStateData);
static void Crypt_AllocCatBinding(HANDLE hState,
    const WINTRUST_DATA *wtd_in, const WINTRUST_CATALOG_INFO *wtc_in,
    const WCHAR *catPath, const WCHAR *memberPath, const WCHAR *memberTag);
static void Crypt_FreeCatBinding(HANDLE hState);
static BOOLEAN Crypt_HandleWinTrustCloseState(
    const WCHAR *trace_tag, BOOLEAN trace,
    BOOLEAN has_state_action, DWORD state_action,
    BOOLEAN has_state_handle, HANDLE hStateData,
    LONG *pResult);
static void Crypt_TraceWinTrustResult(
    const WCHAR *trace_tag, BOOLEAN trace, LONG result,
    BOOLEAN has_union_choice, DWORD union_choice,
    BOOLEAN has_state_action, DWORD state_action,
    HANDLE hStateData, const WCHAR *path);
static void Crypt_TraceWinTrustProviderState(
    const WCHAR *trace_tag, BOOLEAN trace,
    BOOLEAN has_state_action, DWORD state_action,
    BOOLEAN is_force_target, HANDLE hStateData);
static void Crypt_TraceWinTrustInput(
    const WCHAR *trace_tag, BOOLEAN trace,
    const WINTRUST_DATA *pWinTrustData,
    BOOLEAN has_union_choice, DWORD union_choice,
    BOOLEAN has_state_action, DWORD state_action,
    BOOLEAN has_state_handle, HANDLE hStateData);
static BOOLEAN Crypt_ForceWinTrustSuccess(
    const WCHAR *trace_tag, BOOLEAN trace, LONG result,
    BOOLEAN has_state_action, DWORD state_action,
    BOOLEAN is_force_target,
    WINTRUST_DATA *pWinTrustData, HANDLE *phStateData,
    const WCHAR *path);
static LONG Crypt_RunWinVerifyTrust(
    LONG (WINAPI *pfnVerifyTrust)(HWND, GUID *, WINTRUST_DATA *),
    const WCHAR *trace_tag,
    BOOLEAN trace_provider_state,
    HWND hwnd, GUID *pgActionID, WINTRUST_DATA *pWinTrustData);
static void Crypt_EnterSysWvtex(void);
static void Crypt_LeaveSysWvtex(void);
static BOOLEAN Crypt_IsInSysWvtex(void);
static LONG Crypt_TryCatalogScanDir(
    LONG (WINAPI *pfnVerifyTrust)(HWND, GUID *, WINTRUST_DATA *),
    const WCHAR *trace_tag, BOOLEAN trace,
    HWND hwnd, GUID *pgActionID,
    WINTRUST_DATA *pWinTrustData,
    const WCHAR *memberPath,
    HANDLE hMemberFile,
    BYTE *pHash, DWORD cbHash,
    const WCHAR *memberTag,
    const WCHAR *dirPath,
    DWORD *pTried);
static LONG Crypt_TryCatalogVerify(
    LONG (WINAPI *pfnVerifyTrust)(HWND, GUID *, WINTRUST_DATA *),
    const WCHAR *trace_tag, BOOLEAN trace,
    HWND hwnd, GUID *pgActionID,
    WINTRUST_DATA *pWinTrustData,
    const WCHAR *filePath);
static LONG Crypt_TryCatalogScanFallback(
    LONG (WINAPI *pfnVerifyTrust)(HWND, GUID *, WINTRUST_DATA *),
    const WCHAR *trace_tag, BOOLEAN trace,
    HWND hwnd, GUID *pgActionID,
    WINTRUST_DATA *pWinTrustData,
    const WCHAR *memberPath,
    HANDLE hMemberFile,
    BYTE *pHash, DWORD cbHash);
static LONG Crypt_ScanCatalogRoots(
    LONG (WINAPI *pfnVerifyTrust)(HWND, GUID *, WINTRUST_DATA *),
    const WCHAR *trace_tag, BOOLEAN trace,
    HWND hwnd, GUID *pgActionID,
    WINTRUST_DATA *pWinTrustData,
    const WCHAR *memberPath,
    HANDLE hMemberFile,
    BYTE *pHash, DWORD cbHash,
    const WCHAR *memberTag,
    const WCHAR *winDir,
    DWORD *pTried);

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

extern HANDLE File_AcquireMutex(const WCHAR *MutexName);
extern void File_ReleaseMutex(HANDLE hMutex);
extern BOOLEAN File_CopyDataFile(const WCHAR *sourceName, const WCHAR *targetName);
extern VOID File_DeleteDataFile(const WCHAR *name);
extern BOOLEAN File_WriteBufferToDataFile(const WCHAR *name, const WCHAR *data, ULONG cch);


//---------------------------------------------------------------------------
// Variables
//---------------------------------------------------------------------------


static volatile LONG Crypt_TrustRuleInit = 0;
static ULONG Crypt_TrustRuleCount = 0;
static WCHAR Crypt_TrustRules[CRYPT_TRUST_RULE_MAX][CRYPT_TRUST_RULE_LEN] = { 0 };
static UCHAR Crypt_TrustRuleModes[CRYPT_TRUST_RULE_MAX] = { 0 };
static const WCHAR Crypt_TraceTag[] = L"[Crypt] ";
static volatile ULONG_PTR Crypt_ProxyMsgHandles[CRYPT_PROXY_MSG_MAX] = { 0 };
static ULONG_PTR Crypt_FakeStateMarker = 0xC47A1001;
static ULONG_PTR Crypt_ForcedTrustStates[CRYPT_FORCED_STATE_MAX] = { 0 };
static volatile LONG Crypt_CatalogFallbackActive = 0;
typedef struct _CRYPT_CATALOG_CACHE_ENTRY {
    WCHAR memberPath[CRYPT_CATALOG_PATH_MAX];
    WCHAR catalogPath[CRYPT_CATALOG_PATH_MAX];
} CRYPT_CATALOG_CACHE_ENTRY;

// Persistent copy of WINTRUST_DATA + WINTRUST_CATALOG_INFO for a catalog
// verify state, preventing dangling pointers in CRYPT_PROVIDER_DATA.pWintrustData.
typedef struct _CRYPT_CAT_BINDING {
    HANDLE hState;
    WINTRUST_DATA wtd;
    WINTRUST_CATALOG_INFO wtc;
    WCHAR cat_path[CRYPT_CATALOG_PATH_MAX];
    WCHAR member_path[MAX_PATH * 2 + 4];
    WCHAR member_tag[128];
} CRYPT_CAT_BINDING;
static CRYPT_CATALOG_CACHE_ENTRY Crypt_CatalogCache[CRYPT_CATALOG_CACHE_MAX] = { 0 };
static volatile LONG Crypt_CatalogCacheCursor = -1;
static volatile LONG Crypt_CatalogCacheLock = 0;
static WCHAR Crypt_CatalogCacheMutexName[CRYPT_CATALOG_CACHE_MUTEX_NAME_MAX] = { 0 };
static CRYPT_CAT_BINDING * volatile Crypt_CatBindings[CRYPT_FORCED_STATE_MAX] = { NULL };
static CRYPT_PROVIDER_DATA Crypt_FakeProviderData = { 0 };
static CRYPT_PROVIDER_SGNR Crypt_FakeProviderSigner = { 0 };
static CRYPT_PROVIDER_CERT Crypt_FakeProviderCert = { 0 };
static CMSG_SIGNER_INFO Crypt_FakeSignerInfo = { 0 };
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
// Crypt_EnterSysWvtex / Crypt_LeaveSysWvtex / Crypt_IsInSysWvtex
//---------------------------------------------------------------------------


static void Crypt_EnterSysWvtex(void)
{
    THREAD_DATA *data = Dll_GetTlsData(NULL);

    if (data)
        ++data->crypt_in_sys_wvtex;
}


static void Crypt_LeaveSysWvtex(void)
{
    THREAD_DATA *data = Dll_GetTlsData(NULL);

    if (data && data->crypt_in_sys_wvtex > 0)
        --data->crypt_in_sys_wvtex;
}


static BOOLEAN Crypt_IsInSysWvtex(void)
{
    THREAD_DATA *data = Dll_GetTlsData(NULL);

    if (!data)
        return FALSE;
    return (data->crypt_in_sys_wvtex > 0);
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
    DWORD saved_error = GetLastError();

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
    SetLastError(saved_error);
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
// Crypt_ParseTrustRuleMode
//---------------------------------------------------------------------------


static ULONG Crypt_ParseTrustRuleMode(
    const WCHAR *value, WCHAR *rule_buf, size_t rule_buf_count)
{
    size_t len;
    // Backward compatibility: VerifyTrustFile without suffix defaults to fake mode.
    ULONG mode = CRYPT_TRUST_MODE_FAKE;

    if (!value || !rule_buf || rule_buf_count == 0)
        return CRYPT_TRUST_MODE_NONE;

    len = wcslen(value);
    while (len > 0 && iswspace(value[len - 1]))
        --len;

    if (len >= 5 && _wcsnicmp(value + len - 5, L":fake", 5) == 0) {
        mode = CRYPT_TRUST_MODE_FAKE;
        len -= 5;
    } else if (len >= 8 && _wcsnicmp(value + len - 8, L":catalog", 8) == 0) {
        mode = CRYPT_TRUST_MODE_CATALOG;
        len -= 8;
    } else if (len >= 5 && _wcsnicmp(value + len - 5, L":skip", 5) == 0) {
        mode = CRYPT_TRUST_MODE_SKIP;
        len -= 5;
    }

    while (len > 0 && iswspace(value[len - 1]))
        --len;

    while (*value && iswspace(*value)) {
        ++value;
        if (len > 0)
            --len;
    }

    if (len == 0)
        return CRYPT_TRUST_MODE_NONE;

    if (len >= rule_buf_count)
        len = rule_buf_count - 1;

    wmemcpy(rule_buf, value, len);
    rule_buf[len] = L'\0';

    return mode;
}


//---------------------------------------------------------------------------
// Crypt_GetTrustModeForPath
//---------------------------------------------------------------------------


static ULONG Crypt_GetTrustModeForPath(const WCHAR *path)
{
    ULONG i;
    ULONG pass;
    WCHAR path_buf[1024];

    if (!Crypt_CopyPathSafe(path, path_buf, sizeof(path_buf) / sizeof(path_buf[0]))
            || !path_buf[0])
        return CRYPT_TRUST_MODE_NONE;

    Crypt_NormalizePathSeparators(path_buf);

    Crypt_InitTrustRules();

    // Two passes: exact rules (no wildcards) are checked before wildcard
    // rules so that a specific entry like "msiexec.exe:skip" overrides a
    // broader wildcard like "*.exe:fake".
    for (pass = 0; pass < 2; ++pass) {
        for (i = 0; i < Crypt_TrustRuleCount; ++i) {
            const WCHAR *rule = Crypt_TrustRules[i];
            BOOLEAN is_wildcard = (wcschr(rule, L'*') != NULL || wcschr(rule, L'?') != NULL);
            if (pass == 0 && is_wildcard)
                continue;
            if (pass == 1 && !is_wildcard)
                continue;
            if (Crypt_MatchTrustFixPath(rule, path_buf)) {
                ULONG mode = (ULONG)Crypt_TrustRuleModes[i];
                if (mode == CRYPT_TRUST_MODE_SKIP)
                    return CRYPT_TRUST_MODE_NONE;
                return mode;
            }
        }
    }

    return CRYPT_TRUST_MODE_NONE;
}


//---------------------------------------------------------------------------
// Crypt_NormalizePathForCache
//---------------------------------------------------------------------------


static BOOLEAN Crypt_NormalizePathForCache(
    const WCHAR *path, WCHAR *path_buf, size_t path_buf_count)
{
    const WCHAR *norm_path;

    norm_path = Crypt_SkipDosPathPrefix(path);
    if (!norm_path)
        return FALSE;

    if (!Crypt_CopyPathSafe(norm_path, path_buf, path_buf_count) || !path_buf[0])
        return FALSE;

    Crypt_NormalizePathSeparators(path_buf);
    return TRUE;
}


//---------------------------------------------------------------------------
// Crypt_FindCatalogCachePath
//---------------------------------------------------------------------------


static void Crypt_LockCatalogCache(void)
{
    while (InterlockedCompareExchange(&Crypt_CatalogCacheLock, 1, 0) != 0) {
        Sleep(0);
    }
}


static void Crypt_UnlockCatalogCache(void)
{
    InterlockedExchange(&Crypt_CatalogCacheLock, 0);
}


static void Crypt_ClearCatalogCache(void)
{
    ULONG i;

    Crypt_LockCatalogCache();
    for (i = 0; i < CRYPT_CATALOG_CACHE_MAX; ++i) {
        Crypt_CatalogCache[i].memberPath[0] = L'\0';
        Crypt_CatalogCache[i].catalogPath[0] = L'\0';
    }
    InterlockedExchange(&Crypt_CatalogCacheCursor, -1);
    Crypt_UnlockCatalogCache();
}


static BOOLEAN Crypt_FindCatalogCachePathInMemory(
    const WCHAR *memberPath, WCHAR *catalogPath, size_t catalogPathCount)
{
    ULONG i;
    BOOLEAN found = FALSE;

    if (!memberPath || !catalogPath || catalogPathCount == 0)
        return FALSE;

    Crypt_LockCatalogCache();
    for (i = 0; i < CRYPT_CATALOG_CACHE_MAX; ++i) {
        if (Crypt_CatalogCache[i].memberPath[0]
                && _wcsicmp(Crypt_CatalogCache[i].memberPath, memberPath) == 0
                && Crypt_CatalogCache[i].catalogPath[0]) {
            wcsncpy(catalogPath, Crypt_CatalogCache[i].catalogPath, catalogPathCount - 1);
            catalogPath[catalogPathCount - 1] = L'\0';
            found = TRUE;
            break;
        }
    }
    Crypt_UnlockCatalogCache();

    return found;
}


static void Crypt_RememberCatalogCachePathInMemory(
    const WCHAR *memberPath, const WCHAR *catalogPath)
{
    ULONG i;
    LONG idx;

    if (!memberPath || !catalogPath)
        return;

    Crypt_LockCatalogCache();
    for (i = 0; i < CRYPT_CATALOG_CACHE_MAX; ++i) {
        if (Crypt_CatalogCache[i].memberPath[0]
                && _wcsicmp(Crypt_CatalogCache[i].memberPath, memberPath) == 0) {
            wcsncpy(Crypt_CatalogCache[i].catalogPath, catalogPath, CRYPT_CATALOG_PATH_MAX - 1);
            Crypt_CatalogCache[i].catalogPath[CRYPT_CATALOG_PATH_MAX - 1] = L'\0';
            Crypt_UnlockCatalogCache();
            return;
        }
    }

    idx = InterlockedIncrement(&Crypt_CatalogCacheCursor);
    i = (ULONG)(idx % CRYPT_CATALOG_CACHE_MAX);
    wcsncpy(Crypt_CatalogCache[i].memberPath, memberPath, CRYPT_CATALOG_PATH_MAX - 1);
    Crypt_CatalogCache[i].memberPath[CRYPT_CATALOG_PATH_MAX - 1] = L'\0';
    wcsncpy(Crypt_CatalogCache[i].catalogPath, catalogPath, CRYPT_CATALOG_PATH_MAX - 1);
    Crypt_CatalogCache[i].catalogPath[CRYPT_CATALOG_PATH_MAX - 1] = L'\0';
    Crypt_UnlockCatalogCache();
}


static void Crypt_ForgetCatalogCachePathInMemory(const WCHAR *memberPath)
{
    ULONG i;

    if (!memberPath)
        return;

    Crypt_LockCatalogCache();
    for (i = 0; i < CRYPT_CATALOG_CACHE_MAX; ++i) {
        if (Crypt_CatalogCache[i].memberPath[0]
                && _wcsicmp(Crypt_CatalogCache[i].memberPath, memberPath) == 0) {
            Crypt_CatalogCache[i].memberPath[0] = L'\0';
            Crypt_CatalogCache[i].catalogPath[0] = L'\0';
            Crypt_UnlockCatalogCache();
            return;
        }
    }
    Crypt_UnlockCatalogCache();
}


static void Crypt_InitCatalogCacheMutexName(void)
{
    if (Crypt_CatalogCacheMutexName[0] || !Dll_BoxName || !Dll_BoxName[0])
        return;

    Sbie_snwprintf(Crypt_CatalogCacheMutexName,
        sizeof(Crypt_CatalogCacheMutexName) / sizeof(Crypt_CatalogCacheMutexName[0]),
        L"SBIE_%s_CryptCatalogCache_Mutex",
        Dll_BoxName);
    Crypt_CatalogCacheMutexName[
        (sizeof(Crypt_CatalogCacheMutexName) / sizeof(Crypt_CatalogCacheMutexName[0])) - 1] = L'\0';
}


static HANDLE Crypt_LockCatalogCacheFile(void)
{
    Crypt_InitCatalogCacheMutexName();
    if (!Crypt_CatalogCacheMutexName[0])
        return NULL;
    return File_AcquireMutex(Crypt_CatalogCacheMutexName);
}


static BOOLEAN Crypt_OpenBoxDataFileRead(const WCHAR *name, HANDLE *phFile)
{
    ULONG pathLen;
    WCHAR *path;
    UNICODE_STRING objname;
    OBJECT_ATTRIBUTES objattrs;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    if (!name || !phFile || !Dll_BoxFilePath)
        return FALSE;

    *phFile = NULL;
    pathLen = (ULONG)wcslen(Dll_BoxFilePath) + 1 + (ULONG)wcslen(name) + 1;
    path = (WCHAR *)Dll_Alloc(pathLen * sizeof(WCHAR));
    if (!path)
        return FALSE;

    wcscpy(path, Dll_BoxFilePath);
    wcscat(path, L"\\");
    wcscat(path, name);

    RtlInitUnicodeString(&objname, path);
    InitializeObjectAttributes(&objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = NtCreateFile(phFile,
        GENERIC_READ | SYNCHRONIZE,
        &objattrs,
        &ioStatus,
        NULL,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0);

    Dll_Free(path);
    if (!NT_SUCCESS(status)) {
        *phFile = NULL;
        return FALSE;
    }

    return TRUE;
}


static BOOLEAN Crypt_LoadCatalogCacheFileLocked(const WCHAR *name)
{
    HANDLE hFile;
    FILE_STANDARD_INFORMATION fileInfo;
    IO_STATUS_BLOCK ioStatus;
    WCHAR *buffer;
    ULONG byteCount;
    BOOLEAN loaded = FALSE;

    if (!Crypt_OpenBoxDataFileRead(name, &hFile))
        return FALSE;

    memzero(&fileInfo, sizeof(fileInfo));
    if (!NT_SUCCESS(NtQueryInformationFile(
                hFile, &ioStatus, &fileInfo, sizeof(fileInfo), FileStandardInformation))) {
        NtClose(hFile);
        return FALSE;
    }

    if (fileInfo.EndOfFile.QuadPart < 0) {
        NtClose(hFile);
        return FALSE;
    }

    byteCount = (fileInfo.EndOfFile.QuadPart > CRYPT_CATALOG_CACHE_FILE_MAX_BYTES)
        ? CRYPT_CATALOG_CACHE_FILE_MAX_BYTES
        : (ULONG)fileInfo.EndOfFile.QuadPart;
    buffer = (WCHAR *)Dll_Alloc(byteCount + sizeof(WCHAR));
    if (!buffer) {
        NtClose(hFile);
        return FALSE;
    }

    memzero(buffer, byteCount + sizeof(WCHAR));
    if (byteCount != 0) {
        if (!NT_SUCCESS(NtReadFile(
                    hFile, NULL, NULL, NULL, &ioStatus, buffer, byteCount, NULL, NULL))) {
            Dll_Free(buffer);
            NtClose(hFile);
            return FALSE;
        }
        byteCount = (ULONG)ioStatus.Information;
    }
    NtClose(hFile);

    byteCount -= (byteCount % sizeof(WCHAR));
    buffer[byteCount / sizeof(WCHAR)] = L'\0';
    Crypt_ClearCatalogCache();

    if (byteCount >= sizeof(WCHAR) && buffer[0] == 0xFEFF)
        memmove(buffer, buffer + 1, byteCount + sizeof(WCHAR) - sizeof(WCHAR));

    if (buffer[0]) {
        WCHAR *line = buffer;

        while (*line) {
            WCHAR *next = line;
            WCHAR *sep;

            while (*next && *next != L'\r' && *next != L'\n')
                ++next;

            if (*next) {
                *next++ = L'\0';
                while (*next == L'\r' || *next == L'\n')
                    ++next;
            }

            sep = wcschr(line, L'|');
            if (sep) {
                *sep = L'\0';
                if (line[0] && sep[1]) {
                    Crypt_RememberCatalogCachePathInMemory(line, sep + 1);
                    loaded = TRUE;
                }
            }

            line = next;
        }
    }

    Dll_Free(buffer);
    return loaded;
}


static BOOLEAN Crypt_BuildCatalogCacheSnapshot(WCHAR **ppData, ULONG *pcchData)
{
    ULONG i;
    ULONG total = 1;
    WCHAR *data;
    WCHAR *ptr;

    if (!ppData || !pcchData)
        return FALSE;

    *ppData = NULL;
    *pcchData = 0;

    Crypt_LockCatalogCache();
    for (i = 0; i < CRYPT_CATALOG_CACHE_MAX; ++i) {
        if (Crypt_CatalogCache[i].memberPath[0] && Crypt_CatalogCache[i].catalogPath[0]) {
            total += (ULONG)wcslen(Crypt_CatalogCache[i].memberPath);
            total += 1;
            total += (ULONG)wcslen(Crypt_CatalogCache[i].catalogPath);
            total += 2;
        }
    }

    data = (WCHAR *)Dll_Alloc(total * sizeof(WCHAR));
    if (!data) {
        Crypt_UnlockCatalogCache();
        return FALSE;
    }

    ptr = data;
    for (i = 0; i < CRYPT_CATALOG_CACHE_MAX; ++i) {
        const WCHAR *memberPath;
        const WCHAR *catalogPath;
        ULONG memberLen;
        ULONG catalogLen;

        if (!Crypt_CatalogCache[i].memberPath[0] || !Crypt_CatalogCache[i].catalogPath[0])
            continue;

        memberPath = Crypt_CatalogCache[i].memberPath;
        catalogPath = Crypt_CatalogCache[i].catalogPath;
        memberLen = (ULONG)wcslen(memberPath);
        catalogLen = (ULONG)wcslen(catalogPath);

        wmemcpy(ptr, memberPath, memberLen);
        ptr += memberLen;
        *ptr++ = L'|';
        wmemcpy(ptr, catalogPath, catalogLen);
        ptr += catalogLen;
        *ptr++ = L'\r';
        *ptr++ = L'\n';
    }
    *ptr = L'\0';
    Crypt_UnlockCatalogCache();

    *ppData = data;
    *pcchData = (ULONG)(ptr - data);
    return TRUE;
}


static BOOLEAN Crypt_SaveCatalogCacheFileLocked(void)
{
    WCHAR *snapshot = NULL;
    ULONG cchSnapshot = 0;
    BOOLEAN haveBackup;
    BOOLEAN success = FALSE;

    if (!Crypt_BuildCatalogCacheSnapshot(&snapshot, &cchSnapshot))
        return FALSE;

    haveBackup = File_CopyDataFile(
        CRYPT_CATALOG_CACHE_FILE_NAME,
        CRYPT_CATALOG_CACHE_BAK_NAME);

    if (File_WriteBufferToDataFile(
                CRYPT_CATALOG_CACHE_TMP_NAME,
                snapshot,
                cchSnapshot)
            && File_CopyDataFile(
                CRYPT_CATALOG_CACHE_TMP_NAME,
                CRYPT_CATALOG_CACHE_FILE_NAME)) {
        success = TRUE;
    } else if (haveBackup) {
        File_CopyDataFile(
            CRYPT_CATALOG_CACHE_BAK_NAME,
            CRYPT_CATALOG_CACHE_FILE_NAME);
    }

    File_DeleteDataFile(CRYPT_CATALOG_CACHE_TMP_NAME);
    if (success && haveBackup)
        File_DeleteDataFile(CRYPT_CATALOG_CACHE_BAK_NAME);

    Dll_Free(snapshot);
    return success;
}


static BOOLEAN Crypt_WarmCatalogCacheForPath(
    const WCHAR *trace_tag, BOOLEAN trace, const WCHAR *filePath)
{
    static const GUID action_verify_v2 =
        { 0x00aac56b, 0xcd44, 0x11d0, { 0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee } };
    WINTRUST_FILE_INFO wtf;
    WINTRUST_DATA wtd;
    WINTRUST_DATA wtdClose;
    LONG cat_result;

    if (!filePath || !filePath[0] || !__sys_WinVerifyTrust)
        return FALSE;

    if (InterlockedCompareExchange(&Crypt_CatalogFallbackActive, 1, 0) != 0)
        return FALSE;

    memzero(&wtf, sizeof(wtf));
    wtf.cbStruct = sizeof(wtf);
    wtf.pcwszFilePath = filePath;

    memzero(&wtd, sizeof(wtd));
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &wtf;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;

    cat_result = Crypt_TryCatalogVerify(
        __sys_WinVerifyTrust,
        trace_tag,
        trace,
        NULL,
        (GUID *)&action_verify_v2,
        &wtd,
        filePath);

    if (wtd.hWVTStateData) {
        wtdClose = wtd;
        wtdClose.dwStateAction = WTD_STATEACTION_CLOSE;
        __sys_WinVerifyTrust(NULL, (GUID *)&action_verify_v2, &wtdClose);
    }

    InterlockedExchange(&Crypt_CatalogFallbackActive, 0);
    return (cat_result == ERROR_SUCCESS);
}


//---------------------------------------------------------------------------
// Crypt_FindCatalogCachePath
//---------------------------------------------------------------------------


static BOOLEAN Crypt_FindCatalogCachePath(
    const WCHAR *memberPath, WCHAR *catalogPath, size_t catalogPathCount)
{
    WCHAR normMember[CRYPT_CATALOG_PATH_MAX];
    HANDLE hMutex;
    BOOLEAN loaded;

    if (!memberPath || !catalogPath || catalogPathCount == 0)
        return FALSE;

    if (!Crypt_NormalizePathForCache(memberPath, normMember, sizeof(normMember) / sizeof(normMember[0])))
        return FALSE;

    if (Crypt_FindCatalogCachePathInMemory(normMember, catalogPath, catalogPathCount))
        return TRUE;

    hMutex = Crypt_LockCatalogCacheFile();
    if (!hMutex)
        return FALSE;

    loaded = Crypt_LoadCatalogCacheFileLocked(CRYPT_CATALOG_CACHE_FILE_NAME);
    if (!Crypt_FindCatalogCachePathInMemory(normMember, catalogPath, catalogPathCount)) {
        if (!loaded)
            Crypt_LoadCatalogCacheFileLocked(CRYPT_CATALOG_CACHE_BAK_NAME);
    }

    File_ReleaseMutex(hMutex);
    return Crypt_FindCatalogCachePathInMemory(normMember, catalogPath, catalogPathCount);
}


//---------------------------------------------------------------------------
// Crypt_RememberCatalogCachePath
//---------------------------------------------------------------------------


static void Crypt_RememberCatalogCachePath(
    const WCHAR *memberPath, const WCHAR *catalogPath)
{
    WCHAR normMember[CRYPT_CATALOG_PATH_MAX];
    WCHAR normCatalog[CRYPT_CATALOG_PATH_MAX];
    HANDLE hMutex;

    if (!memberPath || !catalogPath)
        return;

    if (!Crypt_NormalizePathForCache(memberPath, normMember, sizeof(normMember) / sizeof(normMember[0])))
        return;
    if (!Crypt_NormalizePathForCache(catalogPath, normCatalog, sizeof(normCatalog) / sizeof(normCatalog[0])))
        return;

    Crypt_RememberCatalogCachePathInMemory(normMember, normCatalog);

    hMutex = Crypt_LockCatalogCacheFile();
    if (!hMutex)
        return;

    if (!Crypt_LoadCatalogCacheFileLocked(CRYPT_CATALOG_CACHE_FILE_NAME))
        Crypt_LoadCatalogCacheFileLocked(CRYPT_CATALOG_CACHE_BAK_NAME);
    Crypt_RememberCatalogCachePathInMemory(normMember, normCatalog);
    Crypt_SaveCatalogCacheFileLocked();
    File_ReleaseMutex(hMutex);
}


//---------------------------------------------------------------------------
// Crypt_ForgetCatalogCachePath
//---------------------------------------------------------------------------


static void Crypt_ForgetCatalogCachePath(const WCHAR *memberPath)
{
    WCHAR normMember[CRYPT_CATALOG_PATH_MAX];
    HANDLE hMutex;

    if (!memberPath)
        return;

    if (!Crypt_NormalizePathForCache(memberPath, normMember, sizeof(normMember) / sizeof(normMember[0])))
        return;

    Crypt_ForgetCatalogCachePathInMemory(normMember);

    hMutex = Crypt_LockCatalogCacheFile();
    if (!hMutex)
        return;

    if (!Crypt_LoadCatalogCacheFileLocked(CRYPT_CATALOG_CACHE_FILE_NAME))
        Crypt_LoadCatalogCacheFileLocked(CRYPT_CATALOG_CACHE_BAK_NAME);
    Crypt_ForgetCatalogCachePathInMemory(normMember);
    Crypt_SaveCatalogCacheFileLocked();
    File_ReleaseMutex(hMutex);
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
// Crypt_CopyWinTrustData
//---------------------------------------------------------------------------


static void Crypt_CopyWinTrustData(
    WINTRUST_DATA *dst, const WINTRUST_DATA *src)
{
    size_t cb;

    if (!dst)
        return;

    memzero(dst, sizeof(*dst));

    if (!src)
        return;

    cb = (size_t)src->cbStruct;
    if (cb > sizeof(*dst))
        cb = sizeof(*dst);

    if (cb >= sizeof(src->cbStruct))
        memcpy(dst, src, cb);
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
    WINTRUST_CATALOG_INFO *pCatalog;

    if (!Crypt_GetWinTrustUnionChoice(pWinTrustData, &union_choice))
        return NULL;

    if (union_choice == WTD_CHOICE_CATALOG) {
        if (pWinTrustData->cbStruct < CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, pCatalog)
                || !pWinTrustData->pCatalog)
            return NULL;

        pCatalog = pWinTrustData->pCatalog;

        if (pCatalog->cbStruct >= CRYPT_STRUCT_FIELD_END(
                    WINTRUST_CATALOG_INFO, pcwszMemberFilePath)
                && pCatalog->pcwszMemberFilePath
                && pCatalog->pcwszMemberFilePath[0])
            return pCatalog->pcwszMemberFilePath;

        if (pCatalog->cbStruct >= CRYPT_STRUCT_FIELD_END(
                    WINTRUST_CATALOG_INFO, pcwszCatalogFilePath)
                && pCatalog->pcwszCatalogFilePath
                && pCatalog->pcwszCatalogFilePath[0])
            return pCatalog->pcwszCatalogFilePath;

        return NULL;
    }

    if (union_choice != WTD_CHOICE_FILE)
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
// Crypt_SkipDosPathPrefix
//---------------------------------------------------------------------------


static const WCHAR *Crypt_SkipDosPathPrefix(const WCHAR *path)
{
    if (!path)
        return NULL;

    if (path[0] == L'\\' && path[1] == L'\\'
            && path[2] == L'?' && path[3] == L'\\'
            && path[5] == L':')
        return path + 4;

    if (path[0] == L'\\' && path[1] == L'?'
            && path[2] == L'?' && path[3] == L'\\'
            && path[5] == L':')
        return path + 4;

    return path;
}


//---------------------------------------------------------------------------
// Crypt_MatchTrustFixPath
//---------------------------------------------------------------------------


static BOOLEAN Crypt_MatchTrustFixPath(const WCHAR *rule, const WCHAR *path)
{
    const WCHAR *base;
    const WCHAR *norm_path;
    const WCHAR *norm_base;

    if (!rule || !*rule || !path || !*path)
        return FALSE;

    base = wcsrchr(path, L'\\');
    if (!base)
        base = path;
    else
        ++base;

    norm_path = Crypt_SkipDosPathPrefix(path);
    norm_base = wcsrchr(norm_path, L'\\');
    if (!norm_base)
        norm_base = norm_path;
    else
        ++norm_base;

    return Crypt_WildcardMatchNoCase(rule, path)
        || Crypt_WildcardMatchNoCase(rule, base)
        || (norm_path != path &&
            (Crypt_WildcardMatchNoCase(rule, norm_path)
                || Crypt_WildcardMatchNoCase(rule, norm_base)));
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
        ULONG mode;
        NTSTATUS status = SbieApi_QueryConf(
            NULL, L"VerifyTrustFile", index,
            conf_buf, sizeof(conf_buf) - 16 * sizeof(WCHAR));
        if (!NT_SUCCESS(status))
            break;
        ++index;

        value = Config_MatchImageAndGetValue(conf_buf, Dll_ImageName, NULL);
        if (value && *value) {
            mode = Crypt_ParseTrustRuleMode(
                value,
                Crypt_TrustRules[count],
                CRYPT_TRUST_RULE_LEN);
            if (mode != CRYPT_TRUST_MODE_NONE && Crypt_TrustRules[count][0]) {
                Crypt_TrustRuleModes[count] = (UCHAR)mode;
                ++count;
            }
        }
    }

    Crypt_TrustRuleCount = count;
    InterlockedExchange(&Crypt_TrustRuleInit, 2);
}


//---------------------------------------------------------------------------
// Crypt_CopyPathSafe
//---------------------------------------------------------------------------


static BOOLEAN Crypt_CopyPathSafe(
    const WCHAR *path, WCHAR *path_buf, size_t path_buf_count)
{
    size_t i;

    if (!path || !path_buf || path_buf_count == 0)
        return FALSE;

    __try {
        for (i = 0; i + 1 < path_buf_count; ++i) {
            WCHAR ch = path[i];
            path_buf[i] = ch;
            if (ch == L'\0')
                return TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        path_buf[0] = L'\0';
        return FALSE;
    }

    path_buf[path_buf_count - 1] = L'\0';
    return TRUE;
}


//---------------------------------------------------------------------------
// Crypt_NormalizePathSeparators
//---------------------------------------------------------------------------


static void Crypt_NormalizePathSeparators(WCHAR *path)
{
    WCHAR *src;
    WCHAR *dst;

    if (!path || !*path)
        return;

    src = path;
    dst = path;

    if ((src[0] == L'\\' || src[0] == L'/')
            && (src[1] == L'\\' || src[1] == L'/')) {
        *dst++ = L'\\';
        *dst++ = L'\\';
        src += 2;

        if ((src[0] == L'?' || src[0] == L'.')
                && (src[1] == L'\\' || src[1] == L'/')) {
            *dst++ = *src++;
            *dst++ = L'\\';
            ++src;
        }
    }

    while (*src) {
        WCHAR ch = *src++;

        if (ch == L'/' || ch == L'\\') {
            if (dst == path || dst[-1] != L'\\')
                *dst++ = L'\\';
            continue;
        }

        *dst++ = ch;
    }

    *dst = L'\0';
}


//---------------------------------------------------------------------------
// Crypt_GetTrustModeForData
//---------------------------------------------------------------------------


static ULONG Crypt_GetTrustModeForData(const WINTRUST_DATA *pWinTrustData)
{
    return Crypt_GetTrustModeForPath(
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
// Crypt_TryCatalogScanDir
//---------------------------------------------------------------------------


static LONG Crypt_TryCatalogScanDir(
    LONG (WINAPI *pfnVerifyTrust)(HWND, GUID *, WINTRUST_DATA *),
    const WCHAR *trace_tag, BOOLEAN trace,
    HWND hwnd, GUID *pgActionID,
    WINTRUST_DATA *pWinTrustData,
    const WCHAR *memberPath,
    HANDLE hMemberFile,
    BYTE *pHash, DWORD cbHash,
    const WCHAR *memberTag,
    const WCHAR *dirPath,
    DWORD *pTried)
{
    typedef HANDLE (WINAPI *P_CryptCATOpen)(LPWSTR, DWORD, HCRYPTPROV, DWORD, DWORD);
    typedef BOOL (WINAPI *P_CryptCATClose)(HANDLE);
    typedef CRYPTCATMEMBER * (WINAPI *P_CryptCATGetMemberInfo)(HANDLE, LPWSTR);

    WCHAR pattern[MAX_PATH + 96];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;
    HMODULE hWintrust;
    P_CryptCATOpen pfnCryptCATOpen;
    P_CryptCATClose pfnCryptCATClose;
    P_CryptCATGetMemberInfo pfnCryptCATGetMemberInfo;

    hWintrust = GetModuleHandleW(L"wintrust.dll");
    if (!hWintrust)
        return TRUST_E_NOSIGNATURE;

    pfnCryptCATOpen = (P_CryptCATOpen)GetProcAddress(hWintrust, "CryptCATOpen");
    pfnCryptCATClose = (P_CryptCATClose)GetProcAddress(hWintrust, "CryptCATClose");
    pfnCryptCATGetMemberInfo = (P_CryptCATGetMemberInfo)GetProcAddress(hWintrust, "CryptCATGetMemberInfo");

    if (!pfnCryptCATOpen || !pfnCryptCATClose || !pfnCryptCATGetMemberInfo)
        return TRUST_E_NOSIGNATURE;

    Sbie_snwprintf(pattern, sizeof(pattern) / sizeof(pattern[0]),
        L"%s\\*.cat", dirPath);

    hFind = FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return TRUST_E_NOSIGNATURE;

    do {
        WCHAR catPath[MAX_PATH + 96];
        WINTRUST_CATALOG_INFO wtc;
        WINTRUST_DATA wtd;
        WINTRUST_DATA wtdClose;
        LONG cat_rc;
        HANDLE tempState = NULL;
        HANDLE hCat = NULL;
        CRYPTCATMEMBER *pMember = NULL;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        Sbie_snwprintf(catPath, sizeof(catPath) / sizeof(catPath[0]),
            L"%s\\%s", dirPath, fd.cFileName);

        hCat = pfnCryptCATOpen((LPWSTR)catPath, CRYPTCAT_OPEN_EXISTING, 0, 0, 0);
        if (!hCat || hCat == INVALID_HANDLE_VALUE)
            continue;

        pMember = pfnCryptCATGetMemberInfo(hCat, (LPWSTR)memberTag);
        pfnCryptCATClose(hCat);
        hCat = NULL;

        if (!pMember)
            continue;

        memzero(&wtc, sizeof(wtc));
        wtc.cbStruct = sizeof(wtc);
        wtc.pcwszCatalogFilePath = catPath;
        wtc.pcwszMemberFilePath = memberPath;
        wtc.pcwszMemberTag = memberTag;
        wtc.hMemberFile = hMemberFile;
        wtc.pbCalculatedFileHash = pHash;
        wtc.cbCalculatedFileHash = cbHash;

        Crypt_CopyWinTrustData(&wtd, pWinTrustData);
        wtd.cbStruct = sizeof(wtd);
        wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
        wtd.pCatalog = &wtc;
        if (wtd.cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, dwStateAction))
            wtd.dwStateAction = WTD_STATEACTION_VERIFY;
        if (wtd.cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, hWVTStateData))
            wtd.hWVTStateData = NULL;

        cat_rc = pfnVerifyTrust(hwnd, pgActionID, &wtd);
        ++(*pTried);

        if (wtd.cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, hWVTStateData))
            tempState = wtd.hWVTStateData;

        if (cat_rc == ERROR_SUCCESS) {
            Crypt_RememberCatalogCachePath(memberPath, catPath);

            if (pWinTrustData->cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, hWVTStateData)
                    && wtd.cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, hWVTStateData)) {
                pWinTrustData->hWVTStateData = wtd.hWVTStateData;
                if (pWinTrustData->hWVTStateData) {
                    Crypt_AllocCatBinding(
                        pWinTrustData->hWVTStateData,
                        &wtd,
                        &wtc,
                        catPath,
                        memberPath,
                        memberTag);
                }
            }

            if (trace) {
                Crypt_Trace(L"%s catalog scan hit rc=%08X file=%s cat=%s tried=%u caller=%p",
                    trace_tag,
                    (ULONG)cat_rc,
                    memberPath,
                    catPath,
                    (ULONG)(*pTried),
                    CRYPT_REDACT(Crypt_GetCallerAddress()));
            }

            FindClose(hFind);
            return ERROR_SUCCESS;
        }

        if (tempState && wtd.cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, dwStateAction)
                && wtd.cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, hWVTStateData)) {
            wtdClose = wtd;
            wtdClose.dwStateAction = WTD_STATEACTION_CLOSE;
            wtdClose.hWVTStateData = tempState;
            pfnVerifyTrust(hwnd, pgActionID, &wtdClose);
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
    return TRUST_E_NOSIGNATURE;
}


//---------------------------------------------------------------------------
// Crypt_ComputeFileSha256
//---------------------------------------------------------------------------


static BOOLEAN Crypt_ComputeFileSha256(HANDLE hFile, BYTE *hashOut, DWORD *cbHashOut)
{
    typedef BOOL (WINAPI *P_CryptAcquireContextW)(
        HCRYPTPROV *, LPCWSTR, LPCWSTR, DWORD, DWORD);
    typedef BOOL (WINAPI *P_CryptCreateHash)(
        HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH *);
    typedef BOOL (WINAPI *P_CryptHashData)(HCRYPTHASH, const BYTE *, DWORD, DWORD);
    typedef BOOL (WINAPI *P_CryptGetHashParam)(HCRYPTHASH, DWORD, BYTE *, DWORD *, DWORD);
    typedef BOOL (WINAPI *P_CryptDestroyHash)(HCRYPTHASH);
    typedef BOOL (WINAPI *P_CryptReleaseContext)(HCRYPTPROV, DWORD);

    HMODULE hAdvapi;
    P_CryptAcquireContextW pfnAcquireCtx;
    P_CryptCreateHash pfnCreateHash;
    P_CryptHashData pfnHashData;
    P_CryptGetHashParam pfnGetHashParam;
    P_CryptDestroyHash pfnDestroyHash;
    P_CryptReleaseContext pfnReleaseCtx;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE *buf = NULL;
    DWORD cbBuf = 0;
    DWORD bytesRead;
    DWORD hashLen;
    BOOLEAN read_ok;
    BOOLEAN ok = FALSE;

    if (!hFile || hFile == INVALID_HANDLE_VALUE || !hashOut || !cbHashOut)
        return FALSE;

    hAdvapi = GetModuleHandleW(L"advapi32.dll");
    if (!hAdvapi)
        return FALSE;

    pfnAcquireCtx  = (P_CryptAcquireContextW)GetProcAddress(hAdvapi, "CryptAcquireContextW");
    pfnCreateHash  = (P_CryptCreateHash)GetProcAddress(hAdvapi, "CryptCreateHash");
    pfnHashData    = (P_CryptHashData)GetProcAddress(hAdvapi, "CryptHashData");
    pfnGetHashParam = (P_CryptGetHashParam)GetProcAddress(hAdvapi, "CryptGetHashParam");
    pfnDestroyHash = (P_CryptDestroyHash)GetProcAddress(hAdvapi, "CryptDestroyHash");
    pfnReleaseCtx  = (P_CryptReleaseContext)GetProcAddress(hAdvapi, "CryptReleaseContext");

    if (!pfnAcquireCtx || !pfnCreateHash || !pfnHashData
            || !pfnGetHashParam || !pfnDestroyHash || !pfnReleaseCtx)
        return FALSE;

    if (SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER
            && GetLastError() != NO_ERROR)
        return FALSE;

    if (!pfnAcquireCtx(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return FALSE;

    if (!pfnCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        goto sha256_done;

    cbBuf = 4096;
    buf = (BYTE *)Dll_AllocTemp(cbBuf);
    if (!buf)
        goto sha256_done;

    read_ok = TRUE;
    for (;;) {
        if (!ReadFile(hFile, buf, cbBuf, &bytesRead, NULL)) {
            read_ok = FALSE;
            break;
        }
        if (bytesRead == 0)
            break;
        if (!pfnHashData(hHash, buf, bytesRead, 0))
            goto sha256_done;
    }
    if (!read_ok)
        goto sha256_done;

    hashLen = 32;
    if (!pfnGetHashParam(hHash, HP_HASHVAL, hashOut, &hashLen, 0))
        goto sha256_done;

    *cbHashOut = hashLen;
    ok = TRUE;

sha256_done:
    if (buf)
        Dll_Free(buf);
    if (hHash)
        pfnDestroyHash(hHash);
    if (hProv)
        pfnReleaseCtx(hProv, 0);
    return ok;
}


//---------------------------------------------------------------------------
// Crypt_ScanCatalogRoots
//---------------------------------------------------------------------------


// Scans catroot for a catalog that covers the member file identified by
// pHash/memberTag. Calls Crypt_TryCatalogScanDir on the root itself, the
// well-known {F750...} GUID subdirectory, and every other subdirectory found
// under the root.
//
// CatRoot2 contains only indexed catalog databases (.catdb), not .cat files,
// so it is not scanned here.
//
// This inner helper lets Crypt_TryCatalogScanFallback reuse the same scan
// logic for both the SHA256 and SHA1 hash passes without duplication.

static LONG Crypt_ScanCatalogRoots(
    LONG (WINAPI *pfnVerifyTrust)(HWND, GUID *, WINTRUST_DATA *),
    const WCHAR *trace_tag, BOOLEAN trace,
    HWND hwnd, GUID *pgActionID,
    WINTRUST_DATA *pWinTrustData,
    const WCHAR *memberPath,
    HANDLE hMemberFile,
    BYTE *pHash, DWORD cbHash,
    const WCHAR *memberTag,
    const WCHAR *winDir,
    DWORD *pTried)
{
    WCHAR rootPath[MAX_PATH + 64];
    WCHAR dirPath[MAX_PATH + 96];
    WIN32_FIND_DATAW dirFd;
    HANDLE hFindDir;

    Sbie_snwprintf(rootPath, sizeof(rootPath) / sizeof(rootPath[0]),
        L"%s\\System32\\catroot", winDir);

    if (Crypt_TryCatalogScanDir(
                pfnVerifyTrust, trace_tag, trace,
                hwnd, pgActionID,
                pWinTrustData,
                memberPath, hMemberFile,
                pHash, cbHash,
                memberTag,
                rootPath,
                pTried) == ERROR_SUCCESS)
        return ERROR_SUCCESS;

    Sbie_snwprintf(dirPath, sizeof(dirPath) / sizeof(dirPath[0]),
        L"%s\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}", rootPath);

    if (Crypt_TryCatalogScanDir(
                pfnVerifyTrust, trace_tag, trace,
                hwnd, pgActionID,
                pWinTrustData,
                memberPath, hMemberFile,
                pHash, cbHash,
                memberTag,
                dirPath,
                pTried) == ERROR_SUCCESS)
        return ERROR_SUCCESS;

    Sbie_snwprintf(dirPath, sizeof(dirPath) / sizeof(dirPath[0]),
        L"%s\\*", rootPath);

    hFindDir = FindFirstFileW(dirPath, &dirFd);
    if (hFindDir == INVALID_HANDLE_VALUE)
        return TRUST_E_NOSIGNATURE;

    do {
        if (!(dirFd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            continue;
        if (dirFd.cFileName[0] == L'.'
                && (dirFd.cFileName[1] == L'\0'
                    || (dirFd.cFileName[1] == L'.' && dirFd.cFileName[2] == L'\0')))
            continue;

        Sbie_snwprintf(dirPath, sizeof(dirPath) / sizeof(dirPath[0]),
            L"%s\\%s", rootPath, dirFd.cFileName);

        if (Crypt_TryCatalogScanDir(
                    pfnVerifyTrust, trace_tag, trace,
                    hwnd, pgActionID,
                    pWinTrustData,
                    memberPath, hMemberFile,
                    pHash, cbHash,
                    memberTag,
                    dirPath,
                    pTried) == ERROR_SUCCESS) {
            FindClose(hFindDir);
            return ERROR_SUCCESS;
        }

        if (*pTried >= 512) {
            if (trace) {
                Crypt_Trace(L"%s catalog scan limit reached file=%s tried=%u caller=%p",
                    trace_tag,
                    memberPath,
                    (ULONG)(*pTried),
                    CRYPT_REDACT(Crypt_GetCallerAddress()));
            }
            FindClose(hFindDir);
            return TRUST_E_NOSIGNATURE;
        }
    } while (FindNextFileW(hFindDir, &dirFd));

    FindClose(hFindDir);

    return TRUST_E_NOSIGNATURE;
}


//---------------------------------------------------------------------------
// Crypt_TryCatalogScanFallback
//---------------------------------------------------------------------------


static LONG Crypt_TryCatalogScanFallback(
    LONG (WINAPI *pfnVerifyTrust)(HWND, GUID *, WINTRUST_DATA *),
    const WCHAR *trace_tag, BOOLEAN trace,
    HWND hwnd, GUID *pgActionID,
    WINTRUST_DATA *pWinTrustData,
    const WCHAR *memberPath,
    HANDLE hMemberFile,
    BYTE *pHash, DWORD cbHash)
{
    WCHAR winDir[MAX_PATH + 1];
    WCHAR memberTag[256];
    DWORD i;
    DWORD tried = 0;

    if (!pfnVerifyTrust || !pWinTrustData || !memberPath || !memberPath[0]
            || !hMemberFile || !pHash || !cbHash)
        return TRUST_E_NOSIGNATURE;

    if (!GetWindowsDirectoryW(winDir, MAX_PATH) || !winDir[0])
        return TRUST_E_NOSIGNATURE;

    // SHA256 pass first, as it is the current standard.
    {
        BYTE sha256Hash[32];
        DWORD cbSha256 = 0;
        WCHAR sha256Tag[256];

        if (Crypt_ComputeFileSha256(hMemberFile, sha256Hash, &cbSha256) && cbSha256 == 32) {
            for (i = 0; i < cbSha256; ++i) {
                static const WCHAR sha256hex[] = L"0123456789ABCDEF";
                sha256Tag[i * 2]     = sha256hex[(sha256Hash[i] >> 4) & 0xF];
                sha256Tag[i * 2 + 1] = sha256hex[sha256Hash[i] & 0xF];
            }
            sha256Tag[cbSha256 * 2] = L'\0';

            if (Crypt_ScanCatalogRoots(
                        pfnVerifyTrust, trace_tag, trace,
                        hwnd, pgActionID,
                        pWinTrustData,
                        memberPath, hMemberFile,
                        sha256Hash, cbSha256,
                        sha256Tag,
                        winDir,
                        &tried) == ERROR_SUCCESS)
                return ERROR_SUCCESS;
        }
    }

    // SHA256 scan found nothing; try SHA1 member hash.
    if (cbHash * 2 + 1 > (DWORD)(sizeof(memberTag) / sizeof(memberTag[0])))
        return TRUST_E_NOSIGNATURE;

    for (i = 0; i < cbHash; ++i) {
        static const WCHAR hex[] = L"0123456789ABCDEF";
        memberTag[i * 2] = hex[(pHash[i] >> 4) & 0xF];
        memberTag[i * 2 + 1] = hex[pHash[i] & 0xF];
    }
    memberTag[cbHash * 2] = L'\0';

    if (Crypt_ScanCatalogRoots(
                pfnVerifyTrust, trace_tag, trace,
                hwnd, pgActionID,
                pWinTrustData,
                memberPath, hMemberFile,
                pHash, cbHash,
                memberTag,
                winDir,
                &tried) == ERROR_SUCCESS)
        return ERROR_SUCCESS;

    if (trace) {
        Crypt_Trace(L"%s catalog scan miss file=%s tried=%u caller=%p",
            trace_tag,
            memberPath,
            (ULONG)tried,
            CRYPT_REDACT(Crypt_GetCallerAddress()));
    }

    return TRUST_E_NOSIGNATURE;
}


//---------------------------------------------------------------------------
// Crypt_TryCatalogVerify
//---------------------------------------------------------------------------


static LONG Crypt_TryCatalogVerify(
    LONG (WINAPI *pfnVerifyTrust)(HWND, GUID *, WINTRUST_DATA *),
    const WCHAR *trace_tag, BOOLEAN trace,
    HWND hwnd, GUID *pgActionID,
    WINTRUST_DATA *pWinTrustData,
    const WCHAR *filePath)
{
    typedef BOOL (WINAPI *P_CryptCATAdminAcquireContext)(HCATADMIN *, const GUID *, DWORD);
    typedef BOOL (WINAPI *P_CryptCATAdminCalcHashFromFileHandle)(HANDLE, DWORD *, BYTE *, DWORD);
    typedef HCATINFO (WINAPI *P_CryptCATAdminEnumCatalogFromHash)(HCATADMIN, BYTE *, DWORD, DWORD, HCATINFO *);
    typedef BOOL (WINAPI *P_CryptCATCatalogInfoFromContext)(HCATINFO, CATALOG_INFO *, DWORD);
    typedef BOOL (WINAPI *P_CryptCATAdminReleaseCatalogContext)(HCATADMIN, HCATINFO, DWORD);
    typedef BOOL (WINAPI *P_CryptCATAdminReleaseContext)(HCATADMIN, DWORD);

    HMODULE hWintrust;
    P_CryptCATAdminAcquireContext pfnAcquireContext;
    P_CryptCATAdminCalcHashFromFileHandle pfnCalcHash;
    P_CryptCATAdminEnumCatalogFromHash pfnEnumCatalog;
    P_CryptCATCatalogInfoFromContext pfnCatalogInfo;
    P_CryptCATAdminReleaseCatalogContext pfnReleaseCatalog;
    P_CryptCATAdminReleaseContext pfnReleaseContext;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    const WCHAR *openPath = filePath;
    const WCHAR *retryPath = NULL;
    HCATADMIN hCatAdmin = NULL;
    HCATINFO hCatInfo = NULL;
    BYTE *pHash = NULL;
    DWORD cbHash = 0;
    CATALOG_INFO catInfo;
    WCHAR cachedCatPath[CRYPT_CATALOG_PATH_MAX] = { 0 };
    WCHAR memberTag[256];
    DWORD i;
    LONG result = TRUST_E_NOSIGNATURE;

    WINTRUST_CATALOG_INFO wtc;
    WINTRUST_DATA wtd;

    if (!pfnVerifyTrust || !pWinTrustData || !filePath || !filePath[0])
        return TRUST_E_NOSIGNATURE;

    if (trace) {
        Crypt_Trace(L"%s catalog begin file=%s caller=%p",
            trace_tag,
            filePath,
            CRYPT_REDACT(Crypt_GetCallerAddress()));
    }

    hWintrust = GetModuleHandleW(L"wintrust.dll");
    if (!hWintrust) {
        if (trace) {
            Crypt_Trace(L"%s catalog skip wintrust missing gle=%08X caller=%p",
                trace_tag,
                (ULONG)GetLastError(),
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
        return TRUST_E_NOSIGNATURE;
    }

    pfnAcquireContext = (P_CryptCATAdminAcquireContext)GetProcAddress(hWintrust, "CryptCATAdminAcquireContext");
    pfnCalcHash = (P_CryptCATAdminCalcHashFromFileHandle)GetProcAddress(hWintrust, "CryptCATAdminCalcHashFromFileHandle");
    pfnEnumCatalog = (P_CryptCATAdminEnumCatalogFromHash)GetProcAddress(hWintrust, "CryptCATAdminEnumCatalogFromHash");
    pfnCatalogInfo = (P_CryptCATCatalogInfoFromContext)GetProcAddress(hWintrust, "CryptCATCatalogInfoFromContext");
    pfnReleaseCatalog = (P_CryptCATAdminReleaseCatalogContext)GetProcAddress(hWintrust, "CryptCATAdminReleaseCatalogContext");
    pfnReleaseContext = (P_CryptCATAdminReleaseContext)GetProcAddress(hWintrust, "CryptCATAdminReleaseContext");

    if (!pfnAcquireContext || !pfnCalcHash || !pfnEnumCatalog || !pfnCatalogInfo
            || !pfnReleaseCatalog || !pfnReleaseContext) {
        if (trace) {
            Crypt_Trace(L"%s catalog skip proc missing acq=%p hash=%p enum=%p info=%p relcat=%p relctx=%p caller=%p",
                trace_tag,
                CRYPT_REDACT(pfnAcquireContext),
                CRYPT_REDACT(pfnCalcHash),
                CRYPT_REDACT(pfnEnumCatalog),
                CRYPT_REDACT(pfnCatalogInfo),
                CRYPT_REDACT(pfnReleaseCatalog),
                CRYPT_REDACT(pfnReleaseContext),
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
        return TRUST_E_NOSIGNATURE;
    }

    if (filePath[0] == L'\\' && filePath[1] == L'\\'
            && filePath[2] == L'?' && filePath[3] == L'\\') {
        retryPath = filePath + 4;
    }

    hFile = CreateFileW(openPath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE && retryPath && retryPath[0]) {
        hFile = CreateFileW(retryPath, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE)
            openPath = retryPath;
    }

    if (hFile == INVALID_HANDLE_VALUE) {
        if (trace) {
            Crypt_Trace(L"%s catalog skip open fail gle=%08X file=%s caller=%p",
                trace_tag,
                (ULONG)GetLastError(),
                filePath,
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
        return TRUST_E_NOSIGNATURE;
    }

    if (!pfnAcquireContext(&hCatAdmin, NULL, 0) || !hCatAdmin) {
        if (trace) {
            Crypt_Trace(L"%s catalog skip acquire fail gle=%08X file=%s caller=%p",
                trace_tag,
                (ULONG)GetLastError(),
                openPath,
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
        goto finish;
    }

    if (!pfnCalcHash(hFile, &cbHash, NULL, 0) || cbHash == 0) {
        if (trace) {
            Crypt_Trace(L"%s catalog skip hash-size fail gle=%08X file=%s caller=%p",
                trace_tag,
                (ULONG)GetLastError(),
                openPath,
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
        goto finish;
    }

    pHash = (BYTE *)Dll_AllocTemp(cbHash);
    if (!pHash) {
        if (trace) {
            Crypt_Trace(L"%s catalog skip hash alloc fail size=%u file=%s caller=%p",
                trace_tag,
                (ULONG)cbHash,
                openPath,
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
        goto finish;
    }

    if (!pfnCalcHash(hFile, &cbHash, pHash, 0)) {
        if (trace) {
            Crypt_Trace(L"%s catalog skip hash fail gle=%08X file=%s caller=%p",
                trace_tag,
                (ULONG)GetLastError(),
                openPath,
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
        goto finish;
    }

    if (cbHash * 2 + 1 > (DWORD)(sizeof(memberTag) / sizeof(memberTag[0]))) {
        if (trace) {
            Crypt_Trace(L"%s catalog skip tag overflow hash=%u file=%s caller=%p",
                trace_tag,
                (ULONG)cbHash,
                openPath,
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
        goto finish;
    }

    for (i = 0; i < cbHash; ++i) {
        static const WCHAR hex[] = L"0123456789ABCDEF";
        memberTag[i * 2] = hex[(pHash[i] >> 4) & 0xF];
        memberTag[i * 2 + 1] = hex[pHash[i] & 0xF];
    }
    memberTag[cbHash * 2] = L'\0';

    if (Crypt_FindCatalogCachePath(openPath, cachedCatPath,
            sizeof(cachedCatPath) / sizeof(cachedCatPath[0]))) {
        WINTRUST_DATA wtdCache;
        WINTRUST_DATA wtdClose;
        HANDLE tempState = NULL;
        BOOLEAN cacheVerifyException = FALSE;

        memzero(&wtc, sizeof(wtc));
        wtc.cbStruct = sizeof(wtc);
        wtc.pcwszCatalogFilePath = cachedCatPath;
        wtc.pcwszMemberFilePath = openPath;
        wtc.pcwszMemberTag = memberTag;
        wtc.hMemberFile = hFile;
        wtc.pbCalculatedFileHash = pHash;
        wtc.cbCalculatedFileHash = cbHash;

        Crypt_CopyWinTrustData(&wtdCache, pWinTrustData);
        wtdCache.cbStruct = sizeof(wtdCache);
        wtdCache.dwUnionChoice = WTD_CHOICE_CATALOG;
        wtdCache.pCatalog = &wtc;
        if (wtdCache.cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, dwStateAction))
            wtdCache.dwStateAction = WTD_STATEACTION_VERIFY;
        if (wtdCache.cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, hWVTStateData))
            wtdCache.hWVTStateData = NULL;

        __try {
            result = pfnVerifyTrust(hwnd, pgActionID, &wtdCache);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            cacheVerifyException = TRUE;
            result = TRUST_E_NOSIGNATURE;
            if (trace) {
                Crypt_Trace(L"%s catalog cache exception code=%08X file=%s cat=%s caller=%p",
                    trace_tag,
                    (ULONG)GetExceptionCode(),
                    openPath,
                    cachedCatPath,
                    CRYPT_REDACT(Crypt_GetCallerAddress()));
            }
        }

        if (wtdCache.cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, hWVTStateData))
            tempState = wtdCache.hWVTStateData;

        if (result == ERROR_SUCCESS) {
            if (pWinTrustData->cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, hWVTStateData)
                    && wtdCache.cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, hWVTStateData)) {
                pWinTrustData->hWVTStateData = wtdCache.hWVTStateData;
                if (pWinTrustData->hWVTStateData) {
                    Crypt_AllocCatBinding(
                        pWinTrustData->hWVTStateData,
                        &wtdCache,
                        &wtc,
                        cachedCatPath,
                        openPath,
                        memberTag);
                }
            }
            if (trace) {
                Crypt_Trace(L"%s catalog cache hit rc=%08X file=%s cat=%s caller=%p",
                    trace_tag,
                    (ULONG)result,
                    openPath,
                    cachedCatPath,
                    CRYPT_REDACT(Crypt_GetCallerAddress()));
            }
            goto finish;
        }

        Crypt_ForgetCatalogCachePath(openPath);

        if (!cacheVerifyException
                && tempState && wtdCache.cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, dwStateAction)
                && wtdCache.cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, hWVTStateData)) {
            wtdClose = wtdCache;
            wtdClose.dwStateAction = WTD_STATEACTION_CLOSE;
            wtdClose.hWVTStateData = tempState;
            __try {
                pfnVerifyTrust(hwnd, pgActionID, &wtdClose);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (trace) {
                    Crypt_Trace(L"%s catalog cache close exception code=%08X file=%s cat=%s caller=%p",
                        trace_tag,
                        (ULONG)GetExceptionCode(),
                        openPath,
                        cachedCatPath,
                        CRYPT_REDACT(Crypt_GetCallerAddress()));
                }
            }
        }

        if (trace) {
            Crypt_Trace(L"%s catalog cache miss rc=%08X file=%s cat=%s caller=%p",
                trace_tag,
                (ULONG)result,
                openPath,
                cachedCatPath,
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
    }

    hCatInfo = pfnEnumCatalog(hCatAdmin, pHash, cbHash, 0, NULL);
    if (!hCatInfo && GetLastError() == ERROR_SERVICE_NOT_ACTIVE) {
        LONG scan_result;

        if (trace) {
            Crypt_Trace(L"%s catalog enum retry on inactive service file=%s caller=%p",
                trace_tag,
                openPath,
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }

        __try {
            scan_result = Crypt_TryCatalogScanFallback(
                pfnVerifyTrust,
                trace_tag,
                trace,
                hwnd,
                pgActionID,
                pWinTrustData,
                openPath,
                hFile,
                pHash,
                cbHash);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            scan_result = TRUST_E_NOSIGNATURE;
            if (trace) {
                Crypt_Trace(L"%s catalog scan exception code=%08X file=%s caller=%p",
                    trace_tag,
                    (ULONG)GetExceptionCode(),
                    openPath,
                    CRYPT_REDACT(Crypt_GetCallerAddress()));
            }
        }
        if (scan_result == ERROR_SUCCESS) {
            result = ERROR_SUCCESS;
            goto finish;
        }
    }

    if (!hCatInfo) {
        if (trace) {
            Crypt_Trace(L"%s catalog skip enum fail gle=%08X hash=%u file=%s caller=%p",
                trace_tag,
                (ULONG)GetLastError(),
                (ULONG)cbHash,
                openPath,
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
        goto finish;
    }

    memzero(&catInfo, sizeof(catInfo));
    catInfo.cbStruct = sizeof(catInfo);
    if (!pfnCatalogInfo(hCatInfo, &catInfo, 0)) {
        if (trace) {
            Crypt_Trace(L"%s catalog skip info fail gle=%08X file=%s caller=%p",
                trace_tag,
                (ULONG)GetLastError(),
                openPath,
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
        goto finish;
    }

    memzero(&wtc, sizeof(wtc));
    wtc.cbStruct = sizeof(wtc);
    wtc.pcwszCatalogFilePath = catInfo.wszCatalogFile;
    wtc.pcwszMemberFilePath = openPath;
    wtc.pcwszMemberTag = memberTag;
    wtc.hMemberFile = hFile;
    wtc.pbCalculatedFileHash = pHash;
    wtc.cbCalculatedFileHash = cbHash;

    Crypt_CopyWinTrustData(&wtd, pWinTrustData);
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
    wtd.pCatalog = &wtc;

    result = pfnVerifyTrust(hwnd, pgActionID, &wtd);

    if (pWinTrustData->cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, hWVTStateData)
            && wtd.cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, hWVTStateData)) {
        pWinTrustData->hWVTStateData = wtd.hWVTStateData;
        if (pWinTrustData->hWVTStateData) {
            Crypt_AllocCatBinding(
                pWinTrustData->hWVTStateData,
                &wtd,
                &wtc,
                catInfo.wszCatalogFile,
                openPath,
                memberTag);
        }
    }

    if (trace) {
        Crypt_Trace(L"%s catalog try rc=%08X gle=%08X file=%s cat=%s tag=%s caller=%p",
            trace_tag,
            (ULONG)result,
            (ULONG)GetLastError(),
            openPath,
            catInfo.wszCatalogFile,
            memberTag,
            CRYPT_REDACT(Crypt_GetCallerAddress()));
    }

    if (result == ERROR_SUCCESS)
        Crypt_RememberCatalogCachePath(openPath, catInfo.wszCatalogFile);

finish:
    if (hCatInfo && pfnReleaseCatalog)
        pfnReleaseCatalog(hCatAdmin, hCatInfo, 0);
    if (hCatAdmin && pfnReleaseContext)
        pfnReleaseContext(hCatAdmin, 0);
    if (pHash)
        Dll_Free(pHash);
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    return result;
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
    DWORD original_err = GetLastError();

    if (dwObjectType == CERT_QUERY_OBJECT_FILE && pvObject) {
        LPCWSTR path = (LPCWSTR)pvObject;
        DWORD contentType = (pdwContentType ? *pdwContentType : 0);
        ULONG trust_mode = Crypt_GetTrustModeForPath(path);
        BOOLEAN force_target = (trust_mode == CRYPT_TRUST_MODE_FAKE);

        Crypt_Trace(L"CryptQueryObject mode=%u force=%u file=%s caller=%p",
            trust_mode, force_target, path, CRYPT_REDACT(Crypt_GetCallerAddress()));

        // Hoist the cert-store closer once instead of repeating the lookup
        // at each cleanup site inside this block.
        HMODULE hCrypt32 = GetModuleHandleW(L"crypt32.dll");
        typedef BOOL (WINAPI *P_CertCloseStore)(HCERTSTORE, DWORD);
        P_CertCloseStore pfnCloseStore = hCrypt32
            ? (P_CertCloseStore)GetProcAddress(hCrypt32, "CertCloseStore") : NULL;

        if (force_target) {
            DWORD proxy_enc = 0;
            DWORD proxy_content = 0;
            DWORD proxy_format = 0;
            DWORD proxy_expected_content = dwExpectedContentTypeFlags;
            DWORD proxy_expected_format = dwExpectedFormatTypeFlags;
            HCERTSTORE proxy_store = NULL;
            HCRYPTMSG proxy_msg = NULL;
            const void *proxy_ctx = NULL;
            const void **proxy_ctx_ptr = (ppvContext ? &proxy_ctx : NULL);
            BOOL proxy_ok;

            if (proxy_expected_content == 0)
                proxy_expected_content = CERT_QUERY_CONTENT_FLAG_ALL;
            if (proxy_expected_format == 0)
                proxy_expected_format = CERT_QUERY_FORMAT_FLAG_ALL;

            proxy_ok = __sys_CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                L"C:\\Windows\\System32\\crypt32.dll",
                proxy_expected_content,
                proxy_expected_format,
                dwFlags,
                &proxy_enc, &proxy_content, &proxy_format,
                &proxy_store, &proxy_msg, proxy_ctx_ptr);

            if (!proxy_ok && proxy_expected_content != CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED) {
                if (proxy_msg) {
                    __sys_CryptMsgClose(proxy_msg);
                    proxy_msg = NULL;
                }

                if (proxy_store) {
                    if (pfnCloseStore)
                        pfnCloseStore(proxy_store, 0);
                    proxy_store = NULL;
                }

                if (proxy_ctx) {
                    Crypt_FreeQueryObjectContext(proxy_content, proxy_ctx);
                    proxy_ctx = NULL;
                }

                proxy_ok = __sys_CryptQueryObject(
                    CERT_QUERY_OBJECT_FILE,
                    L"C:\\Windows\\System32\\crypt32.dll",
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                    CERT_QUERY_FORMAT_FLAG_ALL,
                    0,
                    &proxy_enc, &proxy_content, &proxy_format,
                    &proxy_store, &proxy_msg, proxy_ctx_ptr);
            }

            if (proxy_ok && ppvContext && !proxy_ctx) {
                Crypt_Trace(L"CryptQueryObject proxy invalid context content=%u file=%s caller=%p",
                    proxy_content, path, CRYPT_REDACT(Crypt_GetCallerAddress()));

                if (proxy_msg) {
                    __sys_CryptMsgClose(proxy_msg);
                    proxy_msg = NULL;
                }

                if (proxy_store) {
                    if (pfnCloseStore)
                        pfnCloseStore(proxy_store, 0);
                }

                if (proxy_ctx) {
                    Crypt_FreeQueryObjectContext(proxy_content, proxy_ctx);
                    proxy_ctx = NULL;
                }

                proxy_store = NULL;
                proxy_ok = FALSE;
            }

            if (proxy_ok) {
                if (!phCertStore && proxy_store) {
                    if (pfnCloseStore)
                        pfnCloseStore(proxy_store, 0);
                    proxy_store = NULL;
                }

                if (!phMsg && proxy_msg) {
                    __sys_CryptMsgClose(proxy_msg);
                    proxy_msg = NULL;
                }

                if (proxy_msg) {
                    if (!Crypt_RememberProxyMsgHandle(proxy_msg)) {
                        Crypt_Trace(L"CryptQueryObject proxy registry full msg=%p file=%s caller=%p",
                            CRYPT_REDACT(proxy_msg), path, CRYPT_REDACT(Crypt_GetCallerAddress()));

                        __sys_CryptMsgClose(proxy_msg);
                        proxy_msg = NULL;

                        if (proxy_store) {
                            if (pfnCloseStore)
                                pfnCloseStore(proxy_store, 0);
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

                if (proxy_store != NULL)
                    Crypt_TrySeedFakeProviderCert(proxy_store);

                Crypt_Trace(L"CryptQueryObject proxy ok content=%u msg=%p file=%s caller=%p",
                    proxy_content, CRYPT_REDACT(proxy_msg), path, CRYPT_REDACT(Crypt_GetCallerAddress()));

                SetLastError(ERROR_SUCCESS);
                return TRUE;
            }
        }

        // In catalog mode, always prefer querying the catalog file (.cat)
        // over the member file. If catalog proxying fails, preserve the
        // original member-file result as fallback.
        if (!force_target && trust_mode == CRYPT_TRUST_MODE_CATALOG) {
            Crypt_Trace(L"CryptQueryObject entering catalog proxy for file=%s caller=%p",
                path, CRYPT_REDACT(Crypt_GetCallerAddress()));

            WCHAR catalogPath[CRYPT_CATALOG_PATH_MAX] = { 0 };
            BOOLEAN haveCatalogPath;
            BOOLEAN hadOriginalResult = result;
            DWORD origContent = (pdwContentType ? *pdwContentType : 0);
            HCERTSTORE origStore = (phCertStore ? *phCertStore : NULL);
            HCRYPTMSG origMsg = (phMsg ? *phMsg : NULL);
            const void *origCtx = (ppvContext ? *ppvContext : NULL);

            haveCatalogPath = Crypt_FindCatalogCachePath(path, catalogPath,
                sizeof(catalogPath) / sizeof(catalogPath[0]));

            if ((!haveCatalogPath || !catalogPath[0])
                    && __sys_WinVerifyTrust
                    && Crypt_WarmCatalogCacheForPath(L"WVT", FALSE, path)) {
                haveCatalogPath = Crypt_FindCatalogCachePath(path, catalogPath,
                    sizeof(catalogPath) / sizeof(catalogPath[0]));
            }

            Crypt_Trace(L"CryptQueryObject catalog path: have=%u path=%s file=%s caller=%p",
                haveCatalogPath, (haveCatalogPath ? catalogPath : L"<none>"), path, CRYPT_REDACT(Crypt_GetCallerAddress()));

            if (haveCatalogPath && catalogPath[0]) {
                DWORD cat_enc = 0;
                DWORD cat_content = 0;
                DWORD cat_format = 0;
                HCERTSTORE cat_store = NULL;
                HCRYPTMSG cat_msg = NULL;
                const void *cat_ctx = NULL;
                const void **cat_ctx_ptr = (ppvContext ? &cat_ctx : NULL);
                DWORD cat_expected_content = dwExpectedContentTypeFlags;
                DWORD cat_expected_format = dwExpectedFormatTypeFlags;
                DWORD cat_signed_content =
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED;
                BOOL cat_ok;

                if (cat_expected_content == 0)
                    cat_expected_content = CERT_QUERY_CONTENT_FLAG_ALL;
                if (cat_expected_format == 0)
                    cat_expected_format = CERT_QUERY_FORMAT_FLAG_ALL;

                // Query catalog file with signed-first flags so callers that
                // pass broad content masks still receive signed PKCS7 content.
                cat_ok = __sys_CryptQueryObject(
                    CERT_QUERY_OBJECT_FILE,
                    catalogPath,
                    cat_signed_content,
                    cat_expected_format,
                    dwFlags,
                    &cat_enc, &cat_content, &cat_format,
                    &cat_store, &cat_msg, cat_ctx_ptr);

                if (!cat_ok) {
                    if (cat_msg) {
                        __sys_CryptMsgClose(cat_msg);
                        cat_msg = NULL;
                    }
                    if (cat_store) {
                        if (pfnCloseStore)
                            pfnCloseStore(cat_store, 0);
                        cat_store = NULL;
                    }
                    if (cat_ctx) {
                        Crypt_FreeQueryObjectContext(cat_content, cat_ctx);
                        cat_ctx = NULL;
                    }

                    // Fall back to caller-requested content flags.
                    cat_ok = __sys_CryptQueryObject(
                        CERT_QUERY_OBJECT_FILE,
                        catalogPath,
                        cat_expected_content,
                        cat_expected_format,
                        dwFlags,
                        &cat_enc, &cat_content, &cat_format,
                        &cat_store, &cat_msg, cat_ctx_ptr);
                }

                if (!cat_ok) {
                    if (cat_msg) {
                        __sys_CryptMsgClose(cat_msg);
                        cat_msg = NULL;
                    }
                    if (cat_store) {
                        if (pfnCloseStore)
                            pfnCloseStore(cat_store, 0);
                        cat_store = NULL;
                    }
                    if (cat_ctx) {
                        Crypt_FreeQueryObjectContext(cat_content, cat_ctx);
                        cat_ctx = NULL;
                    }

                    // Last fallback: embedded-PKCS7 on catalog file.
                    cat_ok = __sys_CryptQueryObject(
                    CERT_QUERY_OBJECT_FILE,
                    catalogPath,
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                    CERT_QUERY_FORMAT_FLAG_ALL,
                    dwFlags,
                    &cat_enc, &cat_content, &cat_format,
                    &cat_store, &cat_msg, cat_ctx_ptr);
                }

                // Reject if a context pointer was requested but not returned.
                if (cat_ok && ppvContext && !cat_ctx) {
                    if (cat_msg) {
                        __sys_CryptMsgClose(cat_msg);
                        cat_msg = NULL;
                    }
                    if (cat_store) {
                        if (pfnCloseStore)
                            pfnCloseStore(cat_store, 0);
                        cat_store = NULL;
                    }
                    cat_ok = FALSE;
                }

                if (cat_ok) {
                    // Catalog files can come back as PKCS7_SIGNED_EMBED (10),
                    // which some callers classify as embedded signatures.
                    // Normalize to PKCS7_SIGNED (8) for catalog-mode labeling.
                    if (cat_content == CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED)
                        cat_content = CERT_QUERY_CONTENT_PKCS7_SIGNED;

                    if (!phCertStore && cat_store) {
                        if (pfnCloseStore)
                            pfnCloseStore(cat_store, 0);
                        cat_store = NULL;
                    }
                    if (!phMsg && cat_msg) {
                        __sys_CryptMsgClose(cat_msg);
                        cat_msg = NULL;
                    }

                    if (pdwMsgAndCertEncodingType)
                        *pdwMsgAndCertEncodingType = cat_enc;
                    if (pdwContentType)
                        *pdwContentType = cat_content;
                    if (pdwFormatType)
                        *pdwFormatType = cat_format;
                    if (phCertStore)
                        *phCertStore = cat_store;
                    if (phMsg)
                        *phMsg = cat_msg;
                    if (ppvContext)
                        *ppvContext = cat_ctx;

                    // If the original member-file query succeeded, release its
                    // handles now that catalog-backed outputs replaced them.
                    if (hadOriginalResult) {
                        if (origMsg && origMsg != cat_msg)
                            __sys_CryptMsgClose(origMsg);

                        if (origStore && origStore != cat_store && pfnCloseStore)
                            pfnCloseStore(origStore, 0);

                        if (origCtx && origCtx != cat_ctx)
                            Crypt_FreeQueryObjectContext(origContent, origCtx);
                    }

                    Crypt_Trace(
                        L"CryptQueryObject catalog proxy ok content=%u cat=%s file=%s caller=%p",
                        cat_content, catalogPath, path,
                        CRYPT_REDACT(Crypt_GetCallerAddress()));

                    SetLastError(ERROR_SUCCESS);
                    return TRUE;
                }

                // Catalog proxy failed; clean up and fall through.
                if (cat_msg) {
                    __sys_CryptMsgClose(cat_msg);
                    cat_msg = NULL;
                }
                if (cat_store) {
                    if (pfnCloseStore)
                        pfnCloseStore(cat_store, 0);
                    cat_store = NULL;
                }
                if (cat_ctx) {
                    Crypt_FreeQueryObjectContext(cat_content, cat_ctx);
                    cat_ctx = NULL;
                }

                Crypt_Trace(
                    L"CryptQueryObject catalog proxy fail gle=%08X cat=%s file=%s caller=%p",
                    (ULONG)GetLastError(), catalogPath, path,
                    CRYPT_REDACT(Crypt_GetCallerAddress()));
            }
        }

        if (force_target || trust_mode == CRYPT_TRUST_MODE_CATALOG) {
            Crypt_Trace(L"CryptQueryObject rc=%u content=%u file=%s caller=%p",
                (ULONG)result, contentType, path, CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
    }

    SetLastError(original_err);
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

    if (!hCryptMsg) {
        if (Crypt_HasTrustRules()) {
            Crypt_Trace(L"CryptMsgClose skip null msg caller=%p",
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

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
    Crypt_FakeProviderData.csSigners = 0;
    Crypt_FakeProviderData.pasSigners = NULL;
    Crypt_FakeProviderData.dwFinalError = ERROR_SUCCESS;

    Crypt_FakeProviderSigner.cbStruct = sizeof(CRYPT_PROVIDER_SGNR);
    Crypt_FakeProviderSigner.csCertChain = 0;
    Crypt_FakeProviderSigner.pasCertChain = NULL;
    Crypt_FakeProviderSigner.dwSignerType = 0;
    Crypt_FakeProviderSigner.psSigner = NULL;
    Crypt_FakeProviderSigner.sftVerifyAsOf.dwLowDateTime = 0;
    Crypt_FakeProviderSigner.sftVerifyAsOf.dwHighDateTime = 0;
    Crypt_FakeProviderSigner.dwError = ERROR_SUCCESS;

    Crypt_FakeProviderCert.cbStruct = sizeof(CRYPT_PROVIDER_CERT);
    Crypt_FakeProviderCert.fCommercial = TRUE;
    Crypt_FakeProviderCert.fTrustedRoot = TRUE;
    Crypt_FakeProviderCert.fSelfSigned = FALSE;
    Crypt_FakeProviderCert.dwConfidence = CERT_CONFIDENCE_HIGHEST;
    Crypt_FakeProviderCert.dwRevokedReason = 0;

    Crypt_UpdateFakeProviderStatePointers();

    InterlockedExchange(&inited, 2);
}


//---------------------------------------------------------------------------
// Crypt_HasFakeProviderCert
//---------------------------------------------------------------------------


static BOOLEAN Crypt_HasFakeProviderCert(void)
{
    return (InterlockedCompareExchangePointer(
        (PVOID volatile *)&Crypt_FakeProviderCert.pCert, NULL, NULL) != NULL);
}


//---------------------------------------------------------------------------
// Crypt_TrySeedFakeProviderCert
//---------------------------------------------------------------------------


static void Crypt_TrySeedFakeProviderCert(HCERTSTORE hCertStore)
{
    HMODULE hCrypt32;

    if (!hCertStore || Crypt_HasFakeProviderCert())
        return;

    hCrypt32 = GetModuleHandleW(L"crypt32.dll");
    if (hCrypt32) {
        typedef PCCERT_CONTEXT (WINAPI *P_CertEnum)(HCERTSTORE, PCCERT_CONTEXT);
        typedef PCCERT_CONTEXT (WINAPI *P_CertDup)(PCCERT_CONTEXT);
        typedef BOOL (WINAPI *P_CertFree)(PCCERT_CONTEXT);
        P_CertEnum pfnEnum = (P_CertEnum)GetProcAddress(hCrypt32, "CertEnumCertificatesInStore");
        P_CertDup pfnDup = (P_CertDup)GetProcAddress(hCrypt32, "CertDuplicateCertificateContext");
        P_CertFree pfnFree = (P_CertFree)GetProcAddress(hCrypt32, "CertFreeCertificateContext");

        if (pfnEnum && pfnDup && pfnFree) {
            PCCERT_CONTEXT firstCert = pfnEnum(hCertStore, NULL);

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
                        Crypt_UpdateFakeProviderStatePointers();
                    } else {
                        pfnFree(dupCert);
                    }
                }
            }
        }
    }
}


//---------------------------------------------------------------------------
// Crypt_EnsureFakeProviderCert
//---------------------------------------------------------------------------


static void Crypt_EnsureFakeProviderCert(void)
{
    HMODULE hCrypt32;

    if (Crypt_HasFakeProviderCert())
        return;

    hCrypt32 = GetModuleHandleW(L"crypt32.dll");
    if (!hCrypt32)
        return;

    {
        typedef HCERTSTORE (WINAPI *P_CertOpenSystemStoreW)(HCRYPTPROV_LEGACY, LPCWSTR);
        typedef BOOL (WINAPI *P_CertCloseStore)(HCERTSTORE, DWORD);
        P_CertOpenSystemStoreW pfnOpen =
            (P_CertOpenSystemStoreW)GetProcAddress(hCrypt32, "CertOpenSystemStoreW");
        P_CertCloseStore pfnClose =
            (P_CertCloseStore)GetProcAddress(hCrypt32, "CertCloseStore");

        if (pfnOpen && pfnClose) {
            HCERTSTORE hStore = pfnOpen(0, L"ROOT");
            if (hStore) {
                Crypt_TrySeedFakeProviderCert(hStore);
                pfnClose(hStore, 0);
            }

            if (!Crypt_HasFakeProviderCert()) {
                hStore = pfnOpen(0, L"CA");
                if (hStore) {
                    Crypt_TrySeedFakeProviderCert(hStore);
                    pfnClose(hStore, 0);
                }
            }

            if (!Crypt_HasFakeProviderCert()) {
                hStore = pfnOpen(0, L"MY");
                if (hStore) {
                    Crypt_TrySeedFakeProviderCert(hStore);
                    pfnClose(hStore, 0);
                }
            }
        }
    }

    Crypt_UpdateFakeProviderStatePointers();
}


//---------------------------------------------------------------------------
// Crypt_RefreshFakeProviderState
//---------------------------------------------------------------------------


static void Crypt_RefreshFakeProviderState(void)
{
    Crypt_InitFakeProviderState();
    Crypt_EnsureFakeProviderCert();
    Crypt_UpdateFakeProviderStatePointers();
}


//---------------------------------------------------------------------------
// Crypt_UpdateFakeSignerInfo
//---------------------------------------------------------------------------


static void Crypt_UpdateFakeSignerInfo(void)
{
    PCCERT_CONTEXT pCert = (PCCERT_CONTEXT)InterlockedCompareExchangePointer(
        (PVOID volatile *)&Crypt_FakeProviderCert.pCert, NULL, NULL);

    memzero(&Crypt_FakeSignerInfo, sizeof(Crypt_FakeSignerInfo));

    if (!pCert || !pCert->pCertInfo)
        return;

    Crypt_FakeSignerInfo.dwVersion = CMSG_SIGNER_INFO_V1;
    Crypt_FakeSignerInfo.Issuer = pCert->pCertInfo->Issuer;
    Crypt_FakeSignerInfo.SerialNumber = pCert->pCertInfo->SerialNumber;
    Crypt_FakeSignerInfo.HashAlgorithm.pszObjId = szOID_NIST_sha256;
    Crypt_FakeSignerInfo.HashEncryptionAlgorithm.pszObjId = szOID_RSA_SHA256RSA;
}


//---------------------------------------------------------------------------
// Crypt_UpdateFakeProviderStatePointers
//---------------------------------------------------------------------------


static void Crypt_UpdateFakeProviderStatePointers(void)
{
    Crypt_UpdateFakeSignerInfo();

    if (Crypt_HasFakeProviderCert()) {
        Crypt_FakeProviderSigner.pasCertChain = &Crypt_FakeProviderCert;
        Crypt_FakeProviderSigner.csCertChain = 1;
        Crypt_FakeProviderSigner.psSigner =
            (Crypt_FakeSignerInfo.SerialNumber.pbData && Crypt_FakeSignerInfo.Issuer.pbData)
                ? &Crypt_FakeSignerInfo : NULL;
        Crypt_FakeProviderData.pasSigners = &Crypt_FakeProviderSigner;
        Crypt_FakeProviderData.csSigners = 1;
    } else {
        Crypt_FakeProviderSigner.pasCertChain = NULL;
        Crypt_FakeProviderSigner.csCertChain = 0;
        Crypt_FakeProviderSigner.psSigner = NULL;
        Crypt_FakeProviderData.pasSigners = NULL;
        Crypt_FakeProviderData.csSigners = 0;
    }
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


static BOOLEAN Crypt_HasCatalogBinding(HANDLE hStateData)
{
    ULONG i;

    if (!hStateData)
        return FALSE;

    for (i = 0; i < sizeof(Crypt_CatBindings) / sizeof(Crypt_CatBindings[0]); ++i) {
        if ((PVOID)InterlockedCompareExchangePointer(
                (PVOID volatile *)&Crypt_CatBindings[i], NULL, NULL) != NULL
                && Crypt_CatBindings[i]->hState == hStateData)
            return TRUE;
    }

    return FALSE;
}


static void Crypt_SetProviderDataCatalogSignature(
    CRYPT_PROVIDER_DATA *pProvData, HANDLE hStateData, BOOLEAN force_mark)
{
    if (!pProvData || (!force_mark && !Crypt_HasCatalogBinding(hStateData)))
        return;

    // Mark as catalog signature by setting pPDSip to valid memory.
    // pPDSip != NULL indicates catalog vs embedded signature.
    if (!pProvData->pPDSip && pProvData->cbStruct >= CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, pPDSip)) {
        pProvData->pPDSip = (PVOID)&Crypt_CatBindings[0];
    }

    // Also set dwSubjectChoice to indicate catalog signature type.
    if (pProvData->cbStruct >= CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, dwSubjectChoice)) {
        if (pProvData->dwSubjectChoice == 0) {
            pProvData->dwSubjectChoice = WTD_CHOICE_CATALOG;
        }
    }
}


static void Crypt_SanitizeForcedProviderData(
    CRYPT_PROVIDER_DATA *pProvData, HANDLE hStateData, BOOLEAN trace, BOOLEAN catalog_hint)
{
    DWORD k;
    BOOLEAN has_fake_cert;
    BOOLEAN is_catalog_binding;

    Crypt_RefreshFakeProviderState();
    has_fake_cert = Crypt_HasFakeProviderCert();
    is_catalog_binding = (catalog_hint || Crypt_HasCatalogBinding(hStateData));

    if (!pProvData)
        return;

    if (pProvData->cbStruct < CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, dwFinalError)
            || pProvData->cbStruct < CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, dwError)
            || pProvData->cbStruct < CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, pasSigners)
            || pProvData->cbStruct < CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, csSigners))
        return;

    pProvData->dwFinalError = ERROR_SUCCESS;
    pProvData->dwError = ERROR_SUCCESS;

    // For catalog signatures, mark the provider data as such by setting pPDSip
    if (is_catalog_binding)
        Crypt_SetProviderDataCatalogSignature(pProvData, hStateData, TRUE);

    if ((!pProvData->pasSigners || pProvData->csSigners == 0) && has_fake_cert) {
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
                    && (!pCertChain || cCertChain == 0
                        || (cCertChain > 0 && pCertChain[0].pCert == NULL))) {
                if (has_fake_cert) {
                    Crypt_SetProviderSignerCertChain(
                        &pProvData->pasSigners[k], &Crypt_FakeProviderCert, 1);
                } else {
                    Crypt_SetProviderSignerCertChain(
                        &pProvData->pasSigners[k], NULL, 0);
                }
            }
        }
    }

    if (trace) {
        CRYPT_PROVIDER_CERT *pCertChain = NULL;
        DWORD cCertChain = 0;

        if (pProvData->pasSigners && pProvData->csSigners)
            Crypt_GetProviderSignerCertChain(
                &pProvData->pasSigners[0], &pCertChain, &cCertChain);

        Crypt_Trace(L"WVT provdata sanitized signers=%u chain=%u catalog=%d state=%p",
            pProvData->csSigners,
            cCertChain,
            is_catalog_binding ? 1 : 0,
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
// Crypt_AllocCatBinding
//---------------------------------------------------------------------------


static void Crypt_AllocCatBinding(
    HANDLE hState,
    const WINTRUST_DATA *wtd_in,
    const WINTRUST_CATALOG_INFO *wtc_in,
    const WCHAR *catPath,
    const WCHAR *memberPath,
    const WCHAR *memberTag)
{
    CRYPT_CAT_BINDING *entry;
    CRYPT_PROVIDER_DATA *pProvData;
    ULONG i;
    DWORD cat_len, mem_len, tag_len;

    if (!hState || !wtd_in || !wtc_in)
        return;

    // Replace existing binding for this state.
    Crypt_FreeCatBinding(hState);

    entry = (CRYPT_CAT_BINDING *)Dll_Alloc(sizeof(CRYPT_CAT_BINDING));
    if (!entry)
        return;

    entry->hState = hState;
    memcpy(&entry->wtd, wtd_in, sizeof(WINTRUST_DATA));
    memcpy(&entry->wtc, wtc_in, sizeof(WINTRUST_CATALOG_INFO));

    entry->cat_path[0] = L'\0';
    entry->member_path[0] = L'\0';
    entry->member_tag[0] = L'\0';

    if (catPath && catPath[0]) {
        cat_len = (DWORD)(sizeof(entry->cat_path) / sizeof(WCHAR)) - 1;
        wcsncpy(entry->cat_path, catPath, cat_len);
        entry->cat_path[cat_len] = L'\0';
    }
    if (memberPath && memberPath[0]) {
        mem_len = (DWORD)(sizeof(entry->member_path) / sizeof(WCHAR)) - 1;
        wcsncpy(entry->member_path, memberPath, mem_len);
        entry->member_path[mem_len] = L'\0';
    }
    if (memberTag && memberTag[0]) {
        tag_len = (DWORD)(sizeof(entry->member_tag) / sizeof(WCHAR)) - 1;
        wcsncpy(entry->member_tag, memberTag, tag_len);
        entry->member_tag[tag_len] = L'\0';
    }

    // Fix up internal pointers in the persistent copies.
    entry->wtd.pCatalog = &entry->wtc;
    entry->wtc.pcwszCatalogFilePath = entry->cat_path;
    entry->wtc.pcwszMemberFilePath = entry->member_path;
    entry->wtc.pcwszMemberTag = entry->member_tag;
    // Clear fields that are no longer valid after the verify call returns.
    entry->wtc.hMemberFile = NULL;
    entry->wtc.pbCalculatedFileHash = NULL;
    entry->wtc.cbCalculatedFileHash = 0;

    // Store in the binding table.
    for (i = 0; i < sizeof(Crypt_CatBindings) / sizeof(Crypt_CatBindings[0]); ++i) {
        if (InterlockedCompareExchangePointer(
                (PVOID volatile *)&Crypt_CatBindings[i],
                entry, NULL) == NULL) {
            // Patch the provider data to point to the persistent WINTRUST_DATA
            // copy, preventing CRYPT_PROVIDER_DATA::pWintrustData from dangling.
            if (__sys_WTHelperProvDataFromStateData) {
                pProvData = __sys_WTHelperProvDataFromStateData(hState);
                if (pProvData
                        && pProvData->cbStruct >= CRYPT_STRUCT_FIELD_END(
                                CRYPT_PROVIDER_DATA, pWintrustData)) {
                    pProvData->pWintrustData = &entry->wtd;
                }
            }
            return;
        }
    }

    // Table full - free the entry gracefully.
    Dll_Free(entry);
}


//---------------------------------------------------------------------------
// Crypt_FreeCatBinding
//---------------------------------------------------------------------------


static void Crypt_FreeCatBinding(HANDLE hState)
{
    CRYPT_CAT_BINDING *entry;
    ULONG i;

    if (!hState)
        return;

    for (i = 0; i < sizeof(Crypt_CatBindings) / sizeof(Crypt_CatBindings[0]); ++i) {
        entry = (CRYPT_CAT_BINDING *)InterlockedCompareExchangePointer(
            (PVOID volatile *)&Crypt_CatBindings[i], NULL, NULL);
        if (entry && entry->hState == hState) {
            InterlockedExchangePointer((PVOID volatile *)&Crypt_CatBindings[i], NULL);
            // Intentionally do not free here. Provider callbacks may still
            // hold pWintrustData pointers briefly after close; keeping the
            // allocation avoids use-after-free crashes in tight call races.
            return;
        }
    }
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

    Crypt_FreeCatBinding(hStateData);

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
// Crypt_HandleWinTrustCloseState
//---------------------------------------------------------------------------


static BOOLEAN Crypt_HandleWinTrustCloseState(
    const WCHAR *trace_tag, BOOLEAN trace,
    BOOLEAN has_state_action, DWORD state_action,
    BOOLEAN has_state_handle, HANDLE hStateData,
    LONG *pResult)
{
    BOOLEAN is_forced_state;

    if (!(has_state_action
            && state_action == WTD_STATEACTION_CLOSE
            && has_state_handle
            && hStateData))
        return FALSE;

    is_forced_state = Crypt_IsForcedTrustState(hStateData);

    if (hStateData == Crypt_GetFakeStateHandle()) {
        Crypt_ForgetForcedTrustState(hStateData);
        if (trace) {
            Crypt_Trace(L"%s fake close state=%p caller=%p",
                trace_tag,
                CRYPT_REDACT(hStateData),
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
        SetLastError(ERROR_SUCCESS);
        *pResult = ERROR_SUCCESS;
        return TRUE;
    }

    if (is_forced_state)
        Crypt_ForgetForcedTrustState(hStateData);

    if (is_forced_state && __sys_WTHelperProvDataFromStateData) {
        CRYPT_PROVIDER_DATA *pProv =
            __sys_WTHelperProvDataFromStateData(hStateData);
        Crypt_RestoreForcedProviderData(pProv);
    }

    return FALSE;
}


//---------------------------------------------------------------------------
// Crypt_TraceWinTrustResult
//---------------------------------------------------------------------------


static void Crypt_TraceWinTrustResult(
    const WCHAR *trace_tag, BOOLEAN trace, LONG result,
    BOOLEAN has_union_choice, DWORD union_choice,
    BOOLEAN has_state_action, DWORD state_action,
    HANDLE hStateData, const WCHAR *path)
{
    if (path && path[0]) {
        if (trace
#if !defined(_DEBUG) && !defined(_CRYPTDEBUG)
            && (result != ERROR_SUCCESS
                || Crypt_GetTrustModeForPath(path) == CRYPT_TRUST_MODE_FAKE)
#endif
        ) {
            Crypt_Trace(L"%s rc=%08X action=%u state=%p file=%s caller=%p",
                trace_tag,
                (ULONG)result,
                (ULONG)(has_state_action ? state_action : 0),
                CRYPT_REDACT(hStateData),
                path ? path : L"(null)",
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
    } else {
#if defined(_DEBUG) || defined(_CRYPTDEBUG)
        if (trace && has_union_choice) {
            Crypt_Trace(L"%s rc=%08X choice=%u action=%u state=%p caller=%p",
                trace_tag,
                (ULONG)result,
                (ULONG)union_choice,
                (ULONG)(has_state_action ? state_action : 0),
                CRYPT_REDACT(hStateData),
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
#else
        (void)trace_tag;
        (void)trace;
        (void)result;
        (void)has_union_choice;
        (void)union_choice;
        (void)has_state_action;
        (void)state_action;
        (void)hStateData;
#endif
    }
}


//---------------------------------------------------------------------------
// Crypt_TraceWinTrustProviderState
//---------------------------------------------------------------------------


static void Crypt_TraceWinTrustProviderState(
    const WCHAR *trace_tag, BOOLEAN trace,
    BOOLEAN has_state_action, DWORD state_action,
    BOOLEAN is_force_target, HANDLE hStateData)
{
    if (trace
            && is_force_target
            && has_state_action
            && state_action != WTD_STATEACTION_CLOSE
            && hStateData
            && __sys_WTHelperProvDataFromStateData) {
        CRYPT_PROVIDER_DATA *pProv =
            __sys_WTHelperProvDataFromStateData(hStateData);
        if (pProv) {
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
                L"%s state signers=%u chain=%u pCert=%p sgnrPtr=%p",
                trace_tag,
                signerCount, chainLen, CRYPT_REDACT(pCert), CRYPT_REDACT(signerPtr));
        }
    }
}


//---------------------------------------------------------------------------
// Crypt_TraceWinTrustInput
//---------------------------------------------------------------------------


static void Crypt_TraceWinTrustInput(
    const WCHAR *trace_tag, BOOLEAN trace,
    const WINTRUST_DATA *pWinTrustData,
    BOOLEAN has_union_choice, DWORD union_choice,
    BOOLEAN has_state_action, DWORD state_action,
    BOOLEAN has_state_handle, HANDLE hStateData)
{
    WCHAR file_path_buf[260];
    WCHAR member_path_buf[260];
    WCHAR catalog_path_buf[260];
    WCHAR tag_buf[160];

    file_path_buf[0] = L'\0';
    member_path_buf[0] = L'\0';
    catalog_path_buf[0] = L'\0';
    tag_buf[0] = L'\0';

    if (!trace || !pWinTrustData)
        return;

    if (has_state_action && state_action == WTD_STATEACTION_CLOSE) {
        Crypt_Trace(L"%s input close choice=%u state=%p cb=%u caller=%p",
            trace_tag,
            (ULONG)(has_union_choice ? union_choice : 0),
            CRYPT_REDACT(has_state_handle ? hStateData : NULL),
            (ULONG)pWinTrustData->cbStruct,
            CRYPT_REDACT(Crypt_GetCallerAddress()));
        return;
    }

    if (!has_union_choice) {
        Crypt_Trace(L"%s input missing union choice action=%u state=%p cb=%u caller=%p",
            trace_tag,
            (ULONG)(has_state_action ? state_action : 0),
            CRYPT_REDACT(has_state_handle ? hStateData : NULL),
            (ULONG)pWinTrustData->cbStruct,
            CRYPT_REDACT(Crypt_GetCallerAddress()));
        return;
    }

    if (union_choice == WTD_CHOICE_FILE) {
        WINTRUST_FILE_INFO *pFile = NULL;
        const WCHAR *file_path = NULL;
        DWORD file_cb = 0;

        if (pWinTrustData->cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, pFile)
                && pWinTrustData->pFile) {
            pFile = pWinTrustData->pFile;
            __try {
                file_cb = pFile->cbStruct;
                if (pFile->cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_FILE_INFO, pcwszFilePath))
                    file_path = pFile->pcwszFilePath;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                file_cb = 0;
                file_path = L"<invalid>";
            }
        }

        if (file_path) {
            __try {
                size_t i;
                for (i = 0; i + 1 < sizeof(file_path_buf) / sizeof(file_path_buf[0]); ++i) {
                    WCHAR ch = file_path[i];
                    file_path_buf[i] = ch;
                    if (!ch)
                        break;
                }
                file_path_buf[(sizeof(file_path_buf) / sizeof(file_path_buf[0])) - 1] = L'\0';
                file_path = file_path_buf;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                file_path = L"<invalid>";
            }
        }

        Crypt_Trace(L"%s input choice=%u action=%u state=%p file_cb=%u file=%s caller=%p",
            trace_tag,
            (ULONG)union_choice,
            (ULONG)(has_state_action ? state_action : 0),
            CRYPT_REDACT(has_state_handle ? hStateData : NULL),
            (ULONG)file_cb,
            file_path ? file_path : L"(null)",
            CRYPT_REDACT(Crypt_GetCallerAddress()));
        return;
    }

    if (union_choice == WTD_CHOICE_CATALOG) {
        WINTRUST_CATALOG_INFO *pCatalog = NULL;
        const WCHAR *member_path = NULL;
        const WCHAR *catalog_path = NULL;
        const WCHAR *tag = NULL;
        DWORD catalog_cb = 0;

        if (pWinTrustData->cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_DATA, pCatalog)
                && pWinTrustData->pCatalog) {
            pCatalog = pWinTrustData->pCatalog;
            __try {
                catalog_cb = pCatalog->cbStruct;
                if (pCatalog->cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_CATALOG_INFO, pcwszMemberFilePath))
                    member_path = pCatalog->pcwszMemberFilePath;
                if (pCatalog->cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_CATALOG_INFO, pcwszCatalogFilePath))
                    catalog_path = pCatalog->pcwszCatalogFilePath;
                if (pCatalog->cbStruct >= CRYPT_STRUCT_FIELD_END(WINTRUST_CATALOG_INFO, pcwszMemberTag))
                    tag = pCatalog->pcwszMemberTag;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                catalog_cb = 0;
                member_path = L"<invalid>";
                catalog_path = L"<invalid>";
                tag = L"<invalid>";
            }
        }

        if (member_path) {
            __try {
                size_t i;
                for (i = 0; i + 1 < sizeof(member_path_buf) / sizeof(member_path_buf[0]); ++i) {
                    WCHAR ch = member_path[i];
                    member_path_buf[i] = ch;
                    if (!ch)
                        break;
                }
                member_path_buf[(sizeof(member_path_buf) / sizeof(member_path_buf[0])) - 1] = L'\0';
                member_path = member_path_buf;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                member_path = L"<invalid>";
            }
        }

        if (catalog_path) {
            __try {
                size_t i;
                for (i = 0; i + 1 < sizeof(catalog_path_buf) / sizeof(catalog_path_buf[0]); ++i) {
                    WCHAR ch = catalog_path[i];
                    catalog_path_buf[i] = ch;
                    if (!ch)
                        break;
                }
                catalog_path_buf[(sizeof(catalog_path_buf) / sizeof(catalog_path_buf[0])) - 1] = L'\0';
                catalog_path = catalog_path_buf;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                catalog_path = L"<invalid>";
            }
        }

        if (tag) {
            __try {
                size_t i;
                for (i = 0; i + 1 < sizeof(tag_buf) / sizeof(tag_buf[0]); ++i) {
                    WCHAR ch = tag[i];
                    tag_buf[i] = ch;
                    if (!ch)
                        break;
                }
                tag_buf[(sizeof(tag_buf) / sizeof(tag_buf[0])) - 1] = L'\0';
                tag = tag_buf;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                tag = L"<invalid>";
            }
        }

        Crypt_Trace(
            L"%s input choice=%u action=%u state=%p cat_cb=%u member=%s catalog=%s tag=%s caller=%p",
            trace_tag,
            (ULONG)union_choice,
            (ULONG)(has_state_action ? state_action : 0),
            CRYPT_REDACT(has_state_handle ? hStateData : NULL),
            (ULONG)catalog_cb,
            member_path ? member_path : L"(null)",
            catalog_path ? catalog_path : L"(null)",
            tag ? tag : L"(null)",
            CRYPT_REDACT(Crypt_GetCallerAddress()));
        return;
    }

    Crypt_Trace(L"%s input choice=%u action=%u state=%p cb=%u caller=%p",
        trace_tag,
        (ULONG)union_choice,
        (ULONG)(has_state_action ? state_action : 0),
        CRYPT_REDACT(has_state_handle ? hStateData : NULL),
        (ULONG)pWinTrustData->cbStruct,
        CRYPT_REDACT(Crypt_GetCallerAddress()));
}


//---------------------------------------------------------------------------
// Crypt_ForceWinTrustSuccess
//---------------------------------------------------------------------------


static BOOLEAN Crypt_ForceWinTrustSuccess(
    const WCHAR *trace_tag, BOOLEAN trace, LONG result,
    BOOLEAN has_state_action, DWORD state_action,
    BOOLEAN is_force_target,
    WINTRUST_DATA *pWinTrustData, HANDLE *phStateData,
    const WCHAR *path)
{
    HANDLE hStateData;

    if (!(result != ERROR_SUCCESS
            && has_state_action
            && state_action != WTD_STATEACTION_CLOSE
            && is_force_target))
        return FALSE;

    hStateData = (phStateData ? *phStateData : NULL);

    if (state_action == WTD_STATEACTION_VERIFY) {
        BOOLEAN remember_ok;

        if (!hStateData && Crypt_SetWinTrustStateHandle(
                pWinTrustData, Crypt_GetFakeStateHandle())) {
            hStateData = Crypt_GetFakeStateHandle();
            if (phStateData)
                *phStateData = hStateData;
        }

        remember_ok = Crypt_RememberForcedTrustState(hStateData);

        if (remember_ok
                && hStateData
                && __sys_WTHelperProvDataFromStateData
                && hStateData != Crypt_GetFakeStateHandle()) {
            CRYPT_PROVIDER_DATA *pProv =
                __sys_WTHelperProvDataFromStateData(hStateData);
            Crypt_SanitizeForcedProviderData(pProv, hStateData, trace, FALSE);
        }

        if (!remember_ok && trace && hStateData != Crypt_GetFakeStateHandle()) {
            Crypt_Trace(L"%s force skip sanitize state=%p file=%s caller=%p",
                trace_tag,
                CRYPT_REDACT(hStateData),
                path ? path : L"(null)",
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
    }

    if (trace) {
        Crypt_Trace(L"%s force rc=%08X action=%u state=%p file=%s caller=%p",
            trace_tag,
            (ULONG)result,
            (ULONG)state_action,
            CRYPT_REDACT(hStateData),
            path ? path : L"(null)",
            CRYPT_REDACT(Crypt_GetCallerAddress()));
    }

    SetLastError(ERROR_SUCCESS);
    return TRUE;
}


//---------------------------------------------------------------------------
// Crypt_RunWinVerifyTrust
//---------------------------------------------------------------------------


static LONG Crypt_RunWinVerifyTrust(
    LONG (WINAPI *pfnVerifyTrust)(HWND, GUID *, WINTRUST_DATA *),
    const WCHAR *trace_tag,
    BOOLEAN trace_provider_state,
    HWND hwnd, GUID *pgActionID, WINTRUST_DATA *pWinTrustData)
{
    LONG result;
    const WCHAR *path_ptr = NULL;
    WCHAR path_buf[MAX_PATH + 1] = { 0 };
    const WCHAR *path = path_buf;
    BOOLEAN trace = Crypt_HasTrustRules();
    BOOLEAN is_force_target = FALSE;
    BOOLEAN force_chain_policy = FALSE;
    ULONG trust_mode = CRYPT_TRUST_MODE_NONE;
    BOOLEAN allow_file_path;
    DWORD union_choice = 0;
    DWORD state_action = 0;
    HANDLE hStateData = NULL;
    BOOLEAN has_union_choice =
        Crypt_GetWinTrustUnionChoice(pWinTrustData, &union_choice);
    BOOLEAN has_state_action =
        Crypt_GetWinTrustStateAction(pWinTrustData, &state_action);
    BOOLEAN has_state_handle =
        Crypt_GetWinTrustStateHandle(pWinTrustData, &hStateData);
    BOOLEAN catalog_preferred_tried = FALSE;
    BOOLEAN catalog_preferred_ok = FALSE;

    // Detect re-entrant WVT call from inside real WinVerifyTrustEx.
    // When real WinVerifyTrustEx internally invokes WinVerifyTrust (hooked
    // here) during a CLOSE state action, skip calling __sys_WinVerifyTrust
    // to avoid a double-free: real WinVerifyTrustEx cleans up the state
    // itself after this returns.
    if (pfnVerifyTrust == __sys_WinVerifyTrust
            && Crypt_IsInSysWvtex()
            && has_state_action
            && state_action == WTD_STATEACTION_CLOSE) {
        if (Crypt_HasTrustRules()) {
            Crypt_Trace(L"%s wvtex inner close skip state=%p caller=%p",
                trace_tag,
                CRYPT_REDACT(hStateData),
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
        return ERROR_SUCCESS;
    }

    allow_file_path = (!has_state_action || state_action != WTD_STATEACTION_CLOSE);
    if (allow_file_path) {
        path_ptr = Crypt_GetWinTrustFilePath(pWinTrustData);
        if (!path_ptr
                || !Crypt_CopyPathSafe(path_ptr, path_buf, sizeof(path_buf) / sizeof(path_buf[0]))
                || !path_buf[0]) {
            path_buf[0] = L'\0';
        }
    }

    if (Crypt_HandleWinTrustCloseState(
                trace_tag, trace,
                has_state_action, state_action,
                has_state_handle, hStateData,
                &result))
        return result;

    if (path && path[0] && (!has_state_action || state_action != WTD_STATEACTION_CLOSE)) {
        trust_mode = Crypt_GetTrustModeForPath(path);
        is_force_target = (trust_mode == CRYPT_TRUST_MODE_FAKE);
        force_chain_policy = (trust_mode != CRYPT_TRUST_MODE_NONE);
        if (trace && trust_mode != CRYPT_TRUST_MODE_NONE) {
            Crypt_Trace(L"%s mode=%s file=%s caller=%p",
                trace_tag,
                (trust_mode == CRYPT_TRUST_MODE_CATALOG) ? L"catalog" : L"fake",
                path,
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
    }

    if (force_chain_policy)
        Crypt_EnterForceChainPolicy();

    Crypt_TraceWinTrustInput(
        trace_tag, trace,
        pWinTrustData,
        has_union_choice, union_choice,
        has_state_action, state_action,
        has_state_handle, hStateData);

    // In catalog mode, prefer catalog verification for FILE requests without
    // mutating caller-owned WINTRUST_DATA union arms.
    if (trust_mode == CRYPT_TRUST_MODE_CATALOG
            && has_union_choice
            && union_choice == WTD_CHOICE_FILE
            && (!has_state_action
                || state_action == WTD_STATEACTION_VERIFY
                || state_action == WTD_STATEACTION_IGNORE)
            && path && path[0]) {
        catalog_preferred_tried = TRUE;
        if (InterlockedCompareExchange(&Crypt_CatalogFallbackActive, 1, 0) == 0) {
            LONG cat_result = Crypt_TryCatalogVerify(
                pfnVerifyTrust, trace_tag, trace,
                hwnd, pgActionID,
                pWinTrustData,
                path);

            InterlockedExchange(&Crypt_CatalogFallbackActive, 0);

            if (cat_result == ERROR_SUCCESS) {
                catalog_preferred_ok = TRUE;
                result = ERROR_SUCCESS;
                if (trace) {
                    Crypt_Trace(L"%s catalog preferred rc=%08X file=%s caller=%p",
                        trace_tag,
                        (ULONG)cat_result,
                        path,
                        CRYPT_REDACT(Crypt_GetCallerAddress()));
                }
            }
        } else if (trace) {
            Crypt_Trace(L"%s catalog prefer skip reentrant file=%s caller=%p",
                trace_tag,
                path,
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
    }

    if (!catalog_preferred_ok) {
        BOOLEAN is_wvtex_call = (pfnVerifyTrust == (P_WinVerifyTrust)__sys_WinVerifyTrustEx);
        if (is_wvtex_call)
            Crypt_EnterSysWvtex();
        result = pfnVerifyTrust(hwnd, pgActionID, pWinTrustData);
        if (is_wvtex_call)
            Crypt_LeaveSysWvtex();
    }

    if (trace) {
        DWORD verify_err = GetLastError();
        Crypt_Trace(L"%s post rc=%08X gle=%08X caller=%p",
            trace_tag,
            (ULONG)result,
            (ULONG)verify_err,
            CRYPT_REDACT(Crypt_GetCallerAddress()));
    }

    if (result == TRUST_E_NOSIGNATURE
            && has_union_choice
            && union_choice == WTD_CHOICE_FILE
            && (!has_state_action
                || state_action == WTD_STATEACTION_VERIFY
                || state_action == WTD_STATEACTION_IGNORE)
            && trust_mode == CRYPT_TRUST_MODE_CATALOG
            && !catalog_preferred_tried
            && path && path[0]) {
        if (InterlockedCompareExchange(&Crypt_CatalogFallbackActive, 1, 0) == 0) {
            LONG cat_result = Crypt_TryCatalogVerify(
                pfnVerifyTrust, trace_tag, trace,
                hwnd, pgActionID,
                pWinTrustData,
                path);

            InterlockedExchange(&Crypt_CatalogFallbackActive, 0);

            if (cat_result == ERROR_SUCCESS)
                result = ERROR_SUCCESS;
        } else if (trace) {
            Crypt_Trace(L"%s catalog skip reentrant file=%s caller=%p",
                trace_tag,
                path,
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
    }

    has_state_handle = Crypt_GetWinTrustStateHandle(pWinTrustData, &hStateData);

    if (result == ERROR_SUCCESS
            && trust_mode == CRYPT_TRUST_MODE_CATALOG
            && (!has_state_action || state_action != WTD_STATEACTION_CLOSE)
            && hStateData
            && hStateData != Crypt_GetFakeStateHandle()) {
        BOOLEAN remember_ok = Crypt_RememberForcedTrustState(hStateData);
        if (remember_ok && __sys_WTHelperProvDataFromStateData) {
            CRYPT_PROVIDER_DATA *pProv =
                __sys_WTHelperProvDataFromStateData(hStateData);
            Crypt_SanitizeForcedProviderData(
                pProv, hStateData, trace,
                (has_union_choice && union_choice == WTD_CHOICE_CATALOG));
        } else if (!remember_ok && trace) {
            Crypt_Trace(L"%s catalog state remember failed state=%p file=%s caller=%p",
                trace_tag,
                CRYPT_REDACT(hStateData),
                path ? path : L"(null)",
                CRYPT_REDACT(Crypt_GetCallerAddress()));
        }
    }

    if (force_chain_policy)
        Crypt_LeaveForceChainPolicy();

    if (pWinTrustData) {
        Crypt_TraceWinTrustResult(
            trace_tag, trace, result,
            has_union_choice, union_choice,
            has_state_action, state_action,
            hStateData, path);

        if (trace_provider_state && result == ERROR_SUCCESS)
            Crypt_TraceWinTrustProviderState(
                trace_tag, trace,
                has_state_action, state_action,
                is_force_target, hStateData);

        if (Crypt_ForceWinTrustSuccess(
                    trace_tag, trace, result,
                    has_state_action, state_action,
                    is_force_target,
                    pWinTrustData, &hStateData,
                    path))
            return ERROR_SUCCESS;

        if (has_state_action && state_action == WTD_STATEACTION_CLOSE)
            Crypt_ForgetForcedTrustState(hStateData);
    }

    if (result == ERROR_SUCCESS)
        SetLastError(ERROR_SUCCESS);

    return result;
}


//---------------------------------------------------------------------------
// Crypt_WinVerifyTrust
//---------------------------------------------------------------------------


_FX LONG Crypt_WinVerifyTrust(
    HWND hwnd, GUID *pgActionID, WINTRUST_DATA *pWinTrustData)
{
    return Crypt_RunWinVerifyTrust(
        __sys_WinVerifyTrust, L"WVT", FALSE,
        hwnd, pgActionID, pWinTrustData);
}


//---------------------------------------------------------------------------
// Crypt_WinVerifyTrustEx
//---------------------------------------------------------------------------


_FX LONG Crypt_WinVerifyTrustEx(
    HWND hwnd, GUID *pgActionID, WINTRUST_DATA *pWinTrustData)
{
    return Crypt_RunWinVerifyTrust(
        (P_WinVerifyTrust)__sys_WinVerifyTrustEx, L"WVTEx", TRUE,
        hwnd, pgActionID, pWinTrustData);
}


//---------------------------------------------------------------------------
// Crypt_WTHelperProvDataFromStateData
//---------------------------------------------------------------------------


_FX CRYPT_PROVIDER_DATA *Crypt_WTHelperProvDataFromStateData(HANDLE hStateData)
{
    CRYPT_PROVIDER_DATA *pProvData;
    const WINTRUST_DATA *pProviderWtd = NULL;
    const WCHAR *providerPath = NULL;
    ULONG provider_mode = CRYPT_TRUST_MODE_NONE;
    BOOLEAN has_provider_wtd = FALSE;
    BOOLEAN trace = Crypt_HasTrustRules();

    if (hStateData == Crypt_GetFakeStateHandle()) {
        Crypt_RefreshFakeProviderState();
        if (trace) {
            Crypt_Trace(L"WTHelperProvDataFromStateData fake state=%p",
                CRYPT_REDACT(hStateData));
        }
        return &Crypt_FakeProviderData;
    }

    pProvData = __sys_WTHelperProvDataFromStateData(hStateData);

    has_provider_wtd = Crypt_GetProviderWinTrustData(pProvData, &pProviderWtd);
    if (has_provider_wtd)
        providerPath = Crypt_GetWinTrustFilePath(pProviderWtd);
    if (providerPath && providerPath[0])
        provider_mode = Crypt_GetTrustModeForPath(providerPath);

    if (pProvData && (Crypt_IsForcedTrustState(hStateData)
            || provider_mode != CRYPT_TRUST_MODE_NONE)) {
        if (trace
                && pProvData->cbStruct >= CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, dwFinalError)
                && pProvData->cbStruct >= CRYPT_STRUCT_FIELD_END(CRYPT_PROVIDER_DATA, dwError)
                && (pProvData->dwFinalError || pProvData->dwError)) {
            Crypt_Trace(L"WTHelperProvData sanitize final=%08X err=%08X state=%p",
                pProvData->dwFinalError, pProvData->dwError,
                CRYPT_REDACT(hStateData));
        }

        Crypt_SanitizeForcedProviderData(
            pProvData, hStateData, trace,
            (provider_mode == CRYPT_TRUST_MODE_CATALOG));
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
    ULONG provider_mode = CRYPT_TRUST_MODE_NONE;
    BOOLEAN has_provider_wtd =
        Crypt_GetProviderWinTrustData(pProvData, &pProviderWtd);

    if (pProvData && has_provider_wtd)
        provider_mode = Crypt_GetTrustModeForData(pProviderWtd);

    if (pProvData == &Crypt_FakeProviderData) {
        Crypt_RefreshFakeProviderState();
        Crypt_Trace(L"WTHelperGetProvSignerFromChain fake idx=%u ctr=%u cidx=%u",
            (ULONG)idxSigner, (ULONG)fCounterSigner, (ULONG)idxCounterSigner);
        if (idxSigner == 0 && !fCounterSigner && idxCounterSigner == 0
                && Crypt_HasFakeProviderCert())
            return &Crypt_FakeProviderSigner;
        return NULL;
    }

    pSigner = __sys_WTHelperGetProvSignerFromChain(
        pProvData, idxSigner, fCounterSigner, idxCounterSigner);

    // For fake-mode files always return the fake signer when one is
    // available, regardless of whether the real signer is present.
    // This covers both the "real signer exists but is invalid" and
    // the "no real signer at all" cases in a single check.
    if (provider_mode == CRYPT_TRUST_MODE_FAKE
            && idxSigner == 0
            && !fCounterSigner
            && idxCounterSigner == 0) {
        Crypt_RefreshFakeProviderState();
        if (Crypt_HasFakeProviderCert()) {
            Crypt_Trace(L"WTHelperGetProvSignerFromChain force fake signer");
            return &Crypt_FakeProviderSigner;
        }
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
        Crypt_RefreshFakeProviderState();
        Crypt_Trace(L"WTHelperGetProvCertFromChain fake idx=%u", (ULONG)idxCert);
        if (idxCert == 0 && Crypt_HasFakeProviderCert())
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
    ULONG provider_mode = CRYPT_TRUST_MODE_NONE;
    BOOLEAN has_provider_wtd =
        Crypt_GetProviderWinTrustData(pProvData, &pProviderWtd);

    if (pProvData && has_provider_wtd)
        provider_mode = Crypt_GetTrustModeForData(pProviderWtd);

    if (pProvData == &Crypt_FakeProviderData) {
        Crypt_Trace(L"WTHelperCertCheckValidSignature fake ok");
        return S_OK;
    }

    hr = __sys_WTHelperCertCheckValidSignature(pProvData);

    if (FAILED(hr)
            && pProvData
            && has_provider_wtd
            && provider_mode == CRYPT_TRUST_MODE_FAKE) {

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
