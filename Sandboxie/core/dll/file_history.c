/*
 * Copyright 2026 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */


//---------------------------------------------------------------------------
// File History
//---------------------------------------------------------------------------

#include "common\pattern.h"
#include <bcrypt.h>


//---------------------------------------------------------------------------
// Defines
//---------------------------------------------------------------------------

#define FILE_HISTORY_DIR             L"FileHistory"
#define FILE_HISTORY_INDEX_DIR       L"Index"
#define FILE_HISTORY_ARTIFACT_DIR    L"Artifacts"
#define FILE_HISTORY_BLOB_DIR        L"Blobs"
#define FILE_HISTORY_MARKER_SLOTS    4
#define FILE_HISTORY_COPY_BUFFER     (64 * 1024)
#define FILE_HISTORY_CAPTURE_ATTEMPTS 2
#define FILE_HISTORY_USAGE_SCAN_ATTEMPTS 2
#define FILE_HISTORY_COLLISION_ATTEMPTS 16
#define FILE_HISTORY_PUBLISH_ATTEMPTS 2
#define FILE_HISTORY_SHARING_RETRY_ATTEMPTS 3
#define FILE_HISTORY_SHARING_RETRY_DELAY_MS 10
#define FILE_HISTORY_ULONG_MAX       ((ULONG)-1)
#define FILE_HISTORY_ULONGLONG_MAX   ((ULONGLONG)-1)
#define FILE_HISTORY_DEFAULT_MAX_VERSIONS_TOTAL 2500
#define FILE_HISTORY_DEFAULT_MAX_VERSIONS_PER_FILE 25
#define FILE_HISTORY_DEFAULT_MAX_SIZE_TOTAL_KB (1024 * 1024)
#define FILE_HISTORY_DEFAULT_MAX_FILE_SIZE_KB (10 * 1024)
#define FILE_HISTORY_NOTICE_WARNING  0x00000001
#define FILE_HISTORY_NOTICE_LIMIT    0x00000002
#define FILE_HISTORY_SHA256_SIZE     32
#define FILE_HISTORY_SHA256_TEXT     65
#define FILE_HISTORY_BLOB_NONE       0
#define FILE_HISTORY_BLOB_MISSING    1
#define FILE_HISTORY_BLOB_MATCH      2
#define FILE_HISTORY_BLOB_EXISTING   3
#define FILE_HISTORY_BOX_ROOT        L"%BoxRoot%"


//---------------------------------------------------------------------------
// Variables
//---------------------------------------------------------------------------

static LIST File_HistoryOptions;
static LIST File_HistoryExclusions;
static WCHAR *File_HistoryRoot = NULL;
static WCHAR *File_HistoryIndex = NULL;
static WCHAR *File_HistoryArtifacts = NULL;
static WCHAR *File_HistoryBlobs = NULL;
static ULONG File_HistoryMaxVersionsTotal = 0;
static ULONG File_HistoryMaxVersionsPerFile = 0;
static ULONGLONG File_HistoryMaxSizeTotal = 0;
static ULONGLONG File_HistoryMaxFileSize = 0;
static BOOLEAN File_HistoryCaptureMigrated = FALSE;
static BOOLEAN File_HistoryLogWarnings = TRUE;
static HANDLE File_HistoryNoticeHandle = NULL;
static volatile LONG *File_HistoryNoticeFlags = NULL;
static volatile LONG File_HistoryLocalNoticeFlags = 0;
typedef struct _FILE_HISTORY_USAGE_STATE {
    volatile LONG Initialized;
    ULONG Versions;
    ULONGLONG Size;
} FILE_HISTORY_USAGE_STATE;
C_ASSERT(FIELD_OFFSET(FILE_HISTORY_USAGE_STATE, Size) == 8);
C_ASSERT(sizeof(FILE_HISTORY_USAGE_STATE) == 16);
static HANDLE File_HistoryUsageHandle = NULL;
static FILE_HISTORY_USAGE_STATE *File_HistoryUsageState = NULL;
static volatile LONG File_HistorySequence = 0;

typedef struct _FILE_HISTORY_RENAME_ENTRY {
    LIST_ELEM List;
    WCHAR *Artifact;
    WCHAR *TruePath;
    WCHAR *CopyPath;
} FILE_HISTORY_RENAME_ENTRY;

typedef NTSTATUS (WINAPI *P_FileHistoryBCryptOpenAlgorithmProvider)(
    BCRYPT_ALG_HANDLE *, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *P_FileHistoryBCryptGetProperty)(
    BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG *, ULONG);
typedef NTSTATUS (WINAPI *P_FileHistoryBCryptCreateHash)(
    BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE *, PUCHAR, ULONG,
    PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *P_FileHistoryBCryptHashData)(
    BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *P_FileHistoryBCryptFinishHash)(
    BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *P_FileHistoryBCryptDestroyHash)(
    BCRYPT_HASH_HANDLE);
typedef NTSTATUS (WINAPI *P_FileHistoryBCryptCloseAlgorithmProvider)(
    BCRYPT_ALG_HANDLE, ULONG);

typedef struct _FILE_HISTORY_HASH_CONTEXT {
    BCRYPT_HASH_HANDLE Hash;
    UCHAR *Object;
    P_FileHistoryBCryptHashData HashData;
    P_FileHistoryBCryptFinishHash FinishHash;
    P_FileHistoryBCryptDestroyHash DestroyHash;
} FILE_HISTORY_HASH_CONTEXT;

typedef struct _FILE_HISTORY_HASH_API {
    BCRYPT_ALG_HANDLE Algorithm;
    ULONG ObjectLength;
    P_FileHistoryBCryptCreateHash CreateHash;
    P_FileHistoryBCryptHashData HashData;
    P_FileHistoryBCryptFinishHash FinishHash;
    P_FileHistoryBCryptDestroyHash DestroyHash;
} FILE_HISTORY_HASH_API;

static FILE_HISTORY_HASH_API File_HistoryHashApi;

static _FX NTSTATUS File_HistoryQueryIdentity(
    const WCHAR *Path, FILE_INTERNAL_INFORMATION *Internal,
    FILE_NETWORK_OPEN_INFORMATION *Network,
    FILE_STANDARD_INFORMATION *Standard);
static _FX BOOLEAN File_HistoryQueryProcessCreationTime(
    HANDLE Process, ULONGLONG *CreationTime);
static _FX WCHAR *File_HistoryGetMetadataField(
    const WCHAR *Text, const WCHAR *Name, BOOLEAN Unescape);
static _FX WCHAR *File_HistoryGetCopyPathField(
    const WCHAR *Text, const WCHAR *Name);
static _FX WCHAR *File_HistorySetMetadataField(
    const WCHAR *Text, const WCHAR *Name, const WCHAR *Value);
static _FX VOID File_HistoryUpdatePendingPaths(
    const WCHAR *Artifact, const WCHAR *TruePath, const WCHAR *CopyPath);
static _FX HANDLE File_HistoryCreateLimitMutex(BOOLEAN *Abandoned);
static _FX NTSTATUS File_HistoryCheckLimits(
    const WCHAR *ArtifactPath, ULONGLONG AdditionalSize, HANDLE *Mutex);
static _FX BOOLEAN File_HistoryCapture(
    const WCHAR *TruePath, const WCHAR *CopyPath, const WCHAR *Operation);


//---------------------------------------------------------------------------
// File_HistoryQueryLimit
//---------------------------------------------------------------------------


static _FX ULONGLONG File_HistoryQueryLimit(
    const WCHAR *Name, ULONGLONG Default)
{
    WCHAR text[64];
    WCHAR *ptr;
    ULONGLONG value = 0;
    ULONG digit;

    if (!NT_SUCCESS(SbieApi_QueryConfAsIs(
            NULL, Name, 0, text, sizeof(text))) || !text[0])
        return Default;

    for (ptr = text; *ptr; ++ptr) {
        if (*ptr < L'0' || *ptr > L'9')
            return Default;
        digit = *ptr - L'0';
        if (value > (FILE_HISTORY_ULONGLONG_MAX - digit) / 10)
            return FILE_HISTORY_ULONGLONG_MAX;
        value = value * 10 + digit;
    }

    return value;
}


//---------------------------------------------------------------------------
// File_HistoryHash
//---------------------------------------------------------------------------


static _FX VOID File_HistoryFreeHash(
    FILE_HISTORY_HASH_CONTEXT *Context)
{
    if (Context->Hash && Context->DestroyHash)
        Context->DestroyHash(Context->Hash);
    if (Context->Object)
        Dll_Free(Context->Object);
    memzero(Context, sizeof(FILE_HISTORY_HASH_CONTEXT));
}


static _FX BOOLEAN File_HistoryInitCrypto(void)
{
    WCHAR conf_buf[2048];
    FILE_HISTORY_HASH_API api;
    HMODULE module;
    P_FileHistoryBCryptOpenAlgorithmProvider open_algorithm;
    P_FileHistoryBCryptGetProperty get_property;
    P_FileHistoryBCryptCloseAlgorithmProvider close_provider;
    ULONG object_size;
    ULONG result_size;
    NTSTATUS status;

    if (!SbieApi_QueryConfBool(NULL, L"FileHistory", TRUE) ||
            File_HistoryHashApi.Algorithm)
        return TRUE;
    if (!NT_SUCCESS(SbieApi_QueryConf(
            NULL, L"KeepFileVersions", 0,
            conf_buf, sizeof(conf_buf) - 16 * sizeof(WCHAR))))
        return TRUE;

    memzero(&api, sizeof(api));
    module = GetModuleHandleW(L"bcrypt.dll");
    if (!module)
        module = LoadLibraryW(L"bcrypt.dll");
    if (!module)
        return FALSE;

    open_algorithm =
        (P_FileHistoryBCryptOpenAlgorithmProvider)GetProcAddress(
            module, "BCryptOpenAlgorithmProvider");
    get_property =
        (P_FileHistoryBCryptGetProperty)GetProcAddress(
            module, "BCryptGetProperty");
    api.CreateHash =
        (P_FileHistoryBCryptCreateHash)GetProcAddress(
            module, "BCryptCreateHash");
    api.HashData =
        (P_FileHistoryBCryptHashData)GetProcAddress(
            module, "BCryptHashData");
    api.FinishHash =
        (P_FileHistoryBCryptFinishHash)GetProcAddress(
            module, "BCryptFinishHash");
    api.DestroyHash =
        (P_FileHistoryBCryptDestroyHash)GetProcAddress(
            module, "BCryptDestroyHash");
    close_provider =
        (P_FileHistoryBCryptCloseAlgorithmProvider)GetProcAddress(
            module, "BCryptCloseAlgorithmProvider");
    if (!open_algorithm || !get_property ||
            !api.CreateHash || !api.HashData || !api.FinishHash ||
            !api.DestroyHash || !close_provider) {
        return FALSE;
    }

    status = open_algorithm(
        &api.Algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status))
        return FALSE;

    status = get_property(
        api.Algorithm, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&object_size, sizeof(object_size), &result_size, 0);
    if (!NT_SUCCESS(status) || result_size != sizeof(object_size) ||
            !object_size) {
        close_provider(api.Algorithm, 0);
        return FALSE;
    }

    api.ObjectLength = object_size;
    File_HistoryHashApi = api;
    return TRUE;
}


static _FX BOOLEAN File_HistoryInitHash(
    FILE_HISTORY_HASH_CONTEXT *Context)
{
    NTSTATUS status;

    memzero(Context, sizeof(FILE_HISTORY_HASH_CONTEXT));
    if (!File_HistoryHashApi.Algorithm ||
            !File_HistoryHashApi.CreateHash) {
        return FALSE;
    }

    Context->HashData = File_HistoryHashApi.HashData;
    Context->FinishHash = File_HistoryHashApi.FinishHash;
    Context->DestroyHash = File_HistoryHashApi.DestroyHash;

    Context->Object = Dll_AllocTemp(File_HistoryHashApi.ObjectLength);
    if (!Context->Object) {
        File_HistoryFreeHash(Context);
        return FALSE;
    }
    status = File_HistoryHashApi.CreateHash(
        File_HistoryHashApi.Algorithm, &Context->Hash,
        Context->Object, File_HistoryHashApi.ObjectLength, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        File_HistoryFreeHash(Context);
        return FALSE;
    }

    return TRUE;
}


static _FX BOOLEAN File_HistoryUpdateHash(
    FILE_HISTORY_HASH_CONTEXT *Context, const UCHAR *Data, ULONG Length)
{
    NTSTATUS status;

    if (!Context->Hash)
        return FALSE;
    status = Context->HashData(
        Context->Hash, (PUCHAR)Data, Length, 0);
    if (!NT_SUCCESS(status)) {
        File_HistoryFreeHash(Context);
        return FALSE;
    }
    return TRUE;
}


static _FX BOOLEAN File_HistoryFinishHash(
    FILE_HISTORY_HASH_CONTEXT *Context,
    UCHAR Hash[FILE_HISTORY_SHA256_SIZE])
{
    NTSTATUS status;

    if (!Context->Hash)
        return FALSE;
    status = Context->FinishHash(
        Context->Hash, Hash, FILE_HISTORY_SHA256_SIZE, 0);
    File_HistoryFreeHash(Context);
    return NT_SUCCESS(status);
}


static _FX VOID File_HistoryFormatHash(
    const UCHAR Hash[FILE_HISTORY_SHA256_SIZE],
    WCHAR Text[FILE_HISTORY_SHA256_TEXT])
{
    static const WCHAR hex[] = L"0123456789abcdef";
    ULONG index;

    for (index = 0; index < FILE_HISTORY_SHA256_SIZE; ++index) {
        Text[index * 2] = hex[Hash[index] >> 4];
        Text[index * 2 + 1] = hex[Hash[index] & 0x0F];
    }
    Text[FILE_HISTORY_SHA256_SIZE * 2] = L'\0';
}


//---------------------------------------------------------------------------
// File_HistoryHashPath
//---------------------------------------------------------------------------


static _FX ULONGLONG File_HistoryHashPath(const WCHAR *Path)
{
    ULONGLONG hash = 1469598103934665603ULL;

    while (*Path) {
        WCHAR c = *Path++;
        if (c >= L'A' && c <= L'Z')
            c |= 0x20;
        hash ^= (ULONGLONG)(USHORT)c;
        hash *= 1099511628211ULL;
    }

    return hash;
}


//---------------------------------------------------------------------------
// File_HistoryEscapeDosPath
//---------------------------------------------------------------------------


static _FX WCHAR *File_HistoryEscapeDosPath(const WCHAR *NtPath)
{
    WCHAR *dos_path;
    WCHAR *escaped;
    ULONG length;

    length = wcslen(NtPath) + 64;
    dos_path = Dll_AllocTemp(length * sizeof(WCHAR));
    if (!dos_path)
        return NULL;

    wcscpy(dos_path, NtPath);
    if (!SbieDll_TranslateNtToDosPath(dos_path)) {
        Dll_Free(dos_path);
        return File_JournalEscapeField_internal(L"");
    }

    escaped = File_JournalEscapeField_internal(dos_path);
    Dll_Free(dos_path);
    return escaped;
}


//---------------------------------------------------------------------------
// File_HistoryEscapeCopyPath
//---------------------------------------------------------------------------


static _FX WCHAR *File_HistoryEscapeCopyPath(
    const WCHAR *NtPath, BOOLEAN DosPath)
{
    WCHAR *path;
    WCHAR *root;
    WCHAR *portable = NULL;
    WCHAR *escaped;
    ULONG path_length = (ULONG)wcslen(NtPath);
    ULONG root_length = (ULONG)wcslen(Dll_BoxFilePath);
    ULONG placeholder_length = RTL_NUMBER_OF(FILE_HISTORY_BOX_ROOT) - 1;
    ULONG length;

    path = Dll_AllocTemp((path_length + 64) * sizeof(WCHAR));
    root = Dll_AllocTemp((root_length + 64) * sizeof(WCHAR));
    if (!path || !root) {
        if (root)
            Dll_Free(root);
        if (path)
            Dll_Free(path);
        return NULL;
    }

    wcscpy(path, NtPath);
    wcscpy(root, Dll_BoxFilePath);
    if (DosPath &&
            (!SbieDll_TranslateNtToDosPath(path) ||
             !SbieDll_TranslateNtToDosPath(root))) {
        path[0] = L'\0';
    }

    root_length = (ULONG)wcslen(root);
    while (root_length && root[root_length - 1] == L'\\')
        --root_length;

    if (root_length &&
            _wcsnicmp(path, root, root_length) == 0 &&
            (path[root_length] == L'\0' || path[root_length] == L'\\')) {
        length = placeholder_length +
                 (ULONG)wcslen(path + root_length) + 1;
        portable = Dll_AllocTemp(length * sizeof(WCHAR));
        if (portable) {
            Sbie_snwprintf(portable, length, L"%s%s",
                FILE_HISTORY_BOX_ROOT, path + root_length);
        }
    }

    escaped = File_JournalEscapeField_internal(portable ? portable : path);
    if (portable)
        Dll_Free(portable);
    Dll_Free(root);
    Dll_Free(path);
    return escaped;
}


//---------------------------------------------------------------------------
// File_HistoryValidArtifact
//---------------------------------------------------------------------------


static _FX BOOLEAN File_HistoryValidArtifact(const WCHAR *Artifact)
{
    ULONG index;

    if (wcslen(Artifact) != 51)
        return FALSE;

    for (index = 0; index != 51; ++index) {
        WCHAR ch = Artifact[index];

        if (index == 16 || index == 33 || index == 42) {
            if (ch != L'-')
                return FALSE;
        }
        else if (!((ch >= L'0' && ch <= L'9') ||
                   (ch >= L'A' && ch <= L'F') ||
                   (ch >= L'a' && ch <= L'f'))) {
            return FALSE;
        }
    }

    return TRUE;
}


//---------------------------------------------------------------------------
// File_HistoryMatches
//---------------------------------------------------------------------------


static _FX BOOLEAN File_HistoryMatches(const WCHAR *TruePath)
{
    ULONG path_len;
    WCHAR *path_lwr;
    PATTERN *pat;
    BOOLEAN matched = FALSE;

    if (!File_HistoryRoot || !List_Head(&File_HistoryOptions))
        return FALSE;

    path_len = (wcslen(TruePath) + 1) * sizeof(WCHAR);
    path_lwr = Dll_AllocTemp(path_len);
    if (!path_lwr)
        return FALSE;

    memcpy(path_lwr, TruePath, path_len);
    _wcslwr(path_lwr);
    path_len = wcslen(path_lwr);

    pat = List_Head(&File_HistoryOptions);
    while (pat) {
        if (Pattern_Match(pat, path_lwr, path_len)) {
            matched = TRUE;
            break;
        }
        pat = List_Next(pat);
    }

    if (matched) {
        pat = List_Head(&File_HistoryExclusions);
        while (pat) {
            if (Pattern_Match(pat, path_lwr, path_len)) {
                matched = FALSE;
                break;
            }
            pat = List_Next(pat);
        }
    }

    Dll_Free(path_lwr);
    return matched;
}


//---------------------------------------------------------------------------
// File_HistoryCreateDirectory
//---------------------------------------------------------------------------


static _FX NTSTATUS File_HistoryCreateDirectory(const WCHAR *Path)
{
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    IO_STATUS_BLOCK iosb;
    FILE_ATTRIBUTE_TAG_INFORMATION taginfo;
    HANDLE handle;
    NTSTATUS status;

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, Secure_NormalSD);
    RtlInitUnicodeString(&objname, Path);

    status = __sys_NtCreateFile(
        &handle, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objattrs, &iosb, NULL, FILE_ATTRIBUTE_DIRECTORY,
        FILE_SHARE_VALID_FLAGS, FILE_OPEN_IF,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_OPEN_REPARSE_POINT, NULL, 0);

    if (NT_SUCCESS(status)) {
        status = __sys_NtQueryInformationFile(
            handle, &iosb, &taginfo, sizeof(taginfo),
            FileAttributeTagInformation);
        if (NT_SUCCESS(status) &&
                (taginfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            status = STATUS_ACCESS_DENIED;
        NtClose(handle);
    }

    return status;
}


//---------------------------------------------------------------------------
// File_HistoryDeleteFile
//---------------------------------------------------------------------------


static _FX NTSTATUS File_HistoryDeleteFile(const WCHAR *Path)
{
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlInitUnicodeString(&objname, Path);
    return __sys_NtDeleteFile(&objattrs);
}


static _FX NTSTATUS File_HistoryDeleteHandle(HANDLE Handle)
{
    FILE_DISPOSITION_INFORMATION disposition;
    IO_STATUS_BLOCK iosb;

    disposition.DeleteFileOnClose = TRUE;
    return __sys_NtSetInformationFile(
        Handle, &iosb, &disposition,
        sizeof(disposition), FileDispositionInformation);
}


//---------------------------------------------------------------------------
// File_HistoryRenamePath
//---------------------------------------------------------------------------


static _FX NTSTATUS File_HistoryRenameHandle(
    HANDLE Handle, const WCHAR *TargetPath, BOOLEAN Replace)
{
    IO_STATUS_BLOCK iosb;
    FILE_RENAME_INFORMATION *info;
    NTSTATUS status;
    ULONG path_len;
    ULONG info_len;

    path_len = wcslen(TargetPath) * sizeof(WCHAR);
    info_len = sizeof(FILE_RENAME_INFORMATION) + path_len;
    info = Dll_AllocTemp(info_len);
    if (!info)
        status = STATUS_INSUFFICIENT_RESOURCES;
    else {
        memzero(info, info_len);
        info->ReplaceIfExists = Replace;
        info->RootDirectory = NULL;
        info->FileNameLength = path_len;
        memcpy(info->FileName, TargetPath, path_len);
        status = __sys_NtSetInformationFile(
            Handle, &iosb, info, info_len, FileRenameInformation);
        Dll_Free(info);
    }

    return status;
}


static _FX NTSTATUS File_HistoryRenamePath(
    const WCHAR *SourcePath, const WCHAR *TargetPath, BOOLEAN Replace)
{
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    NTSTATUS status;

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlInitUnicodeString(&objname, SourcePath);
    status = __sys_NtCreateFile(
        &handle, DELETE | SYNCHRONIZE,
        &objattrs, &iosb, NULL, 0, FILE_SHARE_VALID_FLAGS, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_OPEN_REPARSE_POINT, NULL, 0);
    if (!NT_SUCCESS(status))
        return status;

    status = File_HistoryRenameHandle(handle, TargetPath, Replace);
    NtClose(handle);
    return status;
}


static _FX NTSTATUS File_HistoryCreateHardLink(
    const WCHAR *SourcePath, const WCHAR *LinkPath)
{
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    IO_STATUS_BLOCK iosb;
    FILE_LINK_INFORMATION *info;
    HANDLE handle;
    NTSTATUS status;
    ULONG path_len;
    ULONG info_len;

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlInitUnicodeString(&objname, SourcePath);
    status = __sys_NtCreateFile(
        &handle, DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objattrs, &iosb, NULL, 0, FILE_SHARE_VALID_FLAGS, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_OPEN_REPARSE_POINT, NULL, 0);
    if (!NT_SUCCESS(status))
        return status;

    path_len = wcslen(LinkPath) * sizeof(WCHAR);
    info_len = sizeof(FILE_LINK_INFORMATION) + path_len;
    info = Dll_AllocTemp(info_len);
    if (!info)
        status = STATUS_INSUFFICIENT_RESOURCES;
    else {
        memzero(info, info_len);
        info->ReplaceIfExists = FALSE;
        info->RootDirectory = NULL;
        info->FileNameLength = path_len;
        memcpy(info->FileName, LinkPath, path_len);
        status = __sys_NtSetInformationFile(
            handle, &iosb, info, info_len, FileLinkInformation);
        Dll_Free(info);
    }

    NtClose(handle);
    return status;
}


//---------------------------------------------------------------------------
// File_HistoryWriteText
//---------------------------------------------------------------------------


static _FX NTSTATUS File_HistoryWriteText(
    const WCHAR *Path, const WCHAR *Text)
{
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    NTSTATUS status;
    ULONG length;

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, Secure_NormalSD);
    RtlInitUnicodeString(&objname, Path);

    status = __sys_NtCreateFile(
        &handle, FILE_GENERIC_WRITE | SYNCHRONIZE,
        &objattrs, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_VALID_FLAGS, FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_OPEN_REPARSE_POINT, NULL, 0);
    if (!NT_SUCCESS(status))
        return status;

    length = wcslen(Text) * sizeof(WCHAR);
    status = __sys_NtWriteFile(
        handle, NULL, NULL, NULL, &iosb, (void *)Text, length, NULL, NULL);
    if (NT_SUCCESS(status) && iosb.Information != length)
        status = STATUS_DISK_FULL;

    NtClose(handle);
    return status;
}


//---------------------------------------------------------------------------
// File_HistoryWriteTextAtomic
//---------------------------------------------------------------------------


static _FX NTSTATUS File_HistoryWriteTextAtomic(
    const WCHAR *Path, const WCHAR *Text, BOOLEAN Replace)
{
    WCHAR *temp_path;
    NTSTATUS status;
    ULONG length;

    length = wcslen(Path) + 32;
    temp_path = Dll_AllocTemp(length * sizeof(WCHAR));
    if (!temp_path)
        return STATUS_INSUFFICIENT_RESOURCES;

    Sbie_snwprintf(temp_path, length, L"%s.tmp.%08X.%08X",
        Path, Dll_ProcessId, InterlockedIncrement(&File_HistorySequence));
    status = File_HistoryWriteText(temp_path, Text);
    if (!NT_SUCCESS(status)) {
        Dll_Free(temp_path);
        return status;
    }

    status = File_HistoryRenamePath(temp_path, Path, Replace);
    if (!NT_SUCCESS(status))
        File_HistoryDeleteFile(temp_path);
    Dll_Free(temp_path);
    return status;
}


//---------------------------------------------------------------------------
// File_HistoryReadText
//---------------------------------------------------------------------------


static _FX NTSTATUS File_HistoryReadText(
    const WCHAR *Path, WCHAR **Text)
{
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    IO_STATUS_BLOCK iosb;
    FILE_STANDARD_INFORMATION info;
    HANDLE handle;
    NTSTATUS status;
    ULONG length;
    WCHAR *text;

    *Text = NULL;

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlInitUnicodeString(&objname, Path);

    status = __sys_NtCreateFile(
        &handle, FILE_GENERIC_READ | SYNCHRONIZE,
        &objattrs, &iosb, NULL, 0, FILE_SHARE_VALID_FLAGS, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_OPEN_REPARSE_POINT, NULL, 0);
    if (!NT_SUCCESS(status))
        return status;

    status = __sys_NtQueryInformationFile(
        handle, &iosb, &info, sizeof(info), FileStandardInformation);
    if (!NT_SUCCESS(status) ||
            info.EndOfFile.QuadPart < 0 ||
            info.EndOfFile.QuadPart > 256 * 1024) {
        NtClose(handle);
        return NT_SUCCESS(status) ? STATUS_FILE_TOO_LARGE : status;
    }

    length = (ULONG)info.EndOfFile.QuadPart;
    text = Dll_AllocTemp(length + sizeof(WCHAR));
    if (!text) {
        NtClose(handle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = __sys_NtReadFile(
        handle, NULL, NULL, NULL, &iosb, text, length, NULL, NULL);
    NtClose(handle);

    if (!NT_SUCCESS(status)) {
        Dll_Free(text);
        return status;
    }
    if (iosb.Information != length) {
        Dll_Free(text);
        return STATUS_END_OF_FILE;
    }

    text[iosb.Information / sizeof(WCHAR)] = L'\0';
    *Text = text;
    return STATUS_SUCCESS;
}


//---------------------------------------------------------------------------
// File_HistoryBuildMarkerPath
//---------------------------------------------------------------------------


static _FX WCHAR *File_HistoryBuildMarkerPath(
    const WCHAR *TruePath, ULONG Slot)
{
    WCHAR *path;
    ULONG length;

    length = wcslen(File_HistoryIndex) + 32;
    path = Dll_AllocTemp(length * sizeof(WCHAR));
    if (!path)
        return NULL;

    Sbie_snwprintf(path, length, L"%s\\%016I64X.%u.idx",
        File_HistoryIndex, File_HistoryHashPath(TruePath), Slot);
    return path;
}


//---------------------------------------------------------------------------
// File_HistoryParseMarker
//---------------------------------------------------------------------------


static _FX BOOLEAN File_HistoryParseMarker(
    WCHAR *Text, const WCHAR *TruePath, WCHAR *Artifact, ULONG ArtifactLength)
{
    WCHAR *artifact_end;
    WCHAR *path;
    WCHAR *path_end;
    WCHAR *unescaped_path;
    BOOLEAN matches;

    if (_wcsnicmp(Text, L"artifact=", 9) != 0)
        return FALSE;

    artifact_end = wcschr(Text + 9, L'\n');
    if (!artifact_end)
        return FALSE;
    *artifact_end = L'\0';
    if (artifact_end > Text + 9 && artifact_end[-1] == L'\r')
        artifact_end[-1] = L'\0';

    path = artifact_end + 1;
    if (_wcsnicmp(path, L"path=", 5) != 0)
        return FALSE;
    path += 5;
    path_end = wcschr(path, L'\r');
    if (!path_end)
        path_end = wcschr(path, L'\n');
    if (path_end)
        *path_end = L'\0';

    unescaped_path = File_JournalUnescapeField_internal(path);
    if (!unescaped_path)
        return FALSE;
    matches = _wcsicmp(unescaped_path, TruePath) == 0;
    Dll_Free(unescaped_path);
    if (!matches)
        return FALSE;
    if (!File_HistoryValidArtifact(Text + 9))
        return FALSE;

    wcsncpy(Artifact, Text + 9, ArtifactLength - 1);
    Artifact[ArtifactLength - 1] = L'\0';
    return TRUE;
}


//---------------------------------------------------------------------------
// File_HistoryFindMarker
//---------------------------------------------------------------------------


static _FX WCHAR *File_HistoryFindMarker(
    const WCHAR *TruePath, WCHAR *Artifact, ULONG ArtifactLength,
    BOOLEAN FindFree)
{
    WCHAR *first_free = NULL;
    ULONG slot;

    for (slot = 0; slot != FILE_HISTORY_MARKER_SLOTS; ++slot) {
        WCHAR *marker = File_HistoryBuildMarkerPath(TruePath, slot);
        WCHAR *text = NULL;
        NTSTATUS status;

        if (!marker)
            break;

        status = File_HistoryReadText(marker, &text);
        if (NT_SUCCESS(status)) {
            if (File_HistoryParseMarker(
                    text, TruePath, Artifact, ArtifactLength)) {
                Dll_Free(text);
                if (first_free)
                    Dll_Free(first_free);
                return marker;
            }
            Dll_Free(text);
        }
        else if ((status == STATUS_OBJECT_NAME_NOT_FOUND ||
                  status == STATUS_OBJECT_PATH_NOT_FOUND) &&
                 FindFree && !first_free) {
            first_free = marker;
            marker = NULL;
        }

        if (marker)
            Dll_Free(marker);
    }

    return first_free;
}


//---------------------------------------------------------------------------
// File_HistoryCreateMutex
//---------------------------------------------------------------------------


static _FX HANDLE File_HistoryCreateMutex(const WCHAR *TruePath)
{
    WCHAR *name;
    HANDLE mutex;
    DWORD wait_result;
    ULONG length;

    length = wcslen(Dll_BoxName) + 40;
    name = Dll_AllocTemp(length * sizeof(WCHAR));
    if (!name)
        return NULL;

    Sbie_snwprintf(name, length, L"Sandboxie_FileHistory_%s_%016I64X",
        Dll_BoxName, File_HistoryHashPath(TruePath));
    mutex = CreateMutex(NULL, FALSE, name);
    Dll_Free(name);
    if (!mutex)
        return NULL;

    wait_result = WaitForSingleObject(mutex, INFINITE);
    if (wait_result != WAIT_OBJECT_0 && wait_result != WAIT_ABANDONED) {
        CloseHandle(mutex);
        return NULL;
    }

    return mutex;
}


//---------------------------------------------------------------------------
// File_HistoryReleaseMutex
//---------------------------------------------------------------------------


static _FX VOID File_HistoryReleaseMutex(HANDLE Mutex)
{
    if (Mutex) {
        ReleaseMutex(Mutex);
        CloseHandle(Mutex);
    }
}


//---------------------------------------------------------------------------
// File_HistoryCreateLimitMutex
//---------------------------------------------------------------------------


static _FX HANDLE File_HistoryCreateLimitMutex(BOOLEAN *Abandoned)
{
    WCHAR *name;
    HANDLE mutex;
    DWORD wait_result;
    ULONG length;

    if (Abandoned)
        *Abandoned = FALSE;

    length = wcslen(Dll_BoxName) + 40;
    name = Dll_AllocTemp(length * sizeof(WCHAR));
    if (!name)
        return NULL;

    Sbie_snwprintf(name, length, L"Sandboxie_FileHistoryLimit_%s",
        Dll_BoxName);
    mutex = CreateMutex(NULL, FALSE, name);
    Dll_Free(name);
    if (!mutex)
        return NULL;

    wait_result = WaitForSingleObject(mutex, INFINITE);
    if (wait_result != WAIT_OBJECT_0 && wait_result != WAIT_ABANDONED) {
        CloseHandle(mutex);
        return NULL;
    }
    if (wait_result == WAIT_ABANDONED && Abandoned)
        *Abandoned = TRUE;

    return mutex;
}


//---------------------------------------------------------------------------
// File_HistoryCreateMutexPair
//---------------------------------------------------------------------------


static _FX BOOLEAN File_HistoryCreateMutexPair(
    const WCHAR *OldTruePath, const WCHAR *NewTruePath,
    HANDLE *OldMutex, HANDLE *NewMutex)
{
    ULONGLONG old_hash = File_HistoryHashPath(OldTruePath);
    ULONGLONG new_hash = File_HistoryHashPath(NewTruePath);

    *OldMutex = NULL;
    *NewMutex = NULL;

    if (old_hash <= new_hash) {
        *OldMutex = File_HistoryCreateMutex(OldTruePath);
        if (*OldMutex)
            *NewMutex = File_HistoryCreateMutex(NewTruePath);
    }
    else {
        *NewMutex = File_HistoryCreateMutex(NewTruePath);
        if (*NewMutex)
            *OldMutex = File_HistoryCreateMutex(OldTruePath);
    }

    if (!*OldMutex || !*NewMutex) {
        File_HistoryReleaseMutex(*NewMutex);
        File_HistoryReleaseMutex(*OldMutex);
        *OldMutex = NULL;
        *NewMutex = NULL;
        return FALSE;
    }

    return TRUE;
}


//---------------------------------------------------------------------------
// File_HistoryInitNotices
//---------------------------------------------------------------------------


static _FX VOID File_HistoryInitNotices(void)
{
    WCHAR *name;
    ULONG length;

    length = wcslen(Dll_BoxName) + 96;
    name = Dll_AllocTemp(length * sizeof(WCHAR));
    if (!name)
        return;

    Sbie_snwprintf(name, length,
        L"Sandboxie_FileHistoryNotice_%s_%08X",
        Dll_BoxName, Dll_SessionId);
    File_HistoryNoticeHandle = CreateFileMapping(
        INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(LONG), name);

    if (File_HistoryNoticeHandle) {
        File_HistoryNoticeFlags = MapViewOfFile(
            File_HistoryNoticeHandle, FILE_MAP_ALL_ACCESS,
            0, 0, sizeof(LONG));
        if (!File_HistoryNoticeFlags) {
            CloseHandle(File_HistoryNoticeHandle);
            File_HistoryNoticeHandle = NULL;
        }
    }

    Sbie_snwprintf(name, length,
        L"Sandboxie_FileHistoryUsageV1_%s_%08X",
        Dll_BoxName, Dll_SessionId);
    File_HistoryUsageHandle = CreateFileMapping(
        INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0,
        sizeof(FILE_HISTORY_USAGE_STATE), name);
    if (File_HistoryUsageHandle) {
        File_HistoryUsageState = MapViewOfFile(
            File_HistoryUsageHandle, FILE_MAP_ALL_ACCESS,
            0, 0, sizeof(FILE_HISTORY_USAGE_STATE));
        if (!File_HistoryUsageState) {
            CloseHandle(File_HistoryUsageHandle);
            File_HistoryUsageHandle = NULL;
        }
    }
    Dll_Free(name);
}


//---------------------------------------------------------------------------
// File_HistoryClaimNotice
//---------------------------------------------------------------------------


static _FX BOOLEAN File_HistoryClaimNotice(LONG Notice)
{
    volatile LONG *flags = File_HistoryNoticeFlags
        ? File_HistoryNoticeFlags : &File_HistoryLocalNoticeFlags;
    LONG old_flags;

    while (1) {
        old_flags = InterlockedCompareExchange(flags, 0, 0);
        if (old_flags & Notice)
            return FALSE;
        if (InterlockedCompareExchange(
                flags, old_flags | Notice, old_flags) == old_flags)
            return TRUE;
    }
}


//---------------------------------------------------------------------------
// File_HistoryGetUsageState
//---------------------------------------------------------------------------


static _FX FILE_HISTORY_USAGE_STATE *File_HistoryGetUsageState(void)
{
    return File_HistoryUsageState;
}


//---------------------------------------------------------------------------
// File_HistoryInvalidateUsage
//---------------------------------------------------------------------------


static _FX VOID File_HistoryInvalidateUsage(void)
{
    FILE_HISTORY_USAGE_STATE *state = File_HistoryGetUsageState();

    if (state)
        InterlockedExchange(&state->Initialized, 0);
}


//---------------------------------------------------------------------------
// File_HistoryLogWarning
//---------------------------------------------------------------------------


static _FX VOID File_HistoryLogWarning(
    const WCHAR *Operation, NTSTATUS Status, const WCHAR *Path)
{
    if (!File_HistoryLogWarnings)
        return;
    if (!File_HistoryClaimNotice(FILE_HISTORY_NOTICE_WARNING))
        return;

    if (Path) {
        SbieApi_Log(2228,
            L"%S failed with status %08X. The application operation "
            L"continued. Further file-history warnings are suppressed for "
            L"this sandbox session. First affected path: %S",
            Operation, Status, Path);
    }
    else {
        SbieApi_Log(2228,
            L"%S failed with status %08X. Further file-history warnings "
            L"are suppressed for this sandbox session.",
            Operation, Status);
    }
}


//---------------------------------------------------------------------------
// File_HistoryLogLimit
//---------------------------------------------------------------------------


static _FX VOID File_HistoryLogLimit(const WCHAR *Path)
{
    if (!File_HistoryLogWarnings)
        return;
    if (!File_HistoryClaimNotice(FILE_HISTORY_NOTICE_LIMIT))
        return;

    SbieApi_Log(2229,
        L"New evidence is being skipped because file history limits were "
        L"reached. "
        L"Existing evidence is retained and the application operation "
        L"continues. Further limit notices are suppressed for this sandbox "
        L"session. First affected path: %S",
        Path);
}


//---------------------------------------------------------------------------
// File_HistoryUsageReached
//---------------------------------------------------------------------------


static _FX BOOLEAN File_HistoryUsageReached(
    ULONG Versions, ULONGLONG Size,
    ULONG MaxVersions, ULONGLONG MaxSize,
    ULONGLONG AdditionalSize)
{
    return (MaxVersions && Versions >= MaxVersions) ||
           (MaxSize &&
            (Size >= MaxSize || AdditionalSize > MaxSize - Size));
}


//---------------------------------------------------------------------------
// File_HistoryCommitUsage
//---------------------------------------------------------------------------


static _FX VOID File_HistoryCommitUsage(ULONGLONG AdditionalSize)
{
    FILE_HISTORY_USAGE_STATE *state = File_HistoryGetUsageState();

    if (!state ||
            InterlockedCompareExchange(&state->Initialized, 0, 0) != 1)
        return;

    if (AdditionalSize && state->Versions != FILE_HISTORY_ULONG_MAX)
        ++state->Versions;
    if (FILE_HISTORY_ULONGLONG_MAX - state->Size < AdditionalSize)
        state->Size = FILE_HISTORY_ULONGLONG_MAX;
    else
        state->Size += AdditionalSize;
}


//---------------------------------------------------------------------------
// File_HistoryAddDirectoryUsage
//---------------------------------------------------------------------------


static _FX NTSTATUS File_HistoryAddDirectoryUsage(
    const WCHAR *Path, ULONG *Versions, ULONGLONG *Size,
    ULONG MaxVersions)
{
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    IO_STATUS_BLOCK iosb;
    FILE_ATTRIBUTE_TAG_INFORMATION taginfo;
    FILE_DIRECTORY_INFORMATION *info;
    HANDLE handle;
    NTSTATUS status;
    BOOLEAN restart = TRUE;
    ULONG info_len;

    if (MaxVersions && *Versions >= MaxVersions)
        return STATUS_QUOTA_EXCEEDED;

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlInitUnicodeString(&objname, Path);
    status = __sys_NtCreateFile(
        &handle, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objattrs, &iosb, NULL, 0, FILE_SHARE_VALID_FLAGS, FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_OPEN_REPARSE_POINT, NULL, 0);
    if (!NT_SUCCESS(status))
        return status;

    status = __sys_NtQueryInformationFile(
        handle, &iosb, &taginfo, sizeof(taginfo),
        FileAttributeTagInformation);
    if (!NT_SUCCESS(status) ||
            (taginfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        NtClose(handle);
        return NT_SUCCESS(status) ? STATUS_ACCESS_DENIED : status;
    }

    info_len = 4096;
    info = Dll_AllocTemp(info_len);
    if (!info) {
        NtClose(handle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    while (1) {
        ULONG name_len;
        ULONGLONG file_size;

        status = __sys_NtQueryDirectoryFile(
            handle, NULL, NULL, NULL, &iosb,
            info, info_len, FileDirectoryInformation,
            TRUE, NULL, restart);
        restart = FALSE;
        if (!NT_SUCCESS(status))
            break;

        name_len = info->FileNameLength / sizeof(WCHAR);
        if ((info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
                name_len < 4 ||
                _wcsnicmp(info->FileName + name_len - 4, L".bin", 4) != 0) {
            continue;
        }

        file_size = info->EndOfFile.QuadPart > 0
                  ? (ULONGLONG)info->EndOfFile.QuadPart : 0;
        if (file_size && *Versions != FILE_HISTORY_ULONG_MAX)
            ++*Versions;
        if (FILE_HISTORY_ULONGLONG_MAX - *Size < file_size)
            *Size = FILE_HISTORY_ULONGLONG_MAX;
        else
            *Size += file_size;

        if (MaxVersions && *Versions >= MaxVersions) {
            status = STATUS_QUOTA_EXCEEDED;
            break;
        }
    }

    Dll_Free(info);
    NtClose(handle);
    return status == STATUS_NO_MORE_FILES ? STATUS_SUCCESS : status;
}


//---------------------------------------------------------------------------
// File_HistoryQueryUsage
//---------------------------------------------------------------------------


static _FX NTSTATUS File_HistoryQueryUsage(
    ULONG *Versions, ULONGLONG *Size)
{
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    IO_STATUS_BLOCK iosb;
    FILE_ATTRIBUTE_TAG_INFORMATION taginfo;
    FILE_DIRECTORY_INFORMATION *info;
    HANDLE handle;
    NTSTATUS status;
    BOOLEAN restart = TRUE;
    ULONG info_len;

    *Versions = 0;
    *Size = 0;

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlInitUnicodeString(&objname, File_HistoryArtifacts);
    status = __sys_NtCreateFile(
        &handle, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objattrs, &iosb, NULL, 0, FILE_SHARE_VALID_FLAGS, FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_OPEN_REPARSE_POINT, NULL, 0);
    if (!NT_SUCCESS(status))
        return status;

    status = __sys_NtQueryInformationFile(
        handle, &iosb, &taginfo, sizeof(taginfo),
        FileAttributeTagInformation);
    if (!NT_SUCCESS(status) ||
            (taginfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        NtClose(handle);
        return NT_SUCCESS(status) ? STATUS_ACCESS_DENIED : status;
    }

    info_len = 4096;
    info = Dll_AllocTemp(info_len);
    if (!info) {
        NtClose(handle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    while (1) {
        WCHAR artifact[80];
        WCHAR *artifact_path;
        ULONG name_len;
        ULONG length;

        status = __sys_NtQueryDirectoryFile(
            handle, NULL, NULL, NULL, &iosb,
            info, info_len, FileDirectoryInformation,
            TRUE, NULL, restart);
        restart = FALSE;
        if (!NT_SUCCESS(status))
            break;

        name_len = info->FileNameLength / sizeof(WCHAR);
        if (!(info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
                name_len >= RTL_NUMBER_OF_V1(artifact)) {
            continue;
        }

        wmemcpy(artifact, info->FileName, name_len);
        artifact[name_len] = L'\0';
        if (!File_HistoryValidArtifact(artifact))
            continue;

        length = wcslen(File_HistoryArtifacts) + name_len + 2;
        artifact_path = Dll_AllocTemp(length * sizeof(WCHAR));
        if (!artifact_path) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        Sbie_snwprintf(artifact_path, length, L"%s\\%s",
            File_HistoryArtifacts, artifact);
        status = File_HistoryAddDirectoryUsage(
            artifact_path, Versions, Size, 0);
        Dll_Free(artifact_path);
        if (!NT_SUCCESS(status))
            break;
    }

    Dll_Free(info);
    NtClose(handle);
    return status == STATUS_NO_MORE_FILES ? STATUS_SUCCESS : status;
}


//---------------------------------------------------------------------------
// File_HistoryCheckLimits
//---------------------------------------------------------------------------


static _FX NTSTATUS File_HistoryCheckLimits(
    const WCHAR *ArtifactPath, ULONGLONG AdditionalSize, HANDLE *Mutex)
{
    HANDLE mutex;
    NTSTATUS status;
    FILE_HISTORY_USAGE_STATE *usage_state;
    ULONG versions;
    ULONGLONG size;
    ULONG usage_attempts = 0;
    BOOLEAN abandoned;

    *Mutex = NULL;
    versions = 0;
    size = 0;
    if (!AdditionalSize)
        return STATUS_SUCCESS;
    if (File_HistoryMaxFileSize &&
            AdditionalSize > File_HistoryMaxFileSize)
        return STATUS_FILE_TOO_LARGE;

    if (File_HistoryMaxVersionsPerFile) {
        ULONG file_versions = 0;
        ULONGLONG file_size = 0;

        status = File_HistoryAddDirectoryUsage(
            ArtifactPath, &file_versions, &file_size,
            File_HistoryMaxVersionsPerFile);
        if (!NT_SUCCESS(status))
            return status;
    }
    if (!File_HistoryMaxVersionsTotal &&
            !File_HistoryMaxSizeTotal &&
            !File_HistoryGetUsageState())
        return STATUS_SUCCESS;

    mutex = File_HistoryCreateLimitMutex(&abandoned);
    if (!mutex)
        return STATUS_INSUFFICIENT_RESOURCES;

    // Build aggregate usage once per box and session.
    // Captures update it under this mutex; pending removals invalidate it.
    usage_state = File_HistoryGetUsageState();
    if (abandoned && usage_state)
        InterlockedExchange(&usage_state->Initialized, 0);
    if (!usage_state) {
        status = File_HistoryQueryUsage(&versions, &size);
    }
    else {
        while (1) {
            if (InterlockedCompareExchange(
                    &usage_state->Initialized, 0, 0) == 1) {
                versions = usage_state->Versions;
                size = usage_state->Size;
                status = STATUS_SUCCESS;
                break;
            }

            // Publish the scan only if no removal invalidated it.
            InterlockedExchange(&usage_state->Initialized, -1);
            status = File_HistoryQueryUsage(&versions, &size);
            if (!NT_SUCCESS(status)) {
                InterlockedCompareExchange(
                    &usage_state->Initialized, 0, -1);
                break;
            }

            usage_state->Versions = versions;
            usage_state->Size = size;
            if (InterlockedCompareExchange(
                    &usage_state->Initialized, 1, -1) == -1)
                break;
            if (++usage_attempts >= FILE_HISTORY_USAGE_SCAN_ATTEMPTS)
                break;
        }
    }
    if (NT_SUCCESS(status) && File_HistoryUsageReached(
            versions, size,
            File_HistoryMaxVersionsTotal,
            File_HistoryMaxSizeTotal, AdditionalSize)) {
        status = STATUS_QUOTA_EXCEEDED;
    }

    if (!NT_SUCCESS(status)) {
        File_HistoryReleaseMutex(mutex);
        return status;
    }

    *Mutex = mutex;
    return STATUS_SUCCESS;
}


//---------------------------------------------------------------------------
// File_HistoryTrackCreated
//---------------------------------------------------------------------------


static _FX VOID File_HistoryTrackCreated(
    const WCHAR *TruePath, const WCHAR *CopyPath, HANDLE FileHandle)
{
    FILE_INTERNAL_INFORMATION internal;
    FILE_BASIC_INFORMATION basic;
    FILE_ATTRIBUTE_TAG_INFORMATION taginfo;
    IO_STATUS_BLOCK iosb;
    WCHAR artifact[80];
    WCHAR *marker;
    WCHAR *artifact_path;
    WCHAR *text;
    WCHAR *escaped_true;
    WCHAR *escaped_dos;
    WCHAR *escaped_copy;
    WCHAR *escaped_copy_dos;
    WCHAR *escaped_image;
    HANDLE mutex;
    FILETIME now;
    NTSTATUS status;
    ULONG length;

    if (!File_HistoryMatches(TruePath))
        return;

    mutex = File_HistoryCreateMutex(TruePath);
    if (!mutex)
        return;

    marker = File_HistoryFindMarker(
        TruePath, artifact, RTL_NUMBER_OF_V1(artifact), TRUE);
    if (!marker) {
        File_HistoryReleaseMutex(mutex);
        return;
    }

    status = __sys_NtQueryInformationFile(
        FileHandle, &iosb, &internal, sizeof(internal),
        FileInternalInformation);
    if (NT_SUCCESS(status)) {
        status = __sys_NtQueryInformationFile(
            FileHandle, &iosb, &taginfo, sizeof(taginfo),
            FileAttributeTagInformation);
    }
    if (NT_SUCCESS(status) &&
            (taginfo.FileAttributes &
             (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
        status = STATUS_OBJECT_TYPE_MISMATCH;
    }
    if (NT_SUCCESS(status)) {
        status = __sys_NtQueryInformationFile(
            FileHandle, &iosb, &basic, sizeof(basic),
            FileBasicInformation);
    }
    if (!NT_SUCCESS(status)) {
        Dll_Free(marker);
        File_HistoryReleaseMutex(mutex);
        return;
    }

    GetSystemTimeAsFileTime(&now);
    Sbie_snwprintf(artifact, RTL_NUMBER_OF_V1(artifact),
        L"%016I64X-%016I64X-%08X-%08X",
        internal.IndexNumber.QuadPart,
        ((ULONGLONG)now.dwHighDateTime << 32) | now.dwLowDateTime,
        Dll_ProcessId, InterlockedIncrement(&File_HistorySequence));

    length = wcslen(File_HistoryArtifacts) + wcslen(artifact) + 2;
    artifact_path = Dll_AllocTemp(length * sizeof(WCHAR));
    if (!artifact_path) {
        Dll_Free(marker);
        File_HistoryReleaseMutex(mutex);
        return;
    }
    Sbie_snwprintf(artifact_path, length, L"%s\\%s",
        File_HistoryArtifacts, artifact);

    status = File_HistoryCreateDirectory(artifact_path);
    if (NT_SUCCESS(status)) {
        escaped_true = File_JournalEscapeField_internal(TruePath);
        escaped_dos = File_HistoryEscapeDosPath(TruePath);
        escaped_copy = File_HistoryEscapeCopyPath(CopyPath, FALSE);
        escaped_copy_dos = File_HistoryEscapeCopyPath(CopyPath, TRUE);
        escaped_image = File_JournalEscapeField_internal(Dll_ImageName);
        if (escaped_true && escaped_dos && escaped_copy &&
                escaped_copy_dos && escaped_image) {
            length = wcslen(artifact) + wcslen(escaped_true) +
                     wcslen(escaped_dos) + wcslen(escaped_copy) +
                     wcslen(escaped_copy_dos) +
                     wcslen(escaped_image) + 160;
            text = Dll_AllocTemp(length * sizeof(WCHAR));
        }
        else
            text = NULL;
        if (text) {
            Sbie_snwprintf(text, length,
                L"artifact=%s\r\npath=%s\r\ndos_path=%s\r\n"
                L"copy_path=%s\r\ncopy_dos_path=%s\r\n"
                L"created=%016I64X\r\npid=%u\r\nimage=%s\r\n",
                artifact, escaped_true, escaped_dos,
                escaped_copy, escaped_copy_dos,
                basic.CreationTime.QuadPart, Dll_ProcessId, escaped_image);
            status = File_HistoryWriteTextAtomic(
                marker, text, TRUE);
            Dll_Free(text);
        }
        else
            status = STATUS_INSUFFICIENT_RESOURCES;
        if (escaped_true)
            Dll_Free(escaped_true);
        if (escaped_dos)
            Dll_Free(escaped_dos);
        if (escaped_copy)
            Dll_Free(escaped_copy);
        if (escaped_copy_dos)
            Dll_Free(escaped_copy_dos);
        if (escaped_image)
            Dll_Free(escaped_image);
    }

    if (!NT_SUCCESS(status))
        File_HistoryLogWarning(L"Tracking metadata", status, TruePath);

    Dll_Free(artifact_path);
    Dll_Free(marker);
    File_HistoryReleaseMutex(mutex);
}


//---------------------------------------------------------------------------
// File_HistoryTrackMigrated
//---------------------------------------------------------------------------


static _FX VOID File_HistoryTrackMigrated(
    const WCHAR *TruePath, const WCHAR *CopyPath)
{
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    IO_STATUS_BLOCK iosb;
    HANDLE handle = NULL;
    NTSTATUS status;

    if (!File_HistoryCaptureMigrated || !File_HistoryMatches(TruePath))
        return;

    RtlInitUnicodeString(&objname, CopyPath);
    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, Secure_NormalSD);
    status = __sys_NtCreateFile(
        &handle, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objattrs, &iosb, NULL, 0, FILE_SHARE_VALID_FLAGS, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_OPEN_REPARSE_POINT, NULL, 0);
    if (!NT_SUCCESS(status))
        return;

    File_HistoryTrackCreated(TruePath, CopyPath, handle);
    __sys_NtClose(handle);
    File_HistoryCapture(TruePath, CopyPath, L"migrate");
}


//---------------------------------------------------------------------------
// File_HistoryCopyFile
//---------------------------------------------------------------------------


static _FX BOOLEAN File_HistorySameGenerationInfo(
    const FILE_NETWORK_OPEN_INFORMATION *First,
    const FILE_NETWORK_OPEN_INFORMATION *Second)
{
    return First->EndOfFile.QuadPart == Second->EndOfFile.QuadPart &&
           First->LastWriteTime.QuadPart == Second->LastWriteTime.QuadPart &&
           First->ChangeTime.QuadPart == Second->ChangeTime.QuadPart &&
           First->FileAttributes == Second->FileAttributes;
}


static _FX BOOLEAN File_HistoryHashHandle(
    HANDLE Source, const FILE_NETWORK_OPEN_INFORMATION *ExpectedInfo,
    UCHAR Hash[FILE_HISTORY_SHA256_SIZE])
{
    FILE_NETWORK_OPEN_INFORMATION current_info;
    FILE_NETWORK_OPEN_INFORMATION final_info;
    FILE_HISTORY_HASH_CONTEXT hash_context;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    UCHAR *buffer = NULL;
    NTSTATUS status;
    BOOLEAN hashing;

    memzero(&hash_context, sizeof(hash_context));
    hashing = File_HistoryInitHash(&hash_context);
    if (!hashing)
        return FALSE;

    status = __sys_NtQueryInformationFile(
        Source, &iosb, &current_info, sizeof(current_info),
        FileNetworkOpenInformation);
    if (!NT_SUCCESS(status) ||
            !File_HistorySameGenerationInfo(ExpectedInfo, &current_info))
        goto finish;

    if (current_info.EndOfFile.QuadPart > 0) {
        buffer = Dll_AllocTemp(FILE_HISTORY_COPY_BUFFER);
        if (!buffer) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto finish;
        }
    }

    offset.QuadPart = 0;
    while ((ULONGLONG)offset.QuadPart <
            (ULONGLONG)current_info.EndOfFile.QuadPart) {
        ULONGLONG remaining =
            current_info.EndOfFile.QuadPart - offset.QuadPart;
        ULONG length = remaining > FILE_HISTORY_COPY_BUFFER
                     ? FILE_HISTORY_COPY_BUFFER : (ULONG)remaining;

        status = __sys_NtReadFile(
            Source, NULL, NULL, NULL, &iosb,
            buffer, length, &offset, NULL);
        if (!NT_SUCCESS(status))
            goto finish;
        if (!iosb.Information) {
            status = STATUS_END_OF_FILE;
            goto finish;
        }

        length = (ULONG)iosb.Information;
        if (!File_HistoryUpdateHash(&hash_context, buffer, length)) {
            status = STATUS_UNSUCCESSFUL;
            hashing = FALSE;
            goto finish;
        }
        offset.QuadPart += length;
    }

    status = __sys_NtQueryInformationFile(
        Source, &iosb, &final_info, sizeof(final_info),
        FileNetworkOpenInformation);
    if (!NT_SUCCESS(status) ||
            !File_HistorySameGenerationInfo(&current_info, &final_info)) {
        status = STATUS_RETRY;
        goto finish;
    }

    if (hashing && !File_HistoryFinishHash(&hash_context, Hash)) {
        status = STATUS_UNSUCCESSFUL;
        hashing = FALSE;
    }

finish:
    if (buffer)
        Dll_Free(buffer);
    File_HistoryFreeHash(&hash_context);
    return NT_SUCCESS(status) && hashing;
}


static _FX NTSTATUS File_HistoryCopyFile(
    const WCHAR *SourcePath, const WCHAR *TargetPath,
    FILE_NETWORK_OPEN_INFORMATION *SourceInfo,
    UCHAR Hash[FILE_HISTORY_SHA256_SIZE], BOOLEAN *HashValid)
{
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    IO_STATUS_BLOCK iosb;
    FILE_BASIC_INFORMATION basic;
    FILE_NETWORK_OPEN_INFORMATION expected_info;
    FILE_NETWORK_OPEN_INFORMATION current_info;
    FILE_NETWORK_OPEN_INFORMATION final_info;
    LARGE_INTEGER offset;
    HANDLE source = NULL;
    HANDLE target = NULL;
    NTSTATUS status;
    UCHAR *buffer;
    FILE_HISTORY_HASH_CONTEXT hash_context;
    BOOLEAN hashing;

    *HashValid = FALSE;
    memzero(&hash_context, sizeof(hash_context));
    expected_info = *SourceInfo;

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, Secure_NormalSD);

    //
    // Empty files never need a source open.  Skipping the open entirely
    // avoids sharing violations when the application holds the file with
    // ShareMode: None (exclusive), which is common for temporary/scratch
    // files created by Chrome and similar applications.
    //
    if (SourceInfo->EndOfFile.QuadPart == 0) {
        FILE_NETWORK_OPEN_INFORMATION verify_info;

        RtlInitUnicodeString(&objname, TargetPath);
        status = __sys_NtCreateFile(
            &target, FILE_GENERIC_WRITE | SYNCHRONIZE,
            &objattrs, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_VALID_FLAGS, FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_OPEN_REPARSE_POINT, NULL, 0);
        if (!NT_SUCCESS(status)) {
            File_HistoryDeleteFile(TargetPath);
            return status;
        }

        //
        // The source may have been written between the initial
        // NtQueryFullAttributesFile in File_HistoryCapture and
        // this fast path.  Re-query to detect a generation change.
        //
        RtlInitUnicodeString(&objname, SourcePath);
        status = __sys_NtQueryFullAttributesFile(&objattrs, &verify_info);
        if (!NT_SUCCESS(status) ||
                !File_HistorySameGenerationInfo(SourceInfo, &verify_info)) {
            NtClose(target);
            File_HistoryDeleteFile(TargetPath);
            return NT_SUCCESS(status) ? STATUS_RETRY : status;
        }
        *SourceInfo = verify_info;

        {
            NTSTATUS attr_status;

            basic.CreationTime = SourceInfo->CreationTime;
            basic.LastAccessTime = SourceInfo->LastAccessTime;
            basic.LastWriteTime = SourceInfo->LastWriteTime;
            basic.ChangeTime = SourceInfo->ChangeTime;
            basic.FileAttributes = FILE_ATTRIBUTE_NORMAL;
            attr_status = __sys_NtSetInformationFile(
                target, &iosb, &basic, sizeof(basic),
                FileBasicInformation);
            if (!NT_SUCCESS(attr_status))
                File_HistoryLogWarning(
                    L"Preserving file attributes",
                    attr_status, SourcePath);
        }

        // SHA-256 of the empty string
        static const UCHAR empty_hash[FILE_HISTORY_SHA256_SIZE] = {
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
        };
        memcpy(Hash, empty_hash, FILE_HISTORY_SHA256_SIZE);
        *HashValid = TRUE;
        NtClose(target);
        return status;
    }

    RtlInitUnicodeString(&objname, SourcePath);

    {
        ULONG sharing_retries;

        for (sharing_retries = 0; ; ++sharing_retries) {
            status = __sys_NtCreateFile(
                &source, FILE_GENERIC_READ | SYNCHRONIZE,
                &objattrs, &iosb, NULL, 0, FILE_SHARE_VALID_FLAGS,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
                FILE_OPEN_REPARSE_POINT, NULL, 0);
            if (status != STATUS_SHARING_VIOLATION ||
                    sharing_retries >= FILE_HISTORY_SHARING_RETRY_ATTEMPTS)
                break;
            Sleep(FILE_HISTORY_SHARING_RETRY_DELAY_MS
                  * (sharing_retries + 1));
        }
    }

    if (!NT_SUCCESS(status))
        return status;

    status = __sys_NtQueryInformationFile(
        source, &iosb, &current_info, sizeof(current_info),
        FileNetworkOpenInformation);
    if (!NT_SUCCESS(status))
        goto finish;
    if (!File_HistorySameGenerationInfo(&expected_info, &current_info)) {
        status = STATUS_RETRY;
        goto finish;
    }
    *SourceInfo = current_info;

    if (SourceInfo->FileAttributes &
            (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) {
        status = STATUS_ACCESS_DENIED;
        goto finish;
    }

    RtlInitUnicodeString(&objname, TargetPath);
    status = __sys_NtCreateFile(
        &target, FILE_GENERIC_WRITE | SYNCHRONIZE,
        &objattrs, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_VALID_FLAGS, FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_OPEN_REPARSE_POINT, NULL, 0);
    if (!NT_SUCCESS(status))
        goto finish;

    buffer = Dll_AllocTemp(FILE_HISTORY_COPY_BUFFER);
    if (!buffer) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto finish;
    }

    hashing = File_HistoryInitHash(&hash_context);
    offset.QuadPart = 0;
    while ((ULONGLONG)offset.QuadPart <
            (ULONGLONG)SourceInfo->EndOfFile.QuadPart) {
        ULONGLONG remaining =
            SourceInfo->EndOfFile.QuadPart - offset.QuadPart;
        ULONG length = remaining > FILE_HISTORY_COPY_BUFFER
                     ? FILE_HISTORY_COPY_BUFFER : (ULONG)remaining;

        status = __sys_NtReadFile(
            source, NULL, NULL, NULL, &iosb,
            buffer, length, &offset, NULL);
        if (!NT_SUCCESS(status))
            break;
        if (!iosb.Information) {
            status = STATUS_END_OF_FILE;
            break;
        }

        length = (ULONG)iosb.Information;
        status = __sys_NtWriteFile(
            target, NULL, NULL, NULL, &iosb,
            buffer, length, &offset, NULL);
        if (!NT_SUCCESS(status) || iosb.Information != length) {
            if (NT_SUCCESS(status))
                status = STATUS_DISK_FULL;
            break;
        }

        if (hashing &&
                !File_HistoryUpdateHash(&hash_context, buffer, length))
            hashing = FALSE;
        offset.QuadPart += length;
    }

    Dll_Free(buffer);

    if (NT_SUCCESS(status)) {
        status = __sys_NtQueryInformationFile(
            source, &iosb, &final_info, sizeof(final_info),
            FileNetworkOpenInformation);
        if (NT_SUCCESS(status) &&
                !File_HistorySameGenerationInfo(SourceInfo, &final_info))
            status = STATUS_RETRY;
    }

    if (NT_SUCCESS(status)) {
        NTSTATUS attr_status;

        basic.CreationTime = SourceInfo->CreationTime;
        basic.LastAccessTime = SourceInfo->LastAccessTime;
        basic.LastWriteTime = SourceInfo->LastWriteTime;
        basic.ChangeTime = SourceInfo->ChangeTime;
        basic.FileAttributes = FILE_ATTRIBUTE_NORMAL;
        attr_status = __sys_NtSetInformationFile(
            target, &iosb, &basic, sizeof(basic), FileBasicInformation);
        if (!NT_SUCCESS(attr_status))
            File_HistoryLogWarning(
                L"Preserving file attributes", attr_status, SourcePath);
    }

    if (NT_SUCCESS(status) && hashing)
        *HashValid = File_HistoryFinishHash(&hash_context, Hash);
    else
        File_HistoryFreeHash(&hash_context);

finish:
    File_HistoryFreeHash(&hash_context);
    if (target)
        NtClose(target);
    if (source)
        NtClose(source);
    if (!NT_SUCCESS(status))
        File_HistoryDeleteFile(TargetPath);
    return status;
}


//---------------------------------------------------------------------------
// File_HistoryFilesEqual
//---------------------------------------------------------------------------


static _FX BOOLEAN File_HistoryFilesEqual(
    const WCHAR *FirstPath, const WCHAR *SecondPath)
{
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    IO_STATUS_BLOCK iosb1;
    IO_STATUS_BLOCK iosb2;
    FILE_STANDARD_INFORMATION info1;
    FILE_STANDARD_INFORMATION info2;
    LARGE_INTEGER offset;
    HANDLE first = NULL;
    HANDLE second = NULL;
    UCHAR *buffer1 = NULL;
    UCHAR *buffer2 = NULL;
    NTSTATUS status;
    BOOLEAN equal = FALSE;

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlInitUnicodeString(&objname, FirstPath);
    status = __sys_NtCreateFile(
        &first, FILE_GENERIC_READ | SYNCHRONIZE,
        &objattrs, &iosb1, NULL, 0, FILE_SHARE_VALID_FLAGS, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_OPEN_REPARSE_POINT, NULL, 0);
    if (!NT_SUCCESS(status))
        goto finish;

    RtlInitUnicodeString(&objname, SecondPath);
    status = __sys_NtCreateFile(
        &second, FILE_GENERIC_READ | SYNCHRONIZE,
        &objattrs, &iosb2, NULL, 0, FILE_SHARE_VALID_FLAGS, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_OPEN_REPARSE_POINT, NULL, 0);
    if (!NT_SUCCESS(status))
        goto finish;

    status = __sys_NtQueryInformationFile(
        first, &iosb1, &info1, sizeof(info1), FileStandardInformation);
    if (NT_SUCCESS(status)) {
        status = __sys_NtQueryInformationFile(
            second, &iosb2, &info2, sizeof(info2), FileStandardInformation);
    }
    if (!NT_SUCCESS(status) ||
            info1.EndOfFile.QuadPart != info2.EndOfFile.QuadPart)
        goto finish;

    buffer1 = Dll_AllocTemp(FILE_HISTORY_COPY_BUFFER);
    buffer2 = Dll_AllocTemp(FILE_HISTORY_COPY_BUFFER);
    if (!buffer1 || !buffer2)
        goto finish;

    equal = TRUE;
    offset.QuadPart = 0;
    while ((ULONGLONG)offset.QuadPart <
            (ULONGLONG)info1.EndOfFile.QuadPart) {
        ULONGLONG remaining = info1.EndOfFile.QuadPart - offset.QuadPart;
        ULONG length = remaining > FILE_HISTORY_COPY_BUFFER
                     ? FILE_HISTORY_COPY_BUFFER : (ULONG)remaining;

        status = __sys_NtReadFile(
            first, NULL, NULL, NULL, &iosb1,
            buffer1, length, &offset, NULL);
        if (NT_SUCCESS(status)) {
            status = __sys_NtReadFile(
                second, NULL, NULL, NULL, &iosb2,
                buffer2, length, &offset, NULL);
        }
        if (!NT_SUCCESS(status) ||
                iosb1.Information != iosb2.Information ||
                iosb1.Information != length ||
                memcmp(buffer1, buffer2, length) != 0) {
            equal = FALSE;
            break;
        }

        offset.QuadPart += length;
    }

finish:
    if (buffer2)
        Dll_Free(buffer2);
    if (buffer1)
        Dll_Free(buffer1);
    if (second)
        NtClose(second);
    if (first)
        NtClose(first);
    return equal;
}


static _FX ULONG File_HistoryProbeCopyBlob(
    const WCHAR *TempPath,
    const UCHAR Hash[FILE_HISTORY_SHA256_SIZE], BOOLEAN HashValid)
{
    WCHAR hash_text[FILE_HISTORY_SHA256_TEXT];
    WCHAR *blob_path;
    FILE_NETWORK_OPEN_INFORMATION info;
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    NTSTATUS status;
    ULONG length;
    BOOLEAN blob_exists = FALSE;

    if (!HashValid || !File_HistoryBlobs)
        return FILE_HISTORY_BLOB_NONE;

    File_HistoryFormatHash(Hash, hash_text);
    length = wcslen(File_HistoryBlobs) + wcslen(hash_text) + 6;
    blob_path = Dll_AllocTemp(length * sizeof(WCHAR));
    if (!blob_path)
        return FILE_HISTORY_BLOB_NONE;
    Sbie_snwprintf(blob_path, length, L"%s\\%s.bin",
        File_HistoryBlobs, hash_text);

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlInitUnicodeString(&objname, blob_path);
    status = __sys_NtQueryFullAttributesFile(&objattrs, &info);
    if (NT_SUCCESS(status)) {
        if (!(info.FileAttributes &
                (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
            blob_exists = TRUE;
    }
    else if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
            status == STATUS_OBJECT_PATH_NOT_FOUND ||
            status == STATUS_NO_SUCH_FILE) {
        Dll_Free(blob_path);
        return FILE_HISTORY_BLOB_MISSING;
    }

    if (blob_exists && File_HistoryFilesEqual(TempPath, blob_path)) {
        Dll_Free(blob_path);
        return FILE_HISTORY_BLOB_MATCH;
    }

    Dll_Free(blob_path);
    return blob_exists
        ? FILE_HISTORY_BLOB_EXISTING : FILE_HISTORY_BLOB_NONE;
}


static _FX NTSTATUS File_HistoryPublishCopy(
    const WCHAR *TempPath, const WCHAR *VersionPath,
    const UCHAR Hash[FILE_HISTORY_SHA256_SIZE], BOOLEAN HashValid,
    ULONG BlobState, BOOLEAN *ContentReused)
{
    WCHAR hash_text[FILE_HISTORY_SHA256_TEXT];
    WCHAR *blob_path;
    NTSTATUS status;
    ULONG length;

    *ContentReused = FALSE;
    if ((!HashValid || !File_HistoryBlobs) ||
            (BlobState != FILE_HISTORY_BLOB_MISSING &&
             BlobState != FILE_HISTORY_BLOB_MATCH))
        return File_HistoryRenamePath(TempPath, VersionPath, FALSE);

    File_HistoryFormatHash(Hash, hash_text);
    length = wcslen(File_HistoryBlobs) + wcslen(hash_text) + 6;
    blob_path = Dll_AllocTemp(length * sizeof(WCHAR));
    if (!blob_path)
        return File_HistoryRenamePath(TempPath, VersionPath, FALSE);
    Sbie_snwprintf(blob_path, length, L"%s\\%s.bin",
        File_HistoryBlobs, hash_text);

    if (BlobState == FILE_HISTORY_BLOB_MISSING) {
        status = File_HistoryCreateHardLink(TempPath, blob_path);
        if (NT_SUCCESS(status)) {
            status = File_HistoryRenamePath(
                TempPath, VersionPath, FALSE);
            if (!NT_SUCCESS(status))
                File_HistoryDeleteFile(blob_path);
            Dll_Free(blob_path);
            return status;
        }
        if (status != STATUS_OBJECT_NAME_COLLISION) {
            Dll_Free(blob_path);
            return File_HistoryRenamePath(TempPath, VersionPath, FALSE);
        }
    }
    else {
        status = File_HistoryCreateHardLink(blob_path, VersionPath);
        if (NT_SUCCESS(status)) {
            File_HistoryDeleteFile(TempPath);
            *ContentReused = TRUE;
            Dll_Free(blob_path);
            return STATUS_SUCCESS;
        }
        if (status == STATUS_OBJECT_NAME_COLLISION) {
            Dll_Free(blob_path);
            return status;
        }
    }

    Dll_Free(blob_path);
    return File_HistoryRenamePath(TempPath, VersionPath, FALSE);
}


//---------------------------------------------------------------------------
// File_HistorySelectCollisionPair
//---------------------------------------------------------------------------


static _FX NTSTATUS File_HistorySelectCollisionPair(
    const WCHAR *ArtifactPath,
    const FILE_NETWORK_OPEN_INFORMATION *Info,
    WCHAR *VersionPath, WCHAR *MetaPath, ULONG Length)
{
    FILE_NETWORK_OPEN_INFORMATION existing_info;
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    FILETIME now;
    ULONGLONG event_id;
    NTSTATUS status;
    ULONG attempt;

    GetSystemTimeAsFileTime(&now);
    event_id =
        ((ULONGLONG)now.dwHighDateTime << 32) | now.dwLowDateTime;
    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);

    for (attempt = 0;
            attempt < FILE_HISTORY_COLLISION_ATTEMPTS;
            ++attempt) {
        Sbie_snwprintf(VersionPath, Length,
            L"%s\\%016I64X-%016I64X-%016I64X-%016I64X.bin",
            ArtifactPath, Info->LastWriteTime.QuadPart,
            Info->ChangeTime.QuadPart, Info->EndOfFile.QuadPart,
            event_id + attempt);
        Sbie_snwprintf(MetaPath, Length,
            L"%s\\%016I64X-%016I64X-%016I64X-%016I64X.txt",
            ArtifactPath, Info->LastWriteTime.QuadPart,
            Info->ChangeTime.QuadPart, Info->EndOfFile.QuadPart,
            event_id + attempt);

        RtlInitUnicodeString(&objname, VersionPath);
        status = __sys_NtQueryFullAttributesFile(
            &objattrs, &existing_info);
        if (NT_SUCCESS(status))
            continue;
        if (status != STATUS_OBJECT_NAME_NOT_FOUND &&
                status != STATUS_OBJECT_PATH_NOT_FOUND &&
                status != STATUS_NO_SUCH_FILE) {
            return status;
        }

        RtlInitUnicodeString(&objname, MetaPath);
        status = __sys_NtQueryFullAttributesFile(
            &objattrs, &existing_info);
        if (!NT_SUCCESS(status)) {
            if (status != STATUS_OBJECT_NAME_NOT_FOUND &&
                    status != STATUS_OBJECT_PATH_NOT_FOUND &&
                    status != STATUS_NO_SUCH_FILE) {
                return status;
            }
            return STATUS_SUCCESS;
        }
    }

    return STATUS_OBJECT_NAME_COLLISION;
}


//---------------------------------------------------------------------------
// File_HistoryCapture
//---------------------------------------------------------------------------


static _FX BOOLEAN File_HistoryCapture(
    const WCHAR *TruePath, const WCHAR *CopyPath, const WCHAR *Operation)
{
    WCHAR artifact[80];
    WCHAR *marker;
    WCHAR *artifact_path;
    WCHAR *version_path;
    WCHAR *temp_path;
    WCHAR *meta_path;
    WCHAR *text;
    WCHAR *escaped_true;
    WCHAR *escaped_dos;
    WCHAR *escaped_copy;
    WCHAR *escaped_copy_dos;
    WCHAR *escaped_image;
    FILE_NETWORK_OPEN_INFORMATION info;
    FILE_NETWORK_OPEN_INFORMATION existing_info;
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    HANDLE mutex;
    HANDLE limit_mutex = NULL;
    NTSTATUS status;
    ULONG length;
    ULONG attempts = 0;
    ULONG publish_attempt;
    FILETIME now;
    ULONGLONG event_id;
    UCHAR hash[FILE_HISTORY_SHA256_SIZE];
    WCHAR hash_text[FILE_HISTORY_SHA256_TEXT];
    BOOLEAN need_copy;
    BOOLEAN use_collision_name;
    BOOLEAN write_metadata;
    BOOLEAN hash_valid;
    BOOLEAN content_reused;
    ULONG blob_state;

    if (!File_HistoryMatches(TruePath))
        return FALSE;

    mutex = File_HistoryCreateMutex(TruePath);
    if (!mutex)
        return FALSE;

    marker = File_HistoryFindMarker(
        TruePath, artifact, RTL_NUMBER_OF_V1(artifact), FALSE);
    if (!marker) {
        File_HistoryReleaseMutex(mutex);
        return FALSE;
    }
    Dll_Free(marker);

    length = wcslen(File_HistoryArtifacts) + wcslen(artifact) + 2;
    artifact_path = Dll_AllocTemp(length * sizeof(WCHAR));
    if (!artifact_path) {
        File_HistoryReleaseMutex(mutex);
        return FALSE;
    }
    Sbie_snwprintf(artifact_path, length, L"%s\\%s",
        File_HistoryArtifacts, artifact);

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlInitUnicodeString(&objname, CopyPath);
    status = __sys_NtQueryFullAttributesFile(&objattrs, &info);
    if (!NT_SUCCESS(status) ||
            (info.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
                                    FILE_ATTRIBUTE_REPARSE_POINT))) {
        Dll_Free(artifact_path);
        File_HistoryReleaseMutex(mutex);
        return FALSE;
    }

    length = wcslen(artifact_path) + 128;
    version_path = Dll_AllocTemp(length * sizeof(WCHAR));
    meta_path = Dll_AllocTemp(length * sizeof(WCHAR));
    temp_path = Dll_AllocTemp((length + 32) * sizeof(WCHAR));
    if (!version_path || !meta_path || !temp_path) {
        if (version_path)
            Dll_Free(version_path);
        if (meta_path)
            Dll_Free(meta_path);
        if (temp_path)
            Dll_Free(temp_path);
        Dll_Free(artifact_path);
        File_HistoryReleaseMutex(mutex);
        return FALSE;
    }

retry_capture:
    ++attempts;
    need_copy = FALSE;
    use_collision_name = FALSE;
    write_metadata = TRUE;
    hash_valid = FALSE;
    content_reused = FALSE;

    Sbie_snwprintf(version_path, length,
        L"%s\\%016I64X-%016I64X-%016I64X.bin",
        artifact_path, info.LastWriteTime.QuadPart,
        info.ChangeTime.QuadPart, info.EndOfFile.QuadPart);
    Sbie_snwprintf(meta_path, length,
        L"%s\\%016I64X-%016I64X-%016I64X.txt",
        artifact_path, info.LastWriteTime.QuadPart,
        info.ChangeTime.QuadPart, info.EndOfFile.QuadPart);

    RtlInitUnicodeString(&objname, version_path);
    status = __sys_NtQueryFullAttributesFile(&objattrs, &existing_info);
    if (NT_SUCCESS(status)) {
        if (File_HistoryFilesEqual(CopyPath, version_path)) {
            RtlInitUnicodeString(&objname, meta_path);
            status = __sys_NtQueryFullAttributesFile(
                &objattrs, &existing_info);
            if (NT_SUCCESS(status)) {
                if (existing_info.FileAttributes &
                        (FILE_ATTRIBUTE_DIRECTORY |
                         FILE_ATTRIBUTE_REPARSE_POINT)) {
                    status = STATUS_OBJECT_TYPE_MISMATCH;
                }
                else {
                    Dll_Free(meta_path);
                    Dll_Free(temp_path);
                    Dll_Free(version_path);
                    Dll_Free(artifact_path);
                    File_HistoryReleaseMutex(mutex);
                    return TRUE;
                }
            }
            if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
                    status == STATUS_OBJECT_PATH_NOT_FOUND ||
                    status == STATUS_NO_SUCH_FILE) {
                status = STATUS_SUCCESS;
            }
        }
        else {
            need_copy = TRUE;
            use_collision_name = TRUE;
        }
    }
    else if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
            status == STATUS_OBJECT_PATH_NOT_FOUND ||
            status == STATUS_NO_SUCH_FILE) {
        RtlInitUnicodeString(&objname, meta_path);
        status = __sys_NtQueryFullAttributesFile(
            &objattrs, &existing_info);
        if (NT_SUCCESS(status)) {
            need_copy = TRUE;
            use_collision_name = TRUE;
        }
        else if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
                status == STATUS_OBJECT_PATH_NOT_FOUND ||
                status == STATUS_NO_SUCH_FILE) {
            need_copy = TRUE;
        }
    }

    if (need_copy && use_collision_name) {
        status = File_HistorySelectCollisionPair(
            artifact_path, &info, version_path, meta_path, length);
        if (!NT_SUCCESS(status))
            need_copy = FALSE;
    }

    if (need_copy) {
        status = File_HistoryCheckLimits(
            artifact_path,
            info.EndOfFile.QuadPart > 0
                ? (ULONGLONG)info.EndOfFile.QuadPart : 0,
            &limit_mutex);
        if (NT_SUCCESS(status)) {
            File_HistoryReleaseMutex(limit_mutex);
            limit_mutex = NULL;
            Sbie_snwprintf(temp_path, length + 32, L"%s.tmp.%08X.%08X",
                version_path, Dll_ProcessId,
                InterlockedIncrement(&File_HistorySequence));
            status = File_HistoryCopyFile(
                CopyPath, temp_path, &info, hash, &hash_valid);
            if ((status == STATUS_RETRY ||
                 status == STATUS_SHARING_VIOLATION) &&
                    attempts < FILE_HISTORY_CAPTURE_ATTEMPTS) {
                RtlInitUnicodeString(&objname, CopyPath);
                status = __sys_NtQueryFullAttributesFile(&objattrs, &info);
                if (NT_SUCCESS(status)) {
                    if (info.FileAttributes &
                            (FILE_ATTRIBUTE_DIRECTORY |
                             FILE_ATTRIBUTE_REPARSE_POINT)) {
                        status = STATUS_OBJECT_TYPE_MISMATCH;
                    }
                    else
                        goto retry_capture;
                }
            }
            if (NT_SUCCESS(status)) {
                blob_state = File_HistoryProbeCopyBlob(
                    temp_path, hash, hash_valid);
                for (publish_attempt = 0;
                        publish_attempt < FILE_HISTORY_PUBLISH_ATTEMPTS;
                        ++publish_attempt) {
                    status = File_HistoryCheckLimits(
                        artifact_path,
                        info.EndOfFile.QuadPart > 0
                            ? (ULONGLONG)info.EndOfFile.QuadPart : 0,
                        &limit_mutex);
                    if (!NT_SUCCESS(status)) {
                        File_HistoryDeleteFile(temp_path);
                        break;
                    }
                    status = File_HistoryPublishCopy(
                        temp_path, version_path, hash, hash_valid,
                        blob_state, &content_reused);
                    if (NT_SUCCESS(status)) {
                        File_HistoryCommitUsage(
                            info.EndOfFile.QuadPart > 0
                                ? (ULONGLONG)info.EndOfFile.QuadPart : 0);
                        File_HistoryReleaseMutex(limit_mutex);
                        limit_mutex = NULL;
                        break;
                    }
                    File_HistoryReleaseMutex(limit_mutex);
                    limit_mutex = NULL;
                    if (status != STATUS_OBJECT_NAME_COLLISION)
                        break;

                    if (File_HistoryFilesEqual(
                            temp_path, version_path)) {
                        File_HistoryDeleteFile(temp_path);
                        RtlInitUnicodeString(&objname, meta_path);
                        status = __sys_NtQueryFullAttributesFile(
                            &objattrs, &existing_info);
                        if (NT_SUCCESS(status)) {
                            if (existing_info.FileAttributes &
                                    (FILE_ATTRIBUTE_DIRECTORY |
                                     FILE_ATTRIBUTE_REPARSE_POINT)) {
                                status = STATUS_OBJECT_TYPE_MISMATCH;
                            }
                            else
                                write_metadata = FALSE;
                        }
                        else if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
                                status == STATUS_OBJECT_PATH_NOT_FOUND ||
                                status == STATUS_NO_SUCH_FILE) {
                            status = STATUS_SUCCESS;
                        }
                        break;
                    }

                    if (publish_attempt + 1 >=
                            FILE_HISTORY_PUBLISH_ATTEMPTS)
                        break;

                    status = File_HistorySelectCollisionPair(
                        artifact_path, &info,
                        version_path, meta_path, length);
                    if (!NT_SUCCESS(status))
                        break;
                }

                if (!NT_SUCCESS(status))
                    File_HistoryDeleteFile(temp_path);
            }
        }
    }

    if (NT_SUCCESS(status) && write_metadata) {
        GetSystemTimeAsFileTime(&now);
        event_id = ((ULONGLONG)now.dwHighDateTime << 32) | now.dwLowDateTime;

        escaped_true = File_JournalEscapeField_internal(TruePath);
        escaped_dos = File_HistoryEscapeDosPath(TruePath);
        escaped_copy = File_HistoryEscapeCopyPath(CopyPath, FALSE);
        escaped_copy_dos = File_HistoryEscapeCopyPath(CopyPath, TRUE);
        escaped_image = File_JournalEscapeField_internal(Dll_ImageName);
        if (hash_valid)
            File_HistoryFormatHash(hash, hash_text);
        else
            wcscpy(hash_text, L"unavailable");
        if (escaped_true && escaped_dos && escaped_copy &&
                escaped_copy_dos && escaped_image) {
            length = wcslen(artifact) + wcslen(escaped_true) +
                     wcslen(escaped_dos) + wcslen(escaped_copy) +
                     wcslen(escaped_copy_dos) + wcslen(Operation) +
                     wcslen(escaped_image) + 400;
            text = Dll_AllocTemp(length * sizeof(WCHAR));
        }
        else
            text = NULL;
        if (text) {
            Sbie_snwprintf(text, length,
                L"artifact=%s\r\npath=%s\r\ndos_path=%s\r\n"
                L"copy_path=%s\r\ncopy_dos_path=%s\r\n"
                L"operation=%s\r\ntimestamp=%016I64X\r\n"
                L"pid=%u\r\nimage=%s\r\nsize=%I64u\r\n"
                L"attributes=%08X\r\nlast_write=%016I64X\r\n"
                L"change_time=%016I64X\r\nsha256=%s\r\n"
                L"content_reused=%s\r\n",
                artifact, escaped_true, escaped_dos,
                escaped_copy, escaped_copy_dos, Operation, event_id,
                Dll_ProcessId, escaped_image, info.EndOfFile.QuadPart,
                info.FileAttributes, info.LastWriteTime.QuadPart,
                info.ChangeTime.QuadPart, hash_text,
                content_reused ? L"y" : L"n");
            status = File_HistoryWriteTextAtomic(
                meta_path, text, FALSE);
            Dll_Free(text);
        }
        else
            status = STATUS_INSUFFICIENT_RESOURCES;
        if (escaped_true)
            Dll_Free(escaped_true);
        if (escaped_dos)
            Dll_Free(escaped_dos);
        if (escaped_copy)
            Dll_Free(escaped_copy);
        if (escaped_copy_dos)
            Dll_Free(escaped_copy_dos);
        if (escaped_image)
            Dll_Free(escaped_image);
    }

    if (status == STATUS_QUOTA_EXCEEDED)
        File_HistoryLogLimit(TruePath);
    else if (!NT_SUCCESS(status) && status != STATUS_FILE_TOO_LARGE)
        File_HistoryLogWarning(L"Evidence capture", status, TruePath);

    Dll_Free(meta_path);
    Dll_Free(temp_path);
    Dll_Free(version_path);
    Dll_Free(artifact_path);
    File_HistoryReleaseMutex(limit_mutex);
    File_HistoryReleaseMutex(mutex);
    return NT_SUCCESS(status) || status == STATUS_FILE_TOO_LARGE;
}


//---------------------------------------------------------------------------
// File_HistoryArmDelete
//---------------------------------------------------------------------------


static _FX BOOLEAN File_HistoryArmDelete(
    HANDLE FileHandle, const WCHAR *TruePath, const WCHAR *CopyPath)
{
    WCHAR artifact[80];
    WCHAR *marker;
    WCHAR *artifact_path;
    WCHAR *link_path;
    WCHAR *meta_path;
    WCHAR *text;
    WCHAR *escaped_true;
    WCHAR *escaped_dos;
    WCHAR *escaped_copy;
    WCHAR *escaped_copy_dos;
    WCHAR *escaped_image;
    FILE_LINK_INFORMATION *info;
    FILE_NETWORK_OPEN_INFORMATION link_info;
    FILE_NETWORK_OPEN_INFORMATION link_network;
    FILE_NETWORK_OPEN_INFORMATION source_network;
    FILE_INTERNAL_INFORMATION source_internal;
    FILE_INTERNAL_INFORMATION link_internal;
    FILETIME now;
    IO_STATUS_BLOCK iosb;
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    HANDLE mutex;
    HANDLE limit_mutex = NULL;
    NTSTATUS status;
    ULONG length;
    ULONG name_len;
    ULONG info_len;
    ULONGLONG event_id;
    ULONGLONG process_start = 0;
    BOOLEAN link_exists = FALSE;
    BOOLEAN link_created = FALSE;

    if (!File_HistoryMatches(TruePath))
        return FALSE;

    mutex = File_HistoryCreateMutex(TruePath);
    if (!mutex)
        return FALSE;

    marker = File_HistoryFindMarker(
        TruePath, artifact, RTL_NUMBER_OF_V1(artifact), FALSE);
    if (!marker) {
        File_HistoryReleaseMutex(mutex);
        return FALSE;
    }
    Dll_Free(marker);

    length = wcslen(File_HistoryArtifacts) + wcslen(artifact) + 2;
    artifact_path = Dll_AllocTemp(length * sizeof(WCHAR));
    if (!artifact_path) {
        File_HistoryReleaseMutex(mutex);
        return FALSE;
    }
    Sbie_snwprintf(artifact_path, length, L"%s\\%s",
        File_HistoryArtifacts, artifact);

    length = wcslen(artifact_path) + 16;
    link_path = Dll_AllocTemp(length * sizeof(WCHAR));
    meta_path = Dll_AllocTemp(length * sizeof(WCHAR));
    if (!link_path || !meta_path) {
        if (link_path)
            Dll_Free(link_path);
        if (meta_path)
            Dll_Free(meta_path);
        Dll_Free(artifact_path);
        File_HistoryReleaseMutex(mutex);
        return FALSE;
    }
    Sbie_snwprintf(link_path, length, L"%s\\pending.bin", artifact_path);
    Sbie_snwprintf(meta_path, length, L"%s\\pending.txt", artifact_path);

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlInitUnicodeString(&objname, link_path);
    status = __sys_NtQueryFullAttributesFile(&objattrs, &link_info);
    if (NT_SUCCESS(status)) {
        link_exists = TRUE;
        status = __sys_NtQueryInformationFile(
            FileHandle, &iosb, &source_internal, sizeof(source_internal),
            FileInternalInformation);
        if (NT_SUCCESS(status)) {
            status = File_HistoryQueryIdentity(
                link_path, &link_internal, &link_network, NULL);
        }
        if (!NT_SUCCESS(status) ||
                source_internal.IndexNumber.QuadPart !=
                link_internal.IndexNumber.QuadPart) {
            if (NT_SUCCESS(status))
                status = STATUS_OBJECT_NAME_COLLISION;
            link_exists = FALSE;
        }
    }
    else if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
             status == STATUS_OBJECT_PATH_NOT_FOUND ||
             status == STATUS_NO_SUCH_FILE) {
        status = __sys_NtQueryInformationFile(
            FileHandle, &iosb, &source_network, sizeof(source_network),
            FileNetworkOpenInformation);
        if (NT_SUCCESS(status)) {
            status = File_HistoryCheckLimits(
                artifact_path,
                source_network.EndOfFile.QuadPart > 0
                    ? (ULONGLONG)source_network.EndOfFile.QuadPart : 0,
                &limit_mutex);
        }
    }

    if (!link_exists && NT_SUCCESS(status)) {
        name_len = wcslen(link_path) * sizeof(WCHAR);
        info_len = sizeof(FILE_LINK_INFORMATION) + name_len;
        info = Dll_AllocTemp(info_len);
        if (!info) {
            Dll_Free(meta_path);
            Dll_Free(link_path);
            Dll_Free(artifact_path);
            File_HistoryReleaseMutex(limit_mutex);
            File_HistoryReleaseMutex(mutex);
            return FALSE;
        }

        memzero(info, info_len);
        info->ReplaceIfExists = FALSE;
        info->RootDirectory = NULL;
        info->FileNameLength = name_len;
        memcpy(info->FileName, link_path, name_len);
        status = __sys_NtSetInformationFile(
            FileHandle, &iosb, info, info_len, FileLinkInformation);
        Dll_Free(info);
        if (NT_SUCCESS(status)) {
            link_created = TRUE;
            File_HistoryCommitUsage(
                source_network.EndOfFile.QuadPart > 0
                    ? (ULONGLONG)source_network.EndOfFile.QuadPart : 0);
        }
    }

    File_HistoryReleaseMutex(limit_mutex);
    limit_mutex = NULL;

    if (NT_SUCCESS(status)) {
        NTSTATUS meta_status;

        GetSystemTimeAsFileTime(&now);
        event_id = ((ULONGLONG)now.dwHighDateTime << 32) | now.dwLowDateTime;
        File_HistoryQueryProcessCreationTime(
            GetCurrentProcess(), &process_start);
        escaped_true = File_JournalEscapeField_internal(TruePath);
        escaped_dos = File_HistoryEscapeDosPath(TruePath);
        escaped_copy = File_HistoryEscapeCopyPath(CopyPath, FALSE);
        escaped_copy_dos = File_HistoryEscapeCopyPath(CopyPath, TRUE);
        escaped_image = File_JournalEscapeField_internal(Dll_ImageName);
        if (escaped_true && escaped_dos && escaped_copy &&
                escaped_copy_dos && escaped_image) {
            length = wcslen(artifact) + wcslen(escaped_true) +
                     wcslen(escaped_dos) + wcslen(escaped_copy) +
                     wcslen(escaped_copy_dos) +
                     wcslen(escaped_image) + 256;
            text = Dll_AllocTemp(length * sizeof(WCHAR));
        }
        else
            text = NULL;
        if (text) {
            Sbie_snwprintf(text, length,
                L"artifact=%s\r\npath=%s\r\ndos_path=%s\r\n"
                L"copy_path=%s\r\ncopy_dos_path=%s\r\n"
                L"operation=delete-on-close\r\ntimestamp=%016I64X\r\n"
                L"pid=%u\r\nprocess_start=%016I64X\r\n"
                L"image=%s\r\nstate=pending\r\n",
                artifact, escaped_true, escaped_dos,
                escaped_copy, escaped_copy_dos, event_id,
                Dll_ProcessId, process_start, escaped_image);
            meta_status = File_HistoryWriteTextAtomic(
                meta_path, text, TRUE);
            Dll_Free(text);
        }
        else
            meta_status = STATUS_INSUFFICIENT_RESOURCES;
        if (escaped_true)
            Dll_Free(escaped_true);
        if (escaped_dos)
            Dll_Free(escaped_dos);
        if (escaped_copy)
            Dll_Free(escaped_copy);
        if (escaped_copy_dos)
            Dll_Free(escaped_copy_dos);
        if (escaped_image)
            Dll_Free(escaped_image);

        if (!NT_SUCCESS(meta_status)) {
            File_HistoryLogWarning(
                L"Delete-on-close metadata", meta_status, TruePath);
            if (link_created) {
                BOOLEAN rollback_abandoned;
                HANDLE rollback_mutex =
                    File_HistoryCreateLimitMutex(&rollback_abandoned);
                if (rollback_mutex) {
                    NTSTATUS cleanup_status;

                    if (rollback_abandoned)
                        File_HistoryInvalidateUsage();
                    cleanup_status = File_HistoryDeleteFile(link_path);
                    File_HistoryDeleteFile(meta_path);
                    if (NT_SUCCESS(cleanup_status))
                        File_HistoryInvalidateUsage();
                    else
                        File_HistoryLogWarning(
                            L"Delete-on-close evidence rollback",
                            cleanup_status, TruePath);
                    File_HistoryReleaseMutex(rollback_mutex);
                }
                else {
                    NTSTATUS cleanup_status =
                        File_HistoryDeleteFile(link_path);
                    File_HistoryDeleteFile(meta_path);
                    File_HistoryInvalidateUsage();
                    if (!NT_SUCCESS(cleanup_status))
                        File_HistoryLogWarning(
                            L"Delete-on-close evidence rollback",
                            cleanup_status, TruePath);
                }
                status = meta_status;
            }
        }
    }

    if (!NT_SUCCESS(status) && !link_exists) {
        if (status == STATUS_QUOTA_EXCEEDED)
            File_HistoryLogLimit(TruePath);
        else if (status != STATUS_FILE_TOO_LARGE)
            File_HistoryLogWarning(
                L"Delete-on-close evidence link", status, TruePath);
    }

    Dll_Free(meta_path);
    Dll_Free(link_path);
    Dll_Free(artifact_path);
    File_HistoryReleaseMutex(limit_mutex);
    File_HistoryReleaseMutex(mutex);
    return NT_SUCCESS(status) || status == STATUS_FILE_TOO_LARGE;
}


//---------------------------------------------------------------------------
// File_HistoryCancelDelete
//---------------------------------------------------------------------------


static _FX VOID File_HistoryCancelDelete(const WCHAR *TruePath)
{
    WCHAR artifact[80];
    WCHAR *marker;
    WCHAR *path;
    HANDLE mutex;
    HANDLE limit_mutex;
    BOOLEAN abandoned;
    ULONG length;

    if (!File_HistoryRoot)
        return;

    mutex = File_HistoryCreateMutex(TruePath);
    if (!mutex)
        return;

    marker = File_HistoryFindMarker(
        TruePath, artifact, RTL_NUMBER_OF_V1(artifact), FALSE);
    if (!marker) {
        File_HistoryReleaseMutex(mutex);
        return;
    }
    Dll_Free(marker);

    limit_mutex = File_HistoryCreateLimitMutex(&abandoned);
    if (!limit_mutex) {
        File_HistoryReleaseMutex(mutex);
        return;
    }
    if (abandoned)
        File_HistoryInvalidateUsage();

    length = wcslen(File_HistoryArtifacts) + wcslen(artifact) + 24;
    path = Dll_AllocTemp(length * sizeof(WCHAR));
    if (path) {
        NTSTATUS status;

        Sbie_snwprintf(path, length, L"%s\\%s\\pending.bin",
            File_HistoryArtifacts, artifact);
        status = File_HistoryDeleteFile(path);
        if (NT_SUCCESS(status))
            File_HistoryInvalidateUsage();
        Sbie_snwprintf(path, length, L"%s\\%s\\pending.txt",
            File_HistoryArtifacts, artifact);
        File_HistoryDeleteFile(path);
        Dll_Free(path);
    }

    File_HistoryReleaseMutex(limit_mutex);
    File_HistoryReleaseMutex(mutex);
}


//---------------------------------------------------------------------------
// File_HistoryRenameFile
//---------------------------------------------------------------------------


static _FX VOID File_HistoryRenameFile(
    const WCHAR *OldTruePath, const WCHAR *NewTruePath,
    const WCHAR *NewCopyPath, const WCHAR *ExpectedArtifact)
{
    WCHAR artifact[80];
    WCHAR artifact2[80];
    WCHAR *old_marker;
    WCHAR *new_marker;
    WCHAR *text;
    WCHAR *escaped_new;
    WCHAR *escaped_new_dos;
    WCHAR *escaped_copy;
    WCHAR *escaped_copy_dos;
    HANDLE old_mutex;
    HANDLE new_mutex;
    NTSTATUS status;
    ULONG length;

    if (!File_HistoryRoot)
        return;

    if (!File_HistoryCreateMutexPair(
            OldTruePath, NewTruePath, &old_mutex, &new_mutex))
        return;

    old_marker = File_HistoryFindMarker(
        OldTruePath, artifact, RTL_NUMBER_OF_V1(artifact), FALSE);
    if (!old_marker) {
        if (ExpectedArtifact) {
            File_HistoryReleaseMutex(new_mutex);
            File_HistoryReleaseMutex(old_mutex);
            return;
        }

        new_marker = File_HistoryFindMarker(
            NewTruePath, artifact2, RTL_NUMBER_OF_V1(artifact2), FALSE);
        if (new_marker) {
            File_HistoryDeleteFile(new_marker);
            Dll_Free(new_marker);
        }
        File_HistoryReleaseMutex(new_mutex);
        File_HistoryReleaseMutex(old_mutex);
        return;
    }

    if (ExpectedArtifact &&
            _wcsicmp(artifact, ExpectedArtifact) != 0) {
        Dll_Free(old_marker);
        File_HistoryReleaseMutex(new_mutex);
        File_HistoryReleaseMutex(old_mutex);
        return;
    }

    new_marker = File_HistoryFindMarker(
        NewTruePath, artifact2, RTL_NUMBER_OF_V1(artifact2), TRUE);
    if (!new_marker) {
        Dll_Free(old_marker);
        File_HistoryReleaseMutex(new_mutex);
        File_HistoryReleaseMutex(old_mutex);
        return;
    }

    escaped_new = File_JournalEscapeField_internal(NewTruePath);
    escaped_new_dos = File_HistoryEscapeDosPath(NewTruePath);
    escaped_copy = File_HistoryEscapeCopyPath(NewCopyPath, FALSE);
    escaped_copy_dos = File_HistoryEscapeCopyPath(NewCopyPath, TRUE);
    if (escaped_new && escaped_new_dos &&
            escaped_copy && escaped_copy_dos) {
        length = wcslen(artifact) + wcslen(escaped_new) +
                 wcslen(escaped_new_dos) + wcslen(escaped_copy) +
                 wcslen(escaped_copy_dos) + 96;
        text = Dll_AllocTemp(length * sizeof(WCHAR));
    }
    else
        text = NULL;
    if (text) {
        Sbie_snwprintf(text, length,
            L"artifact=%s\r\npath=%s\r\ndos_path=%s\r\n"
            L"copy_path=%s\r\ncopy_dos_path=%s\r\n",
            artifact, escaped_new, escaped_new_dos,
            escaped_copy, escaped_copy_dos);
        status = File_HistoryWriteTextAtomic(
            new_marker, text, TRUE);
        Dll_Free(text);
        if (NT_SUCCESS(status)) {
            File_HistoryUpdatePendingPaths(
                artifact, NewTruePath, NewCopyPath);
            if (_wcsicmp(old_marker, new_marker) != 0)
                File_HistoryDeleteFile(old_marker);
        }
    }
    if (escaped_new)
        Dll_Free(escaped_new);
    if (escaped_new_dos)
        Dll_Free(escaped_new_dos);
    if (escaped_copy)
        Dll_Free(escaped_copy);
    if (escaped_copy_dos)
        Dll_Free(escaped_copy_dos);

    Dll_Free(new_marker);
    Dll_Free(old_marker);
    File_HistoryReleaseMutex(new_mutex);
    File_HistoryReleaseMutex(old_mutex);
}


//---------------------------------------------------------------------------
// File_HistoryGetMetadataField
//---------------------------------------------------------------------------


static _FX WCHAR *File_HistoryGetMetadataField(
    const WCHAR *Text, const WCHAR *Name, BOOLEAN Unescape)
{
    const WCHAR *line = Text;
    ULONG name_len = wcslen(Name);

    while (*line) {
        const WCHAR *end = wcschr(line, L'\n');
        const WCHAR *value;
        ULONG length;
        WCHAR *copy;

        if (!end)
            end = line + wcslen(line);
        if ((ULONG)(end - line) > name_len &&
                _wcsnicmp(line, Name, name_len) == 0 &&
                line[name_len] == L'=') {
            value = line + name_len + 1;
            length = (ULONG)(end - value);
            if (length && value[length - 1] == L'\r')
                --length;

            copy = Dll_AllocTemp((length + 1) * sizeof(WCHAR));
            if (!copy)
                return NULL;
            wmemcpy(copy, value, length);
            copy[length] = L'\0';

            if (Unescape) {
                WCHAR *unescaped =
                    File_JournalUnescapeField_internal(copy);
                Dll_Free(copy);
                return unescaped;
            }
            return copy;
        }

        if (!*end)
            break;
        line = end + 1;
    }

    return NULL;
}


//---------------------------------------------------------------------------
// File_HistoryGetCopyPathField
//---------------------------------------------------------------------------


static _FX WCHAR *File_HistoryGetCopyPathField(
    const WCHAR *Text, const WCHAR *Name)
{
    WCHAR *value = File_HistoryGetMetadataField(Text, Name, TRUE);
    ULONG placeholder_length = RTL_NUMBER_OF(FILE_HISTORY_BOX_ROOT) - 1;
    ULONG root_length;
    ULONG length;
    WCHAR *expanded;

    if (!value ||
            _wcsnicmp(value, FILE_HISTORY_BOX_ROOT,
                placeholder_length) != 0 ||
            (value[placeholder_length] != L'\0' &&
             value[placeholder_length] != L'\\')) {
        return value;
    }

    root_length = (ULONG)wcslen(Dll_BoxFilePath);
    while (root_length && Dll_BoxFilePath[root_length - 1] == L'\\')
        --root_length;

    length = root_length +
             (ULONG)wcslen(value + placeholder_length) + 1;
    expanded = Dll_AllocTemp(length * sizeof(WCHAR));
    if (expanded) {
        Sbie_snwprintf(expanded, length, L"%.*s%s",
            root_length, Dll_BoxFilePath,
            value + placeholder_length);
    }

    Dll_Free(value);
    return expanded;
}


//---------------------------------------------------------------------------
// File_HistorySetMetadataField
//---------------------------------------------------------------------------


static _FX WCHAR *File_HistorySetMetadataField(
    const WCHAR *Text, const WCHAR *Name, const WCHAR *Value)
{
    const WCHAR *line = Text;
    const WCHAR *field = NULL;
    const WCHAR *end;
    WCHAR *updated;
    ULONG name_len = wcslen(Name);
    ULONG prefix_len;
    ULONG suffix_len;
    ULONG value_len;
    ULONG length;

    while (*line) {
        end = wcschr(line, L'\n');
        if (!end)
            end = line + wcslen(line);
        if ((ULONG)(end - line) > name_len &&
                _wcsnicmp(line, Name, name_len) == 0 &&
                line[name_len] == L'=') {
            field = line;
            break;
        }
        if (!*end)
            break;
        line = end + 1;
    }

    if (!field)
        return NULL;

    prefix_len = (ULONG)(field - Text);
    end = wcspbrk(field, L"\r\n");
    if (!end)
        end = field + wcslen(field);
    suffix_len = wcslen(end);
    value_len = wcslen(Value);
    length = prefix_len + name_len + 1 + value_len +
             suffix_len + 1;

    updated = Dll_AllocTemp(length * sizeof(WCHAR));
    if (!updated)
        return NULL;

    wmemcpy(updated, Text, prefix_len);
    wmemcpy(updated + prefix_len, Name, name_len);
    updated[prefix_len + name_len] = L'=';
    wmemcpy(updated + prefix_len + name_len + 1,
        Value, value_len);
    wcscpy(updated + prefix_len + name_len + 1 + value_len, end);
    return updated;
}


static _FX WCHAR *File_HistoryAppendMetadataField(
    const WCHAR *Text, const WCHAR *Name, const WCHAR *Value)
{
    ULONG text_len = wcslen(Text);
    ULONG name_len = wcslen(Name);
    ULONG value_len = wcslen(Value);
    ULONG length = text_len + name_len + value_len + 4;
    WCHAR *updated = Dll_AllocTemp(length * sizeof(WCHAR));

    if (!updated)
        return NULL;
    wmemcpy(updated, Text, text_len);
    wmemcpy(updated + text_len, Name, name_len);
    updated[text_len + name_len] = L'=';
    wmemcpy(updated + text_len + name_len + 1,
        Value, value_len);
    wmemcpy(updated + text_len + name_len + value_len + 1,
        L"\r\n", 2);
    updated[length - 1] = L'\0';
    return updated;
}


static _FX WCHAR *File_HistoryFinalizeMetadata(
    const WCHAR *Text, const FILE_NETWORK_OPEN_INFORMATION *Info,
    const UCHAR Hash[FILE_HISTORY_SHA256_SIZE], BOOLEAN HashValid)
{
    WCHAR size_text[32];
    WCHAR attributes_text[16];
    WCHAR last_write_text[32];
    WCHAR change_time_text[32];
    WCHAR hash_text[FILE_HISTORY_SHA256_TEXT];
    WCHAR *updated;
    WCHAR *next;

    updated = File_HistorySetMetadataField(
        Text, L"state", L"finalized");
    if (!updated)
        return NULL;

    Sbie_snwprintf(size_text, RTL_NUMBER_OF_V1(size_text),
        L"%I64u", Info->EndOfFile.QuadPart);
    Sbie_snwprintf(attributes_text, RTL_NUMBER_OF_V1(attributes_text),
        L"%08X", Info->FileAttributes);
    Sbie_snwprintf(last_write_text, RTL_NUMBER_OF_V1(last_write_text),
        L"%016I64X", Info->LastWriteTime.QuadPart);
    Sbie_snwprintf(change_time_text, RTL_NUMBER_OF_V1(change_time_text),
        L"%016I64X", Info->ChangeTime.QuadPart);
    if (HashValid)
        File_HistoryFormatHash(Hash, hash_text);
    else
        wcscpy(hash_text, L"unavailable");

#define FILE_HISTORY_APPEND_FINAL_FIELD(Name, Value) \
    do { \
        next = File_HistoryAppendMetadataField(updated, Name, Value); \
        Dll_Free(updated); \
        updated = next; \
        if (!updated) \
            return NULL; \
    } while (0)

    FILE_HISTORY_APPEND_FINAL_FIELD(L"size", size_text);
    FILE_HISTORY_APPEND_FINAL_FIELD(L"attributes", attributes_text);
    FILE_HISTORY_APPEND_FINAL_FIELD(L"last_write", last_write_text);
    FILE_HISTORY_APPEND_FINAL_FIELD(L"change_time", change_time_text);
    FILE_HISTORY_APPEND_FINAL_FIELD(L"sha256", hash_text);
    FILE_HISTORY_APPEND_FINAL_FIELD(L"content_reused", L"n");

#undef FILE_HISTORY_APPEND_FINAL_FIELD

    return updated;
}


//---------------------------------------------------------------------------
// File_HistoryUpdatePendingPaths
//---------------------------------------------------------------------------


static _FX VOID File_HistoryUpdatePendingPaths(
    const WCHAR *Artifact, const WCHAR *TruePath, const WCHAR *CopyPath)
{
    WCHAR *meta_path;
    WCHAR *text = NULL;
    WCHAR *updated = NULL;
    WCHAR *updated_copy = NULL;
    WCHAR *updated_dos = NULL;
    WCHAR *updated_copy_dos = NULL;
    WCHAR *escaped_true = NULL;
    WCHAR *escaped_dos = NULL;
    WCHAR *escaped_copy = NULL;
    WCHAR *escaped_copy_dos = NULL;
    NTSTATUS status;
    ULONG length;

    length = wcslen(File_HistoryArtifacts) +
             wcslen(Artifact) + 24;
    meta_path = Dll_AllocTemp(length * sizeof(WCHAR));
    if (!meta_path)
        return;
    Sbie_snwprintf(meta_path, length, L"%s\\%s\\pending.txt",
        File_HistoryArtifacts, Artifact);

    status = File_HistoryReadText(meta_path, &text);
    if (!NT_SUCCESS(status))
        goto finish;

    escaped_true = File_JournalEscapeField_internal(TruePath);
    escaped_dos = File_HistoryEscapeDosPath(TruePath);
    escaped_copy = File_HistoryEscapeCopyPath(CopyPath, FALSE);
    escaped_copy_dos = File_HistoryEscapeCopyPath(CopyPath, TRUE);
    if (!escaped_true || !escaped_dos ||
            !escaped_copy || !escaped_copy_dos)
        goto finish;

    updated = File_HistorySetMetadataField(
        text, L"path", escaped_true);
    if (!updated)
        goto finish;
    updated_copy = File_HistorySetMetadataField(
        updated, L"copy_path", escaped_copy);
    if (!updated_copy)
        goto finish;

    updated_dos = File_HistorySetMetadataField(
        updated_copy, L"dos_path", escaped_dos);
    if (updated_dos) {
        updated_copy_dos = File_HistorySetMetadataField(
            updated_dos, L"copy_dos_path", escaped_copy_dos);
    }

    File_HistoryWriteTextAtomic(
        meta_path, updated_copy_dos ? updated_copy_dos : updated_copy,
        TRUE);

finish:
    if (escaped_copy_dos)
        Dll_Free(escaped_copy_dos);
    if (escaped_copy)
        Dll_Free(escaped_copy);
    if (escaped_dos)
        Dll_Free(escaped_dos);
    if (escaped_true)
        Dll_Free(escaped_true);
    if (updated_copy_dos)
        Dll_Free(updated_copy_dos);
    if (updated_dos)
        Dll_Free(updated_dos);
    if (updated_copy)
        Dll_Free(updated_copy);
    if (updated)
        Dll_Free(updated);
    if (text)
        Dll_Free(text);
    Dll_Free(meta_path);
}


//---------------------------------------------------------------------------
// File_HistoryIsDescendant
//---------------------------------------------------------------------------


static _FX BOOLEAN File_HistoryIsDescendant(
    const WCHAR *Path, const WCHAR *Directory, ULONG *SuffixOffset)
{
    ULONG length = (ULONG)wcslen(Directory);
    ULONG path_length = (ULONG)wcslen(Path);

    while (length && Directory[length - 1] == L'\\')
        --length;

    if (!length || path_length <= length ||
            _wcsnicmp(Path, Directory, length) != 0 ||
            Path[length] != L'\\') {
        return FALSE;
    }

    *SuffixOffset = length;
    return TRUE;
}


//---------------------------------------------------------------------------
// File_HistoryRenameDirectory
//---------------------------------------------------------------------------


static _FX VOID File_HistoryRenameDirectory(
    const WCHAR *OldTruePath, const WCHAR *OldCopyPath,
    const WCHAR *NewTruePath, const WCHAR *NewCopyPath)
{
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    IO_STATUS_BLOCK iosb;
    FILE_ATTRIBUTE_TAG_INFORMATION taginfo;
    FILE_DIRECTORY_INFORMATION *info;
    LIST entries;
    HANDLE handle;
    NTSTATUS status;
    BOOLEAN restart = TRUE;
    ULONG info_len;

    List_Init(&entries);

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlInitUnicodeString(&objname, File_HistoryIndex);
    status = __sys_NtCreateFile(
        &handle, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objattrs, &iosb, NULL, 0, FILE_SHARE_VALID_FLAGS, FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_OPEN_REPARSE_POINT, NULL, 0);
    if (!NT_SUCCESS(status))
        goto finish;

    status = __sys_NtQueryInformationFile(
        handle, &iosb, &taginfo, sizeof(taginfo),
        FileAttributeTagInformation);
    if (!NT_SUCCESS(status) ||
            (taginfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        if (NT_SUCCESS(status))
            status = STATUS_ACCESS_DENIED;
        NtClose(handle);
        goto finish;
    }

    info_len = 4096;
    info = Dll_AllocTemp(info_len);
    if (!info) {
        NtClose(handle);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto finish;
    }

    while (1) {
        WCHAR *marker_path;
        WCHAR *text = NULL;
        WCHAR *artifact = NULL;
        WCHAR *old_true = NULL;
        WCHAR *old_copy = NULL;
        FILE_HISTORY_RENAME_ENTRY *entry;
        ULONG name_len;
        ULONG true_suffix;
        ULONG length;

        status = __sys_NtQueryDirectoryFile(
            handle, NULL, NULL, NULL, &iosb,
            info, info_len, FileDirectoryInformation,
            TRUE, NULL, restart);
        restart = FALSE;
        if (!NT_SUCCESS(status))
            break;

        name_len = info->FileNameLength / sizeof(WCHAR);
        if ((info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
                name_len < 4 ||
                _wcsnicmp(info->FileName + name_len - 4, L".idx", 4) != 0) {
            continue;
        }

        length = wcslen(File_HistoryIndex) + name_len + 2;
        marker_path = Dll_AllocTemp(length * sizeof(WCHAR));
        if (!marker_path) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        Sbie_snwprintf(marker_path, length, L"%s\\%.*s",
            File_HistoryIndex, name_len, info->FileName);

        status = File_HistoryReadText(marker_path, &text);
        Dll_Free(marker_path);
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
                    status == STATUS_OBJECT_PATH_NOT_FOUND ||
                    status == STATUS_NO_SUCH_FILE) {
                status = STATUS_SUCCESS;
                continue;
            }
            break;
        }

        artifact =
            File_HistoryGetMetadataField(text, L"artifact", FALSE);
        old_true =
            File_HistoryGetMetadataField(text, L"path", TRUE);
        old_copy =
            File_HistoryGetCopyPathField(text, L"copy_path");
        if (!artifact || !File_HistoryValidArtifact(artifact) ||
                !old_true ||
                !File_HistoryIsDescendant(
                    old_true, OldTruePath, &true_suffix)) {
            goto next;
        }

        entry = List_Head(&entries);
        while (entry) {
            if (_wcsicmp(entry->TruePath, old_true) == 0)
                goto next;
            entry = List_Next(entry);
        }

        entry = Dll_AllocTemp(sizeof(FILE_HISTORY_RENAME_ENTRY));
        if (!entry) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto next;
        }
        memzero(entry, sizeof(FILE_HISTORY_RENAME_ENTRY));
        entry->Artifact = artifact;
        entry->TruePath = old_true;
        entry->CopyPath = old_copy;
        artifact = NULL;
        old_true = NULL;
        old_copy = NULL;
        List_Insert_After(&entries, NULL, entry);

next:
        if (artifact)
            Dll_Free(artifact);
        if (old_copy)
            Dll_Free(old_copy);
        if (old_true)
            Dll_Free(old_true);
        Dll_Free(text);

        if (!NT_SUCCESS(status))
            break;
    }

    Dll_Free(info);
    NtClose(handle);
    if (status == STATUS_NO_MORE_FILES)
        status = STATUS_SUCCESS;

    while (List_Head(&entries)) {
        FILE_HISTORY_RENAME_ENTRY *entry = List_Head(&entries);
        WCHAR *new_true = NULL;
        WCHAR *new_copy = NULL;
        const WCHAR *copy_base;
        ULONG true_suffix;
        ULONG copy_suffix;
        ULONG length;

        List_Remove(&entries, entry);

        if (!File_HistoryIsDescendant(
                entry->TruePath, OldTruePath, &true_suffix)) {
            goto next_entry;
        }

        copy_base = entry->TruePath;
        copy_suffix = true_suffix;
        if (entry->CopyPath &&
                File_HistoryIsDescendant(
                    entry->CopyPath, OldCopyPath, &copy_suffix)) {
            copy_base = entry->CopyPath;
        }
        else {
            copy_suffix = true_suffix;
        }

        length = wcslen(NewTruePath) +
                 wcslen(entry->TruePath + true_suffix) + 1;
        new_true = Dll_AllocTemp(length * sizeof(WCHAR));
        if (!new_true) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto next_entry;
        }
        Sbie_snwprintf(new_true, length, L"%s%s",
            NewTruePath, entry->TruePath + true_suffix);

        length = wcslen(NewCopyPath) +
                 wcslen(copy_base + copy_suffix) + 1;
        new_copy = Dll_AllocTemp(length * sizeof(WCHAR));
        if (!new_copy) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto next_entry;
        }
        Sbie_snwprintf(new_copy, length, L"%s%s",
            NewCopyPath, copy_base + copy_suffix);

        File_HistoryRenameFile(
            entry->TruePath, new_true, new_copy, entry->Artifact);

next_entry:
        if (new_copy)
            Dll_Free(new_copy);
        if (new_true)
            Dll_Free(new_true);
        if (entry->CopyPath)
            Dll_Free(entry->CopyPath);
        Dll_Free(entry->TruePath);
        Dll_Free(entry->Artifact);
        Dll_Free(entry);
    }

finish:
    if (!NT_SUCCESS(status)) {
        File_HistoryLogWarning(
            L"Directory association remap", status, OldTruePath);
    }
}


//---------------------------------------------------------------------------
// File_HistoryRename
//---------------------------------------------------------------------------


static _FX VOID File_HistoryRename(
    const WCHAR *OldTruePath, const WCHAR *OldCopyPath,
    const WCHAR *NewTruePath, const WCHAR *NewCopyPath,
    BOOLEAN IsDirectory)
{
    if (!File_HistoryRoot)
        return;

    if (IsDirectory) {
        File_HistoryRenameDirectory(
            OldTruePath, OldCopyPath, NewTruePath, NewCopyPath);
    }
    else {
        File_HistoryRenameFile(
            OldTruePath, NewTruePath, NewCopyPath, NULL);
    }
}


//---------------------------------------------------------------------------
// File_HistoryProcessIsLive
//---------------------------------------------------------------------------


static _FX BOOLEAN File_HistoryQueryProcessCreationTime(
    HANDLE Process, ULONGLONG *CreationTime)
{
    FILETIME creation_time;
    FILETIME exit_time;
    FILETIME kernel_time;
    FILETIME user_time;

    if (!GetProcessTimes(
            Process, &creation_time, &exit_time,
            &kernel_time, &user_time))
        return FALSE;

    *CreationTime =
        ((ULONGLONG)creation_time.dwHighDateTime << 32) |
        creation_time.dwLowDateTime;
    return TRUE;
}


static _FX BOOLEAN File_HistoryProcessIsLive(
    ULONG ProcessId, ULONGLONG CreationTime)
{
    HANDLE process;
    DWORD wait_result;
    ULONGLONG current_creation_time;

    if (!ProcessId)
        return FALSE;
    if (ProcessId == Dll_ProcessId) {
        if (!CreationTime ||
                !File_HistoryQueryProcessCreationTime(
                    GetCurrentProcess(), &current_creation_time))
            return TRUE;
        return current_creation_time == CreationTime;
    }

    process = OpenProcess(
        SYNCHRONIZE | (CreationTime
            ? PROCESS_QUERY_LIMITED_INFORMATION : 0),
        FALSE, ProcessId);
    if (!process && CreationTime)
        process = OpenProcess(SYNCHRONIZE, FALSE, ProcessId);
    if (!process)
        return GetLastError() != ERROR_INVALID_PARAMETER;

    wait_result = WaitForSingleObject(process, 0);
    if (wait_result == WAIT_TIMEOUT && CreationTime &&
            File_HistoryQueryProcessCreationTime(
                process, &current_creation_time) &&
            current_creation_time != CreationTime) {
        wait_result = WAIT_OBJECT_0;
    }
    CloseHandle(process);
    return wait_result == WAIT_TIMEOUT;
}


//---------------------------------------------------------------------------
// File_HistoryQueryIdentity
//---------------------------------------------------------------------------


static _FX NTSTATUS File_HistoryQueryHandleIdentity(
    HANDLE Handle, FILE_INTERNAL_INFORMATION *Internal,
    FILE_NETWORK_OPEN_INFORMATION *Network,
    FILE_STANDARD_INFORMATION *Standard)
{
    IO_STATUS_BLOCK iosb;
    FILE_ATTRIBUTE_TAG_INFORMATION taginfo;
    NTSTATUS status;

    status = __sys_NtQueryInformationFile(
        Handle, &iosb, &taginfo, sizeof(taginfo),
        FileAttributeTagInformation);
    if (NT_SUCCESS(status) &&
            (taginfo.FileAttributes &
             (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
        status = STATUS_OBJECT_TYPE_MISMATCH;
    }
    if (NT_SUCCESS(status)) {
        status = __sys_NtQueryInformationFile(
            Handle, &iosb, Internal, sizeof(*Internal),
            FileInternalInformation);
    }
    if (NT_SUCCESS(status)) {
        status = __sys_NtQueryInformationFile(
            Handle, &iosb, Network, sizeof(*Network),
            FileNetworkOpenInformation);
    }
    if (NT_SUCCESS(status) && Standard) {
        status = __sys_NtQueryInformationFile(
            Handle, &iosb, Standard, sizeof(*Standard),
            FileStandardInformation);
    }

    return status;
}


static _FX NTSTATUS File_HistoryQueryIdentity(
    const WCHAR *Path, FILE_INTERNAL_INFORMATION *Internal,
    FILE_NETWORK_OPEN_INFORMATION *Network,
    FILE_STANDARD_INFORMATION *Standard)
{
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    NTSTATUS status;

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlInitUnicodeString(&objname, Path);
    status = __sys_NtCreateFile(
        &handle, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objattrs, &iosb, NULL, 0, FILE_SHARE_VALID_FLAGS, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_OPEN_REPARSE_POINT, NULL, 0);
    if (!NT_SUCCESS(status))
        return status;

    status = File_HistoryQueryHandleIdentity(
        handle, Internal, Network, Standard);
    NtClose(handle);
    return status;
}


//---------------------------------------------------------------------------
// File_HistoryRecoverArtifact
//---------------------------------------------------------------------------


static _FX VOID File_HistoryRecoverArtifact(const WCHAR *Artifact)
{
    FILE_INTERNAL_INFORMATION pending_internal;
    FILE_INTERNAL_INFORMATION fresh_pending_internal;
    FILE_INTERNAL_INFORMATION copy_internal;
    FILE_NETWORK_OPEN_INFORMATION pending_info;
    FILE_NETWORK_OPEN_INFORMATION fresh_pending_info;
    FILE_NETWORK_OPEN_INFORMATION copy_info;
    FILE_STANDARD_INFORMATION pending_standard;
    FILE_STANDARD_INFORMATION fresh_pending_standard;
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    IO_STATUS_BLOCK iosb;
    WCHAR *artifact_path;
    WCHAR *pending_path;
    WCHAR *pending_meta_path;
    WCHAR *version_path;
    WCHAR *version_meta_path;
    WCHAR *pending_text = NULL;
    WCHAR *updated_text = NULL;
    WCHAR *true_path = NULL;
    WCHAR *fresh_true_path = NULL;
    WCHAR *copy_path = NULL;
    WCHAR *pid_text = NULL;
    WCHAR *process_start_text = NULL;
    HANDLE mutex = NULL;
    HANDLE limit_mutex = NULL;
    HANDLE pending_handle = NULL;
    NTSTATUS status;
    ULONG length;
    ULONG process_id;
    ULONGLONG process_start = 0;
    UCHAR hash[FILE_HISTORY_SHA256_SIZE];
    BOOLEAN duplicate_version = FALSE;
    BOOLEAN duplicate_metadata = FALSE;
    BOOLEAN use_collision_name = FALSE;
    BOOLEAN hash_valid;
    BOOLEAN abandoned;

    length = wcslen(File_HistoryArtifacts) + wcslen(Artifact) + 2;
    artifact_path = Dll_AllocTemp(length * sizeof(WCHAR));
    if (!artifact_path)
        return;
    Sbie_snwprintf(artifact_path, length, L"%s\\%s",
        File_HistoryArtifacts, Artifact);

    length = wcslen(artifact_path) + 144;
    pending_path = Dll_AllocTemp(length * sizeof(WCHAR));
    pending_meta_path = Dll_AllocTemp(length * sizeof(WCHAR));
    version_path = Dll_AllocTemp(length * sizeof(WCHAR));
    version_meta_path = Dll_AllocTemp(length * sizeof(WCHAR));
    if (!pending_path || !pending_meta_path ||
            !version_path || !version_meta_path)
        goto finish;

    Sbie_snwprintf(pending_path, length,
        L"%s\\pending.bin", artifact_path);
    Sbie_snwprintf(pending_meta_path, length,
        L"%s\\pending.txt", artifact_path);

    status = File_HistoryReadText(pending_meta_path, &pending_text);
    if (!NT_SUCCESS(status))
        goto finish;

    true_path =
        File_HistoryGetMetadataField(pending_text, L"path", TRUE);
    if (!true_path)
        goto finish;

    mutex = File_HistoryCreateMutex(true_path);
    if (!mutex)
        goto finish;

    Dll_Free(pending_text);
    pending_text = NULL;
    status = File_HistoryReadText(pending_meta_path, &pending_text);
    if (!NT_SUCCESS(status))
        goto finish;

    fresh_true_path =
        File_HistoryGetMetadataField(pending_text, L"path", TRUE);
    if (!fresh_true_path ||
            _wcsicmp(fresh_true_path, true_path) != 0)
        goto finish;

    copy_path =
        File_HistoryGetCopyPathField(pending_text, L"copy_path");
    pid_text =
        File_HistoryGetMetadataField(pending_text, L"pid", FALSE);
    if (!copy_path || !pid_text)
        goto finish;

    process_id = wcstoul(pid_text, NULL, 10);
    process_start_text =
        File_HistoryGetMetadataField(
            pending_text, L"process_start", FALSE);
    if (process_start_text)
        process_start = _wcstoui64(process_start_text, NULL, 16);
    if (File_HistoryProcessIsLive(process_id, process_start))
        goto finish;

    status = File_HistoryQueryIdentity(
        pending_path, &pending_internal, &pending_info, &pending_standard);
    if (!NT_SUCCESS(status))
        goto finish;

    if (File_HistoryMaxFileSize &&
            pending_info.EndOfFile.QuadPart > 0 &&
            (ULONGLONG)pending_info.EndOfFile.QuadPart >
                File_HistoryMaxFileSize) {
        limit_mutex = File_HistoryCreateLimitMutex(&abandoned);
        if (!limit_mutex) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto log_failure;
        }
        if (abandoned)
            File_HistoryInvalidateUsage();
        status = File_HistoryDeleteFile(pending_path);
        if (NT_SUCCESS(status)) {
            File_HistoryInvalidateUsage();
            File_HistoryDeleteFile(pending_meta_path);
        }
        else {
            File_HistoryLogWarning(
                L"Oversized pending evidence cleanup",
                status, true_path);
        }
        File_HistoryReleaseMutex(limit_mutex);
        limit_mutex = NULL;
        goto finish;
    }

    status = File_HistoryQueryIdentity(
        copy_path, &copy_internal, &copy_info, NULL);
    if (NT_SUCCESS(status)) {
        if (copy_internal.IndexNumber.QuadPart ==
                pending_internal.IndexNumber.QuadPart) {
            updated_text =
                File_HistorySetMetadataField(
                    pending_text, L"state", L"still-live");
            if (updated_text)
                File_HistoryWriteTextAtomic(
                    pending_meta_path, updated_text, TRUE);
            goto finish;
        }
    }
    else if (status != STATUS_OBJECT_NAME_NOT_FOUND &&
             status != STATUS_OBJECT_PATH_NOT_FOUND &&
             status != STATUS_NO_SUCH_FILE) {
        goto finish;
    }

    if (pending_standard.NumberOfLinks > 1) {
        updated_text =
            File_HistorySetMetadataField(
                pending_text, L"state", L"still-linked");
        if (updated_text)
            File_HistoryWriteTextAtomic(
                pending_meta_path, updated_text, TRUE);
        goto finish;
    }

    Sbie_snwprintf(version_path, length,
        L"%s\\%016I64X-%016I64X-%016I64X.bin",
        artifact_path, pending_info.LastWriteTime.QuadPart,
        pending_info.ChangeTime.QuadPart,
        pending_info.EndOfFile.QuadPart);
    Sbie_snwprintf(version_meta_path, length,
        L"%s\\%016I64X-%016I64X-%016I64X.txt",
        artifact_path, pending_info.LastWriteTime.QuadPart,
        pending_info.ChangeTime.QuadPart,
        pending_info.EndOfFile.QuadPart);

    status = File_HistoryQueryIdentity(
        version_path, &copy_internal, &copy_info, NULL);
    if (NT_SUCCESS(status)) {
        if (File_HistoryFilesEqual(pending_path, version_path)) {
            duplicate_version = TRUE;
            status = File_HistoryQueryIdentity(
                version_meta_path, &copy_internal, &copy_info, NULL);
            if (NT_SUCCESS(status))
                duplicate_metadata = TRUE;
            else if (status != STATUS_OBJECT_NAME_NOT_FOUND &&
                    status != STATUS_OBJECT_PATH_NOT_FOUND &&
                    status != STATUS_NO_SUCH_FILE) {
                goto log_failure;
            }
        }
        else {
            use_collision_name = TRUE;
        }
    }
    else {
        if (status != STATUS_OBJECT_NAME_NOT_FOUND &&
                status != STATUS_OBJECT_PATH_NOT_FOUND &&
                status != STATUS_NO_SUCH_FILE) {
            goto log_failure;
        }

        status = File_HistoryQueryIdentity(
            version_meta_path, &copy_internal, &copy_info, NULL);
        if (NT_SUCCESS(status))
            use_collision_name = TRUE;
        else if (status != STATUS_OBJECT_NAME_NOT_FOUND &&
                status != STATUS_OBJECT_PATH_NOT_FOUND &&
                status != STATUS_NO_SUCH_FILE) {
            goto log_failure;
        }
    }

    if (use_collision_name) {
        status = File_HistorySelectCollisionPair(
            artifact_path, &pending_info,
            version_path, version_meta_path, length);
        if (!NT_SUCCESS(status))
            goto log_failure;
    }

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlInitUnicodeString(&objname, pending_path);
    status = __sys_NtCreateFile(
        &pending_handle,
        DELETE | FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objattrs, &iosb, NULL, 0, 0, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_OPEN_REPARSE_POINT, NULL, 0);
    if (status == STATUS_SHARING_VIOLATION) {
        updated_text =
            File_HistorySetMetadataField(
                pending_text, L"state", L"still-open");
        if (updated_text)
            File_HistoryWriteTextAtomic(
                pending_meta_path, updated_text, TRUE);
        goto finish;
    }
    if (!NT_SUCCESS(status))
        goto log_failure;

    status = File_HistoryQueryHandleIdentity(
        pending_handle, &fresh_pending_internal,
        &fresh_pending_info, &fresh_pending_standard);
    if (!NT_SUCCESS(status))
        goto log_failure;
    if (fresh_pending_internal.IndexNumber.QuadPart !=
            pending_internal.IndexNumber.QuadPart ||
            !File_HistorySameGenerationInfo(
                &pending_info, &fresh_pending_info) ||
            fresh_pending_standard.NumberOfLinks != 1) {
        goto finish;
    }

    if (!duplicate_metadata) {
        hash_valid = File_HistoryHashHandle(
            pending_handle, &fresh_pending_info, hash);
        updated_text = File_HistoryFinalizeMetadata(
            pending_text, &fresh_pending_info, hash, hash_valid);
        if (!updated_text) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto log_failure;
        }

        status = File_HistoryWriteTextAtomic(
            version_meta_path, updated_text, FALSE);
        if (!NT_SUCCESS(status))
            goto log_failure;
    }

    if (duplicate_version) {
        limit_mutex = File_HistoryCreateLimitMutex(&abandoned);
        if (!limit_mutex)
            goto log_failure;
        if (abandoned)
            File_HistoryInvalidateUsage();
        status = File_HistoryDeleteHandle(pending_handle);
        NtClose(pending_handle);
        pending_handle = NULL;
        if (NT_SUCCESS(status))
            File_HistoryInvalidateUsage();
        File_HistoryReleaseMutex(limit_mutex);
        limit_mutex = NULL;
    }
    else {
        limit_mutex = File_HistoryCreateLimitMutex(&abandoned);
        if (!limit_mutex)
            goto log_failure;
        if (abandoned)
            File_HistoryInvalidateUsage();
        status = File_HistoryRenameHandle(
            pending_handle, version_path, FALSE);
        NtClose(pending_handle);
        pending_handle = NULL;
        if (NT_SUCCESS(status)) {
            File_HistoryInvalidateUsage();
            File_HistoryReleaseMutex(limit_mutex);
            limit_mutex = NULL;
        }
        else {
            File_HistoryReleaseMutex(limit_mutex);
            limit_mutex = NULL;
        }
        if (status == STATUS_OBJECT_NAME_COLLISION) {
            if (File_HistoryFilesEqual(
                    pending_path, version_path)) {
                limit_mutex = File_HistoryCreateLimitMutex(&abandoned);
                if (!limit_mutex)
                    goto log_failure;
                if (abandoned)
                    File_HistoryInvalidateUsage();
                status = File_HistoryDeleteFile(pending_path);
                if (NT_SUCCESS(status))
                    File_HistoryInvalidateUsage();
                File_HistoryReleaseMutex(limit_mutex);
                limit_mutex = NULL;
            }
            else
                File_HistoryDeleteFile(version_meta_path);
        }
        else if (!NT_SUCCESS(status) &&
                status != STATUS_OBJECT_NAME_COLLISION) {
            File_HistoryDeleteFile(version_meta_path);
        }
    }
    if (NT_SUCCESS(status))
        File_HistoryDeleteFile(pending_meta_path);
    else {
log_failure:
        File_HistoryLogWarning(
            L"Pending evidence recovery", status, true_path);
    }

finish:
    if (pending_handle)
        NtClose(pending_handle);
    if (limit_mutex)
        File_HistoryReleaseMutex(limit_mutex);
    if (mutex)
        File_HistoryReleaseMutex(mutex);
    if (pid_text)
        Dll_Free(pid_text);
    if (process_start_text)
        Dll_Free(process_start_text);
    if (copy_path)
        Dll_Free(copy_path);
    if (fresh_true_path)
        Dll_Free(fresh_true_path);
    if (true_path)
        Dll_Free(true_path);
    if (updated_text)
        Dll_Free(updated_text);
    if (pending_text)
        Dll_Free(pending_text);
    if (version_meta_path)
        Dll_Free(version_meta_path);
    if (version_path)
        Dll_Free(version_path);
    if (pending_meta_path)
        Dll_Free(pending_meta_path);
    if (pending_path)
        Dll_Free(pending_path);
    Dll_Free(artifact_path);
}


//---------------------------------------------------------------------------
// File_HistoryRecoverPending
//---------------------------------------------------------------------------


static _FX VOID File_HistoryRecoverPending(void)
{
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    IO_STATUS_BLOCK iosb;
    FILE_ATTRIBUTE_TAG_INFORMATION taginfo;
    FILE_DIRECTORY_INFORMATION *info;
    HANDLE handle;
    NTSTATUS status;
    BOOLEAN restart = TRUE;
    ULONG info_len;

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlInitUnicodeString(&objname, File_HistoryArtifacts);
    status = __sys_NtCreateFile(
        &handle, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objattrs, &iosb, NULL, 0, FILE_SHARE_VALID_FLAGS, FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_OPEN_REPARSE_POINT, NULL, 0);
    if (!NT_SUCCESS(status))
        return;

    status = __sys_NtQueryInformationFile(
        handle, &iosb, &taginfo, sizeof(taginfo),
        FileAttributeTagInformation);
    if (!NT_SUCCESS(status) ||
            (taginfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        NtClose(handle);
        return;
    }

    info_len = 4096;
    info = Dll_AllocTemp(info_len);
    if (!info) {
        NtClose(handle);
        return;
    }

    while (1) {
        WCHAR artifact[80];
        ULONG name_len;

        status = __sys_NtQueryDirectoryFile(
            handle, NULL, NULL, NULL, &iosb,
            info, info_len, FileDirectoryInformation,
            TRUE, NULL, restart);
        restart = FALSE;
        if (!NT_SUCCESS(status))
            break;

        name_len = info->FileNameLength / sizeof(WCHAR);
        if (name_len >= RTL_NUMBER_OF_V1(artifact))
            continue;
        wmemcpy(artifact, info->FileName, name_len);
        artifact[name_len] = L'\0';

        if (File_HistoryValidArtifact(artifact))
            File_HistoryRecoverArtifact(artifact);
    }

    Dll_Free(info);
    NtClose(handle);
}


//---------------------------------------------------------------------------
// File_InitHistory
//---------------------------------------------------------------------------


static _FX BOOLEAN File_InitHistory(void)
{
    WCHAR conf_buf[2048];
    ULONGLONG value;
    ULONGLONG max_size_kb;
    ULONGLONG max_file_size_kb;
    ULONG length;
    NTSTATUS status;

    List_Init(&File_HistoryOptions);
    List_Init(&File_HistoryExclusions);
    Config_InitPatternList(
        NULL, L"KeepFileVersions", &File_HistoryOptions, FALSE);
    Config_InitPatternList(
        NULL, L"KeepFileVersionsExclude",
        &File_HistoryExclusions, FALSE);
    status = SbieApi_QueryConf(
        NULL, L"KeepFileVersions", 0,
        conf_buf, sizeof(conf_buf) - 16 * sizeof(WCHAR));
    if (!NT_SUCCESS(status))
        return TRUE;

    File_HistoryCaptureMigrated =
        SbieApi_QueryConfBool(
            NULL, L"FileHistoryCaptureMigrated", FALSE) ? TRUE : FALSE;
    File_HistoryLogWarnings =
        SbieApi_QueryConfBool(
            NULL, L"FileHistoryLogWarnings", TRUE) ? TRUE : FALSE;

    value = File_HistoryQueryLimit(
        L"FileHistoryMaxVersionsTotal",
        FILE_HISTORY_DEFAULT_MAX_VERSIONS_TOTAL);
    if (value > FILE_HISTORY_ULONG_MAX)
        value = FILE_HISTORY_ULONG_MAX;
    File_HistoryMaxVersionsTotal = (ULONG)value;

    value = File_HistoryQueryLimit(
        L"FileHistoryMaxVersionsPerFile",
        FILE_HISTORY_DEFAULT_MAX_VERSIONS_PER_FILE);
    if (value > FILE_HISTORY_ULONG_MAX)
        value = FILE_HISTORY_ULONG_MAX;
    File_HistoryMaxVersionsPerFile = (ULONG)value;

    max_size_kb = File_HistoryQueryLimit(
        L"FileHistoryMaxSizeTotalKB",
        FILE_HISTORY_DEFAULT_MAX_SIZE_TOTAL_KB);
    File_HistoryMaxSizeTotal =
        max_size_kb > FILE_HISTORY_ULONGLONG_MAX / 1024
        ? FILE_HISTORY_ULONGLONG_MAX : max_size_kb * 1024;
    max_file_size_kb = File_HistoryQueryLimit(
        L"FileHistoryMaxFileSizeKB",
        FILE_HISTORY_DEFAULT_MAX_FILE_SIZE_KB);
    File_HistoryMaxFileSize =
        max_file_size_kb > FILE_HISTORY_ULONGLONG_MAX / 1024
        ? FILE_HISTORY_ULONGLONG_MAX : max_file_size_kb * 1024;
    length = wcslen(Dll_BoxFilePath) + 32;
    File_HistoryRoot = Dll_Alloc(length * sizeof(WCHAR));
    if (!File_HistoryRoot)
        return TRUE;
    Sbie_snwprintf(File_HistoryRoot, length, L"%s\\%s",
        Dll_BoxFilePath, FILE_HISTORY_DIR);

    length = wcslen(File_HistoryRoot) + 16;
    File_HistoryIndex = Dll_Alloc(length * sizeof(WCHAR));
    File_HistoryArtifacts = Dll_Alloc(length * sizeof(WCHAR));
    File_HistoryBlobs = Dll_Alloc(length * sizeof(WCHAR));
    if (!File_HistoryIndex || !File_HistoryArtifacts ||
            !File_HistoryBlobs) {
        if (File_HistoryBlobs)
            Dll_Free(File_HistoryBlobs);
        if (File_HistoryArtifacts)
            Dll_Free(File_HistoryArtifacts);
        if (File_HistoryIndex)
            Dll_Free(File_HistoryIndex);
        Dll_Free(File_HistoryRoot);
        File_HistoryRoot = NULL;
        File_HistoryIndex = NULL;
        File_HistoryArtifacts = NULL;
        File_HistoryBlobs = NULL;
        return TRUE;
    }

    Sbie_snwprintf(File_HistoryIndex, length, L"%s\\%s",
        File_HistoryRoot, FILE_HISTORY_INDEX_DIR);
    Sbie_snwprintf(File_HistoryArtifacts, length, L"%s\\%s",
        File_HistoryRoot, FILE_HISTORY_ARTIFACT_DIR);
    Sbie_snwprintf(File_HistoryBlobs, length, L"%s\\%s",
        File_HistoryRoot, FILE_HISTORY_BLOB_DIR);

    status = File_HistoryCreateDirectory(File_HistoryRoot);
    if (NT_SUCCESS(status))
        status = File_HistoryCreateDirectory(File_HistoryIndex);
    if (NT_SUCCESS(status))
        status = File_HistoryCreateDirectory(File_HistoryArtifacts);
    if (NT_SUCCESS(status))
        status = File_HistoryCreateDirectory(File_HistoryBlobs);

    if (!NT_SUCCESS(status)) {
        File_HistoryLogWarning(L"Archive initialization", status, NULL);
        Dll_Free(File_HistoryBlobs);
        Dll_Free(File_HistoryArtifacts);
        Dll_Free(File_HistoryIndex);
        Dll_Free(File_HistoryRoot);
        File_HistoryRoot = NULL;
        File_HistoryIndex = NULL;
        File_HistoryArtifacts = NULL;
        File_HistoryBlobs = NULL;
        return TRUE;
    }

    File_HistoryInitNotices();
    File_HistoryRecoverPending();

    return TRUE;
}
