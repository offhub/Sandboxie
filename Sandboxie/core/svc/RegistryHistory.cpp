/*
 * Copyright 2026 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "stdafx.h"

#include "RegistryHistory.h"
#include "common/defines.h"
#include "common/win32_ntddk.h"
#include "core/dll/sbiedll.h"

#include <algorithm>
#include <map>
#include <stdio.h>
#include <vector>

namespace
{
    const WCHAR* RegistryHistoryDirectory = L"RegistryHistory";
    const WCHAR* RegistryHistoryHive = L"RegHive.hiv";

    struct CASE_INSENSITIVE_LESS
    {
        bool operator()(const std::wstring& left,
            const std::wstring& right) const
        {
            return _wcsicmp(left.c_str(), right.c_str()) < 0;
        }
    };

    CRITICAL_SECTION RegistryPathLock;
    std::map<std::wstring, std::wstring, CASE_INSENSITIVE_LESS>
        RegistryPaths;

    class BACKUP_PRIVILEGE
    {
    public:
        BACKUP_PRIVILEGE()
            : m_Token(NULL), m_Enabled(false)
        {
            ZeroMemory(&m_Previous, sizeof(m_Previous));
        }

        ~BACKUP_PRIVILEGE()
        {
            if (m_Token) {
                if (m_Enabled && m_Previous.PrivilegeCount != 0)
                    AdjustTokenPrivileges(m_Token, FALSE, &m_Previous,
                        0, NULL, NULL);
                CloseHandle(m_Token);
            }
        }

        bool Enable()
        {
            TOKEN_PRIVILEGES privileges = {};
            if (!LookupPrivilegeValueW(NULL, SE_BACKUP_NAME,
                    &privileges.Privileges[0].Luid))
                return false;

            privileges.PrivilegeCount = 1;
            privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (!OpenProcessToken(GetCurrentProcess(),
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &m_Token))
                return false;

            DWORD previousLength = sizeof(m_Previous);
            SetLastError(ERROR_SUCCESS);
            BOOL adjusted = AdjustTokenPrivileges(m_Token, FALSE,
                &privileges, sizeof(m_Previous), &m_Previous,
                &previousLength);
            m_Enabled = adjusted && GetLastError() == ERROR_SUCCESS;
            return m_Enabled;
        }

    private:
        HANDLE m_Token;
        TOKEN_PRIVILEGES m_Previous;
        bool m_Enabled;
    };

    bool GetRememberedPath(const WCHAR* rootPath, std::wstring& fileRoot)
    {
        for (ULONG attempt = 0; attempt < 20; ++attempt) {
            EnterCriticalSection(&RegistryPathLock);
            auto found = RegistryPaths.find(rootPath);
            if (found != RegistryPaths.end())
                fileRoot = found->second;
            LeaveCriticalSection(&RegistryPathLock);

            if (!fileRoot.empty())
                return true;
            Sleep(50);
        }
        return false;
    }

    std::wstring JoinPath(const std::wstring& left, const WCHAR* right)
    {
        std::wstring path = left;
        if (!path.empty() && path.back() != L'\\')
            path += L'\\';
        path += right;
        return path;
    }

    bool IsSafeDirectory(const std::wstring& path)
    {
        DWORD attributes = GetFileAttributesW(path.c_str());
        return attributes != INVALID_FILE_ATTRIBUTES &&
            (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
    }

    bool CreateDirectoryIfNeeded(const std::wstring& path)
    {
        if (!CreateDirectoryW(path.c_str(), NULL) &&
                GetLastError() != ERROR_ALREADY_EXISTS)
            return false;
        return IsSafeDirectory(path);
    }

    bool DeleteGenerationDirectory(const std::wstring& path)
    {
        DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES ||
                (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            return false;

        static const WCHAR* files[] = {
            L"RegHive.hiv.LOG1", L"RegHive.hiv.LOG2", L"RegHive.hiv",
            L"RegPaths.dat", L"RegPaths_v3.dat", L"RegPaths_v3.sbie",
            L"Generation.ini"
        };
        for (const WCHAR* file : files) {
            std::wstring filePath = JoinPath(path, file);
            if (!DeleteFileW(filePath.c_str()) &&
                    GetLastError() != ERROR_FILE_NOT_FOUND)
                return false;
        }
        return RemoveDirectoryW(path.c_str()) != FALSE;
    }

    std::wstring MakeGenerationName()
    {
        SYSTEMTIME time = {};
        GetSystemTime(&time);

        WCHAR name[64];
        _snwprintf(name, ARRAYSIZE(name) - 1,
            L"%04u%02u%02u-%02u%02u%02u-%03u",
            time.wYear, time.wMonth, time.wDay,
            time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);
        name[ARRAYSIZE(name) - 1] = L'\0';
        return name;
    }

    bool CreateGenerationDirectory(const std::wstring& historyRoot,
        REGISTRY_HISTORY_CAPTURE& capture)
    {
        for (ULONG attempt = 0; attempt < 100; ++attempt) {
            std::wstring generationName = MakeGenerationName();
            capture.FinalPath = JoinPath(historyRoot, generationName.c_str());
            capture.PendingPath = JoinPath(historyRoot,
                (std::wstring(L".pending-") + generationName).c_str());

            if (GetFileAttributesW(capture.FinalPath.c_str()) ==
                    INVALID_FILE_ATTRIBUTES &&
                    CreateDirectoryW(capture.PendingPath.c_str(), NULL)) {
                DWORD attributes = GetFileAttributesW(
                    capture.PendingPath.c_str());
                if (attributes != INVALID_FILE_ATTRIBUTES &&
                        (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
                        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0)
                    return true;
                RemoveDirectoryW(capture.PendingPath.c_str());
            }

            capture.PendingPath.clear();
            capture.FinalPath.clear();
            Sleep(1);
        }
        return false;
    }

    bool WriteGenerationMetadata(const std::wstring& path,
        const WCHAR* boxName, ULONG deleteMode)
    {
        if (!IsSafeDirectory(path))
            return false;

        SYSTEMTIME time = {};
        GetSystemTime(&time);

        WCHAR text[512];
        _snwprintf(text, ARRAYSIZE(text) - 1,
            L"[Generation]\r\nVersion=1\r\n"
            L"CapturedUtc=%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\r\n"
            L"BoxName=%s\r\nDeleteMode=%u\r\n",
            time.wYear, time.wMonth, time.wDay,
            time.wHour, time.wMinute, time.wSecond, time.wMilliseconds,
            boxName, deleteMode);
        text[ARRAYSIZE(text) - 1] = L'\0';

        std::wstring metadata = JoinPath(path, L"Generation.ini");
        HANDLE file = CreateFileW(metadata.c_str(), GENERIC_WRITE, 0, NULL,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE)
            return false;

        WORD bom = 0xFEFF;
        DWORD written = 0;
        bool ok = WriteFile(file, &bom, sizeof(bom), &written, NULL) &&
            written == sizeof(bom);
        DWORD bytes = (DWORD)(wcslen(text) * sizeof(WCHAR));
        ok = ok && WriteFile(file, text, bytes, &written, NULL) &&
            written == bytes && FlushFileBuffers(file);
        CloseHandle(file);
        return ok;
    }

    bool CopyDeleteMetadata(const std::wstring& fileRoot,
        const std::wstring& pendingPath, ULONG deleteMode)
    {
        if (!IsSafeDirectory(pendingPath))
            return false;

        const WCHAR* files[2] = {};
        ULONG fileCount = 0;
        if (deleteMode == 2)
            files[fileCount++] = L"RegPaths.dat";
        else if (deleteMode == 3) {
            files[fileCount++] = L"RegPaths_v3.dat";
            files[fileCount++] = L"RegPaths_v3.sbie";
        }
        for (ULONG index = 0; index < fileCount; ++index) {
            const WCHAR* file = files[index];
            std::wstring source = JoinPath(fileRoot, file);
            DWORD attributes = GetFileAttributesW(source.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES) {
                DWORD error = GetLastError();
                if (error == ERROR_FILE_NOT_FOUND ||
                        error == ERROR_PATH_NOT_FOUND)
                    continue;
                return false;
            }
            if ((attributes & (FILE_ATTRIBUTE_DIRECTORY |
                    FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
                    !CopyFileW(source.c_str(),
                        JoinPath(pendingPath, file).c_str(), TRUE))
                return false;
        }
        return true;
    }

    bool IsGenerationName(const WCHAR* name)
    {
        if (!name || wcslen(name) != 19 || name[8] != L'-' ||
                name[15] != L'-')
            return false;
        for (ULONG index = 0; index < 19; ++index) {
            if (index == 8 || index == 15)
                continue;
            if (name[index] < L'0' || name[index] > L'9')
                return false;
        }

        SYSTEMTIME time = {};
        time.wYear = (name[0] - L'0') * 1000 + (name[1] - L'0') * 100 +
            (name[2] - L'0') * 10 + name[3] - L'0';
        time.wMonth = (name[4] - L'0') * 10 + name[5] - L'0';
        time.wDay = (name[6] - L'0') * 10 + name[7] - L'0';
        time.wHour = (name[9] - L'0') * 10 + name[10] - L'0';
        time.wMinute = (name[11] - L'0') * 10 + name[12] - L'0';
        time.wSecond = (name[13] - L'0') * 10 + name[14] - L'0';
        time.wMilliseconds = (name[16] - L'0') * 100 +
            (name[17] - L'0') * 10 + name[18] - L'0';
        FILETIME fileTime = {};
        return SystemTimeToFileTime(&time, &fileTime) != FALSE;
    }

    bool IsRegularFile(const std::wstring& path)
    {
        DWORD attributes = GetFileAttributesW(path.c_str());
        return attributes != INVALID_FILE_ATTRIBUTES &&
            (attributes & (FILE_ATTRIBUTE_DIRECTORY |
                FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
    }

    void EnforceGenerationLimit(const WCHAR* boxName,
        const std::wstring& historyRoot)
    {
        if (!IsSafeDirectory(historyRoot))
            return;

        ULONG maxGenerations = SbieApi_QueryConfNumber(boxName,
            L"RegistryHistoryMaxGenerations", 20);
        ULONG64 maxSizeBytes = (ULONG64)SbieApi_QueryConfNumber(boxName,
            L"RegistryHistoryMaxSizeKB", 1024 * 1024) * 1024;

        struct GENERATION_INFO {
            std::wstring Name;
            ULONG64 Size;
        };
        std::vector<GENERATION_INFO> generations;
        ULONG64 totalSize = 0;
        WIN32_FIND_DATAW data = {};
        HANDLE find = FindFirstFileW(JoinPath(historyRoot, L"*").c_str(),
            &data);
        if (find != INVALID_HANDLE_VALUE) {
            do {
                if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                        (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                        !IsGenerationName(data.cFileName))
                    continue;
                std::wstring generationPath = JoinPath(historyRoot,
                    data.cFileName);
                if (!IsRegularFile(JoinPath(generationPath,
                        RegistryHistoryHive)) ||
                        !IsRegularFile(JoinPath(generationPath,
                            L"Generation.ini")))
                    continue;
                GENERATION_INFO generation = { data.cFileName, 0 };
                WIN32_FIND_DATAW fileData = {};
                HANDLE fileFind = FindFirstFileW(JoinPath(generationPath,
                    L"*").c_str(),
                    &fileData);
                if (fileFind != INVALID_HANDLE_VALUE) {
                    do {
                        if ((fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                            generation.Size +=
                                (ULONG64(fileData.nFileSizeHigh) << 32) |
                                fileData.nFileSizeLow;
                    } while (FindNextFileW(fileFind, &fileData));
                    FindClose(fileFind);
                }
                totalSize += generation.Size;
                generations.push_back(generation);
            } while (FindNextFileW(find, &data));
            FindClose(find);
        }

        std::sort(generations.begin(), generations.end(),
            [](const GENERATION_INFO& left, const GENERATION_INFO& right) {
                return left.Name < right.Name;
            });
        while (generations.size() > 1 &&
                ((maxGenerations != 0 && generations.size() > maxGenerations) ||
                 (maxSizeBytes != 0 && totalSize > maxSizeBytes))) {
            if (!DeleteGenerationDirectory(
                    JoinPath(historyRoot, generations.front().Name.c_str())))
                break;
            totalSize -= generations.front().Size;
            generations.erase(generations.begin());
        }
    }
}

void RegistryHistory_Initialize()
{
    InitializeCriticalSection(&RegistryPathLock);
}

void RegistryHistory_Shutdown()
{
    EnterCriticalSection(&RegistryPathLock);
    RegistryPaths.clear();
    LeaveCriticalSection(&RegistryPathLock);
    DeleteCriticalSection(&RegistryPathLock);
}

void RegistryHistory_RememberPath(const WCHAR* fileRoot,
    const WCHAR* rootPath)
{
    if (!fileRoot || !*fileRoot || !rootPath || !*rootPath)
        return;

    std::vector<WCHAR> fileBuffer(wcslen(fileRoot) + 16);
    wcscpy(fileBuffer.data(), fileRoot);
    if (!SbieDll_TranslateNtToDosPath(fileBuffer.data()))
        return;

    std::wstring path(fileBuffer.data());
    while (!path.empty() &&
            (path.back() == L'\\' || path.back() == L'/'))
        path.pop_back();
    if (path.empty())
        return;

    EnterCriticalSection(&RegistryPathLock);
    RegistryPaths[rootPath] = path;
    LeaveCriticalSection(&RegistryPathLock);
}

void RegistryHistory_ForgetPath(const WCHAR* rootPath)
{
    if (!rootPath || !*rootPath)
        return;

    EnterCriticalSection(&RegistryPathLock);
    RegistryPaths.erase(rootPath);
    LeaveCriticalSection(&RegistryPathLock);
}

bool RegistryHistory_Prepare(const WCHAR* boxName, const WCHAR* rootPath,
    REGISTRY_HISTORY_CAPTURE& capture)
{
    capture = REGISTRY_HISTORY_CAPTURE();
    if (!SbieApi_QueryConfBool(boxName, L"RegistryHistory", FALSE))
        return false;

    std::wstring fileRoot;
    if (!GetRememberedPath(rootPath, fileRoot))
        return false;

    std::wstring historyRoot = JoinPath(fileRoot, RegistryHistoryDirectory);
    if (!CreateDirectoryIfNeeded(historyRoot))
        return false;

    if (!CreateGenerationDirectory(historyRoot, capture))
        return false;
    if (!IsSafeDirectory(historyRoot) ||
            !IsSafeDirectory(capture.PendingPath)) {
        RegistryHistory_Discard(capture);
        return false;
    }

    ULONG deleteMode = SbieApi_QueryConfBool(boxName,
        L"UseRegDeleteV3", FALSE) ? 3 :
        SbieApi_QueryConfBool(boxName, L"UseRegDeleteV2", FALSE) ? 2 : 1;

    UNICODE_STRING rootName;
    OBJECT_ATTRIBUTES rootAttributes;
    HANDLE rootKey = NULL;
    RtlInitUnicodeString(&rootName, rootPath);
    InitializeObjectAttributes(&rootAttributes, &rootName,
        OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS status = NtOpenKey(&rootKey, KEY_READ, &rootAttributes);
    if (!NT_SUCCESS(status)) {
        if (rootKey)
            NtClose(rootKey);
        RegistryHistory_Discard(capture);
        return false;
    }

    std::wstring hivePath = JoinPath(capture.PendingPath,
        RegistryHistoryHive);
    LSTATUS saveStatus = ERROR_PRIVILEGE_NOT_HELD;
    {
        BACKUP_PRIVILEGE privilege;
        if (privilege.Enable())
            saveStatus = RegSaveKeyExW((HKEY)rootKey, hivePath.c_str(),
                NULL, REG_STANDARD_FORMAT);
    }
    NtClose(rootKey);
    if (saveStatus != ERROR_SUCCESS) {
        RegistryHistory_Discard(capture);
        return false;
    }

    if (!CopyDeleteMetadata(fileRoot, capture.PendingPath, deleteMode) ||
            !WriteGenerationMetadata(capture.PendingPath, boxName,
                deleteMode)) {
        RegistryHistory_Discard(capture);
        return false;
    }

    capture.Prepared = true;
    return true;
}

void RegistryHistory_Commit(const WCHAR* boxName,
    REGISTRY_HISTORY_CAPTURE& capture)
{
    if (!capture.Prepared)
        return;

    if (IsSafeDirectory(capture.PendingPath) &&
            MoveFileExW(capture.PendingPath.c_str(), capture.FinalPath.c_str(),
            MOVEFILE_WRITE_THROUGH)) {
        std::wstring historyRoot = capture.FinalPath.substr(0,
            capture.FinalPath.find_last_of(L"\\/"));
        EnforceGenerationLimit(boxName, historyRoot);
    }
    else {
        DeleteGenerationDirectory(capture.PendingPath);
    }
    capture = REGISTRY_HISTORY_CAPTURE();
}

void RegistryHistory_Discard(REGISTRY_HISTORY_CAPTURE& capture)
{
    if (!capture.PendingPath.empty())
        DeleteGenerationDirectory(capture.PendingPath);
    capture = REGISTRY_HISTORY_CAPTURE();
}
