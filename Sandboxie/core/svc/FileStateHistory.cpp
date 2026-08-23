/*
 * Copyright 2026 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "stdafx.h"

#include "FileStateHistory.h"
#include "HistoryPath.h"
#include "common/defines.h"
#include "common/win32_ntddk.h"
#include "core/dll/sbiedll.h"

#include <algorithm>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <wctype.h>

#ifndef WC_ERR_INVALID_CHARS
#define WC_ERR_INVALID_CHARS        0x00000080
#endif

namespace
{
    const WCHAR* FileStateHistoryDirectory = L"FileStateHistory";
    const WCHAR* FileStateManifest = L"FileMap.dat";
    const ULONG FileStateManifestVersion = 1;

    struct CAPTURE_OPTIONS
    {
        bool HashEnabled = false;
        ULONG64 HashMaxFileSize = 0;
        ULONG64 HashMaxTotalSize = 0;
        ULONG64 HashedSize = 0;
        ULONG MaxEntries = 250000;
        ULONG64 MaxManifestSize = 64ULL * 1024 * 1024;
        std::vector<std::wstring> Exclusions;
    };

    struct CAPTURE_COUNTS
    {
        ULONG Files = 0;
        ULONG Directories = 0;
        ULONG Hashed = 0;
        ULONG HashSkipped = 0;
        ULONG ReparseSkipped = 0;
        ULONG64 ManifestSize = 0;
    };

    std::wstring JoinPath(const std::wstring& left, const WCHAR* right)
    {
        std::wstring path = left;
        if (!path.empty() && path.back() != L'\\')
            path += L'\\';
        path += right;
        return path;
    }

    std::wstring ExtendedPath(const std::wstring& path)
    {
        if (path.compare(0, 4, L"\\\\?\\") == 0 ||
                path.compare(0, 4, L"\\\\.\\") == 0)
            return path;
        if (path.compare(0, 2, L"\\\\") == 0)
            return L"\\\\?\\UNC\\" + path.substr(2);
        if (path.size() >= 3 && path[1] == L':' &&
                (path[2] == L'\\' || path[2] == L'/'))
            return L"\\\\?\\" + path;
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

    std::wstring MakeGenerationName()
    {
        SYSTEMTIME time = {};
        GetSystemTime(&time);
        WCHAR name[64];
        _snwprintf(name, ARRAYSIZE(name) - 1,
            L"%04u%02u%02u-%02u%02u%02u-%03u",
            time.wYear, time.wMonth, time.wDay, time.wHour,
            time.wMinute, time.wSecond, time.wMilliseconds);
        name[ARRAYSIZE(name) - 1] = L'\0';
        return name;
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

    bool CreateGenerationDirectory(const std::wstring& historyRoot,
        std::wstring& pendingPath, std::wstring& finalPath)
    {
        for (ULONG attempt = 0; attempt < 100; ++attempt) {
            std::wstring name = MakeGenerationName();
            finalPath = JoinPath(historyRoot, name.c_str());
            pendingPath = JoinPath(historyRoot,
                (std::wstring(L".pending-") + name).c_str());
            if (GetFileAttributesW(finalPath.c_str()) ==
                    INVALID_FILE_ATTRIBUTES &&
                    CreateDirectoryW(pendingPath.c_str(), NULL)) {
                if (IsSafeDirectory(pendingPath))
                    return true;
                RemoveDirectoryW(pendingPath.c_str());
            }
            pendingPath.clear();
            finalPath.clear();
            Sleep(1);
        }
        return false;
    }

    bool DeleteGenerationDirectory(const std::wstring& path)
    {
        if (!IsSafeDirectory(path))
            return false;
        const WCHAR* files[] = {
            FileStateManifest, L"FilePaths.dat", L"FilePaths_v3.dat",
            L"FilePaths_v3.sbie", L"Generation.ini"
        };
        for (const WCHAR* file : files) {
            if (!DeleteFileW(JoinPath(path, file).c_str()) &&
                    GetLastError() != ERROR_FILE_NOT_FOUND)
                return false;
        }
        return RemoveDirectoryW(path.c_str()) != FALSE;
    }

    bool WildcardMatch(const WCHAR* pattern, const WCHAR* value)
    {
        const WCHAR* star = NULL;
        const WCHAR* retry = NULL;
        while (*value) {
            if (*pattern == L'?' || towlower(*pattern) == towlower(*value)) {
                ++pattern;
                ++value;
            }
            else if (*pattern == L'*') {
                star = pattern++;
                retry = value;
            }
            else if (star) {
                pattern = star + 1;
                value = ++retry;
            }
            else
                return false;
        }
        while (*pattern == L'*')
            ++pattern;
        return *pattern == L'\0';
    }

    bool IsExcluded(const CAPTURE_OPTIONS& options,
        const std::wstring& relativePath)
    {
        for (const std::wstring& pattern : options.Exclusions) {
            if (WildcardMatch(pattern.c_str(), relativePath.c_str()))
                return true;
        }
        return false;
    }

    ULONG QueryConfNumberAllowZero(const WCHAR* boxName,
        const WCHAR* setting, ULONG defaultValue)
    {
        WCHAR value[32] = {};
        if (!NT_SUCCESS(SbieApi_QueryConfAsIs(boxName, setting, 0,
                value, sizeof(value))) || !*value)
            return defaultValue;
        if (value[sizeof(value) / sizeof(value[0]) - 1] != L'\0')
            return defaultValue;
        WCHAR* end = NULL;
        ULONG64 number = _wcstoui64(value, &end, 10);
        while (end && (*end == L' ' || *end == L'\t'))
            ++end;
        if (end == value || *end != L'\0' || number > 0xFFFFFFFFULL)
            return defaultValue;
        return (ULONG)number;
    }

    std::string Utf8(const std::wstring& value)
    {
        if (value.empty())
            return std::string();
        int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
            value.c_str(), (int)value.size(), NULL, 0, NULL, NULL);
        if (length <= 0)
            return std::string();
        std::string result(length, '\0');
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                value.c_str(), (int)value.size(), &result[0], length,
                NULL, NULL) != length)
            result.clear();
        return result;
    }

    std::string EscapePath(const std::wstring& path)
    {
        std::string input = Utf8(path);
        std::string output;
        output.reserve(input.size());
        for (char ch : input) {
            if (ch == '\\')
                output += "\\\\";
            else if (ch == '\t')
                output += "\\t";
            else if (ch == '\r')
                output += "\\r";
            else if (ch == '\n')
                output += "\\n";
            else
                output += ch;
        }
        return output;
    }

    bool WriteData(HANDLE file, const std::string& data,
        CAPTURE_OPTIONS& options, CAPTURE_COUNTS& counts)
    {
        if (counts.ManifestSize > options.MaxManifestSize ||
                data.size() > options.MaxManifestSize - counts.ManifestSize)
            return false;
        DWORD written = 0;
        if (data.size() > MAXDWORD ||
                !WriteFile(file, data.data(), (DWORD)data.size(),
                    &written, NULL) || written != (DWORD)data.size())
            return false;
        counts.ManifestSize += written;
        return true;
    }

    bool HashFile(const std::wstring& path, ULONG64 expectedSize,
        std::string& hashText)
    {
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN |
                FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (file == INVALID_HANDLE_VALUE)
            return false;

        BY_HANDLE_FILE_INFORMATION before = {};
        bool ok = GetFileInformationByHandle(file, &before) != FALSE &&
            (before.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
                FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
            (((ULONG64)before.nFileSizeHigh << 32) | before.nFileSizeLow) ==
                expectedSize;

        BCRYPT_ALG_HANDLE algorithm = NULL;
        BCRYPT_HASH_HANDLE hash = NULL;
        std::vector<UCHAR> object;
        UCHAR digest[32] = {};
        DWORD objectLength = 0;
        DWORD resultLength = 0;
        if (ok)
            ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                NULL, 0) == 0;
        if (ok)
            ok = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                (PUCHAR)&objectLength, sizeof(objectLength), &resultLength, 0) == 0;
        if (ok) {
            object.resize(objectLength);
            ok = BCryptCreateHash(algorithm, &hash, object.data(),
                objectLength, NULL, 0, 0) == 0;
        }

        std::vector<UCHAR> buffer(64 * 1024);
        while (ok) {
            DWORD read = 0;
            if (!ReadFile(file, buffer.data(), (DWORD)buffer.size(), &read, NULL)) {
                ok = false;
                break;
            }
            if (read == 0)
                break;
            ok = BCryptHashData(hash, buffer.data(), read, 0) == 0;
        }
        if (ok)
            ok = BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0;

        BY_HANDLE_FILE_INFORMATION after = {};
        if (ok)
            ok = GetFileInformationByHandle(file, &after) != FALSE &&
                before.nFileSizeHigh == after.nFileSizeHigh &&
                before.nFileSizeLow == after.nFileSizeLow &&
                CompareFileTime(&before.ftLastWriteTime,
                    &after.ftLastWriteTime) == 0;

        if (hash)
            BCryptDestroyHash(hash);
        if (algorithm)
            BCryptCloseAlgorithmProvider(algorithm, 0);
        CloseHandle(file);

        if (!ok)
            return false;
        static const char hex[] = "0123456789abcdef";
        hashText.resize(sizeof(digest) * 2);
        for (ULONG index = 0; index < sizeof(digest); ++index) {
            hashText[index * 2] = hex[digest[index] >> 4];
            hashText[index * 2 + 1] = hex[digest[index] & 0x0F];
        }
        return true;
    }

    bool AddEntry(HANDLE manifest, const std::wstring& fullPath,
        const std::wstring& relativePath, const WIN32_FIND_DATAW& data,
        CAPTURE_OPTIONS& options, CAPTURE_COUNTS& counts)
    {
        if (counts.Files + counts.Directories >= options.MaxEntries)
            return false;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            ++counts.ReparseSkipped;
            return true;
        }

        bool directory = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        ULONG64 size = directory ? 0 :
            ((ULONG64)data.nFileSizeHigh << 32) | data.nFileSizeLow;
        std::string hash = "-";
        bool withinFileHashLimit = options.HashMaxFileSize == 0 ||
            size <= options.HashMaxFileSize;
        bool withinTotalHashLimit = options.HashMaxTotalSize == 0 ||
            (options.HashedSize <= options.HashMaxTotalSize &&
                size <= options.HashMaxTotalSize - options.HashedSize);
        if (!directory && options.HashEnabled && withinFileHashLimit &&
                withinTotalHashLimit) {
            if (HashFile(fullPath, size, hash)) {
                options.HashedSize += size;
                ++counts.Hashed;
            }
            else {
                hash = "!";
                ++counts.HashSkipped;
            }
        }
        else if (!directory && options.HashEnabled) {
            hash = "!";
            ++counts.HashSkipped;
        }

        ULARGE_INTEGER created = {};
        ULARGE_INTEGER modified = {};
        created.LowPart = data.ftCreationTime.dwLowDateTime;
        created.HighPart = data.ftCreationTime.dwHighDateTime;
        modified.LowPart = data.ftLastWriteTime.dwLowDateTime;
        modified.HighPart = data.ftLastWriteTime.dwHighDateTime;

        char prefix[256];
        int length = _snprintf(prefix, sizeof(prefix) - 1,
            "%c\t%08lX\t%I64u\t%016I64X\t%016I64X\t%s\t",
            directory ? 'D' : 'F', data.dwFileAttributes, size,
            created.QuadPart, modified.QuadPart, hash.c_str());
        if (length <= 0 || length >= (int)sizeof(prefix))
            return false;
        prefix[sizeof(prefix) - 1] = '\0';
        std::string line(prefix, length);
        std::string escapedPath = EscapePath(relativePath);
        if (escapedPath.empty())
            return false;
        line += escapedPath;
        line += '\n';
        if (!WriteData(manifest, line, options, counts))
            return false;
        if (directory)
            ++counts.Directories;
        else
            ++counts.Files;
        return true;
    }

    bool ScanDirectory(HANDLE manifest, const std::wstring& root,
        const std::wstring& relative, CAPTURE_OPTIONS& options,
        CAPTURE_COUNTS& counts)
    {
        std::wstring directory = relative.empty()
            ? root : JoinPath(root, relative.c_str());
        if (!IsSafeDirectory(directory))
            return false;

        WIN32_FIND_DATAW data = {};
        HANDLE find = FindFirstFileW(JoinPath(directory, L"*").c_str(), &data);
        if (find == INVALID_HANDLE_VALUE)
            return GetLastError() == ERROR_FILE_NOT_FOUND;

        bool ok = true;
        do {
            if (wcscmp(data.cFileName, L".") == 0 ||
                    wcscmp(data.cFileName, L"..") == 0)
                continue;
            std::wstring childRelative = relative;
            if (!childRelative.empty())
                childRelative += L'\\';
            childRelative += data.cFileName;
            if (IsExcluded(options, childRelative))
                continue;
            std::wstring childPath = JoinPath(root, childRelative.c_str());
            if (!AddEntry(manifest, childPath, childRelative, data,
                    options, counts)) {
                ok = false;
                break;
            }
            if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
                    (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
                    !ScanDirectory(manifest, root, childRelative,
                        options, counts)) {
                ok = false;
                break;
            }
        } while (FindNextFileW(find, &data));
        DWORD error = GetLastError();
        FindClose(find);
        return ok && (error == ERROR_NO_MORE_FILES || error == ERROR_SUCCESS);
    }

    void ReadOptions(const WCHAR* boxName, CAPTURE_OPTIONS& options)
    {
        WCHAR mode[32] = {};
        if (NT_SUCCESS(SbieApi_QueryConf(boxName,
                L"FileStateHistoryHashMode", 0, mode, sizeof(mode))))
            options.HashEnabled = _wcsicmp(mode, L"Limited") == 0;
        options.HashMaxFileSize =
            (ULONG64)QueryConfNumberAllowZero(boxName,
                L"FileStateHistoryHashMaxFileSizeKB", 1024) * 1024;
        options.HashMaxTotalSize =
            (ULONG64)QueryConfNumberAllowZero(boxName,
                L"FileStateHistoryHashMaxTotalKB", 64 * 1024) * 1024;
        for (ULONG index = 0; index < 1000; ++index) {
            WCHAR value[2048] = {};
            if (!NT_SUCCESS(SbieApi_QueryConf(boxName,
                    L"FileStateHistoryExclude", index, value,
                    sizeof(value))))
                break;
            if (*value)
                options.Exclusions.push_back(value);
        }
    }

    bool AutoDeleteRemovesFileStateHistory(const WCHAR* boxName)
    {
        if (!SbieApi_QueryConfBool(boxName, L"AutoDelete", FALSE))
            return false;
        WCHAR mode[32] = {};
        if (!NT_SUCCESS(SbieApi_QueryConf(boxName,
                L"AutoDeleteHistoryMode", 0, mode, sizeof(mode))))
            return false;
        return _wcsicmp(mode, L"FileStates") == 0 ||
            _wcsicmp(mode, L"File") == 0 ||
            _wcsicmp(mode, L"All") == 0;
    }

    std::wstring ReadSnapshotBase(const std::wstring& fileRoot)
    {
        WCHAR value[128] = {};
        GetPrivateProfileStringW(L"Current", L"Snapshot", L"", value,
            ARRAYSIZE(value), JoinPath(fileRoot, L"Snapshots.ini").c_str());
        return value;
    }

    bool CopyDeleteMetadata(const std::wstring& fileRoot,
        const std::wstring& pendingPath, ULONG deleteMode)
    {
        const WCHAR* files[2] = {};
        ULONG fileCount = 0;
        if (deleteMode == 2)
            files[fileCount++] = L"FilePaths.dat";
        else if (deleteMode == 3) {
            files[fileCount++] = L"FilePaths_v3.dat";
            files[fileCount++] = L"FilePaths_v3.sbie";
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

    bool WriteMetadata(const std::wstring& pendingPath,
        const WCHAR* boxName, const CAPTURE_OPTIONS& options,
        const CAPTURE_COUNTS& counts, const std::wstring& snapshotBase,
        ULONG deleteMode)
    {
        SYSTEMTIME time = {};
        GetSystemTime(&time);
        WCHAR text[2048];
        _snwprintf(text, ARRAYSIZE(text) - 1,
            L"[Generation]\r\nVersion=%u\r\n"
            L"CapturedUtc=%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\r\n"
            L"BoxName=%s\r\nSnapshotBase=%s\r\nDeleteMode=%u\r\n"
            L"Files=%u\r\nDirectories=%u\r\nHashed=%u\r\n"
            L"HashSkipped=%u\r\nReparseSkipped=%u\r\n"
            L"HashMode=%s\r\nManifestBytes=%I64u\r\n",
            FileStateManifestVersion, time.wYear, time.wMonth, time.wDay,
            time.wHour, time.wMinute, time.wSecond, time.wMilliseconds,
            boxName, snapshotBase.c_str(), deleteMode, counts.Files,
            counts.Directories,
            counts.Hashed, counts.HashSkipped, counts.ReparseSkipped,
            options.HashEnabled ? L"Limited" : L"Off", counts.ManifestSize);
        text[ARRAYSIZE(text) - 1] = L'\0';

        HANDLE file = CreateFileW(JoinPath(pendingPath,
            L"Generation.ini").c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE)
            return false;
        WORD bom = 0xFEFF;
        DWORD written = 0;
        DWORD bytes = (DWORD)(wcslen(text) * sizeof(WCHAR));
        bool ok = WriteFile(file, &bom, sizeof(bom), &written, NULL) &&
            written == sizeof(bom) &&
            WriteFile(file, text, bytes, &written, NULL) &&
            written == bytes && FlushFileBuffers(file);
        CloseHandle(file);
        return ok;
    }

    void EnforceGenerationLimit(const WCHAR* boxName,
        const std::wstring& historyRoot)
    {
        if (!IsSafeDirectory(historyRoot))
            return;

        ULONG maxGenerations = QueryConfNumberAllowZero(boxName,
            L"FileStateHistoryMaxGenerations", 20);
        ULONG64 maxSize = (ULONG64)QueryConfNumberAllowZero(boxName,
            L"FileStateHistoryMaxSizeKB", 256 * 1024) * 1024;
        struct GENERATION { std::wstring Name; ULONG64 Size; };
        std::vector<GENERATION> generations;
        ULONG64 total = 0;
        WIN32_FIND_DATAW data = {};
        HANDLE find = FindFirstFileW(JoinPath(historyRoot, L"*").c_str(), &data);
        if (find != INVALID_HANDLE_VALUE) {
            do {
                if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                        (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                        !IsGenerationName(data.cFileName))
                    continue;
                std::wstring path = JoinPath(historyRoot, data.cFileName);
                GENERATION generation = { data.cFileName, 0 };
                const WCHAR* files[] = {
                    FileStateManifest, L"Generation.ini", L"FilePaths.dat",
                    L"FilePaths_v3.dat", L"FilePaths_v3.sbie"
                };
                bool valid = true;
                for (ULONG index = 0; index < ARRAYSIZE(files); ++index) {
                    const WCHAR* file = files[index];
                    WIN32_FILE_ATTRIBUTE_DATA info = {};
                    if (!GetFileAttributesExW(JoinPath(path, file).c_str(),
                            GetFileExInfoStandard, &info)) {
                        DWORD error = GetLastError();
                        if (index >= 2 && (error == ERROR_FILE_NOT_FOUND ||
                                error == ERROR_PATH_NOT_FOUND))
                            continue;
                        valid = false;
                        break;
                    }
                    if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
                                FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
                        valid = false;
                        break;
                    }
                    generation.Size += ((ULONG64)info.nFileSizeHigh << 32) |
                        info.nFileSizeLow;
                }
                if (valid) {
                    total += generation.Size;
                    generations.push_back(generation);
                }
            } while (FindNextFileW(find, &data));
            FindClose(find);
        }
        std::sort(generations.begin(), generations.end(),
            [](const GENERATION& left, const GENERATION& right) {
                return left.Name < right.Name;
            });
        while (generations.size() > 1 &&
                ((maxGenerations && generations.size() > maxGenerations) ||
                 (maxSize && total > maxSize))) {
            if (!DeleteGenerationDirectory(JoinPath(historyRoot,
                    generations.front().Name.c_str())))
                break;
            total -= generations.front().Size;
            generations.erase(generations.begin());
        }
    }
}

bool FileStateHistory_Capture(const WCHAR* boxName, const WCHAR* rootPath)
{
    if (!SbieApi_QueryConfBool(boxName, L"FileStateHistory", FALSE))
        return false;
    if (AutoDeleteRemovesFileStateHistory(boxName))
        return false;

    std::wstring fileRoot;
    if (!HistoryPath_Get(rootPath, fileRoot))
        return false;
    fileRoot = ExtendedPath(fileRoot);
    std::wstring historyRoot = JoinPath(fileRoot,
        FileStateHistoryDirectory);
    if (!CreateDirectoryIfNeeded(historyRoot))
        return false;

    std::wstring pendingPath;
    std::wstring finalPath;
    if (!CreateGenerationDirectory(historyRoot, pendingPath, finalPath))
        return false;

    CAPTURE_OPTIONS options;
    CAPTURE_COUNTS counts;
    ReadOptions(boxName, options);
    ULONG deleteMode = SbieApi_QueryConfBool(boxName,
        L"UseFileDeleteV3", FALSE) ? 3 :
        SbieApi_QueryConfBool(boxName, L"UseFileDeleteV2", FALSE) ? 2 : 1;
    HANDLE manifest = CreateFileW(JoinPath(pendingPath,
        FileStateManifest).c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, NULL);
    bool ok = manifest != INVALID_HANDLE_VALUE;
    if (ok)
        ok = WriteData(manifest, "SBIE_FILE_STATE_MAP\t1\n",
            options, counts);

    const WCHAR* roots[] = { L"drive", L"user", L"share" };
    for (ULONG index = 0; ok && index < ARRAYSIZE(roots); ++index) {
        std::wstring path = JoinPath(fileRoot, roots[index]);
        DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            if (GetLastError() == ERROR_FILE_NOT_FOUND ||
                    GetLastError() == ERROR_PATH_NOT_FOUND)
                continue;
            ok = false;
        }
        else if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            ok = false;
        else
            ok = ScanDirectory(manifest, fileRoot, roots[index],
                options, counts);
    }
    if (manifest != INVALID_HANDLE_VALUE) {
        ok = ok && FlushFileBuffers(manifest);
        CloseHandle(manifest);
    }
    if (ok)
        ok = CopyDeleteMetadata(fileRoot, pendingPath, deleteMode);
    if (ok)
        ok = WriteMetadata(pendingPath, boxName, options, counts,
            ReadSnapshotBase(fileRoot), deleteMode);
    if (ok)
        ok = MoveFileExW(pendingPath.c_str(), finalPath.c_str(),
            MOVEFILE_WRITE_THROUGH) != FALSE;
    if (!ok) {
        DeleteGenerationDirectory(pendingPath);
        return false;
    }
    EnforceGenerationLimit(boxName, historyRoot);
    return true;
}
