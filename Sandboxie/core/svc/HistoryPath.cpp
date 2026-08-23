/*
 * Copyright 2026 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "stdafx.h"

#include "HistoryPath.h"
#include "core/dll/sbiedll.h"

#include <map>
#include <vector>

namespace
{
    struct CASE_INSENSITIVE_LESS
    {
        bool operator()(const std::wstring& left,
            const std::wstring& right) const
        {
            return _wcsicmp(left.c_str(), right.c_str()) < 0;
        }
    };

    CRITICAL_SECTION HistoryPathLock;
    std::map<std::wstring, std::wstring, CASE_INSENSITIVE_LESS> HistoryPaths;
}

void HistoryPath_Initialize()
{
    InitializeCriticalSection(&HistoryPathLock);
}

void HistoryPath_Shutdown()
{
    EnterCriticalSection(&HistoryPathLock);
    HistoryPaths.clear();
    LeaveCriticalSection(&HistoryPathLock);
    DeleteCriticalSection(&HistoryPathLock);
}

void HistoryPath_Remember(const WCHAR* fileRoot, const WCHAR* rootPath)
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

    EnterCriticalSection(&HistoryPathLock);
    HistoryPaths[rootPath] = path;
    LeaveCriticalSection(&HistoryPathLock);
}

void HistoryPath_Forget(const WCHAR* rootPath)
{
    if (!rootPath || !*rootPath)
        return;

    EnterCriticalSection(&HistoryPathLock);
    HistoryPaths.erase(rootPath);
    LeaveCriticalSection(&HistoryPathLock);
}

bool HistoryPath_Get(const WCHAR* rootPath, std::wstring& fileRoot)
{
    fileRoot.clear();
    if (!rootPath || !*rootPath)
        return false;

    for (ULONG attempt = 0; attempt < 20; ++attempt) {
        EnterCriticalSection(&HistoryPathLock);
        auto found = HistoryPaths.find(rootPath);
        if (found != HistoryPaths.end())
            fileRoot = found->second;
        LeaveCriticalSection(&HistoryPathLock);

        if (!fileRoot.empty())
            return true;
        Sleep(50);
    }
    return false;
}
