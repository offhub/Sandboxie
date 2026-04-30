/*
 * Copyright 2026 David Xanatos, xanasoft.com
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
// Shared breakout matching helpers for DLL/SVC code paths.
// Keep this header C/C++ compatible and header-only to avoid project wiring.
//---------------------------------------------------------------------------

#ifndef _BREAKOUT_MATCH_H
#define _BREAKOUT_MATCH_H

#include <wchar.h>
#include <wctype.h>
#include "my_version.h"

static __inline int Breakout_WildcardMatchI(const WCHAR *pattern, const WCHAR *text)
{
    if (!pattern || !text)
        return 0;

    while (*pattern) {
        if (*pattern == L'*') {
            while (*pattern == L'*')
                ++pattern;
            if (!*pattern)
                return 1;
            while (*text) {
                if (Breakout_WildcardMatchI(pattern, text))
                    return 1;
                ++text;
            }
            return 0;
        }

        if (!*text)
            return 0;

        if (*pattern != L'?' && towlower(*pattern) != towlower(*text))
            return 0;

        ++pattern;
        ++text;
    }

    return (*text == L'\0');
}

static __inline int Breakout_RuleLooksLikePath(const WCHAR *rule)
{
    return (rule && (wcschr(rule, L'\\') || wcschr(rule, L'/')));
}

static __inline WCHAR *Breakout_FindTargetSeparator(WCHAR *value)
{
    WCHAR *sep = wcschr(value, L'|');
    if (!sep || sep <= value || !sep[1])
        return NULL;

    return sep;
}

static __inline int Breakout_MatchProcessRule(
    const WCHAR *rule, const WCHAR *imageName, const WCHAR *appPath, unsigned long appPathLen)
{
    size_t ruleLen;

    if (!rule || !*rule || !imageName || !*imageName || !appPath || !appPathLen)
        return 0;

    if (_wcsicmp(rule, imageName) == 0)
        return 1;

    if (!Breakout_RuleLooksLikePath(rule))
        return 0;

    ruleLen = wcslen(rule);
    if (!ruleLen)
        return 0;

    if (wcschr(rule, L'*') || wcschr(rule, L'?'))
        return Breakout_WildcardMatchI(rule, appPath);

    if (ruleLen != appPathLen)
        return 0;

    return (_wcsnicmp(rule, appPath, ruleLen) == 0);
}

static __inline int Breakout_MatchFolderRule(
    const WCHAR *rule, const WCHAR *appPath, unsigned long appDirLen)
{
    size_t ruleLen;

    if (!rule || !*rule || !appPath || !appDirLen)
        return 0;

    ruleLen = wcslen(rule);
    while (ruleLen && rule[ruleLen - 1] == L'\\')
        --ruleLen;

    if (!ruleLen || !appDirLen)
        return 0;

    if (wcschr(rule, L'*') || wcschr(rule, L'?'))
        return Breakout_WildcardMatchI(rule, appPath);

    if (ruleLen != appDirLen)
        return 0;

    return (_wcsnicmp(rule, appPath, ruleLen) == 0);
}

static __inline int Breakout_FindProcessMatch(
    const WCHAR *boxname, const WCHAR *imageName, const WCHAR *appPath,
    unsigned long appPathLen, WCHAR *outTarget, size_t outTargetCch, int *outHasTarget)
{
    WCHAR buf[CONF_LINE_LEN];
    unsigned long index = 0;

    if (outTarget && outTargetCch)
        outTarget[0] = L'\0';
    if (outHasTarget)
        *outHasTarget = 0;

    while (1) {
        NTSTATUS status = SbieApi_QueryConfAsIs(boxname, L"BreakoutProcess", index, buf, sizeof(buf) - sizeof(WCHAR));
        WCHAR *sep;

        ++index;
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_BUFFER_TOO_SMALL)
                continue;
            break;
        }

        sep = Breakout_FindTargetSeparator(buf);
        if (sep)
            *sep = L'\0';

        if (!Breakout_MatchProcessRule(buf, imageName, appPath, appPathLen))
            continue;

        if (sep && outHasTarget)
            *outHasTarget = 1;

        if (sep && outTarget && outTargetCch)
            wcscpy_s(outTarget, outTargetCch, sep + 1);

        return 1;
    }

    return 0;
}

static __inline int Breakout_IsSandboxieImageName(const WCHAR *imageName)
{
    if (!imageName || !*imageName)
        return 0;

    if (_wcsicmp(imageName, L"ImBox.exe") == 0)
        return 1;
    if (_wcsicmp(imageName, L"KmdUtil.exe") == 0)
        return 1;
    if (_wcsicmp(imageName, L"SandboxieBITS.exe") == 0)
        return 1;
    if (_wcsicmp(imageName, L"SandboxieCrypto.exe") == 0)
        return 1;
    if (_wcsicmp(imageName, L"SandboxieDcomLaunch.exe") == 0)
        return 1;
    if (_wcsicmp(imageName, L"SandboxieRpcSs.exe") == 0)
        return 1;
    if (_wcsicmp(imageName, L"SandboxieWUAU.exe") == 0)
        return 1;
    if (_wcsicmp(imageName, L"SandMan.exe") == 0)
        return 1;
    if (_wcsicmp(imageName, SBIECTRL_EXE) == 0)
        return 1;
    if (_wcsicmp(imageName, SBIEINI_EXE) == 0)
        return 1;
    if (_wcsicmp(imageName, SBIESVC_EXE) == 0)
        return 1;
    if (_wcsicmp(imageName, START_EXE) == 0)
        return 1;
    if (_wcsicmp(imageName, L"unins000.exe") == 0)
        return 1;
    if (_wcsicmp(imageName, L"UpdUtil.exe") == 0)
        return 1;

    return 0;
}

static __inline int Breakout_IsPathInHome(const WCHAR *appPath)
{
    WCHAR homePath[MAX_PATH];
    ULONG homeLen;

    if (!appPath || !*appPath)
        return 0;

    if (!NT_SUCCESS(SbieApi_GetHomePath(NULL, 0, homePath, MAX_PATH)))
        return 0;

    homeLen = (ULONG)wcslen(homePath);
    if (!homeLen)
        return 0;

    if (_wcsnicmp(appPath, homePath, homeLen) != 0)
        return 0;

    return (appPath[homeLen] == L'\0' || appPath[homeLen] == L'\\' || appPath[homeLen] == L'/');
}

static __inline int Breakout_ShouldIgnoreTarget(const WCHAR *imageName, const WCHAR *appPath)
{
    if (!Breakout_IsPathInHome(appPath))
        return 0;

    return Breakout_IsSandboxieImageName(imageName);
}

#endif
