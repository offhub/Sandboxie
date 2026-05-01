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

#ifndef BREAKOUT_MATCH_NO_CRT
#include <wchar.h>
#include <wctype.h>
#endif
#include "my_version.h"

typedef int (*BreakoutMatchImageFn)(const WCHAR *pattern, const WCHAR *imageName, void *context);
typedef void (*BreakoutAdjustRuleFn)(WCHAR *value, void *context);

static __inline int Breakout_MatchFolderRule(
    const WCHAR *rule, const WCHAR *appPath, unsigned long appDirLen);

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

        if (*pattern != L'?' &&
#ifdef BREAKOUT_MATCH_NO_CRT
            ((*pattern >= L'A' && *pattern <= L'Z') ? (*pattern + (L'a' - L'A')) : *pattern)
                != ((*text >= L'A' && *text <= L'Z') ? (*text + (L'a' - L'A')) : *text)
#else
            towlower(*pattern) != towlower(*text)
#endif
            )
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

static __inline WCHAR *Breakout_MatchImageScopeAndGetValue(
    WCHAR *value, const WCHAR *imageName, BreakoutMatchImageFn matchImage, void *context)
{
    WCHAR *tmp = wcschr(value, L',');

    if (tmp) {
        int inv;
        int match;
        size_t len;

        if (!imageName || !matchImage)
            return NULL;

        if (*value == L'!') {
            inv = 1;
            ++value;
        }
        else
            inv = 0;

        len = (size_t)(tmp - value);
        if (len) {
            WCHAR saved = value[len];
            value[len] = L'\0';
            match = matchImage(value, imageName, context);
            value[len] = saved;
            if (inv)
                match = !match;
            if (!match)
                return NULL;
        }

        value = tmp + 1;
    }

    if (!*value)
        return NULL;

    return value;
}

static __inline void Breakout_TrimTrailingBackslashes(WCHAR *value)
{
    size_t len;

    if (!value)
        return;

    len = wcslen(value);
    while (len && value[len - 1] == L'\\')
        value[--len] = L'\0';
}

#ifndef BREAKOUT_MATCH_NO_QUERY_HELPERS

static __inline int Breakout_CheckFolderMatchFromConf(
    const WCHAR *boxname, const WCHAR *imageName, const WCHAR *appPath, unsigned long appDirLen,
    int allowTargeted, BreakoutMatchImageFn matchImage, void *matchContext,
    BreakoutAdjustRuleFn adjustRule, void *adjustContext)
{
    WCHAR buf[CONF_LINE_LEN];
    unsigned long index = 0;

    while (1) {
        NTSTATUS status = SbieApi_QueryConf(boxname, L"BreakoutFolder", index, buf, sizeof(buf) - 16 * sizeof(WCHAR));
        WCHAR *value;
        WCHAR *sep;

        ++index;
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_BUFFER_TOO_SMALL)
                continue;
            break;
        }

        value = Breakout_MatchImageScopeAndGetValue(buf, imageName, matchImage, matchContext);
        if (!value)
            continue;

        sep = Breakout_FindTargetSeparator(value);
        if (sep) {
            if (!allowTargeted)
                continue;
            *sep = L'\0';
        }

        if (adjustRule)
            adjustRule(value, adjustContext);

        if (Breakout_MatchFolderRule(value, appPath, appDirLen)
            || Breakout_MatchFolderRule(value, appPath, (unsigned long)wcslen(appPath))) {
            return 1;
        }
    }

    return 0;
}

static __inline int Breakout_GetFolderTargetFromConf(
    const WCHAR *boxname, const WCHAR *imageName, const WCHAR *appPath, unsigned long appDirLen,
    WCHAR *outTarget, size_t outTargetCch, BreakoutMatchImageFn matchImage, void *matchContext,
    BreakoutAdjustRuleFn adjustRule, void *adjustContext)
{
    WCHAR buf[CONF_LINE_LEN];
    unsigned long index = 0;

    if (!outTarget || !outTargetCch)
        return 0;

    outTarget[0] = L'\0';

    while (1) {
        NTSTATUS status = SbieApi_QueryConf(boxname, L"BreakoutFolder", index, buf, sizeof(buf) - 16 * sizeof(WCHAR));
        WCHAR *value;
        WCHAR *sep;

        ++index;
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_BUFFER_TOO_SMALL)
                continue;
            break;
        }

        value = Breakout_MatchImageScopeAndGetValue(buf, imageName, matchImage, matchContext);
        if (!value)
            continue;

        sep = Breakout_FindTargetSeparator(value);
        if (!sep)
            continue;

        *sep = L'\0';

        if (adjustRule)
            adjustRule(value, adjustContext);

        if (Breakout_MatchFolderRule(value, appPath, appDirLen)) {
            wcscpy_s(outTarget, outTargetCch, sep + 1);
            return 1;
        }
    }

    return 0;
}

#endif

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

#ifndef BREAKOUT_MATCH_NO_QUERY_HELPERS

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

#endif

#endif
