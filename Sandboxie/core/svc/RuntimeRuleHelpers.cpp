/*
 * Copyright 2026 David Xanatos, xanasoft.com
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "stdafx.h"

#include "common/win32_ntddk.h"
#include "RuntimeRuleHelpers.h"

static BOOLEAN SbieSvc_RuntimeCompileSettingAdjusted(
    SBIE_RT_RULESET* ruleset,
    const WCHAR* setting,
    const WCHAR* value,
    int useRuleExtensions,
    BreakoutAdjustRuleFn adjustRule,
    void* adjustContext)
{
    WCHAR parseBuf[CONF_LINE_LEN];
    WCHAR compileBuf[CONF_LINE_LEN];
    SBIE_PROGRAM_RULE_KIND ruleKind = SBIE_RULE_KIND_NONE;
    SBIE_NORMALIZED_RULE rule;
    WCHAR* parseValue = parseBuf;
    size_t baseOffset;
    size_t suffixOffset;
    WCHAR* compileBase;
    WCHAR* compileSep;

    if (!ruleset || !setting || !value || !*value)
        return FALSE;

    wcscpy_s(parseBuf, ARRAYSIZE(parseBuf), value);
    wcscpy_s(compileBuf, ARRAYSIZE(compileBuf), value);

    if (!ProgramControl_GetRuleKindForSetting(setting, &ruleKind))
        return FALSE;

    if (ruleKind != SBIE_RULE_KIND_PROCESS) {
        parseValue = ProgramControl_ParseImageScopeInPlace(parseBuf, NULL, NULL, NULL, NULL);
        if (!parseValue)
            return FALSE;
    }

    if (!ProgramControl_ParseRuleExtensionsInPlace(parseValue, &rule, useRuleExtensions))
        return FALSE;

    if (adjustRule) {
        baseOffset = (size_t)(rule.base_rule - parseBuf);
        compileBase = compileBuf + baseOffset;
        compileSep = wcschr(compileBase, L'|');
        if (compileSep) {
            if (wcscpy_s(parseBuf, ARRAYSIZE(parseBuf), compileSep) != 0)
                return FALSE;
            *compileSep = L'\0';
        }

        adjustRule(compileBase, adjustContext);

        if (compileSep) {
            compileSep = compileBase + wcslen(compileBase);
            suffixOffset = (size_t)(compileSep - compileBuf);
            if (suffixOffset >= ARRAYSIZE(compileBuf) ||
                wcscpy_s(compileSep, ARRAYSIZE(compileBuf) - suffixOffset, parseBuf) != 0)
                return FALSE;
        }
    }

    return ProgramControl_RuntimeCompileSetting(
        ruleset, setting, compileBuf, useRuleExtensions) ? TRUE : FALSE;
}

BOOLEAN SbieSvc_LoadRuntimeRulesetForSetting(
    const WCHAR* boxname,
    const WCHAR* setting,
    int useRuleExtensions,
    BreakoutAdjustRuleFn adjustRule,
    void* adjustContext,
    SBIE_RT_RULESET* ruleset)
{
    WCHAR buf[CONF_LINE_LEN];
    ULONG index = 0;

    if (!setting || !*setting || !ruleset)
        return FALSE;

    while (1) {
        NTSTATUS status;

        if (_wcsicmp(setting, L"ForceFolder") == 0 ||
            _wcsicmp(setting, L"BreakoutFolder") == 0 ||
            _wcsicmp(setting, L"BreakoutDocument") == 0)
            status = SbieApi_QueryConf(boxname, setting, index, buf, sizeof(buf) - 16 * sizeof(WCHAR));
        else
            status = SbieApi_QueryConfAsIs(boxname, setting, index, buf, sizeof(buf) - sizeof(WCHAR));

        ++index;
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_BUFFER_TOO_SMALL)
                continue;
            break;
        }

        if (!SbieSvc_RuntimeCompileSettingAdjusted(
                ruleset,
                setting,
                buf,
                useRuleExtensions,
                adjustRule,
                adjustContext)) {
            return FALSE;
        }
    }

    return TRUE;
}
