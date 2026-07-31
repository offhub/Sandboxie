/*
 * Copyright 2021-2026 David Xanatos, xanasoft.com
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

#define NOGDI
#include "dll.h"
#include "cmdline.h"
#include "common/pattern.h"

#define CMDLINE_SETTING                 L"CustomProcessCommandLine"
#define CMDLINE_MAX_RULES               128
#define CMDLINE_MAX_CONDITIONS          8
#define CMDLINE_MAX_ARGUMENTS           512

#define CMD_SEEN_DISABLED               0x0001
#define CMD_SEEN_STOP                   0x0002
#define CMD_SEEN_MATCH                  0x0004
#define CMD_SEEN_OCCURRENCES            0x0008
#define CMD_SEEN_DUPLICATE              0x0010

typedef enum {
    CMD_ACTION_NONE,
    CMD_ACTION_CLEAR,
    CMD_ACTION_SET,
    CMD_ACTION_REMOVE,
    CMD_ACTION_REPLACE,
    CMD_ACTION_ADD
} CMD_ACTION;

typedef enum {
    CMD_MATCH_EXACT,
    CMD_MATCH_PATTERN,
    CMD_MATCH_TEXT
} CMD_MATCH;

typedef enum {
    CMD_ADD_END,
    CMD_ADD_START,
    CMD_ADD_BEFORE,
    CMD_ADD_AFTER
} CMD_ADD_POSITION;

typedef struct {
    ULONG prefix_start;
    ULONG raw_start;
    ULONG raw_end;
    WCHAR* value;
} CMD_ARGUMENT;

typedef struct {
    WCHAR* storage;
    WCHAR* selector;
    WCHAR* id;
    WCHAR* value;
    WCHAR* replacement;
    WCHAR* relative;
    WCHAR* conditions[CMDLINE_MAX_CONDITIONS];
    WCHAR* skips[CMDLINE_MAX_CONDITIONS];
    ULONG condition_count;
    ULONG skip_count;
    LONG order;
    CMD_ACTION action;
    CMD_MATCH match;
    CMD_ADD_POSITION position;
    BOOLEAN explicit_order;
    BOOLEAN disabled;
    BOOLEAN stop;
    BOOLEAN occurrences_first;
    BOOLEAN duplicate_allow;
    BOOLEAN selector_match;
} CMD_RULE;

typedef struct {
    WCHAR* text;
    CMD_ARGUMENT* args;
    ULONG count;
    ULONG argv0_end;
    ULONG input_count;
} CMD_STATE;

extern POOL* Dll_PoolTemp;

static BOOLEAN CmdLine_ParseCountCondition(
    const WCHAR* condition, const WCHAR* name, ULONG count,
    BOOLEAN* result);

static WCHAR* CmdLine_DuplicateLength(const WCHAR* text, size_t length);

static void CmdLine_Trim(WCHAR* text)
{
    WCHAR* start;
    size_t len;

    if (!text)
        return;

    start = text;
    while (*start == L' ' || *start == L'\t')
        ++start;

    if (start != text)
        memmove(text, start, (wcslen(start) + 1) * sizeof(WCHAR));

    len = wcslen(text);
    while (len && (text[len - 1] == L' ' || text[len - 1] == L'\t'))
        text[--len] = L'\0';
}

static WCHAR* CmdLine_Duplicate(const WCHAR* text)
{
    return text ? CmdLine_DuplicateLength(text, wcslen(text)) : NULL;
}

static WCHAR* CmdLine_DuplicateLength(const WCHAR* text, size_t length)
{
    WCHAR* copy;

    if (!text)
        return NULL;

    copy = LocalAlloc(LMEM_FIXED, (length + 1) * sizeof(WCHAR));
    if (copy) {
        wmemcpy(copy, text, length);
        copy[length] = L'\0';
    }
    return copy;
}

static WCHAR* CmdLine_NextField(WCHAR** cursor)
{
    WCHAR* field;
    WCHAR* read;
    WCHAR* write;

    if (!cursor || !*cursor)
        return NULL;

    field = *cursor;
    read = field;
    write = field;

    while (*read) {
        if (*read == L';') {
            if (read[1] == L';') {
                *write++ = L';';
                read += 2;
                continue;
            }
            ++read;
            break;
        }
        *write++ = *read++;
    }

    *write = L'\0';
    *cursor = *read ? read : NULL;
    CmdLine_Trim(field);
    return field;
}

static BOOLEAN CmdLine_ParseLong(const WCHAR* text, LONG* value)
{
    WCHAR* end;
    LONG parsed;

    if (!text || !*text || !value)
        return FALSE;

    parsed = wcstol(text, &end, 10);
    if (end == text || *end)
        return FALSE;

    *value = parsed;
    return TRUE;
}

static BOOLEAN CmdLine_ParseBoolean(const WCHAR* text, BOOLEAN* value)
{
    if (!text || !value)
        return FALSE;

    if (_wcsicmp(text, L"y") == 0 || _wcsicmp(text, L"yes") == 0 ||
            _wcsicmp(text, L"true") == 0 || wcscmp(text, L"1") == 0) {
        *value = TRUE;
        return TRUE;
    }

    if (_wcsicmp(text, L"n") == 0 || _wcsicmp(text, L"no") == 0 ||
            _wcsicmp(text, L"false") == 0 || wcscmp(text, L"0") == 0) {
        *value = FALSE;
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN CmdLine_MatchSelector(const WCHAR* selector)
{
    BOOLEAN invert = FALSE;
    BOOLEAN match;
    ULONG len;

    if (!selector || !*selector)
        return FALSE;

    if (*selector == L'!') {
        invert = TRUE;
        ++selector;
    }

    len = (ULONG)wcslen(selector);
    if (!len)
        return FALSE;

    match = Config_MatchImageEx(
        selector, len, Dll_ImageName, 1, Dll_ImageType);

    return invert ? !match : match;
}

static LONG CmdLine_DefaultOrder(CMD_ACTION action)
{
    if (action == CMD_ACTION_CLEAR || action == CMD_ACTION_SET)
        return 100;
    if (action == CMD_ACTION_REMOVE)
        return 200;
    if (action == CMD_ACTION_REPLACE)
        return 300;
    return 400;
}

static BOOLEAN CmdLine_SetAction(
    CMD_RULE* rule, CMD_ACTION action, WCHAR* value)
{
    if (rule->action != CMD_ACTION_NONE)
        return FALSE;

    rule->action = action;
    rule->value = value;
    return TRUE;
}

static BOOLEAN CmdLine_ParseRule(WCHAR* text, CMD_RULE* rule)
{
    WCHAR* comma;
    WCHAR* cursor;
    WCHAR* field;
    ULONG seen = 0;
    ULONG index;
    BOOLEAN unused;

    memset(rule, 0, sizeof(*rule));
    rule->storage = text;
    rule->match = CMD_MATCH_EXACT;
    rule->position = CMD_ADD_END;

    comma = wcschr(text, L',');
    if (!comma)
        return FALSE;

    *comma = L'\0';
    rule->selector = text;
    CmdLine_Trim(rule->selector);
    rule->selector_match = CmdLine_MatchSelector(rule->selector);
    cursor = comma + 1;

    while ((field = CmdLine_NextField(&cursor)) != NULL) {
        WCHAR* equal;
        WCHAR* key;
        WCHAR* value;

        if (!*field)
            continue;

        equal = wcschr(field, L'=');
        if (!equal)
            return FALSE;

        *equal = L'\0';
        key = field;
        value = equal + 1;
        CmdLine_Trim(key);
        CmdLine_Trim(value);

        if (!*key || !*value)
            return FALSE;

        if (_wcsicmp(key, L"Id") == 0) {
            if (rule->id)
                return FALSE;
            rule->id = value;
        }
        else if (_wcsicmp(key, L"Order") == 0) {
            if (rule->explicit_order ||
                    !CmdLine_ParseLong(value, &rule->order) ||
                    rule->order < 0 || rule->order > 9999)
                return FALSE;
            rule->explicit_order = TRUE;
        }
        else if (_wcsicmp(key, L"Disabled") == 0) {
            if ((seen & CMD_SEEN_DISABLED) ||
                    !CmdLine_ParseBoolean(value, &rule->disabled))
                return FALSE;
            seen |= CMD_SEEN_DISABLED;
        }
        else if (_wcsicmp(key, L"Stop") == 0) {
            if ((seen & CMD_SEEN_STOP) ||
                    !CmdLine_ParseBoolean(value, &rule->stop))
                return FALSE;
            seen |= CMD_SEEN_STOP;
        }
        else if (_wcsicmp(key, L"Clear") == 0) {
            if (_wcsicmp(value, L"Arguments") != 0 ||
                    !CmdLine_SetAction(rule, CMD_ACTION_CLEAR, value))
                return FALSE;
        }
        else if (_wcsicmp(key, L"Set") == 0) {
            if (!CmdLine_SetAction(rule, CMD_ACTION_SET, value))
                return FALSE;
        }
        else if (_wcsicmp(key, L"Remove") == 0) {
            if (!CmdLine_SetAction(rule, CMD_ACTION_REMOVE, value))
                return FALSE;
        }
        else if (_wcsicmp(key, L"Replace") == 0) {
            if (!CmdLine_SetAction(rule, CMD_ACTION_REPLACE, value))
                return FALSE;
        }
        else if (_wcsicmp(key, L"With") == 0) {
            if (rule->replacement)
                return FALSE;
            rule->replacement = value;
        }
        else if (_wcsicmp(key, L"Add") == 0) {
            if (!CmdLine_SetAction(rule, CMD_ACTION_ADD, value))
                return FALSE;
        }
        else if (_wcsicmp(key, L"If") == 0) {
            if (rule->condition_count >= CMDLINE_MAX_CONDITIONS)
                return FALSE;
            rule->conditions[rule->condition_count++] = value;
        }
        else if (_wcsicmp(key, L"Skip") == 0) {
            if (rule->skip_count >= CMDLINE_MAX_CONDITIONS)
                return FALSE;
            rule->skips[rule->skip_count++] = value;
        }
        else if (_wcsicmp(key, L"Match") == 0) {
            if (seen & CMD_SEEN_MATCH)
                return FALSE;
            if (_wcsicmp(value, L"Exact") == 0)
                rule->match = CMD_MATCH_EXACT;
            else if (_wcsicmp(value, L"Pattern") == 0)
                rule->match = CMD_MATCH_PATTERN;
            else if (_wcsicmp(value, L"Text") == 0)
                rule->match = CMD_MATCH_TEXT;
            else
                return FALSE;
            seen |= CMD_SEEN_MATCH;
        }
        else if (_wcsicmp(key, L"At") == 0) {
            if (rule->relative)
                return FALSE;
            if (_wcsicmp(value, L"Start") == 0)
                rule->position = CMD_ADD_START;
            else if (_wcsicmp(value, L"End") == 0)
                rule->position = CMD_ADD_END;
            else
                return FALSE;
            rule->relative = value;
        }
        else if (_wcsicmp(key, L"Before") == 0) {
            if (rule->relative)
                return FALSE;
            rule->position = CMD_ADD_BEFORE;
            rule->relative = value;
        }
        else if (_wcsicmp(key, L"After") == 0) {
            if (rule->relative)
                return FALSE;
            rule->position = CMD_ADD_AFTER;
            rule->relative = value;
        }
        else if (_wcsicmp(key, L"Occurrences") == 0) {
            if (seen & CMD_SEEN_OCCURRENCES)
                return FALSE;
            if (_wcsicmp(value, L"First") == 0)
                rule->occurrences_first = TRUE;
            else if (_wcsicmp(value, L"All") != 0)
                return FALSE;
            seen |= CMD_SEEN_OCCURRENCES;
        }
        else if (_wcsicmp(key, L"Duplicate") == 0) {
            if (seen & CMD_SEEN_DUPLICATE)
                return FALSE;
            if (_wcsicmp(value, L"Allow") == 0)
                rule->duplicate_allow = TRUE;
            else if (_wcsicmp(value, L"Skip") != 0)
                return FALSE;
            seen |= CMD_SEEN_DUPLICATE;
        }
        else {
            return FALSE;
        }
    }

    if (rule->disabled)
        return rule->id && rule->action == CMD_ACTION_NONE;

    if (rule->action == CMD_ACTION_NONE)
        return FALSE;
    if (rule->action == CMD_ACTION_REPLACE && !rule->replacement)
        return FALSE;
    if (rule->action != CMD_ACTION_REPLACE && rule->replacement)
        return FALSE;
    if (rule->action != CMD_ACTION_ADD && rule->relative)
        return FALSE;
    if (rule->occurrences_first &&
            rule->action != CMD_ACTION_REMOVE &&
            rule->action != CMD_ACTION_REPLACE)
        return FALSE;
    if (rule->duplicate_allow && rule->action != CMD_ACTION_ADD)
        return FALSE;

    for (index = 0; index < rule->condition_count; ++index) {
        WCHAR* condition = rule->conditions[index];
        if ((_wcsnicmp(condition, L"InputArgCount", 13) == 0 &&
                !CmdLine_ParseCountCondition(
                    condition, L"InputArgCount", 0, &unused)) ||
            (_wcsnicmp(condition, L"ArgCount", 8) == 0 &&
                !CmdLine_ParseCountCondition(
                    condition, L"ArgCount", 0, &unused)))
            return FALSE;
    }
    for (index = 0; index < rule->skip_count; ++index) {
        WCHAR* condition = rule->skips[index];
        if ((_wcsnicmp(condition, L"InputArgCount", 13) == 0 &&
                !CmdLine_ParseCountCondition(
                    condition, L"InputArgCount", 0, &unused)) ||
            (_wcsnicmp(condition, L"ArgCount", 8) == 0 &&
                !CmdLine_ParseCountCondition(
                    condition, L"ArgCount", 0, &unused)))
            return FALSE;
    }

    if (!rule->explicit_order)
        rule->order = CmdLine_DefaultOrder(rule->action);

    return TRUE;
}

static WCHAR* CmdLine_DecodeArgument(
    const WCHAR* text, ULONG start, ULONG end)
{
    WCHAR* decoded;
    ULONG read = start;
    ULONG write = 0;
    BOOLEAN quoted = FALSE;

    decoded = LocalAlloc(LMEM_FIXED, (end - start + 1) * sizeof(WCHAR));
    if (!decoded)
        return NULL;

    while (read < end) {
        ULONG slashes = 0;

        while (read < end && text[read] == L'\\') {
            ++slashes;
            ++read;
        }

        if (read < end && text[read] == L'"') {
            ULONG i;
            for (i = 0; i < slashes / 2; ++i)
                decoded[write++] = L'\\';

            if (slashes & 1) {
                decoded[write++] = L'"';
            }
            else if (quoted && read + 1 < end && text[read + 1] == L'"') {
                decoded[write++] = L'"';
                ++read;
            }
            else {
                quoted = !quoted;
            }
            ++read;
            continue;
        }

        while (slashes--)
            decoded[write++] = L'\\';

        if (read < end)
            decoded[write++] = text[read++];
    }

    decoded[write] = L'\0';
    return decoded;
}

static void CmdLine_FreeArguments(CMD_STATE* state)
{
    ULONG i;

    if (!state || !state->args)
        return;

    for (i = 0; i < state->count; ++i) {
        if (state->args[i].value)
            LocalFree(state->args[i].value);
    }

    LocalFree(state->args);
    state->args = NULL;
    state->count = 0;
}

static BOOLEAN CmdLine_ParseArguments(CMD_STATE* state)
{
    ULONG length;
    ULONG pos;
    ULONG capacity;

    CmdLine_FreeArguments(state);

    length = (ULONG)wcslen(state->text);
    capacity = length / 2 + 2;
    if (capacity > CMDLINE_MAX_ARGUMENTS)
        capacity = CMDLINE_MAX_ARGUMENTS;
    state->args = LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT,
        capacity * sizeof(CMD_ARGUMENT));
    if (!state->args)
        return FALSE;
    pos = 0;
    while (pos < length) {
        ULONG prefix;
        ULONG start;
        BOOLEAN quoted = FALSE;
        ULONG slashes = 0;
        CMD_ARGUMENT* arg;

        prefix = pos;
        while (pos < length && (state->text[pos] == L' ' ||
                state->text[pos] == L'\t'))
            ++pos;
        if (pos == length)
            break;
        if (state->count >= capacity)
            return FALSE;

        start = pos;
        while (pos < length) {
            WCHAR ch = state->text[pos];

            if (ch == L'\\') {
                ++slashes;
                ++pos;
                continue;
            }

            if (ch == L'"') {
                if (!(slashes & 1))
                    quoted = !quoted;
                slashes = 0;
                ++pos;
                continue;
            }

            slashes = 0;
            if (!quoted && (ch == L' ' || ch == L'\t'))
                break;
            ++pos;
        }

        arg = &state->args[state->count++];
        arg->prefix_start = prefix;
        arg->raw_start = start;
        arg->raw_end = pos;
        arg->value = CmdLine_DecodeArgument(state->text, start, pos);
        if (!arg->value)
            return FALSE;
    }

    if (!state->count)
        return FALSE;

    state->argv0_end = state->args[0].raw_end;
    return TRUE;
}

static BOOLEAN CmdLine_MatchPattern(
    const WCHAR* value, const WCHAR* pattern, CMD_MATCH mode)
{
    PATTERN* compiled;
    BOOLEAN match;

    if (!value || !pattern)
        return FALSE;

    if (mode == CMD_MATCH_EXACT)
        return wcscmp(value, pattern) == 0;

    if (mode == CMD_MATCH_TEXT)
        return wcsstr(value, pattern) != NULL;

    compiled = Pattern_Create(Dll_PoolTemp, pattern, FALSE, 0);
    if (!compiled)
        return FALSE;

    match = Pattern_Match(compiled, value, (int)wcslen(value));
    Pattern_Free(compiled);
    return match;
}

static LONG CmdLine_FindArgument(
    const CMD_STATE* state, const WCHAR* pattern, CMD_MATCH mode,
    ULONG start_index)
{
    ULONG i;

    if (start_index < 1)
        start_index = 1;

    for (i = start_index; i < state->count; ++i) {
        if (CmdLine_MatchPattern(state->args[i].value, pattern, mode))
            return (LONG)i;
    }

    return -1;
}

static BOOLEAN CmdLine_ArgumentSequencePresent(
    const CMD_STATE* state, const WCHAR* fragment, CMD_MATCH mode,
    BOOLEAN* present)
{
    CMD_STATE parsed;
    size_t fragment_len;
    ULONG start;
    ULONG part;
    BOOLEAN result = FALSE;

    *present = FALSE;
    memset(&parsed, 0, sizeof(parsed));
    fragment_len = wcslen(fragment);
    parsed.text = LocalAlloc(
        LMEM_FIXED, (fragment_len + 3) * sizeof(WCHAR));
    if (!parsed.text)
        return FALSE;

    wcscpy(parsed.text, L"x ");
    wcscat(parsed.text, fragment);
    if (!CmdLine_ParseArguments(&parsed) || parsed.count < 2)
        goto finish;

    for (start = 1; start + parsed.count - 1 <= state->count; ++start) {
        for (part = 1; part < parsed.count; ++part) {
            if (!CmdLine_MatchPattern(
                    state->args[start + part - 1].value,
                    parsed.args[part].value, mode))
                break;
        }

        if (part == parsed.count) {
            *present = TRUE;
            break;
        }
    }
    result = TRUE;

finish:
    CmdLine_FreeArguments(&parsed);
    if (parsed.text)
        LocalFree(parsed.text);
    return result;
}

static ULONG CmdLine_FragmentArgumentCount(const WCHAR* fragment)
{
    CMD_STATE parsed;
    size_t fragment_len;
    ULONG count = 0;

    memset(&parsed, 0, sizeof(parsed));
    fragment_len = wcslen(fragment);
    parsed.text = LocalAlloc(
        LMEM_FIXED, (fragment_len + 3) * sizeof(WCHAR));
    if (!parsed.text)
        return 0;

    wcscpy(parsed.text, L"x ");
    wcscat(parsed.text, fragment);
    if (CmdLine_ParseArguments(&parsed) && parsed.count > 1)
        count = parsed.count - 1;

    CmdLine_FreeArguments(&parsed);
    LocalFree(parsed.text);
    return count;
}

static BOOLEAN CmdLine_ParseCountCondition(
    const WCHAR* condition, const WCHAR* name, ULONG count,
    BOOLEAN* result)
{
    const WCHAR* op;
    const WCHAR* number;
    WCHAR* end;
    ULONG value;
    size_t name_len = wcslen(name);

    if (_wcsnicmp(condition, name, name_len) != 0)
        return FALSE;

    op = condition + name_len;
    if (*op != L'=' && *op != L'<' && *op != L'>')
        return FALSE;

    number = ((op[0] == L'<' || op[0] == L'>') && op[1] == L'=')
        ? op + 2 : op + 1;
    if (*number < L'0' || *number > L'9')
        return FALSE;
    value = wcstoul(number, &end, 10);

    if (end == number || *end)
        return FALSE;

    if (op[0] == L'=')
        *result = count == value;
    else if (op[0] == L'<' && op[1] == L'=')
        *result = count <= value;
    else if (op[0] == L'>' && op[1] == L'=')
        *result = count >= value;
    else if (op[0] == L'<')
        *result = count < value;
    else
        *result = count > value;

    return TRUE;
}

static BOOLEAN CmdLine_EvaluateCondition(
    const CMD_STATE* state, const WCHAR* condition, CMD_MATCH mode)
{
    BOOLEAN result;
    ULONG arg_count = state->count ? state->count - 1 : 0;

    if (_wcsicmp(condition, L"Empty") == 0)
        return arg_count == 0;
    if (_wcsicmp(condition, L"NotEmpty") == 0)
        return arg_count != 0;
    if (_wcsicmp(condition, L"Forced") == 0)
        return (Dll_ProcessFlags & SBIE_FLAG_FORCED_PROCESS) != 0;
    if (_wcsicmp(condition, L"PCA") == 0)
        return (Dll_ProcessFlags & SBIE_FLAG_PROCESS_IN_PCA_JOB) != 0;

    if (CmdLine_ParseCountCondition(
            condition, L"InputArgCount", state->input_count, &result))
        return result;
    if (CmdLine_ParseCountCondition(
            condition, L"ArgCount", arg_count, &result))
        return result;

    return CmdLine_FindArgument(state, condition, mode, 1) >= 0;
}

static BOOLEAN CmdLine_RuleConditionsMatch(
    const CMD_STATE* state, const CMD_RULE* rule)
{
    ULONG i;

    for (i = 0; i < rule->condition_count; ++i) {
        if (!CmdLine_EvaluateCondition(
                state, rule->conditions[i], rule->match))
            return FALSE;
    }

    for (i = 0; i < rule->skip_count; ++i) {
        if (CmdLine_EvaluateCondition(state, rule->skips[i], rule->match))
            return FALSE;
    }

    return TRUE;
}

static BOOLEAN CmdLine_ReplaceText(
    CMD_STATE* state, ULONG start, ULONG end, const WCHAR* replacement)
{
    size_t old_len;
    size_t replacement_len;
    size_t new_len;
    WCHAR* output;

    old_len = wcslen(state->text);
    replacement_len = replacement ? wcslen(replacement) : 0;
    new_len = old_len - (end - start) + replacement_len;
    if ((new_len + 1) * sizeof(WCHAR) > 0xFFFEu)
        return FALSE;

    output = LocalAlloc(LMEM_FIXED, (new_len + 1) * sizeof(WCHAR));
    if (!output)
        return FALSE;

    wmemcpy(output, state->text, start);
    if (replacement_len)
        wmemcpy(output + start, replacement, replacement_len);
    wcscpy(output + start + replacement_len, state->text + end);

    LocalFree(state->text);
    state->text = output;
    return CmdLine_ParseArguments(state);
}

static BOOLEAN CmdLine_Clear(CMD_STATE* state)
{
    return CmdLine_ReplaceText(
        state, state->argv0_end, (ULONG)wcslen(state->text), NULL);
}

static BOOLEAN CmdLine_Set(CMD_STATE* state, const WCHAR* value)
{
    size_t value_len = wcslen(value);
    WCHAR* replacement = LocalAlloc(
        LMEM_FIXED, (value_len + 2) * sizeof(WCHAR));
    BOOLEAN result;

    if (!replacement)
        return FALSE;

    replacement[0] = L' ';
    wcscpy(replacement + 1, value);
    result = CmdLine_ReplaceText(
        state, state->argv0_end, (ULONG)wcslen(state->text), replacement);
    LocalFree(replacement);
    return result;
}

static BOOLEAN CmdLine_Add(
    CMD_STATE* state, const CMD_RULE* rule, BOOLEAN* applied)
{
    BOOLEAN present;
    ULONG insert_at;
    LONG relative;
    size_t value_len;
    WCHAR* insertion;
    BOOLEAN result;

    *applied = FALSE;
    if (!rule->duplicate_allow) {
        if (!CmdLine_ArgumentSequencePresent(
                state, rule->value, rule->match, &present))
            return FALSE;
        if (present)
            return TRUE;
    }

    if (rule->position == CMD_ADD_START) {
        insert_at = state->argv0_end;
    }
    else if (rule->position == CMD_ADD_END) {
        insert_at = state->args[state->count - 1].raw_end;
    }
    else {
        relative = CmdLine_FindArgument(
            state, rule->relative, rule->match, 1);
        if (relative < 0)
            return TRUE;
        insert_at = rule->position == CMD_ADD_BEFORE
            ? state->args[relative].prefix_start
            : state->args[relative].raw_end;
    }

    value_len = wcslen(rule->value);
    insertion = LocalAlloc(LMEM_FIXED, (value_len + 2) * sizeof(WCHAR));
    if (!insertion)
        return FALSE;

    insertion[0] = L' ';
    wcscpy(insertion + 1, rule->value);
    result = CmdLine_ReplaceText(state, insert_at, insert_at, insertion);
    LocalFree(insertion);
    if (result)
        *applied = TRUE;
    return result;
}

static BOOLEAN CmdLine_RemoveOrReplace(
    CMD_STATE* state, const CMD_RULE* rule, BOOLEAN* applied)
{
    ULONG search = 1;
    ULONG replacement_count = rule->action == CMD_ACTION_REPLACE
        ? CmdLine_FragmentArgumentCount(rule->replacement) : 0;
    LONG found;

    *applied = FALSE;
    if (rule->action == CMD_ACTION_REPLACE && !replacement_count)
        return FALSE;

    while ((found = CmdLine_FindArgument(
            state, rule->value, rule->match, search)) >= 0) {
        ULONG start = rule->action == CMD_ACTION_REPLACE
            ? state->args[found].raw_start
            : state->args[found].prefix_start;
        ULONG end = state->args[found].raw_end;
        const WCHAR* replacement =
            rule->action == CMD_ACTION_REPLACE ? rule->replacement : NULL;

        if (!CmdLine_ReplaceText(state, start, end, replacement))
            return FALSE;
        *applied = TRUE;

        if (rule->occurrences_first)
            break;

        search = replacement
            ? (ULONG)found + replacement_count
            : (ULONG)found;
    }

    return TRUE;
}

static BOOLEAN CmdLine_ApplyRule(
    CMD_STATE* state, const CMD_RULE* rule, BOOLEAN* applied)
{
    if (rule->action == CMD_ACTION_CLEAR) {
        *applied = TRUE;
        return CmdLine_Clear(state);
    }
    if (rule->action == CMD_ACTION_SET) {
        *applied = TRUE;
        return CmdLine_Set(state, rule->value);
    }
    if (rule->action == CMD_ACTION_ADD)
        return CmdLine_Add(state, rule, applied);
    return CmdLine_RemoveOrReplace(state, rule, applied);
}

static BOOLEAN CmdLine_IdSeen(
    CMD_RULE* rules, ULONG count, const WCHAR* id)
{
    ULONG i;

    for (i = 0; i < count; ++i) {
        if (rules[i].id && _wcsicmp(rules[i].id, id) == 0)
            return TRUE;
    }

    return FALSE;
}

static void CmdLine_SortRules(CMD_RULE* rules, ULONG count)
{
    ULONG i;

    for (i = 1; i < count; ++i) {
        CMD_RULE current = rules[i];
        ULONG pos = i;

        while (pos && rules[pos - 1].order > current.order) {
            rules[pos] = rules[pos - 1];
            --pos;
        }
        rules[pos] = current;
    }
}

static BOOLEAN CmdLine_AddChromiumFlags(
    CMD_RULE* rules, ULONG* count)
{
    WCHAR flags[CONF_LINE_LEN];
    WCHAR* storage;
    CMD_RULE* rule;
    NTSTATUS status;

    if (Dll_ImageType != DLL_IMAGE_GOOGLE_CHROME ||
            *count >= CMDLINE_MAX_RULES)
        return TRUE;

    status = SbieApi_QueryConfAsIs(
        NULL, L"CustomChromiumFlags", 0, flags, sizeof(flags));
    if (!NT_SUCCESS(status) || !*flags)
        return TRUE;

    storage = CmdLine_Duplicate(flags);
    if (!storage)
        return FALSE;

    rule = &rules[(*count)++];
    memset(rule, 0, sizeof(*rule));
    rule->storage = storage;
    rule->selector_match = TRUE;
    rule->action = CMD_ACTION_ADD;
    rule->value = storage;
    rule->match = CMD_MATCH_PATTERN;
    rule->position = CMD_ADD_START;
    rule->order = 400;
    rule->skips[rule->skip_count++] = L"--type=*";
    return TRUE;
}

static void CmdLine_FreeRules(CMD_RULE* rules, ULONG count)
{
    ULONG i;
    for (i = 0; i < count; ++i) {
        if (rules[i].storage)
            LocalFree(rules[i].storage);
    }
}

BOOLEAN CmdLine_Build(
    RTL_USER_PROCESS_PARAMETERS* process_parms,
    UNICODE_STRING* command_line_w,
    ANSI_STRING* command_line_a)
{
    CMD_RULE rules[CMDLINE_MAX_RULES];
    CMD_RULE planned[CMDLINE_MAX_RULES];
    CMD_STATE state;
    ULONG count = 0;
    ULONG planned_count = 0;
    ULONG filtered_count = 0;
    ULONG index;
    BOOLEAN changed = FALSE;
    BOOLEAN result = FALSE;
    UNICODE_STRING unicode;
    ANSI_STRING ansi = { 0 };
    WCHAR* original_text = NULL;

    if (!process_parms || !process_parms->CommandLine.Buffer ||
            !process_parms->CommandLine.Length ||
            (process_parms->CommandLine.Length % sizeof(WCHAR)) != 0 ||
            !command_line_w || !command_line_a)
        return FALSE;

    memset(rules, 0, sizeof(rules));
    memset(planned, 0, sizeof(planned));
    memset(&state, 0, sizeof(state));

    if (!CmdLine_AddChromiumFlags(rules, &count))
        goto finish;

    for (index = 0; index < CMDLINE_MAX_RULES; ++index) {
        WCHAR buffer[CONF_LINE_LEN];
        WCHAR* storage;
        NTSTATUS status;

        if (count >= CMDLINE_MAX_RULES)
            break;

        status = SbieApi_QueryConfAsIs(
            NULL, CMDLINE_SETTING, index, buffer, sizeof(buffer));

        if (!NT_SUCCESS(status)) {
            if (status == STATUS_BUFFER_TOO_SMALL)
                continue;
            break;
        }

        storage = CmdLine_Duplicate(buffer);
        if (!storage)
            goto finish;

        if (!CmdLine_ParseRule(storage, &rules[count])) {
            LocalFree(storage);
            continue;
        }

        ++count;
    }

    for (index = 0; index < count; ++index) {
        CMD_RULE* rule = &rules[index];

        if (rule->id && CmdLine_IdSeen(planned, planned_count, rule->id))
            continue;
        if (planned_count >= CMDLINE_MAX_RULES)
            goto finish;

        planned[planned_count++] = *rule;
        rule->storage = NULL;
    }

    for (index = 0; index < planned_count; ++index) {
        if (!planned[index].disabled && planned[index].selector_match)
            planned[filtered_count++] = planned[index];
        else if (planned[index].storage)
            LocalFree(planned[index].storage);
    }
    planned_count = filtered_count;
    CmdLine_SortRules(planned, planned_count);

    if (!planned_count)
        goto finish;

    original_text = CmdLine_DuplicateLength(
        process_parms->CommandLine.Buffer,
        process_parms->CommandLine.Length / sizeof(WCHAR));
    state.text = CmdLine_Duplicate(original_text);
    if (!state.text || !CmdLine_ParseArguments(&state))
        goto finish;
    state.input_count = state.count - 1;

    for (index = 0; index < planned_count; ++index) {
        BOOLEAN applied;

        if (!CmdLine_RuleConditionsMatch(&state, &planned[index]))
            continue;
        if (!CmdLine_ApplyRule(&state, &planned[index], &applied))
            goto finish;
        if (applied)
            changed = TRUE;
        if (applied && planned[index].stop)
            break;
    }

    if (!changed ||
            wcscmp(state.text, original_text) == 0)
        goto finish;

    if ((wcslen(state.text) + 1) * sizeof(WCHAR) > 0xFFFEu)
        goto finish;

    unicode.Buffer = state.text;
    unicode.Length = (USHORT)(wcslen(state.text) * sizeof(WCHAR));
    unicode.MaximumLength = unicode.Length + sizeof(WCHAR);

    if (!NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansi, &unicode, TRUE)))
        goto finish;

    *command_line_w = unicode;
    *command_line_a = ansi;
    state.text = NULL;
    result = TRUE;

finish:
    if (state.text)
        LocalFree(state.text);
    CmdLine_FreeArguments(&state);
    CmdLine_FreeRules(rules, count);
    CmdLine_FreeRules(planned, planned_count);
    if (original_text)
        LocalFree(original_text);
    if (!result && ansi.Buffer)
        RtlFreeAnsiString(&ansi);
    return result;
}
