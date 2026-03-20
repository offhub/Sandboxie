/*
 * Copyright 2021-2024 David Xanatos, xanasoft.com
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
// Kernel
//---------------------------------------------------------------------------

//#define NOGDI
//#include <windows.h>
//#include "common/win32_ntddk.h"
#include "dll.h"
#include "obj.h"
#include <wchar.h>

#include "common/pool.h"
#include "common/map.h"

#define CONF_LINE_LEN               2000    // keep in sync with drv/conf.c
#define KERNEL_CMDLINE_SETTING      L"CustomProcessCommandLine"

#define KERNEL_CMD_ACTION_INSERT_BEFORE    0
#define KERNEL_CMD_ACTION_INSERT_AFTER     1
#define KERNEL_CMD_ACTION_REMOVE           2

//---------------------------------------------------------------------------
// Functions Prototypes
//---------------------------------------------------------------------------

typedef LPWSTR (*P_GetCommandLineW)(VOID);

typedef LPSTR (*P_GetCommandLineA)(VOID);

typedef EXECUTION_STATE (*P_SetThreadExecutionState)(EXECUTION_STATE esFlags);

typedef DWORD(*P_GetTickCount)();

typedef ULONGLONG (*P_GetTickCount64)();

typedef BOOL(*P_QueryUnbiasedInterruptTime)(PULONGLONG UnbiasedTime);

//typedef void(*P_Sleep)(DWORD dwMiSecond);

typedef DWORD(*P_SleepEx)(DWORD dwMiSecond, BOOL bAlert);

typedef BOOL (*P_QueryPerformanceCounter)(LARGE_INTEGER* lpPerformanceCount);


typedef LANGID (*P_GetUserDefaultUILanguage)();

typedef int (*P_GetUserDefaultLocaleName)(LPWSTR lpLocaleName, int cchLocaleName);

typedef int (*LCIDToLocaleName)(LCID Locale, LPWSTR lpName, int cchName, DWORD dwFlags);

typedef LCID (*P_GetUserDefaultLCID)();

typedef LANGID (*P_GetUserDefaultLangID)();

typedef int (*P_GetUserDefaultGeoName)(LPWSTR geoName, int geoNameCount);

typedef LANGID (*P_GetSystemDefaultUILanguage)();

typedef int (*P_GetSystemDefaultLocaleName)(LPWSTR lpLocaleName, int cchLocaleName);

typedef LCID (*P_GetSystemDefaultLCID)();

typedef LANGID (*P_GetSystemDefaultLangID)();

typedef BOOL (*P_GetVolumeInformationByHandleW)(HANDLE hFile, LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber,LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPWSTR  lpFileSystemNameBuffer, DWORD nFileSystemNameSize);

//typedef int (*P_GetLocaleInfoEx)(LPCWSTR lpLocaleName, LCTYPE LCType, LPWSTR lpLCData, int cchData);

//typedef int (*P_GetLocaleInfoA)(LCID Locale, LCTYPE LCType, LPSTR lpLCData, int cchData);

//typedef int (*P_GetLocaleInfoW)(LCID Locale, LCTYPE LCType, LPWSTR lpLCData, int cchData);


//---------------------------------------------------------------------------
// Variables
//---------------------------------------------------------------------------


P_GetCommandLineW				__sys_GetCommandLineW				= NULL;
P_GetCommandLineA				__sys_GetCommandLineA				= NULL;

UNICODE_STRING	Kernel_CommandLineW = { 0 };
ANSI_STRING		Kernel_CommandLineA = { 0 };

P_SetThreadExecutionState		__sys_SetThreadExecutionState		= NULL;
//P_Sleep						__sys_Sleep							= NULL;
P_SleepEx						__sys_SleepEx						= NULL;
P_GetTickCount					__sys_GetTickCount					= NULL;
P_GetTickCount64				__sys_GetTickCount64				= NULL;
P_QueryUnbiasedInterruptTime	__sys_QueryUnbiasedInterruptTime	= NULL;
P_QueryPerformanceCounter		__sys_QueryPerformanceCounter		= NULL;

P_GetUserDefaultUILanguage 		__sys_GetUserDefaultUILanguage 		= NULL;
P_GetUserDefaultLocaleName 		__sys_GetUserDefaultLocaleName 		= NULL;
P_GetUserDefaultLCID 			__sys_GetUserDefaultLCID 			= NULL;
P_GetUserDefaultLangID 			__sys_GetUserDefaultLangID 			= NULL;
P_GetUserDefaultGeoName 		__sys_GetUserDefaultGeoName 		= NULL;
P_GetSystemDefaultUILanguage 	__sys_GetSystemDefaultUILanguage 	= NULL;
P_GetSystemDefaultLocaleName 	__sys_GetSystemDefaultLocaleName 	= NULL;
P_GetSystemDefaultLCID 			__sys_GetSystemDefaultLCID 			= NULL;
P_GetSystemDefaultLangID 		__sys_GetSystemDefaultLangID 		= NULL;
P_GetVolumeInformationByHandleW __sys_GetVolumeInformationByHandleW = NULL;

LCID			Kernel_CustomLCID = 0;

extern POOL* Dll_Pool;

static HASH_MAP Kernel_DiskSN;
static CRITICAL_SECTION Kernel_DiskSN_CritSec;
static ULONG64 Dll_FirstGetTickCountValue = 0;
//---------------------------------------------------------------------------
// Functions
//---------------------------------------------------------------------------

static LPWSTR Kernel_GetCommandLineW(VOID);

static LPSTR Kernel_GetCommandLineA(VOID);

static EXECUTION_STATE Kernel_SetThreadExecutionState(EXECUTION_STATE esFlags);

static DWORD Kernel_GetTickCount();

static ULONGLONG Kernel_GetTickCount64();

static BOOL Kernel_QueryUnbiasedInterruptTime(PULONGLONG UnbiasedTime);

//static void Kernel_Sleep(DWORD dwMiSecond); // no need hooking sleep as it internally just calls SleepEx

static DWORD Kernel_SleepEx(DWORD dwMiSecond, BOOL bAlert);

static BOOL Kernel_QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount);


static LANGID Kernel_GetUserDefaultUILanguage();

static int Kernel_GetUserDefaultLocaleName(LPWSTR lpLocaleName, int cchLocaleName);

static LCID Kernel_GetUserDefaultLCID();

static LANGID Kernel_GetUserDefaultLangID();

static int Kernel_GetUserDefaultGeoName(LPWSTR geoName, int geoNameCount);

static LANGID Kernel_GetSystemDefaultUILanguage();

static int Kernel_GetSystemDefaultLocaleName(LPWSTR lpLocaleName, int cchLocaleName);

static LCID Kernel_GetSystemDefaultLCID();

static LANGID Kernel_GetSystemDefaultLangID();

static BOOL Kernel_GetVolumeInformationByHandleW(HANDLE hFile, LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPWSTR  lpFileSystemNameBuffer, DWORD nFileSystemNameSize);

static void Kernel_TrimString(WCHAR* str);

static BOOLEAN Kernel_AppendCmdParams(WCHAR* dst, ULONG dst_count, const WCHAR* params);

static BOOLEAN Kernel_AppendListItem(WCHAR* dst, ULONG dst_count, const WCHAR* item);

static BOOLEAN Kernel_ContainsTextI(const WCHAR* str, const WCHAR* sub);

static BOOLEAN Kernel_ContainsAnyI(const WCHAR* str, const WCHAR* csv);

static void Kernel_RemoveSubstringI(WCHAR* str, const WCHAR* sub);

static void Kernel_ApplyRemoveRules(WCHAR* cmdline, const WCHAR* rules);

static BOOLEAN Kernel_ParseCmdRule(WCHAR* rule, const WCHAR* current_cmdline, WCHAR** out_params, int* out_action);

extern NTSTATUS File_GetName(
    HANDLE RootDirectory, UNICODE_STRING *ObjectName,
    WCHAR **OutTruePath, WCHAR **OutCopyPath, ULONG *OutFlags);

//---------------------------------------------------------------------------
// Command line helpers
//---------------------------------------------------------------------------


_FX void Kernel_TrimString(WCHAR* str)
{
	size_t len;
	WCHAR* src;

	if (!str)
		return;

	src = str;
	while (*src == L' ' || *src == L'\t')
		++src;

	if (src != str)
		memmove(str, src, (wcslen(src) + 1) * sizeof(WCHAR));

	len = wcslen(str);
	while (len > 0 && (str[len - 1] == L' ' || str[len - 1] == L'\t')) {
		str[len - 1] = L'\0';
		--len;
	}
}


_FX BOOLEAN Kernel_AppendCmdParams(WCHAR* dst, ULONG dst_count, const WCHAR* params)
{
	size_t dst_len;
	size_t add_len;

	if (!dst || !dst_count || !params)
		return FALSE;

	if (!*params)
		return TRUE;

	dst_len = wcslen(dst);
	add_len = wcslen(params);

	if (dst_len && dst[dst_len - 1] != L' ')
		++add_len;

	if (dst_len + add_len + 1 > dst_count)
		return FALSE;

	if (dst_len && dst[dst_len - 1] != L' ')
		wcscat(dst, L" ");

	wcscat(dst, params);
	return TRUE;
}


_FX BOOLEAN Kernel_AppendListItem(WCHAR* dst, ULONG dst_count, const WCHAR* item)
{
	size_t dst_len;
	size_t add_len;

	if (!dst || !dst_count || !item || !*item)
		return FALSE;

	dst_len = wcslen(dst);
	add_len = wcslen(item);

	if (dst_len)
		++add_len; // newline separator

	if (dst_len + add_len + 1 > dst_count)
		return FALSE;

	if (dst_len)
		wcscat(dst, L"\n");

	wcscat(dst, item);
	return TRUE;
}


_FX BOOLEAN Kernel_ContainsTextI(const WCHAR* str, const WCHAR* sub)
{
	const WCHAR* p;
	size_t sub_len;

	if (!str || !sub)
		return FALSE;

	sub_len = wcslen(sub);
	if (sub_len == 0)
		return FALSE;

	for (p = str; *p; ++p) {
		size_t i;
		for (i = 0; i < sub_len; ++i) {
			WCHAR c1 = p[i];
			WCHAR c2 = sub[i];
			if (!c1)
				break;
			if (c1 >= L'A' && c1 <= L'Z')
				c1 += (WCHAR)(L'a' - L'A');
			if (c2 >= L'A' && c2 <= L'Z')
				c2 += (WCHAR)(L'a' - L'A');
			if (c1 != c2)
				break;
		}
		if (i == sub_len)
			return TRUE;
	}

	return FALSE;
}


_FX BOOLEAN Kernel_ContainsAnyI(const WCHAR* str, const WCHAR* csv)
{
	const WCHAR* p;

	if (!str || !csv || !*csv)
		return FALSE;

	p = csv;
	while (*p) {
		const WCHAR* end = wcschr(p, L',');
		WCHAR item[CONF_LINE_LEN];
		size_t len;

		if (!end)
			end = p + wcslen(p);

		len = (size_t)(end - p);
		if (len >= ARRAYSIZE(item))
			len = ARRAYSIZE(item) - 1;

		wmemcpy(item, p, len);
		item[len] = L'\0';
		Kernel_TrimString(item);

		if (*item && Kernel_ContainsTextI(str, item))
			return TRUE;

		if (!*end)
			break;

		p = end + 1;
	}

	return FALSE;
}


_FX void Kernel_RemoveSubstringI(WCHAR* str, const WCHAR* sub)
{
	size_t sub_len;

	if (!str || !sub)
		return;

	sub_len = wcslen(sub);
	if (sub_len == 0)
		return;

	while (1) {
		WCHAR* p = str;
		WCHAR* found = NULL;

		while (*p) {
			size_t i;
			for (i = 0; i < sub_len; ++i) {
				WCHAR c1 = p[i];
				WCHAR c2 = sub[i];
				if (!c1)
					break;
				if (c1 >= L'A' && c1 <= L'Z')
					c1 += (WCHAR)(L'a' - L'A');
				if (c2 >= L'A' && c2 <= L'Z')
					c2 += (WCHAR)(L'a' - L'A');
				if (c1 != c2)
					break;
			}
			if (i == sub_len) {
				found = p;
				break;
			}
			++p;
		}

		if (!found)
			break;

		memmove(found, found + sub_len, (wcslen(found + sub_len) + 1) * sizeof(WCHAR));
	}
}


_FX void Kernel_ApplyRemoveRules(WCHAR* cmdline, const WCHAR* rules)
{
	const WCHAR* p;

	if (!cmdline || !rules || !*rules)
		return;

	p = rules;
	while (*p) {
		const WCHAR* end = wcschr(p, L'\n');
		WCHAR item[CONF_LINE_LEN];
		size_t len;

		if (!end)
			end = p + wcslen(p);

		len = (size_t)(end - p);
		if (len >= ARRAYSIZE(item))
			len = ARRAYSIZE(item) - 1;

		wmemcpy(item, p, len);
		item[len] = L'\0';
		Kernel_TrimString(item);

		if (*item)
			Kernel_RemoveSubstringI(cmdline, item);

		if (!*end)
			break;

		p = end + 1;
	}

	Kernel_TrimString(cmdline);
}


_FX BOOLEAN Kernel_ParseCmdRule(WCHAR* rule, const WCHAR* current_cmdline, WCHAR** out_params, int* out_action)
{
	WCHAR* image = NULL;
	WCHAR* group = NULL;
	WCHAR* special = NULL;
	WCHAR* params = NULL;
	WCHAR* skip = NULL;
	WCHAR* onlyif = NULL;
	BOOLEAN has_action = FALSE;
	BOOLEAN action_is_remove = FALSE;
	int position = KERNEL_CMD_ACTION_INSERT_BEFORE; // default position for Insert
	WCHAR* token;

	if (!rule || !out_params || !out_action)
		return FALSE;

	token = rule;
	while (token && *token) {
		WCHAR* next = wcschr(token, L';');
		WCHAR* eq;
		WCHAR* key;
		WCHAR* val;

		if (next) {
			*next = L'\0';
			++next;
		}

		Kernel_TrimString(token);
		if (!*token) {
			token = next;
			continue;
		}

		eq = wcschr(token, L'=');
		if (!eq)
			return FALSE;

		*eq = L'\0';
		key = token;
		val = eq + 1;
		Kernel_TrimString(key);
		Kernel_TrimString(val);

		if (!*key)
			return FALSE;

		if (_wcsicmp(key, L"Image") == 0) {
			image = val;
		}
		else if (_wcsicmp(key, L"Program") == 0) {
			image = val;
		}
		else if (_wcsicmp(key, L"ProcessGroup") == 0) {
			group = val;
		}
		else if (_wcsicmp(key, L"Group") == 0) {
			group = val;
		}
		else if (_wcsicmp(key, L"SpecialImage") == 0) {
			special = val;
		}
		else if (_wcsicmp(key, L"Params") == 0) {
			params = val;
		}
		else if (_wcsicmp(key, L"Action") == 0) {
			if (_wcsicmp(val, L"Insert") == 0)
				action_is_remove = FALSE;
			else if (_wcsicmp(val, L"Remove") == 0)
				action_is_remove = TRUE;
			else
				return FALSE;
			has_action = TRUE;
		}
		else if (_wcsicmp(key, L"Position") == 0) {
			if (_wcsicmp(val, L"Before") == 0)
				position = KERNEL_CMD_ACTION_INSERT_BEFORE;
			else if (_wcsicmp(val, L"After") == 0)
				position = KERNEL_CMD_ACTION_INSERT_AFTER;
			else
				return FALSE;
		}
		else if (_wcsicmp(key, L"SkipIf") == 0) {
			skip = val;
		}
		else if (_wcsicmp(key, L"OnlyIf") == 0) {
			onlyif = val;
		}
		else {
			return FALSE;
		}

		token = next;
	}

	if (!has_action || !params || !*params)
		return FALSE;

	if ((!image || !*image) && (!group || !*group) && (!special || !*special))
		return FALSE;

	if (current_cmdline && !action_is_remove) {
		// For insert rules, always skip if Params is already present in the command line
		if (Kernel_ContainsTextI(current_cmdline, params))
			return FALSE;
	}

	if (skip && *skip && current_cmdline) {
		if (Kernel_ContainsAnyI(current_cmdline, skip))
			return FALSE;
	}

	if (onlyif && *onlyif && current_cmdline) {
		if (!Kernel_ContainsAnyI(current_cmdline, onlyif))
			return FALSE;
	}

	if (image && *image) {
		BOOLEAN negate = FALSE;
		BOOLEAN match;

		if (*image == L'!') {
			negate = TRUE;
			++image;
			Kernel_TrimString(image);
		}

		if (!*image)
			return FALSE;

		match = SbieDll_MatchImage(image, Dll_ImageName, NULL);
		if ((!negate && !match) || (negate && match))
			return FALSE;
	}

	if (group && *group) {
		if (!Config_MatchImageGroup(group, 0, Dll_ImageName, 0))
			return FALSE;
	}

	if (special && *special) {
		ULONG required_type;
		if (_wcsicmp(special, L"chrome") == 0)
			required_type = DLL_IMAGE_GOOGLE_CHROME;
		else if (_wcsicmp(special, L"firefox") == 0)
			required_type = DLL_IMAGE_MOZILLA_FIREFOX;
		else if (_wcsicmp(special, L"thunderbird") == 0)
			required_type = DLL_IMAGE_MOZILLA_THUNDERBIRD;
		else if (_wcsicmp(special, L"browser") == 0)
			required_type = DLL_IMAGE_OTHER_WEB_BROWSER;
		else if (_wcsicmp(special, L"mail") == 0)
			required_type = DLL_IMAGE_OTHER_MAIL_CLIENT;
		else if (_wcsicmp(special, L"plugin") == 0)
			required_type = DLL_IMAGE_PLUGIN_CONTAINER;
		else
			return FALSE; // unknown type label
		if (Dll_ImageType != required_type)
			return FALSE;
	}

	*out_action = action_is_remove ? KERNEL_CMD_ACTION_REMOVE : position;
	*out_params = params;
	return TRUE;
}

//---------------------------------------------------------------------------
// Kernel_Init
//---------------------------------------------------------------------------


_FX BOOLEAN Kernel_Init()
{
	HMODULE module = Dll_Kernel32;
	RTL_USER_PROCESS_PARAMETERS* ProcessParms = Proc_GetRtlUserProcessParameters();
	BOOLEAN IsFromSandboxieDir = FALSE;
	if (ProcessParms && ProcessParms->ImagePathName.Buffer) {
		// ImagePathName in the PEB may be a native NT path (\Device\...) or a DOS path (C:\...)
		// depending on how the process was started, so check both home paths.
		if (Dll_HomeNtPath && Dll_HomeNtPathLen > 0) {
			ULONG len = Dll_HomeNtPathLen;
			if (_wcsnicmp(ProcessParms->ImagePathName.Buffer, Dll_HomeNtPath, len) == 0 &&
				(ProcessParms->ImagePathName.Buffer[len] == L'\\' || ProcessParms->ImagePathName.Buffer[len] == L'\0'))
				IsFromSandboxieDir = TRUE;
		}
		if (!IsFromSandboxieDir && Dll_HomeDosPath && *Dll_HomeDosPath) {
			ULONG len = (ULONG)wcslen(Dll_HomeDosPath);
			if (_wcsnicmp(ProcessParms->ImagePathName.Buffer, Dll_HomeDosPath, len) == 0 &&
				(ProcessParms->ImagePathName.Buffer[len] == L'\\' || ProcessParms->ImagePathName.Buffer[len] == L'\0'))
				IsFromSandboxieDir = TRUE;
		}
	}
	WCHAR BeforeParams[CONF_LINE_LEN] = { 0 };
	WCHAR AfterParams[CONF_LINE_LEN] = { 0 };
	WCHAR RemoveParams[CONF_LINE_LEN] = { 0 };
	BOOLEAN HasCmdRewrite = FALSE;

	ULONG index = 0;
	const WCHAR* current_cmdline = (ProcessParms && ProcessParms->CommandLine.Buffer)
		? ProcessParms->CommandLine.Buffer : NULL;
	if (!IsFromSandboxieDir) {
		while (1) {
			WCHAR Rule[CONF_LINE_LEN];
			NTSTATUS status = SbieApi_QueryConfAsIs(NULL, KERNEL_CMDLINE_SETTING, index, Rule, ARRAYSIZE(Rule));
			WCHAR* RuleParams = NULL;
			int Action = KERNEL_CMD_ACTION_INSERT_BEFORE;

			++index;
			if (NT_SUCCESS(status)) {
				if (Kernel_ParseCmdRule(Rule, current_cmdline, &RuleParams, &Action)) {
					BOOLEAN ok = FALSE;
					if (Action == KERNEL_CMD_ACTION_INSERT_BEFORE)
						ok = Kernel_AppendCmdParams(BeforeParams, ARRAYSIZE(BeforeParams), RuleParams);
					else if (Action == KERNEL_CMD_ACTION_INSERT_AFTER)
						ok = Kernel_AppendCmdParams(AfterParams, ARRAYSIZE(AfterParams), RuleParams);
					else if (Action == KERNEL_CMD_ACTION_REMOVE)
						ok = Kernel_AppendListItem(RemoveParams, ARRAYSIZE(RemoveParams), RuleParams);

					if (ok)
						HasCmdRewrite = TRUE;
				}
			}
			else if (status != STATUS_BUFFER_TOO_SMALL)
				break;
		}
	}

	if (Dll_ImageType == DLL_IMAGE_GOOGLE_CHROME) {
		if (ProcessParms && ProcessParms->CommandLine.Buffer &&
			!wcsstr(ProcessParms->CommandLine.Buffer, L" --type=")) { // don't add flags to child processes

			NTSTATUS status;
			WCHAR CustomChromiumFlags[CONF_LINE_LEN];
			status = SbieApi_QueryConfAsIs(NULL, L"CustomChromiumFlags", 0, CustomChromiumFlags, ARRAYSIZE(CustomChromiumFlags));
			if (NT_SUCCESS(status)) {
				if (Kernel_AppendCmdParams(BeforeParams, ARRAYSIZE(BeforeParams), CustomChromiumFlags))
					HasCmdRewrite = TRUE;
			}
		}
	}

	if (HasCmdRewrite && ProcessParms && ProcessParms->CommandLine.Buffer) {

		const WCHAR* lpCommandLine = ProcessParms->CommandLine.Buffer;
		const WCHAR* lpArguments = SbieDll_FindArgumentEnd(lpCommandLine);
		size_t cmd_len;
		size_t before_len = wcslen(BeforeParams);
		size_t after_len = wcslen(AfterParams);

		if (lpArguments == NULL)
			lpArguments = wcsrchr(lpCommandLine, L'\0');

		cmd_len = wcslen(lpCommandLine) + before_len + after_len + 8;

		Kernel_CommandLineW.MaximumLength = (USHORT)min(cmd_len * sizeof(WCHAR), 0xFFFEu);
		Kernel_CommandLineW.Buffer = LocalAlloc(LMEM_FIXED, cmd_len * sizeof(WCHAR));

		if (Kernel_CommandLineW.Buffer) {
			size_t arg0_len = (size_t)(lpArguments - lpCommandLine);

			wmemcpy(Kernel_CommandLineW.Buffer, lpCommandLine, arg0_len);
			Kernel_CommandLineW.Buffer[arg0_len] = L'\0';

			if (before_len) {
				if (arg0_len && Kernel_CommandLineW.Buffer[arg0_len - 1] != L' ')
					wcscat(Kernel_CommandLineW.Buffer, L" ");
				wcscat(Kernel_CommandLineW.Buffer, BeforeParams);
			}

			wcscat(Kernel_CommandLineW.Buffer, lpArguments);

			if (after_len) {
				size_t cur_len = wcslen(Kernel_CommandLineW.Buffer);
				if (cur_len && Kernel_CommandLineW.Buffer[cur_len - 1] != L' ')
					wcscat(Kernel_CommandLineW.Buffer, L" ");
				wcscat(Kernel_CommandLineW.Buffer, AfterParams);
			}

			if (RemoveParams[0])
				Kernel_ApplyRemoveRules(Kernel_CommandLineW.Buffer, RemoveParams);

			Kernel_CommandLineW.Length = (USHORT)min(wcslen(Kernel_CommandLineW.Buffer) * sizeof(WCHAR), 0xFFFEu);
			RtlUnicodeStringToAnsiString(&Kernel_CommandLineA, &Kernel_CommandLineW, TRUE);

			// Also update the PEB so the UI and tools reading it directly see the modified command line
			ProcessParms->CommandLine.Buffer = Kernel_CommandLineW.Buffer;
			ProcessParms->CommandLine.Length = Kernel_CommandLineW.Length;
			ProcessParms->CommandLine.MaximumLength = Kernel_CommandLineW.MaximumLength;

			void* GetCommandLineW = GetProcAddress(Dll_KernelBase ? Dll_KernelBase : Dll_Kernel32, "GetCommandLineW");
			SBIEDLL_HOOK(Kernel_, GetCommandLineW);

			void* GetCommandLineA = GetProcAddress(Dll_KernelBase ? Dll_KernelBase : Dll_Kernel32, "GetCommandLineA");
			SBIEDLL_HOOK(Kernel_, GetCommandLineA);
		}
	}

	if (SbieApi_QueryConfBool(NULL, L"BlockInterferePower", FALSE)) {

        SBIEDLL_HOOK(Kernel_, SetThreadExecutionState);
    }

	if (SbieApi_QueryConfBool(NULL, L"UseChangeSpeed", FALSE)) {

		SBIEDLL_HOOK(Kernel_, GetTickCount);
		Dll_FirstGetTickCountValue = __sys_GetTickCount();

		void* GetTickCount64 = GetProcAddress(Dll_KernelBase ? Dll_KernelBase : Dll_Kernel32, "GetTickCount64");
		if (GetTickCount64) {
			SBIEDLL_HOOK(Kernel_, GetTickCount64) 
		}
		void* QueryUnbiasedInterruptTime = GetProcAddress(Dll_KernelBase ? Dll_KernelBase : Dll_Kernel32, "QueryUnbiasedInterruptTime");
		if (QueryUnbiasedInterruptTime) {
			SBIEDLL_HOOK(Kernel_, QueryUnbiasedInterruptTime);
		}
		SBIEDLL_HOOK(Kernel_, QueryPerformanceCounter);
		//SBIEDLL_HOOK(Kernel_, Sleep);
		SBIEDLL_HOOK(Kernel_, SleepEx);	
	}

	Kernel_CustomLCID = (LCID)SbieApi_QueryConfNumber(NULL, L"CustomLCID", 0); // use 1033 for en-US
	if (Kernel_CustomLCID) {
	
		SBIEDLL_HOOK(Kernel_, GetUserDefaultUILanguage);
		void* GetUserDefaultLocaleName = GetProcAddress(Dll_KernelBase ? Dll_KernelBase : Dll_Kernel32, "GetUserDefaultLocaleName");
		if (GetUserDefaultLocaleName) {
			SBIEDLL_HOOK(Kernel_, GetUserDefaultLocaleName);
		}
		SBIEDLL_HOOK(Kernel_, GetUserDefaultLCID);
		SBIEDLL_HOOK(Kernel_, GetUserDefaultLangID);
		void* GetUserDefaultGeoName = GetProcAddress(Dll_KernelBase ? Dll_KernelBase : Dll_Kernel32, "GetUserDefaultGeoName");
		if (GetUserDefaultGeoName) {
			SBIEDLL_HOOK(Kernel_, GetUserDefaultGeoName);
		}
		SBIEDLL_HOOK(Kernel_, GetSystemDefaultUILanguage);
		void* GetSystemDefaultLocaleName = GetProcAddress(Dll_KernelBase ? Dll_KernelBase : Dll_Kernel32, "GetSystemDefaultLocaleName");
		if (GetSystemDefaultLocaleName) {
			SBIEDLL_HOOK(Kernel_, GetSystemDefaultLocaleName);
		}
		SBIEDLL_HOOK(Kernel_, GetSystemDefaultLCID);
		SBIEDLL_HOOK(Kernel_, GetSystemDefaultLangID);
	}

	if (SbieApi_QueryConfBool(NULL, L"HideDiskSerialNumber", FALSE)) {

		InitializeCriticalSection(&Kernel_DiskSN_CritSec);
		map_init(&Kernel_DiskSN, Dll_Pool);

		void* GetVolumeInformationByHandleW = GetProcAddress(Dll_KernelBase ? Dll_KernelBase : Dll_Kernel32, "GetVolumeInformationByHandleW");
		if (GetVolumeInformationByHandleW) {
			SBIEDLL_HOOK(Kernel_, GetVolumeInformationByHandleW);
		}
	}
	return TRUE;
}


//---------------------------------------------------------------------------
// Kernel_GetCommandLineW
//---------------------------------------------------------------------------


_FX LPWSTR Kernel_GetCommandLineW(VOID)
{
	return Kernel_CommandLineW.Buffer;
	//return __sys_GetCommandLineW();
}


//---------------------------------------------------------------------------
// Kernel_GetCommandLineA
//---------------------------------------------------------------------------


_FX LPSTR Kernel_GetCommandLineA(VOID)
{
	return Kernel_CommandLineA.Buffer;
	//return __sys_GetCommandLineA();
}


//---------------------------------------------------------------------------
// Kernel_SetThreadExecutionState
//---------------------------------------------------------------------------


_FX EXECUTION_STATE Kernel_SetThreadExecutionState(EXECUTION_STATE esFlags) 
{
	SetLastError(ERROR_ACCESS_DENIED);
	return 0;
	//return __sys_SetThreadExecutionState(esFlags);
}


//---------------------------------------------------------------------------
// Kernel_GetTickCount
//---------------------------------------------------------------------------


_FX DWORD Kernel_GetTickCount() 
{
	ULONG add = SbieApi_QueryConfNumber(NULL, L"AddTickSpeed", 1);
	ULONG low = SbieApi_QueryConfNumber(NULL, L"LowTickSpeed", 1);
	ULONG64 count = __sys_GetTickCount();
	
	if(add != 0 && low != 0) {
		count = Dll_FirstGetTickCountValue + (count - Dll_FirstGetTickCountValue) * add / low; // multi
	}

	return (DWORD)count;
}


//---------------------------------------------------------------------------
// Kernel_GetTickCount64
//---------------------------------------------------------------------------


_FX ULONGLONG Kernel_GetTickCount64() 
{
	ULONG add = SbieApi_QueryConfNumber(NULL, L"AddTickSpeed", 1);
	ULONG low = SbieApi_QueryConfNumber(NULL, L"LowTickSpeed", 1);
	if (add != 0 && low != 0)
		return __sys_GetTickCount64() * add / low;
	return __sys_GetTickCount64() * add;
}


//---------------------------------------------------------------------------
// Kernel_QueryUnbiasedInterruptTime
//---------------------------------------------------------------------------


_FX BOOL Kernel_QueryUnbiasedInterruptTime(PULONGLONG UnbiasedTime)
{
	BOOL rtn = __sys_QueryUnbiasedInterruptTime(UnbiasedTime);
	ULONG add = SbieApi_QueryConfNumber(NULL, L"AddTickSpeed", 1);
	ULONG low = SbieApi_QueryConfNumber(NULL, L"LowTickSpeed", 1);
	if (add != 0 && low != 0)
		*UnbiasedTime = *UnbiasedTime * add / low;
	else
		*UnbiasedTime *= add;
	return rtn;
}


//---------------------------------------------------------------------------
// Kernel_SleepEx
//---------------------------------------------------------------------------


_FX DWORD Kernel_SleepEx(DWORD dwMiSecond, BOOL bAlert) 
{
	ULONG add = SbieApi_QueryConfNumber(NULL, L"AddSleepSpeed", 1);
	ULONG low = SbieApi_QueryConfNumber(NULL, L"LowSleepSpeed", 1);
	if (add != 0 && low != 0)
		return __sys_SleepEx(dwMiSecond * low / add, bAlert);
	return __sys_SleepEx(dwMiSecond, bAlert);
}


//---------------------------------------------------------------------------
// Kernel_QueryPerformanceCounter
//---------------------------------------------------------------------------


_FX BOOL Kernel_QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount)
{
	BOOL rtn = __sys_QueryPerformanceCounter(lpPerformanceCount);
	ULONG add = SbieApi_QueryConfNumber(NULL, L"AddTickSpeed", 1);
	ULONG low = SbieApi_QueryConfNumber(NULL, L"LowTickSpeed", 1);
	if (add != 0 && low != 0)
		lpPerformanceCount->QuadPart = lpPerformanceCount->QuadPart * add / low;
	return rtn;
}


//---------------------------------------------------------------------------
// Kernel_GetUserDefaultUILanguage
//---------------------------------------------------------------------------


_FX LANGID Kernel_GetUserDefaultUILanguage() 
{
	return (LANGID)Kernel_CustomLCID;
}


//---------------------------------------------------------------------------
// Kernel_GetUserDefaultLocaleName
//---------------------------------------------------------------------------


_FX int Kernel_GetUserDefaultLocaleName(LPWSTR lpLocaleName, int cchLocaleName) 
{
	return Kernel_GetSystemDefaultLocaleName(lpLocaleName, cchLocaleName);
}


//---------------------------------------------------------------------------
// Kernel_GetUserDefaultLCID
//---------------------------------------------------------------------------


_FX LCID Kernel_GetUserDefaultLCID() 
{
	return Kernel_CustomLCID;
}


//---------------------------------------------------------------------------
// Kernel_GetUserDefaultLangID
//---------------------------------------------------------------------------


_FX LANGID Kernel_GetUserDefaultLangID() 
{
	return (LANGID)Kernel_CustomLCID;
}


//---------------------------------------------------------------------------
// Kernel_GetUserDefaultGeoName
//---------------------------------------------------------------------------


_FX int Kernel_GetUserDefaultGeoName(LPWSTR geoName, int geoNameCount) 
{
	WCHAR LocaleName[32];
	int cchLocaleName = Kernel_GetSystemDefaultLocaleName(LocaleName, ARRAYSIZE(LocaleName));
	if (cchLocaleName > 0) {
		WCHAR* Name = wcsrchr(LocaleName, L'-');
		if (Name) {
			int len = (int)wcslen(Name++);
			if (geoNameCount >= len) {
				wcscpy(geoName, Name);
			}
			return len;
		}
	}
	return 0;
}


//---------------------------------------------------------------------------
// Kernel_GetSystemDefaultUILanguage
//---------------------------------------------------------------------------


_FX LANGID Kernel_GetSystemDefaultUILanguage() 
{
	return (LANGID)Kernel_CustomLCID;
}


//---------------------------------------------------------------------------
// Kernel_GetSystemDefaultLocaleName
//---------------------------------------------------------------------------


_FX int Kernel_GetSystemDefaultLocaleName(LPWSTR lpLocaleName, int cchLocaleName) 
{
	LCIDToLocaleName ltln = (LCIDToLocaleName)GetProcAddress(Dll_KernelBase ? Dll_KernelBase : Dll_Kernel32, "LCIDToLocaleName");
	if (ltln) {
		int ret = ltln(Kernel_CustomLCID, lpLocaleName, cchLocaleName, 0);
		if (ret) 
			return ret;
	}
	
	// on failure fallback to en_US
	if (cchLocaleName >= 6) {
		wcscpy(lpLocaleName, L"en_US");
		return 6;
	}
	return 0;
}


//---------------------------------------------------------------------------
// Kernel_GetSystemDefaultLCID
//---------------------------------------------------------------------------


_FX LCID Kernel_GetSystemDefaultLCID() 
{
	return Kernel_CustomLCID;
}


//---------------------------------------------------------------------------
// Kernel_GetSystemDefaultLangID
//---------------------------------------------------------------------------


_FX LANGID Kernel_GetSystemDefaultLangID() 
{
	return (LANGID)Kernel_CustomLCID;
}


//----------------------------------------------------------------------------
//Kernel_GetVolumeInformationByHandleW
//----------------------------------------------------------------------------

BOOL hex_string_to_uint8_array(const wchar_t* str, unsigned char* output_array, size_t* output_length, BOOL swap_bytes);

_FX BOOL Kernel_GetVolumeInformationByHandleW(HANDLE hFile, LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber,LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPWSTR  lpFileSystemNameBuffer, DWORD nFileSystemNameSize) 
{
	DWORD ourSerialNumber = 0;

	BOOL rtn = __sys_GetVolumeInformationByHandleW(hFile, lpVolumeNameBuffer, nVolumeNameSize, &ourSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize);
	if (lpVolumeSerialNumber != NULL) {

        EnterCriticalSection(&Kernel_DiskSN_CritSec);

		void* key = (void*)ourSerialNumber;

		DWORD* lpCachedSerialNumber = map_get(&Kernel_DiskSN, key);
		if (lpCachedSerialNumber)
			*lpVolumeSerialNumber = *lpCachedSerialNumber;
		else
		{
			WCHAR DeviceName[MAX_PATH] = { 0 };

			ULONG LastError;
			THREAD_DATA* TlsData;

			TlsData = Dll_GetTlsData(&LastError);
			Dll_PushTlsNameBuffer(TlsData);

			WCHAR* TruePath, * CopyPath;
			File_GetName(hFile, NULL, &TruePath, &CopyPath, NULL);

			if (_wcsnicmp(TruePath, L"\\Device\\", 8) == 0)
			{
				WCHAR* End = wcschr(TruePath + 8, L'\\');
				if(!End) End = wcschr(TruePath + 8, L'\0');
				wcsncpy(DeviceName, TruePath + 8, End - (TruePath + 8));
			}

			Dll_PopTlsNameBuffer(TlsData);
			SetLastError(LastError);

			if(*DeviceName == 0)
				*lpVolumeSerialNumber = Dll_rand();
			else
			{
				WCHAR Value[30] = { 0 };
				SbieDll_GetSettingsForName(NULL, DeviceName, L"DiskSerialNumber", Value, sizeof(Value), L"");
				DWORD value_buf = 0;;
				size_t value_len = sizeof(value_buf);
				if (hex_string_to_uint8_array(Value, &value_buf, &value_len, TRUE))
					*lpVolumeSerialNumber = value_buf;
				else 
					*lpVolumeSerialNumber = Dll_rand();
			}
			
			map_insert(&Kernel_DiskSN, key, lpVolumeSerialNumber, sizeof(DWORD));
		}

		LeaveCriticalSection(&Kernel_DiskSN_CritSec);
	}
	return rtn;
}
