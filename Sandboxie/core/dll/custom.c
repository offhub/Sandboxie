/*
 * Copyright 2004-2020 Sandboxie Holdings, LLC 
 * Copyright 2020-2023 David Xanatos, xanasoft.com
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
// Customize and Prepare the Sandbox to Run Programs
//---------------------------------------------------------------------------


#include "dll.h"
#include "common/my_version.h"
#include <stdio.h>
#include <objbase.h>

#include "common/pool.h"
#include "common/map.h"

//---------------------------------------------------------------------------
// Functions
//---------------------------------------------------------------------------


BOOLEAN         CustomizeSandbox(void);

static UCHAR    GetSetCustomLevel(UCHAR SetLevel);

static BOOLEAN  Custom_CreateRegLinks(void);
static BOOLEAN  DisableDCOM(void);
static BOOLEAN  DisableRecycleBin(void);
static BOOLEAN  DisableWinRS(void);
static BOOLEAN  DisableWerFaultUI(void);
static BOOLEAN  EnableMsiDebugging(void);
static BOOLEAN  DisableEdgeBoost(void);
static BOOLEAN  Custom_EnableBrowseNewProcess(void);
static BOOLEAN  Custom_DisableBHOs(void);
static BOOLEAN  Custom_OpenWith(void);
static HANDLE   OpenExplorerKey(
                    HANDLE ParentKey, const WCHAR *SubkeyName, ULONG *error);
static void     DeleteShellAssocKeys(ULONG Wow64);
static void     AutoExec(void);
static BOOLEAN  Custom_ProductID(void);


//---------------------------------------------------------------------------
// Variables
//---------------------------------------------------------------------------


static HANDLE AutoExecHKey = NULL;

static const WCHAR *Custom_PrefixHKLM = L"\\Registry\\Machine";
static const WCHAR *Custom_PrefixHKCU = L"\\Registry\\User\\Current";


//---------------------------------------------------------------------------
// CustomizeSandbox
//---------------------------------------------------------------------------


_FX BOOLEAN CustomizeSandbox(void)
{
    //
    // customize sandbox if we need to
    //

    if ((Dll_ProcessFlags & SBIE_FLAG_PRIVACY_MODE) != 0) {

        //Key_CreateBaseKeys();
        File_CreateBaseFolders();
    }

    if (GetSetCustomLevel(0) != '2') {

        Custom_CreateRegLinks();
        DisableDCOM();
        DisableRecycleBin();
        if (SbieApi_QueryConfBool(NULL, L"BlockWinRM", TRUE))
            DisableWinRS();
        DisableWerFaultUI();
        EnableMsiDebugging();
        DisableEdgeBoost();
        Custom_EnableBrowseNewProcess();
        DeleteShellAssocKeys(0);
		Custom_ProductID();
        Custom_DisableBHOs();
        if (Dll_OsBuild >= 8400) // only on win 8 and later
            Custom_OpenWith();

        GetSetCustomLevel('2');

        //
        // process user-defined AutoExec settings
        //

        if (AutoExecHKey)
            AutoExec();
    }

    //
    // finish
    //

    if (AutoExecHKey)
        NtClose(AutoExecHKey);

    return TRUE;
}


//---------------------------------------------------------------------------
// GetSetCustomLevel
//---------------------------------------------------------------------------


_FX UCHAR GetSetCustomLevel(UCHAR SetLevel)
{
    NTSTATUS status;
    UNICODE_STRING uni;
    OBJECT_ATTRIBUTES objattrs;
    KEY_VALUE_PARTIAL_INFORMATION value_info;
    ULONG len;
    WCHAR path[256];

    ULONG Wow64 = Dll_IsWin64 ? KEY_WOW64_64KEY : 0;

    if (! SetLevel) {

        //
        // open the AutoExec key, also used to indicate if this sandbox
        // has already been customized
        //

        wcscpy(path, L"\\registry\\user\\");
        wcscat(path, Dll_SidString);
        //wcscpy(path, Dll_BoxKeyPath);
        //wcscat(path, L"\\user\\current");
        wcscat(path, L"\\software\\SandboxAutoExec");

        RtlInitUnicodeString(&uni, path);

        InitializeObjectAttributes(
            &objattrs, &uni, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = Key_OpenOrCreateIfBoxed(
                        &AutoExecHKey, KEY_ALL_ACCESS | Wow64, &objattrs);
        if (status == STATUS_BAD_INITIAL_PC) {
            value_info.Data[0] = 0;
            status = STATUS_SUCCESS;

        } else if (NT_SUCCESS(status)) {

            RtlInitUnicodeString(&uni, L"");

            status = NtQueryValueKey(
                AutoExecHKey, &uni, KeyValuePartialInformation,
                &value_info, sizeof(value_info), &len);

            if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
                value_info.Data[0] = 0;
                status = STATUS_SUCCESS;
            }
        }

        if (! NT_SUCCESS(status)) {
            value_info.Data[0] = 0;
            Sbie_snwprintf(path, 256, L"%d [%08X]", -2, status);
            SbieApi_Log(2206, path);
        }

        //
        // if UseRegDeleteV2 is set, check if RegPaths.dat was loaded
        // if not it means the box was previously a V1 box,
        // hence return 0 and re run customization
        // 
        // note: DeleteShellAssocKeys deletes the sandboxie shell integration keys
        // so the existence of a RegPaths.dat in a customized box is a reliable indicator
        //

        extern BOOLEAN Key_Delete_v2;
        extern BOOLEAN Key_RegPaths_Loaded;
        if (Key_Delete_v2 && !Key_RegPaths_Loaded)
            return 0;

    } else if (AutoExecHKey) {

        //
        // set flag
        //

        value_info.Data[0] = SetLevel;

        RtlInitUnicodeString(&uni, L"");

        status = NtSetValueKey(
            AutoExecHKey, &uni, 0, REG_BINARY, &value_info.Data, 1);

        if (! NT_SUCCESS(status)) {

            Sbie_snwprintf(path, 256, L"%d [%08X]", -3, status);
            SbieApi_Log(2206, path);
        }
    }

    return value_info.Data[0];
}


//---------------------------------------------------------------------------
// Custom_CreateRegLinks
//---------------------------------------------------------------------------


_FX BOOLEAN Custom_CreateRegLinks(void)
{
    static const WCHAR *_user_current = L"\\user\\current";
    NTSTATUS status;
    WCHAR path[384];
    HKEY hkey1, hkey2;
    UNICODE_STRING uni;
    OBJECT_ATTRIBUTES objattrs;
    WCHAR err[64];

    ULONG Wow64 = Dll_IsWin64 ? KEY_WOW64_64KEY : 0;

    InitializeObjectAttributes(
        &objattrs, &uni, OBJ_CASE_INSENSITIVE, NULL, NULL);

    //
    // create \Registry\User\Current\Software\Classes key as a link
    //

    wcscpy(path, Dll_BoxKeyPath);
    wcscat(path, _user_current);
    wcscat(path, L"\\software\\classes");

    RtlInitUnicodeString(&uni, path);

    status = NtCreateKey(
        &hkey1, KEY_ALL_ACCESS | Wow64, &objattrs,
        0, NULL, REG_OPTION_CREATE_LINK, NULL);

    if (status == STATUS_OBJECT_NAME_COLLISION) {
        // key already exists, possibly indicating OpenKeyPath=*
        return TRUE;
    }

    if (status == STATUS_ACCESS_DENIED) {
        ULONG mp_flags = SbieDll_MatchPath(L'k', path);
        if (PATH_IS_OPEN(mp_flags) || PATH_IS_CLOSED(mp_flags)) {
            // ReadKeyPath=* or ClosedKeyPath=*
            return TRUE;
        }
    }

    if (! NT_SUCCESS(status)) {
        Sbie_snwprintf(err, 64, L"[11 / %08X]", status);
        SbieApi_Log(2326, err);
        return FALSE;
    }

    //
    // create \Registry\User\Current_Classes key
    //

    wcscpy(path, Dll_BoxKeyPath);
    wcscat(path, _user_current);
    wcscat(path, L"_classes");

    RtlInitUnicodeString(&uni, path);

    status = NtCreateKey(
        &hkey2, KEY_ALL_ACCESS | Wow64, &objattrs, 0, NULL, 0, NULL);

    if (NT_SUCCESS(status)) {

        NtClose(hkey2);

    } else if (status != STATUS_OBJECT_NAME_COLLISION) {

		Sbie_snwprintf(err, 64, L"[22 / %08X]", status);
        SbieApi_Log(2326, err);
        NtClose(hkey1);
        return FALSE;
    }

    //
    // point the first key at the second key
    //

    RtlInitUnicodeString(&uni, L"SymbolicLinkValue");

    status = NtSetValueKey(
        hkey1, &uni, 0, REG_LINK, path, wcslen(path) * sizeof(WCHAR));

    NtClose(hkey1);

    if (! NT_SUCCESS(status)) {
		Sbie_snwprintf(err, 64, L"[33 / %08X]", status);
        SbieApi_Log(2326, err);
    }

    return TRUE;
}


//---------------------------------------------------------------------------
// DisableDCOM
//---------------------------------------------------------------------------


_FX BOOLEAN DisableDCOM(void)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    HANDLE handle;
    WCHAR err[64];

    ULONG Wow64 = Dll_IsWin64 ? KEY_WOW64_64KEY : 0;

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);

    //
    // disable DCOM
    //

    RtlInitUnicodeString(&objname,
        L"\\registry\\machine\\software\\microsoft\\ole");

    status = Key_OpenIfBoxed(&handle, KEY_ALL_ACCESS | Wow64, &objattrs);
    if (! NT_SUCCESS(status)) {

        if (status != STATUS_BAD_INITIAL_PC &&
            status != STATUS_OBJECT_NAME_NOT_FOUND) {

			Sbie_snwprintf(err, 64, L"[21 / %08X]", status);
            SbieApi_Log(2309, err);
        }

    } else {

        static WCHAR no[2] = { L'N', L'\0' };
        RtlInitUnicodeString(&objname, L"EnableDCOM");
        status = NtSetValueKey(handle, &objname, 0, REG_SZ, &no, sizeof(no));
        if (! NT_SUCCESS(status)) {
			Sbie_snwprintf(err, 64, L"[22 / %08X]", status);
            SbieApi_Log(2309, err);
        }

        NtClose(handle);
    }

    return TRUE;
}


//---------------------------------------------------------------------------
// DisableWinRS
//
// WinRM/WinRS allows a sandboxed app to run any command in the host.  Disabling AllowNegotiate is one of the ways we
// block WinRS from running in the sandbox.
//---------------------------------------------------------------------------


_FX BOOLEAN DisableWinRS(void)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING uni;
    HANDLE hKeyRoot;
    HANDLE hKeyWinRM;
    HANDLE hKeyWinRMClient;

    // Open HKLM
    RtlInitUnicodeString(&uni, Custom_PrefixHKLM);
    InitializeObjectAttributes(&objattrs, &uni, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (NtOpenKey(&hKeyRoot, KEY_READ, &objattrs) == STATUS_SUCCESS)
    {
        // open/create WinRM parent key
        RtlInitUnicodeString(&uni, L"software\\policies\\microsoft\\windows\\WinRM");
        InitializeObjectAttributes(&objattrs, &uni, OBJ_CASE_INSENSITIVE, hKeyRoot, NULL);
        if (Key_OpenOrCreateIfBoxed(&hKeyWinRM, KEY_ALL_ACCESS, &objattrs) == STATUS_SUCCESS)
        {
            // open/create WinRM Client key
            RtlInitUnicodeString(&uni, L"Client");
            InitializeObjectAttributes(&objattrs, &uni, OBJ_CASE_INSENSITIVE, hKeyWinRM, NULL);
            if (Key_OpenOrCreateIfBoxed(&hKeyWinRMClient, KEY_ALL_ACCESS, &objattrs) == STATUS_SUCCESS)
            {
                // set AllowNegotiate = 0
                ULONG zero = 0;
                RtlInitUnicodeString(&uni, L"AllowNegotiate");
                status = NtSetValueKey(hKeyWinRMClient, &uni, 0, REG_DWORD, &zero, sizeof(zero));
                NtClose(hKeyWinRMClient);
            }
            NtClose(hKeyWinRM);
        }
        NtClose(hKeyRoot);
    }

    return TRUE;
}


//---------------------------------------------------------------------------
// EnableMsiDebugging
//
// Enable Msi Server debug output
//---------------------------------------------------------------------------


_FX BOOLEAN EnableMsiDebugging(void)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING uni;
    HANDLE hKeyRoot;
    HANDLE hKeyMSI;
    HANDLE hKeyWin;

    // Open HKLM
    RtlInitUnicodeString(&uni, Custom_PrefixHKLM);
    InitializeObjectAttributes(&objattrs, &uni, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (NtOpenKey(&hKeyRoot, KEY_READ, &objattrs) == STATUS_SUCCESS)
    {
        // open/create WER parent key
        RtlInitUnicodeString(&uni, L"SOFTWARE\\Policies\\Microsoft\\Windows");
        InitializeObjectAttributes(&objattrs, &uni, OBJ_CASE_INSENSITIVE, hKeyRoot, NULL);
        if (Key_OpenOrCreateIfBoxed(&hKeyWin, KEY_ALL_ACCESS, &objattrs) == STATUS_SUCCESS)
        {
            // open/create WER key
            RtlInitUnicodeString(&uni, L"Installer");
            InitializeObjectAttributes(&objattrs, &uni, OBJ_CASE_INSENSITIVE, hKeyWin, NULL);
            if (Key_OpenOrCreateIfBoxed(&hKeyMSI, KEY_ALL_ACCESS, &objattrs) == STATUS_SUCCESS)
            {
                // set Debug = 7
                DWORD seven = 7;
                RtlInitUnicodeString(&uni, L"Debug");
                status = NtSetValueKey(hKeyMSI, &uni, 0, REG_DWORD, &seven, sizeof(seven));

                // set Logging = "voicewarmupx"
                static const WCHAR str[] = L"voicewarmupx";
                RtlInitUnicodeString(&uni, L"Logging");
                status = NtSetValueKey(hKeyMSI, &uni, 0, REG_SZ, (BYTE *)&str, sizeof(str));

                NtClose(hKeyMSI);
            }
            NtClose(hKeyWin);
        }
        NtClose(hKeyRoot);
    }

    return TRUE;
}


//---------------------------------------------------------------------------
// DisableEdgeBoost
//
// Disable edge startup boost
//---------------------------------------------------------------------------


_FX BOOLEAN DisableEdgeBoost(void)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING uni;
    HANDLE hKeyRoot;
    HANDLE hKeyEdge;

    // Open HKLM
    RtlInitUnicodeString(&uni, Custom_PrefixHKLM);
    InitializeObjectAttributes(&objattrs, &uni, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (NtOpenKey(&hKeyRoot, KEY_READ, &objattrs) == STATUS_SUCCESS)
    {
        // open/create WER parent key
        RtlInitUnicodeString(&uni, L"SOFTWARE\\Policies\\Microsoft\\Edge");
        InitializeObjectAttributes(&objattrs, &uni, OBJ_CASE_INSENSITIVE, hKeyRoot, NULL);
        if (Key_OpenOrCreateIfBoxed(&hKeyEdge, KEY_ALL_ACCESS, &objattrs) == STATUS_SUCCESS)
        {
            DWORD StartupBoostEnabled = 0;
            RtlInitUnicodeString(&uni, L"StartupBoostEnabled");
            status = NtSetValueKey(hKeyEdge, &uni, 0, REG_DWORD, &StartupBoostEnabled, sizeof(StartupBoostEnabled));

            NtClose(hKeyEdge);
        }
        NtClose(hKeyRoot);
    }

    return TRUE;
}


//---------------------------------------------------------------------------
// Custom_OpenWith
// 
// Replace open With dialog as on Win10 it requirers UWP support
//---------------------------------------------------------------------------


_FX BOOLEAN Custom_OpenWith(void)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING uni;
    HANDLE hKeyRoot;
    HANDLE hKey;
    HANDLE hKeyCL;

    ULONG OpenWithSize = (wcslen(Dll_BoxName) + 128) * sizeof(WCHAR);
    WCHAR* OpenWithStr = Dll_AllocTemp(OpenWithSize);
    OpenWithStr[0] = L'\"';
    wcscpy(&OpenWithStr[1], Dll_HomeDosPath);
    wcscat(OpenWithStr, L"\\" START_EXE L"\" open_with \"%1\"");
    OpenWithSize = (wcslen(OpenWithStr) + 1) * sizeof(WCHAR);

    // Open HKLM
    RtlInitUnicodeString(&uni, Custom_PrefixHKLM);
    InitializeObjectAttributes(&objattrs, &uni, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (NtOpenKey(&hKeyRoot, KEY_READ, &objattrs) == STATUS_SUCCESS)
    {
        // open Classes key
        RtlInitUnicodeString(&uni, L"SOFTWARE\\Classes");
        InitializeObjectAttributes(&objattrs, &uni, OBJ_CASE_INSENSITIVE, hKeyRoot, NULL);
        if (Key_OpenOrCreateIfBoxed(&hKeyCL, KEY_ALL_ACCESS, &objattrs) == STATUS_SUCCESS)
        {
            // open/create Undecided\shell\open\command key
            RtlInitUnicodeString(&uni, L"Undecided\\shell\\open\\command");
            InitializeObjectAttributes(&objattrs, &uni, OBJ_CASE_INSENSITIVE, hKeyCL, NULL);
            if (Key_OpenOrCreateIfBoxed(&hKey, KEY_ALL_ACCESS, &objattrs) == STATUS_SUCCESS)
            {
                // set @ = "..."
                RtlInitUnicodeString(&uni, L"");
                status = NtSetValueKey(hKey, &uni, 0, REG_SZ, (BYTE *)OpenWithStr, OpenWithSize);

                RtlInitUnicodeString(&uni, L"DelegateExecute");
                NtDeleteValueKey(hKey, &uni);

                NtClose(hKey);
            }

            // open/create Unknown\shell\Open\command key
            RtlInitUnicodeString(&uni, L"Unknown\\shell\\Open\\command");
            InitializeObjectAttributes(&objattrs, &uni, OBJ_CASE_INSENSITIVE, hKeyCL, NULL);
            if (Key_OpenOrCreateIfBoxed(&hKey, KEY_ALL_ACCESS, &objattrs) == STATUS_SUCCESS)
            {
                // set @ = "..."
                RtlInitUnicodeString(&uni, L"");
                status = NtSetValueKey(hKey, &uni, 0, REG_SZ, (BYTE *)OpenWithStr, OpenWithSize);

                RtlInitUnicodeString(&uni, L"DelegateExecute");
                NtDeleteValueKey(hKey, &uni);

                NtClose(hKey);
            }

            // open/create Unknown\shell\openas\command key
            RtlInitUnicodeString(&uni, L"Unknown\\shell\\openas\\command");
            InitializeObjectAttributes(&objattrs, &uni, OBJ_CASE_INSENSITIVE, hKeyCL, NULL);
            if (Key_OpenOrCreateIfBoxed(&hKey, KEY_ALL_ACCESS, &objattrs) == STATUS_SUCCESS)
            {
                // set @ = "..."
                RtlInitUnicodeString(&uni, L"");
                status = NtSetValueKey(hKey, &uni, 0, REG_SZ, (BYTE *)OpenWithStr, OpenWithSize);

                RtlInitUnicodeString(&uni, L"DelegateExecute");
                NtDeleteValueKey(hKey, &uni);

                NtClose(hKey);
            }

            // open/create Unknown\shell\OpenWithSetDefaultOn\command key
            RtlInitUnicodeString(&uni, L"Unknown\\shell\\OpenWithSetDefaultOn\\command");
            InitializeObjectAttributes(&objattrs, &uni, OBJ_CASE_INSENSITIVE, hKeyCL, NULL);
            if (Key_OpenOrCreateIfBoxed(&hKey, KEY_ALL_ACCESS, &objattrs) == STATUS_SUCCESS)
            {
                // set @ = "..."
                RtlInitUnicodeString(&uni, L"");
                status = NtSetValueKey(hKey, &uni, 0, REG_SZ, (BYTE *)OpenWithStr, OpenWithSize);

                RtlInitUnicodeString(&uni, L"DelegateExecute");
                NtDeleteValueKey(hKey, &uni);

                NtClose(hKey);
            }

            NtClose(hKeyCL);
        }
        NtClose(hKeyRoot);
    }

    Dll_Free(OpenWithStr);

    return TRUE;
}


//---------------------------------------------------------------------------
// DisableWerFaultUI
//
// WerFault's GUI doesn't work very well.  We will do our own in proc.c
//---------------------------------------------------------------------------


_FX BOOLEAN DisableWerFaultUI(void)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING uni;
    HANDLE hKeyRoot;
    HANDLE hKeyWER;
    HANDLE hKeyWin;
    HANDLE hKeyLocalDumps;

    // Open HKLM
    RtlInitUnicodeString(&uni, Custom_PrefixHKLM);
    InitializeObjectAttributes(&objattrs, &uni, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (NtOpenKey(&hKeyRoot, KEY_READ, &objattrs) == STATUS_SUCCESS)
    {
        // open/create WER parent key
        RtlInitUnicodeString(&uni, L"software\\microsoft\\Windows");
        InitializeObjectAttributes(&objattrs, &uni, OBJ_CASE_INSENSITIVE, hKeyRoot, NULL);
        if (Key_OpenOrCreateIfBoxed(&hKeyWin, KEY_ALL_ACCESS, &objattrs) == STATUS_SUCCESS)
        {
            // open/create WER key
            RtlInitUnicodeString(&uni, L"Windows Error Reporting");
            InitializeObjectAttributes(&objattrs, &uni, OBJ_CASE_INSENSITIVE, hKeyWin, NULL);
            if (Key_OpenOrCreateIfBoxed(&hKeyWER, KEY_ALL_ACCESS, &objattrs) == STATUS_SUCCESS)
            {
                // open/create LocalDumps key
                RtlInitUnicodeString(&uni, L"LocalDumps");
                InitializeObjectAttributes(&objattrs, &uni, OBJ_CASE_INSENSITIVE, hKeyWER, NULL);
                if (Key_OpenOrCreateIfBoxed(&hKeyLocalDumps, KEY_ALL_ACCESS, &objattrs) == STATUS_SUCCESS)
                {
                    // set DontShowUI = 1
                    DWORD one = 1;
                    RtlInitUnicodeString(&uni, L"DontShowUI");
                    status = NtSetValueKey(hKeyWER, &uni, 0, REG_DWORD, &one, sizeof(one));
                    NtClose(hKeyLocalDumps);
                }
                NtClose(hKeyWER);
            }
            NtClose(hKeyWin);
        }
        NtClose(hKeyRoot);
    }

    return TRUE;
}


//---------------------------------------------------------------------------
// DisableRecycleBin
//---------------------------------------------------------------------------


_FX BOOLEAN DisableRecycleBin(void)
{
    NTSTATUS status;
    ULONG error;
    HANDLE hkey;
    UNICODE_STRING uni;
    ULONG Wow64;
    ULONG one = 1;

    //
    // Windows 2000/XP Recycle Bin:  settings in HKEY_LOCAL_MACHINE
    //

    if (Dll_IsWin64)
        goto DisableRecycleBinSkipXP;

    error = 0;
    hkey = OpenExplorerKey(HKEY_LOCAL_MACHINE, L"BitBucket", &error);
    if (! hkey) {
        status = STATUS_UNSUCCESSFUL;

    } else if (hkey != INVALID_HANDLE_VALUE) {

        RtlInitUnicodeString(&uni, L"NukeOnDelete");
        status = NtSetValueKey(
            hkey, &uni, 0, REG_DWORD, (BYTE *)&one, sizeof(one));
        if (! NT_SUCCESS(status))
            error = 0x22;

        else {

            RtlInitUnicodeString(&uni, L"UseGlobalSettings");
            status = NtSetValueKey(
                hkey, &uni, 0, REG_DWORD, (BYTE *)&one, sizeof(one));
            if (! NT_SUCCESS(status))
                error = 0x33;
        }

        NtClose(hkey);
    }

    if (error) {
        SbieApi_Log(2311, L"[%02X / %08X]", error, status);
        return FALSE;
    }

DisableRecycleBinSkipXP:

    //
    // Windows Vista/7 Recycle Bin:  settings in HKEY_CURRENT_USER
    //

    Wow64 = Dll_IsWin64 ? KEY_WOW64_64KEY : 0;

    hkey = OpenExplorerKey(HKEY_CURRENT_USER, L"BitBucket", &error);
    if (hkey && hkey != INVALID_HANDLE_VALUE) {

        OBJECT_ATTRIBUTES objattrs;
        UNICODE_STRING objname;
        HANDLE hkey2;

        InitializeObjectAttributes(
            &objattrs, &objname, OBJ_CASE_INSENSITIVE, hkey, NULL);

        RtlInitUnicodeString(&objname, L"Volume");

        status = Key_OpenIfBoxed(&hkey2, KEY_ALL_ACCESS | Wow64, &objattrs);
        if (NT_SUCCESS(status)) {

            ULONG index = 0;
            ULONG len;
            union {
                ULONG info[64];
                KEY_BASIC_INFORMATION kbi;
            } u;
            HANDLE hkey3;

            objattrs.RootDirectory = hkey2;

            while (1) {

                status = NtEnumerateKey(
                    hkey2, index, KeyBasicInformation, &u, sizeof(u), &len);

                if (! NT_SUCCESS(status))
                    break;

                u.kbi.Name[u.kbi.NameLength / sizeof(WCHAR)] = L'\0';
                RtlInitUnicodeString(&objname, u.kbi.Name);

                status = Key_OpenIfBoxed(
                                &hkey3, KEY_ALL_ACCESS | Wow64, &objattrs);
                if (NT_SUCCESS(status)) {

                    RtlInitUnicodeString(&uni, L"NukeOnDelete");
                    status = NtSetValueKey(
                        hkey3, &uni, 0, REG_DWORD,
                        (BYTE *)&one, sizeof(one));

                    NtClose(hkey3);
                }

                ++index;
            }

            NtClose(hkey2);
        }

        NtClose(hkey);
    }

    return TRUE;
}


//---------------------------------------------------------------------------
// Custom_EnableBrowseNewProcess
//---------------------------------------------------------------------------


_FX BOOLEAN Custom_EnableBrowseNewProcess(void)
{
    static const WCHAR yes[] = L"yes";
    NTSTATUS status;
    ULONG error;
    HANDLE hkey;
    UNICODE_STRING uni;

    // BrowseNewProcess

    error = 0;
    hkey = OpenExplorerKey(HKEY_CURRENT_USER, L"BrowseNewProcess", &error);
    if (! hkey) {
        status = STATUS_UNSUCCESSFUL;

    } else if (hkey != INVALID_HANDLE_VALUE) {

        RtlInitUnicodeString(&uni, L"BrowseNewProcess");
        status = NtSetValueKey(
            hkey, &uni, 0, REG_SZ, (BYTE *)&yes, sizeof(yes));
        if (! NT_SUCCESS(status))
            error = 0x22;

        NtClose(hkey);
    }

    if (error) {
        SbieApi_Log(2312, L"[%02X / %08X]", error, status);
        return FALSE;
    }

    return TRUE;
}


//---------------------------------------------------------------------------
// Custom_DisableBHOs
//---------------------------------------------------------------------------


_FX BOOLEAN Custom_DisableBHOs(void)
{
    static const WCHAR *_prefix =
        L"\\registry\\machine\\software\\classes\\clsid\\";
    NTSTATUS status;
    OBJECT_ATTRIBUTES objattrs;
    UNICODE_STRING objname;
    HANDLE handle;
    WCHAR path[128];

    ULONG Wow64 = Dll_IsWin64 ? KEY_WOW64_64KEY : 0;

    InitializeObjectAttributes(
        &objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);

    //
    // disable a NAV plugin that prevents opening Office documents from IE
    //

    wcscpy(path, _prefix);
    wcscat(path, L"{DE1F7EEF-1851-11D3-939E-0004AC1ABE1F}");
    RtlInitUnicodeString(&objname, path);

    status = Key_OpenIfBoxed(&handle, KEY_ALL_ACCESS | Wow64, &objattrs);
    if (NT_SUCCESS(status))
        Key_MarkDeletedAndClose(handle);

    //
    // disable the Java SSVHelper Class that slows down IE
    //

    wcscpy(path, _prefix);
    wcscat(path, L"{761497BB-D6F0-462C-B6EB-D4DAF1D92D43}");
    RtlInitUnicodeString(&objname, path);

    status = Key_OpenIfBoxed(&handle, KEY_ALL_ACCESS | Wow64, &objattrs);
    if (NT_SUCCESS(status))
        Key_MarkDeletedAndClose(handle);

    wcscpy(path, _prefix);
    wcscat(path, L"{DBC80044-A445-435B-BC74-9C25C1C588A9}");
    RtlInitUnicodeString(&objname, path);

    status = Key_OpenIfBoxed(&handle, KEY_ALL_ACCESS | Wow64, &objattrs);
    if (NT_SUCCESS(status))
        Key_MarkDeletedAndClose(handle);

    wcscpy(path, _prefix);
    wcscat(path, L"{E7E6F031-17CE-4C07-BC86-EABFE594F69C}");
    RtlInitUnicodeString(&objname, path);

    status = Key_OpenIfBoxed(&handle, KEY_ALL_ACCESS | Wow64, &objattrs);
    if (NT_SUCCESS(status))
        Key_MarkDeletedAndClose(handle);

    return TRUE;
}


//---------------------------------------------------------------------------
// OpenExplorerKey
//---------------------------------------------------------------------------


_FX HANDLE OpenExplorerKey(
    HANDLE ParentKey, const WCHAR *SubkeyName, ULONG *error)
{
    static const WCHAR *_Explorer =
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer";

    NTSTATUS status;
    HANDLE HKey_Root;
    HANDLE HKey_Explorer;
    HANDLE HKey_Subkey;
    UNICODE_STRING uni;
    OBJECT_ATTRIBUTES objattrs;

    //
    // open HKLM or HKCU depending on ForCurrentUser
    //

    if (ParentKey == HKEY_LOCAL_MACHINE) {

        RtlInitUnicodeString(&uni, Custom_PrefixHKLM);

    } else if (ParentKey == HKEY_CURRENT_USER) {

        RtlInitUnicodeString(&uni, Custom_PrefixHKCU);

    } else {
        *error = 0xAA;
        return NULL;
    }

    InitializeObjectAttributes(
        &objattrs, &uni, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = Key_OpenOrCreateIfBoxed(&HKey_Root, KEY_READ, &objattrs);
    if (status == STATUS_BAD_INITIAL_PC) {
        *error = 0;
        return INVALID_HANDLE_VALUE;
    }

    if (status != STATUS_SUCCESS) {
        *error = 0x99;
        return NULL;
    }

    //
    // open Explorer parent key
    //

    RtlInitUnicodeString(&uni, _Explorer);
    InitializeObjectAttributes(
        &objattrs, &uni, OBJ_CASE_INSENSITIVE, HKey_Root, NULL);
    status = Key_OpenOrCreateIfBoxed(&HKey_Explorer, KEY_READ, &objattrs);
    if (status == STATUS_BAD_INITIAL_PC) {
        *error = 0;
        return INVALID_HANDLE_VALUE;
    }

    NtClose(HKey_Root);

    if (status != STATUS_SUCCESS) {
        *error = 0x88;
        return NULL;
    }

    //
    // open sub key below Explorer
    //

    RtlInitUnicodeString(&uni, SubkeyName);
    InitializeObjectAttributes(
        &objattrs, &uni, OBJ_CASE_INSENSITIVE, HKey_Explorer, NULL);

    status = Key_OpenOrCreateIfBoxed(&HKey_Subkey, KEY_ALL_ACCESS, &objattrs);
    if (status == STATUS_BAD_INITIAL_PC) {
        *error = 0;
        return INVALID_HANDLE_VALUE;
    }

    NtClose(HKey_Explorer);

    if (status != STATUS_SUCCESS) {
        *error = 0x77;
        return NULL;
    }

    return HKey_Subkey;
}


//---------------------------------------------------------------------------
// DeleteShellAssocKeys
//---------------------------------------------------------------------------


_FX void DeleteShellAssocKeys(ULONG Wow64)
{
    static WCHAR *_Registry = L"\\Registry\\";
    static WCHAR *subkeys[] = {
        L"Machine\\Software\\Classes",
        L"User\\Current\\Software\\Classes",
        NULL
    };
    NTSTATUS status;
    HANDLE hkey;
    WCHAR path[128];
    UNICODE_STRING uni;
    OBJECT_ATTRIBUTES objattrs;
    ULONG i;

    //
    // if running on 64-bit Windows, restart ourselves twice
    //

    if (Dll_IsWin64 && (! Wow64)) {

        DeleteShellAssocKeys(KEY_WOW64_64KEY);
        DeleteShellAssocKeys(KEY_WOW64_32KEY);
        return;
    }

    //
    // main process
    //

    for (i = 0; subkeys[i]; ++i) {

        //
        // delete (root)\*\shell\sandbox key
        //

        wcscpy(path, _Registry);
        wcscat(path, subkeys[i]);
        wcscat(path, L"\\*\\shell\\sandbox");

        RtlInitUnicodeString(&uni, path);

        InitializeObjectAttributes(
            &objattrs, &uni, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = Key_OpenIfBoxed(&hkey, KEY_ALL_ACCESS | Wow64, &objattrs);
        if (NT_SUCCESS(status)) {

            Key_NtDeleteKeyTree(hkey, TRUE);
            NtClose(hkey);
        }

        //
        // delete (root)\CompressedFolder\shell\open\ddeexec
        //

        wcscpy(path, _Registry);
        wcscat(path, subkeys[i]);
        wcscat(path, L"\\CompressedFolder\\shell\\open\\ddeexec");

        RtlInitUnicodeString(&uni, path);

        InitializeObjectAttributes(
            &objattrs, &uni, OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = Key_OpenIfBoxed(&hkey, KEY_ALL_ACCESS | Wow64, &objattrs);
        if (NT_SUCCESS(status)) {

            Key_NtDeleteKeyTree(hkey, TRUE);
            NtClose(hkey);
        }
    }
}


//---------------------------------------------------------------------------
// AutoExec
//---------------------------------------------------------------------------


_FX void AutoExec(void)
{
    NTSTATUS status;
    UNICODE_STRING uni;
    WCHAR error_str[16];
    WCHAR* buf1;
    ULONG buf_len;
    ULONG index;
    KEY_VALUE_BASIC_INFORMATION basic_info;
    ULONG len;

    //
    // query the values in the AutoExec setting
    //

    buf_len = 4096 * sizeof(WCHAR);
    buf1 = Dll_AllocTemp(buf_len);
    memzero(buf1, buf_len);

    index = 0;

    while (1) {

        status = SbieApi_QueryConfAsIs(
                            NULL, L"AutoExec", index, buf1, buf_len - 16);
        if (status != 0)
            break;

        //
        // check the key value matching the setting value
        //

        RtlInitUnicodeString(&uni, buf1);

        if (AutoExecHKey) {
            status = NtQueryValueKey(
                AutoExecHKey, &uni, KeyValueBasicInformation,
                &basic_info, sizeof(basic_info), &len);
        } else
            status = STATUS_OBJECT_NAME_NOT_FOUND;

        if (status == STATUS_OBJECT_NAME_NOT_FOUND) {

            if (AutoExecHKey)
                status = NtSetValueKey(AutoExecHKey, &uni, 0, REG_SZ, NULL, 0);
            else
                status = STATUS_SUCCESS;

            if (NT_SUCCESS(status)) {

                SbieDll_ExpandAndRunProgram(buf1);

            } else {
                Sbie_snwprintf(error_str, 16, L"%d [%08X]", index, status);
                SbieApi_Log(2206, error_str);
            }
        }

        ++index;
    }

    //
    // finish
    //

    Dll_Free(buf1);
}


//---------------------------------------------------------------------------
// SbieDll_ExpandAndRunProgram
//---------------------------------------------------------------------------


_FX BOOLEAN SbieDll_ExpandAndRunProgram(const WCHAR *Command)
{
    ULONG len;
    WCHAR *cmdline, *cmdline2;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    BOOL ok;

    //
    // expand command line
    //

    len = ExpandEnvironmentStrings(Command, NULL, 0);
    if (len == 0)
        return FALSE;

    cmdline = Dll_AllocTemp((len + 8) * sizeof(WCHAR));
    ExpandEnvironmentStrings(Command, cmdline, len);
    cmdline[len] = L'\0';

    //
    // expand sandboxie variables
    //

    len = 8192 * sizeof(WCHAR);
    cmdline2 = Dll_AllocTemp(len);

	const WCHAR* ptr1 = cmdline;
	WCHAR* ptr2 = cmdline2;
	for (;;) {
		const WCHAR* ptr = wcschr(ptr1, L'%');
		if (!ptr)
			break;
		const WCHAR* end = wcschr(ptr + 1, L'%');
		if (!end) 
			break;

		if (ptr != ptr1) { // copy static portion unless we start with a %
			ULONG length = (ULONG)(ptr - ptr1);
			wmemcpy(ptr2, ptr1, length);
			ptr2 += length;
		}
		ptr1 = end + 1;

		ULONG length = (ULONG)(end - ptr + 1);
		if (length <= 64) {
			WCHAR Var[66];
			wmemcpy(Var, ptr, length);
			Var[length] = L'\0';
			if (NT_SUCCESS(SbieApi_QueryConf(NULL, Var, CONF_JUST_EXPAND, ptr2, len - ((ptr2 - cmdline2) * sizeof(WCHAR))))) {
				if (_wcsnicmp(ptr2, L"\\Device\\", 8) == 0)
					SbieDll_TranslateNtToDosPath(ptr2);
				ptr2 += wcslen(ptr2);
				continue; // success - look for the next one
			}
		}
		
		// fallback - not found keep the %something%
		wmemcpy(ptr2, ptr, length);
		ptr2 += len;
	}
	wcscpy(ptr2, ptr1); // copy what's left

    Dll_Free(cmdline);

    //
    // execute command line
    //

    memzero(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_FORCEOFFFEEDBACK | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    memzero(&pi, sizeof(PROCESS_INFORMATION));

    ok = CreateProcess(
            NULL, cmdline2, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

    Dll_Free(cmdline2);

    if (ok) {

        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    return (ok ? TRUE : FALSE);
}


//---------------------------------------------------------------------------
// Custom_ComServer
//---------------------------------------------------------------------------


_FX void Custom_ComServer(void)
{
    //
    // the scenario of a forced COM server occurs when the COM server
    // program is forced to run in a sandbox, and it is started by COM
    // outside the sandbox in response to a COM CoCreateInstance request.
    // (typically this is Internet Explorer or Windows Media Player.)
    //
    // the program in the sandbox can't talk to COM outside the sandbox
    // to serve the request, so we need some workaround.  prior to
    // version 4, the workaround was to grant the process full access
    // to the COM IPC objects (like epmapper) and then use the
    // comserver module to simulate a COM server.  This means we talked
    // to the real COM using expected COM interfaces, in order to get
    // the url or file that has to be opened.  then we restarted the
    // process (this time without access to COM IPC objects), specifying
    // the path to the target url or file.
    //
    // in v4 this no longer works because the forced process is running
    // with untrusted privileges so the real COM will not let it sign up
    // as a COM server.  (COM returns error "out of memory" when we try
    // to use CoRegisterClassObject.)  to work around this, the comserver
    // module was moved into SbieSvc, and here we just issue a special
    // SbieDll_RunSandboxed request which runs an instance of SbieSvc
    // outside the sandbox.  SbieSvc (in file core/svc/comserver9.c) then
    // talks to real COM to get the target url or file, then it starts the
    // requested server program in the sandbox.
    //
    // the simulated COM server is implemented in core/svc/comserver9.c
    //

    WCHAR *cmdline;
    WCHAR exepath[MAX_PATH + 4];
    STARTUPINFO StartupInfo;
    PROCESS_INFORMATION ProcessInformation;

    //
    // process is probably a COM server if has both the forced process flag
    // and the protected process flag (see Ipc_IsComServer in core/drv/ipc.c)
    // we also check that several other flags are not set
    //

    const ULONG _FlagsOn    = SBIE_FLAG_FORCED_PROCESS
                            | SBIE_FLAG_PROTECTED_PROCESS;
    const ULONG _FlagsOff   = SBIE_FLAG_IMAGE_FROM_SANDBOX
                            | SBIE_FLAG_PROCESS_IN_PCA_JOB;

    if ((Dll_ProcessFlags & (_FlagsOn | _FlagsOff)) != _FlagsOn)
        return;

    //
    // check if we're running in an IEXPLORE.EXE / WMPLAYER.EXE process,
    // which was given the -Embedding command line switch
    //

    if (    Dll_ImageType != DLL_IMAGE_INTERNET_EXPLORER
        &&  Dll_ImageType != DLL_IMAGE_WINDOWS_MEDIA_PLAYER
        &&  Dll_ImageType != DLL_IMAGE_NULLSOFT_WINAMP
        &&  Dll_ImageType != DLL_IMAGE_PANDORA_KMPLAYER) {

        return;
    }

    cmdline = GetCommandLine();
    if (! cmdline)
        return;
    if (! (wcsstr(cmdline, L"/Embedding") ||
           wcsstr(cmdline, L"-Embedding")))
        return;

    //
    // we are a COM server process that was started by DcomLaunch outside
    // the sandbox but forced to run in the sandbox.  we need to run SbieSvc
    // outside the sandbox so it can talk to COM to get the invoked url,
    // and then restart the server program in the sandbox
    //

    GetModuleFileName(NULL, exepath, MAX_PATH);

    SetEnvironmentVariable(ENV_VAR_PFX L"COMSRV_EXE", exepath);
    SetEnvironmentVariable(ENV_VAR_PFX L"COMSRV_CMD", cmdline);

    memzero(&StartupInfo, sizeof(STARTUPINFO));
    StartupInfo.cb = sizeof(STARTUPINFO);
    StartupInfo.dwFlags = STARTF_FORCEOFFFEEDBACK;

    if (Proc_ImpersonateSelf(TRUE)) {

        // *COMSRV* as cmd line tells SbieSvc ProcessServer to run
        // SbieSvc SANDBOXIE_ComProxy_ComServer:BoxName
        // see also core/svc/ProcessServer.cpp
        // and      core/svc/comserver9.c
        BOOL ok = SbieDll_RunSandboxed(L"", L"*COMSRV*", L"", 0,
                                       &StartupInfo, &ProcessInformation);

        if (ok)
            WaitForSingleObject(ProcessInformation.hProcess, INFINITE);
    }

    ExitProcess(0);
}


//---------------------------------------------------------------------------
// NsiRpc_Init
//---------------------------------------------------------------------------

//#include <objbase.h>

typedef RPC_STATUS (*P_NsiRpcRegisterChangeNotification)(
    LPVOID  p1, LPVOID  p2, LPVOID  p3, LPVOID  p4, LPVOID  p5, LPVOID  p6, LPVOID  p7);

P_NsiRpcRegisterChangeNotification __sys_NsiRpcRegisterChangeNotification = NULL;

static RPC_STATUS NsiRpc_NsiRpcRegisterChangeNotification(
    LPVOID  p1, LPVOID  p2, LPVOID  p3, LPVOID  p4, LPVOID  p5, LPVOID  p6, LPVOID  p7);


_FX BOOLEAN NsiRpc_Init(HMODULE module)
{
    P_NsiRpcRegisterChangeNotification NsiRpcRegisterChangeNotification;

    NsiRpcRegisterChangeNotification = (P_NsiRpcRegisterChangeNotification)
        Ldr_GetProcAddrNew(DllName_winnsi, L"NsiRpcRegisterChangeNotification", "NsiRpcRegisterChangeNotification");

    SBIEDLL_HOOK(NsiRpc_, NsiRpcRegisterChangeNotification);

    return TRUE;
}


//  In Win8.1 WININET initialization needs to register network change events into NSI service (Network Store Interface Service).
//  The communication between guest and NSI service is via epmapper. We currently block epmapper and it blocks guest and NSI service.
//  This causes IE to pop up a dialog "Revocation information for the security certificate for this site is not available. Do you want to proceed?"
//  The fix can be either - 
//  1.  Allowing guest to talk to NSI service by fixing RpcBindingCreateW like what we did for keyiso-crypto and Smart Card service.
//      ( We don't fully know what we actually open to allow guest to talk to NSI service and if it is needed. It has been blocked. )
//  2. Hooking NsiRpcRegisterChangeNotification and silently returning NO_ERROR from the hook.
//      ( Guest app won't get Network Change notification. I am not sure if this is needed for the APP we support. )
//  We choose Fix 2 here. We may need fix 1 if see a need in the future.


_FX RPC_STATUS NsiRpc_NsiRpcRegisterChangeNotification(LPVOID  p1, LPVOID  p2, LPVOID  p3, LPVOID  p4, LPVOID  p5, LPVOID  p6, LPVOID  p7)
{
    RPC_STATUS ret = __sys_NsiRpcRegisterChangeNotification(p1, p2, p3, p4, p5, p6, p7);

    if (EPT_S_NOT_REGISTERED == ret)
    {
        ret = NO_ERROR;
    }
    return ret;
}


//---------------------------------------------------------------------------
// Nsi_Init
//---------------------------------------------------------------------------

/*typedef struct _NPI_MODULEID {
  USHORT            Length;
  NPI_MODULEID_TYPE Type;
  union {
    GUID Guid;
    LUID IfLuid;
  };
} NPI_MODULEID, *PNPI_MODULEID;*/

typedef ULONG (*P_NsiAllocateAndGetTable)(int a1, struct NPI_MODULEID* a2, unsigned int a3, void *a4, int a5, void *a6, int a7, void *a8, int a9, void *a10, int a11, DWORD *a12, int a13);  

P_NsiAllocateAndGetTable __sys_NsiAllocateAndGetTable = NULL;

static ULONG Nsi_NsiAllocateAndGetTable(int a1, struct NPI_MODULEID* a2, unsigned int a3, void *a4, int a5, void *a6, int a7, void *a8, int a9, void *a10, int a11, DWORD *a12, int a13);


extern POOL* Dll_Pool;

static HASH_MAP Custom_NicMac;
static CRITICAL_SECTION Custom_NicMac_CritSec;
static HASH_MAP Custom_NicIndexByOriginal; // original MAC key -> Sandboxie adapter index (DWORD)
static HASH_MAP Custom_NicMacIsFixed;      // original MAC key -> BOOL (TRUE = from NetworkAdapterMAC config, FALSE = random)
static volatile LONG Custom_NicMapsReady = 0; // 1 once Custom_NicMac_CritSec and all NIC maps are initialized

// DHCPv6 DUID + IAID spoofing state (protected by Custom_Dhcpv6CritSec)
static CRITICAL_SECTION Custom_Dhcpv6CritSec;
static volatile LONG     Custom_Dhcpv6Inited = 0;
static volatile LONG     Custom_NicMapWarmup = 0; // 0:not started, 1:in progress, 2:done
static volatile LONG     Custom_NicMapWarmupTid = 0; // TID of thread driving warmup, used to detect re-entrant calls
static BYTE              Custom_FakeDuid[14];  // DUID-LLT: 2+2+4+6
static BOOL              Custom_FakeDuidReady;
static volatile BOOL     Custom_DuidMacResolved; // TRUE once DUID[8..13] resolved from NetworkAdapterMAC/global/random
static HASH_MAP          Custom_FakeIaid;      // per-interface GUID hash -> DWORD

_FX BOOLEAN Nsi_Init(HMODULE module)
{
    if (Config_GetSettingsForImageName_bool(L"HideNetworkAdapterMAC", FALSE)) {

        InitializeCriticalSection(&Custom_NicMac_CritSec);
		map_init(&Custom_NicMac, Dll_Pool);
        map_init(&Custom_NicIndexByOriginal, Dll_Pool);
        map_init(&Custom_NicMacIsFixed, Dll_Pool);
        // Signal after all maps and the critical section are fully ready.
        // Custom_SelectDuidMacFromOriginal and Custom_GetFakeDhcpv6 check this
        // before acquiring Custom_NicMac_CritSec to avoid using an uninitialized
        // CRITICAL_SECTION when called before nsi.dll has been loaded.
        InterlockedExchange(&Custom_NicMapsReady, 1);

        P_NsiAllocateAndGetTable NsiAllocateAndGetTable = (P_NsiAllocateAndGetTable)
            Ldr_GetProcAddrNew(L"nsi.dll", L"NsiAllocateAndGetTable", "NsiAllocateAndGetTable");
        SBIEDLL_HOOK(Nsi_, NsiAllocateAndGetTable);
    }
    return TRUE;
}

BYTE NPI_MS_NDIS_MODULEID[] = { 0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x11, 0x4A, 0x00, 0xEB, 0x1A, 0x9B, 0xD4, 0x11, 0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC };

/*

typedef struct _IP_ADAPTER_INFO {
    struct _IP_ADAPTER_INFO* Next;
    DWORD ComboIndex;
    char AdapterName[MAX_ADAPTER_NAME_LENGTH + 4];
    char Description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4];
    UINT AddressLength;
    BYTE Address[MAX_ADAPTER_ADDRESS_LENGTH];
    DWORD Index;
    UINT Type;
    UINT DhcpEnabled;
    PIP_ADDR_STRING CurrentIpAddress;
    IP_ADDR_STRING IpAddressList;
    IP_ADDR_STRING GatewayList;
    IP_ADDR_STRING DhcpServer;
    BOOL HaveWins;
    IP_ADDR_STRING PrimaryWinsServer;
    IP_ADDR_STRING SecondaryWinsServer;
    time_t LeaseObtained;
    time_t LeaseExpires;
} IP_ADAPTER_INFO, *PIP_ADAPTER_INFO;


__int64 __fastcall AllocateAndGetAdaptersInfo(PIP_ADAPTER_INFO a1)
{
  __int64 result; // rax
  NET_IF_COMPARTMENT_ID CurrentThreadCompartmentId; // eax
  unsigned int v4; // ecx
  __int64 v5; // rdx
  _QWORD *v6; // r13
  unsigned int i; // r14d
  __int64 v8; // r15
  __int64 v9; // rdi
  unsigned int v10; // edi
  void *v11; // rax
  __int64 v12; // rbx
  int v13; // ecx
  __int64 v14; // rax
  unsigned int v15; // eax
  int v16; // eax
  __int64 pAddrEntry[10]; // [rsp+70h] [rbp+7h] BYREF
  unsigned int Count; // [rsp+D0h] [rbp+67h] BYREF
  unsigned int v19; // [rsp+D8h] [rbp+6Fh]
  __int64 pOwnerEntry; // [rsp+E0h] [rbp+77h] BYREF
  __int64 pStateEntry; // [rsp+E8h] [rbp+7Fh] BYREF

  *a1 = 0i64; // Initialize the entire IP_ADAPTER_INFO structure to zero
  result = NsiAllocateAndGetTable(
             1i64,
             &NPI_MS_NDIS_MODULEID,
             1i64,
             pAddrEntry,
             8,
             0i64,
             0,
             &pStateEntry,
             656,
             &pOwnerEntry,
             568,
             &Count,
             0);
  if ( !(_DWORD)result )
  {
    CurrentThreadCompartmentId = GetCurrentThreadCompartmentId();
    v4 = Count;
    v5 = CurrentThreadCompartmentId;
    v19 = CurrentThreadCompartmentId;
    v6 = a1;
    for ( i = 0; i < v4; ++i )
    {
      v8 = 656i64 * i;
      if ( *(_DWORD *)(v8 + pStateEntry) == (_DWORD)v5 )
      {
        v9 = 568i64 * i;
        if ( (unsigned __int8)IsIpv4Interface(pAddrEntry[0] + 8i64 * i, *(unsigned __int16 *)(v9 + pOwnerEntry + 520)) )
        {
          v11 = (void *)MALLOC(0x2E0ui64); // Allocate memory for a new IP_ADAPTER_INFO structure
          v12 = (__int64)v11;
          if ( !v11 )
          {
            v10 = 8;
            goto LABEL_9;
          }
          memset_0(v11, 0, 0x2E0ui64); // Clear the newly allocated structure
          *(_QWORD *)(v12 + 720) = *(_QWORD *)(pAddrEntry[0] + 8i64 * i); // Set internal field (not directly related to IP_ADAPTER_INFO)

          // Setting the AdapterName field
          *(_OWORD *)(v12 + 704) = *(_OWORD *)(v9 + pOwnerEntry + 536);

          // Setting the Index field
          v13 = *(_DWORD *)(v8 + pStateEntry + 536);
          *(_DWORD *)(v12 + 728) = v13;

          // Setting the Type field
          if ( v13 == 5 && (*(_DWORD *)(v8 + pStateEntry + 540) & 0xB) == 8 )
          {
            v16 = *(_DWORD *)(v12 + 728);
            if ( (*(_DWORD *)(v9 + pOwnerEntry + 556) & 0x100) != 0 )
              v16 = 1;
            *(_DWORD *)(v12 + 728) = v16;
          }

          // Setting the ComboIndex field
          *(_DWORD *)(v12 + 8) = *(_DWORD *)(v9 + pOwnerEntry);

          // Setting the AdapterName field using ConvertGuidToStringA
          ConvertGuidToStringA(v9 + pOwnerEntry + 536, v12 + 12, 260i64);

          // Setting the Description field
          v14 = *(unsigned __int16 *)(v9 + pOwnerEntry + 4) >> 1;
          if ( (unsigned int)v14 > 0x100 )
            v14 = 256i64;
          *(_WORD *)(v9 + pOwnerEntry + 2 * v14 + 6) = 0;
          StringCchPrintfA((STRSAFE_LPSTR)(v12 + 272), 0x84ui64, "%S", v9 + pOwnerEntry + 6);

          // Setting the AddressLength field
          v15 = 8;                              // Assignment of AddressLength start
          if ( *(_WORD *)(v8 + pStateEntry + 548) < 8u )
            v15 = *(unsigned __int16 *)(v8 + pStateEntry + 548);
          *(_DWORD *)(v12 + 404) = v15;          // AddressLength

          // Setting the Address field
          memcpy_0((void *)(v12 + 408), (const void *)(v8 + pStateEntry + 550), v15); // Address
          
          // Setting the Index field
          *(_DWORD *)(v12 + 416) = *(_DWORD *)(v9 + pOwnerEntry);

          // Setting the Type field
          *(_DWORD *)(v12 + 420) = *(unsigned __int16 *)(v9 + pOwnerEntry + 520);

          *v6 = v12; // Link the current adapter info structure to the previous one
          v6 = (_QWORD *)v12;

          v10 = AddDhcpInfo(v12); // Call to set DHCP-related fields (DhcpEnabled, DhcpServer, LeaseObtained, LeaseExpires)
          if ( v10 )
            goto LABEL_9;
          v10 = AddNetbtInfo(v12); // Call to set WINS-related fields (HaveWins, PrimaryWinsServer, SecondaryWinsServer)
          if ( v10 )
            goto LABEL_9;
        }
        v4 = Count;
        v5 = v19;
      }
    }

    // Setting additional fields like IP address list and Gateway list
    v10 = AddUnicastAddressInfo(*a1, v5); // Call to set CurrentIpAddress and IpAddressList
    if ( !v10 )
      v10 = AddGatewayInfo(*a1); // Call to set GatewayList
LABEL_9:
    NsiFreeTable(pAddrEntry[0], 0i64, pStateEntry, pOwnerEntry); // Free allocated resources
    return v10;
  }
  return result;
}
*/

int hex_digit_value(wchar_t c) {
    if (c >= (wchar_t)'0' && c <= (wchar_t)'9') {
        return c - (wchar_t)'0';
    } else if (c >= (wchar_t)'a' && c <= (wchar_t)'f') {
        return 10 + (c - (wchar_t)'a');
    } else if (c >= (wchar_t)'A' && c <= (wchar_t)'F') {
        return 10 + (c - (wchar_t)'A');
    } else {
        return -1; // Invalid hex digit
    }
}

BOOL hex_string_to_uint8_array(const wchar_t* str, unsigned char* output_array, size_t* output_length, BOOL swap_bytes)
{
    size_t output_index = 0;
    int digit_high = -1;
    size_t i = 0;
    size_t capacity = *output_length;

    // empty string counts as invalid
    if (!*str)
        return FALSE;

    while (1) {
        wchar_t c = str[i++];
        if (c == 0) {
            break;
        }
        else if (c == (wchar_t)'-') {
            continue;
        }
        else {
            int value = hex_digit_value(c);
            if (value == -1) {
                // Invalid character encountered
                return FALSE;
            }
            if (digit_high == -1) {
                digit_high = value;
            }
            else {
                int digit_low = value;
                if (output_index >= capacity) {
                    // Exceeded capacity of output_array
                    return FALSE;
                }
                output_array[output_index++] = (digit_high << 4) | digit_low;
                digit_high = -1;
            }
        }
    }

    // Check for incomplete byte (odd number of hex digits)
    if (digit_high != -1) {
        return FALSE;
    }

    // Swap the bytes in output_array to match the expected endianness
    if (swap_bytes) {
        size_t j;
        for (j = 0; j < output_index / 2; j++) {
            unsigned char temp = output_array[j];
            output_array[j] = output_array[output_index - 1 - j];
            output_array[output_index - 1 - j] = temp;
        }
    }

    *output_length = output_index;
    return TRUE;
}


//---------------------------------------------------------------------------
// DHCPv6 DUID / IAID Spoofing
//
// HideNetworkAdapterMAC=y activates stable per-sandbox DUID-LLT (14 bytes)
// and deterministic per-interface IAID spoofing.
//
// Resolution priority for the MAC bytes embedded in the DUID (bytes 8..13):
//   1. Indexed  NetworkAdapterMAC (NIC-index config group)  - per-adapter
//   2. Global   NetworkAdapterMAC (image-name config group) - provisional
//   3. Random   fallback (on first use)
//
// IAID computation:
//   - Configured MAC (NetworkAdapterMAC is set): FNV-1a(MAC)
//     -> same IAID for any sandbox with the same configured MAC.
//   - Random MAC (no NetworkAdapterMAC): FNV-1a(BoxName + MAC)
//     -> stable per sandbox, but different from any other sandbox with
//       the same random MAC bytes.
//
// Lock ordering: Custom_Dhcpv6CritSec -> Custom_NicMac_CritSec (map read only;
//   Custom_NicMac_CritSec is released before any blocking SbieDll IOCTL)
//---------------------------------------------------------------------------

// Forward declaration, defined after Custom_EnsureFakeDuidLocked.
static void Custom_ApplySelectedDuidMacLocked(const BYTE *selectedMac);

// True only for DUID-LLT with Ethernet hardware type.
static BOOL Custom_IsDuidLltEthernet(const BYTE *duid, ULONG duidLen)
{
    return (duid != NULL &&
            duidLen >= 14 &&
            duid[0] == 0x00 && duid[1] == 0x01 &&
            duid[2] == 0x00 && duid[3] == 0x01);
}


//---------------------------------------------------------------------------
// Custom_Dhcpv6_EnsureInit
//---------------------------------------------------------------------------

static void Custom_Dhcpv6_EnsureInit(void)
{
    if (InterlockedCompareExchange(&Custom_Dhcpv6Inited, 1, 0) == 0) {
        InitializeCriticalSection(&Custom_Dhcpv6CritSec);
        map_init(&Custom_FakeIaid, Dll_Pool);
        Custom_FakeDuidReady = FALSE;
        Custom_DuidMacResolved = FALSE;
        InterlockedExchange(&Custom_Dhcpv6Inited, 2);
    } else {
        ULONG spins = 0;
        // Use an acquire CAS read to ensure writes from the init thread are
        // visible before we proceed. A plain volatile read lacks the memory
        // barrier needed for correct ordering on ARM64.
        while (InterlockedCompareExchange(&Custom_Dhcpv6Inited, 0, 0) < 2 && ++spins < 10000)
            Sleep(0);
    }
}

//---------------------------------------------------------------------------
// Custom_EnsureFakeDuidLocked
//---------------------------------------------------------------------------

// Initialise Custom_FakeDuid with a random DUID-LLT if not already done.
// If a global NetworkAdapterMAC is configured, overwrite the random link-layer
// bytes immediately as a provisional value (indexed source-interface matching
// can still override it later via Custom_FakeDhcpv6RegValue or
// Custom_GetFakeDhcpv6).  Must be called under Custom_Dhcpv6CritSec.
static void Custom_EnsureFakeDuidLocked(void)
{
    if (!Custom_FakeDuidReady) {
        DWORD r1, r2;
        Custom_FakeDuid[0] = 0x00; Custom_FakeDuid[1] = 0x01; // DUID-LLT
        Custom_FakeDuid[2] = 0x00; Custom_FakeDuid[3] = 0x01; // hw-type Ethernet
        r1 = Dll_rand();
        Custom_FakeDuid[4]  = (BYTE)(r1 >> 24);
        Custom_FakeDuid[5]  = (BYTE)(r1 >> 16);
        Custom_FakeDuid[6]  = (BYTE)(r1 >>  8);
        Custom_FakeDuid[7]  = (BYTE)(r1);
        r1 = Dll_rand(); r2 = Dll_rand();
        Custom_FakeDuid[8]  = (BYTE)(r1 >> 24);
        Custom_FakeDuid[9]  = (BYTE)(r1 >> 16);
        Custom_FakeDuid[10] = (BYTE)(r1 >>  8);
        Custom_FakeDuid[11] = (BYTE)(r1);
        Custom_FakeDuid[12] = (BYTE)(r2 >> 24);
        Custom_FakeDuid[13] = (BYTE)(r2 >> 16);

        // Apply global NetworkAdapterMAC immediately as a provisional value so
        // reg-query callers (e.g. reg.exe) see a stable DUID without waiting for
        // adapter enumeration.  Indexed NIC matching can still override this later.
        {
            WCHAR Value[30] = { 0 };
            if (SbieDll_GetSettingsForName(NULL, Dll_ImageName, L"NetworkAdapterMAC", Value, sizeof(Value), L"")) {
                BYTE selectedMac[8] = { 0 };
                size_t outLen = 8;
                if (hex_string_to_uint8_array(Value, selectedMac, &outLen, FALSE) && outLen >= 6) {
                    Custom_ApplySelectedDuidMacLocked(selectedMac);
                    Custom_DuidMacResolved = FALSE; // provisional: indexed match may still override
                }
            }
        }

        Custom_FakeDuidReady = TRUE;
    }
}

//---------------------------------------------------------------------------
// Custom_MakeMacKey
//---------------------------------------------------------------------------

// Build a pointer-sized hash-map key from up to 8 raw MAC address bytes.
// On 32-bit builds the two 32-bit halves are XOR-folded into one UINT_PTR.
static UINT_PTR Custom_MakeMacKey(const BYTE *mac, ULONG macLen)
{
    BYTE tmp[8] = { 0 };
    ULONG copyLen = (macLen < 8) ? macLen : 8;
    if (copyLen)
        memcpy(tmp, mac, copyLen);

    UINT_PTR key = *(UINT_PTR*)&tmp[0];
#ifndef _WIN64
    key ^= *(UINT_PTR*)&tmp[4];
#endif
    return key;
}


//---------------------------------------------------------------------------
// Custom_ApplySelectedDuidMacLocked
//---------------------------------------------------------------------------

// Write selectedMac[0..5] into Custom_FakeDuid[8..13] and compute a stable
// pseudo-time field (bytes[4..7]) using an FNV-1a hash of the box name and
// the MAC.  Must be called under Custom_Dhcpv6CritSec.
static void Custom_ApplySelectedDuidMacLocked(const BYTE *selectedMac)
{
    DWORD h = 2166136261u; // FNV-1a offset basis
    const WCHAR *p = Dll_BoxName ? Dll_BoxName : L"";
    while (*p) {
        h ^= (DWORD)(*p++);
        h *= 16777619u;
    }
    for (int i = 0; i < 6; ++i) {
        h ^= selectedMac[i];
        h *= 16777619u;
    }

    Custom_FakeDuid[4] = (BYTE)(h >> 24);
    Custom_FakeDuid[5] = (BYTE)(h >> 16);
    Custom_FakeDuid[6] = (BYTE)(h >> 8);
    Custom_FakeDuid[7] = (BYTE)(h);
    memcpy(Custom_FakeDuid + 8, selectedMac, 6);
}


//---------------------------------------------------------------------------
// Custom_SelectDuidMacFromOriginal
//---------------------------------------------------------------------------

// Determine which spoofed MAC bytes should be embedded in the system DUID,
// given the original DUID reported by the OS for a specific adapter.
//
//   1. Extract original link-layer bytes from originalDuid[8..13].
//   2. Look up the Sandboxie NIC index in Custom_NicIndexByOriginal.
//   3. Query NetworkAdapterMAC for that NIC-index config group (indexed).
//   4. Fall back to the global NetworkAdapterMAC image-name setting.
//
// Returns TRUE when *selectedMac was filled.  *usedIndexedMac is TRUE only
// when step 3 succeeded; the caller uses this to decide whether to finalise
// Custom_DuidMacResolved.
//
// Must be called while Custom_Dhcpv6CritSec is held.
// Briefly acquires Custom_NicMac_CritSec (map read only; released before
// the SbieDll config IOCTL to keep the lock-hold time minimal).
static BOOL Custom_SelectDuidMacFromOriginal(
    const BYTE *originalDuid,
    ULONG originalDuidLen,
    BYTE *selectedMac,
    BOOL *usedIndexedMac)
{
    BOOL haveSelectedMac = FALSE;
    *usedIndexedMac = FALSE;

    if (!Custom_IsDuidLltEthernet(originalDuid, originalDuidLen))
        return FALSE;

    // Guard against calling into an uninitialized Custom_NicMac_CritSec.
    // Nsi_Init sets Custom_NicMapsReady=1 only after all maps and the
    // critical section are fully initialized.  If nsi.dll has not been
    // loaded yet (e.g. early startup DUID registry query before iphlpapi
    // is in memory), skip the indexed-MAC lookup and return FALSE so the
    // caller can still fall back to the global NetworkAdapterMAC setting.
    if (InterlockedCompareExchange(&Custom_NicMapsReady, 0, 0) == 0)
        return FALSE;

    BYTE origDuidMac[8] = { 0 };
    memcpy(origDuidMac, originalDuid + 8, 6);

    // Read nicIndex under the lock, then release before the blocking IOCTL in
    // SbieDll_GetSettingsForName. Holding Custom_NicMac_CritSec during a kernel
    // IOCTL would block all concurrent GetAdaptersAddresses callers.
    BOOL haveNicIndex = FALSE;
    DWORD nicIndex = 0;

    EnterCriticalSection(&Custom_NicMac_CritSec);
    UINT_PTR originalKey = Custom_MakeMacKey(origDuidMac, 6);
    DWORD *pNicIndex = (DWORD*)map_get(&Custom_NicIndexByOriginal, (void*)originalKey);
    if (pNicIndex) {
        nicIndex = *pNicIndex;
        haveNicIndex = TRUE;
    }
    LeaveCriticalSection(&Custom_NicMac_CritSec);

    if (haveNicIndex) {
        WCHAR NicIndex[30] = { 0 };
        WCHAR Value[30] = { 0 };
        Sbie_snwprintf(NicIndex, 30, L"%d", nicIndex);
        if (SbieDll_GetSettingsForName(NULL, NicIndex, L"NetworkAdapterMAC", Value, sizeof(Value), L"")) {
            size_t outLen = 8;
            if (hex_string_to_uint8_array(Value, selectedMac, &outLen, FALSE)) {
                // Bounds check: ensure we got between 6 and 8 bytes for a valid MAC -> DUID
                if (outLen >= 6 && outLen <= 8) {
                    haveSelectedMac = TRUE;
                    *usedIndexedMac = TRUE;
                }
            }
        }
    }

    if (!haveSelectedMac) {
        WCHAR Value[30] = { 0 };
        if (SbieDll_GetSettingsForName(NULL, Dll_ImageName, L"NetworkAdapterMAC", Value, sizeof(Value), L"")) {
            size_t outLen = 8;
            if (hex_string_to_uint8_array(Value, selectedMac, &outLen, FALSE)) {
                // Bounds check: ensure we got between 6 and 8 bytes for a valid MAC
                if (outLen >= 6 && outLen <= 8)
                    haveSelectedMac = TRUE;
            }
        }
    }

    return haveSelectedMac;
}


//---------------------------------------------------------------------------
// Custom_WarmupNicMapsForDuid
//---------------------------------------------------------------------------

// Ensure Custom_NicIndexByOriginal is populated before the first DUID
// registry query fires.  Processes that never call GetAdaptersAddresses
// themselves (e.g. reg.exe) would otherwise have an empty NIC index map,
// making indexed NetworkAdapterMAC settings unmatchable.
//
// We resolve GetAdaptersAddresses through GetProcAddress at call time so
// that Sandboxie's own IAT hook on it fires, which drives the Nsi hook
// (Nsi_NsiAllocateAndGetTable) as a side-effect and populates the maps.
//
// Custom_NicMapWarmup state: 0 = not started, 1 = in progress, 2 = done.
static void Custom_WarmupNicMapsForDuid(void)
{
    if (InterlockedCompareExchange(&Custom_NicMapWarmup, 1, 0) == 0) {
        BOOL warmupDone = FALSE;

        // Record this thread's ID before calling GetAdaptersAddresses.
        // If GetAdaptersAddresses internally reads Dhcpv6DUID from the
        // registry (triggering Custom_FakeDhcpv6RegValue again on the
        // same thread), the re-entrant call detects the TID match and
        // returns immediately instead of spinning on Custom_NicMapWarmup.
        InterlockedExchange(&Custom_NicMapWarmupTid, (LONG)GetCurrentThreadId());
        HMODULE iphlp = GetModuleHandleW(L"iphlpapi.dll");

        if (iphlp) {
            typedef ULONG (WINAPI *P_GetAdaptersAddresses)(
                ULONG Family,
                ULONG Flags,
                PVOID Reserved,
                PVOID AdapterAddresses,
                PULONG SizePointer);

            P_GetAdaptersAddresses pGetAdaptersAddresses =
                (P_GetAdaptersAddresses)GetProcAddress(iphlp, "GetAdaptersAddresses");

            if (pGetAdaptersAddresses) {
                ULONG size = 16 * 1024;
                void *buf = NULL;
                int retries = 3;
                ULONG rc;
                // Retry on ERROR_BUFFER_OVERFLOW in case adapters are
                // added between the size query and the data fetch.
                do {
                    if (buf) Dll_Free(buf);
                    buf = Dll_Alloc(size);
                    if (!buf) break;
                    rc = pGetAdaptersAddresses(0 /* AF_UNSPEC */, 0, NULL, buf, &size);
                    warmupDone = TRUE;
                } while (rc == ERROR_BUFFER_OVERFLOW && --retries > 0);

                if (buf)
                    Dll_Free(buf);
            }
        }

        // Keep warmup retryable until GetAdaptersAddresses is actually called.
        // This covers early registry-only processes where iphlpapi.dll is not
        // loaded yet at the first Dhcpv6DUID query.
        InterlockedExchange(&Custom_NicMapWarmupTid, 0);
        InterlockedExchange(&Custom_NicMapWarmup, warmupDone ? 2 : 0);
    } else {
        // Re-entrant call on the warmup thread: GetAdaptersAddresses may
        // internally read Dhcpv6DUID via the registry key hook, which calls
        // Custom_FakeDhcpv6RegValue again and would spin on warmup state=1.
        // Return immediately so the outer warmup call can finish.
        if ((DWORD)InterlockedCompareExchange(&Custom_NicMapWarmupTid, 0, 0) == GetCurrentThreadId())
            return;
        ULONG spins = 0;
        // Use an acquire CAS read for correct memory ordering on ARM64.
        while (InterlockedCompareExchange(&Custom_NicMapWarmup, 0, 0) == 1 && ++spins < 10000)
            Sleep(0);
    }
}


//---------------------------------------------------------------------------
// Custom_GetFakeDhcpv6
//---------------------------------------------------------------------------

// Called from IpHlp_GetAdaptersAddresses (iphlp.c) for each adapter.
//
//   spoofedMac:   already-spoofed physical address bytes for this interface.
//   originalDuid: real DUID reported by the OS, used to identify the source
//                 adapter so that indexed NetworkAdapterMAC settings match.
//   adapterGuid:  ANSI adapter GUID string "{...}" from GetAdaptersAddresses;
//                 used as the shared IAID map key (same hash as the registry
//                 path) so GetAdaptersAddresses and Dhcpv6IAID registry reads
//                 always return the same value.
//
// Writes a stable 14-byte DUID-LLT into duid14[] and a deterministic IAID
// into *iaid.  DUID is system-wide (same for every adapter); IAID is derived
// from the spoofed MAC via FNV-1a (constant for a given MAC, no ifIndex
// dependency) or random-per-process when no MAC is available.
_FX void Custom_GetFakeDhcpv6(
    ULONG ifIndex,
    const BYTE *spoofedMac,
    ULONG macLen,
    const BYTE *originalDuid,
    ULONG originalDuidLen,
    const char *adapterGuid,
    BYTE *duid14,
    ULONG *iaid)
{
    Custom_Dhcpv6_EnsureInit();

    EnterCriticalSection(&Custom_Dhcpv6CritSec);

    // Ensure base DUID exists (random time field + random fallback link-layer bytes).
    Custom_EnsureFakeDuidLocked();

    // Resolve DUID MAC (bytes 8..13) once using requested policy:
    // 1) Find source interface whose original MAC matches original DUID tail.
    // 2) If that interface has indexed NetworkAdapterMAC=<idx>,<mac>, use it.
    // 3) Else if global NetworkAdapterMAC=<mac> exists, use it.
    // 4) Else keep randomized bytes.
    if (!Custom_DuidMacResolved && Custom_IsDuidLltEthernet(originalDuid, originalDuidLen)) {
        BYTE selectedMac[8] = { 0 };
        BOOL usedIndexedMac = FALSE;

        if (Custom_SelectDuidMacFromOriginal(originalDuid, originalDuidLen, selectedMac, &usedIndexedMac))
            Custom_ApplySelectedDuidMacLocked(selectedMac);

        // Finalize only after successful indexed match; global fallback stays
        // provisional so it can still be replaced once index mapping is known.
        Custom_DuidMacResolved = usedIndexedMac;
    }

    memcpy(duid14, Custom_FakeDuid, 14);

    // IAID derivation rules:
    //   1. spoofedMac available from NetworkAdapterMAC config (isFixed):
    //      FNV-1a over all 6 MAC bytes, high bit clear.
    //      Result is constant for a given configured MAC regardless of sandbox or machine.
    //   2. spoofedMac available but randomly generated (!isFixed):
    //      FNV-1a seeded with box name first, then over all 6 MAC bytes.
    //      This ensures two sandboxes that happen to receive the same random MAC
    //      still get distinct IAIDs, while remaining stable within the same sandbox.
    //   3. No MAC:               stable random per-process, keyed by GUID/ifIndex.
    //
    // Whether the MAC was from config is determined by looking up the original MAC
    // (extracted from originalDuid[8..13]) in the Custom_NicMacIsFixed map, which
    // is populated by the NSI hook (Nsi_NsiAllocateAndGetTable) when it assigns a
    // spoofed address.  Unknown adapters (not seen by the NSI hook) default to
    // !isFixed so they also get the box-name salt for additional uniqueness.
    //
    // Lock ordering: Custom_Dhcpv6CritSec -> Custom_NicMac_CritSec (map read only;
    //   Custom_NicMac_CritSec is released before any blocking SbieDll IOCTL)
    //
    // The result is stored in Custom_FakeIaid keyed by adapter GUID hash
    // (same algorithm as Custom_FakeDhcpv6RegValue) so that registry readers
    // always see the same value as GetAdaptersAddresses callers.
    // If a registry query raced first and inserted a random entry, overwrite it
    // with the deterministic MAC-derived value so the registry path self-corrects.
    {
        DWORD fakeIaid;
        BOOLEAN fromMac = FALSE;
        if (spoofedMac != NULL && macLen >= 6) {
            // Determine whether this adapter's MAC was assigned from a fixed
            // NetworkAdapterMAC config entry or was randomly generated.
            // Extract the original (pre-spoof) MAC from the adapter's reported DUID
            // and use it to look up the per-adapter isFixed flag in the NSI map.
            BOOL isFixedMac = FALSE;
            // Only look up the isFixed flag when the NIC maps are initialized.
            // Custom_GetFakeDhcpv6 is called from IpHlp_GetAdaptersAddresses which
            // requires nsi.dll (so Nsi_Init will have run), but guard defensively.
            if (Custom_IsDuidLltEthernet(originalDuid, originalDuidLen) &&
                InterlockedCompareExchange(&Custom_NicMapsReady, 0, 0) != 0) {
                BYTE origDuidMac[8] = { 0 };
                memcpy(origDuidMac, originalDuid + 8, 6);
                UINT_PTR origKey = Custom_MakeMacKey(origDuidMac, 6);
                EnterCriticalSection(&Custom_NicMac_CritSec);
                BOOL *pFixed = (BOOL *)map_get(&Custom_NicMacIsFixed, (void *)origKey);
                if (pFixed) isFixedMac = *pFixed;
                LeaveCriticalSection(&Custom_NicMac_CritSec);
            }

            // FNV-1a IAID derivation.
            // For config MACs: hash MAC only, deterministic across all instances.
            // For random MACs: seed with box name first so two sandboxes sharing the
            // same random MAC bytes still produce different IAIDs.
            DWORD h = 2166136261u; // FNV-1a offset basis
            if (!isFixedMac) {
                const WCHAR *bp = Dll_BoxName ? Dll_BoxName : L"";
                while (*bp) {
                    h ^= (DWORD)(*bp++);
                    h *= 16777619u;
                }
            }
            for (int i = 0; i < 6; i++) {
                h ^= (DWORD)spoofedMac[i];
                h *= 16777619u;
            }
            fakeIaid = h & 0x7FFFFFFF;
            fromMac = TRUE;
        } else {
            fakeIaid = Dll_rand() & 0x7FFFFFFF;
        }

        // Key by adapter GUID hash (same algorithm as Custom_FakeDhcpv6RegValue).
        UINT_PTR key;
        if (adapterGuid && *adapterGuid) {
            key = 5381;
            const char *pg = adapterGuid;
            while (*pg) {
                WCHAR c = (WCHAR)(unsigned char)(*pg);
                if (c >= L'a' && c <= L'z') c -= (L'a' - L'A');
                key = ((key << 5) + key) ^ (UINT_PTR)c;
                pg++;
            }
        } else {
            key = (UINT_PTR)ifIndex;
        }

        void *pExisting = map_get(&Custom_FakeIaid, (void *)key);
        if (pExisting && !fromMac) {
            fakeIaid = *(DWORD *)pExisting; // random fallback: keep pre-existing entry
        } else {
            // MAC-derived: always write, deterministic value wins over any earlier random.
            // Random path: write if not yet present.
            if (!pExisting)
                map_insert(&Custom_FakeIaid, (void *)key, &fakeIaid, sizeof(DWORD));
            else if (fromMac)
                *(DWORD *)pExisting = fakeIaid; // update pre-existing random with deterministic
        }
        *iaid = fakeIaid;
    }

    LeaveCriticalSection(&Custom_Dhcpv6CritSec);
}


//---------------------------------------------------------------------------
// Custom_FakeDhcpv6RegValue
//---------------------------------------------------------------------------

// Called from Key_NtQueryValueKey (key.c) for KeyValuePartialInformation reads.
//
// Intercepts Dhcpv6DUID and Dhcpv6IAID queries under the Tcpip6 registry key
// and returns spoofed values.  Triggers a one-time NIC-map warmup when
// resolving DUID so that indexed NetworkAdapterMAC settings work even in
// processes that never call GetAdaptersAddresses (e.g. reg.exe).
//
// Returns:
//   STATUS_SUCCESS          - fake value written into OutputBuf
//   STATUS_BUFFER_OVERFLOW  - OutputBuf too small; ResultLength is set
//   STATUS_BAD_INITIAL_PC   - not our key/value; fall through to normal logic
_FX NTSTATUS Custom_FakeDhcpv6RegValue(
    const WCHAR *TruePath,
    const WCHAR *ValueName,
    ULONG        ValueNameLen,
    const BYTE  *OriginalDuid,
    ULONG        OriginalDuidLen,
    void        *OutputBuf,
    ULONG        OutputLen,
    ULONG       *ResultLength)
{
    const ULONG kvpiHeaderLen = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data);

    // One-time config check.  CAS(0->1) grants exclusive ownership of init.
    // InterlockedExchange(&inited, 2) is a store-release so 'enabled' is visible
    // before 'inited' reaches 2.  Late-arriving threads spin with an acquire-CAS
    // until 'inited == 2', ensuring correct load ordering on ARM64 as well.
    static BOOL enabled = FALSE;
    static volatile LONG inited = 0;

    if (InterlockedCompareExchange(&inited, 1, 0) == 0) {
        enabled = Config_GetSettingsForImageName_bool(L"HideNetworkAdapterMAC", FALSE);
        InterlockedExchange(&inited, 2);
    } else {
        // Another thread is initializing (inited==1) or already done (inited==2).
        // Spin with an acquire read until initialization is complete.
        // Cap at 10000 iterations (same as Custom_Dhcpv6_EnsureInit) to avoid
        // an infinite spin if the init thread stalls before reaching inited=2.
        ULONG spins = 0;
        while (InterlockedCompareExchange(&inited, 0, 0) < 2 && ++spins < 10000)
            Sleep(0);
    }
    if (!enabled)
        return STATUS_BAD_INITIAL_PC;

    // Both target value names are exactly 10 characters long.
    if (ValueNameLen != 10)
        return STATUS_BAD_INITIAL_PC;

    // Registry path suffixes we match against (case-insensitive).
    static const WCHAR *_Tcpip6Params = L"\\services\\Tcpip6\\Parameters";
    static const WCHAR *_Tcpip6Ifaces = L"\\services\\Tcpip6\\Parameters\\Interfaces\\";

    BOOLEAN isDuid = FALSE;
    BOOLEAN isIaid = FALSE;

    if (_wcsicmp(ValueName, L"Dhcpv6DUID") == 0) {
        // Key must be exactly ...\services\Tcpip6\Parameters  (no sub-key).
        ULONG pathLen   = wcslen(TruePath);
        ULONG paramLen  = wcslen(_Tcpip6Params);
        if (pathLen >= paramLen &&
            _wcsicmp(TruePath + pathLen - paramLen, _Tcpip6Params) == 0)
            isDuid = TRUE;

    } else if (_wcsicmp(ValueName, L"Dhcpv6IAID") == 0) {
        // Key must contain ...\services\Tcpip6\Parameters\Interfaces\  anywhere.
        // Only compare at backslash positions (the pattern starts with '\').
        ULONG ifacesLen = wcslen(_Tcpip6Ifaces);
        const WCHAR *p  = TruePath;
        while ((p = wcschr(p, L'\\')) != NULL) {
            if (_wcsnicmp(p, _Tcpip6Ifaces, ifacesLen) == 0) {
                isIaid = TRUE;
                break;
            }
            p++;
        }
    }

    if (!isDuid && !isIaid)
        return STATUS_BAD_INITIAL_PC;

    if (!ResultLength)
        return STATUS_INVALID_PARAMETER;

    Custom_Dhcpv6_EnsureInit();

    // KEY_VALUE_PARTIAL_INFORMATION header is 3 ULONGs (TitleIndex, Type, DataLength).
    if (!OutputBuf && OutputLen > 0)
        return STATUS_ACCESS_VIOLATION;

    KEY_VALUE_PARTIAL_INFORMATION *kvpi = (KEY_VALUE_PARTIAL_INFORMATION *)OutputBuf;

    if (isDuid) {
        // DUID-LLT: type(2) + hw-type(2) + time(4) + MAC(6) = 14 bytes.
        const ULONG duidLen = 14;
        *ResultLength = kvpiHeaderLen + duidLen;

        if (OutputLen < kvpiHeaderLen)
            return STATUS_BUFFER_OVERFLOW;

        kvpi->TitleIndex = 0;
        kvpi->Type       = REG_BINARY;
        kvpi->DataLength = duidLen;

        if (OutputLen < *ResultLength)
            return STATUS_BUFFER_OVERFLOW;

        if (!Custom_DuidMacResolved && Custom_IsDuidLltEthernet(OriginalDuid, OriginalDuidLen))
            Custom_WarmupNicMapsForDuid();

        EnterCriticalSection(&Custom_Dhcpv6CritSec);
        Custom_EnsureFakeDuidLocked();

        // Use original DUID data (provided by key.c) to attempt indexed
        // source-interface resolution on pure registry query path too.
        if (!Custom_DuidMacResolved && Custom_IsDuidLltEthernet(OriginalDuid, OriginalDuidLen)) {
            BYTE selectedMac[8] = { 0 };
            BOOL usedIndexedMac = FALSE;

            if (Custom_SelectDuidMacFromOriginal(OriginalDuid, OriginalDuidLen, selectedMac, &usedIndexedMac))
                Custom_ApplySelectedDuidMacLocked(selectedMac);

            Custom_DuidMacResolved = usedIndexedMac;
        }
        memcpy(kvpi->Data, Custom_FakeDuid, duidLen);
        LeaveCriticalSection(&Custom_Dhcpv6CritSec);
        return STATUS_SUCCESS;

    } else { // isIaid

        *ResultLength = kvpiHeaderLen + sizeof(DWORD);

        if (OutputLen < kvpiHeaderLen)
            return STATUS_BUFFER_OVERFLOW;

        kvpi->TitleIndex = 0;
        kvpi->Type       = REG_DWORD;
        kvpi->DataLength = sizeof(DWORD);

        if (OutputLen < *ResultLength)
            return STATUS_BUFFER_OVERFLOW;

        // Derive a stable per-GUID key from the last path component.
        // wcsrchr returns the '\' separator itself; skip it so we hash
        // only the GUID text "{XXXXXXXX-...}" without the leading backslash.
        const WCHAR *guid = wcsrchr(TruePath, L'\\');
        if (!guid) guid = TruePath;
        else guid++; // skip leading backslash

        // djb2-XOR: case-insensitive, maps to UINT_PTR for use as map key.
        UINT_PTR key = 5381;
        const WCHAR *p = guid;
        while (*p) {
            WCHAR c = (*p >= L'a' && *p <= L'z') ? (*p - (L'a' - L'A')) : *p;
            key = ((key << 5) + key) ^ (UINT_PTR)c;
            p++;
        }

        // Warmup ensures GetAdaptersAddresses has run and populated Custom_FakeIaid
        // with MAC-derived IAID entries before we look up here.  Without this, a
        // registry-first query would always fall back to a random IAID even when a
        // fixed NetworkAdapterMAC is configured.
        Custom_WarmupNicMapsForDuid();

        EnterCriticalSection(&Custom_Dhcpv6CritSec);
        void *pIaid = map_get(&Custom_FakeIaid, (void *)key);
        DWORD iaid;
        if (pIaid) {
            iaid = *(DWORD *)pIaid;
        } else {
            iaid = Dll_rand() & 0x7FFFFFFF; // keep high bit clear so %d display is never negative
            map_insert(&Custom_FakeIaid, (void *)key, &iaid, sizeof(DWORD));
        }
        LeaveCriticalSection(&Custom_Dhcpv6CritSec);

        *(DWORD *)kvpi->Data = iaid;
        return STATUS_SUCCESS;
    }
}


ULONG Nsi_NsiAllocateAndGetTable(int a1, struct NPI_MODULEID* NPI_MS_ID, unsigned int TcpInformationId, void **pAddrEntry, int SizeOfAddrEntry, void **a6, int a7, void **pStateEntry, int SizeOfStateEntry, void **pOwnerEntry, int SizeOfOwnerEntry, DWORD *Count, int a13)
{
    ULONG ret = __sys_NsiAllocateAndGetTable(a1, NPI_MS_ID, TcpInformationId, pAddrEntry, SizeOfAddrEntry, a6, a7, pStateEntry, SizeOfStateEntry, pOwnerEntry, SizeOfOwnerEntry, Count, a13);
    static volatile long num = 0;
    if (ret == 0 &&
        NPI_MS_ID &&
        memcmp(NPI_MS_ID, NPI_MS_NDIS_MODULEID, sizeof(NPI_MS_NDIS_MODULEID)) == 0 &&
        TcpInformationId == 1 &&
        pStateEntry && *pStateEntry &&
        Count && *Count)
    {
        typedef struct _STATE_ENTRY {
            DWORD ThreadCompartmentId;     // 0
            BYTE Unknown1[18];
            WCHAR AdapterName[256];        // 22
            DWORD Index;                   // 536
            DWORD Type;                    // 540
            BYTE Unknown2[4];
            WORD AddressLength;            // 548
            BYTE Address[8];               // 550
            BYTE Unknown3[98];
        } STATE_ENTRY, * PSTATE_ENTRY;     // 656

        const ULONG minStateSize =
            FIELD_OFFSET(STATE_ENTRY, Address) + sizeof(((PSTATE_ENTRY)0)->Address);
        if ((ULONG)SizeOfStateEntry < minStateSize)
            return ret;

        const ULONG stateStride = (ULONG)SizeOfStateEntry;

        //const int x = sizeof(STATE_ENTRY); 
        //const x1 = FIELD_OFFSET(STATE_ENTRY, Address);

        for (DWORD i = 0; i < *Count; i++) {

            PSTATE_ENTRY pEntry = (PSTATE_ENTRY)((BYTE*)*pStateEntry + i * stateStride);

            if (pEntry->AddressLength) {

                BYTE originalMac[8] = { 0 };
                ULONG originalLen = (pEntry->AddressLength < 8) ? pEntry->AddressLength : 8;
                if (originalLen)
                    memcpy(originalMac, pEntry->Address, originalLen);
                UINT_PTR originalKey = Custom_MakeMacKey(originalMac, originalLen);

                EnterCriticalSection(&Custom_NicMac_CritSec);
		        void* lpMac = map_get(&Custom_NicMac, (void*)originalKey);
                if (lpMac) {
                    memcpy(pEntry->Address, lpMac, 8);
                    LeaveCriticalSection(&Custom_NicMac_CritSec);
                } else {
                    // Assign a unique NicIndex now (under the lock) so that concurrent
                    // threads processing different adapters get distinct indices. Then
                    // release the lock before the blocking SbieDll IOCTL to avoid
                    // stalling every concurrent GetAdaptersAddresses call.
                    DWORD nicIndex = (DWORD)num;
                    num++;
                    LeaveCriticalSection(&Custom_NicMac_CritSec);

                    WCHAR NicIndex[30] = { 0 };
                    WCHAR Value[30] = { 0 };
                    Sbie_snwprintf(NicIndex, 30, L"%d", nicIndex);
                    SbieDll_GetSettingsForName(NULL, NicIndex, L"NetworkAdapterMAC", Value, sizeof(Value), L"");

                    // Compute the spoofed address into a local buffer first.
                    BYTE spoofAddr[8] = { 0 };
                    ULONG addrCopyLen = (pEntry->AddressLength < 8) ? pEntry->AddressLength : 8;
                    if (addrCopyLen)
                        memcpy(spoofAddr, pEntry->Address, addrCopyLen);
                    size_t AddressLen = 8;
                    BOOL macFromConfig = FALSE;
                    if (hex_string_to_uint8_array(Value, spoofAddr, &AddressLen, FALSE)) {
                        // Validate parsed MAC length is in acceptable range (6-8 bytes)
                        if (AddressLen >= 6 && AddressLen <= 8) {
                            macFromConfig = TRUE;
                        }
                    }
                    if (!macFromConfig) {
                        // Config absent, unparseable, or wrong length:
                        // fall back to a fully random address to avoid a hybrid of
                        // configured bytes + original MAC tail bytes.
                        *(DWORD*)&spoofAddr[0] = Dll_rand();
                        *(DWORD*)&spoofAddr[4] = Dll_rand();
                    }

                    // Re-acquire and double-check: another thread may have raced and
                    // already inserted an entry for this adapter's original MAC key.
                    EnterCriticalSection(&Custom_NicMac_CritSec);
                    void *lpMacNow = map_get(&Custom_NicMac, (void*)originalKey);
                    if (!lpMacNow) {
                        map_insert(&Custom_NicMac, (void*)originalKey, spoofAddr, 8);
                        map_insert(&Custom_NicIndexByOriginal, (void*)originalKey, &nicIndex, sizeof(DWORD));
                        map_insert(&Custom_NicMacIsFixed, (void*)originalKey, &macFromConfig, sizeof(BOOL));
                        memcpy(pEntry->Address, spoofAddr, 8);
                    } else {
                        // Lost the race. Roll back the pre-incremented NIC index
                        // counter to keep indices contiguous, but only when no
                        // other thread has advanced 'num' further since our
                        // increment (verified under the lock).  Without this,
                        // a concurrent call on the same adapter wastes a slot
                        // and shifts every subsequent adapter's index up by 1,
                        // breaking NetworkAdapterMAC=N,<mac> config lookups.
                        if ((DWORD)num == nicIndex + 1)
                            num--;
                        // Use the winner's spoofed MAC for this adapter.
                        memcpy(pEntry->Address, lpMacNow, 8);
                    }
                    LeaveCriticalSection(&Custom_NicMac_CritSec);
                }

            }
        }
    }

    return ret;
}




//---------------------------------------------------------------------------
// BEYOND HERE BE DRAGONS - workarounds for non windows components
//---------------------------------------------------------------------------


//---------------------------------------------------------------------------
// Custom_SilverlightAgCore
//---------------------------------------------------------------------------


_FX BOOLEAN Custom_SilverlightAgCore(HMODULE module)
{
    NTSTATUS status;
    UNICODE_STRING uni;
    OBJECT_ATTRIBUTES objattrs;
    HANDLE hKey;

    //
    // turn off Silverlight auto update mode
    //

    InitializeObjectAttributes(
        &objattrs, &uni, OBJ_CASE_INSENSITIVE, NULL, NULL);

    RtlInitUnicodeString(&uni,
        L"\\registry\\user\\current\\software"
            L"\\Microsoft\\Silverlight");

    status = Key_OpenIfBoxed(&hKey, KEY_SET_VALUE, &objattrs);
    if (NT_SUCCESS(status)) {

        ULONG two = 2;

        RtlInitUnicodeString(&uni, L"UpdateMode");

        status = NtSetValueKey(
            hKey, &uni, 0, REG_DWORD, &two, sizeof(ULONG));

        NtClose(hKey);
    }

    return TRUE;
}


//---------------------------------------------------------------------------
// Custom_OsppcDll
//---------------------------------------------------------------------------


_FX BOOLEAN Custom_OsppcDll(HMODULE module)
{
    const WCHAR *ProductNames[] = {
        L"Excel", L"Word", L"PowerPoint", NULL };
    const WCHAR *ValueNames[] = {
        L"DisableAttachmentsInPV",      L"DisableInternetFilesInPV",
        L"DisableUnsafeLocationsInPV",  NULL };

    NTSTATUS status;
    HANDLE hOfficeKey, hKey;
    UNICODE_STRING uni;
    OBJECT_ATTRIBUTES objattrs;
    WCHAR path[128];
    ULONG one = 1;
    ULONG zero = 0;
    ULONG ProductIndex, ValueIndex;

    ULONG Wow64 = 0;
#ifndef _WIN64
    if (Dll_IsWow64)
        Wow64 = KEY_WOW64_64KEY;
#endif

    //
    // open Microsoft Office 2010 registry key
    //

    InitializeObjectAttributes(
        &objattrs, &uni, OBJ_CASE_INSENSITIVE, NULL, NULL);

    RtlInitUnicodeString(&uni, L"\\registry\\user\\current\\software\\Microsoft\\Office\\14.0");

    status = Key_OpenIfBoxed(&hOfficeKey, KEY_ALL_ACCESS | Wow64, &objattrs);
    if (! NT_SUCCESS(status))
        return TRUE;

    //
    // for each product, open the registry key "Security\ProtectedView"
    //

    for (ProductIndex = 0; ProductNames[ProductIndex]; ++ProductIndex) {

        objattrs.RootDirectory = hOfficeKey;
        wcscpy(path, ProductNames[ProductIndex]);
        wcscat(path, L"\\Security\\ProtectedView");
        RtlInitUnicodeString(&uni, path);

        status = Key_OpenIfBoxed(&hKey, KEY_ALL_ACCESS | Wow64, &objattrs);

        if (status == STATUS_OBJECT_NAME_NOT_FOUND) {

            status = NtCreateKey(
                &hKey, KEY_ALL_ACCESS | Wow64, &objattrs,
                0, NULL, 0, NULL);
        }

        if (NT_SUCCESS(status)) {

            for (ValueIndex = 0; ValueNames[ValueIndex]; ++ValueIndex) {

                RtlInitUnicodeString(&uni, ValueNames[ValueIndex]);
                NtSetValueKey(
                    hKey, &uni, 0, REG_DWORD, (BYTE *)&one, sizeof(one));
            }

            NtClose(hKey);
        }
    }

    //
    // for the Microsoft Office Picture Manager, set the FirstBoot value
    //

    if (1) {

        objattrs.RootDirectory = hOfficeKey;
        RtlInitUnicodeString(&uni, L"OIS");
        status = Key_OpenIfBoxed(&hKey, KEY_ALL_ACCESS | Wow64, &objattrs);
        if (NT_SUCCESS(status)) {

            RtlInitUnicodeString(&uni, L"FirstBoot");
            NtSetValueKey(
                hKey, &uni, 0, REG_DWORD, (BYTE *)&zero, sizeof(zero));

            NtClose(hKey);
        }
    }

    //
    // finish
    //

    NtClose(hOfficeKey);
    return TRUE;
}


//---------------------------------------------------------------------------
// Custom_ProductID
//---------------------------------------------------------------------------

/*char* my_itoa(int num, char* str, int radix)
{
	char index[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	unsigned unum;
	int i = 0, j, k;

	
	if (radix == 10 && num < 0)
	{
		unum = (unsigned)-num;
		str[i++] = '-';
	}
	else unum = (unsigned)num;

	
	do
	{
		str[i++] = index[unum % (unsigned)radix];
		unum /= radix;

	} while (unum);

	str[i] = '\0';

	
	if (str[0] == '-') k = 1;
	else k = 0;

	char temp;
	for (j = k; j <= (i - 1) / 2; j++)
	{
		temp = str[j];
		str[j] = str[i - 1 + k - j];
		str[i - 1 + k - j] = temp;
	}

	return str;

}*/

wchar_t* GuidToString(const GUID guid)
{
	static wchar_t buf[64] = {0};
	Sbie_snwprintf(buf, sizeof(buf),
		L"%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
	return buf;
}

_FX BOOLEAN  Custom_ProductID(void) 
{
	if (Config_GetSettingsForImageName_bool(L"RandomRegUID", FALSE)) {
		NTSTATUS status;
		UNICODE_STRING uni;
		OBJECT_ATTRIBUTES objattrs;
		HANDLE hKey;

			InitializeObjectAttributes(
				&objattrs, &uni, OBJ_CASE_INSENSITIVE, NULL, NULL);

		RtlInitUnicodeString(&uni,
			L"\\registry\\Machine\\Software\\"
			L"\\Microsoft\\Windows NT\\CurrentVersion");

		status = Key_OpenIfBoxed(&hKey, KEY_SET_VALUE, &objattrs);
		if (NT_SUCCESS(status)) {

			//UNICODE_STRING buf;
			//RtlInitUnicodeString(&buf, tmp);
			/*if (GetIntLen(dwTick) == 1) {
				//DWORD last = dwTick - (dwTick / 10) * 10;
				DWORD last = dwTick;
				WCHAR chr = GetCharFromInt((int)last);
				Sleep(0);
				DWORD dwTick2 = GetTickCount(),last2=0;
				if (GetIntLen(dwTick) == 1)
					last2 = dwTick2;
				else
					last2 = dwTick2 - (dwTick2 / 10) * 10;
				WCHAR chr2= GetCharFromInt((int)last2);
				wcscpy_s(tmp, 1, chr2);
				wcscat_s(tmp, 1, chr2);
				for(int i=0;i<=2;i++)
					wcscat_s(tmp, 1, chr);
			}*/
			WCHAR tmp[34] = { 0 };

			RtlInitUnicodeString(&uni, L"ProductId");

			int chain1 = Dll_rand() % 10000 + 9999,
				chain2 = Dll_rand() % 10000 + 9999,
				chain3 = Dll_rand() % 10000 + 9999,
				chain4 = Dll_rand() % 10000 + 9999
				;
			Sbie_snwprintf(tmp, 34, L"%05d-%05d-%05d-%05d", chain1, chain2, chain3, chain4);
			
			
			status = NtSetValueKey(
				hKey, &uni, 0, REG_SZ, tmp, sizeof(tmp)+1);
			NtClose(hKey);
		}
		RtlInitUnicodeString(&uni,
			L"\\registry\\Machine\\Software\\"
			L"\\Microsoft\\Cryptography");
		typedef HRESULT(*P_CoCreateGuid)(
			GUID* pguid
			);
			P_CoCreateGuid CoCreateGuid2 = (P_CoCreateGuid)Ldr_GetProcAddrNew(DllName_ole32, L"CoCreateGuid", "CoCreateGuid");
		status = Key_OpenIfBoxed(&hKey, KEY_SET_VALUE, &objattrs);
		if (NT_SUCCESS(status)&&CoCreateGuid2) {
			GUID guid;
			HRESULT h = CoCreateGuid2(&guid);
			WCHAR buf[64] = { 0 };
			if (h == S_OK) {
				WCHAR* pChar = GuidToString(guid);
				lstrcpy(buf, pChar);
				RtlInitUnicodeString(&uni, L"MachineGuid");
				status = NtSetValueKey(
					hKey, &uni, 0, REG_SZ, buf, sizeof(buf) + 1);
			}
			
		}
		NtClose(hKey);
		RtlInitUnicodeString(&uni,
			L"\\registry\\Machine\\Software\\"
			L"\\Microsoft\\SQMClient");

		status = Key_OpenIfBoxed(&hKey, KEY_SET_VALUE, &objattrs);
		if (NT_SUCCESS(status)&&CoCreateGuid2) {
			GUID guid;
			HRESULT h = CoCreateGuid2(&guid);
			WCHAR buf[64] = L"{";
			if (h == S_OK) {
				WCHAR* pChar = GuidToString(guid);
				lstrcat(buf, pChar);
				lstrcat(buf, L"}");
				RtlInitUnicodeString(&uni, L"MachineId");
				status = NtSetValueKey(
					hKey, &uni, 0, REG_SZ, buf, sizeof(buf) + 1);
			}
			
		}
		NtClose(hKey);
		return TRUE;
	}
	return TRUE;
}

#ifndef _M_ARM64

//---------------------------------------------------------------------------
// Custom_InternetDownloadManager
//---------------------------------------------------------------------------


_FX BOOLEAN Custom_InternetDownloadManager(HMODULE module)
{
    //
    // outside the sandbox, IEShims.dll makes sure that IDMIECC has a
    // load count of -1, but our Key_NtQueryValueKeyFakeForInternetExplorer
    // routine turns off DetourDialogs and prevents IEShims.dll from loading
    // so we need to emulate that functionality here
    //

    if (Dll_ImageType == DLL_IMAGE_INTERNET_EXPLORER) {

        Ldr_MakeStaticDll((ULONG_PTR)module);
    }

    return TRUE;
}


//---------------------------------------------------------------------------
//
// avast! compatibility hook:  avast hook dll snxhk.dll (also snxhk64.dll)
// calls LdrGetProcedureAddress to get the address of NtDeviceIoControlFile
// and then copies the code.  if the code includes relative jumps (which
// it does, after processing by SbieDll_Hook), this is not fixed up while
// copying, and causes avast to crash.  to work around this, we return a
// small trampoline with the following code which avoids a relative jump:
// mov eax, NtDeviceIoControlFile; jmp eax
//
//---------------------------------------------------------------------------


//---------------------------------------------------------------------------
// Custom_Avast_SnxHk_LdrGetProcedureAddress
//---------------------------------------------------------------------------


typedef NTSTATUS (*P_LdrGetProcedureAddress)(
    HANDLE ModuleHandle, ANSI_STRING *ProcName, ULONG ProcNum,
    ULONG_PTR *Address);

static P_LdrGetProcedureAddress __sys_LdrGetProcedureAddress = NULL;

static NTSTATUS Custom_Avast_SnxHk_LdrGetProcedureAddress(
    HANDLE ModuleHandle, ANSI_STRING *ProcName, ULONG ProcNum,
    ULONG_PTR *Address);


//---------------------------------------------------------------------------
// Custom_Avast_SnxHk_LdrGetProcedureAddress
//---------------------------------------------------------------------------


_FX NTSTATUS Custom_Avast_SnxHk_LdrGetProcedureAddress(
    HANDLE ModuleHandle, ANSI_STRING *ProcName, ULONG ProcNum,
    ULONG_PTR *Address)
{
    NTSTATUS status = __sys_LdrGetProcedureAddress(
                                ModuleHandle, ProcName, ProcNum, Address);

    if (NT_SUCCESS(status) &&
            ModuleHandle == Dll_Ntdll &&
            ProcName->Length == 21 &&
            memcmp(ProcName->Buffer, "NtDeviceIoControlFile", 21) == 0) {

        static UCHAR *code = 0;
        if (! code) {

            code = Dll_AllocCode128();
#ifdef _WIN64
            *(USHORT *)code = 0xB848;
            *(ULONG64 *)(code + 2) = *Address;
            *(USHORT *)(code + 10) = 0xE0FF;
#else ! _WIN64
            *code = 0xB8;
            *(ULONG *)(code + 1) = *Address;
            *(USHORT *)(code + 5) = 0xE0FF;
#endif _WIN64
        }

        *Address = (ULONG_PTR)code;
    }

    return status;
}


//---------------------------------------------------------------------------
// Custom_Avast_SnxHk
//---------------------------------------------------------------------------


_FX BOOLEAN Custom_Avast_SnxHk(HMODULE module)
{
    static BOOLEAN _done = FALSE;
    if (! _done) {
        SBIEDLL_HOOK(Custom_Avast_SnxHk_,LdrGetProcedureAddress);
        _done = TRUE;
    }
    return TRUE;
}


//---------------------------------------------------------------------------
// Custom_SYSFER_DLL
//---------------------------------------------------------------------------


_FX BOOLEAN Custom_SYSFER_DLL(HMODULE hmodule)
{
    //
    // Symantec Endpoint Protection SYSFER.DLL hooks NT API stubs in
    // NTDLL by simply copying code bytes elsewhere.  this doesn't work
    // for us because it doesn't adjust JMP pointers.  we use this
    // workaround to nullify SYSFER.DLL
    //

    extern IMAGE_OPTIONAL_HEADER *Ldr_OptionalHeader(ULONG_PTR ImageBase);
    ULONG_PTR base = (ULONG_PTR)hmodule;
    IMAGE_OPTIONAL_HEADER *opt_hdr = Ldr_OptionalHeader(base);
    UCHAR *entrypoint = (UCHAR *)(base + opt_hdr->AddressOfEntryPoint);
    ULONG old_prot;
    if (VirtualProtect(entrypoint, 16, PAGE_EXECUTE_READWRITE, &old_prot)) {

        //
        // mov al, 1 ; ret
        //
        // we don't bother with RET 12 on x86 because the NTDLL loader
        // restores the stack pointer that it saved before calling
        //

        *(ULONG *)entrypoint = 0x00C301B0;
    }

    return TRUE;
}


//---------------------------------------------------------------------------
// Custom_Load_UxTheme
//---------------------------------------------------------------------------


/*_FX void Custom_Load_UxTheme(void)
{
    //
    // Google Chrome sandbox process is started with limited privileges
    // but the first thread is given a normal token for start up.
    // outside the sandbox the process creates a STATIC window, before
    // releasing its start up token, this causes UXTHEME.DLL to load in
    // the process.  in the v4 sandbox, with Google Chrome v28, no such
    // window is created, and UXTHEME.DLL will only be loaded as a result
    // of a later call to SystemParametersInfo(SPI_GETFONTSMOOTHING),
    // however by that time the process has limited privileges and this
    // load fails.  we work around this by loading UXTHEME.DLL here.
    //

    if (Dll_ChromeSandbox) {
        typedef BOOL (*P_SystemParametersInfo)(
            UINT uiAction, UINT uiParam, PVOID pvParam, UINT fWinIni);
        P_SystemParametersInfo SystemParametersInfo =
            Ldr_GetProcAddrNew(DllName_user32, L"SystemParametersInfoW","SystemParametersInfoW");
        if (SystemParametersInfo) {
            BOOL v;
            SystemParametersInfo(SPI_GETFONTSMOOTHING, 0, &v, 0);
        }
    }
}*/

//---------------------------------------------------------------------------
// Handles ActivClient's acscmonitor.dll which crashes firefox in sandboxie.
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
// Acscmonitor_LoadLibrary
//---------------------------------------------------------------------------

ULONG CALLBACK Acscmonitor_LoadLibrary(LPVOID lpParam)
{
    // Acscmonitor is a plugin to Firefox which create a thread on initialize.
    // Firefox has a habit of initializing the module right before it's about
    // to unload the DLL, which is causing the crash.
    // Our solution is to prevent the library from ever being removed by holding
    // a reference to it.
    LoadLibraryW(L"acscmonitor.dll");
    return 0;
}

//---------------------------------------------------------------------------
// Acscmonitor_Init
//---------------------------------------------------------------------------

_FX BOOLEAN Acscmonitor_Init(HMODULE hDll)
{
	HANDLE ThreadHandle = CreateThread(NULL, 0, Acscmonitor_LoadLibrary, (LPVOID)0, 0, NULL);
	if (ThreadHandle)
		CloseHandle(ThreadHandle); 
    return TRUE;
}

#endif
