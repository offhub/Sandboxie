/*
 * Copyright 2022-2023 David Xanatos, xanasoft.com
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

#include "../../common/my_version.h"

// Must match the definition in file_del.c (included into file.c before key_del.c)
typedef struct _PATH_NODE PATH_NODE;
typedef struct _PATH_LIST {
    LIST         list;
    PATH_NODE**  buckets;
    ULONG        bucket_count;
} PATH_LIST;

// Must match VPATH_JOURNAL_CTX in file_del.c exactly.
typedef struct _VPATH_JOURNAL_CTX {
    const WCHAR**       pLogName;
    const WCHAR**       pDatName;
    WCHAR*        (*TranslateForWrite)(const WCHAR*);
    WCHAR*        (*TranslateForLoad)(const WCHAR*);
    CRITICAL_SECTION*   CritSec;
    PATH_LIST*          Root;
    HANDLE*             pAppendHandle;
    ULONG*              pAppendLastTick;
    ULONG*              pKeepOpenMs;
    ULONG64*            pLogFileSize;
    ULONG64*            pLogFileDate;
    ULONG64*            pReplayOffset;
    ULONG*              pLogLineCount;
    ULONG*              pMaxSizeBytes;
    ULONG*              pMaxLines;
    ULONG*              pBusyWritesPerSec;
    ULONG*              pBusyHoldMs;
    ULONG*              pMinGraceMs;
    ULONG*              pRecentWriteCount;
    ULONG*              pRecentWriteWindowTick;
    ULONG*              pBusyUntilTick;
    volatile LONG*      pSharedBusyUntilTick;
    WCHAR*              compactMutexName;
    ULONG64*            pDatFileSize;
    ULONG64*            pDatFileDate;
    BOOLEAN*            pIsV3;
} VPATH_JOURNAL_CTX;

BOOLEAN Vfs_AppendAndMaybeCompact_internal(VPATH_JOURNAL_CTX* ctx, BOOLEAN isDelete, const WCHAR* Path, const WCHAR* NewPath);

static VPATH_JOURNAL_CTX Key_JournalCtx;
static const WCHAR* Key_CurrentLogName;
static const WCHAR* Key_CurrentDatName;

//---------------------------------------------------------------------------
// Key (Delete)
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
// Defines
//---------------------------------------------------------------------------

#define KEY_PATH_FILE_NAME      L"RegPaths.dat"
#define KEY_PATH_LOG_FILE_NAME  L"RegPaths.sbie"
#define KEY_PATH_FILE_NAME_V3      L"RegPaths_v3.dat"
#define KEY_PATH_LOG_FILE_NAME_V3  L"RegPaths_v3.sbie"
// In-memory marker for value-delete path segments.
// Both v2 and v3 use '$' in the in-memory tree; v3 serializes it as opcode 3 on disk.
#define KEY_VALUE_SEGMENT_MARKER L'$'

// Hard-cap: force compaction regardless of user settings or burst state.
// 64-bit: 512 MB (MaxSizeKB limit 1 GB / 2); 32-bit: 256 MB (1 GB / 4)
#ifdef _WIN64
#define FILE_JOURNAL_HARD_CAP_BYTES  (512UL * 1024UL * 1024UL)
#else
#define FILE_JOURNAL_HARD_CAP_BYTES  (256UL * 1024UL * 1024UL)
#endif

// Keep in sync with the FILE_..._FLAG's in file_del.c
// 
// path flags, saved to file
#define KEY_DELETED_FLAG       0x0001
#define KEY_RELOCATION_FLAG    0x0002

// internal volatile status flags
#define KEY_PATH_DELETED_FLAG      0x00010000
#define KEY_PATH_RELOCATED_FLAG    0x00020000
#define KEY_CHILDREN_DELETED_FLAG  0x00040000

#define KEY_DELETED_MASK    (KEY_DELETED_FLAG | KEY_PATH_DELETED_FLAG) 
#define KEY_RELOCATED_MASK  (KEY_RELOCATION_FLAG | KEY_PATH_RELOCATED_FLAG) 

#define KEY_IS_DELETED(x)       ((x & KEY_DELETED_FLAG) != 0)
#define KEY_PATH_DELETED(x)     ((x & KEY_DELETED_MASK) != 0)
#define KEY_PARENT_DELETED(x)   ((x & KEY_PATH_DELETED_FLAG) != 0)
#define KEY_PATH_RELOCATED(x)   ((x & KEY_RELOCATED_MASK) != 0)


//---------------------------------------------------------------------------
// Variables
//---------------------------------------------------------------------------


static PATH_LIST Key_PathRoot;
static CRITICAL_SECTION *Key_PathRoot_CritSec = NULL;

BOOLEAN Key_RegPaths_Loaded = FALSE;

static ULONG64 Key_PathsFileSize = 0;
static ULONG64 Key_PathsFileDate = 0;
static ULONG64 Key_PathsLogFileSize = 0;
static ULONG64 Key_PathsLogFileDate = 0;
static ULONG64 Key_PathsLogReplayOffset = 0;
static ULONG Key_PathsLogLineCount = 0;
static volatile ULONG Key_PathsVersion = 0; // count reloads
static HANDLE Key_VcmMutex = NULL;
static ULONG Key_PathRefreshIntervalMs = 50;
static volatile LONG Key_LastRefreshTick = 0;
static BOOLEAN Key_DeleteV3 = FALSE;
static ULONG Key_DeleteV3JournalMaxSizeBytes = 1024 * 1024;
static ULONG Key_DeleteV3JournalMaxLines = 10000;
static ULONG Key_DeleteV3JournalKeepOpenMs = 0;
static HANDLE Key_PathsLogAppendHandle = NULL;
static ULONG Key_PathsLogAppendLastTick = 0;

static ULONG Key_DeleteV3CompactionBusyWritesPerSec = 100;   // 0 = burst-defer disabled
static ULONG Key_DeleteV3CompactionBusyHoldMs = 60000;     // hold window after burst detected (ms)
static ULONG Key_DeleteV3CompactionMinGraceMs = 5000;      // min grace before first compaction (ms)
static ULONG Key_CompactionBusyUntilTick = 0;              // process-local defer-until tick
static ULONG Key_RecentWriteCount = 0;                     // writes in current rate window
static ULONG Key_RecentWriteWindowTick = 0;                // start tick of current rate window

static HANDLE           Key_SharedBusyHandle = NULL;        // named section handle
static volatile LONG*   Key_SharedBusyUntilTick = NULL;     // mapped cross-process BusyUntilTick

// Per-box named object names — populated in Key_InitDelete_v2 with Dll_BoxName so that
// boxes sharing an OpenIpcPath=*SBIE* rule cannot cross-contaminate each other's
// compaction locks or burst-deferral counters.
static WCHAR Key_VcmMutexName[64];
static WCHAR Key_VcmCompactMutexName[64];
static WCHAR Key_VcmBusyTickName[64];


//---------------------------------------------------------------------------
// Functions
//---------------------------------------------------------------------------

static ULONG Key_GetPathFlags(const WCHAR* Path, WCHAR** pRelocation, BOOLEAN CheckChildren);
static BOOLEAN Key_SavePathTree();
static BOOLEAN Key_LoadPathTree();
static VOID Key_RefreshPathTree();
BOOLEAN Key_InitDelete_v2();
VOID Key_SetDeleteV3RefreshInterval(ULONG IntervalMs);
VOID Key_SetDeleteV3(BOOLEAN Enabled);
VOID Key_SetDeleteV3JournalMaxSizeKB(ULONG MaxSizeKB);
VOID Key_SetDeleteV3JournalMaxLines(ULONG MaxLines);
VOID Key_SetDeleteV3JournalKeepOpenMs(ULONG KeepOpenMs);
VOID Key_SetDeleteV3CompactionBusyWritesPerSec(ULONG WritesPerSec);
VOID Key_SetDeleteV3CompactionBusyHoldMs(ULONG HoldMs);
VOID Key_SetDeleteV3CompactionMinGraceMs(ULONG MinGraceMs);
static NTSTATUS Key_MarkDeletedEx_v2(const WCHAR* TruePath, const WCHAR* ValueName);
static ULONG Key_IsDeleted_v2(const WCHAR* TruePath);
static ULONG Key_IsDeletedEx_v2(const WCHAR* TruePath, const WCHAR* ValueName, BOOLEAN IsValue);

//
// we re use the _internal functions of the file implementation as they all are generic enough
//

typedef struct _PATH_TREE_BUF {
    WCHAR*  Data;
    ULONG   Used;   // WCHARs stored
    ULONG   Cap;    // WCHARs allocated
    BOOLEAN OOM;    // set on Dll_Alloc failure
} PATH_TREE_BUF;

VOID File_ClearPathBranche_internal(PATH_LIST* parent);
BOOLEAN File_OpenDataFile(const WCHAR* name, HANDLE* hPathsFile, BOOLEAN Append);
BOOLEAN File_OpenDataFileAppendShared(const WCHAR* name, HANDLE* hPathsFile);
BOOLEAN File_SeekToEndOfFile(HANDLE fileHandle);
BOOLEAN File_AppendPathEntry_internal(HANDLE hPathsFile, const WCHAR* Path, ULONG SetFlags, const WCHAR* Relocation, WCHAR* (*TranslatePath)(const WCHAR*));
ULONG File_AppendPathJournalDelete_internal(HANDLE hPathsFile, const WCHAR* Path, WCHAR* (*TranslatePath)(const WCHAR*), BOOLEAN isV3);
ULONG File_AppendPathJournalRelocation_internal(HANDLE hPathsFile, const WCHAR* OldPath, const WCHAR* NewPath, WCHAR* (*TranslatePath)(const WCHAR*), BOOLEAN isV3);
BOOLEAN File_SavePathTree_internal(PATH_LIST* Root, const WCHAR* name, WCHAR* (*TranslatePath)(const WCHAR *));
BOOLEAN File_LoadPathTree_internal(PATH_LIST* Root, const WCHAR* name, WCHAR* (*TranslatePath)(const WCHAR *));
BOOLEAN File_LoadPathJournal_internal(PATH_LIST* Root, const WCHAR* name, WCHAR* (*TranslatePath)(const WCHAR *), ULONG64* pReplayOffset, ULONG* pAppliedLines);
ULONG File_GetPathFlags_internal(PATH_LIST* Root, const WCHAR* Path, WCHAR** pRelocation, BOOLEAN CheckChildren);
BOOLEAN File_MarkDeleted_internal(PATH_LIST* Root, const WCHAR* Path, BOOLEAN* pTruncated);
VOID File_SetRelocation_internal(PATH_LIST* Root, const WCHAR* OldTruePath, const WCHAR* NewTruePath);
BOOLEAN File_CompactPathJournal_internal(CRITICAL_SECTION* CritSec, PATH_LIST* Root, const WCHAR* datName, const WCHAR* logName, WCHAR* (*TranslatePath)(const WCHAR*), WCHAR* (*TranslatePathForLoad)(const WCHAR*), ULONG64* pLogSize, ULONG64* pLogDate, ULONG64* pReplayOffset, HANDLE* pAppendHandle, BOOLEAN isV3);
VOID File_UpdateJournalState_internal(ULONG BytesWritten, ULONG64* pLogFileSize, ULONG64* pReplayOffset, ULONG* pLogLineCount, ULONG WritesPerSecThreshold, ULONG HoldMs, ULONG MinGraceMs, ULONG* pRecentWriteCount, ULONG* pRecentWriteWindowTick, ULONG* pBusyUntilTick);
BOOLEAN File_ShouldCompactJournal_internal(ULONG WritesPerSecThreshold, ULONG BusyUntilTick, ULONG64 LogFileSize, ULONG MaxSizeBytes, ULONG LogLineCount, ULONG MaxLines);
BOOLEAN File_TryAcquireCompactionMarker(HANDLE* hCompactMutex, const WCHAR* name);
VOID File_AtomicTickMax(volatile LONG* pShared, ULONG newVal);
VOID File_SerializePathNodeToBufferV3(PATH_TREE_BUF* Buf, PATH_LIST* parent, WCHAR* Path, ULONG Length, ULONG SetFlags, WCHAR* (*TranslatePath)(const WCHAR*));
BOOLEAN File_WriteBufferToDataFile(const WCHAR* name, const WCHAR* data, ULONG cch);
// Names are built at init time (Key_InitDelete_v2) to include Dll_BoxName.
#define KEY_VCM_COMPACT_MUTEX Key_VcmCompactMutexName
#define KEY_VCM_BUSY_TICK     Key_VcmBusyTickName

BOOL File_InitBoxRootWatcher();
BOOL File_TestBoxRootChange(ULONG WatchBit);

BOOL File_GetAttributes_internal(const WCHAR *name, ULONG64 *size, ULONG64 *date, ULONG *attrs);

HANDLE File_AcquireMutex(const WCHAR* MutexName);
void File_ReleaseMutex(HANDLE hMutex);
#define KEY_VCM_MUTEX Key_VcmMutexName

static VOID Key_ComposeValuePath(WCHAR* outPath, const WCHAR* TruePath, const WCHAR* ValueName, WCHAR Marker)
{
    wcscpy(outPath, TruePath);
    {
        ULONG len = (ULONG)wcslen(outPath);
        outPath[len] = L'\\';
        outPath[len + 1] = Marker;
        outPath[len + 2] = L'\0';
    }
    wcscat(outPath, ValueName);
}


//---------------------------------------------------------------------------
// Key_GetPathFlags
//---------------------------------------------------------------------------


_FX ULONG Key_GetPathFlags(const WCHAR* Path, WCHAR** pRelocation, BOOLEAN CheckChildren)
{
    ULONG Flags;

    Key_RefreshPathTree();

    EnterCriticalSection(Key_PathRoot_CritSec);

    Flags = File_GetPathFlags_internal(&Key_PathRoot, Path, pRelocation, CheckChildren);

    LeaveCriticalSection(Key_PathRoot_CritSec);

    return Flags;
}


//---------------------------------------------------------------------------
// Key_SavePathTree
//---------------------------------------------------------------------------


_FX BOOLEAN Key_SavePathTree()
{
    const WCHAR* datName = Key_DeleteV3 ? KEY_PATH_FILE_NAME_V3 : KEY_PATH_FILE_NAME;

    EnterCriticalSection(Key_PathRoot_CritSec);

    if (Key_DeleteV3) {
        PATH_TREE_BUF buf = { NULL, 0, 0, FALSE };
        WCHAR* tmpPath = (WCHAR*)Dll_Alloc((0x7FFF + 1) * sizeof(WCHAR));
        if (tmpPath) {
            File_SerializePathNodeToBufferV3(&buf, &Key_PathRoot, tmpPath, 0, 0, NULL);
            Dll_Free(tmpPath);
        } else {
            buf.OOM = TRUE; // Treat tmpPath alloc failure as OOM to avoid truncating the .dat
        }
        if (!buf.OOM)
            File_WriteBufferToDataFile(datName, buf.Data, buf.Used);
        if (buf.Data)
            Dll_Free(buf.Data);
    } else {
        File_SavePathTree_internal(&Key_PathRoot, datName, NULL);
    }

    File_GetAttributes_internal(datName, &Key_PathsFileSize, &Key_PathsFileDate, NULL);

    //Key_PathsVersion++;

    LeaveCriticalSection(Key_PathRoot_CritSec);

    return TRUE;
}


//---------------------------------------------------------------------------
// Key_LoadPathTree
//---------------------------------------------------------------------------


_FX BOOLEAN Key_LoadPathTree()
{
    const WCHAR* datName = Key_DeleteV3 ? KEY_PATH_FILE_NAME_V3 : KEY_PATH_FILE_NAME;
    const WCHAR* logName = Key_DeleteV3 ? KEY_PATH_LOG_FILE_NAME_V3 : KEY_PATH_LOG_FILE_NAME;

    DWORD wait_res = WaitForSingleObject(Key_VcmMutex, 5000);
    if (wait_res != WAIT_OBJECT_0 && wait_res != WAIT_ABANDONED)
        return FALSE;

    EnterCriticalSection(Key_PathRoot_CritSec);

    if (Key_DeleteV3) {
        // V3 .dat uses the same opcode format as .sbie; reuse the journal parser.
        File_ClearPathBranche_internal(&Key_PathRoot);
        ULONG64 dummy_offset = 0;
        Key_RegPaths_Loaded = File_LoadPathJournal_internal(&Key_PathRoot, datName, NULL, &dummy_offset, NULL);

        // V3: always replay the .sbie journal on top of the .dat
        ULONG applied_lines = 0;
        Key_PathsLogReplayOffset = 0;
        File_LoadPathJournal_internal(&Key_PathRoot, logName, NULL, &Key_PathsLogReplayOffset, &applied_lines);
        Key_PathsLogLineCount = applied_lines;
        if (applied_lines > 0)
            Key_RegPaths_Loaded = TRUE;
    } else {
        // V2: legacy .dat format only — no journal interaction.
        Key_RegPaths_Loaded = File_LoadPathTree_internal(&Key_PathRoot, datName, NULL);
    }

    LeaveCriticalSection(Key_PathRoot_CritSec);

    ReleaseMutex(Key_VcmMutex);

    Key_PathsVersion++;

    return TRUE;
}


//---------------------------------------------------------------------------
// Key_RefreshPathTree
//---------------------------------------------------------------------------


_FX VOID Key_RefreshPathTree()
{
    const WCHAR* datName = Key_DeleteV3 ? KEY_PATH_FILE_NAME_V3 : KEY_PATH_FILE_NAME;
    const WCHAR* logName = Key_DeleteV3 ? KEY_PATH_LOG_FILE_NAME_V3 : KEY_PATH_LOG_FILE_NAME;

    ULONG ticks_now = GetTickCount();
    LONG ticks_prev = InterlockedExchangeAdd(&Key_LastRefreshTick, 0);
    if ((LONG)(ticks_now - (ULONG)ticks_prev) < (LONG)Key_PathRefreshIntervalMs)
        return;
    InterlockedExchange(&Key_LastRefreshTick, (LONG)ticks_now);

    // The box-root watcher is an optimization. Some systems may occasionally miss
    // change notifications for sidecar journals, so we also poll metadata here.
    BOOLEAN boxChanged = File_TestBoxRootChange(1);

    ULONG64 PathsFileSize = 0;
    ULONG64 PathsFileDate = 0;
    ULONG64 PathsLogFileSize = 0;
    ULONG64 PathsLogFileDate = 0;

    BOOLEAN bReload = FALSE;
    BOOLEAN bDatChanged = FALSE;
    BOOLEAN bLogChanged = FALSE;
    if (File_GetAttributes_internal(datName, &PathsFileSize, &PathsFileDate, NULL)
        && (Key_PathsFileSize != PathsFileSize || Key_PathsFileDate != PathsFileDate)) {

        // Don't update globals yet; defer until after reload succeeds.
        bReload = TRUE;
        bDatChanged = TRUE;
    }

    if (Key_DeleteV3
        && File_GetAttributes_internal(logName, &PathsLogFileSize, &PathsLogFileDate, NULL)
        && (Key_PathsLogFileSize != PathsLogFileSize || Key_PathsLogFileDate != PathsLogFileDate)) {

        // Don't update globals yet; defer until after reload succeeds.
        bLogChanged = TRUE;
        bReload = TRUE;
    }

    if (!bReload && !boxChanged)
        return;

    if (bReload) {
        //
        // something changed, reload the path tree
        //
        if (bDatChanged || !Key_DeleteV3) {
            if (Key_LoadPathTree()) {
                if (bDatChanged) {
                    Key_PathsFileSize = PathsFileSize;
                    Key_PathsFileDate = PathsFileDate;
                }
                if (bLogChanged) {
                    Key_PathsLogFileSize = PathsLogFileSize;
                    Key_PathsLogFileDate = PathsLogFileDate;
                }
            }
        } else {
            DWORD wait_res = WaitForSingleObject(Key_VcmMutex, 5000);
            if (wait_res != WAIT_OBJECT_0 && wait_res != WAIT_ABANDONED) {
                // mutex not acquired — do a safe full reload instead
                Key_LoadPathTree();
                return;
            }
            EnterCriticalSection(Key_PathRoot_CritSec);

            ULONG64 old_replay_offset = Key_PathsLogReplayOffset;
            ULONG applied_lines = 0;
            if (!File_LoadPathJournal_internal(&Key_PathRoot, logName, NULL, &Key_PathsLogReplayOffset, &applied_lines)) {
                LeaveCriticalSection(Key_PathRoot_CritSec);
                ReleaseMutex(Key_VcmMutex);
                Key_LoadPathTree();
                return;
            }
            // If the journal shrank, another process compacted it and updated
            // the .dat.  The incremental replay would miss those compacted entries,
            // so fall back to a full reload to pick up the new .dat state.
            if (Key_PathsLogReplayOffset < old_replay_offset) {
                LeaveCriticalSection(Key_PathRoot_CritSec);
                ReleaseMutex(Key_VcmMutex);
                Key_LoadPathTree();
                return;
            }
            Key_PathsLogLineCount += applied_lines;
            Key_PathsVersion++;

            if (bLogChanged) {
                Key_PathsLogFileSize = PathsLogFileSize;
                Key_PathsLogFileDate = PathsLogFileDate;
            }
            LeaveCriticalSection(Key_PathRoot_CritSec);
            ReleaseMutex(Key_VcmMutex);
        }
    }
}


//---------------------------------------------------------------------------
// Key_SetDeleteV3RefreshInterval
//---------------------------------------------------------------------------


_FX VOID Key_SetDeleteV3RefreshInterval(ULONG IntervalMs)
{
    if (IntervalMs > 5000)
        IntervalMs = 5000;
    Key_PathRefreshIntervalMs = IntervalMs;
}


//---------------------------------------------------------------------------
// Key_SetDeleteV3
//---------------------------------------------------------------------------


_FX VOID Key_SetDeleteV3(BOOLEAN Enabled)
{
    Key_DeleteV3 = Enabled;
    Key_CurrentLogName = Enabled ? KEY_PATH_LOG_FILE_NAME_V3 : KEY_PATH_LOG_FILE_NAME;
    Key_CurrentDatName = Enabled ? KEY_PATH_FILE_NAME_V3 : KEY_PATH_FILE_NAME;
}


//---------------------------------------------------------------------------
// Key_SetDeleteV3JournalMaxSizeKB
//---------------------------------------------------------------------------


_FX VOID Key_SetDeleteV3JournalMaxSizeKB(ULONG MaxSizeKB)
{
    // Cap at the per-bitness hard-cap so user-configured compaction always fires
    // before the hard cap: 512 MB on 64-bit, 256 MB on 32-bit.
#ifdef _WIN64
    if (MaxSizeKB > 512 * 1024)
        MaxSizeKB = 512 * 1024;
#else
    if (MaxSizeKB > 256 * 1024)
        MaxSizeKB = 256 * 1024;
#endif
    Key_DeleteV3JournalMaxSizeBytes = MaxSizeKB * 1024;
}


//---------------------------------------------------------------------------
// Key_SetDeleteV3JournalMaxLines
//---------------------------------------------------------------------------


_FX VOID Key_SetDeleteV3JournalMaxLines(ULONG MaxLines)
{
    if (MaxLines > 100000000)
        MaxLines = 100000000;
    Key_DeleteV3JournalMaxLines = MaxLines;
}


//---------------------------------------------------------------------------
// Key_SetDeleteV3JournalKeepOpenMs
//---------------------------------------------------------------------------


_FX VOID Key_SetDeleteV3JournalKeepOpenMs(ULONG KeepOpenMs)
{
    if (KeepOpenMs > 60000)
        KeepOpenMs = 60000;
    Key_DeleteV3JournalKeepOpenMs = KeepOpenMs;
}


//---------------------------------------------------------------------------
// Key_SetDeleteV3CompactionBusyWritesPerSec
//---------------------------------------------------------------------------


_FX VOID Key_SetDeleteV3CompactionBusyWritesPerSec(ULONG WritesPerSec)
{
    if (WritesPerSec > 100000)
        WritesPerSec = 100000;
    Key_DeleteV3CompactionBusyWritesPerSec = WritesPerSec;
}


//---------------------------------------------------------------------------
// Key_SetDeleteV3CompactionBusyHoldMs
//---------------------------------------------------------------------------


_FX VOID Key_SetDeleteV3CompactionBusyHoldMs(ULONG HoldMs)
{
    if (HoldMs > 300000)
        HoldMs = 300000;
    Key_DeleteV3CompactionBusyHoldMs = HoldMs;
}


//---------------------------------------------------------------------------
// Key_SetDeleteV3CompactionMinGraceMs
//---------------------------------------------------------------------------


_FX VOID Key_SetDeleteV3CompactionMinGraceMs(ULONG MinGraceMs)
{
    if (MinGraceMs > 300000)
        MinGraceMs = 300000;
    Key_DeleteV3CompactionMinGraceMs = MinGraceMs;
}


//---------------------------------------------------------------------------
// Key_InitDelete_v2
//---------------------------------------------------------------------------


_FX BOOLEAN Key_InitDelete_v2()
{
    memzero(&Key_PathRoot, sizeof(PATH_LIST));

    Key_PathRoot_CritSec = Dll_Alloc(sizeof(CRITICAL_SECTION));
    InitializeCriticalSectionAndSpinCount(Key_PathRoot_CritSec, 1000);

    // Build per-box named-object names. Including Dll_BoxName means that even
    // if a box has an OpenIpcPath rule matching "SBIE*", processes in different
    // boxes cannot share these synchronisation objects.
    Sbie_snwprintf(Key_VcmMutexName,        ARRAYSIZE(Key_VcmMutexName),        L"SBIE_%s_VCM_Mutex",         Dll_BoxName);
    Sbie_snwprintf(Key_VcmCompactMutexName, ARRAYSIZE(Key_VcmCompactMutexName), L"SBIE_%s_VCM_Compact_Mutex", Dll_BoxName);
    Sbie_snwprintf(Key_VcmBusyTickName,     ARRAYSIZE(Key_VcmBusyTickName),     L"SBIE_%s_VCM_BusyTick",      Dll_BoxName);

    // Create the inter-process mutex BEFORE calling Key_LoadPathTree so the
    // initial load is correctly serialized against other processes.
    {
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = SbieDll_GetPublicSD();
        sa.bInheritHandle = FALSE;
        Key_VcmMutex = CreateMutex(&sa, FALSE, KEY_VCM_MUTEX);
    }

    if (Key_DeleteV3) {
        // Named page-file-backed section for cross-process burst-deferral (registry journal).
        // Only needed in v3 journal mode.
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = SbieDll_GetPublicSD();
        sa.bInheritHandle = FALSE;
        Key_SharedBusyHandle = CreateFileMapping(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, sizeof(LONG), KEY_VCM_BUSY_TICK);
        if (Key_SharedBusyHandle)
            Key_SharedBusyUntilTick = (volatile LONG*)MapViewOfFile(Key_SharedBusyHandle, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(LONG));

        // Initialise the registry VCM journal context used by Vfs_AppendAndMaybeCompact_internal.
        Key_JournalCtx.pLogName            = &Key_CurrentLogName;
        Key_JournalCtx.pDatName            = &Key_CurrentDatName;
        Key_JournalCtx.TranslateForWrite   = NULL;
        Key_JournalCtx.TranslateForLoad    = NULL;
        Key_JournalCtx.CritSec             = Key_PathRoot_CritSec;
        Key_JournalCtx.Root                = &Key_PathRoot;
        Key_JournalCtx.pAppendHandle       = &Key_PathsLogAppendHandle;
        Key_JournalCtx.pAppendLastTick     = &Key_PathsLogAppendLastTick;
        Key_JournalCtx.pKeepOpenMs         = &Key_DeleteV3JournalKeepOpenMs;
        Key_JournalCtx.pLogFileSize        = &Key_PathsLogFileSize;
        Key_JournalCtx.pLogFileDate        = &Key_PathsLogFileDate;
        Key_JournalCtx.pReplayOffset       = &Key_PathsLogReplayOffset;
        Key_JournalCtx.pLogLineCount       = &Key_PathsLogLineCount;
        Key_JournalCtx.pMaxSizeBytes       = &Key_DeleteV3JournalMaxSizeBytes;
        Key_JournalCtx.pMaxLines           = &Key_DeleteV3JournalMaxLines;
        Key_JournalCtx.pBusyWritesPerSec   = &Key_DeleteV3CompactionBusyWritesPerSec;
        Key_JournalCtx.pBusyHoldMs         = &Key_DeleteV3CompactionBusyHoldMs;
        Key_JournalCtx.pMinGraceMs         = &Key_DeleteV3CompactionMinGraceMs;
        Key_JournalCtx.pRecentWriteCount   = &Key_RecentWriteCount;
        Key_JournalCtx.pRecentWriteWindowTick = &Key_RecentWriteWindowTick;
        Key_JournalCtx.pBusyUntilTick      = &Key_CompactionBusyUntilTick;
        Key_JournalCtx.pSharedBusyUntilTick = Key_SharedBusyUntilTick;
        Key_JournalCtx.compactMutexName    = Key_VcmCompactMutexName;
        Key_JournalCtx.pDatFileSize        = &Key_PathsFileSize;
        Key_JournalCtx.pDatFileDate        = &Key_PathsFileDate;
        Key_JournalCtx.pIsV3               = &Key_DeleteV3;
    }

    Key_LoadPathTree(); // sets Key_PathsLogReplayOffset and Key_PathsLogLineCount

//#ifdef WITH_DEBUG
//    Key_SavePathTree();
//#endif

    // Update the dat/log size+date caches used by Key_RefreshPathTree for
    // change-detection.  Key_LoadPathTree does not update these in journal mode.
    {
        const WCHAR* datName = Key_DeleteV3 ? KEY_PATH_FILE_NAME_V3 : KEY_PATH_FILE_NAME;
        const WCHAR* logName = Key_DeleteV3 ? KEY_PATH_LOG_FILE_NAME_V3 : KEY_PATH_LOG_FILE_NAME;
        File_GetAttributes_internal(datName, &Key_PathsFileSize, &Key_PathsFileDate, NULL);
        if (Key_DeleteV3)
            File_GetAttributes_internal(logName, &Key_PathsLogFileSize, &Key_PathsLogFileDate, NULL);
    }
    // NOTE: do NOT reset Key_PathsLogReplayOffset / Key_PathsLogLineCount here;
    // Key_LoadPathTree already initialised them correctly.
    Key_PathsLogAppendLastTick = 0;
    if (Key_PathsLogAppendHandle) {
        NtClose(Key_PathsLogAppendHandle);
        Key_PathsLogAppendHandle = NULL;
    }

    File_InitBoxRootWatcher();

    return TRUE;
}


//---------------------------------------------------------------------------
// Key_MarkDeletedEx_v2
//---------------------------------------------------------------------------


_FX NTSTATUS Key_MarkDeletedEx_v2(const WCHAR* TruePath, const WCHAR* ValueName)
{
    //
    // add a key/value or directory to the deleted list
    //

    DWORD wait_res = WaitForSingleObject(Key_VcmMutex, 5000);
    if (wait_res != WAIT_OBJECT_0 && wait_res != WAIT_ABANDONED)
        return STATUS_TIMEOUT;

    THREAD_DATA *TlsData = Dll_GetTlsData(NULL);

    WCHAR* FullPath = Dll_GetTlsNameBuffer(TlsData, TMPL_NAME_BUFFER, 
        (wcslen(TruePath) + (ValueName ? wcslen(ValueName) : 0) + 16) * sizeof(WCHAR)); // template buffer is not used for reg repurpose it here

    if (ValueName)
        Key_ComposeValuePath(FullPath, TruePath, ValueName, KEY_VALUE_SEGMENT_MARKER);
    else
        wcscpy(FullPath, TruePath);

    EnterCriticalSection(Key_PathRoot_CritSec);

    BOOLEAN bTruncated = FALSE;
    BOOLEAN bSet = File_MarkDeleted_internal(&Key_PathRoot, FullPath, &bTruncated);

    LeaveCriticalSection(Key_PathRoot_CritSec);

    if (bSet) 
    {
        if (Key_DeleteV3) {
            // For value deletes, pass (TruePath, ValueName) to emit opcode 3.
            // For key deletes, pass (FullPath, NULL) to emit opcode 1.
            if (!Vfs_AppendAndMaybeCompact_internal(&Key_JournalCtx, TRUE, ValueName ? TruePath : FullPath, ValueName))
                Key_SavePathTree();
        }
        else
        {
        //
        // Optimization: When marking a lot of host keys as deleted, only append single line entries if possible instead of re creating the entire file
        //

        ULONG64 PathsFileSize = 0;
        ULONG64 PathsFileDate = 0;
        if (!bTruncated 
            && File_GetAttributes_internal(KEY_PATH_FILE_NAME, &PathsFileSize, &PathsFileDate, NULL)
            && (Key_PathsFileSize == PathsFileSize && Key_PathsFileDate == PathsFileDate)) {

            HANDLE hPathsFile;
            if (File_OpenDataFile(KEY_PATH_FILE_NAME, &hPathsFile, TRUE))
            {
                BOOLEAN ok = File_AppendPathEntry_internal(hPathsFile, FullPath, KEY_DELETED_FLAG, NULL, NULL);

                NtClose(hPathsFile);

                //Key_PathsVersion++;

                if (ok)
                    File_GetAttributes_internal(KEY_PATH_FILE_NAME, &Key_PathsFileSize, &Key_PathsFileDate, NULL);
                else
                    Key_SavePathTree();
            }
        }
        else
            Key_SavePathTree();
        }
    }

    ReleaseMutex(Key_VcmMutex);

    return STATUS_SUCCESS;
}


//---------------------------------------------------------------------------
// Key_IsDeleted_v2
//---------------------------------------------------------------------------


_FX ULONG Key_IsDeleted_v2(const WCHAR* TruePath)
{
    //
    // check if the key/value or one of its parent directories is listed as deleted
    //

    ULONG Flags = Key_GetPathFlags(TruePath, NULL, FALSE);

    return (Flags & KEY_DELETED_MASK);
}


//---------------------------------------------------------------------------
// Key_IsDeletedEx_v2
//---------------------------------------------------------------------------


_FX ULONG Key_IsDeletedEx_v2(const WCHAR* TruePath, const WCHAR* ValueName, BOOLEAN IsValue)
{
    //
    // check if the key/value or one of its parent directories is listed as deleted
    //

    THREAD_DATA *TlsData = Dll_GetTlsData(NULL);

    WCHAR* FullPath = Dll_GetTlsNameBuffer(TlsData, TMPL_NAME_BUFFER, 
        (wcslen(TruePath) + (ValueName ? wcslen(ValueName) : 0) + 16) * sizeof(WCHAR)); // template buffer is not used for reg repurpose it here

    wcscpy(FullPath, TruePath);
    if (ValueName) {
        if (IsValue) {
            // Both v2 and v3 use '$' as the in-memory value-delete marker.
            Key_ComposeValuePath(FullPath, TruePath, ValueName, KEY_VALUE_SEGMENT_MARKER);
            return Key_IsDeleted_v2(FullPath);
        }

        wcscat(FullPath, L"\\");
        wcscat(FullPath, ValueName);
    }

    return Key_IsDeleted_v2(FullPath);
}


//---------------------------------------------------------------------------
// Key_HasDeleted_v2
//---------------------------------------------------------------------------


_FX BOOLEAN Key_HasDeleted_v2(const WCHAR* TruePath)
{
    //
    // Check if this folder has deleted children
    //

    ULONG Flags = Key_GetPathFlags(TruePath, NULL, TRUE);

    return (Flags & KEY_CHILDREN_DELETED_FLAG) != 0;
}


//---------------------------------------------------------------------------
// Key_SetRelocation
//---------------------------------------------------------------------------


_FX NTSTATUS Key_SetRelocation(const WCHAR *OldTruePath, const WCHAR *NewTruePath)
{
    //
    // List a mapping for the new location
    //

    DWORD wait_res = WaitForSingleObject(Key_VcmMutex, 5000);
    if (wait_res != WAIT_OBJECT_0 && wait_res != WAIT_ABANDONED)
        return STATUS_TIMEOUT;

    EnterCriticalSection(Key_PathRoot_CritSec);

    File_SetRelocation_internal(&Key_PathRoot, OldTruePath, NewTruePath);

    LeaveCriticalSection(Key_PathRoot_CritSec);

    if (Key_DeleteV3) {
        if (!Vfs_AppendAndMaybeCompact_internal(&Key_JournalCtx, FALSE, OldTruePath, NewTruePath))
            Key_SavePathTree();
    }
    else {
        Key_SavePathTree();
    }

    ReleaseMutex(Key_VcmMutex);

    return STATUS_SUCCESS;
}


//---------------------------------------------------------------------------
// Key_GetRelocation
//---------------------------------------------------------------------------


_FX WCHAR* Key_GetRelocation(const WCHAR *TruePath)
{
    //
    // Get redirection location, only if its the actual path and not a parent
    // 

    WCHAR* OldTruePath = NULL;
    ULONG Flags = Key_GetPathFlags(TruePath, &OldTruePath, FALSE);
    if (KEY_PATH_RELOCATED(Flags))
        return OldTruePath;

    return NULL;
}


//---------------------------------------------------------------------------
// Key_ResolveTruePath
//---------------------------------------------------------------------------


_FX WCHAR* Key_ResolveTruePath(const WCHAR *TruePath, ULONG* PathFlags)
{
    //
    // Resolve the true path, taking into account redirection locations of parent folder
    // 

    WCHAR* OldTruePath = NULL;
    ULONG Flags = Key_GetPathFlags(TruePath, &OldTruePath, FALSE);
    if (PathFlags) *PathFlags = Flags;

    return OldTruePath;
}

