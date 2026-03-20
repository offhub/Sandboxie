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

//---------------------------------------------------------------------------
// File (Delete)
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
// Defines
//---------------------------------------------------------------------------

#define FILE_PATH_FILE_NAME     L"FilePaths.dat"
#define FILE_PATH_LOG_FILE_NAME L"FilePaths.sbie"

// Delete V3 file names — used exclusively in v3 mode.
// V3 = V2 + forced journaling + new format (escaped entries, opcode 3 for reg values).
// Not backward compatible with v2 files; switching requires a clean box.
#define FILE_PATH_FILE_NAME_V3     L"FilePaths_v3.dat"
#define FILE_PATH_LOG_FILE_NAME_V3 L"FilePaths_v3.sbie"

// Hard-cap: force compaction regardless of user settings or burst state.
// 64-bit: 512 MB (MaxSizeKB limit 1 GB / 2); 32-bit: 256 MB (1 GB / 4)
#ifdef _WIN64
#define FILE_JOURNAL_HARD_CAP_BYTES  (512UL * 1024UL * 1024UL)
#else
#define FILE_JOURNAL_HARD_CAP_BYTES  (256UL * 1024UL * 1024UL)
#endif

// path flags, saved to file
#define FILE_DELETED_FLAG       0x0001
#define FILE_RELOCATION_FLAG    0x0002

// internal volatile status flags
#define FILE_PATH_DELETED_FLAG      0x00010000
#define FILE_PATH_RELOCATED_FLAG    0x00020000
#define FILE_CHILDREN_DELETED_FLAG  0x00040000

#define FILE_DELETED_MASK   (FILE_DELETED_FLAG | FILE_PATH_DELETED_FLAG) 
#define FILE_RELOCATED_MASK (FILE_RELOCATION_FLAG | FILE_PATH_RELOCATED_FLAG) 

#define FILE_IS_DELETED(x)      ((x & FILE_DELETED_FLAG) != 0)
#define FILE_PATH_DELETED(x)    ((x & FILE_DELETED_MASK) != 0)
#define FILE_PARENT_DELETED(x)  ((x & FILE_PATH_DELETED_FLAG) != 0)
#define FILE_PATH_RELOCATED(x)  ((x & FILE_RELOCATED_MASK) != 0)

//---------------------------------------------------------------------------
// Structures and Types
//---------------------------------------------------------------------------

#define PATH_LIST_HASH_THRESHOLD  8    // switch to hash table above this many children
#define PATH_LIST_INITIAL_BUCKETS 16   // initial bucket count (must be power of 2)

typedef struct _PATH_NODE PATH_NODE;
typedef struct _PATH_LIST {
    LIST         list;          // MUST be first member — cast to LIST* is always valid
    PATH_NODE**  buckets;       // hash buckets (NULL while list.count <= threshold)
    ULONG        bucket_count;  // number of buckets, always a power of 2
} PATH_LIST;

typedef struct _PATH_NODE {
    LIST_ELEM    list_elem;
    PATH_LIST    items;         // children list + optional hash table
    PATH_NODE*   hash_chain;    // intrusive chain within parent's hash bucket
    ULONG        flags;
    WCHAR*       relocation;
    ULONG        name_hash;     // FNV-1a case-insensitive hash of name[]
    ULONG        name_len;
    WCHAR        name[1];
} PATH_NODE;


//---------------------------------------------------------------------------
// Variables
//---------------------------------------------------------------------------


static PATH_LIST File_PathRoot;
static CRITICAL_SECTION *File_PathRoot_CritSec = NULL;

static HANDLE File_BoxRootWatcher = NULL;
static IO_STATUS_BLOCK File_NotifyIosb;
static FILE_NOTIFY_INFORMATION File_NotifyInfo[2];
static ULONG File_BoxRootChangeBits = 0;
static HANDLE File_VfsMutex = NULL;

static ULONG64 File_PathsFileSize = 0;
static ULONG64 File_PathsFileDate = 0;
static ULONG64 File_PathsLogFileSize = 0;
static ULONG64 File_PathsLogFileDate = 0;
static ULONG64 File_PathsLogReplayOffset = 0;
static ULONG File_PathsLogLineCount = 0;
static volatile LONG File_LastRefreshTick = 0;
static volatile ULONG File_PathsVersion = 0; // bumped on every path-tree reload; observed by File_Merge
static ULONG File_PathRefreshIntervalMs = 50;
static BOOLEAN File_DeleteV3 = FALSE; // v3 mode: journal + new format always enabled
static ULONG File_DeleteV3JournalMaxSizeBytes = 1024 * 1024;
static ULONG File_DeleteV3JournalMaxLines = 10000;
static ULONG File_DeleteV3JournalKeepOpenMs = 0;
static HANDLE File_PathsLogAppendHandle = NULL;
static ULONG File_PathsLogAppendLastTick = 0;

static ULONG File_DeleteV3CompactionBusyWritesPerSec = 100;  // 0 = burst-defer disabled
static ULONG File_DeleteV3CompactionBusyHoldMs = 60000;    // hold window after burst detected (ms)
static ULONG File_DeleteV3CompactionMinGraceMs = 5000;     // min grace before first compaction (ms)
static ULONG File_CompactionBusyUntilTick = 0;             // process-local defer-until tick
static ULONG File_RecentWriteCount = 0;                    // writes in current rate window
static ULONG File_RecentWriteWindowTick = 0;               // start tick of current rate window

static HANDLE           File_SharedBusyHandle = NULL;       // named section handle
static volatile LONG*   File_SharedBusyUntilTick = NULL;    // mapped cross-process BusyUntilTick

// Per-box named object names — populated in File_InitDelete_v2 with Dll_BoxName so that
// boxes sharing an OpenIpcPath=*SBIE* rule cannot cross-contaminate each other's
// compaction locks or burst-deferral counters.
// Worst-case length: "SBIE_" + 32-char box name + "_VFS_Compact_Mutex" + NUL = 56 WCHAR.
static WCHAR File_VfsMutexName[64];
static WCHAR File_VfsCompactMutexName[64];
static WCHAR File_VfsBusyTickName[64];

//---------------------------------------------------------------------------
// VPATH_JOURNAL_CTX — bundles all per-VFS journal state so that the shared
// Vfs_AppendAndMaybeCompact_internal helper can serve both the file VFS and
// the registry VCM journal without code duplication.
// key_del.c re-declares this struct (must keep in sync).
//---------------------------------------------------------------------------

typedef struct _VPATH_JOURNAL_CTX {
    // Log (.sbie) and snapshot (.dat) file names — pointer-to-pointer so the
    // ctx always reflects the current mode even if File_SetDeleteV3 is called
    // after init.
    const WCHAR**       pLogName;
    const WCHAR**       pDatName;
    // Path translation callbacks (NULL = no translation, e.g. registry paths)
    WCHAR*        (*TranslateForWrite)(const WCHAR*);
    WCHAR*        (*TranslateForLoad)(const WCHAR*);
    // Critical section and in-memory tree
    CRITICAL_SECTION*   CritSec;
    PATH_LIST*          Root;
    // Keep-open append handle cache
    HANDLE*             pAppendHandle;
    ULONG*              pAppendLastTick;
    ULONG*              pKeepOpenMs;
    // Journal size / replay tracking
    ULONG64*            pLogFileSize;
    ULONG64*            pLogFileDate;
    ULONG64*            pReplayOffset;
    ULONG*              pLogLineCount;
    // Compaction thresholds (pointers so runtime setter changes are picked up)
    ULONG*              pMaxSizeBytes;
    ULONG*              pMaxLines;
    // Burst-deferral settings
    ULONG*              pBusyWritesPerSec;
    ULONG*              pBusyHoldMs;
    ULONG*              pMinGraceMs;
    // Burst-deferral counters
    ULONG*              pRecentWriteCount;
    ULONG*              pRecentWriteWindowTick;
    ULONG*              pBusyUntilTick;
    volatile LONG*      pSharedBusyUntilTick;
    // Compaction mutex name (points to a per-box [64]-char WCHAR array)
    WCHAR*              compactMutexName;
    // Snapshot (.dat) size/date tracking — updated post-compact
    ULONG64*            pDatFileSize;
    ULONG64*            pDatFileDate;
    // v3 mode flag — pointer so the ctx tracks the live global
    BOOLEAN*            pIsV3;
} VPATH_JOURNAL_CTX;

static VPATH_JOURNAL_CTX File_JournalCtx;
static const WCHAR* File_CurrentLogName;
static const WCHAR* File_CurrentDatName;

//---------------------------------------------------------------------------
// Functions
//---------------------------------------------------------------------------

static ULONG File_GetPathFlags(const WCHAR* Path, WCHAR** pRelocation, BOOLEAN CheckChildren);
static const WCHAR* File_TrimTrailingBackslashes(const WCHAR* Path, int slot);
static BOOLEAN File_SavePathTree();
static BOOLEAN File_LoadPathTree();
static VOID File_RefreshPathTree();
BOOLEAN File_InitDelete_v2();
VOID File_SetDeleteV3RefreshInterval(ULONG IntervalMs);
VOID File_SetDeleteV3(BOOLEAN Enabled);
VOID File_SetDeleteV3JournalMaxSizeKB(ULONG MaxSizeKB);

static NTSTATUS File_MarkDeleted_v2(const WCHAR *TruePath);
static ULONG File_IsDeleted_v2(const WCHAR* TruePath);
static BOOLEAN File_HasDeleted_v2(const WCHAR* TruePath);
static WCHAR* File_GetRelocation(const WCHAR* TruePath);
static NTSTATUS File_SetRelocation(const WCHAR *OldTruePath, const WCHAR *NewTruePath);

BOOL File_InitBoxRootWatcher();
BOOL File_TestBoxRootChange(ULONG WatchBit);

BOOL File_GetAttributes_internal(const WCHAR *name, ULONG64 *size, ULONG64 *date, ULONG *attrs);

HANDLE File_AcquireMutex(const WCHAR* MutexName);
void File_ReleaseMutex(HANDLE hMutex);
// Names are built at init time (File_InitDelete_v2) to include Dll_BoxName,
// so that boxes with overlapping OpenIpcPath rules cannot share these objects.
#define FILE_VFS_MUTEX         File_VfsMutexName
#define FILE_VFS_COMPACT_MUTEX File_VfsCompactMutexName
// A 4-byte page-file-backed named section shared among all sandbox processes
// for the same sandbox.  Holds the cross-process BusyUntilTick (ULONG / LONG),
// atomically updated via InterlockedCompareExchange so no mutex is needed.
#define FILE_VFS_BUSY_TICK     File_VfsBusyTickName

#define FILE_UTF16_LE_BOM ((WCHAR)0xFEFF)

ULONG File_AppendPathJournalDelete_internal(HANDLE hPathsFile, const WCHAR* Path, WCHAR* (*TranslatePath)(const WCHAR*), BOOLEAN isV3);
ULONG File_AppendPathJournalRelocation_internal(HANDLE hPathsFile, const WCHAR* OldPath, const WCHAR* NewPath, WCHAR* (*TranslatePath)(const WCHAR*), BOOLEAN isV3);
ULONG File_AppendPathJournalValueDelete_internal(HANDLE hPathsFile, const WCHAR* KeyPath, const WCHAR* ValueName, WCHAR* (*TranslatePath)(const WCHAR*), BOOLEAN isV3);
BOOLEAN File_LoadPathJournal_internal(PATH_LIST* Root, const WCHAR* name, WCHAR* (*TranslatePath)(const WCHAR *), ULONG64* pReplayOffset, ULONG* pAppliedLines);
BOOLEAN File_MarkDeleted_internal(PATH_LIST* Root, const WCHAR* Path, BOOLEAN* pTruncated);
VOID File_SetRelocation_internal(PATH_LIST* Root, const WCHAR *OldTruePath, const WCHAR *NewTruePath);
BOOLEAN File_CompactPathJournal_internal(CRITICAL_SECTION* CritSec, PATH_LIST* Root, const WCHAR* datName, const WCHAR* logName, WCHAR* (*TranslatePath)(const WCHAR*), WCHAR* (*TranslatePathForLoad)(const WCHAR*), ULONG64* pLogSize, ULONG64* pLogDate, ULONG64* pReplayOffset, HANDLE* pAppendHandle, BOOLEAN isV3);
VOID File_UpdateJournalState_internal(ULONG BytesWritten, ULONG64* pLogFileSize, ULONG64* pReplayOffset, ULONG* pLogLineCount, ULONG WritesPerSecThreshold, ULONG HoldMs, ULONG MinGraceMs, ULONG* pRecentWriteCount, ULONG* pRecentWriteWindowTick, ULONG* pBusyUntilTick);
BOOLEAN File_ShouldCompactJournal_internal(ULONG WritesPerSecThreshold, ULONG BusyUntilTick, ULONG64 LogFileSize, ULONG MaxSizeBytes, ULONG LogLineCount, ULONG MaxLines);
VOID File_SetDeleteV3JournalMaxLines(ULONG MaxLines);
VOID File_SetDeleteV3JournalKeepOpenMs(ULONG KeepOpenMs);
VOID File_SetDeleteV3CompactionMinGraceMs(ULONG MinGraceMs);
VOID File_AtomicTickMax(volatile LONG* pShared, ULONG newVal);
BOOLEAN Vfs_AppendAndMaybeCompact_internal(VPATH_JOURNAL_CTX* ctx, BOOLEAN isDelete, const WCHAR* Path, const WCHAR* NewPath);

//---------------------------------------------------------------------------
// File_ClearPathBranche
//---------------------------------------------------------------------------


_FX VOID File_ClearPathBranche_internal(PATH_LIST* parent)
{
    PATH_NODE* child = List_Head(parent);
    while (child) {

        PATH_NODE* next_child = List_Next(child);

        File_ClearPathBranche_internal(&child->items);

        List_Remove((LIST*)parent, child);
        if(child->relocation) Dll_Free(child->relocation);
        Dll_Free(child);

        child = next_child;
    }
    if (parent->buckets) {
        Dll_Free(parent->buckets);
        parent->buckets = NULL;
        parent->bucket_count = 0;
    }
}


static ULONG PathNode_HashName(const WCHAR* name, ULONG len) {
    ULONG hash = 2166136261UL;
    for (ULONG i = 0; i < len; i++) {
        WCHAR c = name[i];
        if (c >= L'A' && c <= L'Z') c |= 0x20;
        hash ^= (ULONG)(USHORT)c;
        hash *= 16777619UL;
    }
    return hash;
}

static void PathList_BuildTable(PATH_LIST* parent, ULONG bucket_count) {
    parent->buckets = Dll_Alloc(bucket_count * sizeof(PATH_NODE*));
    if (!parent->buckets) return;
    memzero(parent->buckets, bucket_count * sizeof(PATH_NODE*));
    parent->bucket_count = bucket_count;
    PATH_NODE* child = List_Head(parent);
    while (child) {
        ULONG idx = child->name_hash & (bucket_count - 1);
        child->hash_chain = parent->buckets[idx];
        parent->buckets[idx] = child;
        child = List_Next(child);
    }
}

static void PathList_Rebuild(PATH_LIST* parent) {
    if (parent->buckets) {
        Dll_Free(parent->buckets);
        parent->buckets = NULL;
        parent->bucket_count = 0;
    }
    if (parent->list.count > PATH_LIST_HASH_THRESHOLD) {
        ULONG bc = PATH_LIST_INITIAL_BUCKETS;
        while ((ULONG)parent->list.count > bc * 3 / 4) bc <<= 1;
        PathList_BuildTable(parent, bc);
    }
}

static void PathList_RemoveFromTable(PATH_LIST* parent, PATH_NODE* node) {
    ULONG idx = node->name_hash & (parent->bucket_count - 1);
    PATH_NODE** pp = &parent->buckets[idx];
    while (*pp) {
        if (*pp == node) {
            *pp = node->hash_chain;
            break;
        }
        pp = &(*pp)->hash_chain;
    }
    node->hash_chain = NULL;
}


//---------------------------------------------------------------------------
// File_GetPathNode_internal
//---------------------------------------------------------------------------


_FX PATH_NODE* File_GetPathNode_internal(PATH_LIST* parent, const WCHAR* name, ULONG name_len, BOOLEAN can_add) 
{
    ULONG hash = PathNode_HashName(name, name_len);
    PATH_NODE* child;

    if (parent->buckets) {
        // O(1) hash lookup
        ULONG idx = hash & (parent->bucket_count - 1);
        child = parent->buckets[idx];
        while (child) {
            if (child->name_hash == hash && child->name_len == name_len
                    && _wcsnicmp(child->name, name, name_len) == 0)
                break;
            child = child->hash_chain;
        }
    } else {
        // O(n) linear scan for small lists
        child = List_Head(parent);
        while (child) {
            if (child->name_len == name_len && _wcsnicmp(child->name, name, name_len) == 0)
                break;
            child = List_Next(child);
        }
    }

    if (!child && can_add) {

        child = Dll_Alloc(sizeof(PATH_NODE) + name_len*sizeof(WCHAR));
        if (!child) return NULL;
        memzero(child, sizeof(PATH_NODE));
        child->name_len = name_len;
        child->name_hash = hash;
        wmemcpy(child->name, name, name_len);
        child->name[name_len] = L'\0';

        List_Insert_After((LIST*)parent, NULL, child);

        if (parent->buckets) {
            // Insert into existing table; grow if load factor exceeds 75%
            if ((ULONG)parent->list.count > parent->bucket_count * 3 / 4) {
                ULONG new_bc = parent->bucket_count * 2;
                Dll_Free(parent->buckets);
                parent->buckets = NULL;
                parent->bucket_count = 0;
                PathList_BuildTable(parent, new_bc);
            } else {
                ULONG idx = hash & (parent->bucket_count - 1);
                child->hash_chain = parent->buckets[idx];
                parent->buckets[idx] = child;
            }
        } else if (parent->list.count > PATH_LIST_HASH_THRESHOLD) {
            // Threshold crossed: build initial hash table
            PathList_BuildTable(parent, PATH_LIST_INITIAL_BUCKETS);
        }
    }

    return child;
}


//---------------------------------------------------------------------------
// File_FindPathBranche_internal
//---------------------------------------------------------------------------


_FX PATH_NODE* File_FindPathBranche_internal(PATH_LIST* Root, const WCHAR* Path, PATH_LIST** pParent, BOOLEAN can_add) 
{
    PATH_LIST* Parent = Root;
    PATH_NODE* Node;
    const WCHAR* next;
    for (const WCHAR* ptr = Path; *ptr; ptr = next + 1) {
        next = wcschr(ptr, L'\\');
        if (ptr == next) // handle initial \ as well as \\ or \\\ etc cases
            continue;
        if(!next) next = wcschr(ptr, L'\0'); // last
        
        Node = File_GetPathNode_internal(Parent, ptr, (ULONG)(next - ptr), can_add);
        if (!Node)
            return NULL;

        if (*next == L'\0') {
            if (pParent) *pParent = Parent;
            return Node;
        }
        Parent = &Node->items;
    }

    return NULL;
}


//---------------------------------------------------------------------------
// File_SetPathFlags_internal
//---------------------------------------------------------------------------


_FX VOID File_SetPathFlags_internal(PATH_LIST* Root, const WCHAR* Path, ULONG setFlags, ULONG clrFlags, const WCHAR* Relocation)
{
    PATH_LIST* Parent = Root;
    PATH_NODE* Node;
    const WCHAR* next;
    for (const WCHAR* ptr = Path; *ptr; ptr = next + 1) {
        next = wcschr(ptr, L'\\');
        if (ptr == next) // handle initial \ as well as \\ or \\\ etc cases
            continue;
        if(!next) next = wcschr(ptr, L'\0'); // last
        
        Node = File_GetPathNode_internal(Parent, ptr, (ULONG)(next - ptr), TRUE);
        if (!Node)
            return; // OOM: allocation of an intermediate or leaf node failed; silently abort.
                    // Callers (File_MarkDeleted_internal, File_SetRelocation_internal, the .dat
                    // loader) treat a missing node as "not deleted / not relocated", which is the
                    // safest degradation: a false-negative (guest code reaches real host files) is
                    // always better than a NULL-deref crash of the sandboxed process.

        if (*next == L'\0') { // set flag always on the last element only

            Node->flags |= setFlags;
            Node->flags &= ~clrFlags;

            if ((clrFlags & FILE_RELOCATION_FLAG) != 0 || (setFlags & FILE_RELOCATION_FLAG) != 0) {
                if (Node->relocation) {
                    Dll_Free(Node->relocation);
                    Node->relocation = NULL;
                }
            }
            if ((setFlags & FILE_RELOCATION_FLAG) != 0 && Relocation != NULL) {
                if (Relocation && wcslen(Relocation) > 0) {
                    Node->relocation = Dll_Alloc((wcslen(Relocation) + 1) * sizeof(WCHAR));
                    if (Node->relocation)
                        wcscpy(Node->relocation, Relocation);
                    else
                        Node->flags &= ~FILE_RELOCATION_FLAG; // Alloc failed; clear the flag so
                                                               // the node is not left half-wired
                                                               // (flag set but no target string).
                }
            }

            break;
        }
        Parent = &Node->items;
    }
}


//---------------------------------------------------------------------------
// File_GetPathFlags_internal
//---------------------------------------------------------------------------


_FX ULONG File_GetPathFlags_internal(PATH_LIST* Root, const WCHAR* Path, WCHAR** pRelocation, BOOLEAN CheckChildren)
{
    ULONG Flags = 0;
    const WCHAR* Relocation = NULL;
    const WCHAR* SubPath = NULL;

    PATH_LIST* Parent = Root;
    PATH_NODE* Node;
    const WCHAR* next;
    for (const WCHAR* ptr = Path; *ptr; ptr = next + 1) {
        next = wcschr(ptr, L'\\');
        if (ptr == next) // handle initial \ as well as \\ or \\\ etc cases
            continue;
        if(!next) next = wcschr(ptr, L'\0'); // last
        
        Node = File_GetPathNode_internal(Parent, ptr, (ULONG)(next - ptr), FALSE);
        if (!Node)
            break;

        //
        // we return the last relocation target
        //

        if ((Node->flags & FILE_RELOCATION_FLAG) != 0) {
            Relocation = Node->relocation;
            SubPath = next;
        }


        if (*next == L'\0') { // last path segment

            if ((Node->flags & FILE_RELOCATION_FLAG) != 0) 
                Flags |= FILE_RELOCATION_FLAG; 
            if ((Node->flags & FILE_DELETED_FLAG) != 0)
                Flags |= FILE_DELETED_FLAG; // flag set for the path

            if (CheckChildren && Node->items.list.count != 0)
                Flags |= FILE_CHILDREN_DELETED_FLAG;

            break;
        }

        //
        // if we encounter a relocation, previous deletions on the path will be reset
        // relocations are only allowed to exist for non-deleted paths
        //

        if ((Node->flags & FILE_RELOCATION_FLAG) != 0) {
            Flags = 0; // reset
            Flags |= FILE_PATH_RELOCATED_FLAG;
        }
        else if ((Node->flags & FILE_DELETED_FLAG) != 0)
            Flags |= FILE_PATH_DELETED_FLAG; // flag set for ancestor

        Parent = &Node->items;
    }

    if (Relocation && pRelocation) {

        THREAD_DATA *TlsData = Dll_GetTlsData(NULL);

        *pRelocation = Dll_GetTlsNameBuffer(TlsData, MISC_NAME_BUFFER, (wcslen(Relocation) + wcslen(SubPath) + 16) * sizeof(WCHAR)); // +16 some room for changes
        wcscpy(*pRelocation, Relocation);
        wcscat(*pRelocation, SubPath);
    }

    return Flags;
}


//---------------------------------------------------------------------------
// File_NormalizePath
//---------------------------------------------------------------------------


_FX const WCHAR* File_NormalizePath(const WCHAR* path, int slot)
{
    //
    // if we have a path that looks like any of these
    // \Device\LanmanRedirector\server\shr\f1.txt
    // \Device\LanmanRedirector\;Q:000000000000b09f\server\shr\f1.txt
    // \Device\Mup\;LanmanRedirector\server\share\f1.txt
    // \Device\Mup\;LanmanRedirector\;Q:000000000000b09f\server\share\f1.txt
    // then translate to
    // \Device\Mup\server\shr\f1.txt
    // and test again.  We do this because open/closed paths are
    // recorded in the \Device\Mup format.  See File_TranslateShares.
    //

    ULONG PrefixLen;
    if (_wcsnicmp(path, File_Redirector, File_RedirectorLen - 1) == 0)
        PrefixLen = File_RedirectorLen - 1;
    else if (_wcsnicmp(path, File_MupRedir, File_MupRedirLen - 1) == 0)
        PrefixLen = File_MupRedirLen - 1;
    else if (_wcsnicmp(path, File_DfsClientRedir, File_DfsClientRedirLen - 1) == 0)
        PrefixLen = File_DfsClientRedirLen - 1;
    else if (_wcsnicmp(path, File_HgfsRedir, File_HgfsRedirLen - 1) == 0)
        PrefixLen = File_HgfsRedirLen - 1;
    else if (_wcsnicmp(path, File_Mup, File_MupLen - 1) == 0)
        PrefixLen = File_MupLen - 1;
    else
        PrefixLen = 0;

    if (PrefixLen && path[PrefixLen] == L'\\' &&
        path[PrefixLen + 1] != L'\0') {

        const WCHAR* ptr = path + PrefixLen;
        if (ptr[1] == L';')
            ptr = wcschr(ptr + 2, L'\\');

        if (ptr && ptr[0] && ptr[1]) {

            //
            // the path represents a network share
            //

            THREAD_DATA *TlsData = Dll_GetTlsData(NULL);

            ULONG len1 = wcslen(ptr + 1);
            ULONG len2 = (File_MupLen + len1 + 8) * sizeof(WCHAR);
            WCHAR* path2 = Dll_GetTlsNameBuffer(TlsData, slot, len2);

            wmemcpy(path2, File_Mup, File_MupLen);
            path2[File_MupLen] = L'\\';
            wmemcpy(path2 + File_MupLen + 1, ptr + 1, len1 + 1);
            len1 += File_MupLen + 1;

            return path2;
        }
    }

    return path;
}


//---------------------------------------------------------------------------
// File_GetPathFlags
//---------------------------------------------------------------------------


_FX ULONG File_GetPathFlags(const WCHAR* Path, WCHAR** pRelocation, BOOLEAN CheckChildren)
{
    ULONG Flags;

    File_RefreshPathTree();

    EnterCriticalSection(File_PathRoot_CritSec);

    Flags = File_GetPathFlags_internal(&File_PathRoot,
        File_TrimTrailingBackslashes(File_NormalizePath(Path, NORM_NAME_BUFFER), MISC_NAME_BUFFER),
        pRelocation, CheckChildren);

    LeaveCriticalSection(File_PathRoot_CritSec);

    return Flags;
}


_FX const WCHAR* File_TrimTrailingBackslashes(const WCHAR* Path, int slot)
{
    ULONG len = (ULONG)wcslen(Path);
    while (len > 1 && Path[len - 1] == L'\\') {
        if (len == 3 && Path[1] == L':')
            break;
        len -= 1;
    }

    if (Path[len] == L'\0')
        return Path;

    THREAD_DATA *TlsData = Dll_GetTlsData(NULL);
    WCHAR* Trimmed = Dll_GetTlsNameBuffer(TlsData, slot, (len + 1) * sizeof(WCHAR));
    wmemcpy(Trimmed, Path, len);
    Trimmed[len] = L'\0';
    return Trimmed;
}


//---------------------------------------------------------------------------
// File_AppendPathEntry_internal
//---------------------------------------------------------------------------


static BOOLEAN File_IsValidStoragePath_internal(const WCHAR* Path)
{
    const WCHAR* backslash;

    if (!Path || !Path[0])
        return FALSE;

    if (Path[0] == L'\\' && Path[1] == L'\\')
        return TRUE;

    backslash = wcschr(Path + (Path[0] == L'\\' ? 1 : 0), L'\\');
    if (!backslash)
        backslash = wcschr(Path, L'\0');

    return (backslash > Path && *(backslash - 1) == L':');
}


static BOOLEAN File_IsValidStorageFallbackPath_internal(const WCHAR* Path)
{
    if (File_IsValidStoragePath_internal(Path))
        return TRUE;

    if (!Path || !Path[0])
        return FALSE;

    return (_wcsnicmp(Path, L"\\Device\\", 8) == 0 ||
            _wcsnicmp(Path, L"\\??\\", 4) == 0 ||
            _wcsnicmp(Path, L"\\SystemRoot\\", 12) == 0);
}


static BOOLEAN File_IsDosDrivePath_internal(const WCHAR* Path)
{
    WCHAR c;

    if (!Path)
        return FALSE;

    c = Path[0];
    return (((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z')) &&
            Path[1] == L':' &&
            (Path[2] == L'\\' || Path[2] == L'/' || Path[2] == L'\0'));
}


static BOOLEAN File_IsDriveLessDosPath_internal(const WCHAR* Path)
{
    if (!Path)
        return FALSE;

    return (Path[0] == L':' &&
            (Path[1] == L'\\' || Path[1] == L'/' || Path[1] == L'\0'));
}


static BOOLEAN File_HasMalformedDosPathPair_internal(const WCHAR* Path1, const WCHAR* Path2)
{
    return (File_IsDriveLessDosPath_internal(Path1) ||
            (Path2 && File_IsDriveLessDosPath_internal(Path2)));
}


static const WCHAR* File_GetPathForStorage_internal(
    const WCHAR* Path, WCHAR* (*TranslatePath)(const WCHAR*), WCHAR** pPathEx)
{
    *pPathEx = NULL;

    if (!TranslatePath)
        return Path;

    *pPathEx = TranslatePath(Path);
    if (*pPathEx) {
        if (File_IsValidStoragePath_internal(*pPathEx))
            return *pPathEx;

        Dll_Free(*pPathEx);
        *pPathEx = NULL;
    }

    if (File_IsValidStorageFallbackPath_internal(Path))
        return Path;

    return NULL;
}


_FX BOOLEAN File_AppendPathEntry_internal(HANDLE hPathsFile, const WCHAR* Path, ULONG SetFlags, const WCHAR* Relocation, WCHAR* (*TranslatePath)(const WCHAR*))
{
    IO_STATUS_BLOCK IoStatusBlock;

    WCHAR* PathEx = NULL;
    const WCHAR* FinalPath = File_GetPathForStorage_internal(Path, TranslatePath, &PathEx);
    if (!FinalPath)
        return FALSE;

    WCHAR* RelocationEx = NULL;
    const WCHAR* FinalRelocation = NULL;
    if (Relocation != NULL)
        FinalRelocation = File_GetPathForStorage_internal(Relocation, TranslatePath, &RelocationEx);
    if (Relocation != NULL && !FinalRelocation) {
        if (PathEx) Dll_Free(PathEx);
        return FALSE;
    }

    WCHAR FlagStr[16];
    _ultow(SetFlags, FlagStr, 16);

    // Build and write the entire line in a single NtWriteFile call: path|flags[|relocation]\r\n
    ULONG LineLen = (ULONG)(wcslen(FinalPath) + 1 + wcslen(FlagStr) + 2);
    if (FinalRelocation)
        LineLen += 1 + (ULONG)wcslen(FinalRelocation);

    WCHAR* Line = Dll_Alloc((LineLen + 1) * sizeof(WCHAR));
    if (!Line) {
        if (PathEx) Dll_Free(PathEx);
        if (RelocationEx) Dll_Free(RelocationEx);
        return FALSE;
    }
    wcscpy(Line, FinalPath);
    wcscat(Line, L"|");
    wcscat(Line, FlagStr);
    if (FinalRelocation) {
        wcscat(Line, L"|");
        wcscat(Line, FinalRelocation);
    }
    wcscat(Line, L"\r\n");

    NTSTATUS status = NtWriteFile(hPathsFile, NULL, NULL, NULL, &IoStatusBlock, Line, LineLen * sizeof(WCHAR), NULL, NULL);
    Dll_Free(Line);

    if (PathEx) Dll_Free(PathEx);
    if (RelocationEx) Dll_Free(RelocationEx);
    return NT_SUCCESS(status) && (ULONG)IoStatusBlock.Information == LineLen * sizeof(WCHAR);
}

static WCHAR* File_JournalEscapeField_internal(const WCHAR* in)
{
    ULONG inLen;
    WCHAR* out;
    ULONG si, di;

    if (!in)
        return NULL;

    inLen = (ULONG)wcslen(in);
    out = Dll_Alloc((inLen * 2 + 1) * sizeof(WCHAR));
    if (!out)
        return NULL;

    si = 0;
    di = 0;
    while (si < inLen) {
        WCHAR ch = in[si++];
        if (ch == L'\\' || ch == L'|') {
            out[di++] = L'\\';
            out[di++] = ch;
        } else {
            out[di++] = ch;
        }
    }
    out[di] = L'\0';
    return out;
}

static WCHAR* File_JournalUnescapeField_internal(const WCHAR* in)
{
    ULONG inLen;
    WCHAR* out;
    ULONG si, di;

    if (!in)
        return NULL;

    inLen = (ULONG)wcslen(in);
    out = Dll_Alloc((inLen + 1) * sizeof(WCHAR));
    if (!out)
        return NULL;

    si = 0;
    di = 0;
    while (si < inLen) {
        WCHAR ch = in[si++];
        if (ch == L'\\' && si < inLen) {
            WCHAR esc = in[si++];
            if (esc == L'|' || esc == L'\\')
                ch = esc;
            else {
                // Unknown escape: keep both bytes for forward compatibility.
                out[di++] = L'\\';
                ch = esc;
            }
        }
        out[di++] = ch;
    }
    out[di] = L'\0';
    return out;
}

static WCHAR* File_JournalFindUnescapedPipe_internal(WCHAR* in)
{
    WCHAR* p = in;
    if (!p)
        return NULL;

    while (*p) {
        if (*p == L'\\' && p[1]) {
            p += 2;
            continue;
        }
        if (*p == L'|')
            return p;
        ++p;
    }
    return NULL;
}


//---------------------------------------------------------------------------
// File_AppendPathJournalDelete_internal
//---------------------------------------------------------------------------


_FX ULONG File_AppendPathJournalDelete_internal(HANDLE hPathsFile, const WCHAR* Path, WCHAR* (*TranslatePath)(const WCHAR*), BOOLEAN isV3)
{
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS status;

    WCHAR* PathEx = NULL;
    const WCHAR* FinalPath = File_GetPathForStorage_internal(Path, TranslatePath, &PathEx);
    if (!FinalPath)
        return 0;

    WCHAR* EscapedPath = NULL;
    const WCHAR* WritePath = FinalPath;
    if (isV3) {
        EscapedPath = File_JournalEscapeField_internal(FinalPath);
        if (!EscapedPath) {
            if (PathEx) Dll_Free(PathEx);
            return 0;
        }
        WritePath = EscapedPath;
    }

    ULONG LineLen = (ULONG)wcslen(WritePath) + 1 + 1 + 2; // <path>|1\r\n
    WCHAR* Line = Dll_Alloc((LineLen + 1) * sizeof(WCHAR));
    if (!Line) {
        if (EscapedPath) Dll_Free(EscapedPath);
        if (PathEx) Dll_Free(PathEx);
        return 0;
    }
    wcscpy(Line, WritePath);
    wcscat(Line, L"|1");
    wcscat(Line, L"\r\n");

    ULONG BytesToWrite = LineLen * sizeof(WCHAR);
    status = NtWriteFile(hPathsFile, NULL, NULL, NULL, &IoStatusBlock, Line, BytesToWrite, NULL, NULL);
    Dll_Free(Line);
    if (EscapedPath) Dll_Free(EscapedPath);

    if (PathEx) Dll_Free(PathEx);

    // Return bytes written so callers can update the size cache incrementally
    // without an extra NtQueryAttributesFile stat syscall under the VFS mutex.
    if (NT_SUCCESS(status) && IoStatusBlock.Information == BytesToWrite)
        return BytesToWrite;
    return 0;
}


//---------------------------------------------------------------------------
// File_AppendPathJournalRelocation_internal
//---------------------------------------------------------------------------


_FX ULONG File_AppendPathJournalRelocation_internal(HANDLE hPathsFile, const WCHAR* OldPath, const WCHAR* NewPath, WCHAR* (*TranslatePath)(const WCHAR*), BOOLEAN isV3)
{
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS status;

    WCHAR* OldPathEx = NULL;
    WCHAR* NewPathEx = NULL;
    const WCHAR* FinalOldPath = File_GetPathForStorage_internal(OldPath, TranslatePath, &OldPathEx);
    const WCHAR* FinalNewPath = File_GetPathForStorage_internal(NewPath, TranslatePath, &NewPathEx);
    if (!FinalOldPath || !FinalNewPath) {
        if (OldPathEx) Dll_Free(OldPathEx);
        if (NewPathEx) Dll_Free(NewPathEx);
        return 0;
    }

    WCHAR* EscapedOldPath = NULL;
    WCHAR* EscapedNewPath = NULL;
    const WCHAR* WriteOldPath = FinalOldPath;
    const WCHAR* WriteNewPath = FinalNewPath;
    if (isV3) {
        EscapedOldPath = File_JournalEscapeField_internal(FinalOldPath);
        EscapedNewPath = File_JournalEscapeField_internal(FinalNewPath);
        if (!EscapedOldPath || !EscapedNewPath) {
            if (EscapedOldPath) Dll_Free(EscapedOldPath);
            if (EscapedNewPath) Dll_Free(EscapedNewPath);
            if (OldPathEx) Dll_Free(OldPathEx);
            if (NewPathEx) Dll_Free(NewPathEx);
            return 0;
        }
        WriteOldPath = EscapedOldPath;
        WriteNewPath = EscapedNewPath;
    }

    ULONG LineLen = (ULONG)wcslen(WriteOldPath) + 1 + 1 + 1 + (ULONG)wcslen(WriteNewPath) + 2; // <old>|2|<new>\r\n
    WCHAR* Line = Dll_Alloc((LineLen + 1) * sizeof(WCHAR));
    if (!Line) {
        if (EscapedOldPath) Dll_Free(EscapedOldPath);
        if (EscapedNewPath) Dll_Free(EscapedNewPath);
        if (OldPathEx) Dll_Free(OldPathEx);
        if (NewPathEx) Dll_Free(NewPathEx);
        return 0;
    }
    wcscpy(Line, WriteOldPath);
    wcscat(Line, L"|");
    wcscat(Line, L"2");
    wcscat(Line, L"|");
    wcscat(Line, WriteNewPath);
    wcscat(Line, L"\r\n");

    ULONG BytesToWrite = LineLen * sizeof(WCHAR);
    status = NtWriteFile(hPathsFile, NULL, NULL, NULL, &IoStatusBlock, Line, BytesToWrite, NULL, NULL);
    Dll_Free(Line);
    if (EscapedOldPath) Dll_Free(EscapedOldPath);
    if (EscapedNewPath) Dll_Free(EscapedNewPath);

    if (OldPathEx) Dll_Free(OldPathEx);
    if (NewPathEx) Dll_Free(NewPathEx);

    // Return bytes written so callers can update the size cache incrementally
    // without an extra NtQueryAttributesFile stat syscall under the VFS mutex.
    if (NT_SUCCESS(status) && IoStatusBlock.Information == BytesToWrite)
        return BytesToWrite;
    return 0;
}


//---------------------------------------------------------------------------
// File_AppendPathJournalValueDelete_internal
//---------------------------------------------------------------------------


_FX ULONG File_AppendPathJournalValueDelete_internal(HANDLE hPathsFile, const WCHAR* KeyPath, const WCHAR* ValueName, WCHAR* (*TranslatePath)(const WCHAR*), BOOLEAN isV3)
{
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS status;

    if (!ValueName)
        return 0;

    WCHAR* KeyPathEx = NULL;
    const WCHAR* FinalKeyPath = File_GetPathForStorage_internal(KeyPath, TranslatePath, &KeyPathEx);
    if (!FinalKeyPath)
        return 0;

    WCHAR* EscapedKeyPath = NULL;
    WCHAR* EscapedValue = NULL;
    const WCHAR* WriteKeyPath = FinalKeyPath;
    const WCHAR* WriteValue = ValueName;

    if (isV3) {
        EscapedKeyPath = File_JournalEscapeField_internal(FinalKeyPath);
        EscapedValue = File_JournalEscapeField_internal(ValueName);
        if (!EscapedKeyPath || !EscapedValue) {
            if (EscapedKeyPath) Dll_Free(EscapedKeyPath);
            if (EscapedValue) Dll_Free(EscapedValue);
            if (KeyPathEx) Dll_Free(KeyPathEx);
            return 0;
        }
        WriteKeyPath = EscapedKeyPath;
        WriteValue = EscapedValue;
    }

    ULONG LineLen = (ULONG)wcslen(WriteKeyPath) + 1 + 1 + 1 + (ULONG)wcslen(WriteValue) + 2; // <key>|3|<value>

    WCHAR* Line = Dll_Alloc((LineLen + 1) * sizeof(WCHAR));
    if (!Line) {
        if (EscapedKeyPath) Dll_Free(EscapedKeyPath);
        if (EscapedValue) Dll_Free(EscapedValue);
        if (KeyPathEx) Dll_Free(KeyPathEx);
        return 0;
    }

    wcscpy(Line, WriteKeyPath);
    wcscat(Line, L"|");
    wcscat(Line, L"3");
    wcscat(Line, L"|");
    wcscat(Line, WriteValue);
    wcscat(Line, L"\r\n");

    ULONG BytesToWrite = LineLen * sizeof(WCHAR);
    status = NtWriteFile(hPathsFile, NULL, NULL, NULL, &IoStatusBlock, Line, BytesToWrite, NULL, NULL);
    Dll_Free(Line);
    if (EscapedKeyPath) Dll_Free(EscapedKeyPath);
    if (EscapedValue) Dll_Free(EscapedValue);

    if (KeyPathEx) Dll_Free(KeyPathEx);

    if (NT_SUCCESS(status) && IoStatusBlock.Information == BytesToWrite)
        return BytesToWrite;
    return 0;
}

//---------------------------------------------------------------------------
// File_SavePathNode_internal
//---------------------------------------------------------------------------


_FX VOID File_SavePathNode_internal(HANDLE hPathsFile, PATH_LIST* parent, WCHAR* Path, ULONG Length, ULONG SetFlags, WCHAR* (*TranslatePath)(const WCHAR *)) 
{
    // append  L"\\"
    if (Length + 1 >= 0x7FFF) return; // path too deep to serialize safely; skip subtree
    Path[Length++] = L'\\'; //Path[Length] = L'0';
    WCHAR* PathBase = Path + Length;

    PATH_NODE* child;
    child = List_Head(parent);
    while (child) {

        if (Length + child->name_len >= 0x7FFF) { child = List_Next(child); continue; }
        wmemcpy(PathBase, child->name, child->name_len + 1);
        ULONG Path_Len = Length + child->name_len;

        //
        // don't write down flags that were already set for the parent, 
        // unless we have a relocation, that resets everything
        //

        if ((child->flags & FILE_RELOCATION_FLAG) != 0)
            SetFlags = 0;

        if ((child->flags & ~SetFlags) != 0 || child->relocation != NULL) 
            File_AppendPathEntry_internal(hPathsFile, Path, child->flags, child->relocation, TranslatePath);

        File_SavePathNode_internal(hPathsFile, &child->items, Path, Path_Len, SetFlags | child->flags, TranslatePath);

        child = List_Next(child);
    }
}


//---------------------------------------------------------------------------
// PATH_TREE_BUF -- growable in-memory write buffer for tree serialization.
//---------------------------------------------------------------------------

typedef struct _PATH_TREE_BUF {
    WCHAR*  Data;
    ULONG   Used;   // WCHARs stored
    ULONG   Cap;    // WCHARs allocated
    BOOLEAN OOM;    // set on Dll_Alloc failure
} PATH_TREE_BUF;

static VOID File_TreeBufAppend(PATH_TREE_BUF* b, const WCHAR* s, ULONG n)
{
    if (b->OOM || !n) return;
    if (n > 0xFFFFFFFFUL - b->Used) { b->OOM = TRUE; return; }
    if (b->Used + n > b->Cap) {
        ULONG nc = b->Cap ? b->Cap * 2 : 8192; // initial 16 KB
        // Guard against ULONG overflow in the doubling: if b->Cap * 2 wrapped,
        // nc is now smaller than b->Cap.  Treat as out-of-memory.
        if (b->Cap && nc < b->Cap) { b->OOM = TRUE; return; }
        while (nc < b->Used + n) {
            ULONG nc2 = nc * 2;
            if (nc2 <= nc) { b->OOM = TRUE; return; } // overflow guard
            nc = nc2;
        }
        WCHAR* d = (WCHAR*)Dll_Alloc(nc * sizeof(WCHAR));
        if (!d) { b->OOM = TRUE; return; }
        if (b->Data) { wmemcpy(d, b->Data, b->Used); Dll_Free(b->Data); }
        b->Data = d; b->Cap = nc;
    }
    wmemcpy(b->Data + b->Used, s, n);
    b->Used += n;
}

//---------------------------------------------------------------------------
// File_AppendPathEntryToBuffer_internal
// Mirrors File_AppendPathEntry_internal writing to an in-memory PATH_TREE_BUF.
//---------------------------------------------------------------------------

static VOID File_AppendPathEntryToBuffer_internal(PATH_TREE_BUF* Buf, const WCHAR* Path, ULONG SetFlags, const WCHAR* Relocation, WCHAR* (*TranslatePath)(const WCHAR*))
{
    WCHAR* PathEx = NULL;
    const WCHAR* FinalPath = File_GetPathForStorage_internal(Path, TranslatePath, &PathEx);
    if (!FinalPath) return;

    WCHAR* RelocationEx = NULL;
    const WCHAR* FinalRelocation = NULL;
    if (Relocation) {
        FinalRelocation = File_GetPathForStorage_internal(Relocation, TranslatePath, &RelocationEx);
        if (!FinalRelocation) { if (PathEx) Dll_Free(PathEx); return; }
    }

    WCHAR FlagStr[16];
    _ultow(SetFlags, FlagStr, 16);

    File_TreeBufAppend(Buf, FinalPath,       (ULONG)wcslen(FinalPath));
    File_TreeBufAppend(Buf, L"|",            1);
    File_TreeBufAppend(Buf, FlagStr,         (ULONG)wcslen(FlagStr));
    if (FinalRelocation) {
        File_TreeBufAppend(Buf, L"|",        1);
        File_TreeBufAppend(Buf, FinalRelocation, (ULONG)wcslen(FinalRelocation));
    }
    File_TreeBufAppend(Buf, L"\r\n",         2);

    if (PathEx)       Dll_Free(PathEx);
    if (RelocationEx) Dll_Free(RelocationEx);
}

//---------------------------------------------------------------------------
// File_SerializePathNodeToBuffer
// Mirrors File_SavePathNode_internal writing to an in-memory PATH_TREE_BUF.
//---------------------------------------------------------------------------

static VOID File_SerializePathNodeToBuffer(PATH_TREE_BUF* Buf, PATH_LIST* parent, WCHAR* Path, ULONG Length, ULONG SetFlags, WCHAR* (*TranslatePath)(const WCHAR*))
{
    if (Length + 1 >= 0x7FFF) return; // path too deep to serialize safely; skip subtree
    Path[Length++] = L'\\';
    WCHAR* PathBase = Path + Length;

    PATH_NODE* child = List_Head(parent);
    while (child) {
        if (Length + child->name_len >= 0x7FFF) { child = List_Next(child); continue; }
        wmemcpy(PathBase, child->name, child->name_len + 1);
        ULONG Path_Len = Length + child->name_len;

        if ((child->flags & FILE_RELOCATION_FLAG) != 0)
            SetFlags = 0;

        if ((child->flags & ~SetFlags) != 0 || child->relocation != NULL)
            File_AppendPathEntryToBuffer_internal(Buf, Path, child->flags, child->relocation, TranslatePath);

        File_SerializePathNodeToBuffer(Buf, &child->items, Path, Path_Len, SetFlags | child->flags, TranslatePath);
        child = List_Next(child);
    }
}

//---------------------------------------------------------------------------
// File_AppendPathEntryToBufferV3_internal
// V3 variant: writes opcode 1 (delete) and opcode 2 (relocation) lines
// with pipe/backslash escaping, matching the journal format.
//---------------------------------------------------------------------------

static VOID File_AppendPathEntryToBufferV3_internal(PATH_TREE_BUF* Buf, const WCHAR* Path,
    ULONG NewFlags, const WCHAR* Relocation, WCHAR* (*TranslatePath)(const WCHAR*))
{
    WCHAR* PathEx = NULL;
    const WCHAR* FinalPath = File_GetPathForStorage_internal(Path, TranslatePath, &PathEx);
    if (!FinalPath) return;

    WCHAR* EscapedPath = File_JournalEscapeField_internal(FinalPath);
    if (!EscapedPath) { if (PathEx) Dll_Free(PathEx); return; }

    if (Relocation) {
        WCHAR* RelocationEx = NULL;
        const WCHAR* FinalRelocation = File_GetPathForStorage_internal(Relocation, TranslatePath, &RelocationEx);
        if (FinalRelocation) {
            WCHAR* EscapedRelocation = File_JournalEscapeField_internal(FinalRelocation);
            if (EscapedRelocation) {
                File_TreeBufAppend(Buf, EscapedPath, (ULONG)wcslen(EscapedPath));
                File_TreeBufAppend(Buf, L"|2|", 3);
                File_TreeBufAppend(Buf, EscapedRelocation, (ULONG)wcslen(EscapedRelocation));
                File_TreeBufAppend(Buf, L"\r\n", 2);
                Dll_Free(EscapedRelocation);
            }
        }
        if (RelocationEx) Dll_Free(RelocationEx);
    }

    if (NewFlags & FILE_DELETED_FLAG) {
        File_TreeBufAppend(Buf, EscapedPath, (ULONG)wcslen(EscapedPath));
        File_TreeBufAppend(Buf, L"|1\r\n", 4);
    }

    Dll_Free(EscapedPath);
    if (PathEx) Dll_Free(PathEx);
}

//---------------------------------------------------------------------------
// File_SerializePathNodeToBufferV3
// V3 variant: emits opcode 1/2/3 lines with escaping.
// Value-delete marker nodes (name[0] == L'$') become opcode 3.
//---------------------------------------------------------------------------

VOID File_SerializePathNodeToBufferV3(PATH_TREE_BUF* Buf, PATH_LIST* parent,
    WCHAR* Path, ULONG Length, ULONG SetFlags, WCHAR* (*TranslatePath)(const WCHAR*))
{
    if (Length + 1 >= 0x7FFF) return;
    Path[Length++] = L'\\';
    WCHAR* PathBase = Path + Length;

    PATH_NODE* child = List_Head(parent);
    while (child) {
        if (Length + child->name_len >= 0x7FFF) { child = List_Next(child); continue; }
        wmemcpy(PathBase, child->name, child->name_len + 1);
        ULONG Path_Len = Length + child->name_len;

        if ((child->flags & FILE_RELOCATION_FLAG) != 0)
            SetFlags = 0;

        // Check if this is a value-delete marker node (registry only).
        if (child->name_len > 0 && child->name[0] == L'$') {
            // Emit opcode 3: parent_path|3|value_name
            if (child->flags & FILE_DELETED_FLAG) {
                WCHAR savedChar = Path[Length - 1]; // the '\' before marker
                Path[Length - 1] = L'\0'; // null-terminate parent path

                WCHAR* ParentPathEx = NULL;
                const WCHAR* FinalParentPath = File_GetPathForStorage_internal(Path, TranslatePath, &ParentPathEx);
                if (FinalParentPath) {
                    WCHAR* EscapedParent = File_JournalEscapeField_internal(FinalParentPath);
                    WCHAR* EscapedValue = File_JournalEscapeField_internal(child->name + 1);
                    if (EscapedParent && EscapedValue) {
                        File_TreeBufAppend(Buf, EscapedParent, (ULONG)wcslen(EscapedParent));
                        File_TreeBufAppend(Buf, L"|3|", 3);
                        File_TreeBufAppend(Buf, EscapedValue, (ULONG)wcslen(EscapedValue));
                        File_TreeBufAppend(Buf, L"\r\n", 2);
                    }
                    if (EscapedParent) Dll_Free(EscapedParent);
                    if (EscapedValue) Dll_Free(EscapedValue);
                }
                if (ParentPathEx) Dll_Free(ParentPathEx);
                Path[Length - 1] = savedChar; // restore
            }
            // Marker nodes are leaf-only; skip recursion.
        } else {
            if ((child->flags & ~SetFlags) != 0 || child->relocation != NULL)
                File_AppendPathEntryToBufferV3_internal(Buf, Path, child->flags, child->relocation, TranslatePath);

            File_SerializePathNodeToBufferV3(Buf, &child->items, Path, Path_Len, SetFlags | child->flags, TranslatePath);
        }

        child = List_Next(child);
    }
}


//---------------------------------------------------------------------------
// File_SeekToEndOfFile
//---------------------------------------------------------------------------


_FX BOOLEAN File_SeekToEndOfFile(HANDLE fileHandle) 
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    FILE_STANDARD_INFORMATION fileStandardInfo;

    status = NtQueryInformationFile(fileHandle, &ioStatusBlock, &fileStandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
    if (NT_SUCCESS(status)) 
    {
        FILE_POSITION_INFORMATION filePosition;
        filePosition.CurrentByteOffset = fileStandardInfo.EndOfFile;

        status = NtSetInformationFile(fileHandle, &ioStatusBlock, &filePosition, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation);
    }

    return NT_SUCCESS(status);
}


//---------------------------------------------------------------------------
// File_OpenDataFile
//---------------------------------------------------------------------------


_FX BOOLEAN File_OpenDataFile(const WCHAR* name, HANDLE* hPathsFile, BOOLEAN Append)
{
    ULONG pathLen = (ULONG)wcslen(Dll_BoxFilePath) + 1 + (ULONG)wcslen(name) + 1;
    WCHAR* PathsFile = (WCHAR*)Dll_Alloc(pathLen * sizeof(WCHAR));
    if (!PathsFile) return FALSE;
    wcscpy(PathsFile, Dll_BoxFilePath);
    wcscat(PathsFile, L"\\");
    wcscat(PathsFile, name);

    UNICODE_STRING objname;
    RtlInitUnicodeString(&objname, PathsFile);

    OBJECT_ATTRIBUTES objattrs;
    InitializeObjectAttributes(&objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK IoStatusBlock;
    BOOLEAN ok = NT_SUCCESS(NtCreateFile(hPathsFile, GENERIC_WRITE | SYNCHRONIZE, &objattrs, &IoStatusBlock, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, Append ? FILE_OPEN_IF : FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0));
    Dll_Free(PathsFile);
    if (!ok) return FALSE;

    if (Append) {
        if (!File_SeekToEndOfFile(*hPathsFile)) {
            NtClose(*hPathsFile);
            return FALSE;
        }
    }

    return TRUE;
}


_FX BOOLEAN File_OpenDataFileAppendShared(const WCHAR* name, HANDLE* hPathsFile)
{
    ULONG pathLen = (ULONG)wcslen(Dll_BoxFilePath) + 1 + (ULONG)wcslen(name) + 1;
    WCHAR* PathsFile = (WCHAR*)Dll_Alloc(pathLen * sizeof(WCHAR));
    if (!PathsFile) return FALSE;
    wcscpy(PathsFile, Dll_BoxFilePath);
    wcscat(PathsFile, L"\\");
    wcscat(PathsFile, name);

    UNICODE_STRING objname;
    RtlInitUnicodeString(&objname, PathsFile);

    OBJECT_ATTRIBUTES objattrs;
    InitializeObjectAttributes(&objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK IoStatusBlock;
    BOOLEAN ok = NT_SUCCESS(NtCreateFile(hPathsFile, GENERIC_WRITE | SYNCHRONIZE, &objattrs, &IoStatusBlock, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0));
    Dll_Free(PathsFile);
    if (!ok) return FALSE;

    if (!File_SeekToEndOfFile(*hPathsFile)) {
        NtClose(*hPathsFile);
        *hPathsFile = NULL;
        return FALSE;
    }

    return TRUE;
}


_FX BOOLEAN File_CopyDataFile(const WCHAR* sourceName, const WCHAR* targetName)
{
    WCHAR* SourceFile = (WCHAR*)Dll_Alloc(((ULONG)wcslen(Dll_BoxFilePath) + 1 + (ULONG)wcslen(sourceName) + 1) * sizeof(WCHAR));
    WCHAR* TargetFile = (WCHAR*)Dll_Alloc(((ULONG)wcslen(Dll_BoxFilePath) + 1 + (ULONG)wcslen(targetName) + 1) * sizeof(WCHAR));
    if (!SourceFile || !TargetFile) {
        if (SourceFile) Dll_Free(SourceFile);
        if (TargetFile) Dll_Free(TargetFile);
        return FALSE;
    }
    wcscpy(SourceFile, Dll_BoxFilePath);
    wcscat(SourceFile, L"\\");
    wcscat(SourceFile, sourceName);

    wcscpy(TargetFile, Dll_BoxFilePath);
    wcscat(TargetFile, L"\\");
    wcscat(TargetFile, targetName);

    UNICODE_STRING srcObjName;
    RtlInitUnicodeString(&srcObjName, SourceFile);
    OBJECT_ATTRIBUTES srcObjAttrs;
    InitializeObjectAttributes(&srcObjAttrs, &srcObjName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    UNICODE_STRING dstObjName;
    RtlInitUnicodeString(&dstObjName, TargetFile);
    OBJECT_ATTRIBUTES dstObjAttrs;
    InitializeObjectAttributes(&dstObjAttrs, &dstObjName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE hSource = NULL;
    HANDLE hTarget = NULL;
    BOOLEAN success = FALSE;

    if (!NT_SUCCESS(NtCreateFile(&hSource, GENERIC_READ | SYNCHRONIZE, &srcObjAttrs, &IoStatusBlock, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0)))
        goto finish;

    if (!NT_SUCCESS(NtCreateFile(&hTarget, GENERIC_WRITE | SYNCHRONIZE, &dstObjAttrs, &IoStatusBlock, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0)))
        goto finish;

    UCHAR buffer[16 * 1024];
    while (TRUE) {
        NTSTATUS status = NtReadFile(hSource, NULL, NULL, NULL, &IoStatusBlock, buffer, sizeof(buffer), NULL, NULL);
        if (status == STATUS_END_OF_FILE)
            break; // clean end-of-file: copy is complete
        if (!NT_SUCCESS(status))
            goto finish;

        ULONG bytesRead = (ULONG)IoStatusBlock.Information;
        if (bytesRead == 0)
            break;

        status = NtWriteFile(hTarget, NULL, NULL, NULL, &IoStatusBlock, buffer, bytesRead, NULL, NULL);
        if (!NT_SUCCESS(status) || IoStatusBlock.Information != bytesRead)
            goto finish;
    }

    success = TRUE;

finish:
    Dll_Free(TargetFile);
    Dll_Free(SourceFile);
    if (hTarget)
        NtClose(hTarget);
    if (hSource)
        NtClose(hSource);
    return success;
}


_FX VOID File_DeleteDataFile(const WCHAR* name)
{
    ULONG pathLen = (ULONG)wcslen(Dll_BoxFilePath) + 1 + (ULONG)wcslen(name) + 1;
    WCHAR* PathsFile = (WCHAR*)Dll_Alloc(pathLen * sizeof(WCHAR));
    if (!PathsFile) return;
    wcscpy(PathsFile, Dll_BoxFilePath);
    wcscat(PathsFile, L"\\");
    wcscat(PathsFile, name);

    UNICODE_STRING objname;
    RtlInitUnicodeString(&objname, PathsFile);

    OBJECT_ATTRIBUTES objattrs;
    InitializeObjectAttributes(&objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NtDeleteFile(&objattrs);
    Dll_Free(PathsFile);
}


_FX BOOLEAN File_TryAcquireCompactionMarker(HANDLE* hCompactMutex, const WCHAR* name)
{
    *hCompactMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, name);
    if (!*hCompactMutex) {
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = SbieDll_GetPublicSD();
        sa.bInheritHandle = FALSE;
        *hCompactMutex = CreateMutex(&sa, FALSE, name);
    }
    if (!*hCompactMutex) {
        // Low-resource or restricted-permissions condition: compaction silently
        // skipped.  Journal will continue to grow past its configured limits until
        // the condition is resolved.
        return FALSE;
    }

    if (WaitForSingleObject(*hCompactMutex, 0) != WAIT_OBJECT_0) {
        // Another process is already compacting — let it finish; skip here.
        CloseHandle(*hCompactMutex);
        *hCompactMutex = NULL;
        return FALSE;
    }

    return TRUE;
}


//---------------------------------------------------------------------------
// File_SavePathTree_internal
//---------------------------------------------------------------------------


_FX BOOLEAN File_SavePathTree_internal(PATH_LIST* Root, const WCHAR* name, WCHAR* (*TranslatePath)(const WCHAR *))
{
    WCHAR* Path = (WCHAR *)Dll_Alloc((0x7FFF + 1)*sizeof(WCHAR)); // max nt path
    if (!Path) return FALSE;

    HANDLE hPathsFile;
    if (!File_OpenDataFile(name, &hPathsFile, FALSE)) {
        Dll_Free(Path);
        return FALSE;
    }

    File_SavePathNode_internal(hPathsFile, Root, Path, 0, 0, TranslatePath);

    Dll_Free(Path);

    NtClose(hPathsFile);
    return TRUE;
}


//---------------------------------------------------------------------------
// File_WriteBufferToDataFile
// Writes a serialized tree buffer to a .dat file in one write call.
// Mirrors the file-write portion of File_SavePathTree_internal.
//---------------------------------------------------------------------------

BOOLEAN File_WriteBufferToDataFile(const WCHAR* name, const WCHAR* data, ULONG cch)
{
    HANDLE hFile;
    if (!File_OpenDataFile(name, &hFile, FALSE))
        return FALSE;

    BOOLEAN ok = TRUE;
    if (cch > 0) {
        IO_STATUS_BLOCK iosb;
        ULONG bytes = cch * sizeof(WCHAR);
        NTSTATUS status = NtWriteFile(hFile, NULL, NULL, NULL, &iosb, (PVOID)data, bytes, NULL, NULL);
        if (!NT_SUCCESS(status) || iosb.Information != bytes)
            ok = FALSE;
    }
    NtClose(hFile);
    return ok;
}


//---------------------------------------------------------------------------
// File_TranslateNtToDosPathForDatFile
//---------------------------------------------------------------------------


_FX WCHAR* File_TranslateNtToDosPathForDatFile(const WCHAR *NtPath)
{
    if (!NtPath)
        return NULL;

    WCHAR *DosPath = NULL;
    ULONG len_nt;

    len_nt = wcslen(NtPath) + 11;
    DosPath = Dll_Alloc(len_nt * sizeof(WCHAR));
    if (!DosPath) return NULL;
    wcscpy(DosPath, NtPath);

    // Already-DOS input can be seen from legacy/corrupt state and must be kept
    // unchanged. Running the NT->DOS fallback below on "E:\\..." would strip
    // the drive letter and produce malformed ":\\...".
    if (File_IsDosDrivePath_internal(DosPath))
        return DosPath;

    //
    // Hack Hack: when we load a drive which does not exist we create an entry like
    // L"\\C:\\path" in out tree to not forget it even though the NtPath is unknown
    // here we must handle that special case and strip the L'\\'
    //

    if (DosPath[0] == L'\\') {
        const WCHAR* backslash = wcschr(DosPath + 1, L'\\');
        if (!backslash) backslash = wcschr(DosPath, L'\0');
        if (backslash > DosPath && *(backslash - 1) == L':') {
            wmemmove(DosPath, DosPath + 1, wcslen(DosPath)); // -1 (for '\\') + 1 (for '\0')
            return DosPath;
        }
    }


    if (_wcsnicmp(DosPath, File_Mup, File_MupLen) == 0) {

        WCHAR *ptr = DosPath + File_MupLen - 1;
        wmemmove(DosPath + 1, ptr, wcslen(ptr) + 1);

    } else {

        const FILE_DRIVE *drive;
        ULONG path_len, prefix_len;

        path_len = wcslen(DosPath);

        drive = File_GetDriveForPath(DosPath, path_len);
        if (drive)
            prefix_len = drive->len;
        else
            drive = File_GetDriveForUncPath(DosPath, path_len, &prefix_len);

        if (drive) {

            WCHAR drive_letter = drive->letter;
            WCHAR *ptr = DosPath + prefix_len;

            LeaveCriticalSection(File_DrivesAndLinks_CritSec);

            if (*ptr == L'\\' || *ptr == L'\0') {
                path_len = wcslen(ptr);
                wmemmove(DosPath + 2, ptr, path_len + 1);
                DosPath[0] = drive_letter;
                DosPath[1] = L':';

                if (File_DriveAddSN && *drive->sn) {

                    wmemmove(DosPath + 11, DosPath + 1, path_len + 2);
                    DosPath[1] = L'~';
                    wmemcpy(DosPath + 2, drive->sn, 9);
                }
            }

        } else {

            Dll_Free(DosPath);
            DosPath = NULL;
        }
    }

    return DosPath;
}


//---------------------------------------------------------------------------
// File_SavePathTree
//---------------------------------------------------------------------------


_FX BOOLEAN File_SavePathTree()
{
    const WCHAR* datName = File_DeleteV3 ? FILE_PATH_FILE_NAME_V3 : FILE_PATH_FILE_NAME;

    EnterCriticalSection(File_PathRoot_CritSec);

    if (File_DeleteV3) {
        PATH_TREE_BUF buf = { NULL, 0, 0, FALSE };
        WCHAR* tmpPath = (WCHAR*)Dll_Alloc((0x7FFF + 1) * sizeof(WCHAR));
        if (tmpPath) {
            File_SerializePathNodeToBufferV3(&buf, &File_PathRoot, tmpPath, 0, 0, File_TranslateNtToDosPathForDatFile);
            Dll_Free(tmpPath);
        } else {
            buf.OOM = TRUE; // Treat tmpPath alloc failure as OOM to avoid truncating the .dat
        }
        if (!buf.OOM)
            File_WriteBufferToDataFile(datName, buf.Data, buf.Used);
        if (buf.Data)
            Dll_Free(buf.Data);
    } else {
        File_SavePathTree_internal(&File_PathRoot, datName, File_TranslateNtToDosPathForDatFile);
    }

    File_GetAttributes_internal(datName, &File_PathsFileSize, &File_PathsFileDate, NULL);

    LeaveCriticalSection(File_PathRoot_CritSec);

    return TRUE;
}


//---------------------------------------------------------------------------
// File_AcquireMutex
//---------------------------------------------------------------------------


_FX HANDLE File_AcquireMutex(const WCHAR *MutexName)
{
    HANDLE hMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, MutexName);
    if (! hMutex) {
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = SbieDll_GetPublicSD();
        sa.bInheritHandle = FALSE;
        hMutex = CreateMutex(&sa, FALSE, MutexName);
    }
    if (hMutex) {
        DWORD wait_res = WaitForSingleObject(hMutex, 5000);
        if (wait_res != WAIT_OBJECT_0 && wait_res != WAIT_ABANDONED) {
            // Timeout or error: do not return a handle the caller doesn't own.
            CloseHandle(hMutex);
            return NULL;
        }
    }

    return hMutex;
}


//---------------------------------------------------------------------------
// Scm_ReleaseMutex
//---------------------------------------------------------------------------


_FX void File_ReleaseMutex(HANDLE hMutex)
{
    if (hMutex) {

        ReleaseMutex(hMutex);

        CloseHandle(hMutex);
    }
}


//---------------------------------------------------------------------------
// File_LoadPathTree_internal
//---------------------------------------------------------------------------


_FX BOOLEAN File_LoadPathTree_internal(PATH_LIST* Root, const WCHAR* name, WCHAR* (*TranslatePath)(const WCHAR *))
{
    ULONG pathLen = (ULONG)wcslen(Dll_BoxFilePath) + 1 + (ULONG)wcslen(name) + 1;
    WCHAR* PathsFile = (WCHAR*)Dll_Alloc(pathLen * sizeof(WCHAR));
    if (!PathsFile) return FALSE;
    wcscpy(PathsFile, Dll_BoxFilePath);
    wcscat(PathsFile, L"\\");
    wcscat(PathsFile, name);

    UNICODE_STRING objname;
    RtlInitUnicodeString(&objname, PathsFile);

    OBJECT_ATTRIBUTES objattrs;
    InitializeObjectAttributes(&objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hPathsFile;
    IO_STATUS_BLOCK IoStatusBlock;
    if (!NT_SUCCESS(NtCreateFile(&hPathsFile, GENERIC_READ | SYNCHRONIZE, &objattrs, &IoStatusBlock, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0))) {
        if (NT_SUCCESS(NtCreateFile(&hPathsFile, GENERIC_WRITE | SYNCHRONIZE, &objattrs, &IoStatusBlock, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0)))
            NtClose(hPathsFile);
        Dll_Free(PathsFile);
        return FALSE;
    }
    Dll_Free(PathsFile);

    FILE_STANDARD_INFORMATION FileStdInfo;
    memzero(&FileStdInfo, sizeof(FileStdInfo));
    NtQueryInformationFile(hPathsFile, &IoStatusBlock, &FileStdInfo, sizeof(FileStdInfo), FileStandardInformation);
    // Match the journal loader: cap at FILE_JOURNAL_HARD_CAP_BYTES to prevent
    // ULONG overflow in (fileSize + 128) and limit allocation on corrupt .dat files.
    ULONG fileSize = (FileStdInfo.EndOfFile.QuadPart > (ULONG64)FILE_JOURNAL_HARD_CAP_BYTES)
        ? (ULONG)FILE_JOURNAL_HARD_CAP_BYTES : (ULONG)FileStdInfo.EndOfFile.QuadPart;

    WCHAR* Buffer = (WCHAR *)Dll_Alloc(fileSize + 128);
    if (!Buffer) {
        NtClose(hPathsFile);
        return FALSE;
    }
    NtReadFile(hPathsFile, NULL, NULL, NULL, &IoStatusBlock, Buffer, fileSize, NULL, NULL);
    ULONG bytesRead = (ULONG)IoStatusBlock.Information;
    if (bytesRead & 1)
        bytesRead -= 1; // malformed/truncated byte stream: keep WCHAR alignment
    Buffer[bytesRead/sizeof(WCHAR)] = L'\0';

    File_ClearPathBranche_internal(Root);

    WCHAR* Next = Buffer;
    if (bytesRead >= sizeof(WCHAR) && Next[0] == FILE_UTF16_LE_BOM)
        Next += 1;
    while (*Next) {
        WCHAR* Line = Next;
        WCHAR* End = wcschr(Line, L'\n');
        if (End == NULL) {
            End = wcschr(Line, L'\0');
            Next = End;
        } else
            Next = End + 1;
        LONG LineLen = (LONG)(End - Line);
        if (LineLen >= 1 && Line[LineLen - 1] == L'\r')
            LineLen -= 1;
        
        WCHAR savechar = Line[LineLen];
        Line[LineLen] = L'\0';

        WCHAR* Path = Line;

        WCHAR* Sep = wcschr(Line, L'|');
        if (!Sep || Sep > Next) continue; // invalid line, flags field missing
        *Sep = L'\0';

        WCHAR* Relocation = NULL;

        WCHAR* endptr;
        ULONG Flags = wcstoul(Sep + 1, &endptr, 16);
        // Mask to the two on-disk flag bits.  A corrupted or externally-edited .dat file could
        // otherwise set internal volatile bits (0xFFFF0000) on tree nodes, producing false
        // "deleted" or "relocated" results.
        Flags &= (FILE_DELETED_FLAG | FILE_RELOCATION_FLAG);
        if (endptr && *endptr == L'|') 
            Relocation = endptr + 1;

        if (File_HasMalformedDosPathPair_internal(Path, Relocation)) {
            *Sep = L'|';
            Line[LineLen] = savechar;
            continue;
        }

        WCHAR* PathEx = TranslatePath ? TranslatePath(Path) : NULL;
        WCHAR* RelocationEx = (TranslatePath && Relocation) ? TranslatePath(Relocation) : NULL;

        File_SetPathFlags_internal(Root, PathEx ? PathEx : Path, Flags, 0, RelocationEx ? RelocationEx : Relocation);

        if (PathEx) Dll_Free(PathEx);
        if (RelocationEx) Dll_Free(RelocationEx);

        *Sep = L'|';
        Line[LineLen] = savechar;
    }

    Dll_Free(Buffer);

    NtClose(hPathsFile);

    return TRUE;
}


//---------------------------------------------------------------------------
// File_LoadPathJournal_internal
//---------------------------------------------------------------------------


_FX BOOLEAN File_LoadPathJournal_internal(PATH_LIST* Root, const WCHAR* name, WCHAR* (*TranslatePath)(const WCHAR *), ULONG64* pReplayOffset, ULONG* pAppliedLines)
{
    ULONG pathLen = (ULONG)wcslen(Dll_BoxFilePath) + 1 + (ULONG)wcslen(name) + 1;
    WCHAR* PathsFile = (WCHAR*)Dll_Alloc(pathLen * sizeof(WCHAR));
    if (!PathsFile) return FALSE;
    wcscpy(PathsFile, Dll_BoxFilePath);
    wcscat(PathsFile, L"\\");
    wcscat(PathsFile, name);

    UNICODE_STRING objname;
    RtlInitUnicodeString(&objname, PathsFile);

    OBJECT_ATTRIBUTES objattrs;
    InitializeObjectAttributes(&objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hPathsFile;
    IO_STATUS_BLOCK IoStatusBlock;
    if (!NT_SUCCESS(NtCreateFile(&hPathsFile, GENERIC_READ | SYNCHRONIZE, &objattrs, &IoStatusBlock, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0))) {
        // Side-effect: if the .sbie journal file doesn't exist yet, create an empty one so
        // that File_RefreshPathTree's size/date change-detection has a stable inode to watch.
        if (NT_SUCCESS(NtCreateFile(&hPathsFile, GENERIC_WRITE | SYNCHRONIZE, &objattrs, &IoStatusBlock, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0)))
            NtClose(hPathsFile);
        Dll_Free(PathsFile);
        return FALSE;
    }
    Dll_Free(PathsFile);

    if (pAppliedLines)
        *pAppliedLines = 0;

    FILE_STANDARD_INFORMATION FileStdInfo;
    memzero(&FileStdInfo, sizeof(FileStdInfo));
    NtQueryInformationFile(hPathsFile, &IoStatusBlock, &FileStdInfo, sizeof(FileStdInfo), FileStandardInformation);
    // Cap at FILE_JOURNAL_HARD_CAP_BYTES (matches the .dat loader) to bound the
    // readOffset arithmetic and keep the Dll_Alloc(readSize + 128) safe.
    ULONG fileSize = (FileStdInfo.EndOfFile.QuadPart > (ULONG64)FILE_JOURNAL_HARD_CAP_BYTES)
        ? (ULONG)FILE_JOURNAL_HARD_CAP_BYTES : (ULONG)FileStdInfo.EndOfFile.QuadPart;

    ULONG readOffset = 0;
    if (pReplayOffset && *pReplayOffset <= fileSize)
        readOffset = (ULONG)*pReplayOffset;

    if (readOffset) {
        FILE_POSITION_INFORMATION filePosition;
        filePosition.CurrentByteOffset.QuadPart = readOffset;
        // If the seek fails, reading from the wrong offset would re-apply already-processed
        // entries, corrupting the in-memory tree.  Return FALSE so the caller falls back to
        // a full reload rather than silently replaying stale data.
        if (!NT_SUCCESS(NtSetInformationFile(hPathsFile, &IoStatusBlock, &filePosition, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation))) {
            NtClose(hPathsFile);
            return FALSE;
        }
    }

    ULONG readSize = (readOffset < fileSize) ? (fileSize - readOffset) : 0;
    // Defense-in-depth: readSize <= fileSize <= FILE_JOURNAL_HARD_CAP_BYTES already,
    // but keep the explicit clamp to make the Dll_Alloc(readSize + 128) safety obvious.
    if (readSize > (ULONG)FILE_JOURNAL_HARD_CAP_BYTES)
        readSize = (ULONG)FILE_JOURNAL_HARD_CAP_BYTES;
    WCHAR* Buffer = (WCHAR *)Dll_Alloc(readSize + 128);
    if (!Buffer) {
        NtClose(hPathsFile);
        return FALSE;
    }
    NTSTATUS read_status = NtReadFile(hPathsFile, NULL, NULL, NULL, &IoStatusBlock, Buffer, readSize, NULL, NULL);
    if (!NT_SUCCESS(read_status)) {
        Dll_Free(Buffer);
        NtClose(hPathsFile);
        return FALSE;
    }
    ULONG bytesRead = (ULONG)IoStatusBlock.Information;
    if (bytesRead > readSize)
        bytesRead = readSize;
    if (bytesRead & 1)
        bytesRead -= 1; // malformed/truncated byte stream: keep WCHAR alignment
    Buffer[bytesRead / sizeof(WCHAR)] = L'\0';

    WCHAR* ParseStart = Buffer;
    if (readOffset == 0 && bytesRead >= sizeof(WCHAR) && ParseStart[0] == FILE_UTF16_LE_BOM)
        ParseStart += 1;

    // Only parse complete lines to avoid losing operations when the last line
    // is observed mid-write by a concurrent reader.
    WCHAR* ParseEnd = Buffer + (bytesRead / sizeof(WCHAR));
    if (bytesRead != 0 && ParseEnd > ParseStart && ParseEnd[-1] != L'\n') {
        WCHAR* LastNl = wcsrchr(ParseStart, L'\n');
        if (LastNl)
            ParseEnd = LastNl + 1;
        else
            ParseEnd = ParseStart;
    }

    WCHAR* Next = ParseStart;
    while (Next < ParseEnd && *Next) {
        WCHAR* Line = Next;
        WCHAR* End = wcschr(Line, L'\n');
        if (End == NULL) {
            End = ParseEnd;
            Next = End;
        } else
            Next = End + 1;

        LONG LineLen = (LONG)(End - Line);
        if (LineLen >= 1 && Line[LineLen - 1] == L'\r')
            LineLen -= 1;
        if (LineLen < 3)
            continue;

        WCHAR savechar = Line[LineLen];
        Line[LineLen] = L'\0';

        WCHAR* Sep1 = File_JournalFindUnescapedPipe_internal(Line);
        if (Sep1) {
            *Sep1 = L'\0';
            WCHAR* Part2 = Sep1 + 1;
            WCHAR* Sep2 = File_JournalFindUnescapedPipe_internal(Part2);

            // Separator contract: only unescaped '|' is structural. Escaped
            // payload pipes are written as '\|' and must not split fields.
            // This keeps opcode parsing stable for both plain and escaped
            // journal lines while still using opcodes 1/2/3 only.

            // Journal format:
            // path|1 (delete)
            // path|2|newPath (relocation)
            // keyPath|3|valueName (registry value delete, key_del.c)
            // In escaped mode, payload fields are backslash-escaped but opcodes
            // remain 1/2/3 for backward-compatible reads.
            if (_wcsicmp(Part2, L"1") == 0) {
                WCHAR* ParsedPath = File_JournalUnescapeField_internal(Line);
                const WCHAR* UsePath = ParsedPath ? ParsedPath : Line;
                if (File_HasMalformedDosPathPair_internal(UsePath, NULL)) {
                    if (ParsedPath) Dll_Free(ParsedPath);
                    *Sep1 = L'|';
                    Line[LineLen] = savechar;
                    continue;
                }
                WCHAR* PathEx = TranslatePath ? TranslatePath(UsePath) : NULL;
                const WCHAR* FinalPath = File_TrimTrailingBackslashes(PathEx ? PathEx : UsePath, TMPL_NAME_BUFFER);
                File_MarkDeleted_internal(Root, FinalPath, NULL);
                if (PathEx) Dll_Free(PathEx);
                if (ParsedPath) Dll_Free(ParsedPath);
                if (pAppliedLines) *pAppliedLines += 1;
            }
            else if (Sep2) {
                *Sep2 = L'\0';
                if (_wcsicmp(Part2, L"2") == 0) {
                    WCHAR* ParsedOld = File_JournalUnescapeField_internal(Line);
                    WCHAR* ParsedNew = File_JournalUnescapeField_internal(Sep2 + 1);
                    const WCHAR* UseOld = ParsedOld ? ParsedOld : Line;
                    const WCHAR* UseNew = ParsedNew ? ParsedNew : (Sep2 + 1);
                    if (File_HasMalformedDosPathPair_internal(UseOld, UseNew)) {
                        if (ParsedOld) Dll_Free(ParsedOld);
                        if (ParsedNew) Dll_Free(ParsedNew);
                        *Sep2 = L'|';
                        *Sep1 = L'|';
                        Line[LineLen] = savechar;
                        continue;
                    }
                    WCHAR* OldPathEx = TranslatePath ? TranslatePath(UseOld) : NULL;
                    WCHAR* NewPathEx = TranslatePath ? TranslatePath(UseNew) : NULL;
                    const WCHAR* FinalOldPath = File_TrimTrailingBackslashes(OldPathEx ? OldPathEx : UseOld, TMPL_NAME_BUFFER);
                    const WCHAR* FinalNewPath = File_TrimTrailingBackslashes(NewPathEx ? NewPathEx : UseNew, NORM_NAME_BUFFER);
                    File_SetRelocation_internal(Root, FinalOldPath, FinalNewPath);
                    if (OldPathEx) Dll_Free(OldPathEx);
                    if (NewPathEx) Dll_Free(NewPathEx);
                    if (ParsedOld) Dll_Free(ParsedOld);
                    if (ParsedNew) Dll_Free(ParsedNew);
                    if (pAppliedLines) *pAppliedLines += 1;
                }
                else if (_wcsicmp(Part2, L"3") == 0) {
                    WCHAR* ParsedKey = File_JournalUnescapeField_internal(Line);
                    WCHAR* ParsedValue = File_JournalUnescapeField_internal(Sep2 + 1);
                    const WCHAR* UseKey = ParsedKey ? ParsedKey : Line;
                    const WCHAR* ValueName = ParsedValue ? ParsedValue : (Sep2 + 1);
                    if (File_IsDriveLessDosPath_internal(UseKey)) {
                        if (ParsedKey) Dll_Free(ParsedKey);
                        if (ParsedValue) Dll_Free(ParsedValue);
                        *Sep2 = L'|';
                        *Sep1 = L'|';
                        Line[LineLen] = savechar;
                        continue;
                    }
                    WCHAR* KeyPathEx = TranslatePath ? TranslatePath(UseKey) : NULL;
                    const WCHAR* FinalKeyPath = File_TrimTrailingBackslashes(KeyPathEx ? KeyPathEx : UseKey, TMPL_NAME_BUFFER);

                    ULONG pathLen = (ULONG)wcslen(FinalKeyPath);
                    ULONG valueLen = (ULONG)wcslen(ValueName);
                    WCHAR* FullPath = (WCHAR*)Dll_Alloc((pathLen + 1 + 1 + valueLen + 1) * sizeof(WCHAR));
                    if (FullPath) {
                        wcscpy(FullPath, FinalKeyPath);
                        FullPath[pathLen] = L'\\';
                        FullPath[pathLen + 1] = L'$';
                        FullPath[pathLen + 2] = L'\0';
                        wcscat(FullPath, ValueName);

                        File_MarkDeleted_internal(Root, FullPath, NULL);
                        Dll_Free(FullPath);
                        if (pAppliedLines) *pAppliedLines += 1;
                    }

                    if (KeyPathEx) Dll_Free(KeyPathEx);
                    if (ParsedKey) Dll_Free(ParsedKey);
                    if (ParsedValue) Dll_Free(ParsedValue);
                }
                *Sep2 = L'|';
            }

            *Sep1 = L'|';
        }

        Line[LineLen] = savechar;
    }

    Dll_Free(Buffer);
    NtClose(hPathsFile);

    if (pReplayOffset)
        *pReplayOffset = (ULONG64)readOffset + (ULONG)((ParseEnd - Buffer) * sizeof(WCHAR));

    return TRUE;
}


//---------------------------------------------------------------------------
// File_CompactPathJournal_internal
//---------------------------------------------------------------------------


_FX BOOLEAN File_CompactPathJournal_internal(CRITICAL_SECTION* CritSec, PATH_LIST* Root, const WCHAR* datName, const WCHAR* logName, WCHAR* (*TranslatePath)(const WCHAR*), WCHAR* (*TranslatePathForLoad)(const WCHAR*), ULONG64* pLogSize, ULONG64* pLogDate, ULONG64* pReplayOffset, HANDLE* pAppendHandle, BOOLEAN isV3)
{
    // Close the caller's keep-open append handle (still under CritSec on entry).
    if (pAppendHandle && *pAppendHandle) {
        NtClose(*pAppendHandle);
        *pAppendHandle = NULL;
    }

    // Phase 1 (under CritSec, held by caller on entry):
    // Replay the complete journal from offset 0 so the in-memory tree includes every
    // entry written by other processes since this process last refreshed.  The VFS
    // mutex is held by the caller throughout, preventing any new journal appends.
    // TranslatePathForLoad is the inverse of TranslatePath: the journal stores paths
    // in "storage" format (e.g. DOS paths), but the in-memory tree uses the opposite
    // format (e.g. NT paths for the file VFS).  Using TranslatePath here would corrupt
    // paths — e.g. File_TranslateNtToDosPathForDatFile applied to "E:\Qt\..." strips the
    // drive letter, turning it into ":\Qt\...".
    BOOLEAN replay_ok = FALSE;
    {
        ULONG64 dummy_offset = 0;
        replay_ok = File_LoadPathJournal_internal(Root, logName, TranslatePathForLoad, &dummy_offset, NULL);
    }

    // Never compact/truncate if full replay failed; keeping the journal is safer
    // than committing a potentially incomplete in-memory snapshot to .dat.
    if (!replay_ok)
        return FALSE;

    // Serialize the now-complete tree to a heap buffer so all disk IO can be done
    // outside CritSec (Phase 2), keeping in-process query latency low.
    PATH_TREE_BUF compactBuf;
    compactBuf.Data = NULL; compactBuf.Used = 0; compactBuf.Cap = 0; compactBuf.OOM = FALSE;
    BOOLEAN bSerializedOK = FALSE;
    WCHAR* tmpPath = (WCHAR*)Dll_Alloc((0x7FFF + 1) * sizeof(WCHAR)); // max NT path
    if (tmpPath) {
        if (isV3)
            File_SerializePathNodeToBufferV3(&compactBuf, Root, tmpPath, 0, 0, TranslatePath);
        else
            File_SerializePathNodeToBuffer(&compactBuf, Root, tmpPath, 0, 0, TranslatePath);
        bSerializedOK = TRUE;
        Dll_Free(tmpPath);
        tmpPath = NULL;
    }

    // Release CritSec: tree snapshot is in compactBuf; the VFS mutex prevents concurrent
    // tree-modification by any other thread (they also require the VFS mutex first).
    // CritSec is intentionally released during disk I/O to avoid blocking in-process
    // readers (e.g. File_IsDeleted_v2) during potentially long compaction writes.
    // The VFS mutex (held by the caller) prevents concurrent tree mutations — all
    // writers also acquire the VFS mutex before CritSec.  Readers only hold CritSec
    // for the duration of their lookup, and the tree remains in a consistent state
    // throughout because no mutations can happen without the VFS mutex.
    LeaveCriticalSection(CritSec);

    // Phase 2 (outside CritSec): all disk IO.
    BOOLEAN bLogTruncated = FALSE;
    if (bSerializedOK && !compactBuf.OOM) {
        // Back up the previous .dat before overwriting.  This is a best-effort
        // safety net: if the write below succeeds, we delete the backup.  If the
        // write fails (disk full, I/O error), we leave the backup in place.
        // NOTE: startup code (File_LoadPathTree / File_InitDelete_v2) does NOT
        // currently attempt to restore from .dat.bak.  A future improvement could
        // detect a stale .dat.bak on init and use it to recover a corrupted .dat.
        BOOLEAN haveDatBackup = FALSE;
        ULONG bakLen = (ULONG)wcslen(datName) + 5; // ".bak\0"
        WCHAR* datBackupName = (WCHAR*)Dll_Alloc(bakLen * sizeof(WCHAR));
        if (datBackupName) {
            wcscpy(datBackupName, datName);
            wcscat(datBackupName, L".bak");
            haveDatBackup = File_CopyDataFile(datName, datBackupName);
        }

        // Write the serialized tree to .dat.  Only truncate the journal if this
        // succeeds to avoid data loss (e.g. disk-full scenario).
        if (File_WriteBufferToDataFile(datName, compactBuf.Data, compactBuf.Used)) {
            HANDLE hLogFile;
            if (File_OpenDataFile(logName, &hLogFile, FALSE)) {
                NtClose(hLogFile);
                if (pLogSize && pLogDate)
                    File_GetAttributes_internal(logName, pLogSize, pLogDate, NULL);
                if (pReplayOffset)
                    *pReplayOffset = 0;
                bLogTruncated = TRUE;
            }
        }

        // Only remove the backup once we have confirmed that the new .dat was
        // fully written (bLogTruncated == TRUE means both the write and the
        // journal truncation succeeded).  If the write failed, the backup is the
        // only surviving copy of the previous .dat state — deleting it here
        // would cause permanent data loss.
        if (haveDatBackup && bLogTruncated)
            File_DeleteDataFile(datBackupName);
        if (datBackupName)
            Dll_Free(datBackupName);
    }

    if (compactBuf.Data)
        Dll_Free(compactBuf.Data);

    // Re-acquire CritSec so the caller's LeaveCriticalSection remains valid and
    // post-compact state updates (.dat size/date, line count) stay protected.
    EnterCriticalSection(CritSec);
    // Note: caller resets its own line count after this call only when TRUE is returned.
    return bLogTruncated;
}


//---------------------------------------------------------------------------
// File_TranslateDosToNtPathForDatFile
//---------------------------------------------------------------------------


_FX WCHAR *File_TranslateDosToNtPathForDatFile(const WCHAR *DosPath)
{
    WCHAR *NtPath = NULL;

    if (DosPath && DosPath[0] && DosPath[1]) {

        if (DosPath[0] == L'\\' && DosPath[1] == L'\\') {

            //
            // network path
            //

            DosPath += 2;
            NtPath = File_ConcatPath2(File_Mup, File_MupLen, DosPath, wcslen(DosPath));

        } else if (DosPath[0] != L'\\') {

            const WCHAR* backslash = wcschr(DosPath, L'\\');
            if(!backslash) backslash = wcschr(DosPath, L'\0');
            if (*(backslash - 1) == L':') {

                ULONG path_pos = (ULONG)(backslash - DosPath);

                //
                // drive-letter path
                //

                FILE_DRIVE* drive = File_GetDriveForLetter(DosPath[0]);
                if (drive) {

                    if (File_DriveAddSN && *drive->sn) {

                        //
                        // if the volume serial numbers don't match return NULL
                        //

                        if (_wcsnicmp(DosPath + 2, drive->sn, 9) != 0) {
                            LeaveCriticalSection(File_DrivesAndLinks_CritSec);
                            return NULL;
                        }
                    }

                    DosPath += path_pos;
                    NtPath = File_ConcatPath2(drive->path, drive->len, DosPath, wcslen(DosPath));

                    LeaveCriticalSection(File_DrivesAndLinks_CritSec);
                }
            }
        }
    }

    return NtPath;
}


//---------------------------------------------------------------------------
// File_LoadPathTree
//---------------------------------------------------------------------------


_FX BOOLEAN File_LoadPathTree()
{
    const WCHAR* datName = File_DeleteV3 ? FILE_PATH_FILE_NAME_V3 : FILE_PATH_FILE_NAME;
    const WCHAR* logName = File_DeleteV3 ? FILE_PATH_LOG_FILE_NAME_V3 : FILE_PATH_LOG_FILE_NAME;

    DWORD wait_res = WaitForSingleObject(File_VfsMutex, 5000);
    if (wait_res != WAIT_OBJECT_0 && wait_res != WAIT_ABANDONED)
        return FALSE;

    EnterCriticalSection(File_PathRoot_CritSec);

    if (File_DeleteV3) {
        // V3 .dat uses the same opcode format as .sbie; reuse the journal parser.
        File_ClearPathBranche_internal(&File_PathRoot);
        ULONG64 dummy_offset = 0;
        File_LoadPathJournal_internal(&File_PathRoot, datName, File_TranslateDosToNtPathForDatFile, &dummy_offset, NULL);

        // V3: journal (.sbie) is always active; replay it on top of the .dat snapshot.
        ULONG applied_lines = 0;
        File_PathsLogReplayOffset = 0;
        File_LoadPathJournal_internal(&File_PathRoot, logName, File_TranslateDosToNtPathForDatFile, &File_PathsLogReplayOffset, &applied_lines);
        File_PathsLogLineCount = applied_lines;
    } else {
        // V2: legacy .dat format only — no journal interaction.
        File_LoadPathTree_internal(&File_PathRoot, datName, File_TranslateDosToNtPathForDatFile);
    }

    LeaveCriticalSection(File_PathRoot_CritSec);

    ReleaseMutex(File_VfsMutex);

    File_PathsVersion++;

    return TRUE;
}


//---------------------------------------------------------------------------
// File_RefreshPathTree
//---------------------------------------------------------------------------


_FX VOID File_RefreshPathTree()
{
    const WCHAR* datName = File_DeleteV3 ? FILE_PATH_FILE_NAME_V3 : FILE_PATH_FILE_NAME;
    const WCHAR* logName = File_DeleteV3 ? FILE_PATH_LOG_FILE_NAME_V3 : FILE_PATH_LOG_FILE_NAME;

    ULONG ticks_now = GetTickCount();
    LONG ticks_prev = InterlockedExchangeAdd(&File_LastRefreshTick, 0);
    if ((LONG)(ticks_now - (ULONG)ticks_prev) < (LONG)File_PathRefreshIntervalMs)
        return;
    InterlockedExchange(&File_LastRefreshTick, (LONG)ticks_now);

    // The box-root watcher is an optimization. Some systems may occasionally miss
    // change notifications for sidecar journals, so we also poll metadata here.
    BOOLEAN boxChanged = File_TestBoxRootChange(0);

    ULONG64 PathsFileSize = 0;
    ULONG64 PathsFileDate = 0;
    ULONG64 PathsLogFileSize = 0;
    ULONG64 PathsLogFileDate = 0;

    BOOLEAN bReload = FALSE;
    BOOLEAN bDatChanged = FALSE;
    BOOLEAN bLogChanged = FALSE;
    if (File_GetAttributes_internal(datName, &PathsFileSize, &PathsFileDate, NULL)
        && (File_PathsFileSize != PathsFileSize || File_PathsFileDate != PathsFileDate)) {

        // Don't update globals yet; defer until after reload succeeds.
        bReload = TRUE;
        bDatChanged = TRUE;
    }

    if (File_DeleteV3
        && File_GetAttributes_internal(logName, &PathsLogFileSize, &PathsLogFileDate, NULL)
        && (File_PathsLogFileSize != PathsLogFileSize || File_PathsLogFileDate != PathsLogFileDate)) {

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
        if (bDatChanged || !File_DeleteV3) {
            if (File_LoadPathTree()) {
                if (bDatChanged) {
                    File_PathsFileSize = PathsFileSize;
                    File_PathsFileDate = PathsFileDate;
                }
                if (bLogChanged) {
                    File_PathsLogFileSize = PathsLogFileSize;
                    File_PathsLogFileDate = PathsLogFileDate;
                }
            }
        } else {
            DWORD wait_res = WaitForSingleObject(File_VfsMutex, 5000);
            if (wait_res != WAIT_OBJECT_0 && wait_res != WAIT_ABANDONED) {
                // mutex not acquired — do a safe full reload instead
                File_LoadPathTree();
                return;
            }
            EnterCriticalSection(File_PathRoot_CritSec);

            ULONG64 old_replay_offset = File_PathsLogReplayOffset;
            ULONG applied_lines = 0;
            if (!File_LoadPathJournal_internal(&File_PathRoot, logName, File_TranslateDosToNtPathForDatFile, &File_PathsLogReplayOffset, &applied_lines)) {
                LeaveCriticalSection(File_PathRoot_CritSec);
                ReleaseMutex(File_VfsMutex);
                File_LoadPathTree();
                return;
            }
            // If the journal shrank, another process compacted it and updated
            // the .dat.  The incremental replay would miss those compacted entries,
            // so fall back to a full reload to pick up the new .dat state.
            if (File_PathsLogReplayOffset < old_replay_offset) {
                LeaveCriticalSection(File_PathRoot_CritSec);
                ReleaseMutex(File_VfsMutex);
                File_LoadPathTree();
                return;
            }
            File_PathsLogLineCount += applied_lines;
            File_PathsVersion++;

            if (bLogChanged) {
                File_PathsLogFileSize = PathsLogFileSize;
                File_PathsLogFileDate = PathsLogFileDate;
            }
            LeaveCriticalSection(File_PathRoot_CritSec);
            ReleaseMutex(File_VfsMutex);
        }
    }
}


//---------------------------------------------------------------------------
// File_SetDeleteV3RefreshInterval
//---------------------------------------------------------------------------


_FX VOID File_SetDeleteV3RefreshInterval(ULONG IntervalMs)
{
    if (IntervalMs > 5000)
        IntervalMs = 5000;
    File_PathRefreshIntervalMs = IntervalMs;
}


//---------------------------------------------------------------------------
// File_SetDeleteV3
//---------------------------------------------------------------------------


_FX VOID File_SetDeleteV3(BOOLEAN Enabled)
{
    File_DeleteV3 = Enabled;
    File_CurrentLogName = Enabled ? FILE_PATH_LOG_FILE_NAME_V3 : FILE_PATH_LOG_FILE_NAME;
    File_CurrentDatName = Enabled ? FILE_PATH_FILE_NAME_V3 : FILE_PATH_FILE_NAME;
}


//---------------------------------------------------------------------------
// File_SetDeleteV3JournalMaxSizeKB
//---------------------------------------------------------------------------


_FX VOID File_SetDeleteV3JournalMaxSizeKB(ULONG MaxSizeKB)
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
    File_DeleteV3JournalMaxSizeBytes = MaxSizeKB * 1024;
}


//---------------------------------------------------------------------------
// File_SetDeleteV3JournalMaxLines
//---------------------------------------------------------------------------


_FX VOID File_SetDeleteV3JournalMaxLines(ULONG MaxLines)
{
    if (MaxLines > 100000000)
        MaxLines = 100000000;
    File_DeleteV3JournalMaxLines = MaxLines;
}


//---------------------------------------------------------------------------
// File_SetDeleteV3JournalKeepOpenMs
//---------------------------------------------------------------------------


_FX VOID File_SetDeleteV3JournalKeepOpenMs(ULONG KeepOpenMs)
{
    if (KeepOpenMs > 60000)
        KeepOpenMs = 60000;
    File_DeleteV3JournalKeepOpenMs = KeepOpenMs;
}


//---------------------------------------------------------------------------
// File_SetDeleteV3CompactionBusyWritesPerSec
//---------------------------------------------------------------------------


_FX VOID File_SetDeleteV3CompactionBusyWritesPerSec(ULONG WritesPerSec)
{
    if (WritesPerSec > 100000)
        WritesPerSec = 100000;
    File_DeleteV3CompactionBusyWritesPerSec = WritesPerSec;
}


//---------------------------------------------------------------------------
// File_SetDeleteV3CompactionBusyHoldMs
//---------------------------------------------------------------------------


_FX VOID File_SetDeleteV3CompactionBusyHoldMs(ULONG HoldMs)
{
    if (HoldMs > 300000)
        HoldMs = 300000;
    File_DeleteV3CompactionBusyHoldMs = HoldMs;
}


//---------------------------------------------------------------------------
// File_SetDeleteV3CompactionMinGraceMs
//---------------------------------------------------------------------------


_FX VOID File_SetDeleteV3CompactionMinGraceMs(ULONG MinGraceMs)
{
    if (MinGraceMs > 300000)
        MinGraceMs = 300000;
    File_DeleteV3CompactionMinGraceMs = MinGraceMs;
}


//---------------------------------------------------------------------------
// File_AtomicTickMax
//
// Lock-free CAS loop that writes newVal into *pShared only when newVal is
// strictly later (in tick space) than the current value.  Safe to call from
// any process at any time — no additional synchronisation needed.
//---------------------------------------------------------------------------


_FX VOID File_AtomicTickMax(volatile LONG* pShared, ULONG newVal)
{
    if (!pShared)
        return;
    LONG expected;
    do {
        expected = *pShared;
        if ((LONG)(newVal - (ULONG)expected) <= 0)
            return; // newVal is not later than current — nothing to do
    } while (InterlockedCompareExchange(pShared, (LONG)newVal, expected) != expected);
}


//---------------------------------------------------------------------------
// File_InitDelete_v2
//---------------------------------------------------------------------------


_FX BOOLEAN File_InitDelete_v2()
{
    memzero(&File_PathRoot, sizeof(PATH_LIST));

    File_PathRoot_CritSec = Dll_Alloc(sizeof(CRITICAL_SECTION));
    InitializeCriticalSectionAndSpinCount(File_PathRoot_CritSec, 1000);

    // Build per-box named-object names. Including Dll_BoxName means that even
    // if a box has an OpenIpcPath rule matching "SBIE*", processes in different
    // boxes cannot share these synchronisation objects.
    Sbie_snwprintf(File_VfsMutexName,        ARRAYSIZE(File_VfsMutexName),        L"SBIE_%s_VFS_Mutex",         Dll_BoxName);
    Sbie_snwprintf(File_VfsCompactMutexName, ARRAYSIZE(File_VfsCompactMutexName), L"SBIE_%s_VFS_Compact_Mutex", Dll_BoxName);
    Sbie_snwprintf(File_VfsBusyTickName,     ARRAYSIZE(File_VfsBusyTickName),     L"SBIE_%s_VFS_BusyTick",      Dll_BoxName);

    // Create the inter-process mutex BEFORE calling File_LoadPathTree so the
    // initial load is correctly serialized against other processes.
    {
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = SbieDll_GetPublicSD();
        sa.bInheritHandle = FALSE;
        File_VfsMutex = CreateMutex(&sa, FALSE, FILE_VFS_MUTEX);
    }

    if (File_DeleteV3) {
        // Named page-file-backed section — shared among all sandbox processes for
        // cross-process burst-deferral.  Only needed in v3 journal mode.
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = SbieDll_GetPublicSD();
        sa.bInheritHandle = FALSE;
        File_SharedBusyHandle = CreateFileMapping(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, sizeof(LONG), FILE_VFS_BUSY_TICK);
        if (File_SharedBusyHandle)
            File_SharedBusyUntilTick = (volatile LONG*)MapViewOfFile(File_SharedBusyHandle, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(LONG));

        // Initialise the file VFS journal context used by Vfs_AppendAndMaybeCompact_internal.
        // All fields are pointers to module-global variables; setters update those variables
        // directly, so the context always reflects the current configuration.
        File_JournalCtx.pLogName            = &File_CurrentLogName;
        File_JournalCtx.pDatName            = &File_CurrentDatName;
        File_JournalCtx.TranslateForWrite   = File_TranslateNtToDosPathForDatFile;
        File_JournalCtx.TranslateForLoad    = File_TranslateDosToNtPathForDatFile;
        File_JournalCtx.CritSec             = File_PathRoot_CritSec;
        File_JournalCtx.Root                = &File_PathRoot;
        File_JournalCtx.pAppendHandle       = &File_PathsLogAppendHandle;
        File_JournalCtx.pAppendLastTick     = &File_PathsLogAppendLastTick;
        File_JournalCtx.pKeepOpenMs         = &File_DeleteV3JournalKeepOpenMs;
        File_JournalCtx.pLogFileSize        = &File_PathsLogFileSize;
        File_JournalCtx.pLogFileDate        = &File_PathsLogFileDate;
        File_JournalCtx.pReplayOffset       = &File_PathsLogReplayOffset;
        File_JournalCtx.pLogLineCount       = &File_PathsLogLineCount;
        File_JournalCtx.pMaxSizeBytes       = &File_DeleteV3JournalMaxSizeBytes;
        File_JournalCtx.pMaxLines           = &File_DeleteV3JournalMaxLines;
        File_JournalCtx.pBusyWritesPerSec   = &File_DeleteV3CompactionBusyWritesPerSec;
        File_JournalCtx.pBusyHoldMs         = &File_DeleteV3CompactionBusyHoldMs;
        File_JournalCtx.pMinGraceMs         = &File_DeleteV3CompactionMinGraceMs;
        File_JournalCtx.pRecentWriteCount   = &File_RecentWriteCount;
        File_JournalCtx.pRecentWriteWindowTick = &File_RecentWriteWindowTick;
        File_JournalCtx.pBusyUntilTick      = &File_CompactionBusyUntilTick;
        File_JournalCtx.pSharedBusyUntilTick = File_SharedBusyUntilTick;
        File_JournalCtx.compactMutexName    = File_VfsCompactMutexName;
        File_JournalCtx.pDatFileSize        = &File_PathsFileSize;
        File_JournalCtx.pDatFileDate        = &File_PathsFileDate;
        File_JournalCtx.pIsV3               = &File_DeleteV3;
    }

    File_LoadPathTree(); // sets File_PathsLogReplayOffset and File_PathsLogLineCount

//#ifdef WITH_DEBUG
//    File_SavePathTree();
//#endif

    // Update the dat/log size+date caches used by File_RefreshPathTree for
    // change-detection.  File_LoadPathTree does not update these in journal mode.
    {
        const WCHAR* datName = File_DeleteV3 ? FILE_PATH_FILE_NAME_V3 : FILE_PATH_FILE_NAME;
        const WCHAR* logName = File_DeleteV3 ? FILE_PATH_LOG_FILE_NAME_V3 : FILE_PATH_LOG_FILE_NAME;
        File_GetAttributes_internal(datName, &File_PathsFileSize, &File_PathsFileDate, NULL);
        if (File_DeleteV3)
            File_GetAttributes_internal(logName, &File_PathsLogFileSize, &File_PathsLogFileDate, NULL);
    }
    // NOTE: do NOT reset File_PathsLogReplayOffset / File_PathsLogLineCount here;
    // File_LoadPathTree already initialised them correctly.
    File_PathsLogAppendLastTick = 0;
    if (File_PathsLogAppendHandle) {
        NtClose(File_PathsLogAppendHandle);
        File_PathsLogAppendHandle = NULL;
    }

    File_InitBoxRootWatcher();

    return TRUE;
}


//---------------------------------------------------------------------------
// File_InitBoxRootWatcher
//---------------------------------------------------------------------------


_FX BOOL File_InitBoxRootWatcher()
{
    if (File_BoxRootWatcher)
        return TRUE; // already initialized

    UNICODE_STRING objname;
    RtlInitUnicodeString(&objname, Dll_BoxFilePath);

    OBJECT_ATTRIBUTES objattrs;
    InitializeObjectAttributes(&objattrs, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatusBlock;
    if (NT_SUCCESS(NtOpenFile(&FileHandle, FILE_READ_DATA | SYNCHRONIZE, &objattrs, &IoStatusBlock, FILE_SHARE_VALID_FLAGS, FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT))) {

        // IoStatusBlock MUST be static/global because NtNotifyChangeDirectoryFile works asynchronously.
        // It may write into io after the function has left, which may result in all sorts of memory corruption.
        if (NT_SUCCESS(NtNotifyChangeDirectoryFile(FileHandle, NULL, NULL, NULL, &File_NotifyIosb, File_NotifyInfo, sizeof(File_NotifyInfo), FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE, FALSE))) {

            File_BoxRootWatcher = FileHandle;

            //FindNextChangeNotification(File_BoxRootWatcher);  // arm the watcher
            NtNotifyChangeDirectoryFile(File_BoxRootWatcher, NULL, NULL, NULL, &File_NotifyIosb, File_NotifyInfo, sizeof(File_NotifyInfo), 3u, 1u);

            return TRUE;
        }
        else
            NtClose(FileHandle);
    }
    return FALSE;
}


//---------------------------------------------------------------------------
// File_TestBoxRootChange
//---------------------------------------------------------------------------


_FX BOOL File_TestBoxRootChange(ULONG WatchBit)
{
    if (!File_BoxRootWatcher)
        return FALSE; // not initialized

    LARGE_INTEGER Timeout = { 0 };
    if(NtWaitForSingleObject(File_BoxRootWatcher, 0, &Timeout) == WAIT_OBJECT_0) {
    //if (WaitForSingleObject(File_BoxRootWatcher, 0) == WAIT_OBJECT_0) {

        InterlockedOr((LONG*)&File_BoxRootChangeBits, -1); // set all bits atomically

        //FindNextChangeNotification(File_BoxRootWatcher); // rearm the watcher
        NtNotifyChangeDirectoryFile(File_BoxRootWatcher, NULL, NULL, NULL, &File_NotifyIosb, File_NotifyInfo, sizeof(File_NotifyInfo), 3u, 1u);
    }

    ULONG WatchMask = 1 << WatchBit;
    LONG prev = InterlockedAnd((LONG*)&File_BoxRootChangeBits, ~(LONG)WatchMask); // clear bit atomically
    BOOL bRet = (prev & (LONG)WatchMask) != 0;
    return bRet;
}


//---------------------------------------------------------------------------
// File_UpdateJournalState_internal
//---------------------------------------------------------------------------


_FX VOID File_UpdateJournalState_internal(ULONG BytesWritten, ULONG64* pLogFileSize, ULONG64* pReplayOffset, ULONG* pLogLineCount,
    ULONG WritesPerSecThreshold, ULONG HoldMs, ULONG MinGraceMs, ULONG* pRecentWriteCount, ULONG* pRecentWriteWindowTick, ULONG* pBusyUntilTick)
{
    // Keep cached size/replay/line counters in sync with successful local appends.
    *pLogFileSize += BytesWritten;
    *pReplayOffset += BytesWritten;
    *pLogLineCount += 1;

    if (WritesPerSecThreshold != 0) {
        ULONG busy_ticks = GetTickCount();
        *pRecentWriteCount += 1;

        if (*pRecentWriteWindowTick == 0) {
            *pRecentWriteWindowTick = busy_ticks;
            // Pre-arm the busy window on the first write so the burst-deferral
            // window is active from the very start and compaction cannot fire
            // during the first 1-second rate-measurement blind spot.
            if (MinGraceMs > 0) {
                ULONG grace_until = busy_ticks + MinGraceMs;
                if (*pBusyUntilTick == 0 || (LONG)(grace_until - *pBusyUntilTick) > 0)
                    *pBusyUntilTick = grace_until;
            }
        }

        ULONG elapsed = busy_ticks - *pRecentWriteWindowTick;
        if (elapsed >= 1000) {
            // Guard against ULONG overflow: if write count already exceeds the
            // threshold per millisecond, clamp rather than overflow the multiply.
            ULONG rate = (*pRecentWriteCount > 0xFFFFFFFF / 1000)
                ? 0xFFFFFFFF
                : (*pRecentWriteCount * 1000) / (elapsed ? elapsed : 1);
            *pRecentWriteCount = 0;
            *pRecentWriteWindowTick = busy_ticks;
            if (rate >= WritesPerSecThreshold)
                *pBusyUntilTick = busy_ticks + HoldMs;
        }
    }
}


//---------------------------------------------------------------------------
// File_ShouldCompactJournal_internal
//---------------------------------------------------------------------------


_FX BOOLEAN File_ShouldCompactJournal_internal(ULONG WritesPerSecThreshold, ULONG BusyUntilTick, ULONG64 LogFileSize, ULONG MaxSizeBytes,
    ULONG LogLineCount, ULONG MaxLines)
{
    BOOLEAN bHighIO = (WritesPerSecThreshold != 0 && BusyUntilTick != 0 && (LONG)(GetTickCount() - BusyUntilTick) < 0);
    BOOLEAN bCompactBySize = (!bHighIO && MaxSizeBytes != 0 && LogFileSize >= MaxSizeBytes);
    BOOLEAN bCompactByLines = (!bHighIO && MaxLines != 0 && LogLineCount >= MaxLines);
    return (bCompactBySize || bCompactByLines);
}


//---------------------------------------------------------------------------
// File_MarkDeleted_internal
//---------------------------------------------------------------------------


_FX BOOLEAN File_MarkDeleted_internal(PATH_LIST* Root, const WCHAR* Path, BOOLEAN* pTruncated)
{
    // 1. remove deleted branch

    PATH_LIST* Parent = NULL;
    PATH_NODE* Node = File_FindPathBranche_internal(Root, Path, &Parent, FALSE);
    if (Node) {
        if (Node->flags == FILE_DELETED_FLAG && Node->items.list.count == 0)
            return FALSE; // already marked deleted

        if (Parent->buckets) PathList_RemoveFromTable(Parent, Node);
        List_Remove((LIST*)Parent, Node);

        File_ClearPathBranche_internal(&Node->items);
        if (Node->relocation) Dll_Free(Node->relocation);
        Dll_Free(Node);
        if (pTruncated) *pTruncated = TRUE;
    }

    // 2. set deleted flag

    File_SetPathFlags_internal(Root, Path, FILE_DELETED_FLAG, 0, NULL);

    // done

    return TRUE;
}


//---------------------------------------------------------------------------
// Vjs_OpenHandle_internal
//
// Acquire (or reuse) the journal log handle for appending. Context-generic
// replacement for the former module-specific *_OpenJournalHandle functions.
// *pOneShotHandle is set TRUE when the returned handle must be closed by the
// caller after use.
//---------------------------------------------------------------------------

static BOOLEAN Vjs_OpenHandle_internal(VPATH_JOURNAL_CTX* ctx, HANDLE* phHandle, BOOLEAN* pOneShotHandle)
{
    *pOneShotHandle = TRUE;
    *phHandle = NULL;

    if (*ctx->pKeepOpenMs != 0) {
        ULONG ticks_now = GetTickCount();
        if (*ctx->pAppendHandle && (LONG)(ticks_now - *ctx->pAppendLastTick) > (LONG)*ctx->pKeepOpenMs) {
            NtClose(*ctx->pAppendHandle);
            *ctx->pAppendHandle = NULL;
        }
        if (!*ctx->pAppendHandle && File_OpenDataFileAppendShared(*ctx->pLogName, ctx->pAppendHandle)) {
            *ctx->pAppendLastTick = ticks_now;
        }
        if (*ctx->pAppendHandle) {
            *phHandle = *ctx->pAppendHandle;
            *pOneShotHandle = FALSE;
            return TRUE;
        }
    }

    File_OpenDataFile(*ctx->pLogName, phHandle, TRUE);
    // *pOneShotHandle is already TRUE; caller must close the handle after use.
    return *phHandle != NULL;
}


//---------------------------------------------------------------------------
// Vfs_AppendAndMaybeCompact_internal
//
// Opens the journal, appends one delete or relocation entry, updates the
// cached counters, and triggers compaction when thresholds are exceeded.
// Returns TRUE if the entry was persisted; FALSE means the caller should fall
// back to re-saving the full snapshot (.dat).
// isDelete: TRUE = "path|1" delete entry; FALSE = "old|2|new" relocation.
//---------------------------------------------------------------------------

_FX BOOLEAN Vfs_AppendAndMaybeCompact_internal(
    VPATH_JOURNAL_CTX* ctx,
    BOOLEAN isDelete,
    const WCHAR* Path,
    const WCHAR* NewPath)
{
    ULONG bJournalPersisted = 0;
    HANDLE hPathsFile = NULL;
    BOOLEAN one_shot_handle = TRUE;

    Vjs_OpenHandle_internal(ctx, &hPathsFile, &one_shot_handle);

    if (hPathsFile) {
        if (!one_shot_handle && !File_SeekToEndOfFile(hPathsFile)) {
            NtClose(*ctx->pAppendHandle);
            *ctx->pAppendHandle = NULL;
            hPathsFile = NULL;
            // Retry with a fresh one-shot handle rather than silently dropping the entry.
            File_OpenDataFile(*ctx->pLogName, &hPathsFile, TRUE);
            one_shot_handle = TRUE;
        }
        if (hPathsFile) {
            if (isDelete) {
                if (NewPath)
                    bJournalPersisted = File_AppendPathJournalValueDelete_internal(
                        hPathsFile, Path, NewPath, ctx->TranslateForWrite, *ctx->pIsV3);
                else
                    bJournalPersisted = File_AppendPathJournalDelete_internal(
                        hPathsFile, Path, ctx->TranslateForWrite, *ctx->pIsV3);
            }
            else
                bJournalPersisted = File_AppendPathJournalRelocation_internal(
                    hPathsFile, Path, NewPath, ctx->TranslateForWrite, *ctx->pIsV3);
        }
        if (one_shot_handle)
            NtClose(hPathsFile);
        else
            *ctx->pAppendLastTick = GetTickCount();

        if (bJournalPersisted) {
            File_UpdateJournalState_internal(bJournalPersisted,
                ctx->pLogFileSize, ctx->pReplayOffset, ctx->pLogLineCount,
                *ctx->pBusyWritesPerSec, *ctx->pBusyHoldMs, *ctx->pMinGraceMs,
                ctx->pRecentWriteCount, ctx->pRecentWriteWindowTick, ctx->pBusyUntilTick);

            // Publish local BusyUntilTick to the cross-process shared region so
            // other sandbox processes also defer compaction during a burst.
            File_AtomicTickMax(ctx->pSharedBusyUntilTick, *ctx->pBusyUntilTick);
            ULONG effectiveBusy = ctx->pSharedBusyUntilTick
                ? (ULONG)*ctx->pSharedBusyUntilTick : *ctx->pBusyUntilTick;

            if (File_ShouldCompactJournal_internal(*ctx->pBusyWritesPerSec, effectiveBusy,
                    *ctx->pLogFileSize, *ctx->pMaxSizeBytes,
                    *ctx->pLogLineCount, *ctx->pMaxLines)
                || *ctx->pLogFileSize >= FILE_JOURNAL_HARD_CAP_BYTES) {

                HANDLE hCompactMutex = NULL;
                if (File_TryAcquireCompactionMarker(&hCompactMutex, ctx->compactMutexName)) {
                    EnterCriticalSection(ctx->CritSec);
                    if (File_CompactPathJournal_internal(ctx->CritSec, ctx->Root,
                            *ctx->pDatName, *ctx->pLogName,
                            ctx->TranslateForWrite, ctx->TranslateForLoad,
                            ctx->pLogFileSize, ctx->pLogFileDate,
                            ctx->pReplayOffset, ctx->pAppendHandle, *ctx->pIsV3)) {
                        *ctx->pLogLineCount = 0;
                        // Mandatory post-compact busy tick: prevents back-to-back compactions
                        // when limits are set low (burst would otherwise re-trigger
                        // compaction on the very next write that pushes over the threshold).
                        ULONG post = GetTickCount() + *ctx->pBusyHoldMs;
                        if ((LONG)(post - *ctx->pBusyUntilTick) > 0)
                            *ctx->pBusyUntilTick = post;
                        File_AtomicTickMax(ctx->pSharedBusyUntilTick, *ctx->pBusyUntilTick);
                    }
                    File_GetAttributes_internal(*ctx->pDatName,
                        ctx->pDatFileSize, ctx->pDatFileDate, NULL);
                    LeaveCriticalSection(ctx->CritSec);
                    File_ReleaseMutex(hCompactMutex);
                }
            }
        } else if (!one_shot_handle) {
            NtClose(*ctx->pAppendHandle);
            *ctx->pAppendHandle = NULL;
        }
    }

    return bJournalPersisted != 0;
}


//---------------------------------------------------------------------------
// File_MarkDeleted_v2
//---------------------------------------------------------------------------


_FX NTSTATUS File_MarkDeleted_v2(const WCHAR* TruePath)
{
    //
    // add a file or directory to the deleted list
    //

    DWORD wait_res = WaitForSingleObject(File_VfsMutex, 5000);
    if (wait_res != WAIT_OBJECT_0 && wait_res != WAIT_ABANDONED)
        return STATUS_TIMEOUT;

    EnterCriticalSection(File_PathRoot_CritSec);

    const WCHAR* Path = File_TrimTrailingBackslashes(File_NormalizePath(TruePath, NORM_NAME_BUFFER), TMPL_NAME_BUFFER);
    BOOLEAN bTruncated = FALSE;
    BOOLEAN bSet = File_MarkDeleted_internal(&File_PathRoot, Path, &bTruncated);

    LeaveCriticalSection(File_PathRoot_CritSec);

    if (bSet)
    {
        // Do NOT bump File_PathsVersion here. Per-delete invalidation can reset
        // in-progress directory merge state and make a single delete/rename
        // operation fan out to sibling entries. Keep version bumps tied to
        // full reload/replay paths only (File_LoadPathTree/File_RefreshPathTree).
        if (File_DeleteV3) {
            if (!Vfs_AppendAndMaybeCompact_internal(&File_JournalCtx, TRUE, Path, NULL))
                File_SavePathTree();
        }
        else
        {
        //
        // Optimization: When marking a lot of host files as deleted, only append single line entries if possible instead of re creating the entire file
        //

        ULONG64 PathsFileSize = 0;
        ULONG64 PathsFileDate = 0;
        if (!bTruncated 
            && File_GetAttributes_internal(FILE_PATH_FILE_NAME, &PathsFileSize, &PathsFileDate, NULL)
            && (File_PathsFileSize == PathsFileSize && File_PathsFileDate == PathsFileDate)) {

            HANDLE hPathsFile;
            if (File_OpenDataFile(FILE_PATH_FILE_NAME, &hPathsFile, TRUE))
            {
                BOOLEAN ok = File_AppendPathEntry_internal(hPathsFile, Path, FILE_DELETED_FLAG, NULL, File_TranslateNtToDosPathForDatFile);

                NtClose(hPathsFile);

                if (ok)
                    File_GetAttributes_internal(FILE_PATH_FILE_NAME, &File_PathsFileSize, &File_PathsFileDate, NULL);
                else
                    File_SavePathTree();
            }
        }
        else
            File_SavePathTree();
        }
    }

    ReleaseMutex(File_VfsMutex);

    return STATUS_SUCCESS;
}


//---------------------------------------------------------------------------
// File_IsDeleted_v2
//---------------------------------------------------------------------------


_FX ULONG File_IsDeleted_v2(const WCHAR* TruePath)
{
    //
    // check if the file or one of its parent directories is listed as deleted
    // use the dedicated test method to properly take into account relocations
    //

    ULONG Flags = File_GetPathFlags(TruePath, NULL, FALSE);

    return (Flags & FILE_DELETED_MASK);
}


//---------------------------------------------------------------------------
// File_HasDeleted_v2
//---------------------------------------------------------------------------


_FX BOOLEAN File_HasDeleted_v2(const WCHAR* TruePath)
{
    //
    // Check if this folder has deleted children
    //

    ULONG Flags = File_GetPathFlags(TruePath, NULL, TRUE);

    return (Flags & FILE_CHILDREN_DELETED_FLAG) != 0;
}


//---------------------------------------------------------------------------
// File_SetRelocation_internal
//---------------------------------------------------------------------------


_FX VOID File_SetRelocation_internal(PATH_LIST* Root, const WCHAR *OldTruePath, const WCHAR *NewTruePath)
{
    // 0. check for no operation - in this case 5. would loop forever

    if (_wcsicmp(OldTruePath, NewTruePath) == 0)
        return;
    
    // 1. separate branch from OldTruePath
    
    PATH_LIST* Parent = NULL;
    PATH_NODE* Node = File_FindPathBranche_internal(Root, OldTruePath, &Parent, FALSE);
    //if(Node) 
    //    List_Remove(Parent, Node); // leave node in it may have a delete flag

    // 2. check if old path has a relocation

    BOOLEAN HasRelocation = FALSE;
    if (Node && (Node->flags & FILE_RELOCATION_FLAG) != 0) {
        Node->flags &= ~FILE_RELOCATION_FLAG;
        if (Node->relocation) {
            HasRelocation = TRUE;
            OldTruePath = Node->relocation; // update relocation to oritinal true target
        }
    }


    // 3. add true delete entry OldTruePath

    File_SetPathFlags_internal(Root, OldTruePath, FILE_DELETED_FLAG, 0, NULL);


    // 4. set redirection NewTruePath -> OldTruePath

    PATH_NODE* NewNode = File_FindPathBranche_internal(Root, NewTruePath, NULL, TRUE);
    if (!NewNode) return; // OOM: cannot record relocation, state left consistent (deletion still applied)

    // OldTruePath may have a relocated parent, if so unwrap it
    if (!HasRelocation) {
        WCHAR* OldOldTruePath = NULL;
        File_GetPathFlags_internal(Root, OldTruePath, &OldOldTruePath, TRUE);
        if (OldOldTruePath) OldTruePath = OldOldTruePath;
    }
    
    NewNode->flags |= FILE_RELOCATION_FLAG;
    if (NewNode->relocation) {
        Dll_Free(NewNode->relocation);
        NewNode->relocation = NULL;
    }
    NewNode->relocation = Dll_Alloc((wcslen(OldTruePath) + 1) * sizeof(WCHAR));
    if (NewNode->relocation)
        wcscpy(NewNode->relocation, OldTruePath);
    else
        NewNode->flags &= ~FILE_RELOCATION_FLAG; // Alloc failed; clear flag so node is not left in a half-wired state
    

    // 5. reatach branch to NewTruePath

    if (Node) {
        PATH_NODE* child = List_Head(&Node->items);
        while (child) {

            PATH_NODE* next_child = List_Next(child);

            List_Remove(&Node->items, child);
                
            List_Insert_After(&NewNode->items, NULL, child);

            child = next_child;
        }
        // Rebuild hash tables to reflect the transferred children
        PathList_Rebuild(&Node->items);
        PathList_Rebuild(&NewNode->items);
    }
    

    // 6. clean up

    //if (Node) {
    if (HasRelocation) {
        //if (Node->relocation)
        Dll_Free(Node->relocation);
        Node->relocation = NULL;       
        //Dll_Free(Node);
    }
}


//---------------------------------------------------------------------------
// File_SetRelocation
//---------------------------------------------------------------------------


_FX NTSTATUS File_SetRelocation(const WCHAR* OldTruePath, const WCHAR* NewTruePath)
{
    //
    // List a mapping for the new location
    //

    DWORD wait_res = WaitForSingleObject(File_VfsMutex, 5000);
    if (wait_res != WAIT_OBJECT_0 && wait_res != WAIT_ABANDONED)
        return STATUS_TIMEOUT;

    const WCHAR* OldPath = File_TrimTrailingBackslashes(File_NormalizePath(OldTruePath, NORM_NAME_BUFFER), TMPL_NAME_BUFFER);
    const WCHAR* NewPath = File_TrimTrailingBackslashes(File_NormalizePath(NewTruePath, MISC_NAME_BUFFER), MISC_NAME_BUFFER);

    EnterCriticalSection(File_PathRoot_CritSec);

    File_SetRelocation_internal(&File_PathRoot, OldPath, NewPath);

    LeaveCriticalSection(File_PathRoot_CritSec);

    if (File_DeleteV3) {
        if (!Vfs_AppendAndMaybeCompact_internal(&File_JournalCtx, FALSE, OldPath, NewPath))
            File_SavePathTree();
    }
    else {
        File_SavePathTree();
    }

    ReleaseMutex(File_VfsMutex);

    return STATUS_SUCCESS;
}


//---------------------------------------------------------------------------
// File_GetRelocation
//---------------------------------------------------------------------------


_FX WCHAR* File_GetRelocation(const WCHAR *TruePath)
{
    //
    // Get redirection location, only if its the actual path and not a parent
    // 

    WCHAR* OldTruePath = NULL;
    ULONG Flags = File_GetPathFlags(TruePath, &OldTruePath, FALSE);
    if (FILE_PATH_RELOCATED(Flags))
        return OldTruePath;

    return NULL;
}


//---------------------------------------------------------------------------
// File_GetAttributes_internal
//---------------------------------------------------------------------------


BOOL File_GetAttributes_internal(const WCHAR *name, ULONG64 *size, ULONG64 *date, ULONG *attrs)
{
    ULONG pathLen = (ULONG)wcslen(Dll_BoxFilePath) + 1 + (ULONG)wcslen(name) + 1;
    WCHAR* PathsFile = (WCHAR*)Dll_Alloc(pathLen * sizeof(WCHAR));
    if (!PathsFile) return FALSE;
    wcscpy(PathsFile, Dll_BoxFilePath);
    wcscat(PathsFile, L"\\");
    wcscat(PathsFile, name);
    BOOL ret = SbieDll_QueryFileAttributes(PathsFile, size, date, attrs);
    Dll_Free(PathsFile);
    return ret;
}
