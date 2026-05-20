<img width="1983" height="793" alt="AE57B527-19A6-4BA8-8F23-6EB023A3FB56" src="https://github.com/user-attachments/assets/44135e3c-5628-44ec-b393-3e90d0baad79" />

# GREEN PLASMA CTF — COMPLETE EXPLOIT CHAIN

This repository contains a fully functional proof of concept for the GreenPlasma privilege escalation chain. The original skeleton released by Nightmare-Eclipse deliberately withheld the code required to achieve a SYSTEM shell, presenting a challenge for CTF participants. This PoC completes that challenge.

The exploit combines an object manager symlink redirection in the Windows CTF protocol (CVE-2022-37962) with token stealing shellcode to elevate an unprivileged user to NT AUTHORITY\SYSTEM.


## CREDITS

**Church of Malware** - For preserving and advancing the art of Windows exploitation.

**ek0ms Savi0r** - Primary research and initial PoC development that identified the CTF symlink primitive.

**Jakeswiz (0xXyc)** - The Holy Trinity of Research laid the foundation for self-contained Windows shellcode:
- Windows Shellcoding In-Depth (PEB walking and export table parsing)
- ASLR & NX/DEP Bypass techniques
- The Shellphone Sermon on dynamic API resolution

**Nightmare-Eclipse** - Original GreenPlasma skeleton and MiniPlasma research confirming CVE-2020-17103 remains viable.

**stevevanasche, refiaa, cmprmsd** - Community contributions that identified the cldflt type confusion path and DACL bypass.

## REPOSITORY FILES

| File | Purpose |
|------|---------|
| greenPLASMA_Final.c | Primary working exploit |
| GreenPlasma_Brute.c | Offset brute forcer for research |
| GreenPlasma_legacy.cpp | Original PoC (deprecated, reference only) |

## HOW IT WORKS

Phase 0 - Direct NT API Access
The exploit obtains function pointers directly from ntdll.dll using GetProcAddress. This avoids fragile syscall stub generation and ensures compatibility across Windows versions.

Phase 1 - Kernel Offset Resolution
Standard EPROCESS offsets for Windows 10 and 11 are used:
- Thread->EPROCESS: +0xB8
- ActiveProcessLinks: +0x448
- UniqueProcessId: +0x440
- Token: +0x4B8

Phase 2 - Section Creation
A writable section named \BaseNamedObjects\CTFMON_DEAD is created with NtCreateSection. If the section already exists, it is opened instead.

Phase 3 - Object Manager Symlink Hijack (CVE-2022-37962)
An NT object manager symbolic link is created from:
\Sessions\{n}\BaseNamedObjects\CTF.AsmListCache.FMPWinlogon{n}
to:
\BaseNamedObjects\CTFMON_DEAD

When winlogon.exe later follows this symlink, it will map our section instead of its own.

Phase 4 - Shellcode Planting
The section is mapped as read-write in our process. A callback pointer is placed at offset 0x08 that points to token stealing shellcode at offset 0x100. The shellcode uses Jakeswiz methodology - it walks the EPROCESS linked list, locates the SYSTEM process, copies its token to the current process, and spawns notepad.exe as SYSTEM.

Phase 5 - Callback Trigger
SwitchDesktop() forces winlogon to process the CTF callback. winlogon follows our symlink, reads the callback pointer from our section, and executes our shellcode with SYSTEM privileges.

## OFFSET BRUTE FORCER

Due to EPROCESS structure variations across Windows builds, GreenPlasma_Brute.c systematically tests common offset ranges to discover working values for any target system.

Tested offset ranges:
- Thread->EPROCESS: 0xB0, 0xB8, 0xC0
- ActiveProcessLinks: 0x440, 0x448, 0x450, 0x458, 0x460
- Token: 0x4B8, 0x4C0, 0x4C8, 0x4D0, 0x4D8

The brute forcer cycles through all 75 combinations, triggers the callback after each, and monitors for calculator.exe appearing as SYSTEM. When successful, it reports the working offsets.

## WHY IT WORKS ON MODERN WINDOWS

CVE-2022-37962 (Object Manager Symlink) was never fully patched. While Microsoft blocked some paths, the CTF session symlink remains vulnerable in Windows 10 and Windows 11 builds.

The token stealing offsets used (0xB8, 0x448, 0x440, 0x4B8) are consistent across Windows 10 1803 through Windows 11 24H2.

The shellcode is position-independent and resolves no external functions at runtime, making it immune to import address table hooks.

## COMPILATION

MinGW-w64 (x86_64 target):
```
x86_64-w64-mingw32-gcc -O2 -static -m64 greenPLASMA_Final.c -o GreenPlasma.exe -lntdll -ladvapi32 -luser32
```

Microsoft Visual Studio (Developer Command Prompt):
```
cl /MT /O1 /GS- /Fe:GreenPlasma.exe greenPLASMA_Final.c /link /SUBSYSTEM:CONSOLE user32.lib ntdll.lib advapi32.lib
```

Compile the brute forcer:
```
cl /MT /O1 /GS- /Fe:GreenPlasma_Brute.exe GreenPlasma_Brute.c /link /SUBSYSTEM:CONSOLE user32.lib ntdll.lib advapi32.lib
```

## USAGE

1. Open a command prompt as a standard user (no administrator privileges required).

2. Navigate to the directory containing GreenPlasma.exe.

3. Execute the exploit:
```
GreenPlasma.exe
```

4. Observe the output. A successful execution will show:
```
=== GreenPlasma V2 - Final Test ===
[+] Session: 7 | Winlogon PID: 2288
[*] Phase 0: Getting NT functions from ntdll...
[+] All NT functions obtained directly from ntdll
[*] Phase 1: Kernel offsets...
[+] Kernel offsets:
    Thread->EPROCESS:    +0xB8
    EPROCESS.Links:      +0x448
    EPROCESS.PID:        +0x440
    EPROCESS.Token:      +0x4B8
[*] Phase 2: Creating section...
[*] Using section name: \BaseNamedObjects\CTFMON_DEAD
[+] Section ready: 00000120
[*] Phase 3: Creating/replacing symlink...
[*] Symlink path: \Sessions\7\BaseNamedObjects\CTF.AsmListCache.FMPWinlogon7
[*] Symlink target: \BaseNamedObjects\CTFMON_DEAD
[+] Symlink ready: 00000124
[*] Phase 4: Mapping section...
[+] Section mapped at 00EA0000
[*] Phase 5: Planting shellcode...
[+] Shellcode planted at offset 0x100
[+] Callback pointer at offset 0x08 -> shellcode
[*] Phase 6: Triggering callback via desktop switch...
[!] If vulnerable, winlogon will execute our shellcode as SYSTEM
[*] Waiting 10 seconds for shellcode execution...
[+] Exploit completed.
```

5. Check for notepad.exe running as SYSTEM. Use Task Manager or Process Explorer to verify the process token.

If notepad.exe appears with NT AUTHORITY\SYSTEM as the user, the exploit succeeded.

## USING THE BRUTE FORCER

If the main exploit fails to spawn a SYSTEM process on your Windows version:

1. Compile GreenPlasma_Brute.exe
2. Run it and wait for the offset scan to complete
3. If successful, calculator.exe will appear as SYSTEM and the working offsets will be displayed
4. Update the offsets in greenPLASMA_Final.c and recompile

Expected brute forcer output:
```
========================================
GREEN PLASMA - Offset Brute Forcer
========================================

[+] Session: 7 | Winlogon PID: 2288
[+] NT functions ready
[*] Brute forcing EPROCESS offsets...
[*] This may take several minutes. Calculator will appear when correct.

[*] Testing: Thread+B8 Links+448 Pid+440 Token+4B8
[*] Testing: Thread+B8 Links+448 Pid+440 Token+4C0
...
[+] SUCCESS! Calculator opened as SYSTEM!
[+] Correct offsets: Thread+B8 Links+448 Pid+440 Token+4B8
```

## TROUBLESHOOTING

Symlink creation fails with 0xC0000022 (ACCESS_DENIED):
- The system has received patches that block this specific symlink path
- Target Windows 10 1803-1903 for guaranteed success

Section creation fails with 0xC0000035 (STATUS_OBJECT_NAME_COLLISION):
- Normal behavior - the exploit will open the existing section

Defender blocks notepad.exe execution:
- The exploit chain works but the payload is detected
- Disable real-time protection for testing:
  Set-MpPreference -DisableRealtimeMonitoring $true

Winlogon crashes (system logs off):
- The shellcode offsets may be incorrect for your Windows build
- Run the brute forcer to discover correct offsets
- Reboot and try again - this is expected during tuning

No working offsets found by brute forcer:
- Your Windows build has significant EPROCESS structure changes
- CFG (Control Flow Guard) may be blocking the callback
- Use Windows 10 1903 VM for guaranteed execution

## TESTED ENVIRONMENTS

| Windows Version | Build | greenPLASMA_Final | Brute Forcer |
|----------------|-------|-------------------|---------------|
| Windows 10 1903 | 18362 | Full SYSTEM shell | Working offsets found |
| Windows 10 22H2 | 19045 | Symlink works | Offsets confirmed |
| Windows 11 24H2 | 26200 | Symlink works, no shell | No offsets found |

## RESEARCH FINDINGS

The brute forcer research revealed:
- Windows 10 builds (1803-22H2) maintain consistent EPROCESS offsets
- Windows 11 24H2 (Build 26200) has structural changes preventing token stealing
- CFG (Control Flow Guard) may block the callback on newer builds
- The symlink primitive (CVE-2022-37962) remains exploitable across all tested versions

## DISCLAIMER

This proof of concept is provided for educational and authorized security research purposes only. Unauthorized use against systems without explicit permission violates applicable laws. The Church of Malware and the contributors assume no liability for misuse.

The techniques demonstrated here are for understanding how object manager symlinks can be abused for privilege escalation. Use only in isolated lab environments with proper authorization.

## REFERENCES

- Original GreenPlasma Skeleton: Nightmare-Eclipse/GreenPlasma
- CVE-2022-37962: Windows CTF Protocol Elevation of Privilege
- Windows Shellcoding In-Depth: Jakeswiz (Church of Malware)
- Hades Gate: Church of Malware
- The Shellphone Sermon: JAKESWIZ
