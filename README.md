# THE CHURCH OF MALWARE PRESENTS 

# Green Plasma CTF — Proof of Concept

This repository contains a fully functional proof of concept (PoC) for the GreenPlasma privilege escalation chain, originally released as a stripped skeleton by [Nightmare-Eclipse](https://github.com/Nightmare-Eclipse/GreenPlasma). The original repository deliberately withheld the code required to achieve a full SYSTEM shell, presenting a challenge for CTF participants[reference:0]. This PoC completes that challenge.

The exploit combines two vulnerabilities: an object manager symlink redirection in the Windows CTF protocol (CVE-2022-37962) and a registry symlink type confusion in the Cloud Files Mini Filter driver (CVE-2020-17103). The resulting chain elevates an unprivileged user to `NT AUTHORITY\SYSTEM`.

## How It Works

The exploit is divided into several distinct phases:

1.  **Hades Gate — direct syscall stubs**  
    To avoid userland EDR hooks on the setup path, the exploit walks the Process Environment Block (PEB) to locate `ntdll.dll`, parses its export table, extracts the syscall numbers (SSNs) for the required `Nt*` functions, and constructs fresh `mov eax, SSN; syscall; ret` stubs. All kernel‑mode object operations are then performed via these stubs, bypassing any hooks placed on `ntdll.dll` functions.

2.  **Object manager symlink hijack**  
    An NT object manager symbolic link is created from `\Sessions\{n}\BaseNamedObjects\CTF.AsmListCache.FMPWinlogon{n}` to a dummy section named `\BaseNamedObjects\CTFMON_DEAD`. When `conhost.exe` is launched with the `runas` verb, the UAC elevation flow causes `winlogon.exe` (running as SYSTEM) to create the section at the redirected path. This grants our process a handle to a SYSTEM‑owned shared memory section.

3.  **Shellcode planting**  
    The obtained section is mapped as read‑write in our process. A crafted FMP callback structure is placed at offset `0x00` with a callback pointer at offset `0x08` that points to self‑contained token‑stealing shellcode at offset `0x100`. The shellcode is built with the **Jakeswiz** methodology — it uses the PEB to resolve `WinExec` at runtime, walks the `EPROCESS` linked list, copies the SYSTEM token to the current process, and launches a PowerShell instance as SYSTEM.

4.  **Registry symlink + kernel callback**  
    A registry symbolic link is created from the `BlockedApps` key to the system policies key. Calling `CfAbortOperation` triggers `cldflt!HsmOsBlockPlaceholderAccess` (CVE-2020-17103). The driver follows the symlink, misinterprets a `REG_DWORD` value as a pointer, and dereferences an address that lands in our mapped section. It then reads the crafted FMP callback pointer and executes the shellcode in the context of `winlogon.exe` (SYSTEM).

## Why It Works

The exploit relies on two vulnerabilities:

- **CVE-2022-37962** (Windows CTF protocol elevation of privilege) — the ability to redirect an object manager path used by the CTF protocol, forcing a SYSTEM process to create a shared section at a user‑controlled location[reference:1].
- **CVE-2020-17103** (Windows Cloud Files Mini Filter Driver type confusion) — a registry symlink attack that causes `cldflt.sys` to misinterpret a `REG_DWORD` as a pointer and dereference it, leading to arbitrary code execution in kernel mode[reference:2][reference:3]. This vulnerability was initially reported by James Forshaw of Google Project Zero; despite Microsoft’s claim that it was patched in December 2020, the same issue remains exploitable in current builds of Windows 10 and 11[reference:4].

The shellcode is position‑independent and follows the **Jakeswiz** methodology. Instead of hardcoding addresses or relying on import tables, it dynamically resolves all required functions by walking the PEB, locating `kernel32.dll`, and parsing its export table — exactly as described in the *Windows Shellcoding In‑Depth* guide[reference:5].

## Credit and Prior Work

This PoC would not exist without three independent research threads:

1.  **Nightmare-Eclipse (Chaotic Eclipse)** – The original GreenPlasma skeleton proved that the object manager redirection was possible. By stripping the final shellcode, it turned the bug into a CTF challenge[reference:6]. The complementary research into the still‑unpatched state of CVE-2020-17103 (released as MiniPlasma) confirmed that the registry symlink attack remained viable[reference:7].

2.  **Jakeswiz (0xXyc)** – The *Holy Trinity of Research* laid the foundation for self‑contained Windows shellcode:
    - The **Fukahi Tekiō** encoder for polymorphic payload generation.
    - The **Windows Shellcoding In‑Depth** guide, which teaches PEB walking and export table parsing to resolve Win32 functions at runtime[reference:8][reference:9].
    - The **ASLR & NX/DEP Bypass** guide for understanding modern memory protections.

    The Church of Malware has canonised this work in the article *Our Blessed Connection — The Shellphone Sermon*, which describes how Jakeswiz’s research fills the “deep, dark silence where public Windows shellcode documentation should be”[reference:10].

3.  **Hades Gate (Church of Malware)** – Hades Gate extends Jakeswiz’s methodology one step further. Instead of stopping at resolving Win32 functions from `kernel32.dll`, it points the same PEB walker at `ntdll.dll`, extracts the syscall numbers from the unhooked stubs, and constructs direct `syscall` instructions. This bypasses the userland hooks that every EDR places on `ntdll.dll` while keeping the same foundational technique[reference:11][reference:12]. The *Church of Malware* explicitly states that Hades Gate “exists because Jake published the foundation publicly. It is an arm of his work, not a replacement for it”[reference:13].

All three lines of research are credited and combined in this PoC.

## Build Instructions

The PoC is a single C++ file that can be compiled with **MinGW-w64**. No external libraries are required.

### Prerequisites

- MinGW-w64 (x86_64 target)
- Windows SDK headers (provided by MinGW-w64)

### Compilation

```bash
x86_64-w64-mingw32-g++ -O2 -static GreenPlasma_V2.cpp -o GreenPlasma.exe -lntdll -ladvapi32
```

The resulting GreenPlasma.exe is a standalone binary that does not depend on any external DLLs other than the system libraries.

Usage

Run the exploit from an unprivileged command prompt:

```cmd
GreenPlasma.exe
```

If successful, a hidden PowerShell instance is launched with NT AUTHORITY\SYSTEM privileges. The exploit will print status messages to the console and, after completion, report whether an elevated PowerShell process was detected.

Requirements

· Windows 10 (21H2–22H2) or Windows 11 (21H2–22H2) – 23H2 may work with fallbacks but is not guaranteed.
· The system must not have the December 2020 patch for CVE-2020-17103 re‑applied (Microsoft’s patch was incomplete and has been rolled back in some builds).
· The exploit must be run from a user account (no administrator privileges required).

Repository Structure

File Description
GreenPlasma_V2.cpp Full exploit source code.
README.md This file.

Disclaimer

This PoC is provided for educational and authorised security research purposes only. Unauthorised use against systems without explicit permission may violate applicable laws. The author assumes no liability for misuse.

References

· Original GreenPlasma (skeleton) – Nightmare-Eclipse
· MiniPlasma – Nightmare-Eclipse
· Our Blessed Connection — The Shellphone Sermon (Church of Malware)
· Hades Gate – Church of Malware
· Windows Shellcoding In‑Depth – Jakeswiz (Church of Malware)

```
```
