# CWLHerpaderping - Code Flow Summary

This document summarizes the code flow of `CWLHerpaderping`, focusing on how the loader reads a PE payload, creates a ghost process via `NtCreateUserProcess` using the temp file as the image path, overwrites the backing file on disk before the thread runs, and spoofs process parameters so the ghost appears as `RuntimeBroker.exe`.

## Source Map

| Component | Path | Role |
|---|---|---|
| Main implant | `../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp` | Entry point, ETW patch, payload read/delete, herpaderping flow |
| Native declarations | `../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLInc.h` | NT types, PEB structures, function typedefs |
| API hashing | `../../resources/payloads/CWLHerpaderping/CWLHerpaderping/api_hash.h` | DJB2 hash constants for EAT-walk API resolution |
| Indirect syscall helpers | `../../resources/payloads/CWLHerpaderping/CWLHerpaderping/syscall.h` | Halo's Gate SSN resolution, syscall gadget, runtime stub builder |
| Stack spoofing | `../../resources/payloads/CWLHerpaderping/CWLHerpaderping/StackSpoof.cpp` | Fake return address inside a trusted module |
| Obfuscated strings | `../../resources/payloads/CWLHerpaderping/CWLHerpaderping/obfstr.h` | Compile-time XOR string obfuscation |

## High-Level Runtime Flow

```text
wmain()
  -> [#ifdef ENABLE_ETW_PATCH] PatchEtw()     <- T1562.006, conditional
  -> GetPayloadBuffer()
       -> GetFileType(STD_INPUT_HANDLE)
       -> MODE 1 (stdin pipe - T1620 Reflective Code Loading):
            -> ReadFile(stdin, 4-byte LE size header)
            -> VirtualAlloc(PAGE_READWRITE, size)
            -> ReadFile(stdin, payload bytes)
            -> NO DISK FILE (reflective)
       -> MODE 2 (file fallback - T1070.004 File Deletion):
            -> CreateFileW(PAYLOAD_PATH)
            -> ReadFile(payload bytes)
            -> DeleteFileW(PAYLOAD_PATH)        <- payload deleted before decode
            -> [#ifdef ENABLE_PAYLOAD_XOR] XOR decode in-place  <- T1027.013
  -> Herpaderping(payloadBuffer, payloadSize)
       -> InitSyscallPool() + INDIRECT_SYSCALL(NtCreateUserProcess) x1
       -> SealSyscallPool()                    <- stub page -> PAGE_EXECUTE_READ
       -> RtlCreateProcessParametersEx(RuntimeBroker.exe)  [RESOLVE_API]
       -> GetTempFileNameW(prefix "HD") -> hTemp
       -> WriteFile(payload -> hTemp) + FlushFileBuffers + CloseHandle
       -> GetNonJobParent()                    <- PPID spoof: svchost/wininit Session 0
       -> NtCreateUserProcess(ntImagePath, processParameters, PS_ATTRIBUTE_LIST)  [StackSpoof]
            -> creates process + suspended thread atomically
            -> image loaded from temp file; process parameters embedded from RtlCreateProcessParametersEx
       -> CreateFileW(hTemp, SHARE_READ|SHARE_DELETE) + SetFilePointer(0)
       -> WriteFile loop "Hello From CyberWarFare Labs\n" (herpaderping overwrite)
       -> CloseHandle(hTemp)
       -> ResumeThread(hThread)               <- Win32, not spoofed
       -> DeleteFileW(tempFile)               <- T1070.004 temp file deleted after resume
```

Core point: the payload is not injected with `WriteProcessMemory`. The payload enters the process image when `NtCreateUserProcess` maps the temp file at process creation time. The file is overwritten after the process exists but before the thread runs, so on-disk content does not match the in-memory image. `NtCreateUserProcess` creates both the process and its initial thread atomically — no separate `NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, or `NtCreateThreadEx` calls.

## Entry Point

`wmain()` in `CWLImplant.cpp`:

```text
[#ifdef ENABLE_ETW_PATCH] PatchEtw()
GetPayloadBuffer(payloadSize)
Herpaderping(payloadBuffer, payloadSize)
```

### Default Payload Path (Mode 2 only)

```text
C:\temp\payload64.exe
```

Overridden at build time via `/p:CustomPayloadPath="C:\\ProgramData\\CertCA.bin"` (used in emulation plan). Only used when stdin is not a pipe.

### Stdin Redirection (Mode 1)

When the binary is spawned with stdin pipe redirection (e.g., via Node.js `spawnSync` with `input` option), `GetFileType(STD_INPUT_HANDLE) == FILE_TYPE_PIPE` routes to reflective mode. `PAYLOAD_PATH` is never opened.

Payload format: 4-byte little-endian size header followed by raw PE bytes. Sanity check: 1 KB – 50 MB range.

## Stage 1 — Static Evasion Helpers

Two compile-time helpers reduce static signatures before any runtime behavior:

1. **`obfstr.h`** — `OBFSTR()` / `OBFWSTR()` XOR-obfuscate sensitive string literals at compile time. Strings such as `svchost.exe`, `wininit.exe`, `kernel32.dll`, `C:\Windows\System32\RuntimeBroker.exe`, and `C:\Windows\System32` are not present as plaintext literals. At call time each helper decrypts into a `thread_local` buffer.

2. **`api_hash.h`** — `RESOLVE_API(hNtdll, ApiName)` finds APIs without plaintext names at call sites. `GetNtdllBase()` walks the PEB in-process to locate the `ntdll` base, then parses the Export Address Table, hashes each export name with DJB2, and compares against `ApiHash::` constants. APIs resolved this way in the current codebase: `EtwEventWrite`, `RtlCreateProcessParametersEx`, `RtlInitUnicodeString`, `RtlImageNtHeader`, `NtReadVirtualMemory`.

   `NtCreateUserProcess` uses a separate path: `InitSyscallPool` + `INDIRECT_SYSCALL` (Halo's Gate SSN resolution), not `RESOLVE_API`.

   Scope note: `StackSpoof.cpp::FindReturnAddressGadget()` calls `GetModuleHandleA(moduleName)` with `OBFSTR("kernel32.dll")` at the call site; API hashing is for the ntdll path only.

## Stage 2 — ETW Patch (Conditional)

`PatchEtw()` is only compiled and called when the binary is built with `ENABLE_ETW_PATCH` (`/p:ETWPatch=1`). Without that flag the function does not exist and ETW suppression is skipped entirely.

When active, `PatchEtw()` resolves `ntdll!EtwEventWrite` via `RESOLVE_API`, changes page protection to `PAGE_EXECUTE_READWRITE`, and patches the first three bytes to:

```text
xor eax,eax; ret
```

This makes ETW writes in the loader process silently return success before any NT API is called, suppressing DC0021 (OS API Execution) telemetry for subsequent operations.

Artifacts to watch:

| Artifact | Meaning |
|---|---|
| Modified bytes at `ntdll!EtwEventWrite` | ETW tampering in loader process memory |
| `VirtualProtect` on `ntdll.dll` code region | Preparation for executable memory patching |

## Stage 3 — Payload Acquisition (Dual Mode)

`GetPayloadBuffer()` supports two loading modes selected at runtime.

### Mode 1: Reflective Loading via Stdin (T1620)

**Trigger:** `GetFileType(STD_INPUT_HANDLE) == FILE_TYPE_PIPE`

1. Read 4-byte LE size header from stdin via `ReadFile`.
2. Allocate buffer with `VirtualAlloc(PAGE_READWRITE, size)`.
3. Read payload bytes from stdin via `ReadFile`.
4. Return buffer; payload never touches disk.

### Mode 2: File-based Loading with Deletion (T1070.004)

**Trigger:** stdin is not a pipe (console or normal file handle)

1. Open `PAYLOAD_PATH` with `CreateFileW`.
2. Allocate buffer with `VirtualAlloc(PAGE_READWRITE)`.
3. Read payload into buffer with `ReadFile`.
4. Close handle.
5. `DeleteFileW(PAYLOAD_PATH)` — payload deleted before decode (T1070.004).
6. `[#ifdef ENABLE_PAYLOAD_XOR]` XOR decode in-place — `decoded[i] = buf[i] ^ ((0xA3 + i * 0x5B) & 0xFF)` (T1027.013).

**XOR decode detail (ENABLE_PAYLOAD_XOR only):**
- Encodes/decodes with the same position-dependent formula (self-inverse).
- First byte: `0x4D ('M') ^ 0xA3 = 0xEE` — on-disk file does not start with `MZ`.
- The file is deleted before decode runs, so no plaintext PE exists on disk at any point.
- Applies only to Mode 2; Mode 1 receives plain PE bytes from the pipe.

After either mode the loader holds the PE payload in a heap buffer.

## Stage 4 — Indirect Syscall Setup

Inside `Herpaderping()`, `InitSyscallPool(hNtdll)` and `INDIRECT_SYSCALL` build a stub for **one** NT API:

| API | Purpose |
|---|---|
| `NtCreateUserProcess` | Create ghost process + suspended thread atomically |

`syscall.h` performs three tasks for each stub:

1. Read the SSN from the ntdll stub bytes. If the stub is hooked (first bytes do not match the expected syscall pattern), Halo's Gate infers the SSN from neighboring stubs.
2. Locate a `syscall; ret` gadget inside the `.text` section of `ntdll`.
3. Build a runtime stub: `mov r10,rcx; mov eax,<SSN>; movabs r11,<gadget>; jmp r11`.

`SealSyscallPool()` flips the page containing the stub to `PAGE_EXECUTE_READ` immediately after, removing the RWX window.

All other APIs (`RtlCreateProcessParametersEx`, `RtlInitUnicodeString`, `RtlImageNtHeader`, `NtReadVirtualMemory`) are resolved via `RESOLVE_API` (DJB2 EAT walk), not indirect syscalls.

## Stage 5 — Process Parameters (Before Process Creation)

Before the ghost process is created, `Herpaderping()` builds the spoofed process parameters:

```text
ImagePathName = C:\Windows\System32\RuntimeBroker.exe
DllPath       = C:\Windows\System32
```

Flow:

1. `RtlInitUnicodeString()` on the target path and DLL directory strings (both from `OBFWSTR`).
2. `RtlCreateProcessParametersEx()` creates `RTL_USER_PROCESS_PARAMETERS` with `RTL_USER_PROC_PARAMS_NORMALIZED`.
3. Pointer stored in `processParameters` — passed directly to `NtCreateUserProcess`.

**Key difference from old implementation:** parameters are prepared locally and handed to `NtCreateUserProcess` as a parameter. There is no separate `NtAllocateVirtualMemory` + `NtWriteVirtualMemory` + `WriteProcessMemory` injection step.

## Stage 6 — Temp File Staging

The herpaderping trick requires a legitimate PE on disk before process creation:

1. `GetTempPathW()` gets `%TEMP%`.
2. `GetTempFileNameW(tempPath, L"HD", 0, tempFile)` creates a file with `HD` prefix.
3. `CreateFileW()` opens the temp file with `GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE`.
4. `WriteFile()` writes the full PE payload to the temp file.
5. `FlushFileBuffers(hTemp)` + `CloseHandle(hTemp)`.
6. Build NT path: `wsprintfW(ntImagePath, L"\\??\\%s", tempFile)`.

Artifacts to watch:

| Artifact | Meaning |
|---|---|
| `%TEMP%\HD*.tmp` created | Temp backing file with valid PE content |
| `FlushFileBuffers` on temp file before process creation | Ensures image is flushed before the NT loader maps it |

## Stage 7 — Parent Process Selection (PPID Spoof)

`GetNonJobParent()` enumerates processes with a ToolHelp snapshot and prioritizes:

1. `svchost.exe` in Session 0 (non-PPL, always accessible, reliable)
2. `wininit.exe` in Session 0 (fallback)
3. `GetCurrentProcess()` (no spoof)

```cpp
OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pid)
```

The returned handle is used as the `PS_ATTRIBUTE_PARENT_PROCESS` attribute in `NtCreateUserProcess`. The goal is to place the ghost in Session 0 under a well-known system process, avoiding IIS job-object or session constraints from the caller.

**Token note:** `NtCreateUserProcess` inherits the **calling process's** token by default (unlike `NtCreateProcessEx`, which inherited the spoofed parent's token). No separate `NtSetInformationProcess(ProcessAccessToken)` fixup is needed or present.

Artifacts to watch:

| Artifact | Meaning |
|---|---|
| `CreateToolhelp32Snapshot` + `Process32First/Next` | Process enumeration before spawning |
| `OpenProcess(PROCESS_CREATE_PROCESS)` into `svchost.exe` or `wininit.exe` | PPID spoof preparation |
| Child process parent resolves to `svchost.exe` / `wininit.exe` | Parent lineage does not reflect the real caller |

## Stage 8 — Ghost Process Creation

`NtCreateUserProcess` is the single injection-critical call. It is invoked through an indirect syscall stub wrapped by `StackSpoofer`:

```cpp
StackSpoofer spoofer(OBFSTR("kernel32.dll"));
spoofer.Activate();
status = pNtCreateUserProcess(&hProcess, &hThread,
                              PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
                              NULL, NULL,
                              0,
                              THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
                              processParameters,
                              &createInfo,
                              &attrList);
spoofer.Deactivate();
```

`PS_ATTRIBUTE_LIST` carries two entries:

| Attribute | Value |
|---|---|
| `PS_ATTRIBUTE_IMAGE_NAME` | NT path of `HD*.tmp` (the temp file with the PE payload) |
| `PS_ATTRIBUTE_PARENT_PROCESS` | Handle to `svchost.exe` / `wininit.exe` (PPID spoof) |

`NtCreateUserProcess` maps the PE from the temp file, applies the process parameters, and creates the initial thread in suspended state — all atomically. The thread will not run until `ResumeThread`.

`StackSpoofer::Activate()` plants a fake return address inside `kernel32.dll` on the stack before the syscall. EDR stack-walk inspection sees the call origin as `kernel32.dll` instead of the stub page. `Deactivate()` restores the real return address after the syscall returns.

Artifacts to watch:

| Artifact | Meaning |
|---|---|
| `NtCreateUserProcess` with `PS_ATTRIBUTE_IMAGE_NAME` = `HD*.tmp` | Process image loaded from a temp file, not a normal executable path |
| `PS_ATTRIBUTE_PARENT_PROCESS` pointing to `svchost.exe` / `wininit.exe` | PPID spoofed at creation time |
| Stack return address in `kernel32.dll` during syscall | Stack spoofing indicator |

## Stage 9 — File Herpaderping (Overwrite)

After the ghost process exists but before the thread runs, the code overwrites the temp file with decoy content:

1. `CreateFileW(tempFile, GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_DELETE, ...)` — reopens with share flags.
2. `SetFilePointer(hTemp, 0, 0, FILE_BEGIN)`.
3. Loop `WriteFile()` with `L"Hello From CyberWarFare Labs\n"` until `bufferSize (0x1000)` is consumed.
4. `CloseHandle(hTemp)`.

Because the process was created from the file before the overwrite, the mapped image in memory still contains the original PE payload. The backing file on disk now contains junk — disk content no longer matches the in-memory image. This is the process herpaderping effect.

If the file cannot be reopened (e.g., the OS holds an exclusive section lock), the overwrite is skipped silently with a debug log; the ghost process still runs.

Artifacts to watch:

| Artifact | Meaning |
|---|---|
| `%TEMP%\HD*.tmp` overwritten after `NtCreateUserProcess` | Backing file replaced with junk |
| Disk image differs from process memory image | Process herpaderping indicator |

## Stage 10 — Resume Thread and Cleanup

```text
ResumeThread(hThread)    <- Win32, not stack-spoofed
DeleteFileW(tempFile)    <- marks HD*.tmp for deletion (not immediate)
```

`ResumeThread` is a standard Win32 call and is not wrapped by `StackSpoofer`. After the thread is resumed, `DeleteFileW(tempFile)` is called on the overwritten temp file.

**Important:** `DeleteFileW` calls `NtSetInformationFile(FileDispositionInformation, DeleteFile=TRUE)` internally. Windows returns `STATUS_CANNOT_DELETE` (`ERROR_ACCESS_DENIED`) for any file that has an active `SEC_IMAGE` image section — the code does not check this return value, so the failure is silent.

The image section backing `HD*.tmp` is created internally by `NtCreateUserProcess`. Killing the ghost process terminates threads and cleans up VADs, but the **EPROCESS kernel object** stays alive until every open handle to the process is closed. Security tools (Sysmon, EDR, Task Manager) typically hold open handles to processes for monitoring, which keeps EPROCESS alive, which keeps the image section alive, which keeps `DeleteFileW` failing.

Practical result: `HD*.tmp` is a **persistent on-disk IOC** that remains until:
1. The ghost process is killed, **and**
2. All handles to the process object are closed (including those held by security tools).

To force deletion, `FileDispositionInformationEx` with `FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK` is required — standard `DeleteFileW` cannot do it while a `SEC_IMAGE` section exists.

Artifacts to watch:

| Artifact | Meaning |
|---|---|
| `ResumeThread` on the ghost process thread | Thread activation after file overwrite |
| `HD*.tmp` persists on disk even after ghost process is killed | `DeleteFileW` fails silently; image section keeps file pinned until all process handles close |
| `HD*.tmp` content is junk (`Hello From CyberWarFare Labs`) | File was overwritten but never deleted; persistent herpaderping indicator |

## Stack Spoofing Flow

`StackSpoofer` is used around **one** call in the current implementation.

1. Constructor captures `_AddressOfReturnAddress()` (return-address slot on the stack).
2. `FindReturnAddressGadget(OBFSTR("kernel32.dll"))` finds a `ret` gadget inside a trusted module.
3. `Activate()` overwrites the return-address slot with the gadget address.
4. The indirect syscall (`NtCreateUserProcess`) executes; EDR stack walk sees the call chain terminating in `kernel32.dll`.
5. `Deactivate()` restores the original return address.

| Call | Stack-spoofed? |
|---|---|
| `NtCreateUserProcess` | Yes |
| `ResumeThread` | No |
| All `RESOLVE_API` calls | No |

## Detection-Relevant Code Paths

| Behavior | Code path | Observable artifact |
|---|---|---|
| ETW tampering (conditional) | `wmain()` -> `PatchEtw()` (`#ifdef ENABLE_ETW_PATCH`) | `ntdll!EtwEventWrite` patched to `xor eax,eax; ret`; `VirtualProtect` on ntdll code page |
| Reflective payload load (Mode 1) | `GetPayloadBuffer()` stdin detection | `GetFileType(STD_INPUT_HANDLE) == FILE_TYPE_PIPE`; payload read from stdin; no disk artifact |
| File-based payload load (Mode 2) | `GetPayloadBuffer()` file fallback | `PAYLOAD_PATH` read then deleted via `DeleteFileW` |
| XOR payload decode (Mode 2, conditional) | `#ifdef ENABLE_PAYLOAD_XOR` in `GetPayloadBuffer()` | On-disk file first byte `0xEE`, not `MZ`; in-memory buffer becomes valid PE after decode |
| Temp PE staging | `Herpaderping()` -> `GetTempFileNameW` / `WriteFile` | `%TEMP%\HD*.tmp` created with PE content |
| PPID spoof candidate search | `GetNonJobParent()` | `CreateToolhelp32Snapshot` + `Process32First/Next` + `OpenProcess(PROCESS_CREATE_PROCESS)` on Session 0 process |
| Ghost process creation | `NtCreateUserProcess(ntImagePath, processParameters, attrList)` | Process image from `HD*.tmp`; PPID = `svchost.exe` / `wininit.exe`; token = caller token (no fixup) |
| Stack spoofing | `StackSpoofer::Activate/Deactivate` around `NtCreateUserProcess` | Return address in `kernel32.dll` during syscall |
| File overwrite after process creation | `CreateFileW(SHARE_READ|SHARE_DELETE)` + `WriteFile` loop | `HD*.tmp` content overwritten with `Hello From CyberWarFare Labs` before thread starts |
| Thread resume | `ResumeThread(hThread)` | Ghost thread activated; process begins executing payload from in-memory image |
| Temp file deletion | `DeleteFileW(tempFile)` after `ResumeThread` | `HD*.tmp` disappears seconds after creation; disk image no longer present |
| PEB/process parameter spoof | `RtlCreateProcessParametersEx` passed to `NtCreateUserProcess` | `ProcessParameters.ImagePathName` claims `RuntimeBroker.exe`; actual image from temp file |
| String obfuscation | `OBFSTR()` / `OBFWSTR()` at call sites | Sensitive strings not present as plaintext in binary |
| API hash resolution | `GetNtdllBase()` -> `RESOLVE_API()` | ntdll APIs resolved by PEB walk + DJB2 EAT hash; no `GetProcAddress("ApiName")` |
| Indirect syscall | `InitSyscallPool` + `INDIRECT_SYSCALL(NtCreateUserProcess)` | Syscall originates from `ntdll` gadget, not the stub page or normal import path |

## Reading Order

1. `CWLImplant.cpp`: read `wmain()`, `GetPayloadBuffer()`, then `Herpaderping()` in order.
2. `obfstr.h`: understand compile-time XOR string obfuscation.
3. `api_hash.h`: understand PEB walk and DJB2 EAT hash resolution.
4. `syscall.h`: understand how the single `NtCreateUserProcess` indirect syscall stub is built.
5. `StackSpoof.cpp`: understand how the fake return address is placed and restored.
6. `CWLInc.h`: consult NT structure typedefs (`PS_ATTRIBUTE_LIST`, `PS_CREATE_INFO`, `RTL_USER_PROCESS_PARAMETERS`) when call signatures are unclear.

