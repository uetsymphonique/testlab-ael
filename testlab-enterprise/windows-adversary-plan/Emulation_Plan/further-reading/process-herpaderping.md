# CWLHerpaderping - Code Flow Summary

This document summarizes the code flow of `CWLHerpaderping`, focusing on how the loader reads a PE payload, creates a process from a `SEC_IMAGE` section, overwrites the backing file on disk, spoofs process metadata, and starts a thread at the payload entry point.

## Source Map

| Component | Path | Role |
|---|---|---|
| Main implant | `../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp` | Entry point, ETW patch, payload read/delete, herpaderping flow |
| Native declarations | `../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLInc.h` | NT types, PEB structures, function typedefs |
| API hashing | `../../resources/payloads/CWLHerpaderping/CWLHerpaderping/api_hash.h` | Hash constants for API resolution |
| Indirect syscall helpers | `../../resources/payloads/CWLHerpaderping/CWLHerpaderping/syscall.h` | Halo's Gate SSN resolution, syscall gadget, runtime stubs |
| Stack spoofing | `../../resources/payloads/CWLHerpaderping/CWLHerpaderping/StackSpoof.cpp` | Fake return address inside a trusted module |
| Obfuscated strings | `../../resources/payloads/CWLHerpaderping/CWLHerpaderping/obfstr.h` | Compile-time string obfuscation |

## High-Level Runtime Flow

```text
main()
  -> PatchEtw()
  -> GetPayloadBuffer()
       -> CreateFileW(PAYLOAD_PATH)
       -> ReadFile(payload bytes)
       -> DeleteFileW(PAYLOAD_PATH)
  -> Herpaderping(payloadBuffer, payloadSize)
       -> InitSyscallPool()
       -> build indirect syscall stubs
       -> create temp file
       -> write payload bytes to temp file
       -> NtCreateSection(SEC_IMAGE, temp file)
       -> choose spoofed parent process
       -> NtCreateProcessEx(section, parent)
       -> duplicate caller token into ghost process
       -> calculate payload entry point
       -> overwrite temp file with junk
       -> build spoofed process parameters
       -> write process parameters into remote process
       -> patch remote PEB ProcessParameters pointer
       -> NtCreateThreadEx(entryPoint)
```

Core point: the payload is not written into the remote process with `WriteProcessMemory`. The payload enters the process through the image section created by `NtCreateSection(..., SEC_IMAGE, hTemp)`. Later `NtAllocateVirtualMemory` and `NtWriteVirtualMemory` calls are used for process parameters and PEB spoofing, not payload-byte injection.

## Entry Point

`main()` in `CWLImplant.cpp` is short:

```text
PatchEtw()
GetPayloadBuffer(payloadSize)
Herpaderping(payloadBuffer, payloadSize)
```

The default `PAYLOAD_PATH` is:

```text
C:\temp\payload64.exe
```

This path can be overridden at build time with a preprocessor definition. The payload is expected to be an x64 PE with a normal entry point.

## Stage 1 - Static Evasion Helpers

Before the runtime flow begins, the code uses two static evasion helpers:

1. `obfstr.h` provides `OBFSTR()` and `OBFWSTR()` to XOR-obfuscate string literals at compile time. Sensitive strings such as `svchost.exe`, `wininit.exe`, `kernel32.dll`, `C:\Windows\System32\RuntimeBroker.exe`, and `C:\Windows\System32` are not used directly as plaintext literals at call sites. When needed, the helper decrypts them into a `thread_local` buffer and returns a pointer to the caller.
2. `api_hash.h` replaces `GetProcAddress("ApiName")`-style resolution for ntdll APIs. The code finds the `ntdll` base through a PEB walk (`GetNtdllBase()`), parses the Export Address Table, hashes each export name with DJB2, and compares it with constants in `ApiHash::`. `RESOLVE_API(hNtdll, NtCreateSection)` returns a function pointer without storing plaintext API names at the source call site.

APIs resolved by hash include `EtwEventWrite`, `NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`, `NtQueryInformationProcess`, `NtSetInformationProcess`, `RtlCreateProcessParametersEx`, `RtlInitUnicodeString`, `RtlImageNtHeader`, and `NtReadVirtualMemory`.

Scope note: `StackSpoof.cpp::FindReturnAddressGadget()` still calls `GetModuleHandleA(moduleName)` to find a trusted module, but the call site passes `OBFSTR("kernel32.dll")`; API hashing primarily applies to the ntdll API resolution path.

## Stage 2 - ETW Patch

`PatchEtw()` resolves `ntdll!EtwEventWrite`, changes page protection to writable, and patches the first three bytes to:

```text
xor eax,eax; ret
```

The goal is to make the caller process return fake success for internal ETW writes before sensitive NT APIs are called. This defense-evasion step happens before the full herpaderping flow.

Artifacts to watch:

| Artifact | Meaning |
|---|---|
| Modified bytes at `ntdll!EtwEventWrite` | ETW tampering in loader process memory |
| `VirtualProtect` on an `ntdll.dll` code region | Preparation for executable memory patching |

## Stage 3 - Read and Remove Payload

`GetPayloadBuffer()`:

1. Opens `PAYLOAD_PATH` with `CreateFileW`.
2. Gets the file size.
3. Allocates heap memory with `VirtualAlloc(PAGE_READWRITE)`.
4. Reads the payload into memory with `ReadFile`.
5. Closes the handle.
6. Deletes the original payload with `DeleteFileW(PAYLOAD_PATH)`.

After this step, the loader keeps the PE payload in a heap buffer; the original payload file is removed to reduce disk footprint.

## Stage 4 - Indirect Syscall Setup

Inside `Herpaderping()`, the code calls `InitSyscallPool(hNtdll)` and creates stubs for five sensitive NT APIs:

| API | Purpose |
|---|---|
| `NtCreateSection` | Create a `SEC_IMAGE` section from the temp file |
| `NtCreateProcessEx` | Create a process from the section handle |
| `NtAllocateVirtualMemory` | Allocate memory in the ghost process for process parameters |
| `NtWriteVirtualMemory` | Write process parameters into the ghost process |
| `NtCreateThreadEx` | Start a thread at the payload entry point |

`syscall.h` performs three tasks:

1. Finds the SSN directly from the ntdll stub; if the stub is hooked, it uses Halo's Gate to infer the SSN from neighboring stubs.
2. Finds a `syscall; ret` gadget in the `.text` section of `ntdll`.
3. Builds a runtime stub shaped like `mov r10, rcx; mov eax, <SSN>; movabs r11, <gadget>; jmp r11`.

After the stubs are created, `SealSyscallPool()` changes the page containing the stubs to `PAGE_EXECUTE_READ`, avoiding a long-lived RWX page.

## Stage 5 - Temp File and SEC_IMAGE Section

The herpaderping flow starts with a temp file:

1. `GetTempPathW()` gets `%TEMP%`.
2. `GetTempFileNameW(tempPath, L"HD", ...)` creates a file with the `HD` prefix.
3. `CreateFileW()` opens the temp file.
4. `WriteFile()` writes the PE payload bytes to the temp file.
5. `NtCreateSection(..., PAGE_READONLY, SEC_IMAGE, hTemp)` creates an image section from the file handle.

`NtCreateSection` is called through an indirect syscall and wrapped by `StackSpoofer`.

Artifacts to watch:

| Artifact | Meaning |
|---|---|
| `%TEMP%\HD*.tmp` created | Initial backing file containing the PE payload |
| `NtCreateSection` with `SEC_IMAGE` on a temp file | Process image is mapped from a section instead of a normal executable path |

## Stage 6 - Parent Process Selection

`GetNonJobParent()` enumerates processes with a ToolHelp snapshot and prioritizes:

1. `svchost.exe` in Session 0
2. `wininit.exe` in Session 0
3. fallback to `GetCurrentProcess()`

The code opens the parent with `PROCESS_CREATE_PROCESS`. This parent handle is passed into `NtCreateProcessEx`. The goal is to create the ghost process under a Session 0 parent and avoid caller-side job-object or session constraints.

Artifacts to watch:

| Artifact | Meaning |
|---|---|
| `CreateToolhelp32Snapshot` + `Process32First/Next` | Process enumeration before spawning |
| `OpenProcess(PROCESS_CREATE_PROCESS)` into `svchost.exe` or `wininit.exe` | Preparation for PPID spoofing |
| Child process parent is `svchost.exe` or `wininit.exe` | Parent lineage does not reflect the real caller |

## Stage 7 - Ghost Process Creation and Token Fixup

`NtCreateProcessEx()` creates a process from `hSection`, not from an executable path. Because the parent is `svchost.exe` or `wininit.exe`, the new process may inherit the parent token. The code fixes that with token reassignment:

1. Resolve `NtSetInformationProcess`.
2. `OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY)`.
3. `DuplicateTokenEx(..., TokenPrimary)`.
4. Call `NtSetInformationProcess(hProcess, ProcessAccessToken=9, PROCESS_ACCESS_TOKEN)`.

Expected result: the ghost process keeps the spoofed parent/session, but its token is changed back to the caller token.

## Stage 8 - Entry Point Resolution

`GetEntryPoint()`:

1. Resolves `RtlImageNtHeader`.
2. Resolves `NtReadVirtualMemory`.
3. Reads the remote PEB with `NtReadVirtualMemory`.
4. Gets `AddressOfEntryPoint` from the local payload PE buffer.
5. Adds `AddressOfEntryPoint` to `ImageBaseAddress` from the remote PEB.

The final entry point is the thread start address for `NtCreateThreadEx`.

## Stage 9 - File Herpaderping

After the section and process are created, the code returns to the temp file:

1. `SetFilePointer(hTemp, 0, FILE_BEGIN)`.
2. Set `bufferSize = 0x1000`.
3. Loop `WriteFile()` with the string `Hello From CyberWarFare Labs\n` at the beginning of the file.

Because the process was created from the image section before the file was overwritten, the memory image still contains the original PE payload while the backing file on disk no longer matches the running image.

Artifacts to watch:

| Artifact | Meaning |
|---|---|
| `%TEMP%\HD*.tmp` overwritten after `NtCreateProcessEx` | Backing file is no longer the original PE |
| Disk image differs from memory image | Process herpaderping indicator |

## Stage 10 - Process Parameters Spoofing

The code creates spoofed process parameters with:

```text
ImagePathName = C:\Windows\System32\RuntimeBroker.exe
DllPath       = C:\Windows\System32
```

Flow:

1. `RtlInitUnicodeString()` for the target path and DLL directory.
2. `RtlCreateProcessParametersEx()` creates `RTL_USER_PROCESS_PARAMETERS`.
3. `NtAllocateVirtualMemory()` allocates memory in the ghost process.
4. `NtWriteVirtualMemory()` writes the process parameters structure into the remote process.
5. `WriteProcessMemory()` patches `remotePEB->ProcessParameters` to point to the new structure.

`NtAllocateVirtualMemory` and `NtWriteVirtualMemory` here serve PEB command-line/image-path spoofing. Payload execution was already determined by the section created earlier.

Artifacts to watch:

| Artifact | Meaning |
|---|---|
| PEB `ProcessParameters.ImagePathName` is `RuntimeBroker.exe` | Process metadata is spoofed |
| Process memory image does not match `RuntimeBroker.exe` | Mismatch between PEB/path and mapped image |
| `WriteProcessMemory` into PEB/process-parameters memory | Remote process metadata patch |

## Stage 11 - Start Payload

Finally, the code calls:

```text
NtCreateThreadEx(hProcess, entryPoint)
```

The thread start address is the entry point calculated from the original PE payload. This call also goes through an indirect syscall and is wrapped by `StackSpoofer`.

After the thread is created, the loader closes the temp file handle and returns success.

## Stack Spoofing Flow

`StackSpoofer` is used around important indirect syscalls.

1. The constructor obtains the current return-address location with `_AddressOfReturnAddress()`.
2. `FindReturnAddressGadget("kernel32.dll")` finds a return/epilogue gadget inside a trusted module.
3. `Activate()` replaces the return address on the stack with the gadget inside `kernel32.dll`.
4. The indirect syscall runs.
5. `Deactivate()` restores the original return address.

Wrapped calls:

| Call | Purpose |
|---|---|
| `NtCreateSection` | Hide call origin during section creation |
| `NtCreateProcessEx` | Hide call origin during ghost process creation |
| `NtAllocateVirtualMemory` | Hide call origin during remote parameter allocation |
| `NtWriteVirtualMemory` | Hide call origin during remote parameter writing |
| `NtCreateThreadEx` | Hide call origin during payload start |

`WriteProcessMemory()` is used to patch the PEB pointer and is not wrapped by `StackSpoofer`.

## Detection-Relevant Code Paths

| Behavior | Code path | Observable artifact |
|---|---|---|
| ETW tampering | `main()` -> `PatchEtw()` | `ntdll!EtwEventWrite` patched to immediate success |
| Payload read/delete | `GetPayloadBuffer()` | `PAYLOAD_PATH` read then deleted |
| Temp PE staging | `Herpaderping()` -> `GetTempFileNameW` / `WriteFile` | `%TEMP%\HD*.tmp` created with PE content |
| Image section creation | `NtCreateSection(..., SEC_IMAGE, hTemp)` | Image section backed by temp file |
| PPID spoof candidate search | `GetNonJobParent()` | Process enumeration and handle open to Session 0 process |
| Ghost process creation | `NtCreateProcessEx(section, parent)` | Process created from section, parent appears as `svchost.exe` or `wininit.exe` |
| Token reassignment | `NtSetInformationProcess(ProcessAccessToken)` | New process token changed to caller token |
| File overwrite after section map | `SetFilePointer` + `WriteFile` loop | `%TEMP%\HD*.tmp` content overwritten with junk |
| PEB/process parameter spoof | `RtlCreateProcessParametersEx` -> `NtWriteVirtualMemory` -> `WriteProcessMemory` | Image path/command metadata claims `RuntimeBroker.exe` |
| Payload thread start | `NtCreateThreadEx(entryPoint)` | Thread starts at payload PE entry point inside ghost process |
| String obfuscation | `OBFSTR()` / `OBFWSTR()` | Sensitive process/module/path literals are XOR-obfuscated at compile time |
| API hash resolution | `GetNtdllBase()` -> `RESOLVE_API()` | ntdll APIs resolved by PEB walk and DJB2 EAT hash lookup |
| Indirect syscall use | `syscall.h` stubs | Syscalls originate through an `ntdll` gadget, not the normal import call path |
| Stack spoofing | `StackSpoofer::Activate/Deactivate` | Stack return address points into `kernel32.dll` during sensitive calls |

## Reading Order

1. `CWLImplant.cpp`: read `main()`, `GetPayloadBuffer()`, then `Herpaderping()`.
2. `obfstr.h`: understand compile-time XOR string obfuscation.
3. `api_hash.h`: understand PEB walk and DJB2 EAT hash resolution.
4. `syscall.h`: understand how the five indirect syscall stubs are built.
5. `StackSpoof.cpp`: understand how the fake return address is placed and restored.
6. `CWLInc.h`: consult typedefs only when an NT structure/function signature is unclear.

## ATT&CK-Relevant Behaviors

| Behavior | Likely ATT&CK mapping |
|---|---|
| Compile-time XOR obfuscation of sensitive strings | `T1027.002` Obfuscated Files or Information: Software Packing |
| PEB/EAT hash-based API resolution | `T1027.007` Obfuscated Files or Information: Dynamic API Resolution |
| Process created from manipulated image section | `T1055` Process Injection / process herpaderping-style injection |
| ETW patching | `T1562.006` Impair Defenses: Indicator Blocking |
| Indirect native API/syscall execution | `T1106` Native API |
| Parent process spoofing | `T1134` Access Token Manipulation / defense evasion context, depending scenario mapping |
| Payload file deletion and temp overwrite | `T1070.004` File Deletion, if modeled as a distinct observable event |
| RuntimeBroker process parameter spoofing | `T1036.005` Masquerading: Match Legitimate Name or Location, if detection criteria focuses on process metadata mismatch |
| PEB / process argument spoofing | `T1564.010` Hide Artifacts: Process Argument Spoofing |
