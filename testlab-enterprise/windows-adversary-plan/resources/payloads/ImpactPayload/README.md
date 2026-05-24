# ImpactPayload

Single binary consolidating Phase 5 Step 1 impact chain (T1490 + T1489 + T1486) into one process execution. Replaces the 7-process sequence (`vssadmin.exe`, `sc.exe`, `powershell.exe`) with direct Windows API calls and evasion layers.

**Language:** C (with embedded `tiny-AES-c`)
**Target:** IIS01, runs as `NT AUTHORITY\SYSTEM` via dnscat2 cmd.exe shell
**Deployed as:** `CertMaint.exe` (matches campaign `Cert*` naming convention)
**Scope:** Operational actions only — backup, verification, and cleanup remain manual operator procedures.

---

## Actions

### 1. VSS Shadow Deletion (T1490)

COM API via `IVssBackupComponents::DeleteSnapshots`. Delete operation executes inside `vssvc.exe` through COM RPC. No `vssadmin.exe` process created.

VSS interface is loaded from `vssapi.dll` via `CreateVssBackupComponentsInternal` (internal export, not the public `CreateVssBackupComponents`). Context set to `VSS_CTX_ALL` (`0xFFFFFFFF`) to enumerate all shadow copy types. Each snapshot is deleted individually by ID via `IVssBackupComponents::DeleteSnapshots`.

### 2. Service Stop (T1489)

SCM API: `OpenSCManagerW` → `OpenServiceW` → `ControlService(SERVICE_CONTROL_STOP)`. Polls `QueryServiceStatus` until `SERVICE_STOPPED` (30-second timeout, 1-second intervals). No `sc.exe` process created.

### 3. Service Start (post-encryption)

Same SCM path, `StartServiceW`. Polls until `SERVICE_RUNNING`. No `sc.exe` process created.

### 4. AES-256-CBC File Encryption (T1486)

Embedded `tiny-AES-c`, statically compiled. No dependency on `bcrypt.dll` or `advapi32` crypto. File I/O via memory-mapped sections: `CreateFileMapping(PAGE_READWRITE, paddedSize)` → `MapViewOfFile(FILE_MAP_WRITE)` → encrypt in-place → `FlushViewOfFile`. PKCS7 padding applied to the final block before encryption (`memset(pView + origSize, padLen, padLen)`). No `powershell.exe` process created.

---

## Evasion — Phase 2

### Stack strings

All sensitive string literals are absent from PE `.rdata`. Instead, each is constructed byte-by-byte into a local stack buffer by a dedicated `ss_*` function. The compiler emits inline `mov` immediates in `.text` rather than static data references. Strings covered:

| `ss_*` function | String |
|---|---|
| `ss_vssapi_dll` | `vssapi.dll` (wide) |
| `ss_advapi32_dll` | `advapi32.dll` (wide) |
| `ss_CreateVssBC` | `CreateVssBackupComponentsInternal` (narrow) |
| `ss_VssFreeSnap` | `VssFreeSnapshotPropertiesInternal` (narrow) |
| `ss_OpenSCManagerW` | `OpenSCManagerW` (narrow) |
| `ss_OpenServiceW` | `OpenServiceW` (narrow) |
| `ss_ControlService` | `ControlService` (narrow) |
| `ss_StartServiceW` | `StartServiceW` (narrow) |
| `ss_CloseServiceHandle` | `CloseServiceHandle` (narrow) |
| `ss_QueryServiceStatus` | `QueryServiceStatus` (narrow) |
| `ss_arg_target` | `--target` (wide) |
| `ss_arg_service` | `--service` (wide) |
| `ss_arg_files` | `--files` (wide) |

### Thread pool execution

Each action (VSS delete, service stop, encrypt, service start) is submitted via `CreateThreadpoolWork` / `SubmitThreadpoolWork` and awaited with `WaitForThreadpoolWorkCallbacks`. Call stacks originate from `ntdll!TppWorkerThread` rather than `main()`. `run_work()` serializes execution: each work item is fully awaited before the next is submitted, preserving VSS → stop → encrypt → start order.

### Dynamic import — SCM API

`OpenSCManagerW`, `OpenServiceW`, `ControlService`, `StartServiceW`, `CloseServiceHandle`, and `QueryServiceStatus` are resolved at startup via `LoadLibraryW` (stack-string `advapi32.dll`) + `GetProcAddress` (stack-string function names) into `g_scm.*`. No SCM names appear in the IAT or `.rdata`.

`advapi32.lib` is not linked — it is absent from the build line. The module handle is not freed (process-lifetime).

**Resulting IAT:** `kernel32.dll` (file I/O, memory mapping, thread pool), `ole32.dll` (COM init for VSS). No `advapi32.dll` entries.

### Log message camouflage

All `printf` output uses maintenance-tool vocabulary. No string in the binary references encryption, shadow copies, or service names explicitly. Expected `strings` output profile matches a storage/certificate maintenance utility.

---

## VSS vtable indices

Derived from declaration order in `vsbackup.h` (Windows SDK 10.0.26100.0). IUnknown occupies slots 0–2.

| Constant | Index | Method |
|---|---|---|
| `IVBC_RELEASE` | 2 | `IUnknown::Release` |
| `IVBC_INITFORBACKUP` | 5 | `IVssBackupComponents::InitializeForBackup` |
| `IVBC_SETBACKUPSTATE` | 6 | `IVssBackupComponents::SetBackupState` |
| `IVBC_SETCONTEXT` | 35 | `IVssBackupComponents::SetContext` |
| `IVBC_DELETESNAPSHOTS` | 39 | `IVssBackupComponents::DeleteSnapshots` |
| `IVBC_QUERY` | 43 | `IVssBackupComponents::Query` |
| `IVEO_RELEASE` | 2 | `IUnknown::Release` (on IVssEnumObject) |
| `IVEO_NEXT` | 3 | `IVssEnumObject::Next` |

`SetBackupState` call args: `selectComponents=false, bootableState=true, backupType=VSS_BT_FULL(1), partialFile=false`. `SetContext` value: `(LONG)-1` = `VSS_CTX_ALL`.

---

## Key / IV

Hardcoded in `g_key[32]` and `g_iv[16]` as decimal byte arrays (no string literal).

| | ASCII |
|---|---|
| Key | `RansomGrp2025!@#$%^&*()_+={|}:;"` (32 bytes) |
| IV | `IIS01EncIV2025!@` (16 bytes) |

All file paths and service name are supplied via CLI — not embedded in the binary.

---

## Build

```bat
REM x64 Native Tools Command Prompt for VS
cl /O2 /MT /W4 impact.c aes.c /Fe:impact.exe /link ole32.lib
```

Or run `build.bat` from the same directory.

---

## CLI Usage

```
CertMaint.exe --target "C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA" --service MSSQL$SQLEXPRESS --files UploadPortalDB.mdf,UploadPortalDB_log.ldf
```

---

## Files

| File | Description |
|---|---|
| `impact.c` | Main source |
| `aes.c` | AES-256-CBC encrypt-only implementation (tiny-AES-c, public domain) |
| `aes.h` | AES header |
| `build.bat` | MSVC build command |
