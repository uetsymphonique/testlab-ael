# ImpactPayload

Single binary consolidating Phase 5 Step 1 impact chain (T1490 + T1489 + T1486) into one process execution. Replaces the current 7-process sequence (`vssadmin.exe`, `sc.exe`, `powershell.exe`) with direct Windows API calls.

**Language:** C (with embedded `tiny-AES-c`)
**Target:** IIS01, runs as `NT AUTHORITY\SYSTEM` via dnscat2 cmd.exe shell
**Scope:** Operational actions only — backup, verification, and cleanup remain manual operator procedures.

---

## Actions

### 1. VSS Shadow Deletion (T1490)

COM API via `IVssBackupComponents::DeleteSnapshots`. CoCreateInstance activates the VSS coordinator; the delete operation executes inside `vssvc.exe` through COM RPC. No `vssadmin.exe` process created.

### 2. Service Stop (T1489)

SCM API: `OpenSCManagerW` → `OpenServiceW` → `ControlService(SERVICE_CONTROL_STOP)`. Polls `QueryServiceStatus` until `SERVICE_STOPPED`. No `sc.exe` process created.

### 3. Service Start (post-encryption)

SCM API: `StartServiceW` on same service handle. Polls until `SERVICE_RUNNING`. No `sc.exe` process created.

### 4. AES-256-CBC File Encryption (T1486)

Embedded AES implementation (`tiny-AES-c`, statically compiled). No dependency on `bcrypt.dll` or `advapi32` crypto functions. File I/O through memory-mapped sections: `CreateFileMapping(SEC_COMMIT)` → `MapViewOfFile(FILE_MAP_WRITE)` → encrypt in-place → `FlushViewOfFile`. No `powershell.exe` process created.

Key and IV are hardcoded byte arrays (same values as current Phase 5). PKCS7 padding applied to final block.

---

## Development Phases

### Phase 1 — Functional consolidation

Build the binary with all 4 actions in sequence:

1. `CoCreateInstance(CLSID_VSSCoordinator)` → enumerate and delete all shadow copies
2. `ControlService(SERVICE_CONTROL_STOP)` on `MSSQL$SQLEXPRESS`, wait for stopped state
3. Memory-map each target file (`UploadPortalDB.mdf`, `UploadPortalDB_log.ldf`), AES-256-CBC encrypt in-place with embedded `tiny-AES-c`, PKCS7 pad final block
4. `StartServiceW` on `MSSQL$SQLEXPRESS`, wait for running state

Minimal console output: one status line per action (`[+] VSS deleted`, `[+] MSSQL stopped`, etc.) for operator confirmation. No encoded strings, no API hiding — plain Win32 calls. Validate on IIS01 before proceeding to Phase 2.

### Phase 2 — Defense evasion integration

After Phase 1 is tested and confirmed working, add evasion layers:

1. **Stack strings** — sensitive string literals (`MSSQL$SQLEXPRESS`, file paths, COM CLSIDs) constructed at runtime via `mov` instructions on the stack. No contiguous plaintext in the PE `.rdata` section.
2. **Thread pool execution** — each action (VSS delete, service stop, encrypt, service start) queued as a `CreateThreadpoolWork` / `SubmitThreadpoolWork` callback. Call stacks show `ntdll!TppWorkerThread` origin instead of `main()`.
3. **Import by ordinal** — SCM functions (`OpenSCManagerW`, `OpenServiceW`, `ControlService`, `StartServiceW`) imported from `advapi32.dll` by ordinal number. No API name strings in the IAT.

---

## CLI Usage (planned)

```
impact.exe --target "C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA" --service MSSQL$SQLEXPRESS --files UploadPortalDB.mdf,UploadPortalDB_log.ldf
```

All parameters provided via command line — no hardcoded paths in the binary (paths only in the dnscat2 command that launches it).
