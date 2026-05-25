# Noise Behavior — IIS AppPool Escalation Path

## Overview

Noise behaviors are natural-looking admin activities run **concurrently** on the same
hosts as the attack, so detection products must distinguish legitimate admin telemetry
from attacker telemetry by process context and lineage — not by host name alone.

A second operator (noise operator) executes these blocks on **IIS01** and **DC01** as
`TESTLAB\Administrator` while the red team operator drives the main attack chain on
those same hosts.

Phase 1 (Initial Access & C2) has no noise block — the techniques involved (web exploit,
reflective PE loading, named-pipe privilege escalation, process masquerading) are too
anomalous to have realistic benign analogs. Noise starts from Phase 2 onward.

### Lab Topology

| Role | Hostname | IP | Noise User |
| ---- | -------- | --- | ---------- |
| Domain Controller | DC01 | 10.12.10.10 | TESTLAB\Administrator |
| IIS Server | IIS01 | 10.12.10.20 | TESTLAB\Administrator |

**Domain:** `testlab.local` / `TESTLAB`

### Access Method

The noise operator connects to each host via RDP:

```cmd
mstsc /v:10.12.10.20   # IIS01
mstsc /v:10.12.10.10   # DC01
```

Log in as `TESTLAB\Administrator`. All noise procedures below are run inside the RDP
session unless stated otherwise.

---

## Legend

| Notation | Meaning |
| -------- | ------- |
| 🔊 | Noise / Calibrated-Benign activity |
| ☣️ | Cleanup step required after noise window |

---

## Noise Block 1 — Concurrent with Phase 2 (Discovery & Credential Access on IIS01)

**Timing:** Start when the red team begins host/domain reconnaissance from the SYSTEM
dnscat2 session on IIS01.

**Host:** IIS01 (`10.12.10.20`) — `TESTLAB\Administrator` via RDP

---

### 🔊 System Check

> **Noise bank sources:** T1082 `systeminfo | findstr` → [Scattered Spider P6](../../../../noise-collection/noise-behavior.md); [ER6 Ransomware Test 3](../../../../noise-collection/noise-behavior.md); [ER6 CL0P Step 4](../../../../noise-collection/noise-behavior.md) · T1057 `tasklist /v` → [Scattered Spider P6](../../../../noise-collection/noise-behavior.md) · T1007 `Get-WmiObject Win32_Service` → [ER6 Ransomware Test 3](../../../../noise-collection/noise-behavior.md); [ER6 CL0P Step 4](../../../../noise-collection/noise-behavior.md) · T1083 `Get-ChildItem` → [ER6 Ransomware Test 4](../../../../noise-collection/noise-behavior.md); [LockBit Step 2](../../../../noise-collection/noise-behavior.md) · T1059.001 `Get-PSDrive` → [mustang-panda-noise §4.1](../../../../noise-collection/mustang-panda-noise.md)

**Behavior:** Admin performs routine IIS server health checks on IIS01 — retrieving system locale, listing running processes, querying services via WMI, enumerating the public share, and checking disk usage. These commands overlap in technique class with Phase 2's host reconnaissance executed by the attacker from the SYSTEM dnscat2 ghost session (`whoami /all`, `WmiAvQuery.exe`, process listing). Both the admin and the attacker query system state using the same native tools; the distinguishing signal is process lineage: the admin's commands spawn from an interactive RDP desktop session (`explorer.exe → cmd.exe / powershell.exe`), while the attacker's commands spawn from the Herpaderping-masqueraded C2 ghost (`RuntimeBroker.exe → dnscat2 shell`). A product must resolve context by parent process tree rather than suppressing the entire technique class.

#### Procedures

- Retrieve system locale

  ```cmd
  systeminfo | findstr /B /C:"System Locale"
  ```

- List running processes

  ```cmd
  tasklist /v /fi "STATUS eq running"
  ```

- Query running services

  ```powershell
  Get-WmiObject -Class Win32_Service | Where-Object {$_.State -eq "Running"} | Format-Table
  ```

- Enumerate files, create and delete a test file

  ```powershell
  Get-ChildItem
  Set-Location -Path C:\Users\Public\
  New-Item -ItemType File -Name new_readme_report.txt
  Remove-Item new_readme_report.txt
  ```

- Check disk usage

  ```powershell
  Get-PSDrive
  ```

#### Reference Table

| Tactic | Technique ID | Technique Name | Detection Criteria | Category | Host | User | Noise Bank Source |
| ------ | ------------ | -------------- | ------------------ | -------- | ---- | ---- | ----------------- |
| Discovery | T1082 | System Information Discovery | `cmd.exe` executed `systeminfo \| findstr /B /C:"System Locale"` on IIS01 | Calibrated - Benign | IIS01 10.12.10.20 | TESTLAB\Administrator | Scattered Spider P6; ER6 Ransomware Test 3; ER6 CL0P Step 4 |
| Discovery | T1057 | Process Discovery | `cmd.exe` executed `tasklist /v /fi "STATUS eq running"` on IIS01 | Calibrated - Benign | IIS01 10.12.10.20 | TESTLAB\Administrator | Scattered Spider P6 |
| Discovery | T1007 | System Service Discovery | `powershell.exe` executed `Get-WmiObject -Class Win32_Service` on IIS01 | Calibrated - Benign | IIS01 10.12.10.20 | TESTLAB\Administrator | ER6 Ransomware Test 3; ER6 CL0P Step 4 |
| Discovery | T1083 | File and Directory Discovery | `powershell.exe` executed `Get-ChildItem` + `New-Item` / `Remove-Item` in `C:\Users\Public\` on IIS01 | Calibrated - Benign | IIS01 10.12.10.20 | TESTLAB\Administrator | ER6 Ransomware Test 4; LockBit Step 2 |
| Execution | T1059.001 | PowerShell | `powershell.exe` executes `Get-WmiObject`, `Get-ChildItem`, `Get-PSDrive` on IIS01 | Calibrated - Benign | IIS01 10.12.10.20 | TESTLAB\Administrator | ER6 Ransomware Test 3, 4; mustang-panda-noise §4.1 |
| Execution | T1059.003 | Windows Command Shell | `cmd.exe` executes `systeminfo \| findstr` and `tasklist` on IIS01 | Calibrated - Benign | IIS01 10.12.10.20 | TESTLAB\Administrator | Scattered Spider P6; ER6 Ransomware Test 3 |

---

### 🔊 Network Configuration Check

> **Noise bank sources:** T1016 `ipconfig /all` → [Scattered Spider P6](../../../../noise-collection/noise-behavior.md) · T1016.001 `ping google.com` → [mustang-panda-noise §3.3](../../../../noise-collection/mustang-panda-noise.md)

**Behavior:** Admin verifies network adapter configuration and external reachability on IIS01 — standard server maintenance that generates T1016 / T1016.001 telemetry concurrent with the attacker's network discovery in Phase 2 (interface enumeration and DC reachability checks from the SYSTEM dnscat2 session). The attacker's network discovery targets internal infrastructure (DC01 SMB access, domain controller identification); the admin's targets are general adapter review and internet connectivity. Distinguishing signal: command arguments (`ipconfig /all` vs. targeted host queries) and parent process tree — admin from RDP session; attacker from SYSTEM dnscat2 ghost.

#### Procedures

- View network adapter configuration

  ```cmd
  ipconfig /all
  ```

- Test internet connectivity

  ```cmd
  ping google.com
  ```

#### Reference Table

| Tactic | Technique ID | Technique Name | Detection Criteria | Category | Host | User | Noise Bank Source |
| ------ | ------------ | -------------- | ------------------ | -------- | ---- | ---- | ----------------- |
| Discovery | T1016 | System Network Configuration Discovery | `cmd.exe` executed `ipconfig /all` on IIS01 | Calibrated - Benign | IIS01 10.12.10.20 | TESTLAB\Administrator | Scattered Spider P6 |
| Discovery | T1016.001 | System Network Configuration Discovery: Internet Connection Discovery | `cmd.exe` executed `ping google.com` on IIS01 | Calibrated - Benign | IIS01 10.12.10.20 | TESTLAB\Administrator | mustang-panda-noise §3.3 |
| Execution | T1059.003 | Windows Command Shell | `cmd.exe` executes `ipconfig` and `ping` on IIS01 | Calibrated - Benign | IIS01 10.12.10.20 | TESTLAB\Administrator | Scattered Spider P6; mustang-panda-noise §3.3 |

---

## Noise Block 2 — Concurrent with Phase 3 (Lateral Movement & Persistence on DC01)

**Timing:** Start when the red team executes `go-thehash.exe` PtH to DC01 and begins
deploying persistence mechanisms.

**Host:** DC01 (`10.12.10.10`) — `TESTLAB\Administrator` via RDP (or console)

---

### 🔊 Account Discovery

> **Noise bank sources:** T1087.002 `net user` → [mustang-panda-noise §3.1](../../../../noise-collection/mustang-panda-noise.md)

**Behavior:** Admin lists domain user accounts on DC01 — a common verification step after AD configuration changes — generating T1087.002 telemetry concurrent with Phase 3's domain enumeration (`net group "Domain Admins" /domain`, `net user /domain` from the go-thehash PtH WMI session as `TESTLAB\Administrator`). Both the admin and the attacker authenticate as `TESTLAB\Administrator` to DC01; the distinguishing signal is process lineage: the admin's `net user` spawns from an interactive RDP `cmd.exe` under `explorer.exe`, while the attacker's enumeration spawns from `wmiprvse.exe` under the go-thehash lateral movement session.

#### Procedures

- List domain user accounts

  ```cmd
  net user
  ```

#### Reference Table

| Tactic | Technique ID | Technique Name | Detection Criteria | Category | Host | User | Noise Bank Source |
| ------ | ------------ | -------------- | ------------------ | -------- | ---- | ---- | ----------------- |
| Discovery | T1087.002 | Account Discovery: Domain Account | `cmd.exe` executed `net user` on DC01 | Calibrated - Benign | DC01 10.12.10.10 | TESTLAB\Administrator | mustang-panda-noise §3.1 |
| Execution | T1059.003 | Windows Command Shell | `cmd.exe` executes `net user` on DC01 | Calibrated - Benign | DC01 10.12.10.10 | TESTLAB\Administrator | mustang-panda-noise §3.1 |

---

### 🔊 Scheduled Task

> **Noise bank sources:** T1053.005 `schtasks /create` → [Scattered Spider P6](../../../../noise-collection/noise-behavior.md)

**Behavior:** Admin schedules a daily PowerShell maintenance script to run as SYSTEM — a standard Windows server administration pattern — generating T1053.005 telemetry concurrent with Phase 3's persistence deployment (WMI event subscription, registry service, svcbackup service). The technique class overlaps (Scheduled Task / Persistence), but the parameters differ (task name `DailyTask`, script `C:\Scripts\Backup.ps1`) and the creation context differs: admin spawns `schtasks.exe` from an interactive RDP session, while the attacker's persistence mechanisms are deployed from the dnscat2 C2 ghost or PtH WMI session. Note: this behavior is sourced from Scattered Spider Protections Test 6, a Protections-only scenario. In a Detections context this means a product may alert on it — which is expected and acceptable as a Calibrated-Benign event; it is not penalized.

#### Procedures

- Schedule a daily PowerShell maintenance task as SYSTEM

  ```cmd
  schtasks /create /tn "DailyTask" /tr "powershell.exe -File C:\Scripts\Backup.ps1" /sc daily /st 14:00 /ru "System"
  ```

- ☣️ Delete the task after the noise window

  ```cmd
  schtasks /delete /tn "DailyTask" /f
  ```

#### Reference Table

| Tactic | Technique ID | Technique Name | Detection Criteria | Category | Host | User | Noise Bank Source |
| ------ | ------------ | -------------- | ------------------ | -------- | ---- | ---- | ----------------- |
| Execution | T1053.005 | Scheduled Task/Job: Scheduled Task | `cmd.exe` executed `schtasks /create /tn "DailyTask"` running PowerShell as SYSTEM on DC01 | Calibrated - Benign | DC01 10.12.10.10 | TESTLAB\Administrator | Scattered Spider P6 |
| Execution | T1059.003 | Windows Command Shell | `cmd.exe` executes `schtasks` on DC01 | Calibrated - Benign | DC01 10.12.10.10 | TESTLAB\Administrator | Scattered Spider P6 |

---

## Noise Block 3 — Concurrent with Phase 5 (Impact on IIS01 + DC01)

**Timing:** Start when the red team begins `CertMaint.exe` execution on IIS01 (VSS
deletion, MSSQL stop, AES encryption).

**Hosts:** IIS01 and DC01 — `TESTLAB\Administrator` via RDP

---

### 🔊 Archive + Service Stop (IIS01)

> **Noise bank sources:** T1560.001 `7z archive with password` → [ER6 Ransomware Test 5](../../../../noise-collection/noise-behavior.md); [ER6 CL0P Noise Step](../../../../noise-collection/noise-behavior.md) · T1489 `Stop-Service` batch → [ER6 Ransomware Test 3](../../../../noise-collection/noise-behavior.md); [ER6 CL0P Step 4](../../../../noise-collection/noise-behavior.md)

**Behavior:** Admin archives the public share for an offboarding transition using 7-Zip with a password, and stops a batch of unused consumer services for performance tuning — generating T1560.001 and T1489 telemetry concurrent with Phase 5's impact execution by `CertMaint.exe` on IIS01 (7z compression of ntds.dit staging, `net stop MSSQLSERVER`). The collisions are intentional: both the admin and `CertMaint.exe` invoke 7z with a password flag, and both stop Windows services. The distinguishing signals are archive path (`C:\Users\Public\` vs. ntds staging directory), service names (`Bluetooth`, `BTAGService`, `OneSync`, `XblGameSave`, `WbioSrvc` vs. `MSSQLSERVER`), and parent process (`cmd.exe / powershell.exe` from RDP session vs. `CertMaint.exe` spawned from the SYSTEM dnscat2 ghost). Both T1560.001 and T1489 are validated in Detection-scenario sources (CL0P Scenario Step 4 and Noise Step).

#### Procedures

- Archive files with 7-Zip and a password

  ```cmd
  7z a C:\Temp\transition_off_share.zip C:\Users\Public\ -p!Evals123
  ```

- Stop a batch of services

  ```powershell
  Stop-Service -Name Bluetooth
  Stop-Service -Name BTAGService
  Stop-Service -Name OneSync
  Stop-Service -Name XblGameSave
  Stop-Service -Name WbioSrvc
  ```

- ☣️ Remove the archive

  ```cmd
  del C:\Temp\transition_off_share.zip
  ```

#### Reference Table

| Tactic | Technique ID | Technique Name | Detection Criteria | Category | Host | User | Noise Bank Source |
| ------ | ------------ | -------------- | ------------------ | -------- | ---- | ---- | ----------------- |
| Collection | T1560.001 | Archive Collected Data: Archive via Utility | `7z.exe` archives `C:\Users\Public\` with password `-p!Evals123` on IIS01 | Calibrated - Benign | IIS01 10.12.10.20 | TESTLAB\Administrator | ER6 Ransomware Test 5; ER6 CL0P Noise Step |
| Impact | T1489 | Service Stop | `powershell.exe` executed `Stop-Service` batch (`Bluetooth`, `BTAGService`, `OneSync`, `XblGameSave`, `WbioSrvc`) on IIS01 | Calibrated - Benign | IIS01 10.12.10.20 | TESTLAB\Administrator | ER6 Ransomware Test 3; ER6 CL0P Step 4 |
| Execution | T1059.001 | PowerShell | `powershell.exe` executes `Stop-Service` batch on IIS01 | Calibrated - Benign | IIS01 10.12.10.20 | TESTLAB\Administrator | ER6 Ransomware Test 3; ER6 CL0P Step 4 |
| Execution | T1059.003 | Windows Command Shell | `cmd.exe` executes `7z` on IIS01 | Calibrated - Benign | IIS01 10.12.10.20 | TESTLAB\Administrator | ER6 CL0P Noise Step |

---

### 🔊 VSS + Firewall + Recycle Bin (DC01)

> **Noise bank sources:** T1490 `vssadmin add shadowstorage` + `vssadmin create shadow` → [LockBit Step 4](../../../../noise-collection/noise-behavior.md) · T1562.004 `netsh advfirewall set allprofiles state off` → [ER6 Ransomware Test 3](../../../../noise-collection/noise-behavior.md); [ER6 CL0P Step 4](../../../../noise-collection/noise-behavior.md) · T1070 recycle bin clear → [ER6 Ransomware Test 8](../../../../noise-collection/noise-behavior.md); [LockBit Step 7](../../../../noise-collection/noise-behavior.md)

**Behavior:** Admin creates a VSS snapshot for backup verification, disables Windows Defender Firewall for a maintenance window, and empties the recycle bin on DC01 — generating T1490, T1562.004, and T1070 telemetry concurrent with Phase 5's impact execution. The T1490 case is the sharpest FP test: the admin uses `vssadmin add shadowstorage` and `vssadmin create shadow` (creating a backup), while `CertMaint.exe` uses `IVssBackupComponents::DeleteSnapshots` via COM (destroying all backups) — same technique ID, opposite sub-operation, different parent process. The key distinction is vssadmin sub-command (`add/create` vs. `delete`) and process lineage (`cmd.exe` from RDP vs. `CertMaint.exe` from SYSTEM dnscat2 ghost). T1562.004 (firewall disable) and T1070 (recycle bin clear) have no direct analog in Phase 5's attack techniques but generate high-signal events that test whether a product incorrectly correlates admin activity into the attack chain; both are sourced from Detection scenarios (CL0P Scenario and LockBit Scenario respectively). All three behaviors are validated in Detection-scenario sources.

#### Procedures

- Add shadow storage and create a VSS snapshot

  ```cmd
  vssadmin add shadowstorage /for=C: /on=C: /maxsize=UNBOUNDED
  vssadmin create shadow /for=C:
  ```

- Disable Windows Firewall for all profiles

  ```cmd
  netsh advfirewall set allprofiles state off
  ```

- Clear the recycle bin (GUI — right-click Desktop > **Empty Recycle Bin**)

#### Reference Table

| Tactic | Technique ID | Technique Name | Detection Criteria | Category | Host | User | Noise Bank Source |
| ------ | ------------ | -------------- | ------------------ | -------- | ---- | ---- | ----------------- |
| Impact | T1490 | Inhibit System Recovery | `cmd.exe` executed `vssadmin add shadowstorage` + `vssadmin create shadow /for=C:` on DC01 | Calibrated - Benign | DC01 10.12.10.10 | TESTLAB\Administrator | LockBit Step 4 |
| Defense Evasion | T1562.004 | Impair Defenses: Disable or Modify System Firewall | `cmd.exe` executed `netsh advfirewall set allprofiles state off` on DC01 | Calibrated - Benign | DC01 10.12.10.10 | TESTLAB\Administrator | ER6 Ransomware Test 3; ER6 CL0P Step 4 |
| Defense Evasion | T1070 | Indicator Removal | User clears recycle bin via GUI (right-click > Empty Recycle Bin) on DC01 | Calibrated - Benign | DC01 10.12.10.10 | TESTLAB\Administrator | ER6 Ransomware Test 8; LockBit Step 7 |
| Execution | T1059.003 | Windows Command Shell | `cmd.exe` executes `vssadmin` and `netsh advfirewall` on DC01 | Calibrated - Benign | DC01 10.12.10.10 | TESTLAB\Administrator | LockBit Step 4; ER6 Ransomware Test 3 |

---

## Appendix — ATT&CK Coverage Summary

| Tactic | Technique ID | Technique Name | Noise Block | Host |
| ------ | ------------ | -------------- | ----------- | ---- |
| Discovery | T1082 | System Information Discovery | Block 1 | IIS01 |
| Discovery | T1057 | Process Discovery | Block 1 | IIS01 |
| Discovery | T1007 | System Service Discovery | Block 1 | IIS01 |
| Discovery | T1083 | File and Directory Discovery | Block 1 | IIS01 |
| Discovery | T1016 | System Network Configuration Discovery | Block 1 | IIS01 |
| Discovery | T1016.001 | System Network Configuration Discovery: Internet Connection Discovery | Block 1 | IIS01 |
| Discovery | T1087.002 | Account Discovery: Domain Account | Block 2 | DC01 |
| Execution | T1059.001 | PowerShell | Block 1, 3 | IIS01 |
| Execution | T1059.003 | Windows Command Shell | Block 1, 2, 3 | IIS01, DC01 |
| Execution | T1053.005 | Scheduled Task/Job: Scheduled Task | Block 2 | DC01 |
| Collection | T1560.001 | Archive Collected Data: Archive via Utility | Block 3 | IIS01 |
| Impact | T1489 | Service Stop | Block 3 | IIS01 |
| Impact | T1490 | Inhibit System Recovery | Block 3 | DC01 |
| Defense Evasion | T1562.004 | Impair Defenses: Disable or Modify System Firewall | Block 3 | DC01 |
| Defense Evasion | T1070 | Indicator Removal | Block 3 | DC01 |
