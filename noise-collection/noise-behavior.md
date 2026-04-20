# Noise Behavior Collection

## Overview

This document aggregates every noise / false-positive calibration activity that appears inside the 2024-2025 ATT&CK Evaluations emulation plans in this repository. Noise is the set of benign or legitimate-looking behaviors intentionally executed so that detection products can be measured against false positives alongside true-positive red team substeps.

Entries are organized by ATT&CK tactic (cross-scenario), then by technique. Commands are copied verbatim from the source scenarios (including original escape characters) so they can be executed as-is. Each entry maps back to every scenario that contains the behavior.

## Legend

| Emoji | Meaning |
| ----- | ------- |
| :loud_sound: | Noise / calibrated-benign activity |
| :microphone: | Voice Track (scenario narration) |
| :hammer: | Setup / prerequisites |
| :biohazard: | Red team procedures |
| :broom: | Cleanup |
| :mag: | Reference / ATT&CK mapping |
| :arrow_right: | Navigation / move between hosts |
| :information_source: | Note |

## Sources

| # | Scenario | Noise Blocks |
| - | -------- | ------------ |
| 1 | [Scattered Spider Protections Test 6 (NOISE ONLY)](../Enterprise/scattered_spider/Emulation_Plan/Protections_Test_6_Scenario.md) | entire scenario |
| 2 | [ER6 Ransomware Protections (Test 1 - Test 8)](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) | 8 blocks |
| 3 | [DPRK Protections (Test 9, Test 10)](../Enterprise/dprk/Emulation_Plan/Protections.md) | 2 blocks |
| 4 | [ER6 DPRK Scenario (Step 4 Collection)](../Enterprise/dprk/Emulation_Plan/ER6_DPRK_Scenario.md) | 1 block |
| 5 | [ER6 CL0P Scenario (Step 2, Noise Step, Step 4)](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md) | 3 blocks |
| 6 | [ER6 LockBit Scenario (Step 2, Step 4, Step 7)](../Enterprise/lockbit/Emulation_Plan/ER6_LockBit_Scenario.md) | 3 blocks |

## Summary ATT&CK Coverage

| Tactic | Technique ID | Technique Name | Source Scenarios |
| ------ | ------------ | -------------- | ---------------- |
| Discovery | T1082 | System Information Discovery | Scattered Spider P6; ER6 Ransomware Test 3; ER6 CL0P Step 4 |
| Discovery | T1083 | File and Directory Discovery | ER6 Ransomware Test 4; LockBit Step 2 |
| Discovery | T1057 | Process Discovery | Scattered Spider P6 |
| Discovery | T1016 | System Network Configuration Discovery | Scattered Spider P6 |
| Discovery | T1007 | System Service Discovery | ER6 Ransomware Test 3; ER6 CL0P Step 4 |
| Discovery | T1614 | System Location Discovery | ER6 Ransomware Test 3; ER6 CL0P Step 4 |
| Execution | T1059.001 | PowerShell | ER6 Ransomware Test 3, 4; ER6 CL0P Step 4; LockBit Step 2 |
| Execution | T1059.002 | AppleScript | DPRK Protections Test 9; ER6 DPRK Step 4 |
| Execution | T1059.003 | Windows Command Shell | Scattered Spider P6; ER6 Ransomware Test 2, 3, 5 |
| Execution | T1053.005 | Scheduled Task | Scattered Spider P6 |
| Execution | T1218.011 | System Binary Proxy Execution: Rundll32 | ER6 Ransomware Test 2; ER6 CL0P Step 2 |
| Execution | T1569.002 | System Services: Service Execution | ER6 Ransomware Test 7 |
| Defense Evasion | T1562.004 | Impair Defenses: Disable or Modify System Firewall | ER6 Ransomware Test 3; ER6 CL0P Step 4 |
| Defense Evasion | T1546.012 | Event Triggered Execution: IFEO Injection | ER6 Ransomware Test 2; ER6 CL0P Step 2 |
| Defense Evasion | T1027 | Obfuscated Files or Information | ER6 Ransomware Test 2; ER6 CL0P Step 2 |
| Defense Evasion | T1070 | Indicator Removal | ER6 Ransomware Test 8; LockBit Step 7 |
| Lateral Movement | T1021.001 | Remote Services: RDP | Scattered Spider P6; ER6 Ransomware Test 1, 3, 6 |
| Lateral Movement | T1021.002 | Remote Services: SMB / Windows Admin Shares | ER6 Ransomware Test 5, 7, 8; ER6 CL0P Noise Step; LockBit Step 7 |
| Lateral Movement | T1021.005 | Remote Services: VNC | DPRK Protections Test 9, Test 10; ER6 DPRK Step 4 |
| Lateral Movement | T1021.006 | Remote Services: Windows Remote Management | ER6 CL0P Noise Step |
| Lateral Movement | T1570 | Lateral Tool Transfer | ER6 Ransomware Test 7; ER6 CL0P Noise Step |
| Command and Control | T1105 | Ingress Tool Transfer | Scattered Spider P6; ER6 Ransomware Test 1; DPRK Protections Test 10; ER6 DPRK Step 4 |
| Command and Control | T1072 | Software Deployment Tools | ER6 Ransomware Test 1, 5, 6, 7; LockBit Step 4; ER6 CL0P Noise Step; DPRK Protections Test 10; ER6 DPRK Step 4 |
| Collection | T1560.001 | Archive Collected Data: Archive via Utility | ER6 Ransomware Test 5; ER6 CL0P Noise Step |
| Impact | T1489 | Service Stop | ER6 Ransomware Test 3; ER6 CL0P Step 4 |
| Impact | T1490 | Inhibit System Recovery | LockBit Step 2, Step 4 |
| User Activity | - | Browser / Document / Installer interaction | multiple |

---

## :mag: Discovery

### :loud_sound: System Information Discovery (T1082)

**Behavior:** Users run `systeminfo` piped into `findstr` to retrieve system locale or run `Get-WinSystemLocale` in PowerShell. These are common administrator commands that can collide with malware host-profiling.

**Commands / Activity:**

```cmd
systeminfo | findstr /B /C:"System Locale"
```

```cmd
cmd.exe executed systeminfo | findstr /B /C:'System Locale'
```

```powershell
Get-WinSystemLocale
```

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Discovery | T1082 | cmd.exe executed systeminfo | findstr | Calibrated - Benign | tentowers 10.26.4.102 | vale\tharlaw | [Scattered Spider Protections Test 6](../Enterprise/scattered_spider/Emulation_Plan/Protections_Test_6_Scenario.md) |
| Discovery | T1082 | cmd.exe executed systeminfo | findstr | Calibrated - Benign | lisa 10.222.25.65 | sonicbeats37.fm\sooyoung | [ER6 Ransomware Protections Test 3](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Discovery | T1082 | cmd.exe executed systeminfo | findstr | Calibrated - Benign | Windows victim workstation | encryptpotter.net user | [ER6 CL0P Step 4](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md) |
| Discovery | T1614 | PowerShell Get-WinSystemLocale | Calibrated - Benign | lisa 10.222.25.65 | sonicbeats37.fm\sooyoung | [ER6 Ransomware Protections Test 3](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Discovery | T1614 | PowerShell Get-WinSystemLocale | Calibrated - Benign | Windows victim workstation | encryptpotter.net user | [ER6 CL0P Step 4](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md) |

### :loud_sound: File and Directory Discovery (T1083)

**Behavior:** User enumerates files with PowerShell `Get-ChildItem`, changes location, creates and deletes a benign text file. Mirrors ransomware enumeration but is framed as user admin activity.

**Commands / Activity:**

```powershell
Get-ChildItem
Set-Location -Path C:\Users\Public\
New-Item -ItemType File -Name new_readme_report.txt
Remove-Item new_readme_report.txt
```

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Discovery | T1083 | PowerShell Get-ChildItem enumerates directory | Calibrated - Benign | bts 10.222.25.61 | sonicbeats37.fm\yoona | [ER6 Ransomware Protections Test 4](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Discovery | T1083 | PowerShell Get-ChildItem + file create/delete | Calibrated - Benign | LockBit affiliate workstation | - | [ER6 LockBit Step 2](../Enterprise/lockbit/Emulation_Plan/ER6_LockBit_Scenario.md) |

### :loud_sound: Process Discovery (T1057)

**Behavior:** User lists running processes with verbose output filtered by running status, a common troubleshooting action.

**Commands / Activity:**

```cmd
tasklist /v /fi "STATUS eq running"
```

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Discovery | T1057 | cmd.exe executed tasklist | Calibrated - Benign | tentowers 10.26.4.102 | vale\tharlaw | [Scattered Spider Protections Test 6](../Enterprise/scattered_spider/Emulation_Plan/Protections_Test_6_Scenario.md) |

### :loud_sound: System Network Configuration Discovery (T1016)

**Behavior:** User runs `ipconfig /all` to view network adapters.

**Commands / Activity:**

```cmd
ipconfig /all
```

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Discovery | T1016 | cmd.exe executed ipconfig | Calibrated - Benign | tentowers 10.26.4.102 | vale\tharlaw | [Scattered Spider Protections Test 6](../Enterprise/scattered_spider/Emulation_Plan/Protections_Test_6_Scenario.md) |

### :loud_sound: System Service Discovery (T1007)

**Behavior:** User queries running services via WMI and formats the result as a table.

**Commands / Activity:**

```powershell
Get-WmiObject -Class Win32_Service | Where-Object {{}$_.State -eq \"Running\"{}} | Format-Table
```

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Discovery | T1007 | PowerShell Get-WmiObject Win32_Service | Calibrated - Benign | lisa 10.222.25.65 | sonicbeats37.fm\sooyoung | [ER6 Ransomware Protections Test 3](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Discovery | T1007 | PowerShell Get-WmiObject Win32_Service | Calibrated - Benign | Windows victim workstation | encryptpotter.net user | [ER6 CL0P Step 4](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md) |

---

## :mag: Execution

### :loud_sound: Scheduled Task (T1053.005)

**Behavior:** User schedules a daily PowerShell maintenance task to run under the SYSTEM account, overlapping with persistence-style activity.

**Commands / Activity:**

```cmd
schtasks /create /tn "DailyTask" /tr "powershell.exe -File C:\Scripts\Backup.ps1" /sc daily /st 14:00 /ru "System"
```

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Execution | T1053.005 | cmd.exe executed schtasks to schedule Backup PowerShell | Calibrated - Benign | tentowers 10.26.4.102 | vale\tharlaw | [Scattered Spider Protections Test 6](../Enterprise/scattered_spider/Emulation_Plan/Protections_Test_6_Scenario.md) |

### :loud_sound: Rundll32 Proxy Execution (T1218.011)

**Behavior:** User triggers `rundll32 url.dll,FileProtocolHandler` to open an URL, then kills msedge. This is a well-known LOLBIN execution path frequently abused by malware.

**Commands / Activity:**

```cmd
cmd.exe executed rundll32  url.dll,FileProtocolHandler https://www.google.com & taskkill /F /IM \"msedge.exe\" /T
```

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Execution | T1218.011 | rundll32 url.dll,FileProtocolHandler invoked via cmd.exe | Calibrated - Benign | bts 10.222.25.61 | sonicbeats37.fm\yoona | [ER6 Ransomware Protections Test 2](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Execution | T1218.011 | rundll32 url.dll,FileProtocolHandler invoked via cmd.exe | Calibrated - Benign | vault713 10.55.3.100 | encryptpotter.net\ranrok | [ER6 CL0P Step 2](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md) |

### :loud_sound: Windows Command Shell (T1059.003)

**Behavior:** User executes installers, copy operations and benign commands from `cmd.exe`. Included primarily as the parent-process of other noise sub-techniques.

**Commands / Activity:**

```cmd
.\TaskCoach
```

```cmd
cmd.exe executed copy /b C:\\Users\\Public\\hidden.txt C:\\Users\\Public\\original.txt
```

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Execution | T1059.003 | cmd.exe executes TaskCoach installer | Calibrated - Benign | tentowers 10.26.4.102 | vale\tharlaw | [Scattered Spider Protections Test 6](../Enterprise/scattered_spider/Emulation_Plan/Protections_Test_6_Scenario.md) |
| Execution | T1059.003 | cmd.exe executes copy /b to embed a text file | Calibrated - Benign | bts 10.222.25.61 | sonicbeats37.fm\yoona | [ER6 Ransomware Protections Test 2](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Execution | T1059.003 | cmd.exe executes copy /b to embed a text file | Calibrated - Benign | vault713 10.55.3.100 | encryptpotter.net\ranrok | [ER6 CL0P Step 2](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md) |

### :loud_sound: PowerShell (T1059.001)

**Behavior:** Several noise blocks use PowerShell as the execution host for enumeration, service control, and file manipulation. Individual commands are also captured under their dedicated technique sections.

**Commands / Activity:**

```powershell
Get-ChildItem
Set-Location -Path C:\Users\Public\
New-Item -ItemType File -Name new_readme_report.txt
Remove-Item new_readme_report.txt
Get-WmiObject -Class Win32_Service | Where-Object {{}$_.State -eq \"Running\"{}} | Format-Table
Get-WinSystemLocale
```

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Execution | T1059.001 | PowerShell noise commands (Get-ChildItem, Set-Location, New-Item, Remove-Item) | Calibrated - Benign | bts 10.222.25.61 | sonicbeats37.fm\yoona | [ER6 Ransomware Protections Test 4](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Execution | T1059.001 | PowerShell Get-WmiObject + Stop-Service batch | Calibrated - Benign | lisa 10.222.25.65 | sonicbeats37.fm\sooyoung | [ER6 Ransomware Protections Test 3](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Execution | T1059.001 | PowerShell Get-WmiObject + Stop-Service batch | Calibrated - Benign | Windows victim workstation | encryptpotter.net user | [ER6 CL0P Step 4](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md) |
| Execution | T1059.001 | PowerShell Get-ChildItem + file create/delete | Calibrated - Benign | LockBit affiliate workstation | - | [ER6 LockBit Step 2](../Enterprise/lockbit/Emulation_Plan/ER6_LockBit_Scenario.md) |

### :loud_sound: AppleScript (T1059.002)

**Behavior:** macOS user saves and runs a benign Finder script (`count_files.scpt`) from Script Editor. It chooses a folder via the Finder dialog and counts non-folder items, mimicking the victim-side APT interaction surface.

**Commands / Activity:**

```applescript
tell application "Finder"
    set ffolder to choose folder
    set sccripts to every item of ffolder whose kind is not "folder"
    get count of sccripts
end tell
```

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Execution | T1059.002 | Script Editor runs count_files.scpt via Finder | Calibrated - Benign | itzy 10.222.25.70 (macOS) | venom | [DPRK Protections Test 9](../Enterprise/dprk/Emulation_Plan/Protections.md) |
| Execution | T1059.002 | Script Editor runs count_files.scpt via Finder | Calibrated - Benign | hogshead 10.55.4.50 (macOS) | ranrok | [ER6 DPRK Scenario Step 4](../Enterprise/dprk/Emulation_Plan/ER6_DPRK_Scenario.md) |

---

## :mag: Defense Evasion

### :loud_sound: Disable or Modify System Firewall (T1562.004)

**Behavior:** User turns off Windows Defender Firewall for all profiles via `netsh`, a command line flag very commonly misused by ransomware pre-encryption.

**Commands / Activity:**

```cmd
cmd.exe executed netsh advfirewall set allprofiles state off
```

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Defense Evasion | T1562.004 | cmd.exe executed netsh advfirewall set allprofiles state off | Calibrated - Benign | lisa 10.222.25.65 | sonicbeats37.fm\sooyoung | [ER6 Ransomware Protections Test 3](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Defense Evasion | T1562.004 | cmd.exe executed netsh advfirewall set allprofiles state off | Calibrated - Benign | Windows victim workstation | encryptpotter.net user | [ER6 CL0P Step 4](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md) |

### :loud_sound: Image File Execution Options Injection (T1546.012)

**Behavior:** User modifies the IFEO registry key for `msedge.exe` so launching Edge spawns Firefox instead. A classic persistence / debugger hijack pattern.

**Commands / Activity:**

```cmd
reg add \HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\msedge.exe\" /v Debugger /t REG_SZ /d \"C:\\Program Files\\Mozilla Firefox\\firefox.exe\""
```

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Defense Evasion | T1546.012 | reg add IFEO Debugger value for msedge.exe | Calibrated - Benign | bts 10.222.25.61 | sonicbeats37.fm\yoona | [ER6 Ransomware Protections Test 2](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Defense Evasion | T1546.012 | reg add IFEO Debugger value for msedge.exe | Calibrated - Benign | vault713 10.55.3.100 | encryptpotter.net\ranrok | [ER6 CL0P Step 2](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md) |

### :loud_sound: Obfuscated Files or Information / File Embedding (T1027)

**Behavior:** User embeds one text file inside another using the binary append mode of `copy`. The resulting artifact has two concatenated payloads in a single file.

**Commands / Activity:**

```cmd
notepad.exe creates C:\\Users\\Public\\hidden.txt" & "C:\\Users\\Public\\original.txt
cmd.exe executed copy /b C:\\Users\\Public\\hidden.txt C:\\Users\\Public\\original.txt
```

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Defense Evasion | T1027 | copy /b concatenates hidden.txt into original.txt | Calibrated - Benign | bts 10.222.25.61 | sonicbeats37.fm\yoona | [ER6 Ransomware Protections Test 2](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Defense Evasion | T1027 | copy /b concatenates hidden.txt into original.txt | Calibrated - Benign | vault713 10.55.3.100 | encryptpotter.net\ranrok | [ER6 CL0P Step 2](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md) |

### :loud_sound: Indicator Removal (T1070)

**Behavior:** User clears the recycle bin after copying files, overlapping with the cleanup stage of data-staging intrusions.

**Commands / Activity:**

* User will clear the recycling bin (via GUI - right-click Empty Recycle Bin).

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Defense Evasion | T1070 | User clears recycle bin | Calibrated - Benign | bts 10.222.25.61 / exo 10.222.25.62 | sonicbeats37.fm\yoona, sonicbeats37.fm\sunny | [ER6 Ransomware Protections Test 8](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Defense Evasion | T1070 | User clears recycle bin | Calibrated - Benign | LockBit affiliate workstation | - | [ER6 LockBit Step 7](../Enterprise/lockbit/Emulation_Plan/ER6_LockBit_Scenario.md) |

---

## :mag: Lateral Movement

### :loud_sound: Remote Services: RDP (T1021.001)

**Behavior:** User performs intra-range RDP hops between workstations and servers. Valid user-on-user-behavior that frequently resembles adversary movement.

**Commands / Activity:**

```cmd
mstsc /v:10.26.3.101
```

Additional noise narratives:

* User will RDP from EXO to BLACKPINK (ER6 Ransomware Test 1).
* User will RDP from EXO to ASIX (ER6 Ransomware Test 3).
* User will RDP from BLACKPINK to EXO (ER6 Ransomware Test 6).

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Lateral Movement | T1021.001 | tharlaw connects to RAS 10.26.3.101 via RDP (mstsc) | Calibrated - Benign | tentowers 10.26.4.102 | vale\tharlaw | [Scattered Spider Protections Test 6](../Enterprise/scattered_spider/Emulation_Plan/Protections_Test_6_Scenario.md) |
| Lateral Movement | T1021.001 | User RDP EXO -> BLACKPINK | Calibrated - Benign | exo -> blackpink | sonicbeats37.fm user | [ER6 Ransomware Protections Test 1](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Lateral Movement | T1021.001 | User RDP EXO -> ASIX | Calibrated - Benign | exo -> asix | sonicbeats37.fm user | [ER6 Ransomware Protections Test 3](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Lateral Movement | T1021.001 | User RDP BLACKPINK -> EXO | Calibrated - Benign | blackpink -> exo | sonicbeats37.fm user | [ER6 Ransomware Protections Test 6](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |

### :loud_sound: Remote Services: SMB / Windows Admin Shares (T1021.002)

**Behavior:** User maps remote SMB shares, copies files to and from them, and in the false-positive calibration blocks uses `net use` and PsExec to reach admin shares.

**Commands / Activity:**

```cmd
net use
net use Z: \\10.222.15.15\D$\data /persistent:yes /user:sonicbeats37.fm\sooyoung
```

```psh
$computers="10.222.25.61","10.222.25.62";
foreach ($computer in $computers){
psexec \\$computer -s -u sonicbeats37.fm\sooyoung -p Dental-Crew -c "C:\users\sooyoung\Desktop\install_software.bat";
}
```

Additional noise narratives:

* User maps a network drive to a remote SMB share, copies files locally, then disconnects (ER6 Test 8, LockBit Step 7).
* User drops `xfer.zip` onto the mounted network share `Z:` (CL0P Noise Step).

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Lateral Movement | T1021.002 | net use mounts Z: to \\10.222.15.15\D$\data | Calibrated - Benign | eyescream 199.88.44.201 | devadmin / sonicbeats37.fm\sooyoung | [ER6 Ransomware Protections Test 5](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Lateral Movement | T1021.002 | PsExec loop deploys install_software.bat to remote admin shares | Calibrated - Benign | blackpink 10.222.15.10 -> bts, exo | sonicbeats37.fm\sooyoung | [ER6 Ransomware Protections Test 7](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Lateral Movement | T1021.002 | User maps remote SMB share and copies files | Calibrated - Benign | bts 10.222.25.61, exo 10.222.25.62 | sonicbeats37.fm\yoona, sonicbeats37.fm\sunny | [ER6 Ransomware Protections Test 8](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Lateral Movement | T1021.002 | User drags xfer.zip to mapped share Z: | Calibrated - Benign | diagonalley 10.55.4.21, gobbledgook 10.55.4.22 | encryptpotter.net\griphook | [ER6 CL0P Noise Step](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md) |
| Lateral Movement | T1021.002 | User maps remote SMB share and copies files | Calibrated - Benign | LockBit affiliate workstation | - | [ER6 LockBit Step 7](../Enterprise/lockbit/Emulation_Plan/ER6_LockBit_Scenario.md) |

### :loud_sound: Remote Services: VNC (T1021.005)

**Behavior:** Operator initiates a VNC session from the jumpbox to the macOS victim to simulate legitimate remote administration, before executing macOS user actions.

**Commands / Activity:**

* VNC client to `10.222.25.70::5900` (password `test1234`), login with `venom` / `Thin-Hash`.
* VNC client to `10.55.4.50::5900` (password `test1234`), login with `ranrok` / `Ladylike-Laugh`.

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Lateral Movement | T1021.005 | VNC connection to macOS victim | Calibrated - Benign | itzy 10.222.25.70 | venom | [DPRK Protections Test 9](../Enterprise/dprk/Emulation_Plan/Protections.md) |
| Lateral Movement | T1021.005 | VNC connection to macOS victim | Calibrated - Benign | itzy 10.222.25.70 | venom | [DPRK Protections Test 10](../Enterprise/dprk/Emulation_Plan/Protections.md) |
| Lateral Movement | T1021.005 | VNC connection to macOS victim | Calibrated - Benign | hogshead 10.55.4.50 | ranrok | [ER6 DPRK Scenario Step 4](../Enterprise/dprk/Emulation_Plan/ER6_DPRK_Scenario.md) |

### :loud_sound: Remote Services: Windows Remote Management (T1021.006)

**Behavior:** Operator fan-outs a benign Chocolatey install command across multiple domain hosts using `Invoke-Command`. WinRM / PowerShell Remoting is frequently abused for lateral execution.

**Commands / Activity:**

```cmd
Invoke-Command -ComputerName diagonalley,gobbledgook,vault713,azkaban,hangleton -ScriptBlock { choco install 7zip -y }
```

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Lateral Movement | T1021.006 | Invoke-Command installs 7zip on multiple domain hosts | Calibrated - Benign | vault713 10.55.3.100 -> domain hosts | encryptpotter.net\ranrok | [ER6 CL0P Noise Step](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md) |

### :loud_sound: Lateral Tool Transfer (T1570)

**Behavior:** Operator transfers an installer script (`install_software.bat`) or a `xfer.zip` archive to other hosts via PsExec or mapped share drag-and-drop.

**Commands / Activity:**

```cmd
choco install -y notepadplusplus
choco install -y adobereader
```

```psh
psexec \\$computer -s -u sonicbeats37.fm\sooyoung -p Dental-Crew -c "C:\users\sooyoung\Desktop\install_software.bat"
```

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Lateral Movement | T1570 | PsExec -c copies install_software.bat to remote hosts | Calibrated - Benign | blackpink 10.222.15.10 -> bts, exo | sonicbeats37.fm\sooyoung | [ER6 Ransomware Protections Test 7](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Lateral Movement | T1570 | Drag xfer.zip to mapped share then copy to remote Downloads | Calibrated - Benign | diagonalley 10.55.4.21 / gobbledgook 10.55.4.22 | encryptpotter.net\griphook | [ER6 CL0P Noise Step](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md) |

### :loud_sound: System Services: Service Execution (T1569.002)

**Behavior:** PsExec creates a remote Windows service on the target to launch the batch script. Counts as service-execution for the false-positive window.

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Execution | T1569.002 | PsExec spawns remote service to run install_software.bat | Calibrated - Benign | bts 10.222.25.61, exo 10.222.25.62 | sonicbeats37.fm\sooyoung | [ER6 Ransomware Protections Test 7](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |

---

## :mag: Command and Control / Ingress

### :loud_sound: Ingress Tool Transfer (T1105)

**Behavior:** User uses `curl` to download public datasets, legitimate installers (TaskCoach, IntelliJ), or task-management tools. Common sysadmin activity and a frequent FP against "curl download" detections.

**Commands / Activity:**

```cmd
curl -L -o C:\Users\%username%\Downloads\TaskCoachSetup.exe https://sourceforge.net/projects/taskcoach/files/latest/download
```

```cmd
curl -O https://data.un.org/_Docs/SYB/CSV/SYB66_1_202310_Population,%20Surface%20Area%20and%20Density.csv
curl -O https://data.un.org/_Docs/SYB/CSV/SYB66_327_202310_International%20Migrants%20and%20Refugees.csv
curl -O https://data.un.org/_Docs/SYB/CSV/SYB61_253_Population%20Growth%20Rates%20in%20Urban%20areas%20and%20Capital%20cities.csv
curl -O https://data.un.org/_Docs/SYB/CSV/SYB66_230_202310_GDP%20and%20GDP%20Per%20Capita.csv"
curl -O https://data.un.org/_Docs/SYB/CSV/SYB66_153_202310_Gross%20Value%20Added%20by%20Economic%20Activity.csv
curl -O https://data.un.org/_Docs/SYB/CSV/SYB66_128_202310_Consumer%20Price%20Index.csv
```

Additional noise narratives:

* User opens Safari and downloads IntelliJ Apple Silicon `.dmg` from <https://www.jetbrains.com/idea/download/?section=mac> (DPRK Protections Test 10, ER6 DPRK Step 4).

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Command and Control | T1105 | cmd.exe executed curl to download TaskCoachSetup | Calibrated - Benign | tentowers 10.26.4.102 | vale\tharlaw | [Scattered Spider Protections Test 6](../Enterprise/scattered_spider/Emulation_Plan/Protections_Test_6_Scenario.md) |
| Command and Control | T1105 | curl -O retrieves UN CSV files | Calibrated - Benign | bts 10.222.25.61 | sonicbeats37.fm\yoona | [ER6 Ransomware Protections Test 1](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Command and Control | T1105 | Safari downloads IntelliJ .dmg | Calibrated - Benign | itzy 10.222.25.70 | venom | [DPRK Protections Test 10](../Enterprise/dprk/Emulation_Plan/Protections.md) |
| Command and Control | T1105 | Safari downloads IntelliJ .dmg | Calibrated - Benign | hogshead 10.55.4.50 | ranrok | [ER6 DPRK Scenario Step 4](../Enterprise/dprk/Emulation_Plan/ER6_DPRK_Scenario.md) |

### :loud_sound: Software Deployment Tools (T1072)

**Behavior:** User installs legitimate software (Chrome, 7zip, profwiz, ldapadmin, Notepad++, Adobe Reader, FoxAdminPro, TaskCoach, IntelliJ) via `choco install` or GUI installers. Package manager noise overlaps heavily with malware-delivered installs.

**Commands / Activity:**

```cmd
choco install googlechrome -y
choco install 7zip -y
choco install profwiz -y
choco install ldapadmin -y
choco install -y notepadplusplus
choco install -y adobereader
```

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Command and Control | T1072 | choco install googlechrome | Calibrated - Benign | bts 10.222.25.61 | sonicbeats37.fm\yoona | [ER6 Ransomware Protections Test 1](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Command and Control | T1072 | choco install 7zip | Calibrated - Benign | eyescream 199.88.44.201 | devadmin | [ER6 Ransomware Protections Test 5](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Command and Control | T1072 | choco install profwiz, ldapadmin | Calibrated - Benign | Windows workstations | - | [ER6 Ransomware Protections Test 6](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Command and Control | T1072 | choco install notepadplusplus, adobereader via PsExec | Calibrated - Benign | bts 10.222.25.61, exo 10.222.25.62 | sonicbeats37.fm\sooyoung | [ER6 Ransomware Protections Test 7](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Command and Control | T1072 | choco install 7zip via Invoke-Command | Calibrated - Benign | vault713 10.55.3.100 -> domain hosts | encryptpotter.net\ranrok | [ER6 CL0P Noise Step](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md) |
| Command and Control | T1072 | choco install profwiz, ldapadmin | Calibrated - Benign | LockBit affiliate workstation | - | [ER6 LockBit Step 4](../Enterprise/lockbit/Emulation_Plan/ER6_LockBit_Scenario.md) |
| Command and Control | T1072 | User installs IntelliJ from downloaded .dmg | Calibrated - Benign | itzy 10.222.25.70 | venom | [DPRK Protections Test 10](../Enterprise/dprk/Emulation_Plan/Protections.md) |
| Command and Control | T1072 | User installs IntelliJ from downloaded .dmg | Calibrated - Benign | hogshead 10.55.4.50 | ranrok | [ER6 DPRK Scenario Step 4](../Enterprise/dprk/Emulation_Plan/ER6_DPRK_Scenario.md) |

---

## :mag: Collection

### :loud_sound: Archive Collected Data: Archive via Utility (T1560.001)

**Behavior:** User zips Documents folders with 7-Zip (command-line or GUI) using a password and moves the archive to a staging location. Overlaps with ransomware / exfil staging.

**Commands / Activity:**

```cmd
7z a Z:\transition_off_share.zip Z:\Documents\ -p!Evals123
```

```cmd
move Z:\transition_off_share.zip C:\users\op1\Desktop
rmdir /S /Q Z:\Documents\
```

Additional noise narratives:

* User creates `xfer` folder in Documents, drags files in, right-click > 7-ZIP > Add to Archive with password `leakycauldron`, deletes original folder (CL0P Noise Step).

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Collection | T1560.001 | 7z.exe archives Z:\Documents with password | Calibrated - Benign | eyescream 199.88.44.201 | devadmin | [ER6 Ransomware Protections Test 5](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Collection | T1560.001 | 7-ZIP GUI archives xfer folder with password | Calibrated - Benign | diagonalley 10.55.4.21 | encryptpotter.net\griphook | [ER6 CL0P Noise Step](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md) |

---

## :mag: Impact

### :loud_sound: Service Stop (T1489)

**Behavior:** User stops a batch of Windows services (`Bluetooth`, `BTAGService`, `OneSync`, `XblGameSave`, `WbioSrvc`). These are benign services commonly disabled for performance but can trigger the same detections as ransomware preparing for encryption.

**Commands / Activity:**

```powershell
Stop-Service -Name Bluetooth{TAB}
Stop-Service -Name BTAGService
Stop-Service -Name OneSync{TAB}
Stop-Service -Name XblGameSave
Stop-Service -Name WbioSrvc
```

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Impact | T1489 | PowerShell Stop-Service batch | Calibrated - Benign | lisa 10.222.25.65 | sonicbeats37.fm\sooyoung | [ER6 Ransomware Protections Test 3](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| Impact | T1489 | PowerShell Stop-Service batch | Calibrated - Benign | Windows victim workstation | encryptpotter.net user | [ER6 CL0P Step 4](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md) |

### :loud_sound: Inhibit System Recovery (T1490)

**Behavior:** User interacts with Volume Shadow Copies through symlinks and `vssadmin` add/create commands. Highly suspicious when combined with ransomware, but here framed as benign backup operations.

**Commands / Activity:**

```cmd
cmd /c mklink /D C:\Temp\vss \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

```cmd
vssadmin add shadowstorage /for=C: /on=C: /maxsize=UNBOUNDED
vssadmin create shadow /for=C:
```

| Tactic | Technique ID | Detection Criteria | Category | Host | User | Source Scenario |
| ------ | ------------ | ------------------ | -------- | ---- | ---- | --------------- |
| Impact | T1490 | mklink /D to \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\ | Calibrated - Benign | LockBit affiliate workstation | - | [ER6 LockBit Step 2](../Enterprise/lockbit/Emulation_Plan/ER6_LockBit_Scenario.md) |
| Impact | T1490 | vssadmin add shadowstorage / create shadow | Calibrated - Benign | LockBit affiliate workstation | - | [ER6 LockBit Step 4](../Enterprise/lockbit/Emulation_Plan/ER6_LockBit_Scenario.md) |

---

## :mag: User Activity (non-ATT&CK)

These noise elements are explicitly described in the scenarios as pure user interaction with the GUI or the browser, so no ATT&CK technique is cleanly associated. They are still part of the false-positive calibration window.

### :loud_sound: Browser activity

* Firefox search: `windows what services to stop to speed up`.
* Visit <https://www.komando.com/news/pc-speed-boost/843692/>.
* Firefox search: `powershell get win32_service only running`.
* Visit <https://superuser.com/questions/1136143/script-to-get-all-stopped-services-with-startup-type-automatic-windows>.
* Safari on macOS visits <https://www.jetbrains.com/idea/download/?section=mac> and downloads IntelliJ `.dmg` (Apple Silicon).

| Host | User | Source Scenario |
| ---- | ---- | --------------- |
| tentowers 10.26.4.102 | vale\tharlaw | [Scattered Spider Protections Test 6](../Enterprise/scattered_spider/Emulation_Plan/Protections_Test_6_Scenario.md) |
| itzy 10.222.25.70 | venom | [DPRK Protections Test 10](../Enterprise/dprk/Emulation_Plan/Protections.md) |
| hogshead 10.55.4.50 | ranrok | [ER6 DPRK Scenario Step 4](../Enterprise/dprk/Emulation_Plan/ER6_DPRK_Scenario.md) |

### :loud_sound: Document / text file creation

* Open Notepad, add the following lines and save as `C:\Users\Public\SupervisorNote.txt`:

```text
Create promotional material for worker morale. Add a new section to the company website.

Look into trouble coming from Dorne.
```

* Create `C:\Users\Public\hidden.txt` and `C:\Users\Public\original.txt` via Notepad.

| Host | User | Source Scenario |
| ---- | ---- | --------------- |
| tentowers 10.26.4.102 | vale\tharlaw | [Scattered Spider Protections Test 6](../Enterprise/scattered_spider/Emulation_Plan/Protections_Test_6_Scenario.md) |
| bts 10.222.25.61 | sonicbeats37.fm\yoona | [ER6 Ransomware Protections Test 2](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md) |
| vault713 10.55.3.100 | encryptpotter.net\ranrok | [ER6 CL0P Step 2](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md) |

### :loud_sound: Installer / GUI software interaction

* Run `.\TaskCoach` installer, accept defaults, install, then close the app.
* Install IntelliJ from the downloaded `.dmg`, then open IntelliJ.
* Open WordPad and leave it running during noise.
* Right-click > 7-ZIP > Extract Here with password `leakycauldron`.

| Host | User | Source Scenario |
| ---- | ---- | --------------- |
| tentowers 10.26.4.102 | vale\tharlaw | [Scattered Spider Protections Test 6](../Enterprise/scattered_spider/Emulation_Plan/Protections_Test_6_Scenario.md) |
| itzy 10.222.25.70 | venom | [DPRK Protections Test 10](../Enterprise/dprk/Emulation_Plan/Protections.md) |
| hogshead 10.55.4.50 | ranrok | [ER6 DPRK Scenario Step 4](../Enterprise/dprk/Emulation_Plan/ER6_DPRK_Scenario.md) |
| diagonalley 10.55.4.21, gobbledgook 10.55.4.22 | encryptpotter.net\griphook | [ER6 CL0P Noise Step](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md) |

---

## Appendix - Source Scenario Index

Reverse lookup: each scenario and the noise techniques it contributes.

### [Scattered Spider Protections Test 6 (NOISE ONLY)](../Enterprise/scattered_spider/Emulation_Plan/Protections_Test_6_Scenario.md)

> :information_source: Entire scenario is noise; originally documented to evaluate false positives in Enterprise 2025 ATT&CK Evaluations.

* T1053.005 Scheduled Task (`schtasks /create DailyTask`)
* T1057 Process Discovery (`tasklist /v`)
* T1016 System Network Configuration Discovery (`ipconfig /all`)
* T1021.001 RDP (`mstsc /v:10.26.3.101`)
* T1105 Ingress Tool Transfer (`curl -L` TaskCoach)
* T1059.003 Windows Command Shell (`.\TaskCoach`)
* T1082 System Information Discovery (`systeminfo | findstr`)
* User activity: Firefox browsing, Notepad `SupervisorNote.txt`, TaskCoach installer

### [ER6 Ransomware Protections](../Enterprise/protections/2024/Emulation_Plan/ER6_Ransomware_Protections.md)

* **Test 1 (line 32):** T1105 (curl UN CSVs), T1072 (choco chrome), T1021.001 (RDP EXO -> BLACKPINK)
* **Test 2 (line 129):** T1218.011 (rundll32 url.dll), T1059.003 (copy /b), T1027 (hidden.txt embed), T1546.012 (reg add IFEO msedge), user activity (Notepad files)
* **Test 3 (line 260):** T1082 (systeminfo|findstr), T1562.004 (netsh advfirewall off), T1007 (Get-WmiObject Win32_Service), T1489 (Stop-Service batch), T1614 (Get-WinSystemLocale), T1021.001 (RDP EXO -> ASIX)
* **Test 4 (line 366):** T1083 (Get-ChildItem), T1059.001 (Set-Location / New-Item / Remove-Item)
* **Test 5 (line 438, False Positive):** T1021.002 (net use Z: \\10.222.15.15), T1072 (choco 7zip), T1560.001 (7z archive), T1059.003 (move / rmdir)
* **Test 6 (line 565):** T1072 (choco profwiz, ldapadmin), T1021.001 (RDP BLACKPINK -> EXO)
* **Test 7 (line 643, False Positive):** T1072 (choco notepadplusplus, adobereader), T1021.002 (PsExec remote admin shares), T1570 (PsExec -c lateral copy), T1569.002 (PsExec service execution)
* **Test 8 (line 766):** T1021.002 (map SMB share), T1070 (clear recycle bin)

### [DPRK Protections](../Enterprise/dprk/Emulation_Plan/Protections.md)

* **Test 9 (line 27, False Positive):** T1021.005 (VNC itzy), T1059.002 (count_files.scpt in Script Editor)
* **Test 10 (line 155, False Positive):** T1021.005 (VNC itzy), T1105 (Safari IntelliJ dmg), T1072 (install IntelliJ)

### [ER6 DPRK Scenario](../Enterprise/dprk/Emulation_Plan/ER6_DPRK_Scenario.md)

* **Step 4 Collection (line 248):** T1021.005 (VNC hogshead), T1059.002 (count_files.scpt), T1105 (Safari IntelliJ dmg), T1072 (install IntelliJ)

### [ER6 CL0P Scenario](../Enterprise/cl0p/Emulation_Plan/ER6_CL0P_Scenario.md)

* **Step 2 (line 107):** T1218.011 (rundll32 url.dll), T1059.003 (copy /b), T1027 (hidden.txt embed), T1546.012 (reg add IFEO msedge)
* **Noise Step (line 212):** T1021.006 (Invoke-Command choco 7zip), T1072 (choco 7zip), T1560.001 (7-ZIP GUI xfer.zip), T1021.002 (drop xfer.zip on Z:), T1570 (xfer.zip lateral transfer)
* **Step 4 (line 298):** T1082 (systeminfo|findstr), T1562.004 (netsh advfirewall off), T1007 (Get-WmiObject Win32_Service), T1489 (Stop-Service batch), T1614 (Get-WinSystemLocale)

### [ER6 LockBit Scenario](../Enterprise/lockbit/Emulation_Plan/ER6_LockBit_Scenario.md)

* **Step 2 (line 162):** T1490 (mklink VSS), T1083 (Get-ChildItem), T1059.001 (New-Item / Remove-Item)
* **Step 4 (line 247):** T1490 (vssadmin add/create shadow), T1072 (choco profwiz, ldapadmin)
* **Step 7 (line 522):** T1021.002 (map SMB share, copy, disconnect), T1070 (clear recycle bin)
