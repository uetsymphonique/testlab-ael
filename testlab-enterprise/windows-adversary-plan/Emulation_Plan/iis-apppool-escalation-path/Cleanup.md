# Cleanup Guide

This guide removes files created during completed phases so the lab is ready for
another run. It is not intended to remove telemetry, logs, or forensic evidence.

## Phase 1 - Initial Access & Command and Control

### 1. Close dnscat2 sessions

On the attacker machine, terminate the sessions created from the IIS server.

```text
dnscat2> sessions
dnscat2> session -k <iis-server-system-session-id>
```

Stop the dnscat2 listener if Phase 1 is complete and no later phase depends on
the active C2 server.

### 2. Clean the IIS server

Run on `IIS01` / `react.testlab.local` as an administrator.

`CWLHerpaderping` deletes `CertCA.enc` automatically after reading it into memory.
The items below are included as a safety net in case Phase 1 was interrupted.

```powershell
$phase1ServerFiles = @(
    "C:\Windows\Temp\CertEnrollSvc.exe",
    "C:\ProgramData\CertCA.enc"
)

foreach ($path in $phase1ServerFiles) {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
}

Get-ChildItem -Path "C:\Windows\Temp" -Filter "HD*.tmp" -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue
```

Verify:

```powershell
$phase1ServerFiles | ForEach-Object {
    [pscustomobject]@{ Path = $_; Exists = Test-Path -LiteralPath $_ }
}
Get-ChildItem -Path "C:\Windows\Temp" -Filter "HD*.tmp" -ErrorAction SilentlyContinue
```

### 3. Optional Step 2 cleanup — Restore Windows Defender on IIS01

Run only if Optional Step 2 (Disable Windows Defender) was executed.

Run on `IIS01` as an administrator.

```powershell
Set-MpPreference -DisableRealtimeMonitoring 0 -DisableBehaviorMonitoring 0 -DisableScriptScanning 0

Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
    -Name "DisableAntiSpyware" -Force -ErrorAction SilentlyContinue
```

Verify:

```powershell
Get-MpPreference | Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableScriptScanning
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -ErrorAction SilentlyContinue
```

## Phase 2 - Discovery & Credential Access

Phase 2 reuses the elevated dnscat2 session from Phase 1. Do not close that
session here if the operator will continue into Phase 3.

### 1. Clean the IIS server

Run on `IIS01` / `react.testlab.local` as an administrator.

`wdhelper.exe` writes the LSASS dump to a randomised path (`C:\Windows\Temp\~DFxxxx.tmp`).
The dump is SYSTEM-owned; run the wildcard removal from an elevated session.

```powershell
$phase2ServerFiles = @(
    "C:\Windows\Temp\diaghost.exe",
    "C:\Windows\Temp\wdhelper.gz",
    "C:\Windows\Temp\wdhelper.exe"
)

foreach ($path in $phase2ServerFiles) {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
}

Get-ChildItem -Path "C:\Windows\Temp" -Filter "~DF*.tmp" -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue
```

If the EPERM workaround was used (dump copied to `C:\inetpub\react.testlab.local\`), also remove:

```powershell
Get-ChildItem -Path "C:\inetpub\react.testlab.local" -Filter "~DF*.tmp" -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue
```

Verify:

```powershell
$phase2ServerFiles | ForEach-Object {
    [pscustomobject]@{ Path = $_; Exists = Test-Path -LiteralPath $_ }
}
Get-ChildItem -Path "C:\Windows\Temp" -Filter "~DF*.tmp" -ErrorAction SilentlyContinue
```

### 2. Optional attacker-side cleanup

Remove downloaded dump and decrypted credential files if no longer needed.

```powershell
Remove-Item -LiteralPath ".\resources\payloads\react2shell-tool\wdhelper.gz" -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path ".\resources\payloads\react2shell-tool" -Filter "downloaded_~DF*.tmp" |
    Remove-Item -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath ".\lsass.dmp" -Force -ErrorAction SilentlyContinue
```

### 3. Optional Step 3B cleanup — comsvcs.dll LSASS dump

Run only if Optional Step 3B (Rundll32 + comsvcs.dll MiniDump) was executed.

Run on `IIS01` as an administrator.

```powershell
Remove-Item -LiteralPath "C:\Windows\Temp\g.dmp" -Force -ErrorAction SilentlyContinue
```

Remove from the attacker workspace:

```bash
rm -f downloaded_g.dmp
```

## Phase 3 - Lateral Movement, C2 Establishment & Persistence

Phase 3 creates persistence on `DC01`. Run this section when the operator is
tearing down the phase, not when continuing to test persistence recovery.

### 1. Close DC01 dnscat2 sessions

On the attacker machine, close the DC01 sessions created by WMI, SCM, WMI
persistence, logon script, and service persistence paths.

```text
dnscat2> sessions
dnscat2> session -k <dc01-session-id>
```

Repeat `session -k` for each DC01 session.

### 2. Remove domain backdoor account

Run on `DC01` as a domain administrator.

```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members "svcbackup" -Confirm:$false -ErrorAction SilentlyContinue
Remove-ADUser -Identity "svcbackup" -Confirm:$false -ErrorAction SilentlyContinue

Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" `
    -Name "svcbackup" -Force -ErrorAction SilentlyContinue
```

Verify:

```powershell
Get-ADUser -Identity "svcbackup" -ErrorAction SilentlyContinue
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" `
    -Name "svcbackup" -ErrorAction SilentlyContinue
```

### 3. Remove WMI permanent event subscription

Run on `DC01` as an administrator.

```powershell
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding |
    Where-Object { $_.Filter -like "*CertPolicyFilter*" -or $_.Consumer -like "*CertPolicyConsumer*" } |
    Remove-WmiObject

Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
    Where-Object { $_.Name -eq "CertPolicyConsumer" } |
    Remove-WmiObject

Get-WmiObject -Namespace root\subscription -Class __EventFilter |
    Where-Object { $_.Name -eq "CertPolicyFilter" } |
    Remove-WmiObject

Get-WmiObject -Namespace root\cimv2 -Class __IntervalTimerInstruction |
    Where-Object { $_.TimerID -eq "CertPolicyTimer" } |
    Remove-WmiObject
```

Verify:

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter |
    Where-Object { $_.Name -eq "CertPolicyFilter" }
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
    Where-Object { $_.Name -eq "CertPolicyConsumer" }
```

### 4. Remove GPO logon script artifact

Run on `DC01` as a domain administrator.

Determine the pre-attack state before proceeding. The appropriate cleanup path
depends on the state of `gPCUserExtensionNames` and `scripts.ini` before Step 13
was executed.

#### Case A - `gPCUserExtensionNames` was NULL

Use this path for a clean environment with no prior logon scripts.

```powershell
Remove-Item -LiteralPath "C:\Windows\SYSVOL\sysvol\testlab.local\scripts\update.exe" -Force -ErrorAction SilentlyContinue

$scriptRoot = "C:\Windows\SYSVOL\sysvol\testlab.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\User\Scripts"
Remove-Item -LiteralPath "$scriptRoot\scripts.ini" -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "$scriptRoot\Logon" -Recurse -Force -ErrorAction SilentlyContinue

$dn = "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=testlab,DC=local"
$v = (Get-ADObject $dn -Properties versionNumber).versionNumber
Set-ADObject $dn -Clear gPCUserExtensionNames -Replace @{versionNumber = ($v + 65536)}

$gpt = "C:\Windows\SYSVOL\sysvol\testlab.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.ini"
$v = [int]([regex]::Match((Get-Content -LiteralPath $gpt -Raw), "Version=(\d+)").Groups[1].Value)
(Get-Content -LiteralPath $gpt) -replace "Version=$v", "Version=$($v + 65536)" |
    Set-Content -LiteralPath $gpt -Encoding ASCII
```

#### Case B - Other User CSEs existed but no logon script was configured

Remove the Scripts CSE block from `gPCUserExtensionNames` while preserving other
CSE entries; delete `scripts.ini` entirely.

```powershell
Remove-Item -LiteralPath "C:\Windows\SYSVOL\sysvol\testlab.local\scripts\update.exe" -Force -ErrorAction SilentlyContinue

$scriptRoot = "C:\Windows\SYSVOL\sysvol\testlab.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\User\Scripts"
Remove-Item -LiteralPath "$scriptRoot\scripts.ini" -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "$scriptRoot\Logon" -Recurse -Force -ErrorAction SilentlyContinue

$dn = "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=testlab,DC=local"
$obj = Get-ADObject $dn -Properties gPCUserExtensionNames,versionNumber
$cleaned = [regex]::Replace(
    [string]$obj.gPCUserExtensionNames,
    "\[\{42B5FAAE-6536-11D2-AE5A-0000F87571E3\}\{40B66650-4972-11D1-A7CA-0000F87571E3\}\]",
    ""
)
if ($cleaned) {
    Set-ADObject $dn -Replace @{gPCUserExtensionNames = $cleaned; versionNumber = ($obj.versionNumber + 65536)}
} else {
    Set-ADObject $dn -Clear gPCUserExtensionNames -Replace @{versionNumber = ($obj.versionNumber + 65536)}
}

$gpt = "C:\Windows\SYSVOL\sysvol\testlab.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.ini"
$v = [int]([regex]::Match((Get-Content -LiteralPath $gpt -Raw), "Version=(\d+)").Groups[1].Value)
(Get-Content -LiteralPath $gpt) -replace "Version=$v", "Version=$($v + 65536)" |
    Set-Content -LiteralPath $gpt -Encoding ASCII
```

#### Case C - Logon scripts already existed before attack

Only remove the specific `update.exe` entry appended to `scripts.ini`. Leave
`gPCUserExtensionNames` intact because the Scripts CSE was already present before
the attack.

```powershell
Remove-Item -LiteralPath "C:\Windows\SYSVOL\sysvol\testlab.local\scripts\update.exe" -Force -ErrorAction SilentlyContinue

$scriptIni = "C:\Windows\SYSVOL\sysvol\testlab.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\User\Scripts\scripts.ini"
$raw = Get-Content -LiteralPath $scriptIni -Raw -Encoding Unicode
$cleaned = [regex]::Replace(
    $raw,
    "\d+CmdLine=\\\\testlab\.local\\SYSVOL\\testlab\.local\\scripts\\update\.exe\r?\n\d+Parameters=[^\r\n]*\r?\n",
    ""
)
[System.IO.File]::WriteAllText($scriptIni, $cleaned, [System.Text.Encoding]::Unicode)

$dn = "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=testlab,DC=local"
$v = (Get-ADObject $dn -Properties versionNumber).versionNumber
Set-ADObject $dn -Replace @{versionNumber = ($v + 65536)}

$gpt = "C:\Windows\SYSVOL\sysvol\testlab.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.ini"
$v = [int]([regex]::Match((Get-Content -LiteralPath $gpt -Raw), "Version=(\d+)").Groups[1].Value)
(Get-Content -LiteralPath $gpt) -replace "Version=$v", "Version=$($v + 65536)" |
    Set-Content -LiteralPath $gpt -Encoding ASCII
```

### 5. Remove service persistence

Run on `DC01` as an administrator.

```powershell
C:\ProgramData\ServiceInstaller.exe stop CertPolicyHost
C:\ProgramData\ServiceInstaller.exe uninstall CertPolicyHost

C:\ProgramData\NtServiceInstaller.exe stop CertPolicyCache
C:\ProgramData\NtServiceInstaller.exe uninstall CertPolicyCache
```

Verify:

```powershell
Get-Service -Name CertPolicyHost,CertPolicyCache -ErrorAction SilentlyContinue
Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\CertPolicyCache"
Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\CertPolicyHost"
```

### 6. Clean DC01 dropped files

Run on `DC01` as an administrator.

`CertCA.enc` is deleted automatically by CWLHerpaderping at Phase 3 runtime; it is
included here as a safety net in case execution was interrupted.

```powershell
$phase3DcFiles = @(
    "C:\ProgramData\CertCA.enc",
    "C:\ProgramData\CertEnrollAgent.exe",
    "C:\ProgramData\policyupdate.exe",
    "C:\ProgramData\policysync.exe",
    "C:\ProgramData\ServiceInstaller.exe",
    "C:\ProgramData\NtServiceInstaller.exe"
)

foreach ($path in $phase3DcFiles) {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
}

Get-ChildItem -Path "C:\Windows\Temp" -Filter "HD*.tmp" -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue
```

Verify:

```powershell
$phase3DcFiles | ForEach-Object {
    [pscustomobject]@{ Path = $_; Exists = Test-Path -LiteralPath $_ }
}
Get-ChildItem -Path "C:\Windows\Temp" -Filter "HD*.tmp" -ErrorAction SilentlyContinue
```

### 7. Clean IIS01 staging files

Run on `IIS01` / `react.testlab.local` as an administrator.

`policyupdate.bin`, `policysync.bin`, `ServiceInstaller.bin`, and `NtServiceInstaller.bin`
are the raw staged names on IIS01 — they are transferred to DC01 as `.exe` but remain as
`.bin` on IIS01 because the staging step does not rename them.

```powershell
$phase3IisFiles = @(
    "C:\ProgramData\CertCA.enc",
    "C:\ProgramData\CertEnrollAgent.exe",
    "C:\ProgramData\go-thehash.exe",
    "C:\ProgramData\policyupdate.bin",
    "C:\ProgramData\policysync.bin",
    "C:\ProgramData\ServiceInstaller.bin",
    "C:\ProgramData\NtServiceInstaller.bin"
)

foreach ($path in $phase3IisFiles) {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
}
```

Verify:

```powershell
$phase3IisFiles | ForEach-Object {
    [pscustomobject]@{ Path = $_; Exists = Test-Path -LiteralPath $_ }
}
```

## Phase 4 - Collection & Exfiltration

Phase 4 does not create persistent C2 or persistence artifacts. All cleanup targets
staged files on DC01 and IIS01. The `certstore.cmd` files in NETLOGON and the IIS01
web root are deleted inline at the end of Phase 4 Step 2; run Sections 2 and 3 below
only if those inline deletions were skipped.

### 1. Clean DC01 collection staging directory and archives

Run on `DC01` as an administrator.

`certstore.cmd` is the primary output of `PolicySyncSvc.exe`. The `certstore.ddf` and
`certstore.cab` entries apply only if the alternative Step 1B (makecab LOLBin) was run.

```powershell
$phase4DcFiles = @(
    "C:\ProgramData\PolicySyncSvc.exe",
    "C:\ProgramData\certstore.cmd",
    "C:\ProgramData\certstore.ddf",
    "C:\ProgramData\certstore.cab"
)

foreach ($path in $phase4DcFiles) {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
}

Remove-Item -LiteralPath "C:\ProgramData\CertStore" -Recurse -Force -ErrorAction SilentlyContinue
```

Verify:

```powershell
$phase4DcFiles | ForEach-Object {
    [pscustomobject]@{ Path = $_; Exists = Test-Path -LiteralPath $_ }
}
Test-Path -LiteralPath "C:\ProgramData\CertStore"
```

### 2. Clean DC01 NETLOGON staging file (if inline cleanup was skipped)

Run on `DC01` as an administrator.

```powershell
Remove-Item -LiteralPath "C:\Windows\SYSVOL\sysvol\testlab.local\scripts\certstore.cmd" -Force -ErrorAction SilentlyContinue
```

### 3. Clean IIS01 web root staging file (if inline cleanup was skipped)

Run on `IIS01` as an administrator.

```powershell
Remove-Item -LiteralPath "C:\inetpub\react.testlab.local\certstore.cmd" -Force -ErrorAction SilentlyContinue
```

### 4. Clean IIS01 temp files

Run on `IIS01` as an administrator.

```powershell
$phase4IisFiles = @(
    "C:\Windows\Temp\PolicySyncSvc.exe"
)

foreach ($path in $phase4IisFiles) {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
}
```

Verify:

```powershell
$phase4IisFiles | ForEach-Object {
    [pscustomobject]@{ Path = $_; Exists = Test-Path -LiteralPath $_ }
}
```

### 5. Optional attacker-side cleanup

Remove the downloaded archive and extracted credential files from the attacker workspace.
The decryption script deletes `certstore.zip` automatically; `certstore.cmd` and the
`certstore/` directory remain.

```bash
rm -f resources/payloads/react2shell-tool/certstore.cmd
rm -rf certstore/
```

## Phase 5 - Impact: Data Encryption and Internal Defacement

Phase 5 makes several changes that require manual reversal. Clean in this order:
restore encrypted database files from backup → restart MSSQL service → remove backup
files → remove registry values → remove ransom notes → restore defaced web page.

VSS shadow copies deleted in Step 1 cannot be reversed by command — recreate them
manually or restore from a VM snapshot if a clean recovery-test environment is required.

### 1. Restore encrypted database files on IIS01

Step 1 of Phase 5 overwrites `UploadPortalDB.mdf` and `UploadPortalDB_log.ldf` in
place with AES-256 ciphertext. Backup copies were saved to `C:\Windows\Temp\` before
encryption. Restore them before restarting the service.

Run on `IIS01` as an administrator.

```powershell
$dataPath = "C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA"

Copy-Item "$env:windir\Temp\UploadPortalDB.mdf.backup"     "$dataPath\UploadPortalDB.mdf"     -Force
Copy-Item "$env:windir\Temp\UploadPortalDB_log.ldf.backup" "$dataPath\UploadPortalDB_log.ldf" -Force
```

Verify the restored files match the original backup sizes (8,388,608 bytes):

```powershell
$dataPath = "C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA"

Get-Item "$dataPath\UploadPortalDB.mdf", "$dataPath\UploadPortalDB_log.ldf" |
    Select-Object Name, Length, LastWriteTime
```

### 2. Restart MSSQL service on IIS01

Run on `IIS01` as an administrator.

```powershell
sc.exe start MSSQL`$SQLEXPRESS
```

Verify the service is running and `UploadPortalDB` is accessible:

```powershell
Get-Service -Name "MSSQL`$SQLEXPRESS" | Select-Object Name, Status

& "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\180\Tools\Binn\SQLCMD.EXE" `
    -S "localhost\SQLEXPRESS" -E -C `
    -Q "SELECT name, state_desc FROM sys.databases WHERE name = 'UploadPortalDB'"
# Expected: state_desc = ONLINE
```

### 3. Remove backup files from IIS01

Run on `IIS01` as an administrator.

```powershell
Remove-Item -LiteralPath "C:\Windows\Temp\UploadPortalDB.mdf.backup"     -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "C:\Windows\Temp\UploadPortalDB_log.ldf.backup" -Force -ErrorAction SilentlyContinue
```

Verify:

```powershell
Test-Path "C:\Windows\Temp\UploadPortalDB.mdf.backup"
Test-Path "C:\Windows\Temp\UploadPortalDB_log.ldf.backup"
# Both expected: False
```

### 4. Remove CertMaint staged files from IIS01

Run on `IIS01` as an administrator.

`CertMaint.bin` is renamed to `CertMaint.exe` during staging — only the `.exe` remains on disk.

```powershell
Remove-Item -LiteralPath "C:\ProgramData\CertMaint.exe" -Force -ErrorAction SilentlyContinue
```

Verify:

```powershell
Test-Path -LiteralPath "C:\ProgramData\CertMaint.exe"
# Expected: False
```

### 5. Remove logon-screen registry defacement on DC01

Run on `DC01` as an administrator.

```powershell
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "LegalNoticeCaption" -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "LegalNoticeText" -Force -ErrorAction SilentlyContinue
```

Verify:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |
    Select-Object LegalNoticeCaption, LegalNoticeText
# Both expected: empty / not present
```

### 6. Remove ransom notes on DC01

Run on `DC01` as an administrator.

```powershell
$phase5DcFiles = @(
    "C:\README_DECRYPT.txt",
    "C:\Users\Administrator\Desktop\README_DECRYPT.txt"
)

foreach ($path in $phase5DcFiles) {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
}
```

Verify:

```powershell
$phase5DcFiles | ForEach-Object {
    [pscustomobject]@{ Path = $_; Exists = Test-Path -LiteralPath $_ }
}
# Both expected: False
```

### 7. Remove defaced web page on IIS01

The react2shell eval channel created `index.html` in the upload portal web root. The
original landing page is `Default.aspx`; deleting the attacker-created `index.html`
restores IIS to serving `Default.aspx` as the default document.

Run on `IIS01` as an administrator.

```powershell
Remove-Item -LiteralPath "C:\inetpub\upload.testlab.local\index.html" -Force -ErrorAction SilentlyContinue
```

Verify:

```powershell
Test-Path -LiteralPath "C:\inetpub\upload.testlab.local\index.html"
# Expected: False

Invoke-WebRequest -Uri "http://upload.testlab.local/" -UseBasicParsing |
    Select-Object StatusCode, @{N="Title"; E={($_.Content -split '<title>|</title>')[1]}}
# Expected: original upload portal title, not "ENCRYPTED"
```

### 8. Non-reversible changes — restore from VM snapshot if needed

The following Phase 5 change cannot be reversed by command:

- **VSS shadows deleted** — `vssapi.dll` COM call removes all volume
  snapshots; they cannot be recreated retroactively. Recreate manually with
  `vssadmin create shadow /for=C:` or restore `IIS01` from a pre-Phase-5 VM snapshot.

If a fully clean lab state is required for another Phase 5 run, restore `IIS01` from a
VM snapshot taken before Phase 5 execution.
