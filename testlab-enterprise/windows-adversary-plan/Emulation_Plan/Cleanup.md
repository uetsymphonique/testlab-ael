# Cleanup Guide

This guide removes files created during completed phases so the lab is ready for
another run. It is not intended to remove telemetry, logs, or forensic evidence.

## Phase 1 - Initial Access & Command and Control

### 1. Close dnscat2 sessions

On the attacker machine, terminate the sessions created from the workstation and
IIS server paths.

```text
dnscat2> sessions
dnscat2> session -k <workstation-session-id>
dnscat2> session -k <iis-server-system-session-id>
```

Stop the dnscat2 listener if Phase 1 is complete and no later phase depends on
the active C2 server.

### 2. Clean the victim workstation

Run on the workstation used for the drive-by / HTA path.

```powershell
$phase1WorkstationFiles = @(
    "$env:USERPROFILE\Downloads\cert_bundle.txt",
    "$env:TEMP\hpsolutionsportal.bin",
    "$env:TEMP\hpsolutionsportal.hta",
    "C:\ProgramData\CertCA.bin",
    "$env:APPDATA\Microsoft\Windows\CertEnrollAgent.bin",
    "$env:APPDATA\Microsoft\Windows\CertEnrollAgent.exe"
)

foreach ($path in $phase1WorkstationFiles) {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
}

Get-ChildItem -Path $env:TEMP -Filter "HD*.tmp" -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue
```

Verify:

```powershell
$phase1WorkstationFiles | ForEach-Object {
    [pscustomobject]@{ Path = $_; Exists = Test-Path -LiteralPath $_ }
}
Get-ChildItem -Path $env:TEMP -Filter "HD*.tmp" -ErrorAction SilentlyContinue
```

### 3. Clean the IIS server

Run on `IIS01` / `react.testlab.local` as an administrator.

```powershell
$phase1ServerFiles = @(
    "C:\Windows\Temp\CertEnrollSvc.b64",
    "C:\Windows\Temp\CertEnrollSvc.bin",
    "C:\Windows\Temp\CertEnrollSvc.exe",
    "C:\Windows\Temp\dnscat2.b64",
    "C:\Windows\Temp\CertEnrollAgent.b64",
    "C:\ProgramData\CertCA.bin",
    "C:\ProgramData\CertEnrollAgent.bin",
    "C:\ProgramData\CertEnrollAgent.exe"
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

### 4. Clean uploaded files from `upload.testlab.local`

Run on `IIS01` as an administrator. The upload site path is defined in setup as
`C:\inetpub\upload.testlab.local\uploads`.

```powershell
$phase1UploadedFiles = @(
    "C:\inetpub\upload.testlab.local\uploads\staging.html",
    "C:\inetpub\upload.testlab.local\uploads\dnscat2.exe",
    "C:\inetpub\upload.testlab.local\uploads\CWLHerpaderping.exe"
)

foreach ($path in $phase1UploadedFiles) {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
}
```

Verify:

```powershell
$phase1UploadedFiles | ForEach-Object {
    [pscustomobject]@{ Path = $_; Exists = Test-Path -LiteralPath $_ }
}
```

### 5. Optional attacker-side cleanup

If the generated React RCE upload blobs are no longer needed, remove them from
the attacker workspace.

```powershell
Remove-Item -LiteralPath ".\resources\payloads\react2shell-tool\CertEnrollSvc.b64" -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath ".\resources\payloads\react2shell-tool\dnscat2.b64" -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath ".\resources\payloads\react2shell-tool\CertEnrollAgent.b64" -Force -ErrorAction SilentlyContinue
```

## Phase 2 - Discovery & Credential Access

Phase 2 reuses the elevated dnscat2 session from Phase 1. Do not close that
session here if the operator will continue into Phase 3.

### 1. Clean the IIS server

Run on `IIS01` / `react.testlab.local` as an administrator.

```powershell
$phase2ServerFiles = @(
    "C:\Windows\Temp\WdiBoot.b64",
    "C:\Windows\Temp\WdiBoot.bin",
    "C:\Windows\Temp\WdiBoot.exe",
    "C:\Windows\Temp\f.elif",
    "C:\inetpub\react.testlab.local\f.elif"
)

foreach ($path in $phase2ServerFiles) {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
}
```

Verify:

```powershell
$phase2ServerFiles | ForEach-Object {
    [pscustomobject]@{ Path = $_; Exists = Test-Path -LiteralPath $_ }
}
```

### 2. Optional attacker-side cleanup

Remove local files generated or downloaded during the LSASS dump workflow if the
operator no longer needs them.

```powershell
Remove-Item -LiteralPath ".\resources\payloads\react2shell-tool\WdiBoot.b64" -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath ".\resources\payloads\react2shell-tool\downloaded_f.elif" -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath ".\resources\payloads\react2shell-tool\lsass.dmp" -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath ".\downloaded_f.elif" -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath ".\lsass.dmp" -Force -ErrorAction SilentlyContinue
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
```

Verify:

```powershell
Get-ADUser -Identity "svcbackup" -ErrorAction SilentlyContinue
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

```powershell
$phase3DcFiles = @(
    "C:\ProgramData\CertCA.bin",
    "C:\ProgramData\CertEnrollAgent.exe",
    "C:\ProgramData\dnscat2.exe",
    "C:\ProgramData\dnscat-service.exe",
    "C:\ProgramData\ServiceInstaller.exe",
    "C:\ProgramData\NtServiceInstaller.exe",
    "C:\Windows\Temp\ls.txt"
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

```powershell
$phase3IisFiles = @(
    "C:\Windows\Temp\dnscat2.b64",
    "C:\Windows\Temp\CertEnrollAgent.b64",
    "C:\Windows\Temp\go-thehash.b64",
    "C:\Windows\Temp\ServiceInstaller.b64",
    "C:\Windows\Temp\NtServiceInstaller.b64",
    "C:\ProgramData\CertCA.bin",
    "C:\ProgramData\CertEnrollAgent.bin",
    "C:\ProgramData\CertEnrollAgent.exe",
    "C:\ProgramData\dnscat2.exe",
    "C:\ProgramData\dnscat-service.exe",
    "C:\ProgramData\go-thehash.bin",
    "C:\ProgramData\go-thehash.exe",
    "C:\ProgramData\ServiceInstaller.exe",
    "C:\ProgramData\NtServiceInstaller.exe"
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

### 8. Optional attacker-side cleanup

Remove encoded payloads and local verification output if the operator no longer
needs them.

```powershell
Remove-Item -LiteralPath ".\resources\payloads\react2shell-tool\dnscat2.b64" -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath ".\resources\payloads\react2shell-tool\CertEnrollAgent.b64" -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath ".\resources\payloads\react2shell-tool\go-thehash.b64" -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath ".\resources\payloads\react2shell-tool\ServiceInstaller.b64" -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath ".\resources\payloads\react2shell-tool\NtServiceInstaller.b64" -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath ".\ls.txt" -Force -ErrorAction SilentlyContinue
```
