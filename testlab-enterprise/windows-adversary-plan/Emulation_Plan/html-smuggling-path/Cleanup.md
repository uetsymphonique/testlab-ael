# Cleanup Guide

This guide removes files created during completed phases so the lab is ready for
another run. It is not intended to remove telemetry, logs, or forensic evidence.

## Phase 1 - Initial Access & Command and Control

### 1. Close dnscat2 sessions

On the attacker machine, terminate the sessions created from the workstation path.

```text
dnscat2> sessions
dnscat2> session -k <workstation-session-id>
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

### 3. Clean uploaded files from `upload.testlab.local`

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
