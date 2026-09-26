# Cleanup

Reverse-order cleanup: Phase 4 → Phase 1, then controlServer/attacker-side. Each section assumes the prior phase's cleanup has **not** yet run - skip any step where the artifact was already removed during the phase itself.

> Run cleanup **after** all detection telemetry and evidence screenshots are collected. Cleanup commands use the same channels as the emulation (xprun/xprun-out, xpexec, xpfile, TONESHELL shell) - confirm channels are still active before starting.

---

## Quick Cleanup via Direct RDP

When you can RDP into each lab host directly (e.g. post-evaluation, or C2 channels are already dead), run these scripts as **Administrator** on each host. This replaces the per-phase channel-based cleanup below.

### DC01 (RDP as TESTLAB\Administrator)

```bat
@echo off
echo [*] DC01 cleanup starting...

:: Kill pipe agents (WMI-launched console agent + SCM-launched service agent)
taskkill /F /IM smbpipe-agent.exe 2>nul
taskkill /F /IM smbpipe-agent-svc.exe 2>nul

:: Remove persistence service via built-in uninstall (NT native API cleanup)
C:\Windows\Temp\NtServiceInstaller.exe uninstall OracleXAService 2>nul

:: Delete tool binaries
del /f /q C:\Windows\Temp\smbpipe-agent.exe 2>nul
del /f /q C:\Windows\Temp\smbpipe-agent-svc.exe 2>nul
del /f /q C:\Windows\Temp\PolicySyncSvc.exe 2>nul
del /f /q C:\Windows\Temp\NtServiceInstaller.exe 2>nul

:: Delete NTDS container + staging
del /f /q C:\ProgramData\certstore.cmd 2>nul
rmdir /s /q C:\ProgramData\CertStore 2>nul

:: Delete stale VSS shadows
vssadmin delete shadows /all /quiet 2>nul

echo [+] DC01 cleanup done.
```

### IIS01 (RDP as TESTLAB\Administrator)

```bat
@echo off
echo [*] IIS01 cleanup starting...

:: Revert the firewall rule widened in Phase 2 Step 6 (before deleting FwPolicySvc.exe)
netsh advfirewall firewall set rule name="SQL Server (TCP 1433)" new profile=domain

:: Delete all staged binaries
del /f /q C:\ProgramData\go-thehash.exe 2>nul
del /f /q C:\ProgramData\smbpipe-agent.exe 2>nul
del /f /q C:\ProgramData\smbpipe-agent-svc.exe 2>nul
del /f /q C:\ProgramData\PolicySyncSvc.exe 2>nul
del /f /q C:\ProgramData\NtServiceInstaller.exe 2>nul
del /f /q C:\ProgramData\CertEnrollSvc.exe 2>nul
del /f /q C:\ProgramData\ReflectDump.exe 2>nul
del /f /q C:\ProgramData\FwPolicySvc.exe 2>nul
del /f /q C:\ProgramData\fwp_out.txt 2>nul
del /f /q C:\ProgramData\fwp_rev.txt 2>nul

:: Delete dump/temp/output files
del /f /q C:\ProgramData\DF*.tmp 2>nul
del /f /q C:\ProgramData\rdump_out.txt 2>nul
del /f /q C:\ProgramData\sys_out.txt 2>nul
del /f /q C:\ProgramData\certstore.cmd 2>nul
del /f /q C:\ProgramData\*.stl 2>nul

echo [*] Resetting MSSQL configuration...
sqlcmd -S localhost\SQLEXPRESS -E -C -Q "EXECUTE AS LOGIN='sa';IF DB_ID('xpagent') IS NOT NULL DROP DATABASE xpagent;"
sqlcmd -S localhost\SQLEXPRESS -E -C -Q "EXECUTE AS LOGIN='sa';EXEC sp_configure 'xp_cmdshell',0;RECONFIGURE;EXEC sp_configure 'Ole Automation Procedures',0;RECONFIGURE;"
sqlcmd -S localhost\SQLEXPRESS -E -C -Q "EXECUTE AS LOGIN='sa';REVOKE ADMINISTER BULK OPERATIONS FROM [svc_app_dev];"
sqlcmd -S localhost\SQLEXPRESS -E -C -Q "EXECUTE AS LOGIN='sa';IF OBJECT_ID('tempdb..stg','U') IS NOT NULL DROP TABLE tempdb..stg;IF OBJECT_ID('tempdb..exfil','U') IS NOT NULL DROP TABLE tempdb..exfil;"

echo [+] IIS01 cleanup done.
```

### WS01 (RDP as TESTLAB\labuser)

```bat
@echo off
echo [*] WS01 cleanup starting...

:: Kill TONESHELL processes
taskkill /F /IM waitfor.exe 2>nul
taskkill /F /IM EssosUpdate.exe 2>nul

:: Delete extraction directory, ZIP, and lure
rmdir /s /q "C:\Users\labuser\Downloads\250325_Pentos_Board_Minutes" 2>nul
del /f /q "C:\Users\labuser\Downloads\250325_Pentos_Board_Minutes.zip" 2>nul
del /f /q "C:\Users\labuser\Desktop\Braavos_Competitiveness_Brief.docx" 2>nul
del /f /q "C:\Users\labuser\Desktop\Essos_Compliance_Update.docx" 2>nul

:: Delete HTML smuggling artifacts (Step 1C variant)
del /f /q "C:\Users\labuser\Downloads\Essos_Compliance_Update.cer" 2>nul
del /f /q "C:\Users\labuser\AppData\Local\Temp\Essos_Compliance_Update.bin" 2>nul
del /f /q "C:\Users\labuser\AppData\Local\Temp\Essos_Compliance_Update.hta" 2>nul
del /f /q "C:\Users\labuser\AppData\Local\Temp\EssosUpdate.exe" 2>nul
del /f /q "C:\Users\labuser\AppData\Local\Temp\wsdapi.dll" 2>nul

:: Delete BITS downloader and clear any residual BITS job queue (Step 1B variant)
del /f /q "C:\Users\labuser\Downloads\BitsDownloader.exe" 2>nul
bitsadmin /reset /allusers >nul 2>&1

:: Delete TONESHELL persistence file
del /f /q "%USERPROFILE%\AppData\Roaming\Microsoft\Web.CompressShaders.config" 2>nul

:: Delete TONESHELL log files (TONESHELL_LOG_DIR = C:\Windows\Temp)
del /f /q C:\Windows\Temp\wsdapih.log 2>nul
del /f /q C:\Windows\Temp\wsdapisr.log 2>nul
del /f /q C:\Windows\Temp\wsdapi_dat.log 2>nul
del /f /q C:\Windows\Temp\toneshell_shellcode.log 2>nul

:: Clean temp staging residuals
del /f /q C:\Windows\Temp\WNetHelper.exe 2>nul
del /f /q C:\Windows\Temp\credvault.exe 2>nul
del /f /q C:\Windows\Temp\*.stl 2>nul
del /f /q C:\Windows\Temp\*.sql 2>nul
del /f /q C:\Windows\Temp\*.hex* 2>nul

echo [+] WS01 cleanup done.
```

> After running the three scripts above, skip to the [Attacker / ControlServer Side](#attacker--controlserver-side) section and then run the [Verification Checklist](#verification-checklist).

---

## Per-Phase Cleanup via C2 Channels

Use this path when C2 channels are still active and direct RDP is not available (e.g. mid-evaluation reset).

---

## Phase 4 - DC01 Artifacts

### 4a. Kill smbpipe-agent processes on DC01

Two pipe agents may still be running: the WMI-launched console agent (`smbpipe-agent.exe`, from Step 3) and the SCM-launched service agent (`smbpipe-agent-svc.exe`, from Step 3B - running detached as `NT AUTHORITY\SYSTEM`). Kill both before removing binaries.

```
xprun-out C:\ProgramData\go-thehash.exe pipe DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a oraclexa "taskkill /F /IM smbpipe-agent.exe"
xprun-out C:\ProgramData\go-thehash.exe pipe DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a oraclexa_svc "taskkill /F /IM smbpipe-agent-svc.exe"
```

> The transient SCM service registration (`<random-12-char>`) is deleted by `go-thehash exec` itself (`DeleteService`) and needs no cleanup. The `\\.\pipe\oraclexa_svc` pipe disappears when its owning process dies.
>
> If a pipe channel is unresponsive (agent already dead), use WMI:
>
> ```
> xprun C:\ProgramData\go-thehash.exe exec-wmi DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a "cmd /c taskkill /F /IM smbpipe-agent.exe & taskkill /F /IM smbpipe-agent-svc.exe"
> ```

### 4b. Remove OracleXAService via NtServiceInstaller uninstall on DC01

NtServiceInstaller.exe has a built-in `uninstall` command that reverses the registry-backed service creation via the same NT native APIs. Use it before deleting the tool binary.

```
xprun-out C:\ProgramData\go-thehash.exe pipe DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a oraclexa "C:\Windows\Temp\NtServiceInstaller.exe uninstall OracleXAService"
```

> If the pipe agent is already dead, use WMI:
>
> ```
> xprun C:\ProgramData\go-thehash.exe exec-wmi DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a "C:\Windows\Temp\NtServiceInstaller.exe uninstall OracleXAService"
> ```

### 4c. Delete tool binaries from DC01

```
xprun C:\ProgramData\go-thehash.exe exec-wmi DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a "cmd /c del /f C:\Windows\Temp\smbpipe-agent.exe C:\Windows\Temp\smbpipe-agent-svc.exe C:\Windows\Temp\PolicySyncSvc.exe C:\Windows\Temp\NtServiceInstaller.exe"
```

### 4d. Delete NTDS container from DC01

If `certstore.cmd` was not already removed during exfil:

```
xprun C:\ProgramData\go-thehash.exe exec-wmi DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a "cmd /c del /f C:\ProgramData\certstore.cmd"
```

### 4e. Delete VSS shadow copy remnants on DC01

PolicySyncSvc.exe's `--cleanup` flag should have deleted the shadow copy. Verify and clean any stale shadows:

```
xprun C:\ProgramData\go-thehash.exe exec-wmi DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a "cmd /c vssadmin delete shadows /all /quiet"
```

### 4f. Delete CertStore staging directory on DC01

If `--cleanup` did not remove it:

```
xprun C:\ProgramData\go-thehash.exe exec-wmi DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a "cmd /c rmdir /s /q C:\ProgramData\CertStore"
```

### 4g. Delete Phase 4 staged binaries from IIS01

```
xpfile del C:\ProgramData\go-thehash.exe
xpfile del C:\ProgramData\smbpipe-agent.exe
xpfile del C:\ProgramData\smbpipe-agent-svc.exe
xpfile del C:\ProgramData\PolicySyncSvc.exe
xpfile del C:\ProgramData\NtServiceInstaller.exe
```

### 4h. Delete certstore.cmd from IIS01

If the exfil download left it on IIS01:

```
xpfile del C:\ProgramData\certstore.cmd
```

---

## Phase 3 - IIS01 Credential Dump Artifacts

### 3a. Delete ReflectDump.exe from IIS01

```
xpfile del C:\ProgramData\ReflectDump.exe
```

### 3b. Delete dump file and output redirect (if not already cleaned in Phase 3 Step 3)

> Both files are owned by `NT AUTHORITY\SYSTEM` (created via `CreateProcessWithTokenW`). `xpfile del` returns `0x800A0046` Permission Denied — requires EfsPotato SYSTEM escalation.

```
xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c del /f C:\ProgramData\DF*.tmp" lsarpc
xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c del /f C:\ProgramData\rdump_out.txt" lsarpc
```

### 3c. Drop tempdb..exfil table (if not already dropped)

```python
# In toneshell_shell.py - via the existing MSSQL channel
```

```sql
EXECUTE AS LOGIN='sa';
IF OBJECT_ID('tempdb..exfil','U') IS NOT NULL DROP TABLE tempdb..exfil;
```

---

## Phase 2 - Collection, IIS01 MSSQL & Privilege Escalation Artifacts

### 2a. Revert the `SQL Server (TCP 1433)` firewall rule to Domain-only

Step 6 widened the rule to all profiles (`0x7FFFFFFF`). Restore the baseline **before** deleting `FwPolicySvc.exe` (the tool is the revert mechanism) and before deleting `CertEnrollSvc.exe` (the SYSTEM chain the revert runs through).

```
xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c C:\ProgramData\FwPolicySvc.exe setprofiles \"SQL Server (TCP 1433)\" domain > C:\ProgramData\fwp_rev.txt 2>&1" lsarpc
xpfile cat C:\ProgramData\fwp_rev.txt
```

> Expected: `[+] rule 'SQL Server (TCP 1433)' profiles set to domain (0x1)`. If `FwPolicySvc.exe` is already gone, revert from an elevated shell instead: `netsh advfirewall firewall set rule name="SQL Server (TCP 1433)" new profile=domain`.

### 2b. Delete FwPolicySvc.exe and fwp_out.txt from IIS01

> Both files are owned by `NT AUTHORITY\SYSTEM` (created/dispatched through the EfsPotato SYSTEM chain). `xpfile del` returns `0x800A0046` Permission Denied — requires the same SYSTEM escalation used in Step 6.

```
xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c del /f C:\ProgramData\fwp_out.txt C:\ProgramData\fwp_rev.txt C:\ProgramData\FwPolicySvc.exe" lsarpc
```

### 2c. Delete CertEnrollSvc.exe from IIS01

```
xpfile del C:\ProgramData\CertEnrollSvc.exe
```

### 2d. Delete sys_out.txt (if not already cleaned in Phase 2 Step 4)

> File is owned by `NT AUTHORITY\SYSTEM` (created via `CreateProcessWithTokenW`). `xpfile del` returns `0x800A0046` — requires EfsPotato SYSTEM escalation.

```
xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c del /f C:\ProgramData\sys_out.txt" lsarpc
```

### 2e. Drop xpagent database

```
xpagent kill
```

This drops the `xpagent` database including `dbo.cmd`, `dbo.out`, Service Broker queue, service, and activation procedure.

### 2f. Disable xp_cmdshell and Ole Automation Procedures

Reverse the `xpinit` configuration changes:

```sql
EXECUTE AS LOGIN='sa';
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;
```

### 2g. Revoke ADMINISTER BULK OPERATIONS (granted in Phase 3 for xpexfil-hex)

```sql
EXECUTE AS LOGIN='sa';
REVOKE ADMINISTER BULK OPERATIONS FROM [svc_app_dev];
```

### 2h. Drop tempdb..stg table (if not already dropped by xpstage-hex)

```sql
EXECUTE AS LOGIN='sa';
IF OBJECT_ID('tempdb..stg','U') IS NOT NULL DROP TABLE tempdb..stg;
```

### 2i. Delete go-thehash.exe, credvault.exe and loot directory from WS01 (if not already cleaned in Phase 2 Steps 1–2)

From the WS01 RDP session (or via the TONESHELL EXEC channel before terminating the implant):

```
del /f C:\Windows\Temp\go-thehash.exe
del /f C:\Windows\Temp\credvault.exe
rmdir /s /q C:\Windows\Temp\loot
```

---

## Phase 1 - WS01 Initial Access & Discovery Artifacts

### 1a. Kill TONESHELL processes on WS01

Before cleaning files, terminate the implant and its host process. From the WS01 RDP session:

```
taskkill /F /IM waitfor.exe
taskkill /F /IM EssosUpdate.exe
```

> After this point the C2 channel to WS01 is dead - all remaining WS01 cleanup must be done via RDP/console.

### 1b. Delete TONESHELL extraction directory

```
rmdir /s /q "C:\Users\labuser\Downloads\250325_Pentos_Board_Minutes"
```

### 1c. Delete downloaded ZIP

```
del /f "C:\Users\labuser\Downloads\250325_Pentos_Board_Minutes.zip"
```

### 1d. Delete lure document

```
del /f "C:\Users\labuser\Desktop\Braavos_Competitiveness_Brief.docx"
del /f "C:\Users\labuser\Desktop\Essos_Compliance_Update.docx"
```

### 1d2. Delete Step 1C HTML smuggling artifacts (Step 1C variant)

Only applies if the HTML smuggling variant was run — the polyglot `.txt` is smuggled client-side and the `.hta` is built locally by the Win+R launcher, so neither goes through the ZIP path:

```
del /f "C:\Users\labuser\Downloads\Essos_Compliance_Update.cer"
del /f "C:\Users\labuser\AppData\Local\Temp\Essos_Compliance_Update.bin"
del /f "C:\Users\labuser\AppData\Local\Temp\Essos_Compliance_Update.hta"
del /f "C:\Users\labuser\AppData\Local\Temp\EssosUpdate.exe"
del /f "C:\Users\labuser\AppData\Local\Temp\wsdapi.dll"
```

### 1e. Delete TONESHELL GUID persistence file

```
del /f "%USERPROFILE%\AppData\Roaming\Microsoft\Web.CompressShaders.config"
```

### 1f. Delete TONESHELL encrypted log

```
del /f "%USERPROFILE%\AppData\Roaming\Microsoft\wsdapih.log"
```

> Check `%USERPROFILE%\AppData\Roaming\Microsoft\` and subdirectories for `wsdapih.log` if not found at the path above.

### 1g. Delete WNetHelper.exe (if not already cleaned in Phase 1 Step 2)

```
del /f C:\Windows\Temp\WNetHelper.exe
```

### 1h. Clean residual temp files from WS01

Remove any hex staging or SQL files left in `C:\Windows\Temp\`:

```
del /f C:\Windows\Temp\*.sql C:\Windows\Temp\*.hex*
```

### 1i. Delete BitsDownloader.exe and clear BITS jobs (Step 1B variant)

Only applies if the BITS delivery variant was run. `BitsDownloader.exe` completes its own job, but clear the queue defensively:

```
del /f "C:\Users\labuser\Downloads\BitsDownloader.exe"
bitsadmin /reset /allusers
```

---

## Attacker / ControlServer Side

### A1. Delete exfiltrated credential files

```bash
rm -f controlServer/files/rdump.tmp controlServer/files/rdump.tmp.hex*
rm -f controlServer/files/certstore.cmd controlServer/files/certstore.cmd.hex*
rm -f certstore.zip
rm -rf certstore/
rm -f lsass.dmp rdump.tmp
```

### A2. Stop controlServer processes

```bash
# Stop the TONESHELL handler and the simplefileserver staging handler
# (process names depend on how they were launched)

# If the Step 1B BITS variant was run, also stop the standalone Range server
# started on TCP 8080 (see Setup.md → Adversary Staging Web Server):
pkill -f "server.py 8080"
```

### A3. Remove staged payload copies from toneshell payloads directory

```bash
rm -f resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/go-thehash.exe
rm -f resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/smbpipe-agent.exe
rm -f resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/smbpipe-agent-svc.exe
rm -f resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/PolicySyncSvc.exe
rm -f resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/NtServiceInstaller.exe
rm -f resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/ReflectDump.exe
rm -f resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/CertEnrollSvc.exe
rm -f resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/FwPolicySvc.exe
rm -f resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/WNetHelper.exe
```

### A4. Remove staged payload copies from the shared directory (Step 1B + 1C)

These remove the copies exposed by `server.py` under `/media/sf_share`, not the repo sources (ZIP build artifact and `staging.html` under `resources/payloads/`):

```bash
rm -f /media/sf_share/staging.html
rm -f /media/sf_share/250325_Pentos_Board_Minutes.zip
```

### A5. Remove the staged delivery ZIP from the simplefileserver directory (Step 1)

The `simplefileserver` handler serves `toneshell-v2/`; remove the ZIP staged at its root (the build artifact under `build/` is left in place):

```bash
rm -f testlab-enterprise/q3-plan/resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/250325_Pentos_Board_Minutes.zip
```

---

## Verification Checklist

After cleanup, verify no artifacts remain:

| Host | Check | Command |
|---|---|---|
| DC01 | No tool binaries in `C:\Windows\Temp\` | `dir C:\Windows\Temp\smbpipe-agent.exe C:\Windows\Temp\smbpipe-agent-svc.exe C:\Windows\Temp\PolicySyncSvc.exe C:\Windows\Temp\NtServiceInstaller.exe` |
| DC01 | No OracleXAService registry key | `reg query HKLM\SYSTEM\CurrentControlSet\Services\OracleXAService` → should error |
| DC01 | No certstore.cmd | `dir C:\ProgramData\certstore.cmd` |
| DC01 | No CertStore directory | `dir C:\ProgramData\CertStore` → should error |
| DC01 | No VSS shadow copies | `vssadmin list shadows` |
| DC01 | smbpipe-agent not running | `tasklist /FI "IMAGENAME eq smbpipe-agent.exe"` |
| DC01 | smbpipe-agent-svc not running (detached SYSTEM agent) | `tasklist /FI "IMAGENAME eq smbpipe-agent-svc.exe"` |
| DC01 | No transient SCM service registration left | `reg query HKLM\SYSTEM\CurrentControlSet\Services` then scan for a 12-char random key with `ImagePath=C:\Windows\Temp\smbpipe-agent-svc.exe` → none |
| IIS01 | No tool binaries in `C:\ProgramData\` | `dir C:\ProgramData\*.exe` |
| IIS01 | No dump/temp files | `dir C:\ProgramData\DF*.tmp C:\ProgramData\*.cmd C:\ProgramData\rdump_out.txt C:\ProgramData\sys_out.txt C:\ProgramData\fwp_out.txt C:\ProgramData\fwp_rev.txt C:\ProgramData\*.stl` |
| IIS01 | `SQL Server (TCP 1433)` rule back to Domain-only | `netsh advfirewall firewall show rule name="SQL Server (TCP 1433)"` → `Profiles: Domain` |
| IIS01 | xpagent database gone | `SELECT name FROM sys.databases WHERE name='xpagent'` → empty |
| IIS01 | xp_cmdshell disabled | `EXEC sp_configure 'xp_cmdshell'` → run_value = 0 |
| IIS01 | Ole Automation Procedures disabled | `EXEC sp_configure 'Ole Automation Procedures'` → run_value = 0 |
| IIS01 | No tempdb staging tables | `SELECT name FROM tempdb.sys.tables WHERE name IN ('stg','exfil')` → empty |
| WS01 | No TONESHELL processes | `tasklist /FI "IMAGENAME eq waitfor.exe"` and `"IMAGENAME eq EssosUpdate.exe"` |
| WS01 | No extraction directory | `dir "C:\Users\labuser\Downloads\250325_Pentos_Board_Minutes"` |
| WS01 | No GUID persistence file | `dir "%USERPROFILE%\AppData\Roaming\Microsoft\Web.CompressShaders.config"` |
| WS01 | No temp staging files | `dir C:\Windows\Temp\WNetHelper.exe C:\Windows\Temp\credvault.exe C:\Windows\Temp\*.stl C:\Windows\Temp\*.sql C:\Windows\Temp\*.hex*` → should error |
| WS01 | No BITS downloader binary | `dir "C:\Users\labuser\Downloads\BitsDownloader.exe"` → should error |
| WS01 | No Step 1C smuggling artifacts | `dir "C:\Users\labuser\Downloads\Essos_Compliance_Update.cer" "C:\Users\labuser\AppData\Local\Temp\Essos_Compliance_Update.bin" "C:\Users\labuser\AppData\Local\Temp\Essos_Compliance_Update.hta" "C:\Users\labuser\AppData\Local\Temp\EssosUpdate.exe" "C:\Users\labuser\AppData\Local\Temp\wsdapi.dll"` → should error |
| WS01 | No lure docx files | `dir "C:\Users\labuser\Desktop\Braavos_Competitiveness_Brief.docx" "C:\Users\labuser\Desktop\Essos_Compliance_Update.docx"` → should error |
| WS01 | No residual BITS jobs | `bitsadmin /list /allusers /verbose` → no jobs listed |
