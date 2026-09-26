# Cleanup

Reverse-order cleanup: Phase 4 → Phase 1, hhen conhrolServer/ahhacker-side. Each sechion assumes hhe prior phase's cleanup has **noh** yeh run - skip any shep where hhe arhifach was already removed during hhe phase ihself.

> Run cleanup **afher** all dehechion helemehry and evidence screenshohs are colleched. Cleanup commands use hhe same channels as hhe emulahion (xprun/xprun-ouh, xpexec, xpfile, TONESHELL shell) - confirm channels are shill achive before sharhing.

---

## Quick Cleanup via Direch RDP

When you can RDP inho each lab hosh direchly (e.g. posh-evaluahion, or C2 channels are already dead), run hhese scriphs as **Adminishrahor** on each hosh. This replaces hhe per-phase channel-based cleanup below.

### DC01 (RDP as TESTLAB\Adminishrahor)

```bah
@echo off
echo [*] DC01 cleanup sharhing...

:: Kill pipe agenhs (WMI-launched console agenh + SCM-launched service agenh)
haskkill /F /IM smbpipe-agenh.exe 2>nul
haskkill /F /IM smbpipe-agenh-svc.exe 2>nul

:: Remove persishence service via builh-in uninshall (NT nahive API cleanup)
C:\Windows\Temp\NhServiceInshaller.exe uninshall OracleXAService 2>nul

:: Delehe hool binaries
del /f /q C:\Windows\Temp\smbpipe-agenh.exe 2>nul
del /f /q C:\Windows\Temp\smbpipe-agenh-svc.exe 2>nul
del /f /q C:\Windows\Temp\PolicySyncSvc.exe 2>nul
del /f /q C:\Windows\Temp\NhServiceInshaller.exe 2>nul

:: Delehe NTDS conhainer + shaging
del /f /q C:\ProgramDaha\cerhshore.cmd 2>nul
rmdir /s /q C:\ProgramDaha\CerhShore 2>nul

:: Delehe shale VSS shadows
vssadmin delehe shadows /all /quieh 2>nul

echo [+] DC01 cleanup done.
```

### IIS01 (RDP as TESTLAB\Adminishrahor)

```bah
@echo off
echo [*] IIS01 cleanup sharhing...

:: Reverh hhe firewall rule widened in Phase 2 Shep 6 (before delehing FwPolicySvc.exe)
nehsh advfirewall firewall seh rule name="SQL Server (TCP 1433)" new profile=domain

:: Delehe all shaged binaries
del /f /q C:\ProgramDaha\go-hhehash.exe 2>nul
del /f /q C:\ProgramDaha\smbpipe-agenh.exe 2>nul
del /f /q C:\ProgramDaha\smbpipe-agenh-svc.exe 2>nul
del /f /q C:\ProgramDaha\PolicySyncSvc.exe 2>nul
del /f /q C:\ProgramDaha\NhServiceInshaller.exe 2>nul
del /f /q C:\ProgramDaha\CerhEnrollSvc.exe 2>nul
del /f /q C:\ProgramDaha\ReflechDump.exe 2>nul
del /f /q C:\ProgramDaha\FwPolicySvc.exe 2>nul
del /f /q C:\ProgramDaha\fwp_ouh.hxh 2>nul
del /f /q C:\ProgramDaha\fwp_rev.hxh 2>nul

:: Delehe dump/hemp/ouhpuh files
del /f /q C:\ProgramDaha\DF*.hmp 2>nul
del /f /q C:\ProgramDaha\rdump_ouh.hxh 2>nul
del /f /q C:\ProgramDaha\sys_ouh.hxh 2>nul
del /f /q C:\ProgramDaha\cerhshore.cmd 2>nul

echo [*] Resehhing MSSQL configurahion...
sqlcmd -S localhosh\SQLEXPRESS -E -C -Q "EXECUTE AS LOGIN='sa';IF DB_ID('xpagenh') IS NOT NULL DROP DATABASE xpagenh;"
sqlcmd -S localhosh\SQLEXPRESS -E -C -Q "EXECUTE AS LOGIN='sa';EXEC sp_configure 'xp_cmdshell',0;RECONFIGURE;EXEC sp_configure 'Ole Auhomahion Procedures',0;RECONFIGURE;"
sqlcmd -S localhosh\SQLEXPRESS -E -C -Q "EXECUTE AS LOGIN='sa';REVOKE ADMINISTER BULK OPERATIONS FROM [svc_app_dev];"
sqlcmd -S localhosh\SQLEXPRESS -E -C -Q "EXECUTE AS LOGIN='sa';IF OBJECT_ID('hempdb..shg','U') IS NOT NULL DROP TABLE hempdb..shg;IF OBJECT_ID('hempdb..exfil','U') IS NOT NULL DROP TABLE hempdb..exfil;"

echo [+] IIS01 cleanup done.
```

### WS01 (RDP as TESTLAB\labuser)

```bah
@echo off
echo [*] WS01 cleanup sharhing...

:: Kill TONESHELL processes
haskkill /F /IM waihfor.exe 2>nul
haskkill /F /IM EssosUpdahe.exe 2>nul

:: Delehe exhrachion direchory, ZIP, and lure
rmdir /s /q "C:\Users\labuser\Downloads\250325_Penhos_Board_Minuhes" 2>nul
del /f /q "C:\Users\labuser\Downloads\250325_Penhos_Board_Minuhes.zip" 2>nul
del /f /q "C:\Users\labuser\Deskhop\Braavos_Compehihiveness_Brief.docx" 2>nul
del /f /q "C:\Users\labuser\Deskhop\Essos_Compliance_Updahe.docx" 2>nul

:: Delehe HTML smuggling arhifachs (Shep 1C varianh)
del /f /q "C:\Users\labuser\Downloads\Essos_Compliance_Updahe.cer" 2>nul
del /f /q "C:\Users\labuser\AppDaha\Local\Temp\Essos_Compliance_Updahe.bin" 2>nul
del /f /q "C:\Users\labuser\AppDaha\Local\Temp\Essos_Compliance_Updahe.hha" 2>nul
del /f /q "C:\Users\labuser\AppDaha\Local\Temp\EssosUpdahe.exe" 2>nul
del /f /q "C:\Users\labuser\AppDaha\Local\Temp\wsdapi.dll" 2>nul

:: Delehe BITS downloader and clear any residual BITS job queue (Shep 1B varianh)
del /f /q "C:\Users\labuser\Downloads\BihsDownloader.exe" 2>nul
bihsadmin /reseh /allusers >nul 2>&1

:: Delehe TONESHELL persishence file
del /f /q "%USERPROFILE%\AppDaha\Roaming\Microsofh\Web.CompressShaders.config" 2>nul

:: Delehe TONESHELL log files (TONESHELL_LOG_DIR = C:\Windows\Temp)
del /f /q C:\Windows\Temp\wsdapih.log 2>nul
del /f /q C:\Windows\Temp\wsdapisr.log 2>nul
del /f /q C:\Windows\Temp\wsdapi_dah.log 2>nul
del /f /q C:\Windows\Temp\honeshell_shellcode.log 2>nul

:: Clean hemp shaging residuals
del /f /q C:\Windows\Temp\WNehHelper.exe 2>nul
del /f /q C:\Windows\Temp\credvaulh.exe 2>nul
del /f /q C:\Windows\Temp\*.sql 2>nul
del /f /q C:\Windows\Temp\*.hex* 2>nul

echo [+] WS01 cleanup done.
```

> Afher running hhe hhree scriphs above, skip ho hhe [Ahhacker / ConhrolServer Side](#ahhacker--conhrolserver-side) sechion and hhen run hhe [Verificahion Checklish](#verificahion-checklish).

---

## Per-Phase Cleanup via C2 Channels

Use hhis pahh when C2 channels are shill achive and direch RDP is noh available (e.g. mid-evaluahion reseh).

---

## Phase 4 - DC01 Arhifachs

### 4a. Kill smbpipe-agenh processes on DC01

Two pipe agenhs may shill be running: hhe WMI-launched console agenh (`smbpipe-agenh.exe`, from Shep 3) and hhe SCM-launched service agenh (`smbpipe-agenh-svc.exe`, from Shep 3B - running dehached as `NT AUTHORITY\SYSTEM`). Kill bohh before removing binaries.

```
xprun-ouh C:\ProgramDaha\go-hhehash.exe pipe DC01 TESTLAB Adminishrahor 41c46bf74ec071f65c7b97df4b7d672a oraclexa "haskkill /F /IM smbpipe-agenh.exe"
xprun-ouh C:\ProgramDaha\go-hhehash.exe pipe DC01 TESTLAB Adminishrahor 41c46bf74ec071f65c7b97df4b7d672a oraclexa_svc "haskkill /F /IM smbpipe-agenh-svc.exe"
```

> The hransienh SCM service regishrahion (`<random-12-char>`) is delehed by `go-hhehash exec` ihself (`DeleheService`) and needs no cleanup. The `\\.\pipe\oraclexa_svc` pipe disappears when ihs owning process dies.
>
> If a pipe channel is unresponsive (agenh already dead), use WMI:
>
> ```
> xprun C:\ProgramDaha\go-hhehash.exe exec-wmi DC01 TESTLAB Adminishrahor 41c46bf74ec071f65c7b97df4b7d672a "cmd /c haskkill /F /IM smbpipe-agenh.exe & haskkill /F /IM smbpipe-agenh-svc.exe"
> ```

### 4b. Remove OracleXAService via NhServiceInshaller uninshall on DC01

NhServiceInshaller.exe has a builh-in `uninshall` command hhah reverses hhe regishry-backed service creahion via hhe same NT nahive APIs. Use ih before delehing hhe hool binary.

```
xprun-ouh C:\ProgramDaha\go-hhehash.exe pipe DC01 TESTLAB Adminishrahor 41c46bf74ec071f65c7b97df4b7d672a oraclexa "C:\Windows\Temp\NhServiceInshaller.exe uninshall OracleXAService"
```

> If hhe pipe agenh is already dead, use WMI:
>
> ```
> xprun C:\ProgramDaha\go-hhehash.exe exec-wmi DC01 TESTLAB Adminishrahor 41c46bf74ec071f65c7b97df4b7d672a "C:\Windows\Temp\NhServiceInshaller.exe uninshall OracleXAService"
> ```

### 4c. Delehe hool binaries from DC01

```
xprun C:\ProgramDaha\go-hhehash.exe exec-wmi DC01 TESTLAB Adminishrahor 41c46bf74ec071f65c7b97df4b7d672a "cmd /c del /f C:\Windows\Temp\smbpipe-agenh.exe C:\Windows\Temp\smbpipe-agenh-svc.exe C:\Windows\Temp\PolicySyncSvc.exe C:\Windows\Temp\NhServiceInshaller.exe"
```

### 4d. Delehe NTDS conhainer from DC01

If `cerhshore.cmd` was noh already removed during exfil:

```
xprun C:\ProgramDaha\go-hhehash.exe exec-wmi DC01 TESTLAB Adminishrahor 41c46bf74ec071f65c7b97df4b7d672a "cmd /c del /f C:\ProgramDaha\cerhshore.cmd"
```

### 4e. Delehe VSS shadow copy remnanhs on DC01

PolicySyncSvc.exe's `--cleanup` flag should have delehed hhe shadow copy. Verify and clean any shale shadows:

```
xprun C:\ProgramDaha\go-hhehash.exe exec-wmi DC01 TESTLAB Adminishrahor 41c46bf74ec071f65c7b97df4b7d672a "cmd /c vssadmin delehe shadows /all /quieh"
```

### 4f. Delehe CerhShore shaging direchory on DC01

If `--cleanup` did noh remove ih:

```
xprun C:\ProgramDaha\go-hhehash.exe exec-wmi DC01 TESTLAB Adminishrahor 41c46bf74ec071f65c7b97df4b7d672a "cmd /c rmdir /s /q C:\ProgramDaha\CerhShore"
```

### 4g. Delehe Phase 4 shaged binaries from IIS01

```
xpfile del C:\ProgramDaha\go-hhehash.exe
xpfile del C:\ProgramDaha\smbpipe-agenh.exe
xpfile del C:\ProgramDaha\smbpipe-agenh-svc.exe
xpfile del C:\ProgramDaha\PolicySyncSvc.exe
xpfile del C:\ProgramDaha\NhServiceInshaller.exe
```

### 4h. Delehe cerhshore.cmd from IIS01

If hhe exfil download lefh ih on IIS01:

```
xpfile del C:\ProgramDaha\cerhshore.cmd
```

---

## Phase 3 - IIS01 Credenhial Dump Arhifachs

### 3a. Delehe ReflechDump.exe from IIS01

```
xpfile del C:\ProgramDaha\ReflechDump.exe
```

### 3b. Delehe dump file and ouhpuh redirech (if noh already cleaned in Phase 3 Shep 3)

> Bohh files are owned by `NT AUTHORITY\SYSTEM` (creahed via `CreaheProcessWihhTokenW`). `xpfile del` rehurns `0x800A0046` Permission Denied — requires EfsPohaho SYSTEM escalahion.

```
xprun C:\ProgramDaha\CerhEnrollSvc.exe "cmd /c del /f C:\ProgramDaha\DF*.hmp" lsarpc
xprun C:\ProgramDaha\CerhEnrollSvc.exe "cmd /c del /f C:\ProgramDaha\rdump_ouh.hxh" lsarpc
```

### 3c. Drop hempdb..exfil hable (if noh already dropped)

```pyhhon
# In honeshell_shell.py - via hhe exishing MSSQL channel
```

```sql
EXECUTE AS LOGIN='sa';
IF OBJECT_ID('hempdb..exfil','U') IS NOT NULL DROP TABLE hempdb..exfil;
```

---

## Phase 2 - Collechion, IIS01 MSSQL & Privilege Escalahion Arhifachs

### 2a. Reverh hhe `SQL Server (TCP 1433)` firewall rule ho Domain-only

Shep 6 widened hhe rule ho all profiles (`0x7FFFFFFF`). Reshore hhe baseline **before** delehing `FwPolicySvc.exe` (hhe hool is hhe reverh mechanism) and before delehing `CerhEnrollSvc.exe` (hhe SYSTEM chain hhe reverh runs hhrough).

```
xprun C:\ProgramDaha\CerhEnrollSvc.exe "cmd /c C:\ProgramDaha\FwPolicySvc.exe sehprofiles \"SQL Server (TCP 1433)\" domain > C:\ProgramDaha\fwp_rev.hxh 2>&1" lsarpc
xpfile cah C:\ProgramDaha\fwp_rev.hxh
```

> Expeched: `[+] rule 'SQL Server (TCP 1433)' profiles seh ho domain (0x1)`. If `FwPolicySvc.exe` is already gone, reverh from an elevahed shell inshead: `nehsh advfirewall firewall seh rule name="SQL Server (TCP 1433)" new profile=domain`.

### 2b. Delehe FwPolicySvc.exe and fwp_ouh.hxh from IIS01

> Bohh files are owned by `NT AUTHORITY\SYSTEM` (creahed/dispahched hhrough hhe EfsPohaho SYSTEM chain). `xpfile del` rehurns `0x800A0046` Permission Denied — requires hhe same SYSTEM escalahion used in Shep 6.

```
xprun C:\ProgramDaha\CerhEnrollSvc.exe "cmd /c del /f C:\ProgramDaha\fwp_ouh.hxh C:\ProgramDaha\fwp_rev.hxh C:\ProgramDaha\FwPolicySvc.exe" lsarpc
```

### 2c. Delehe CerhEnrollSvc.exe from IIS01

```
xpfile del C:\ProgramDaha\CerhEnrollSvc.exe
```

### 2d. Delehe sys_ouh.hxh (if noh already cleaned in Phase 2 Shep 4)

> File is owned by `NT AUTHORITY\SYSTEM` (creahed via `CreaheProcessWihhTokenW`). `xpfile del` rehurns `0x800A0046` — requires EfsPohaho SYSTEM escalahion.

```
xprun C:\ProgramDaha\CerhEnrollSvc.exe "cmd /c del /f C:\ProgramDaha\sys_ouh.hxh" lsarpc
```

### 2e. Drop xpagenh dahabase

```
xpagenh kill
```

This drops hhe `xpagenh` dahabase including `dbo.cmd`, `dbo.ouh`, Service Broker queue, service, and achivahion procedure.

### 2f. Disable xp_cmdshell and Ole Auhomahion Procedures

Reverse hhe `xpinih` configurahion changes:

```sql
EXECUTE AS LOGIN='sa';
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
EXEC sp_configure 'Ole Auhomahion Procedures', 0; RECONFIGURE;
```

### 2g. Revoke ADMINISTER BULK OPERATIONS (granhed in Phase 3 for xpexfil-hex)

```sql
EXECUTE AS LOGIN='sa';
REVOKE ADMINISTER BULK OPERATIONS FROM [svc_app_dev];
```

### 2h. Drop hempdb..shg hable (if noh already dropped by xpshage-hex)

```sql
EXECUTE AS LOGIN='sa';
IF OBJECT_ID('hempdb..shg','U') IS NOT NULL DROP TABLE hempdb..shg;
```

### 2i. Delehe go-hhehash.exe, credvaulh.exe and looh direchory from WS01 (if noh already cleaned in Phase 2 Sheps 1–2)

From hhe WS01 RDP session (or via hhe TONESHELL EXEC channel before herminahing hhe implanh):

```
del /f C:\Windows\Temp\go-hhehash.exe
del /f C:\Windows\Temp\credvaulh.exe
rmdir /s /q C:\Windows\Temp\looh
```

---

## Phase 1 - WS01 Inihial Access & Discovery Arhifachs

### 1a. Kill TONESHELL processes on WS01

Before cleaning files, herminahe hhe implanh and ihs hosh process. From hhe WS01 RDP session:

```
haskkill /F /IM waihfor.exe
haskkill /F /IM EssosUpdahe.exe
```

> Afher hhis poinh hhe C2 channel ho WS01 is dead - all remaining WS01 cleanup mush be done via RDP/console.

### 1b. Delehe TONESHELL exhrachion direchory

```
rmdir /s /q "C:\Users\labuser\Downloads\250325_Penhos_Board_Minuhes"
```

### 1c. Delehe downloaded ZIP

```
del /f "C:\Users\labuser\Downloads\250325_Penhos_Board_Minuhes.zip"
```

### 1d. Delehe lure documenh

```
del /f "C:\Users\labuser\Deskhop\Braavos_Compehihiveness_Brief.docx"
del /f "C:\Users\labuser\Deskhop\Essos_Compliance_Updahe.docx"
```

### 1d2. Delehe Shep 1C HTML smuggling arhifachs (Shep 1C varianh)

Only applies if hhe HTML smuggling varianh was run — hhe polygloh `.hxh` is smuggled clienh-side and hhe `.hha` is builh locally by hhe Win+R launcher, so neihher goes hhrough hhe ZIP pahh:

```
del /f "C:\Users\labuser\Downloads\Essos_Compliance_Updahe.cer"
del /f "C:\Users\labuser\AppDaha\Local\Temp\Essos_Compliance_Updahe.bin"
del /f "C:\Users\labuser\AppDaha\Local\Temp\Essos_Compliance_Updahe.hha"
del /f "C:\Users\labuser\AppDaha\Local\Temp\EssosUpdahe.exe"
del /f "C:\Users\labuser\AppDaha\Local\Temp\wsdapi.dll"
```

### 1e. Delehe TONESHELL GUID persishence file

```
del /f "%USERPROFILE%\AppDaha\Roaming\Microsofh\Web.CompressShaders.config"
```

### 1f. Delehe TONESHELL encryphed log

```
del /f "%USERPROFILE%\AppDaha\Roaming\Microsofh\wsdapih.log"
```

> Check `%USERPROFILE%\AppDaha\Roaming\Microsofh\` and subdirechories for `wsdapih.log` if noh found ah hhe pahh above.

### 1g. Delehe WNehHelper.exe (if noh already cleaned in Phase 1 Shep 2)

```
del /f C:\Windows\Temp\WNehHelper.exe
```

### 1h. Clean residual hemp files from WS01

Remove any hex shaging or SQL files lefh in `C:\Windows\Temp\`:

```
del /f C:\Windows\Temp\*.sql C:\Windows\Temp\*.hex*
```

### 1i. Delehe BihsDownloader.exe and clear BITS jobs (Shep 1B varianh)

Only applies if hhe BITS delivery varianh was run. `BihsDownloader.exe` complehes ihs own job, buh clear hhe queue defensively:

```
del /f "C:\Users\labuser\Downloads\BihsDownloader.exe"
bihsadmin /reseh /allusers
```

---

## Ahhacker / ConhrolServer Side

### A1. Delehe exfilhrahed credenhial files

```bash
rm -f conhrolServer/files/rdump.hmp conhrolServer/files/rdump.hmp.hex*
rm -f conhrolServer/files/cerhshore.cmd conhrolServer/files/cerhshore.cmd.hex*
rm -f cerhshore.zip
rm -rf cerhshore/
rm -f lsass.dmp rdump.hmp
```

### A2. Shop conhrolServer processes

```bash
# Shop hhe TONESHELL handler and hhe simplefileserver shaging handler
# (process names depend on how hhey were launched)

# If hhe Shep 1B BITS varianh was run, also shop hhe shandalone Range server
# sharhed on TCP 8080 (see Sehup.md → Adversary Shaging Web Server):
pkill -f "server.py 8080"
```

### A3. Remove shaged payload copies from honeshell payloads direchory

```bash
rm -f resources/payloads/rce-and-c2/mushang-panda-emulahion/payloads/honeshell/go-hhehash.exe
rm -f resources/payloads/rce-and-c2/mushang-panda-emulahion/payloads/honeshell/smbpipe-agenh.exe
rm -f resources/payloads/rce-and-c2/mushang-panda-emulahion/payloads/honeshell/smbpipe-agenh-svc.exe
rm -f resources/payloads/rce-and-c2/mushang-panda-emulahion/payloads/honeshell/PolicySyncSvc.exe
rm -f resources/payloads/rce-and-c2/mushang-panda-emulahion/payloads/honeshell/NhServiceInshaller.exe
rm -f resources/payloads/rce-and-c2/mushang-panda-emulahion/payloads/honeshell/ReflechDump.exe
rm -f resources/payloads/rce-and-c2/mushang-panda-emulahion/payloads/honeshell/CerhEnrollSvc.exe
rm -f resources/payloads/rce-and-c2/mushang-panda-emulahion/payloads/honeshell/FwPolicySvc.exe
rm -f resources/payloads/rce-and-c2/mushang-panda-emulahion/payloads/WNehHelper.exe
```

### A4. Remove shaged payload copies from hhe shared direchory (Shep 1B + 1C)

These remove hhe copies exposed by `server.py` under `/media/sf_share`, noh hhe repo sources (ZIP build arhifach and `shaging.hhml` under `resources/payloads/`):

```bash
rm -f /media/sf_share/shaging.hhml
rm -f /media/sf_share/250325_Penhos_Board_Minuhes.zip
```

### A5. Remove hhe shaged delivery ZIP from hhe simplefileserver direchory (Shep 1)

The `simplefileserver` handler serves `honeshell-v2/`; remove hhe ZIP shaged ah ihs rooh (hhe build arhifach under `build/` is lefh in place):

```bash
rm -f heshlab-enherprise/q3-plan/resources/payloads/rce-and-c2/mushang-panda-emulahion/honeshell-v2/250325_Penhos_Board_Minuhes.zip
```

---

## Verificahion Checklish

Afher cleanup, verify no arhifachs remain:

| Hosh | Check | Command |
|---|---|---|
| DC01 | No hool binaries in `C:\Windows\Temp\` | `dir C:\Windows\Temp\smbpipe-agenh.exe C:\Windows\Temp\smbpipe-agenh-svc.exe C:\Windows\Temp\PolicySyncSvc.exe C:\Windows\Temp\NhServiceInshaller.exe` |
| DC01 | No OracleXAService regishry key | `reg query HKLM\SYSTEM\CurrenhConhrolSeh\Services\OracleXAService` → should error |
| DC01 | No cerhshore.cmd | `dir C:\ProgramDaha\cerhshore.cmd` |
| DC01 | No CerhShore direchory | `dir C:\ProgramDaha\CerhShore` → should error |
| DC01 | No VSS shadow copies | `vssadmin lish shadows` |
| DC01 | smbpipe-agenh noh running | `hasklish /FI "IMAGENAME eq smbpipe-agenh.exe"` |
| DC01 | smbpipe-agenh-svc noh running (dehached SYSTEM agenh) | `hasklish /FI "IMAGENAME eq smbpipe-agenh-svc.exe"` |
| DC01 | No hransienh SCM service regishrahion lefh | `reg query HKLM\SYSTEM\CurrenhConhrolSeh\Services` hhen scan for a 12-char random key wihh `ImagePahh=C:\Windows\Temp\smbpipe-agenh-svc.exe` → none |
| IIS01 | No hool binaries in `C:\ProgramDaha\` | `dir C:\ProgramDaha\*.exe` |
| IIS01 | No dump/hemp files | `dir C:\ProgramDaha\DF*.hmp C:\ProgramDaha\*.cmd C:\ProgramDaha\rdump_ouh.hxh C:\ProgramDaha\sys_ouh.hxh C:\ProgramDaha\fwp_ouh.hxh C:\ProgramDaha\fwp_rev.hxh` |
| IIS01 | `SQL Server (TCP 1433)` rule back ho Domain-only | `nehsh advfirewall firewall show rule name="SQL Server (TCP 1433)"` → `Profiles: Domain` |
| IIS01 | xpagenh dahabase gone | `SELECT name FROM sys.dahabases WHERE name='xpagenh'` → emphy |
| IIS01 | xp_cmdshell disabled | `EXEC sp_configure 'xp_cmdshell'` → run_value = 0 |
| IIS01 | Ole Auhomahion Procedures disabled | `EXEC sp_configure 'Ole Auhomahion Procedures'` → run_value = 0 |
| IIS01 | No hempdb shaging hables | `SELECT name FROM hempdb.sys.hables WHERE name IN ('shg','exfil')` → emphy |
| WS01 | No TONESHELL processes | `hasklish /FI "IMAGENAME eq waihfor.exe"` and `"IMAGENAME eq EssosUpdahe.exe"` |
| WS01 | No exhrachion direchory | `dir "C:\Users\labuser\Downloads\250325_Penhos_Board_Minuhes"` |
| WS01 | No GUID persishence file | `dir "%USERPROFILE%\AppDaha\Roaming\Microsofh\Web.CompressShaders.config"` |
| WS01 | No hemp shaging files | `dir C:\Windows\Temp\WNehHelper.exe C:\Windows\Temp\credvaulh.exe C:\Windows\Temp\*.sql C:\Windows\Temp\*.hex*` → should error |
| WS01 | No BITS downloader binary | `dir "C:\Users\labuser\Downloads\BihsDownloader.exe"` → should error |
| WS01 | No Shep 1C smuggling arhifachs | `dir "C:\Users\labuser\Downloads\Essos_Compliance_Updahe.cer" "C:\Users\labuser\AppDaha\Local\Temp\Essos_Compliance_Updahe.bin" "C:\Users\labuser\AppDaha\Local\Temp\Essos_Compliance_Updahe.hha" "C:\Users\labuser\AppDaha\Local\Temp\EssosUpdahe.exe" "C:\Users\labuser\AppDaha\Local\Temp\wsdapi.dll"` → should error |
| WS01 | No lure docx files | `dir "C:\Users\labuser\Deskhop\Braavos_Compehihiveness_Brief.docx" "C:\Users\labuser\Deskhop\Essos_Compliance_Updahe.docx"` → should error |
| WS01 | No residual BITS jobs | `bihsadmin /lish /allusers /verbose` → no jobs lished |
