# Lab Setup — MSSQL Impersonation Chain (on shared IIS01)

Reuses the existing `IIS01` / `SQLEXPRESS` instance (already provisioned by
[`../../../windows-adversary-plan/resources/setup/Windows Server 2022-IIS.md`](../../../windows-adversary-plan/resources/setup/Windows%20Server%202022-IIS.md))
instead of a dedicated host — same `testlab.local` domain, same SQL Server
Express install. No new VM required.

Purpose: give a TONESHELL-compromised dev workstation (`WS01` / `labuser`) a
realistic path from low-privilege SQL credentials to `NT AUTHORITY\SYSTEM` on
`IIS01`, via SQL Server impersonation (`EXECUTE AS LOGIN`) → `xp_cmdshell` →
[EfsPotato](../payloads/priv-escalation/EfsPotato/) token theft. Verified
against real-world MSSQL pentest methodology (NetSPI, PowerUpSQL
`Invoke-SQLAuditPrivImpersonateLogin`) — not a fabricated chain.

## Prerequisite — clean baseline required

`IIS01\SQLEXPRESS` previously carried `UploadPortalDB` for the
`iis-apppool-escalation-path` Phase 5 impact test (T1489 stop service → T1486
AES-256 encrypt). That database was found in `RECOVERY_PENDING` (Error 824
torn-page, matching Phase 5's own documented output) with no backup files
remaining at `C:\Windows\Temp\`, and has since been dropped:

```powershell
& "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\180\Tools\Binn\SQLCMD.EXE" `
    -S "localhost\SQLEXPRESS" -E -C -Q "DROP DATABASE UploadPortalDB;"
Remove-Item "C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA\UploadPortalDB.mdf" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA\UploadPortalDB_log.ldf" -Force -ErrorAction SilentlyContinue
```

**Known shared-infra impact**: `iis-apppool-escalation-path/Phase 5.md` no
longer has a target database. Whoever owns that path needs to recreate
`UploadPortalDB` from the SQL block in `Windows Server 2022-IIS.md` before
re-running Phase 5 — out of scope for this doc, flagging only.

**Ordering constraint going forward**: this chain must run *before*
`iis-apppool-escalation-path/Phase 5.md` in any full-lab run on `IIS01`.
Phase 5 stops the service and encrypts database files in place — running it
after this setup will corrupt `DevPortalDB` the same way it corrupted
`UploadPortalDB`. Take a VM snapshot of `IIS01` once this setup is verified
(Step 8) so a bad Phase 5 run doesn't repeat the earlier incident.

**Service account correction**: `Windows Server 2022-IIS.md`'s unattended
install explicitly passed `/SQLSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"`
(confirmed via `Summary.txt` in `...\170\Setup Bootstrap\Log\`) instead of
leaving the installer default, which is a per-instance **virtual account**
(`NT SERVICE\MSSQL$SQLEXPRESS`) per Microsoft's documented behavior. Corrected
to the virtual account for a realistic baseline:

```powershell
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement") | Out-Null
$wmi = New-Object Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer "localhost"
$svc = $wmi.Services | Where-Object { $_.Name -eq 'MSSQL$SQLEXPRESS' }
$svc.SetServiceAccount('NT SERVICE\MSSQL$SQLEXPRESS', $null)
$svc.Alter()
Restart-Service "MSSQL`$SQLEXPRESS"
```

Safe to change: the DATA directory ACL already grants `FullControl` to
`NT SERVICE\MSSQL$SQLEXPRESS` specifically (confirmed via `Get-Acl`), not to
`NETWORK SERVICE` — SQL Server's per-service SID (`SERVICE_SID_TYPE:
UNRESTRICTED`, confirmed via `sc.exe qsidtype`) attaches that SID to the
process token regardless of the actual logon account, so the switch didn't
require any ACL changes and doesn't affect `iis-apppool-escalation-path`'s
use of the same data directory. Verified post-restart: identity resolves to
`nt service\mssql$sqlexpress`, `SeImpersonatePrivilege` still present, and the
Step 5 `IMPERSONATE` grant survived the restart intact.

---

## Step 1 — Fix TCP port to static

Confirmed via `Get-ItemProperty ...\IPAll` that the named instance currently
listens on a **dynamic port** (`59007` at time of writing). Real DBA practice
fixes a static port on any instance accessed remotely — also required here so
the port doesn't change every time the service restarts (including restarts
triggered by other phases).

```powershell
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQLServer\SuperSocketNetLib\Tcp\IPAll" `
    -Name TcpPort -Value "1433"
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQLServer\SuperSocketNetLib\Tcp\IPAll" `
    -Name TcpDynamicPorts -Value ""
Restart-Service "MSSQL`$SQLEXPRESS"
```

Verify:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQLServer\SuperSocketNetLib\Tcp\IPAll" -Name TcpPort, TcpDynamicPorts
# Expected: TcpPort = 1433, TcpDynamicPorts = (empty)
```

---

## Step 2 — Firewall (Domain profile only)

Restricted to the `Domain` profile, not `Any` — matches internal network
segmentation; the instance should never be reachable from outside the lab
subnet.

```powershell
New-NetFirewallRule -DisplayName "SQL Server (TCP 1433)" -Direction Inbound `
    -Protocol TCP -LocalPort 1433 -Action Allow -Profile Domain
```

---

## Step 3 — Application database (`DevPortalDB`)

Run on `IIS01` as sysadmin (`TESTLAB\Administrator`):

```powershell
& "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\180\Tools\Binn\SQLCMD.EXE" `
    -S "localhost\SQLEXPRESS" -E -C -Q "SELECT @@VERSION"
```

```sql
CREATE DATABASE DevPortalDB;
GO
USE DevPortalDB;
GO
CREATE TABLE Notes (
    NoteId    INT IDENTITY(1,1) PRIMARY KEY,
    Author    NVARCHAR(100) NOT NULL,
    Body      NVARCHAR(1000) NOT NULL,
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSDATETIME()
);
GO
-- Content doubles as an in-band "paper trail" explaining the Step 5
-- misconfig — reads like a real, half-finished internal note rather than
-- a planted vulnerability marker.
INSERT INTO Notes (Author, Body) VALUES
    ('labuser', 'Remember to rotate the app SQL password after the audit.'),
    ('labuser', 'sa impersonate grant still needed until the new service is live.');
GO
```

---

## Step 4 — Low-privilege application login (`svc_app_dev`)

`CHECK_POLICY = OFF` reflects a common real-world pattern — service accounts
are frequently exempted from password-expiry policy to avoid unplanned
outages, not set this way "to make the lab easier."

```sql
CREATE LOGIN svc_app_dev WITH PASSWORD = 'D3vPortal!2025', CHECK_POLICY = OFF;
GO
USE DevPortalDB;
GO
CREATE USER svc_app_dev FOR LOGIN svc_app_dev;
GO
ALTER ROLE db_datareader ADD MEMBER svc_app_dev;
GO
```

---

## Step 5 — The misconfiguration: legacy `IMPERSONATE` grant on `sa`

```sql
USE master;
GO
GRANT IMPERSONATE ON LOGIN::sa TO [svc_app_dev];
GO
```

Verify the grant is discoverable — this is the exact query the emulation's
enumeration step will run (join on `grantee_principal_id` + `major_id`, not
`grantor_principal_id` as some public write-ups show, which surfaces the
wrong side of the grant):

```sql
SELECT pe.permission_name, pe.state_desc, pr.name AS grantee, pr2.name AS impersonatable_login
FROM sys.server_permissions pe
JOIN sys.server_principals pr  ON pe.grantee_principal_id = pr.principal_id
JOIN sys.server_principals pr2 ON pe.major_id = pr2.principal_id
WHERE pe.permission_name = 'IMPERSONATE';
```

`xp_cmdshell` stays **disabled** at this point (SQL Server default) — enabling
it is part of the attack procedure, not the lab baseline.

---

## Step 6 — Credential artifact on WS01

Primary artifact — plaintext connection string in an app config directory
(the discovery target for TONESHELL):

```powershell
# Run on WS01 as labuser
New-Item -Path "C:\Users\labuser\Documents\DevPortal" -ItemType Directory -Force

@"
{
  "ConnectionStrings": {
    "DevPortalDB": "Server=iis01.testlab.local;Database=DevPortalDB;User Id=svc_app_dev;Password=D3vPortal!2025;TrustServerCertificate=True;"
  }
}
"@ | Out-File -FilePath "C:\Users\labuser\Documents\DevPortal\appsettings.json" -Encoding utf8
```

Optional stronger artifact — SSMS "Remember Password" saved connection.
Verified on-instance (SSMS 20): the password does **not** land in
`UserSettings.xml` (the `<Password />` node stays empty) or in a
`SqlStudio.bin`-style file at all — SSMS 20 persists it through **Windows
Credential Manager** instead, as a `Generic` credential with target
`LegacyGeneric:target=Microsoft:SSMS:20:<server>:<user>:<serverType-guid>:1`
and `Local machine` persistence. Because TONESHELL is already running as
`labuser`, it can read the credential in-session (e.g. via the
`CredentialManager` PowerShell module's `Get-StoredCredential`, or a direct
`CredRead`/`CredEnumerate` P/Invoke) without any offline DPAPI cracking. This
maps cleanly to **`T1555.004` — Credentials from Password Stores: Windows
Credential Manager**, a real ATT&CK sub-technique — no mapping ambiguity like
the earlier DPAPI-blob-in-file assumption had.

Install SSMS on `WS01` (separate from the `sqlcmd` client already in use —
no dependency between them, GUI-only, ~700MB-1GB):

```powershell
# Run on WS01 as Administrator
winget install --id Microsoft.SQLServerManagementStudio -e
```

To seed the artifact: open SSMS as `labuser`, connect once to
`iis01.testlab.local` as `svc_app_dev` / `D3vPortal!2025` with "Remember
password" checked, then close SSMS. Verify the credential landed in Credential
Manager:

```powershell
cmdkey /list
# Expected: a "LegacyGeneric:target=Microsoft:SSMS:..." entry, User: svc_app_dev, Local machine persistence
```

Confirm the credential is actually retrievable in-session (verified working —
decrypts without needing `labuser`'s Windows logon password or any offline
cracking):

```powershell
Install-Module CredentialManager -Scope CurrentUser -Force -AllowClobber

# Use the exact target string from the cmdkey /list output above
$cred = Get-StoredCredential -Target "LegacyGeneric:target=Microsoft:SSMS:20:iis01.testlab.local:svc_app_dev:8c91a03d-f9b4-46c0-a305-b5dcc79ff907:1"
$cred.UserName
$cred.GetNetworkCredential().Password
# Expected: svc_app_dev / D3vPortal!2025
```

Use this as an alternative or additional Reference Table row — not required
for the chain to function.

---

## Step 7 — Verify

Lightweight client for WS01: install `sqlcmd` (Go rewrite, single static exe,
no separate ODBC driver needed) via `winget install --id Microsoft.Sqlcmd -e`.
Once installed it's on PATH as `sqlcmd` in a new shell — no need for the full
`...\ODBC\180\Tools\Binn\SQLCMD.EXE` path used on IIS01.

```powershell
# From WS01: confirm remote connectivity as the dev login, and confirm baseline (not sysadmin yet)
sqlcmd -S "iis01.testlab.local" -U svc_app_dev -P "D3vPortal!2025" -C `
    -Q "SELECT SUSER_SNAME(), IS_SRVROLEMEMBER('sysadmin')"
# Expected: svc_app_dev, 0

# On IIS01: confirm MSSQLSERVER/SQLEXPRESS service identity and SeImpersonatePrivilege
# (temporarily enable xp_cmdshell as sysadmin to check, then disable again — do not
#  leave it enabled after this verification step)
& "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\180\Tools\Binn\SQLCMD.EXE" `
    -S "localhost\SQLEXPRESS" -E -C -Q "
    EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
    EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
    EXEC xp_cmdshell 'whoami';
    EXEC xp_cmdshell 'whoami /priv';
    EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
    "
# Expected identity: NT SERVICE\MSSQL$SQLEXPRESS (virtual account — see
#   "Service account correction" in the Prerequisite section)
# Expected privilege list: SeImpersonatePrivilege present
```

---

## Step 8 — Snapshot

Take a VM snapshot of `IIS01` now that the baseline above is verified. This
is the only reliable recovery path if a later phase run (on this or another
path sharing the host) corrupts state again — see the `UploadPortalDB`
incident this doc opened with.
