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

> **Keep this as a SQL login — do not convert it to `FROM WINDOWS`.** The
> password-reuse behavior below (Step 4b) depends on the same password existing
> as *both* a SQL login and a domain account. A Windows-authenticated SQL login
> would remove the plaintext-password signal the chain is built around.

---

## Step 4b — Same password as a domain account (`TESTLAB\svc_app_dev`)

The adversary finds the SQL password in `appsettings.json` / Credential Manager
(Step 6, Phase 2 Step 1) and tries it against the domain — a real password-reuse
pattern. For that to work, a domain account must exist with the **same
password** as the SQL login. Run on `DC01`:

```powershell
$p = ConvertTo-SecureString "D3vPortal!2025" -AsPlainText -Force

New-ADUser `
    -SamAccountName "svc_app_dev" `
    -UserPrincipalName "svc_app_dev@testlab.local" `
    -Name "svc_app_dev" `
    -AccountPassword $p `
    -PasswordNeverExpires $true `
    -Enabled $true
```

**Least privilege — deliberately a plain domain user.** Do **not** add this
account to `Domain Admins`, `Backup Operators`, `Remote Desktop Users`,
`Remote Management Users`, `Protected Users`, or any other privileged group,
and do **not** register an SPN for it. The only capabilities it carries are the
ones granted below:

| Scope | Grant | Where |
|---|---|---|
| AD | `Domain Users` only (default), password never expires | DC01 (this step) |
| IIS01 local | `IIS_IUSRS` membership + `SeServiceLogonRight` | Step 4c |
| SQL | `db_datareader` on `DevPortalDB` + `IMPERSONATE ON LOGIN::sa` | Step 4 (existing) |
| SMB | Read on `\\IIS01\DevPortal` | Step 4c |

Verify on `DC01`:

```powershell
Get-ADUser svc_app_dev -Properties MemberOf, PasswordNeverExpires |
    Select-Object SamAccountName, Enabled, PasswordNeverExpires, MemberOf
# Expected: Enabled=True, PasswordNeverExpires=True, MemberOf = Domain Users only
```

> **Why this makes T1078.002 detectable.** Baseline: `svc_app_dev` only ever
> logs on interactively/service (type 5/3) *on IIS01*. An adversary using the
> same credentials from `WS01` is an anomaly — the domain account authenticating
> from a host it has never originated from is the discriminative signal
> (AN0590), independent of the Pass-the-Hash NTLM signal.

---

## Step 4c — SMB share and app files on IIS01 (`\\IIS01\DevPortal`)

Provides the collection target for automated collection (T1119) and the read
grant `svc_app_dev` needs. Run on `IIS01` as `TESTLAB\Administrator`:

```powershell
New-Item -Path "C:\DevPortal" -ItemType Directory -Force
New-Item -Path "C:\DevPortal\config" -ItemType Directory -Force
New-Item -Path "C:\DevPortal\deploy" -ItemType Directory -Force

@"
{
  "ConnectionStrings": {
    "DevPortalDB": "Server=iis01.testlab.local;Database=DevPortalDB;User Id=svc_app_dev;Password=D3vPortal!2025;TrustServerCertificate=True;"
  },
  "Logging": { "LogLevel": { "Default": "Information" } }
}
"@ | Out-File -FilePath "C:\DevPortal\config\appsettings.json" -Encoding utf8

@"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings>
    <add key="ApiBaseUrl" value="https://iis01.testlab.local/api" />
    <add key="Environment" value="Staging" />
  </appSettings>
</configuration>
"@ | Out-File -FilePath "C:\DevPortal\config\web.config" -Encoding utf8

@"
# DevPortal staging deploy helper
param([string]`$Target = "iis01.testlab.local")
Write-Host "Deploying DevPortal to `$Target ..."
"@ | Out-File -FilePath "C:\DevPortal\deploy\deploy.ps1" -Encoding utf8
```

Create the share, read-only for `svc_app_dev`:

```powershell
New-SmbShare -Name "DevPortal" -Path "C:\DevPortal" -ReadAccess "TESTLAB\svc_app_dev"
```

Grant the account the local IIS group membership and the "log on as a service"
right (so it can also be used as an app-pool/service identity in the baseline,
consistent with a real dev service account):

```powershell
Add-LocalGroupMember -Group "IIS_IUSRS" -Member "TESTLAB\svc_app_dev"

$sid = (New-Object System.Security.Principal.NTAccount("TESTLAB\svc_app_dev")).Translate(
    [System.Security.Principal.SecurityIdentifier]).Value
$tmp = [System.IO.Path]::GetTempFileName()
secedit /export /cfg $tmp | Out-Null
(Get-Content $tmp) -replace "^(SeServiceLogonRight.*)$", "`$1,*$sid" |
    Set-Content $tmp
secedit /configure /db secedit.sdb /cfg $tmp /areas USER_RIGHTS | Out-Null
Remove-Item $tmp, secedit.sdb -Force -ErrorAction SilentlyContinue
```

Verify from `IIS01`:

```powershell
Get-SmbShare -Name "DevPortal" | Select-Object Name, Path, ShareState
Get-SmbShareAccess -Name "DevPortal"
# Expected: TESTLAB\svc_app_dev with Read access
```

> **Scope note.** The share is read-only for `svc_app_dev` on purpose. `collect`
> (T1119) only reads; if a future step needs write, extend the grant explicitly
> rather than widening it here.

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

## Step 7b — Verify Kerberos and SMB prerequisites

Required before any `-krb` (Kerberos) or `collect` (SMB) step will work. Run on
`WS01` unless noted.

**1. DNS — the target must resolve to a hostname, not an IP.** Kerberos forms a
`cifs/<hostname>` SPN and rejects IP literals outright, so `iis01.testlab.local`
must resolve:

```powershell
Resolve-DnsName iis01.testlab.local
# Expected: 10.12.10.20 (A record; if missing, add it on DC01:
#   Add-DnsServerResourceRecordA -ZoneName testlab.local -Name iis01 -IPv4Address 10.12.10.20 )
```

**2. Clock skew — Kerberos fails past ~5 minutes of drift.**

```powershell
w32tm /stripchart /computer:DC01 /samples:3 /dataonly
# Expected: offset within a few seconds. If large, resync:
#   w32tm /resync   (or point WS01/IIS01 at DC01 via Set-DnsClientServerAddress / w32tm /config)
```

**3. KDC reachable on tcp/88.**

```powershell
Test-NetConnection DC01 -Port 88
# Expected: TcpTestSucceeded: True
```

**4. SMB reachable on tcp/445 (for `collect`).**

```powershell
Test-NetConnection iis01.testlab.local -Port 445
# Expected: TcpTestSucceeded: True
```

**5. Encryption-type compatibility.** `go-thehash -krb` derives a Kerberos key
from the password. If the account's `msDS-SupportedEncryptionTypes` is set to a
type the client cannot use (e.g. AES-only with an RC4-only client, or RC4
disabled domain-wide), logon fails with `KDC_ERR_ETYPE_NOSUPP`. Check on `DC01`:

```powershell
Get-ADUser svc_app_dev -Properties msDS-SupportedEncryptionTypes |
    Select-Object SamAccountName, msDS-SupportedEncryptionTypes
# 0 / not set = default (AES + RC4). Leave unset unless the lab enforces otherwise.
```

**6. End-to-end smoke test (benign) — optional but recommended.** Confirm the
account can actually get a ticket and read the share before running Phase 2:

```powershell
net use \\iis01.testlab.local\DevPortal /user:TESTLAB\svc_app_dev "D3vPortal!2025"
dir \\iis01.testlab.local\DevPortal\config
net use \\iis01.testlab.local\DevPortal /delete
# Expected: appsettings.json, web.config listed; no access-denied
# (net use by hostname uses Kerberos → produces 4768/4769 on DC01)
```

---

## Step 8 — Snapshot

Take a VM snapshot of `IIS01` now that the baseline above is verified. This
is the only reliable recovery path if a later phase run (on this or another
path sharing the host) corrupts state again — see the `UploadPortalDB`
incident this doc opened with.

---

## Step 9 — Disable TermService and enable WinRM access

Phase 3 uses PhantomRPC TERM variant, which registers a fake RPC server on
the `TermSrvApi` ALPC endpoint. This requires TermService (Remote Desktop
Services) to be **stopped and disabled** on IIS01 so the endpoint is
unoccupied.

### Enable WinRM on IIS01 (before disabling RDP)

WinRM should already be enabled on a domain-joined Server 2022. Verify:

```powershell
Get-Service WinRM | Select-Object Name, Status, StartType
# Expected: WinRM, Running, Automatic
```

If not running:

```powershell
Enable-PSRemoting -Force
```

### Configure host machine for WinRM access

The host machine is not domain-joined, so it needs TrustedHosts configured.
Run on the host (PowerShell as Admin):

```powershell
Start-Service WinRM
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.56.4" -Force
```

Verify connectivity before disabling RDP:

```powershell
Enter-PSSession -ComputerName 192.168.56.4 -Credential TESTLAB\administrator
# Expected: prompt changes to [192.168.56.4]: PS C:\Users\administrator.TESTLAB\Documents>
Exit-PSSession
```

### Disable TermService

Run on IIS01 (via the WinRM session just verified, or via RDP one last time):

```powershell
Stop-Service TermService -Force
Set-Service TermService -StartupType Disabled
Get-Service TermService | Select-Object Name, Status, StartType
# Expected: TermService, Stopped, Disabled
```

### Re-enable (after testing, or to restore RDP access)

```powershell
Set-Service TermService -StartupType Manual
Start-Service TermService
```

---

## Step 10 — Network connectivity summary

| Source | Destination | Port | Protocol | Required for |
| - | - | - | - | - |
| WS01 (10.12.10.30) | IIS01 (10.12.10.20) | 1433 | TCP | MSSQL credential use (Phase 2) |
| WS01 (10.12.10.30) | IIS01 (10.12.10.20) | 445 | TCP | SMB share read — valid-account logon + collection (Phase 2) |
| WS01 (10.12.10.30) | DC01 (10.12.10.10) | 88 | TCP/UDP | Kerberos KDC — `4768`/`4769` ticket requests (Phase 2) |
| WS01 (10.12.10.30) | DC01 (10.12.10.10) | 53 | TCP/UDP | DNS resolution of `iis01.testlab.local` (Kerberos SPN) |
| WS01 (10.12.10.30) | IIS01 (10.12.10.20) | 445 | TCP | DCOM/RPC dynamic range if `exec-wmi` is used (Phase 4) |

---

## Step 11 — Baseline inventory and cleanup boundaries

These objects are **baseline** — created by this setup and part of normal lab
state. `Cleanup.md` must **not** remove them between runs; they exist so the
adversary behaviors have something to target:

| Object | Location | Purpose |
|---|---|---|
| AD account `TESTLAB\svc_app_dev` | DC01 | Valid domain account (T1078.002) |
| SQL login `svc_app_dev` + `IMPERSONATE ON LOGIN::sa` | IIS01 `DevPortalDB` | Password-reuse source + privilege escalation |
| SMB share `\\IIS01\DevPortal` + files | IIS01 `C:\DevPortal` | Collection target (T1119) |
| `appsettings.json` / SSMS Credential Manager entry | WS01 | Credential discovery artifact |

What cleanup **should** revert after a run (adversary-created, not baseline):
- Any `net use` drive mappings the adversary left mounted on WS01
- Any files `collect` copied into a local staging directory on WS01/IIS01
- `xp_cmdshell` / `Ole Automation Procedures` / `ADMINISTER BULK OPERATIONS`
  changes (already covered by `Cleanup.md`)
- `DevPortal` share contents **modified** during a run — restore from the VM
  snapshot (Step 8) if a phase corrupts them, as with the `UploadPortalDB`
  incident noted at the top of this document
