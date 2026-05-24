# Lab Setup - Windows Server 2022 with IIS
## ASPX Web Upload Endpoint
```powershell
# Run as Administrator
Install-WindowsFeature -Name Web-Server -IncludeManagementTools
Install-WindowsFeature -Name Web-Asp-Net45
Install-WindowsFeature -Name Web-Mgmt-Console
```

Create web root
```powershell
New-Item -Path "C:\inetpub\upload.testlab.local" -ItemType Directory
New-Item -Path "C:\inetpub\upload.testlab.local\uploads" -ItemType Directory
```

Configure IIS
```powershell
Import-Module WebAdministration

# Create Application Pool
New-WebAppPool -Name "upload.testlab.local"

# Create Website
New-Website -Name "upload.testlab.local" `
    -Port 80 `
    -HostHeader "upload.testlab.local" `
    -PhysicalPath "C:\inetpub\upload.testlab.local" `
    -ApplicationPool "upload.testlab.local"

# Start site (AppPool will start automatically)
Start-Website -Name "upload.testlab.local"
```

Set permissions
```powershell
# Allow IIS to write to uploads directory
$acl = Get-Acl "C:\inetpub\upload.testlab.local\uploads"
$permission = "IIS APPPOOL\upload.testlab.local","FullControl","ContainerInherit,ObjectInherit","None","Allow"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($rule)
Set-Acl "C:\inetpub\upload.testlab.local\uploads" $acl
```

Check MIME types
```powershell
Get-WebConfigurationProperty -PSPath "IIS:\Sites\upload.testlab.local" `
    -Filter "system.webServer/staticContent" `
    -Name "collection" |
    Select-Object fileExtension, mimeType |
    Sort-Object fileExtension
```

Browse to `http://upload.testlab.local` then upload webshell `antak.aspx` to the uploads directory.
Access the webshell at `http://upload.testlab.local/uploads/antak.aspx`

---

## React2Shell Vulnerable Web (react.testlab.local)

Node.js/Next.js app hosted via **IISNode** so the worker process runs under the IIS AppPool identity — required for impersonation scenarios where RCE via CVE-2025-55182 should yield `IIS APPPOOL\react.testlab.local` privileges.

### How IISNode achieves AppPool identity

IISNode creates the Node.js process as a child of `w3wp.exe`. It communicates via a **named pipe** whose path is injected as `process.env.PORT`. The custom `server.js` below passes that value directly to `http.Server.listen()` — if you use `parseInt(process.env.PORT)` instead, Node falls back to TCP port 3000 and the pipe binding fails.

### Prerequisites

```powershell
# Node.js LTS (winget not available on Windows Server — download MSI directly)
$nodeMsi = "$env:TEMP\nodejs-lts.msi"
Invoke-WebRequest -Uri "https://nodejs.org/dist/v22.15.0/node-v22.15.0-x64.msi" `
    -OutFile $nodeMsi
Start-Process msiexec.exe -ArgumentList "/i `"$nodeMsi`" /qn" -Wait

# Reload PATH so npm/node are available in the current session
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")

# IISNode (x64) — download installer from:
# https://github.com/Azure/iisnode/releases  (iisnode-full-vX.X.XX-x64.msi)

# URL Rewrite module — required for IISNode request routing
# https://www.iis.net/downloads/microsoft/url-rewrite
```

### Deploy application

```powershell
New-Item -Path "C:\inetpub\react.testlab.local" -ItemType Directory

Copy-Item -Path ".\react2shell-vuln-web\*" `
    -Destination "C:\inetpub\react.testlab.local" -Recurse -Force
```

Build the app (run as a user with write access, not as AppPool):
```powershell
Set-Location "C:\inetpub\react.testlab.local"
npm install
npm run build
```

### Create IISNode entry point

Create `C:\inetpub\react.testlab.local\server.js`:
```javascript
const { createServer } = require('http');
const { parse }        = require('url');
const next             = require('next');

const app    = next({ dev: false });
const handle = app.getRequestHandler();

app.prepare().then(() => {
    createServer((req, res) => {
        handle(req, res, parse(req.url, true));
    }).listen(process.env.PORT || 3000);
});
```

### Create web.config

Create `C:\inetpub\react.testlab.local\web.config`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="iisnode" path="server.js" verb="*" modules="iisnode" />
    </handlers>
    <rewrite>
      <rules>
        <rule name="all" patternSyntax="ECMAScript" stopProcessing="true">
          <match url=".*" />
          <conditions logicalGrouping="MatchAll">
            <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true" />
          </conditions>
          <action type="Rewrite" url="server.js" />
        </rule>
      </rules>
    </rewrite>
    <httpErrors existingResponse="PassThrough" />
    <iisnode loggingEnabled="true"
             logDirectory="iisnode"
             watchedFiles="web.config;server.js" />
  </system.webServer>
</configuration>
```

### Configure IIS

```powershell
Import-Module WebAdministration

New-WebAppPool -Name "react.testlab.local"

New-Website -Name "react.testlab.local" `
    -Port 80 `
    -HostHeader "react.testlab.local" `
    -PhysicalPath "C:\inetpub\react.testlab.local" `
    -ApplicationPool "react.testlab.local"

Start-Website -Name "react.testlab.local"
```

### Set permissions

```powershell
# Read+Execute on webroot (Node.js process reads .next/, node_modules/, server.js)
$webroot = "C:\inetpub\react.testlab.local"
$acl = Get-Acl $webroot
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "IIS APPPOOL\react.testlab.local",
    "ReadAndExecute",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl.SetAccessRule($rule)
Set-Acl $webroot $acl

# FullControl on iisnode log directory (IISNode writes stdout/stderr logs here)
New-Item -Path "$webroot\iisnode" -ItemType Directory -Force
$acl2 = Get-Acl "$webroot\iisnode"
$rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "IIS APPPOOL\react.testlab.local",
    "FullControl",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl2.SetAccessRule($rule2)
Set-Acl "$webroot\iisnode" $acl2
```

### Verify AppPool identity after exploit

After exploiting CVE-2025-55182, the RCE output should show the AppPool identity:
```
POST http://react.testlab.local/ (Next-Action header)
→ whoami  →  iis apppool\react.testlab.local
```

IISNode stdout is logged to `C:\inetpub\react.testlab.local\iisnode\` — useful for debugging Node.js startup errors.

---

## SQL Server Express (testlab MSSQL instance)

A lightweight SQL Server Express instance on IIS01 representing a backend database for
the upload portal. Its primary purpose is to provide **realistic T1489 → T1486 impact
targets**: `*.mdf` / `*.ldf` files that are file-locked by the MSSQL service and become
encryptable after the service is stopped.

Service name used in emulation procedures: **`MSSQL$SQLEXPRESS`**  
Data file path: **`C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA\`**

### Install SQL Server Express (unattended)

Download the Express installer (offline/full package ~250 MB so Node-to-MSSQL latency is
not a concern):

```powershell
# Download SQL Server 2022 Express full package
$sqlInstaller = "$env:TEMP\SQL2022-SSEI-Expr.exe"
Invoke-WebRequest `
    -Uri "https://go.microsoft.com/fwlink/p/?linkid=2216019&clcid=0x409&culture=en-us&country=US" `
    -OutFile $sqlInstaller

# Extract to a local folder first, then install silently
# (the SSEI bootstrapper requires /ACTION=Download before silent install)
Start-Process $sqlInstaller `
    -ArgumentList "/ACTION=Download /MEDIATYPE=Core /MEDIAPATH=`"$env:TEMP\SQLExpress2022`" /QUIET" `
    -Wait

# Silent install — named instance SQLEXPRESS, mixed-mode auth, sa disabled (Windows auth only)
Start-Process "$env:TEMP\SQLExpress2022\SQLEXPR_x64_ENU.exe" `
    -ArgumentList @(
        "/Q",
        "/ACTION=Install",
        "/INSTANCENAME=SQLEXPRESS",
        "/FEATURES=SQLEngine",
        "/SECURITYMODE=SQL",
        "/SAPWD=`"mssql.gr3atAga1n`"",
        "/SQLSVCACCOUNT=`"NT AUTHORITY\NETWORK SERVICE`"",
        "/SQLSYSADMINACCOUNTS=`"TESTLAB\Administrator`"",
        "/TCPENABLED=1",
        "/NPENABLED=0",
        "/IACCEPTSQLSERVERLICENSETERMS"
    ) -Wait
```

> **Note on `/SECURITYMODE=SQL`**: Mixed-mode auth is enabled so `sa` can be used if
> needed; in practice the emulation uses Windows auth (`TESTLAB\Administrator`). The sa
> password is `mssql.gr3atAga1n` — change if policy requires, but keep a record for
> procedures that reference it.

Verify the service started:

```powershell
Get-Service -Name "MSSQL`$SQLEXPRESS" | Select-Object Name, Status, StartType
# Expected: Running, Automatic
```

### Create the application database

Connect with `sqlcmd` (installed with SQL Server) and create a database that represents
upload-portal metadata — realistic content for Phase 5 encryption:

```powershell
# Confirm sqlcmd is on PATH (SQL Server adds it during install)
# ODBC Driver 18 requires -C to trust the self-signed server certificate
& "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\180\Tools\Binn\SQLCMD.EXE" `
    -S "localhost\SQLEXPRESS" -E -C -Q "SELECT @@VERSION"
```

```sql
-- Run via sqlcmd -S localhost\SQLEXPRESS -E -C
-- Creates database UploadPortalDB with two tables and seed data

CREATE DATABASE UploadPortalDB;
GO

USE UploadPortalDB;
GO

CREATE TABLE UploadedFiles (
    FileId      INT IDENTITY(1,1) PRIMARY KEY,
    FileName    NVARCHAR(260)  NOT NULL,
    UploadedBy  NVARCHAR(100)  NOT NULL,
    UploadedAt  DATETIME2      NOT NULL DEFAULT SYSDATETIME(),
    FileSizeKB  INT,
    StoredPath  NVARCHAR(500)
);
GO

CREATE TABLE Users (
    UserId      INT IDENTITY(1,1) PRIMARY KEY,
    Username    NVARCHAR(100) NOT NULL UNIQUE,
    PasswordHash NVARCHAR(256) NOT NULL,
    Role        NVARCHAR(50)  NOT NULL DEFAULT 'user',
    CreatedAt   DATETIME2     NOT NULL DEFAULT SYSDATETIME()
);
GO

-- Seed data (password hashes are bcrypt placeholders — not real credentials)
INSERT INTO Users (Username, PasswordHash, Role) VALUES
    ('admin',    '$2b$12$eImiTXuWVxfM37uY4JANjA==', 'admin'),
    ('jsmith',   '$2b$12$LIHMqK9FqEPtestlabABCD==', 'user'),
    ('mwilliams','$2b$12$XYZlabplaceholderhash==',  'user');
GO

INSERT INTO UploadedFiles (FileName, UploadedBy, FileSizeKB, StoredPath) VALUES
    ('Q1_Report.pdf',        'jsmith',    1240, 'C:\inetpub\upload.testlab.local\uploads\Q1_Report.pdf'),
    ('network_diagram.vsdx', 'mwilliams', 840,  'C:\inetpub\upload.testlab.local\uploads\network_diagram.vsdx'),
    ('employee_list.xlsx',   'admin',     312,  'C:\inetpub\upload.testlab.local\uploads\employee_list.xlsx');
GO
```

One-liner to run the script from a file (save the SQL block above as
`resources/setup/init-uploadportaldb.sql`):

```powershell
& "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\180\Tools\Binn\SQLCMD.EXE" `
    -S "localhost\SQLEXPRESS" -E -C `
    -i "C:\path\to\resources\setup\init-uploadportaldb.sql"
```

### Confirm data file paths

After database creation, verify the MDF/LDF locations — these are the files targeted by
Phase 5 T1486 encryption after T1489 stops the service:

```powershell
& "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\180\Tools\Binn\SQLCMD.EXE" `
    -S "localhost\SQLEXPRESS" -E -C -Q `
    "SELECT name, physical_name FROM sys.master_files WHERE database_id = DB_ID('UploadPortalDB')"
```

Expected output:

```text
name                      physical_name
------------------------- ------------------------------------------------------------------
UploadPortalDB            C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA\UploadPortalDB.mdf
UploadPortalDB_log        C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA\UploadPortalDB_log.ldf
```

### Firewall (optional — local-only access)

The MSSQL instance only needs to be reachable from IIS01 itself (the emulation accesses
it via the existing SYSTEM dnscat2 session). If no external SQL access is required, leave
the Windows Firewall blocking TCP 1433:

```powershell
# Confirm port is NOT exposed externally (expected: no output = no inbound rule)
Get-NetFirewallRule -DisplayName "*SQL*" | Where-Object { $_.Direction -eq "Inbound" }
```

If you need SSMS access from the dev machine for setup verification, add a temporary
inbound rule and remove it afterward:

```powershell
New-NetFirewallRule -DisplayName "SQL Express temp" -Direction Inbound `
    -Protocol TCP -LocalPort 1433 -Action Allow -Profile Any

# Remove after setup is confirmed
Remove-NetFirewallRule -DisplayName "SQL Express temp"
```

### Verify data directory ACL (informational)

`NT AUTHORITY\SYSTEM` inherits **Full Control** on `C:\Program Files\` from the default
Windows ACL — no explicit grant is needed. Phase 5 encryption (running as SYSTEM via the
dnscat2 session) will have access without any setup step here.

Confirm after install if needed:

```powershell
(Get-Acl "C:\Program Files\Microsoft SQL Server\MSSQL17.SQLEXPRESS\MSSQL\DATA").Access |
    Select-Object IdentityReference, FileSystemRights, IsInherited |
    Format-Table -AutoSize
# Expected: NT AUTHORITY\SYSTEM — FullControl
```

