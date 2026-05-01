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

