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

