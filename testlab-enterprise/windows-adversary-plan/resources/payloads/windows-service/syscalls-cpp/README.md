# NtServiceInstaller (C++) - Technical Overview

## Technique Summary

Service installation using direct NT syscalls (`ntdll.dll`) for registry manipulation, bypassing user-mode API hooks on `advapi32.dll`. This C++ native implementation provides maximum stealth with minimal footprint (~20KB vs ~35MB .NET version).

**Key Characteristics:**
- Native C++ implementation (no runtime dependencies)
- Direct `ntdll.dll` syscalls for registry operations
- Bypasses `advapi32.dll` CreateService/DeleteService APIs
- File size: ~15-25 KB
- No service-specific event logs during install/uninstall
- Requires system reboot for SCM to load service
- Maximum EDR evasion

## MITRE ATT&CK Mapping

**Tactic:** Persistence, Privilege Escalation, Defense Evasion

**Techniques:**
- **T1543.003** - Create or Modify System Process: Windows Service
  - Creates service via registry manipulation
  - Service configured for auto-start
  - Runs as SYSTEM account

- **T1112** - Modify Registry
  - Direct registry key creation via NtCreateKey
  - Registry values set via NtSetValueKey
  - Persistence through service registry entries

- **T1106** - Native API
  - Uses native NT APIs (ntdll.dll) instead of Windows APIs
  - Bypasses user-mode hooks on advapi32.dll

**Detection Opportunities:**
- Security Event ID 4657 (Registry value modified - if auditing enabled)
- Security Event ID 4660 (Object deleted - if auditing enabled)
- Sysmon Event ID 1 (Process creation)
- Sysmon Event ID 7 (Image loaded - ntdll.dll without advapi32.dll service APIs)
- Sysmon Event ID 12 (Registry object added/deleted)
- Sysmon Event ID 13 (Registry value set)
- **Missing:** System Event ID 7045/7040 (service install/delete events)

**Evasion Characteristics:**
- No Event ID 7045 (service installed)
- No Event ID 4697 (service installed)
- No CreateService API call
- Appears as registry operations only
- Minimal file size for easy deployment

---

## Build Instructions

### Prerequisites
- MinGW-w64 GCC or MSVC compiler
- Windows OS

### Build Commands

**MinGW (Recommended):**
```bash
g++ -o NtServiceInstaller.exe main.cpp nt_api.cpp service_installer.cpp -ladvapi32 -municode -static -s -O2
```

**MSVC:**
```cmd
cl /EHsc /O2 /Fe:NtServiceInstaller.exe main.cpp nt_api.cpp service_installer.cpp advapi32.lib /link /SUBSYSTEM:CONSOLE
```

**Output:** ~15-25 KB standalone executable

---

## Code Flow

### Install Service

```
User Command
  ↓
main.cpp → wmain()
  ↓
service_installer.cpp → InstallService()
  ↓
InitNtFunctions() [Load ntdll.dll functions]
  ↓
NtOpenKey(\Registry\Machine\SYSTEM\CurrentControlSet\Services)
  ↓
NtCreateKey(ServiceName)
  ↓
NtSetValueKey("Type", REG_DWORD, 16)
NtSetValueKey("Start", REG_DWORD, 2)
NtSetValueKey("ErrorControl", REG_DWORD, 1)
NtSetValueKey("ImagePath", REG_SZ, exePath)
NtSetValueKey("DisplayName", REG_SZ, displayName)
NtSetValueKey("ObjectName", REG_SZ, "LocalSystem")
  ↓
NtClose()
```

**Event Logs:**
- **System Log**: None (registry-only operation)
- **Security Log** (Event ID 4657): Registry value modified (if auditing enabled)
- **Sysmon** (Event ID 1): Process creation - NtServiceInstaller.exe
- **Sysmon** (Event ID 12): Registry object added - Service key created
- **Sysmon** (Event ID 13): Registry value set - Multiple values (Type, Start, ImagePath, etc.)

**Log Sources:**
- `%SystemRoot%\System32\winevt\Logs\Security.evtx`
- `%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`

**Note:** Service will NOT appear in System log or SCM until system reboot.

---

### Start Service

```
User Command
  ↓
main.cpp → wmain()
  ↓
service_installer.cpp → StartServiceByName()
  ↓
OpenSCManager() [advapi32.dll fallback]
  ↓
OpenService()
StartService()
CloseServiceHandle()
```

**Event Logs:**
- **System Log** (Event ID 7036): Service entered running state
- **Sysmon** (Event ID 1): Process creation - NtServiceInstaller.exe

**Note:** Only works after system reboot when SCM has loaded the service.

---

### Stop Service

```
User Command
  ↓
service_installer.cpp → StopServiceByName()
  ↓
OpenSCManager()
OpenService()
ControlService(SERVICE_CONTROL_STOP)
CloseServiceHandle()
```

**Event Logs:**
- **System Log** (Event ID 7036): Service entered stopped state
- **Sysmon** (Event ID 1): Process creation

---

### Uninstall Service

```
User Command
  ↓
service_installer.cpp → UninstallService()
  ↓
StopServiceByName() [if running]
  ↓
NtOpenKey(\Registry\Machine\SYSTEM\CurrentControlSet\Services)
  ↓
NtOpenKey(ServiceName)
  ↓
NtDeleteKey()
  ↓
NtClose()
```

**Event Logs:**
- **Security Log** (Event ID 4660): Object deleted (if auditing enabled)
- **Sysmon** (Event ID 1): Process creation
- **Sysmon** (Event ID 12): Registry object deleted

**Note:** No System log event for service deletion.

---

## Quick Verification (Pre-Reboot)

Since service only appears in SCM after reboot, verify installation via registry:

### PowerShell Verification

```powershell
# Check if service exists in registry
$servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\<ServiceName>"

if (Test-Path $servicePath) {
    Write-Host "[+] Service installed in registry" -ForegroundColor Green
    Get-ItemProperty $servicePath | Format-List Type, Start, ErrorControl, ImagePath, DisplayName, ObjectName
} else {
    Write-Host "[!] Service not found" -ForegroundColor Red
}
```

### Registry Editor (regedit)

1. Open `regedit.exe`
2. Navigate to: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services`
3. Look for service name
4. Verify values:
   - `Type` = 16 (0x10)
   - `Start` = 2 (Auto-start)
   - `ErrorControl` = 1
   - `ImagePath` = Your executable path
   - `ObjectName` = LocalSystem

### Command Line Check

```cmd
rem Query registry directly
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>"

rem Should show:
rem Type           REG_DWORD    0x10
rem Start          REG_DWORD    0x2
rem ErrorControl   REG_DWORD    0x1
rem ImagePath      REG_SZ       C:\path\service.exe
```

### Verification Script

```powershell
# Save as verify-service.ps1
param($ServiceName)

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$scmCheck = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

Write-Host "=== Service Verification ===" -ForegroundColor Cyan
Write-Host ""

# Check registry
if (Test-Path $regPath) {
    Write-Host "[+] Registry: Service key exists" -ForegroundColor Green
    $props = Get-ItemProperty $regPath
    Write-Host "    Type: $($props.Type) (should be 16)"
    Write-Host "    Start: $($props.Start) (should be 2)"
    Write-Host "    ImagePath: $($props.ImagePath)"
} else {
    Write-Host "[!] Registry: Service not found" -ForegroundColor Red
}

# Check SCM
Write-Host ""
if ($scmCheck) {
    Write-Host "[+] SCM: Service loaded" -ForegroundColor Green
    Write-Host "    Status: $($scmCheck.Status)"
    Write-Host "    StartType: $($scmCheck.StartType)"
} else {
    Write-Host "[!] SCM: Service not loaded (requires reboot)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Note: If service is in registry but not SCM, reboot is required."
```

Run: `.\verify-service.ps1 -ServiceName YourServiceName`

---

## Usage Examples

### Install Service

```cmd
NtServiceInstaller.exe install "C:\MyApp\service.exe" MyService "My Service" "Service Description"
```

### Verify Installation (Before Reboot)

```powershell
# PowerShell verification
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\MyService"

# Expected output shows Type=16, Start=2, ImagePath, etc.
```

### Reboot System

```powershell
Restart-Computer
```

### Start Service (After Reboot)

```cmd
NtServiceInstaller.exe start MyService
```

### Check Status

```cmd
NtServiceInstaller.exe status MyService
```

### Stop Service

```cmd
NtServiceInstaller.exe stop MyService
```

### Uninstall Service

```cmd
NtServiceInstaller.exe uninstall MyService
```

---

## DLL Loading Events

**Sysmon Event ID 7 (Image Loaded):**

Process: `NtServiceInstaller.exe`

**DLLs Loaded:**
- `ntdll.dll` - NT syscalls (primary)
- `kernel32.dll` - Core Windows APIs
- `advapi32.dll` - Only for ServiceController operations (start/stop)
- `sechost.dll` - Security host library

**Key Difference:**
- **Install/Uninstall**: Only `ntdll.dll` registry operations
- **Start/Stop**: Loads `advapi32.dll` (fallback to SCM)

**Detection:** 
- Install: `ntdll.dll` loads WITHOUT subsequent `advapi32.dll` service APIs
- Start/Stop: `advapi32.dll` loads for ServiceController

---

## Detection Points

**Process Creation:**
- `NtServiceInstaller.exe` process spawn

**API Monitoring:**
- `ntdll!NtOpenKey`
- `ntdll!NtCreateKey`
- `ntdll!NtSetValueKey`
- `ntdll!NtDeleteKey`
- `ntdll!NtClose`

**Bypassed APIs:**
- `advapi32!CreateService` - NOT called during install
- `advapi32!DeleteService` - NOT called during uninstall
- `advapi32!OpenSCManager` - NOT called during install/uninstall

**Registry Modifications:**
- `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>`

**File System:**
- Service executable path (ImagePath value)

---

## Key Differences from .NET Version

| Feature | C++ Native | .NET (C#) |
|---------|------------|-----------|
| File Size | 15-25 KB | 35-65 MB |
| Runtime | None | .NET 8 required |
| Startup Time | <10ms | ~200ms |
| Memory Usage | 1-2 MB | 20-50 MB |
| Metadata | None | .NET assembly info |
| Obfuscation | Easier | Harder |
| Detection Surface | Minimal | Larger |

---

## Advantages over advapi32 Version

**Stealth:**
- No Event ID 7045 (service installed) in System log
- No Event ID 4697 (service installed) in Security log
- Only registry modification events (if auditing enabled)

**Evasion:**
- Bypasses advapi32.dll user-mode hooks
- No service-specific event log entries
- Appears as registry operations only

**Deployment:**
- Tiny file size (~20 KB)
- No runtime dependencies
- Single file executable
- Easy to embed/obfuscate

---

## Important Notes

1. **Reboot Requirement:**
   - Service created in registry only
   - SCM loads services on boot
   - Service will NOT appear in `sc query` or `Get-Service` until reboot
   - Use registry verification before reboot

2. **Administrator Privileges:**
   - All operations require Administrator privileges
   - Run PowerShell/CMD as Administrator

3. **Cleanup:**
   ```cmd
   rem Stop service (after reboot)
   NtServiceInstaller.exe stop ServiceName
   
   rem Uninstall
   NtServiceInstaller.exe uninstall ServiceName
   
   rem Manual registry cleanup if needed
   reg delete "HKLM\SYSTEM\CurrentControlSet\Services\ServiceName" /f
   ```

4. **OPSEC Considerations:**
   - Service names should blend in (e.g., "WindowsUpdate", "SecurityService")
   - Use legitimate-looking paths
   - Consider deployment timing (maintenance windows)
   - Monitor for registry auditing policies
