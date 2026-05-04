# ServiceInstaller (C++) - Technical Overview

## Technique Summary

Service installation using direct Windows API calls (`advapi32.dll`) to create and manage Windows services without spawning `sc.exe`. This C++ native implementation provides good stealth with minimal footprint (~20KB vs ~35MB .NET version) while maintaining immediate SCM integration.

**Key Characteristics:**
- Native C++ implementation (no runtime dependencies)
- Direct `advapi32.dll` API calls (CreateService, DeleteService)
- File size: ~15-20 KB
- No child process spawning (no sc.exe)
- Service immediately available in SCM
- Standard Windows event logging
- Moderate EDR evasion

## MITRE ATT&CK Mapping

**Tactic:** Persistence, Privilege Escalation

**Techniques:**
- **T1543.003** - Create or Modify System Process: Windows Service
  - Uses CreateService API to install service
  - Service configured for auto-start
  - Runs as SYSTEM account

**Sub-techniques:**
- Service installation via advapi32.dll APIs
- Registry modification at `HKLM\SYSTEM\CurrentControlSet\Services`

**Detection Opportunities:**
- System Event ID 7045 (New service installed)
- Security Event ID 4697 (Service installed - if auditing enabled)
- Sysmon Event ID 1 (Process creation)
- Sysmon Event ID 7 (Image loaded - advapi32.dll)
- Sysmon Event ID 12/13 (Registry modifications)

**Evasion Characteristics:**
- No sc.exe process spawning
- Direct API calls
- Minimal deployment footprint

---

## Build Instructions

### Prerequisites
- MinGW-w64 GCC or MSVC compiler
- Windows OS

### Build Commands

**MinGW (Recommended):**
```bash
g++ -o ServiceInstaller.exe main.cpp service_installer.cpp -ladvapi32 -municode -static -s -O2
```

**MSVC:**
```cmd
cl /EHsc /O2 /Fe:ServiceInstaller.exe main.cpp service_installer.cpp advapi32.lib /link /SUBSYSTEM:CONSOLE
```

**Output:** ~15-20 KB standalone executable

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
OpenSCManager(SC_MANAGER_CREATE_SERVICE)
  ↓
CreateService(SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START)
  ↓
ChangeServiceConfig2(SERVICE_CONFIG_DESCRIPTION) [optional]
  ↓
CloseServiceHandle()
```

**Event Logs:**
- **System Log** (Event ID 7045): New service installed
- **Security Log** (Event ID 4697): Service installed (if auditing enabled)
- **Sysmon** (Event ID 1): Process creation - ServiceInstaller.exe
- **Sysmon** (Event ID 13): Registry value set - Service registry keys
- **Sysmon** (Event ID 12): Registry object added - Service key created

**Log Sources:**
- `%SystemRoot%\System32\winevt\Logs\System.evtx`
- `%SystemRoot%\System32\winevt\Logs\Security.evtx`
- `%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`

---

### Start Service

```
User Command
  ↓
service_installer.cpp → StartServiceByName()
  ↓
OpenSCManager(SC_MANAGER_CONNECT)
  ↓
OpenService(SERVICE_START)
  ↓
StartService()
  ↓
CloseServiceHandle()
```

**Event Logs:**
- **System Log** (Event ID 7036): Service entered running state
- **Sysmon** (Event ID 1): Process creation - ServiceInstaller.exe

**Log Sources:**
- `%SystemRoot%\System32\winevt\Logs\System.evtx`
- `%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`

---

### Stop Service

```
User Command
  ↓
service_installer.cpp → StopServiceByName()
  ↓
OpenSCManager(SC_MANAGER_CONNECT)
  ↓
OpenService(SERVICE_STOP)
  ↓
ControlService(SERVICE_CONTROL_STOP)
  ↓
CloseServiceHandle()
```

**Event Logs:**
- **System Log** (Event ID 7036): Service entered stopped state
- **Sysmon** (Event ID 1): Process creation - ServiceInstaller.exe

**Log Sources:**
- `%SystemRoot%\System32\winevt\Logs\System.evtx`
- `%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`

---

### Uninstall Service

```
User Command
  ↓
service_installer.cpp → UninstallService()
  ↓
OpenSCManager(SC_MANAGER_CONNECT)
  ↓
OpenService(DELETE)
  ↓
ControlService(SERVICE_CONTROL_STOP) [if running]
  ↓
DeleteService()
  ↓
CloseServiceHandle()
```

**Event Logs:**
- **System Log** (Event ID 7040): Service deleted
- **Sysmon** (Event ID 1): Process creation - ServiceInstaller.exe
- **Sysmon** (Event ID 12): Registry object deleted - Service key removed
- **Sysmon** (Event ID 13): Registry values deleted

**Log Sources:**
- `%SystemRoot%\System32\winevt\Logs\System.evtx`
- `%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`

---

### Query Status

```
User Command
  ↓
service_installer.cpp → GetServiceStatusByName()
  ↓
OpenSCManager(SC_MANAGER_CONNECT)
  ↓
OpenService(SERVICE_QUERY_STATUS)
  ↓
QueryServiceStatus()
  ↓
CloseServiceHandle()
```

**Event Logs:**
- None (read-only operation)

---

## Usage Examples

### Install Service

```cmd
ServiceInstaller.exe install "C:\MyApp\service.exe" MyService "My Service" "Service Description"
```

**Immediate verification:**
```cmd
ServiceInstaller.exe status MyService
# or
sc query MyService
# or
Get-Service MyService
```

### Start Service

```cmd
ServiceInstaller.exe start MyService
```

### Check Status

```cmd
ServiceInstaller.exe status MyService
```

### Stop Service

```cmd
ServiceInstaller.exe stop MyService
```

### Uninstall Service

```cmd
ServiceInstaller.exe uninstall MyService
```

---

## API Calls Summary

| Operation | advapi32.dll APIs |
|-----------|-------------------|
| Install | OpenSCManager, CreateService, CloseServiceHandle |
| Start | OpenSCManager, OpenService, StartService, CloseServiceHandle |
| Stop | OpenSCManager, OpenService, ControlService, CloseServiceHandle |
| Uninstall | OpenSCManager, OpenService, ControlService, DeleteService, CloseServiceHandle |
| Status | OpenSCManager, OpenService, QueryServiceStatus, CloseServiceHandle |

---

## DLL Loading Events

**Sysmon Event ID 7 (Image Loaded):**

Process: `ServiceInstaller.exe`

**DLLs Loaded:**
- `ntdll.dll` - NT layer
- `kernel32.dll` - Core Windows APIs
- `advapi32.dll` - Service management APIs
- `sechost.dll` - Security host library

**Log Source:**
- `Microsoft-Windows-Sysmon%4Operational.evtx`

**Detection:** Look for `advapi32.dll` loads followed by service-related API calls.

---

## Detection Points

**Process Creation:**
- `ServiceInstaller.exe` process spawn

**API Monitoring:**
- `advapi32!OpenSCManager`
- `advapi32!CreateService`
- `advapi32!StartService`
- `advapi32!ControlService`
- `advapi32!DeleteService`

**Registry Modifications:**
- `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>`

**File System:**
- Service executable path access

---

## Key Differences from .NET Version

| Feature | C++ Native | .NET (C#) |
|---------|------------|-----------|
| File Size | 15-20 KB | 35-65 MB |
| Runtime | None | .NET 8 required |
| Startup Time | <10ms | ~200ms |
| Memory Usage | 1-2 MB | 20-50 MB |
| Metadata | None | .NET assembly info |
| Obfuscation | Easier | Harder |
| Detection Surface | Minimal | Larger |

---

## Advantages

**vs sc.exe:**
- No child process spawning
- No command-line arguments visible
- Direct API calls

**vs .NET version:**
- Tiny file size (~20 KB)
- No runtime dependencies
- Faster startup
- Less detection surface
- Easier to obfuscate

**vs syscalls version:**
- Service **immediately** available (no reboot)
- Simpler implementation
- Standard Windows APIs
- Easier to maintain

---

## Important Notes

1. **Administrator Privileges:**
   - All operations require Administrator privileges
   - Run PowerShell/CMD as Administrator

2. **Service Availability:**
   - Service immediately available in SCM after installation
   - Can start immediately (no reboot needed)
   - Shows up in `sc query` and `Get-Service`

3. **Cleanup:**
   ```cmd
   rem Stop service
   ServiceInstaller.exe stop ServiceName
   
   rem Uninstall
   ServiceInstaller.exe uninstall ServiceName
   ```

4. **OPSEC Considerations:**
   - Service names should blend in (e.g., "WindowsUpdate", "SecurityService")
   - Use legitimate-looking paths
   - Monitor for service creation event logs (Event ID 7045, 4697)
   - Consider deployment timing (maintenance windows)

5. **Event Log Artifacts:**
   - Event ID 7045 will be logged (service installed)
   - Event ID 4697 may be logged (if auditing enabled)
   - Sysmon will log process creation and registry modifications
   - More visible than syscalls approach but simpler to use
