# Phant0m Detection Telemetry Assessment

## T1562.002 - Impair Defenses: Disable Windows Event Logging

| Data Component | Event Name | Channel | Status | Reason |
|----------------|------------|---------|--------|--------|
| Service Metadata (DC0041) | EventCode=7035 | WinEventLog:System | NOT APPEARS | Service not stopped via SCM, threads killed directly |
| Service Metadata (DC0041) | EventCode=7036 | WinEventLog:System | NOT APPEARS | Service status remains "Running" |
| Application Log Content (DC0038) | EventCode=1102 | WinEventLog:Security | NOT APPEARS | Logs not cleared, service cannot write new events |
| Windows Registry Key Modification (DC0063) | EventCode=13, 14 | WinEventLog:Sysmon | NOT APPEARS | No registry modifications to EventLog service |
| Process Creation (DC0032) | EventCode=1 | WinEventLog:Sysmon | APPEARS | Phant0m process creation |
| **Process Access (DC0035)** | **EventCode=10** | **WinEventLog:Sysmon** | **APPEARS (CRITICAL)** | **OpenThread/OpenProcess on svchost.exe with THREAD_TERMINATE** |

---

## T1106 - Native API

| Data Component | Event Name | Channel | Status | Reason |
|----------------|------------|---------|--------|--------|
| Module Load (DC0016) | EventCode=7 | WinEventLog:Sysmon | APPEARS | Loads ntdll.dll, advapi32.dll via GetModuleHandleA |
| Process Access (DC0035) | EventCode=10 | WinEventLog:Sysmon | APPEARS | OpenThread/OpenProcess on svchost.exe |
| Process Creation (DC0032) | EventCode=1 | WinEventLog:Sysmon | APPEARS | Phant0m process creation |

**Native API Calls Telemetry**:

| API | Windows Event Log | ETW | EDR |
|-----|-------------------|-----|-----|
| `NtQueryInformationThread()` | No | Yes (custom consumer) | Yes (behavioral) |
| `I_QueryTagInformation()` | No | Limited | Yes (API hooking) |
| `ReadProcessMemory()` | No | Yes (custom consumer) | Yes (API hooking) |
| `TerminateThread()` | No | Yes (custom consumer) | Yes (API hooking) |

**Detection Methods**:
- **Windows Event Log**: No native telemetry
- **ETW**: Requires custom ETW consumers (e.g., NT Kernel Logger, Microsoft-Windows-Kernel-Audit-API-Calls provider)
- **EDR**: Behavioral detection, kernel callbacks, API hooking (Microsoft Defender for Endpoint, CrowdStrike, etc.)

---

## Critical Detection Point

**Sysmon Event 10 (Process Access)**:
- SourceImage: `phant0m.exe` (or unknown executable)
- TargetImage: `C:\Windows\System32\svchost.exe`
- GrantedAccess: `0x1430` (includes `THREAD_TERMINATE 0x0001`)
- CallTrace: Contains ntdll.dll
