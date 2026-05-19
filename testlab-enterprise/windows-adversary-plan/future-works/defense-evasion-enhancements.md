# Defense Evasion Enhancements - Phase 1 Step 3

## Overview
Proposed additions to Step 3 (Server-Side RCE & Privilege Escalation) to expand Defense Evasion coverage per Scenario 1 scope. Focus on techniques that enhance payload stealth without impacting general detection evaluation.

---

## T1620 - Reflective Code Loading

**Target:** CWLHerpaderping payload staging flow

**Change:** Modify `CertEnrollAgent.exe` to accept dnscat2 PE bytes via stdin/CLI argument instead of reading from `C:\ProgramData\CertCA.bin`. Payload enters Herpaderping flow as memory buffer, eliminating standalone disk artifact.

**Impact:**
- Removes T1070.004 (File Deletion) row for `CertCA.bin`
- Adds Calibrated T1620 row for VirtualAlloc → memcpy chain
- Requires modification to `CWLHerpaderping/CWLImplant.cpp::GetPayloadBuffer()`

---

## T1497.001 - Virtualization/Sandbox Evasion: System Checks

**Target:** EfsPotato privilege escalation

**Change:** Add pre-execution checks in `CertEnrollSvc.exe` to detect VM/sandbox:
- WMI queries: `Win32_ComputerSystem.Manufacturer/Model` for VMware/VirtualBox/QEMU/Xen
- Registry: `HKLM\HARDWARE\DEVICEMAP\Scsi\...\Identifier` for VM disk controllers
- Process enumeration: procmon, procexp, wireshark, fiddler, debuggers

**Impact:**
- 3× Not Calibrated rows (WMI check, Registry check, Process check)
- Exit silently if sandbox detected
- Requires modification to `EfsPotato/CertEnrollSvc.cs::Main()`

---

## T1497.002 - User Activity Based Checks

**Target:** dnscat2 C2 beacon

**Change:** Delay DNS queries until user activity detected via `GetLastInputInfo()` loop (60s threshold, 10s recheck interval).

**Impact:**
- 1× Not Calibrated row for timing-based sandbox evasion
- Requires modification to dnscat2 client initialization
- Lower priority due to implementation complexity in Go client

---

## T1564.001 - Hidden Files and Directories

**Target:** Staged payloads

**Change:** Add `attrib.exe +h` commands after decoding binaries:
- `C:\Windows\Temp\CertEnrollSvc.exe`
- `C:\ProgramData\CertEnrollAgent.exe`
- Intermediate `.b64` files

**Impact:**
- 2× Calibrated rows for attrib.exe process creation
- Requires new `hide()` command in react2shell-tool `file_ops.py`
- Low implementation effort, high observability value

---

## Implementation Priority

1. **T1564.001** (Low effort, Calibrated, immediate value)
2. **T1497.001** (Low effort, Not Calibrated, realistic behavior)
3. **T1620** (Medium effort, Calibrated, eliminates disk artifact)
4. **T1497.002** (Medium effort, Not Calibrated, optional)

---

## Notes

- T1070.001, T1562.002 deferred per user request to avoid impacting detection evaluation
- All Not Calibrated assignments follow attack-behavior-methodology.md (pre-execution checks, setup steps)
- Source code modifications required for CertEnrollSvc.cs, CWLImplant.cpp, react2shell-tool
