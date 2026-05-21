# Phase 4 - Collection & Exfiltration: Plan & Deferred Steps

Target phase: `Emulation_Plan/iis-apppool-escalation-path/Phase 4.md`

---

## Implemented — iis-apppool-escalation-path (Steps 1–6)

Steps 1–6 are fully written in Phase 4.md. All run from DC01/IIS01 via the
`TESTLAB\Administrator` dnscat2 shell (Phase 3 end state).

| Step | Technique(s) | Description | Host |
|------|---|---|---|
| 1 | T1003.003 *(out-of-scope)*, T1005, T1074.001, T1119 | VSS shadow → ntds.dit + SYSTEM.hiv; reg save SAM + SECURITY → CertStore\ staging | DC01 |
| 2 | T1039 | Recursive config file sweep from `\\IIS01\C$\inetpub\` over admin share | DC01 → IIS01 |
| 3 | T1560.001 | `makecab.exe` cabinet archive (LOLBin, process-creation telemetry) | DC01 |
| 4 | T1560.002 | `.NET ZipFile::CreateFromDirectory` (DLL image-load + Script Block Logging) | DC01 |
| 5 | T1560.003 | PowerShell XOR loop (key `0x5A`) → `certstore.tmp`, ZIP deleted | DC01 |
| 6 | T1021.002, T1041 | `copy certstore.tmp \\IIS01\C$\inetpub\react.testlab.local\`; react2shell `download`; impacket-secretsdump offline | DC01 → IIS01 |

**T1041 resolved:** react2shell HTTP channel is the C2 for this path — `rce > download`
reads the archive in 8,192-byte chunks. dnscat2 DNS tunnel remains impractical for the
full archive (~1–5 KB/s vs. multi-MB ntds.dit).

---

## Deferred — Workstation Collection (T1113, T1115)

These steps require an **interactive desktop session** on WS01. Removed from Phase 4
because the iis-apppool path is server-focused; DC01 runs headless (session 0 only),
and `CopyFromScreen` on session 0 returns a blank bitmap.

Target: a dedicated **workstation-only emulation path** where the domain-user dnscat2
session on WS01 is the primary foothold (e.g., html-smuggling-path or a new WS01 chain).

**C2 prerequisite:** WS01 domain-user dnscat2 — from SYSVOL logon script persistence
(Phase 3 Step 8, `update.exe`) or initial-access delivery in a workstation path.

### Step A — Screen Capture (T1113)

**Host:** WS01 | **Actor:** TESTLAB\<domain user>

`.NET Graphics.CopyFromScreen` captures the active desktop without spawning any external
tool. Observable via DLL image loads and PNG file write only.

```text
command (ws01) > shell
C:\Windows\Temp> powershell -NoProfile -Command "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $s=[Windows.Forms.SystemInformation]::VirtualScreen; $b=New-Object Drawing.Bitmap $s.Width,$s.Height; $g=[Drawing.Graphics]::FromImage($b); $g.CopyFromScreen($s.Left,$s.Top,0,0,$b.Size); $b.Save('C:\Windows\Temp\screen.png'); $g.Dispose(); $b.Dispose()"
```

Detection surface:
- Sysmon Event 7 on WS01: `System.Windows.Forms.dll` + `System.Drawing.dll` into `powershell.exe` (unusual for background non-UI process)
- Sysmon Event 11 on WS01: `screen.png` created in `C:\Windows\Temp\`
- PowerShell Script Block Logging Event 4104: `CopyFromScreen` call visible

Reference Table row:

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Collection | T1113 | Screen Capture | Windows | Sysmon Event 7 on WS01: `System.Windows.Forms.dll` and `System.Drawing.dll` loaded into `powershell.exe` running under `update.exe` (logon-script dnscat2 parent) — unusual DLL set for a background non-UI process; Sysmon Event 11 on WS01: `screen.png` created in `C:\Windows\Temp\` by `powershell.exe`; PowerShell Script Block Logging Event 4104: `CopyFromScreen` call visible | Calibrated - Not Benign | `[Drawing.Graphics]::CopyFromScreen` captures the domain user's active desktop and saves it as `screen.png` in `C:\Windows\Temp\`; no external screenshot binary spawned — implemented entirely via in-process .NET API calls | WS01 | TESTLAB\<domain user> | - | -

---

### Step B — Clipboard Data (T1115)

**Host:** WS01 | **Actor:** TESTLAB\<domain user> (same session as Step A)

`Get-Clipboard` reads the active user clipboard. Output written to `clipboard.txt`
if non-empty. Weaker detection surface than API-hook-based theft — no cross-process
`OpenClipboard`/`GetClipboardData` event.

```text
C:\Windows\Temp> powershell -NoProfile -Command "$clip=Get-Clipboard -Raw; if ($clip) { $clip | Out-File -FilePath 'C:\Windows\Temp\clipboard.txt' -Encoding UTF8 }"
```

Detection surface:
- PowerShell Script Block Logging Event 4104: `Get-Clipboard -Raw` from `update.exe` parent
- Sysmon Event 11 on WS01: `clipboard.txt` written to `C:\Windows\Temp\`

Reference Table row:

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Collection | T1115 | Clipboard Data | Windows | PowerShell Script Block Logging Event 4104 on WS01: `Get-Clipboard -Raw` called from within `powershell.exe` spawned by `update.exe` (logon-script dnscat2 parent); Sysmon Event 11 on WS01: `clipboard.txt` written to `C:\Windows\Temp\` by `powershell.exe` | Not Calibrated - Not Benign | `Get-Clipboard -Raw` reads the active user clipboard; content written to `clipboard.txt` if non-empty; weaker detection surface than foreign-process API-hook clipboard theft — no `OpenClipboard`/`GetClipboardData` cross-process event generated | WS01 | TESTLAB\<domain user> | - | -

---

## Deferred — Alternative Exfiltration (T1048)

Require an attacker-side HTTP/HTTPS receiver not yet set up. Lower priority now that
T1041 via react2shell covers the main archive exfil.

- **T1048.003** (unencrypted): `Invoke-WebRequest` POST → Python `http.server` with POST handler
- **T1048.002** (asymmetric encrypted): HTTPS POST → Python `ssl.SSLContext` with self-signed cert
- **T1048.001** (symmetric encrypted): `AesCng` encrypt in PowerShell + HTTP POST — highest complexity

---

## Full Technique Coverage Summary

| Step | Technique(s) | Scope | Status | Category |
|------|---|---|---|---|
| 1 | T1003.003 | out-of-scope (explicit) | Implemented | Calibrated |
| 1 | T1005, T1074.001, T1119 | in-scope | Implemented | T1005 Calibrated; T1074.001 Not Calibrated; T1119 Calibrated |
| 2 | T1039 | in-scope | Implemented | Calibrated |
| 3 | T1560.001 | in-scope | Implemented | Calibrated |
| 4 | T1560.002 | in-scope | Implemented | Calibrated |
| 5 | T1560.003 | in-scope | Implemented | Calibrated |
| 6 | T1021.002, T1041 | in-scope | Implemented | Calibrated |
| A | T1113 | in-scope | **Deferred — workstation path** | Calibrated |
| B | T1115 | in-scope | **Deferred — workstation path** | Not Calibrated |
| — | T1048.001/002/003 | in-scope | **Deferred — needs receiver** | Calibrated |
