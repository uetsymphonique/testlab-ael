# LSASS Memory Dumping via Process Reflection

This is the **detection-side companion** to the tool docs. For build, full
evasion posture, XOR scheme, and execution flow see
[`../../resources/payloads/cred-access/LsassReflectDumping/README.md`](../../resources/payloads/cred-access/LsassReflectDumping/README.md).
For the emulation procedures (staging, exfil, decode) see
[`../iis-apppool-escalation-path/Phase 2.md`](../iis-apppool-escalation-path/Phase 2.md)
Step 3.

This file focuses on **what defenders can still see** after the binary's
evasions, the **detection chain**, and the rationale of the design choices
that shape that chain.

---

## Why Process Reflection

The classic LSASS dump pattern is the EDR golden signal:

```
OpenProcess(lsass.exe, PROCESS_ALL_ACCESS) → MiniDumpWriteDump(lsass_handle, *.dmp)
```

Three behavioural hits — a `0x1FFFFF` handle on `lsass.exe`, a `dbghelp.dll`
load, and a `.dmp` file with MDMP magic — all attributable to the same PID
within seconds. Any reasonable EDR ties them together.

`RtlCreateProcessReflection` (undocumented `ntdll` export) forks LSASS into a
new PID. `MiniDumpWriteDump` then runs against **the fork**, not LSASS — the
dump handle no longer carries the `lsass.exe` name, breaking name-based
correlation on the dump call. The output is callback-captured to a 75 MB
heap buffer, XOR-encrypted in place, and flushed once to a randomised temp
file. Each classic signal is moved or shaped so that simple-string rules
miss it — but every one of them still **fires** on a sufficiently behavioural
sensor. See [Detection Chain](#detection-chain) below.

---

## Design Posture

The binary on disk is `wdhelper.exe` (PE metadata claims *Diagnostic Tools /
Windows Diagnostic Helper*, `10.0.19041.1`). Each design choice maps to one
class of detection it is meant to evade:

| Axis | Choice | Evades |
|---|---|---|
| LSASS handle mask | `REFLECT_ACCESS` ≈ `0x4FA` (`CREATE_PROCESS | CREATE_THREAD | DUP_HANDLE | QUERY_INFORMATION | VM_OPERATION | VM_READ | VM_WRITE`) | EC=10 rules keyed on `GrantedAccess=0x1FFFFF` |
| Process discovery | `EnumProcesses` + `QueryFullProcessImageNameW` | Tool­help APIs commonly tagged as enumeration tradecraft |
| Reflection PID re-open | Reuse `info.ReflectionProcessHandle` for dump + terminate | A second EC=10 against the clone PID |
| Wait pattern | Bounded poll on `GetExitCodeProcess`, max ≈ 1 s | Two telemetry-visible `Sleep(5000)` idle waits + long process lifetime |
| `MiniDumpWriteDump` resolve | `LoadLibraryA("dbghelp.dll")` + `GetProcAddress` | Static IAT entry for `dbghelp.dll` (`dumpbin /imports`) |
| XOR key | `(0xA3 + i*0x5B) & 0xFF` (linear position-dependent) | Fixed first-byte signature; one decoder shared with `NtdsRawDump` / `CWLHerpaderping` |
| Output path | `%TEMP%\~DFxxxx.tmp` via `GetTempFileNameW(L"DF")` | Static filename / `.dmp` extension rules; CWD-relative artefact |
| PE metadata | Filled neutral `VS_VERSION_INFO` from `ReflectDump.rc` | "Fresh PE with empty version info" heuristic |

The underlying behaviours — a non-Microsoft binary with a `VM_READ`-capable
handle to `lsass.exe`, a `dbghelp` mapping, a large opaque file write — are
still present. The detection chain below maps to that shape.

---

## Detection Chain

Correlate Sysmon events within a **≈ 1 second window** on the IIS host.
Process lifetime is ≈ 1 s end-to-end thanks to the bounded poll, so a
long-window correlator will under-fire.

```
EC=10  wdhelper.exe → lsass.exe        GrantedAccess=0x04FA  (not 0x1FFFFF)
  ↓
EC=1   wdhelper.exe spawns child       PID=N, image=<reflection>, no command line, module list mirrors lsass
  ↓
EC=7   wdhelper.exe loads dbghelp.dll  (load is runtime, but still observable)
  ↓
EC=11  wdhelper.exe writes %TEMP%\~DFxxxx.tmp   single WriteFile, tens-to-hundreds of MB, high entropy
  ↓
EC=5   reflection PID terminated by wdhelper.exe
```

### Per-event detection value

**EC=10 — LSASS handle open.** Mask is `0x04FA`, not `0x1FFFFF`. Rules that
match only on `GrantedAccess=0x1FFFFF` will miss this. Behavioural rules
should key on **any mask combination granting `VM_READ` to `lsass.exe` from
a non-Microsoft-signed process** — that catches arbitrary mask values.

**EC=1 — reflection process creation.** The clone has an empty command line,
no on-disk image of its own, and its loaded-module list mirrors `lsass.exe`
(includes `lsasrv.dll`, `samsrv.dll`, etc.). Detection rule: a process with
no command line whose module list contains `lsasrv.dll` and whose parent is
not `services.exe`.

**EC=7 — `dbghelp.dll` module load.** Runtime resolution defeats *static*
IAT inspection, not runtime telemetry: `LoadLibraryA` triggers EC=7 the same
as a static IAT load. The high-signal correlation is **EC=10 (LSASS) + EC=7
(`dbghelp`) from the same unsigned PID within ≈ 1 s**.

**EC=11 — output file write.** Path matches `%TEMP%\~DF*.tmp` — same pattern
as legitimate MS Office/shell temp files, so path alone is not enough. The
distinguishing features are: single write (not chunked), large size (≥ 5 MB —
the binary's own validation threshold), and **written by the same PID that
just held a `VM_READ` handle on `lsass.exe`**. The file has no MDMP magic and
no PE headers — entropy ≈ 7.9 / byte over the whole file, including the
first few KB where legitimate temp files normally have low-entropy headers.

**EC=5 — reflection process exit.** Lifetime ≈ 1 s, terminated by parent.

### Authenticode pivot

The binary is not Authenticode-signed (this plan does not self-sign). The
`VS_VERSION_INFO` resource looks neutral but the PE has no signature blob.
Detection rule: any of the EC=10 / EC=7 / EC=11 hits above from a process
whose `OriginalFilename` claims to be a Windows component but whose
Authenticode signature is absent or invalid — high-signal pivot that
bypasses the metadata camouflage entirely.

### Static-analysis pivot

`dumpbin /imports wdhelper.exe` shows imports from `kernel32`, `ntdll`,
`advapi32`, `psapi` — and **no `dbghelp.dll`**. A binary whose static IAT
imports `psapi!EnumProcesses` and `kernel32!QueryFullProcessImageNameW` but
not `dbghelp.dll` is a credential-dump candidate by construction: the only
common reason to drop `dbghelp` from the IAT is to hide it from triage
tooling.

---

## Mitigations

- **PPL / RunAsPPL** on `lsass.exe` (`RunAsPPL=1` under
  `HKLM\System\CurrentControlSet\Control\Lsa`). Blocks `OpenProcess` with
  `VM_READ` from any non-PPL caller — the technique fails at the first
  `OpenProcess(REFLECT_ACCESS)`. Highest-leverage mitigation.
- **Credential Guard.** Moves NTLM/Kerberos secrets into an isolated VTL1
  process; an attacker who still gets a dump finds far less of value in it.
- **EDR LSASS handle-access rules that key on capability, not mask value.**
  Any mask combination granting `VM_READ` + `VM_OPERATION` to `lsass.exe`
  from an unsigned process should fire, regardless of whether the integer
  is `0x1FFFFF` or `0x04FA`.

---

## See Also

- [`../../resources/payloads/cred-access/LsassReflectDumping/README.md`](../../resources/payloads/cred-access/LsassReflectDumping/README.md) — build, full evasion posture, XOR decoder
- [`../iis-apppool-escalation-path/Phase 2.md`](../iis-apppool-escalation-path/Phase 2.md) — emulation usage (Step 3)
