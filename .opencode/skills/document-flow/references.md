# document-flow — Reference

Atomic-unit contract, source-code adapter, and observable filter. Read this file before tracing a payload.

---

## The atomic unit

> **One behavior = one adversary intent = one observable system action.**

A behavior is **not** the same as a Reference Table row. `map-technique` may fan one behavior into ≥1 rows (e.g. DLL side-loading is Execution **and** Stealth). Keep the breakdown at the *action* level; do not pre-split by technique.

Write each behavior as: `<actor> <action> <target/artifact>` — no technique ID, no Calibrated/Not judgment, no anomaly verdict.

| | Example |
|---|---|
| correct | `implant reflectively loads PE into svchost.exe` |
| correct | `implant opens TCP connection to 191.44.44.199:443` |
| wrong (two intents bundled) | `decrypts shellcode and executes it` |
| wrong (pure compute, no artifact) | `XOR-decodes the payload buffer` |

---

## Source-code adapter

Trace the **execution flow** from the entry point — not the file top-to-bottom. Extract the API/syscall sequences that produce observable artifacts.

**Stopping floor — stop at the level a detection product would observe as one event, not per-API call.** Collapse a call sequence serving one artifact-outcome into one behavior:
- `CreateFile` + `SetFilePointer` + `ReadFile` + `CloseHandle` on one path = one "reads `<path>`" behavior
- `VirtualAlloc(RWX)` + `memcpy` + `CreateRemoteThread` = one "injects shellcode into `<target>`" behavior

**Key API families to watch:**

| API / syscall family | Observable artifact |
|---|---|
| `CreateFile`, `WriteFile`, `DeleteFile` | File on disk |
| `RegSetValue`, `RegCreateKey`, `RegDeleteKey` | Registry key/value |
| `connect`, `send`, `recv`, DNS resolution | Network connection |
| `CreateProcess`, `ShellExecute`, `WinExec` | Child process |
| `WriteProcessMemory`, `CreateRemoteThread`, `QueueUserAPC` | Cross-process injection |
| `VirtualAlloc(RWX)`, `VirtualProtect(RWX)` | RWX private allocation (memory) |
| `OpenProcessToken`, `DuplicateToken`, `ImpersonateLoggedOnUser` | Token / identity |

**Fold** pure computation into the action it serves:
- Decode/decrypt loops, hash-based API resolution, string building → fold unless the computation itself surfaces a memory artifact on the advanced detection surface

**Keep** intent-bearing actions that leave no artifact, tagged `[no-artifact]` — never fold them away; they are chain links `assign-category` needs for its redundancy check.

---

## Observable filter

Tag each behavior with the artifact class it leaves. The class is a **tag, not a gate** — keep intent-bearing actions either way:

| Class | Example triggers |
|---|---|
| `file` | create / write / rename / read / delete on disk |
| `registry` | set / create / delete key or value |
| `network` | connect, listen, DNS query, data transfer |
| `process` | spawn child, inject, open handle |
| `memory` | RWX allocation, unbacked thread, module overwrite |
| `identity` | token manipulation, auth, credential use |
| `[no-artifact]` | intent-bearing action with no observable trace — keep, never fold |

---

## Produces → consumes edges

For each behavior, record which artifact it leaves and which downstream behavior `#` reads it. This is what `assign-category` uses for its redundancy (Q-B) check — a missing edge hides whether a behavior is an implementation detail of a later scored row.

Format: `<artifact summary> [class] → #<N>` (omit `→` if it is a chain terminal).

Example: `RWX alloc [memory] → #3`
