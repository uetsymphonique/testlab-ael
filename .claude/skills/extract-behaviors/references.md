# extract-behaviors — Reference

Atomic-unit contract, granularity rules, observable filter, and three input adapters. Read this file before extracting behaviors.

---

## The atomic unit

> **One behavior = one adversary intent = one observable system action.**

A behavior is **not** the same as a Reference Table row. A single observable action can map to more than one tactic — DLL side-loading is Execution **and** Stealth — so `map-technique` may fan one behavior into ≥1 rows. Keep the breakdown strictly at the *action* level; do not try to pre-split by technique.

Write each behavior as a neutral observation: `<actor> <action> <target/artifact>` — no technique ID, no Calibrated/Not judgment.

| | Example |
|---|---|
| ✅ | `EssosUpdate.exe loads wsdapi.dll from C:\Users\Public\` |
| ✅ | `waitfor.exe opens TCP connection to 191.44.44.199:443` |
| ❌ (two intents bundled) | `sideloads a DLL and beacons out to C2` |
| ❌ (pure internal compute, no artifact) | `XOR-decodes the payload in memory` |

---

## Granularity rules

**Split into separate behaviors when:**
- The **intent / tactic shifts** (e.g., sideload for execution → then network for C2 = two behaviors)
- The **actor changes** (a new process or principal performs the next action)
- A **different artifact class** is touched (file → registry → network → process → memory → identity)

> Split by *action*, not by technique. Use intent / actor / artifact-class shifts as the splitting signals — do **not** mentally map techniques to decide line boundaries. A single action that happens to span multiple tactics stays one line; `map-technique` fans it into multiple rows later.

**Merge / fold when:**
- A step is **pure internal computation** with no surfaced artifact — fold into the observable outcome it enables (decrypt-then-write = the write is the behavior)
- Multiple consecutive commands serve **one intent and one artifact** — collapse to one behavior

**Keep (do not discard as "internal"):**
- In-memory actions that leave an artifact on the advanced detection surface — RWX private allocation, unbacked executable thread, cross-process write. These are real observable behaviors even with no file/registry trace.

---

## Inclusive extraction

Extract **every** observable action, including ones that will likely end up Not Calibrated (setup steps, implementation details). **Do not pre-filter here.** Calibration is downstream (`assign-category`), and it needs the full ordered chain to reason about redundancy and implementation-detail relationships. A slightly over-extracted list is correct.

---

## Observable filter (tag, not gate)

An action becomes a behavior when it carries **adversary intent**. The six artifact classes tell you *whether it leaves an observable artifact* — but they are a **tag, not a gate**:

- **Has an artifact** → tag it with the class below
- **Intent-bearing but no observable artifact** (evasion step, in-memory action with no surface trace) → **keep it and tag `[no-artifact]`**. Do NOT drop it — that absence is exactly what `assign-category` needs
- **Pure computation with no intent of its own** (XOR math, hashing for API resolution, string building) → **fold** into the artifact-producing action it serves; this is the only thing that disappears

| Class | Example triggers |
|---|---|
| File | create / write / rename / read / delete on disk |
| Registry | set / create / delete key or value |
| Network | connect, listen, DNS query, data transfer |
| Process | spawn child, inject, open handle, suspend/resume |
| Memory | RWX allocation, unbacked thread, module overwrite (advanced surface only) |
| Identity | token manipulation, auth, credential use, account creation |

---

## Three input adapters

### [A] Attack-chain description / narrative / CTI

- Read for adversary actions; segment the narrative at each **intent shift**
- Surface **implied** actions the prose skips (e.g., "gained SYSTEM" implies a privilege-escalation action with its own artifact)
- Record tools/binaries named and the artifacts they imply

### [B] Payload source code

- **Trace the execution flow**, not the file top-to-bottom. Extract the API/syscalls that produce artifacts: `CreateFile`, `RegSetValue`, `connect`/`send`, `CreateProcess`, `WriteProcessMemory`, `CreateRemoteThread`, `VirtualAlloc(RWX)`, token APIs, etc.
- For each, derive the behavior line: actor = which process runs this code; action = the API's observable effect; artifact = the concrete path / key / endpoint / target
- **Stop at the level a detection product would observe as one event, not per-API call.** Collapse a call sequence serving one artifact-outcome into one behavior (`CreateFile`+`SetFilePointer`+`ReadFile`+`CloseHandle` on one path = one "reads `<path>`" behavior)
- Fold pure computation (decode loops, hashing for API resolution) into the action it serves; keep only if it surfaces a memory artifact on the advanced surface
- Source code reveals exact artifacts a description hides (paths, ports, registry keys, injection targets) — but also contains dead branches, unused evasion scaffolding, and implicit intent. Prefer source when artifacts matter; prefer author description when intent is what matters

### [C] Raw command sequence

- Treat each command, pipe stage, and chained-operator branch (`&&`, `|`, `;`) as a candidate action
- **Group** consecutive commands that serve one intent and one artifact into a single behavior; **split** a one-liner that does two distinct things
- Expand LOLBin invocations into their real effect (e.g., `rundll32 comsvcs.dll … MiniDump` = a process opening a handle to LSASS and writing a dump file — two artifact classes)

---

## Output format

An ordered list (temporal execution order), one line per behavior:

```
1. <actor> <action> <target/artifact>
2. <actor> <action> <target/artifact>
...
```

When feeding the map → criteria → category pipeline, annotate each line with:
- **[class]** — the artifact class, or `[no-artifact]`
- **(context: …)** — a one-clause neutral note on what normal looks like; this is an *observation*, not a detection judgment

Example annotated line:
`3. w3wp.exe spawns cmd.exe  [process] (context: IIS worker never spawns a shell in normal operation)`
