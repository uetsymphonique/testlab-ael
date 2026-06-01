# Guide: Breaking Down Red Team Activity into Behaviors

> **Consumed by:** `/extract-behaviors`, `/write-phase`, `/document-flow` — see [pipeline.md](../pipeline.md)

How to turn an **unstructured input** — an attack-chain description, payload source code, or a raw command sequence — into an **ordered list of atomic behaviors**. This is the upstream extraction step: its output feeds `map-technique` (each behavior → tactic/technique) and serves as a reference channel for `write-detection-criteria` (each behavior already carries the actor/action/artifact and an anomaly seed).

This guide only **extracts and orders behaviors**. It does not assign ATT&CK IDs, judge Calibrated/Not Calibrated, write final Detection Criteria, or author Procedures — those are separate passes.

---

## The atomic unit (the shared contract)

A **behavior** is the unit every downstream pass consumes. Get the granularity right here and mapping, calibration, and criteria all become straightforward.

> **One behavior = one adversary intent = one observable system action.**

A behavior is **not** the same as a Reference Table row. A single observable action can map to more than one tactic — DLL side-loading is Execution **and** Defense Evasion — so `map-technique` may fan one behavior out into **≥1 rows**. Keep the breakdown strictly at the *action* level; do not try to pre-split by technique, and do not assume one line will become exactly one row.

Write each behavior as a **neutral observation** in the form:

`<actor> <action> <target/artifact>`

— the same skeleton as the Detection Criteria / Red Team Activity columns, but **without** a technique ID and **without** any Calibrated/Not judgment. Those are added later. The breakdown's only job is to surface the right actions at the right granularity.

| | Example |
|---|---|
| ✅ | `EssosUpdate.exe loads wsdapi.dll from C:\Users\Public\` |
| ✅ | `waitfor.exe opens TCP connection to 191.44.44.199:443` |
| ❌ (two intents bundled) | `sideloads a DLL and beacons out to C2` |
| ❌ (pure internal compute, no artifact) | `XOR-decodes the payload in memory` |

---

## Granularity rules

**Split into separate behaviors when:**
- The **intent / tactic shifts** (e.g., sideload for execution → then network for C2 = two behaviors).
- The **actor changes** (a new process or principal performs the next action).
- A **different artifact class** is touched (file → registry → network → process → memory → identity).
> **Split by *action*, not by technique.** Use intent / actor / artifact-class shifts above as the splitting signals — do **not** mentally map techniques to decide line boundaries (that would pull `map-technique`'s job upstream and create a circular dependency). A *single* action that happens to span multiple tactics — e.g. side-loading — stays **one line**; `map-technique` fans it into multiple rows later. Conversely, two genuinely separate actions stay on separate lines regardless of how they map.

**Merge / fold when:**
- A step is **pure internal computation** with no surfaced artifact — fold it into the observable outcome it enables (decrypt-then-write = the write is the behavior; the decrypt is its mechanism).
- Multiple consecutive commands serve **one intent and one artifact** — collapse to one behavior.

**Keep (do not discard as "internal"):**
- In-memory actions that leave an artifact on the advanced detection surface — RWX private allocation, unbacked executable thread, cross-process write. These are real observable behaviors even with no file/registry trace.

---

## Inclusive extraction

Extract **every** observable action, including ones that will likely end up Not Calibrated (setup steps, implementation details). **Do not pre-filter here.** Calibration is a downstream decision (`assign-category`), and it needs the full ordered chain to reason about redundancy and implementation-detail relationships. A breakdown that is slightly *over-extracted* relative to the final scored set is correct.

---

## The observable filter

An action becomes a behavior when it carries **adversary intent**. The six artifact classes below tell you *whether it leaves an observable artifact* — but that is a **tag, not a gate**. Keep intent-bearing actions either way:

- **Has an artifact** → tag it with the class(es) below.
- **Intent-bearing but produces no observable artifact** (e.g. an evasion step whose whole purpose is to avoid observation, an in-memory action with no surface trace) → **keep it and tag `[no-artifact]`**. Do **not** drop it. That absence is exactly what `assign-category` needs to justify a Not-Calibrated step ("all actions in this step are in-memory inside a ghost process"). Dropping it here hides the chain link.
- **Pure computation with no intent of its own** (XOR math, hashing for API resolution, string building) → **fold** into the artifact-producing action it serves. This is the only thing that disappears.

The six artifact classes (the tag, when an artifact exists):

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

The question is always the same — *"which actions touch the system?"* — but the extraction method differs by input.

### [A] Attack-chain description / narrative / CTI

- Read for adversary actions; segment the narrative at each **intent shift**.
- Surface **implied** actions the prose skips (e.g., "gained SYSTEM" implies a privilege-escalation action with its own artifact).
- Record tools/binaries named and the artifacts they imply.

### [B] Payload source code

- **Trace the execution flow**, not the file top-to-bottom. Extract the API/syscalls that produce artifacts: `CreateFile`, `RegSetValue`, `connect`/`send`, `CreateProcess`, `WriteProcessMemory`, `CreateRemoteThread`, `VirtualAlloc(RWX)`, token APIs, etc.
- For each, derive the behavior line: actor = which process runs this code; action = the API's observable effect; artifact = the concrete path / key / endpoint / target.
- **Stopping floor — extract at the level a detection product would observe as one event, not at the level of every API call.** Collapse the call sequence that serves a single artifact-outcome into one behavior (`CreateFile`+`SetFilePointer`+`ReadFile`+`CloseHandle` on one path = one "reads `<path>`" behavior). Going finer produces noise that burdens `map-technique` and `assign-category`.
- Fold pure computation (decode loops, hashing for API resolution) into the action it serves; keep it only if it surfaces a memory artifact on the advanced surface.
- Source code is **high-value but noisy**: it reveals artifacts a description hides (exact paths, ports, registry keys, injection targets) — but it also contains dead branches, unused evasion scaffolding, and intent that is only implicit. Prefer source when the artifacts matter and the author is unavailable; prefer a description from the author when intent is what matters and the code is self-authored.

### [C] Raw command sequence

- Treat each command, pipe stage, and chained-operator branch (`&&`, `|`, `;`) as a candidate action.
- **Group** consecutive commands that serve one intent and one artifact into a single behavior; **split** a one-liner that does two distinct things.
- Expand LOLBin invocations into their real effect (e.g., `rundll32 comsvcs.dll … MiniDump` = a process opening a handle to LSASS and writing a dump file — two artifact classes).

---

## Output format

An **ordered list** (temporal execution order), one line per behavior:

```
1. <actor> <action> <target/artifact>
2. <actor> <action> <target/artifact>
...
```

Default output is just these lines — do **not** write to any file unless asked. When the list is feeding `map-technique` or `write-detection-criteria`, optionally annotate each line with two lightweight tags:

- **[class]** — the artifact class (file / registry / network / process / memory / identity), or `[no-artifact]` for an intent-bearing action with no observable trace. This seeds the tactic guess and flags chain links `assign-category` must account for.
- **(context: …)** — a one-clause neutral note on what normal looks like or what deviates. This is an *observation*, not a detection judgment; `write-detection-criteria` is the only pass that names the anomaly axis. Do not phrase it as a finished criteria.

Example annotated line:
`3. w3wp.exe spawns cmd.exe  [process] (context: IIS worker never spawns a shell in normal operation)`

**Persisting in a pipeline.** `map-technique` → `assign-category` → `write-detection-criteria` are separate skill calls with no shared memory; an ephemeral chat list forces each to re-derive it. When the breakdown will feed that pipeline, **offer** to persist the list as the Reference Table skeleton in the Phase file (one row per behavior, technique/criteria/category left blank) so downstream passes anchor to it — but only write after the user agrees.

---

## Boundaries

- **Does not assign ATT&CK IDs** → `map-technique` (a behavior may still fan into ≥1 rows there).
- **Does not judge Calibrated/Not** → `assign-category` (breakdown is inclusive; calibration filters later).
- **Does not name the anomaly axis or write Detection Criteria** → `write-detection-criteria` (breakdown only records neutral context).
- **Does not author Procedures or the Phase file** → `write-phase`.
