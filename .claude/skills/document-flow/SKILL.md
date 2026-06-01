---
name: document-flow
description: Break a payload's source code into an ordered behavior list and persist it as a compact Flow.md beside the payload — the extraction half of the per-payload analysis; ATT&CK mapping is a separate map-technique pass after the user verifies
model: claude-sonnet-4-6
effort: high
allowed-tools: Read, Write, Glob, Grep
---

Break a payload's **source code** into an ordered list of atomic behaviors and persist it as a compact `Flow.md` in the payload directory.

**Objective:** produce the per-payload bridge between source code and the detection pipeline. `Flow.md` is a **neutral, precomputed analysis** — each behavior's `actor action artifact`, the artifact it produces and which downstream behavior consumes it, and a neutral baseline note. It later feeds `assign-category` and `write-detection-criteria`, which read it instead of re-deriving from source. Token efficiency is a hard requirement — this file is loaded into context when those skills run.

This skill runs in **two steps with a user-verification gate between them**:

1. **Extract behaviors** (this skill) — trace the source, write the behavior skeleton to `Flow.md` with the `Tactic / TID` column left as `—`. Stop and let the user verify.
2. **Map ATT&CK** (handed off, not automatic) — suggest running `map-technique` to fill the `Tactic / TID` column.

This skill owns step 1 only. It does **not** map techniques (`map-technique`), decide Calibrated/Not Calibrated (`assign-category`), name the anomaly axis or write Detection Criteria (`write-detection-criteria`), or author Phase content (`write-phase`). It emits the neutral behavior skeleton and stops.

## Before starting

Read `plan-for-agent/guides/behavior-breakdown.md` — the atomic-unit contract, the **source-code adapter** (trace execution flow, stop at event level not per-API, fold pure computation, keep intent-bearing no-artifact links tagged), and the six-class observable filter. This is the same guide `extract-behaviors` defers to; `Flow.md` is its output persisted in the payload's compact format.

## Steps

1. Ask the user (or read from context): which payload directory / source file(s)? Default the output to `<payload-dir>/Flow.md`.
2. Read the source. Trace execution flow from the entry point; identify the artifact-producing API/syscall sequences.
3. **Extract behaviors** (behavior-breakdown.md source adapter): one behavior = one intent = one observable action, written `actor action artifact`. Collapse a call sequence serving one artifact-outcome into one behavior; fold pure computation; keep intent-bearing no-artifact links tagged `[no-artifact]`. Keep temporal order.
4. For each behavior, record the **produces→consumes edge** (the artifact it leaves and which later behavior `#` reads it — what `assign-category` needs for its redundancy check) and a neutral **baseline context** note where one is obvious (the anomaly-axis seed for `write-detection-criteria`). Do **not** write the anomaly verdict, Category, or Detection Criteria.
5. **Write `Flow.md`** in the format below, with `Tactic / TID` left as `—` on every row.
6. **Stop at the verification gate.** Present the behavior skeleton and ask the user to verify granularity, edges, and ordering before mapping. Do **not** proceed to mapping yourself.
7. **Suggest the next step:** once the user is satisfied, run `map-technique` to fill the `Tactic / TID` column (one behavior may map to ≥1 tactics → ≥1 rows).

## `Flow.md` format

Keep it to a header plus one table. **One line per behavior. No multi-sentence cells.** Prose is the enemy here — every token competes with the downstream skill's reasoning budget.

```markdown
# <tool-name> — Flow

**Entry:** <entry point / main function>  ·  **Artifact summary:** <one line>

| # | Behavior (`actor action artifact`) | Artifact [class] → consumed by | Tactic / TID — Technique Name | Context (baseline) |
|---|---|---|---|---|
| 1 | implant resolves API by hash | — [no-artifact] → #3 | — | LoadLibrary/GetProcAddress absent from IAT |
| 2 | implant XOR-decrypts shellcode to heap | RWX alloc [memory] → #3 | — | private-commit RWX, no backing file |
| 3 | implant reflectively loads PE | thread in mapped region [memory] | — | start address outside any image |
```

- **`#`** — temporal order; reference these numbers in the consumed-by column.
- **Artifact [class]** — the six observable classes from behavior-breakdown.md (`file`, `process`, `registry`, `netconn`, `memory`, …) or `[no-artifact]` for intent-bearing links that leave no trace.
- **→ consumed by** — the later `#` that reads this artifact; omit if it is a chain terminal.
- **Tactic / TID — Technique Name** — leave as `—`; filled by the `map-technique` pass. Format: `<Tactic> / <TID> — <Technique Name>`. For sub-techniques, use the full `Parent: Sub-technique` name (e.g. `Defense Evasion / T1027.007 — Obfuscated Files or Information: Dynamic API Resolution`). For parent techniques with no sub, the name alone suffices (e.g. `Execution / T1106 — Native API`). Sub-technique preferred over parent when one fits.
- **Context (baseline)** — neutral one-liner; leave blank if none is obvious. Never an anomaly verdict.

## Notes

- The output of this skill is the behavior skeleton with `Tactic / TID = —`. The column is filled only after the user verifies and `map-technique` runs — same two-pass pattern as `write-phase` → `map-technique`.
- `Flow.md` is **per payload** (internal mechanics of one binary) — distinct from the Phase Reference Table (the operational, scored surface). The Phase table may collapse a whole payload into a few rows; `Flow.md` explains what is inside. `write-phase`/`map-technique` may pull from it when building rows.
- No Category, no Detection Criteria columns — that keeps `Flow.md` from duplicating or drifting against the scored Phase table.
- If the input is not source code (a chain description or raw command sequence), `extract-behaviors` is the right entry instead — this skill is for tracing a payload's code.
- Re-run when the source changes; `Flow.md` is a cache of the source analysis, not a one-time artifact.
