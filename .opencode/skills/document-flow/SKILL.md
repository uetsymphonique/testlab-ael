---
name: document-flow
description: Break a payload's source code into an ordered behavior list and persist it as a compact Flow.md beside the payload — the extraction half of the per-payload analysis; ATT&CK mapping is a separate map-technique pass after the user verifies
effort: high
allowed-tools: Read, Write, Glob, Grep
---

Break a payload's **source code** into an ordered list of atomic behaviors and persist it as a compact `Flow.md` in the payload directory.

<HARD-GATE>
1. This skill OWNS extraction only. Write the behavior skeleton with `Tactic / TID` left as `—`. Do NOT map techniques, decide Category, name an anomaly axis, or write Detection Criteria.
2. STOP at the verification gate (step 6). Present the skeleton and let the user verify granularity / edges / ordering BEFORE mapping. Do NOT run `map-technique` yourself.
3. Token efficiency is a hard requirement: one line per behavior, no multi-sentence cells. `Flow.md` is loaded into downstream context — prose competes with their reasoning budget.
4. Keep intent-bearing no-artifact links tagged `[no-artifact]`; record the produces→consumes edge on every row.
</HARD-GATE>

**Objective:** produce the per-payload bridge between source code and the detection pipeline. `Flow.md` is a **neutral, precomputed analysis** — each behavior's `actor action artifact`, the artifact it produces and which downstream behavior consumes it, and a neutral baseline note. It later feeds `assign-category` and `write-detection-criteria`, which read it instead of re-deriving from source. Token efficiency is a hard requirement — this file is loaded into context when those skills run.

This skill runs in **two steps with a user-verification gate between them**:

1. **Extract behaviors** (this skill) — trace the source, write the behavior skeleton to `Flow.md` with the `Tactic / TID` column left as `—`. Stop and let the user verify.
2. **Map ATT&CK** (handed off, not automatic) — suggest running `map-technique` to fill the `Tactic / TID` column.

This skill owns step 1 only. It does **not** map techniques (`map-technique`), decide Calibrated/Not Calibrated (`assign-category`), name the anomaly axis or write Detection Criteria (`write-detection-criteria`), or author Phase content (`write-phase`). It emits the neutral behavior skeleton and stops.

**Before proceeding:** Read `references.md` in this skill folder — it contains the atomic-unit contract, the source-code adapter (trace execution flow, stop at event level not per-API, fold pure computation, keep intent-bearing no-artifact links tagged), the six-class observable filter, and the produces→consumes edge format.

## Steps

**Track coverage explicitly.** As you trace the source, create a task (or tracked checklist entry) for each artifact-producing call sequence you find, and mark it done only once its behavior row is written. A code path left untracked is the usual cause of a missing behavior in `Flow.md`.

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
- **Tactic / TID — Technique Name** — leave as `—`; filled by the `map-technique` pass. Format: `<Tactic> / <TID> — <Technique Name>`. For sub-techniques, use the full `Parent: Sub-technique` name (e.g. `Stealth / T1027.007 — Obfuscated Files or Information: Dynamic API Resolution`). For parent techniques with no sub, the name alone suffices (e.g. `Execution / T1106 — Native API`). Sub-technique preferred over parent when one fits.
- **Context (baseline)** — neutral one-liner; leave blank if none is obvious. Never an anomaly verdict.

## Anti-Patterns — named rationalizations to reject

**"I'll fill the Tactic/TID while I'm tracing the code."** Mapping is a separate, user-verified pass. Leave `—`; filling it here skips the verification gate that downstream granularity depends on.

**"The breakdown is obviously right — skip the verification gate."** The gate is mandatory. `assign-category` and `write-detection-criteria` read this file instead of re-deriving from source; unverified granularity propagates silently into both.

**"Add a sentence of detail to be safe."** Token budget is a hard constraint — `Flow.md` is loaded into downstream context. One line per behavior; prose competes directly with their reasoning budget.

**"This API call deserves its own row."** Stop at event level, not per-API. Fold a call sequence serving one artifact-outcome into one behavior (the source adapter in `behavior-breakdown.md`).

## Red Flags — STOP if you are thinking:

| If you think… | The reality is… |
|---|---|
| "Fill the Tactic/TID now" | Mapping is a separate verified pass — leave `—` and stop at the gate |
| "Granularity's fine, skip verification" | The gate is mandatory — downstream reads this instead of the source |
| "Add a clarifying sentence" | Token budget is hard — one line per behavior |
| "This API call is its own behavior" | Stop at event level — fold per-API sequences serving one artifact |
| "No artifact, drop this link" | Keep it tagged `[no-artifact]` — it's a chain edge the redundancy check needs |

## Terminal state

The terminal state is: `Flow.md` written in the prescribed format — one line per behavior, `Tactic / TID = —`, produces→consumes edges and neutral baseline context filled — and the skill STOPPED at the verification gate with the skeleton presented to the user.

Suggest running `map-technique` next (after the user verifies). Do NOT map techniques, write Detection Criteria, assign Category, or add those columns yourself.

## Notes

- The output of this skill is the behavior skeleton with `Tactic / TID = —`. The column is filled only after the user verifies and `map-technique` runs — same two-pass pattern as `write-phase` → `map-technique`.
- `Flow.md` is **per payload** (internal mechanics of one binary) — distinct from the Phase Reference Table (the operational, scored surface). The Phase table may collapse a whole payload into a few rows; `Flow.md` explains what is inside. `write-phase`/`map-technique` may pull from it when building rows.
- No Category, no Detection Criteria columns — that keeps `Flow.md` from duplicating or drifting against the scored Phase table.
- If the input is not source code (a chain description or raw command sequence), `extract-behaviors` is the right entry instead — this skill is for tracing a payload's code.
- Re-run when the source changes; `Flow.md` is a cache of the source analysis, not a one-time artifact.
