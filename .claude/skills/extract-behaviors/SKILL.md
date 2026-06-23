---
name: extract-behaviors
description: Break an unstructured input (attack-chain description, payload source code, or raw command sequence) into an ordered list of atomic observable behaviors — the ingest-path entry that feeds map-technique and write-detection-criteria
model: claude-sonnet-4-6
effort: medium
allowed-tools: Read, Glob, Grep, Edit
---

Break an **unstructured input** into an ordered list of atomic, observable behaviors.

<HARD-GATE>
1. Output is the ordered behavior list. Do NOT write to any file unless the user agrees (step 6) — downstream skills share no memory, so offer first, then write only on yes.
2. Stay INCLUSIVE: extract setup and implementation-detail actions too. Do NOT pre-filter for calibration — that is `assign-category`'s job downstream.
3. Do NOT assign ATT&CK IDs, judge Category, name an anomaly axis, or write Detection Criteria. The `(context: …)` note is a neutral baseline observation, never an anomaly verdict.
4. Keep intent-bearing no-artifact actions, tagged `[no-artifact]` — never fold them away; they are chain links `assign-category` needs.
</HARD-GATE>

**Objective:** produce the shared atomic unit of the pipeline — *one behavior = one intent = one observable system action* — written as a neutral `<actor> <action> <target/artifact>` line, with no technique ID and no Calibrated/Not judgment. A behavior is **not** 1:1 with a Reference Table row: a single action can map to multiple tactics, so `map-technique` may fan one behavior into ≥1 rows. Getting granularity right here keeps distinct actions unbundled (so mapping does not lose rows) and hands `write-detection-criteria` a clean actor/action/artifact plus a neutral context note.

**Position in flow:** this is the entry of the **ingest path** — run it when the starting point is raw source code, a command sequence, or a CTI/chain description. When designing forward from a chosen scope technique, you do not need it.

Input may be: an attack-chain description / CTI, payload source code, or a raw command sequence. Output is just the list — **do not write to any file unless asked.**

## Before starting

Read `plan-for-agent/guides/behavior-breakdown.md` — the atomic-unit contract (and why it is not 1:1 with rows), granularity rules, inclusive-extraction principle, the six-class observable filter (tag, not gate), and the three input adapters.

## Steps

**Track coverage explicitly.** As you walk the input, create a task (or tracked checklist entry) for each segment / function / command you must account for, and mark it done only once its behavior(s) are emitted. This makes inclusive extraction observable — a segment left untracked is the usual cause of a silently dropped behavior.

1. Identify the **input type** (description / source code / command sequence) and read it from context or the path the user gives.
2. Extract intent-bearing actions using the matching adapter:
   - **Description** → segment at each intent shift; surface implied actions.
   - **Source code** → trace execution flow; pull artifact-producing API/syscalls. **Stop at event level, not per-API** — collapse a call sequence serving one artifact-outcome into one behavior. Fold pure computation.
   - **Command sequence** → each command / pipe / chained branch is a candidate; group by single intent+artifact; expand LOLBins into their real effect.
3. Apply granularity rules: split on intent/actor/artifact-class shift; never bundle two distinct actions in one line. Fold pure computation into the action it serves — but **keep** intent-bearing actions that leave no artifact, tagged `[no-artifact]` (they are chain links `assign-category` needs).
4. Stay **inclusive** — extract setup and implementation-detail actions too; do not pre-filter for calibration (that is `assign-category`'s job downstream).
5. Emit an ordered list (temporal order), one `<actor> <action> <target/artifact>` line per behavior. When feeding mapping/criteria, annotate each line with `[artifact class]` (or `[no-artifact]`) and an optional `(context: …)` note.
6. If the list will feed the map → category → criteria pipeline, **offer** to persist it as the Reference Table skeleton in the Phase file (downstream skill calls share no memory) — write only after the user agrees.

## Anti-Patterns — named rationalizations to reject

**"This step is just setup, leave it out."** Extraction is inclusive. Calibration filtering happens downstream in `assign-category` — dropping setup actions here silently removes rows that pass can never recover.

**"This action is suspicious / anomalous, I'll note that."** The `(context: …)` note is a neutral baseline observation only. Naming the anomaly axis is `write-detection-criteria`'s job — a premature verdict here biases the whole pipeline.

**"It leaves no artifact, so drop it."** Keep it, tagged `[no-artifact]`. Intent-bearing no-artifact actions are chain links `assign-category` needs for its redundancy check.

**"I'll just save it to the Phase file to be helpful."** Persist only after the user agrees (step 6). Offer, then write on yes — never write unprompted.

**"One behavior = one Reference Table row, so I'll merge actions to match."** A behavior is *not* 1:1 with a row — one action can span multiple tactics and `map-technique` fans it into several rows. Keep distinct actions unbundled.

## Red Flags — STOP if you are thinking:

| If you think… | The reality is… |
|---|---|
| "Skip the setup steps" | Extraction is inclusive — calibration filtering is `assign-category`'s job |
| "I'll flag this as anomalous" | Context is neutral baseline only — anomaly naming is `write-detection-criteria`'s |
| "No artifact, drop it" | Keep it tagged `[no-artifact]` — it's a chain link the redundancy check needs |
| "I'll save it to the Phase file" | Only after the user agrees — offer first |
| "Merge these to match one row" | Behavior ≠ 1:1 with row — keep actions distinct, mapping fans them |

## Terminal state

The terminal state is: an ordered (temporal) behavior list, one `<actor> <action> <target/artifact>` line each, annotated with `[artifact class]` (or `[no-artifact]`) and an optional neutral `(context: …)` note. Persisted to a file only if the user agreed in step 6.

Hand off to `/map-technique` next. Do NOT assign ATT&CK IDs, judge Category, name anomalies, or write Detection Criteria yourself.

## Notes

- This skill exists in parallel to `write-phase` (which has its own inline breakdown) — use it standalone when the input is unstructured or code, or when only the behavior list is needed. The granularity rules live once in `behavior-breakdown.md`; both skills defer to it.
- Do not assign ATT&CK IDs (`map-technique`), judge Category (`assign-category`), name the anomaly axis or write Detection Criteria (`write-detection-criteria`), or author Procedures (`write-phase`).
- The `(context: …)` note is a neutral observation about baseline, **not** an anomaly verdict — that naming belongs to `write-detection-criteria`.
