---
name: write-detection-criteria
description: Write the Detection Criteria column for every Reference Table row in a Phase file — name the discriminative anomaly as one SIEM-queryable signal, or document its absence. The stable evidence base that assign-category reads to label; runs BEFORE assign-category
model: claude-sonnet-4-6
effort: high
allowed-tools: Read, Edit, Grep
---

Write the `Detection Criteria` column for **every** Reference Table row in a Phase file — a concrete signal where an anomaly exists, or a documented absence where it does not.

**Objective:** for each row, name the **anomaly axis** — how the behavior deviates from baseline — in a form a product can write a rule on or feed into risk scoring. This column is the **stable evidence base** the labeling step reads: a concrete signal means the four conditions hold in practice; a documented absence names which condition fails. **This skill runs first, before `assign-category`, and covers all rows** — do not assume `Category` labels exist and do not skip rows. It does not assign Category; it produces the evidence Category reads.

> Why first: Category's logic is heuristic and expected to change; Detection Criteria is the stable artifact. Writing it first replaces the old "imagine whether a criteria could be written" guess (a hallucination risk) with evidence, and lets the label be re-derived later without re-writing criteria.

## Before starting

Read `plan-for-agent/guides/detection-criteria.md` — the anomaly-first principle, the two anomaly tiers and their formats, the anomaly→label diagnostic, the quality elements, and the reverse-diagnostic table.

## Steps

1. Ask the user: which Phase file? which rows? (or read from context). Default to **all rows** in the file — not just a labeled subset.
2. For each row, **identify the anomaly axis**: state what the behavior looks like in normal operation, then what deviates.
3. Express that anomaly in the matching format:
   - **Intrinsic anomaly** (artifact rare by itself) → single-signal form `<process|principal> <action> <artifact|target> [on <host>]`.
   - **Contextual anomaly** (common artifacts, rare combination/sequence) → behavioral-pattern form.
   - **Random value** in the pattern → write the stable pattern, not the value.
4. If no concrete signal can be written, **document the absence** instead of forcing a vague sentence — write `N/A — <failing condition>: <one-line reason>` (e.g. `N/A — C3: in-memory only inside a ghost process, not evaluator-verifiable`). This documented absence is the evidence `assign-category` reads to Not-Calibrate the row.
5. Run the forward checklist and the reverse diagnostic to decide signal-vs-absence — but do not assign Category here.

## Notes

- Do not assign or change `Category` labels — that is `assign-category`'s job downstream. This skill is **upstream**: it produces the evidence (signal or documented absence); the label is read from it later. There is no loop back — the label has not been assigned yet.
- A concrete signal does **not** by itself make a row Calibrated — a row with a perfectly writable signal can still be Not-Calibrated by `assign-category` on scope or redundancy grounds. Identical signals on two rows are exactly how it detects a double-count, so write them faithfully.
- State the anomaly as a positive pattern, never a list of absences (e.g., "sparse IAT — only 2 entries", not "CreateFile absent from IAT").
- The same conciseness discipline extends to the `Red Team Activity` column: one decisive sentence (see the guide's closing section) — tidy it if asked.
