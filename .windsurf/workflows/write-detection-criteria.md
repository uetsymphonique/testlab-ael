---
description: Write the Detection Criteria column for every Reference Table row in a Phase file — name the discriminative anomaly as one SIEM-queryable signal, or document its absence. The stable evidence base that assign-category reads to label; runs BEFORE assign-category
---

# Write Detection Criteria

Write the `Detection Criteria` column for **every** Reference Table row in a Phase file — a concrete signal where an anomaly exists, or a documented absence where it does not.

**Objective:** for each row, write the **vendor accountability signal** — the evidence that, if absent from a product's output, constitutes an attributable detection gap on the declared telemetry surface. Identifying the anomaly axis (how the behavior deviates from baseline) is the *method*; the *goal* is a signal where vendor failure to produce it is clearly the vendor's fault, not a measurement artifact. This column is the **stable evidence base** the labeling step reads: a concrete signal means the signal is writable and self-evidencing in practice (Conditions 1–3 hold); a documented absence names the condition that **prevents writing a signal at all**. **This skill runs first, before `/assign-category`, and covers all rows** — do not assume `Category` labels exist and do not skip rows. It does not assign Category; it produces the evidence Category reads.

> **`N/A` ≠ "this row will be Not-Calibrated".** A documented absence is reserved for a genuine condition-failure that makes a signal *unwritable* — no anomaly axis (C1), in-process/ghost-only so not evaluator-verifiable (C3), or artifact off the declared surface (C4 off-surface). A row whose signal **is** cleanly writable but that `/assign-category` will later demote for **redundancy or salience** (connective tissue — tool transfer, generic interpreter spawn, native recon command, transport plumbing, channel reuse) keeps its faithful positive signal here. That demotion is recorded by `/assign-category` as label rationale; it is **not** forced back into this column as a fake `N/A`. Do not couple the two: many Not-Calibrated rows correctly carry a clean positive signal.

> Why first: Category's logic is heuristic and expected to change; Detection Criteria is the stable artifact. Writing it first replaces the old "imagine whether a criteria could be written" guess (a hallucination risk) with evidence, and lets the label be re-derived later without re-writing criteria.

## Before starting

Read `plan-for-agent/guides/detection-criteria.md` — the anomaly-first principle, the two anomaly tiers and their formats, the anomaly→label diagnostic, the quality elements, and the reverse-diagnostic table.

## Steps

1. Ask the user: which Phase file? which rows? (or read from context). Default to **all rows** in the file — not just a labeled subset.
2. For each row, **identify the vendor accountability signal**: on the declared telemetry surface, what would a correctly-functioning product emit when this behavior occurs? Identifying what deviates from baseline is the method — the goal is a signal where vendor failure to emit it is attributable to a capability gap, not a measurement artifact.
3. Express that anomaly in the matching format:
   - **Intrinsic anomaly** (artifact rare by itself) → single-signal form `<process|principal> <action> <artifact|target> [on <host>]`.
   - **Contextual anomaly** (common artifacts, rare combination/sequence) → behavioral-pattern form.
   - **Random value** in the pattern → write the stable pattern, not the value.
4. Decide signal-vs-absence on **writability only**, not on the anticipated label:
   - If a concrete signal can be written → write it faithfully, **even if you expect the row to be Not-Calibrated** for redundancy or salience. Do not pre-empt `/assign-category` by downgrading a writable signal to `N/A`.
   - If no concrete signal can be written → **document the absence** instead of forcing a vague sentence: `N/A — <failing condition>: <one-line reason>` (e.g. `N/A — C3: in-memory only inside a ghost process, not evaluator-verifiable`). Reserve this for the three unwritable cases only: C1 (no anomaly axis), C3 (in-process/ghost, not evaluator-verifiable), C4 (artifact off the declared surface).
5. Run the forward checklist and the reverse diagnostic to decide signal-vs-absence — but do not assign Category here.

## Notes

- The signal must land on the declared measurement surface (Scenario 1 EDR default). An observable artifact that falls outside the declared surface is **not** a detection criteria — write `N/A — C4: artifact outside declared surface` rather than asserting an off-surface observable as a scoring point.
- Do not assign or change `Category` labels — that is `/assign-category`'s job downstream. This skill is **upstream**: it produces the evidence (signal or documented absence); the label is read from it later.
- A concrete signal does **not** by itself make a row Calibrated — a row with a perfectly writable signal can still be Not-Calibrated by `/assign-category` on **scope, redundancy, or salience** grounds (connective tissue that is observable but not a distinct scored opportunity). In all these cases the row **keeps its positive signal** here; the demotion lives in the Category column, never as a fake `N/A`. Identical signals on two rows are exactly how `/assign-category` detects a double-count, so write them faithfully.
- Mirror of the above: a documented `N/A` is **not** the general marker for "will be Not-Calibrated". It marks only that a signal could not be written (C1/C3/C4-off-surface). If you can write the signal, write it — even for tool transfers, generic `cmd.exe`/`powershell.exe` spawns, native recon commands, or transport plumbing that you expect to be demoted.
- State the anomaly as a positive pattern, never a list of absences (e.g., "sparse IAT — only 2 entries", not "CreateFile absent from IAT").
- The same conciseness discipline extends to the `Red Team Activity` column: one decisive sentence (see the guide's closing section) — tidy it if asked.
