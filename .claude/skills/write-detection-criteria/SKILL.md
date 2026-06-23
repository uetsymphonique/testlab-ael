---
name: write-detection-criteria
description: Write the Detection Criteria column for every Reference Table row in a Phase file — name the discriminative anomaly as one SIEM-queryable signal, or document its absence. The stable evidence base that assign-category reads to label; runs BEFORE assign-category
model: claude-sonnet-4-6
effort: high
allowed-tools: Read, Edit, Grep
---

Write the `Detection Criteria` column for **every** Reference Table row in a Phase file — a concrete signal where an anomaly exists, or a documented absence where it does not.

<HARD-GATE>
This skill runs BEFORE `assign-category` and covers EVERY row — no exceptions, regardless of how trivial a behavior appears.
1. Do NOT skip a row because it "looks like setup" or "is obviously Not-Calibrated". Every row gets a Detection Criteria cell.
2. Decide signal-vs-absence on WRITABILITY ALONE. If a concrete signal can be written, write it — even when you expect the row to be demoted later. Never downgrade a writable signal to `N/A` to pre-empt `assign-category`.
3. Do NOT assign, change, or imagine a `Category` label. You produce evidence; the label is read off it downstream.
</HARD-GATE>

**Objective:** for each row, write the **vendor accountability signal** — the evidence that, if absent from a product's output, constitutes an attributable detection gap on the declared telemetry surface. Identifying the anomaly axis (how the behavior deviates from baseline) is the *method*; the *goal* is a signal where vendor failure to produce it is clearly the vendor's fault, not a measurement artifact. This column is the **stable evidence base** the labeling step reads: a concrete signal means the signal is writable and self-evidencing in practice (Conditions 1–3 hold); a documented absence names the condition that **prevents writing a signal at all**. **This skill runs first, before `assign-category`, and covers all rows** — do not assume `Category` labels exist and do not skip rows. It does not assign Category; it produces the evidence Category reads.

> **`N/A` ≠ "this row will be Not-Calibrated".** A documented absence is reserved for a genuine condition-failure that makes a signal *unwritable* — no anomaly axis (C1), a one-off value with no stable pattern to write (C2), in-process/ghost-only so not evaluator-verifiable (C3), or artifact off the declared surface (C4 off-surface). A row whose signal **is** cleanly writable but that `assign-category` will later demote for **redundancy or salience** (connective tissue — tool transfer, generic interpreter spawn, native recon command, transport plumbing, channel reuse) keeps its faithful positive signal here. That demotion is recorded by `assign-category` as label rationale; it is **not** forced back into this column as a fake `N/A`. Do not couple the two: many Not-Calibrated rows correctly carry a clean positive signal.

> Why first: Category's logic is heuristic and expected to change; Detection Criteria is the stable artifact. Writing it first replaces the old "imagine whether a criteria could be written" guess (a hallucination risk) with evidence, and lets the label be re-derived later without re-writing criteria.

## Before starting

Read `plan-for-agent/guides/detection-criteria.md` — the anomaly-first principle, the two anomaly tiers and their formats, the anomaly→label diagnostic, the quality elements, and the reverse-diagnostic table.

## Steps

**Track coverage explicitly.** Before writing any criteria, enumerate every Reference Table row and create one task per row (or a tracked checklist). Mark a row complete only after its Detection Criteria cell is written. This makes "covered every row" observable, not merely claimed — do not report done while any row is unmarked.

1. Ask the user: which Phase file? which rows? (or read from context). Default to **all rows** in the file — not just a labeled subset.
2. For each row, **identify the vendor accountability signal**: on the declared telemetry surface, what would a correctly-functioning product emit when this behavior occurs? Identifying what deviates from baseline is the method — the goal is a signal where vendor failure to emit it is attributable to a capability gap, not a measurement artifact.
3. Express that anomaly in the matching format:
   - **Intrinsic anomaly** (artifact rare by itself) → single-signal form `<process|principal> <action> <artifact|target> [on <host>]`.
   - **Contextual anomaly** (common artifacts, rare combination/sequence) → behavioral-pattern form.
   - **Random value** in the pattern → write the stable pattern, not the value.
4. Decide signal-vs-absence on **writability only**, not on the anticipated label:
   - If a concrete signal can be written → write it faithfully, **even if you expect the row to be Not-Calibrated** for redundancy or salience. Do not pre-empt `assign-category` by downgrading a writable signal to `N/A`.
   - If no concrete signal can be written → **document the absence** instead of forcing a vague sentence: `N/A — <failing condition>: <one-line reason>` (e.g. `N/A — C3: in-memory only inside a ghost process, not evaluator-verifiable`). Reserve this for the four unwritable cases only: C1 (no anomaly axis), C2 (only true for one specific run, no stable pattern to write), C3 (in-process/ghost, not evaluator-verifiable), C4 (artifact off the declared surface).
5. Run the forward checklist and the reverse diagnostic to decide signal-vs-absence — but do not assign Category here.

## Anti-Patterns — named rationalizations to reject

**"This row is obviously Not-Calibrated, I'll just write `N/A`."** `N/A` is reserved for a signal that is *unwritable* (C1 / C2 / C3 / C4-off-surface). A writable signal on a row you expect to be demoted for redundancy or salience still gets its faithful positive signal — the demotion is `assign-category`'s job, recorded in the Category column, never as a fake `N/A` here. Coupling the two is the single most common error.

**"These rows are setup / connective tissue — I'll skip them."** Coverage is every row. A skipped row has no evidence base, forcing `assign-category` back into imagining criteria — exactly the hallucination this ordering was built to remove.

**"The signal here is identical to the row above — I'll vague it or write 'see above'."** Each row needs its own complete evidence. `assign-category` detects a double-count by matching the **same technique + same artifact/target** across rows (not by verbatim-identical text) — a vagued or "see above" row hides whether it is genuinely redundant and leaves it with no evidence base. Write each row's signal faithfully and in full; do not blur them.

**"I can write the criteria and decide the label in the same pass."** The label has not been assigned yet, on purpose. Mixing the two re-introduces the "imagine whether a criteria could be written" guess. Write only the evidence.

## Red Flags — STOP if you are thinking:

| If you think… | The reality is… |
|---|---|
| "This'll be Not-Calibrated anyway, write `N/A`" | `N/A` ≠ Not-Calibrated. A writable signal gets written; demotion is the Category column's job |
| "These are just setup rows, skip them" | Every skipped row forces `assign-category` to hallucinate criteria — the exact failure this order prevents |
| "Same signal as the row above, I'll shorten it" | Each row needs its own evidence; `assign-category` matches double-counts on technique+artifact, not on your shortening — write both faithfully |
| "Let me label Category while I'm here" | Category is not assigned yet, by design — produce evidence only |
| "It's observable, so write it as the signal" | Off the declared surface = `N/A — C4`, not a scoring signal |

## Terminal state

The terminal state is: the `Detection Criteria` column is filled for **every** row — each cell holds either a concrete signal or a documented `N/A — <Cx>: <reason>` absence — and no other column has been touched.

Do NOT invoke `assign-category`, edit the `Category` column, or assign labels — the label has not been assigned yet and is not yours to write. Reporting completion (or suggesting the user run `assign-category` next) is the only exit.

## Notes

- The signal must land on the declared measurement surface, read from the **Surface Profile** — the Layer 0 table in `category-assignment.md` (Scenario 1 EDR default). This is the *same* profile `assign-category`'s Question A reads; the Surface test here and the scope check there must agree on one pinned profile, so a signal written on-surface is not later rejected as off-surface. An observable artifact outside that surface is **not** a detection criteria — write `N/A — C4: artifact outside declared surface` rather than asserting an off-surface observable as a scoring point.
- **Anchor an environment-relative baseline.** A signal like `w3wp.exe spawns cmd.exe` assumes a clean web tier; on a host that runs operator scripts the same event is benign. When the anomaly rests on a clean-baseline assumption, anchor it to the host role/build stated in the plan's `summary.md` / setup docs rather than leaving it implicit — otherwise two authors on two environments write conflicting "correct" signals.
- Do not assign or change `Category` labels — that is `assign-category`'s job downstream. This skill is **upstream**: it produces the evidence (signal or documented absence); the label is read from it later. There is no loop back — the label has not been assigned yet.
- A concrete signal does **not** by itself make a row Calibrated — a row with a perfectly writable signal can still be Not-Calibrated by `assign-category` on **scope, redundancy, or salience** grounds (connective tissue that is observable but not a distinct scored opportunity). In all these cases the row **keeps its positive signal** here; the demotion lives in the Category column, never as a fake `N/A`. `assign-category` detects a double-count by the same technique + same artifact/target across two rows (not by verbatim-identical text), so write each row's signal faithfully and in full rather than blurring one into the other.
- Mirror of the above: a documented `N/A` is **not** the general marker for "will be Not-Calibrated". It marks only that a signal could not be written (C1/C2/C3/C4-off-surface). If you can write the signal, write it — even for tool transfers, generic `cmd.exe`/`powershell.exe` spawns, native recon commands, or transport plumbing that you expect to be demoted.
- State the anomaly as a positive pattern, never a list of absences (e.g., "sparse IAT — only 2 entries", not "CreateFile absent from IAT").
- The same conciseness discipline extends to the `Red Team Activity` column: one decisive sentence (see the guide's closing section) — tidy it if asked.
