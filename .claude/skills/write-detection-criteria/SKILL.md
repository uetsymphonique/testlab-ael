---
name: write-detection-criteria
description: Write the Detection Criteria column for every Reference Table row in a Phase file — name the discriminative anomaly as one SIEM-queryable signal, or document its absence. The stable evidence base that assign-category reads to label; runs BEFORE assign-category
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

**Objective:** for each row, write the **vendor accountability signal** — the evidence that, if absent from a product's output, constitutes an attributable detection gap on the declared telemetry surface. Identifying the anomaly axis (how the behavior deviates from baseline) is the *method*; the *goal* is a signal where vendor failure to produce it is clearly the vendor's fault, not a measurement artifact. This column is the **stable evidence base** the labeling step reads.

> **`N/A` ≠ "this row will be Not-Calibrated".** A documented absence is reserved for a genuine condition-failure that makes a signal *unwritable* — three absolute cases: no discriminative signal can be written (C1), artifact not evaluator-verifiable (C2), or artifact off the declared surface (C3). A row whose signal **is** cleanly writable but that `assign-category` will later demote for **redundancy or salience** keeps its faithful positive signal here. That demotion is recorded by `assign-category` as label rationale; it is **not** forced back into this column as a fake `N/A`.

> Why first: Category's logic is heuristic and expected to change; Detection Criteria is the stable artifact. Writing it first replaces the old "imagine whether a criteria could be written" guess with evidence, and lets the label be re-derived later without re-writing criteria.

---

## Signal formats

Two tiers — identifying which tier the anomaly lives in **is** the act of choosing the format. See **references.md → Signal format examples** for correct/wrong examples of each.

**Tier 1 — Intrinsic anomaly** (artifact rare by itself): the event barely appears in any baseline; a single rule suffices.
`<process | principal> <action> <artifact | target> [on <host>]`

**Tier 2 — Contextual anomaly** (combination/sequence is rare; individual artifacts are common): no single fragment alerts; the combination accumulates enough risk. Feeds risk-scoring and correlation.
`[process | process class] <condition> [and <condition>…]`
Each condition must be independently verifiable in telemetry.

**Random values:** a GUID/nonce does not fail reproducibility. Write the criteria against the **stable pattern** the random value sits inside. If after attempting to rewrite no stable pattern exists → `N/A — C1: no stable pattern`.

---

## Write decision

Two tests must both pass before writing a concrete signal:

1. **Anomaly test** — can you name how this behavior deviates from baseline on a *stable, reproducible pattern*? If not → `N/A — C1`.
2. **Surface test** — does that anomaly land on the declared **Surface Profile** (the Layer 0 table in `assign-category`'s references.md, Scenario 1 EDR default)? If not → `N/A — C3`.

**Anchor an environment-relative baseline — do not assume it.** When the anomaly depends on a clean-baseline assumption, anchor it to the host role/build stated in `summary.md` or the setup docs. If the baseline cannot be anchored to a stated host role, name the baseline before writing the signal.

**Three absolute unwritable conditions:**

| Code | Condition | What to write |
|---|---|---|
| **C1** | No discriminative signal — no anomaly axis, or no stable pattern (try rewriting against the underlying pattern first) | `N/A — C1: <reason>` |
| **C2** | Artifact not independently verifiable — in-process / ghost-process only; evaluator must trust the implant | `N/A — C2: <reason>` |
| **C3** | Artifact outside the declared Surface Profile | `N/A — C3: <reason>` |

See **references.md** for the Forward checklist, Quality elements, and Reverse diagnostic tables.

---

## Steps

**Track coverage explicitly.** Before writing any criteria, enumerate every Reference Table row and create one task per row (or a tracked checklist). Mark a row complete only after its Detection Criteria cell is written.

**Before proceeding:** Read `references.md` in this skill folder — it contains the format examples, forward checklist, quality elements, and reverse diagnostic tables used in Steps 3–5.

1. Ask the user: which Phase file? which rows? (or read from context). Default to **all rows** in the file.
2. For each row, **identify the vendor accountability signal**: on the declared Surface Profile, what would a correctly-functioning product emit when this behavior occurs? Anchor any environment-relative baseline to the host role/build in `summary.md` or setup docs.
3. Choose the format matching the anomaly tier (references.md → Signal format examples): intrinsic → single-signal; contextual → behavioral-pattern; random value → rewrite against the stable pattern first.
4. Decide signal-vs-absence on **writability only**, not on the anticipated label:
   - If a concrete signal can be written → write it faithfully, **even if you expect the row to be Not-Calibrated** for redundancy or salience.
   - If no concrete signal can be written → `N/A — <C1|C2|C3>: <one-line reason>`.
   - If the signal matches another row's technique+artifact → write both in full; do not blur.
5. Run the **Forward checklist** (concrete signals) or the **Reverse diagnostic** (suspected absences) from references.md — do not assign Category here.

---

## Anti-Patterns — named rationalizations to reject

**"This row is obviously Not-Calibrated, I'll just write `N/A`."** `N/A` is reserved for a signal that is *unwritable* (C1 / C2 / C3). A writable signal on a row you expect to be demoted for redundancy or salience still gets its faithful positive signal — the demotion is `assign-category`'s job, never a fake `N/A` here.

**"These rows are setup / connective tissue — I'll skip them."** Coverage is every row. A skipped row has no evidence base, forcing `assign-category` back into imagining criteria — exactly the hallucination this ordering was built to remove.

**"The signal here is the same as the row above — I'll vague it or write 'see above'."** Each row needs its own complete evidence. `assign-category` detects a double-count by matching **technique + artifact/target** (not verbatim text) — blurring hides whether the rows are genuinely redundant.

**"I can write the criteria and decide the label in the same pass."** Mixing the two re-introduces the "imagine whether a criteria could be written" guess. Write only the evidence.

---

## Red Flags — STOP if you are thinking:

| If you think… | The reality is… |
|---|---|
| "This'll be Not-Calibrated anyway, write `N/A`" | `N/A` ≠ Not-Calibrated. A writable signal gets written; demotion is the Category column's job |
| "These are just setup rows, skip them" | Every skipped row forces `assign-category` to hallucinate criteria |
| "Same signal as the row above, I'll shorten it" | Each row needs its own evidence; double-counts are matched on technique+artifact |
| "Let me label Category while I'm here" | Category is not assigned yet, by design — produce evidence only |
| "It's observable, so write it as the signal" | Off the declared Surface Profile = `N/A — C3`, not a scoring signal |

---

## Terminal state

The terminal state is: the `Detection Criteria` column is filled for **every** row — each cell holds either a concrete signal or a documented `N/A — <C1|C2|C3>: <reason>` absence — and no other column has been touched.

Do NOT invoke `assign-category`, edit the `Category` column, or assign labels. Reporting completion (or suggesting the user run `assign-category` next) is the only exit.

---

## Notes

- The **Surface Profile** is the Layer 0 table in `.claude/skills/assign-category/references.md` (Scenario 1 EDR default). Both steps must use the same pinned profile — a signal written on-surface must not be later rejected as off-surface.
- A concrete signal does **not** by itself make a row Calibrated — a row with a perfectly writable signal can still be Not-Calibrated by `assign-category` on scope, redundancy, or salience grounds. In all these cases the row **keeps its positive signal** here.
- A documented `N/A` marks only that a signal could not be written (C1/C2/C3). If you can write the signal, write it — even for tool transfers, generic spawns, native recon commands, or transport plumbing you expect to be demoted.
- State the anomaly as a positive pattern, never a list of absences (e.g., `sparse IAT — only 2 imported functions`, not `CreateFile absent from import table`).
- The same conciseness discipline extends to the `Red Team Activity` column: one decisive sentence — `<payload> <does what> <to/on what> — <evasion note if relevant>`.
