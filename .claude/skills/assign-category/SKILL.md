---
name: assign-category
description: Assign Calibrated / Not Calibrated labels to Reference Table rows in a Phase file — deciding which adversary behaviors count toward the detection-rate denominator
effort: high
allowed-tools: Read, Edit, Grep
---

Assign Calibrated / Not Calibrated labels to Reference Table rows in a Phase file.

<HARD-GATE>
This skill runs AFTER `write-detection-criteria` and READS the written criteria — it never imagines or rewrites it.
1. The `Detection Criteria` column must already be filled for every row. If any row's criteria is missing or `TBD`, STOP and run `write-detection-criteria` first — do not invent criteria to label against.
2. READ each row's criteria before labeling. Do NOT label from the behavior description alone.
3. A concrete, writable signal is NOT sufficient for Calibrated — the decision lives at C4. Most Not-Calibrated rows carry a clean signal.
4. Do NOT edit the `Detection Criteria` column. You own only `Category` and `Calibration Reason`.
5. ACW (chain importance) is a separate axis — it never raises or lowers a calibration label.
</HARD-GATE>

**Objective:** calibrate the scoring surface of a Phase — decide which rows are *fair, scored detection opportunities* (counted in the detection-rate denominator) versus setup steps, implementation details, or artifacts outside the measurement surface (not scored). A row is Calibrated only when its artifact is **observable, reproducible, independently verifiable, and fairly scoreable** on the declared telemetry surface, and is not already represented better by another row. The output is an accurate `Category` column.

> Order rationale: Detection Criteria is the stable evidence base; Category is the heuristic verdict on top. Reading the written criteria replaces the old "imagine whether a criteria could be written" guess with evidence, and lets labels be re-derived when the heuristic changes — without touching criteria.

---

## Steps

**Before proceeding:** Read `references.md` in this skill folder — it contains the Surface Profile, full Layer 1–3 logic, C4 gate, Quick labeling template, Reason tags, and structural signal checks. The skill cannot run correctly without these tables.

**Track coverage explicitly.** Before labeling, enumerate every Reference Table row and create one task per row (or a tracked checklist). Mark a row complete only after both its `Category` and `Calibration Reason` cells are written.

1. Ask the user: which Phase file? which steps/rows to review? (or read from context)

2. **Establish Surface Profile** (references.md → Surface Profile):
   - Detections or Protections scenario?
   - **Echo the active Surface Profile explicitly — never label on a silent default.** State which profile row is in force. This choice sets the detection-rate denominator.
   - Default: **Scenario 1 (EDR)**. Declare Basic EDR explicitly only when targeting a product without advanced in-memory / injection-monitoring capabilities.

3. **Sketch the execution chain** for the step under review: list substeps in temporal order, note which artifact each produces and which downstream substep consumes it. Use this map when applying Question B.

4. **For each row, read its Detection Criteria first**, then run the 3-layer process (references.md → Layer 1, Layer 2, C4):
   - A concrete signal → Conditions 1–3 hold in practice; proceed to scope (Q-A), redundancy (Q-B), then C4.
   - A documented `N/A — <code>: <reason>` → that condition fails → Not Calibrated; record the matching short tag in `Calibration Reason`.
   - **C4 is the real decision.** Most Not Calibrated rows pass Conditions 1–3 perfectly. Do not stop at "a signal exists".
   - Use the **Quick labeling template** (references.md) as a 7-question shortcut.

5. **Write output in-place**: `Category` (clean enum) and `Calibration Reason` (reason tag for NC rows, `-` for Calibrated). If `Calibration Reason` column is missing, add it between `Category` and `Red Team Activity`. Leave `Detection Criteria` untouched.

6. **Completeness check:**
   - Every NC row carries a reason tag (references.md → Reason tags).
   - Every step with 0 Calibrated rows needs one explicit justification sentence.
   - No consecutive steps with 0 Calibrated rows without documented justification.

7. **Run Layer 3 structural signals check** (references.md → Layer 3) to catch mislabeling patterns.

8. **Hand off** to `assign-acw`. Do NOT edit Detection Criteria, re-author Phase content, map techniques, or assign ACW.

---

## Anti-Patterns — named rationalizations to reject

**"I can tell this is Calibrated just by reading the behavior."** The behavior is not the evidence — the written Detection Criteria is. Label from the criteria you read, not from the red-team activity description.

**"It has a clean, writable signal, so it's Calibrated."** Conditions 1–3 earn only eligibility. netstat, ipconfig, tool download, and PsExec all pass perfectly and are still Not-Calibrated. The real decision is C4.

**"The criteria here is weak or wrong — let me fix it."** Detection Criteria is upstream evidence and off-limits. Fix the **label** and record the reason; never edit the criteria.

**"This step is Critical / high-value, so it should be Calibrated."** ACW and calibration are independent axes. A Critical bottleneck can be an unobservable in-memory step → Critical ACW *and* Not Calibrated.

**"These rows in the step look alike — label them the same."** Calibration is per-row. Two rows naming the *same artifact/event under the same technique at the same capability depth* is the double-count signal → one Calibrated, the other NC as `redundant@<TechID>`. Match on the technique+artifact pair, not on verbatim criteria text.

**"The actor is anomalous, so the action is Calibrated."** Actor anomaly is context, not a rebuttal criterion. For connective-tissue priors, the rebuttal must be triggered by the **primary artifact** the action produces — not by who performed it. For T1105, ask whether the transferred file has an independently observable anomaly. If not, the prior holds; check Q-B against any downstream row that captures the file's distinctive property.

---

## Red Flags — STOP if you are thinking:

| If you think… | The reality is… |
|---|---|
| "I don't need to read the criteria for this one" | The criteria IS the evidence — labeling without it is the exact failure this order prevents |
| "Clean signal → Calibrated" | Conditions 1–3 only earn eligibility; the decision is C4 (netstat/ipconfig pass 1–3 and are NC) |
| "This criteria looks off, I'll tweak it" | Detection Criteria is off-limits — fix the label, not the upstream evidence |
| "High ACW, so keep it Calibrated" | ACW and calibration never govern each other — all four combinations are valid |
| "All NC rows just need the `Category` enum" | Every NC row also needs a `Calibration Reason` tag; the reason is what lets the label be re-derived |

---

## Terminal state

Every Reference Table row has a clean `Category` enum **and** a `Calibration Reason` (reason tag for NC rows, `-` for Calibrated), with the `Detection Criteria` column left exactly as written upstream. Then hand off to `assign-acw`.

---

## Notes

- Two valid labels in scope: `Calibrated - Not Benign`, `Not Calibrated - Not Benign`. `Calibrated - Benign` is out of scope and handled separately.
- The Calibrated label is **independent of ACW**. A Critical-ACW step can be Not Calibrated; a Low-ACW step can be Calibrated. The two axes only combine in the scoring formula, not here.
- Detection Criteria is the **evidence**, written upstream and read here — never imagined or rewritten. If a row's written signal contradicts the label you'd assign, fix the **label** here; never edit the criteria.
