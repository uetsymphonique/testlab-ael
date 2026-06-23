---
name: assign-category
description: Assign Calibrated / Not Calibrated labels to Reference Table rows in a Phase file — deciding which adversary behaviors count toward the detection-rate denominator
model: claude-sonnet-4-6
effort: high
allowed-tools: Read, Edit, Grep
---

Assign Calibrated / Not Calibrated labels to Reference Table rows in a Phase file.

<HARD-GATE>
This skill runs AFTER `write-detection-criteria` and READS the written criteria — it never imagines or rewrites it.
1. The `Detection Criteria` column must already be filled for every row. If any row's criteria is missing or `TBD`, STOP and run `write-detection-criteria` first — do not invent criteria to label against.
2. READ each row's criteria before labeling. Do NOT label from the behavior description alone.
3. A concrete, writable signal is NOT sufficient for Calibrated — the decision lives at Condition 4. Most Not-Calibrated rows carry a clean signal.
4. Do NOT edit the `Detection Criteria` column. You own only `Category` and `Calibration Reason`.
5. ACW (chain importance) is a separate axis — it never raises or lowers a calibration label.
</HARD-GATE>

**Objective:** calibrate the scoring surface of a Phase — decide which rows are *fair, scored detection opportunities* (counted in the detection-rate denominator) versus setup steps, implementation details, or artifacts outside the measurement surface (not scored). A row is Calibrated only when its artifact is **observable, reproducible, independently verifiable, and fairly scoreable** on the declared telemetry surface, and is not already represented better by another row. The output is an accurate `Category` column.

This skill does **not** author Phase content (`write-phase`), map ATT&CK techniques (`map-technique`), weight the attack chain (`assign-acw`), or write the Detection Criteria text (`write-detection-criteria`). It runs **after** `write-detection-criteria`: the `Detection Criteria` column is already filled for every row — a concrete signal, or a documented `N/A — <condition>: <reason>` absence — and this skill **reads it as evidence** to label. It only assigns labels; it never writes or imagines criteria.

> Order rationale: Detection Criteria is the stable evidence base; Category is the heuristic verdict on top. Reading the written criteria replaces the old "imagine whether a criteria could be written" guess (a hallucination risk) with evidence, and lets labels be re-derived when the heuristic changes — without touching criteria.

## Before starting

Read in order:
1. `plan-for-agent/guides/category-assignment.md` — the 3-layer process and 6-question quick template
2. `plan-for-agent/attack-behavior-methodology.md` — deeper methodology with MITRE examples (read when edge cases arise)

## Steps

**Track coverage explicitly.** Before labeling, enumerate every Reference Table row and create one task per row (or a tracked checklist). Mark a row complete only after both its `Category` and `Calibration Reason` cells are written. This makes "labeled every row" observable, not claimed — do not report done while any row is unmarked.

1. Ask the user: which Phase file? which steps/rows to review? (or read from context)
2. Establish context (Layer 0 of category-assignment.md) — the **Surface Profile** is the single source of truth both this skill and `write-detection-criteria` consume; the canonical channel list lives in the Layer 0 table of `category-assignment.md`:
   - Detections or Protections scenario?
   - Surface type: **Scenario 1 (EDR) is the default** (full advanced surface: process tree + file I/O + registry + netconn + memory scanning + process injection ETW + native API monitoring + YARA/capability matching).
   - **Echo the active Surface Profile explicitly at run start — never label on a silent default.** Even when defaulting to Scenario 1 (EDR), state it. This choice **sets the detection-rate denominator**: dropping to Basic EDR makes in-memory behaviors fail C1 (they leave the surface), so fewer rows survive to be scored — changing the profile silently moves which rows count. Confirm the profile matches the product actually under evaluation before proceeding.
   - Declare **Scenario 1 (Basic EDR)** explicitly only when the evaluation deliberately targets a product without advanced in-memory / injection-monitoring capabilities.
   - Other options: Scenario 2 (XDR), Custom (list channels explicitly before proceeding).

3. Sketch the execution chain for the step under review:
   - List substeps in temporal order; for each, note which artifact it produces and which downstream substep consumes it.
   - Use this map when applying Layer 1 Question B. A row is an implementation detail only if the chain map shows the downstream Calibrated row **directly proves** this one fired — not merely because it is upstream.

4. For each Reference Table row, **read its Detection Criteria first** (the upstream evidence), then run the 3-layer process:
   - **Primary evaluation question:** *"If this vendor misses this signal, is the miss attributable to the vendor?"* This is the through-line for the entire labeling decision. Condition 4 (the scoring gate) is the evaluation design decision; Conditions 1–3 are an **elimination filter** — they verify the artifact is stable and independently confirmable, which is what makes a miss *attributable*, but passing them earns only *eligibility*, not a point.
   - **Read the criteria**: a concrete signal means Conditions 1–3 (Observable, Reproducible, Independently verifiable) already hold in practice — do not re-derive them by imagining. A documented `N/A — <Cx>: <reason>` absence names the failing condition directly → Not Calibrated on that condition.
   - **A concrete signal is not enough.** Most Not Calibrated rows pass C1–C3 perfectly (netstat, ipconfig, tool download, PsExec). Do not equate "a writable signal exists" with Calibrated — the decision lives at C4.
   - **Layer 1**: scope check — is the artifact on the declared detection surface? (independent of criteria)
   - **Layer 1**: redundancy check — is this an implementation detail of another Calibrated row? The double-count signal is two rows naming the **same artifact/event under the same technique at the same capability depth** — match on that semantic pair, not on verbatim-identical criteria text (upstream may phrase two genuinely-redundant rows differently, or phrase two distinct ones alike). If they need fundamentally different telemetry depth (raw netconn vs JA3), both may stay Calibrated. (independent of criteria quality)
   - **Layer 2 — C1–C3 filter**: take Conditions 1–3 from the written criteria (eligibility only).
   - **Layer 2 — C4 scoring gate** (the real decision; all three must hold): **4a** crediting it measures behavior detection, not command-string / IOC matching; **4b** it is a new independent detection opportunity, not one already guaranteed by another scored row (exfil over a *new* channel = Calibrated; exfil over an *existing* C2 = Not Calibrated); **4c** it is a distinctive actor-signature TTP, not generic connective tissue (delivery, transport/T1105, interpreter spawn, native recon, remote-exec plumbing, pure staging). These are rebuttable priors — the same technique flips by its role in the step.

5. Update the `Category` column (clean enum, no free text) and the `Calibration Reason` column (the reason tag for NC rows, `-` for Calibrated) in-place in the Phase file. If the `Calibration Reason` column is missing from an older table, add it between `Category` and `Red Team Activity`. Leave the `Detection Criteria` column untouched — it is upstream evidence, not yours to edit.

6. Completeness check:
   - **Every Not Calibrated row carries a one-line reason tag in the `Calibration Reason` column** (not in `Category` — that stays a clean filterable enum) — `out-of-surface` / `redundant@<TechID>` / `transport` / `interpreter-spawn` / `native-recon` / `staging` / `in-process` / `IOC-only` / `C1`\|`C2`\|`C3`. Calibrated rows get `-`. (`staging` covers the pure-staging / indicator-removal connective-tissue class — internal housekeeping with no distinctive detection surface.) The recorded reason matters more than the label: it lets the label be re-derived when the heuristic changes, and a same-technique flip by role (rar staging vs rar+exfil objective; click delivery vs scored user-execution) is legitimate **only** if the reason explains it. Never write the tag into `Detection Criteria` (off-limits) — for a C1–C3 failure the detail already lives there as `N/A — <Cx>`; just mirror the short `C1`/`C2`/`C3` tag in `Calibration Reason`.
   - For any step where **all rows are Not Calibrated**, confirm a justification exists — the reason tags above usually supply it. If none can be written, re-evaluate that step.
   - Verify no consecutive steps have 0 Calibrated rows without documented justification.

7. After updating, run the structural signals check (Layer 3) to catch common mislabeling patterns.

8. Hand off: labeling is the last per-row content pass. Detection Criteria is already written (upstream). Next, ACW weighting runs on the flattened scoring CSV — run `assign-acw`.

## Anti-Patterns — named rationalizations to reject

**"I can tell this is Calibrated just by reading the behavior."** The behavior is not the evidence — the written Detection Criteria is. Label from the criteria you read, not from the red-team activity description. Labeling without reading the criteria is the failure this skill's ordering exists to prevent.

**"It has a clean, writable signal, so it's Calibrated."** Conditions 1–3 (observable / reproducible / verifiable) are an *elimination filter* that earns only eligibility. netstat, ipconfig, tool download, and PsExec all pass C1–C3 perfectly and are still Not-Calibrated. The real decision is C4 — do not stop at "a signal exists".

**"The criteria here is weak or wrong — let me fix it."** Detection Criteria is upstream evidence and off-limits. If a row's signal contradicts the label you'd assign, fix the **label** and record the reason; never edit the criteria (that is `write-detection-criteria`'s job).

**"This step is Critical / high-value, so it should be Calibrated."** ACW (chain importance) and calibration are independent axes. A Critical bottleneck can be an unobservable in-memory step → Critical ACW *and* Not Calibrated. Judge calibration only on observability / reproducibility / verifiability / scope.

**"These rows in the step look alike — label them the same."** Calibration is per-row. Two rows naming the *same artifact/event under the same technique* (at the same capability depth) is the double-count signal → one Calibrated, the other Not-Calibrated as `redundant@<TechID>`, not both the same. Match on the technique+artifact pair, not on verbatim criteria text.

## Red Flags — STOP if you are thinking:

| If you think… | The reality is… |
|---|---|
| "I don't need to read the criteria for this one" | The criteria IS the evidence — labeling without it is the exact failure this order prevents |
| "Clean signal → Calibrated" | C1–C3 only earn eligibility; the decision is C4 (netstat/ipconfig pass C1–C3 and are NC) |
| "This criteria looks off, I'll tweak it" | Detection Criteria is off-limits — fix the label, not the upstream evidence |
| "High ACW, so keep it Calibrated" | ACW and calibration never govern each other — all four combinations are valid |
| "All NC rows just need the `Category` enum" | Every NC row also needs a `Calibration Reason` tag; the reason is what lets the label be re-derived |

## Terminal state

The terminal state is: every Reference Table row has a clean `Category` enum **and** a `Calibration Reason` (a reason tag for NC rows, `-` for Calibrated), with the `Detection Criteria` column left exactly as written upstream.

Then hand off to `assign-acw` (the next pipeline step on the flattened scoring CSV). Do NOT edit Detection Criteria, re-author Phase content, map techniques, or assign ACW yourself — those belong to other skills.

## Notes

- Two valid labels in scope: `Calibrated - Not Benign`, `Not Calibrated - Not Benign`. `Calibrated - Benign` (false-positive threshold test) is **out of scope for this skill** and handled separately.
- The Calibrated label is **independent of ACW**. A technique's importance in the chain (Critical/High/Medium/Low, owned by `assign-acw`) never makes a row more or less scoreable — judge calibration only on observability/reproducibility/verifiability. A Critical-ACW step can be Not Calibrated; a Low-ACW step can be Calibrated. The two axes only combine in the scoring formula, not here.
- Detection Criteria is the **evidence**, written upstream and read here — never imagined or rewritten. A row carrying a documented `N/A — <reason>` absence is the direct signal to Not-Calibrate it on the named condition. If a row's written signal contradicts the label you'd assign, fix the **label** here; never edit the criteria (that is `write-detection-criteria`'s job).
