---
name: assign-category
description: Assign Calibrated / Not Calibrated labels to Reference Table rows in a Phase file — deciding which adversary behaviors count toward the detection-rate denominator
model: claude-sonnet-4-6
effort: high
allowed-tools: Read, Edit, Grep
---

Assign Calibrated / Not Calibrated labels to Reference Table rows in a Phase file.

**Objective:** calibrate the scoring surface of a Phase — decide which rows are *fair, scored detection opportunities* (counted in the detection-rate denominator) versus setup steps, implementation details, or artifacts outside the measurement surface (not scored). A row is Calibrated only when its artifact is **observable, reproducible, independently verifiable, and fairly scoreable** on the declared telemetry surface, and is not already represented better by another row. The output is an accurate `Category` column.

This skill does **not** author Phase content (`write-phase`), map ATT&CK techniques (`map-technique`), weight the attack chain (`assign-acw`), or write the Detection Criteria text (`write-detection-criteria`). It runs **after** `write-detection-criteria`: the `Detection Criteria` column is already filled for every row — a concrete signal, or a documented `N/A — <condition>: <reason>` absence — and this skill **reads it as evidence** to label. It only assigns labels; it never writes or imagines criteria.

> Order rationale: Detection Criteria is the stable evidence base; Category is the heuristic verdict on top. Reading the written criteria replaces the old "imagine whether a criteria could be written" guess (a hallucination risk) with evidence, and lets labels be re-derived when the heuristic changes — without touching criteria.

## Before starting

Read in order:
1. `plan-for-agent/guides/category-assignment.md` — the 3-layer process and 6-question quick template
2. `plan-for-agent/attack-behavior-methodology.md` — deeper methodology with MITRE examples (read when edge cases arise)

## Steps

1. Ask the user: which Phase file? which steps/rows to review? (or read from context)
2. Establish context (Layer 0 of category-assignment.md):
   - Detections or Protections scenario?
   - Surface type: **Scenario 1 (EDR) is the default** (full advanced surface: process tree + file I/O + registry + netconn + memory scanning + process injection ETW + native API monitoring + YARA/capability matching). No declaration needed — assume this unless told otherwise.
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
   - **Layer 1**: redundancy check — is this an implementation detail of another Calibrated row? Two rows carrying **identical criteria** is the signal of a double-count. (independent of criteria quality)
   - **Layer 2 — C1–C3 filter**: take Conditions 1–3 from the written criteria (eligibility only).
   - **Layer 2 — C4 scoring gate** (the real decision; all three must hold): **4a** crediting it measures behavior detection, not command-string / IOC matching; **4b** it is a new independent detection opportunity, not one already guaranteed by another scored row (exfil over a *new* channel = Calibrated; exfil over an *existing* C2 = Not Calibrated); **4c** it is a distinctive actor-signature TTP, not generic connective tissue (delivery, transport/T1105, interpreter spawn, native recon, remote-exec plumbing, pure staging). These are rebuttable priors — the same technique flips by its role in the step.

5. Update the `Category` column (clean enum, no free text) and the `Calibration Reason` column (the reason tag for NC rows, `-` for Calibrated) in-place in the Phase file. If the `Calibration Reason` column is missing from an older table, add it between `Category` and `Red Team Activity`. Leave the `Detection Criteria` column untouched — it is upstream evidence, not yours to edit.

6. Completeness check:
   - **Every Not Calibrated row carries a one-line reason tag in the `Calibration Reason` column** (not in `Category` — that stays a clean filterable enum) — `out-of-surface` / `redundant@<TechID>` / `transport` / `interpreter-spawn` / `native-recon` / `in-process` / `IOC-only` / `C1`\|`C2`\|`C3`. Calibrated rows get `-`. The recorded reason matters more than the label: it lets the label be re-derived when the heuristic changes, and a same-technique flip by role (rar staging vs rar+exfil objective; click delivery vs scored user-execution) is legitimate **only** if the reason explains it. Never write the tag into `Detection Criteria` (off-limits) — for a C1–C3 failure the detail already lives there as `N/A — <Cx>`; just mirror the short `C1`/`C2`/`C3` tag in `Calibration Reason`.
   - For any step where **all rows are Not Calibrated**, confirm a justification exists — the reason tags above usually supply it. If none can be written, re-evaluate that step.
   - Verify no consecutive steps have 0 Calibrated rows without documented justification.

7. After updating, run the structural signals check (Layer 3) to catch common mislabeling patterns.

8. Hand off: labeling is the last per-row content pass. Detection Criteria is already written (upstream). Next, ACW weighting runs on the flattened scoring CSV — run `assign-acw`.

## Notes

- Two valid labels in scope: `Calibrated - Not Benign`, `Not Calibrated - Not Benign`. `Calibrated - Benign` (false-positive threshold test) is **out of scope for this skill** and handled separately.
- The Calibrated label is **independent of ACW**. A technique's importance in the chain (Critical/High/Medium/Low, owned by `assign-acw`) never makes a row more or less scoreable — judge calibration only on observability/reproducibility/verifiability. A Critical-ACW step can be Not Calibrated; a Low-ACW step can be Calibrated. The two axes only combine in the scoring formula, not here.
- Detection Criteria is the **evidence**, written upstream and read here — never imagined or rewritten. A row carrying a documented `N/A — <reason>` absence is the direct signal to Not-Calibrate it on the named condition. If a row's written signal contradicts the label you'd assign, fix the **label** here; never edit the criteria (that is `write-detection-criteria`'s job).
