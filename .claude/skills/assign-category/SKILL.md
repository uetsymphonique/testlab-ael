---
name: assign-category
description: Assign Calibrated / Not Calibrated labels to Reference Table rows in a Phase file
model: claude-sonnet-4-6
effort: medium
allowed-tools: Read, Edit, Grep
---

Assign Calibrated / Not Calibrated labels to Reference Table rows in a Phase file.

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

4. For each Reference Table row, run the 3-layer process:
   - **Layer 1**: scope check — is the artifact on the declared detection surface?
   - **Layer 1**: redundancy check — is this an implementation detail of another Calibrated row?
   - **Layer 2**: 4-condition checklist (Observable, Reproducible, Independently verifiable, Fair scoring point)

5. Update the `Category` column in-place in the Phase file.

6. Completeness check before moving to Detection Criteria:
   - For any step where **all rows are Not Calibrated**, write one justification sentence. If a clear justification cannot be written, re-evaluate that step.
   - Verify no consecutive steps have 0 Calibrated rows without documented justification.

7. For each `Calibrated` row, verify the `Detection Criteria` meets the format:
   `<process> <action> <artifact/target> [on <host>]`

## Notes

- Three valid labels: `Calibrated - Not Benign`, `Not Calibrated - Not Benign`, `Calibrated - Benign`
- If Detection Criteria cannot be written specifically enough → reconsider the label (likely Not Calibrated)
- After updating, run the structural signals check (Layer 3) to catch common mislabeling patterns
