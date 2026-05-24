---
description: Assign Calibrated / Not Calibrated labels to Reference Table rows in a Phase file
---
 
# Assign Category
 
Assign Calibrated / Not Calibrated labels to Reference Table rows in a Phase file.
 
## Before starting
 
Read in order:
1. `plan-for-agent/guides/category-assignment.md` — the 3-layer process and 6-question quick template
2. `plan-for-agent/attack-behavior-methodology.md` — deeper methodology with MITRE examples (read when edge cases arise)
 
## Steps
 
1. Ask the user: which Phase file? which steps/rows to review? (or read from context)
 
2. Establish context (Layer 0 of category-assignment.md):
   - Detections or Protections scenario?
   - Scenario 1 (EDR surface) or Scenario 2 (XDR surface)?
 
3. For each Reference Table row, run the 3-layer process:
   - **Layer 1**: scope check — is the artifact on the declared detection surface?
   - **Layer 1**: redundancy check — is this an implementation detail of another Calibrated row?
   - **Layer 2**: 4-condition checklist (Observable, Reproducible, Independently verifiable, Fair scoring point)
 
4. Update the `Category` column in-place in the Phase file.
 
5. For each `Calibrated` row, verify the `Detection Criteria` meets the format:
   `<process> <action> <artifact/target> [on <host>]`
 
## Notes
 
- Three valid labels: `Calibrated - Not Benign`, `Not Calibrated - Not Benign`, `Calibrated - Benign`
- If Detection Criteria cannot be written specifically enough → reconsider the label (likely Not Calibrated)
- After updating, run the structural signals check (Layer 3) to catch common mislabeling patterns