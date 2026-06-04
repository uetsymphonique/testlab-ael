---
description: Map a described adversary behavior to ATT&CK tactic, technique, and sub-technique
---
 
# Map Technique
 
Map a described adversary behavior to the correct ATT&CK tactic, technique, and sub-technique.
 
## Before starting
 
Read `plan-for-agent/guides/technique-mapping.md` — it contains the full 4-step process and lookup tables.
 
## Steps
 
1. Ask the user to describe the behavior (or read from the current file context / selection).
 
2. Identify tactic from behavior intent.
 
3. Open the relevant `mitre-knowledge-base/techniques/<tactic>.md` and find the technique and sub-technique.
 
4. Report:
   - Tactic, Technique ID (with sub-technique if applicable), Technique Name, Platform
   - If multiple tactics apply (e.g. DLL Side-Loading = Execution + Defense Evasion), list all rows
 
5. **Write back** (when the behaviors came from a file with a mapping column to fill):
   - `Flow.md` (from `/document-flow`): fill the `Tactic / TID` column on each behavior row. When one behavior maps to multiple tactics, split it into one row per tactic, keeping the same `#`/edge/context (e.g. `#3` → `#3a`, `#3b`).
   - Phase Reference Table (from `/write-phase`): fill the `Tactic`, `Technique ID`, `Technique Name` columns, replacing the `—` placeholders.
   - Edit only the mapping columns — do not touch behavior text, edges, Category, or Detection Criteria. If no target file is in context, just report (step 4) and stop.
 
## Notes
 
- Always prefer sub-technique over parent when behavior is specific enough
- If behavior maps to multiple tactics, create a separate Reference Table row for each
- Do not check scope membership — mapping correctness is the only goal
- When writing back, only the mapping columns are yours to edit. Behavior text, produces→consumes edges, Category, and Detection Criteria belong to other skills — leave them untouched.