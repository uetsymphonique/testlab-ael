---
description: Map a described adversary behavior to ATT&CK tactic, technique, and sub-technique
---
 
# Map Technique
 
Map a described adversary behavior to the correct ATT&CK tactic, technique, and sub-technique. Verify scope membership.
 
## Before starting
 
Read `plan-for-agent/guides/technique-mapping.md` — it contains the full 4-step process and lookup tables.
 
## Steps
 
1. Ask the user to describe the behavior (or read from the current file context / selection).
 
2. Follow the 4-step process in `technique-mapping.md`:
   - **Step 1**: identify tactic from behavior intent
   - **Step 2**: open the relevant `mitre-knowledge-base/techniques/<tactic>.md`
   - **Step 3**: find the technique and sub-technique (prefer sub-technique when one fits)
   - **Step 4**: cross-reference against `testlab-enterprise/mitre-outline/Scenario 1.md` or `Scenario 2.md`
 
3. Report:
   - Tactic, Technique ID (with sub-technique if applicable), Technique Name, Platform
   - Whether the technique is in scope for Scenario 1 / Scenario 2
   - If multiple tactics apply (e.g. DLL Side-Loading = Execution + Defense Evasion), list all rows
 
## Notes
 
- Always prefer sub-technique over parent when behavior is specific enough
- If behavior maps to multiple tactics, create a separate Reference Table row for each
- If no in-scope technique matches, report that and do not assign the nearest guess