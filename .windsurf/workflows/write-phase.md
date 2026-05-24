---
description: Write or update an attack Phase file in the emulation plan following MITRE format
---
 
# Write Phase
 
You are writing or updating an attack Phase file in the adversary emulation plan.
 
## Before writing
 
Read in this order:
1. `plan-for-agent/emulation-plan-structure.md` — mandatory format spec (Step structure, Voice Track, Procedures, Reference Tables, ☣️ notation)
2. `plan-for-agent/detections-overview.md` **or** `plan-for-agent/protections-overview.md` — based on scenario type
3. `testlab-enterprise/windows-adversary-plan/Emulation_Plan/summary.md` — understand current plan structure and lab topology
 
Then ask the user:
- Which attack path? (`iis-apppool-escalation-path`, `html-smuggling-path`, or other)
- Which phase number / file?
- Which techniques or behaviors to cover?
 
## Phase file structure
 
Use this template as the skeleton. Follow the structure exactly — do not invent new sections or rename fields.
 
```markdown
# Phase N — <Tactic Chain Title>
 
<!-- CTI references used in this phase. Number them here; cite with [N] in the Reference Tables below. -->
[1]: <url>
 
---
 
## Step 0 — Setup
 
### Procedures
 
- Verify C2 session is active on `<hostname> (<IP>)`
- Confirm operator is connected to attack host
 
---
 
## Step N — <Tactic: Short Description>
 
### Voice Track
 
<Adversary-perspective narrative. Third person. Explain what the adversary is trying to achieve and why at this point in the chain. Connect to the context from previous steps.>
 
### Procedures
 
- ☣️ <Dangerous/destructive step — changes system state, runs payload, or executes attack behavior>
 
  ```powershell
  <exact command>
  ```
 
  - ***Expected Output***
    ```text
    <expected output confirming success>
    ```
 
- <Non-dangerous step — navigation, reading output, setup>
 
### Reference Tables
 
| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - |
| <Tactic> | T<ID>.<sub> | <Full Technique: Sub-technique Name> | Windows | `<process> <action> <artifact> on <host>` | Calibrated - Not Benign | <Short description of red team behavior from external view> | <hostname> (<IP>) | <DOMAIN\user> | [link](<relative path to payload>) | [1] |
 
---
 
## End of Phase
 
### Procedures
 
- Document artifacts created for cleanup reference (see `Cleanup.md`)
```
 
## Technique selection
 
- Only use techniques from scope: `testlab-enterprise/mitre-outline/Scenario 1.md` or `Scenario 2.md`
- Look up theory in `mitre-knowledge-base/techniques/<tactic>.md`
- Find concrete command examples in `atomic-red-team/atomics/<TID>/`
- When unsure of a technique mapping, read `plan-for-agent/guides/technique-mapping.md`
 
## Writing procedures
 
- **Voice Track**: third-person adversary perspective; continuous narrative from prior steps
- **Procedures**: numbered steps with exact commands; prefix dangerous/destructive steps with `☣️`
- **Expected Output**: include under a step when output confirms success
 
## Reference Table
 
Fill all 11 columns for every observable behavior in the step. Read `plan-for-agent/guides/category-assignment.md` before assigning the `Category` column.
 
Detection Criteria format: `<process> <action> <artifact/target> [on <host>]`
Example: `waitfor.exe connects to 191.44.44.199 over TCP port 443`
 
## After writing
 
Verify technique coverage:
```powershell
cd testlab-enterprise/mitre-outline
python check.py --scope "Scenario 1.md" --folder ../windows-adversary-plan/Emulation_Plan/<path>
```