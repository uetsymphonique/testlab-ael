---
name: write-phase
description: Write or update an attack Phase file in the emulation plan following MITRE format (Voice Track, Procedures, Reference Tables)
model: claude-sonnet-4-6
effort: medium
allowed-tools: Read, Edit, Write, Glob, Grep, PowerShell
---

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

Use `phase-template.md` (in this skill's directory) as the skeleton. Follow the structure exactly — do not invent new sections or rename fields.

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
