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
- Which behaviors to cover? (describe behaviors — technique mapping happens in a separate `/map-technique` pass)
 
## Phase file structure

Use `phase-template.md` (in this skill's directory) as the skeleton. Follow the structure exactly — do not invent new sections or rename fields.
 
## Writing procedures
 
- **Voice Track**: third-person adversary perspective; continuous narrative from prior steps
- **Procedures**: numbered steps with exact commands; prefix dangerous/destructive steps with `☣️`
- **Expected Output**: include under a step when output confirms success
 
## Reference Table
 
This skill produces a **behavior-ordered skeleton** only. Do not select techniques, write detection criteria, or assign categories — those happen in separate passes:
 
- `/map-technique` — fills Technique ID, Technique Name, Tactic (one behavior may fan into ≥1 rows)
- `/write-detection-criteria` — writes the Detection Criteria for **every** row (concrete signal or documented `N/A — <Cx>` absence) — the evidence base, **before** labeling
- `/assign-category` — reads that Detection Criteria and assigns the Calibrated / Not Calibrated label
 
For each observable behavior in the step, add one row with:
- **Tactic / Technique ID / Technique Name**: leave as `—` (to be filled by `/map-technique`)
- **Platform**: fill (Windows / Linux / etc.)
- **Detection Criteria**: leave as `TBD`
- **Category**: leave as `TBD`
- **Red Team Activity**: fill — short description of what the red team does, from an external observer's view
- **Hosts / Users / Source Code Links / Relevant CTI Reports**: fill what is known
 
Row order must follow temporal execution order within the step. Start one row per distinct observable behavior (`/map-technique` may later split a row into several when one behavior spans multiple tactics).

> **Granularity rules live in one place:** `plan-for-agent/guides/behavior-breakdown.md` (atomic-unit contract, split/fold/keep rules, observable filter). Do not restate them here — defer to the guide so the two skills cannot drift. When the input is unstructured (a raw chain description, payload source code, or a command sequence), run `/extract-behaviors` first to get the ordered behavior list, then turn each behavior into a row here.