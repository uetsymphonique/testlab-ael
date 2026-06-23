---
name: write-phase
description: Write or update an attack Phase file in the emulation plan following MITRE format (Voice Track, Procedures, Reference Tables)
model: claude-sonnet-4-6
effort: medium
allowed-tools: Read, Edit, Write, Glob, Grep, PowerShell
---

You are writing or updating an attack Phase file in the adversary emulation plan.

<HARD-GATE>
This skill produces a behavior-ordered SKELETON only.
1. Leave `Tactic` / `Technique ID` / `Technique Name` as `—`, `Detection Criteria` as `TBD`, `Category` as `TBD`. Do NOT map techniques, write criteria, or assign labels here — each is a separate downstream pass.
2. Use `phase-template.md` exactly — do not invent, rename, or drop sections.
3. Row order MUST follow temporal execution order within the step.
4. If the input is unstructured (raw chain description, source code, command sequence), run `/extract-behaviors` FIRST — do not improvise the behavior breakdown inline.
</HARD-GATE>

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

**Track coverage explicitly.** Before writing rows, enumerate the step's observable behaviors and create one task per behavior (or a tracked checklist). Mark each complete only after its row exists with all placeholder/known columns filled. Do not report done while any behavior lacks a row.

For each observable behavior in the step, add one row with:
- **Tactic / Technique ID / Technique Name**: leave as `—` (to be filled by `/map-technique`)
- **Platform**: fill (Windows / Linux / etc.)
- **Detection Criteria**: leave as `TBD`
- **Category**: leave as `TBD`
- **Red Team Activity**: fill — short description of what the red team does, from an external observer's view
- **Hosts / Users / Source Code Links / Relevant CTI Reports**: fill what is known

Row order must follow temporal execution order within the step. Start one row per distinct observable behavior (`/map-technique` may later split a row into several when one behavior spans multiple tactics).

## Anti-Patterns — named rationalizations to reject

**"I already know the technique — I'll fill the TID now."** Mapping is a separate, verified pass. Leave `—`; filling it here couples two skills and bypasses `/map-technique`'s knowledge-base check.

**"I have the context, I'll write a quick detection note."** `Detection Criteria` is `TBD` here. `write-detection-criteria` owns it and must cover every row as a deliberate pass — a half-written note is worse than the placeholder.

**"This phase needs an extra section to explain X."** Follow `phase-template.md` exactly. Inventing or renaming sections breaks the format every downstream reader and skill depends on.

**"The input is messy but I'll just eyeball the behaviors."** Run `/extract-behaviors` first when the input is unstructured. Granularity rules live in `behavior-breakdown.md` — improvising them here drifts from the guide.

## Red Flags — STOP if you are thinking:

| If you think… | The reality is… |
|---|---|
| "I know the TID, fill it now" | Mapping is a separate verified pass — leave `—` |
| "Quick detection note while I'm here" | Criteria is `TBD`; `write-detection-criteria` owns it across every row |
| "Add a section to explain this" | Follow `phase-template.md` exactly — no new/renamed sections |
| "Eyeball the behaviors from this messy input" | Run `/extract-behaviors` first — granularity lives in the guide |
| "One row covers this whole payload" | One distinct observable behavior per row; mapping may fan it later |

## Terminal state

The terminal state is: a Phase file matching `phase-template.md`, with one temporally-ordered row per distinct observable behavior, and the `Tactic` / `Technique ID` / `Technique Name` = `—`, `Detection Criteria` = `TBD`, `Category` = `TBD` placeholders intact.

Hand off to `/map-technique` next. Do NOT fill the mapping, criteria, or category columns yourself.

> **Granularity rules live in one place:** `plan-for-agent/guides/behavior-breakdown.md` (atomic-unit contract, split/fold/keep rules, observable filter). Do not restate them here — defer to the guide so the two skills cannot drift. When the input is unstructured (a raw chain description, payload source code, or a command sequence), run `/extract-behaviors` first to get the ordered behavior list, then turn each behavior into a row here.
