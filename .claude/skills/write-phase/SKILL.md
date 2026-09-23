---
name: write-phase
description: Write or update an attack Phase file in the emulation plan following MITRE format (Voice Track, Procedures, Reference Tables)
effort: medium
allowed-tools: Read, Edit, Write, Glob, Grep, PowerShell
---

You are writing or updating an attack Phase file in the adversary emulation plan.

<HARD-GATE>
This skill produces a behavior-ordered SKELETON only.
1. Leave `Tactic` / `Technique ID` / `Technique Name` as `-`, `Detection Criteria` as `TBD`, `Category` as `TBD`. Do NOT map techniques, write criteria, or assign labels here - each is a separate downstream pass.
2. Use `phase-template.md` exactly - do not invent, rename, or drop sections.
3. Row order MUST follow temporal execution order within the step.
4. The input to Reference Table rows MUST be a processed behavior list from `/extract-behaviors`. Run `/extract-behaviors` first regardless of input form - commands, scripts, source code, or descriptions all require this pass before rows are written. (For source code payloads, `/extract-behaviors` will check for an existing `Flow.md` from `/document-flow` automatically.)
</HARD-GATE>

**Before proceeding:** Read `references.md` in this skill folder - it contains the format spec (Voice Track, Procedures, ☣️ notation, Reference Table columns) and behavior granularity rules used throughout this skill.

## Before writing

Read in this order:
1. `phase-template.md` (this skill's directory) - exact skeleton; follow it without inventing or renaming sections
2. `references.md` (this skill's directory) - format spec and granularity rules
3. `testlab-enterprise/windows-adversary-plan/Emulation_Plan/summary.md` - current plan structure and lab topology (runtime context; read fresh)

Then ask the user:
- Which attack path? (`iis-apppool-escalation-path`, `html-smuggling-path`, or other)
- Which phase number / file?
- Which behaviors to cover? (describe behaviors - technique mapping happens in a separate `/map-technique` pass)

## Reference Table

This skill produces a **behavior-ordered skeleton** only. Do not select techniques, write detection criteria, or assign categories - those happen in separate passes:

- `/map-technique` - fills Technique ID, Technique Name, Tactic (one behavior may fan into ≥1 rows)
- `/write-detection-criteria` - writes the Detection Criteria for **every** row (concrete signal or documented `N/A - <Cx>` absence) - the evidence base, **before** labeling
- `/assign-category` - reads that Detection Criteria and assigns the Calibrated / Not Calibrated label

**Track coverage explicitly.** Before writing rows, enumerate the step's observable behaviors and create one task per behavior (or a tracked checklist). Mark each complete only after its row exists with all placeholder/known columns filled. Do not report done while any behavior lacks a row.

For each observable behavior in the step, add one row - see **references.md → Reference Table columns** for which cells to fill now vs. leave as placeholder. Row order must follow temporal execution order within the step. One row per distinct observable behavior; `/map-technique` may later fan a row into several when one behavior spans multiple tactics.

## Anti-Patterns - named rationalizations to reject

**"I already know the technique - I'll fill the TID now."** Mapping is a separate, verified pass. Leave `-`; filling it here couples two skills and bypasses `/map-technique`'s knowledge-base check.

**"I have the context, I'll write a quick detection note."** `Detection Criteria` is `TBD` here. `write-detection-criteria` owns it and must cover every row as a deliberate pass - a half-written note is worse than the placeholder.

**"This phase needs an extra section to explain X."** Follow `phase-template.md` exactly. Inventing or renaming sections breaks the format every downstream reader and skill depends on.

**"I have the commands/descriptions ready - I'll write the rows directly."** `/extract-behaviors` (or `/document-flow` for source code) is always required before writing rows, regardless of input form. Granularity and atomicity rules live in those skills - improvising inline drifts from spec.

## Red Flags - STOP if you are thinking:

| If you think… | The reality is… |
|---|---|
| "I know the TID, fill it now" | Mapping is a separate verified pass - leave `-` |
| "Quick detection note while I'm here" | Criteria is `TBD`; `write-detection-criteria` owns it across every row |
| "Add a section to explain this" | Follow `phase-template.md` exactly - no new/renamed sections |
| "Commands are clear enough, write rows directly" | `/extract-behaviors` is required before rows regardless of input form |
| "One row covers this whole payload" | One distinct observable behavior per row; mapping may fan it later |

## Terminal state

The terminal state is: a Phase file matching `phase-template.md`, with one temporally-ordered row per distinct observable behavior, and the `Tactic` / `Technique ID` / `Technique Name` = `-`, `Detection Criteria` = `TBD`, `Category` = `TBD` placeholders intact.

Hand off to `/map-technique` next. Do NOT fill the mapping, criteria, or category columns yourself.

> Always run `/extract-behaviors` before writing rows - regardless of whether the input is commands, scripts, descriptions, or a full payload. Write-phase only accepts a processed behavior list as input to its Reference Table. For source code payloads, `/extract-behaviors` checks for an existing `Flow.md` (from `/document-flow`) automatically as a fast path. Granularity and atomicity rules live in those skills - do not re-derive them inline.
