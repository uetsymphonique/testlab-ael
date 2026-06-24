---
name: map-technique
description: Map a described adversary behavior to the correct ATT&CK tactic, technique, and sub-technique — and fill the mapping column when the behaviors came from a Flow.md or Phase Reference Table
effort: medium
allowed-tools: Read, Grep, Edit
---

Map a described adversary behavior to the correct ATT&CK tactic, technique, and sub-technique.

<HARD-GATE>
1. When writing back, edit ONLY the mapping columns (`Tactic` / `Technique ID` / `Technique Name`, or `Tactic / TID` in a Flow.md). Never touch behavior text, produces→consumes edges, Category, or Detection Criteria.
2. Map from the knowledge base, not from memory — but DO NOT `Read` the whole tactic file (they run to thousands of lines of Detection/Procedure noise that mapping never needs). `Grep` the slim technique menu instead (see references.md → KB lookup) and confirm the ID and sub-technique before writing it.
3. Prefer the sub-technique over the parent whenever the behavior is specific enough.
4. If no target file with a mapping column is in context, REPORT only (step 4) and stop — do not create or modify a file.
</HARD-GATE>

**Before proceeding:** Read `references.md` in this skill folder — it contains the tactic identification table, knowledge-base file paths, sub-technique selection rules, verification process, and common pitfalls.

## Steps

**Track coverage explicitly when filling a file.** Before writing back, enumerate every behavior row needing a mapping and create one task per row (or a tracked checklist). Mark a row complete only after its mapping columns are filled (a behavior that fans into ≥1 tactics counts done only when all its rows exist). Do not report done while any row still shows `—`.

1. Ask the user to describe the behavior (or read from the current file context / selection). When the input is unstructured (source code, command sequence, CTI), a behavior list from `extract-behaviors` is the cleanest input — one observable action per line, with distinct actions already unbundled. Note a single behavior may still map to multiple tactics → multiple rows (see step 4); the list keeps actions separate, not techniques.
2. **Identify tactic** from behavior intent using the tactic identification table (references.md). A single behavior may serve multiple tactics simultaneously.
3. **Grep the slim technique menu** for the identified tactic file (references.md → KB lookup: `Grep` `^### ` for headings, never `Read` the whole file). This returns every technique and sub-technique as `TID - Name` with its line number — the menu to pick from. Narrow to candidates by name, then `Read` a 2-line range at the candidate's line number to get its description and confirm the mechanism/sub-technique. Prefer sub-technique over parent when the behavior is specific enough. Never read the whole file or the Detection/Procedure blocks.
4. Report:
   - Tactic, Technique ID (with sub-technique if applicable), Technique Name, Platform
   - If multiple tactics apply (e.g. DLL Side-Loading = Execution + Defense Evasion), list all rows
   - Check references.md → Common pitfalls for Execution/Lateral Movement, PE/Persistence, and Defense Evasion cross-list cases
5. **Write back** (when the behaviors came from a file with a mapping column to fill):
   - `Flow.md` (from `document-flow`): fill the `Tactic / TID` column on each behavior row. When one behavior maps to multiple tactics, split it into one row per tactic, keeping the same `#`/edge/context (e.g. `#3` → `#3a`, `#3b`).
   - Phase Reference Table (from `write-phase`): fill the `Tactic`, `Technique ID`, `Technique Name` columns, replacing the `—` placeholders.
   - Edit only the mapping columns — do not touch behavior text, edges, Category, or Detection Criteria. If no target file is in context, just report (step 4) and stop.

## Anti-Patterns — named rationalizations to reject

**"I know this TID from memory — no need to open the knowledge base."** Technique IDs and sub-technique splits drift between ATT&CK versions. Confirm against `mitre-knowledge-base/techniques/<tactic>.md` before writing; a wrong TID poisons every downstream pass.

**"The parent technique is close enough."** Prefer the sub-technique whenever the behavior is specific enough — the parent is a fallback, not a default.

**"While I'm here I'll fix the behavior wording / add a detection note."** Only the mapping columns are yours. Behavior text, edges, Category, and Detection Criteria belong to other skills — leave them untouched.

**"This behavior looks out of scope, I'll drop it."** Scope membership is `check-coverage`'s job, not yours. Map every behavior correctly regardless of scope.

## Red Flags — STOP if you are thinking:

| If you think… | The reality is… |
|---|---|
| "I'm confident of the TID, skip the KB lookup" | TIDs and sub-technique splits drift — confirm, a wrong ID poisons downstream |
| "Parent technique will do" | Prefer the sub-technique when the behavior is specific enough |
| "I'll tidy the behavior text too" | Only mapping columns are yours — other columns belong to other skills |
| "Looks out of scope, drop it" | Scope is `check-coverage`'s job — map it correctly anyway |
| "One TID covers this whole behavior" | One behavior can span multiple tactics → one row per tactic |

## Terminal state

The terminal state is: the mapping columns are filled (`—` placeholders replaced), with one row per tactic where a behavior spans several, and no other column touched. If no target file is in context, the terminal state is the reported mapping (step 4) — no file written.

Do NOT proceed to write Detection Criteria, assign Category, or check scope — each is a separate downstream skill.

## Notes

- Always prefer sub-technique over parent when behavior is specific enough
- If behavior maps to multiple tactics, create a separate Reference Table row for each
- Do not check scope membership — mapping correctness is the only goal
- When writing back, only the mapping columns are yours to edit. Behavior text, produces→consumes edges, Category, and Detection Criteria belong to other skills — leave them untouched.
