---
name: emulate-technique
description: Explore implementation options for an ATT&CK technique and recommend the best-fit approach for the user's constraints. Not detection-oriented — focuses on understanding the technique and selecting a practical execution method.
effort: high
allowed-tools: Read, Grep, Glob
---

Help the user understand a technique and identify the most suitable implementation approach. The goal is informed recommendation — not copying an ART test verbatim.

ART is a reference to understand what variants exist and what each requires, not a source to copy from.

<HARD-GATE>
1. This skill RECOMMENDS only. Produce no Reference Table, no detection surface, no scope check, and write no payload file — those belong to other skills.
2. Read the FULL ART file (`<TID>.md`, plus `.yaml` for prereqs) before recommending — the first test is rarely the best fit.
3. Do NOT copy ART commands verbatim — adapt to the user's host / privilege / OS. If you invent an approach not in ART, label it explicitly and state its basis.
</HARD-GATE>

---

## Before starting — gather requirements

Ask the following in a **single message** (do not ask one at a time):

1. **Technique**: ID (e.g. `T1003.001`) or behavior description
2. **Tool constraints**: available tools/binaries on the target host; any restrictions (LOLBin-only, custom payload already built, specific binary required)?
3. **Execution context**: host type, OS version, and privilege level at execution time
4. **Goal**: what does the user want to achieve or understand? (e.g. produce a specific artifact, simulate a specific actor's tooling, understand implementation options, avoid a specific approach)

If the user's message already answers some of these, skip those questions.

---

## Research loop

### Step 1 — Understand the technique

If the input is a description (not an ID), confirm the ID and sub-technique from the knowledge base — but DO NOT `Read` the whole tactic file (they run to thousands of lines of Detection/Procedure noise this step never needs). `Grep pattern="^### " path="mitre-knowledge-base/techniques/<tactic>.md" output_mode="content"` to get the `TID - Name` menu with line numbers, then `Read` a 2-line range at the candidate's line number for its description.

Read only that technique entry to understand: what behavior it describes, what variants exist conceptually, and what the key technical mechanism is. Never read the whole tactic file or the Detection/Procedure blocks.

### Step 2 — Survey ART variants

Read `atomic-red-team/atomics/<TID>/<TID>.md`. For each test, note:
- What tool/API/method it uses
- What privilege and OS it requires
- What artifacts it produces (files, processes, registry, network)

Also read `<TID>.yaml` if the markdown omits prereqs.

Read the **full file** — do not stop at the first test.

### Step 3 — Recommend

Filter variants against the user's constraints (tool availability, privilege, OS). From what remains, recommend the best-fit approach.

Synthesis is preferred over selection: if no single ART test matches well, combine relevant parts or adapt from first principles using the technique description and known tooling.

State the rationale: why this approach over the alternatives.

---

## Output format

```
### <TID> — <Technique Name>

**Approach:** <one sentence — tool/API/method>
**Rationale:** <why this over discarded candidates>

**Execution context:** <host> / <privilege>

**Commands:**
[exact commands adapted to context; ☣️ on dangerous steps]

**Artifacts produced:**
- <artifact>: <what it is and where>
```

No Reference Table. No detection surface. No scope check.

---

## Anti-Patterns — named rationalizations to reject

**"The first ART test looks fine, recommend it."** Read the full file. Techniques often have many variants with different privilege / OS / artifact profiles; the first is rarely the best fit for the user's constraints.

**"I'll copy the ART command as-is."** ART is a reference, not a source. Adapt every command to the user's host, privilege, and OS — a verbatim copy usually misfits the context.

**"While I'm here, I'll build the payload / write the rows."** Recommend-only. `craft-payload` builds the artifact and `write-phase` authors the rows — producing them here oversteps the skill boundary.

**"ART has no test for this, so I'm stuck."** Design from `mitre-knowledge-base` + known tooling, and label the approach as invented with its basis. No ART test is not a dead end.

## Red Flags — STOP if you are thinking:

| If you think… | The reality is… |
|---|---|
| "First ART test is good enough" | Read the full file — many variants, first isn't always best |
| "Copy the ART command verbatim" | Adapt to host/privilege/OS — ART is a reference, not a source |
| "I'll build the payload too" | Recommend-only — `craft-payload` / `write-phase` own that |
| "No ART test, I'm stuck" | Design from knowledge-base + tooling, labeled as invented |
| "Add a quick Reference Table" | No table / surface / scope here — recommendation only |

## Terminal state

The terminal state is: a recommendation in the prescribed output format — approach, rationale, execution context, adapted commands, and artifacts produced.

Hand off to `craft-payload` if a payload needs building. Do NOT produce a Reference Table, detection surface, scope check, or payload file.

## Notes

- Always read the full ART file — techniques often have many variants; the first is not always the best fit
- If ART has no test, state this and design from `mitre-knowledge-base` + known tooling
- Do not copy ART commands verbatim — adapt to the user's context
- If inventing an approach not in ART, label it explicitly and explain the basis
