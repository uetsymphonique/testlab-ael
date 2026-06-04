---
description: Explore implementation options for an ATT&CK technique and recommend the best-fit approach for the user's constraints. Not detection-oriented — focuses on understanding the technique and selecting a practical execution method.
---

# Emulate Technique

Help the user understand a technique and identify the most suitable implementation approach. The goal is informed recommendation — not copying an ART test verbatim.

ART is a reference to understand what variants exist and what each requires, not a source to copy from.

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

If the input is a description (not an ID), look up `mitre-knowledge-base/techniques/<tactic>.md` to confirm the ID and sub-technique.

Read the technique entry to understand: what behavior it describes, what variants exist conceptually, and what the key technical mechanism is.

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

## Notes

- Always read the full ART file — techniques often have many variants; the first is not always the best fit
- If ART has no test, state this and design from `mitre-knowledge-base` + known tooling
- Do not copy ART commands verbatim — adapt to the user's context
- If inventing an approach not in ART, label it explicitly and explain the basis