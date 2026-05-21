---
name: emulate-technique
description: Select and design a concrete simulation approach for one or more ATT&CK techniques, tailored to user constraints (tools, host, privilege, fidelity goal). Synthesizes across ART test variants rather than picking one verbatim.
model: claude-sonnet-4-6
effort: high
allowed-tools: Read, Grep, Glob
---

Design a technique simulation plan for each requested technique. The goal is a **tailored, executable approach** — not a copy of one ART test. You must understand what the user needs, survey all ART variants for each technique, then synthesize the best-fit approach.

---

## Before starting — gather requirements

Ask the following in a **single message** (do not ask one at a time):

1. **Techniques**: IDs (e.g. `T1003.001`), behavior descriptions ("dump LSASS without Sysinternals"), or references to existing steps ("Phase 2 Step 3 LSASS dump" — then read that Phase file)
2. **Tool constraints**: which tools/binaries are available on the target host? Any restrictions (LOLBin-only, no Mimikatz, custom payload already built, specific binary)?
3. **Execution context**: host type (workstation / server), OS version, and privilege level at execution time (SYSTEM / Admin / low-priv)?
4. **Fidelity goal**: what outcome matters most?
   - Maximize detection surface (produce as many observable artifacts as possible)?
   - Test a specific artifact or telemetry channel?
   - Simulate a specific threat actor's tooling?
   - Avoid specific signatures while still producing the behavior?
5. **Output intent**: will the result feed into a Phase file (needs Reference Table row), or is it a standalone test?

If the user's message already answers some questions, do not re-ask those — proceed with what is known and ask only what is missing.

---

## Per-technique research loop

For each technique in the input list, execute the following in order:

### Step 1 — Confirm ATT&CK mapping

Follow the same process as `map-technique`:

1. Read `plan-for-agent/guides/technique-mapping.md` for the 4-step process
2. If the input is a description (not an ID), identify tactic → look up `mitre-knowledge-base/techniques/<tactic>.md` → find ID and sub-technique
3. Verify scope: cross-reference against `testlab-enterprise/mitre-outline/Scenario 1.md` and `Scenario 2.md`
4. If out of scope, flag it — continue only if user explicitly requested it

### Step 2 — Read the ART file

Read `atomic-red-team/atomics/<TID>/<TID>.md` for the technique.

For each atomic test in that file, extract and record:
- **Test name and number**
- **Method**: which binary/tool/API is used?
- **Execution requirements**: prerequisite tools, privileges needed, OS constraints
- **Artifacts produced**: what files, registry keys, processes, network events are generated?
- **Detection surface**: what telemetry channel would catch this? (process creation, file write, network, script block log, etc.)
- **Complexity**: is setup complex, or is it a one-liner?

Also read the `.yaml` file (`<TID>.yaml`) if the markdown is incomplete or missing prereqs.

### Step 3 — Filter and select

Compare the ART variants against the user's requirements:

| Filter dimension | Apply when |
|---|---|
| Tool availability | Drop variants requiring unavailable binaries |
| Privilege | Drop variants requiring higher privilege than user has |
| OS constraint | Drop variants incompatible with declared OS |
| Fidelity goal | Rank remaining variants by how well they produce the desired artifact |

After filtering, you will have a **candidate set**. Do not stop here — proceed to synthesis.

### Step 4 — Synthesize the approach

**This is the core of the skill.** Do not simply output the selected ART test.

Synthesis means:
- If one ART test matches well → adapt its commands for the user's context (paths, binary names, user accounts, host-specific values)
- If the user's goal requires artifacts from multiple ART tests → combine the relevant steps into a unified sequence
- If tool constraints rule out all ART tests → design an approach from first principles, using the ART description and `mitre-knowledge-base` to understand what behavior and artifacts to produce
- If the fidelity goal is to maximize detection surface → choose or combine the variants that produce the most distinct, measurable telemetry events
- If the fidelity goal is actor fidelity → prioritize the variant that matches the actor's known tooling (read Phase file context or CTI if available)

State the synthesis rationale explicitly: why this approach over other candidates.

---

## Output format

For each technique, produce the following block:

```
### <TID> — <Technique Name>
**Scope:** In scope (Scenario N) / Out of scope [flagged]
**Chosen approach:** <one sentence — what method / tool / API>
**Rationale:** <why this approach over discarded candidates, matched against user's constraints>

**Execution context:** <host> / <user> / <privilege>

**Commands:**
[list exact commands, adapted to context; mark ☣️ on dangerous steps]

**Expected artifacts:**
- <artifact 1>: <what it is, where it appears>
- <artifact 2>: ...

**Detection surface:**
- <telemetry channel>: <specific observable — e.g., "rundll32.exe spawns with comsvcs.dll argument accessing lsass PID">
```

If the user requested a Reference Table row (output intent = Phase file), append:

```
**Reference Table row:**
| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - |
| <tactic> | <TID> | <name> | Windows | <detection criteria> | | <red team activity> | <host> | <user> | | |
```

Leave `Category` blank — it is assigned separately via `assign-category`.

---

## Notes

- Always read the full ART file before selecting — techniques often have 10+ variants; early variants are not always the best fit
- Prefer sub-technique over parent when behavior is specific
- If multiple tactics apply to the same behavior (e.g., DLL side-loading = Defense Evasion + Execution), produce one row per tactic
- If ART has no test for the technique, state this explicitly and design the approach from `mitre-knowledge-base` + known tooling for the technique
- Do not invent commands — adapt from ART or documented tooling; if inventing, label it "custom approach" and explain
