# Guide: Writing an Attack Emulation Step

How to build a step in the emulation plan — from an attack idea to complete procedures and reference table. Two branches depending on the input.

---

## Branch [1] — Design behavior from a description

Use when: given a description of a behavior to simulate, or continuing an attack chain from prior steps.

### Step 1 — Identify the behavior to simulate

Input may be:
- A short description of the desired behavior (e.g., "adversary needs to maintain persistence after gaining foothold")
- A specific technique or sub-technique to cover
- Context from prior steps in the emulation plan (where the attacker is, what they have access to)

### Step 2 — Cross-reference technique scope

> See `technique-mapping.md` for how to identify the tactic, look up the technique file, and verify scope.

Look up technique scope at:
- `testlab-enterprise/mitre-outline/Scenario 1.md`
- `testlab-enterprise/mitre-outline/Scenario 2.md`

Determine:
- Which in-scope technique does the described behavior map to?
- If multiple techniques fit, which best suits the current attack chain context?
- If no in-scope technique matches → do not include (unless explicitly requested)

### Step 3 — Look up definition and atomic tests

After identifying the technique:

1. Read the definition in `mitre-knowledge-base/techniques/<tactic>.md` — understand the official description, sub-techniques, detection notes
2. Read atomic tests at `atomic-red-team/atomics/<TID>/<TID>.md` — get real commands, understand artifacts created, reference expected output

Goal: simulate behavior as close to real-world execution as possible — do not invent commands.

### Step 4 — Write the step

Write following the standard format (`emulation-plan-structure.md`):

1. **Voice Track** — describe adversary intent at this step in third person, continuous with prior step context
2. **Procedures** — list each execution step with exact commands; use `☣️` for dangerous steps; include Expected Output where needed to confirm success
3. **Reference Table** — fill all 11 columns for each observable behavior in the step (see below)

---

## Branch [2] — Break down from an existing source

Use when: a document describing adversary behavior is already available (CTI report, threat intel write-up, malware analysis, old MITRE scenario...) and needs to be converted into an emulation step.

### Step 1 — Read source, extract behaviors

Read the source to extract a list of specific behaviors:
- What does the adversary do?
- Which tools or binaries are used?
- What artifacts are created (file, registry, network, process)?
- What is the execution sequence?

Record behaviors clearly in order.

### Step 2 — Map tactics

> See `technique-mapping.md` — Step 1 for guiding questions per tactic.

For each extracted behavior, identify the appropriate MITRE ATT&CK tactic (Initial Access, Execution, Persistence, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Command and Control, Impact).

### Step 3 — Map techniques

> See `technique-mapping.md` — Steps 2, 3, 4 for how to look up the technique file, identify sub-technique, and verify scope.

For each tactic-mapped behavior, find the corresponding technique (and sub-technique):
- Look up `mitre-knowledge-base/techniques/<tactic>.md` to confirm the exact technique ID
- Cross-reference against Scenario 1 / Scenario 2 scope — note when a technique is out of scope

### Step 4 — Write the step

Same as Branch [1] Step 4: Voice Track → Procedures → Reference Table.

---

## Filling the Reference Table

After writing Procedures (regardless of branch), fill the Reference Table for each observable behavior:

| Column | Guidance |
|---|---|
| `Tactic` | Full tactic name (e.g., Defense Evasion) |
| `Technique ID` | ATT&CK ID including sub-technique if applicable (e.g., T1574.002) |
| `Technique Name` | Full name including sub-technique |
| `Platform` | Windows / Linux / IaaS... |
| `Detection Criteria` | See below |
| `Category` | **Leave blank** — assign separately (see `category-assignment.md`) |
| `Red Team Activity` | Short description of the behavior from an external viewpoint |
| `Hosts` | Hostname + IP |
| `Users` | Account performing the action |
| `Source Code Links` | Link to custom tool/payload if applicable |
| `Relevant CTI Reports` | Reference numbers from the file header `[N]` |

**Writing Detection Criteria:**
- Format: `<process> <action> <artifact/target> [on <host>]`
- Correct: `waitfor.exe connects to 191.44.44.199 over TCP port 443`
- Incorrect: `Malware connects to C2`
- Must be specific enough to query directly in SIEM/EDR
- Each observable event gets its own row, even if they share a technique ID

> **Note:** The `Category` column is left blank at this stage. Assigning `Calibrated`/`Not Calibrated` is a separate process — see `category-assignment.md`.
