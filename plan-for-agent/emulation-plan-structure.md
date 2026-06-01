# Emulation Plan Presentation Format

> **Consumed by:** `/write-phase` — see [pipeline.md](pipeline.md)

Derived from `Enterprise/mustang_panda/` and `Enterprise/scattered_spider/`.

---

## Directory Structure

```
Enterprise/<adversary>/
├── Emulation_Plan/
│   ├── <Adversary>_Scenario.md          # Main scenario
│   ├── <Adversary>_Alternative_Steps.md # Alternative steps for different environments
│   ├── <Adversary>_Cleanup_Guide.md     # Post-test cleanup guide
│   ├── Protections_Test_<N>_Scenario.md # Sub-scenarios for protections tests
│   └── README.md
├── CTI_Emulation_Resources/
│   └── <Adversary>_Scenario_Overview.md # High-level summary for newcomers
├── Resources/                           # Tool source code, payloads, C2 client
├── Attack_Layers/                       # ATT&CK Navigator layer files
└── README.md
```

---

## Main Scenario File Structure

### 1. Header — CTI citations

The file begins with a numbered list of all CTI references used. These numbers are cited inline in the Reference Tables.

```markdown
[1]:https://cloud.google.com/blog/topics/...
[2]:https://unit42.paloaltonetworks.com/...
```

### 2. Step 0 — Setup

Includes:
- How to connect to the attack host (typically via RDP or SSH)
- Starting the C2 server / handler
- Setting up the Kali environment (venv, tools)
- Connecting to jumpbox and victim host

```markdown
## Step 0 - Setup
### Procedures
- ☣️ Initiate an RDP session to the Kali attack host `driftmark (174.3.0.70)`
- ☣️ In a new terminal window, start the C2 handler if not already running
```

### 3. Attack Steps

Each step corresponds to a **tactic phase** or a group of related techniques. Structure:

```markdown
## Step <N> - <Tactic>

### Voice Track
<Paragraph describing behavior from the adversary's perspective. Written as narrative.>

### Procedures
<Step-by-step execution list, including:>
- ☣️ <Red team step (harmful)>
- <Step without symbol (normal setup, no special attention needed)>

  ```cmd/bash/python
  <exact command>
  ```

  - ***Expected Output***
    ```text
    <expected output>
    ```

### Reference Tables
<ATT&CK mapping table>
```

**Procedure notation rules:**
- `☣️` marks steps that are **genuinely dangerous red team actions** — changing system state, running payloads, or performing attack behavior. Only these steps require operator caution.
- Steps without `☣️` are normal (opening a browser, navigating UI, reading output...).

### 4. Reference Table — Standard Format

Each step ends with a Reference Table mapping the performed behavior to ATT&CK.

```markdown
| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Defense Evasion | T1574.002 | Hijack Execution Flow: DLL Side-Loading | Windows | gflags.exe side loads unsigned gflagsui.dll | Calibrated - Not Benign | Legitimate binary `gflags.exe` side-loads TONESHELL loader DLL | bitterbridge (10.26.4.103) | btully | [DLL exports](../Resources/...) | [21], [22]
```

**Column descriptions:**

| Column | Description |
|---|---|
| `Tactic` | MITRE tactic (written in full) |
| `Technique ID` | ATT&CK ID (e.g., `T1574.002`) |
| `Technique Name` | Full name including sub-technique if applicable |
| `Platform` | `Windows`, `Linux`, `IaaS`, `Identity Provider`... |
| `Detection Criteria` | **Specific observable condition** — must be a checkable event/artifact (not a generic description) |
| `Category` | `Calibrated - Not Benign` / `Not Calibrated - Not Benign` / `Calibrated - Benign` |
| `Red Team Activity` | Short description of red team behavior from an external viewpoint |
| `Hosts` | Specific hostname + IP where the behavior occurs |
| `Users` | Account performing the behavior |
| `Source Code Links` | Link to code in Resources/ (if custom tool) |
| `Relevant CTI Reports` | Reference numbers from the header (e.g., `[2], [9]`) |

**Important notes on Detection Criteria:**
- Must be specific down to process name + argument: `waitfor.exe executed netstat -anop tcp`
- Do not write generic descriptions like "malware connects to C2"
- If a technique occurs on multiple hosts, create a separate row per host

### 5. End of Test

```markdown
## End of Test
### Voice Track
This step includes the shutdown procedures for the end of this Protections Test
### Procedures
- <Close sessions, clean up artifacts if needed>
```

---

## Alternative Steps Structure

`<Adversary>_Alternative_Steps.md` contains **alternative steps** for each step in the main scenario, used when:
- The environment does not support the original technique
- A different variant of the same technique is being tested
- A backup is needed in case the primary payload is blocked

Format is the same as the main scenario but with a header indicating which Step it replaces.

---

## Protections Tests Structure

Each `Protections_Test_<N>_Scenario.md` is an **independent sub-scenario** that does not inherit state from the main scenario. Structure mirrors the main scenario but:
- Only 2–4 steps (isolated sub-chain)
- May use a different delivery vector (e.g., PIF dropper instead of DOCX)
- Different lab environment (different domain, different hostnames)
- Test numbers are not necessarily consecutive — only a subset is assigned to each adversary

---

## Cleanup Guide Structure

`<Adversary>_Cleanup_Guide.md` lists every artifact created in the main scenario and how to remove it:
- Dropped files/folders
- Created registry keys
- Created scheduled tasks
- Running processes to kill
- Network connections to terminate
