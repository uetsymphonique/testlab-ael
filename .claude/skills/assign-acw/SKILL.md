---
name: assign-acw
description: Assign Attack Chain Weighting (ACW) to every technique row in a plan CSV file. Reads attack chain context from summary.md, applies criticality weights per unique Technique ID, and writes an ACW column back to the CSV.
model: claude-sonnet-4-6
effort: medium
allowed-tools: Read, Write, Grep, Glob
---

Assign ACW (Attack Chain Weighting) to all rows in a plan CSV, regardless of Calibrated/Not Calibrated status. Calibrated labels may change later; weighting all rows now ensures scores are ready as soon as labels are finalized.

---

## Inputs to gather

Ask the user (combine into one message):

1. **CSV file path** — the plan CSV to update (e.g., `testlab-enterprise/mitre-outline/iisprivileged-escalation-to-DC.csv`)
2. **Summary file** — the attack chain summary to read for chain-level context (default: `testlab-enterprise/windows-adversary-plan/Emulation_Plan/summary.md`)
3. **Write-back** — should the CSV be updated in-place, or output a new file? (default: in-place)

If the user's message already specifies file paths, skip asking.

---

## Scoring reference

From `testlab-enterprise/mitre-outline/Scoring Specification.md` and `testlab-enterprise/mitre-outline/Methodology Overview.md`:

| ACW Level | Weight | Criteria |
|---|---|---|
| **Critical** | 1.0× | High impact; real-world prevalence; hard to detect; **enables primary attack objectives** (credential access enabling lateral movement, ransomware payload, domain compromise) |
| **High** | 0.75× | Significant impact; commonly observed in-the-wild; not yet chain-ending but advances the primary objective significantly |
| **Medium** | 0.5× | Moderate impact; typically preparatory or intermediate steps (discovery, staging, tool transfer) |
| **Low** | 0.25× | Easy to detect; limited strategic value in isolation; reconnaissance or enumeration with no direct impact |

MITRE's stated examples:
- Critical: T1003 (Credential Dumping), T1486 (Ransomware encryption)
- High: T1105 (Ingress Tool Transfer)
- Medium: T1082 (System Information Discovery)
- Low: T1033 (System Owner/User Discovery)

---

## Process

### Step 1 — Read chain context

Read the summary file. Identify:
- The overall attack chain phases and their objectives
- Which techniques are **chain-enabling** (without this, the next phase cannot proceed)
- Which techniques are **chain-ending** (ransomware, domain compromise, credential harvest)
- Which techniques are **preparatory** (staging, upload, decode steps)
- Which techniques are **evasion-only** (no independent impact if removed from chain)

### Step 2 — Read the CSV

Read the CSV file. Extract all unique Technique IDs and their associated steps, tactics, and red team activity descriptions.

**Expected CSV columns:** `Step`, `Tactic`, `Technique ID`, `Technique Name`, `Platform`, `Detection Criteria`, `Category`, `Red Team Activity`, `Hosts`, `Users`

### Step 3 — Assign ACW per unique Technique ID

ACW is assigned **per Technique ID** (e.g., T1003.001), not per row. If the same TID appears in multiple steps or rows, it receives the same ACW everywhere.

For each unique TID, reason through the following questions in order:

1. **Is this technique chain-ending or the terminal impact?**
   - Ransomware (T1486), credential harvest enabling domain-wide compromise (T1003.003 + T1550.002 chain), VSS deletion blocking recovery (T1490) → **Critical**

2. **Is this technique chain-enabling — does it directly unlock the next major phase?**
   - Technique without which lateral movement, privilege escalation, or persistence cannot proceed → **Critical**
   - Technique that significantly advances the objective but has alternatives → **High**

3. **Is this technique a significant standalone behavior with real-world prevalence?**
   - Commonly observed in threat actor campaigns, significant artifact, but not chain-ending → **High**

4. **Is this technique preparatory or staging?**
   - Ingress tool transfer, decode, staging files for later use → **High** (if directly enables Critical next step) or **Medium** (if generic infrastructure)

5. **Is this technique purely evasion or obfuscation with no independent impact?**
   - Stripped payloads, dynamic API resolution, hidden window, masquerading names only → **Medium** or **Low**

6. **Is this technique pure reconnaissance or enumeration?**
   - Discovery of users, groups, shares, software → **Low** to **Medium** depending on whether the output directly enabled a Critical next step

> **Note on sub-techniques:** T1003.001 (LSASS) and T1003.003 (NTDS) may receive different ACW if their chain roles differ. Evaluate each sub-technique independently.

### Step 4 — Consistency check

Before writing:
- Verify all rows with the same Technique ID have the same ACW
- Verify at least one Critical technique exists in the chain
- Verify chain-terminal techniques (ransomware, domain takeover) are Critical
- Flag any technique assigned Critical that is purely evasion/obfuscation — re-evaluate

### Step 5 — Write output

**In the CSV:** Insert an `ACW` column immediately after the `Category` column.

Format:
- `Critical` (not `Critical (1.0×)` — keep the label short for column width)
- `High`
- `Medium`
- `Low`

**In the terminal:** Output a summary table:

```
| Technique ID | Technique Name | ACW | Rationale |
|---|---|---|---|
| T1003.001 | LSASS Memory | Critical | Enables TESTLAB\Administrator hash recovery → PtH → DC01 lateral movement chain |
| T1105 | Ingress Tool Transfer | High | ... |
```

Group by ACW level (Critical first), then by Technique ID within each group.

Also report:
- Total rows processed
- Calibrated rows that will be scored (ACW counts in formula)
- Not Calibrated rows also weighted (tracked, will count when label changes)
- Weighted DC denominator estimate: `Σ ACW_weight × 3.0` for Calibrated rows only

---

## Notes

- Do **not** skip Not Calibrated rows — weight all rows; the Calibrated distinction is tracked separately in the Category column
- If a technique appears in an ALT step only, assign ACW as if it were the main path unless the user specifies otherwise
- If the same TID appears in different phases with meaningfully different chain roles, use the highest ACW that applies
- Do not assign Critical to techniques that are purely evasion mechanisms with no direct impact objective, even if they are technically sophisticated
- T1059.003 (cmd.exe shell) and T1106 (Native API) are typically **Not Calibrated** implementation details — their ACW still should be assigned, but note in the summary that they are unlikely to accumulate scoring weight
