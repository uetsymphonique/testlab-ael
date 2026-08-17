---
name: assign-acw
description: Assign Attack Chain Weighting (ACW) to every behavior row in a plan CSV file. Reads attack chain context from summary.md, weights each behavior by its role in the attack chain, and writes an ACW column back to the CSV.
effort: medium
allowed-tools: Read, Write, Grep, Glob
---

Assign ACW (Attack Chain Weighting) to all rows in a plan CSV, regardless of Calibrated/Not Calibrated status. Calibrated labels may change later; weighting all rows now ensures scores are ready as soon as labels are finalized.

<HARD-GATE>
1. Weight EVERY row, including Not-Calibrated ones. ACW and Category are independent axes — never lower an ACW because a row is/might be Not-Calibrated, never treat a high ACW as a reason to keep a row Calibrated.
2. ACW is per BEHAVIOR (per row), not per Technique ID. The same TID on two rows can get different ACW by its role each place — do not collapse them to one weight.
3. Weight on chain role ALONE (terminal objective / bottleneck / value-to-attacker). Work the role questions top-down, FIRST MATCH WINS.
4. Do NOT compute any score, denominator, or Weighted_DC — that is the separate scoring script's job. This skill writes only the `ACW` column.
</HARD-GATE>

**Before proceeding:** Read `references.md` in this skill folder — it contains the ACW levels table, role-weighting decision tree (Q1–Q6), cross-cutting modifier, consistency check criteria, and output format spec.

ACW originates from `testlab-enterprise/mitre-outline/Scoring Specification.md` as a scoring axis of its own — the *importance* multiplier on Detection Coverage. It is not a calibration decision.

---

## What ACW measures — the role of a *behavior* in the chain

**The scored unit is the behavior, not the technique.** DC is scored per behavior; ACW is therefore assigned **per behavior (per row)**, not per Technique ID. The same technique can appear under several behaviors at different points in the chain and **each occurrence gets its own ACW**, because its role differs each place it appears (e.g., `T1003` dumping a local cache to move sideways vs. dumping the domain credential store as the terminal objective — same TID, different weight).

> MITRE's per-technique examples (in references.md) are a condensed illustration that does **not** cover the one-technique-many-roles case. Do not build the weighting purely from them — weight by the behavior's role in *this* chain.

ACW asks: **how much does this behavior matter to the attacker's progress through the chain?** Three lenses, strongest first:

- **Terminal objective** — the behavior is the goal the step-cluster / whole chain is driving toward. → **Critical**.
- **Bottleneck** — the behavior *creates* a new opportunity the chain depends on: initial access, privilege escalation, or lateral movement to another host. Remove it and the downstream steps collapse. → **Critical**.
- **Value-to-attacker** — the leverage the behavior hands the attacker. The greater the capability gained, the higher the weight. → **Medium / Low**.

## ACW vs Category — two independent axes

ACW and the `Category` (Calibrated / Not Calibrated) label answer different questions and **do not govern each other**.

| Axis | Question it answers | Owner skill |
|---|---|---|
| **ACW** | *What role does this behavior play in the attack chain?* | `assign-acw` |
| **Category** | *Is this behavior a fair, scoreable detection point?* | `assign-category` |

Rules that follow:
- Assign ACW from **chain criticality alone** — do not lower ACW for Not-Calibrated rows, do not treat high ACW as a reason to keep a row Calibrated.
- **All four combinations are valid.** A Critical pivot that happens to be an unobservable in-memory step is still **Critical ACW *and* Not Calibrated**.
- The two axes only combine **later, in scoring** — that computation is **out of scope here**.

---

## Inputs to gather

Ask the user (combine into one message):

1. **CSV file path** — the plan CSV to update (e.g., `testlab-enterprise/mitre-outline/iis-apppool-elevation.csv`)
2. **Summary file** — the attack chain summary to read for chain-level context (default: `testlab-enterprise/windows-adversary-plan/Emulation_Plan/summary.md`)
3. **Write-back** — should the CSV be updated in-place, or output a new file? (default: in-place)

If the user's message already specifies file paths, skip asking.

---

## Process

### Step 1 — Read chain context

Read the summary file. Identify at the **behavior** level:
- The overall attack chain phases and the objective each step-cluster drives toward
- Which behaviors are **terminal objectives** (ransomware, domain compromise, the decisive credential harvest)
- Which behaviors are **bottlenecks** (the chain is forced through them; no cheap alternative path)
- Which behaviors are **preparatory** (staging, upload, decode steps)
- Which behaviors are **evasion-only** (little independent leverage if removed from chain)

### Step 2 — Read the CSV

Read the CSV file. Each **row is one behavior** — extract every row with its step, tactic, technique, and red team activity description. Do not collapse rows by Technique ID; the same TID on two rows is two behaviors.

**Expected CSV columns:** `Step`, `Tactic`, `Technique ID`, `Technique Name`, `Platform`, `Detection Criteria`, `Category`, `Calibration Reason`, `Red Team Activity`, `Hosts`, `Users`

### Step 3 — Assign ACW per behavior (per row)

**Track coverage explicitly.** Create one task per CSV row (or a tracked checklist) and mark it done only after its `ACW` cell is written. Do not report done while any row is unweighted.

Use the **role-weighting decision tree** (references.md → Q1–Q6, first match wins) to assign each row's ACW. After bucketing all rows, apply the **cross-cutting modifier** (references.md → Hard-to-detect tie-breaker).

### Step 4 — Consistency check

Run the checks in **references.md → Consistency check** before writing. Key gate: Critical ceiling ~35% — if over, re-review sub-cluster vs whole-chain terminal distinction.

### Step 5 — Write output

See **references.md → Output format** for column placement, label shorthand, and the terminal summary table spec.

---

## Anti-Patterns — named rationalizations to reject

**"Same TID as that other row — give it the same ACW."** Weight by role, not by technique label. The same TID plays different roles at different chain points (LSASS-cache pivot vs NTDS terminal harvest) — each occurrence gets its own ACW.

**"This row is Not Calibrated, so ACW low / skip it."** ACW and Category are independent axes. Weight every row on its chain role; a Critical bottleneck that happens to be an unobservable in-memory step is still Critical ACW *and* Not Calibrated.

**"This evasion is technically sophisticated → Critical."** Critical is for a terminal-objective or bottleneck role. Pure evasion/obfuscation that hands no new capability is Medium/Low by chain leverage, however clever.

**"Critical is important, so mark plenty of rows Critical."** Critical ceiling is ~35%. Over that, the usual cause is scoring a sub-cluster terminal as if it were the whole-chain terminal — re-review against Q1's tiers.

**"This ALT path is a fallback, so lower its weight."** ALTs widen technique coverage, they are not fallbacks. An ALT and its main step share a role → same ACW.

## Red Flags — STOP if you are thinking:

| If you think… | The reality is… |
|---|---|
| "Same TID → same ACW" | Weight by chain role; the same TID can differ row to row |
| "Not Calibrated → low/skip ACW" | Independent axes — weight every row on chain role |
| "Sophisticated evasion → Critical" | Critical is terminal/bottleneck role; pure evasion is Medium/Low |
| "Mark lots of rows Critical" | Critical ceiling ~35% — re-review sub-cluster vs whole-chain terminals |
| "ALT is a fallback, weight it down" | ALTs widen coverage — same role, same ACW as the main step |

## Terminal state

The terminal state is: the `ACW` column populated for **every** row (`Critical` / `High` / `Medium` / `Low`), plus the per-behavior summary table and the count tally output to the terminal.

This is the end of the per-row pipeline. Do NOT compute any score, denominator, or Weighted_DC, and do NOT change Category labels — those belong to the scoring script and `assign-category` respectively.

## Notes

- Do **not** skip Not Calibrated rows — weight all rows; the Calibrated distinction is tracked separately in the Category column
- **ALT steps exist to widen coverage to more techniques, not as fallback paths.** An ALT and its main step carry the **same** ACW — weight both by their shared chain role. The existence of an ALT does not lower the main step's ACW (and vice versa)
- If the same TID appears in different rows with different chain roles, give **each its own ACW** by role — do not collapse them to one weight
- Do not assign Critical to behaviors that are purely evasion mechanisms with no terminal/bottleneck role, even if they are technically sophisticated
- T1059.003 (cmd.exe shell) and T1106 (Native API) are **low-leverage execution plumbing** — they hand the attacker no terminal/bottleneck role on their own → usually **Low ACW**. (Whether they are Calibrated is a separate axis, not decided here.)
