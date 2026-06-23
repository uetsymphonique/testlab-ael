---
name: assign-acw
description: Assign Attack Chain Weighting (ACW) to every behavior row in a plan CSV file. Reads attack chain context from summary.md, weights each behavior by its role in the attack chain, and writes an ACW column back to the CSV.
model: claude-sonnet-4-6
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

ACW originates from `testlab-enterprise/mitre-outline/Scoring Specification.md` as a scoring axis of its own — the *importance* multiplier on Detection Coverage. It is not a calibration decision.

---

## What ACW measures — the role of a *behavior* in the chain

**The scored unit is the behavior, not the technique.** DC is scored per behavior; ACW is therefore assigned **per behavior (per row)**, not per Technique ID. The same technique can appear under several behaviors at different points in the chain and **each occurrence gets its own ACW**, because its role differs each place it appears (e.g., `T1003` dumping a local cache to move sideways vs. dumping the domain credential store as the terminal objective — same TID, different weight).

> MITRE's per-technique examples (below) are a condensed illustration that does **not** cover the one-technique-many-roles case. Do not build the weighting purely from them — weight by the behavior's role in *this* chain.

ACW asks: **how much does this behavior matter to the attacker's progress through the chain?** Three lenses, strongest first:

- **Terminal objective** — the behavior is the goal the step-cluster / whole chain is driving toward (ransomware encryption, domain takeover, the credential harvest that unlocks the crown jewels). → **Critical**.
- **Bottleneck** — the behavior *creates* a new opportunity the chain depends on: initial access, privilege escalation, or lateral movement to another host. Remove it and the downstream steps collapse. → **Critical**.
- **Value-to-attacker** — the leverage the behavior hands the attacker. The greater the capability gained, the higher the weight; preparatory / staging / standalone recon yields little leverage on its own. → **Medium / Low**.

## ACW vs Category — two independent axes

ACW and the `Category` (Calibrated / Not Calibrated) label answer different questions and **do not govern each other**. Conflating them is the most common error when this skill is run alongside `assign-category`.

| Axis | Question it answers | Owner skill | Source |
|---|---|---|---|
| **ACW** | *What role does this behavior play in the attack chain?* (terminal objective, bottleneck, value-to-attacker) | `assign-acw` | Scoring Specification → ACW |
| **Category** | *Is this behavior a fair, scoreable detection point?* (observable, reproducible, independently verifiable) | `assign-category` | calibration methodology |

Rules that follow:

- Assign ACW from **chain criticality alone**. Do **not** lower an ACW because a row is (or might become) Not Calibrated, and do **not** treat a high ACW as a reason to keep a row Calibrated.
- **All four combinations are valid.** A Critical pivot that happens to be an unobservable in-memory step is still **Critical ACW *and* Not Calibrated**. A noisy, easily-detected recon command can be **Calibrated *and* Low ACW**.
- Either label can be wrong **independently**. Re-checking or correcting one never forces a change to the other.
- The two axes only combine **later, in scoring** — a separate script multiplies each behavior's DC by its ACW and sums over the Calibrated behaviors. That computation is **out of scope here**: this skill only writes the ACW label. Score each axis on its own merits and leave the formula to the scorer.

## Inputs to gather

Ask the user (combine into one message):

1. **CSV file path** — the plan CSV to update (e.g., `testlab-enterprise/mitre-outline/iis-apppool-elevation.csv`)
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

MITRE's stated examples — these are the **typical level of the technique standing alone**, not a fixed value. When the same technique plays a bottleneck or terminal-objective role in this chain, weight it up by that role:
- Critical: T1003 (Credential Dumping), T1486 (Ransomware encryption)
- High: T1105 (Ingress Tool Transfer)
- Medium: T1082 (System Information Discovery)
- Low: T1033 (System Owner/User Discovery)

---

## Process

### Step 1 — Read chain context

Read the summary file. Identify, at the **behavior** level:
- The overall attack chain phases and the objective each step-cluster drives toward
- Which behaviors are **terminal objectives** (ransomware, domain compromise, the decisive credential harvest)
- Which behaviors are **bottlenecks** (the chain is forced through them; no cheap alternative path)
- Which behaviors are **preparatory** (staging, upload, decode steps)
- Which behaviors are **evasion-only** (little independent leverage if removed from chain)

### Step 2 — Read the CSV

Read the CSV file. Each **row is one behavior** — extract every row with its step, tactic, technique, and red team activity description. Do not collapse rows by Technique ID; the same TID on two rows is two behaviors.

**Expected CSV columns:** `Step`, `Tactic`, `Technique ID`, `Technique Name`, `Platform`, `Detection Criteria`, `Category`, `Calibration Reason`, `Red Team Activity`, `Hosts`, `Users`

### Step 3 — Assign ACW per behavior (per row)

**Track coverage explicitly.** Create one task per CSV row (or a tracked checklist) and mark it done only after its `ACW` cell is written. Do not report done while any row is unweighted — every row gets an ACW, Calibrated or not.

ACW is assigned **per behavior**, i.e. **per row** — not per Technique ID. The same TID appearing on multiple rows can receive **different** ACW, because its role in the chain differs each place it appears. Weight each row on *its* role, not on its technique label.

For each behavior row, reason through the following questions in order (**first match wins, top-down**):

1. **Is this behavior a terminal objective — and at what level?**
   - Terminal of the **whole chain** (ransomware encryption T1486, domain takeover, the credential harvest that unlocks the crown jewels, VSS deletion blocking recovery T1490) → **Critical**
   - Terminal of a **sub-cluster that is itself a mandatory bottleneck** of the chain (e.g. LSASS dump ending the credential-access cluster that feeds the only PtH into DC) → **Critical**
   - Terminal of a **genuinely optional parallel cluster** (the whole cluster can be removed and the chain still reaches its objective — *not* an ALT coverage variant) → **High**
   - ⚠️ An **ALT path is not an "optional cluster".** Two ALTs reaching the same pivot (e.g. WMI path vs SCM path) exist to widen technique coverage — weight **both** by their shared role (Critical if that role is lateral movement). The optional-cluster demotion applies only when deleting the cluster leaves the chain intact.

2. **Is this behavior a bottleneck — does it *create* a new opportunity the chain depends on: initial access, privilege escalation, or lateral movement to another host?**
   - Yes (e.g. EfsPotato → SYSTEM, PtH → DC01 C$, the RCE that opens the first shell) → **Critical**
   - The existence of an ALT achieving the same pivot does **not** lower this score — the ALT is coverage, weighted the same (see the ALT note under "Notes").

3. **Is this behavior high-value-to-attacker on its own, with real-world prevalence?**
   - Commonly seen in threat-actor campaigns, hands the attacker significant capability, but not the terminal objective → **High**
   - Bias up when the behavior is **hard to detect** (one of MITRE's Critical traits — missing it costs the defender more)

4. **Is this behavior preparatory or staging?**
   - Ingress tool transfer, decode, staging files for later use → **High** (if it directly feeds a Critical next behavior) or **Medium** (generic infrastructure)

5. **Is this behavior evasion/obfuscation whose leverage *in the chain* is low on its own?**
   - **Tie-break Q4 vs Q5:** if a step both decodes/stages *and* evades, ask *"does it hand the attacker new capability / move the chain forward?"* — Yes (decode → reflective load → live C2) makes it **staging (Q4)**, weighted by what it feeds. No (it only lowers detectability while capability is unchanged) makes it **pure evasion (Q5)**.
   - Stripped payloads, dynamic API resolution, hidden window, masquerading names → **Medium** or **Low** *by chain role*.
   - Judge role only. Whether the row is also Not Calibrated is a separate axis (see "ACW vs Category") and must not push this score up or down.

6. **Is this behavior pure reconnaissance or enumeration?**
   - Discovery of users, groups, shares, software → **Low** to **Medium** depending on whether its output directly enabled a Critical next behavior

> **Same technique, different role:** the LSASS-cache dump used to pivot once and the NTDS dump that is the terminal credential harvest are two behaviors — weight each on its own role even when the TID (or its parent T1003) repeats. Sub-techniques are no exception.

### Step 3b — Cross-cutting modifier (applied *after* bucketing)

"Hard to detect" is a Critical trait, but it is a tie-breaker, not a bucket of its own:
- If a behavior already landed at **High** *and* is hard to detect (in-memory only, no command line, no file artifact) → consider promoting to **Critical**: missing it costs the defender more.
- Hard-to-detect **never** lifts a Low/Medium row to Critical on its own — it only breaks the **High ↔ Critical** tie.

### Step 4 — Consistency check

Before writing:
- Verify each behavior is weighted on **its own** chain role — do **not** force rows that share a Technique ID to the same ACW
- Verify at least one Critical behavior exists in the chain
- Verify chain-terminal behaviors (ransomware, domain takeover) are Critical
- Flag any behavior assigned Critical that is purely evasion/obfuscation — re-evaluate against the three lenses
- **Critical ceiling:** Critical is for behaviors whose removal breaks the chain or which *are* the impact — expect them to be a minority of rows. If **more than ~35%** of rows are Critical, re-review: the usual cause is scoring a *sub-cluster* terminal (Q1 tier 2/3) as if it were the *whole-chain* terminal.

### Step 5 — Write output

**In the CSV:** Insert an `ACW` column immediately after the `Calibration Reason` column (keep `Category` and its `Calibration Reason` adjacent).

Format:
- `Critical` (not `Critical (1.0×)` — keep the label short for column width)
- `High`
- `Medium`
- `Low`

**In the terminal:** Output a summary table — **one line per behavior row**, not per Technique ID:

```
| Step | Behavior (Red Team Activity) | Technique ID | ACW | Role / Rationale |
|---|---|---|---|---|
| Step 2 | Dump LSASS for TESTLAB\Administrator hash | T1003.001 | Critical | Bottleneck → PtH → DC01 lateral movement |
| Step 4 | Dump NTDS.dit domain credential store | T1003.003 | Critical | Terminal objective of the credential-harvest cluster |
| Step 1 | Ingress-transfer dnscat2 implant | T1105 | High | Staging that feeds Critical C2 |
```

When the same TID recurs with different ACW, keep both lines so the role difference is visible. Group by ACW level (Critical first), then by step order within each group.

Also report a brief tally:
- Total behavior rows processed
- Count per ACW level (Critical / High / Medium / Low)

Do **not** compute any score, denominator, or Weighted_DC here — that is the separate scoring script's job. This skill's output is the populated `ACW` column plus the summary tally above.

---

## Anti-Patterns — named rationalizations to reject

**"Same TID as that other row — give it the same ACW."** Weight by role, not by technique label. The same TID plays different roles at different chain points (LSASS-cache pivot vs NTDS terminal harvest) — each occurrence gets its own ACW.

**"This row is Not Calibrated, so ACW low / skip it."** ACW and Category are independent axes. Weight every row on its chain role; a Critical bottleneck that happens to be an unobservable in-memory step is still Critical ACW *and* Not Calibrated.

**"This evasion is technically sophisticated → Critical."** Critical is for a terminal-objective or bottleneck role. Pure evasion/obfuscation that hands no new capability is Medium/Low by chain leverage, however clever.

**"Critical is important, so mark plenty of rows Critical."** Critical ceiling is ~35%. Over that, the usual cause is scoring a *sub-cluster* terminal as if it were the *whole-chain* terminal — re-review against Q1's tiers.

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
- **ALT steps exist to widen coverage to more techniques, not as fallback paths.** An ALT and its main step carry the **same** ACW — weight both by their shared chain role. The existence of an ALT does not lower the main step's ACW (and vice versa); do not treat an ALT as a "redundant path that lowers pivotality".
- If the same TID appears in different rows with different chain roles, give **each its own ACW** by role — do not collapse them to one weight
- Do not assign Critical to behaviors that are purely evasion mechanisms with no terminal/bottleneck role, even if they are technically sophisticated
- T1059.003 (cmd.exe shell) and T1106 (Native API) are **low-leverage execution plumbing** — they hand the attacker no terminal/bottleneck role on their own → usually **Low ACW**. (Whether they are Calibrated is a separate axis, not decided here.)
