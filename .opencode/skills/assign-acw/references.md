# assign-acw — Reference

ACW levels, role-weighting decision tree, cross-cutting modifier, consistency check, and output format. Read this file before weighting any rows.

---

## ACW levels

| ACW Level | Weight | Criteria |
|---|---|---|
| **Critical** | 1.0× | High impact; real-world prevalence; hard to detect; **enables primary attack objectives** (credential access enabling lateral movement, ransomware payload, domain compromise) |
| **High** | 0.75× | Significant impact; commonly observed in-the-wild; not yet chain-ending but advances the primary objective significantly |
| **Medium** | 0.5× | Moderate impact; typically preparatory or intermediate steps (discovery, staging, tool transfer) |
| **Low** | 0.25× | Easy to detect; limited strategic value in isolation; reconnaissance or enumeration with no direct impact |

MITRE's stated examples (the **typical level of the technique standing alone**, not a fixed value — when the same technique plays a bottleneck or terminal-objective role in this chain, weight it up by that role):
- Critical: T1003 (Credential Dumping), T1486 (Ransomware encryption)
- High: T1105 (Ingress Tool Transfer)
- Medium: T1082 (System Information Discovery)
- Low: T1033 (System Owner/User Discovery)

---

## Role-weighting decision tree (first match wins, top-down)

**Q1 — Is this behavior a terminal objective?**
- Terminal of the **whole chain** (ransomware encryption T1486, domain takeover, the credential harvest that unlocks the crown jewels, VSS deletion blocking recovery T1490) → **Critical**
- Terminal of a **sub-cluster that is itself a mandatory bottleneck** of the chain (e.g. LSASS dump ending the credential-access cluster that feeds the only PtH into DC) → **Critical**
- Terminal of a **genuinely optional parallel cluster** (the whole cluster can be removed and the chain still reaches its objective — *not* an ALT coverage variant) → **High**

> **ALT path ≠ optional cluster.** Two ALTs reaching the same pivot (e.g. WMI path vs SCM path) exist to widen technique coverage — weight **both** by their shared role (Critical if that role is lateral movement). The optional-cluster demotion applies only when deleting the cluster leaves the chain intact without taking an alternative path.

**Q2 — Is this behavior a bottleneck — does it *create* a new opportunity the chain depends on: initial access, privilege escalation, or lateral movement to another host?**
- Yes (e.g. EfsPotato → SYSTEM, PtH → DC01 C$, the RCE that opens the first shell) → **Critical**
- The existence of an ALT achieving the same pivot does **not** lower this score — the ALT is coverage, weighted the same.

**Q3 — Is this behavior high-value-to-attacker on its own, with real-world prevalence?**
- Commonly seen in threat-actor campaigns, hands the attacker significant capability, but not the terminal objective → **High**
- Bias up when the behavior is **hard to detect** (one of MITRE's Critical traits — missing it costs the defender more)

**Q4 — Is this behavior preparatory or staging?**
- Ingress tool transfer, decode, staging files for later use → **High** (if it directly feeds a Critical next behavior) or **Medium** (generic infrastructure)

**Q5 — Is this behavior evasion/obfuscation whose leverage *in the chain* is low on its own?**
- **Tie-break Q4 vs Q5:** if a step both decodes/stages *and* evades, ask *"does it hand the attacker new capability / move the chain forward?"* — Yes (decode → reflective load → live C2) makes it **staging (Q4)**, weighted by what it feeds. No (it only lowers detectability while capability is unchanged) makes it **pure evasion (Q5)**.
- Stripped payloads, dynamic API resolution, hidden window, masquerading names → **Medium** or **Low** *by chain role*.
- Judge role only. Whether the row is also Not Calibrated is a separate axis and must not push this score up or down.

**Q6 — Is this behavior pure reconnaissance or enumeration?**
- Discovery of users, groups, shares, software → **Low** to **Medium** depending on whether its output directly enabled a Critical next behavior

> **Same technique, different role:** the LSASS-cache dump used to pivot once and the NTDS dump that is the terminal credential harvest are two behaviors — weight each on its own role even when the TID repeats. Sub-techniques are no exception.

---

## Cross-cutting modifier (applied *after* bucketing)

"Hard to detect" is a Critical trait, but it is a tie-breaker, not a bucket of its own:
- If a behavior already landed at **High** *and* is hard to detect (in-memory only, no command line, no file artifact) → consider promoting to **Critical**: missing it costs the defender more.
- Hard-to-detect **never** lifts a Low/Medium row to Critical on its own — it only breaks the **High ↔ Critical** tie.

---

## Consistency check (run before writing output)

- Verify each behavior is weighted on **its own** chain role — do not force rows that share a Technique ID to the same ACW
- Verify at least one Critical behavior exists in the chain
- Verify chain-terminal behaviors (ransomware, domain takeover) are Critical
- Flag any behavior assigned Critical that is purely evasion/obfuscation — re-evaluate against the three lenses
- **Critical ceiling ~35%:** if more than ~35% of rows are Critical, re-review — the usual cause is scoring a sub-cluster terminal (Q1 tier 2/3) as if it were the whole-chain terminal

---

## Output format

**In the CSV:** Insert an `ACW` column immediately after the `Calibration Reason` column (keeps `Category` and `Calibration Reason` adjacent). Use short labels: `Critical`, `High`, `Medium`, `Low` (not `Critical (1.0×)`).

**In the terminal:** One line per behavior row (not per Technique ID):

```
| Step | Behavior (Red Team Activity) | Technique ID | ACW | Role / Rationale |
|---|---|---|---|---|
| Step 2 | Dump LSASS for TESTLAB\Administrator hash | T1003.001 | Critical | Bottleneck → PtH → DC01 lateral movement |
| Step 4 | Dump NTDS.dit domain credential store | T1003.003 | Critical | Terminal objective of the credential-harvest cluster |
| Step 1 | Ingress-transfer dnscat2 implant | T1105 | High | Staging that feeds Critical C2 |
```

When the same TID recurs with different ACW, keep both lines so the role difference is visible. Group by ACW level (Critical first), then by step order within each group.

Also report a brief tally: total behavior rows processed + count per ACW level (Critical / High / Medium / Low).
