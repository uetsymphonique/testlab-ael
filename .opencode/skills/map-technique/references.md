# map-technique — Reference

Tactic identification table, knowledge-base file paths, verification process, and common pitfalls. Read this file before mapping any behavior.

---

## Tactic identification table

Cross-reference the behavior against these guiding questions to determine what the adversary is trying to accomplish. A single behavior may serve multiple tactics simultaneously — in that case, create one row per tactic in the Reference Table.

| Tactic ID | Tactic Name | Guiding question |
|---|---|---|
| TA0001 | Initial Access | Is the adversary trying to gain entry into the network for the first time? |
| TA0002 | Execution | Is the adversary running code or commands on a system? |
| TA0003 | Persistence | Is the adversary trying to maintain access across reboots or resets? |
| TA0004 | Privilege Escalation | Is the adversary trying to gain higher privileges? |
| TA0005 | Stealth | Is the adversary trying to hide/blend in by concealing or obfuscating their actions — without touching security tooling itself? |
| TA0006 | Credential Access | Is the adversary trying to obtain credentials? |
| TA0007 | Discovery | Is the adversary collecting information about the environment? |
| TA0008 | Lateral Movement | Is the adversary trying to move to another system? |
| TA0009 | Collection | Is the adversary gathering target data? |
| TA0010 | Exfiltration | Is the adversary trying to move data out of the network? |
| TA0011 | Command and Control | Is the adversary communicating with a compromised system? |
| TA0040 | Impact | Is the adversary trying to destroy, disrupt, or encrypt data? |
| TA0042 | Resource Development | Is the adversary building infrastructure or resources to support operations? |
| TA0043 | Reconnaissance | Is the adversary gathering information to plan an attack? |
| TA0112 | Defense Impairment | Is the adversary trying to break, disable, or tamper with security controls, logging, or monitoring tooling directly? |

> As of ATT&CK v19.1, the former **Defense Evasion** (TA0005) tactic was split in two: **Stealth** (TA0005 — same ID, renamed) covers concealment/blending-in behaviors, and **Defense Impairment** (TA0112 — new) covers direct interference with defensive systems (disabling logs, tampering with tools/firewalls, weakening auth or crypto). See the cross-list pitfall below for how to pick between them.

---

## KB lookup — Grep the slim menu, never Read the whole file

These tactic files are large (Stealth ≈ 3,000 lines, Persistence ≈ 1,800), because every technique carries a full `**Detection**` block and a long `**Procedure Examples**` list. **None of that is needed for mapping.** `Read`ing the whole file is what bloats context.

The files are perfectly regular: every technique is a `### TID - Name` heading followed by **exactly one** description line, then `**Detection**` / `**Procedure Examples**`.

**Browse stage — pick the technique.** Grep just the headings for the one tactic file:

```
Grep  pattern="^### "  path="mitre-knowledge-base/techniques/<tactic>.md"  output_mode="content"
```

This returns the entire technique menu — parents *and* sub-techniques (e.g. `T1027.001`, `T1027.002`) — each with its `TID - Name` and its **line number**, at a tiny fraction of the full file. The names alone narrow the candidates fast. (Note: the Grep tool omits long lines from output, so descriptions do not come back here even with `-A 1` — that is fine, get them in the verify stage.)

**Verify stage — read only the chosen technique's description.** Take the line number of the candidate from the menu and `Read` a narrow range to get its description, e.g. `Read path="…/<tactic>.md" offset=<line> limit=2`. The description line confirms mechanism and platform and lets you choose between a parent and its sub-techniques (read each candidate sub's one line). Never widen back to the whole file, and never pull the `**Detection**` / `**Procedure Examples**` blocks — they belong to `write-detection-criteria`, not mapping.

### File paths (tactic → file)

| Tactic | Path |
|---|---|
| Initial Access | `mitre-knowledge-base/techniques/TA0001-initial-access.md` |
| Execution | `mitre-knowledge-base/techniques/TA0002-execution.md` |
| Persistence | `mitre-knowledge-base/techniques/TA0003-persistence.md` |
| Privilege Escalation | `mitre-knowledge-base/techniques/TA0004-privilege-escalation.md` |
| Stealth | `mitre-knowledge-base/techniques/TA0005-stealth.md` |
| Credential Access | `mitre-knowledge-base/techniques/TA0006-credential-access.md` |
| Discovery | `mitre-knowledge-base/techniques/TA0007-discovery.md` |
| Lateral Movement | `mitre-knowledge-base/techniques/TA0008-lateral-movement.md` |
| Collection | `mitre-knowledge-base/techniques/TA0009-collection.md` |
| Exfiltration | `mitre-knowledge-base/techniques/TA0010-exfiltration.md` |
| Command and Control | `mitre-knowledge-base/techniques/TA0011-command-and-control.md` |
| Impact | `mitre-knowledge-base/techniques/TA0040-impact.md` |
| Resource Development | `mitre-knowledge-base/techniques/TA0042-resource-development.md` |
| Reconnaissance | `mitre-knowledge-base/techniques/TA0043-reconnaissance.md` |
| Defense Impairment | `mitre-knowledge-base/techniques/TA0112-defense-impairment.md` |

Grep only the file(s) for the tactic(s) identified — never open all files, and never `Read` a file in full.

---

## Technique and sub-technique selection

In the tactic file, find the technique that matches the behavior:

1. **Parent technique** (T1XXX) — check for a match
2. **Sub-technique** (T1XXX.YYY) — if sub-techniques exist, determine which one fits. **Prefer sub-technique over parent when one fits** — the parent is a fallback, not a default

Required output per behavior:
- **Technique ID**: full ID including sub-technique (e.g., `T1059.001`, not `T1059`)
- **Technique Name**: full name including sub-technique (e.g., `Command and Scripting Interpreter: PowerShell`)

Common parent-to-sub patterns:
- `T1218` System Binary Proxy Execution → identify sub by binary: `.010` Regsvr32, `.007` Msiexec, `.013` Mavinject…
- `T1059` Command and Scripting Interpreter → identify sub by interpreter: `.001` PowerShell, `.003` cmd, `.007` JavaScript…

---

## Verification process (when a TID is already in mind)

Use when a technique ID is already suggested (from prior knowledge, a source, or a user hint) and needs to be confirmed as correctly describing the behavior under review. This is a verification step, not a search step.

1. Grep the technique heading in the relevant tactic file to get its line number, e.g. `Grep pattern="^### T1574" path="…/<tactic>.md" output_mode="content"` (do not `Read` the whole file)
2. `Read` a narrow range at that line number (`offset=<line> limit=2`) to land on the technique ID with its description
3. Read the main description — compare with the behavior:
   - Does the **mechanism** match? (e.g., T1574.001 covers DLL Side-Loading, Search Order Hijacking, Redirection, Phantom, and Substitution as of ATT&CK v19.1 — if the behavior is `gup.exe` loading `libcurl.dll`, it matches)
   - Does the **platform** match? (Windows / Linux / IaaS…)
4. If the technique has sub-techniques, read each to determine which the behavior falls under — do not stop at the parent if a sub fits better
5. Conclusion: definition matches → confirm; definition does not match → search from Step 1

When reading to verify, focus on **mechanism**, not just name.

---

## Common pitfalls

- **Execution vs Lateral Movement**: when an adversary runs commands remotely on another host (WMI, PsExec, WinRM), combine both tactics — Lateral Movement is the movement vector, Execution is the code-running behavior. Create two rows.
- **Privilege Escalation and Persistence overlap**: many techniques in TA0004 also appear in TA0003 — determine whether the behavior is primarily escalation or persistence, or list both if both apply.
- **Stealth vs Defense Impairment cross-list**: many techniques from other tactics carry an evasion component and cross-list into one of the two former-Defense-Evasion tactics. Pick based on mechanism, not just "this evades detection":
  - **TA0005 Stealth** — the behavior conceals, obfuscates, or blends in (e.g. `T1027` Obfuscated Files, `T1036` Masquerading, `T1055` Process Injection, `T1564` Hide Artifacts, `T1070` Indicator Removal) — security tooling itself is left running and untouched.
  - **TA0112 Defense Impairment** — the behavior directly disables, tampers with, or weakens a defensive control (e.g. `T1685` Disable or Modify Tools, `T1686` Disable or Modify System Firewall, `T1556` Modify Authentication Process, `T1553` Subvert Trust Controls, `T1112` Modify Registry when the target is a security-relevant key).
  - If the behavior has both a concealment step and an impairment step, add one row per tactic.
- **Do not guess on out-of-scope techniques**: if the behavior does not match any in-scope technique, report that rather than selecting the closest guess.
