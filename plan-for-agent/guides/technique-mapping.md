# Guide: Technique Mapping

How to identify the ATT&CK tactic and technique corresponding to a specific adversary behavior, for use in filling Reference Tables in the emulation plan.

> **Scope of this guide:** Identify the correct Tactic, Technique ID, Technique Name, and Platform for a behavior. This guide does **not** handle the `Detection Criteria` or `Category` columns — those are covered separately in `category-assignment.md`.

---

## Step 1 — Identify the tactic from the behavior

Read the behavior description and cross-reference with tactic definitions in `mitre-knowledge-base/tactics.md` to determine what the adversary is trying to accomplish:

| Tactic ID | Tactic Name | Guiding question |
|---|---|---|
| TA0001 | Initial Access | Is the adversary trying to gain entry into the network for the first time? |
| TA0002 | Execution | Is the adversary running code or commands on a system? |
| TA0003 | Persistence | Is the adversary trying to maintain access across reboots or resets? |
| TA0004 | Privilege Escalation | Is the adversary trying to gain higher privileges? |
| TA0005 | Defense Evasion | Is the adversary trying to avoid detection? |
| TA0006 | Credential Access | Is the adversary trying to obtain credentials? |
| TA0007 | Discovery | Is the adversary collecting information about the environment? |
| TA0008 | Lateral Movement | Is the adversary trying to move to another system? |
| TA0009 | Collection | Is the adversary gathering target data? |
| TA0010 | Exfiltration | Is the adversary trying to move data out of the network? |
| TA0011 | Command and Control | Is the adversary communicating with a compromised system? |
| TA0040 | Impact | Is the adversary trying to destroy, disrupt, or encrypt data? |
| TA0042 | Resource Development | Is the adversary building infrastructure or resources to support operations? |
| TA0043 | Reconnaissance | Is the adversary gathering information to plan an attack? |

> A single behavior may serve multiple tactics simultaneously — e.g., DLL Side-Loading is both Execution and Defense Evasion. In this case, create multiple rows in the Reference Table, one per tactic.

---

## Step 2 — Look up the technique file by tactic

Each tactic has a corresponding technique definition file in `mitre-knowledge-base/techniques/`:

| Tactic | Path |
|---|---|
| Initial Access | `mitre-knowledge-base/techniques/TA0001-initial-access.md` |
| Execution | `mitre-knowledge-base/techniques/TA0002-execution.md` |
| Persistence | `mitre-knowledge-base/techniques/TA0003-persistence.md` |
| Privilege Escalation | `mitre-knowledge-base/techniques/TA0004-privilege-escalation.md` |
| Defense Evasion | `mitre-knowledge-base/techniques/TA0005-defense-evasion.md` |
| Credential Access | `mitre-knowledge-base/techniques/TA0006-credential-access.md` |
| Discovery | `mitre-knowledge-base/techniques/TA0007-discovery.md` |
| Lateral Movement | `mitre-knowledge-base/techniques/TA0008-lateral-movement.md` |
| Collection | `mitre-knowledge-base/techniques/TA0009-collection.md` |
| Exfiltration | `mitre-knowledge-base/techniques/TA0010-exfiltration.md` |
| Command and Control | `mitre-knowledge-base/techniques/TA0011-command-and-control.md` |
| Impact | `mitre-knowledge-base/techniques/TA0040-impact.md` |
| Reconnaissance | `mitre-knowledge-base/techniques/TA0043-reconnaissance.md` |

Open the relevant file and find the technique that matches the behavior.

---

## Step 3 — Identify technique and sub-technique

In the technique file, read the description to determine:

1. **Parent technique** (T1XXX) — check for a match
2. **Sub-technique** (T1XXX.YYY) — if sub-techniques exist, determine which one the specific behavior falls under. **Prefer sub-technique over parent when one fits** — avoid assigning at the parent level when the behavior clearly maps to a specific sub-technique

Required output:
- **Technique ID**: full ID including sub-technique if applicable (e.g., `T1059.001`, not just `T1059`)
- **Technique Name**: full name including sub-technique (e.g., `Command and Scripting Interpreter: PowerShell`)

---

## Step 4 — Cross-reference technique scope

After identifying the technique ID, verify against evaluation scope:

- `testlab-enterprise/mitre-outline/Scenario 1.md` — Crimeware-as-a-Service (Windows EDR)
- `testlab-enterprise/mitre-outline/Scenario 2.md` — PRC Espionage (cross-platform, XDR)

Record:
- Technique in scope → add to Reference Table normally
- Technique out of scope → note it; only include if explicitly requested

---

## Confirming a known technique maps to the behavior

Use when: a technique ID is already in mind (from a suggestion, source, or prior knowledge) and needs to be confirmed as correctly describing the behavior under review. This is a verification step, not a search step.

### Verification process

1. **Open the technique file** for the relevant tactic from the table in Step 2
2. **Navigate to the technique ID** in question
3. **Read the main description** — compare with the behavior:
   - Does the mechanism match? (e.g., T1574.002 describes a DLL loaded by a legitimate binary — if the behavior is `gup.exe` loading `libcurl.dll`, it matches)
   - Does the platform match? (Windows / Linux / IaaS...)
4. **If the technique has sub-techniques**, read each to determine which the behavior falls under — do not stop at the parent if a sub fits better
5. **Conclusion**:
   - Definition matches → confirm using that technique ID
   - Definition does not match → find another technique, repeat from Step 1/2/3

### What to read in the technique file

Each technique in `mitre-knowledge-base/techniques/` typically contains:
- **General description** — what adversaries use this technique to accomplish
- **Real-world examples** — common tools, binaries, or execution methods
- **Sub-techniques** (if present) — descriptions of specific variants

When reading to verify, focus on **mechanism**, not just name. For example:
- `T1218` System Binary Proxy Execution — parent; identify the sub: `.010` Regsvr32, `.007` Msiexec, `.013` Mavinject...
- `T1059` Command and Scripting Interpreter — parent; identify sub by interpreter: `.001` PowerShell, `.003` cmd, `.007` JavaScript...

---

## Common pitfalls

- **Execution vs Lateral Movement**: when an adversary runs commands remotely on another host (WMI, PsExec, WinRM), combine both tactics — Lateral Movement is the movement vector, Execution is the code-running behavior. Create two rows.
- **Privilege Escalation and Persistence overlap**: many techniques in TA0004 also appear in TA0003 — determine whether the behavior is primarily escalation or persistence, or list both if both apply.
- **Defense Evasion cross-list**: many techniques from other tactics are cross-listed into TA0005 when they have an evasion component. If the behavior has a clear evasion component, add a TA0005 row with the cross-listed technique.
- **Do not assign out-of-scope techniques**: if the behavior does not match any in-scope technique, report that rather than selecting the closest guess.
