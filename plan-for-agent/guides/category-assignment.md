# Guide: Assigning Category Labels and Verifying Detection Criteria

How to determine the `Calibrated`/`Not Calibrated` label for each Reference Table row, and verify that Detection Criteria meet the required standard. This is the operational process; `attack-behavior-methodology.md` is the extended commentary with examples from past MITRE scenarios.

---

## Three valid labels

| Label | Meaning |
|---|---|
| `Calibrated - Not Benign` | Scored behavior — counts toward the detection rate denominator |
| `Not Calibrated - Not Benign` | Setup substep, implementation detail, or fails a condition — does not count toward denominator |
| `Calibrated - Benign` | Legitimate behavior that looks like an attack — used to test false positive threshold |

> **Distinguishing `Not Benign` vs `Benign`:** This is a question about **adversary intent within the attack chain context**, not about whether the tool is dangerous. `whoami`, `ping`, `nltest` run from a compromised account are `Calibrated - Not Benign` because these are adversary behaviors in context. Only use `Calibrated - Benign` when the behavior is explicitly designed to test FP threshold.

---

## Labeling process — 3 layers

### Layer 0 — Establish context (do this before reviewing any substep)

Answer 2 questions before evaluating any substep:

**1. Test type:** Detections or Protections?
- **Detections** — evaluates detection capability across a behavior chain
- **Protections** — evaluates blocking of a specific behavior; nearly all rows are Calibrated

**2. Scenario measurement surface (determines Condition 4):**

| Type | In-scope telemetry channels | Reference |
|---|---|---|
| Scenario 1 (EDR) | Process tree, command line, file I/O, registry, network connection, DNS, script-block log | Mustang Panda 2025 |
| Scenario 2 (XDR) | All Scenario 1 + IdP/SSO audit log, cloud API call log, cross-host correlation | Scattered Spider 2025 |
| Protections | Depends on declared scope: add email gateway, web filter, identity provider if applicable | — |

> Layer 0 context determines Condition 4 in Layer 2. Do not skip this step.

---

### Layer 1 — Pre-filter before applying the 4 conditions

Two independent questions, in order. Stop immediately when you get "Yes":

**Question A — Is the artifact on this scenario's detection surface?**

> *"Does the artifact produced by this substep belong to the telemetry channels declared in Layer 0?"*

- **No** → **Not Calibrated** — artifact is outside the measurement surface (mail gateway, attacker infra, outside EDR scope). This is not a "setup" issue in the causal sense — it fails Condition 4 immediately. No further evaluation needed.

**Question B — Is this substep an implementation detail of another Calibrated row?**

> *"Is this substep the mechanism implementing an objective already measured by another Calibrated row (at the same level or downstream) — or does it independently represent a distinct adversary objective?"*

- **Yes** → **Not Calibrated** — implementation detail. Three cases:
  - **Same level:** the same artifact/event is already described more precisely by another row (double-count)
  - **Downstream:** substep establishes execution context for a Calibrated row downstream — if the vendor detects that downstream row, they have already observed the result of this substep
  - **Dead-end chain:** the substep's artifact is only consumed by Not Calibrated rows, with no path to any scored detection opportunity

**→ Both questions "No/No"** → substep is a **primary output** — proceed to Layer 2.

> **Distinguishing the two Not Calibrated reasons:** Question A = artifact is outside the detection surface (scope issue). Question B = artifact is on the surface but is the mechanism of an objective already measured elsewhere (redundancy issue). The reason "this step is a prerequisite for the next step" **alone** is not sufficient to Not Calibrate — the question must always be whether its objective is already better represented by another row.

---

### Layer 2 — 4-condition checklist for Calibrated

A substep is **Calibrated** if and only if it satisfies **all 4** conditions:

| # | Condition | Exclusions |
|---|---|---|
| 1 | **Observable** — there is at least one artifact in the telemetry channels declared in Layer 0 | Artifact exists only in process memory |
| 2 | **Reproducible** — artifact appears consistently across runs | Random GUIDs, timing-dependent, exists only in stack/heap |
| 3 | **Independently verifiable** — evaluator can confirm the artifact without relying on red team claims | Process identity is compromised (ghost/injected process), artifact only verifiable via malware source code |
| 4 | **Fair scoring point** — the product under test has the opportunity to observe the artifact if functioning correctly | Artifact is outside the measurement surface of the product type being tested |

> **On ghost/injected processes and Condition 3:** When a process is injected into, its identity is no longer trustworthy. Condition 3 only fails when the artifact **depends on process identity to be verified** — i.e., the evaluator must trust that the process is running malware in order to conclude the artifact is malicious. Conversely, if the artifact **exists independently outside process context** and is self-evidencing, Condition 3 still passes even if the executing process is a ghost.
>
> - **Fails Condition 3:** in-process behavior (API call, in-memory shellcode, output visible only in process context), child process output consumed internally by the implant
> - **Passes Condition 3:** artifact persists on the system after the process ends (registry key, scheduled task, file on disk with clear attribution), network connection to an external attacker-controlled endpoint (attribution does not depend on process identity)

> **On Condition 4 between the two scenarios:** The same technique can flip labels between Scenario 1 and Scenario 2 if the required telemetry channel (cloud audit log, IdP event) only exists in Scenario 2's measurement surface.

Any condition unsatisfied → **Not Calibrated**.

---

### Layer 3 — Structural signals suggesting a mislabel

After labeling, check for the following patterns — these commonly warrant re-review:

- **Calibrated ratio ~100% in a Detections scenario with heavy custom implant use** → suspicious; implant-heavy chains typically have many evasion mechanisms that fail Condition 1 or 3.
- **Two rows with the same technique and same physical event** → double-count; one is likely an implementation detail of the other.
- **Not Calibrated but artifact is clear, on the measurement surface, with no other row representing it** → re-check Layer 1; if it is genuinely not a setup/implementation detail → consider upgrading to Calibrated.
- **Calibrated but Detection Criteria cannot be written specifically** → artifact is not truly observable or reproducible; consider downgrading to Not Calibrated.

---

## Verifying Detection Criteria

After labeling, verify the `Detection Criteria` column for every **Calibrated** row:

**Required format:** `<process|principal> <action> <artifact|target> [on <host>]`

| | Example |
|---|---|
| ✅ Correct | `waitfor.exe connects to 191.44.44.199 over TCP port 443` |
| ✅ Correct | `EssosUpdate.exe side-loads unsigned wsdapi.dll from C:\Users\Public\` |
| ❌ Incorrect | `Malware connects to C2` |
| ❌ Incorrect | `Loader decrypts payload` |

**Detection Criteria checklist:**
- [ ] Has a specific process/principal (filename, not just "malware")
- [ ] Has a specific action (loads, executes, connects, writes, reads...)
- [ ] Has a specific artifact/target (full path, IP:port, filename, registry key)
- [ ] Can be used to query directly in SIEM/EDR without additional information
- [ ] If behavior occurs on multiple hosts → split into multiple rows, each with a specific host

> If Detection Criteria cannot be written specifically enough → this is a signal the substep is actually Not Calibrated (fails Condition 1 or 2). Revisit the label before attempting to force a criteria.

---

## Quick labeling template (6 questions in order)

Stop immediately on "No":

1. Is this substep the **primary output** of an adversary action? (No → Not Calibrated)
2. Is there an **artifact outside memory**, on the surface declared in Layer 0? (No → Not Calibrated)
3. Does the artifact **reproduce consistently** across runs? (No → Not Calibrated)
4. Can the evaluator **independently verify** the artifact? (No → Not Calibrated)
5. Is there another Calibrated row that **already represents this information better**? (Yes → Not Calibrated)
6. Can Detection Criteria be written in specific form? (No → rewrite or Not Calibrated)

→ All 6 pass: **Calibrated - Not Benign**.
