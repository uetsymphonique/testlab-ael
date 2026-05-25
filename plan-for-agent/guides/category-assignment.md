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

**When to include `Calibrated - Benign` rows:**
- Include at least 1 row per scenario for any LOLBin or admin tool used in a way indistinguishable from legitimate usage.
- Write Detection Criteria in the same format as a `Not Benign` row — the test is whether the vendor discriminates correctly.
- Document the expected FP risk in the Red Team Activity column: describe what legitimate usage of the same tool looks like.
- These rows do **not** count toward the detection rate denominator; they contribute to a separate FP ratio.

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
| **Scenario 1 (EDR)** | Process tree, command line, file I/O, registry, network connection, DNS, script-block log; memory scanning (RWX regions, unbacked threads, module list anomalies); process injection monitoring (ETW cross-process access events); native API monitoring (kernel-level callbacks for suspicious API sequences); YARA / capability signature matching (file and in-memory) | **Default** — applies unless Basic is explicitly declared |
| Scenario 1 (Basic EDR) | Process tree, command line, file I/O, registry, network connection, DNS, script-block log only | Declare explicitly when targeting a product or configuration without advanced in-memory / injection-monitoring capabilities |
| Scenario 2 (XDR) | All Scenario 1 + IdP/SSO audit log, cloud API call log, cross-host correlation | Declare at eval start |
| Protections | Depends on declared scope: add email gateway, web filter, identity provider if applicable | — |
| Custom | Explicitly enumerated by the phase author — list channels in the Phase file's Layer 0 block | — |

> **Scenario 1 default rationale:** The default targets products with up-to-date detection mechanisms. Declare **Scenario 1 (Basic EDR)** explicitly when the evaluation deliberately targets a product or configuration without advanced in-memory or injection-monitoring capabilities.

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
  - **Same level:** the same artifact/event is already described more precisely by another row (double-count). Note: two rows sharing the same physical event are a double-count **only if** they require the same detection capability to observe. If they require fundamentally different telemetry depth (e.g., raw netconn vs. TLS/JA3 fingerprint analysis), both may remain Calibrated — but the Detection Criteria **must** make the capability difference explicit.
  - **Downstream:** the downstream Calibrated row **directly proves** this substep occurred — i.e., detecting the downstream artifact necessarily implies this artifact was already observed. Do **not** apply this case merely because a step is upstream; if the upstream artifact provides an earlier, independent detection opportunity that could interrupt the chain, it is not an implementation detail.
  - **Dead-end chain:** the substep's artifact is only consumed by Not Calibrated rows, with no path to any scored detection opportunity

> **Static file properties and Q-B:** A row describing a static file property (cert signature, file entropy, embedded section content) is not exempt from Q-B merely because the artifact is on disk. Apply the redundancy test normally: if the property's only role is to enable a downstream technique already captured by a Calibrated row, it is an implementation detail. If it represents an independently observable forensic artifact that the evaluator can verify by scanning the file — without relying on any runtime event — it passes Q-B.

| Example | Q-B answer | Reason |
|---|---|---|
| `mavinject.exe` spawn → upstream of `waitfor.exe → C2` | **No** | Catching `mavinject.exe` does not prove implant delivery; both are independent detection opportunities |
| XOR decrypt in-memory → upstream of the same C2 connection | **Yes** | Detecting the C2 connection already proves the module executed; the in-memory step is its implementation detail |
| T1071.001 `gup.exe → host:443` vs T1573.002 same connection with JA3 criteria | **No** | Different detection capability required; keep both if Detection Criteria are distinct |

**→ Both questions "No/No"** → substep is a **primary output** — proceed to Layer 2.

> **Distinguishing the two Not Calibrated reasons:** Question A = artifact is outside the detection surface (scope issue). Question B = artifact is on the surface but is the mechanism of an objective already measured elsewhere (redundancy issue). The reason "this step is a prerequisite for the next step" **alone** is not sufficient to Not Calibrate — the question must always be whether its objective is already better represented by another row.

---

### Layer 2 — 4-condition checklist for Calibrated

A substep is **Calibrated** if and only if it satisfies **all 4** conditions:

| # | Condition | Exclusions |
|---|---|---|
| 1 | **Observable** — there is at least one artifact in the telemetry channels declared in Layer 0 | Artifact exists only in process memory AND Scenario 1 (Basic EDR) is declared — Scenario 1 default includes memory scanning |
| 2 | **Reproducible** — the artifact's **type or pattern** appears consistently across runs | The specific value is random AND no stable pattern exists to form a detection criterion (e.g., pure entropy blob, heap address) |
| 3 | **Independently verifiable** — evaluator can confirm the artifact without relying on red team claims | Process identity is compromised (ghost/injected process), artifact only verifiable via malware source code |
| 4 | **Fair scoring point** — the product under test has the opportunity to observe the artifact if functioning correctly | Artifact is outside the measurement surface of the product type being tested |

> **On Condition 2 and pattern-based reproducibility:** A random value (e.g., GUID, nonce) does not automatically fail Condition 2. The question is whether a **stable detection pattern** exists. A GUID value itself is not reproducible; the pattern "non-COM process generates a GUID and writes it to a non-standard path" is. Write Detection Criteria against the pattern, not the value. Condition 2 fails only when no stable pattern can be identified (e.g., the artifact is a raw entropy blob or a stack address with no consistent behavioral context).

> **On ghost/injected processes and Condition 3:** When a process is injected into, its identity is no longer trustworthy. Condition 3 only fails when the artifact **depends on process identity to be verified** — i.e., the evaluator must trust that the process is running malware in order to conclude the artifact is malicious. Conversely, if the artifact **exists independently outside process context** and is self-evidencing, Condition 3 still passes even if the executing process is a ghost.
>
> - **Fails Condition 3:** in-process behavior (API call, in-memory shellcode, output visible only in process context), child process output consumed internally by the implant
> - **Passes Condition 3:** artifact persists on the system after the process ends (registry key, scheduled task, file on disk with clear attribution), network connection to an external attacker-controlled endpoint (attribution does not depend on process identity)

**Injection technique reference (Conditions 1 and 3):**

| Injection technique | Artifact that survives | C1 passes? | C3 passes? |
|---|---|---|---|
| Process hollowing | Image base mismatch (detectable via memory scan / ETW) | Yes (Scenario 1 default); No (Basic EDR) | Yes — PE header comparison is evaluator-independent |
| Module stomping | DLL load event still fires; PE on disk intact | Yes (module load / file I/O channel) | Yes |
| APC injection | Thread creation event; `QueueUserAPC` visible via ETW | Yes (Scenario 1 default); No (Basic EDR) | Yes |
| Reflective DLL load | RWX private allocation; unbacked executable thread | Yes (Scenario 1 default); No (Basic EDR) | Yes — RWX region is self-evidencing |
| Shellcode only (no file, no netconn) | RWX/unbacked thread if memory scanning in scope | Yes (Scenario 1 default); No (Basic EDR) | No — behavior visible only in process context |

> **On Condition 4 between the two scenarios:** The same technique can flip labels between Scenario 1 and Scenario 2 if the required telemetry channel (cloud audit log, IdP event) only exists in Scenario 2's measurement surface.

Any condition unsatisfied → **Not Calibrated**.

---

### Layer 3 — Structural signals suggesting a mislabel

After labeling, check for the following patterns — these commonly warrant re-review:

- **Calibrated ratio ~100% in a Detections scenario with heavy custom implant use** → suspicious; implant-heavy chains typically have many evasion mechanisms that fail Condition 1 or 3.
- **Two rows with the same technique and same physical event** → double-count; one is likely an implementation detail of the other.
- **Not Calibrated but artifact is clear, on the measurement surface, with no other row representing it** → re-check Layer 1; if it is genuinely not a setup/implementation detail → consider upgrading to Calibrated.
- **Calibrated but Detection Criteria cannot be written specifically** → artifact is not truly observable or reproducible; consider downgrading to Not Calibrated.
- **Entire step has 0 Calibrated rows** → write one explicit justification sentence before proceeding (e.g., "all artifacts are in-memory inside a ghost process" or "all artifacts are on attacker infrastructure"). If a clear justification cannot be written, re-evaluate the entire step.
- **T1071 and T1573 (or similar multi-technique rows) cite the same process and destination without distinct criteria** → apply the same-level capability check from Question B; keep both rows only if Detection Criteria explicitly require different telemetry depth (e.g., raw netconn vs. TLS/JA3 fingerprint).

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

**Behavioral pattern format (alternative when no single artifact is sufficient):**

When a detection depends on a combination of observable conditions rather than one specific artifact, behavioral criteria are acceptable and preferred:

`[process | process class] <condition> [and <condition>…]`

| | Example |
|---|---|
| ✅ Correct | `any process loads unsigned DLL from user-writable path and creates outbound network connection` |
| ✅ Correct | `EssosUpdate.exe spawns child process not matching known-good child list` |
| ❌ Incorrect | `suspicious process does something malicious` |

> Behavioral criteria must still satisfy the checklist below: each condition must be independently verifiable in telemetry without relying on red team claims.

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
2. Is there an **observable artifact** on the surface declared in Layer 0? (Memory indicators such as RWX regions and unbacked threads count for Scenario 1 default; do not count for Scenario 1 Basic.) (No → Not Calibrated)
3. Does the artifact **reproduce consistently** across runs? (No → Not Calibrated)
4. Can the evaluator **independently verify** the artifact? (No → Not Calibrated)
5. Is there another Calibrated row that **already represents this information better**? (Yes → Not Calibrated)
6. Can Detection Criteria be written in specific form? (No → rewrite or Not Calibrated)

→ All 6 pass: **Calibrated - Not Benign**.
