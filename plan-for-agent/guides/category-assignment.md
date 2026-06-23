# Guide: Assigning Category Labels

> **Consumed by:** `/assign-category` — see [pipeline.md](../pipeline.md)

How to determine the `Calibrated`/`Not Calibrated` label for each Reference Table row. **Detection Criteria is written first** (`detection-criteria.md` / `write-detection-criteria`, run before this step); this guide **reads** that column as evidence and decides the label from it — it does not author or verify criteria. This is the operational process; `attack-behavior-methodology.md` is the extended commentary with examples from past MITRE scenarios.

> **Criteria is the evidence, not something you imagine here.** Every row already carries a Detection Criteria: either a concrete signal, or a documented `N/A — <Cx>: <reason>` absence. A concrete signal means Conditions 1–3 hold in practice; a documented absence names the failing condition. Read it — do not re-derive observability/reproducibility/verifiability by guessing whether a criteria *could* be written.

---

## Valid labels (Not Benign scope)

| Label | Meaning |
|---|---|
| `Calibrated - Not Benign` | Scored behavior — counts toward the detection rate denominator |
| `Not Calibrated - Not Benign` | Setup substep, implementation detail, or fails a condition — does not count toward denominator |

> **Scope:** this guide labels Not Benign behaviors only. `Calibrated - Benign` (false-positive threshold test rows for LOLBin or admin-tool usage indistinguishable from legitimate activity) is out of scope and handled by a separate process.

---

## Labeling process — 3 layers

### Layer 0 — Establish context (do this before reviewing any substep)

Answer 2 questions before evaluating any substep:

**1. Test type:** Detections or Protections?
- **Detections** — evaluates detection capability across a behavior chain
- **Protections** — evaluates blocking of a specific behavior; nearly all rows are Calibrated

**2. Scenario measurement surface — the "Surface Profile" (determines Condition 4):**

> This table is the **single source of truth** for the measurement surface, consumed by **both** `write-detection-criteria` (its Surface test) and this guide (Question A). The two steps must read the *same* profile — if they assume different surfaces, an artifact written as on-surface upstream can be rejected as off-surface downstream with no reconciliation. Pin one profile per plan and reference it from both.

| Type | In-scope telemetry channels | Reference |
|---|---|---|
| **Scenario 1 (EDR)** | Process tree, command line, file I/O, registry, network connection, DNS, script-block log; memory scanning (RWX regions, unbacked threads, module list anomalies); process injection monitoring (ETW cross-process access events); native API monitoring (kernel-level callbacks for suspicious API sequences); YARA / capability signature matching (file and in-memory) | **Default** — applies unless Basic is explicitly declared |
| Scenario 1 (Basic EDR) | Process tree, command line, file I/O, registry, network connection, DNS, script-block log only | Declare explicitly when targeting a product or configuration without advanced in-memory / injection-monitoring capabilities |
| Scenario 2 (XDR) | All Scenario 1 + IdP/SSO audit log, cloud API call log, cross-host correlation | Declare at eval start |
| Protections | Depends on declared scope: add email gateway, web filter, identity provider if applicable | — |
| Custom | Explicitly enumerated by the phase author — list channels in the Phase file's Layer 0 block | — |

> **Scenario 1 default rationale:** The default targets products with up-to-date detection mechanisms. Declare **Scenario 1 (Basic EDR)** explicitly when the evaluation deliberately targets a product or configuration without advanced in-memory or injection-monitoring capabilities.

> **Echo the active profile — do not run on a silent default.** State which row of this table is in force before labeling, even when it is the Scenario 1 (EDR) default. The choice **sets the detection-rate denominator**: under Basic EDR the in-memory channels disappear, so memory-only behaviors fail C1 and drop out of the scored set; under full EDR they survive to C4. A default left unstated quietly fixes which rows can ever be scored — make it a deliberate, recorded decision matched to the product under evaluation.

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
  - **Dead-end chain:** the substep's artifact is only consumed by Not Calibrated rows, with no path to any scored detection opportunity. When Not Calibrating via dead-end, verify the Detection Criteria column already carries a documented `N/A — Q-B dead-end: <reason>` entry; if it carries a positive signal instead, flag the row back to `write-detection-criteria` to add the N/A documentation before finalizing the label.

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

> **Primary evaluation question:** *"If this vendor misses this signal, is the miss attributable to the vendor?"* This is the through-line for every labeling decision. Condition 4 (fair scoring point) is the evaluation design gate; Conditions 1–3 are its technical enablers — they verify the artifact is stable and independently confirmable, which is what makes a miss attributable. A row can pass C1–C3 and still fail C4; it cannot pass C4 if C1–C3 fail.

> **C1–C3 are an elimination filter, not the dividing line. C4 is the scoring gate.** Empirically, the majority of Not Calibrated rows pass C1–C3 perfectly — `netstat`, `ipconfig`, tool download, `PsExec`, `msiexec→GUP` are all observable, reproducible, and independently verifiable on the process tree, yet MITRE excludes them. **Observability earns eligibility, not a point.** Passing C1–C3 only means the row is *eligible to be scored*; whether it *is* scored is decided entirely at C4. Do not treat "a concrete signal exists" as "Calibrated" — that is the single most common mislabel.

**Read Conditions 1–3 off the written Detection Criteria; do not imagine them.** A concrete signal in the criteria column = Conditions 1–3 hold. A documented `N/A — <Cx>: <reason>` absence = that condition fails. Layer 2's C1–C3 is mostly a *read* of upstream evidence; **C4 is judged fresh here** and carries the real labeling weight.

A substep is **Calibrated** only if it passes the C1–C3 filter **and** clears the C4 scoring gate:

| # | Condition | Exclusions |
|---|---|---|
| 1 | **Observable** — there is at least one artifact in the telemetry channels declared in Layer 0 | Artifact exists only in process memory AND Scenario 1 (Basic EDR) is declared — Scenario 1 default includes memory scanning |
| 2 | **Reproducible** — the artifact's **type or pattern** appears consistently across runs | The specific value is random AND no stable pattern exists to form a detection criterion (e.g., pure entropy blob, heap address) |
| 3 | **Independently verifiable** — evaluator can confirm the artifact without relying on red team claims | Process identity is compromised (ghost/injected process), artifact only verifiable via malware source code |
| 4 | **Distinctive, independent scoring point** — crediting this row measures *behavior detection*, not string/IOC matching, **and** it is a new independent detection opportunity not already guaranteed by another scored row. Three sub-tests, all must hold (see below): **(4a) forces behavioral understanding** — catching it requires the product to understand the behavior, not match a command string or known IOC; **(4b) new & independent opportunity** — if the other rows it depends on were already caught, this still offers a separate chance to cut the chain; **(4c) distinctive TTP** — it is a behavior a competent product of the declared tier is genuinely expected to flag (the actor-signature "aha" moment), not generic connective tissue | Scoring it rewards IOC/command-string matching (4a); detecting it is already guaranteed by another scored row (4b); generic connective tissue / transport / interpreter spawn whose miss is not fairly attributable (4c); artifact outside the measurement surface |

> **On Condition 2 and pattern-based reproducibility:** A random value (e.g., GUID, nonce) does not automatically fail Condition 2. The question is whether a **stable detection pattern** exists. A GUID value itself is not reproducible; the pattern "non-COM process generates a GUID and writes it to a non-standard path" is. Write Detection Criteria against the pattern, not the value. Condition 2 fails only when no stable pattern can be identified (e.g., the artifact is a raw entropy blob or a stack address with no consistent behavioral context).
>
> **The artifact must still surface independently (ties to C3).** `CoCreateGuid` is the canonical split case: an in-process `CoCreateGuid` call whose value never leaves the process is in-process behavior → Not Calibrated; the *same* call passes only once the GUID lands in an independently-verifiable artifact (written to disk or registry on a non-standard path). The stable pattern earns eligibility; the independent artifact is what clears C3. Same technique, label flips on whether it leaves the process.

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

#### Unpacking C4 — the scoring gate

**4a — Behavior detection, not IOC matching.** A scored detection must force the vendor to *understand the behavior*. `netstat -anop tcp` leaves a perfect process-tree artifact, but crediting it only rewards a product that matches the command string — it proves nothing about behavioral capability. If the only writable signal is a fixed command line, a hardcoded filename, a specific IP/port, or a file hash, the row fails 4a. (This is the Layer-3 "IOC-specific signal" check promoted to a front-line gate.) Score the *distinctive action*, not the indicator.

**4b — New & independent detection opportunity.** A row earns a point only if it opens a detection chance that another scored row does not already guarantee. The sharpest contrast: **exfil over an already-established C2 channel (T1041) = Not Calibrated** — the C2 channel is already a scored cut-point, the exfil adds no independent opportunity; but **exfil over a newly-opened channel (T1048.003 FTP) = Calibrated** — it is a separate, independently-detectable cut-point. Ask: *"If every row this one depends on were already caught, would this still be its own detection opportunity?"* No → fold it into the row that already represents it.

**4c — Distinctive TTP vs. connective tissue.** MITRE's Calibrated set converges on actor-signature behaviors a competent product is genuinely expected to flag: DLL sideload, crypto-loader (decrypt + reflective load + dynamic API resolution), persistence artifact (run key / scheduled task), credential-dumping core, unusual C2 channel (VS Code tunnel, GitHub SSH, PlugX HTTPS), archive + alternate-protocol exfil. The inverse — generic *connective tissue* — is systematically excluded even when well-observed, because missing it is not fairly attributable to a detection-capability gap:

| Connective-tissue class | Prior | Rationale |
|---|---|---|
| Delivery & user-interaction (email, click, open file) | Strong NC | The lure, not a vendor behavior-detection opportunity |
| Tool transfer (T1105 download / copy-in) | Strong NC | Transport; score what the tool *does*, not its arrival |
| Generic interpreter spawn ("PowerShell executes commands") | Near-absolute NC | Score the distinctive action the interpreter performs, never the spawn |
| Native recon commands (netstat / ipconfig / nbtscan) | Strong NC | Crediting them rewards command-string matching (fails 4a) |
| Remote-exec plumbing (PsExec ADMIN$ / PSEXESVC / copy) | Strong NC | Mechanism of the lateral-movement objective scored elsewhere |
| Indicator removal / pure staging | Strong NC | Internal housekeeping, no distinctive detection surface — tag `staging` |

> **These are rebuttable priors, not technique-ID blocklists.** The same technique flips by its **role in the step** — `rar` collection is Not Calibrated as generic staging but Calibrated when the archive + its alternate-protocol exfil is the distinctive objective; a click is Not Calibrated as delivery but Calibrated when it is the scored user-execution moment. Use the prior as the default, then let the per-step role rebut it. Do **not** hardcode "T1105 is always NC" — record *why* it is NC in this step (see Layer 3 / the reason-tag requirement).

Any C1–C3 condition unsatisfied, or the C4 gate not cleared → **Not Calibrated**.

---

### Layer 3 — Structural signals suggesting a mislabel

After labeling, check for the following patterns — these commonly warrant re-review:

- **Calibrated ratio ~100% in a Detections scenario with heavy custom implant use** → suspicious; implant-heavy chains typically have many evasion mechanisms that fail Condition 1 or 3.
- **Two rows with the same technique and same physical event** → double-count; one is likely an implementation detail of the other.
- **Not Calibrated but artifact is clear, on the measurement surface, with no other row representing it** → re-check Layer 1; if it is genuinely not a setup/implementation detail → consider upgrading to Calibrated.
- **Calibrated but its Detection Criteria is a documented `N/A — <reason>` absence** → contradiction; the absence names a failing condition — Not Calibrate it.
- **Entire step has 0 Calibrated rows** → write one explicit justification sentence before proceeding (e.g., "all artifacts are in-memory inside a ghost process" or "all artifacts are on attacker infrastructure"). If a clear justification cannot be written, re-evaluate the entire step.
- **T1071 and T1573 (or similar multi-technique rows) cite the same process and destination without distinct criteria** → apply the same-level capability check from Question B; keep both rows only if Detection Criteria explicitly require different telemetry depth (e.g., raw netconn vs. TLS/JA3 fingerprint).
- **Detection Criteria cites a value-specific artifact without a behavioral pattern** (exact byte value, hardcoded filename, specific IP/port, file hash) → probe whether a technique-generalizable pattern formulation exists; if only an IOC-specific signal can be written, flag for `write-detection-criteria` review — a vendor detecting the IOC variant but not the underlying behavior passes an IOC check, not a behavior-centric detection.
- **Concrete positive Detection Criteria + Not Calibrated label without a documented Q-A/Q-B/N/A reason** → inconsistency; a positive signal either yields Calibrated or must carry an explicit Not Calibrated justification in the criteria column; send the row back to `write-detection-criteria` to document `N/A — <reason>` before finalizing.
- **Two rows with the same Technique ID but different process subject** → verify the Detection Criteria cite different actors/processes and different physical events; if the same physical event observed from two angles, apply Q-B same-level double-count; if different instances of the same capability in different processes, both may remain Calibrated.

---

## Reading Detection Criteria as evidence

The `Detection Criteria` column is written **before** labeling, by its own guide **`detection-criteria.md`** (`write-detection-criteria` skill). This guide does not author or verify criteria — it reads the column:

- **Concrete signal present** → Conditions 1–3 are satisfied in practice. Proceed on scope (Q-A), redundancy (Q-B), and Condition 4.
- **Documented `N/A — <Cx>: <reason>` absence** → that condition fails → **Not Calibrated**, no further imagination needed.

Never edit the criteria from here. If a row's written signal makes you doubt the label, change the **label**; if you doubt the **signal**, send the row back to `write-detection-criteria`.

---

## Quick labeling template (7 questions in order)

Stop immediately on "No" (or "Yes" where noted). Questions 1–6 establish *eligibility* (the C1–C3 filter + redundancy); **Question 7 is the C4 scoring gate and carries the real decision** — most well-observed rows die here, not above.

1. Is this substep the **primary output** of an adversary action? (No → Not Calibrated)
2. Is there an **observable artifact** on the surface declared in Layer 0? (Memory indicators such as RWX regions and unbacked threads count for Scenario 1 default; do not count for Scenario 1 Basic.) (No → Not Calibrated)
3. Does the artifact **reproduce consistently** across runs? (No → Not Calibrated)
4. Can the evaluator **independently verify** the artifact? (No → Not Calibrated)
5. Is there another Calibrated row that **already represents this information better**? (Yes → Not Calibrated)
6. Is the **written** Detection Criteria a concrete signal (not a documented `N/A — <reason>` absence)? (No → Not Calibrated)
7. **C4 scoring gate** — does crediting this row measure *behavior detection*, and is it a *distinctive, independent* opportunity? All three must hold:
   - **4a** Catching it forces behavioral understanding, not command-string / IOC matching? (No → Not Calibrated — connective tissue)
   - **4b** Still an independent detection opportunity if the rows it depends on were already caught? (No → Not Calibrated — folded into that row)
   - **4c** A distinctive actor-signature TTP a competent product is expected to flag, not generic delivery / transport / interpreter spawn / native recon? (No → Not Calibrated)

→ All 7 pass: **Calibrated - Not Benign** (`Calibration Reason` = `-`). Any Not Calibrated outcome → keep `Category` a clean enum and write the one-line reason tag in the **`Calibration Reason`** column (`out-of-surface` / `redundant@<TechID>` / `transport` / `interpreter-spawn` / `native-recon` / `staging` / `in-process` / `IOC-only` / `C1`\|`C2`\|`C3`), so the label can be re-derived when the heuristic changes.

> **Where the reason lives.** `Category` stays a clean enum so it remains filterable/groupable by tooling — never put free text there. The reason goes in its own **`Calibration Reason`** column (owned by this skill), and never in `Detection Criteria` (that column is off-limits here). Two reason sources, do not contradict:
> - **C1–C3 failure** → `Detection Criteria` already holds the detailed `N/A — <Cx>: <reason>` (authored upstream); set `Calibration Reason` to the matching short tag `C1`/`C2`/`C3`.
> - **NC on scope / redundancy / connective-tissue**, where `Detection Criteria` legitimately holds a *positive* signal (e.g. to expose a double-count) → the positive signal stays as evidence; the short "why not scored" tag goes in `Calibration Reason`.
