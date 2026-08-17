# assign-category - Reference

Detailed lookup tables used throughout Steps 2–7. Read this file before labeling.

---

## Surface Profile (Layer 0)

Echo one row before labeling. This table is the single source of truth consumed by both this skill (Question A) and `write-detection-criteria` (Surface test) - both must read the same pinned profile.

| Profile | In-scope telemetry channels |
|---|---|
| **Scenario 1 (EDR)** ← default | Process tree, command line, file I/O, registry, network connection, DNS, script-block log; memory scanning (RWX regions, unbacked threads, module list anomalies); process injection monitoring (ETW cross-process access events); native API monitoring (kernel-level callbacks for suspicious API sequences); YARA / capability signature matching (file and in-memory) |
| Scenario 1 (Basic EDR) | Process tree, command line, file I/O, registry, network connection, DNS, script-block log only - declare explicitly |
| Scenario 2 (XDR) | All Scenario 1 + IdP/SSO audit log, cloud API call log, cross-host correlation - declare at eval start |
| Custom | Explicitly enumerated channels listed in the Phase file's Layer 0 block |

---

## Layer 1 - Pre-filter (stop on first Yes)

**Question A - Is the artifact on the declared surface?**
No → **Not Calibrated** (`out-of-surface`). The artifact is off the measurement surface (mirrors `N/A - C3` from Detection Criteria) - disqualified before any scoring; no further evaluation needed.

**Question B - Is this an implementation detail of another Calibrated row?**
Yes → **Not Calibrated**. Three sub-cases:
- **Same level:** same artifact/event already described more precisely by another row (double-count). Two rows sharing the same physical event are a double-count *only if* they require the same detection capability. Different telemetry depth (raw netconn vs TLS/JA3) → both may stay Calibrated, but criteria must make the capability difference explicit.
- **Downstream:** the downstream Calibrated row *directly proves* this one fired. Do not apply merely because a step is upstream - if it offers an earlier independent detection opportunity, it is not an implementation detail.
- **Dead-end chain:** artifact only consumed by NC rows, no path to any scored opportunity.

> **Static file properties are not exempt from Q-B.** A row describing a static file property (cert signature, entropy, embedded section content) must still pass the redundancy test: if its only role is to enable a downstream technique already captured by a Calibrated row, it is an implementation detail. If it represents an independently observable forensic artifact the evaluator can verify by scanning the file - without relying on any runtime event - it passes Q-B.

> **"This step is a prerequisite" alone is not sufficient to Not Calibrate.** Q-A = artifact is outside the detection surface (scope issue). Q-B = artifact is on the surface but the objective is already measured elsewhere (redundancy issue). Being upstream of a Calibrated row does not make a step an implementation detail - only if the downstream row *directly proves* this one fired.

**Q-B examples:**

| Example | Q-B answer | Reason |
|---|---|---|
| `mavinject.exe` spawn → upstream of `waitfor.exe → C2` | No | Catching `mavinject.exe` does not prove implant delivery; both are independent detection opportunities |
| XOR decrypt in-memory → upstream of the same C2 connection | Yes | Detecting the C2 connection already proves the module executed; the in-memory step is its implementation detail |
| T1071.001 `gup.exe → host:443` vs T1573.002 same connection with JA3 criteria | No | Different detection capability required; keep both if Detection Criteria are distinct |
| T1105 write of a file with no independently observable anomaly → downstream Calibrated row captures the file's distinctive property | Yes | Downstream row directly proves staging occurred; the write event has no primary artifact anomaly to independently justify a scored point → `redundant@<downstream_tech>` |
| T1105 write of a file with an independently observable anomaly (PE class, YARA-matchable content) → downstream row scores a different detection angle | No | The file itself carries an override-triggering property; the write event and the downstream detection require different capabilities |

Both No → primary output, proceed to Layer 2.

---

## Layer 2 - Conditions

**Read Conditions 1–3 off the written Detection Criteria; do not re-derive them.** A concrete signal = 1–3 hold. A documented `N/A - <code>` = that condition fails → NC. C4 is judged fresh here.

> **Code mapping - the `N/A - Cx` codes are NOT the same numbering as Conditions 1–3.** The Detection Criteria codes are permuted relative to this table; map them explicitly:
> - `N/A - C3` (off surface) ↔ **Condition 1** (Observable) - also caught earlier by Q-A
> - `N/A - C1` (no signal / no stable pattern) ↔ **Condition 2** (Reproducible)
> - `N/A - C2` (in-process / not verifiable) ↔ **Condition 3** (Independently verifiable)
>
> Mirror the original `Cx` code into `Calibration Reason` (tags `C1`/`C2`, or `out-of-surface` for C3) - do not relabel it to the Condition number.

| # | Condition | Fails when |
|---|---|---|
| 1 | **Observable** - artifact exists in the declared telemetry channels | Memory-only AND Basic EDR declared (default EDR includes memory scanning) |
| 2 | **Reproducible** - artifact's type or pattern appears consistently across runs | Specific value is random AND no stable pattern exists (pure entropy blob, stack address - try rewriting against the pattern first) |
| 3 | **Independently verifiable** - evaluator can confirm without trusting red-team claims | Process identity is compromised (ghost/injected), artifact only verifiable via malware source |
| **C4** | **Distinctive, independent scoring point** - all three sub-gates must hold | See C4 detail below |

> **Condition 3 - ghost/injected process pass/fail:** Condition 3 fails only when the artifact *depends on process identity to be verified* - i.e., the evaluator must trust that the process is running malware to conclude the artifact is malicious.
> - Fails: in-process behavior (API call, in-memory shellcode, output visible only in process context); child process output consumed internally by the implant
> - Passes: artifact persists on the system after the process ends (registry key, scheduled task, file on disk with clear attribution); network connection to an external attacker-controlled endpoint (attribution does not depend on process identity); PE header mismatch or RWX region detectable by memory scan independently of process identity

**Injection technique quick reference:**

| Technique | Artifact | Cond. 1 (default EDR) | Cond. 3 |
|---|---|---|---|
| Process hollowing | Image base mismatch (memory scan / ETW) | Yes | Yes - PE comparison is evaluator-independent |
| Module stomping | DLL load event; PE on disk intact | Yes | Yes |
| APC injection | Thread creation; `QueueUserAPC` via ETW | Yes | Yes |
| Reflective DLL load | RWX private allocation; unbacked executable thread | Yes | Yes - RWX region is self-evidencing |
| Shellcode only (no file, no netconn) | RWX/unbacked thread if memory scanning in scope | Yes (default) / No (Basic) | No - behavior visible only in process context |

---

## C4 - Scoring gate (all three sub-gates must hold)

**4a - Generalizable behavioral signal, not a fixed indicator.** The row is scoreable only if a discriminative signal exists that *generalizes across instances* of the behavior - a property of the *action*, not one emulation-specific value (command string, hardcoded filename, specific IP/port, file hash). This judges the **signal**, not how a vendor detects it: catching a distinctive action via a YARA/signature is fine and still Calibrated. Fails 4a only when the **sole** writable signal is a fixed indicator the real adversary would rotate. Score the *distinctive action*, not the indicator.

**4b - New & independent detection opportunity.** A row earns a point only if it opens a detection chance another scored row does not already guarantee. Exfil over an *existing* C2 channel = NC (channel already scored); exfil over a *newly-opened* channel = Calibrated (separate detection opportunity). Ask: *"If every row this one depends on were already caught, would this still be its own detection opportunity?"*

**4c - Distinctive TTP vs. Generic Operational Behaviors.** Score actor-signature behaviors a competent product of the declared tier is genuinely expected to flag. Exclude Generic Operational Behaviors - missing them is not fairly attributable to a detection-capability gap:

| Generic Operational Behavior class | Default Verdict | Rationale |
|---|---|---|
| Delivery & user-interaction (email, click, open file) | Strong NC | The lure, not a behavior-detection opportunity |
| Tool transfer (T1105 download / copy-in) | Strong NC | Transport; score what the tool *does*, not its arrival |
| Generic interpreter spawn ("PowerShell executes commands") | Near-absolute NC | Score the distinctive action the interpreter performs, never the spawn |
| Native recon commands (netstat / ipconfig / nbtscan) | Strong NC | Ubiquitous in benign admin - not distinctive (4c); no generalizable malicious signal beyond the command string (4a) |
| Remote-exec plumbing (PsExec ADMIN$ / PSEXESVC / copy) | Strong NC | Mechanism of lateral-movement objective scored elsewhere |
| Indicator removal / pure staging | Strong NC | Internal housekeeping, no distinctive detection surface |

> **Overridable default verdicts, not technique-ID blocklists.** The same technique flips by its *role in the step* - `rar` staging is NC; `rar` + alternate-protocol exfil as the distinctive objective is Calibrated. Record *why* it is NC in this step.

> **Override trigger - when to probe instead of applying the default verdict mechanically.** Read the written criteria before applying any strong-default NC. If the criteria carries a condition **beyond the default verdict's class definition** (a structural property of the artifact, a content fingerprint, a behavioral pattern intrinsic to the action - not merely actor + action + target), the default verdict is no longer the right description and the override must be tested explicitly. Tool transfer (T1105) writing a generic file = default verdict holds; tool transfer writing a binary with PE-format YARA detection = lifted out of the default verdict, test C4 fresh. Apply this probe to every default verdict in the C4c table, not just T1105.

> **Identifying the primary artifact before testing the override.** The override must be triggered by the **primary artifact** of the action - not by metadata about who performed it. For T1105, the primary artifact is the transferred file, not the writer process. An anomalous actor (IIS worker, browser, Office app writing to a suspicious path) is context; it does not by itself lift the transport default verdict. Ask: *does the file have an independently observable anomaly?* If yes, test C4 fresh. If no, check Q-B: a downstream Calibrated row that captures the file's distinctive property (e.g., a file-scan row for the same artifact) directly proves staging occurred → write event is `redundant@<that row>`. The same logic applies to other Generic Operational Behavior default verdicts: always identify what the action *produces* as its primary artifact, then test whether *that artifact* carries the override-triggering property.

Any Condition 1–3 unsatisfied, or C4 not cleared → **Not Calibrated**.

---

## Quick labeling template (7 questions)

Stop on first No (or first Yes for Q5). Questions 1–6 = eligibility filter; **Q7 = C4 scoring gate - the real decision.**

1. Is this the **primary output** of an adversary action? (No → NC)
2. Is there an **observable artifact** on the declared surface? (No → NC; memory indicators count for default EDR, not Basic)
3. Does the artifact **reproduce consistently** across runs via a stable pattern? (No → NC)
4. Can the evaluator **independently verify** it without trusting red-team claims? (No → NC)
5. Is there another Calibrated row that **already represents this information better**? (Yes → NC)
6. Is the written Detection Criteria a **concrete signal** (not a documented `N/A` absence)? (No → NC)
7. **C4 gate** - all three must hold:
   - **4a** Does a generalizable behavioral signal exist (not just a fixed emulation-specific indicator)? (No → NC)
   - **4b** Still an independent detection opportunity if dependent rows were already caught? (No → NC)
   - **4c** Distinctive actor-signature TTP, not a Generic Operational Behavior? (No → NC)

→ All pass: **Calibrated - Not Benign** (`Calibration Reason` = `-`)

---

## Reason tags

Every NC row carries one tag in `Calibration Reason`. The tag is what lets the label be re-derived when the heuristic changes.

| Tag | When to use |
|---|---|
| `out-of-surface` | Artifact outside the declared Surface Profile (Q-A fail) |
| `redundant@<TechID>` | Implementation detail of another Calibrated row (Q-B fail) |
| `transport` | Tool transfer / generic delivery (C4c - Generic Operational Behavior) |
| `interpreter-spawn` | Generic interpreter spawn (C4c) |
| `remote-exec` | Remote-exec plumbing (PsExec ADMIN$ / PSEXESVC / copy) - mechanism of a lateral-movement objective scored elsewhere (C4c) |
| `native-recon` | Native recon command - ubiquitous benign admin, not distinctive (C4c); no signal beyond the command string (C4a) |
| `staging` | Pure staging / indicator removal - internal housekeeping (C4c) |
| `in-process` | In-process behavior, evaluator cannot verify without trusting red-team claims |
| `IOC-only` | Only writable signal is a fixed indicator - no behavioral pattern (C4a) |
| `C1` | No discriminative signal or no stable pattern - mirrors `N/A - C1` from Detection Criteria |
| `C2` | In-process / not independently verifiable - mirrors `N/A - C2` from Detection Criteria |

> `Category` stays a clean enum (filterable by tooling) - never put free text there. For a C1/C2 failure the detail already lives in `Detection Criteria` as `N/A - <code>: <reason>`; just mirror the short tag here. For NC on scope/redundancy/Generic-Operational-Behavior where `Detection Criteria` holds a *positive* signal, the positive signal stays as evidence; the short tag goes in `Calibration Reason`.

---

## Layer 3 - Structural signals (check after labeling)

These patterns commonly warrant re-review:

- **Calibrated ratio ~100% in a Detections scenario with heavy custom implant use** → suspicious; implant-heavy chains typically have many evasion steps that fail Condition 1 or 3.
- **Two rows with the same technique and same physical event** → double-count; one is likely an implementation detail.
- **NC but artifact is clear, on-surface, with no other row representing it** → re-check Layer 1; if genuinely not setup/implementation detail → consider upgrading.
- **Calibrated but Detection Criteria is a documented `N/A` absence** → contradiction; Not-Calibrate it.
- **Entire step has 0 Calibrated rows** → write one explicit justification sentence before proceeding.
- **Two rows cite the same process and destination without distinct criteria** → apply Q-B same-level capability check; keep both only if criteria explicitly require different telemetry depth.
- **Criteria cites a value-specific artifact without a behavioral pattern** (exact byte value, hardcoded filename, specific IP, file hash) → probe for a generalizable pattern; if only an IOC-specific signal can be written, flag for `write-detection-criteria` review.
- **Concrete positive Detection Criteria + NC label without a documented reason tag** → inconsistency; send back to `write-detection-criteria` to document `N/A` before finalizing.
- **Two rows with the same Technique ID but different process subject** → verify DC cite different actors/processes and different physical events; same physical event observed from two angles → Q-B same-level double-count; different instances of the same capability in different processes, both may remain Calibrated.
