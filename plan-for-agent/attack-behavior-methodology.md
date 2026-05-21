# Attack Behavior Methodology

Derived from [`Enterprise/mustang_panda/Emulation_Plan/`](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md) and [`Enterprise/scattered_spider/Emulation_Plan/`](../Enterprise/scattered_spider/Emulation_Plan/Scattered_Spider_Scenario.md).

This file is the **extended commentary** for the operational process in [`guides/category-assignment.md`](./guides/category-assignment.md): it uses published MITRE scenarios to explain why those rules are sound and how they manifest in practice. When you need to assign a label to a specific row, use `guides/category-assignment.md` as the operational standard; use this file for background, examples, and reasoning.

---

## Category Classification System

Each technique in the Reference Table receives one of the following categories:

| Category | Meaning |
|---|---|
| `Calibrated - Not Benign` | Substep is a **scored behavior** and satisfies all 4 conditions (observable, reproducible, independently verifiable, fair scoring point). Behavior is malicious; counts toward the detection rate denominator. |
| `Not Calibrated - Not Benign` | Substep **is not scored** because the artifact is outside the detection surface, is an **implementation detail / redundancy** of a behavior already measured more precisely, or fails at least one of the 4 conditions. Behavior is malicious; still recorded fully in the Reference Table but does not count toward the denominator. |
| `Calibrated - Benign` | Substep is **legitimate, normal behavior** that looks like an attack from a telemetry perspective. Used to test false-positive thresholds. |

---

## Principle 1 — Labels are per-scenario, per-substep decisions

`Calibrated` / `Not Calibrated` is **not a fixed attribute of a technique**. The same technique can receive different labels across scenarios depending on the test type and the substep's role in the chain.

**Real example:** `T1566.001 Spearphishing Attachment`
- [Mustang Panda **main scenario**](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md) → **Not Calibrated**: email delivery is outside the EDR endpoint surface being measured; this substep is only a prerequisite for the victim downloading the payload.
- [Mustang Panda **Protections Test 4**](../Enterprise/mustang_panda/Emulation_Plan/Protections_Test_4_Scenario.md) → **Calibrated**: test surface extends to the email gateway; blocking delivery is the actual measurement point.

Implication: establish context first before labeling — do not assign based on intuition or "what this technique usually is."

---

## Labeling process — 3 layers

### Layer 0 — Establish context (do this before reviewing any substep)

Record **4 parameters** for the scenario being built:

1. **Test type**: Detections or Protections.
2. **Scenario type** (Detections only):
   - **Scenario 1 — EDR-centric**: target is EDR / endpoint protection / host-focused SIEM. Measurement surface limited to endpoint sensors.
   - **Scenario 2 — XDR / Enterprise**: target is XDR platform, identity protection, MDR/MSSP. Measurement surface extends to identity, cloud, cross-host.
3. **Measurement surface**: explicitly list the telemetry channels assumed to be covered.

   | Type | In-scope telemetry channels |
   |---|---|
   | Scenario 1 (EDR) | Process tree, command line, file I/O, registry, network connection, DNS query, script-block log — **endpoint sensors only** |
   | Scenario 2 (XDR) | All Scenario 1 **plus**: IdP/SSO audit log, cloud API call log (AWS CloudTrail, Azure AD, GCP), cross-host correlation, identity anomaly signal |
   | Protections | Depends on scope: add email gateway, web filter, identity provider if declared in setup |

4. **Substep's role in the chain**: see Layer 1.

### Layer 1 — Pre-filter before applying the 4 conditions

Per `guides/category-assignment.md`, before calling a substep a `Calibrated` candidate, separate two distinct `Not Calibrated` reasons:

1. **Scope issue** — is the artifact on the detection surface declared in Layer 0?
   - If **no**, substep → `Not Calibrated`.
2. **Redundancy issue** — is the substep an implementation detail of a behavior already measured better in another row?
   - If **yes**, substep → `Not Calibrated`. May be the same event double-counted, an upstream mechanism serving a downstream objective that already has a row, or a dead-end chain with no remaining path to a scoring opportunity.

If both answers are **no**, the substep is the **primary output** of an adversary action and proceeds to Layer 2. A `primary output` only becomes a **scored behavior** if it also satisfies all 4 conditions in Layer 2.

> Key distinction: a step being a prerequisite for the next step **alone is not sufficient** to Not Calibrate it. If the step itself produces an independent artifact, on the detection surface, not better represented by another row, it may still be a valid measurement point.

**Groups that are commonly implementation details:**
- Native API calls inside a loader chain (T1106 `NtCreateSection`, `ws2_32.send`, `MSXML2.XMLHTTP`) when another substep already describes the chain's output (process-create, file-write, network connection).
- Encrypted content inside a payload that is already Calibrated (T1027.013 PEM structure of a file already Calibrated at HTML Smuggling).
- Auxiliary API calls for token/handle manipulation when the process-create outcome is already measured (T1134.002 `CreateProcessAsUser` when T1134.001 is already Calibrated).
- Tool scanning behavior inside an authenticated session (T1213, T1552 tool executing against an internal service) when the authentication event (T1078) is already Calibrated: the tool's internal requests may be indistinguishable from legitimate browsing without knowing the tool signature; under this framework, the authentication log entry is typically the stronger scoring point. Example from [Scattered Spider Step 8](../Enterprise/scattered_spider/Emulation_Plan/Scattered_Spider_Scenario.md): `T1078` Wekan authentication is Calibrated, while `T1552` Jecretz execution against Wekan is Not Calibrated. This interpretation is drawn from pattern-reading of the scenario, not from a public MITRE statement of reasoning.

**Groups that commonly fall into scope issue or redundancy issue:**
- Attacker uploading a file to a server → usually attacker-side staging or an upstream step already better represented by the victim-side download.
- Email arriving at a mailbox in an endpoint-only Detections scenario → outside the EDR detection surface.
- User clicking to open a file/link when the real target is the process spawn from that action → usually better represented by the downstream process execution row. *Exception*: if the click produces a browser request to a specific phishing domain and that is a network event on the detection surface, the click may be its own primary output (see T1204.001 in [Mustang Panda Step 7](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md)).
- **Post-objective cleanup/teardown steps**: deleting files, deleting registry keys, self-deleting batch scripts after the adversary has already achieved the objective (e.g., [Mustang Panda Step 9](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md) `del_WinGupSvc.bat`) → typically no longer a scoring objective; distinct from in-chain stealth cleanup that is still serving the attack flow and may produce its own primary output.

### Layer 2 — 4-condition checklist for Calibrated

A substep is Calibrated if and only if it satisfies **all 4** conditions:

| # | Condition | Exclusions |
|---|---|---|
| 1 | **Observable** — at least one artifact exists in the telemetry channels declared in Layer 0 (process, file, registry, network, DNS, auth, cloud event) | Artifact exists only in malware process memory or does not generate stable external telemetry |
| 2 | **Reproducible** — artifact appears consistently across runs: path, filename, command line, IP/port, sender/recipient | Timing-dependent, randomly generated GUIDs not following a template, data only in stack/heap |
| 3 | **Independently verifiable** — evaluator can confirm the artifact without relying on red team claims (OS log, file on disk, packet capture, event log) | Only verifiable by reading malware source code |
| 4 | **Fair scoring point** — the product category under test has the opportunity to observe the artifact if functioning correctly | Artifact belongs to a surface the product does not cover in the test scope |

> **Condition 4 is the primary label flip point between Scenario 1 and Scenario 2.** The same technique may pass in Scenario 2 but fail in Scenario 1 if the artifact is outside the endpoint:
> - `T1078.004` Valid Accounts: Cloud Accounts — no endpoint artifact → **Not Calibrated** in Scenario 1; cloud audit log (AWS CloudTrail) is an independently verifiable artifact → **Calibrated** in Scenario 2.
> - `T1550.004` Web Session Cookie pivot cross-host — endpoint does not observe session reuse; IdP/SSO anomaly is detectable → **Calibrated** in Scenario 2.
> - Conversely, artifacts only meaningful when trusting a ghost/injected process identity fail **Condition 3** regardless of scenario — not affected by measurement surface breadth.

> **On ghost/injected processes and Condition 3:** An injected execution context does not automatically make every artifact Not Calibrated. Condition 3 only fails when the evaluator must trust that process identity to conclude the behavior is malicious.
> - In [Mustang Panda Step 2](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md), `waitfor.exe` runs `netstat`, `ipconfig`, SharpNBTScan, downloads `mswin1.exe`; all these rows are `Not Calibrated`. The most consistent interpretation under this framework is that their malicious meaning depends heavily on the implanted context, so they fail Condition 3.
> - But in the same scenario, `waitfor.exe` creates a registry run key `AccessoryInputServices`, a scheduled task with the same name, and exfiltrates a RAR via FTP; MITRE assigns those rows `Calibrated` because the registry key, scheduled task, and network transfer to an external endpoint are independent artifacts outside process context, verifiable without trusting process identity. See [Mustang Panda Step 5](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md) and [Step 7](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md).

> **Example of Condition 3 failure that is not a redundancy:** `T1573.001` using PSK symmetric encryption. If the payload bytes can only be proven using a key hidden inside the malware, the evaluator cannot independently confirm "this is T1573.001" from external telemetry → `Not Calibrated`. In contrast, `T1573.002` TLS/asymmetric has a certificate and JA3 fingerprint independently available from a network capture, making it a distinct detection axis that can be `Calibrated` even when C2 web protocol is also already Calibrated. Confirmed by [Mustang Panda Step 7](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md): both `T1071.001` and `T1573.002` are Calibrated.

Any condition unsatisfied → **Not Calibrated**.

### Layer 3 — Heuristics for detecting mislabels

After labeling, check against these patterns:

- **Anti-analysis / internal evasion check labeled Calibrated** → almost always wrong. `T1497` foreground window check, `T1622` IsDebuggerPresent — checks occur entirely in process memory with no external artifact, Condition 1 fails.
- **In-memory native API call labeled Calibrated** → almost always wrong. `T1106` CoCreateGuid, `ws2_32.send`, `T1082` GetComputerNameA called from injected context — no EDR-observable artifact independent of the already-Calibrated process-create/network event at another link; Condition 1 fails or it is an implementation detail of a scored downstream behavior.
- **Calibrated but Detection Criteria written abstractly** (`Malware connects to C2`, `Loader decrypts payload`) → violates Conditions 1–2. Downgrade to Not Calibrated or rewrite Detection Criteria to be specific first.
- **Not Calibrated but artifact is clear, on the measurement surface, appearing for the first time in the chain** → re-check Layer 1: if it is not genuinely a scope issue or redundancy → upgrade to Calibrated.
- **Calibrated ratio ~100% in a Detections scenario with a stealthy adversary** → suspicious: adversary custom malware in practice has many evasion/internal chain steps → re-check each substep.
- **Two rows with the same technique and same physical event, same label** → double-count; one is an implementation detail of the other.
- **Same technique flips label between two scenarios** → correct if test type or measurement surface differs; incorrect if same context and same event.

---

## Principle 2 — Why Calibrated ratios differ across scenarios

A scenario's Calibrated ratio typically reflects two simultaneous factors:

1. **Adversary stealth profile** — chains using many loaders, injection, or in-memory behavior tend to produce more `Not Calibrated` rows than chains relying on legitimate tools and valid credentials.
2. **Scenario measurement surface** — Scenario 2 includes identity/cloud telemetry, making more cross-domain behaviors fair scoring points, while Scenario 1 endpoint-only does not.

| Adversary | Calibrated ratio | Explanation |
|---|---|---|
| [Mustang Panda (main)](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md) | ~39% | Custom malware (TONESHELL, PlugX) with deep injection chains. Most evasion chain steps are Not Calibrated. |
| [Scattered Spider (main)](../Enterprise/scattered_spider/Emulation_Plan/Scattered_Spider_Scenario.md) | ~93% | Legitimate tools + valid credentials. No significant evasion → artifacts clear across all surfaces. |
| Protections tests ([PT4](../Enterprise/mustang_panda/Emulation_Plan/Protections_Test_4_Scenario.md), [PT5](../Enterprise/mustang_panda/Emulation_Plan/Protections_Test_5_Scenario.md), [SS PT1](../Enterprise/scattered_spider/Emulation_Plan/Protections_Test_1_Scenario.md)…) | ~97% | Testing controls → clear, reproducible signals needed → nearly all Calibrated. |

Layer 2 specifies the rule for both drivers: measurement surface only affects `fair scoring point`, while artifacts that depend on process identity still fail `independently verifiable` regardless of scenario breadth. When building Scenario 2, review cross-domain techniques: `T1078.004`, `T1550.004`, `T1098.00x`, `T1087.004`, `T1580`, `T1619`.

## Principle 3 — Calibrated defines the valid scope of the detection measurement question

The `Calibrated` label does not merely describe how clear an artifact is — it defines **the valid scope of the evaluation question**.

The detection evaluation question: *"Did the vendor detect this behavior?"* only has measurement value when the evaluator can **independently confirm the artifact existed** on the victim system. Only then can a "miss" be attributed to the vendor.

| Label | Evaluator can verify artifact? | Miss attributable to? | Counts in detection statistics? |
|---|---|---|---|
| `Calibrated` | Yes — artifact is guaranteed to exist and satisfies all 4 conditions | Vendor | **Yes — counts toward denominator** |
| `Not Calibrated` | Not counted: artifact outside detection surface, substep is redundancy/implementation detail, or artifact fails one of the 4 conditions (not observable, not reproducible, not independently verifiable, outside measurement surface) | Cannot be determined | **No** |

**Concrete example ([Mustang Panda Step 1](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md)):**
- `T1574.002` DLL Side-Loading `wsdapi.dll` → **Calibrated** → evaluator confirms `wsdapi.dll` on disk loaded by `EssosUpdate.exe` → a miss clearly means the vendor did not detect → counts toward denominator
- `T1497` Foreground window check → **Not Calibrated** → `GetForegroundWindow()` call occurs in memory with no external artifact the evaluator can independently verify → a miss may be due to the artifact not being observable, not necessarily vendor failure → does not count toward denominator

### Notes to avoid misunderstanding

**Not Calibrated ≠ "does not need to be detected."**
Not Calibrated behaviors are still fully recorded with Detection Criteria in the Reference Table. They serve three distinct purposes:
1. **Completeness** — the scenario accurately reflects real adversary behavior without editorial cuts for measurement reasons
2. **Analyst reference** — if a vendor detects a Not Calibrated behavior, that is bonus visibility worth noting
3. **Stealth profile** — a high Not Calibrated ratio reflects an adversary using custom malware with deep evasion chains (see Principle 2)

**Not Calibrated ≠ "easy to label."**
Assigning `Calibrated` to a behavior whose artifact is not truly guaranteed → corrupts the denominator → inflates detection rate dishonestly. The `Calibrated` label is only assigned when the red team can **commit** that the artifact exists on the victim in a way the evaluator can independently confirm.

---

## Principle 4 — Detection Criteria must be a specific, observable event

**Incorrect:**
```
| Detection Criteria |
| Malware connects to C2 |
```

**Correct:**
```
| Detection Criteria |
| waitfor.exe connects to 191.44.44.199 over TCP port 443 |
```

**Detection Criteria writing rules:**
- Format: `<parent_process> <action> <artifact/target> [on <host>]`
- Must be queryable directly in SIEM / EDR
- If artifact has a specific path → write the full path
- If on multiple hosts → write the specific host in the row or split into multiple rows

---

## Principle 5 — Each observable event gets its own row

Do not combine multiple events into one row even if they share a technique:

```markdown
| Persistence | T1053.005 | Scheduled Task | Windows | .pif executable created GFlagEditor folder | Calibrated - Not Benign | ... |
| Persistence | T1053.005 | Scheduled Task | Windows | .pif executable scheduled task to execute gflags.exe | Calibrated - Not Benign | ... |
```

Two rows, same technique ID, but two distinct observable events → separate rows.

---

## Principle 6 — Protections tests vs Main scenario

### Main scenario (Detections)

**Question:** Does the detector *see* the behavior?

- Full kill chain across many steps
- Mixed Calibrated / Not Calibrated according to adversary nature and Scenario type
- Executed sequentially with dependencies (each step requires prior state)
- Measurement surface per Layer 0; Scenario 1 endpoint-only, Scenario 2 adds identity/cloud/cross-host.

### Protections tests (Protections)

**Question:** Does the security control *block* the behavior?

- Short sub-chain, isolating one capability block
- Typically very high Calibrated ratio — the test needs clear, reproducible signals to measure protection outcome
- Each test runs independently, with no state dependencies on other tests
- Evaluation surface depends on test scope; may include email gateway, web filter, identity provider if declared
- **Different delivery vector** from the main scenario to test generality of the control

**Example delivery variants (Mustang Panda 2025):**
- [Main](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md): DOCX spearphishing → TONESHELL (`wsdapi.dll`)
- [Protections Test 4](../Enterprise/mustang_panda/Emulation_Plan/Protections_Test_4_Scenario.md): PIF dropper → TONESHELL (`gflagsui.dll`)
- [Protections Test 5](../Enterprise/mustang_panda/Emulation_Plan/Protections_Test_5_Scenario.md): MSC file via MMC → PlugX (`rcdll.dll`)

If a control only blocks by file hash, it will fail against variants — that is the point.

**Implication for labels:** flipping `T1566.001 Spearphishing` between Detections and Protections in Principle 1 is valid because the measurement scope differs.

---

## Principle 7 — CTI grounding is required

Every technique must have at least one CTI report in the `Relevant CTI Reports` column. The behavior must be **observed in the wild** — do not add techniques without CTI backing.

This is why the file header always contains numbered CTI citations `[1]`, `[2]`...

---

## Principle 8 — Source code links for custom tools

When a technique uses a custom tool (TONESHELL, PlugX...), the `Source Code Links` column must point to the **specific function** in the source code, not just the file:

```markdown
| [PerformFileDownloadTask](../Resources/toneshell/src/shellcode/exec.cpp#L241-L346) |
| [Xor Functions](../Resources/toneshell/src/common/xor.cpp) |
```

For COTS tools (Snaffler, rclone, WinRAR...) → link to the repo or leave blank.

---

## Template for designing a new attack behavior

1. **Select a technique** with CTI backing for the adversary being simulated.
2. **Identify the artifact**: what does the technique produce? File? Registry? Network? Process?
3. **Assign Category** — follow the labeling process flow:
   1. Is the artifact on the **detection surface** declared in Layer 0? (No → Not Calibrated)
   2. Is there another Calibrated row that **already represents this information better**? (Yes → Not Calibrated)
   3. If through both: is this substep the **primary output** of the adversary action? (No → Not Calibrated)
   4. Is the artifact **observable** outside memory? (No → Not Calibrated)
   5. Is the artifact **reproducible** across runs? (No → Not Calibrated)
   6. Can the evaluator **independently verify** the artifact? (No → Not Calibrated)
   7. Is this a **fair scoring point** for the product type under test? (No → Not Calibrated)
   8. Can Detection Criteria be written in the form `<process|principal> <action> <artifact|target>` specifically? (No → rewrite first or Not Calibrated)

   → Through questions 1–3: substep is a **primary output**.
   → Through questions 4–8: substep qualifies as **Calibrated - Not Benign**.
4. **Write Detection Criteria**: one specific sentence in the form `<process> <action> <artifact/target> [on <host>]`.
5. **Identify host + user**: which machine does the behavior occur on, under which account.
6. **Add source code link** if a custom tool is used.
