# Guide: Writing and Verifying Detection Criteria

> **Consumed by:** `/write-detection-criteria` — see [pipeline.md](../pipeline.md)

How to write the `Detection Criteria` column for **every** Reference Table row, and verify it meets the required standard. This step runs **first**, before labeling — it produces the evidence base. `category-assignment.md` then *reads* this column to decide *whether* a row is scored; this guide decides *how* the signal is written, or records that no signal exists.

> Scope: Detection Criteria is written for **every row**. Where an anomaly axis exists, write the concrete signal. Where it does not, write a **documented absence** — `N/A — <failing condition>: <one-line reason>` (e.g. `N/A — C3: in-memory only inside a ghost process, not evaluator-verifiable`) — never a vague sentence. The documented absence is the evidence `assign-category` reads to Not-Calibrate the row; the label is **not** decided here.

---

## Core principle: define the vendor accountability signal

A Detection Criteria does not describe "process X did action Y." It **names the signal that, if absent from a product's output, constitutes an attributable detection gap** — expressed as the anomaly axis (how the behavior deviates from baseline) on the declared telemetry surface, in a form a product can key a rule on or feed into risk scoring.

Two tests must both pass before writing a concrete signal:

1. **Anomaly test** — can you name how this behavior deviates from baseline? If not → `N/A — C1: no anomaly axis`.
2. **Surface test** — does that anomaly land on the declared telemetry surface? Read the surface from the **Surface Profile** — the Layer 0 table in `category-assignment.md` (Scenario 1 EDR default). This is the *same* profile `assign-category`'s Question A reads; both steps must consult one pinned profile so an on-surface signal here is not later rejected as off-surface there. If not on-surface → `N/A — C4: artifact outside declared surface`.

Naming the anomaly is the *method*. The *goal* is a signal where vendor failure to produce it is clearly the vendor's fault, not a measurement artifact.

**Criteria is the evidence the label is read from.** If both tests pass and you can articulate the anomaly concretely on-surface, the four Calibration conditions hold in practice. If either fails, write the documented absence (`N/A — <Cx>: <reason>`); `assign-category` reads it as the Not-Calibrated signal.

**Hidden test — every Criteria must implicitly answer: "deviates from *what baseline*, on *what surface*?"** The baseline must be a **pattern, not a value** (otherwise the criteria is brittle and fails reproducibility). The surface must be the declared measurement scope (otherwise the criteria is off-target).

> **Anchor an environment-relative baseline, do not assume it.** "An IIS worker never spawns a shell" or "this host runs no operator scripts" is a claim about *this* lab, not a universal truth — on a host with operations tooling the same event is normal. When the anomaly depends on a clean-baseline assumption, anchor it to the plan's lab topology (the role/build of the host in `summary.md` or the setup docs), so two authors on two environments do not write conflicting "correct" signals. If the baseline cannot be anchored to a stated host role, the deviation is not yet established — name the baseline before writing the signal.

> Example of the lens: `w3wp.exe spawns cmd.exe` is strong not because it is a process tree, but because an IIS worker process **never** spawns a shell in normal operation — and that event lands on every EDR's process-creation channel. Both the anomaly and the surface are explicit.

---

## Two tiers of anomaly → two Criteria formats

Identifying which tier the deviation lives in **is** the act of choosing the format.

### Tier 1 — Intrinsic anomaly (the artifact is rare by itself)

The event barely appears in any baseline; it is enough to write a single rule on. → **single-signal format.**

`<process | principal> <action> <artifact | target> [on <host>]`

| | Example |
|---|---|
| ✅ | `mavinject.exe injects into waitfor.exe` |
| ✅ | `EssosUpdate.exe side-loads unsigned wsdapi.dll from C:\Users\Public\` |
| ✅ | `waitfor.exe connects to 191.44.44.199 over TCP port 443` |
| ❌ | `Malware connects to C2` |
| ❌ | `Loader decrypts payload` |

### Tier 2 — Contextual anomaly (each artifact is common; the combination/sequence is rare)

No single fragment alerts; the **combination accumulates enough risk** in a context. This is the form that feeds risk-scoring and correlation rather than a boolean rule. → **behavioral-pattern format.**

`[process | process class] <condition> [and <condition>…]`

| | Example |
|---|---|
| ✅ | `process loads unsigned DLL from user-writable path and creates outbound network connection` |
| ✅ | `EssosUpdate.exe spawns child process not matching known-good child list` |
| ❌ | `suspicious process does something malicious` |

> Each condition in a behavioral pattern must still be independently verifiable in telemetry — the combination is what's anomalous, not red-team assertion.

### Random values → write the pattern, not the value

A GUID/nonce does not fail reproducibility. Write the criteria against the **stable pattern** the random value sits inside.

| | Example |
|---|---|
| ✅ | `non-COM process generates a GUID and writes it to a non-standard path` |
| ❌ | `process writes {3F2504E0-4F89-...}` |

---

## Vendor accountability signal — write decision (diagnostic)

Use this to decide what to *write*; `assign-category` makes the final label call by reading the result:

| Both tests pass? | What to write | Label implication |
|---|---|---|
| **Yes** — anomaly exists AND lands on the declared surface | Concrete signal in `<process> <action> <artifact>` form | `Calibrated - Not Benign` (pending assign-category's scope/redundancy checks) |
| **Anomaly exists but off declared surface** | `N/A — C4: <reason>` | `Not Calibrated` |
| **No anomaly axis** — behavior identical to baseline | `N/A — C1: no anomaly axis` | `Not Calibrated` |

> The absence of an anomaly is diagnostic information — do not force a signal where none exists. Write the documented absence so `assign-category` has the explicit reason to Not-Calibrate.

---

## Quality elements (each proves a Calibration condition)

A well-formed Criteria satisfies all of these; each one is the operational proof of a condition behind the label:

| Element | Proves |
|---|---|
| **Concrete & directly queryable** — specific process/principal (a filename, not "malware") + specific action + specific artifact (full path, IP:port, registry key). Paste-into-SIEM test: no extra context needed. | Condition 1 — Observable |
| **One decisive positive signal** — state what IS there, framed as the anomalous pattern. No lists of absences, no implementation detail (XOR formula, byte offsets) beyond what's needed to write a rule. | Writing discipline |
| **Pattern, not value** — durable across runs; write against the stable behavioral pattern. | Condition 2 — Reproducible |
| **Evaluator-verifiable without red-team claims** — points to an artifact confirmable from telemetry alone (registry key on disk, external netconn, attributed file), never to in-process state that requires trusting the implant. | Condition 3 — Independently verifiable |
| **Telemetry-depth explicit when two rows share one physical event** — keep both rows only if their criteria require different capability (raw netconn vs JA3/TLS fingerprint). Identical criteria on two rows = double-count. | Redundancy (Question B) |
| **One host per row** — multi-host behavior splits into one row per host, each with its own `on <host>`. | Clean scoping |

> Frame negatives as positives: write `sparse IAT — only 2 imported functions`, not `CreateFile absent from import table`.

---

## Forward checklist

For every row with a concrete signal (rows that resolve to a documented absence skip this — see the reverse diagnostic):

- [ ] Names the anomaly axis (you can state the baseline it deviates from)
- [ ] Specific process/principal (filename, not "malware")
- [ ] Specific action (loads, executes, connects, writes, spawns…)
- [ ] Specific artifact/target (full path, IP:port, filename, registry key)
- [ ] Queryable directly in SIEM/EDR with no additional context
- [ ] One decisive positive signal — not a list of absences or implementation details
- [ ] Multi-host behavior split into one row per host

---

## Reverse diagnostic (Criteria symptom → failing condition → action)

If the Criteria comes out like the left column, there is no clean signal — write the documented absence with the failing condition; `assign-category` reads it:

| Criteria symptom | Failing condition | What to write |
|---|---|---|
| Cannot write without "suspicious / malicious" | C1 — not truly observable | `N/A — C1: <reason>` |
| Only true for one specific run | C2 — not reproducible | Rewrite against the pattern; if none exists, `N/A — C2: <reason>` |
| Must trust the process is running malware to conclude it's bad | C3 — not independently verifiable | `N/A — C3: <reason>` (typical for in-memory-only / ghost-process behavior) |
| Observable artifact but outside the declared telemetry surface (e.g. cloud audit log for Scenario 1 EDR, email gateway event for endpoint-only scope) | C4 — not a fair scoring point on this surface | `N/A — C4: <reason>` |
| Same artifact/target as a neighboring row under the same technique | Redundancy (Q-B) | Write the signal faithfully and in full — `assign-category` detects the double-count by the technique+artifact match (not verbatim text); do not blur or "see above" |
| All-negative phrasing ("no strings", "absent from…") | Right tech, wrong altitude | Reframe as a positive anomalous pattern |
| No baseline can be named | Core principle | `N/A — C1: no baseline / anomaly axis` |

> A row that resists specific criteria does not get a forced sentence — it gets a documented `N/A — <Cx>: <reason>`. The label is `assign-category`'s call, made by reading that.

---

## Related: Red Team Activity column

The same conciseness discipline applies: one sentence stating the decisive action, not a technical walkthrough.

`<payload> <does what> <to/on what> — <evasion note if relevant>`

- Omit formulas, variable names, method chains unless they are the detection signal itself.
- Two short sentences maximum, only if one is genuinely insufficient.
