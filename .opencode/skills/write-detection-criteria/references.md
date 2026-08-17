# write-detection-criteria - Reference

Detailed lookup tables used by Steps 3–5. Read this file before writing criteria.

---

## Signal format examples

### Tier 1 - Intrinsic anomaly
`<process | principal> <action> <artifact | target> [on <host>]`

| | Example |
|---|---|
| correct | `mavinject.exe injects into waitfor.exe` |
| correct | `EssosUpdate.exe side-loads unsigned wsdapi.dll from C:\Users\Public\` |
| correct | `waitfor.exe connects to 191.44.44.199 over TCP port 443` |
| wrong | `Malware connects to C2` |
| wrong | `Loader decrypts payload` |

### Tier 2 - Contextual anomaly
`[process | process class] <condition> [and <condition>…]`

| | Example |
|---|---|
| correct | `process loads unsigned DLL from user-writable path and creates outbound network connection` |
| correct | `EssosUpdate.exe spawns child process not matching known-good child list` |
| wrong | `suspicious process does something malicious` |

### Random values → write the pattern, not the value

| | Example |
|---|---|
| correct | `non-COM process generates a GUID and writes it to a non-standard path` |
| wrong | `process writes {3F2504E0-4F89-...}` |

---

## Forward checklist (concrete-signal rows only)

- [ ] Names the anomaly axis - you can state the baseline it deviates from
- [ ] Specific process/principal (filename, not "malware")
- [ ] Specific action (loads, executes, connects, writes, spawns…)
- [ ] Specific artifact/target (full path, IP:port, filename, registry key)
- [ ] Queryable directly in SIEM/EDR with no additional context
- [ ] One decisive positive signal - not a list of absences or implementation details
- [ ] Multi-host behavior split into one row per host
- [ ] **Technique-witness binding** - observing this signal lets the analyst conclude *this technique* fired, not a sibling/downstream event that happens to share the same physical artifact. If the only writable signal evidences a different technique on the same event, leave it to that sibling row and write `N/A - C3` here.
- [ ] **Stability under adversary control** - the pattern survives what the operator can change between engagements (encoding keys, build-time constants, hardcoded paths/names), not just runtime randomness. Probe: "if the attacker rotates this value tomorrow, does the signal still fire?" If no, rewrite against the structure-invariant pattern or write `N/A - C1`.

---

## Quality elements

Each element proves a specific property that makes the signal usable as evidence:

| Element | Why it matters |
|---|---|
| **Concrete & directly queryable** - specific process/principal (filename, not "malware") + specific action + specific artifact (full path, IP:port, registry key); paste into SIEM with no extra context | Any analyst can write a rule from it without additional context - no guessing required |
| **One decisive positive signal** - state what IS there as the anomalous pattern; no lists of absences, no implementation details (byte offsets, XOR formula) beyond what is needed to write a rule | Prevents vague "suspicious" phrasing that cannot be evaluated or disputed |
| **Pattern, not value** - durable across runs; write against the stable behavioral pattern, not the random value | Signal holds consistently regardless of randomization - not brittle to a specific run |
| **Evaluator-verifiable without red-team claims** - artifact confirmable from telemetry alone (file on disk, external netconn, attributed artifact), never in-process state requiring trust in the implant | Absence of the signal is attributable to the vendor, not to trust assumptions |
| **Telemetry-depth explicit when two rows share one physical event** - keep both rows only if criteria require different capability (raw netconn vs JA3/TLS fingerprint); identical criteria = double-count | Distinguishes genuinely separate detection opportunities from the same event seen twice |
| **One host per row** - multi-host behavior splits into one row per host, each with its own `on <host>` | Keeps each signal unambiguous about where to look |

---

## Reverse diagnostic

If the criteria comes out like the left column, there is no clean signal:

| Symptom | Failing condition | Action |
|---|---|---|
| Cannot write without "suspicious / malicious" | C1 - no anomaly axis | `N/A - C1: <reason>` |
| Only true for one specific run | C1 - no stable pattern | Rewrite against the underlying pattern first; if none exists → `N/A - C1: no stable pattern` |
| Pattern looks fixed but the fixed value is derived from an operator-controlled input (encoding key, build constant, hardcoded name) | C1 - stable under one config, not under config rotation | Probe: "if the operator rotates this value next engagement, does the signal still fire?" If no, rewrite against a structure-invariant pattern; if none exists → `N/A - C1: only writable signal is config-derived` |
| Signal is on-surface and writable, but it evidences a sibling/downstream technique (same physical artifact), not the technique on this row | C3 - signal off the technique being scored | `N/A - C3: signal witnesses <other technique>, not this one`; let the sibling row carry it |
| Tier 1 signal (`actor + action + target`) collapses into a busy baseline (the actor legitimately performs this action against this target class) | Tier 1 chosen prematurely | Add an independent condition about the artifact itself (content, structure, signature) and reframe as Tier 2; only fall back to `N/A` after the multi-condition form fails |
| Must trust the implant to conclude it is bad | C2 - not independently verifiable | `N/A - C2: <reason>` |
| Observable artifact but outside declared Surface Profile | C3 - off surface | `N/A - C3: <reason>` |
| Same artifact/target as neighboring row under same technique | Redundancy (Q-B) | Write faithfully and in full - `assign-category` detects the double-count by the technique+artifact match, not verbatim text; do not blur or "see above" |
| All-negative phrasing ("no strings", "absent from…") | Right tech, wrong altitude | Reframe as a positive anomalous pattern |
| No baseline can be named | C1 | `N/A - C1: no baseline / anomaly axis` |
