# write-phase — Reference

Format spec and granularity rules used throughout. Read this file before writing any Phase file.

---

## Phase file format

### Structure overview

A Phase file has four parts in order:
1. **CTI header** — numbered reference list (`[1]: <url>`) at the top; cite with `[N]` in Reference Tables
2. **Step 0 — Setup** — C2 session verification, operator connection; no Reference Table
3. **Attack steps** (Step 1 … N) — each has Voice Track → Procedures → Reference Tables
4. **End of Test** (optional) — shutdown/cleanup procedures

Use `phase-template.md` (in this skill's directory) as the exact skeleton. Do not invent, rename, or drop sections.

---

### Voice Track

- Third-person adversary perspective
- Continuous narrative — connect to prior steps; explain what the adversary is trying to achieve and why at this point in the chain
- One paragraph per step; do not bullet-list the Voice Track

---

### Procedures

- Numbered list (or unnested bullets); exact commands in fenced code blocks
- Include **Expected Output** under any step where output confirms success:
  ```
  - ***Expected Output***
    ```text
    <expected output>
    ```
  ```
- Prefix with `☣️` only for steps that are **genuinely dangerous**: changing system state, running payloads, or executing attack behavior. Navigation, reading output, and normal setup do NOT get `☣️`.

---

### Reference Table columns

| Column | What to fill | Notes |
|---|---|---|
| `Summary` | Formal noun phrase identifying the specific behavior | Fill now — 5–10 words; name the tool or actor, the mechanism, and the artifact or target. Format: `<tool/actor> <mechanism> <artifact/target>` (e.g. `MiniDumpWriteDump LSASS process memory dump`, `reg.exe HKCU run key persistence write`, `dnscat2 DnsQuery_W encrypted DNS C2 beacon`). Must be specific enough to distinguish this row from every other row in the plan — generic labels like `payload drop`, `file write`, or `eval execution` are not acceptable without qualifying the specific tool and artifact. No technique ID or tactic label. Used as the row identifier in the management portal. |
| `Tactic` | Leave `—` | Filled by `/map-technique` |
| `Technique ID` | Leave `—` | Filled by `/map-technique` |
| `Technique Name` | Leave `—` | Filled by `/map-technique` |
| `Platform` | `Windows` / `Linux` / `IaaS` / etc. | Fill now |
| `Detection Criteria` | Leave `TBD` | Filled by `/write-detection-criteria` |
| `Category` | Leave `TBD` | Filled by `/assign-category` |
| `Calibration Reason` | Leave `TBD` | Filled by `/assign-category` |
| `Red Team Activity` | Short description of red team behavior from external observer's view — one decisive sentence | Fill now |
| `Hosts` | `hostname (IP)` where the behavior occurs | Fill now |
| `Users` | Account performing the behavior | Fill now |
| `Source Code Links` | Relative path to payload in `Resources/` (if custom tool) | Fill if known |
| `Relevant CTI Reports` | Reference numbers from the CTI header, e.g. `[2], [9]` | Fill if known |

**Multi-host rule:** if a behavior occurs on multiple hosts, create a separate row per host — each with its own `Hosts` and `Users` cells.

**Row order** must follow temporal execution order within the step. Each row = one distinct observable behavior. Do not try to consolidate two distinct behaviors into one row.