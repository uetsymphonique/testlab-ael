---
description: Build, compile, or script a payload for the emulation plan (Go, Python, PowerShell)
---
 
# Craft Payload
 
Build or modify a payload for use in the emulation plan. Keep the dev environment constraints in mind at every step.
 
## Before starting
 
Read `plan-for-agent/guides/cli-execution.md` — this is the authoritative source for what toolchains are available in the current dev environment. Do not assume a compiler or runtime is available unless it appears there.
 
## Gather requirements
 
Ask the user (combine into one message if multiple questions apply):
 
1. **What to build**: describe the payload behavior, or reference a technique ID / Phase step
2. **Language / format**: Go binary, Python script, PowerShell, C# — or no preference (you suggest based on available toolchain)
3. **Target context**: where will this run on the lab host? (architecture, OS, privilege level)
4. **Placement**: which plan and directory should the payload go into? (defaults to `testlab-enterprise/windows-adversary-plan/resources/payloads/`)
 
Note: `cli-execution.md` describes the **dev environment** used to compose payloads — not the lab/victim host. Do not infer target-host capabilities from it. If the user requests a language the guide does not list as available, say so and propose the closest available alternative.
 
## Build steps
 
1. **Write source**: create source file(s) under the target payload directory
 
2. **Compile** (if applicable):
   - Go: `go build -o <output.exe> .` from the payload directory
   - Python: no compile step; verify with `D:\vcs\ael\venv\Scripts\python.exe <script>.py --help` or equivalent
   - C# via VS: wrap the build command with `& "C:\Program Files\Microsoft Visual Studio\...\VsDevCmd.bat"` then invoke `csc` or `msbuild`
 
3. **Verify**: run the binary with `--help` or a benign argument to confirm it executes without error (do not trigger live behavior in the dev environment)
 
4. **Place output**: put the final artifact in the correct subdirectory under `resources/payloads/`:
 
| Payload type | Directory |
|---|---|
| Coupled to a specific technique | `payloads/<TID>/` (e.g. `T1055/`) |
| Named tool or framework | `payloads/<tool-name>/` (e.g. `dnscat2/`) |
| Exploit PoC | `payloads/<CVE-or-exploit-name>/` |
| Custom implant / multi-file | `payloads/<project-name>/` with documentation |
 
5. **Document**: write the payload's documentation files (see `## Payload documentation`).
 
## Payload documentation
 
A payload directory uses up to **three** documentation files, each with a single responsibility — do not let their contents overlap:
 
| File | Owns | Produced by |
|---|---|---|
| `README.md` | **What / why** — tool purpose, high-level behavior, target context, how to run it | this skill |
| `Build.md` | **How to build** — toolchain, build command, build options/variants, output artifact | this skill |
| `Flow.md` | **Internal mechanics** — codeflow broken into behaviors + ATT&CK mapping | `/document-flow` skill |
 
Always write `README.md`. Write `Build.md` when the payload is compiled or has non-obvious build options (skip for a single trivial script). Produce `Flow.md` by running `/document-flow` — do **not** author it here.
 
### `README.md` template
 
````markdown
# <tool-name>
 
**Purpose:** <one line — what this payload does and which technique/Phase step it serves>
 
## Overview
<2–4 sentences of insight: high-level behavior, the mechanism that makes it work>
 
## Target context
- **Host / OS / arch:** <where it runs on the lab>
- **Privilege required:** <e.g. SYSTEM, domain user>
 
## Usage
<exact invocation in the lab; ☣️ on dangerous steps>
 
## See also
- Build: `Build.md`  ·  Code flow & ATT&CK mapping: `Flow.md`
````
 
### `Build.md` template
 
````markdown
# <tool-name> — Build
 
**Toolchain:** <e.g. Go 1.x — see plan-for-agent/guides/cli-execution.md>
 
## Build
```<exact build command from the payload directory>```
 
## Options
<build flags / variants and what each changes — omit if none>
 
## Output
- **Artifact:** <output.exe and where it lands>
- **Dev-env verify:** <benign `--help`/dry-run command>
````
 
## Notes
 
- **Input handoff**: when the approach is unclear or has alternatives, `/emulate-technique` is the upstream skill that decides it; this skill builds what it recommends.
- **Output handoff**: when the payload is referenced from a Phase file, give `/write-phase` the relative path from `Emulation_Plan/` to `../resources/payloads/<dir>/`. To break the payload's source into behaviors + ATT&CK mapping (`Flow.md`), run `/document-flow`.
- Do not run live attack behavior in the dev environment — compile and dry-run only.
- If the payload is already built (user provides source), skip to the place/verify step.