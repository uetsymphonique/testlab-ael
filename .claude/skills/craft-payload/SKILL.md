---
name: craft-payload
description: Build, compile, or script a payload for the emulation plan. Handles Go binaries, Python scripts, and PowerShell payloads within dev environment constraints.
model: claude-sonnet-4-6
effort: high
allowed-tools: Read, Write, Edit, Glob, Grep, PowerShell, Bash
---

Build or modify a runnable payload for the emulation plan, then place it in `resources/payloads/` following the plan's directory convention.

<HARD-GATE>
1. Do NOT run live attack behavior in the dev environment. Compile and dry-run (`--help` / benign arg) ONLY — this dev env composes payloads, it is not the lab/victim host.
2. Use ONLY toolchains listed in `plan-for-agent/guides/cli-execution.md`. Do NOT assume a compiler/runtime exists. If the user asks for a language not listed, say so and propose the closest available alternative — do not silently substitute.
3. This skill takes an ALREADY-DECIDED approach. If the technique variant is not yet chosen, run `emulate-technique` first — do not pick the approach here.
4. Do NOT author `Flow.md` here (that is `document-flow`). Write `README.md` (always) and `Build.md` (when compiled / non-trivial build).
</HARD-GATE>

This skill takes an **already-decided approach** and produces the artifact. It does **not** choose which technique variant to emulate (`emulate-technique` surveys the options and recommends the approach), map ATT&CK techniques (`map-technique`), or author Phase content (`write-phase`). If the approach is not yet decided, run `emulate-technique` first.

## Before starting

Read `plan-for-agent/guides/cli-execution.md` — the **authoritative and only** source for what toolchains exist in the current dev environment. Do not assume a compiler or runtime is available unless it appears there, and do not restate its contents here (that creates a second source that drifts). If the user requests a language the guide does not list as available, say so and propose the closest available alternative.

Note: `cli-execution.md` describes the **dev environment** used to compose payloads — not the lab/victim host. Do not infer target-host capabilities from it.

## Gather requirements

Ask the user (combine into one message if multiple questions apply):

1. **What to build**: describe the payload behavior, or reference a technique ID / Phase step
2. **Language / format**: Go binary, Python script, PowerShell, C# — or no preference (you suggest based on the available toolchain)
3. **Target context**: where will this run on the lab host? (architecture, OS, privilege level)
4. **Placement**: which plan and directory should the payload go into? (defaults to `testlab-enterprise/windows-adversary-plan/resources/payloads/`)

If the user's message already answers some of these, skip those questions.

## Build steps

1. **Write source**: create source file(s) under the target payload directory.
2. **Compile** (if applicable) using the toolchain from `cli-execution.md`:
   - Go: `go build -o <output.exe> .` from the payload directory
   - Python: no compile step; verify with `D:\vcs\ael\venv\Scripts\python.exe <script>.py --help` or equivalent
   - C# via VS Build Tools: wrap the build with the Visual Studio Developer Command Prompt (`& "...\VsDevCmd.bat"`) before invoking `csc` / `msbuild`
3. **Verify**: run the binary with `--help` or a benign argument to confirm it executes without error. Do **not** trigger live attack behavior in the dev environment.
4. **Place output**: put the final artifact in the correct subdirectory under `resources/payloads/`:

| Payload type | Directory |
|---|---|
| Coupled to a specific technique | `payloads/<TID>/` (e.g. `T1055/`) |
| Named tool or framework | `payloads/<tool-name>/` (e.g. `dnscat2/`) |
| Exploit PoC | `payloads/<CVE-or-exploit-name>/` |
| Custom implant / multi-file | `payloads/<project-name>/` with documentation (see below) |

5. **Document**: write the payload's documentation files (see `## Payload documentation`).

## Payload documentation

A payload directory uses up to **three** documentation files, each with a single responsibility — do not let their contents overlap:

| File | Owns | Produced by |
|---|---|---|
| `README.md` | **What / why** — tool purpose, high-level behavior, target context, how to run it | this skill |
| `Build.md` | **How to build** — toolchain, build command, build options/variants, output artifact | this skill |
| `Flow.md` | **Internal mechanics** — codeflow broken into behaviors + ATT&CK mapping | `document-flow` skill |

Always write `README.md`. Write `Build.md` when the payload is compiled or has non-obvious build options (skip for a single trivial script). Produce `Flow.md` by running `document-flow` — do **not** author it here.

### `README.md` template

```markdown
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
```

### `Build.md` template

```markdown
# <tool-name> — Build

**Toolchain:** <e.g. Go 1.x — see plan-for-agent/guides/cli-execution.md>

## Build
```<exact build command from the payload directory>```

## Options
<build flags / variants and what each changes — omit if none>

## Output
- **Artifact:** <output.exe and where it lands>
- **Dev-env verify:** <benign `--help`/dry-run command>
```

## Anti-Patterns — named rationalizations to reject

**"Let me just run it once to confirm it really works."** Dry-run only (`--help` / benign arg). Never trigger live attack behavior in the dev environment — it is not the lab host and running the payload there is the one irreversible mistake this skill exists to prevent.

**"Go/C# probably isn't installed, but I'll try anyway."** Use only toolchains in `cli-execution.md`. Confirm availability there; if the requested language is absent, say so and propose the closest available alternative — do not silently substitute or assume.

**"I'll decide the technique variant as I build."** Approach selection is `emulate-technique`'s job. If it is not decided, stop and run that first — building the wrong variant wastes the whole artifact.

**"I'll document the code flow + ATT&CK mapping in the README."** `Flow.md` (via `document-flow`) owns internal mechanics + mapping. Keep `README.md` to what/why and `Build.md` to how-to-build — overlapping them creates two sources that drift.

## Red Flags — STOP if you are thinking:

| If you think… | The reality is… |
|---|---|
| "Run it once to be sure" | Dry-run only — never live attack behavior in the dev env |
| "Probably installed, I'll try" | Only `cli-execution.md` toolchains — confirm, don't assume |
| "I'll pick the variant as I go" | Approach selection is `emulate-technique`'s — run it first if undecided |
| "Document the mechanics in README" | `Flow.md` owns mechanics+mapping — keep README to what/why |
| "Overwrite the existing payload here" | Check provenance first — if this session didn't create it, confirm before replacing |

## Terminal state

The terminal state is: source written under the correct `resources/payloads/<dir>/`, compiled if applicable, dry-run-verified with a benign argument, and documented with `README.md` (always) plus `Build.md` (when compiled / non-trivial).

Hand off the relative path to `write-phase`, and suggest `document-flow` to produce `Flow.md`. Do NOT run live attack behavior, map techniques, author Phase content, or write `Flow.md` yourself.

## Notes

- **Input handoff**: when the approach is unclear or has alternatives, `emulate-technique` is the upstream skill that decides it; this skill builds what it recommends.
- **Output handoff**: when the payload is referenced from a Phase file, give `write-phase` the relative path from `Emulation_Plan/` to `../resources/payloads/<dir>/`. To break the payload's source into behaviors + ATT&CK mapping (`Flow.md`), run `document-flow`.
- Do not run live attack behavior in the dev environment — compile and dry-run only.
- If the payload is already built (user provides source), skip to the place/verify step.
