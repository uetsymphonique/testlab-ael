---
name: craft-payload
description: Build, compile, or script a payload for the emulation plan. Handles Go binaries, Python scripts, and PowerShell payloads within dev environment constraints.
model: claude-sonnet-4-6
effort: high
allowed-tools: Read, Write, Edit, Glob, Grep, PowerShell, Bash
---

Build or modify a payload for use in the emulation plan. Keep the dev environment constraints in mind at every step.

## Before starting

Read `plan-for-agent/guides/cli-execution.md` — this is the authoritative source for what toolchains are available in the current dev environment. Do not assume a compiler or runtime is available unless it appears there.

## Gather requirements

Ask the user (combine into one message if multiple questions apply):

1. **What to build**: describe the payload behavior, or reference a technique ID / Phase step
2. **Language / format**: Go binary, Python script, PowerShell, C# — or no preference (you suggest based on available toolchain)
3. **Target context**: where will this run on the lab host? (architecture, OS, privilege level)
4. **Placement**: which plan and directory should the payload go into? (defaults to `testlab-enterprise/windows-adversary-plan/resources/payloads/`)

## Toolchain constraints

From `cli-execution.md`, the dev environment provides:

| Tool | Available | Notes |
|---|---|---|
| Go | ✅ | `go.exe` directly in PATH |
| Python | ✅ | venv at `D:\vcs\ael\venv\` — activate before running |
| PowerShell | ✅ | Available directly |
| cmd | ✅ | Available directly |
| Visual Studio / MSBuild / csc | ⚠️ | Installed but only usable via VS Developer Command Prompt — requires specific invocation |
| g++ | ❌ | Not installed |

If the user requests a language not available above, say so and propose the closest available alternative.

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
| Custom implant / multi-file | `payloads/<project-name>/` with a `README.md` |

5. **README.md**: create one if the payload directory has more than one file, or if build steps are non-obvious. Include: purpose, build command, usage, target context.

## Notes

- Do not run live attack behavior in the dev environment — compile and do a dry-run only
- If the payload is already built (user provides source), skip to the place/verify step
- If the user needs the payload referenced from a Phase file, provide the relative path from `Emulation_Plan/` to `../resources/payloads/<dir>/`
