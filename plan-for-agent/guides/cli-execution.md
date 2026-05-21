# Guide: Dev CLI Execution Constraints

This file describes the **development environment used to compose, test, or support procedure writing in this repo**.

This is **not** a description of the test execution environment, victim host, attack host, or lab target. When writing `Procedures` in the emulation plan, do not infer that a tool is available on the test machine just because it is or is not listed here. Lab capabilities must be derived from `resources/setup/`, Phase file content, or plan-specific setup documentation.

## Available in the current dev environment

### Code interpreters

- Go via `go.exe`
- Python virtual environment at `D:\vcs\ael\venv\`

### Command execution

- PowerShell
- `cmd`

## Not directly available in the current dev environment

- Visual Studio Build Tools — installed but only usable inside the Visual Studio Developer Command Prompt
- `g++` — not installed
