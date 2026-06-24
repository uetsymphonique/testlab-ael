# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Goal

Build an **adversary emulation plan** aligned with the MITRE ATT&CK Evaluation 2026 to test detection capabilities of security products on a Windows Enterprise environment.

This repo is a fork of the **ATT&CK Evaluations Library** by MITRE. The original content stores past adversary emulation scenarios used as reference to understand how MITRE interprets adversary behavior, structures operation flows, writes procedures and payloads, and maps to ATT&CK.

`ael/Enterprise/` is the **primary insight source** because it contains Enterprise-environment scenarios most relevant to building and refining plans under `testlab-enterprise/`. Do not copy old scenarios; use `ael/Enterprise/` only to extract patterns, understand MITRE's behavior descriptions, phase breakdown, operation flow writing style, and ATT&CK mapping approach. Current scenarios must be designed independently based on the technique scope MITRE published for this year.

When using `ael/Enterprise/` for insight, distinguish between two groups:

- **Detections** — scenarios for evaluating detection, investigation, and description capability. 2025 examples: `ael/Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md`, `ael/Enterprise/scattered_spider/Emulation_Plan/Scattered_Spider_Scenario.md`.
- **Protections** — scenarios for evaluating prevention/blocking per isolated protection tests. 2025 examples: `ael/Enterprise/scattered_spider/Emulation_Plan/Protections_Test_*.md`, `ael/Enterprise/mustang_panda/Emulation_Plan/Protections_Test_4_Scenario.md`, `ael/Enterprise/mustang_panda/Emulation_Plan/Protections_Test_5_Scenario.md`.

Identify which group you are learning patterns from before reading, because objectives, flow depth, and expected outcome presentation differ.

---

## Technique Scope

The technique list in scope for this year's evaluation is published in:

- `testlab-enterprise/mitre-outline/Scenario 1.md` — **Crimeware-as-a-Service** (Windows endpoint-focused, ransomware/wipe endpoint chain)
- `testlab-enterprise/mitre-outline/Scenario 2.md` — **PRC Espionage Group** (Enterprise-wide, cross-platform: Windows + Linux + AWS, APT-style)

These two files are the **mandatory technique scope**. The goal is not to copy an old scenario but to use the published techniques as required scope, then consult `ael/Enterprise/` for insight on how MITRE thinks and presents behavior. When selecting techniques to add to a plan, **always cross-reference against these two files**. Prioritize techniques that appear in scope; do not add out-of-scope techniques unless explicitly asked.

---

## Workspace Plans in `testlab-enterprise/`

All adversary emulation plans live under `testlab-enterprise/`. Each plan is an independent peer directory:

- `testlab-enterprise/windows-adversary-plan/` — current Windows Enterprise plan
- Additional plans may be added as `testlab-enterprise/<plan-name>/`

When working, identify the correct `<plan-name>` from the user's request or the open file. Do not hard-code `windows-adversary-plan` if the task concerns a different plan.

### Standard Plan Structure

```
<plan-name>/
├── Emulation_Plan/
│   ├── Phase 1.md → Phase N.md   (or attack path subdirectories)
│   ├── Setup.md
│   ├── Cleanup.md
│   ├── summary.md
│   └── further-reading/
└── resources/
    ├── payloads/
    │   ├── <technique-id>/
    │   ├── <tool-or-framework>/
    │   ├── <exploit-or-cve>/
    │   └── <standalone-binary>
    └── setup/
        ├── <host-or-service-setup>.md
        ├── <vulnerable-app>/
        └── <environment-dependency>/
```

Each plan does not need every directory from the start, but keep these functional groups as the plan grows so agents and operators can find documentation, payloads, setup, and cleanup reliably.

### `Emulation_Plan/`

Contains **Phase files** — each is a complete attack scenario following the standard emulation plan format. Each Phase corresponds to a sub-attack chain.

Concrete structure may differ between plans. For example, `windows-adversary-plan` does not use a linear `Phase 1.md → Phase N.md` structure but instead splits into parallel **attack path subdirectories**. Always read `summary.md` of the specific plan first to understand its actual structure.

Phase file content: each file is a complete execution plan with Steps containing a **Voice Track** (adversary-perspective behavior narrative), **Procedures** (step-by-step commands, use `☣️` for dangerous steps), and **Reference Tables** (ATT&CK mapping with specific Detection Criteria).

| File / Directory | Content |
|---|---|
| `Setup.md` | Lab and operator preparation before running phases |
| `Cleanup.md` | Artifact cleanup after testing |
| `summary.md` | Flow summary or overall plan status |
| `further-reading/` | Reference notes for specific tools/techniques in the plan |

### `resources/payloads/`

Organized by tool name or technique ID (e.g. `dnscat2/`, `T1189/`, `CVE-2025-9491_POC/`). Add `README.md` when a payload has multiple files.

### `resources/setup/`

Contains lab infrastructure docs: instructions for standing up hosts, domains, services, cloud resources, vulnerable applications, or dependencies needed to run the plan. Does not contain payloads or attack procedures.

### Current Plan: `windows-adversary-plan`

Located at `testlab-enterprise/windows-adversary-plan/`. Uses **parallel attack path subdirectories** instead of a linear phase structure. Read `Emulation_Plan/summary.md` for the full attack flow, lab topology, and phase breakdown across all three paths.

---

## Reference Libraries

### MITRE Knowledge Base

Path: `mitre-knowledge-base/techniques/`

Per-tactic technique theory. Use when you need technique descriptions, sub-techniques, detection notes, and mitigations before adding to a plan.

| File | Tactic |
|---|---|
| `TA0001-initial-access.md` | Initial Access |
| `TA0002-execution.md` | Execution |
| `TA0003-persistence.md` | Persistence |
| `TA0004-privilege-escalation.md` | Privilege Escalation |
| `TA0005-defense-evasion.md` | Defense Evasion |
| `TA0006-credential-access.md` | Credential Access |
| `TA0007-discovery.md` | Discovery |
| `TA0008-lateral-movement.md` | Lateral Movement |
| `TA0009-collection.md` | Collection |
| `TA0010-exfiltration.md` | Exfiltration |
| `TA0011-command-and-control.md` | Command and Control |
| `TA0040-impact.md` | Impact |
| `TA0043-reconnaissance.md` | Reconnaissance |

### Atomic Red Team (ART)

Path: `atomic-red-team/atomics/`

Open-source attack behavior simulation library. Each subdirectory corresponds to a technique ID (e.g. `T1003.001/`), containing:
- `T<ID>.md` — atomic tests with concrete commands
- `T<ID>.yaml` — machine-readable test definitions
- `src/` — supporting scripts (if present)

Use when: needing practical technique implementation, finding example commands, or understanding technical behavior.

---

## Technique Coverage Check

Run from `testlab-enterprise/mitre-outline/`:

```bash
# Mark techniques from a folder of Phase files into a scope file
python check.py --scope "Scenario 1.md" --folder ../windows-adversary-plan/Emulation_Plan/iis-apppool-escalation-path

# Mark from specific plan files
python check.py --scope "Scenario 1.md" Phase1.md Phase2.md

# Reset all marks in a scope file
python check.py --reset --scope "Scenario 1.md"
```

`check.py` reads `Reference Tables` from Phase `.md` files, checks technique IDs against the scope checklist, and writes out-of-scope entries to `<scope>_out_of_scope.csv`.

---

## Workflow

> The workflow below is a reference. Specific user requests may require a different approach.

1. Identify whether the task is **Detections** or **Protections**; read `plan-for-agent/detections-overview.md` or `plan-for-agent/protections-overview.md`.
2. If building or restructuring a large flow, consult `plan-for-agent/chain-breakdown.md`.
3. **Select techniques** from Scenario 1 / Scenario 2 scope; use the `/extract-behaviors`, `/map-technique`, and `/write-phase` skills to process unstructured input into a Phase file.
4. **Look up theory** in `mitre-knowledge-base/techniques/` and **consult ART** in `atomic-red-team/atomics/` to understand real behavior.
5. **Build payload** — place in `resources/payloads/<tool-or-technique>/` with a `README.md`.
6. **Write / update Phase file** using the `/write-phase` skill; reference payloads with relative paths to `../resources/payloads/`.
7. Before finalizing the Reference Table: run `/write-detection-criteria` to write Detection Criteria for **every** row first, then run `/assign-category` to label rows.
