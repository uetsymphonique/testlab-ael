# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Goal

Build an **adversary emulation plan** aligned with the MITRE ATT&CK Evaluation 2026 to test detection capabilities of security products on a Windows Enterprise environment.

This repo is a fork of the **ATT&CK Evaluations Library** by MITRE. The original content stores past adversary emulation scenarios used as reference to understand how MITRE interprets adversary behavior, structures operation flows, writes procedures and payloads, and maps to ATT&CK.

`Enterprise/` is the **primary insight source** because it contains Enterprise-environment scenarios most relevant to building and refining plans under `testlab-enterprise/`. Do not copy old scenarios; use `Enterprise/` only to extract patterns, understand MITRE's behavior descriptions, phase breakdown, operation flow writing style, and ATT&CK mapping approach. Current scenarios must be designed independently based on the technique scope MITRE published for this year.

When using `Enterprise/` for insight, distinguish between two groups:

- **Detections** — scenarios for evaluating detection, investigation, and description capability. 2025 examples: `Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md`, `Enterprise/scattered_spider/Emulation_Plan/Scattered_Spider_Scenario.md`.
- **Protections** — scenarios for evaluating prevention/blocking per isolated protection tests. 2025 examples: `Enterprise/scattered_spider/Emulation_Plan/Protections_Test_*.md`, `Enterprise/mustang_panda/Emulation_Plan/Protections_Test_4_Scenario.md`, `Enterprise/mustang_panda/Emulation_Plan/Protections_Test_5_Scenario.md`.

Identify which group you are learning patterns from before reading, because objectives, flow depth, and expected outcome presentation differ.

---

## Technique Scope

The technique list in scope for this year's evaluation is published in:

- `testlab-enterprise/mitre-outline/Scenario 1.md` — **Crimeware-as-a-Service** (Windows endpoint-focused, ransomware/wipe endpoint chain)
- `testlab-enterprise/mitre-outline/Scenario 2.md` — **PRC Espionage Group** (Enterprise-wide, cross-platform: Windows + Linux + AWS, APT-style)

These two files are the **mandatory technique scope**. The goal is not to copy an old scenario but to use the published techniques as required scope, then consult `Enterprise/` for insight on how MITRE thinks and presents behavior. When selecting techniques to add to a plan, **always cross-reference against these two files**. Prioritize techniques that appear in scope; do not add out-of-scope techniques unless explicitly asked.

---

## Internal Docs in `plan-for-agent/`

This file is the top-level entry point for agent guidance. When a task touches a specialized topic, read the corresponding file rather than reasoning from scratch.

| File | Read when |
|---|---|
| [`detections-overview.md`](plan-for-agent/detections-overview.md) | Need to distinguish goals, flow depth, and expectations of **Detections** scenarios |
| [`protections-overview.md`](plan-for-agent/protections-overview.md) | Need to design or review **Protections** scenarios and protection outcomes |
| [`emulation-plan-structure.md`](plan-for-agent/emulation-plan-structure.md) | Writing or editing any file in `Emulation_Plan/`: Step structure, Voice Track, Procedures, Reference Tables |
| [`chain-breakdown.md`](plan-for-agent/chain-breakdown.md) | Need a phase/attack chain template when building a new plan or reorganizing flow |
| [`attack-behavior-methodology.md`](plan-for-agent/attack-behavior-methodology.md) | Need deep methodology: behavior, Category, CTI grounding, detection criteria, Detections vs Protections differences |
| [`guides/attack-emulation.md`](plan-for-agent/guides/attack-emulation.md) | Turning an idea or CTI source into a complete attack emulation step |
| [`guides/technique-mapping.md`](plan-for-agent/guides/technique-mapping.md) | Identifying tactic, technique, sub-technique, platform, and verifying scope membership |
| [`guides/category-assignment.md`](plan-for-agent/guides/category-assignment.md) | Assigning `Calibrated` / `Not Calibrated` or checking Detection Criteria |
| [`guides/cli-execution.md`](plan-for-agent/guides/cli-execution.md) | CLI/toolchain constraints of the **dev environment used to compose procedures** — do not use this to infer lab or victim host capabilities |
| [`appendix/calibrated-assign-mindmap.md`](plan-for-agent/appendix/calibrated-assign-mindmap.md) | Visual summary of the Category labeling flow |

**Recommended reading order when writing or editing a Phase:**

1. `detections-overview.md` or `protections-overview.md`
2. `emulation-plan-structure.md`
3. When selecting or verifying behavior: `chain-breakdown.md`, `guides/technique-mapping.md`, `guides/attack-emulation.md`
4. Before finalizing the Reference Table: `guides/category-assignment.md`, then `attack-behavior-methodology.md` for deeper grounding

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

Contains **Phase files** — each is a complete attack scenario following the standard emulation plan format (see `plan-for-agent/emulation-plan-structure.md`). Each Phase corresponds to a sub-attack chain.

Concrete structure may differ between plans. For example, `windows-adversary-plan` does not use a linear `Phase 1.md → Phase N.md` structure but instead splits into parallel **attack path subdirectories**. Always read `summary.md` of the specific plan first to understand its actual structure.

Phase file content: each file is a complete execution plan with Steps containing a **Voice Track** (adversary-perspective behavior narrative), **Procedures** (step-by-step commands, use `☣️` for dangerous steps), and **Reference Tables** (ATT&CK mapping with specific Detection Criteria). See `emulation-plan-structure.md` for the exact format.

| File / Directory | Content |
|---|---|
| `Setup.md` | Lab and operator preparation before running phases |
| `Cleanup.md` | Artifact cleanup after testing |
| `summary.md` | Flow summary or overall plan status |
| `further-reading/` | Reference notes for specific tools/techniques in the plan |

### `resources/payloads/`

Contains all payloads, tools, and exploit PoCs used in the phases. Organized by tool name or technique ID:

| Type | Organization |
|---|---|
| Technique-specific payload | By technique ID if tightly coupled, e.g. `T1189/` |
| Tool or framework | By tool name, e.g. `dnscat2/`, `go-thehash/`, `Invoke-TheHash/` |
| Exploit PoC | By CVE or exploit name, e.g. `CVE-2025-9491_POC/` |
| Custom implant/service | By project/payload name; add README or build notes if multiple files |
| Standalone binary | May go at `payloads/` root if single artifact, but prefer a subdirectory if source, config, or docs are included |

When adding a new payload: place it in a subdirectory by tool name or technique ID. Add `README.md` if the payload has multiple files.

### `resources/setup/`

Contains lab infrastructure docs: instructions for standing up hosts, domains, services, cloud resources, vulnerable applications, or dependencies needed to run the plan. Does not contain payloads or attack procedures.

### Current Plan: `windows-adversary-plan`

Located at `testlab-enterprise/windows-adversary-plan/`. This plan uses **parallel attack path subdirectories** instead of a linear phase structure, both converging at IIS01 SYSTEM C2 before lateral movement:

**`Emulation_Plan/html-smuggling-path/`** — user-driven path (WS01)

| File | Content |
|---|---|
| `Phase 1.md` | Initial Access & C2: HTML smuggling → copy-paste PowerShell → HTA dropper → dnscat2 C2 on WS01 |
| `Cleanup.md` | Artifact cleanup for this path |

**`Emulation_Plan/iis-apppool-escalation-path/`** — server-side path (IIS01 → DC01)

| File | Content |
|---|---|
| `Phase 1.md` | Initial Access & C2: CVE-2025-55182 React RSC RCE → react2shell eval shell → EfsPotato SYSTEM → Herpaderping ghost → dnscat2 C2 on IIS01 (Step 1A: T1620 reflective load; Step 1B: file-based full chain) |
| `Phase 2.md` | Discovery & Credential Access: ReflectDump LSASS → XOR-encrypted `f.elif` → exfil via react2shell → offline decrypt; host & domain recon (WmiAvQuery, whoami, nltest, net group, net view) |
| `Phase 3.md` | Lateral Movement, C2, Persistence: go-thehash.exe PtH → DC01 C$; WMI path (C2 as TESTLAB\Administrator) + SCM path (C2 as SYSTEM); 5 persistence mechanisms (svcbackup, WMI subscription, SYSVOL logon script, API service, registry service) |
| `Cleanup.md` | Artifact cleanup for this path |

**`Emulation_Plan/summary.md`** — overall flow summary and lab topology for both paths.

| Group | Components |
|---|---|
| Payloads/tools | `T1189/`, `CWLHerpaderping/`, `EfsPotato/`, `react2shell-tool/`, `dnscat2/`, `dnscat2.exe`, `go-thehash/`, `Invoke-TheHash/`, `LsassReflectDumping/`, `WmiAvQuery/`, `webshell/`, `windows-service/` |
| Setup | `Windows Server 2022-DC.md`, `Windows Server 2022-IIS.md`, `file-upload-vuln-web/`, `react2shell-vuln-web/` |

---

## Reference Libraries

### Emulation Plan Structure

Path: `plan-for-agent/emulation-plan-structure.md`

Defines the standard format for Phase files: Step structure, Voice Track, Procedures, Reference Tables, `☣️` notation, and Reference Table column format. **Read this before writing or editing any Phase file.**

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

1. Identify whether the task is **Detections** or **Protections**; read the corresponding overview.
2. If building or restructuring a large flow, consult `chain-breakdown.md`.
3. **Select techniques** from Scenario 1 / Scenario 2 scope; use `guides/technique-mapping.md` to map tactic / technique / sub-technique.
4. **Look up theory** in `mitre-knowledge-base/techniques/` and **consult ART** in `atomic-red-team/atomics/` to understand real behavior.
5. To create a new step, use `guides/attack-emulation.md`; to run commands in the dev environment to support procedure writing, check `guides/cli-execution.md`. Do not use this file to infer what tools are available on the lab or victim host.
6. **Build payload** — place in `resources/payloads/<tool-or-technique>/` with a `README.md`.
7. **Write / update Phase file** per `emulation-plan-structure.md`, referencing payloads with relative paths to `../resources/payloads/`.
8. Before finalizing the Reference Table, use `guides/category-assignment.md`; for deeper methodological reasoning, cross-reference `attack-behavior-methodology.md`.
