# Detections Methodology Overview

## Objective

**Detections** scenarios evaluate a security product's ability to detect, record, correlate, and support investigation of adversary behavior chains in an Enterprise environment. The focus is on observing attack behavior through telemetry and detection logic — blocking at execution time is not required.

In the context of this project, Detections are used to build an adversary emulation scenario that serves as a preparation standard for the product before the MITRE ATT&CK Evaluation. Technique scope must align with `testlab-enterprise/mitre-outline/Scenario 1.md` and `Scenario 2.md`.

## Key Characteristics

- Typically a long behavior chain with a clear adversary context, from Initial Access through subsequent tactics such as Execution, Persistence, Defense Evasion, Discovery, Credential Access, Lateral Movement, Collection, Exfiltration, Command and Control, or Impact.
- Each step needs a **Voice Track** explaining adversary intent — not just listing commands.
- **Procedures** describe execution in enough detail to reproduce in the lab, with expected output when needed to confirm a step ran correctly.
- **Reference Tables** are critical: they map tactic, technique ID, technique name, platform, detection criteria, category, red team activity, host/user, source code, and CTI references.
- Detection Criteria should describe observable signals: process, command line, file, registry, network, authentication, cloud event, or relevant telemetry.
- Multiple sequential behaviors may form a single operation flow, because the goal is to evaluate detection capability across a chain and in context.

## 2025 Reference Examples

- `Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md`
- `Enterprise/scattered_spider/Emulation_Plan/Scattered_Spider_Scenario.md`

Use the above only to extract insight on how MITRE presents behavior, phases, procedures, and detection mapping. Do not copy scenarios, payloads, or flows verbatim.

## How to Apply

When writing or editing a Detections scenario:

1. Select techniques from this year's MITRE scope.
2. Consult old Detections scenarios if needed to understand how MITRE interprets specific behaviors.
3. Design an independent flow for `windows-adversary-plan`.
4. Write steps following the standard format: Voice Track, Procedures, Reference Tables.
5. Ensure Detection Criteria are specific, verifiable by telemetry, and not generic descriptions.
