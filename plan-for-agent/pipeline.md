# Skill Pipeline Map

Single source of truth for **how the skills chain together** and **which guide backs each skill**.

The repo runs a deliberate **two-layer architecture**, and the two layers live in two directories by necessity — this is not accidental sprawl:

- **Execution layer** — `.claude/skills/<name>/SKILL.md`. Thin wrappers: when to run, inputs to gather, step order, boundaries, handoffs. Must live under `.claude/skills/` so the harness discovers them as slash commands.
- **Knowledge layer** — `plan-for-agent/`. The methodology each skill defers to (rules, tables, processes). Read by skills **and** by humans **and** by Claude when working without a skill. A guide may back several skills (`behavior-breakdown.md` backs three), so it cannot be co-located inside any one skill directory.

Skills **never restate** guide content — they link to it, so the knowledge lives once and cannot drift.

---

## Pipeline flow (DAG)

```
SUPPORT — payload sub-branch                INGEST — unstructured input
  emulate-technique  (recommend approach)     raw code / commands / CTI
        │                                            │
        ▼                                            ▼
  craft-payload  (build binary +              extract-behaviors  (behavior list;
                  README.md / Build.md)         optionally persist Phase skeleton)
        │                                            │
        ▼                                            │
  document-flow  (Flow.md skeleton,                  │
                  Tactic/TID = —)                    │
        │                                            │
        └───────────────┬────────────────────────────┘
                        │            FORWARD DESIGN — from scope technique
                        │              write-phase  (Phase skeleton: behavior rows,
                        │                            Tactic/TID = —, Category/Criteria = TBD)
                        │                                  │
                        ▼                                  ▼
                  map-technique  (fill Tactic / TID on whichever skeleton: Flow.md or Phase)
                                                           │
                                                           ▼
                  write-detection-criteria  (fill Detection Criteria for EVERY row:
                                             concrete signal, or documented N/A — <Cx> absence)
                                             ── the STABLE EVIDENCE base ──
                                                           │
                                                           ▼
                          assign-category  (READ the criteria → label Calibrated / Not Calibrated)
                                             ── the HEURISTIC verdict, re-runnable ──
                                                           │
                                                           ▼  (Phase table flattened to a scoring CSV)
                                                     assign-acw  (fill ACW column, per behavior row)
```

> **Criteria before Category — on purpose.** Detection Criteria is the stable evidence base; Category is the heuristic verdict read off it. Writing criteria first (for *every* row, documenting absences) removes the hallucination risk of `assign-category` *imagining* whether a criteria could be written, and lets the label be re-derived when the heuristic changes — without touching criteria.

**Entry points** (three ways a behavior skeleton is born):
- `write-phase` — forward design from an in-scope technique.
- `extract-behaviors` — ingest unstructured input (chain description / commands / source).
- `document-flow` — ingest a payload's **source code**, persisted as a co-located `Flow.md`.

All three converge on `map-technique`, then the Phase path runs **criteria → category → acw**. `Flow.md` is a neutral per-payload analysis that *feeds* the Phase rows and the downstream criteria/category passes (it is not itself scored).

---

## Skill ↔ guide ↔ artifact

| Skill | Reads (knowledge layer) | Writes (artifact / column it owns) |
|---|---|---|
| `emulate-technique` | `mitre-knowledge-base/`, `atomic-red-team/` (not a guide) | — (recommends only) |
| `craft-payload` | `guides/cli-execution.md` | payload source, `README.md`, `Build.md` |
| `document-flow` | `guides/behavior-breakdown.md` | `Flow.md` (behavior rows + edges + context; `Tactic/TID = —`) |
| `extract-behaviors` | `guides/behavior-breakdown.md` | behavior list (optionally Phase skeleton rows) |
| `write-phase` | `emulation-plan-structure.md`, `detections-overview.md` / `protections-overview.md`, `guides/behavior-breakdown.md` | Phase file skeleton |
| `map-technique` | `guides/technique-mapping.md` | `Tactic` / `Technique ID` / `Technique Name` columns |
| `write-detection-criteria` | `guides/detection-criteria.md` | `Detection Criteria` column (every row: concrete signal or documented `N/A — <Cx>` absence) |
| `assign-category` | `guides/category-assignment.md`, `attack-behavior-methodology.md`, `appendix/calibrated-assign-mindmap.md`, **+ the written `Detection Criteria` column as evidence** | `Category` column |
| `assign-acw` | `testlab-enterprise/mitre-outline/Scoring Specification.md` (not a guide) | `ACW` column (scoring CSV) |

**Write-ownership is column-disjoint:** no skill edits a column another skill owns. `document-flow` owns behavior text + produces→consumes edges + baseline context; `map-technique` owns the mapping columns; `assign-category` owns Category; `write-detection-criteria` owns Detection Criteria; `assign-acw` owns ACW. This is what lets the same file pass through several skills without clobbering.

**Guides with no skill wrapper** (used directly per the CLAUDE.md workflow, not via a slash command): `guides/attack-emulation.md`, `chain-breakdown.md`.
