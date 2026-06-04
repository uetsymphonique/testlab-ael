# Mindmap: Category Labeling Flow

Decision logic summary for the `/assign-category` workflow.

```mermaid
flowchart TD
    START([Row to label])
    START --> L0

    L0["Layer 0: Establish context\nDet / Prot · Default surface: Scenario 1 Adv EDR\nBasic EDR: declare explicitly\nOther: Scenario 2 XDR / Custom"]

    L0 --> PQ

    PQ["Primary question\nIs a vendor miss attributable to the vendor?"]

    PQ --> SKETCH

    SKETCH["Sketch execution chain\nTemporal order · artifact to consumer\nUse when applying Q-B"]

    SKETCH --> READ

    READ["Read Detection Criteria first\nConcrete signal written → C1-C3 already hold\nN/A — Cx: reason → fails Cx directly\nNever edit criteria"]

    READ --> QA

    QA{"Q-A: Artifact on declared surface?"}

    QA -- No --> NC_A(["Not Calibrated — scope miss"])
    QA -- Yes --> QB

    QB{"Q-B: Implementation detail\nof another Calibrated row?\nIdentical criteria = double-count"}

    QB -- "Yes\ndouble-count / mechanism / dead-end" --> NC_B(["Not Calibrated — redundancy"])
    QB -- "No — primary output" --> CRITQ

    CRITQ{"Criteria: concrete signal written?"}

    CRITQ -- "N/A — Cx documented" --> NCL2(["Not Calibrated — Cx fails"])
    CRITQ -- "Concrete — C1-C3 hold" --> C4

    C4{"C4: Fair scoring point\nfor declared surface?"}
    C4 -- No --> NCL2
    C4 -- Yes --> CAL(["Calibrated - Not Benign"])

    CAL --> COMP
    NCL2 --> COMP
    NC_A --> COMP
    NC_B --> COMP

    COMP["Completeness check\nAll-Not-Cal step? justify.\nNo consecutive 0-Calibrated steps."]

    COMP --> L3

    L3["Layer 3: Structural signals\n1. 100% Calibrated in implant chain? re-check C1/C3\n2. Two rows, same physical event? Q-B double-count\n3. Clear artifact unrepresented? re-check Q-B\n4. N/A + Calibrated label? contradiction\n5. Value-specific IOC only? flag /write-detection-criteria\n6. Concrete criteria + Not Cal + no reason? re-label\n7. Same TechID, diff subject? verify different event"]

    L3 --> HANDOFF

    HANDOFF(["Labeling complete — run /assign-acw"])
```

---

## Common Path Summary

| Pattern | Stops at | Result |
|---|---|---|
| Email receipt, attacker infra | Question A | Not Calibrated |
| Criteria documents `N/A — C3: in-memory artifact` | Criteria quality check | Not Calibrated |
| Ghost process spawns child (in-process output) | Q-B dead-end or N/A — C3 | Not Calibrated |
| Ghost process creates registry key / scheduled task | Q-B No → C4 Pass (external artifact) | Calibrated |
| Ghost process connects to attacker IP | Q-B No → C4 Pass (attribution by endpoint) | Calibrated |
| Cloud API call in EDR-only scope | Question A No or C4 No | Not Calibrated |
| Cloud API call in XDR scope | Question A Yes → C4 Pass | Calibrated |
| Setup step leading to Calibrated downstream | Question B Yes — downstream | Not Calibrated |
| Setup step leading to all-Not-Calibrated chain | Question B Yes — dead-end | Not Calibrated |

---

## Labels in scope

- `Calibrated - Not Benign` — concrete signal, C1–C3 hold, C4 passes
- `Not Calibrated - Not Benign` — fails any condition, scope miss, or redundancy
- `Calibrated - Benign` — **out of scope** for this workflow (false-positive threshold test, handled separately)

> The Calibrated label is **independent of ACW**. A technique's importance in the attack chain (Critical / High / Medium / Low) never makes a row more or less scoreable — judge calibration on observability / reproducibility / verifiability only.
