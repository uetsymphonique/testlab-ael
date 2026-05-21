# Mindmap: Category Labeling Flow

Decision logic summary for `guides/category-assignment.md`.

```mermaid
flowchart TD
    START([Substep to label])
    START --> L0

    L0["🔵 Layer 0 — Establish context\n──────────────────────\nTest type: Detections · Protections\nSurface: EDR · XDR · Protections scope\n→ Determines scope for Question A & Condition 4"]

    L0 --> A

    A{"Question A\nIs artifact on\ndetection surface?"}

    A -- "No\nmail gateway · attacker infra\noutside EDR / XDR scope" --> NC_A

    NC_A(["✗ Not Calibrated\n— scope miss\nfails Condition 4 immediately"])

    A -- Yes --> B

    B{"Question B\nIs substep an implementation detail\nof another Calibrated row?"}

    B -- "Yes" --> NC_B_label["Three forms:
    ① same level — double-count
    ② downstream — mechanism
    ③ dead-end — no scored path"]
    NC_B_label --> NC_B

    NC_B(["✗ Not Calibrated\n— redundancy"])

    B -- "No\n→ primary output" --> C1

    subgraph L2 ["Layer 2 — 4 conditions  ·  all must pass"]
        direction TB
        C1{"C1 Observable\nArtifact exists outside process memory\nin declared telemetry channel?"}
        C1 -- No --> NCL2(["✗ Not Calibrated"])
        C1 -- Yes --> C2

        C2{"C2 Reproducible\nArtifact appears consistently\nacross runs?"}
        C2 -- No --> NCL2
        C2 -- Yes --> C3

        C3{"C3 Independently verifiable\nEvaluator can confirm artifact\nwithout trusting process identity?"}
        C3 -- "No\nin-memory / ghost-dependent artifact" --> NCL2
        C3 -- "Yes\nexternal artifact · non-ghost · persistent system change" --> C4

        C4{"C4 Fair scoring point\nDoes the product under test have opportunity\nto see artifact within its scope?"}
        C4 -- "No\noutside product scope\nEDR / XDR flip" --> NCL2
        C4 -- Yes --> CAL
    end

    CAL(["✅ Calibrated\n— Not Benign  or  Benign"])

    CAL --> SUBLABEL{"Sub-label:\nBenign or Not Benign?"}
    SUBLABEL -- "Adversary action\nin attack context" --> NB(["Calibrated - Not Benign"])
    SUBLABEL -- "Explicitly designed to test FP" --> BN(["Calibrated - Benign"])

    NB --> L3
    BN --> L3

    L3["🟡 Layer 3 — Structural review\n──────────────────────\n① Calibrated ~100% in implant-heavy chain? → re-check C1/C3\n② Two rows sharing same physical event? → double-count, Question B\n③ Not Calibrated but artifact is clear, unrepresented? → re-check Question B\n④ Detection Criteria cannot be written specifically? → suspect C1/C2, downgrade label"]
```

---

## Common Path Summary

| Pattern | Stops at | Result |
|---|---|---|
| Email receipt, attacker infra | Question A | Not Calibrated |
| Ghost process spawns child (in-process output) | Question B dead-end or C3 | Not Calibrated |
| Ghost process creates registry key / scheduled task | Question B No → Layer 2 C3 **Pass** (external artifact) | Calibrated |
| Ghost process connects to attacker IP | Question B No → C3 **Pass** (attribution by endpoint) | Calibrated |
| Cloud API call in EDR-only scope | Question A No or C4 No | Not Calibrated |
| Cloud API call in XDR scope | Question A Yes → Layer 2 → **Pass** | Calibrated |
| Setup step leading to Calibrated downstream | Question B Yes — downstream | Not Calibrated |
| Setup step leading to all-Not-Calibrated chain | Question B Yes — dead-end | Not Calibrated |
