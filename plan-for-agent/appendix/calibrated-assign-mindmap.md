# Mindmap: Luồng gán nhãn Category

Diagram tóm tắt logic ra quyết định của `skills/category-assignment.md`.

```mermaid
flowchart TD
    START([Substep cần gán nhãn])
    START --> L0

    L0["🔵 Lớp 0 — Xác lập context\n──────────────────────\nLoại test: Detections · Protections\nSurface: EDR · XDR · Protections scope\n→ Quyết định scope cho Câu A & Condition 4"]

    L0 --> A

    A{"Câu A\nArtifact có nằm trên\ndetection surface?"}

    A -- "No\nmail gateway · attacker infra\nngoài EDR / XDR scope" --> NC_A

    NC_A(["✗ Not Calibrated\n— scope miss\nfail Condition 4 ngay từ đầu"])

    A -- Yes --> B

    B{"Câu B\nSubstep là implementation detail\ncủa một Calibrated row khác?"}

    B -- "Yes" --> NC_B_label["Ba dạng:
    ① cùng cấp — double-count
    ② downstream — mechanism
    ③ dead-end — no scored path"]
    NC_B_label --> NC_B

    NC_B(["✗ Not Calibrated\n— redundancy"])

    B -- "No\n→ primary output" --> C1

    subgraph L2 ["Lớp 2 — 4 điều kiện  ·  tất cả phải pass"]
        direction TB
        C1{"C1 Observable\nArtifact tồn tại ngoài process memory\ntrong kênh telemetry đã khai báo?"}
        C1 -- No --> NCL2(["✗ Not Calibrated"])
        C1 -- Yes --> C2

        C2{"C2 Reproducible\nArtifact lặp lại được\ngiữa các lần chạy?"}
        C2 -- No --> NCL2
        C2 -- Yes --> C3

        C3{"C3 Independently verifiable\nEvaluator confirm được artifact\nmà không cần trust process identity?"}
        C3 -- "No\nin-memory / ghost-dependent artifact" --> NCL2
        C3 -- "Yes\nexternal artifact · non-ghost · persistent system change" --> C4

        C4{"C4 Fair scoring point\nSản phẩm đang test có cơ hội\nthấy artifact trong scope của nó?"}
        C4 -- "No\nngoài scope sản phẩm\nEDR / XDR flip" --> NCL2
        C4 -- Yes --> CAL
    end

    CAL(["✅ Calibrated\n— Not Benign  hoặc  Benign"])

    CAL --> SUBLABEL{"Sub-label:\nBenign hay Not Benign?"}
    SUBLABEL -- "Adversary action\ntrong attack context" --> NB(["Calibrated - Not Benign"])
    SUBLABEL -- "Thiết kế rõ để test FP" --> BN(["Calibrated - Benign"])

    NB --> L3
    BN --> L3

    L3["🟡 Lớp 3 — Structural review\n──────────────────────\n① Calibrated ~100% trong implant-heavy chain? → rà soát C1/C3\n② Hai row cùng event vật lý? → double-count, Câu B\n③ Not Calibrated nhưng artifact rõ, không ai đại diện? → xem lại Câu B\n④ Detection Criteria không viết cụ thể được? → nghi ngờ C1/C2, hạ nhãn"]
```

---

## Tóm tắt path thường gặp

| Pattern | Dừng tại | Kết quả |
|---|---|---|
| Email receipt, attacker infra | Câu A | Not Calibrated |
| Ghost process spawn child (in-process output) | Câu B dead-end hoặc C3 | Not Calibrated |
| Ghost process tạo registry key / scheduled task | Câu B No → Lớp 2 C3 **Pass** (external artifact) | Calibrated |
| Ghost process connect attacker IP | Câu B No → C3 **Pass** (attribution by endpoint) | Calibrated |
| Cloud API call trong EDR-only scope | Câu A No hoặc C4 No | Not Calibrated |
| Cloud API call trong XDR scope | Câu A Yes → Lớp 2 → **Pass** | Calibrated |
| Setup step dẫn đến Calibrated downstream | Câu B Yes — downstream | Not Calibrated |
| Setup step dẫn đến chain toàn Not Calibrated | Câu B Yes — dead-end | Not Calibrated |
