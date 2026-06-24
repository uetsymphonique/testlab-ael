# Skill Workflow — Vai trò và luồng chạy

Hai luồng tách biệt: **Procedure-Crafting Loop** (chạy lặp theo từng technique/behavior) và **Scoring Pass** (chạy một lần sau khi toàn bộ plan hoàn chỉnh).

---

## Procedure-Crafting Loop

```mermaid
flowchart TD
    INPUT([Technique list / Behavior description])

    subgraph A["Stage A — Specification"]
        SPEC[Brainstorm + research\nconversation / emulate-technique]
    end

    subgraph B["Stage B — Crafting"]
        direction TB
        CMD[Command / short script\nconversation hoặc emulate-technique]
        CP[craft-payload]
        DF[document-flow]
        FLOW[(Flow.md)]
        CP -->|phức tạp| DF --> FLOW
    end

    subgraph C["Stage C — Behavior Extraction  ·  GATE"]
        direction TB
        EB[extract-behaviors]
        FP{Flow.md\ntồn tại?}
        EB --> FP
        FP -->|có| USEFM[dùng Flow.md\nlàm fast path]
        FP -->|không| DIRECT[trace trực tiếp\ntừ input]
    end

    BLIST[/"ordered behavior list — &lt;actor&gt; &lt;action&gt; &lt;target&gt; [class]"/]

    subgraph D["Stage D — Phase Writing"]
        WP[write-phase]
        FILLS["Điền ngay: Summary · Platform · Hosts · Users · Red Team Activity · Source Code Links\nPlaceholder: Tactic — · TID — · Detection Criteria TBD · Category TBD"]
        WP --> FILLS
    end

    subgraph E["Stage E — Reference Table Passes"]
        direction TB
        MT[map-technique\nfills Tactic / TID / Name]
        WDC[write-detection-criteria\nfills Detection Criteria]
        AC[assign-category\nfills Category / Calibration Reason]
        MT --> WDC --> AC
    end

    INPUT --> A --> B
    CMD --> EB
    B --> EB
    FLOW -.->|source code path| FP
    USEFM --> BLIST
    DIRECT --> BLIST
    BLIST --> WP
    WP --> E
```

---

## Scoring Pass

Chạy độc lập một lần sau khi toàn bộ plan hoàn chỉnh — không thuộc procedure-crafting loop.

```mermaid
flowchart LR
    CSV([Full plan CSV]) & SUM([summary.md]) --> ACW[assign-acw]
    ACW --> OUT[/ACW column per behavior row\nCritical · High · Medium · Low/]
```

---

## Skill Reference

| Skill | Vai trò | Stage |
|---|---|---|
| `emulate-technique` | Khảo sát variant kỹ thuật, đề xuất hướng triển khai | A / B |
| `craft-payload` | Build và verify payload (Go / Python / C# / PowerShell) | B |
| `document-flow` | Trace source code → `Flow.md` (behavior list + artifact map + produces→consumes) | B — complex payload only |
| `extract-behaviors` | Chuyển mọi input thành ordered atomic behavior list; check `Flow.md` trước nếu input là source code | C |
| `write-phase` | Viết Phase file skeleton từ behavior list | D |
| `map-technique` | Điền Tactic / Technique ID / Technique Name vào Reference Table | E |
| `write-detection-criteria` | Viết Detection Criteria cho mọi row | E |
| `assign-category` | Gán Calibrated / Not Calibrated bằng cách đọc Detection Criteria | E |
| `assign-acw` | Gán ACW (chain-role weight) per behavior trên toàn bộ plan CSV | Scoring — độc lập |
