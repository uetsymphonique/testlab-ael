# Phân tích thiết kế các skill — Mục lục

Loạt tài liệu giải thích **lý do thiết kế** của từng skill trong `.claude/skills/`. Mỗi bài làm rõ: skill giải bài toán gì, vị trí trong pipeline, các lựa chọn thiết kế & lý do (kèm đánh đổi), luồng nội bộ, và **đánh giá khách quan** (ưu điểm / nhược điểm / khi nào dễ sai).

Đây là tầng *mô tả lý do* — không thay thế `SKILL.md` (quy tắc thực thi) hay các guide trong `plan-for-agent/` (phương pháp). Khi đọc, ghép ba tầng: bài phân tích (vì sao) → SKILL.md (làm gì) → guide (làm thế nào).

> Bối cảnh kiến trúc hai tầng và DAG đầy đủ: `plan-for-agent/pipeline.md`.

## Đọc theo thứ tự pipeline

**Nhánh SUPPORT (payload):**
1. [`emulate-technique`](skill-analysis-emulate-technique.md) — khuyến nghị cách triển khai technique
2. [`craft-payload`](skill-analysis-craft-payload.md) — build artifact + README/Build
3. [`document-flow`](skill-analysis-document-flow.md) — trace mã nguồn → `Flow.md`

**Nhánh INGEST (đầu vào không cấu trúc):**
4. [`extract-behaviors`](skill-analysis-extract-behaviors.md) — danh sách hành vi nguyên tử

**Nhánh FORWARD DESIGN (từ technique trong scope):**
5. [`write-phase`](skill-analysis-write-phase.md) — Phase skeleton theo `phase-template.md`

**Hội tụ — chuỗi gán nhãn per-row:**
6. [`map-technique`](skill-analysis-map-technique.md) — điền Tactic / Technique ID / Name
7. [`write-detection-criteria`](skill-analysis-write-detection-criteria.md) — nền bằng chứng (mọi dòng)
8. [`assign-category`](skill-analysis-assign-category.md) — verdict Calibrated / Not Calibrated *(bài pilot)*
9. [`assign-acw`](skill-analysis-assign-acw.md) — trọng số chuỗi tấn công (per-row)

## Tài liệu liên quan trong appendix
- [`calibrated-assign-mindmap.md`](calibrated-assign-mindmap.md) — sơ đồ quyết định của `assign-category` (kèm giải thích tiếng Việt)

## Vài chủ đề xuyên suốt (đọc kèm sẽ thấy lặp lại có chủ ý)
- **Column-disjoint write ownership** — không skill nào ghi đè cột của skill khác; nền tảng để một file đi qua nhiều skill. Rõ nhất ở `map-technique`, `write-detection-criteria`, `assign-category`, `assign-acw`.
- **Criteria trước, Category sau** — tách bằng chứng ổn định khỏi verdict heuristic để chống ảo giác và cho phép re-label. Xem cặp `write-detection-criteria` ↔ `assign-category`.
- **ACW độc lập với Category** — hai trục không chi phối nhau; cả 4 tổ hợp hợp lệ. Xem `assign-acw` và `assign-category`.
- **Skeleton + cổng kiểm chứng** — nhiều skill chỉ ra khung (placeholder `—`/`TBD`) rồi dừng cho người duyệt trước khi pass sau chạy. Xem `write-phase`, `document-flow`.
- **Defer về guide, không restate** — granularity sống một chỗ trong `behavior-breakdown.md`; ba skill cùng trỏ về để không drift.
