# Phân tích thiết kế skill: `craft-payload`

> Bài phân tích trong loạt tài liệu giải thích **lý do thiết kế** của từng skill trong `.claude/skills/`. Mục tiêu: làm rõ vị trí trong pipeline, chứng minh tính hợp lý của các lựa chọn, và nhìn nhận khách quan ưu/nhược điểm. Đây là tài liệu *mô tả lý do* — không phải bản sao SKILL.md (xem `.claude/skills/craft-payload/SKILL.md`).

---

## 1. Skill này giải bài toán gì

Sau khi đã chọn cách triển khai (qua `emulate-technique`), cần **biến approach thành một artifact chạy được** — Go binary, Python/PowerShell script, C# — rồi đặt vào `resources/payloads/` theo đúng quy ước thư mục của plan.

`craft-payload` nhận một **approach đã quyết định** và sản xuất artifact + tài liệu kèm theo. Nó *không* chọn biến thể technique, *không* map ATT&CK, *không* viết nội dung Phase.

---

## 2. Vị trí trong pipeline

```
emulate-technique  →  [craft-payload]  →  document-flow  →  map-technique → ...
 (chọn approach)       (build + README/Build)  (Flow.md)
```

- **Đầu vào:** approach đã chốt + yêu cầu (ngôn ngữ/định dạng, bối cảnh target, nơi đặt).
- **Đầu ra:** mã nguồn payload đã compile (nếu cần), đã dry-run kiểm tra, + `README.md` (luôn có) và `Build.md` (khi compile/build không tầm thường).
- **Đọc:** `plan-for-agent/guides/cli-execution.md` — nguồn *duy nhất và có thẩm quyền* về toolchain có trong dev environment.

---

## 3. Các lựa chọn thiết kế & lý do

### 3.1. KHÔNG chạy hành vi tấn công thật trong dev environment
**Lựa chọn:** chỉ compile và dry-run (`--help` / tham số vô hại). Tuyệt đối không kích hoạt hành vi tấn công thật.

**Lý do:** dev environment là nơi *soạn* payload, **không phải** lab/victim host. Chạy payload thật ở đây là sai lầm *không thể hoàn tác* — và là rủi ro lớn nhất skill này tồn tại để chặn. Đây là Hard Gate #1, được nhắc lại ở Anti-Pattern ("để tôi chạy thử một lần cho chắc") vì đây chính là cách hợp lý hóa dẫn tới tai nạn.

### 3.2. Chỉ dùng toolchain trong `cli-execution.md`, không giả định
**Lựa chọn:** không giả định có sẵn compiler/runtime. Nếu người dùng yêu cầu ngôn ngữ không có trong guide → nói thẳng và đề xuất phương án gần nhất, **không thay thầm**.

**Lý do:** một nguồn sự thật duy nhất cho năng lực dev-env. Skill *không restate* nội dung guide (tránh tạo nguồn thứ hai gây drift). Quan trọng: `cli-execution.md` mô tả *dev environment*, **không** phải năng lực của lab/victim host — không được suy ngược.

### 3.3. Approach phải được quyết định TRƯỚC
**Lựa chọn:** skill này nhận approach *đã chốt*. Nếu chưa chọn biến thể → dừng và chạy `emulate-technique` trước.

**Lý do:** chọn approach là việc của `emulate-technique`. Build nhầm biến thể làm lãng phí toàn bộ artifact. Tách "chọn" khỏi "build" giữ mỗi skill một trách nhiệm.

### 3.4. Tài liệu tách trách nhiệm: README / Build / Flow
**Lựa chọn:** tối đa ba file tài liệu, mỗi file một trách nhiệm — `README.md` (cái gì/tại sao), `Build.md` (build thế nào), `Flow.md` (cơ chế nội bộ + ATT&CK mapping). **`Flow.md` do `document-flow` viết, không viết ở đây.**

**Lý do:** không cho nội dung chồng lấn để tránh hai nguồn drift nhau. README giữ ở mức what/why; cơ chế + mapping nằm ở Flow.md (skill khác sở hữu).

### 3.5. Kiểm tra provenance trước khi ghi đè
**Lựa chọn:** một Red Flag nhắc: nếu payload đã tồn tại mà *không phải* do phiên này tạo, xác nhận trước khi thay.

**Lý do:** đây là phiên bản nhẹ của nguyên tắc "xác nhận trước hành động khó hoàn tác". (Lưu ý: bộ tuning của repo cố ý *không* thêm cổng xác nhận destructive nặng — chỉ dừng ở mức nhắc provenance.)

---

## 4. Luồng nội bộ (tóm tắt)

1. **Đọc `cli-execution.md`** xác nhận toolchain.
2. **Thu thập yêu cầu** (gom một tin nhắn): build gì, ngôn ngữ/định dạng, bối cảnh target, nơi đặt.
3. **Viết mã nguồn** → **Compile** (nếu cần, theo toolchain guide) → **Verify** bằng dry-run vô hại → **Đặt output** đúng thư mục con (`<TID>/`, `<tool-name>/`, `<CVE>/`, hoặc `<project>/`).
4. **Viết tài liệu**: `README.md` luôn có; `Build.md` khi compile/non-trivial. `Flow.md` để dành cho `document-flow`.

---

## 5. Đánh giá khách quan

### Ưu điểm
- **Chặn được sai lầm không hoàn tác** — quy tắc "no live attack in dev env" là rào chắn an toàn rõ ràng và đáng giá nhất.
- **Một nguồn toolchain duy nhất** — trỏ về `cli-execution.md` thay vì liệt kê lại, nên không drift khi dev-env đổi.
- **Tài liệu không chồng lấn** — README/Build/Flow phân vai sạch, giảm trùng lặp và mâu thuẫn.
- **Bàn giao rõ** — vào từ `emulate-technique`, ra sang `write-phase`/`document-flow` bằng đường dẫn tương đối.

### Nhược điểm / đánh đổi
- **Không kiểm chứng được hành vi thật trong dev-env** — chỉ dry-run, nên độ tin cậy "payload thực sự hoạt động đúng" bị hoãn sang lab. Đây là cái giá *cố ý* của an toàn.
- **Danh sách toolchain cứng** — nếu người dùng cần ngôn ngữ ngoài guide, skill chỉ đề xuất thay thế chứ không mở rộng; linh hoạt đổi lấy tính nhất quán.
- **Nhiều chặng bàn giao** — approach (emulate) → build (đây) → Flow (document-flow) → rows (write-phase). Với payload đơn giản, chuỗi này có thể thấy nặng.
- **Cổng provenance nhẹ** — chỉ *nhắc*, không *chặn cứng* ghi đè; nếu model bỏ qua nhắc nhở, vẫn có thể ghi đè artifact cũ.

### Khi nào dễ sai nhất
- "Chạy thử một lần cho chắc" → kích hoạt hành vi thật trong dev-env (lỗi nghiêm trọng nhất).
- Giả định Go/C# có sẵn thay vì xác nhận trong `cli-execution.md`.
- Bắt đầu build khi biến thể chưa được chọn.
- Viết cơ chế + mapping vào README thay vì để Flow.md.

---

## 6. Liên hệ
- Quy tắc thực thi: `.claude/skills/craft-payload/SKILL.md`
- Nguồn toolchain: `plan-for-agent/guides/cli-execution.md`
- Skill liền kề: `emulate-technique` (upstream — chọn approach), `document-flow` (viết `Flow.md`), `write-phase` (tham chiếu payload từ Phase)
