# Phân tích thiết kế skill: `emulate-technique`

> Bài phân tích trong loạt tài liệu giải thích **lý do thiết kế** của từng skill trong `.claude/skills/`. Mục tiêu: làm rõ vị trí trong pipeline, chứng minh tính hợp lý của các lựa chọn, và nhìn nhận khách quan ưu/nhược điểm. Đây là tài liệu *mô tả lý do* — không phải bản sao SKILL.md (xem trực tiếp `.claude/skills/emulate-technique/SKILL.md` để biết quy tắc thực thi).

---

## 1. Skill này giải bài toán gì

Cho một technique ATT&CK (hoặc một mô tả hành vi), có rất nhiều cách triển khai khác nhau — mỗi cách đòi hỏi quyền hạn, OS, công cụ khác nhau và để lại artifact khác nhau. `emulate-technique` giúp **hiểu technique** và **chọn cách triển khai phù hợp nhất với ràng buộc của người dùng**.

Điểm cần nhấn: đây **không** phải skill hướng-phát-hiện (detection). Nó không sinh Reference Table, không xác định bề mặt phát hiện, không kiểm tra phạm vi. Nó chỉ trả lời một câu: *"với host / quyền / OS này, nên triển khai technique theo cách nào và vì sao?"*

---

## 2. Vị trí trong pipeline

```
[emulate-technique]  →  craft-payload  →  document-flow  →  map-technique → ...
 (khuyến nghị cách)     (build payload)    (Flow.md)
```

- **Đầu vào:** technique ID hoặc mô tả hành vi + ràng buộc (công cụ sẵn có, host/OS/quyền, mục tiêu).
- **Đầu ra:** một *khuyến nghị* theo format chuẩn — approach, rationale, execution context, lệnh đã chỉnh theo bối cảnh, artifact tạo ra. **Không ghi file nào.**
- **Đọc:** `mitre-knowledge-base/techniques/` và `atomic-red-team/atomics/` (ART) — đây là *nguồn tham khảo*, không phải guide phương pháp.

Đây là nhánh **SUPPORT** (hỗ trợ payload). Nó đứng trước `craft-payload`: chọn cách làm xong mới build.

---

## 3. Các lựa chọn thiết kế & lý do

### 3.1. Chỉ khuyến nghị — không build, không map, không sinh bảng
**Lựa chọn:** skill này *recommend-only*. Không Reference Table, không detection surface, không scope check, không ghi payload file.

**Lý do:** mỗi việc đó thuộc về skill khác (`craft-payload` build, `map-technique` map, `write-phase` viết bảng). Giữ ranh giới hẹp khiến skill có một trách nhiệm rõ và bàn giao sạch. Nếu nó "tiện tay làm luôn", nó sẽ lấn sân và phá nguyên tắc column-disjoint của pipeline.

### 3.2. Đọc TOÀN BỘ file ART, không dừng ở test đầu tiên
**Lựa chọn:** bắt buộc đọc hết `<TID>.md` (và `.yaml` cho prereq) trước khi khuyến nghị.

**Lý do:** một technique thường có nhiều biến thể với hồ sơ quyền/OS/artifact rất khác nhau; test đầu tiên *hiếm khi* là lựa chọn tốt nhất cho ràng buộc cụ thể. Đây là loại lỗi "lấy cái đầu tiên gặp" mà Anti-Pattern/Red Flags nhắm thẳng vào.

### 3.3. Không sao chép lệnh ART nguyên văn — và đánh dấu approach tự chế
**Lựa chọn:** ART là *reference*, không phải *source*. Mọi lệnh phải chỉnh theo host/quyền/OS. Nếu tự nghĩ ra cách không có trong ART, **gắn nhãn rõ** là invented và nêu cơ sở.

**Lý do:** sao chép nguyên văn thường lệch bối cảnh thật. Việc bắt gắn nhãn approach tự chế giữ tính minh bạch — người đọc biết phần nào dựa trên ART, phần nào là suy luận.

### 3.4. Ưu tiên tổng hợp hơn chọn lựa
**Lựa chọn:** nếu không test ART nào khớp tốt, *kết hợp* các phần liên quan hoặc thiết kế từ nguyên lý đầu (dựa trên mô tả technique + tooling đã biết) thay vì gượng ép chọn một test.

**Lý do:** "không có test ART" không phải ngõ cụt. Bài toán là phục vụ ràng buộc của người dùng, không phải vừa khít thư viện ART.

### 3.5. Hỏi yêu cầu trong MỘT tin nhắn
**Lựa chọn:** gom 4 câu hỏi (technique, ràng buộc công cụ, bối cảnh thực thi, mục tiêu) vào một lượt; bỏ qua câu nào người dùng đã trả lời.

**Lý do:** giảm ma sát qua-lại. Đây là pattern chung của các skill có giai đoạn thu thập yêu cầu.

---

## 4. Luồng nội bộ (tóm tắt)

1. **Hiểu technique** — nếu đầu vào là mô tả, tra `mitre-knowledge-base` để xác định ID/sub-technique và cơ chế kỹ thuật.
2. **Khảo sát biến thể ART** — đọc *toàn bộ* `<TID>.md`, ghi với mỗi test: công cụ/API, quyền/OS yêu cầu, artifact tạo ra.
3. **Khuyến nghị** — lọc biến thể theo ràng buộc, chọn cái khớp nhất (hoặc tổng hợp), nêu rõ *vì sao cái này hơn các phương án bị loại*.

Output theo format cố định, kết thúc bằng "No Reference Table. No detection surface. No scope check."

---

## 5. Đánh giá khách quan

### Ưu điểm
- **Ranh giới sạch** — recommend-only khiến skill dễ kiểm soát và bàn giao rõ sang `craft-payload`.
- **Chống lỗi "lấy cái đầu tiên"** — bắt đọc hết ART là cơ chế đơn giản mà hiệu quả.
- **Minh bạch nguồn** — approach tự chế phải gắn nhãn, nên người đọc đánh giá được độ tin cậy.
- **Tổng hợp được khuyến khích** — không bị giam trong thư viện ART, xử lý được technique chưa có atomic test.

### Nhược điểm / đánh đổi
- **Khuyến nghị mang tính chủ quan** — "khớp nhất" phụ thuộc phán đoán; hai lần chạy có thể ra hai approach khác nhau cho cùng ràng buộc.
- **Phụ thuộc độ phủ của ART/KB** — với technique ít tài liệu, chất lượng khuyến nghị giảm và phần "invented" tăng.
- **Thêm một chặng bàn giao** — recommend-only nghĩa là phải sang `craft-payload` mới có artifact; với ca đơn giản, đây là một bước trung gian có thể thấy thừa.
- **Không có cơ chế kiểm chứng** — vì không build/run, tính khả thi của lệnh khuyến nghị chỉ được xác nhận ở bước sau (lab), không phải ở đây.

### Khi nào dễ sai nhất
- Dừng ở test ART đầu tiên thay vì đọc hết file.
- Chép lệnh nguyên văn mà quên chỉnh host/quyền/OS.
- Lấn sang build payload / viết bảng (vi phạm ranh giới recommend-only).
- Tự chế approach mà quên gắn nhãn invented + cơ sở.

---

## 6. Liên hệ
- Quy tắc thực thi: `.claude/skills/emulate-technique/SKILL.md`
- Nguồn tham khảo: `mitre-knowledge-base/techniques/`, `atomic-red-team/atomics/<TID>/`
- Skill liền kề: `craft-payload` (downstream — build approach đã chọn)
