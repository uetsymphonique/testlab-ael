# Phân tích thiết kế skill: `document-flow`

> Bài phân tích trong loạt tài liệu giải thích **lý do thiết kế** của từng skill trong `.claude/skills/`. Mục tiêu: làm rõ vị trí trong pipeline, chứng minh tính hợp lý của các lựa chọn, và nhìn nhận khách quan ưu/nhược điểm. Đây là tài liệu *mô tả lý do* — không phải bản sao SKILL.md (xem `.claude/skills/document-flow/SKILL.md`).

---

## 1. Skill này giải bài toán gì

Một payload có thể là vài trăm dòng mã. Pipeline phát hiện không nên đọc lại mã nguồn mỗi lần — nó cần một **bản phân tích trung lập, đã tính sẵn**. `document-flow` *trace mã nguồn* của một payload, tách thành **danh sách hành vi nguyên tử có thứ tự**, và lưu thành một `Flow.md` *gọn* ngay cạnh payload.

`Flow.md` là **cầu nối per-payload** giữa mã nguồn và pipeline phát hiện: mỗi hành vi viết dạng `actor action artifact`, kèm artifact nó tạo ra → hành vi nào tiêu thụ, và một ghi chú baseline trung lập. Sau đó `assign-category` và `write-detection-criteria` *đọc file này* thay vì suy lại từ mã.

---

## 2. Vị trí trong pipeline

```
craft-payload  →  [document-flow]  →  map-technique  →  (criteria → category → ...)
 (build)           (Flow.md skeleton,
                    Tactic/TID = —)
```

- **Đầu vào:** mã nguồn payload.
- **Đầu ra:** `Flow.md` — bảng hành vi + cạnh produces→consumes + context baseline, cột `Tactic / TID` để **`—`**.
- **Đọc:** `plan-for-agent/guides/behavior-breakdown.md` (cùng guide mà `extract-behaviors` dùng).

`Flow.md` là phân tích trung lập *feeding* các dòng Phase và các pass criteria/category — bản thân nó *không* được chấm điểm.

---

## 3. Các lựa chọn thiết kế & lý do

### 3.1. Chỉ trích xuất — để `Tactic / TID = —`
**Lựa chọn:** skill này *chỉ* sở hữu phần trích xuất. Viết skeleton hành vi với cột mapping bỏ trống. Không map, không quyết Category, không đặt trục anomaly, không viết Detection Criteria.

**Lý do:** mapping là một pass riêng, *có người kiểm chứng*. Điền TID ngay khi đang trace sẽ bỏ qua cổng kiểm chứng granularity mà các bước hạ nguồn phụ thuộc.

### 3.2. DỪNG ở cổng kiểm chứng (step 6)
**Lựa chọn:** trình skeleton ra cho người dùng xác nhận *granularity / cạnh / thứ tự* **trước khi** map. Không tự chạy `map-technique`.

**Lý do:** vì `assign-category` và `write-detection-criteria` đọc `Flow.md` *thay cho* mã nguồn, granularity sai sẽ lan thầm vào cả hai. Cổng kiểm chứng là nơi chặn lỗi đó *một lần*, trước khi nó nhân lên.

### 3.3. Tiết kiệm token là yêu cầu CỨNG
**Lựa chọn:** một dòng cho một hành vi, không ô nào dài nhiều câu.

**Lý do:** `Flow.md` được *nạp vào context* của skill hạ nguồn — mỗi token văn xuôi cạnh tranh trực tiếp với ngân sách suy luận của chúng. Đây là quyết định hiệu năng, không phải thẩm mỹ.

### 3.4. Giữ cạnh produces→consumes và link `[no-artifact]`
**Lựa chọn:** mỗi dòng ghi artifact nó để lại và hành vi `#` nào đọc nó; hành vi không để lại dấu vết vẫn giữ, gắn `[no-artifact]`.

**Lý do:** cạnh produces→consumes chính là thứ `assign-category` cần cho *kiểm tra trùng lặp* (Q-B). Bỏ link no-artifact là bỏ một mắt xích chuỗi.

### 3.5. Dừng ở mức *sự kiện*, không per-API
**Lựa chọn:** gộp một chuỗi call phục vụ *một outcome-artifact* thành một hành vi; fold tính toán thuần.

**Lý do:** một API call không đáng một dòng. Mức nguyên tử là *một intent = một hành động quan sát được* (theo source adapter trong `behavior-breakdown.md`), không phải mỗi lời gọi hàm.

---

## 4. Luồng nội bộ (tóm tắt)

1. Xác định payload-dir / source file; mặc định output `<payload-dir>/Flow.md`.
2. Đọc mã, trace từ entry point, tìm các chuỗi API/syscall tạo artifact.
3. **Trích hành vi** theo source adapter: gộp chuỗi call phục vụ một artifact thành một dòng, fold tính toán thuần, giữ link no-artifact.
4. Ghi cạnh **produces→consumes** + ghi chú baseline trung lập (không phải verdict anomaly).
5. **Viết `Flow.md`** với `Tactic / TID = —` trên mọi dòng.
6. **Dừng ở cổng kiểm chứng** — trình skeleton, chờ người dùng xác nhận.
7. Gợi ý chạy `map-technique` (sau khi người dùng duyệt).

---

## 5. Đánh giá khách quan

### Ưu điểm
- **Tách mã nguồn khỏi pipeline đúng chỗ** — pipeline đọc `Flow.md` thay vì parse lại mã mỗi lần, vừa nhanh vừa nhất quán.
- **Cổng kiểm chứng chặn lỗi sớm** — granularity được người duyệt một lần trước khi lan xuống criteria/category.
- **Kỷ luật token rõ ràng** — file gọn nên không ăn ngân sách suy luận hạ nguồn.
- **Cạnh produces→consumes là dữ liệu thật cho redundancy check** — không phải suy đoán lại.

### Nhược điểm / đánh đổi
- **Là cache — phải re-run khi mã đổi.** `Flow.md` không phải artifact một-lần; nếu mã nguồn thay đổi mà quên chạy lại, nó lệch thầm với thực tế.
- **Cổng kiểm chứng thêm một điểm dừng** — luồng không tự động chạy thẳng tới mapping; với payload nhỏ, đây là ma sát.
- **Kỷ luật token có thể làm mất sắc thái** — ép một dòng/hành vi đôi khi nén mất chi tiết mà người trace thấy đáng ghi (phải tin rằng `write-detection-criteria` sẽ khôi phục từ mã khi cần).
- **Phụ thuộc chất lượng trace** — code path bị bỏ sót = hành vi thiếu trong `Flow.md`; "track coverage explicitly" giảm thiểu nhưng không loại bỏ.

### Khi nào dễ sai nhất
- Điền `Tactic/TID` ngay khi trace (bỏ qua cổng kiểm chứng).
- Bỏ qua cổng kiểm chứng vì "thấy đúng rồi".
- Thêm câu giải thích "cho chắc" (phá kỷ luật token).
- Tách mỗi API call thành một dòng thay vì dừng ở mức sự kiện.
- Bỏ link no-artifact vì "không để lại dấu vết".

---

## 6. Liên hệ
- Quy tắc thực thi: `.claude/skills/document-flow/SKILL.md`
- Phương pháp nền: `plan-for-agent/guides/behavior-breakdown.md`
- Skill liền kề: `craft-payload` (upstream — tạo payload), `map-technique` (downstream — điền `Tactic / TID`). Khi đầu vào *không* phải mã nguồn (mô tả chuỗi / chuỗi lệnh), dùng `extract-behaviors` thay vì skill này.
