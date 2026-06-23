# Phân tích thiết kế skill: `map-technique`

> Bài phân tích trong loạt tài liệu giải thích **lý do thiết kế** của từng skill trong `.claude/skills/`. Mục tiêu: làm rõ vị trí trong pipeline, chứng minh tính hợp lý của các lựa chọn, và nhìn nhận khách quan ưu/nhược điểm. Đây là tài liệu *mô tả lý do* — không phải bản sao SKILL.md (xem `.claude/skills/map-technique/SKILL.md`).

---

## 1. Skill này giải bài toán gì

`map-technique` ánh xạ một hành vi adversary đã mô tả sang đúng **tactic / technique / sub-technique** của ATT&CK, và điền cột mapping khi các hành vi đến từ một `Flow.md` hoặc một Phase Reference Table.

Đây là **điểm hội tụ** của pipeline: ba nguồn skeleton khác nhau (`write-phase`, `extract-behaviors`, `document-flow`) đều chảy về đây để được gán ID.

---

## 2. Vị trí trong pipeline

```
write-phase  ─┐
extract-behaviors ─┼─→  [map-technique]  →  write-detection-criteria  →  assign-category → ...
document-flow ─┘        (điền Tactic / TID / Name)
```

- **Đầu vào:** mô tả hành vi (hoặc skeleton có cột mapping bỏ trống).
- **Đầu ra:** điền các cột `Tactic` / `Technique ID` / `Technique Name` (hoặc `Tactic / TID` trong `Flow.md`), thay placeholder `—`.
- **Đọc:** `plan-for-agent/guides/technique-mapping.md` + `mitre-knowledge-base/techniques/<tactic>.md`.

---

## 3. Các lựa chọn thiết kế & lý do

### 3.1. Chỉ sửa cột mapping
**Lựa chọn:** khi ghi ngược, chỉ động vào `Tactic`/`Technique ID`/`Technique Name`. Không chạm behavior text, cạnh produces→consumes, Category, hay Detection Criteria.

**Lý do:** đây là nguyên tắc **column-disjoint write ownership** của toàn pipeline — không skill nào ghi đè cột của skill khác. Chính nó cho phép cùng một file đi qua nhiều skill mà không clobber.

### 3.2. Map từ knowledge base, KHÔNG từ trí nhớ
**Lựa chọn:** mở `mitre-knowledge-base/techniques/<tactic>.md` xác nhận ID và sub-technique *trước khi* viết.

**Lý do:** technique ID và cách tách sub-technique *drift* giữa các phiên bản ATT&CK. Một TID sai **đầu độc mọi pass hạ nguồn** (criteria viết cho sai technique, category chấm sai bề mặt). Xác nhận KB là rào chắn rẻ cho lỗi đắt.

### 3.3. Ưu tiên sub-technique hơn parent
**Lựa chọn:** dùng sub-technique bất cứ khi nào hành vi đủ cụ thể; parent chỉ là *fallback*, không phải mặc định.

**Lý do:** độ phân giải cao hơn giúp criteria và category bám đúng bề mặt thật của hành vi.

### 3.4. Một hành vi → nhiều tactic → nhiều dòng
**Lựa chọn:** nếu một hành vi trải nhiều tactic (vd DLL Side-Loading = Execution + Defense Evasion), tãi thành một dòng/một tactic, giữ nguyên `#`/cạnh/context (vd `#3` → `#3a`, `#3b`).

**Lý do:** mỗi tactic là một cơ hội phát hiện riêng; gộp một dòng làm mất một cơ hội ở hạ nguồn.

### 3.5. Report-only khi không có file
**Lựa chọn:** nếu không có file đích với cột mapping trong context, *chỉ báo cáo* (step 4) rồi dừng — không tạo/sửa file.

**Lý do:** giữ skill an toàn ở chế độ tư vấn thuần khi chưa có chỗ ghi; tránh tạo file ngoài ý muốn.

### 3.6. Không kiểm tra scope
**Lựa chọn:** map mọi hành vi đúng *bất kể* nó có trong scope hay không. Kiểm tra scope là việc của `check-coverage`.

**Lý do:** trộn "map" với "lọc scope" làm hai trách nhiệm dính nhau; map đúng trước, lọc scope là pass riêng.

---

## 4. Luồng nội bộ (tóm tắt)

1. Mô tả hành vi (hoặc đọc từ file/selection). Đầu vào sạch nhất là danh sách từ `extract-behaviors`.
2. Xác định **tactic** từ intent.
3. Mở `mitre-knowledge-base/techniques/<tactic>.md` tìm technique + sub-technique.
4. **Báo cáo**: Tactic, Technique ID (kèm sub nếu có), Name, Platform; nếu nhiều tactic, liệt kê đủ các dòng.
5. **Ghi ngược** (khi có file): điền cột mapping trên `Flow.md` hoặc Phase table; tãi dòng khi một hành vi trải nhiều tactic; *chỉ* sửa cột mapping.

---

## 5. Đánh giá khách quan

### Ưu điểm
- **Rào chắn rẻ cho lỗi đắt** — bắt tra KB chặn một TID sai trước khi nó đầu độc mọi pass sau.
- **Column-disjoint sạch** — chỉ sửa cột của mình, nên file đi qua nhiều skill không bị clobber.
- **Hội tụ ba nguồn về một chỗ** — mọi skeleton (forward/ingest/source) đều được gán ID nhất quán bởi một skill.
- **Hai chế độ an toàn** — report-only khi chưa có file, write-back khi có.

### Nhược điểm / đánh đổi
- **Tra KB thêm ma sát** — với hành vi quá quen, việc bắt mở file KB thấy chậm; đây là cái giá cố ý đổi lấy độ chính xác.
- **Phụ thuộc KB cập nhật** — nếu `mitre-knowledge-base` lỗi thời so với ATT&CK hiện hành, "xác nhận theo KB" vẫn ra ID cũ; rào chắn chỉ tốt bằng nguồn nó tra.
- **Tãi dòng làm bảng phình** — một hành vi trải nhiều tactic thành nhiều dòng đúng về mặt phát hiện nhưng làm bảng dài hơn và cần `#a/#b` để giữ liên kết.
- **Ranh giới "không kiểm scope" dễ gây bối rối** — người vận hành có thể tưởng map xong là đã lọc scope; thực ra cần chạy `check-coverage` riêng.

### Khi nào dễ sai nhất
- "Chắc TID này, khỏi tra KB" (TID drift → đầu độc hạ nguồn).
- Dùng parent khi sub-technique mới đúng.
- Tiện tay sửa behavior text / thêm detection note (vi phạm column-disjoint).
- Bỏ hành vi "có vẻ ngoài scope" (đó là việc của `check-coverage`).
- Một TID gói cả hành vi trải nhiều tactic (quên tãi dòng).

---

## 6. Liên hệ
- Quy tắc thực thi: `.claude/skills/map-technique/SKILL.md`
- Phương pháp nền: `plan-for-agent/guides/technique-mapping.md`, `mitre-knowledge-base/techniques/`
- Skill liền kề: `write-phase` / `extract-behaviors` / `document-flow` (upstream — tạo skeleton), `write-detection-criteria` (downstream)
