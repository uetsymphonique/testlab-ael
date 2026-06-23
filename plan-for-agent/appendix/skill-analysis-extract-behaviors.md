# Phân tích thiết kế skill: `extract-behaviors`

> Bài phân tích trong loạt tài liệu giải thích **lý do thiết kế** của từng skill trong `.claude/skills/`. Mục tiêu: làm rõ vị trí trong pipeline, chứng minh tính hợp lý của các lựa chọn, và nhìn nhận khách quan ưu/nhược điểm. Đây là tài liệu *mô tả lý do* — không phải bản sao SKILL.md (xem `.claude/skills/extract-behaviors/SKILL.md`).

---

## 1. Skill này giải bài toán gì

Khi điểm xuất phát là một đầu vào *không có cấu trúc* — mô tả chuỗi tấn công / CTI, mã nguồn payload, hoặc một chuỗi lệnh thô — pipeline cần biến nó thành **danh sách hành vi nguyên tử, quan sát được, có thứ tự**. `extract-behaviors` sản xuất chính **đơn vị nguyên tử dùng chung của toàn pipeline**: *một hành vi = một intent = một hành động hệ thống quan sát được*, viết dạng `<actor> <action> <target/artifact>`, **không** technique ID, **không** phán xét Calibrated.

Điểm tinh tế: một hành vi **không** ánh xạ 1:1 với một dòng Reference Table — một hành động có thể trải nhiều tactic, nên `map-technique` có thể *tãi* một hành vi thành ≥1 dòng. Làm đúng granularity ở đây giữ các hành động riêng biệt không bị gộp (để mapping không mất dòng).

---

## 2. Vị trí trong pipeline

```
raw code / commands / CTI  →  [extract-behaviors]  →  map-technique  →  ...
                               (danh sách hành vi)
```

- **Đầu vào:** mô tả/CTI, mã nguồn, hoặc chuỗi lệnh.
- **Đầu ra:** *chỉ là danh sách* — mỗi dòng `<actor> <action> <target/artifact>` + `[artifact class]` (hoặc `[no-artifact]`) + ghi chú `(context: …)` trung lập tùy chọn. **Không ghi file trừ khi người dùng đồng ý.**
- **Đọc:** `plan-for-agent/guides/behavior-breakdown.md`.

Đây là **entry của nhánh INGEST**. Khi thiết kế *xuôi* từ một technique đã chọn trong scope, không cần skill này (dùng `write-phase`).

---

## 3. Các lựa chọn thiết kế & lý do

### 3.1. Chỉ ra danh sách — không ghi file khi chưa được đồng ý
**Lựa chọn:** output là danh sách hành vi. Chỉ persist thành skeleton Phase nếu người dùng đồng ý (step 6).

**Lý do:** các skill hạ nguồn *không chia sẻ bộ nhớ* — nên nếu cần chuyển tiếp thì phải ghi ra, nhưng việc ghi file là quyết định của người dùng. *Offer trước, ghi khi "yes"* — không ghi tự phát.

### 3.2. Trích xuất INCLUSIVE — giữ cả setup
**Lựa chọn:** trích cả hành động setup và chi tiết triển khai. **Không** lọc trước theo calibration.

**Lý do:** lọc calibration là việc của `assign-category` ở hạ nguồn. Bỏ một hành động setup *tại đây* là xóa thầm một dòng mà các pass sau **không bao giờ khôi phục được**. Inclusive là hướng an toàn: thừa còn lọc được, thiếu thì mất.

### 3.3. Không gán ID / Category / Criteria / anomaly
**Lựa chọn:** không technique ID, không phán Category, không đặt trục anomaly. Ghi chú `(context: …)` chỉ là *quan sát baseline trung lập*, không bao giờ là verdict.

**Lý do:** đặt tên anomaly là việc của `write-detection-criteria`; một verdict sớm ở đây sẽ *làm lệch toàn pipeline*. Giữ output trung lập để mỗi skill hạ nguồn tự quyết trên phần việc của nó.

### 3.4. Giữ hành động `[no-artifact]`
**Lựa chọn:** hành động mang intent nhưng không để lại dấu vết vẫn giữ, gắn `[no-artifact]` — không fold đi.

**Lý do:** chúng là *mắt xích chuỗi* mà `assign-category` cần cho kiểm tra trùng lặp. Fold mất chúng là làm đứt thông tin redundancy.

### 3.5. Khẳng định "behavior ≠ 1:1 với row"
**Lựa chọn:** không gộp hành động để "khớp một dòng".

**Lý do:** một hành động có thể trải nhiều tactic; `map-technique` sẽ tãi nó thành nhiều dòng. Gộp sớm làm mất khả năng tãi đó.

---

## 4. Luồng nội bộ (tóm tắt)

1. Xác định **loại đầu vào** (mô tả / mã nguồn / chuỗi lệnh).
2. Trích hành động mang intent bằng *adapter* tương ứng:
   - **Mô tả** → cắt tại mỗi chuyển intent; làm lộ hành động ngầm.
   - **Mã nguồn** → trace execution flow; dừng ở mức sự kiện, fold tính toán thuần.
   - **Chuỗi lệnh** → mỗi lệnh/pipe/nhánh là ứng viên; gom theo intent+artifact; bung LOLBin thành hiệu ứng thật.
3. Áp quy tắc granularity: tách khi đổi intent/actor/artifact-class; giữ link no-artifact.
4. Giữ **inclusive** — không lọc calibration.
5. Phát danh sách có thứ tự thời gian, annotate `[artifact class]` + `(context: …)`.
6. *Offer* persist thành skeleton Phase — chỉ ghi sau khi đồng ý.

---

## 5. Đánh giá khách quan

### Ưu điểm
- **Một định nghĩa granularity duy nhất** — trỏ về `behavior-breakdown.md`, dùng chung với `write-phase`/`document-flow`, nên ba skill không drift.
- **Inclusive bảo toàn thông tin** — không mất dòng ở khâu đầu, để khâu lọc nằm đúng chỗ hạ nguồn.
- **Output trung lập** — không verdict sớm, nên không làm lệch các pass sau.
- **Không ghi tự phát** — tôn trọng việc skill không chia sẻ bộ nhớ và quyền quyết định của người dùng.

### Nhược điểm / đánh đổi
- **Danh sách "ồn" hơn** — inclusive nghĩa là nhiều dòng setup/plumbing mà cuối cùng sẽ bị `assign-category` loại; người đọc phải chấp nhận danh sách dài hơn cái thực sự được chấm điểm.
- **Đẩy gánh nặng lọc xuống hạ nguồn** — chất lượng cuối phụ thuộc `assign-category` lọc đúng; nếu hạ nguồn lười, "rác" inclusive trôi vào bảng.
- **Granularity vẫn là phán đoán** — "một intent" ở đâu kết thúc là chủ quan ở ca biên; guide giảm thiểu nhưng không xóa.
- **Trùng vai với breakdown nội tuyến của `write-phase`** — hai đường vào (ingest vs forward) có hai breakdown; chủ ý là cùng defer về một guide, nhưng vẫn là hai điểm cần đồng bộ.

### Khi nào dễ sai nhất
- Bỏ bước setup vì "chỉ là setup" (vi phạm inclusive).
- Gắn cờ "đáng ngờ/anomalous" trong `(context: …)` (verdict sớm).
- Bỏ hành động no-artifact.
- Tự ghi vào Phase file khi chưa được đồng ý.
- Gộp hành động để "khớp một dòng".

---

## 6. Liên hệ
- Quy tắc thực thi: `.claude/skills/extract-behaviors/SKILL.md`
- Phương pháp nền: `plan-for-agent/guides/behavior-breakdown.md`
- Skill liền kề: `map-technique` (downstream — gán ID, tãi dòng). Khi đầu vào là *mã nguồn payload* và muốn lưu cạnh payload, dùng `document-flow`; khi thiết kế xuôi từ technique trong scope, dùng `write-phase`.
