# Phân tích thiết kế skill: `assign-acw`

> Bài phân tích trong loạt tài liệu giải thích **lý do thiết kế** của từng skill trong `.claude/skills/`. Mục tiêu: làm rõ vị trí trong pipeline, chứng minh tính hợp lý của các lựa chọn, và nhìn nhận khách quan ưu/nhược điểm. Đây là tài liệu *mô tả lý do* — không phải bản sao SKILL.md (xem `.claude/skills/assign-acw/SKILL.md`).

---

## 1. Skill này giải bài toán gì

`assign-acw` gán **Attack Chain Weighting (ACW)** — `Critical` / `High` / `Medium` / `Low` — cho **mọi dòng** trong CSV của plan, dựa trên *vai trò của hành vi trong chuỗi tấn công*. ACW là **hệ số tầm quan trọng** nhân lên Detection Coverage khi chấm điểm; nó *không* phải quyết định calibration.

Câu hỏi ACW trả lời: **hành vi này quan trọng tới đâu với tiến trình của kẻ tấn công qua chuỗi?** — qua ba lăng kính: *terminal objective* (mục tiêu chuỗi/cụm đang hướng tới), *bottleneck* (tạo ra cơ hội mới mà chuỗi phụ thuộc), *value-to-attacker* (đòn bẩy năng lực).

---

## 2. Vị trí trong pipeline

```
... → assign-category  →  [assign-acw]
       (nhãn Calibrated)    (cột ACW, per-row — pass per-row CUỐI CÙNG)
```

- **Đầu vào:** CSV của plan (đã có Category + Calibration Reason) + `summary.md` cho ngữ cảnh chuỗi.
- **Đầu ra:** điền cột `ACW` cho *mọi* dòng + bảng tóm tắt per-behavior + tally đếm theo mức.
- **Đọc:** `testlab-enterprise/mitre-outline/Scoring Specification.md`.

Đây là **pass per-row cuối cùng**. Sau đó là script chấm điểm (ngoài phạm vi skill).

---

## 3. Các lựa chọn thiết kế & lý do

### 3.1. Cân MỌI dòng — kể cả Not-Calibrated
**Lựa chọn:** gán ACW cho *mọi* dòng, không bỏ dòng Not-Calibrated.

**Lý do:** nhãn Calibrated *có thể đổi* về sau; cân sẵn mọi dòng đảm bảo điểm sẵn sàng ngay khi nhãn chốt. ACW và Category là **hai trục độc lập** — không bao giờ hạ ACW vì một dòng (có thể) Not-Calibrated, cũng không giữ một dòng Calibrated chỉ vì ACW cao.

### 3.2. ACW là per-BEHAVIOR (per-row), không per-Technique ID
**Lựa chọn:** cùng một TID trên hai dòng có thể nhận ACW *khác nhau* theo vai trò mỗi nơi.

**Lý do:** đơn vị được chấm là *hành vi*, không phải technique. `T1003` dump cache cục bộ để pivot một lần vs dump kho credential miền làm *mục tiêu cuối* — cùng TID, khác trọng số. Gộp về một weight làm mất khác biệt vai trò.

### 3.3. Cân theo vai trò chuỗi ĐƠN THUẦN, first-match-wins top-down
**Lựa chọn:** làm bộ câu hỏi vai trò từ trên xuống (terminal objective → bottleneck → value → staging → evasion → recon), *trùng đầu tiên thắng*.

**Lý do:** thứ tự ưu tiên rõ ràng làm quyết định tái lập được và tránh tranh cãi "vừa là cái này vừa là cái kia". Tie-break Q4-vs-Q5 (staging vs evasion thuần) được nêu tường minh.

### 3.4. KHÔNG tính điểm
**Lựa chọn:** chỉ ghi cột `ACW`. Không tính score, denominator, hay Weighted_DC.

**Lý do:** phép nhân DC × ACW và tổng hợp là việc của *script chấm điểm* riêng. Mỗi trục được chấm trên giá trị riêng; để công thức cho scorer giữ ranh giới sạch.

### 3.5. Trần Critical ~35% + ALT là coverage, không phải fallback
**Lựa chọn:** nếu >~35% dòng là Critical, soi lại (thường do chấm *sub-cluster terminal* như thể *whole-chain terminal*). ALT và bước chính *chia sẻ vai trò* → **cùng** ACW; ALT không hạ trọng số bước chính.

**Lý do:** Critical dành cho hành vi mà *gỡ đi là gãy chuỗi* hoặc *chính là impact* — phải là thiểu số. Trần là cơ chế tự-kiểm bắt lạm phát Critical. ALT tồn tại để *mở rộng phủ technique*, không phải đường lui, nên không làm bước chính bớt pivotal.

### 3.6. "Hard-to-detect" là tie-break, không phải bucket
**Lựa chọn:** khó-phát-hiện chỉ nâng **High ↔ Critical**, không tự kéo Low/Medium lên Critical.

**Lý do:** khó-phát-hiện là một đặc tính Critical của MITRE nhưng nếu thành bucket riêng sẽ lạm phát Critical; giới hạn nó ở vai trò tie-break giữ kỷ luật.

---

## 4. Luồng nội bộ (tóm tắt)

1. **Đọc ngữ cảnh chuỗi** từ `summary.md`: pha nào, hành vi nào là terminal/bottleneck/preparatory/evasion-only.
2. **Đọc CSV**: mỗi *dòng là một hành vi*; không gộp theo TID.
3. **Gán ACW per-row** theo bộ câu hỏi top-down, first-match-wins.
4. **Modifier chéo** (sau khi xếp bucket): hard-to-detect nâng High→Critical.
5. **Kiểm tra nhất quán**: ít nhất một Critical tồn tại; terminal chuỗi phải Critical; gắn cờ Critical thuần evasion; **trần Critical ~35%**.
6. **Ghi output**: chèn cột `ACW` sau `Calibration Reason`; in bảng tóm tắt per-behavior + tally. *Không* tính điểm.

---

## 5. Đánh giá khách quan

### Ưu điểm
- **Hai trục tách bạch rõ ràng** — ACW (vai trò chuỗi) vs Category (chấm điểm được không) độc lập; cả 4 tổ hợp hợp lệ. Đây là chỗ chống lỗi "Critical nên phải Calibrated".
- **Per-behavior phản ánh thực tế** — cùng TID khác vai trò được cân khác nhau, sát cách chuỗi thật vận hành.
- **First-match-wins làm quyết định tái lập** — thứ tự ưu tiên rõ giảm tranh cãi ca chồng vai trò.
- **Trần Critical tự-kiểm lạm phát** — cơ chế đơn giản bắt lỗi phổ biến (chấm sub-cluster như whole-chain).

### Nhược điểm / đánh đổi
- **Phán đoán vai trò vẫn chủ quan** — "terminal của cụm" hay "bottleneck" ở ca biên phụ thuộc cách đọc `summary.md`; hai người có thể cân khác nhau.
- **Trần 35% là heuristic, không phải luật** — đúng cho nhiều chuỗi nhưng một chuỗi ngắn toàn bước quyết định có thể vượt 35% *một cách chính đáng*; con số là cờ để soi lại, không phải ngưỡng cứng.
- **Kỷ luật "trục độc lập" khó giữ khi chạy cạnh `assign-category`** — cám dỗ để Category kéo ACW (hoặc ngược lại) là lỗi phổ biến nhất; skill phải nhắc nhiều lần qua Anti-Pattern/Red Flags.
- **Lặp per-row tốn công** — cân từng dòng (không gộp TID) đúng nhưng nặng tay với CSV lớn; "track coverage explicitly" giúp nhưng không giảm khối lượng.

### Khi nào dễ sai nhất
- "Cùng TID → cùng ACW" (quên vai trò khác nhau per-row).
- "Not-Calibrated → ACW thấp/bỏ qua" (trộn hai trục).
- "Evasion tinh vi → Critical" (Critical là terminal/bottleneck, không phải độ tinh vi).
- Đánh nhiều dòng Critical (vượt trần ~35%).
- "ALT là fallback → hạ trọng số" (ALT là coverage, cùng vai trò cùng ACW).

---

## 6. Liên hệ
- Quy tắc thực thi: `.claude/skills/assign-acw/SKILL.md`
- Nguồn trọng số: `testlab-enterprise/mitre-outline/Scoring Specification.md`, `Methodology Overview.md`
- Skill liền kề: `assign-category` (trục độc lập — chạy trước trên Phase table). Phép nhân DC × ACW thuộc *script chấm điểm*, ngoài phạm vi skill này.
