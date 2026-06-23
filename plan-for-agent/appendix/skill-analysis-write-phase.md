# Phân tích thiết kế skill: `write-phase`

> Bài phân tích trong loạt tài liệu giải thích **lý do thiết kế** của từng skill trong `.claude/skills/`. Mục tiêu: làm rõ vị trí trong pipeline, chứng minh tính hợp lý của các lựa chọn, và nhìn nhận khách quan ưu/nhược điểm. Đây là tài liệu *mô tả lý do* — không phải bản sao SKILL.md (xem `.claude/skills/write-phase/SKILL.md`).

---

## 1. Skill này giải bài toán gì

`write-phase` viết hoặc cập nhật một **Phase file** trong emulation plan theo đúng format MITRE — Voice Track (góc nhìn adversary), Procedures (lệnh từng bước, `☣️` cho bước nguy hiểm), và Reference Table (ánh xạ ATT&CK + Detection Criteria).

Điểm cốt lõi: skill này chỉ sản xuất **bộ khung (skeleton) sắp theo hành vi**. Nó *không* chọn technique, *không* viết Detection Criteria, *không* gán Category — mỗi việc là một pass riêng ở hạ nguồn.

---

## 2. Vị trí trong pipeline

```
technique trong scope  →  [write-phase]  →  map-technique  →  write-detection-criteria → assign-category → ...
                           (Phase skeleton:
                            Tactic/TID = —, Criteria/Category = TBD)
```

- **Đầu vào:** một technique trong scope (Scenario 1/2) + mô tả các hành vi cần phủ.
- **Đầu ra:** Phase file khớp `phase-template.md`, mỗi hành vi quan sát được là một dòng, các cột mapping = `—`, `Detection Criteria` = `TBD`, `Category` = `TBD`.
- **Đọc:** `emulation-plan-structure.md`, `detections-overview.md`/`protections-overview.md`, `summary.md` của plan, và `behavior-breakdown.md`.

Đây là **entry của nhánh FORWARD DESIGN** (thiết kế xuôi từ technique trong scope).

---

## 3. Các lựa chọn thiết kế & lý do

### 3.1. Chỉ tạo SKELETON — để placeholder `—` / `TBD`
**Lựa chọn:** để `Tactic`/`Technique ID`/`Technique Name` = `—`, `Detection Criteria` = `TBD`, `Category` = `TBD`. Không map, không viết criteria, không gán nhãn tại đây.

**Lý do:** mỗi cột đó thuộc một pass *được kiểm chứng riêng*. Điền TID ở đây bỏ qua bước tra knowledge-base của `map-technique`; viết một detection note vội còn *tệ hơn* placeholder vì nó giả vờ đã xong. Placeholder rõ ràng là tín hiệu trung thực "chưa làm".

### 3.2. Dùng `phase-template.md` *chính xác*
**Lựa chọn:** không bịa, đổi tên, hay bỏ section.

**Lý do:** mọi reader và skill hạ nguồn phụ thuộc đúng format đó. Thêm/đổi section phá hợp đồng cấu trúc mà cả pipeline dựa vào.

### 3.3. Thứ tự dòng phải theo thứ tự thực thi (temporal)
**Lựa chọn:** dòng sắp theo trình tự thời gian trong step.

**Lý do:** thứ tự thời gian là dữ liệu mà các pass sau dùng (vd `assign-category` phác chuỗi để kiểm tra trùng lặp; `assign-acw` đọc vai trò chuỗi). Sắp sai thứ tự làm hỏng các suy luận đó.

### 3.4. Đầu vào không cấu trúc → chạy `extract-behaviors` TRƯỚC
**Lựa chọn:** nếu đầu vào là mô tả chuỗi thô / mã nguồn / chuỗi lệnh, chạy `/extract-behaviors` trước, không tự "ước lượng" breakdown nội tuyến.

**Lý do:** quy tắc granularity sống trong `behavior-breakdown.md`. Tự ứng biến ở đây sẽ drift khỏi guide. (Skill có breakdown nội tuyến cho đầu vào *đã có cấu trúc*, nhưng vẫn defer granularity về guide.)

---

## 4. Luồng nội bộ (tóm tắt)

1. Đọc spec format + overview tương ứng (Detections/Protections) + `summary.md` của plan.
2. Hỏi: attack path nào? phase nào? hành vi nào cần phủ?
3. Viết **Voice Track** (ngôi thứ ba, mạch nối tiếp step trước) và **Procedures** (lệnh chính xác, `☣️` cho bước nguy hiểm).
4. Với mỗi hành vi quan sát được, thêm **một dòng**: cột mapping = `—`, Platform điền, Criteria/Category = `TBD`, Red Team Activity điền (góc nhìn người quan sát ngoài), Hosts/Users/links điền phần đã biết.
5. Bàn giao `/map-technique`.

---

## 5. Đánh giá khách quan

### Ưu điểm
- **Skeleton trung thực** — placeholder `—`/`TBD` nói rõ "chưa làm", tránh ảo giác một bảng đã hoàn chỉnh.
- **Format bất biến** — bám sát `phase-template.md` giữ mọi reader/skill hạ nguồn đọc được nhất quán.
- **Thứ tự thời gian là dữ liệu** — nuôi đúng các pass redundancy/ACW sau này.
- **Granularity một nguồn** — defer về `behavior-breakdown.md`, không drift với `extract-behaviors`/`document-flow`.

### Nhược điểm / đánh đổi
- **File chưa dùng được ngay** — sau skeleton còn 3+ pass (map → criteria → category → acw) mới hoàn chỉnh; với người mới, một Phase đầy `TBD` trông như "chưa xong" và dễ bị điền vội sai chỗ.
- **Template cứng** — không cho thêm section kể cả khi một Phase thật sự cần giải thích thêm; tính nhất quán đổi lấy linh hoạt.
- **Hai breakdown song song** — `write-phase` có breakdown nội tuyến còn `extract-behaviors` đứng riêng; chủ ý là cùng defer guide, nhưng vẫn là hai đường cần giữ đồng bộ.
- **Phụ thuộc người vận hành tôn trọng ranh giới** — không có cơ chế *cứng* chặn việc điền TID/criteria sớm; chỉ có Hard Gate/Red Flags nhắc.

### Khi nào dễ sai nhất
- "Biết TID rồi, điền luôn" (bỏ qua pass map có kiểm chứng).
- Viết detection note vội thay vì để `TBD`.
- Thêm/đổi tên section ngoài template.
- "Mắt thường" breakdown đầu vào lộn xộn thay vì chạy `extract-behaviors`.
- Một dòng gộp cả payload thay vì một dòng/một hành vi quan sát được.

---

## 6. Liên hệ
- Quy tắc thực thi: `.claude/skills/write-phase/SKILL.md` (+ `phase-template.md` trong cùng thư mục)
- Phương pháp nền: `plan-for-agent/emulation-plan-structure.md`, `detections-overview.md`/`protections-overview.md`, `guides/behavior-breakdown.md`
- Skill liền kề: `extract-behaviors` (upstream cho đầu vào không cấu trúc), `map-technique` (downstream — điền mapping)
