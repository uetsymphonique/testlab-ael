# Skill: Viết Attack Emulation Step

Mô tả cách xây dựng một step trong emulation plan — từ ý tưởng tấn công đến procedures và reference table đầy đủ. Có hai nhánh làm việc tùy theo đầu vào.

---

## Nhánh [1] — Tự thiết kế hành vi từ gợi ý

Dùng khi: nhận được mô tả hành vi muốn mô phỏng, hoặc cần tiếp diễn attack chain từ các steps trước.

### Bước 1 — Nhận định hành vi cần mô phỏng

Input có thể là:
- Mô tả ngắn về hành vi (ví dụ: "adversary cần duy trì persistence sau khi có foothold")
- Technique/sub-technique cụ thể muốn cover
- Context từ các steps trước trong emulation plan (attacker đang ở đâu, đang có gì)

### Bước 2 — Đối chiếu với technique scope

> Xem `technique-mapping.md` để biết cách xác định tactic, tra technique file, và đối chiếu scope.

Tra cứu technique scope tại:
- `d:\vcs\ael\testlab-enterprise\mitre-outline\Scenario 1.md`
- `d:\vcs\ael\testlab-enterprise\mitre-outline\Scenario 2.md`

Xác định:
- Hành vi mô tả khớp với technique nào trong scope?
- Nếu nhiều technique phù hợp, ưu tiên technique nào phù hợp nhất với attack chain hiện tại?
- Nếu hành vi không có technique tương ứng trong scope → không đưa vào (trừ khi được yêu cầu rõ ràng)

### Bước 3 — Tra cứu định nghĩa và atomic test

Sau khi xác định technique:

1. Đọc định nghĩa trong `d:\vcs\ael\mitre-knowledge-base\techniques\<tactic>.md` — hiểu mô tả chính thức, sub-techniques, detection notes
2. Đọc atomic test tại `d:\vcs\ael\atomic-red-team\atomics\<TID>\<TID>.md` — lấy câu lệnh thực tế, hiểu artifact được tạo ra, tham khảo expected output

Mục tiêu: mô phỏng hành vi sát với cách thực thi thực tế, không tự bịa câu lệnh.

### Bước 4 — Viết step

Viết theo format chuẩn (`emulation-plan-structure.md`):

1. **Voice Track** — mô tả ý đồ adversary ở bước này, viết ở ngôi thứ ba, liên tục với ngữ cảnh steps trước
2. **Procedures** — liệt kê từng bước thực thi với câu lệnh cụ thể, dùng `☣️` cho bước nguy hiểm, kèm Expected Output khi cần xác nhận
3. **Reference Table** — điền đầy đủ 11 cột cho từng behavior trong step (xem bên dưới)

---

## Nhánh [2] — Breakdown từ source cho sẵn

Dùng khi: có sẵn một tài liệu mô tả hành vi adversary (CTI report, threat intel write-up, malware analysis, MITRE scenario cũ...) và cần chuyển thành emulation step.

### Bước 1 — Đọc source, chiết xuất hành vi

Đọc source để lấy ra danh sách hành vi cụ thể:
- Adversary làm gì?
- Công cụ/binary nào được dùng?
- Artifact nào được tạo ra (file, registry, network, process)?
- Sequence thực hiện ra sao?

Ghi chú rõ các hành vi theo thứ tự thực hiện.

### Bước 2 — Mapping tactics

> Xem `technique-mapping.md` — Bước 1 để biết câu hỏi định hướng cho từng tactic.

Với mỗi hành vi chiết xuất được, xác định tactic phù hợp theo MITRE ATT&CK (Initial Access, Execution, Persistence, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Command and Control, Impact).

### Bước 3 — Mapping techniques

> Xem `technique-mapping.md` — Bước 2, 3, 4 để biết cách tra technique file, xác định sub-technique, và đối chiếu scope.

Với mỗi hành vi đã gán tactic, tìm technique (và sub-technique) tương ứng:
- Tra `d:\vcs\ael\mitre-knowledge-base\techniques\<tactic>.md` để xác định technique ID chính xác
- Đối chiếu với technique scope trong Scenario 1 / Scenario 2 — ghi chú khi technique nằm ngoài scope

### Bước 4 — Viết step

Tương tự Nhánh [1] Bước 4: Voice Track → Procedures → Reference Table.

---

## Điền Reference Table

Sau khi viết Procedures (dù theo nhánh nào), điền Reference Table cho từng hành vi observable:

| Cột | Hướng dẫn điền |
|---|---|
| `Tactic` | Tactic đầy đủ (ví dụ: Defense Evasion) |
| `Technique ID` | ID ATT&CK bao gồm sub-technique nếu có (ví dụ: T1574.002) |
| `Technique Name` | Tên đầy đủ bao gồm sub-technique |
| `Platform` | Windows / Linux / IaaS... |
| `Detection Criteria` | Xem mục dưới |
| `Category` | **Để trống** — gán nhãn ở bước riêng (xem `category-assignment.md`) |
| `Red Team Activity` | Mô tả ngắn hành vi từ góc nhìn bên ngoài |
| `Hosts` | Hostname + IP |
| `Users` | Tài khoản thực hiện |
| `Source Code Links` | Link đến custom tool/payload nếu có |
| `Relevant CTI Reports` | Số reference từ header file `[N]` |

**Viết Detection Criteria:**
- Format: `<process> <action> <artifact/target> [trên <host>]`
- Ví dụ đúng: `waitfor.exe connects to 191.44.44.199 over TCP port 443`
- Ví dụ sai: `Malware connects to C2`
- Phải đủ cụ thể để query trực tiếp trong SIEM/EDR
- Mỗi observable event tách thành một row riêng, kể cả khi cùng technique ID

> **Lưu ý:** Cột `Category` chưa điền ở bước này. Việc gán nhãn `Calibrated`/`Not Calibrated` là một skill riêng biệt — xem `category-assignment.md`.
