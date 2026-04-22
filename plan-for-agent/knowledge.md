# Agent Knowledge Base

## Mục tiêu dự án

Xây dựng **adversary emulation plan** bám sát kịch bản MITRE ATT&CK Evaluation 2026, phục vụ kiểm thử khả năng phát hiện của sản phẩm bảo mật trên môi trường Windows Enterprise.

---

## Technique Scope

Danh sách kỹ thuật nằm trong phạm vi đánh giá được công bố ở:

- `d:\vcs\ael\testlab-enterprise\mitre-outline\Scenario 1.md` — **Crimeware-as-a-Service** (Windows endpoint-focused, ransomware/wipe endpoint chain)
- `d:\vcs\ael\testlab-enterprise\mitre-outline\Scenario 2.md` — **PRC Espionage Group** (Enterprise-wide, cross-platform: Windows + Linux + AWS cloud, APT-style)

Khi chọn technique để thêm vào kế hoạch, **phải đối chiếu với technique scope trong hai file trên**. Ưu tiên các technique xuất hiện trong scope, không tự ý thêm technique ngoài danh sách trừ khi được yêu cầu rõ ràng.

---

## Workspace chính: `windows-adversary-plan`

Root: `d:\vcs\ael\testlab-enterprise\windows-adversary-plan\`

### Phase files (`Phase 1.md` → `Phase 5.md`)

Mỗi Phase tương ứng với một **sub-attack chain** — nhóm các hành vi thường được thực hiện liên tiếp, có sự kết hợp hoặc phụ thuộc nhau theo flow dưới đây (định nghĩa trong `d:\vcs\ael\testlab-enterprise\mitre-outline\chain-breakdown.md`):

| File | Tactic chain |
|---|---|
| `Phase 1.md` | Initial Access → Execution → (Command & Control) → (Persistence) → (Defense Evasion) |
| `Phase 2.md` | Discovery → Credential Access |
| `Phase 3.md` | Lateral Movement + Privilege Escalation → Execution → (Persistence) → (Defense Evasion) |
| `Phase 4.md` | Collection → Exfiltration |
| `Phase 5.md` | Impact |

**Nội dung của Phase files**: mô tả sơ bộ các vector tấn công, technique ID, và tham chiếu đến Procedure file tương ứng. Không chứa câu lệnh hay payload chi tiết.

### `Procedures/`

Path: `d:\vcs\ael\testlab-enterprise\windows-adversary-plan\Procedures\`

Chứa:
- **Procedure markdown files** (`T<ID>.md`): mô tả chi tiết từng Atomic Test, bao gồm technique tags, nền tảng hỗ trợ, và câu lệnh/payload thực thi. Đây là nơi đặt hướng dẫn step-by-step.
- **`payloads/`**: các file payload thực tế (script, tool, exploit PoC...) được tổ chức theo technique ID hoặc tên công cụ.

Quy tắc đặt tên Procedure file: `T<TechniqueID>.md` (ví dụ: `T1189.md`, `T1190.md`).

### `resources/`

Path: `d:\vcs\ael\testlab-enterprise\windows-adversary-plan\resources\`

Chứa tài liệu liên quan đến **môi trường lab và hạ tầng**: hướng dẫn dựng máy chủ, cấu hình IIS, các ứng dụng web dễ bị tấn công dùng cho lab, v.v. Không chứa payload hay kịch bản tấn công.

---

## Thư viện tham khảo

### MITRE Knowledge Base

Path: `d:\vcs\ael\mitre-knowledge-base\techniques\`

Chứa lý thuyết chi tiết về từng technique, phân loại theo tactic. Mỗi file tương ứng một tactic:

| File | Tactic |
|---|---|
| `TA0001-initial-access.md` | Initial Access |
| `TA0002-execution.md` | Execution |
| `TA0003-persistence.md` | Persistence |
| `TA0004-privilege-escalation.md` | Privilege Escalation |
| `TA0005-defense-evasion.md` | Defense Evasion |
| `TA0006-credential-access.md` | Credential Access |
| `TA0007-discovery.md` | Discovery |
| `TA0008-lateral-movement.md` | Lateral Movement |
| `TA0009-collection.md` | Collection |
| `TA0010-exfiltration.md` | Exfiltration |
| `TA0011-command-and-control.md` | Command and Control |
| `TA0040-impact.md` | Impact |
| `TA0043-reconnaissance.md` | Reconnaissance |

**Dùng khi**: cần hiểu mô tả, sub-techniques, detection notes, và mitigation của một technique trước khi đưa vào kế hoạch.

### Atomic Red Team (ART)

Path: `d:\vcs\ael\atomic-red-team\atomics\`

Thư viện mô phỏng hành vi tấn công mã nguồn mở. Mỗi thư mục con tương ứng một technique ID (ví dụ: `T1003.001\`), bên trong chứa:
- `T<ID>.md` — mô tả các atomic test với câu lệnh cụ thể
- `T<ID>.yaml` — định nghĩa test dạng máy đọc được
- `src/` — script hỗ trợ (nếu có)

**Dùng khi**: cần tham khảo cách thực hiện thực tế của một technique, tìm câu lệnh mẫu, hoặc hiểu rõ hành vi kỹ thuật trước khi viết Procedure.

---

## Quy trình làm việc

> **Lưu ý:** Quy trình dưới đây mang tính tham khảo. Câu hỏi hoặc task cụ thể của người dùng có thể yêu cầu cách xử lý khác, nhưng nhìn chung các approach này hữu ích khi làm việc với các task liên quan đến adversary plan.

1. **Chọn technique** từ scope của Scenario 1 / Scenario 2
2. **Tra cứu lý thuyết** trong `mitre-knowledge-base/techniques/`
3. **Tham khảo ART** trong `atomic-red-team/atomics/` để hiểu hành vi thực tế
4. **Viết Procedure** vào `Procedures/T<ID>.md` với Atomic Tests chi tiết
5. **Đặt payload** vào `Procedures/payloads/` nếu có file đi kèm
6. **Cập nhật Phase file** tương ứng với mô tả sơ bộ + tham chiếu đến Procedure
