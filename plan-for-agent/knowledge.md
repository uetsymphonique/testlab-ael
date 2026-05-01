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

```
windows-adversary-plan/
├── Emulation_Plan/
│   ├── Phase 1.md → Phase 5.md
│   └── Overview.md
└── resources/
    ├── payloads/
    │   ├── T1189/               # Drive-by / HTA chain
    │   ├── CWLHerpaderping/     # Process Herpaderping injector
    │   ├── CVE-2025-9491_POC/   # Exploit PoC
    │   ├── react2shell-tool/    # React2Shell exploit tool
    │   ├── webshell/            # Webshell payloads
    │   └── dnscat2.exe          # C2 beacon binary
    └── setup/
        ├── Windows Server 2022-IIS.md
        ├── file-upload-vuln-web/
        └── react2shell-vuln-web/
```

### `Emulation_Plan/`

Path: `d:\vcs\ael\testlab-enterprise\windows-adversary-plan\Emulation_Plan\`

Chứa các **Phase file** — mỗi file là một kịch bản tấn công hoàn chỉnh theo format emulation plan chuẩn (tham khảo `d:\vcs\ael\plan-for-agent\emulation-plan-structure.md`). Mỗi Phase tương ứng một sub-attack chain:

| File | Tactic chain |
|---|---|
| `Phase 1.md` | Initial Access → Execution → Command & Control → (Defense Evasion) |
| `Phase 2.md` | Discovery → Credential Access |
| `Phase 3.md` | Lateral Movement + Privilege Escalation → Execution → (Persistence) |
| `Phase 4.md` | Collection → Exfiltration |
| `Phase 5.md` | Impact |

**Nội dung của Phase files**: mỗi file là một execution plan đầy đủ gồm các Steps với **Voice Track** (mô tả hành vi từ góc nhìn adversary), **Procedures** (câu lệnh step-by-step, dùng `☣️` cho bước nguy hiểm), và **Reference Tables** (ATT&CK mapping với Detection Criteria cụ thể). Xem `emulation-plan-structure.md` để biết format chi tiết.

### `resources/payloads/`

Path: `d:\vcs\ael\testlab-enterprise\windows-adversary-plan\resources\payloads\`

Chứa toàn bộ payload, tool, và exploit PoC dùng trong các Phase. Tổ chức theo tên công cụ hoặc technique ID:

| Thư mục / File | Nội dung |
|---|---|
| `T1189/` | Drive-by chain: `staging.html`, `stage1.hta`, `cert_bundle.txt`, `encode-command.py` |
| `CWLHerpaderping/` | Process Herpaderping injector — source C++ + build output |
| `CVE-2025-9491_POC/` | Exploit PoC cho CVE-2025-9491 |
| `react2shell-tool/` | Tool khai thác React2Shell RCE |
| `webshell/` | ASPX webshell |
| `dnscat2.exe` | dnscat2 C2 client binary |

Khi thêm payload mới: đặt vào thư mục con theo tên tool hoặc technique ID. Đặt `README.md` trong thư mục nếu payload có nhiều file.

### `resources/setup/`

Path: `d:\vcs\ael\testlab-enterprise\windows-adversary-plan\resources\setup\`

Chứa tài liệu hạ tầng lab: hướng dẫn dựng IIS, cấu hình ứng dụng web dễ bị tấn công (`file-upload-vuln-web`, `react2shell-vuln-web`), v.v. Không chứa payload hay kịch bản tấn công.

---

## Thư viện tham khảo

### Emulation Plan Structure

Path: `d:\vcs\ael\plan-for-agent\emulation-plan-structure.md`

Định nghĩa format chuẩn cho Phase files trong `Emulation_Plan/`: cấu trúc Step, Voice Track, Procedures, Reference Tables, ký hiệu `☣️`, và format cột Reference Table. **Đọc file này trước khi viết hoặc sửa bất kỳ Phase file nào.**

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

**Dùng khi**: cần tham khảo cách thực hiện thực tế của một technique, tìm câu lệnh mẫu, hoặc hiểu rõ hành vi kỹ thuật.

---

## Quy trình làm việc

> **Lưu ý:** Quy trình dưới đây mang tính tham khảo. Câu hỏi hoặc task cụ thể của người dùng có thể yêu cầu cách xử lý khác.

1. **Chọn technique** từ scope của Scenario 1 / Scenario 2
2. **Tra cứu lý thuyết** trong `mitre-knowledge-base/techniques/`
3. **Tham khảo ART** trong `atomic-red-team/atomics/` để hiểu hành vi thực tế
4. **Xây dựng payload** — đặt vào `resources/payloads/<tool-or-technique>/` kèm `README.md`
5. **Viết / cập nhật Phase file** trong `Emulation_Plan/` theo format emulation plan (Step + Voice Track + Procedures + Reference Table), tham chiếu payload bằng đường dẫn tương đối đến `../resources/payloads/`
