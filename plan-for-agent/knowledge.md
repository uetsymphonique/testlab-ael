# Agent Knowledge Base

## Mục tiêu dự án

Xây dựng **adversary emulation plan** bám sát kịch bản MITRE ATT&CK Evaluation 2026, phục vụ kiểm thử khả năng phát hiện của sản phẩm bảo mật trên môi trường Windows Enterprise.

Repo này là một fork từ **ATT&CK Evaluations Library** của MITRE Evaluations. Nội dung gốc lưu trữ các kịch bản adversary emulation mà MITRE đã từng thực hiện trong các năm trước, dùng làm nguồn tham khảo để hiểu insight, cách MITRE diễn giải hành vi adversary, cấu trúc operation flow, procedure, payload/resource, và ATT&CK mapping.

Thư mục `d:\vcs\ael\Enterprise\` là **nguồn insight chính** vì chứa các kịch bản trong môi trường Enterprise, phù hợp nhất với mục tiêu hiện tại khi xây dựng hoặc hiệu chỉnh các plan trong `testlab-enterprise\`. Không bám sát hoặc sao chép kịch bản các năm trước; chỉ dùng `Enterprise\` để rút pattern, hiểu cách MITRE mô tả hành vi, chia phase, viết operation flow, và ánh xạ detection theo ATT&CK. Kịch bản hiện tại cần được thiết kế độc lập dựa trên scope technique MITRE công bố cho năm nay.

Trong các kịch bản Enterprise, cần phân biệt hai nhóm chính:

- **Detections** — kịch bản dùng để đánh giá khả năng phát hiện, điều tra, và mô tả detection. Ví dụ 2025: `d:\vcs\ael\Enterprise\mustang_panda\Emulation_Plan\Mustang_Panda_Scenario.md`, `d:\vcs\ael\Enterprise\scattered_spider\Emulation_Plan\Scattered_Spider_Scenario.md`.
- **Protections** — kịch bản dùng để đánh giá khả năng ngăn chặn/bảo vệ theo các protection test riêng lẻ. Ví dụ 2025: `d:\vcs\ael\Enterprise\scattered_spider\Emulation_Plan\Protections_Test_1_Scenario.md`, `d:\vcs\ael\Enterprise\scattered_spider\Emulation_Plan\Protections_Test_2_Scenario.md`, `d:\vcs\ael\Enterprise\scattered_spider\Emulation_Plan\Protections_Test_3_Scenario.md`, `d:\vcs\ael\Enterprise\scattered_spider\Emulation_Plan\Protections_Test_6_Scenario.md`, `d:\vcs\ael\Enterprise\scattered_spider\Emulation_Plan\Protections_Test_7_Scenario.md`, `d:\vcs\ael\Enterprise\mustang_panda\Emulation_Plan\Protections_Test_4_Scenario.md`, `d:\vcs\ael\Enterprise\mustang_panda\Emulation_Plan\Protections_Test_5_Scenario.md`.

Khi dùng `Enterprise\` để lấy insight, xác định trước đang học pattern của **Detections** hay **Protections** vì mục tiêu, mức độ chi tiết, và cách trình bày expected outcome có thể khác nhau.

---

## Technique Scope

Danh sách kỹ thuật nằm trong phạm vi đánh giá MITRE ATT&CK Evaluation năm nay được MITRE mới công bố ở:

- `d:\vcs\ael\testlab-enterprise\mitre-outline\Scenario 1.md` — **Crimeware-as-a-Service** (Windows endpoint-focused, ransomware/wipe endpoint chain)
- `d:\vcs\ael\testlab-enterprise\mitre-outline\Scenario 2.md` — **PRC Espionage Group** (Enterprise-wide, cross-platform: Windows + Linux + AWS cloud, APT-style)

Hai file này là **đề cương technique chính** để dựng kịch bản chuẩn bị cho sản phẩm trước khi tham gia đánh giá. Mục tiêu không phải sao chép nguyên một kịch bản cũ, mà là dùng các technique đã công bố làm phạm vi bắt buộc, sau đó tham khảo `Enterprise\` để lấy insight về cách MITRE tư duy và trình bày hành vi trong các kỳ trước.

Khi chọn technique để thêm vào kế hoạch, **phải đối chiếu với technique scope trong hai file trên**. Ưu tiên các technique xuất hiện trong scope, không tự ý thêm technique ngoài danh sách trừ khi được yêu cầu rõ ràng.

---

## Tài liệu nội bộ trong `plan-for-agent`

`knowledge.md` chỉ là điểm vào cấp cao. Khi task chạm đến một chủ đề chuyên biệt, đọc file tương ứng thay vì suy luận lại từ đầu hoặc nhồi toàn bộ quy tắc vào một nơi.

| File | Dùng khi |
|---|---|
| [`detections-overview.md`](./detections-overview.md) | Cần phân biệt mục tiêu, độ dài flow, và kỳ vọng của kịch bản **Detections**. |
| [`protections-overview.md`](./protections-overview.md) | Cần thiết kế hoặc review kịch bản **Protections** và protection outcome. |
| [`emulation-plan-structure.md`](./emulation-plan-structure.md) | Viết hoặc sửa bất kỳ file trong `Emulation_Plan/`: cấu trúc Step, Voice Track, Procedures, Reference Table. |
| [`chain-breakdown.md`](./chain-breakdown.md) | Cần tham khảo template chia phase / attack chain khi dựng plan mới hoặc sắp xếp lại flow. |
| [`attack-behavior-methodology.md`](./attack-behavior-methodology.md) | Cần hiểu phương pháp luận đầy đủ về behavior, Category, CTI grounding, detection criteria, và khác biệt giữa Detections / Protections. |
| [`skills/attack-emulation.md`](./skills/attack-emulation.md) | Cần chuyển ý tưởng hoặc source CTI thành một attack emulation step hoàn chỉnh. |
| [`skills/technique-mapping.md`](./skills/technique-mapping.md) | Cần xác định tactic, technique, sub-technique, platform, và kiểm tra có nằm trong scope không. |
| [`skills/category-assignment.md`](./skills/category-assignment.md) | Cần gán `Calibrated` / `Not Calibrated` hoặc kiểm tra `Detection Criteria`. |
| [`skills/cli-execution.md`](./skills/cli-execution.md) | Cần biết ràng buộc CLI/toolchain của **môi trường dev dùng để soạn procedures**; không dùng file này để suy ra capability của lab hoặc host chạy bài test. |
| [`appendix/calibrated-assign-mindmap.md`](./appendix/calibrated-assign-mindmap.md) | Cần bản tóm tắt trực quan của luồng gán nhãn Category. |

Thứ tự đọc khuyến nghị khi viết hoặc sửa một Phase:

1. `knowledge.md`
2. `detections-overview.md` hoặc `protections-overview.md`
3. `emulation-plan-structure.md`
4. Khi cần chọn hoặc kiểm tra behavior: `chain-breakdown.md`, `skills/technique-mapping.md`, `skills/attack-emulation.md`
5. Trước khi chốt Reference Table: `skills/category-assignment.md` và khi cần nền tảng sâu hơn thì `attack-behavior-methodology.md`

---

## Workspace plan trong `testlab-enterprise`

Các adversary emulation plan sống dưới `d:\vcs\ael\testlab-enterprise\`. Mỗi plan nên là một thư mục độc lập ngang hàng nhau, ví dụ:

- `d:\vcs\ael\testlab-enterprise\windows-adversary-plan\` — plan Windows Enterprise hiện tại
- Các plan khác có thể được thêm sau này dưới dạng `d:\vcs\ael\testlab-enterprise\<plan-name>\`

Khi làm việc, xác định đúng `<plan-name>` từ yêu cầu của người dùng hoặc từ file đang mở. Không hard-code `windows-adversary-plan` nếu task đang nói về plan khác.

### Cấu trúc chuẩn của một plan

Root: `d:\vcs\ael\testlab-enterprise\<plan-name>\`

```
<plan-name>/
├── Emulation_Plan/
│   ├── Phase 1.md → Phase 5.md
│   ├── Setup.md
│   ├── Cleanup.md
│   ├── summary.md
│   └── further-reading/
└── resources/
    ├── payloads/
    │   ├── <technique-id>/
    │   ├── <tool-or-framework>/
    │   ├── <exploit-or-cve>/
    │   └── <standalone-binary-or-artifact>
    └── setup/
        ├── <host-or-service-setup>.md
        ├── <vulnerable-app>/
        └── <environment-dependency>/
```

Một plan không bắt buộc phải có đầy đủ mọi thư mục/file ngay từ đầu, nhưng nên giữ các nhóm chức năng trên khi mở rộng để agent và operator dễ tìm đúng tài liệu, payload, setup, và cleanup.

### `Emulation_Plan/`

Path mẫu: `d:\vcs\ael\testlab-enterprise\<plan-name>\Emulation_Plan\`

Chứa các **Phase file** — mỗi file là một kịch bản tấn công hoàn chỉnh theo format emulation plan chuẩn (tham khảo `d:\vcs\ael\plan-for-agent\emulation-plan-structure.md`). Mỗi Phase tương ứng một sub-attack chain.

Cấu trúc cụ thể có thể khác nhau giữa các plan. Ví dụ, `windows-adversary-plan` không dùng cấu trúc `Phase 1.md → Phase N.md` tuyến tính mà chia thành các **attack path subdirectory** song song (xem mục **Plan hiện tại** bên dưới). Khi làm việc với một plan cụ thể, đọc `summary.md` của plan đó trước để nắm cấu trúc thực tế.

Mapping Phase → tactic chain có thể thay đổi theo từng plan. Khi cập nhật plan, ưu tiên mô tả đúng flow thực tế của plan đó hơn là ép theo bảng mẫu dưới đây:

| File (mẫu tham khảo) | Tactic chain |
|---|---|
| `Phase 1.md` | Initial Access → Execution → Command & Control → (Defense Evasion) |
| `Phase 2.md` | Discovery → Credential Access |
| `Phase 3.md` | Lateral Movement + Privilege Escalation → Execution → (Persistence) |
| `Phase 4.md` | Collection → Exfiltration |
| `Phase 5.md` | Impact |

**Nội dung của Phase files**: mỗi file là một execution plan đầy đủ gồm các Steps với **Voice Track** (mô tả hành vi từ góc nhìn adversary), **Procedures** (câu lệnh step-by-step, dùng `☣️` cho bước nguy hiểm), và **Reference Tables** (ATT&CK mapping với Detection Criteria cụ thể). Xem `emulation-plan-structure.md` để biết format chi tiết.

Ngoài các Phase chính:

| File / Thư mục | Nội dung |
|---|---|
| `Setup.md` | Chuẩn bị lab/operator trước khi chạy các Phase. |
| `Cleanup.md` | Dọn dẹp artifact sau test. |
| `summary.md` | Tóm tắt flow hoặc trạng thái tổng quan của plan. |
| `further-reading/` | Ghi chú tham khảo cho các tool/kỹ thuật cụ thể của plan. |

### `resources/payloads/`

Path mẫu: `d:\vcs\ael\testlab-enterprise\<plan-name>\resources\payloads\`

Chứa toàn bộ payload, tool, và exploit PoC dùng trong các Phase. Tổ chức theo tên công cụ hoặc technique ID:

| Loại | Cách tổ chức |
|---|---|
| Technique-specific payload | Đặt theo technique ID nếu payload gắn chặt với một technique, ví dụ `T1189/`. |
| Tool hoặc framework | Đặt theo tên tool, ví dụ `dnscat2/`, `go-thehash/`, `Invoke-TheHash/`. |
| Exploit PoC | Đặt theo CVE hoặc tên exploit, ví dụ `CVE-2025-9491_POC/`. |
| Custom implant/service | Đặt theo tên project/payload, kèm README hoặc build note nếu có nhiều file. |
| Binary dùng trực tiếp | Có thể đặt ở root `payloads/` nếu là artifact đơn lẻ, nhưng ưu tiên thư mục riêng nếu có source, config, hoặc tài liệu đi kèm. |

Khi thêm payload mới: đặt vào thư mục con theo tên tool hoặc technique ID. Đặt `README.md` trong thư mục nếu payload có nhiều file.

### `resources/setup/`

Path mẫu: `d:\vcs\ael\testlab-enterprise\<plan-name>\resources\setup\`

Chứa tài liệu hạ tầng lab: hướng dẫn dựng host, domain, service, cloud resource, vulnerable application, hoặc dependency cần thiết để chạy plan. Không chứa payload hay kịch bản tấn công. Payload và tool phải nằm trong `resources/payloads/`; procedures tấn công phải nằm trong `Emulation_Plan/`.

### Plan hiện tại: `windows-adversary-plan`

Plan Windows Enterprise hiện tại nằm tại `d:\vcs\ael\testlab-enterprise\windows-adversary-plan\`. Plan này **không dùng cấu trúc Phase tuyến tính** mà chia `Emulation_Plan/` thành hai attack path subdirectory song song, cùng hội tụ tại IIS01 SYSTEM C2 trước khi chuyển sang lateral movement:

**`Emulation_Plan/html-smuggling-path/`** — path user-driven (WS01)

| File | Nội dung |
|---|---|
| `Plan.md` | Initial Access & C2: HTML smuggling → copy-paste PowerShell → HTA dropper → dnscat2 C2 trên WS01 |
| `Cleanup.md` | Dọn dẹp artifact của path này |

**`Emulation_Plan/iis-apppool-escalation-path/`** — path server-side (IIS01 → DC01)

| File | Nội dung |
|---|---|
| `Phase 1.md` | Initial Access & C2: CVE-2025-55182 React RSC RCE → react2shell eval shell → EfsPotato SYSTEM → Herpaderping ghost → dnscat2 C2 trên IIS01 (Step 1A: T1620 reflective load; Step 1B: file-based full chain) |
| `Phase 2.md` | Discovery & Credential Access: ReflectDump LSASS → XOR-encrypted `f.elif` → exfil qua react2shell → offline decrypt; host & domain recon (WmiAvQuery, whoami, nltest, net group, net view) |
| `Phase 3.md` | Lateral Movement, C2, Persistence: go-thehash.exe PtH → DC01 C$; WMI path (C2 as TESTLAB\Administrator) + SCM path (C2 as SYSTEM); 5 persistence mechanisms (svcbackup, WMI subscription, SYSVOL logon script, API service, registry service) |
| `Cleanup.md` | Dọn dẹp artifact của path này |

**`Emulation_Plan/summary.md`** — tóm tắt flow tổng thể và lab topology cả 2 path.

| Nhóm | Thành phần |
|---|---|
| Payload/tool | `T1189/`, `CWLHerpaderping/`, `EfsPotato/`, `react2shell-tool/`, `dnscat2/`, `dnscat2.exe`, `go-thehash/`, `Invoke-TheHash/`, `LsassReflectDumping/`, `WmiAvQuery/`, `webshell/`, `windows-service/` |
| Setup | `Windows Server 2022-DC.md`, `Windows Server 2022-IIS.md`, `file-upload-vuln-web/`, `react2shell-vuln-web/` |

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

1. Xác định task đang thuộc **Detections** hay **Protections**; đọc overview tương ứng.
2. Nếu cần dựng hoặc chỉnh flow lớn, tham khảo `chain-breakdown.md`.
3. **Chọn technique** từ scope của Scenario 1 / Scenario 2; dùng `skills/technique-mapping.md` để map tactic / technique / sub-technique.
4. **Tra cứu lý thuyết** trong `mitre-knowledge-base/techniques/` và **tham khảo ART** trong `atomic-red-team/atomics/` để hiểu hành vi thực tế.
5. Nếu cần tạo step mới, dùng `skills/attack-emulation.md`; nếu cần chạy lệnh trong môi trường dev để hỗ trợ soạn procedures, kiểm tra `skills/cli-execution.md`. Không dùng file này để suy ra tool nào có sẵn trên lab hoặc victim host.
6. **Xây dựng payload** — đặt vào `resources/payloads/<tool-or-technique>/` kèm `README.md`.
7. **Viết / cập nhật Phase file** theo `emulation-plan-structure.md`, tham chiếu payload bằng đường dẫn tương đối đến `../resources/payloads/`.
8. Trước khi chốt Reference Table, dùng `skills/category-assignment.md`; nếu cần lý do phương pháp luận chi tiết hơn, đối chiếu `attack-behavior-methodology.md`.
