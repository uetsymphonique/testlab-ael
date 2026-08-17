# Overview

Danh sách này tổng hợp các kỹ thuật/sub-kỹ thuật ATT&CK **đã có telemetry/detection rule phủ (coverage = 1)** hoặc **đã có khả năng prevent (chặn)**, tính đến Q3 2026, trong tổng số 45 kỹ thuật xuất hiện lặp lại qua các kỳ đánh giá MITRE ATT&CK Evaluations (2023–2026). Đây không phải là một kịch bản tấn công mới mà là bảng kiểm kê (inventory) các kỹ thuật đã sẵn sàng detection và/hoặc prevention, dùng làm tham chiếu khi thiết kế Phase cho các plan tấn công dưới `testlab-enterprise/` — phục vụ dựng kịch bản cho cả hai mục tiêu Detections và Protections, ưu tiên các kỹ thuật đã có coverage để đảm bảo hành vi thực thi có thể được quan sát/đánh giá.

Lưu ý: dòng `T1003 - OS Credential Dumping` trong sheet `Prevention` được ghi chú `Sub-technique (8)`, tức khả năng prevent áp dụng ở mức 8 sub-kỹ thuật con (T1003.001–T1003.008) chứ không phải kỹ thuật cha. Danh sách bên dưới đã khai triển sub-kỹ thuật này thay cho dòng `T1003` gộp, nhưng loại bỏ T1003.007 (Proc Filesystem) và T1003.008 (/etc/passwd and /etc/shadow) vì đây là 2 sub-kỹ thuật chỉ áp dụng trên Linux, không phù hợp với môi trường test toàn Windows — còn lại 6/8 sub-kỹ thuật.

Ideal for: tham chiếu chéo khi thiết kế Phase mới, chọn kỹ thuật đã có sẵn detection/prevention để xây dựng chuỗi tấn công có thể kiểm chứng.

Nguồn dữ liệu và tiêu chí:
- **Nguồn:** `technique_detection_Q3_2024.xlsx` (sheet `Detection` và `Prevention`), được extract sang `technique_detection_Q3_2024.md`.
- **Years / Frequency:** số năm đánh giá (2023–2026) mà kỹ thuật xuất hiện; tần suất càng cao càng phản ánh mức độ phổ biến của kỹ thuật trong các kịch bản MITRE. Sheet `Prevention` không có các cột này.
- **Bộ lọc (Detection):** chỉ giữ lại các dòng có `Khả năng phủ telemetry Q3 -2026 = 1`; các kỹ thuật có flag = 0 không được đưa vào danh sách này.
- **Bộ lọc (Prevention):** giữ toàn bộ các dòng trong sheet `Prevention` (5 dòng gốc, trong đó dòng `T1003` được khai triển thành các sub-kỹ thuật theo ghi chú `Sub-technique (8)`, nhưng loại 2 sub Linux-only T1003.007/T1003.008 → còn 6 sub T1003.001–T1003.006 → 10 kỹ thuật/sub-kỹ thuật sau khai triển), gộp chung vào danh sách theo tactic bên dưới cùng các kỹ thuật từ Detection.
- Tactic của từng kỹ thuật được tra cứu qua skill `/map-technique` đối chiếu với `mitre-knowledge-base/techniques/`.

# Test Environment

**Cơ sở hạ tầng Thử nghiệm** Danh sách này áp dụng cho cùng môi trường mạng thử nghiệm (Detections Range) tập trung vào điểm cuối được dùng để đánh giá các plan tấn công. Cơ sở hạ tầng mô phỏng này bao gồm:

| Component                         | Specification                                                          |
| --------------------------------- | ---------------------------------------------------------------------- |
| Domain Controllers & File Servers | Windows Server 2022                                                    |
| Web Servers                       | Windows Server 2022                                                    |
| Workstations                      | Windows 11 Enterprise                                                  |
| Email Infrastructure              | Exchange Server 2019                                                   |
| Network Firewall                  | pfSense or Open Source                                                 |
| Network Segmentation              | Realistic segmentation — DMZ, internal workstation zones, server zones |

# Technique Scope (Detection Coverage = 1 + Prevention Coverage, by Tactic)

29 kỹ thuật/sub-kỹ thuật đã có telemetry phủ (Detection), cộng thêm 10 kỹ thuật/sub-kỹ thuật đã có khả năng prevent (Prevention, trích từ sheet `Prevention` trong `technique_detection_Q3_2024.md`, với T1003 đã khai triển thành 6 sub-kỹ thuật Windows-relevant T1003.001–T1003.006). Kỹ thuật thuộc nhiều tactic trong ATT&CK (T1078.002, T1543.003, T1112, T1055.001, T1055.002) được liệt kê lặp lại ở mọi tactic áp dụng.

Lưu ý: nguồn Prevention ghi ID `T1055.1` / `T1055.2`, đã chuẩn hóa về đúng định dạng ATT&CK `T1055.001` / `T1055.002`.

Lưu ý (cập nhật ATT&CK v19.1): tactic `Defense Evasion` (TA0005) đã được MITRE tách thành `Stealth` (TA0005) và tactic mới `Defense Impairment` (TA0112). Kỹ thuật `T1562.004 - Impair Defenses: Disable or Modify System Firewall` đã bị revoke, thay thế bằng `T1686.003 - Disable or Modify System Firewall: Windows Host Firewall` (tactic Defense Impairment). `T1548.002` không còn cross-list sang Defense Evasion/Stealth/Defense Impairment, chỉ còn thuộc Privilege Escalation.

## Initial Access
- [ ] T1078.002 - Valid Accounts: Domain Accounts

## Execution
- [ ] T1047 - Windows Management Instrumentation
- [ ] T1059.001 - Command and Scripting Interpreter: PowerShell
- [ ] T1059.003 - Command and Scripting Interpreter: Windows Command Shell
- [ ] T1204.002 - User Execution: Malicious File
- [ ] T1569.002 - System Services: Service Execution

## Persistence
- [ ] T1078.002 - Valid Accounts: Domain Accounts
- [ ] T1112 - Modify Registry
- [ ] T1543.003 - Create or Modify System Process: Windows Service

## Privilege Escalation
- [ ] T1078.002 - Valid Accounts: Domain Accounts
- [ ] T1543.003 - Create or Modify System Process: Windows Service
- [ ] T1068 - Exploitation for Privilege Escalation
- [ ] T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control
- [ ] T1055.001 - Process Injection: Dynamic-link Library Injection
- [ ] T1055.002 - Process Injection: Portable Executable Injection

## Stealth
- [ ] T1006 - Direct Volume Access
- [ ] T1070.004 - Indicator Removal: File Deletion
- [ ] T1078.002 - Valid Accounts: Domain Accounts
- [ ] T1055.001 - Process Injection: Dynamic-link Library Injection
- [ ] T1055.002 - Process Injection: Portable Executable Injection

## Defense Impairment
- [ ] T1112 - Modify Registry
- [ ] T1686.003 - Disable or Modify System Firewall: Windows Host Firewall

## Credential Access
- [ ] T1003.001 - OS Credential Dumping: LSASS Memory
- [ ] T1003.002 - OS Credential Dumping: Security Account Manager
- [ ] T1003.003 - OS Credential Dumping: NTDS
- [ ] T1003.004 - OS Credential Dumping: LSA Secrets
- [ ] T1003.005 - OS Credential Dumping: Cached Domain Credentials
- [ ] T1003.006 - OS Credential Dumping: DCSync

## Discovery
- [ ] T1007 - System Service Discovery
- [ ] T1018 - Remote System Discovery
- [ ] T1033 - System Owner/User Discovery
- [ ] T1057 - Process Discovery
- [ ] T1069.001 - Permission Groups Discovery: Local Groups
- [ ] T1069.002 - Permission Groups Discovery: Domain Groups
- [ ] T1082 - System Information Discovery
- [ ] T1083 - File and Directory Discovery
- [ ] T1087.002 - Account Discovery: Domain Account

## Lateral Movement
- [ ] T1021.002 - Remote Services: SMB/Windows Admin Shares
- [ ] T1021.004 - Remote Services: SSH
- [ ] T1570 - Lateral Tool Transfer

## Collection
- [ ] T1119 - Automated Collection

## Command and Control
- [ ] T1105 - Ingress Tool Transfer
- [ ] T1573.002 - Encrypted Channel: Asymmetric Cryptography

## Exfiltration
- [ ] T1041 - Exfiltration Over C2 Channel
