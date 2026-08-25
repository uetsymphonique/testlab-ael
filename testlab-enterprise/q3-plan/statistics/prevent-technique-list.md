# Overview

Danh sách các kỹ thuật/sub-kỹ thuật ATT&CK **đã có khả năng prevent**, tính đến Q3 2026. Trích từ sheet `Prevention` trong `technique_detection_Q3_2024.md`. Có thể trùng với `detect-technique-list.md` — không sao, hai file phục vụ hai mục tiêu kiểm tra độc lập (Detections và Protections).

Dùng làm scope file cho `check.py` khi kiểm tra plan coverage cho mục tiêu **Protections**.

Nguồn:
- T1068, T1548.002, T1055.001, T1055.002 — trực tiếp từ sheet Prevention
- T1003.001–T1003.006 — khai triển từ `T1003 Sub-technique (8)`, loại T1003.007/T1003.008 (Linux-only)

Lưu ý: nguồn Prevention ghi ID `T1055.1` / `T1055.2`, đã chuẩn hóa về `T1055.001` / `T1055.002`.

Lưu ý (ATT&CK v19.1): T1548.002 chỉ còn thuộc Privilege Escalation (không còn cross-list sang Stealth/Defense Impairment).

# Technique Scope (Prevention-Only, by Tactic)

## Privilege Escalation
- [ ] T1068 - Exploitation for Privilege Escalation
- [ ] T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control
- [ ] T1055.001 - Process Injection: Dynamic-link Library Injection
- [ ] T1055.002 - Process Injection: Portable Executable Injection

## Stealth
- [ ] T1055.001 - Process Injection: Dynamic-link Library Injection
- [ ] T1055.002 - Process Injection: Portable Executable Injection

## Credential Access
- [ ] T1003.001 - OS Credential Dumping: LSASS Memory
- [ ] T1003.002 - OS Credential Dumping: Security Account Manager
- [ ] T1003.003 - OS Credential Dumping: NTDS
- [ ] T1003.004 - OS Credential Dumping: LSA Secrets
- [ ] T1003.005 - OS Credential Dumping: Cached Domain Credentials
- [ ] T1003.006 - OS Credential Dumping: DCSync
