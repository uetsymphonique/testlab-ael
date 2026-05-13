# Detections Methodology Overview

## Mục tiêu

**Detections** là nhóm kịch bản dùng để đánh giá khả năng sản phẩm bảo mật phát hiện, ghi nhận, tương quan, và hỗ trợ điều tra chuỗi hành vi adversary trong môi trường Enterprise. Trọng tâm là quan sát được hành vi tấn công qua telemetry và detection logic, không nhất thiết phải chặn hành vi ngay tại thời điểm thực thi.

Trong bối cảnh dự án này, Detections dùng để dựng một adversary emulation scenario đóng vai trò đề cương chuẩn bị cho sản phẩm trước MITRE ATT&CK Evaluation. Scope technique phải bám theo `testlab-enterprise\mitre-outline\Scenario 1.md` và `Scenario 2.md`.

## Đặc điểm cơ bản

- Thường là một chuỗi hành vi dài, có ngữ cảnh adversary rõ ràng từ Initial Access đến các tactic sau như Execution, Persistence, Defense Evasion, Discovery, Credential Access, Lateral Movement, Collection, Exfiltration, Command and Control, hoặc Impact.
- Mỗi step cần có **Voice Track** để giải thích ý đồ adversary, không chỉ liệt kê command.
- **Procedures** mô tả cách thực hiện đủ chi tiết để tái hiện trong lab, kèm expected output khi cần xác nhận bước chạy đúng.
- **Reference Tables** là phần rất quan trọng, dùng để ánh xạ tactic, technique ID, technique name, platform, detection criteria, category, red team activity, host/user, source code, và CTI reference.
- Detection Criteria nên mô tả tín hiệu có thể quan sát được: process, command line, file, registry, network, authentication, cloud event, hoặc telemetry liên quan.
- Có thể có nhiều hành vi liên tiếp tạo thành một operation flow, vì mục tiêu là đánh giá khả năng phát hiện theo chuỗi và theo bối cảnh.

## Ví dụ tham khảo 2025

- `Enterprise\mustang_panda\Emulation_Plan\Mustang_Panda_Scenario.md`
- `Enterprise\scattered_spider\Emulation_Plan\Scattered_Spider_Scenario.md`

Chỉ dùng các file trên để lấy insight về cách MITRE trình bày hành vi, phase, procedure, và detection mapping. Không sao chép kịch bản, payload, hoặc flow nguyên bản.

## Cách áp dụng cho agent

Khi viết hoặc sửa kịch bản Detections:

1. Chọn technique từ scope MITRE năm nay.
2. Tìm insight trong các Detections scenario cũ nếu cần hiểu cách MITRE diễn giải hành vi.
3. Thiết kế flow độc lập cho `windows-adversary-plan`.
4. Viết step theo format chuẩn: Voice Track, Procedures, Reference Tables.
5. Đảm bảo Detection Criteria cụ thể, có thể kiểm chứng bằng telemetry, và không chỉ là mô tả chung chung.
