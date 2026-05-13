# Protections Methodology Overview

## Mục tiêu

**Protections** là nhóm kịch bản dùng để đánh giá khả năng sản phẩm bảo mật ngăn chặn, làm gián đoạn, hoặc giảm tác động của một hành vi adversary cụ thể. Trọng tâm là outcome bảo vệ tại thời điểm hoặc gần thời điểm thực thi, khác với Detections vốn tập trung vào khả năng quan sát và điều tra.

Trong bối cảnh dự án này, Protections dùng để hiểu cách MITRE tách các hành vi cần kiểm tra thành những protection test nhỏ hơn, từ đó hỗ trợ chuẩn bị sản phẩm trước MITRE ATT&CK Evaluation. Scope technique vẫn phải đối chiếu với `testlab-enterprise\mitre-outline\Scenario 1.md` và `Scenario 2.md`.

## Đặc điểm cơ bản

- Thường ngắn và tập trung hơn Detections, mỗi test xoay quanh một hoặc một cụm hành vi cần đánh giá khả năng chặn.
- Có thể bắt đầu từ trạng thái đã có foothold hoặc đã chuẩn bị sẵn lab context, thay vì mô phỏng toàn bộ intrusion chain từ đầu.
- **Voice Track** vẫn cần mô tả ý đồ adversary, nhưng thường trực tiếp hơn và gắn với hành vi cần protection.
- **Procedures** cần đủ rõ để tạo ra hành vi kiểm thử nhất quán, bao gồm setup, execution, và expected output.
- **Reference Tables** vẫn ánh xạ ATT&CK, nhưng Detection Criteria thường nên được hiểu như tiêu chí quan sát/protection outcome cho hành vi đó.
- Kịch bản Protections nên nhấn mạnh điều kiện thành công/thất bại của protection: hành vi có bị block, quarantine, rollback, deny, kill process, prevent file write, prevent credential access, prevent network connection, hoặc ngăn tác động cuối hay không.
- Vì mục tiêu là protection, tránh kéo dài thành một operation flow quá rộng nếu không cần thiết.

## Ví dụ tham khảo 2025

- `Enterprise\scattered_spider\Emulation_Plan\Protections_Test_1_Scenario.md`
- `Enterprise\scattered_spider\Emulation_Plan\Protections_Test_2_Scenario.md`
- `Enterprise\scattered_spider\Emulation_Plan\Protections_Test_3_Scenario.md`
- `Enterprise\scattered_spider\Emulation_Plan\Protections_Test_6_Scenario.md`
- `Enterprise\scattered_spider\Emulation_Plan\Protections_Test_7_Scenario.md`
- `Enterprise\mustang_panda\Emulation_Plan\Protections_Test_4_Scenario.md`
- `Enterprise\mustang_panda\Emulation_Plan\Protections_Test_5_Scenario.md`

Chỉ dùng các file trên để lấy insight về cách MITRE cô lập hành vi protection test, mô tả procedure, và xác định outcome. Không sao chép kịch bản, payload, hoặc flow nguyên bản.

## Cách áp dụng cho agent

Khi viết hoặc sửa kịch bản Protections:

1. Chọn technique hoặc cụm hành vi cần kiểm tra từ scope MITRE năm nay.
2. Xác định rõ protection outcome mong muốn trước khi viết procedure.
3. Thiết kế test nhỏ, tái lập được, và không mở rộng thành full chain nếu mục tiêu chỉ là protection.
4. Viết setup và procedure đủ rõ để tạo cùng một hành vi trong lab.
5. Ghi rõ tiêu chí đánh giá: sản phẩm cần chặn, cảnh báo, cô lập, hoặc giảm tác động ở điểm nào.
