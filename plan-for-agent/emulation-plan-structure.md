# Cách trình bày của một Emulation Plan

Rút ra từ `Enterprise/mustang_panda/` và `Enterprise/scattered_spider/`.

---

## Cấu trúc thư mục

```
Enterprise/<adversary>/
├── Emulation_Plan/
│   ├── <Adversary>_Scenario.md          # Kịch bản chính (main scenario)
│   ├── <Adversary>_Alternative_Steps.md # Các bước thay thế tùy môi trường
│   ├── <Adversary>_Cleanup_Guide.md     # Hướng dẫn dọn dẹp sau test
│   ├── Protections_Test_<N>_Scenario.md # Kịch bản con cho protections tests
│   └── README.md
├── CTI_Emulation_Resources/
│   └── <Adversary>_Scenario_Overview.md # Tóm tắt high-level cho người mới
├── Resources/                           # Source code tool, payload, C2 client
├── Attack_Layers/                       # ATT&CK Navigator layer files
└── README.md
```

---

## Cấu trúc file Scenario chính

### 1. Header — CTI citations

Phần đầu file liệt kê toàn bộ CTI references được đánh số. Số này được dùng inline trong Reference Tables sau.

```markdown
[1]:https://cloud.google.com/blog/topics/...
[2]:https://unit42.paloaltonetworks.com/...
```

### 2. Step 0 — Setup

Bao gồm:
- Cách kết nối vào attack host (thường qua RDP hoặc SSH)
- Khởi động C2 server / handler
- Thiết lập môi trường Kali (venv, tools)
- Kết nối đến jumpbox và victim host

```markdown
## Step 0 - Setup
### Procedures
- ☣️ Initiate an RDP session to the Kali attack host `driftmark (174.3.0.70)`
- ☣️ In a new terminal window, start the C2 handler if not already running
```

### 3. Các Steps tấn công

Mỗi step tương ứng một **tactic phase** hoặc nhóm kỹ thuật liên quan. Cấu trúc:

```markdown
## Step <N> - <Tactic>

### Voice Track
<Đoạn văn mô tả hành vi ở góc nhìn adversary. Viết như đang kể chuyện.>

### Procedures
<Danh sách các bước thực thi step-by-step, bao gồm:>
- ☣️ <Bước red team (có hại)>
- <Bước không có ký hiệu (setup bình thường, không cần chú ý đặc biệt)>

  ```cmd/bash/python
  <câu lệnh cụ thể>
  ```

  - ***Expected Output***
    ```text
    <output mong đợi>
    ```

### Reference Tables
<Bảng ATT&CK mapping>
```

**Quy tắc ký hiệu trong Procedures:**
- `☣️` đánh dấu bước **red team thực sự nguy hiểm** — thay đổi trạng thái hệ thống, chạy payload, hoặc thực hiện hành vi tấn công. Chỉ những bước này mới cần operator thực thi cẩn thận.
- Bước không có `☣️` là bước bình thường (mở browser, navigate UI, đọc output...).

### 4. Reference Table — format chuẩn

Mỗi step kết thúc với một Reference Table ánh xạ hành vi vừa thực hiện sang ATT&CK.

```markdown
| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Defense Evasion | T1574.002 | Hijack Execution Flow: DLL Side-Loading | Windows | gflags.exe side loads unsigned gflagsui.dll | Calibrated - Not Benign | Legitimate binary `gflags.exe` side-loads TONESHELL loader DLL | bitterbridge (10.26.4.103) | btully | [DLL exports](../Resources/...) | [21], [22]
```

**Ý nghĩa từng cột:**

| Cột | Mô tả |
|---|---|
| `Tactic` | MITRE tactic (viết đầy đủ) |
| `Technique ID` | ID ATT&CK (e.g., `T1574.002`) |
| `Technique Name` | Tên đầy đủ bao gồm sub-technique nếu có |
| `Platform` | `Windows`, `Linux`, `IaaS`, `Identity Provider`... |
| `Detection Criteria` | **Điều kiện quan sát cụ thể** — phải là một event/artifact có thể check được (không phải mô tả chung) |
| `Category` | `Calibrated - Not Benign` / `Not Calibrated - Not Benign` / `Calibrated - Benign` |
| `Red Team Activity` | Mô tả ngắn hành vi red team từ góc nhìn bên ngoài |
| `Hosts` | Hostname + IP cụ thể nơi hành vi xảy ra |
| `Users` | Tài khoản thực hiện hành vi |
| `Source Code Links` | Link đến code trong Resources/ (nếu là custom tool) |
| `Relevant CTI Reports` | Số reference từ header (e.g., `[2], [9]`) |

**Lưu ý quan trọng về Detection Criteria:**
- Phải cụ thể đến mức process name + argument: `waitfor.exe executed netstat -anop tcp`
- Không viết chung chung như "malware connects to C2"
- Nếu một technique xảy ra nhiều lần ở các hosts khác nhau, tách thành nhiều row

### 5. End of Test

```markdown
## End of Test
### Voice Track
This step includes the shutdown procedures for the end of this Protections Test
### Procedures
- <Đóng sessions, dọn dẹp artifacts nếu cần>
```

---

## Cấu trúc Alternative Steps

`<Adversary>_Alternative_Steps.md` chứa các **bước thay thế** cho từng step trong main scenario, dùng khi:
- Môi trường không hỗ trợ kỹ thuật gốc
- Muốn test variant khác của cùng technique
- Backup nếu payload chính bị block

Format giống main scenario nhưng có header ghi rõ đây là thay thế cho Step nào.

---

## Cấu trúc Protections Tests

Mỗi `Protections_Test_<N>_Scenario.md` là một **kịch bản con độc lập**, không kế thừa state từ main scenario. Cấu trúc giống main scenario nhưng:
- Chỉ có 2–4 steps (sub-chain cô lập)
- Có thể dùng delivery vector khác (ví dụ: PIF dropper thay vì DOCX)
- Môi trường lab khác (domain khác, hostname khác)
- Số test không nhất thiết liên tục — chỉ một subset được gán cho mỗi adversary

---

## Cấu trúc Cleanup Guide

`<Adversary>_Cleanup_Guide.md` liệt kê từng artifact được tạo ra trong main scenario và cách xóa:
- File/folder đã drop
- Registry key đã tạo
- Scheduled task đã tạo
- Process đang chạy cần kill
- Network connections cần terminate
