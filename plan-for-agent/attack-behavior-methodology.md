# Phương pháp luận trong việc dựng các hành vi tấn công

Rút ra từ `Enterprise/mustang_panda/Emulation_Plan/` và `Enterprise/scattered_spider/Emulation_Plan/`.

---

## Hệ thống phân loại Category

Mỗi technique trong Reference Table được gán một trong các category sau:

| Category | Ý nghĩa |
|---|---|
| `Calibrated - Not Benign` | Red team **chủ động tạo artifact rõ ràng** để detector có thể thấy. Hành vi là malicious. |
| `Not Calibrated - Not Benign` | Red team **thực hiện tự nhiên** không có artifact nhân tạo. Hành vi là malicious. |
| `Calibrated - Benign` | Red team thực hiện hành vi **benign nhưng trông giống attack**. Dùng cho noise/false-positive testing. |

---

## Nguyên lý 1 — Calibrated vs Not Calibrated

### Calibrated — Not Benign

Dùng khi technique **tạo ra artifact cố định, dễ quan sát**. Red team đảm bảo artifact tồn tại trước khi hỏi "detector có thấy không?".

**Ví dụ điển hình:**
- DLL Side-Loading: `gflags.exe` side-loads `gflagsui.dll` — file name cụ thể, path cụ thể
- Spearphishing attachment: email từ `dnaharis@tyrosh.com` với file đính kèm tên cụ thể
- Scheduled Task: task name `GFlagEditor` được tạo trong registry
- Tool download: `waitfor.exe` downloaded `Snaffler.exe` từ URL cụ thể

**Pattern chung:** Có thể viết Detection Criteria dạng `<process> executed <tool/command> tại <path>`

### Not Calibrated — Not Benign

Dùng khi technique **không thể tạo artifact nhân tạo thêm** mà không thay đổi bản chất của nó. Detector phải tự phát hiện từ behavioral pattern.

**Các nhóm technique thường là Not Calibrated:**

1. **Anti-analysis / Evasion stealthy** — technique cốt lõi là ẩn mình:
   - `T1497` Sandbox Evasion (kiểm tra foreground window, process name)
   - `T1622` Debugger Evasion (IsDebuggerPresent)
   - `T1218.013` Mavinject injection chain
   - `T1027.009` Embedded shellcode trong DLL data section

2. **Valid credential usage** — không có artifact phân biệt được với user hợp lệ:
   - `T1078.002` Valid Domain Accounts (đăng nhập bằng credential đúng)
   - `T1550.004` Web Session Cookie (dùng cookie hợp lệ đã bị đánh cắp)

3. **Inherently behavioral** — technique biểu hiện qua hành vi liên tục, không phải artifact tĩnh:
   - `T1095` Non-Application Layer Protocol (raw TCP traffic)
   - `T1213.003` Data from Code Repositories (query tool chạy tự nhiên)

**Pattern nhận biết:** Detection Criteria khó viết cụ thể — thường vẫn viết được nhưng artifact không phải do red team chủ động "để lại", mà là side effect tự nhiên của kỹ thuật.

---

## Nguyên lý 2 — Tỷ lệ Calibrated phản ánh stealth profile của adversary

| Adversary | Calibrated ratio | Giải thích |
|---|---|---|
| Mustang Panda (main scenario) | ~39% | Dùng custom malware (TONESHELL, PlugX) với nhiều lớp anti-analysis. Phần lớn evasion chain là Not Calibrated. |
| Scattered Spider (main scenario) | ~93% | Dùng legitimate tools và valid credentials. Hầu hết hành vi để lại artifact rõ ràng vì không có evasion đặc biệt. |
| Protections tests (cả hai) | ~97% | Test controls → cần signal rõ ràng → gần như toàn bộ Calibrated. |

**Kết luận:** Khi thiết kế hành vi tấn công, adversary dùng custom stealthy malware → nhiều Not Calibrated hơn. Adversary dùng legitimate tools → phần lớn Calibrated.

---

## Nguyên lý 3 — Detection Criteria phải là observable, specific event

**Sai:**
```
| Detection Criteria |
| Malware connects to C2 |
```

**Đúng:**
```
| Detection Criteria |
| waitfor.exe connects to 191.44.44.199 over TCP port 443 |
```

**Quy tắc viết Detection Criteria:**
- Format: `<parent_process> <action> <artifact/target> [trên <host>]`
- Phải có thể dùng để query trực tiếp trong SIEM / EDR
- Nếu artifact có path cụ thể → ghi path đầy đủ
- Nếu có nhiều host → ghi host cụ thể trong row hoặc tách row

---

## Nguyên lý 4 — Mỗi observable event là một row riêng

Không gộp nhiều events vào một row dù cùng technique:

```markdown
| Persistence | T1053.005 | Scheduled Task | Windows | .pif executable created GFlagEditor folder | Calibrated - Not Benign | ... |
| Persistence | T1053.005 | Scheduled Task | Windows | .pif executable scheduled task to execute gflags.exe | Calibrated - Not Benign | ... |
```

Hai row trên cùng technique ID nhưng hai observable events khác nhau → tách riêng.

---

## Nguyên lý 5 — Protections tests vs Main scenario

### Main scenario (Detections)

**Câu hỏi:** Detector có *nhìn thấy* hành vi không?

- Full kill chain 9+ steps
- Mix Calibrated / Not Calibrated theo bản chất adversary
- Thực hiện theo trình tự phụ thuộc nhau (cần step trước để thực hiện step sau)
- Môi trường: main eval domain

### Protections tests (Protections)

**Câu hỏi:** Security control có *chặn* hành vi không?

- Sub-chain 2–4 steps, cô lập một capability block
- Gần như 100% Calibrated để signal rõ ràng và reproducible
- Mỗi test chạy độc lập, không phụ thuộc state test khác
- Môi trường: separate protections domain
- **Delivery vector khác** so với main scenario để test generality của control

**Ví dụ delivery variant:**
- Main: DOCX spearphishing → TONESHELL (`wsdapi.dll`)
- Protections Test 4: PIF dropper → TONESHELL (`gflagsui.dll`)
- Protections Test 5: MSC file via MMC → PlugX (`rcdll.dll`)

Nếu control chỉ block theo file hash thì sẽ fail với variant — đây chính là mục đích.

---

## Nguyên lý 6 — CTI grounding bắt buộc

Mỗi technique phải có ít nhất một CTI report trong cột `Relevant CTI Reports`. Hành vi phải được **observed in the wild** — không tự ý thêm technique không có CTI backing.

Đây là lý do file header luôn có phần CTI citations được đánh số `[1]`, `[2]`...

---

## Nguyên lý 7 — Source code links cho custom tools

Khi technique dùng custom tool (TONESHELL, PlugX...), cột `Source Code Links` phải trỏ đến **hàm cụ thể** trong source code, không phải chỉ file:

```markdown
| [PerformFileDownloadTask](../Resources/toneshell/src/shellcode/exec.cpp#L241-L346) |
| [Xor Functions](../Resources/toneshell/src/common/xor.cpp) |
```

Với COTS tools (Snaffler, rclone, WinRAR...) → link đến repo hoặc để trống.

---

## Template thiết kế một hành vi tấn công mới

1. **Chọn technique** có CTI backing cho adversary đang mô phỏng
2. **Xác định artifact**: technique tạo ra artifact gì? File? Registry? Network connection? Process?
3. **Gán Category**:
   - Artifact tạo ra có thể được red team kiểm soát để rõ ràng hơn → `Calibrated`
   - Artifact là side effect tự nhiên không thể thêm signal → `Not Calibrated`
4. **Viết Detection Criteria**: một câu cụ thể format `<process> <action> <target>`
5. **Xác định host + user**: hành vi xảy ra trên máy nào, tài khoản nào
6. **Thêm source code link** nếu dùng custom tool
