# Phương pháp luận trong việc dựng hành vi Noise

Rút ra từ `Enterprise/scattered_spider/Emulation_Plan/Protections_Test_6_Scenario.md` và `noise-collection/noise-behavior.md`.

---

## Mục đích của Noise

Noise test đo **false positive rate** của security control, song song với việc đo true positive rate qua attack tests.

**Câu hỏi cốt lõi của noise test:** Nếu control block activity này → nó đang block một hành vi *bình thường của user*. Đây là kết quả fail, không kém gì việc miss một attack.

Một test suite hoàn chỉnh **bắt buộc** có cả hai chiều:
- Attack tests: đo khả năng phát hiện/chặn attack → True Positive
- Noise tests: đo khả năng *không* chặn benign → False Positive

---

## Category label

Noise activity dùng category: **`Calibrated - Benign`**

- `Calibrated`: red team chủ động tạo artifact rõ ràng (giống attack calibrated)
- `Benign`: hành vi là legitimate user activity, không phải attack

Cột `Red Team Activity` thường để trống hoặc `-` vì đây là *user activity*, không phải red team.

---

## Nguyên lý 1 — Dùng cùng Technique ID với attack, nhưng context khác

Noise technique phải **overlap technique ID với attack technique**. Nếu attack dùng `T1105` (curl download payload) thì noise cũng dùng `T1105` (curl download installer hợp lệ).

**Mục đích:** Kiểm tra xem rule/control có phân biệt được malicious vs legitimate use của cùng technique không. Nếu rule detect cả hai → false positive.

**Ví dụ từ Scattered Spider Test 6:**

| Attack technique | Noise equivalent |
|---|---|
| `T1105` — download Snaffler.exe từ attacker server | `T1105` — curl download TaskCoach từ SourceForge |
| `T1053.005` — tạo scheduled task để chạy malware | `T1053.005` — tạo DailyTask chạy Backup.ps1 hàng ngày |
| `T1021.001` — RDP lateral movement | `T1021.001` — admin RDP vào remote access server bình thường |
| `T1016` — ipconfig thu thập network info | `T1016` — admin chạy ipconfig để kiểm tra cấu hình mạng |
| `T1057` — tasklist để enumerate processes | `T1057` — user chạy tasklist debug performance |

---

## Nguyên lý 2 — Noise phải có realistic user story

Mỗi noise activity phải có **lý do hợp lý tại sao user làm điều này**. Không chỉ là "chạy lệnh cho xong" mà phải có context:

**Sai (không có user story):**
```
- Chạy ipconfig /all
```

**Đúng (có user story):**
```
- Run the following command to display detailed network configuration
  information.
  > ipconfig /all
```

Các user story điển hình trong noise tests:
- Người dùng tìm kiếm trên Google về cách tối ưu Windows → sau đó chạy lệnh liên quan
- Admin lên lịch backup hàng ngày tự động
- User tạo file ghi chú công việc
- Admin cài đặt phần mềm hợp lệ từ repo công khai
- User RDP vào server để thực hiện maintenance thường xuyên

---

## Nguyên lý 3 — Thứ tự thực hiện noise phải có flow tự nhiên

Noise test không phải danh sách lệnh rời rạc. Các activity phải **kết nối với nhau** theo flow hợp lý của một user:

```
Từ Scattered Spider Test 6:
1. Tạo scheduled task (admin task)
2. Mở notepad, viết supervisor note
3. Mở browser tìm kiếm về Windows services
4. Vào forum đọc bài về service optimization
5. Chạy tasklist để xem processes
6. Chạy ipconfig /all
7. RDP sang server khác
8. Download TaskCoach (task management app)
9. Cài đặt TaskCoach
10. Chạy systeminfo | findstr
```

Flow này kể câu chuyện: *user admin đang tối ưu hệ thống* — tất cả hành vi đều coherent.

---

## Nguyên lý 4 — Time spacing giữa các noise activity

Mỗi noise activity phải có **"Wait one minute"** hoặc tương đương giữa các bước:

```markdown
- Wait one minute, then press win+R and then enter `cmd` to open Command Prompt.
- Run the following command to...
```

Mục đích: tránh tạo ra burst pattern mà chỉ malware mới làm (thực hiện nhiều thao tác liên tiếp trong vài giây).

---

## Nguyên lý 5 — Noise test là dedicated, không lồng vào attack test

Noise activity **không trộn lẫn** vào giữa các attack steps. Nó là một test riêng hoàn toàn:

- Scattered Spider: `Protections_Test_6_Scenario.md` (NOISE ONLY) — toàn bộ file là noise
- Trong title file ghi rõ `(NOISE ONLY)` để phân biệt

Trong Reference Table của noise test, cột `Red Team Activity` để `-` hoặc trống vì không có red team action — chỉ có user action.

---

## Nguyên lý 6 — Các technique phổ biến nhất trong noise tests

Dựa trên `noise-collection/noise-behavior.md`, các technique sau xuất hiện nhiều nhất trong các noise tests (cross-scenario):

| Tactic | Technique | Lý do phổ biến |
|---|---|---|
| Command and Control | `T1105` Ingress Tool Transfer | curl/browser download rất phổ biến với user và attacker |
| Command and Control | `T1072` Software Deployment Tools | choco install overlap với malware installer |
| Lateral Movement | `T1021.001` RDP | admin RDP vs adversary lateral movement |
| Lateral Movement | `T1021.002` SMB/Admin Shares | net use / PsExec đều dùng cho admin và attack |
| Discovery | `T1082` System Information Discovery | systeminfo chạy bởi cả admin và malware |
| Discovery | `T1057` Process Discovery | tasklist /v |
| Discovery | `T1016` Network Config Discovery | ipconfig /all |
| Discovery | `T1007` System Service Discovery | Get-WmiObject Win32_Service |
| Execution | `T1053.005` Scheduled Task | schtasks create cho backup vs persistence |
| Execution | `T1059.001` PowerShell | Get-ChildItem, Stop-Service đều rất phổ biến |
| Defense Evasion | `T1562.004` Disable Firewall | netsh advfirewall = admin task và ransomware prep |
| Collection | `T1560.001` Archive via Utility | 7z với password = file backup và data staging |

---

## Template thiết kế một noise block mới

1. **Chọn technique** cần test false positive — thường là technique cũng xuất hiện trong attack test tương ứng
2. **Tạo user story**: ai là user? họ đang làm gì? lý do hợp lý là gì?
3. **Chọn tool/command benign** thực hiện cùng technique (e.g., curl download legit installer thay vì payload)
4. **Viết flow** với time spacing, context-setting (browser search trước khi chạy lệnh)
5. **Điền Reference Table**:
   - Category: `Calibrated - Benign`
   - Red Team Activity: `-` (để trống)
   - Detection Criteria: `<process> executed <command>` (giống attack criteria về format)
6. **Verify overlap**: detection criteria của noise phải trigger **cùng rule** có thể trigger với attack — nếu không overlap thì noise test vô nghĩa

---

## Ví dụ hoàn chỉnh: thiết kế noise cho T1105 (Ingress Tool Transfer)

**Attack equivalent:** `curl.exe` download `Snaffler.exe` từ `http://pasteme.io/files/Snaffler.exe`

**Noise design:**

**User story:** User admin cần cài task management tool để theo dõi công việc.

**Flow:**
```
1. User mở browser, tìm "windows task management software free"
2. User vào trang SourceForge, tìm TaskCoach
3. User mở cmd, chạy:
   curl -L -o C:\Users\%username%\Downloads\TaskCoachSetup.exe
         https://sourceforge.net/projects/taskcoach/files/latest/download
4. User cài TaskCoach, đóng cửa sổ
```

**Reference Table:**
```
| Command and Control | T1105 | Ingress Tool Transfer | Windows
| cmd.exe executed curl to download TaskCoachSetup.exe from SourceForge
| Calibrated - Benign | - | tentowers (10.26.4.102) | tharlaw | - | -
```

**Overlap check:** Rule "curl.exe downloads .exe file" sẽ trigger cả noise lẫn attack → noise test hợp lệ.
