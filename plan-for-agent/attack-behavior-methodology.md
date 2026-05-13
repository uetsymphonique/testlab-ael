# Phương pháp luận trong việc dựng các hành vi tấn công

Rút ra từ [`Enterprise/mustang_panda/Emulation_Plan/`](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md) và [`Enterprise/scattered_spider/Emulation_Plan/`](../Enterprise/scattered_spider/Emulation_Plan/Scattered_Spider_Scenario.md).

---

## Hệ thống phân loại Category

Mỗi technique trong Reference Table được gán một trong các category sau:

| Category | Ý nghĩa |
|---|---|
| `Calibrated - Not Benign` | Substep là **scored behavior** và thoả 4 điều kiện (observable, reproducible, independently verifiable, fair scoring point). Hành vi là malicious; được tính vào denominator của detection rate. |
| `Not Calibrated - Not Benign` | Substep **không được tính điểm** vì một trong ba lý do: (1) là **setup substep** — tiền đề cho scored behavior kế tiếp; (2) là **implementation detail** — cơ chế bên trong của scored behavior khác đã có mắt xích đo rõ hơn; (3) là scored behavior nhưng **không thoả ít nhất một trong 4 điều kiện**. Hành vi là malicious, vẫn ghi đầy đủ trong Reference Table nhưng không tính vào denominator. |
| `Calibrated - Benign` | Substep là hành vi **hợp lệ, bình thường** nhưng trông giống attack từ góc nhìn telemetry. Dùng để kiểm tra false-positive — xem `noise-behavior-methodology.md`. |

---

## Nguyên lý 1 — Nhãn là quyết định per scenario, per substep

`Calibrated` / `Not Calibrated` **không phải thuộc tính cố định của technique**. Cùng một technique có thể nhận nhãn khác nhau giữa hai scenario tuỳ vào loại test và vai trò của substep trong chuỗi.

**Ví dụ thực tế:** `T1566.001 Spearphishing Attachment`
- [Mustang Panda **main scenario**](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md) → **Not Calibrated**: email delivery nằm ngoài bề mặt EDR endpoint đang đo; substep này chỉ là tiền đề để victim download payload.
- [Mustang Panda **Protections Test 4**](../Enterprise/mustang_panda/Emulation_Plan/Protections_Test_4_Scenario.md) → **Calibrated**: bề mặt test mở rộng sang email gateway; chặn delivery chính là điểm cần đo.

Hệ quả: khi gán nhãn, phải xác lập ngữ cảnh trước, không gán theo cảm tính hoặc theo "technique này thường là gì".

---

## Quy trình gán nhãn — 3 lớp

### Lớp 0 — Xác lập ngữ cảnh (làm trước khi nhìn vào từng substep)

Ghi rõ **4 thông số** cho scenario đang xây:

1. **Loại test**: Detections hay Protections.
2. **Loại Scenario** (chỉ áp dụng cho Detections):
   - **Scenario 1 — EDR-centric**: target là EDR / endpoint protection / SIEM tập trung host. Bề mặt đo giới hạn trong endpoint sensors.
   - **Scenario 2 — XDR / Enterprise**: target là XDR platform, identity protection, MDR/MSSP. Bề mặt đo mở rộng sang identity, cloud, cross-host.
3. **Bề mặt đo lường**: liệt kê cụ thể các kênh telemetry được giả định bao phủ.

   | Loại | Kênh telemetry trong scope |
   |---|---|
   | Scenario 1 (EDR) | Process tree, command line, file I/O, registry, network connection, DNS query, script-block log — **chỉ endpoint sensors** |
   | Scenario 2 (XDR) | Tất cả Scenario 1 **cộng thêm**: IdP/SSO audit log, cloud API call log (AWS CloudTrail, Azure AD, GCP), cross-host correlation, identity anomaly signal |
   | Protections | Tuỳ scope: thêm email gateway, web filter, identity provider nếu khai báo trong setup |

4. **Mục tiêu của substep trong chuỗi**: xem Lớp 1.

### Lớp 1 — Xác định vai trò trong chuỗi (gating)

Phân loại substep vào 1 trong 3 vai trò. Chỉ vai trò **Scored behavior** mới được phép Calibrated; hai vai trò còn lại → Not Calibrated ngay, không cần kiểm tra tiếp.

| Vai trò | Đặc điểm | Nhãn |
|---|---|---|
| **Scored behavior** | Điểm bạn muốn đo: vendor có thấy / có chặn không | Ứng viên Calibrated → đi tiếp Lớp 2 |
| **Setup substep** | Tồn tại để dẫn đến scored behavior kế tiếp; bỏ nó thì behavior kế tiếp không xảy ra | Not Calibrated |
| **Implementation detail** | Cơ chế bên trong của một scored behavior khác đã được đo ở mắt xích quan trọng hơn | Not Calibrated |

**Cách phát hiện:**
- Setup substep: *"Nếu bỏ substep này thì scored behavior tiếp theo còn xảy ra không?"* — Không → setup.
- Implementation detail: *"Có substep Calibrated khác trong chuỗi này đã nói lên thông tin tương đương nhưng rõ hơn không?"* — Có → implementation detail, tránh double-count.

**Các nhóm thường là implementation detail:**
- Native API call nằm trong loader chain (T1106 `NtCreateSection`, `ws2_32.send`, `MSXML2.XMLHTTP`) khi đã có substep mô tả output của chain đó (process-create, file-write, network connection).
- Nội dung mã hoá bên trong payload đã Calibrated (T1027.013 PEM structure của file đã Calibrated ở HTML Smuggling).
- API call phụ phục vụ token/handle thao tác khi đã có substep đo process-create outcome (T1134.002 `CreateProcessAsUser` khi T1134.001 đã Calibrated).
- **T1573.001** (PSK symmetric) khi C2 channel đã Calibrated (T1071.004): payload bytes mã hoá bằng key ẩn trong malware, evaluator không verify được mà không có key → không thể độc lập confirm "đây là T1573.001" → Not Calibrated.
  - **Ngoại lệ — T1573.002** (TLS/asymmetric): TLS certificate và JA3 fingerprint là artifact độc lập verify được từ network capture. Đây là detection axis riêng biệt (TLS fingerprinting, cert analysis). T1573.002 được Calibrated ngay cả khi T1071.001 đã Calibrated — hai row, hai điểm đo khác nhau. Xác nhận từ [Mustang Panda Step 7](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md) PlugX C2: cả T1071.001 và T1573.002 đều Calibrated.
- Tool scanning behavior bên trong authenticated session (T1213, T1552 tool execute against internal service) khi authentication event (T1078) đã Calibrated: tool's internal requests khó phân biệt với legitimate browsing nếu không biết trước tool signature → Not Calibrated. Authentication log entry là scoring point, không phải scanning behavior.

**Các nhóm thường là setup substep:**
- Attacker upload file lên server → đây chỉ là staging để victim sau đó tải; victim-side event mới là scored.
- Email arrive ở mailbox trong Detections endpoint-only (không bao gồm mail gateway trong scope).
- User click mở file/link khi mục tiêu thật sự là process spawn từ đó — *ngoại lệ*: nếu click gây ra browser request đến domain phishing cụ thể và đó là network event được đo, click có thể Calibrated (xem T1204.001 [Mustang Panda Step 7](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md)).
- **Post-objective cleanup/teardown steps**: xoá file, xoá registry key, self-delete batch script sau khi adversary đã đạt objective (ví dụ [Mustang Panda Step 9](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md) `del_WinGupSvc.bat`) → Not Calibrated dù artifact cụ thể. Phân biệt với in-chain stealth cleanup (xoá staged file trong khi attack flow đang tiếp diễn) — loại này có thể Calibrated.
- **Substep thực thi qua ghost/injected process**: khi executing process bản thân là ghost process (Herpaderping) hoặc bị inject bởi implant (ví dụ `waitfor.exe` sau `mavinject`), *mọi substep* được thực thi qua process đó đều Not Calibrated — kể cả khi artifact cụ thể. Lý do: evaluator không thể độc lập quy trách nhiệm "miss này do vendor kém" khi parent process context là anomaly chưa được xác lập; attribution không thể độc lập verify. Xác nhận từ [Mustang Panda Step 2](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md): T1049 `netstat`, T1016 `ipconfig`, T1018 SharpNBTScan đều Not Calibrated khi chạy qua `waitfor.exe`. *Contrast*: [Scattered Spider Step 2](../Enterprise/scattered_spider/Emulation_Plan/Scattered_Spider_Scenario.md) — cùng T1018, T1049 nhưng chạy từ `cmd.exe` user bình thường → tất cả Calibrated.

### Lớp 2 — Checklist 4 điều kiện cho Calibrated

Substep được Calibrated khi và chỉ khi thoả **tất cả 4** điều kiện:

| # | Điều kiện | Loại trừ |
|---|---|---|
| 1 | **Observable** — có ít nhất một artifact thuộc kênh telemetry đã khai báo ở Lớp 0 (process, file, registry, network, DNS, auth, cloud event) | Artifact chỉ tồn tại trong memory tiến trình malware hoặc không sinh telemetry ổn định bên ngoài |
| 2 | **Reproducible** — artifact xuất hiện giống nhau ở mọi lần chạy: path, filename, command line, IP/port, sender/recipient | Timing-dependent, GUID ngẫu nhiên không theo template, dữ liệu chỉ có trong stack/heap |
| 3 | **Independently verifiable** — evaluator xác nhận được artifact mà không dựa vào claim của red team (OS log, file trên disk, packet capture, event log) | Chỉ verify được bằng cách đọc source code malware |
| 4 | **Fair scoring point** — sản phẩm thuộc category đang test có cơ hội thấy artifact nếu hoạt động đúng chức năng | Artifact thuộc bề mặt mà loại sản phẩm không bao phủ trong scope test |

> **Điều kiện 4 là điểm flip nhãn chính giữa Scenario 1 và Scenario 2.** Cùng một technique có thể pass ở Scenario 2 nhưng fail ở Scenario 1 nếu artifact nằm ngoài endpoint:
> - `T1078.004` Valid Accounts: Cloud Accounts — không có endpoint artifact → **Not Calibrated** ở Scenario 1; cloud audit log (AWS CloudTrail) là artifact độc lập verify được → **Calibrated** ở Scenario 2.
> - `T1550.004` Web Session Cookie pivot cross-host — endpoint không thấy session reuse; IdP/SSO anomaly detectable → **Calibrated** ở Scenario 2.
> - Ngược lại, **ghost process rule** làm fail **điều kiện 3** (independently verifiable) bất kể Scenario — không bị ảnh hưởng bởi measurement surface.

Một điều kiện không thoả → **Not Calibrated**.

### Lớp 3 — Heuristic phát hiện gán sai

Sau khi gán nhãn, đối chiếu:

- **Anti-analysis / evasion check nội bộ được Calibrated** → gần như luôn sai. `T1497` foreground window, `T1622` IsDebuggerPresent — check xảy ra hoàn toàn trong memory tiến trình, không có external artifact, điều kiện 1 không thoả.
- **Native API call in-memory được Calibrated** → gần như luôn sai. `T1106` CoCreateGuid, `ws2_32.send`, `T1082` GetComputerNameA khi gọi từ injected context — không có artifact EDR-observable độc lập với process-create/network event đã Calibrated ở mắt xích khác; điều kiện 1 không thoả hoặc là implementation detail của scored behavior kế tiếp.
- **Calibrated nhưng Detection Criteria viết trừu tượng** (`Malware connects to C2`, `Loader decrypts payload`) → vi phạm điều kiện 1–2. Hạ xuống Not Calibrated hoặc viết lại Detection Criteria cụ thể trước.
- **Not Calibrated nhưng artifact rõ, thuộc bề mặt đo, lần đầu xuất hiện trong chuỗi** → kiểm tra Lớp 1: nếu không phải setup hay implementation detail thật sự → nâng Calibrated.
- **Tỷ lệ Calibrated ~100% trong Detections của adversary stealthy** → nghi ngờ: adversary custom malware thực tế có nhiều evasion/internal chain → kiểm tra lại từng substep.
- **Hai row cùng technique, cùng event vật lý, cùng nhãn** → double-count; một trong hai là implementation detail.
- **Cùng technique flip nhãn giữa hai scenario** → đúng nếu loại test hoặc bề mặt đo khác nhau; sai nếu cùng ngữ cảnh và cùng event.
- **Discovery/lateral commands Calibrated khi chạy bởi user process nhưng Not Calibrated khi chạy qua implant** → kiểm tra executing process. Nếu parent là ghost/injected → Not Calibrated dù artifact rõ (xem "Substep thực thi qua ghost/injected process" ở Lớp 1). Ví dụ: T1018 `nltest` từ `cmd.exe` user ([Scattered Spider Step 2](../Enterprise/scattered_spider/Emulation_Plan/Scattered_Spider_Scenario.md)) → Calibrated; T1018 SharpNBTScan từ `waitfor.exe` (TONESHELL) ([Mustang Panda Step 2](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md)) → Not Calibrated.

---

## Nguyên lý 2 — Tỷ lệ Calibrated bị chi phối bởi hai driver độc lập

Tỷ lệ Calibrated trong một scenario không chỉ phản ánh một yếu tố — nó là tích hợp của **hai driver** tác động độc lập:

---

### Driver 1 — Stealth profile của adversary

| Adversary | Calibrated ratio | Giải thích |
|---|---|---|
| [Mustang Panda (main)](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md) | ~39% | Custom malware (TONESHELL, PlugX) với injection chain sâu. Phần lớn evasion chain là Not Calibrated. |
| [Scattered Spider (main)](../Enterprise/scattered_spider/Emulation_Plan/Scattered_Spider_Scenario.md) | ~93% | Legitimate tools + valid credentials. Không có evasion đặc biệt → artifact rõ ràng trên mọi surface. |
| Protections tests ([PT4](../Enterprise/mustang_panda/Emulation_Plan/Protections_Test_4_Scenario.md), [PT5](../Enterprise/mustang_panda/Emulation_Plan/Protections_Test_5_Scenario.md), [SS PT1](../Enterprise/scattered_spider/Emulation_Plan/Protections_Test_1_Scenario.md)…) | ~97% | Test controls → cần signal rõ ràng → gần như toàn bộ Calibrated. |

**Stealth profile** không chỉ do technique mà còn do *ai thực thi* — cùng hành vi flip nhãn tuỳ executing agent:

| Scenario | Technique | Executing agent | Nhãn |
|---|---|---|---|
| [Scattered Spider Step 2](../Enterprise/scattered_spider/Emulation_Plan/Scattered_Spider_Scenario.md) | T1018 `nltest /dclist` | `cmd.exe` user bình thường | Calibrated |
| [Mustang Panda Step 2](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md) | T1018 SharpNBTScan | `waitfor.exe` ghost (TONESHELL via mavinject) | Not Calibrated |
| [Scattered Spider Step 2](../Enterprise/scattered_spider/Emulation_Plan/Scattered_Spider_Scenario.md) | T1105 AdExplorer download | `firefox.exe` | Calibrated |
| [Mustang Panda Step 2](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md) | T1105 SharpNBTScan download | `waitfor.exe` ghost | Not Calibrated |

Kết luận thực hành: trong scenario dùng custom implant với injection chain, action **sau injection** thường Not Calibrated; action **trước injection** (DLL load, injection event) thường Calibrated.

---

### Driver 2 — Measurement surface của Scenario (Scenario 1 vs Scenario 2)

Cùng một adversary và cùng technique, **Scenario 2 cho tỷ lệ Calibrated cao hơn Scenario 1** vì bề mặt đo rộng hơn — nhiều techniques pass điều kiện 4 (fair scoring point) hơn:

| Technique | Scenario 1 (EDR) | Scenario 2 (XDR) | Lý do flip |
|---|---|---|---|
| `T1078.004` Valid Accounts: Cloud Accounts | **Not Calibrated** | **Calibrated** | Không có endpoint artifact; cloud audit log (CloudTrail, Entra ID) là artifact độc lập |
| `T1550.004` Web Session Cookie | **Not Calibrated** | **Calibrated** | Endpoint không thấy session reuse; IdP/SSO anomaly là scored signal |
| `T1098.001` Additional Cloud Credentials | **Not Calibrated** | **Calibrated** | Chỉ có cloud audit trail; không có endpoint artifact |
| `T1003.001` LSASS Dump | **Calibrated** | **Calibrated** | Endpoint artifact rõ; cả hai đều thấy |
| `T1049` netstat qua ghost process | **Not Calibrated** | **Not Calibrated** | Ghost process rule fail điều kiện 3 — không phụ thuộc measurement surface |

**Nguyên tắc:** Scenario 2 mở rộng "fair scoring point" sang identity + cloud layer, nhưng **không ảnh hưởng đến điều kiện 3** (independently verifiable theo execution context). Ghost process rule và subprocess attribution vẫn áp dụng nguyên vẹn trong cả hai Scenario.

**Hệ quả thiết kế:** Khi xây plan cho Scenario 2, cần review lại các technique cross-domain (T1078.004, T1550.004, T1098.00x, T1087.004, T1580, T1619…) — những technique này sẽ là **Calibrated** nếu có artifact trong cloud/identity layer, dù chúng sẽ là Not Calibrated nếu plan chỉ target Scenario 1.

## Nguyên lý 3 — Calibrated là điều kiện để một behavior được đưa vào thống kê detection

Nhãn `Calibrated` không chỉ mô tả mức độ rõ ràng của artifact — nó xác định **phạm vi hợp lệ của câu hỏi đánh giá**.

Câu hỏi đánh giá detection: *"Vendor có detect hành vi này không?"* chỉ có giá trị đo lường khi người đánh giá có thể **độc lập xác nhận artifact đã tồn tại** trên hệ thống victim. Chỉ khi đó một "miss" mới có thể được quy trách nhiệm cho vendor.

| Nhãn | Evaluator verify được artifact? | Miss → quy cho ai? | Đưa vào thống kê detection? |
|---|---|---|---|
| `Calibrated` | Có — artifact được đảm bảo tạo ra và thoả 4 điều kiện | Vendor | **Có — tính vào denominator** |
| `Not Calibrated` | Không tính: substep là setup/implementation detail, hoặc artifact không thoả một trong 4 điều kiện (không observable, không reproducible, không verify độc lập được, ngoài bề mặt đo) | Không xác định được | **Không** |

**Ví dụ cụ thể ([Mustang Panda Step 1](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md)):**
- `T1574.002` DLL Side-Loading `wsdapi.dll` → **Calibrated** → evaluator xác nhận file `wsdapi.dll` trên disk và được load bởi `EssosUpdate.exe` → miss rõ ràng là vendor không detect → tính vào denominator
- `T1497` Foreground window check → **Not Calibrated** → `GetForegroundWindow()` call xảy ra trong memory, không có external artifact evaluator có thể verify độc lập → miss có thể do artifact không observable, không phải do vendor kém → không tính vào denominator

### Lưu ý để tránh hiểu sai

**Not Calibrated ≠ "không cần detect".**
Các hành vi Not Calibrated vẫn được ghi đầy đủ Detection Criteria trong Reference Table. Chúng phục vụ ba mục đích riêng:
1. **Completeness** — scenario phản ánh đúng hành vi thực của adversary, không bị cắt xén vì lý do đo lường
2. **Analyst reference** — nếu vendor detect được behavior Not Calibrated, đó là bonus visibility đáng ghi nhận
3. **Stealth profile** — tỷ lệ Not Calibrated cao phản ánh adversary dùng custom malware với evasion chain sâu (xem Nguyên lý 2)

**Not Calibrated ≠ "dễ gán nhãn".**
Gán `Calibrated` cho một behavior mà artifact không thực sự guaranteed → làm sai denominator → detection rate bị inflate không trung thực. Nhãn `Calibrated` chỉ được gán khi red team có thể **cam kết** artifact tồn tại trên victim theo cách evaluator có thể xác nhận độc lập.

---

## Nguyên lý 4 — Detection Criteria phải là observable, specific event

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

## Nguyên lý 5 — Mỗi observable event là một row riêng

Không gộp nhiều events vào một row dù cùng technique:

```markdown
| Persistence | T1053.005 | Scheduled Task | Windows | .pif executable created GFlagEditor folder | Calibrated - Not Benign | ... |
| Persistence | T1053.005 | Scheduled Task | Windows | .pif executable scheduled task to execute gflags.exe | Calibrated - Not Benign | ... |
```

Hai row trên cùng technique ID nhưng hai observable events khác nhau → tách riêng.

---

## Nguyên lý 6 — Protections tests vs Main scenario

### Main scenario (Detections)

**Câu hỏi:** Detector có *nhìn thấy* hành vi không?

- Full kill chain nhiều steps
- Mix Calibrated / Not Calibrated theo bản chất adversary và loại Scenario
- Thực hiện theo trình tự phụ thuộc nhau (cần step trước để thực hiện step sau)
- **Bề mặt đo khác nhau theo Scenario:**

| | Scenario 1 | Scenario 2 |
|---|---|---|
| Target product | EDR, endpoint protection, SIEM | XDR, identity protection, MDR/MSSP |
| Sensor scope | Endpoint only | Endpoint + IdP + Cloud + cross-host |
| Calibrated ratio (cùng adversary) | Thấp hơn — cross-domain techniques fail điều kiện 4 | Cao hơn — cloud/identity artifact đủ điều kiện |
| Typical technique scope | Process, file, registry, network trên một host | Thêm T1078.004, T1550.004, T1098.00x, T1580, T1619… |

### Protections tests (Protections)

**Câu hỏi:** Security control có *chặn* hành vi không?

- Sub-chain ngắn, cô lập một capability block
- Gần như 100% Calibrated — test cần signal rõ ràng và reproducible để đo protection outcome
- Mỗi test chạy độc lập, không phụ thuộc state test khác
- Bề mặt đo mở rộng: thêm email gateway, web filter, identity provider tuỳ scope
- **Delivery vector khác** so với main scenario để test generality của control

**Ví dụ delivery variant (Mustang Panda 2025):**
- [Main](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md): DOCX spearphishing → TONESHELL (`wsdapi.dll`)
- [Protections Test 4](../Enterprise/mustang_panda/Emulation_Plan/Protections_Test_4_Scenario.md): PIF dropper → TONESHELL (`gflagsui.dll`)
- [Protections Test 5](../Enterprise/mustang_panda/Emulation_Plan/Protections_Test_5_Scenario.md): MSC file via MMC → PlugX (`rcdll.dll`)

Nếu control chỉ block theo file hash thì sẽ fail với variant — đây chính là mục đích.

**Hệ quả đối với nhãn:** cùng `T1566.001 Spearphishing` là Not Calibrated trong Detections (email ngoài bề mặt EDR) nhưng Calibrated trong Protections (email gateway trong scope). Đây là flip hợp lệ theo Nguyên lý 1.

---

## Nguyên lý 7 — CTI grounding bắt buộc

Mỗi technique phải có ít nhất một CTI report trong cột `Relevant CTI Reports`. Hành vi phải được **observed in the wild** — không tự ý thêm technique không có CTI backing.

Đây là lý do file header luôn có phần CTI citations được đánh số `[1]`, `[2]`...

---

## Nguyên lý 8 — Source code links cho custom tools

Khi technique dùng custom tool (TONESHELL, PlugX...), cột `Source Code Links` phải trỏ đến **hàm cụ thể** trong source code, không phải chỉ file:

```markdown
| [PerformFileDownloadTask](../Resources/toneshell/src/shellcode/exec.cpp#L241-L346) |
| [Xor Functions](../Resources/toneshell/src/common/xor.cpp) |
```

Với COTS tools (Snaffler, rclone, WinRAR...) → link đến repo hoặc để trống.

---

## Template thiết kế một hành vi tấn công mới

1. **Chọn technique** có CTI backing cho adversary đang mô phỏng.
2. **Xác định artifact**: technique tạo ra artifact gì? File? Registry? Network? Process?
3. **Gán Category** — trả lời 6 câu theo thứ tự, dừng ngay khi gặp "No":
   1. Substep này có phải **scored behavior** không? (No → Not Calibrated)
   2. Có **artifact ngoài memory**, trên bề mặt sản phẩm bao phủ không? — áp dụng đúng bề mặt đã khai báo ở Lớp 0: Scenario 1 chỉ tính endpoint; Scenario 2 tính thêm cloud/identity. (No → Not Calibrated)
   3. Artifact **lặp lại được** giữa các lần chạy không? (No → Not Calibrated)
   4. Evaluator **độc lập verify** được artifact không? (No → Not Calibrated)
   5. Có scored substep khác đã **đại diện thông tin này tốt hơn** không? (Yes → Not Calibrated)
   6. Detection Criteria viết được dạng `<process|principal> <action> <artifact|target>` cụ thể không? (No → viết lại trước hoặc Not Calibrated)

   → Tất cả 6 câu đều ổn: **Calibrated - Not Benign**.
4. **Viết Detection Criteria**: một câu cụ thể format `<process> <action> <artifact/target> [trên <host>]`.
5. **Xác định host + user**: hành vi xảy ra trên máy nào, tài khoản nào.
6. **Thêm source code link** nếu dùng custom tool.
