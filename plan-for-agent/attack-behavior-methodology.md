# Phương pháp luận trong việc dựng các hành vi tấn công

Rút ra từ [`Enterprise/mustang_panda/Emulation_Plan/`](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md) và [`Enterprise/scattered_spider/Emulation_Plan/`](../Enterprise/scattered_spider/Emulation_Plan/Scattered_Spider_Scenario.md).

File này là **bản diễn giải mở rộng** cho quy trình vận hành trong [`skills/category-assignment.md`](./skills/category-assignment.md): dùng các kịch bản MITRE đã công bố để giải thích vì sao các rule đó hợp lý và chúng biểu hiện ra sao trong thực tế. Khi cần quyết định nhãn cho một row cụ thể, dùng `skills/category-assignment.md` làm chuẩn thao tác; dùng file này để đọc nền tảng, ví dụ, và lập luận.

---

## Hệ thống phân loại Category

Mỗi technique trong Reference Table được gán một trong các category sau:

| Category | Ý nghĩa |
|---|---|
| `Calibrated - Not Benign` | Substep là **scored behavior** và thoả 4 điều kiện (observable, reproducible, independently verifiable, fair scoring point). Hành vi là malicious; được tính vào denominator của detection rate. |
| `Not Calibrated - Not Benign` | Substep **không được tính điểm** vì artifact nằm ngoài detection surface, là **implementation detail / redundancy** của một behavior đã được đo rõ hơn, hoặc không thoả ít nhất một trong 4 điều kiện. Hành vi là malicious, vẫn ghi đầy đủ trong Reference Table nhưng không tính vào denominator. |
| `Calibrated - Benign` | Substep là hành vi **hợp lệ, bình thường** nhưng trông giống attack từ góc nhìn telemetry. Dùng để kiểm tra false-positive. |

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

### Lớp 1 — Sàng lọc trước khi áp 4 điều kiện

Theo `skills/category-assignment.md`, trước khi gọi một substep là ứng viên `Calibrated`, cần tách hai loại lý do `Not Calibrated` khác nhau:

1. **Scope issue** — artifact có nằm trên detection surface đã khai báo ở Lớp 0 không?
   - Nếu **không**, substep → `Not Calibrated`.
2. **Redundancy issue** — substep có phải implementation detail của một behavior đã được đo tốt hơn ở row khác không?
   - Nếu **có**, substep → `Not Calibrated`. Có thể là cùng event bị double-count, cơ chế upstream chỉ phục vụ objective downstream đã có row đại diện, hoặc một dead-end chain không còn đường nào đến scoring opportunity.

Nếu cả hai câu trả lời đều **không**, substep là **primary output** của adversary action và mới đi tiếp sang Lớp 2. Một `primary output` chỉ trở thành **scored behavior** khi nó tiếp tục thoả cả 4 điều kiện ở Lớp 2.

> Điểm cần tránh hiểu sai: một bước là điều kiện tiên quyết cho bước sau **chưa đủ** để tự động `Not Calibrated`. Nếu chính bước đó tạo ra artifact độc lập, nằm trên detection surface, không bị row khác đại diện tốt hơn, nó vẫn có thể là điểm đo hợp lệ.

**Các nhóm thường là implementation detail:**
- Native API call nằm trong loader chain (T1106 `NtCreateSection`, `ws2_32.send`, `MSXML2.XMLHTTP`) khi đã có substep mô tả output của chain đó (process-create, file-write, network connection).
- Nội dung mã hoá bên trong payload đã Calibrated (T1027.013 PEM structure của file đã Calibrated ở HTML Smuggling).
- API call phụ phục vụ token/handle thao tác khi đã có substep đo process-create outcome (T1134.002 `CreateProcessAsUser` khi T1134.001 đã Calibrated).
- Tool scanning behavior bên trong authenticated session (T1213, T1552 tool execute against internal service) khi authentication event (T1078) đã Calibrated: tool's internal requests có thể khó phân biệt với legitimate browsing nếu không biết trước tool signature; theo framework này, authentication log entry thường là scoring point mạnh hơn scanning behavior. Ví dụ [Scattered Spider Step 8](../Enterprise/scattered_spider/Emulation_Plan/Scattered_Spider_Scenario.md): `T1078` Wekan authentication được Calibrated, còn `T1552` Jecretz execute against Wekan là Not Calibrated. Đây là cách diễn giải từ pattern của scenario, không phải claim rằng MITRE đã công bố công khai lý do phân loại.

**Các nhóm thường rơi vào scope issue hoặc redundancy issue:**
- Attacker upload file lên server → thường là attacker-side staging hoặc bước upstream đã được victim-side download đại diện tốt hơn.
- Email arrive ở mailbox trong Detections endpoint-only → nằm ngoài detection surface của EDR.
- User click mở file/link khi mục tiêu thật sự là process spawn từ đó → thường bị row process execution downstream đại diện tốt hơn. *Ngoại lệ*: nếu click tạo browser request đến phishing domain cụ thể và đó là network event thuộc detection surface, click có thể là primary output riêng (xem T1204.001 [Mustang Panda Step 7](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md)).
- **Post-objective cleanup/teardown steps**: xoá file, xoá registry key, self-delete batch script sau khi adversary đã đạt objective (ví dụ [Mustang Panda Step 9](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md) `del_WinGupSvc.bat`) → thường không còn là scoring objective; khác với in-chain stealth cleanup đang phục vụ attack flow và có thể tạo primary output riêng.

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
> - Ngược lại, artifact chỉ có ý nghĩa khi phải tin vào identity của một ghost/injected process sẽ fail **điều kiện 3** bất kể Scenario — không bị ảnh hưởng bởi measurement surface.

> **Về ghost/injected process và điều kiện 3:** execution context bị inject không làm mọi artifact tự động `Not Calibrated`. Điều kiện 3 chỉ fail khi evaluator phải tin vào process identity đó mới kết luận được hành vi là malicious.
> - Trong [Mustang Panda Step 2](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md), `waitfor.exe` chạy `netstat`, `ipconfig`, SharpNBTScan, download `mswin1.exe`; các row này đều `Not Calibrated`. Cách giải thích phù hợp nhất với framework này là malicious meaning của chúng phụ thuộc mạnh vào implanted context, nên fail điều kiện 3.
> - Nhưng trong cùng scenario, `waitfor.exe` tạo registry run key `AccessoryInputServices`, scheduled task cùng tên, và exfiltrate RAR qua FTP; MITRE gán các row đó `Calibrated` vì registry key, scheduled task, và network transfer tới endpoint ngoại vi là artifact độc lập ngoài process context, có thể verify mà không cần tin process identity. Xem [Mustang Panda Step 5](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md) và [Step 7](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md).

> **Ví dụ fail điều kiện 3 không phải redundancy:** `T1573.001` dùng PSK symmetric encryption. Nếu payload bytes chỉ chứng minh được bằng key ẩn trong malware, evaluator không thể độc lập xác nhận "đây là T1573.001" từ telemetry bên ngoài → `Not Calibrated`. Ngược lại, `T1573.002` TLS/asymmetric có certificate và JA3 fingerprint độc lập từ network capture, nên là detection axis riêng và có thể `Calibrated` ngay cả khi C2 web protocol cũng đã Calibrated. Xác nhận từ [Mustang Panda Step 7](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md): cả `T1071.001` và `T1573.002` đều Calibrated.

Một điều kiện không thoả → **Not Calibrated**.

### Lớp 3 — Heuristic phát hiện gán sai

Sau khi gán nhãn, đối chiếu:

- **Anti-analysis / evasion check nội bộ được Calibrated** → gần như luôn sai. `T1497` foreground window, `T1622` IsDebuggerPresent — check xảy ra hoàn toàn trong memory tiến trình, không có external artifact, điều kiện 1 không thoả.
- **Native API call in-memory được Calibrated** → gần như luôn sai. `T1106` CoCreateGuid, `ws2_32.send`, `T1082` GetComputerNameA khi gọi từ injected context — không có artifact EDR-observable độc lập với process-create/network event đã Calibrated ở mắt xích khác; điều kiện 1 không thoả hoặc là implementation detail của scored behavior kế tiếp.
- **Calibrated nhưng Detection Criteria viết trừu tượng** (`Malware connects to C2`, `Loader decrypts payload`) → vi phạm điều kiện 1–2. Hạ xuống Not Calibrated hoặc viết lại Detection Criteria cụ thể trước.
- **Not Calibrated nhưng artifact rõ, thuộc bề mặt đo, lần đầu xuất hiện trong chuỗi** → kiểm tra Lớp 1: nếu không phải scope issue hay redundancy issue thật sự → nâng Calibrated.
- **Tỷ lệ Calibrated ~100% trong Detections của adversary stealthy** → nghi ngờ: adversary custom malware thực tế có nhiều evasion/internal chain → kiểm tra lại từng substep.
- **Hai row cùng technique, cùng event vật lý, cùng nhãn** → double-count; một trong hai là implementation detail.
- **Cùng technique flip nhãn giữa hai scenario** → đúng nếu loại test hoặc bề mặt đo khác nhau; sai nếu cùng ngữ cảnh và cùng event.

---

## Nguyên lý 2 — Vì sao tỷ lệ Calibrated khác nhau giữa các scenario

Tỷ lệ Calibrated của một scenario thường phản ánh đồng thời:

1. **Stealth profile của adversary** — chain dùng nhiều loader, injection, hoặc hành vi in-memory thường tạo ra nhiều row `Not Calibrated` hơn chain dựa trên legitimate tools và valid credentials.
2. **Measurement surface của scenario** — Scenario 2 có thêm identity/cloud telemetry nên nhiều behavior cross-domain có thể trở thành fair scoring point, trong khi Scenario 1 endpoint-only thì không.

| Adversary | Calibrated ratio | Giải thích |
|---|---|---|
| [Mustang Panda (main)](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md) | ~39% | Custom malware (TONESHELL, PlugX) với injection chain sâu. Phần lớn evasion chain là Not Calibrated. |
| [Scattered Spider (main)](../Enterprise/scattered_spider/Emulation_Plan/Scattered_Spider_Scenario.md) | ~93% | Legitimate tools + valid credentials. Không có evasion đặc biệt → artifact rõ ràng trên mọi surface. |
| Protections tests ([PT4](../Enterprise/mustang_panda/Emulation_Plan/Protections_Test_4_Scenario.md), [PT5](../Enterprise/mustang_panda/Emulation_Plan/Protections_Test_5_Scenario.md), [SS PT1](../Enterprise/scattered_spider/Emulation_Plan/Protections_Test_1_Scenario.md)…) | ~97% | Test controls → cần signal rõ ràng → gần như toàn bộ Calibrated. |

Phần Lớp 2 đã nêu rule cụ thể cho cả hai driver: measurement surface chỉ tác động đến `fair scoring point`, còn artifact phụ thuộc process identity vẫn fail `independently verifiable` dù scenario rộng hơn. Khi xây Scenario 2, vì vậy cần review lại các technique cross-domain như `T1078.004`, `T1550.004`, `T1098.00x`, `T1087.004`, `T1580`, `T1619`.

## Nguyên lý 3 — Calibrated là điều kiện để một behavior được đưa vào thống kê detection

Nhãn `Calibrated` không chỉ mô tả mức độ rõ ràng của artifact — nó xác định **phạm vi hợp lệ của câu hỏi đánh giá**.

Câu hỏi đánh giá detection: *"Vendor có detect hành vi này không?"* chỉ có giá trị đo lường khi người đánh giá có thể **độc lập xác nhận artifact đã tồn tại** trên hệ thống victim. Chỉ khi đó một "miss" mới có thể được quy trách nhiệm cho vendor.

| Nhãn | Evaluator verify được artifact? | Miss → quy cho ai? | Đưa vào thống kê detection? |
|---|---|---|---|
| `Calibrated` | Có — artifact được đảm bảo tạo ra và thoả 4 điều kiện | Vendor | **Có — tính vào denominator** |
| `Not Calibrated` | Không tính: artifact ngoài detection surface, substep là redundancy / implementation detail, hoặc artifact không thoả một trong 4 điều kiện (không observable, không reproducible, không verify độc lập được, ngoài bề mặt đo) | Không xác định được | **Không** |

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
- Bề mặt đo theo Scenario lấy từ Lớp 0; Scenario 1 endpoint-only, Scenario 2 thêm identity/cloud/cross-host.

### Protections tests (Protections)

**Câu hỏi:** Security control có *chặn* hành vi không?

- Sub-chain ngắn, cô lập một capability block
- Thường có tỷ lệ Calibrated rất cao — test cần signal rõ ràng và reproducible để đo protection outcome
- Mỗi test chạy độc lập, không phụ thuộc state test khác
- Bề mặt đánh giá phụ thuộc scope của test; có thể gồm email gateway, web filter, identity provider nếu được khai báo
- **Delivery vector khác** so với main scenario để test generality của control

**Ví dụ delivery variant (Mustang Panda 2025):**
- [Main](../Enterprise/mustang_panda/Emulation_Plan/Mustang_Panda_Scenario.md): DOCX spearphishing → TONESHELL (`wsdapi.dll`)
- [Protections Test 4](../Enterprise/mustang_panda/Emulation_Plan/Protections_Test_4_Scenario.md): PIF dropper → TONESHELL (`gflagsui.dll`)
- [Protections Test 5](../Enterprise/mustang_panda/Emulation_Plan/Protections_Test_5_Scenario.md): MSC file via MMC → PlugX (`rcdll.dll`)

Nếu control chỉ block theo file hash thì sẽ fail với variant — đây chính là mục đích.

**Hệ quả đối với nhãn:** flip `T1566.001 Spearphishing` giữa Detections và Protections ở Nguyên lý 1 là hợp lệ vì scope đo khác nhau.

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
3. **Gán Category** — đi theo đúng flow của quy trình gán nhãn:
   1. Artifact có nằm trên **detection surface** đã khai báo ở Lớp 0 không? (No → Not Calibrated)
   2. Có row Calibrated khác đã **đại diện thông tin này tốt hơn** không? (Yes → Not Calibrated)
   3. Nếu qua được hai câu trên, substep này có phải **primary output** của adversary action không? (No → Not Calibrated)
   4. Artifact có **observable** ngoài memory không? (No → Not Calibrated)
   5. Artifact có **reproducible** giữa các lần chạy không? (No → Not Calibrated)
   6. Evaluator có **independently verify** được artifact không? (No → Not Calibrated)
   7. Đây có phải **fair scoring point** cho loại sản phẩm đang test không? (No → Not Calibrated)
   8. Detection Criteria có viết được dạng `<process|principal> <action> <artifact|target>` cụ thể không? (No → viết lại trước hoặc Not Calibrated)

   → Qua câu 1–3: substep là **primary output**.
   → Qua tiếp câu 4–8: substep đủ điều kiện **Calibrated - Not Benign**.
4. **Viết Detection Criteria**: một câu cụ thể format `<process> <action> <artifact/target> [trên <host>]`.
5. **Xác định host + user**: hành vi xảy ra trên máy nào, tài khoản nào.
6. **Thêm source code link** nếu dùng custom tool.
