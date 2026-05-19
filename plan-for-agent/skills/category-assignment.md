# Skill: Gán nhãn Category và kiểm tra Detection Criteria

Mô tả quy trình xác định nhãn `Calibrated`/`Not Calibrated` cho từng row trong Reference Table, và kiểm tra Detection Criteria đạt chuẩn. Đây là quy trình vận hành chuẩn; `attack-behavior-methodology.md` là bản diễn giải mở rộng bằng dẫn chứng từ các scenario MITRE cũ.

---

## Ba nhãn có thể gán

| Nhãn | Ý nghĩa |
|---|---|
| `Calibrated - Not Benign` | Scored behavior — tính vào denominator detection rate |
| `Not Calibrated - Not Benign` | Setup substep, implementation detail, hoặc không thoả điều kiện — không tính vào denominator |
| `Calibrated - Benign` | Hành vi hợp lệ trông giống attack — dùng để kiểm tra false positive |

> **Phân biệt sub-label `Not Benign` vs `Benign`:** Đây là câu hỏi về **ý định adversary trong ngữ cảnh attack chain**, không phải về tính nguy hiểm của công cụ. Lệnh `whoami`, `ping`, `nltest` chạy từ tài khoản bị compromise là `Calibrated - Not Benign` vì đây là hành vi adversary trong context. Chỉ dùng `Calibrated - Benign` khi behavior được thiết kế rõ ràng để test FP threshold.

---

## Quy trình gán nhãn — 3 lớp

### Lớp 0 — Xác lập ngữ cảnh (làm trước khi nhìn vào từng substep)

Trả lời 2 câu trước khi đánh giá bất kỳ substep nào:

**1. Loại test:** Detections hay Protections?
- **Detections** — đánh giá khả năng phát hiện theo chuỗi hành vi
- **Protections** — đánh giá khả năng chặn một hành vi cụ thể; gần như toàn bộ row là Calibrated

**2. Bề mặt đo của scenario (quyết định Condition 4):**

| Loại | Kênh telemetry trong scope | Proxy reference |
|---|---|---|
| Scenario 1 (EDR) | Process tree, command line, file I/O, registry, network connection, DNS, script-block log | Mustang Panda 2025 |
| Scenario 2 (XDR) | Tất cả Scenario 1 + IdP/SSO audit log, cloud API call log, cross-host correlation | Scattered Spider 2025 |
| Protections | Tuỳ scope khai báo: thêm email gateway, web filter, identity provider nếu có | — |

> Ngữ cảnh ở Lớp 0 quyết định Condition 4 ở Lớp 2. Không bỏ qua bước này.

---

### Lớp 1 — Sàng lọc trước khi áp 4 điều kiện

Hai câu hỏi độc lập, theo thứ tự. Dừng ngay khi gặp "Yes":

**Câu hỏi A — Artifact có nằm trên detection surface của scenario này không?**

> *"Artifact mà substep này tạo ra có thuộc kênh telemetry đã khai báo ở Lớp 0 không?"*

- **No** → **Not Calibrated** — artifact nằm ngoài bề mặt đo (mail gateway, attacker infra, bên ngoài EDR scope). Đây không phải "setup" theo nghĩa causal — đây là fail Condition 4 ngay từ đầu. Không cần xét tiếp.

**Câu hỏi B — Substep này là implementation detail của một Calibrated row khác không?**

> *"Substep này là cơ chế thực hiện một objective đã được đo ở row Calibrated khác (cùng cấp hoặc downstream) — hay nó tự mình đại diện cho một adversary objective độc lập?"*

- **Yes** → **Not Calibrated** — implementation detail. Ba trường hợp:
  - **Cùng cấp:** cùng artifact/event đã được row khác mô tả rõ hơn (double-count)
  - **Downstream:** substep là cơ chế thiết lập execution context cho một Calibrated row phía sau — nếu vendor detect được row downstream đó, họ đã observe được kết quả của substep này
  - **Dead-end chain:** artifact của substep chỉ được consumed bởi Not Calibrated rows, không có path nào đến scored detection opportunity — substep produce dữ liệu mà chain xử lý nó đều đã bị kill ở Câu A/B hoặc Lớp 2

**→ Cả hai câu "No/No"** → substep là **primary output** — tiếp tục Lớp 2.

> **Phân biệt hai lý do Not Calibrated:** Câu A = artifact nằm ngoài detection surface (scope issue). Câu B = artifact trên surface nhưng là cơ chế của một objective đã được đo ở nơi khác (redundancy issue). Lý do "bước này là điều kiện tiên quyết cho bước sau" **một mình** không đủ để Not Calibrate — câu hỏi luôn phải là liệu objective của nó đã được đại diện tốt hơn ở row khác chưa.

---

### Lớp 2 — Checklist 4 điều kiện cho Calibrated

Substep được **Calibrated** khi và chỉ khi thoả **tất cả 4** điều kiện:

| # | Điều kiện | Loại trừ |
|---|---|---|
| 1 | **Observable** — có artifact thuộc kênh telemetry đã khai báo ở Lớp 0 | Artifact chỉ tồn tại trong memory tiến trình |
| 2 | **Reproducible** — artifact xuất hiện giống nhau ở mọi lần chạy | GUID ngẫu nhiên, timing-dependent, chỉ tồn tại trong stack/heap |
| 3 | **Independently verifiable** — evaluator xác nhận được artifact không cần dựa vào claim của red team | Process identity bị compromise (ghost/injected process), artifact chỉ verify qua source code malware |
| 4 | **Fair scoring point** — sản phẩm đang test có cơ hội thấy artifact nếu hoạt động đúng chức năng | Artifact nằm ngoài bề mặt đo của loại sản phẩm đang test |

> **Về ghost/injected process và Condition 3:** Khi một process bị inject vào, identity của nó không còn đáng tin. Condition 3 chỉ fail khi artifact **phụ thuộc vào process identity để verify** — tức là evaluator cần tin rằng process đó đang chạy malware mới kết luận được artifact là malicious. Ngược lại, nếu artifact **tồn tại độc lập ngoài process context** và tự nó đủ để verify, Condition 3 vẫn pass dù executing process là ghost.
>
> - **Fail Condition 3:** hành vi in-process (API call, in-memory shellcode, output chỉ visible trong process context), child process output chỉ consumed nội bộ bởi implant
> - **Pass Condition 3:** artifact persist trên hệ thống sau khi process kết thúc (registry key, scheduled task, file trên disk với attribution rõ), network connection đến external attacker-controlled endpoint (attribution không phụ thuộc process identity)

> **Về Condition 4 giữa hai scenario:** Cùng một technique có thể flip nhãn giữa Scenario 1 và Scenario 2 nếu kênh telemetry cần thiết (cloud audit log, IdP event) chỉ có trong bề mặt đo của Scenario 2.

Một điều kiện không thoả → **Not Calibrated**.

---

### Lớp 3 — Structural signals nghi ngờ gán sai

Sau khi gán nhãn, kiểm tra các dấu hiệu sau — những trường hợp này thường cần rà soát lại:

- **Tỷ lệ Calibrated ~100% trong Detections adversary dùng custom implant** → nghi ngờ; implant-heavy chain thực tế có nhiều evasion mechanism fail Condition 1 hoặc 3.
- **Hai row cùng technique, cùng event vật lý** → double-count; xem xét một row là implementation detail của row còn lại.
- **Not Calibrated nhưng artifact rõ, trên bề mặt đo, không có row khác đại diện** → kiểm tra Lớp 1; nếu không phải setup/implementation detail → xem xét nâng lên Calibrated.
- **Calibrated nhưng Detection Criteria không thể viết cụ thể** → artifact không thực sự observable hoặc reproducible; xem xét hạ xuống Not Calibrated.

---

## Kiểm tra Detection Criteria

Sau khi gán nhãn, kiểm tra cột `Detection Criteria` của mỗi row **Calibrated**:

**Format bắt buộc:** `<process|principal> <action> <artifact|target> [trên <host>]`

| | Ví dụ |
|---|---|
| ✅ Đúng | `waitfor.exe connects to 191.44.44.199 over TCP port 443` |
| ✅ Đúng | `EssosUpdate.exe side-loads unsigned wsdapi.dll from C:\Users\Public\` |
| ❌ Sai | `Malware connects to C2` |
| ❌ Sai | `Loader decrypts payload` |

**Checklist Detection Criteria:**
- [ ] Có process/principal cụ thể (tên file, không chỉ "malware")
- [ ] Có action cụ thể (loads, executes, connects, writes, reads...)
- [ ] Có artifact/target cụ thể (path đầy đủ, IP:port, tên file, registry key)
- [ ] Có thể dùng để query trực tiếp trong SIEM/EDR mà không cần thêm thông tin
- [ ] Nếu hành vi xảy ra trên nhiều host → tách thành nhiều row, mỗi row ghi host cụ thể

> Nếu Detection Criteria không thể viết đủ cụ thể → đây là dấu hiệu substep thực ra là Not Calibrated (fail Condition 1 hoặc 2). Xem lại nhãn trước khi cố viết criteria.

---

## Template gán nhãn nhanh (6 câu theo thứ tự)

Dừng ngay khi gặp "No":

1. Substep này có phải **primary output** của adversary action không? (No → Not Calibrated)
2. Có **artifact ngoài memory**, trên bề mặt đã khai báo ở Lớp 0 không? (No → Not Calibrated)
3. Artifact **lặp lại được** giữa các lần chạy không? (No → Not Calibrated)
4. Evaluator **độc lập verify** được artifact không? (No → Not Calibrated)
5. Có row Calibrated khác đã **đại diện thông tin này tốt hơn** không? (Yes → Not Calibrated)
6. Detection Criteria viết được dạng cụ thể không? (No → viết lại hoặc Not Calibrated)

→ Tất cả 6 câu ổn: **Calibrated - Not Benign**.
