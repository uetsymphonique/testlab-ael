# Phân tích skill: write-detection-criteria

Tài liệu này giải thích từ gốc rễ tại sao skill `write-detection-criteria` tồn tại, nó làm gì, mỗi bước thiết kế vì lý do gì, và đánh giá khách quan điểm mạnh/yếu.

---

## Terminology

**Detection Criteria**
Nội dung của cột cùng tên trong Reference Table — một tín hiệu SIEM-queryable mô tả hành vi dưới dạng sự kiện có thể quan sát được (`process` `action` `artifact`), hoặc tài liệu hoá lý do tại sao tín hiệu đó không thể viết được.

**Vendor accountability signal**
Mục đích thực sự của Detection Criteria: tín hiệu mà nếu vắng mặt trong output của sản phẩm, thì sự vắng mặt đó rõ ràng là lỗi của vendor — không phải do đo lường sai, không phải do môi trường đặc biệt. Đây là nền tảng để MITRE quy trách nhiệm cho sản phẩm.

**Anomaly axis**
Chiều mà hành vi lệch khỏi baseline. Xác định được anomaly axis = xác định được có gì để phát hiện hay không. Không có anomaly axis → không thể viết criteria.

**Surface Profile (Layer 0)**
Bảng khai báo telemetry surface của scenario: loại dữ liệu nào được thu thập, trên host nào. Scenario 1 default là EDR. Artifact nằm ngoài Surface Profile → không thể là scoring signal dù hoàn toàn observable.

**Tier 1 — Intrinsic anomaly**
Artifact hiếm gặp đơn độc — bản thân sự kiện đã đủ khác thường để cảnh báo. Một rule duy nhất là đủ.
Format: `<process | principal> <action> <artifact | target> [on <host>]`

**Tier 2 — Contextual anomaly**
Artifact thường gặp khi nhìn riêng lẻ, nhưng sự kết hợp / chuỗi mới là điều bất thường. Không có fragment nào đủ để alert một mình — phải tích luỹ risk hoặc correlate.
Format: `[process | process class] <condition> [and <condition>…]`

**C1 / C2 / C3 — ba điều kiện unwritable tuyệt đối**

| Code | Điều kiện |
|---|---|
| **C1** | Không có anomaly axis, hoặc không có stable pattern (random value không có underlying pattern) |
| **C2** | Artifact không thể xác minh độc lập — chỉ trong process memory, evaluator phải tin vào implant |
| **C3** | Artifact nằm ngoài Surface Profile đã khai báo |

**Writability**
Tiêu chí duy nhất để quyết định viết signal hay `N/A`. Không phải "tôi nghĩ row này sẽ bị demote", không phải "behavior này quá đơn giản" — chỉ: *có thể viết một concrete signal không?*

**Stable pattern**
Pattern hành vi tồn tại ổn định qua các lần chạy. GUID/nonce là random value — nhưng hành vi "non-COM process generates GUID and writes to non-standard path" là stable. Criteria phải bám vào pattern, không phải vào giá trị cụ thể.

---

## Tại sao skill này tồn tại

### Vấn đề trước khi có skill này

Trước đây, labeling (Calibrated / Not Calibrated) và viết criteria được thực hiện trong cùng một pass. Hệ quả:

1. **Hallucination vòng tròn**: model quyết định label trước ("row này chắc Not-Calibrated") rồi rationalize criteria cho khớp — hoặc skip criteria hoàn toàn vì "không cần". Không ai buộc model phải thực sự đối mặt với câu hỏi: *có thể viết signal không?*

2. **Label làm ô nhiễm criteria**: criteria bị viết theo hướng "cố tình vague" để tránh Calibrated, hoặc "cố tình strong" để đạt Calibrated — thay vì phản ánh thực tế signal.

3. **Criteria không stable**: khi label thay đổi (do review, do context mới), criteria cũng bị rewrite theo — mất anchor.

### Giải pháp

Tách evidence ra khỏi verdict:

- `write-detection-criteria` → viết evidence (stable, chỉ phụ thuộc vào signal writability)
- `assign-category` → đọc evidence đó và ra verdict (heuristic, có thể re-derive mà không cần rewrite criteria)

Criteria là artifact ổn định. Label là heuristic verdict đọc từ artifact đó. Thay đổi label không làm hỏng criteria.

---

## Các bước và lý do thiết kế

### Step 1 — Xác định scope

> *"Ask the user: which Phase file? which rows? Default to all rows."*

**Nhiệm vụ**: xác định coverage trước khi bắt đầu, tạo checklist one-task-per-row để track.

**Câu hỏi step này trả lời**: Tôi cần viết criteria cho những row nào? Có row nào tôi được phép bỏ qua không?

**Lý do thiết kế**: Default là *tất cả row* — không có row "quá nhỏ để cần criteria". Row bị skip là row `assign-category` phải tự đoán criteria, tức là bước tách evidence/verdict vừa thiết kế lại bị vô hiệu hoá ngay tại đây.

---

### Step 2 — Xác định vendor accountability signal

> *"For each row, identify what a correctly-functioning product would emit when this behavior occurs."*

**Nhiệm vụ**: với mỗi row, tìm câu trả lời cho câu hỏi cốt lõi — *nếu sản phẩm hoạt động đúng, nó sẽ emit sự kiện gì?*

**Câu hỏi step này trả lời**:
- Artifact nào được tạo ra bởi hành vi này?
- Telemetry layer nào sẽ ghi nhận nó?
- Process/principal nào là actor?
- Baseline của host role này là gì, và hành vi này lệch khỏi baseline ở điểm nào?

**Lý do thiết kế**: "Vendor accountability" thay vì "detection criteria" là framing quan trọng. Nó buộc phải hỏi: *nếu sản phẩm bỏ lỡ điều này, đó có phải lỗi của sản phẩm không, hay đó là artifact không ai có thể detect?* Chỉ khi câu trả lời là "lỗi của sản phẩm" thì mới có signal để viết.

Anchoring baseline vào host role (từ `summary.md` hoặc setup docs) thay vì assume là bước quan trọng — cùng một behavior có thể là intrinsic anomaly trên một web server nhưng là noise trên một developer workstation.

---

### Step 3 — Chọn format tier

> *"Choose the format matching the anomaly tier."*

**Nhiệm vụ**: quyết định Tier 1 hay Tier 2 dựa trên tính chất của anomaly.

**Câu hỏi step này trả lời**: Artifact này hiếm gặp đơn độc (Tier 1), hay chỉ bất thường trong context/combination (Tier 2)?

**Lý do thiết kế**: Hai tier không phải tuỳ chọn style — chúng phản ánh loại detection logic cần thiết:
- Tier 1 → một rule đủ để fire → criteria viết như event filter
- Tier 2 → phải correlate nhiều conditions → criteria viết như behavioral pattern cho risk engine

Áp sai tier không gây lỗi syntax nhưng gây lỗi logic: viết Tier 1 format cho một artifact phổ biến tạo ra false-positive lớn; viết Tier 2 format cho một artifact intrinsic là over-engineering không cần thiết.

---

### Step 4 — Quyết định signal vs absence trên writability đơn thuần

> *"Decide signal-vs-absence on writability only, not on the anticipated label."*

**Nhiệm vụ**: viết signal nếu có thể viết được, viết `N/A — <Cx>` nếu không — bất kể kết quả labeling dự kiến là gì.

**Câu hỏi step này trả lời**: Signal này có thể viết được không? (Không phải: label sẽ là gì?)

**Lý do thiết kế**: Đây là điểm cốt lõi nhất của toàn bộ skill. Discipline này loại bỏ hai anti-pattern nguy hiểm nhất:

1. *"Row này sẽ Not-Calibrated nên tôi viết N/A để tiết kiệm"* → N/A giờ có nghĩa hoàn toàn khác: *signal unwritable*, không phải *label sẽ là Not-Calibrated*. Một row có signal hoàn toàn writable nhưng bị demote vì redundancy vẫn phải giữ nguyên positive signal — `assign-category` ghi lý do demotion vào cột `Calibration Reason` (cột `Category` giữ là clean enum), không đẩy nó ngược lại thành fake N/A.

2. *"Tôi biết Category rồi, viết criteria cho match"* → không được. Criteria phải phản ánh thực tế của signal, không phải mong muốn về label.

---

### Step 5 — Chạy Forward checklist / Reverse diagnostic

> *"Run the Forward checklist (concrete signals) or the Reverse diagnostic (suspected absences)."*

**Nhiệm vụ**: quality gate trước khi commit vào file.

**Câu hỏi step này trả lời**:
- Forward checklist: criteria này có thể paste vào SIEM/EDR và query được không? Có đủ specific không? Có phải positive pattern không?
- Reverse diagnostic: nếu tôi đang ngả về N/A, tôi đang fail ở điều kiện nào (C1/C2/C3)?

**Lý do thiết kế**: Hai chiều kiểm tra này tương ứng với hai trường hợp cần chất lượng khác nhau:
- Signal row cần phải queryable, không phải chỉ đúng về mặt khái niệm
- Absence row cần phải classify rõ lý do — "N/A" không có code là evidence kém, không thể audit sau

Reverse diagnostic đặc biệt quan trọng vì nó bắt được pattern "viết signal bằng negative phrasing" (ví dụ: "CreateFile absent from import table") — về kỹ thuật là đúng nhưng không thể query, phải reframe thành positive anomalous pattern.

---

## Đánh giá khách quan

### Điểm mạnh

**Separation of concerns thực sự**
Criteria và label là hai artifact độc lập. Label có thể thay đổi mà không cần rewrite criteria — không mất anchor khi context thay đổi.

**N/A có semantics rõ ràng**
Ba code (C1/C2/C3) biến N/A thành thông tin thay vì lỗ hổng. Reviewer biết chính xác lý do không có signal — và có thể dispute nếu disagree.

**Writability làm tiêu chí duy nhất**
Loại bỏ toàn bộ lớp bias từ anticipated label. Model phải đối mặt với signal trước khi được phép nghĩ đến label.

**Coverage requirement (mọi row)**
Ngăn không cho "setup rows" bị drop silently. Một row được skip là một blind spot không được document.

**Format discipline (Tier 1 / Tier 2)**
Buộc phải phân loại tính chất anomaly trước khi viết — ngăn viết surface-level description thay vì detection logic.

---

### Điểm yếu

**Phụ thuộc vào baseline knowledge**
Anomaly axis phụ thuộc vào người viết biết baseline của host role là gì. Nếu model không có thông tin đủ về host build (từ `summary.md` hoặc setup docs), anomaly claim sẽ yếu hoặc sai. Skill không có cơ chế validate baseline — nó chỉ yêu cầu "anchor to host role", không kiểm tra baseline đó có đúng không.

**Tier 1 / Tier 2 phân loại có vùng xám**
Nhiều behaviors nằm giữa hai tier: artifact không phải intrinsic rare nhưng cũng không cần full correlation. Model phải tự quyết định mà không có heuristic rõ ràng hơn "hiếm gặp đơn độc hay không". Dễ nhất quán kém giữa các session.

**Surface Profile là dependency ngoài**
Layer 0 table nằm trong `assign-category/references.md`. Nếu Surface Profile thay đổi, criteria đã viết trên Surface Profile cũ có thể không còn valid — nhưng skill không có mechanism để flag điều này. Người review phải manually reconcile.

**Telemetry depth không được validate tự động**
Khi hai rows chia sẻ một physical event (ví dụ: cùng netconn nhưng một row dùng raw IP, row kia dùng JA3 fingerprint), skill chỉ note rule trong references.md chứ không enforce. Model có thể viết identical criteria cho hai rows mà không bị detect — double-count chỉ được bắt khi `assign-category` chạy sau.

**C1 / C2 / C3 yêu cầu judgment tốt**
Model có thể misclassify — đặc biệt C1 vs "lazy" (signal writable nhưng cần thêm effort để reframe thành positive pattern). Reverse diagnostic giúp phần nào nhưng không prevent được misclassification hoàn toàn.
