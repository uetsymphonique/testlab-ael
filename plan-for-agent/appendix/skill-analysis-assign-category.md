# Phân tích skill: assign-category

Tài liệu này giải thích từ gốc rễ tại sao skill `assign-category` tồn tại, nó làm gì, mỗi bước thiết kế vì lý do gì, và đánh giá khách quan điểm mạnh/yếu.

---

## Terminology

**Calibrated / Not Calibrated**
Hai label duy nhất trong scope. "Calibrated" = hành vi này được tính là một scored detection opportunity — đây là cơ hội detection fair, scored. "Not Calibrated" = không được tính. Label không phán xét xem hành vi có "quan trọng" hay không — chỉ phán xét xem nó có *fair để score vendor* hay không.

**Surface Profile (Layer 0)**
Khai báo telemetry surface của scenario: loại dữ liệu nào được thu thập, trên loại sensor nào. Phải được echo tường minh trước khi label bất kỳ row nào. Default là Scenario 1 (EDR). Quyết định này thiết lập tập scored detection opportunities — thay đổi profile = thay đổi toàn bộ kết quả scoring.

**Layer 1 — Pre-filter (Q-A / Q-B)**
Hai câu hỏi loại trừ sớm, chạy trước khi đánh giá signal quality:
- **Q-A**: Artifact có nằm trong Surface Profile không? Không → NC ngay.
- **Q-B**: Đây có phải implementation detail của một Calibrated row khác không? Có → NC ngay.

**Q-B — Implementation detail**
Một row là implementation detail của row khác khi: row downstream đã Calibrated và detecting row đó *trực tiếp chứng minh* row này đã xảy ra. Không phải mọi upstream step đều là implementation detail — chỉ khi row đó không mở ra detection opportunity độc lập nào. Q-B có ba sub-case (references.md): **same-level** (double-count, xem dưới), **downstream** (downstream row trực tiếp chứng minh row này), và **dead-end chain** (artifact chỉ bị các NC row tiêu thụ, không có path tới scored opportunity nào). Static file property (chữ ký cert, entropy, nội dung section nhúng) không được miễn trừ khỏi Q-B: nếu vai trò duy nhất của nó là enable một technique downstream đã được một Calibrated row khác capture, nó vẫn là implementation detail; chỉ pass Q-B nếu là forensic artifact quan sát độc lập được bằng cách scan file, không phụ thuộc runtime event nào.

**Double-count**
Trường hợp Q-B same-level: hai rows mô tả cùng physical event với cùng technique và cùng artifact/target, yêu cầu cùng detection capability. Một được Calibrated, cái kia NC với tag `redundant@<TechID>`. Match trên technique+artifact, không phải verbatim text.

**Layer 2 — Conditions 1–3**
Ba điều kiện eligibility đọc từ Detection Criteria đã viết:
- **Condition 1**: Observable — artifact tồn tại trong telemetry channels đã khai báo (lưu ý: memory-only artifact chỉ fail C1 khi Basic EDR được declare; default EDR đã gồm memory scanning)
- **Condition 2**: Reproducible — artifact xuất hiện ổn định qua nhiều runs (stable pattern)
- **Condition 3**: Independently verifiable — evaluator xác nhận được mà không cần tin vào red team

Conditions 1–3 chỉ cho *eligibility*, không phải verdict. Đa số rows fail ở C4, không phải ở đây.

**Code mapping (Cx ↔ Condition N là hai hệ đánh số khác nhau)**
Mã `N/A — Cx` ghi trong Detection Criteria **không** trùng số với Condition N ở đây — chúng bị hoán vị: `N/A — C3` (off-surface) ↔ Condition 1 (Observable); `N/A — C1` (no signal) ↔ Condition 2 (Reproducible); `N/A — C2` (not verifiable) ↔ Condition 3 (Independently verifiable). Khi ghi vào `Calibration Reason`, mirror đúng mã `Cx` gốc, không đổi thành số Condition.

**C4 — Scoring gate (điều kiện thực sự)**
Gate thực sự quyết định Calibrated. Ba sub-gate đều phải pass:
- **4a**: Signal phân biệt phải là property của *hành vi/TTP* — generalize qua các instance, không phải một indicator cố định riêng của lần emulation này (command string, IP, file hash, filename). Không phán xét cơ chế detect của vendor; phán xét xem signal có generalize ngoài run cụ thể không
- **4b**: Mở ra detection opportunity mới và độc lập — không phải cơ hội đã được guarantee bởi row khác
- **4c**: Distinctive TTP (actor-signature behavior) — không phải Generic Operational Behavior (transport, interpreter spawn, native recon, staging)

**Generic Operational Behavior**
Class hành vi không được score vì missing chúng không phản ánh detection capability gap thực sự. Gồm: tool transfer, generic interpreter spawn, native recon commands (netstat/ipconfig), remote-exec plumbing (PsExec mechanism), pure staging. Đây là "overridable default verdicts" — cùng technique có thể flip tùy vai trò trong step.

**Reason tags**
Short tag ghi vào `Calibration Reason` cho mọi NC row. Lý do cần tag: khi heuristic thay đổi, label có thể re-derive từ tag mà không cần đọc lại toàn bộ criteria. Không được để NC row không có tag.

**Layer 3 — Structural signals**
Checklist pattern-level sau khi label xong. Bắt các lỗi hệ thống như: Calibrated ratio bất thường, double-count ẩn, mâu thuẫn giữa positive criteria và NC label, hoặc ngược lại.

**Overridable default verdicts**
Generic Operational Behavior classification không phải blocklist theo TID. Cùng một technique (ví dụ `rar` compression) là NC khi staging nội bộ, nhưng là Calibrated khi kết hợp exfil qua alternate protocol thành objective chính. Default verdict "strong NC" có thể bị ghi đè nếu documented rõ vai trò trong step.

**Primary artifact (cơ chế ghi đè default verdict)**
Override của một strong-NC default verdict phải được trigger bởi **primary artifact** mà hành động *tạo ra*, không phải bởi metadata về *ai* thực hiện. Với T1105, primary artifact là file được transfer, không phải process ghi nó. Actor bất thường (IIS worker, browser, Office app ghi vào path lạ) chỉ là context — tự nó không lift transport default verdict. Câu hỏi đúng: *"file có anomaly quan sát độc lập không?"* (PE-class, YARA-matchable content). Có → test C4 fresh; không → giữ default verdict, check Q-B với downstream row bắt được property đó. Áp dụng cho mọi default verdict trong bảng C4c, không riêng T1105.

---

## Tại sao skill này tồn tại

### Vấn đề

Không phải mọi hành vi detectable đều nên được score. Nếu tính tất cả behaviors vào tập scored detection opportunities:

1. **Tập scored detection opportunities gồm behavior không generalize được**: với một số row, dấu hiệu phân biệt duy nhất là một indicator *riêng của lần emulation này* — đúng IP, đúng filename, đúng hash mà ta tình cờ chọn. Vấn đề **không phải** việc vendor bắt bằng signature/YARA — vendor được tự do detect bằng bất kỳ cơ chế nào, và bắt được vẫn là bắt được. Vấn đề nằm ở *tập scored detection opportunities*: eval đo khả năng phát hiện **hành vi của adversary**, mà adversary thật sẽ xoay vòng IP/filename/hash. Nếu signal phân biệt duy nhất của một row chỉ là một IOC cố định như vậy, chấm điểm nó đo "vendor có match đúng artifact của ta không", không phải "vendor có phát hiện được TTP không" → phình tập scored detection opportunities mà không đo capability.

2. **Double-counting**: hai rows mô tả cùng physical event nhưng dưới hai góc nhìn → nếu cả hai đều Calibrated, một lần detect thực tế cho điểm hai lần.

3. **Generic Operational Behavior làm loãng tập scored detection opportunities**: tool download, interpreter spawn, native recon (`netstat`/`ipconfig`) xuất hiện trong gần như mọi workflow lành tính — chúng không distinctive với adversary. Vấn đề không phải "dễ string-match", mà là **missing chúng không fairly quy được thành capability gap**: mọi sản phẩm đều thấy `netstat` chạy mỗi ngày, không alert nó là quyết định FP-tuning hợp lý chứ không phải lỗ hổng. Để chúng trong tập scored detection opportunities = không phân biệt được sản phẩm thực sự capable với sản phẩm yếu.

4. **Tập scored detection opportunities không ổn định**: nếu không có tiêu chí rõ ràng, tập này biến động theo người review — cùng phase, hai reviewer cho ra detection rate khác nhau.

### Giải pháp

`assign-category` thiết lập tập scored detection opportunities chính xác bằng một quy trình có thể audit và re-derive:

- Đọc Detection Criteria đã viết (evidence, không imagine) → Layer 1 pre-filter → Conditions 1–3 eligibility → C4 scoring gate
- Mọi NC row có reason tag → label re-derivable khi heuristic thay đổi
- Surface Profile echoed tường minh → tập scored detection opportunities stable và traceable

---

## Các bước và lý do thiết kế

### Step 1 — Xác định scope

> *"Ask the user: which Phase file? which steps/rows? Default to all rows."*

**Nhiệm vụ**: xác định coverage, tạo checklist one-task-per-row.

**Câu hỏi step này trả lời**: Tôi cần label những row nào?

**Lý do thiết kế**: Giống `write-detection-criteria` — default là all rows để không có row nào bị drop silently khỏi việc xem xét scored detection opportunities. Một row không được label = row không được quyết định có được tính là scored detection opportunity hay không.

---

### Step 2 — Establish Surface Profile

> *"Echo the active Surface Profile explicitly — never label on a silent default."*

**Nhiệm vụ**: khai báo Surface Profile trước khi label bất kỳ row nào. Default là Scenario 1 (EDR).

**Câu hỏi step này trả lời**: Telemetry surface nào đang active? Artifact off-surface trông như thế nào với profile này?

**Lý do thiết kế**: Surface Profile quyết định Q-A của mọi row. Không echo nó = model có thể label dựa trên default ngầm không nhất quán giữa sessions. Tệ hơn: nếu `write-detection-criteria` dùng một profile và `assign-category` dùng profile khác, một signal được viết "on-surface" có thể bị Q-A reject — mâu thuẫn giữa hai skills. Cả hai skills phải đọc cùng Surface Profile table (trong references.md này).

---

### Step 3 — Sketch execution chain

> *"List substeps in temporal order, note which artifact each produces and which downstream substep consumes it."*

**Nhiệm vụ**: vẽ bản đồ execution flow của step đang review để dùng khi apply Q-B.

**Câu hỏi step này trả lời**: Row nào là upstream/downstream của row nào? Row nào detect được row nào?

**Lý do thiết kế**: Q-B (implementation detail) yêu cầu biết "detecting row X có *trực tiếp chứng minh* row Y đã xảy ra không?" — không thể trả lời câu này nếu không có map về flow. Không có bước này, Q-B degenerates thành "row này có vẻ là setup" → subjective.

Việc sketch chain cũng ngăn false positive của Q-B: nhiều upstream step tưởng là implementation detail nhưng thực ra là independent detection opportunity (ví dụ: `mavinject.exe` spawn không chứng minh implant delivery đã thành công — hai opportunities độc lập).

---

### Step 4 — Label từng row qua 3-layer process

> *"Read its Detection Criteria first, then run Layer 1, Layer 2, C4."*

**Nhiệm vụ**: với mỗi row, đọc criteria đã viết và chạy qua toàn bộ gate sequence.

**Câu hỏi step này trả lời**: Row này có fair để score vendor không? Nếu không, vì lý do nào trong số các lý do được define rõ?

**Lý do thiết kế**: Thứ tự Layer 1 → Layer 2 → C4 không phải tuỳ ý:

- **Layer 1 trước** (Q-A, Q-B): Loại trừ những rows không nên được đánh giá signal quality — surface miss và redundancy. Nếu artifact off-surface, không cần hỏi nó reproducible không; nếu là implementation detail, không cần hỏi về distinctive TTP.

- **Conditions 1–3 đọc từ criteria**: Không re-derive. Nếu criteria là `N/A — C1`, Condition 2 (Reproducible) fail được đọc ra từ đó ngay — không cần model phán xét lại. Lưu ý mã `N/A — Cx` **không** đánh số trùng với Condition N — chúng bị hoán vị (`C3`↔Condition 1 Observable, `C1`↔Condition 2 Reproducible, `C2`↔Condition 3 Independently verifiable); mirror đúng mã gốc vào `Calibration Reason`, không đổi thành số Condition. Đây là lý do tại sao `write-detection-criteria` chạy trước.

- **C4 là gate thực sự**: Đây là điểm thiết kế cốt lõi. Conditions 1–3 chỉ là eligibility — rất nhiều rows pass cả ba mà vẫn NC. C4 hỏi: "Nếu vendor detect được điều này, điều đó có nghĩa là vendor *có capability* không, hay chỉ là vendor có signature/string-match?" Không có C4, score sẽ thưởng cho mọi thứ có signal, bao gồm `ipconfig`, `netstat`, hay bất kỳ native command nào.

**Quick labeling template** là shortcut 7 câu cho C4 — cho phép chạy toàn bộ quy trình trong một pass mà không mất bước.

---

### Step 5 — Write output in-place

> *"Category (clean enum) and Calibration Reason (reason tag for NC rows, `-` for Calibrated)."*

**Nhiệm vụ**: ghi kết quả vào hai cột — Category enum và Calibration Reason tag.

**Câu hỏi step này trả lời**: Label là gì, và lý do cụ thể là gì?

**Lý do thiết kế**: Tách `Category` (filterable enum) và `Calibration Reason` (human-readable reason tag) thay vì merge vào một cell là quyết định tooling:
- `Category` cần filterable/queryable by downstream scripts → clean enum, không có free text
- `Calibration Reason` cần human-auditable và re-derivable → tagged reason, không phải prose

Calibrated rows có `-` trong Calibration Reason là intentional: không có "lý do Calibrated" cần document — evidence đã nằm trong Detection Criteria và label logic là "all gates passed".

---

### Step 6 — Completeness check

> *"Every NC row carries a reason tag. Every step with 0 Calibrated rows needs one explicit justification sentence."*

**Nhiệm vụ**: kiểm tra không có NC row nào thiếu tag, và không có step nào có 0 Calibrated rows mà không document lý do. Skill còn thêm một luật: không được có **các step liên tiếp** cùng 0 Calibrated rows mà không có justification.

**Câu hỏi step này trả lời**: Mọi NC label đều có lý do traceable chưa? Có step nào không có detection opportunity không, và nếu có thì đó là intentional chưa?

**Lý do thiết kế**: NC không có reason tag = label không re-derivable. Khi heuristic thay đổi (C4c default verdict bị ghi đè, Surface Profile thay đổi), không biết NC đó do lý do nào → phải review lại từ đầu.

Điều kiện "0 Calibrated rows" là warning, không phải error — một step toàn setup/evasion/transport có thể hoàn toàn NC hợp lý. Nhưng phải documented tường minh vì nó ảnh hưởng trực tiếp đến tập scored detection opportunities.

---

### Step 7 — Layer 3 structural signals check

> *"Run Layer 3 to catch mislabeling patterns."*

**Nhiệm vụ**: sau khi label xong, chạy checklist pattern-level để bắt các lỗi hệ thống.

**Câu hỏi step này trả lời**: Nhìn toàn bộ kết quả labeling, có pattern nào bất thường gợi ý mislabeling hệ thống không?

**Lý do thiết kế**: Row-by-row labeling có thể locally consistent nhưng globally wrong. Layer 3 bắt các pattern không visible từ single-row perspective:
- Calibrated ratio ~100% với heavy custom implant use → suspiciously high (implant-heavy chains thường có nhiều in-process steps fail Condition 1 hoặc 3)
- Positive Detection Criteria + NC label mà không có reason tag → contradiction ẩn
- Hai rows cùng technique cùng process cùng destination không có criteria phân biệt → double-count chưa được bắt ở Q-B

---

### Step 8 — Hand off sang `assign-acw`

> *"Hand off to `assign-acw`. Do NOT edit Detection Criteria, re-author Phase content, map techniques, or assign ACW."*

**Nhiệm vụ**: kết thúc phiên labeling, chuyển sang skill kế tiếp trong pipeline.

**Câu hỏi step này trả lời**: Đã xong việc của skill này chưa, và ranh giới với skill kế tiếp nằm ở đâu?

**Lý do thiết kế**: Trục **Verdict** (Category) dừng lại ở đây; trục **Importance** (ACW) là công việc hoàn toàn tách biệt của `assign-acw`, đọc ngữ cảnh chuỗi tấn công chứ không đọc lại Category. Việc chặn rõ ràng "không edit Detection Criteria, không map technique, không gán ACW" ngăn skill này lấn sang phạm vi của `write-detection-criteria`, `map-technique`, hoặc `assign-acw` chỉ vì đang tiện tay sửa.

---

## Đánh giá khách quan

### Điểm mạnh

**C4 giữ tập scored detection opportunities chỉ gồm behavior generalize được và distinctive**
Đây là contribution lớn nhất. Không có C4, tập này gồm cả những row mà dấu hiệu phân biệt chỉ là IOC riêng của run này, hoặc plumbing phổ biến (`netstat`, `ipconfig`) chạy trong mọi môi trường. C4a hỏi: signal có phải property của TTP generalize được, hay chỉ là indicator cố định của lần emulation này? — câu hỏi này (không liên quan tới việc vendor detect bằng cơ chế gì) giữ tập này chỉ gồm behavior thực sự đo được capability.

**Reason tags làm NC labels auditable và re-derivable**
Khi heuristic thay đổi, không cần chạy lại toàn bộ decision logic từ đầu — đọc reason tag là biết ngay row đó fail ở gate nào. Overridable default verdicts kết hợp với reason tags cho phép systematic review theo từng gate thay vì row-by-row.

**Overridable default verdicts không phải blocklist theo TID**
Generic Operational Behavior classification theo vai trò trong step, không theo Technique ID. Cùng `T1105` (Ingress Tool Transfer) là NC khi là pure download nhưng có thể Calibrated khi là phần của distinctive exfil objective. Điều này ngăn over-generalization làm mất detection opportunities thực.

**Layer 3 là self-check hệ thống**
Pattern-level check sau khi label xong bắt được các lỗi không visible từ single-row perspective. Đặc biệt: phát hiện double-count ẩn khi Q-B same-level chưa được apply đúng.

**Đọc từ criteria đã viết thay vì imagine**
Giống như `write-detection-criteria`, principle này loại bỏ hallucination: model phải đối mặt với concrete evidence trước khi label. NC vì criteria là `N/A — C2` khác hoàn toàn với NC vì "tôi nghĩ behavior này khó detect" — cái trước traceable, cái sau là guess.

---

### Điểm yếu

**Q-B là gate khó nhất và dễ sai nhất**
"Detecting row downstream *trực tiếp chứng minh* row upstream đã xảy ra" yêu cầu counterfactual reasoning khó: "nếu chỉ có row downstream được detect, liệu có suy ra được row upstream đã xảy ra không?" Model phải model execution semantics, không chỉ đọc criteria. Kết quả: Q-B hay bị over-applied (mọi upstream step bị gọi là implementation detail) hoặc under-applied (double-count không được bắt).

**C4b yêu cầu counterfactual phức tạp**
"Còn là independent opportunity nếu dependent rows đã bị catch" là câu hỏi về execution logic, không phải về signal quality. Model phải hỏi: "Nếu vendor đã catch row X, row Y có thêm information gì không?" — khó answer chính xác nếu không có deep understanding về attack chain.

**Generic Operational Behavior default verdicts có thể over-apply**
"Strong NC" default verdict cho interpreter spawn và native recon là đúng trong đa số trường hợp, nhưng model có thể apply chúng mechanically không cần check vai trò. Lưu ý: override *không* được trigger bởi actor anomaly và *không bao giờ* chấm điểm bản thân cái spawn — skill nói rõ "score the distinctive action the interpreter performs, **never** the spawn". Ví dụ đúng: `powershell.exe` spawn là NC (interpreter-spawn), nhưng *hành động distinctive* mà nó thực hiện sau đó (ví dụ in-memory AMSI patch với pattern quan sát được) mới là Calibrated — và nó được score như một row riêng, không phải vì process cha bất thường. Default verdict không thay thế được việc xác định primary artifact của hành động.

**Surface Profile là shared dependency với write-detection-criteria**
Nếu Surface Profile không được echo tường minh ở cả hai skills, có thể xảy ra drift: criteria viết on-surface với một profile, label đọc từ criteria đó nhưng dùng profile khác → signal hợp lệ bị Q-A reject. Không có mechanism tự động detect drift này giữa hai sessions.

**Layer 3 là checklist, không phải enforcement**
Layer 3 structural signals gợi ý re-review nhưng không block labeling. Model có thể acknowledge pattern "Calibrated ratio ~100%" và tiếp tục mà không revisit. Human review là fallback cần thiết.

**Double-count detection phụ thuộc vào criteria specificity**
Q-B same-level match trên "technique + artifact/target + telemetry depth". Nếu Detection Criteria của hai rows quá vague (không specify process, không specify artifact đủ cụ thể), match có thể miss — double-count không được phát hiện. Điều này tạo dependency ngược lại về chất lượng của `write-detection-criteria` output.

---

## Ví dụ từ Phase 1 (iis-apppool-escalation-path)

Các ví dụ dưới đây lấy từ Reference Tables thực tế của Phase 1 để minh hoạ các concept trừu tượng trong các mục trên. Source: `testlab-enterprise/windows-adversary-plan/Emulation_Plan/iis-apppool-escalation-path/Phase 1.md`.

---

### Q-B downstream + Primary artifact: cặp T1105 trong Step 1

Cùng technique T1105, cùng actor (node.exe), cùng step — label khác nhau hoàn toàn:

| Row | Category | Calibration Reason | Lý do |
|---|---|---|---|
| `dnscat2 XOR-encoded PE write to CertCA.enc` | NC | `redundant@T1027.013` | Primary artifact của write là file CertCA.enc; property distinctive duy nhất (first byte 0xEE, XOR-encoded PE structure) đã được T1027.013 capture — detecting T1027.013 trực tiếp chứng minh write này đã xảy ra → Q-B downstream |
| `EfsPotato PE base64-stream write to CertEnrollSvc.bin` | Calibrated | `-` | Primary artifact là executable-class binary tại `C:\Windows\Temp\` viết bởi node.exe — không có downstream row nào capture anomaly này; node.exe viết PE vào Temp là detection opportunity độc lập trên IIS01 baseline |

**Bài học**: cùng TID, cùng actor, kết quả khác nhau vì primary artifact của từng action khác nhau về tính độc lập. Actor bất thường (node.exe viết file) là context, không phải basis của override — câu hỏi đúng là "file có anomaly quan sát độc lập không, hay property đó đã bị một Calibrated row khác own?"

---

### C4c interpreter-spawn default verdict và khi nào nó không apply: T1059.007 cluster trong Step 1–2

Cùng T1059.007, nhưng 3 row NC vì C2, 1 row Calibrated:

| Row | Category | Reason | Primary artifact của action |
|---|---|---|---|
| `node.exe eval charcode chunk-stream dnscat2 to CertCA.enc` | NC | `C2` | Eval xảy ra trong V8 runtime — artifact ngoài duy nhất là CertCA.enc file-create, đã covered bởi T1105/T1027.013 |
| `node.exe eval charcode chunk-stream EfsPotato to CertEnrollSvc.bin` | NC | `C2` | Eval trong V8 runtime — artifact ngoài duy nhất là CertEnrollSvc.bin file-create, covered bởi T1105 |
| `node.exe eval fs.renameSync CertEnrollSvc .bin to .exe` | NC | `C2` | Eval trong V8 runtime — artifact ngoài duy nhất là file rename, covered bởi T1036.005 |
| `node.exe spawnSync CertEnrollSvc.exe stdin PE delivery` | Calibrated | `-` | **Child process creation** — Sysmon EID 1 ghi node.exe spawning executable từ `C:\Windows\Temp\`; event này externally observable và độc lập với các row trên |

Ba row NC không phải vì interpreter-spawn default verdict (C4c) — chúng NC vì **C2** (in-process execution, không có externally verifiable artifact). Row Calibrated không bị NC interpreter-spawn default verdict vì primary artifact của `spawnSync` là một child process creation event (Sysmon EID 1), không phải spawn của interpreter — đây là event độc lập và distinctive trên IIS web worker baseline. Phân biệt: interpreter-spawn default verdict covers "interpreter được spawn để chạy commands" (cái spawn là generic transport); còn đây là interpreter spawning một target binary riêng, và cái process creation event chính là detection opportunity.

---

### C4 là gate thực sự: T1070.004 temp PE delete trong Step 2

Row `CertEnrollSvc.exe temp PE file delete after SYSTEM child exit` (T1070.004):
- **Detection Criteria**: Sysmon EID 23 file-delete attributed to CertEnrollSvc.exe trên freshly-created executable trong temp directory; write-spawn-delete sequence là anomalous behavioral pattern.
- **Category**: NC `staging`

Signal hoàn toàn writable, pass C1/C2/C3 — nhưng NC vì C4c. Behavior là internal housekeeping (cleanup sau khi SYSTEM child exit): indicator removal thuộc Generic Operational Behavior class, missing nó không fairly quy được thành detection capability gap. Đây là case điển hình minh hoạ lý do thiết kế C4: "Conditions 1–3 chỉ là eligibility — rất nhiều rows pass cả ba mà vẫn NC."

---

### interpreter-spawn default verdict khi actor bất thường: T1059.003 cmd.exe spawn trong Step 4

Row `RuntimeBroker.exe ghost process cmd.exe SYSTEM shell spawn` (T1059.003):
- **Detection Criteria**: RuntimeBroker.exe spawns cmd.exe as NT AUTHORITY\SYSTEM — RuntimeBroker.exe is not a parent of interactive command interpreters in any Windows baseline; Sysmon EID 1 captures the parent-child relationship.
- **Category**: NC `interpreter-spawn`

Dù actor (RuntimeBroker.exe ghost process) cực kỳ bất thường, cmd.exe spawn vẫn NC vì interpreter-spawn default verdict. Actor anomaly là context, không phải override trigger. Câu hỏi đúng: "primary artifact của action (cmd.exe process creation) có property gì độc lập ngoài việc là một interpreter spawn không?" — không có. Behavior distinctive thực sự (ghost process, PPID spoof, image-content mismatch) đã được score trong các row T1055, T1134.004, T1036.005 của Step 3. cmd.exe spawn là Generic Operational Behavior để operator tương tác tiếp.

Đây cũng minh hoạ điểm yếu "Generic Operational Behavior default verdicts có thể over-apply": nếu không có execution chain sketch (Step 3 của skill), dễ flip label này sang Calibrated chỉ vì "RuntimeBroker.exe spawning cmd.exe looks suspicious" — nhưng suspicious actor không thay đổi classification của hành động spawn-interpreter.
