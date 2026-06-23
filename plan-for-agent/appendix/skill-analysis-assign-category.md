# Phân tích thiết kế skill: `assign-category`

> Bài phân tích trong loạt tài liệu giải thích **lý do thiết kế** của từng skill trong `.claude/skills/`. Mục tiêu: làm rõ skill nằm ở đâu trong pipeline, chứng minh tính hợp lý của các lựa chọn, và nhìn nhận khách quan ưu/nhược điểm. Đây là tài liệu *mô tả lý do* — không phải bản sao của SKILL.md (xem trực tiếp `.claude/skills/assign-category/SKILL.md` để biết quy tắc thực thi, và `appendix/calibrated-assign-mindmap.md` cho sơ đồ quyết định).

---

## 1. Skill này giải bài toán gì

Một Phase file chứa nhiều dòng hành vi (Reference Table). Không phải dòng nào cũng là **cơ hội phát hiện công bằng** để tính vào tỷ lệ phát hiện của sản phẩm bảo mật. `assign-category` quyết định dòng nào được tính (`Calibrated`) và dòng nào không (`Not Calibrated`) — tức là **định nghĩa mẫu số của detection-rate**.

Đây là một quyết định *đánh giá* (evaluation design), không phải quyết định *kỹ thuật tấn công*. Câu hỏi xuyên suốt: **"nếu sản phẩm bỏ sót tín hiệu này, lỗi đó có quy được cho nhà cung cấp không?"** Nếu không quy được (artifact nằm ngoài bề mặt telemetry, hoặc chỉ tồn tại trong bộ nhớ không kiểm chứng được) thì không công bằng để chấm điểm.

---

## 2. Vị trí trong pipeline

```
... → map-technique → write-detection-criteria → [assign-category] → assign-acw
                       (bằng chứng ổn định)       (verdict heuristic)   (trục độc lập)
```

- **Đầu vào:** một Phase file đã có cột `Detection Criteria` được điền **cho mọi dòng** (từ `write-detection-criteria`).
- **Đầu ra:** điền hai cột — `Category` (enum sạch) và `Calibration Reason` (tag lý do).
- **Bàn giao:** sang `assign-acw` để chấm trọng số chuỗi tấn công.

Điểm cốt lõi về vị trí: skill này **chạy SAU `write-detection-criteria` và ĐỌC** cột bằng chứng đó, chứ không tự tưởng tượng ra. Đây là lựa chọn thiết kế quan trọng nhất, phân tích ở mục 3.1.

---

## 3. Các lựa chọn thiết kế & lý do

### 3.1. Tách "viết bằng chứng" khỏi "gán nhãn" — và xếp bằng chứng trước

**Lựa chọn:** Detection Criteria được viết trước, ở một skill riêng. `assign-category` chỉ đọc nó.

**Lý do:** Trước đây nếu một skill vừa gán nhãn vừa tự hỏi "có viết được tín hiệu phát hiện cho dòng này không?", nó phải *tưởng tượng* ra bằng chứng — đúng kiểu tình huống dễ sinh ảo giác (hallucination). Bằng cách bắt buộc bằng chứng phải **đã được viết ra** trước, quyết định gán nhãn trở thành thao tác *đọc* trên dữ liệu có thật.

**Lợi ích kép quan trọng:** logic phân loại là *heuristic* và được kỳ vọng sẽ thay đổi theo thời gian; còn Detection Criteria là *artifact ổn định*. Tách hai tầng cho phép **chạy lại việc gán nhãn** khi heuristic đổi mà **không phải viết lại bằng chứng**. Đây là dạng tách "dữ liệu ổn định" vs "phán đoán biến động" — một quyết định kiến trúc tốt.

> Đánh đổi (khách quan): cái giá là chuỗi pipeline dài hơn và hai skill phải được chạy đúng thứ tự. Nếu người dùng chạy `assign-category` khi cột criteria còn `TBD`, skill phải dừng — đó là lý do có Hard Gate #1. Sự an toàn này đổi bằng một chút ma sát vận hành.

### 3.2. "Tín hiệu sạch" KHÔNG đồng nghĩa "Calibrated"

**Lựa chọn:** Conditions 1–3 (Observable / Reproducible / Independently verifiable) chỉ là **bộ lọc loại trừ** (elimination filter) cho *tính đủ điều kiện*; quyết định thật nằm ở **Condition 4**.

**Lý do:** Đây là chỗ trực giác hay sai nhất. `netstat`, `ipconfig`, tải tool, `PsExec` đều cho tín hiệu hoàn hảo (qua C1–C3) nhưng vẫn là **Not Calibrated**. Vì có tín hiệu ≠ có điểm. C4 mới hỏi đúng câu: tín hiệu này có phải **cơ hội phát hiện độc lập, mang chữ ký đặc trưng của actor**, hay chỉ là "mô liên kết" chung chung (delivery, transport, spawn interpreter, recon native)?

C4 gồm ba điều kiện đồng thời phải đúng:
- **4a** — chấm việc *phát hiện hành vi*, không phải khớp chuỗi lệnh / IOC.
- **4b** — là cơ hội phát hiện *mới và độc lập*, không trùng với dòng đã được chấm (exfil qua kênh *mới* = Calibrated; exfil qua C2 *đã có* = Not Calibrated).
- **4c** — là TTP *đặc trưng của actor*, không phải mô liên kết.

**Vì sao thiết kế thành "prior có thể bác bỏ":** cùng một technique có thể lật nhãn tùy *vai trò trong bước*. Rar dùng để staging vs rar+exfil là mục tiêu — cùng kỹ thuật, khác nhãn. Việc tách C1–C3 (đủ điều kiện) khỏi C4 (chấm điểm) khiến quy tắc này diễn đạt được rõ ràng thay vì gói chung thành "có vẻ quan trọng".

### 3.3. Output là HAI cột, không phải một

**Lựa chọn:** `Category` giữ là enum sạch (lọc/đếm được); lý do được tách sang `Calibration Reason` dưới dạng tag từ vựng cố định (`out-of-surface` / `redundant@<TechID>` / `transport` / `interpreter-spawn` / `native-recon` / `staging` / `in-process` / `IOC-only` / `C1|C2|C3`).

**Lý do:** "Lý do được ghi lại quan trọng hơn cái nhãn." Khi heuristic đổi, có thể **suy lại nhãn từ tag** mà không cần phân tích lại từ đầu. Một cú lật nhãn theo vai trò (staging vs objective) chỉ *hợp lệ khi tag giải thích được nó*. Giữ `Category` sạch cũng cho phép script chấm điểm hạ nguồn lọc nhanh mà không phải parse văn bản tự do.

> Đánh đổi: thêm một cột nghĩa là thêm kỷ luật điền dữ liệu. Skill bù lại bằng "completeness check" — mọi dòng NC phải có tag, nếu thiếu coi như chưa xong.

### 3.4. Không được sửa cột `Detection Criteria`; ACW là trục độc lập

**Lựa chọn:** quyền ghi theo cột tách bạch — skill này chỉ sở hữu `Category` + `Calibration Reason`. Nếu thấy criteria "có vẻ sai", sửa **nhãn**, không sửa bằng chứng. Và độ quan trọng chuỗi (ACW) **không bao giờ** nâng/hạ nhãn calibration.

**Lý do:** Đây là nguyên tắc "column-disjoint write ownership" của toàn pipeline — cho phép cùng một file đi qua nhiều skill mà không skill nào ghi đè cột của skill khác. Việc tách ACW khỏi Category ngăn lỗi phổ biến nhất: "bước này Critical nên phải Calibrated". Thực tế cả 4 tổ hợp đều hợp lệ (một pivot Critical nhưng chỉ tồn tại in-memory thì vẫn Critical-ACW *và* Not-Calibrated).

### 3.5. Lớp tuning hành vi: Hard Gate + Anti-Pattern + Red Flags

**Lựa chọn:** đầu SKILL.md có `<HARD-GATE>` liệt kê 5 bất biến; cuối có bảng "Anti-Patterns" (bác bỏ các lý do hợp lý hóa có tên) và "Red Flags" (dừng lại nếu đang nghĩ…).

**Lý do:** Các lỗi của skill này không phải lỗi *kiến thức* mà là lỗi *tự thuyết phục* ("dòng này nhìn là biết Calibrated", "criteria yếu, để tôi sửa luôn"). Liệt kê thẳng các rationalization đó và phản bác từng cái sẽ chặn được lối tắt sai ngay tại thời điểm model định đi vào. Đây là pattern L1/L2/L4/L5 từ `skill-lesson-learn.md`.

---

## 3b. Trục thuộc tính & tiêu chí quyết định (đào sâu)

Gán nhãn là một **chuỗi cổng `first-stop-wins`**: dừng ngay khi một cổng kết luận Not-Calibrated. Các trục, theo thứ tự áp dụng:

| Trục | Tầng | Giá trị | Vai trò |
|---|---|---|---|
| **Surface type** | L0 | `S1-EDR (default)` / `Basic EDR` / `XDR` / `Custom` | đặt nội dung C1 (kênh memory in/out) và C4 (kênh nào tính điểm) |
| **Scope (Q-A)** | L1 | `on-surface` / `off` | first-stop → tag `out-of-surface` |
| **Redundancy (Q-B)** | L1 | `independent` / `same-level dup` / `downstream-proven` / `dead-end` | first-stop → tag `redundant@<TID>` |
| **C1–C3 eligibility** | L2 | pass/fail — *đọc từ criteria, không re-derive* | elimination filter (chỉ cho *đủ điều kiện*) |
| **C4a** behavior-vs-IOC | L2 | `behavior` / `IOC-only` | scoring gate → tag `IOC-only` |
| **C4b** independence | L2 | `new opportunity` / `folded` | scoring gate → `redundant`/`transport` |
| **C4c** distinctive | L2 | `actor-signature` / `connective-tissue` | scoring gate → tag mô-liên-kết |
| **Output: Category** | — | enum sạch | verdict lọc/đếm được |
| **Output: Calibration Reason** | — | 8-tag vocab | lý do *suy-lại-được* |
| **ACW** | (downstream) | trực giao | **không bao giờ** chi phối nhãn |

**Tiêu chí cốt lõi — tín hiệu sạch (C1–C3) chỉ mua *eligibility*; điểm thật quyết ở C4.** Phần lớn dòng Not-Calibrated *vượt* C1–C3 hoàn hảo (netstat, ipconfig, tool download, PsExec). Cây quyết định dồn trọng lượng vào C4, và trong C4 dồn tiếp vào **4c** (distinctive vs connective-tissue) — mắt xích chủ quan nhất.

**Ba sub-test của C4 có bản chất nhận thức rất khác nhau** (điểm ít được nói tới, nhưng quyết định độ tin cậy của cả khung):
- *4a* — gần **khách quan**: tín hiệu viết-được duy nhất có phải một chuỗi/hash/IP/filename cố định không? Gần như tra được.
- *4b* — mang tính **cấu trúc**: phụ thuộc *sketch chuỗi*, tức phụ thuộc cách dòng đã được tách ở `write-phase`/`map-technique`. Đúng/sai theo cấu trúc bảng, không theo trực giác.
- *4c* — là **phán đoán thẩm mỹ** "actor-signature aha" dựa trên prior bác-bỏ-được theo vai trò. Kém tái lập nhất.

"Cả ba phải đúng" gộp ba thứ khác hẳn epistemic status thành một cổng — nên độ tái lập của *toàn bộ* nhãn bị kéo xuống bằng mắt xích yếu nhất là 4c. Đây là lý do tag `Calibration Reason` tồn tại: nó không làm 4c khách quan hơn, nhưng *ghi lại* cú phán đoán để suy-lại-được.

---

## 4. Luồng nội bộ (tóm tắt)

1. **Layer 0** — xác lập bối cảnh: Detections/Protections, bề mặt telemetry (mặc định Scenario 1 EDR).
2. **Sketch** chuỗi thực thi theo thứ tự thời gian (phục vụ kiểm tra trùng lặp ở Q-B).
3. Với mỗi dòng: **đọc Detection Criteria trước** → Q-A (trên bề mặt khai báo?) → Q-B (chi tiết triển khai của dòng Calibrated khác?) → C1–C3 (đủ điều kiện) → **C4 (chấm điểm thật)**.
4. Ghi `Category` + `Calibration Reason` tại chỗ.
5. **Completeness check** — mọi dòng NC có tag; bước toàn-NC phải có lý do; không hai bước liên tiếp 0-Calibrated vô cớ.
6. **Layer 3** — kiểm tra tín hiệu cấu trúc bắt lỗi gán nhãn phổ biến.
7. Bàn giao `assign-acw`.

(Sơ đồ đầy đủ: `appendix/calibrated-assign-mindmap.md`.)

---

## 5. Đánh giá khách quan

### Ưu điểm

- **Chống ảo giác bằng kiến trúc, không bằng lời nhắc.** Bắt đọc bằng chứng có thật thay vì tin vào "nhắc model cẩn thận" — đây là cách bền vững nhất.
- **Tách ổn định/biến động đúng chỗ.** Criteria (ổn định) tách khỏi Category (heuristic) cho phép chạy lại nhãn mà không đụng bằng chứng — chịu được việc heuristic tiến hóa.
- **Tag lý do làm nhãn có thể truy vết & suy lại.** Quyết định không còn là hộp đen; một cú lật nhãn theo vai trò luôn kèm lời giải thích.
- **Các bất biến được phát biểu rõ** (C1–C3 vs C4, ACW độc lập, column-disjoint) nên ít bị diễn giải tùy tiện.

### Nhược điểm / đánh đổi

- **Phụ thuộc thứ tự chạy.** Nếu upstream chưa xong (criteria còn `TBD`), skill buộc phải dừng. Sức mạnh của thiết kế cũng là điểm cứng nhắc của nó — không "chạy tắt" được.
- **C4 vẫn là phán đoán.** 4a/4b/4c là "prior có thể bác bỏ", nên hai người (hoặc hai lần chạy) có thể khác nhau ở ca biên. Thiết kế giảm thiểu bằng tag lý do, nhưng không loại bỏ hoàn toàn tính chủ quan — đây là giới hạn nội tại của bài toán calibration, không phải lỗi skill.
- **Chi phí nhận thức cao.** Người vận hành phải nắm Layer 0–3, phân biệt C1–C3 vs C4, và bộ tag — đường học dốc hơn một skill gán nhãn ngây thơ. Bù lại bằng mindmap + guide, nhưng vẫn là chi phí thật.
- **Nhiều bất biến trùng lặp giữa Hard Gate / Anti-Pattern / Red Flags / Notes.** Sự lặp lại này có chủ đích (chặn rationalization ở nhiều điểm), nhưng làm SKILL.md dài và cần đồng bộ khi sửa — rủi ro drift nội bộ nếu một chỗ được cập nhật mà chỗ khác quên.

### Phản biện sâu (điểm căng trong chính khung)

- **Khung nghiêm ngặt nhưng thừa kế trọn tính chủ quan của 4c.** Mọi scaffolding — Layer 0–3, C1–C3, 4a/4b — bao quanh một hạt nhân (4c) vốn là *prior bác-bỏ-được theo vai trò trong bước*. Hai lần chạy có thể khác nhau ở ca biên dù mọi bước khác giống hệt. Đây không phải lỗi skill mà là giới hạn nội tại của bài toán calibration; nhưng cần nói thẳng: độ chặt của khung *che* chứ không *xoá* điểm mềm này.
- **Vocabulary tag từng có lỗ phủ — nay đã vá bằng tag `staging`.** Bộ tag cũ (`out-of-surface` / `redundant@<TID>` / `transport` / `interpreter-spawn` / `native-recon` / `in-process` / `IOC-only` / `C1|C2|C3`) **thiếu tag cho "pure staging / indicator removal"** dù chính bảng connective-tissue trong guide liệt kê chúng là một lớp NC riêng; một dòng rar-staging hợp lệ bị loại buộc phải nhét vào `transport`/`redundant@`, làm *mất* lý do thật. Vì thiết kế dựa trên tiền đề "lý do quan trọng hơn nhãn", lỗ phủ này không cosmetic — nó hỏng đúng tính năng suy-lại-được mà hai-cột-output dựng lên. Đã thêm tag `staging` (cả SKILL.md `.windsurf`, guide, emulation-plan-structure, mindmap) ánh xạ thẳng vào hàng "Indicator removal / pure staging". *Bài học còn lại:* bộ tag là enum đóng nằm rải ở ~6 file — mỗi lần mở rộng phải sửa đồng bộ, nếu không lại drift.
- **Bộ dò double-count từng phụ thuộc *câu chữ* upstream — nay khoá theo ngữ nghĩa.** Trước đây Q-B same-level mô tả bắt trùng qua "criteria y hệt": nếu `write-detection-criteria` diễn đạt hai dòng *thực sự trùng* bằng hai câu hơi khác nhau thì bộ dò trượt; hai skill khớp nhau qua **độ chính xác verbatim** — ràng buộc ngầm dễ vỡ. → *Đã giảm thiểu:* bộ dò nay khoá theo **same technique + same artifact/target (cùng capability depth)**, nêu rõ "không dựa verbatim text", khớp với Q-B vốn đã ngữ nghĩa (`category-assignment.md` Same-level). *Residual:* "same artifact" vẫn cần đọc-hiểu của người vận hành, không phải so khớp máy móc tuyệt đối — chỉ chuyển từ phụ-thuộc-câu-chữ sang phụ-thuộc-phán-đoán-ngữ-nghĩa.
- **Layer 0 default là cái núm tác động lớn nhất nhưng từng dễ bị bỏ qua nhất.** Default full-EDR (memory scan + ETW + YARA) khiến nhiều hành vi in-memory *vượt* C1 (thay vì rớt như trên Basic EDR), đẩy thêm dòng xuống C4 và **nới mẫu số detection-rate**; một dòng mặc định lặng lẽ dịch chuyển toàn bộ denominator. → *Đã giảm thiểu:* Layer 0 nay đặt tên **Surface Profile**, **buộc echo profile tường minh** ("never label on a silent default") và ghi rõ "lựa chọn này set detection-rate denominator", buộc xác nhận khớp sản phẩm đang đánh giá. *Residual:* vẫn là kỷ luật quy trình chứ chưa phải cổng cứng — người vận hành vẫn có thể echo cho-có rồi để nguyên default.
- **"Đọc C1–C3, đừng re-derive" đổi rủi-ro-ảo-giác lấy rủi-ro-lan-truyền.** Nếu upstream lỡ viết một tín hiệu off-surface thành positive, skill này được *lệnh* đọc đó như "C1–C3 hold" và có thể Calibrate sai. Cái split chống hallucination cũng mở một đường propagation; chốt chặn duy nhất là vài tín hiệu Layer 3 (vd "Calibrated nhưng criteria là `N/A`") cộng quyền gửi-ngược dòng. Không Layer-3 nào khớp thì lỗi đi thẳng xuống điểm.
- **ACW-độc-lập là *norm*, không phải *invariant* được tool đảm bảo.** Hai cột tách nhau nhưng cùng một người điền ở hai pass liền kề; lực kéo "Critical → phải Calibrated" là nhận thức. Skill chặn bằng Anti-Pattern/Red Flags (lời nhắc lặp lại), không bằng cơ chế cứng — nên đây là bất biến *được nhắc*, không phải *được cưỡng chế*.

### Khi nào dễ sai nhất

- Gán nhãn từ mô tả hành vi thay vì từ criteria đã viết (Hard Gate #2 tồn tại đúng vì lỗi này).
- Dừng ở "có tín hiệu sạch → Calibrated" mà không tới C4.
- Để ACW/độ quan trọng chuỗi kéo nhãn.
- Quên tag `Calibration Reason` cho dòng NC.

---

## 6. Liên hệ

- Quy tắc thực thi: `.claude/skills/assign-category/SKILL.md`
- Phương pháp nền: `plan-for-agent/guides/category-assignment.md`, `plan-for-agent/attack-behavior-methodology.md`
- Sơ đồ quyết định: `plan-for-agent/appendix/calibrated-assign-mindmap.md`
- Skill liền kề: `write-detection-criteria` (upstream — viết bằng chứng), `assign-acw` (downstream — trục trọng số độc lập)
