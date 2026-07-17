# Phân tích skill: assign-acw

Tài liệu này giải thích từ gốc rễ tại sao skill `assign-acw` tồn tại, nó làm gì, mỗi bước thiết kế vì lý do gì, và đánh giá khách quan điểm mạnh/yếu.

---

## Terminology

**ACW — Attack Chain Weighting**
Trọng số *importance* gán cho mỗi behavior, phản ánh hành vi đó quan trọng đến mức nào với tiến trình của attacker qua chuỗi tấn công. Bốn mức: **Critical (1.0×) · High (0.75×) · Medium (0.5×) · Low (0.25×)**. ACW là một scoring axis độc lập trong `Scoring Specification.md` — nó là hệ số nhân lên Detection Coverage (và Protection Coverage), không phải một calibration decision.

**Scored unit = behavior, không phải technique**
DC được chấm per behavior (per row), nên ACW cũng gán **per behavior**, không phải per Technique ID. Cùng một TID xuất hiện ở nhiều row khác nhau trong chuỗi → mỗi lần xuất hiện nhận ACW riêng theo vai trò của nó ở chỗ đó. Đây là điểm khác biệt cốt lõi so với bảng ví dụ per-technique của MITRE.

**Ba lens đánh giá (mạnh → yếu)**
- **Terminal objective** — hành vi là đích mà step-cluster / cả chuỗi đang hướng tới (ransomware encryption, domain takeover, credential harvest quyết định). → **Critical**.
- **Bottleneck** — hành vi *tạo ra* một cơ hội mới mà chuỗi phụ thuộc vào: initial access, privilege escalation, hoặc lateral movement sang host khác. Bỏ nó đi thì downstream sụp đổ. → **Critical**.
- **Value-to-attacker** — đòn bẩy hành vi trao cho attacker. Capability càng lớn, weight càng cao. → **High / Medium / Low**.

**Decision tree Q1–Q6 (first match wins)**
Sáu câu hỏi chạy top-down, dừng ở match đầu tiên: Q1 terminal objective → Q2 bottleneck → Q3 high-value-on-its-own → Q4 preparatory/staging → Q5 evasion/obfuscation → Q6 pure recon/enumeration. Thứ tự phản ánh thứ tự ưu tiên của vai trò, không phải checklist tuỳ ý.

**Cross-cutting modifier (hard-to-detect tie-breaker)**
"Khó phát hiện" là một trait của Critical nhưng chỉ dùng làm tie-breaker, không phải bucket riêng. Một row đã ở **High** *và* hard-to-detect (in-memory only, no command line, no file artifact) → cân nhắc promote lên **Critical** vì missing nó tốn defender nhiều hơn. Hard-to-detect **không bao giờ** tự nâng một row Low/Medium lên Critical — nó chỉ phá thế hoà **High ↔ Critical**.

**Critical ceiling ~35%**
Trần kiểm soát: nếu hơn ~35% số row là Critical, phải re-review. Nguyên nhân thường gặp là chấm một sub-cluster terminal (Q1 tier 2/3) như thể nó là whole-chain terminal.

**ALT path ≠ optional cluster / fallback**
ALT tồn tại để mở rộng technique coverage, không phải đường dự phòng. ALT và main step chia sẻ cùng vai trò → **cùng ACW**. Demotion "optional cluster" chỉ áp dụng khi xoá cluster mà chuỗi vẫn về đích *mà không cần* đi đường thay thế.

---

## Tại sao skill này tồn tại

### Vấn đề

`Scoring Specification.md` định nghĩa `Weighted_DC_normalized = Σ(DC × ACW) / (Σ ACW × 3.0)`. ACW đứng ở cả tử số lẫn mẫu số — tức là **chất lượng gán ACW quyết định trực tiếp điểm cuối**. Nếu gán ACW tuỳ tiện sẽ phát sinh các lỗi:

1. **Đánh đồng theo Technique ID**: cách tự nhiên nhất (và sai) là tra bảng MITRE rồi gán cùng một weight cho mọi row có cùng TID. Nhưng `T1003` dump LSASS-cache để pivot một lần khác hẳn `T1003` dump NTDS.dit như terminal harvest — gán chung một weight làm sai cả tử lẫn mẫu của công thức.

2. **Để Category lây nhiễm ACW**: model dễ suy luận "row này Not-Calibrated nên ACW thấp / bỏ qua". Đây là nhầm lẫn hai axis độc lập. Một Critical bottleneck là in-memory step không observable vẫn phải là **Critical ACW *và* Not Calibrated** — bỏ nó khỏi mẫu số (Σ ACW) làm méo normalization.

3. **Lạm phát Critical**: nếu coi "Critical = quan trọng" thì mọi behavior trông sophisticated đều bị gán Critical. Khi đó mẫu số `Σ ACW` phình lên, độ phân giải giữa hành vi thực sự quyết định và hành vi phụ trợ biến mất — điểm mất ý nghĩa.

4. **Lẫn weighting với scoring**: nếu skill tự tính luôn Weighted_DC/denominator, nó vừa gán trọng số vừa chấm điểm trong một pass → không audit được, không tách được lỗi weighting khỏi lỗi scoring.

### Giải pháp

`assign-acw` tách **weighting** ra khỏi **scoring** và ra khỏi **calibration**:

- Gán ACW per behavior, chỉ dựa trên **chain role** (đọc từ `summary.md`) — không nhìn Category, không tính điểm.
- Decision tree Q1–Q6 first-match-wins → quy trình deterministic, re-derivable.
- Critical ceiling ~35% như một self-check chống lạm phát.
- Terminal state dừng ở cột `ACW`; tuyệt đối không tính `Weighted_DC`/denominator — đó là việc của scoring script.

---

## Các bước và lý do thiết kế

### Step 0 — Gather inputs

> *"CSV file path · Summary file · Write-back in-place hay file mới."*

**Nhiệm vụ**: xác định CSV cần cập nhật, summary để đọc chain context, và chế độ ghi (default in-place).

**Câu hỏi step này trả lời**: Tôi đang weight plan nào, đọc chain từ đâu?

**Lý do thiết kế**: ACW chỉ có nghĩa khi đặt trong một chain cụ thể — cùng một behavior nhận weight khác nhau tuỳ chuỗi. Vì vậy summary file là input bắt buộc, không phải optional context. Nếu user đã nêu path trong message thì skip hỏi.

---

### Step 1 — Read chain context

> *"Identify at the behavior level: terminal objectives, bottlenecks, preparatory, evasion-only."*

**Nhiệm vụ**: đọc summary, phân loại sơ bộ các behavior theo bốn nhóm vai trò trước khi chạm vào CSV.

**Câu hỏi step này trả lời**: Đâu là đích cuối chuỗi? Đâu là các pivot bắt buộc? Đâu là staging/evasion?

**Lý do thiết kế**: Đây là bước thiết lập "bản đồ vai trò" mà toàn bộ decision tree dựa vào. Q1 (terminal) và Q2 (bottleneck) không thể trả lời nếu chưa biết chuỗi đang hướng về đâu và bị ép qua những điểm nào. Đọc chain *trước* khi đọc từng row ngăn lỗi phổ biến: weight từng hành vi như một đơn vị cô lập (mọi exploit trông đều "quan trọng") thay vì theo vị trí của nó trong chuỗi.

---

### Step 2 — Read the CSV

> *"Each row is one behavior — do not collapse rows by Technique ID."*

**Nhiệm vụ**: trích mọi row kèm step, tactic, technique, red team activity. Không gộp row theo TID.

**Câu hỏi step này trả lời**: Có bao nhiêu behavior cần weight, mỗi behavior nằm ở step nào?

**Lý do thiết kế**: Câu lệnh "không collapse theo TID" đặt ngay tại bước đọc vì đây là nơi lỗi đánh đồng-theo-TID phát sinh. Nếu model gộp hai row T1047 thành một "technique WMI", nó đã đánh mất thông tin vai trò trước khi tới được decision tree.

---

### Step 3 — Assign ACW per behavior (per row)

> *"Use the Q1–Q6 decision tree, first match wins. Track coverage explicitly — one task per row."*

**Nhiệm vụ**: chạy mỗi row qua Q1–Q6, gán đúng một mức ACW; sau khi bucket xong, áp cross-cutting modifier.

**Câu hỏi step này trả lời**: Vai trò của *behavior này tại chỗ này* trong chuỗi là gì?

**Lý do thiết kế**: First-match-wins làm quy trình deterministic — không có chuyện một row vừa "terminal" vừa "staging" gây ambiguity, vì Q1 chặn trước Q4. Thứ tự câu hỏi cũng chính là thứ tự ưu tiên vai trò: terminal/bottleneck (Critical) phải được loại ra trước khi xét value/staging/evasion. Coverage tracking (one task per row) đảm bảo không row nào bị bỏ trống ACW — một row trống ACW là một số hạng thiếu trong cả tử lẫn mẫu của công thức scoring.

Cross-cutting modifier áp **sau** khi bucket, không trong lúc bucket, để hard-to-detect không bị dùng như cái cớ nâng tuỳ tiện — nó chỉ được phép phá thế hoà High↔Critical đã hình thành.

---

### Step 4 — Consistency check

> *"Critical ceiling ~35%. Verify same-TID rows weighted on own role. Flag pure-evasion Critical."*

**Nhiệm vụ**: chạy checklist pattern-level trước khi ghi: ít nhất một Critical tồn tại, chain-terminal là Critical, không có pure-evasion bị gán Critical, và trần Critical ~35%.

**Câu hỏi step này trả lời**: Nhìn toàn bộ phân bố ACW, có pattern bất thường gợi ý lỗi hệ thống không?

**Lý do thiết kế**: Row-by-row có thể locally đúng nhưng globally lệch. Trần 35% bắt đúng lỗi nguy hiểm nhất — lạm phát Critical do nhầm sub-cluster terminal với whole-chain terminal. Đây là self-check tương tự Layer 3 của `assign-category`: không chặn cứng, nhưng buộc re-review khi pattern khả nghi.

---

### Step 5 — Write output

> *"Insert ACW column after Calibration Reason. Short labels. Terminal summary table + tally."*

**Nhiệm vụ**: ghi cột `ACW` ngay sau `Calibration Reason` (giữ Category và Calibration Reason liền kề), dùng nhãn ngắn; xuất bảng summary per-behavior và tally ra terminal.

**Câu hỏi step này trả lời**: Kết quả được ghi ở đâu và trình bày thế nào để người review thấy được khác biệt vai trò?

**Lý do thiết kế**: Đặt `ACW` cạnh `Calibration Reason` chứ không xen giữa Category/Calibration Reason là chủ ý — hai cột calibration phải dính nhau để đọc. Khi cùng TID tái xuất với ACW khác nhau, giữ **cả hai dòng** trong summary để khác biệt vai trò hiển thị rõ — đây chính là bằng chứng skill đã weight theo role chứ không theo TID.

---

## Đánh giá khách quan

### Điểm mạnh

**Tách bạch ba axis: weighting / calibration / scoring**
ACW chỉ trả lời "vai trò trong chuỗi", Category trả lời "có fair để score không", scoring script mới combine. Bốn tổ hợp (Critical+Calibrated, Critical+NC, …) đều hợp lệ. Việc cấm skill tính `Weighted_DC` giữ cho lỗi weighting không lẫn với lỗi scoring — audit từng tầng độc lập.

**Weight per behavior, không per TID**
Đây là contribution lớn nhất và cũng là điểm dễ sai nhất nếu không có skill. Cùng `T1047` là Critical khi là pivot PtH→WMI sang DC01, nhưng High khi chỉ là VSS create/delete trên host hiện tại. Decision tree first-match-wins làm khác biệt này deterministic thay vì cảm tính.

**Critical ceiling chống lạm phát có định lượng**
~35% là con số cụ thể, không phải lời khuyên mơ hồ. Nó biến "đừng gán quá nhiều Critical" thành một gate kiểm tra được, và chỉ thẳng nguyên nhân thường gặp (sub-cluster vs whole-chain terminal).

**ALT = coverage, không phải fallback**
Quy tắc "ALT và main step cùng ACW" ngăn lỗi hạ weight một nhánh chỉ vì có nhánh song song. Hai đường WMI/SCM cùng đạt một pivot đều Critical — đo đúng rằng cả hai đều là cách thực hiện cùng một bước lateral movement quyết định.

**Decision tree đọc từ chain role, không từ Category hay TID label**
Buộc model đối mặt với câu hỏi vai trò trước khi gán số, loại bỏ hai shortcut sai: tra bảng MITRE theo TID, và suy ACW từ Calibrated/NC.

### Điểm yếu

**Phụ thuộc nặng vào chất lượng summary.md**
Toàn bộ Q1/Q2 dựa vào việc summary mô tả đúng đâu là terminal và đâu là bottleneck. Nếu summary mơ hồ về objective hoặc thiếu topology (host nào pivot sang host nào), model phải suy đoán vai trò → weight yếu hoặc sai. Skill không có cơ chế validate summary.

**Phân biệt bottleneck vs value-to-attacker (Q2 vs Q3) có vùng xám**
"Tạo ra cơ hội mới mà chuỗi phụ thuộc vào" so với "trao capability đáng kể nhưng không phải pivot" đôi khi khó tách. Một credential dump vừa là terminal của cred-cluster vừa feed lateral movement — xếp Critical (Q1/Q2) hay High (Q3) phụ thuộc cách model đọc ranh giới cluster. Nhất quán kém giữa các session.

**Cross-cutting modifier dựa vào phán đoán "hard-to-detect"**
Tie-breaker này yêu cầu model tự đánh giá in-memory/no-artifact — vốn là lĩnh vực của `write-detection-criteria`. Nếu hai skill đánh giá độ khó phát hiện khác nhau, một row có thể được promote/không-promote không nhất quán. Modifier cũng dễ bị bỏ qua vì nó là bước "cân nhắc", không bắt buộc.

**Critical ceiling là warning, không phải enforcement**
~35% gợi ý re-review nhưng không chặn ghi output. Model có thể acknowledge "vượt 35%" rồi vẫn ghi. Với chuỗi thực sự dày bottleneck (nhiều pivot bắt buộc), ngưỡng 35% có thể bị vượt một cách chính đáng — không có quy tắc rõ phân biệt "vượt do lạm phát" với "vượt do chuỗi thực sự critical-heavy".

**Phụ thuộc vào việc CSV không bị collapse từ trước**
Nếu CSV đầu vào đã gộp behavior theo TID (do skill upstream làm sai), `assign-acw` không thể tách lại — nó chỉ weight được các row sẵn có. Tính đúng của per-behavior weighting kế thừa tính đúng của `write-phase`/`map-technique` ở thượng nguồn.

---

## Ví dụ từ iis-apppool-elevation-new.csv

Các ví dụ dưới đây lấy từ plan CSV thực tế (`testlab-enterprise/mitre-outline/iis-apppool-elevation-new.csv`, 112 behavior rows). Tally: Critical 15 · High 12 · Medium 50 · Low 35 → **Critical ratio 13,4%**, nằm an toàn dưới trần ~35%.

---

### Same TID, khác role: T1047 (WMI) — Critical vs High

| Step | Behavior | ACW | Vai trò |
|---|---|---|---|
| Step 2 (Lateral Movement) | `go-thehash.exe` gọi WMI COM spawn remote process trên **DC01** | **Critical** | Bottleneck — đây là pivot PtH→WMI sang DC, chuỗi phụ thuộc vào nó để chạm domain controller |
| Step 1 (DC Cred Material) | `PolicySyncSvc.exe` tạo/xoá VSS shadow copy qua WMI `Win32_ShadowCopy` | **High** | Advances objective (lấy ntds.dit từ shadow) nhưng không tạo pivot mới — value-to-attacker, không phải bottleneck |

**Bài học**: cùng `T1047`, weight tách hẳn nhau vì vai trò khác — Q2 (bottleneck) bắt row đầu, Q3 (high-value) bắt row sau. Gộp theo TID sẽ xoá mất khác biệt này.

---

### Same TID, khác role: T1570 (Lateral Tool Transfer) — Critical vs Medium

| Step | Behavior | ACW | Category | Vai trò |
|---|---|---|---|---|
| Step 2 | `go-thehash.exe put` chuyển dnscat2 payload + Herpaderping loader IIS01→**DC01** | **Critical** | Calibrated | Cấu thành pivot lateral movement quyết định sang DC01 |
| Step 3 | `go-thehash.exe put` ghi 4 persistence binary vào `C:\ProgramData\` trên DC01 | **Medium** | NC `transport` | Staging chuẩn bị, không tạo pivot |
| Step 1 | DC01 dnscat2 shell copy `PolicySyncSvc.exe` từ `\\IIS01\C$\...` sang `C:\ProgramData\` | **Medium** | NC `transport` | Di chuyển file phụ trợ, low leverage |

**Bài học**: minh hoạ đồng thời hai nguyên tắc — (1) cùng TID khác ACW theo role; (2) **ACW độc lập Category**: row Critical tình cờ Calibrated, hai row Medium tình cờ NC `transport`, nhưng ACW được quyết bởi chain role chứ không bởi nhãn calibration.

---

### ACW độc lập Category: T1105 (Ingress Tool Transfer) — cùng High, khác Category

| Step | Behavior | ACW | Category |
|---|---|---|---|
| Step 1 | `stage --encrypt` stream XOR+base64 dnscat2 PE vào `__stageBuffer` qua eval | **High** | NC `redundant@T1027.013` |
| Step 1 | `stage` stream base64 EfsPotato PE vào `__stageBuffer` qua eval, flush một lần | **High** | Calibrated |

**Bài học**: hai row cùng **High** (đều là staging feed một Critical next behavior) nhưng Category khác nhau — một bị demote vì redundancy, một Calibrated. Đây là bằng chứng trực tiếp: ACW không bị Category kéo lên/xuống. Nếu để Category lây nhiễm, row NC đã bị hạ ACW sai.

---

### Cluster Critical: terminal objectives và bottlenecks

Các row Critical trong plan rơi đúng vào hai lens mạnh nhất:

| Behavior | TID | Lens |
|---|---|---|
| Exploit CVE-2025-55182 gửi RSC flight data mở shell đầu tiên | T1190 | Bottleneck — initial access |
| EfsPotato khai thác `SeImpersonatePrivilege` → SYSTEM | T1134.001 | Bottleneck — privilege escalation |
| `go-thehash.exe` xác thực DC01 bằng raw NT hash (PtH) | T1550.002 | Bottleneck — lateral movement sang DC |
| ReflectDump fork LSASS, dump qua MiniDumpWriteDump | T1003.001 | Terminal của credential-access cluster |
| `PolicySyncSvc.exe` mở backup handle trên `ntds.dit` shadow | T1003.003 | Terminal — domain credential harvest |
| `CertMaint.exe` mã hoá database files (ransomware) | T1486 | Terminal của cả chuỗi |
| `CertMaint.exe` xoá toàn bộ VSS shadow copy chặn recovery | T1490 | Terminal — recovery inhibition |

Không row nào trong nhóm này là "sophisticated evasion" — chúng Critical vì *vai trò* (mở cơ hội mới hoặc là đích), đúng tinh thần Q1/Q2.

---

### Đáy thang: execution plumbing và evasion → Low

| Behavior | TID | ACW | Lý do |
|---|---|---|---|
| `node.exe` eval charcode-encoded JavaScript (eval path) | T1059.007 | **Low** | Execution plumbing — interpreter chạy code, không tự trao capability mới (Q5/Q6) |
| Encode mọi Node.js API call thành charcode array | T1027.010 | **Low** | Pure obfuscation — chỉ giảm detectability, capability không đổi |
| `stage` decode base64 từ in-memory buffer ghi ra disk | T1140 | **Low** | Decode phụ trợ, low leverage in isolation |

**Bài học**: dù charcode-encoding và in-memory eval về kỹ thuật khá tinh vi, chúng nhận **Low** vì xét theo *chain leverage* chúng không mở cơ hội mới nào — đúng anti-pattern mà skill cảnh báo: *"sophisticated evasion → Critical"* là sai.
