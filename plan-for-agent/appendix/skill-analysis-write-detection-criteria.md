# Phân tích thiết kế skill: `write-detection-criteria`

> Bài phân tích trong loạt tài liệu giải thích **lý do thiết kế** của từng skill trong `.claude/skills/`. Mục tiêu: làm rõ vị trí trong pipeline, chứng minh tính hợp lý của các lựa chọn, và nhìn nhận khách quan ưu/nhược điểm. Đây là tài liệu *mô tả lý do* — không phải bản sao SKILL.md (xem `.claude/skills/write-detection-criteria/SKILL.md`).

---

## 1. Skill này giải bài toán gì

Với **mỗi** dòng trong Reference Table, `write-detection-criteria` viết **tín hiệu quy trách nhiệm nhà cung cấp** (vendor accountability signal) — bằng chứng mà nếu *vắng* trong output của sản phẩm thì cấu thành một lỗ hổng phát hiện *quy được cho nhà cung cấp* trên bề mặt telemetry đã khai báo.

Cách làm là *xác định trục anomaly* (hành vi lệch baseline thế nào); *mục tiêu* là một tín hiệu mà lỗi không phát ra nó rõ ràng là lỗi của vendor, không phải artifact đo lường. Nếu không viết được tín hiệu cụ thể, *ghi nhận sự vắng mặt* dạng `N/A — <Cx>: <lý do>`.

Đây là **nền bằng chứng ổn định** mà bước gán nhãn (`assign-category`) sẽ *đọc*.

---

## 2. Vị trí trong pipeline

```
map-technique  →  [write-detection-criteria]  →  assign-category  →  assign-acw
                   (nền bằng chứng ổn định —      (verdict heuristic
                    PHỦ MỌI DÒNG)                  đọc bằng chứng này)
```

- **Đầu vào:** Phase file đã có cột mapping; chạy trên **mọi dòng**, không phải tập con đã gán nhãn.
- **Đầu ra:** cột `Detection Criteria` đầy đủ — mỗi ô là *tín hiệu cụ thể* hoặc *vắng mặt có ghi nhận* `N/A — <Cx>`. Không chạm cột nào khác.
- **Đọc:** `plan-for-agent/guides/detection-criteria.md`.

Skill này chạy **trước** `assign-category` — đây là quyết định thứ tự quan trọng nhất (xem 3.1).

---

## 3. Các lựa chọn thiết kế & lý do

### 3.1. Viết bằng chứng TRƯỚC, gán nhãn SAU
**Lựa chọn:** Detection Criteria được viết ở skill này, *trước* khi `assign-category` chạy. Category sau đó chỉ *đọc* nó.

**Lý do:** logic Category là *heuristic* và được kỳ vọng sẽ đổi; Detection Criteria là *artifact ổn định*. Viết bằng chứng trước thay thế phỏng đoán cũ "tưởng tượng xem có viết được criteria không" (một rủi ro ảo giác) bằng dữ liệu thật, và cho phép *suy lại nhãn* khi heuristic đổi mà **không phải viết lại criteria**. Đây là mặt đối xứng của cùng quyết định kiến trúc được phân tích trong bài `assign-category`.

### 3.2. Phủ MỌI dòng — không bỏ dòng nào
**Lựa chọn:** cột Detection Criteria điền cho *mọi* dòng, dù hành vi trông tầm thường hay "rõ ràng là Not-Calibrated".

**Lý do:** một dòng bị bỏ = không có nền bằng chứng → ép `assign-category` quay lại *tưởng tượng* criteria — đúng cái ảo giác mà thứ tự này dựng lên để loại bỏ. Đây là Hard Gate #1.

### 3.3. Quyết "tín hiệu vs N/A" CHỈ theo tính-viết-được, không theo nhãn dự kiến
**Lựa chọn:** nếu *viết được* tín hiệu cụ thể → viết, **kể cả khi** dự đoán dòng sẽ bị hạ nhãn vì redundancy/salience. `N/A` *chỉ* dành cho bốn ca *không viết được*: C1 (không có trục anomaly), C2 (chỉ đúng một lần chạy, không rút ra pattern ổn định để viết), C3 (in-process/ghost, evaluator không kiểm chứng được), C4 (artifact ngoài bề mặt khai báo).

**Lý do:** **`N/A` ≠ "dòng này sẽ Not-Calibrated".** Đây là lỗi phổ biến nhất. Một dòng có tín hiệu sạch nhưng sau bị `assign-category` hạ vì *mô liên kết* (tool transfer, spawn interpreter chung, recon native, reuse kênh) **vẫn giữ tín hiệu dương trung thực** ở đây; việc hạ nhãn được ghi ở cột Category, *không* bị ép ngược thành `N/A` giả. Tách hai thứ này là cốt lõi.

### 3.4. Không gán/sửa Category
**Lựa chọn:** chỉ sản xuất bằng chứng; nhãn được đọc *từ* nó ở hạ nguồn. Không loop ngược.

**Lý do:** trộn "viết criteria" và "gán nhãn" trong một pass tái sinh đúng cái phỏng đoán "tưởng tượng xem có viết được criteria không". Viết *chỉ* bằng chứng.

### 3.5. Tín hiệu trùng nhau phải viết trung thực, verbatim
**Lựa chọn:** nếu tín hiệu giống hệt dòng trên, *vẫn viết đầy đủ cả hai*, không "see above", không làm mờ.

**Lý do:** hai dòng mang criteria *y hệt* chính là cách `assign-category` phát hiện double-count. Làm mờ chúng là phá bộ dò trùng lặp.

---

## 3b. Trục thuộc tính & tiêu chí quyết định (đào sâu)

Skill này thực chất là một **cây quyết định trên vài trục thuộc tính độc lập**. Tách rõ chúng giúp thấy đâu là thao tác máy móc, đâu là phán đoán thật sự.

| Trục | Đo điều gì | Giá trị | Quyết bởi tiêu chí |
|---|---|---|---|
| **Writability** *(gate trung tâm)* | Có viết được tín hiệu cụ thể không | `signal` / `absence` | Anomaly test ∧ Surface test ∧ pattern ổn định ∧ verifiable |
| **Failing-condition** *(chỉ khi `absence`)* | Điều kiện nào *chặn* viết tín hiệu | `C1` / `C2` / `C3` / `C4-off-surface` | reverse diagnostic |
| **Anomaly tier** | Artifact hiếm tự thân, hay chỉ hiếm khi tổ hợp | `intrinsic` / `contextual` | "rare by itself?" → chọn format |
| **Value-vs-pattern** | Giá trị ngẫu nhiên có baseline ổn định không | `value` (giòn) / `pattern` (bền) | viết theo pattern, không theo value |
| **Surface** | Tín hiệu rơi vào kênh telemetry nào | declared surface (EDR default) | Layer 0 — *thẩm quyền nằm ở downstream* |

**Tiêu chí cốt lõi — chỉ `writability` quyết signal-vs-absence, tách khỏi nhãn dự kiến.** Đây là trục được "khoá cứng" nhất: dù biết trước dòng sẽ bị hạ nhãn vì redundancy/salience, nếu viết được tín hiệu thì vẫn viết. Mọi trục còn lại chỉ định *dạng* tín hiệu, không định *có hay không*.

**Hai test hợp thành gate `writability`** (cộng hai điều kiện ngầm):
1. *Anomaly test* — gọi tên được baseline mà hành vi lệch khỏi? Không → `N/A — C1`.
2. *Surface test* — anomaly đó rơi vào surface đã khai báo? Không → `N/A — C4`.
3. *(ngầm)* pattern ổn định — nếu chỉ đúng một lần chạy và không rút ra được pattern → `N/A — C2`.
4. *(ngầm)* verifiable không cần tin implant — in-process/ghost → `N/A — C3`.

**Phân tầng anomaly *chính là* hành vi chọn format**, không phải hai bước rời. `intrinsic` → single-signal `<process> <action> <artifact>`; `contextual` → behavioral-pattern (mỗi điều kiện con vẫn phải verifiable riêng — cái hiếm là *tổ hợp*, không phải từng mảnh).

---

## 4. Luồng nội bộ (tóm tắt)

1. Mặc định phủ **mọi dòng** trong file.
2. Với mỗi dòng, **xác định vendor accountability signal**: trên bề mặt đã khai báo, một sản phẩm hoạt động đúng sẽ phát ra gì khi hành vi này xảy ra?
3. Diễn đạt anomaly theo format khớp: **intrinsic** (artifact tự thân hiếm) → dạng single-signal; **contextual** (artifact thường, tổ hợp hiếm) → dạng behavioral-pattern; giá trị ngẫu nhiên → viết *mẫu ổn định*, không viết giá trị.
4. Quyết tín-hiệu-vs-vắng-mặt **chỉ theo tính-viết-được**: viết được thì viết (kể cả khi dự đoán bị hạ nhãn); không viết được thì `N/A — <Cx>: <lý do>`.
5. Chạy forward checklist + reverse diagnostic — nhưng *không* gán Category.

---

## 5. Đánh giá khách quan

### Ưu điểm
- **Loại ảo giác tận gốc** — buộc bằng chứng tồn tại trước khi gán nhãn, thay vì để model "tưởng tượng" có viết được criteria không.
- **Tách ổn định/biến động** — criteria ổn định, Category heuristic; cho phép re-label mà không đụng bằng chứng.
- **Phủ-mọi-dòng làm "đã xong" quan sát được** — không dòng nào bị bỏ thầm.
- **Tín hiệu trùng = bộ dò double-count** — viết trung thực biến trùng lặp thành dữ liệu chẩn đoán thay vì lỗi cần che.

### Nhược điểm / đánh đổi
- **Cảm giác "làm thừa"** — viết tín hiệu cho cả dòng biết trước sẽ bị hạ nhãn nghe phí công; thực ra là *cố ý* (giữ nền bằng chứng đầy đủ), nhưng dễ bị người vận hành cắt xén.
- **Ranh giới `N/A` cần kỷ luật cao** — chỉ bốn ca C1/C2/C3/C4 mới được `N/A`; trực giác hay lạm dụng `N/A` cho "dòng này không quan trọng", đúng cái Anti-Pattern cảnh báo.
- **Xác định anomaly vẫn chủ quan** — "tín hiệu một sản phẩm đúng sẽ phát ra" phụ thuộc giả định về năng lực bề mặt; ca biên có thể tranh luận.
- **Phụ thuộc bề mặt khai báo đúng** — nếu Layer 0 (bề mặt telemetry) bị hiểu sai ở `assign-category`, ranh giới "observable vs `N/A — C4`" ở đây cũng lệch theo.

### Phản biện sâu (điểm căng trong chính khung)
- **Số ca `N/A` đã đồng bộ về bốn (C1/C2/C3/C4) — trước đây là một bất nhất giữa SKILL.md và guide.** Guide `detection-criteria.md` (reverse diagnostic) luôn cho phép `N/A — C2` khi tín hiệu *chỉ đúng một lần chạy và không rút ra pattern nào* (blob entropy thuần, heap address không ngữ cảnh), nhưng SKILL.md từng chốt "three unwritable cases" và bỏ C2, khiến §1/§3.3 bám theo cũng thiếu. Lý do C2 là ca `absence` hợp lệ riêng: ép nó về C1 ("không có anomaly axis") là sai bản chất — anomaly *có*, chỉ không có pattern ổn định để viết. Nay SKILL.md (cả bản `.windsurf`) đã liệt kê đủ bốn ca, khớp guide và §3b. *Bài học còn lại:* vocabulary "số ca" sống ở hai nguồn nên dễ lệch khi sửa một chỗ — đây là rủi ro drift, không còn là mâu thuẫn đang mở.
- **Baseline mang tính môi trường, nhưng test từng coi nó như khách quan.** `w3wp.exe spawns cmd.exe` là anomaly trong web-tier sạch; trên host có script vận hành hay chạy shell thì baseline khác hẳn. Anomaly test giả định người viết biết baseline "đúng", nhưng baseline phụ thuộc lab cụ thể. → *Đã giảm thiểu:* guide nay buộc **neo baseline môi trường vào host role/build** khai trong `summary.md`/setup docs (mục "Anchor an environment-relative baseline"); SKILL.md có note tương ứng — "nếu không neo được thì deviation chưa được thiết lập, đặt tên baseline trước khi viết". *Residual:* vẫn dựa vào `summary.md` được viết đúng và người viết chịu đọc nó, không có cơ chế cưỡng chế tự động.
- **Ranh giới `intrinsic`/`contextual` chính là chỗ khó nhất, nhưng được trình bày như đọc-ra-được.** "unsigned DLL từ user path" là hiếm tự thân (intrinsic) hay chỉ hiếm khi kèm netconn (contextual)? Chọn sai tier → sai format: viết single-signal cho cái thực ra cần tổ hợp sẽ sinh giả dương; viết behavioral-pattern cho cái vốn đủ alert một mình thì làm loãng tín hiệu. Phân tier là phán đoán, không phải tra bảng — nhưng cây quyết định đặt nó như bước cơ học.
- **Thẩm quyền "surface" nằm ở downstream nhưng quyết định surface-test lại ở upstream.** Cùng phép kiểm "trên surface không?" chạy **hai lần** — writability-test (→ `N/A — C4`) ở skill này, và Q-A scope ở `assign-category`. Nếu hai bên giả định surface lệch nhau thì mâu thuẫn mà không có cơ chế hoà giải. → *Đã giảm thiểu:* cả hai skill nay trỏ về **một Surface Profile chung** (bảng Layer 0 trong `category-assignment.md`); Surface test (upstream) và Question A (downstream) đọc cùng một profile được *pin*, guide nêu rõ "must consult the *same* profile". *Residual:* vẫn là quy ước "đọc cùng bảng" — chưa có kiểm tra tự động bắt hai bên thực sự dùng cùng giá trị; vẫn dựa Layer 3 + quyền gửi-ngược-dòng làm chốt cuối.
- **"Vendor accountability" giả định một capability envelope từng không nói rõ.** "sản phẩm hoạt động đúng sẽ phát ra gì" phụ thuộc default EDR rất hào phóng (memory scan + ETW injection + YARA); đổi default → tập "viết được tín hiệu" co/giãn theo. → *Đã giảm thiểu:* envelope giờ là **Surface Profile tường minh** (bảng Layer 0 liệt kê đủ kênh), upstream được trỏ thẳng tới nó qua Surface test; phía Layer 0 gắn cờ "lựa chọn này set denominator" + buộc echo profile (không chạy trên default im lặng). *Residual:* envelope vẫn là một bảng người vận hành phải *chọn đúng*, không suy ra được tự động từ sản phẩm thật đang đánh giá.

### Khi nào dễ sai nhất
- "Dòng này kiểu gì cũng Not-Calibrated, ghi `N/A`" (lạm dụng `N/A`).
- Bỏ qua dòng "chỉ là setup".
- Làm mờ/"see above" tín hiệu trùng (phá bộ dò double-count).
- Tiện tay gán Category trong cùng pass.
- Khẳng định một observable *ngoài* bề mặt như điểm chấm, thay vì `N/A — C4`.

---

## 6. Liên hệ
- Quy tắc thực thi: `.claude/skills/write-detection-criteria/SKILL.md`
- Phương pháp nền: `plan-for-agent/guides/detection-criteria.md`
- Skill liền kề: `map-technique` (upstream — điền mapping), `assign-category` (downstream — đọc bằng chứng này để gán nhãn). Xem thêm bài phân tích `assign-category` cho mặt đối xứng của quyết định "criteria trước, category sau".
