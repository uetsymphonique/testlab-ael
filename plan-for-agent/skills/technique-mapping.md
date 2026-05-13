# Skill: Technique Mapping

Mô tả cách xác định tactic và technique ATT&CK tương ứng với một hành vi adversary cụ thể, phục vụ việc điền Reference Table trong emulation plan.

> **Phạm vi của skill này:** Xác định đúng Tactic, Technique ID, Technique Name, và Platform cho một hành vi. Skill này **không** xử lý cột `Detection Criteria` và cột `Category` — đó là hai skill riêng biệt:
> - Viết Detection Criteria → xem `category-assignment.md`
> - Gán nhãn Calibrated/Not Calibrated → xem `category-assignment.md`

---

## Bước 1 — Xác định tactic từ hành vi

Đọc mô tả hành vi và đối chiếu với định nghĩa tactic trong `d:\vcs\ael\mitre-knowledge-base\tactics.md` để xác định adversary đang cố làm gì:

| Tactic ID | Tactic Name | Câu hỏi định hướng |
|---|---|---|
| TA0001 | Initial Access | Adversary đang cố xâm nhập vào mạng lần đầu không? |
| TA0002 | Execution | Adversary đang chạy code/lệnh trên hệ thống không? |
| TA0003 | Persistence | Adversary đang cố duy trì quyền truy cập qua reboot/reset không? |
| TA0004 | Privilege Escalation | Adversary đang cố leo thang lên quyền cao hơn không? |
| TA0005 | Defense Evasion | Adversary đang cố tránh bị phát hiện không? |
| TA0006 | Credential Access | Adversary đang cố lấy thông tin xác thực không? |
| TA0007 | Discovery | Adversary đang thu thập thông tin về môi trường không? |
| TA0008 | Lateral Movement | Adversary đang cố di chuyển sang hệ thống khác không? |
| TA0009 | Collection | Adversary đang thu thập dữ liệu mục tiêu không? |
| TA0010 | Exfiltration | Adversary đang cố đưa dữ liệu ra ngoài mạng không? |
| TA0011 | Command and Control | Adversary đang giao tiếp với hệ thống bị kiểm soát không? |
| TA0040 | Impact | Adversary đang cố phá hoại, làm gián đoạn, hoặc mã hóa dữ liệu không? |
| TA0042 | Resource Development | Adversary đang xây dựng hạ tầng/tài nguyên hỗ trợ không? |
| TA0043 | Reconnaissance | Adversary đang thu thập thông tin để lên kế hoạch tấn công không? |

> Một hành vi có thể phục vụ nhiều tactic đồng thời — ví dụ DLL Side-Loading vừa là Execution vừa là Defense Evasion. Trong trường hợp này, tách thành nhiều row trong Reference Table, mỗi row một tactic.

---

## Bước 2 — Tra technique file theo tactic

Mỗi tactic có một file định nghĩa technique tương ứng trong `d:\vcs\ael\mitre-knowledge-base\techniques\`:

| Tactic | Path |
|---|---|
| Initial Access | `d:\vcs\ael\mitre-knowledge-base\techniques\TA0001-initial-access.md` |
| Execution | `d:\vcs\ael\mitre-knowledge-base\techniques\TA0002-execution.md` |
| Persistence | `d:\vcs\ael\mitre-knowledge-base\techniques\TA0003-persistence.md` |
| Privilege Escalation | `d:\vcs\ael\mitre-knowledge-base\techniques\TA0004-privilege-escalation.md` |
| Defense Evasion | `d:\vcs\ael\mitre-knowledge-base\techniques\TA0005-defense-evasion.md` |
| Credential Access | `d:\vcs\ael\mitre-knowledge-base\techniques\TA0006-credential-access.md` |
| Discovery | `d:\vcs\ael\mitre-knowledge-base\techniques\TA0007-discovery.md` |
| Lateral Movement | `d:\vcs\ael\mitre-knowledge-base\techniques\TA0008-lateral-movement.md` |
| Collection | `d:\vcs\ael\mitre-knowledge-base\techniques\TA0009-collection.md` |
| Exfiltration | `d:\vcs\ael\mitre-knowledge-base\techniques\TA0010-exfiltration.md` |
| Command and Control | `d:\vcs\ael\mitre-knowledge-base\techniques\TA0011-command-and-control.md` |
| Impact | `d:\vcs\ael\mitre-knowledge-base\techniques\TA0040-impact.md` |
| Reconnaissance | `d:\vcs\ael\mitre-knowledge-base\techniques\TA0043-reconnaissance.md` |

Mở file tương ứng và tìm technique phù hợp với hành vi đang xét.

---

## Bước 3 — Xác định technique và sub-technique

Trong file technique, đọc phần mô tả để xác định:

1. **Technique parent** (T1XXX) — xem có match không
2. **Sub-technique** (T1XXX.YYY) — nếu có sub-techniques, kiểm tra xem hành vi cụ thể rơi vào sub-technique nào. **Ưu tiên gán sub-technique nếu có** — tránh gán chỉ ở level parent khi hành vi rõ ràng là một sub-technique cụ thể

Kết quả cần có:
- **Technique ID**: đầy đủ bao gồm sub-technique nếu có (ví dụ: `T1059.001`, không chỉ `T1059`)
- **Technique Name**: tên đầy đủ bao gồm sub-technique (ví dụ: `Command and Scripting Interpreter: PowerShell`)

---

## Bước 4 — Đối chiếu với technique scope

Sau khi xác định technique ID, đối chiếu với scope đánh giá:

- `d:\vcs\ael\testlab-enterprise\mitre-outline\Scenario 1.md` — Crimeware-as-a-Service (Windows EDR)
- `d:\vcs\ael\testlab-enterprise\mitre-outline\Scenario 2.md` — PRC Espionage (cross-platform, XDR)

Ghi nhận:
- Technique có trong scope → đưa vào Reference Table bình thường
- Technique không trong scope → ghi chú, chỉ đưa vào nếu được yêu cầu rõ ràng

---

## Xác nhận technique đã biết có map được với hành vi không

Dùng khi: đã có một technique ID trong đầu (từ gợi ý, từ source, hoặc từ kinh nghiệm) và cần xác nhận nó có thực sự mô tả đúng hành vi đang xét không. Đây là bước kiểm tra, không phải bước tìm kiếm.

### Quy trình xác nhận

1. **Mở file technique** của tactic tương ứng theo bảng ở Bước 2
2. **Tìm đến technique ID** cần kiểm tra trong file
3. **Đọc phần mô tả chính** của technique — so sánh với hành vi đang xét:
   - Cơ chế thực hiện có khớp không? (ví dụ: T1574.002 mô tả DLL được load bởi legitimate binary — nếu hành vi là `gup.exe` load `libcurl.dll` thì khớp)
   - Platform có khớp không? (Windows / Linux / IaaS...)
4. **Nếu technique có sub-techniques**, đọc từng sub-technique để xác định hành vi rơi vào sub nào — tránh dừng ở parent nếu sub phù hợp hơn
5. **Kết luận**:
   - Định nghĩa khớp → xác nhận dùng technique ID đó
   - Định nghĩa không khớp → tìm technique khác, lặp lại từ Bước 1/2/3

### Những gì cần đọc trong file technique

Mỗi technique trong `mitre-knowledge-base/techniques/` thường có:
- **Mô tả tổng quát** — adversary dùng technique này để làm gì
- **Ví dụ thực tế** — công cụ, binary, hoặc cách thực hiện điển hình
- **Sub-techniques** (nếu có) — mô tả biến thể cụ thể

Khi đọc để xác nhận, tập trung vào **cơ chế** (mechanism), không chỉ tên. Ví dụ:
- `T1218` System Binary Proxy Execution — parent; cần xác định sub: `.010` Regsvr32, `.007` Msiexec, `.013` Mavinject...
- `T1059` Command and Scripting Interpreter — parent; cần xác định sub theo interpreter: `.001` PowerShell, `.003` cmd, `.007` JavaScript...

---

## Lưu ý thường gặp

- **Tactic Execution vs Lateral Movement**: khi adversary chạy lệnh từ xa trên host khác (WMI, PsExec, WinRM) thì kết hợp cả hai tactic — Lateral Movement là vector di chuyển, Execution là hành vi chạy code. Tách thành hai row.
- **Privilege Escalation và Persistence overlap**: nhiều technique trong TA0004 cũng xuất hiện ở TA0003 — kiểm tra xem hành vi chủ yếu là leo thang hay duy trì, hoặc liệt kê cả hai nếu đều đúng.
- **Defense Evasion cross-list**: nhiều technique từ tactic khác được cross-list vào TA0005 khi có tác dụng evasion. Nếu hành vi có component evasion rõ ràng, thêm row TA0005 kèm technique cross-listed.
- **Không gán technique ngoài scope**: nếu hành vi không khớp với bất kỳ technique nào trong scope, báo lại thay vì tự ý chọn technique gần nhất.
