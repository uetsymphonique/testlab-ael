# Future Plan — Backlog chưa áp dụng vào Retest hiện tại

Tài liệu này gom lại các hạng mục đã phân tích trong quá trình rà soát `Micro_Emulation_Plan.md` đối chiếu với `../EDR_Detection_Specification.md` và bộ rule mẫu `../Sample yara rules/`, nhưng **chưa đưa vào plan chính** vì phạm vi lần retest hiện tại đã chốt (không mở rộng thêm hành vi/technique mới). Giữ lại đây để cân nhắc khi có lần retest mở rộng sau.

Không có mục nào trong file này được coi là đã duyệt để chạy — mọi thứ ở đây là đề xuất/ghi nhận, cần xác nhận lại trước khi đưa vào `Micro_Emulation_Plan.md`.

---

## 1. Mở rộng bao phủ hành vi (coverage) — khả thi trong lab hiện tại, không cần vector khởi đầu mới

### 1.1 Sửa lỗi thiết kế khiến `SSH_Config_Or_KeyDir_Created_By_App_User` không thể fire
- **Hiện trạng:** `Setup.md` §2.3 pre-create `~/.ssh` (mode 700) và `authorized_keys` rỗng ngay khi dựng lab, trước khi attacker chạm vào Step 4. Vì thư mục đã tồn tại từ trước, hành vi "app user tự tạo `.ssh` lần đầu" mà rule này tìm không bao giờ xảy ra trong lần chạy thật.
- **Đề xuất:** chuyển `mkdir -p -m 700 ~/.ssh` sang thực hiện **trong Step 4** (do attacker chạy), Setup.md chỉ đảm bảo `sshd` cài đặt và cấu hình sẵn sàng, không tạo sẵn thư mục `.ssh`.
- **Cần xác nhận trước khi áp dụng:** `sshd`/`PubkeyAuthentication` không yêu cầu `.ssh` phải tồn tại từ lúc service khởi động.

### 1.2 E6 — Privilege/credential access (Discovery bổ sung)
- Spec (`EDR_Detection_Specification.md` §3, nhóm E6) ghi nhận đây là gap đã biết ở báo cáo gốc, nằm ngoài phạm vi G1–G7 hiện tại.
- **Đề xuất:** thêm 1-2 lệnh discovery vô hại vào cuối Step 1 hoặc Step 5 (đã có shell sẵn, không cần vector mới): `sudo -l 2>/dev/null`, thử đọc `~/.ssh/id_rsa 2>/dev/null`, `cat /etc/shadow 2>/dev/null`.

### 1.3 `LD_Preload_Env_Set` (E5 "Bonus hardening")
- Set `LD_PRELOAD` cho tiến trình tự chạy không cần root (`export LD_PRELOAD=/tmp/x.so` trước khi chạy một lệnh).
- Có thể thêm như biến thể defense-evasion/persistence bổ sung ở Step 2/3, không có trong scope G1–G7 hiện tại.

### 1.4 `Cron_Or_Systemd_Persistence` (E5 "Bonus hardening") — phần cron
- `crontab -e` cho chính user `svcapp` (crontab cá nhân, không phải `/etc/crontab`) không cần root — có thể thêm song song với SSH key ở Step 4 làm cơ chế persistence thứ hai.
- Phần systemd **user unit** (`~/.config/systemd/user/`) chỉ khả thi nếu lab đã bật `loginctl enable-linger svcapp` — cần xác nhận Setup.md trước khi coi là khả thi.

### 1.5 G7 — thiếu bằng chứng socket trực tiếp cho outbound connect khi pivot
- Step 1/2 đã có xác nhận `ss` trực tiếp trên host cho listening socket; Step 5 (pivot sang `target-host`) vẫn chỉ xác nhận gián tiếp qua `id` chạy thành công.
- **Đề xuất:** thêm `ss -tnp | grep :22` (hoặc tương đương) ngay sau lệnh `ssh` pivot, cho đối xứng về format với Step 1/2.

### 1.6 Không khả thi trong giới hạn "không root" hiện tại (ghi nhận, không triển khai)
- `LdSoPreload_File_Modified` — cần ghi `/etc/ld.so.preload`, đòi hỏi root.
- Sửa `crontab` hệ thống (`/etc/cron.*`), `sshd_config`, systemd unit tại `/etc/systemd/system/` — cùng lý do, mâu thuẫn với nguyên tắc "không sudo/wheel cho `svcapp`".

---

## 2. Lỗi trong bộ rule mẫu tham khảo (`Sample yara rules/`)

Không phải lỗi của `Micro_Emulation_Plan.md`, nhưng ảnh hưởng trực tiếp đến việc tự-đánh-giá xem bộ rule minh hoạ có "bắt" được kịch bản hay không.

### 2.1 List `app_users` trong `vsa_redteam.yaml` thiếu `svcapp`
- Hiện chỉ có `[vsa, aom, oss, tomcat, java, nginx, www-data, apache, mysql, postgres]` — sót lại từ môi trường gốc, chưa từng được cập nhật để có `svcapp` (username thật của toàn bộ lab).
- Hậu quả: 7 rule sau không bao giờ fire được với đúng lab hiện tại vì gate theo `spawned_by_app_user`/`user.name in (app_users)`:
  `ELF_Dropped_In_Sensitive_Dir_By_App_User`, `Execute_From_Ephemeral_Dir_By_App_User`, `Unexpected_TCP_Listener_By_App_User`, `Python_Acts_As_Port_Forwarder`, `SSH_Config_Or_KeyDir_Created_By_App_User`, `SSH_Client_From_App_Daemon`, `Outbound_Connect_From_App_User_To_Non_Standard_Port`.
- **Đề xuất:** thêm `svcapp` vào list. Chưa áp dụng — chờ quyết định vì đây là file rule tham khảo, chỉnh sửa nó nằm ngoài phạm vi đã chốt của lần retest này.

### 2.2 `SSH_Client_From_App_Daemon` không thực sự kiểm tra process ancestry
- Dù tên rule ngụ ý kiểm tra process-tree, điều kiện thực tế chỉ check `proc.name in (ssh, autossh, scp, sftp)` + `user.name in (app_users)` — không có `parent_is_app_daemon` hay tương đương.
- Việc `Micro_Emulation_Plan.md` giữ đúng ancestry ở Step 4/5 (pivot từ session Meterpreter, không phải session SSH mới) vẫn đúng về mặt tái tạo hành vi gốc và vẫn có giá trị test với các sản phẩm thật có check ancestry, nhưng với đúng rule mẫu này, ancestry không tạo khác biệt về kết quả match.

### 2.3 Rule `Bash_History_File_Tampered` không theo dõi `symlink()`
- Bước `ln -sf /dev/null ~/.bash_history` ở Step 3 không được rule này bắt (macro `write_open` chỉ theo dõi `open/creat/rename/unlink/truncate`, không có `symlink`/`symlinkat`).
- Không nghiêm trọng vì bước `shred` ngay trước đã bắt được, nhưng bản thân kỹ thuật symlink có 0% coverage trong bộ rule mẫu.

### 2.4 YARA Y4/Y5/Y6 có bề mặt kích hoạt thấp/bằng 0 với cách viết kịch bản hiện tại
- **Y4** (`Python_PortForwarder_Script`): `resources/pf.py` không chứa `forward`/`tunnel`/`portfwd`/`paramiko` — không khớp kể cả khi không đổi tên biến/hàm.
- **Y5** (`Linux_Log_Wiper_Indicators`), **Y6** (`SSH_AuthorizedKeys_Persistence_Script`): là static file-content scanner, nhưng Step 3/4 gõ lệnh trực tiếp vào shell tương tác, không lưu thành file script nào để quét — gần như không có cơ hội fire.
- **Y2** (`Msfvenom_Generated_Payload_Strings`): chuỗi `metsrv`/`stdapi_` thường chỉ có trong memory sau khi stage 2 của Meterpreter load (sau khi `multi/handler` connect), chưa chắc có trong file stager nhỏ ghi lên `/tmp` ở Step 1.
- Chuỗi trigger tự động Y1/Y2/Y3/Y8 (theo header `vsa_redteam.yar`: "kích hoạt khi Falco fire `ELF_Dropped_In_Sensitive_Dir_By_App_User`") bị đứt vì rule Falco đó đã hỏng theo mục 2.1.

---

## 3. Ý tưởng bypass rule chưa áp dụng (ngoài phạm vi đã chốt)

### 3.1 Bypass `SSH_Authorized_Keys_Modified` qua process masquerading (T1036)
- Whitelist `allowed_authkey_writers` (`sshd, useradd, usermod, cloud-init, ...`) là whitelist theo tên tiến trình cụ thể, không loại trừ theo nhóm `shell_binaries` như các rule khác (khác với `Bash_History_File_Tampered`).
- Muốn né thật cần giả danh tên tiến trình (`prctl(PR_SET_NAME, ...)` hoặc `argv[0]` spoofing) — thuộc kỹ thuật Masquerading (T1036), hiện ngoài phạm vi 5 step đã chốt, cần một behavior/step riêng nếu muốn đưa vào lần retest mở rộng.

### 3.2 `ld-linux.so.2` để chạy ELF không cần bit `+x` (chưa kiểm chứng)
- Ý tưởng né `Chmod_Exec_On_Newly_Written_File` bằng cách gọi thẳng dynamic loader (`/lib64/ld-linux-x86-64.so.2 /tmp/backupv2`) thay vì `chmod +x` rồi exec trực tiếp.
- Chưa áp dụng vì payload `msfvenom -f elf` (dạng shellcode-wrapper) thường là ET_EXEC tĩnh, chưa chắc tương thích với cách gọi qua dynamic loader — cần test thực tế trước khi đưa vào plan chính. Cách B hiện tại (`os.chmod` qua Python) đã đủ để làm biến thể đối chứng cho rule này.

---

## Gợi ý thứ tự ưu tiên nếu mở rộng ở lần sau

1. **1.1** — lỗi thiết kế thật trong `Setup.md` (không phải chỉ là "thiếu coverage"), nên sửa sớm nhất bất kể có mở rộng scope hay không.
2. **2.1** — ảnh hưởng đến toàn bộ khả năng tự-đánh-giá xem bộ rule mẫu có coverage cho kịch bản hay không; nên sửa trước khi dùng bộ rule này để tự kiểm tra bất kỳ thay đổi nào khác.
3. Các mục còn lại (1.2–1.5, 2.2–2.4, 3.1–3.2) — tuỳ ngân sách thời gian và phạm vi retest lần sau.
