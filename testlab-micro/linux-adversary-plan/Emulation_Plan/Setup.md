# Setup — Lab tự dựng (generic) cho Retest EDR

**Lý do cần lab tự dựng:** hiện không có thông tin hay kết nối vào hệ thống mục tiêu thật. Để phát triển và kiểm chứng kịch bản retest, cần một lab generic tái tạo đúng **điều kiện hành vi** (service account non-root, app daemon, thư mục nhạy cảm, SSH, host thứ hai cho lateral movement) mà không phụ thuộc hạ tầng thật. Khi có quyền truy cập hệ thống thật, chạy lại đúng kịch bản trên đó để đối chiếu.

---

## 1. Topology

| Vai trò | Tên lab | Ghi chú |
|---|---|---|
| Attacker | `attacker` (10.10.10.5) | Kali hoặc Linux bất kỳ có `msfvenom`, `metasploit-framework`, `python3` |
| App host | `app-host` (10.10.10.10) | Nơi cài **sản phẩm EDR cần test** — subject-under-test |
| Target host | `target-host` (10.10.10.20) | Đích của bước lateral movement (S5) |

Mạng nội bộ giữa 3 host, attacker reach được app-host; app-host reach được target-host qua SSH.

> Nếu sản phẩm EDR cần test dùng driver eBPF/kernel module, dùng **VM đầy đủ** (không dùng container thiếu quyền kernel) để đảm bảo capability tương đương môi trường thật.

---

## 2. Provisioning `app-host`

0. Cài hệ điều hành theo support matrix của sản phẩm EDR cần test (chú ý kernel version nếu EDR dùng eBPF). Ví dụ dưới đây dùng Ubuntu/Debian (`apt`); nếu dùng RHEL/CentOS thay `apt` bằng `dnf`/`yum` và tên gói tương ứng.

### 2.1 Tạo service account `svcapp`

```bash
# -r: system account, -m: tạo home dir, -s: shell login được (cần cho S1 spawn shell)
useradd -r -m -d /home/svcapp -s /bin/bash svcapp
passwd svcapp          # đặt password nếu cần login trực tiếp để debug lab (không bắt buộc)
id svcapp               # xác nhận UID/GID, home dir
ls -ld /home/svcapp     # mặc định 700, chủ sở hữu svcapp:svcapp — giữ nguyên
```

> Không thêm `svcapp` vào nhóm `sudo`/`wheel` — mục tiêu là mô phỏng đúng quyền hạn chế của user ứng dụng, không phải admin.

### 2.1bis Cấp quyền ghi log cho `svcapp` (phục vụ Step 3 / G5)

**Lý do:** mặc định Debian/Ubuntu, các file log liên quan tới G5 (xóa dấu vết) có 3 mức quyền khác nhau đối với một user thường như `svcapp`:

| File | Owner:Group mặc định | Mode | `svcapp` ghi được nếu chỉ thêm vào group? |
|---|---|---|---|
| `/var/log/wtmp`, `/var/run/utmp` | `root:utmp` | `rw-rw-r--` | **Có** — group `utmp` có quyền ghi |
| `/var/log/btmp` | `root:utmp` | `rw-r-----` | **Không** — group chỉ có quyền đọc, chỉ owner (root) ghi được |
| `/var/log/auth.log` | `syslog:adm` | `rw-r-----` | **Không** — group `adm` chỉ có quyền đọc, chỉ owner (syslog/root) ghi được |
| `/var/log/lastlog` | `root:root` | `rw-r--r--` | **Không** — chỉ owner (root) ghi được |

`lastlog` được thêm vào danh sách để khớp đúng procedure CTI tham chiếu (Salt Typhoon: "cleared logs including .bash_history, auth.log, lastlog, wtmp, and btmp") — xem thêm `mitre-knowledge-base/techniques/TA0005-defense-evasion.md` §T1070.002.

Nếu không xử lý, 3/4 lệnh truncate ở Step 3 sẽ báo `Permission denied` dưới `svcapp` — không phản ánh đúng "Redteam khai thác thành công" ở tài liệu gốc. Xử lý bằng **group membership + ACL trực tiếp trên các file còn lại**, không dùng `sudo`/`wheel` (giữ đúng nguyên tắc ở §2.1 — đây là quyền ghi file cụ thể, không phải quyền thực thi lệnh tuỳ ý với quyền root):

```bash
# wtmp/utmp: group utmp đã có quyền ghi theo mặc định — chỉ cần thêm svcapp vào group
usermod -aG utmp svcapp

# btmp/auth.log/lastlog: group chỉ đọc (hoặc không có group riêng) theo mặc định — cấp ACL ghi trực tiếp cho riêng svcapp
apt install -y acl
setfacl -m u:svcapp:rw /var/log/btmp /var/log/auth.log /var/log/lastlog

# Xác nhận
id -nG svcapp                                            # kỳ vọng thấy "utmp" trong danh sách group
getfacl /var/log/btmp /var/log/auth.log /var/log/lastlog # kỳ vọng thấy "user:svcapp:rw-"
```

> Trên RHEL/CentOS, log tương ứng là `/var/log/secure` (thường `root:root`, mode `600` — chặt hơn hẳn), thay `apt install acl` bằng `dnf install acl` và đổi đường dẫn khi setfacl.

> **Lưu ý vận hành:** `logrotate` có thể reset ACL/ownership của file log khi xoay vòng (tạo file mới). Nếu lab chạy qua nhiều ngày, kiểm tra lại `getfacl` trước khi chạy Step 3; nếu ACL bị mất, chạy lại lệnh `setfacl` ở trên.

### 2.2 Cài app daemon giả lập chạy dưới `svcapp`

Mục tiêu: có một tiến trình app daemon thật sự chạy liên tục dưới `svcapp`, để khi attacker spawn shell từ đó, process-tree có dạng `app daemon → bash/python` — đúng điều kiện các rule "app user spawns shell" cần quan sát.

```bash
apt update && apt install -y python3 python3-venv python3-pip

# Tạo app dummy dưới home svcapp
mkdir -p /home/svcapp/app
cat > /home/svcapp/app/app.py <<'EOF'
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route("/")
def index():
    return "ok"

# ⚠️ LAB-ONLY: mô phỏng một RCE có kiểm soát trong app thật để tạo foothold
# ban đầu cho retest (vector RCE thật của kịch bản gốc không nằm trong phạm
# vi file EDR-only nên không tái tạo được nguyên bản — endpoint này CHỈ dùng
# để đưa attacker vào đúng vị trí "đã có execution dưới quyền app daemon"
# trước khi bắt đầu S1). Không dùng ngoài mạng lab cô lập.
@app.route("/debug/exec")
def debug_exec():
    cmd = request.args.get("cmd", "")
    result = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
    return result.stdout + result.stderr
EOF
chown -R svcapp:svcapp /home/svcapp/app

# Venv + gunicorn, chạy bằng chính user svcapp (không dùng sudo -u root)
su - svcapp -c "python3 -m venv /home/svcapp/app/venv"
su - svcapp -c "/home/svcapp/app/venv/bin/pip install flask gunicorn"
```

Tạo systemd unit chạy daemon dưới quyền `svcapp` (không phải root), bind ra ngoài để attacker gọi được:

```ini
# /etc/systemd/system/dummyapp.service
[Unit]
Description=Dummy app daemon (svcapp)
After=network.target

[Service]
User=svcapp
Group=svcapp
WorkingDirectory=/home/svcapp/app
ExecStart=/home/svcapp/app/venv/bin/gunicorn -w 2 -b 0.0.0.0:8888 app:app
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now dummyapp
systemctl status dummyapp          # kiểm tra Active: running
ps -ef --forest | grep -A2 gunicorn   # xác nhận master/worker process đều chạy dưới UID svcapp, không phải root

# Xác nhận endpoint gọi được từ attacker và lệnh chạy đúng dưới svcapp
curl "http://<IP app-host>:8888/debug/exec?cmd=id"   # kỳ vọng: uid=.../svcapp
```

Đây chính là "app daemon" đóng vai trò foothold ban đầu ở S1: mọi lệnh gọi qua `/debug/exec` chạy như tiến trình con của gunicorn worker (UID `svcapp`), nên toàn bộ chuỗi hành vi phía sau (ghi file, chmod, chạy payload, và cả session bind shell mở ra từ đó) đều thừa kế đúng process-tree `app daemon → bash → …` — không phải giả định suông qua SSH/su thủ công.

> **Cảnh báo:** `/debug/exec` là RCE có chủ đích, chỉ chấp nhận được trong mạng lab cô lập, không public ra ngoài, và phải gỡ bỏ/host lại khi không dùng cho retest.

### 2.3 Chuẩn bị SSH cho `svcapp`

```bash
apt install -y openssh-server
systemctl enable --now ssh

su - svcapp -c "mkdir -p -m 700 ~/.ssh"
su - svcapp -c "touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

Để `svcapp` login được qua SSH trong lab (phục vụ việc attacker "quay lại" sau khi thêm key ở S4), đảm bảo `sshd_config` không chặn:

```bash
grep -E "^(PasswordAuthentication|PubkeyAuthentication|AllowUsers)" /etc/ssh/sshd_config
# PubkeyAuthentication yes (mặc định) là đủ cho retest S4
```

> Không tự thêm sẵn public key nào vào `authorized_keys` lúc setup — file này cần **trống** trước khi chạy S4, vì hành vi ghi vào file này chính là hành vi cần EDR phát hiện.

### 2.4 Thư mục nhạy cảm cho S1/S2

Không cần cấu hình thêm — `/tmp`, `/dev/shm`, `/home/svcapp` là default trên mọi bản Linux và `svcapp` có quyền ghi vào các thư mục này theo mặc định hệ thống (world-writable + sticky bit cho `/tmp`, `/dev/shm`).

```bash
ls -ld /tmp /dev/shm /home/svcapp
```

### 2.5 Cài sản phẩm EDR cần test

**Cài sản phẩm EDR cần test lên `app-host`** theo hướng dẫn triển khai riêng của sản phẩm đó (bắt buộc — đây là mục tiêu retest, không thuộc phạm vi generic của tài liệu này).

### 2.6 Baseline trước khi test

```bash
ps -ef --forest > /root/baseline_ps.txt
ss -tulnp > /root/baseline_ports.txt
wc -l /var/log/*.log 2>/dev/null > /root/baseline_logsize.txt

# wtmp/utmp/btmp/lastlog là binary, không dùng wc -l trực tiếp — dùng số dòng qua `last`/`lastb`/`lastlog`
# và kích thước byte, phục vụ đối chiếu trước/sau Step 3 (G5)
last -f /var/log/wtmp | wc -l > /root/baseline_wtmp_entries.txt
lastb -f /var/log/btmp 2>/dev/null | wc -l > /root/baseline_btmp_entries.txt
lastlog | wc -l > /root/baseline_lastlog_entries.txt
stat -c '%n %s' /var/log/wtmp /var/run/utmp /var/log/btmp /var/log/auth.log /var/log/lastlog > /root/baseline_logfiles_size.txt
```

Lưu lại các file trên để đối chiếu khi phân tích alert sau khi chạy retest.

---

## 3. Provisioning `target-host`

1. Cài hệ điều hành tương tự `app-host`.
2. Bật SSH server.
3. Tạo 1 account dùng riêng cho test lateral movement, ví dụ `opsuser`.
4. (Tuỳ chọn, khuyến nghị) Cài EDR lên `target-host` nếu muốn retest luôn khả năng phát hiện phía đích, không chỉ phía nguồn.

---

## 4. Seed credential cho bước lateral movement (S5)

Kịch bản gốc giả định attacker đã có sẵn một tài khoản hợp lệ để pivot sang host thứ hai, lấy được từ một bước trước đó không nằm trong phạm vi retest này — nên **không rõ credential đó thực chất là gì**. Trong lab tự dựng, credential này cần được **seed thủ công, minh bạch**, không phải một hành vi tấn công cần EDR phát hiện:

- Đặt sẵn 1 SSH private key (hoặc password) của `opsuser`@`target-host` vào một vị trí mà attacker có thể "tìm thấy" sau khi đã có shell trên `app-host` ở S1 (ví dụ: file cấu hình app, biến môi trường của service `svcapp`).
- Việc seed này chỉ nhằm đảm bảo S5 chạy được trong lab — **không tính vào ma trận kết quả** của kịch bản retest.

---

## 5. Đối tượng cần xác nhận trước khi chạy retest

- [ ] Sản phẩm EDR cần test đã cài và đang chạy healthy trên `app-host` (và `target-host` nếu trong scope).
- [ ] Có quyền xem dashboard/alert console của sản phẩm (chỉ đọc, không xem cấu hình rule nội bộ — giữ black-box).
- [ ] Baseline process/port/log đã được ghi lại trước khi bắt đầu S1.
- [ ] Đã seed credential lateral movement theo mục 4 (nếu S5 nằm trong phạm vi retest lần này).
