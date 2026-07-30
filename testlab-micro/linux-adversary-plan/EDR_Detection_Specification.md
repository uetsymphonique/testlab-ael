# Specification — Yêu cầu phát hiện EDR cho Retest

---

## 1. Nguyên tắc thiết kế (đọc trước khi dùng tài liệu này)

1. **Giữ nguyên hành vi cốt lõi** của lần đánh giá gốc (cùng công cụ, cùng kỹ thuật, cùng trình tự T1→T5) để so sánh được táo-với-táo giữa "trước fix" và "sau fix" khi retest.
2. **Không thiết kế hoặc dự đoán kết quả theo đúng rule Falco/YARA liệt kê ở §4/§5** — các rule này là minh hoạ cách một sản phẩm cụ thể *có thể* phát hiện, không phải checklist để né hoặc để "lọt qua". Đánh giá sản phẩm cần test theo hướng **black-box**: chỉ dựa vào alert/log thực tế xuất hiện trên console, không xem cấu hình rule nội bộ của sản phẩm đó.
3. Mỗi dòng "Nguyên nhân miss" ở §2 là **một tiêu chí pass/fail độc lập**, phải test và ghi nhận riêng, không gộp chung thành một kết luận duy nhất.
4. Thêm biến thể tối thiểu (đổi tên file, đổi port, đổi cấu trúc script) khi tái tạo **chỉ để loại trừ khả năng sản phẩm chỉ chặn theo IOC tĩnh** (hash/tên file/script y hệt), không phải để mở rộng phạm vi tấn công mới.
5. Các hành vi track-covering / persistence / lateral movement (G5–G7) không có dòng "Nguyên nhân miss" riêng ở tài liệu gốc, nhưng vẫn nằm trong mô tả bước tấn công → vẫn cần test đầy đủ để đánh giá toàn diện, không chỉ 4 gap có tên (G1–G4).

---

## 2. Hành vi cần tái tạo & tiêu chí miss cần re-verify

| ID | Giai đoạn (ATT&CK) | Hành vi | Công cụ/Lệnh tham chiếu | Nguyên nhân miss (tài liệu gốc) |
|---|---|---|---|---|
| G1 | Execution / Ingress Tool Transfer (T1059, T1105) | Tạo payload Meterpreter, ghi lên app-host, chạy bind shell | `msfvenom -p linux/x86/meterpreter/bind_tcp LPORT=9001 -f elf -o <payload>` + ghi file qua `echo`/hex-dump + Metasploit multi/handler | Không phát hiện được mã độc máy chủ (thiếu visibility tầng syscall cho `execve`) |
| G2 | (cùng bước G1) | Ghi file bindshell (ELF) vào thư mục nhạy cảm | như trên | Không phát hiện được hành vi tạo file thực thi trong thư mục nhạy cảm (thiếu visibility `open`/`write`/`truncate`) |
| G3 | (cùng bước G1) | Bindshell mở listening port dưới quyền user ứng dụng | như trên | Không phát hiện được hành vi mở port bất thường trên máy chủ (thiếu visibility `bind`/`listen`) |
| G4 | Command & Control / Proxy (T1090, T1572) | Script Python port-forward, ghi vào thư mục nhạy cảm, chạy dưới user ứng dụng | Script Python tự viết (socket listener + forward tới sshd nội bộ) | Không phát hiện được hành vi tạo file portfwd trong thư mục nhạy cảm |
| G5* | Defense Evasion (T1070, T1562) | Xóa/sửa `wtmp`, `utmp`, `btmp`, log text (`auth.log`/`secure`), xóa `.bash_history`, `unset HISTFILE` | `>`/`truncate`/`shred` trên các file log, thao tác biến `HISTFILE` | Không có dòng riêng ở tài liệu gốc — suy ra từ mô tả bước |
| G6* | Persistence (T1098.004) | Ghi thêm SSH public key vào `authorized_keys` của user ứng dụng | `>> ~/.ssh/authorized_keys` | Không có dòng riêng — suy ra từ mô tả bước |
| G7* | Lateral Movement (T1021.004) + Valid Accounts (T1078) | Từ app-host pivot sang target-host bằng tài khoản lấy được ở bước trước | SSH client qua kênh tunnel/portfwd đã tạo ở G4 | Không có dòng riêng — suy ra từ mô tả bước |

`*` = bổ sung ngoài phạm vi 4 "Nguyên nhân miss" có tên gốc, để test toàn diện chuỗi hành vi.

**Điểm chung của G1–G7:** toàn bộ xảy ra dưới quyền user ứng dụng (không cần root) — sản phẩm cần test phải phát hiện được ở tầng syscall/eBPF hoặc tương đương, không chỉ dựa vào audit log của tiến trình chạy bằng quyền root.

---

## 3. Yêu cầu bao phủ sự kiện (event coverage)

| Nhóm | Nội dung cần quan sát được | Bắt buộc cho |
|---|---|---|
| **E1** | Process execve: `pid, ppid, uid, exe, cmdline (full argv), cwd, TTY` | G1, G3, G4, G7 |
| **E2** | File create/write: `open/openat, creat, rename, unlink, truncate`, kèm path/mode/size | G2, G4, G6 |
| **E3** | Log tampering: `write`/`unlink` trên `wtmp`, `utmp`, `btmp`, `lastlog`, `auth.log`/`secure`, `.bash_history` | G5 |
| **E4** | Network socket: `bind`, `listen`, `connect` | G3, G4, G7 |
| **E5** | Persistence: `cron`, systemd unit, `.bashrc`, `sshd_config`, `authorized_keys`, `LD_PRELOAD`, kernel module | G6 |
| **E6** | Privilege/credential access: `sudo`, đọc `/etc/shadow`, đọc `~/.ssh/id_*`, `pkexec`, chuỗi `su` | Không nằm trong G1–G7 hiện tại, nhưng là gap đã ghi nhận riêng ở báo cáo gốc — cân nhắc bổ sung nếu mở rộng phạm vi retest |

Chi tiết điều kiện cảnh báo cho từng nhóm (tham khảo, không phải checklist thiết kế test — xem nguyên tắc §1.2):

### E1 — Process execve
- Chuỗi ancestor chứa app daemon → spawn `bash`, `sh`, `python`, `nc`, `ncat`, `socat`, `curl`, `wget`, `ssh`, `scp`, `sftp`, `chmod +x`, `base64 -d`.
- Command-line chứa: `msfvenom`, `meterpreter`, `bind_tcp`, `reverse_tcp`, `/dev/tcp/`, `bash -i`, `python -c 'import pty'`.
- File exec nằm trong `/tmp`, `/dev/shm`, `/var/tmp`, `~/` với quyền `+x` mới cấp trong thời gian ngắn.
- `echo`/`printf` với argv dài, chứa ký tự `\x` (dấu hiệu ghi ELF qua echo/hex-dump).

### E2 — File create/write
- File mang magic `\x7fELF` được ghi trong `/tmp`, `/dev/shm`, `/var/tmp`, `~/`, thư mục app.
- File `.py`/`.sh` được ghi bởi user ứng dụng, sau đó có execve trong thời gian ngắn.
- `chmod`/`fchmodat` set bit `+x` cho file vừa tạo bởi cùng process.
- Ghi vào `~/.ssh/authorized_keys` hoặc path khớp `AuthorizedKeysFile` trong `sshd_config`.

### E3 — Log tampering
- Process không phải `systemd-journald`/`rsyslogd`/`logrotate`/`auditd` thực hiện `open(O_WRONLY|O_TRUNC)` hoặc `unlink()` trên các file log liệt kê ở G5.
- Ghi vào `~/.bash_history` với size nhỏ hơn trước.
- `setenv`/`exec` với `HISTFILE=/dev/null`, `HISTSIZE=0`, `unset HISTFILE`, `set +o history`.
- `shred`, `truncate -s 0`, `dd if=/dev/zero of=/var/log/*`, `> /var/log/*`.

### E4 — Network/socket
- `bind()` trên port TCP không nằm trong whitelist port dịch vụ của app.
- Kết nối outbound từ user ứng dụng tới port SSH phi chuẩn.
- Process (`python`/`python3`) mở đồng thời một listening socket VÀ một connect socket → dấu hiệu port forwarder/relay.
- SSH client chạy dưới user ứng dụng.

### E5 — Persistence
- Sửa `crontab`, `/etc/cron.*`.
- Tạo/sửa systemd unit.
- Ghi vào `~/.bashrc`, `/etc/profile.d/*`, `~/.ssh/rc`.
- Sửa `sshd_config` (`Match User`, `ForceCommand`, `AuthorizedKeysCommand`).
- `LD_PRELOAD` set trong env hoặc `/etc/ld.so.preload` bị sửa.

### E6 — Privilege/credential access
- `sudo -l`/`-u` không TTY, hoặc password-less đột ngột.
- Đọc `/etc/shadow`, `/etc/passwd` bởi non-root user.
- Đọc `~/.ssh/id_*` private key.
- `su` chain, `pkexec`, `polkit` gọi bất thường.

---

## 4. YARA rules tham khảo (bổ sung vì engine hành vi không đọc content file)

> Giữ nguyên theo yêu cầu §1.2 — dùng để hiểu **dạng tín hiệu** (signature-shape) một static scanner có thể bắt, không dùng để thiết kế payload né rule.

### Y1 — Meterpreter Linux ELF bind_tcp/reverse_tcp
```yara
rule Meterpreter_Linux_x86_Stager
{
    meta:
        description = "Metasploit linux/x86 bind_tcp / reverse_tcp stager"
        reference = "modules/payloads/singles/linux/x86/*"
    strings:
        $elf = { 7F 45 4C 46 01 01 01 00 }
        $sc1 = { 31 DB F7 E3 B0 66 }
        $sc2 = { B0 3F CD 80 }
        $sc3 = { 68 2F 2F 73 68 68 2F 62 69 6E }
        $sc4 = { B0 0B CD 80 }
        $bind_hint = { 66 68 ?? ?? 66 6A 02 }
    condition:
        $elf at 0 and filesize < 200KB and 3 of ($sc*, $bind_hint)
}

rule Meterpreter_Linux_x64_Stager
{
    strings:
        $elf64 = { 7F 45 4C 46 02 01 01 00 }
        $sc_socket = { 6A 29 58 6A 02 5F 6A 01 5E 99 0F 05 }
        $sc_bind   = { 6A 31 58 48 89 C7 48 89 E6 6A 10 5A 0F 05 }
        $sc_listen = { 6A 32 58 6A 01 5E 0F 05 }
        $sc_accept = { 6A 2B 58 6A 00 48 89 C6 48 89 C2 0F 05 }
        $sc_dup2   = { 48 97 6A 03 5E 48 FF CE 6A 21 58 0F 05 }
        $sc_execve = { 48 BB 2F 2F 62 69 6E 2F 73 68 }
    condition:
        $elf64 at 0 and filesize < 300KB and 3 of ($sc_*)
}
```

### Y2 — msfvenom / metsrv fingerprints
```yara
rule Msfvenom_Generated_Payload_Strings
{
    strings:
        $s1 = "metsrv"          ascii
        $s2 = "stdapi_"         ascii
        $s3 = "priv_"           ascii
        $s4 = "core_channel_"   ascii
        $s5 = "meterpreter"     ascii nocase
        $s6 = "reverse_tcp"     ascii
        $s7 = "bind_tcp"        ascii
    condition:
        (uint32(0) == 0x464c457f) and 2 of them
}
```

### Y3 — ELF nhỏ, không section — shellcode-loader
```yara
rule Suspicious_Tiny_ELF
{
    condition:
        uint32(0) == 0x464c457f
        and filesize < 8KB
        and filesize > 100
}
```

### Y4 — Python port-forwarder script (khớp G4)
```yara
rule Python_PortForwarder_Script
{
    strings:
        $py  = "#!/usr/bin/env python"    ascii
        $py2 = "#!/usr/bin/python"        ascii
        $imp1 = "import socket"           ascii
        $imp2 = "import select"           ascii
        $imp3 = "import threading"        ascii
        $imp4 = "import paramiko"         ascii
        $fn1  = "SO_REUSEADDR"            ascii
        $fn2  = ".bind("                  ascii
        $fn3  = ".listen("                ascii
        $fn5  = ".connect("               ascii
        $fn6  = "forward"                 ascii nocase
        $fn7  = "tunnel"                  ascii nocase
        $fn8  = "portfwd"                 ascii nocase
    condition:
        ($py or $py2 or $imp1)
        and $fn1 and $fn2 and $fn3 and $fn5
        and 1 of ($fn6, $fn7, $fn8, $imp4)
}
```

### Y5 — Log-wiping utility / one-liner (khớp G5)
```yara
rule Linux_Log_Wiper_Indicators
{
    strings:
        $u1 = "utmpdump"            ascii
        $u2 = "wtmp"                ascii
        $u3 = "btmp"                ascii
        $c1 = "> /var/log/"         ascii
        $c2 = "truncate -s 0 /var/log" ascii
        $c3 = "shred -uz /var/log"  ascii
        $c4 = "unset HISTFILE"      ascii
        $c5 = "HISTFILE=/dev/null"  ascii
        $c6 = "history -c"          ascii
        $tool1 = "logtamper"        ascii nocase
        $tool2 = "logwipe"          ascii nocase
        $tool3 = "zapper"           ascii nocase
    condition:
        3 of them or any of ($tool*)
}
```

### Y6 — SSH key persistence dropper (khớp G6)
```yara
rule SSH_AuthorizedKeys_Persistence_Script
{
    strings:
        $a1 = "authorized_keys"     ascii
        $a3 = "ssh-rsa "            ascii
        $a4 = "ssh-ed25519 "        ascii
        $a5 = "ecdsa-sha2-"         ascii
        $b1 = ">> ~/.ssh/authorized_keys"  ascii
        $b2 = "chmod 600"           ascii
        $b3 = "mkdir -p ~/.ssh"     ascii
    condition:
        ($a1 and ($a3 or $a4 or $a5)) or (2 of ($b*))
}
```

### Y7 — Bash reverse-shell one-liner
```yara
rule Bash_Reverse_Shell_Oneliner
{
    strings:
        $s1 = "bash -i >& /dev/tcp/"        ascii
        $s2 = "0<&196;exec 196<>/dev/tcp/"  ascii
        $s3 = "sh -i >& /dev/tcp/"          ascii
        $s4 = "exec 5<>/dev/tcp/"           ascii
        $s5 = "python -c 'import pty"       ascii
        $s6 = "socat exec:'bash -li'"       ascii
        $s7 = "nc -e /bin/"                 ascii
    condition:
        any of them
}
```

### Y8 — Meterpreter in-memory
```yara
rule Meterpreter_In_Memory
{
    strings:
        $m2 = "ReflectiveLoader"    ascii
        $m3 = "stdapi"              ascii
        $m4 = "core_channel_open"   ascii
        $m5 = "core_migrate"        ascii
        $m6 = "priv_passwd_get_sam_hashes" ascii
    condition:
        3 of them
}
```

---

## 5. Falco rule mapping tham khảo

> File rule đầy đủ: [`Sample yara rules/vsa_redteam.yaml`](Sample%20yara%20rules/vsa_redteam.yaml), [`Sample yara rules/vsa_redteam.yar`](Sample%20yara%20rules/vsa_redteam.yar). Cả hai đã được ẩn danh (author/tên đơn vị, tham chiếu VSA/AOM đổi sang app-host/target-host, list `vsa_service_ports` đổi tên thành `app_service_ports`).

| Rule Falco | Map với | Priority |
|---|---|---|
| `App_User_Spawns_Reverse_Shell_Primitive` | G1, G7 (execution primitive) | CRITICAL |
| `ELF_Dropped_In_Sensitive_Dir_By_App_User` | G1/G2 (payload drop) | HIGH |
| `Chmod_Exec_On_Newly_Written_File` | G1/G2 | HIGH |
| `Echo_Or_Printf_Writes_Binary_Blob` | G2 (ghi ELF qua echo) | HIGH |
| `Execute_From_Ephemeral_Dir_By_App_User` | G1 (chạy payload từ /tmp) | CRITICAL |
| `Unexpected_TCP_Listener_By_App_User` | G3 (bind port lạ) | CRITICAL |
| `Python_Acts_As_Port_Forwarder` | G4 | HIGH |
| `Wtmp_Utmp_Btmp_Tampering` | G5 | CRITICAL |
| `Text_Log_Truncation_Or_Delete` | G5 (auth.log/audit.log) | CRITICAL |
| `Shell_History_Cleared` | G5 (unset HISTFILE) | WARNING |
| `Bash_History_File_Tampered` | G5 | HIGH |
| `Log_Wipe_Utility_Executed` | G5 (shred/wipe) | HIGH |
| `SSH_Authorized_Keys_Modified` | G6 | CRITICAL |
| `SSH_Config_Or_KeyDir_Created_By_App_User` | G6 | HIGH |
| `SSH_Client_From_App_Daemon` | G7 (pivot) | HIGH |
| `Outbound_Connect_From_App_User_To_Non_Standard_Port` | G7 | HIGH |
| `LD_Preload_Env_Set` | Bonus hardening (E6 phụ trợ) | HIGH |
| `LdSoPreload_File_Modified` | Bonus hardening | CRITICAL |
| `Cron_Or_Systemd_Persistence` | Bonus hardening (E5 phụ trợ) | HIGH |

---

## 6. Ghi chú kỹ thuật (product-agnostic)

- Sản phẩm cần test phải capture ở tầng syscall/eBPF (hoặc tương đương) để có event `listen`/`connect`/`open(O_TRUNC)` chính xác — audit log chỉ ở tầng ứng dụng/root là không đủ cho G1–G7.
- Cần capture đầy đủ argv của `execve` (không chỉ tên binary) để bắt được các one-liner reverse-shell và lệnh `echo`/hex-dump ở G1/G2.
- Field môi trường tiến trình (`proc.env` hoặc tương đương) hữu ích cho phát hiện `LD_PRELOAD`/`HISTFILE` — nhiều engine mặc định tắt capture này vì chi phí hiệu năng, cần xác nhận đã bật trước khi retest.
- Nếu `app-host`/`target-host` chạy trong container, cần thêm điều kiện phân biệt container/host và whitelist port riêng theo image.

---

## 7. Liên kết tới Emulation Plan

Bản đặc tả này là đầu vào cho `Emulation_Plan/Micro_Emulation_Plan.md` (Step 1–5 map G1–G7) và `Emulation_Plan/Setup.md` (lab dựng vai trò `app-host`/`target-host`). Khi thêm/sửa step trong Emulation Plan, đối chiếu lại §2–§3 ở đây để đảm bảo không bỏ sót tiêu chí miss nào của lần đánh giá gốc.
