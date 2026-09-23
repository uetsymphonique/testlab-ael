# html-smuggling-hta

Third delivery variant for q3-plan Phase 1 (Step 1C). Instead of downloading the
password-protected ZIP (Step 1) or retrieving it over BITS (Step 1B), the lure page
**reconstructs an HTA client-side** and `mshta.exe` runs it. The HTA drops the existing
ToneShell sideload loader (`EssosUpdate.exe` + `wsdapi.dll`) and launches it, so the rest
of the chain (sideload → sandbox checks → `waitfor.exe` → TONESHELL C2) is unchanged.

## Chain

```
[labuser CTRL+clicks the docx link]
        |
        v
[browser opens http://192.168.56.2:8080/staging.html]
        |
        v
[page reconstructs Essos_Compliance_Update.hta from an embedded base64 blob]
   - no HTTP GET for the .hta (T1027.006 HTML Smuggling)
        |
        v
[labuser opens the .hta -> mshta.exe runs it]
        |
        v
[HTA writes EssosUpdate.exe + wsdapi.dll (embedded base64) to %TEMP%]
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
| `staging.tpl.html` | Smuggling page **template** (`@@HTA_B64@@` placeholder) |
| `stage1.tpl.hta` | HTA **template** (`@@EXE_B64@@` / `@@DLL_B64@@` placeholders) |
| `build.py` | Generates the two runtime files below |
| `stage1.hta` | Generated HTA (embeds `EssosUpdate.exe` + `wsdapi.dll`) — committed |
| `staging.html` | Generated lure page (embeds `stage1.hta`) — committed, served by the operator |

`staging.tpl.html` / `stage1.tpl.hta` are the editable sources; never edit the generated
`staging.html` / `stage1.hta` by hand — re-run `build.py`.

## Build

```bash
python build.py
```

Reads the loader from the ToneShell tree:

- `../../rce-and-c2/mustang-panda-emulation/toneshell-v2/EssosUpdate.exe` (112,984 bytes)
- `../../rce-and-c2/mustang-panda-emulation/toneshell-v2/build/src/wsdapi/Release/wsdapi.dll` (193,160 bytes)

Outputs:

- `stage1.hta` (~410 KB) — HTA with both loader binaries base64-embedded in hidden `<textarea>` elements
- `staging.html` (~555 KB) — page with the HTA base64-embedded in `var b64 = '...'`

## Server requirements

Only `staging.html` is served, from the same staging web server used by Step 1:

```
http://192.168.56.2:8080/staging.html
```

`Essos_Compliance_Update.hta` is **not** hosted — it is reconstructed inside the browser.

## Runtime notes

- The page only acts when `window.location.hostname === '192.168.56.2'`; any other
  hostname redirects to `https://login.microsoftonline.com/`.
- The HTA writes to `%TEMP%\EssosUpdate.exe` and `%TEMP%\wsdapi.dll` (same directory so the
  DLL search-order sideload resolves), then launches the loader hidden (`nShow=0`).
- `wsdapi.dll` validates its host process leaf name is `EssosUpdate.exe`; keep that name.

## Rebuild

After changing either template, re-run `build.py` and re-serve `staging.html`.
