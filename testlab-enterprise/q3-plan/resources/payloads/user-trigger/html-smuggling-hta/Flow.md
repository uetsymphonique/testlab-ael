# html-smuggling-hta — Flow

**Entry:** victim browser loads http://192.168.56.2:8080/staging.html (served web content, no compiled binary)  ·  **Artifact summary:** browser-smuggled polyglot .cer → powershell-decoded .hta → mshta-dropped EssosUpdate.exe + wsdapi.dll in %TEMP% → hidden loader launch (wsdapi.dll sideload handoff)

| # | Behavior (`actor action artifact`) | Artifact [class] → consumed by | Tactic / TID — Technique Name | Context (baseline) |
|---|---|---|---|---|
| 1 | labuser follows lure link to staging page | — [no-artifact] → #2 | — | lure link delivered via Phase 1 email (outside this payload) |
| 2 | browser fetches staging.html from 192.168.56.2:8080 | HTTP session /staging.html [netconn] → #3 | — | operator hosts only staging.html; .cer and .hta are never served over HTTP |
| 3 | page renders fake Entra ID device-compliance UI (3 s spinner, then two-step instructions) | — [no-artifact] → #6 | — | instructions: Win+R → Copy command → paste → Enter; step 1 claims file already downloaded |
| 4 | page pre-loads clipboard with PowerShell launcher one-liner at UI reveal | launcher one-liner in clipboard [clipboard] → #8 | — | navigator.clipboard.writeText; launcher string assembled from split fragments |
| 5 | page reconstructs Essos_Compliance_Update.cer from embedded base64 and triggers browser save to Downloads | %USERPROFILE%\Downloads\Essos_Compliance_Update.cer [file] → #10 | — | atob → Blob → object URL → synthetic anchor download; no HTTP request for the .cer; browser applies Zone.Identifier (ZoneId=3) |
| 6 | labuser opens Run dialog (Win+R) | — [no-artifact] → #8 | — | user action per on-screen step 2 |
| 7 | labuser clicks "Copy command" button; page re-writes launcher to clipboard | launcher one-liner in clipboard [clipboard] → #8 | — | clipboard API with hidden-textarea execCommand('copy') fallback |
| 8 | labuser pastes launcher into Run dialog and presses Enter | — [no-artifact] → #9 | — | ClickFix paste-execute step |
| 9 | Run dialog (explorer.exe) spawns powershell.exe -w h -ep bypass -c "iex(gc -Raw '%USERPROFILE%\Downloads\Essos_Compliance_Update.cer')" | powershell.exe process [process] → #10 | — | hidden window (-w h), ExecutionPolicy Bypass |
| 10 | powershell reads polyglot .cer, keeps regex-matching base64 lines, decodes via FromBase64Transform, writes %TEMP%\Essos_Compliance_Update.bin | %TEMP%\Essos_Compliance_Update.bin [file] → #11 | — | PEM certificate-bundle body inside <# #> PowerShell block comment; decode output equals hpsolutionsportal.hta content (410,067 B) |
| 11 | powershell renames %TEMP%\Essos_Compliance_Update.bin to Essos_Compliance_Update.hta (removing any pre-existing .hta) | %TEMP%\Essos_Compliance_Update.hta [file] → #12 | — | Remove-Item -Force then Rename-Item; powershell-created file carries no Zone.Identifier ADS |
| 12 | powershell launches mshta.exe on %TEMP%\Essos_Compliance_Update.hta | mshta.exe process [process] → #13 | — | HTA runs in Local Machine zone (no MotW); WINDOWSTATE=minimize, SHOWINTASKBAR=no |
| 13 | HTA Window_OnLoad writes %TEMP%\EssosUpdate.exe from hidden-textarea base64 (MSXML2.DOMDocument bin.base64 → ADODB.Stream SaveToFile) | %TEMP%\EssosUpdate.exe [file] → #15 | — | SaveToFile overwrite mode; loader binary taken from toneshell-v2 (112,984 B) |
| 14 | HTA writes %TEMP%\wsdapi.dll from second hidden textarea (same MSXML2/ADODB routine) | %TEMP%\wsdapi.dll [file] → #16 | — | 193,160 B sideload DLL; same directory as host exe |
| 15 | HTA launches %TEMP%\EssosUpdate.exe hidden via Shell.Application.ShellExecute ("open", nShow=0) | EssosUpdate.exe process [process] → #16 | — | COM ShellExecute from VBScript; hidden window |
| 16 | EssosUpdate.exe loads wsdapi.dll from %TEMP% (DLL search-order sideload) | wsdapi.dll module in EssosUpdate.exe [process] | — | handoff boundary — wsdapi.dll internal chain (sandbox checks, waitfor.exe, TONESHELL C2) continues in toneshell-v2 Flow |
| 17 | HTA closes its window (setTimeout self.close 3 s); mshta.exe exits | short-lived mshta.exe [process] | — | ~3 s lifetime under powershell.exe parent |
