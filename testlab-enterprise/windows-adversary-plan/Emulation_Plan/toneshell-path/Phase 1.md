# Phase 1 - Initial Access: Drive-by Compromise & Toneshell Sideloading

## Overview

The attacker abuses an unrestricted file upload feature on `upload.testlab.local` to host a fake update page. A domain user is lured to the page via a spearphishing link and is tricked into downloading a password-protected RAR archive. Upon extraction and execution of an embedded LNK file, a legitimate executable is launched to sideload the Toneshell backdoor, which injects into `waitfor.exe` and establishes a C2 connection.

---

## Step 0 - Setup

> Full setup procedures are documented in [Setup.md](../Setup.md).

---

## Step 1 - Initial Access: Web-Delivered Archive and Execution

### Voice Track

The attacker hosts a malicious HTML page at `http://upload.testlab.local/uploads/update.html` along with a password-protected RAR archive `Important_Update.rar`. The attacker delivers the link to the target user via email or chat.

When the victim opens the link, the page displays a message urging them to download a critical system update and provides the password (`infected`) to extract it. The victim downloads `Important_Update.rar` to their `Downloads` folder. The page visit acts as a Drive-by Compromise mechanism, luring the user to manually retrieve the payload.

The victim extracts the contents of the RAR archive using the provided password. Inside the archive is a shortcut file (`Update.lnk`) and a hidden directory containing `EssosUpdate.exe` (a renamed legitimate Microsoft binary `wsddebug_host.exe`) and `wsdapi.dll` (the TONESHELL loader). The victim double-clicks the `Update.lnk` file.

The LNK file executes `EssosUpdate.exe`. This legitimate, signed binary is vulnerable to DLL sideloading and automatically loads the malicious `wsdapi.dll` (TONESHELL) located in the same directory. The TONESHELL loader performs several anti-analysis techniques before registering and re-executing itself a second time via `regsvr32.exe`. After spawning a child `waitfor.exe` process, the loader executes itself a third time by using `mavinject.exe` to inject itself into the spawned `waitfor.exe` process.

Once executed in the intended `waitfor.exe` child process, TONESHELL XOR decrypts and reflectively loads the embedded shellcode payload into memory. The shellcode discovers the computer name, generates a GUID for the victim, and connects to the attacker C2 server (`192.168.56.2`) over TCP port 443.

### Procedures

- ☣️ Verify the lure page is reachable from the workstation:
  ```
  http://upload.testlab.local/uploads/update.html
  ```

- Deliver the URL `http://upload.testlab.local/uploads/update.html` to the victim user on `WS01` through a chosen social-delivery path.

- On the victim workstation, open the URL in the browser.

- Observe: the page instructs the user to download `Important_Update.rar` and provides the password `infected`.

- Click the download link and save `Important_Update.rar` to `%USERPROFILE%\Downloads\`.

- Extract the archive using the password `infected`.

- Double-click `Update.lnk` located in the extracted folder. Switch windows several times to bypass the foreground window sandbox check.

- ☣️ Observe on the victim workstation that `EssosUpdate.exe` is launched by `explorer.exe`.

- ☣️ Observe that `EssosUpdate.exe` side-loads `wsdapi.dll`.

- ☣️ Observe that `EssosUpdate.exe` executes `regsvr32.exe /s` to register and load `wsdapi.dll`.

- ☣️ Observe that `regsvr32.exe` spawns `waitfor.exe` and then executes `mavinject.exe` to inject `wsdapi.dll` into `waitfor.exe`.

- ☣️ Observe that `waitfor.exe` initiates an outbound network connection to the attacker C2 (`192.168.56.2`) over port 443.

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
|  - | - | - | - | - | - | - | - | - | - | - |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Windows | User receives message with URL pointing to `upload.testlab.local` | Not Calibrated - Not Benign | Attacker sends a link to the victim directing them to the malicious update page | victim-workstation | domain user | - | - |
| Initial Access | T1189 | Drive-by Compromise | Windows | `msedge.exe` / `chrome.exe` connects to `http://upload.testlab.local/uploads/update.html` | Not Calibrated - Not Benign | Victim visits the attacker-controlled page which hosts the lure and payload | victim-workstation | domain user | - | - |
| Execution | T1204.001 | User Execution: Malicious Link | Windows | User clicks the link to download the RAR archive | Not Calibrated - Not Benign | Victim interacts with the malicious download link on the page | victim-workstation | domain user | - | - |
| Defense Evasion | T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Windows | `msedge.exe` downloads and user extracts the contents of the password-protected RAR file `Important_Update.rar` | Calibrated - Not Benign | Archive is password protected to evade network inspection | victim-workstation | domain user | - | - |
| Execution | T1204.002 | User Execution: Malicious File | Windows | `explorer.exe` executes the LNK file `Update.lnk` | Not Calibrated - Not Benign | Victim executes the malicious shortcut file | victim-workstation | domain user | - | - |
| Execution | T1204.002 | User Execution: Malicious File | Windows | LNK file execution launches `EssosUpdate.exe` (renamed `wsddebug_host.exe`) | Not Calibrated - Not Benign | Shortcut points to and launches the renamed legitimate binary | victim-workstation | domain user | - | - |
| Defense Evasion | T1036.003 | Masquerading: Rename System Utilities | Windows | `EssosUpdate.exe` executed from extracted folder by `explorer.exe` on WS01; PE version info `OriginalFilename` field contains `wsddebug_host.exe` — binary name on disk does not match the Microsoft SDK utility it was copied from | Calibrated - Not Benign | `wsddebug_host.exe` (Microsoft Windows SDK debugging binary, signed by Microsoft) is copied and renamed to `EssosUpdate.exe` inside the RAR archive; the renamed legitimate binary is invoked via LNK as the DLL sideloading host, masking the loader launcher as a plausible software update executable | WS01 (10.12.10.30) | domain user | - | - |
| Defense Evasion | T1574.001 | Hijack Execution Flow: DLL | Windows | `EssosUpdate.exe` side-loads `wsdapi.dll` | Calibrated - Not Benign | Legitimate executable loads malicious TONESHELL loader DLL | victim-workstation | domain user | - | - |
| Defense Evasion | T1553.002 | Subvert Trust Controls: Code Signing | Windows | `wsdapi.dll` is signed with a self-signed cert | Calibrated - Not Benign | TONESHELL loader DLL is signed with a self-signed certificate | victim-workstation | domain user | - | - |
| Defense Evasion | T1497 | Virtualization/Sandbox Evasion | Windows | `wsdapi.dll` checks if current process name matches `EssosUpdate.exe` using `GetModuleFileNameW` and checks for changes to the foreground window | Not Calibrated - Not Benign | TONESHELL loader performs anti-analysis checks to evade sandboxing | victim-workstation | domain user | - | - |
| Defense Evasion | T1622 | Debugger Evasion | Windows | `wsdapi.dll` uses custom exceptions to hinder debuggers | Not Calibrated - Not Benign | TONESHELL loader uses custom exceptions | victim-workstation | domain user | - | - |
| Defense Evasion | T1218.010 | System Binary Proxy Execution: Regsvr32 | Windows | `EssosUpdate.exe` executes `regsvr32.exe /s` to register and load `wsdapi.dll` | Calibrated - Not Benign | TONESHELL loader registers and re-executes itself using `regsvr32.exe` | victim-workstation | domain user | - | - |
| Defense Evasion | T1218.013 | System Binary Proxy Execution: Mavinject | Windows | `regsvr32.exe` spawns `waitfor.exe` then executes `mavinject.exe` to inject `wsdapi.dll` into `waitfor.exe` | Calibrated - Not Benign | `regsvr32.exe` executes `mavinject` to inject the TONESHELL loader DLL into the target process | victim-workstation | domain user | - | - |
| Defense Evasion | T1055.001 | Process Injection: Dynamic-link Library Injection | Windows | `mavinject.exe` creates a remote thread in `waitfor.exe` with `StartFunction: LoadLibraryW` on WS01 (Sysmon Event 8 CreateRemoteThread: SourceImage `mavinject.exe`, TargetImage `waitfor.exe`) | Calibrated - Not Benign | `mavinject.exe` performs classic DLL injection into `waitfor.exe`: `VirtualAllocEx` allocates remote memory for the `wsdapi.dll` path, `WriteProcessMemory` writes the path string, `CreateRemoteThread` starts execution at `LoadLibraryW` in the target process address space | WS01 (10.12.10.30) | domain user | - | - |
| Defense Evasion | T1027.009 | Obfuscated Files or Information: Embedded Payloads | Windows | `wsdapi.dll` contains embedded shellcode in the data section | Not Calibrated - Not Benign | TONESHELL loader DLL contains embedded shellcode payload | victim-workstation | domain user | - | - |
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Windows | `wsdapi.dll` XOR decrypts embedded shellcode | Calibrated - Not Benign | TONESHELL loader XOR decrypts its embedded shellcode | victim-workstation | domain user | - | - |
| Defense Evasion | T1620 | Reflective Code Loading | Windows | `wsdapi.dll` reflectively loads and executes the shellcode | Calibrated - Not Benign | TONESHELL loader reflectively loads and executes the decrypted shellcode | victim-workstation | domain user | - | - |
| Discovery | T1082 | System Information Discovery | Windows | `waitfor.exe` discovers computer name via `GetComputerNameA` | Not Calibrated - Not Benign | TONESHELL payload discovers the workstation computer name | victim-workstation | domain user | - | - |
| Execution | T1106 | Native API | Windows | `waitfor.exe` creates a random GUID using `CoCreateGuid` and uses ws2_32 `send` API to connect to C2 | Not Calibrated - Not Benign | TONESHELL uses native Windows APIs to generate an ID and communicate | victim-workstation | domain user | - | - |
| Command and Control | T1095 | Non-Application Layer Protocol | Windows | `waitfor.exe` connects to `192.168.56.2` over TCP port 443 | Calibrated - Not Benign | TONESHELL connects to attacker C2 | victim-workstation | domain user | - | - |
