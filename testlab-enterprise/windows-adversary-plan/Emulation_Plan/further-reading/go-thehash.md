# go-thehash - Code Flow Summary

This document summarizes the code flow of `go-thehash`, a Go Pass-the-Hash SMB/WMI toolkit. The tool authenticates to remote Windows systems with NTLMv2 using a raw NT hash, then performs SMB file operations, remote execution through the Service Control Manager or WMI/DCOM, and host enumeration through SRVS and SAMR RPC interfaces.

## Source Map

| Component | Path | Role |
|---|---|---|
| CLI and operations | `../../resources/payloads/go-thehash/main.go` | Argument parsing, SMB authentication, file operations, execution, enumeration |
| Module definition | `../../resources/payloads/go-thehash/go.mod` | Go module, `go-smb` dependency, local replace directive |
| Payload README | `../../resources/payloads/go-thehash/README.md` | Build, usage, examples, detection notes |
| Compiled binary | `../../resources/payloads/go-thehash/go-thehash.exe` | Windows build output used in emulation |
| Vendored SMB/RPC library | `../../resources/payloads/go-thehash/go-smb/` | Local copy of `github.com/jfjallid/go-smb` used for SMB, NTLM, DCE/RPC, DCOM, WMI |
| SMB transport | `../../resources/payloads/go-thehash/go-smb/smb/` | SMB connection, session, file transfer, tree connect |
| NTLM/SPNEGO | `../../resources/payloads/go-thehash/go-smb/ntlmssp/`, `../../resources/payloads/go-thehash/go-smb/spnego/` | NTLM initiator and SPNEGO wrapping |
| DCE/RPC core | `../../resources/payloads/go-thehash/go-smb/dcerpc/` | RPC bind and transport abstractions |
| SMB RPC transport | `../../resources/payloads/go-thehash/go-smb/dcerpc/smbtransport/` | DCE/RPC over SMB named pipe file handles |
| Service Control RPC | `../../resources/payloads/go-thehash/go-smb/dcerpc/msscmr/` | MS-SCMR service creation, start, delete |
| Server Service RPC | `../../resources/payloads/go-thehash/go-smb/dcerpc/mssrvs/` | Share and session enumeration |
| SAMR RPC | `../../resources/payloads/go-thehash/go-smb/dcerpc/mssamr/` | Local user enumeration |
| DCOM/WMI RPC | `../../resources/payloads/go-thehash/go-smb/dcerpc/msdcom/` | DCOM connection and WMI method execution |

## High-Level Runtime Flow

```text
main()
  -> validate subcommand and arguments
  -> route by subcommand:
       put/get/del/ls
         -> connect(target, domain, user, ntHash)
         -> SMB file operation on selected share
       exec
         -> connect(target, domain, user, ntHash)
         -> bind to IPC$\svcctl
         -> create transient service with command as BinaryPathName
         -> start service
         -> delete service
       exec-wmi
         -> decode NT hash
         -> DCOM/WMI NTLM connection
         -> Win32_Process.Create(command)
       enum shares/sessions/users
         -> connect(target, domain, user, ntHash)
         -> bind to IPC$ RPC pipe
         -> call SRVS or SAMR enumeration method
```

Core authentication model:

```text
operator supplies 32-char NT hash
  -> hex.DecodeString(hashHex)
  -> spnego.NTLMInitiator{User, Domain, Hash}
  -> smb.NewConnection({Host: target, Port: 445, Initiator})
  -> NTLMv2 authentication without plaintext password or Windows SSPI
```

## Entry Point and CLI Dispatch

`main()` reads `os.Args[1]` as the subcommand and dispatches through a `switch`.

Supported subcommands:

| Subcommand | Argument shape | Code path |
|---|---|---|
| `put` | `<target> <domain> <user> <nt-hash> <share> <remote-path> <local-path>` | `connect()` -> `putFile()` |
| `get` | `<target> <domain> <user> <nt-hash> <share> <remote-path> <local-path>` | `connect()` -> `getFile()` |
| `del` | `<target> <domain> <user> <nt-hash> <share> <remote-path>` | `connect()` -> `deleteRemoteFile()` |
| `ls` | `<target> <domain> <user> <nt-hash> <share> <remote-dir> [pattern]` | `connect()` -> `listDir()` |
| `exec` | `<target> <domain> <user> <nt-hash> <command>` | `connect()` -> `execViaService()` |
| `exec-wmi` | `<target> <domain> <user> <nt-hash> <command>` | `hex.DecodeString()` -> `execViaWMI()` |
| `enum shares` | `<target> <domain> <user> <nt-hash>` | `connect()` -> `enumShares()` |
| `enum sessions` | `<target> <domain> <user> <nt-hash>` | `connect()` -> `enumSessions()` |
| `enum users` | `<target> <domain> <user> <nt-hash> [netbios-name]` | `connect()` -> `enumUsers()` |

Invalid argument counts call `usage()` and exit. Successful SMB-based commands print the authenticated identity before running the requested action.

## Pass-the-Hash Authentication

`connect(target, domain, user, hashHex)` performs the shared SMB authentication flow:

1. Decode the provided 32-character NT hash with `hex.DecodeString(hashHex)`.
2. Build `smb.Options` with `Host`, `Port: 445`, and a `spnego.NTLMInitiator`.
3. Set `NTLMInitiator.User`, `Domain`, and raw `Hash`.
4. Call `smb.NewConnection(options)`.
5. Verify `session.IsAuthenticated()`.
6. Return the authenticated `*smb.Connection`.

The code does not use plaintext passwords, Windows credential APIs, Kerberos, or Windows SSPI. Authentication is handled in-process by the Go SMB/NTLM stack.

## SMB File Operations

File operations reuse the authenticated SMB session and operate against caller-selected shares such as `ADMIN$` or `C$`.

### Upload

`putFile(session, share, remotePath, localPath)`:

```text
os.Open(localPath)
session.PutFile(share, remotePath, 0, read callback)
print uploaded byte count
```

The read callback streams local file bytes into the SMB upload operation.

### Download

`getFile(session, share, remotePath, localPath)`:

```text
os.Create(localPath)
session.RetrieveFile(share, remotePath, 0, write callback)
print downloaded byte count
```

If retrieval fails, the partially written local output file is removed.

### Delete

`deleteRemoteFile(session, share, remotePath)` calls:

```text
session.DeleteFile(share, remotePath)
```

### Directory Listing

`listDir(session, share, dir, pattern, recurse)` defaults `pattern` to `*`, then calls either:

```text
session.ListDirectory(share, dir, pattern)
session.ListRecurseDirectory(share, dir, pattern)
```

The CLI path passes `recurse=false`, so `ls` is non-recursive. Output includes file/directory type, UTC last-write time converted from Windows FILETIME, size, name, and hidden-file marker.

## Remote Execution Through Service Control Manager

`exec` uses SMB named pipes and MS-SCMR to create a transient Windows service.

```text
execViaService(session, command)
  -> TreeConnect("IPC$")
  -> OpenFile("IPC$", msscmr.MSRPCSvcCtlPipe)
  -> smbtransport.NewSMBTransport(pipe)
  -> dcerpc.Bind(..., msscmr.MSRPCUuidSvcCtl, ...)
  -> msscmr.NewRPCCon(bind)
  -> randName(12)
  -> CreateService(serviceName, ..., command, ...)
  -> StartService(serviceName, nil)
  -> DeleteService(serviceName)
```

The service name is 12 random lowercase letters from `randName(12)`. The supplied `command` is used as the service binary path. This means shell built-ins must be wrapped explicitly, for example:

```text
%COMSPEC% /c whoami > C:\Windows\Temp\out.txt
```

`ERROR_SERVICE_REQUEST_TIMEOUT` / timeout during `StartService` is treated as expected when the command does not behave like a real Windows service. The command may still have been dispatched before SCM terminates it.

## Remote Execution Through WMI/DCOM

`exec-wmi` uses DCOM and WMI instead of the Service Control Manager.

```text
execViaWMI(target, domain, user, hashBytes, command)
  -> msdcom.DCOMOptions{
       MechFactory: NTLMInitiator with raw hash,
       AuthLevel: RpcAuthnLevelPktPrivacy
     }
  -> msdcom.NewDCOMConnection(target, opts)
  -> msdcom.NewWMIClient(conn, "//./root/cimv2")
  -> wmi.GetObject("Win32_Process")
  -> msdcom.BuildMethodInput(classDef, "Create", {"CommandLine": command})
  -> wmi.ExecMethod("Win32_Process", "Create", inParams)
  -> parse ReturnValue and ProcessId when available
```

Unlike `exec`, this path does not create a Windows service and therefore does not leave SCM service-install artifacts. The created process runs under the authenticated caller context rather than LocalSystem.

## Enumeration Flow

Enumeration commands authenticate over SMB, connect to `IPC$`, bind to the relevant RPC interface over an SMB named pipe, and call a protocol-specific method.

### Shared SRVS Binding

`bindSrvsvc(session)`:

```text
TreeConnect("IPC$")
OpenFile("IPC$", mssrvs.MSRPCSrvSvcPipe)
smbtransport.NewSMBTransport(pipe)
dcerpc.Bind(..., mssrvs.MSRPCUuidSrvSvc, ...)
mssrvs.NewRPCCon(bind)
```

Callers receive both the RPC connection and a cleanup function that closes the pipe and disconnects `IPC$`.

### Share Enumeration

`enumShares(session, target)`:

```text
bindSrvsvc(session)
rpccon.NetShareEnumAll(target)
print name, type, hidden flag, comment
```

This discovers administrative and normal shares exposed by the target Server service.

### Session Enumeration

`enumSessions(session)`:

```text
bindSrvsvc(session)
rpccon.NetSessionEnum("", "", 10)
print client, user, active time, idle time
```

If no `Level10` entries are returned, the tool prints that no active sessions were found.

### Local User Enumeration

`bindSamr(session)` uses the same `IPC$` + SMB transport pattern, but opens `mssamr.MSRPCSamrPipe` and binds to the SAMR interface.

`enumUsers(session, netbiosName)`:

```text
bindSamr(session)
rpccon.ListLocalUsers(netbiosName, 500)
print RID and name
```

If `netbiosName` is omitted, the underlying SAMR helper attempts auto-detection.

## Vendored go-smb Dependency

`go.mod` declares:

```text
require github.com/jfjallid/go-smb v0.7.0
replace github.com/jfjallid/go-smb => ./go-smb
```

The local `go-smb/` directory provides the SMB, NTLM, SPNEGO, DCE/RPC, DCOM, WMI, SRVS, SAMR, and SCMR implementation used by the tool. This allows offline builds and avoids relying on Windows-native authentication libraries.

## Detection-Relevant Code Paths

| Behavior | Code path | Observable artifact |
|---|---|---|
| Pass-the-Hash network logon | `connect()` -> `smb.NewConnection()` with `NTLMInitiator.Hash` | Target receives NTLM network authentication, commonly Windows Event ID `4624` Logon Type `3` |
| SMB2 connection to target | `smb.NewConnection({Port: 445})` | TCP/445 session from operator host to target |
| File upload | `putFile()` -> `session.PutFile()` | SMB write to selected share such as `ADMIN$` or `C$` |
| File download | `getFile()` -> `session.RetrieveFile()` | SMB read from selected share |
| Remote file delete | `deleteRemoteFile()` -> `session.DeleteFile()` | SMB delete operation on remote share path |
| Directory listing | `listDir()` -> `session.ListDirectory()` | SMB directory query against selected share |
| SCM execution | `execViaService()` -> `OpenFile("IPC$", svcctl)` -> `CreateService` -> `StartService` | `IPC$\svcctl` DCE/RPC plus service creation, commonly Event ID `7045` |
| Random service name | `randName(12)` | 12-letter lowercase transient service name |
| Service cleanup | `execViaService()` -> `DeleteService()` | Service deleted after launch; creation artifact may remain in logs |
| WMI execution | `execViaWMI()` -> `Win32_Process.Create` | DCOM to TCP/135 plus dynamic RPC port, process creation through WMI |
| Share enumeration | `enumShares()` -> `NetShareEnumAll` | SRVS RPC over `IPC$\srvsvc` |
| Session enumeration | `enumSessions()` -> `NetSessionEnum` | SRVS RPC over `IPC$\srvsvc` |
| User enumeration | `enumUsers()` -> `ListLocalUsers` | SAMR RPC over `IPC$\samr` |
| No PowerShell dependency | Static Go binary path | Execution does not require `powershell.exe` or PowerShell logging |
| No Windows SSPI dependency | `go-smb` NTLM/SPNEGO implementation | Authentication implemented inside the process with supplied hash bytes |

## ATT&CK-Relevant Behaviors

| Behavior | Likely ATT&CK mapping |
|---|---|
| Authentication with a raw NT hash | `T1550.002` Use Alternate Authentication Material: Pass the Hash |
| SMB admin share file transfer | `T1021.002` Remote Services: SMB/Windows Admin Shares and `T1105` Ingress Tool Transfer, depending scenario context |
| Remote execution through transient service creation | `T1569.002` System Services: Service Execution |
| Remote execution through WMI `Win32_Process.Create` | `T1047` Windows Management Instrumentation |
| Share enumeration through SRVS | `T1135` Network Share Discovery |
| Active session enumeration through SRVS | `T1049` System Network Connections Discovery, depending detection framing |
| Local user enumeration through SAMR | `T1087.001` Account Discovery: Local Account |
| Remote file listing through SMB | `T1083` File and Directory Discovery |

## Reading Order

1. `README.md` for operator-facing usage, examples, and detection notes.
2. `main.go`: read `main()` and `usage()` to understand CLI dispatch and argument shapes.
3. `connect()` to understand Pass-the-Hash NTLM authentication setup.
4. `putFile()`, `getFile()`, `deleteRemoteFile()`, and `listDir()` for SMB file operations.
5. `execViaService()` for SCMR-based remote execution over `IPC$\svcctl`.
6. `execViaWMI()` for DCOM/WMI-based `Win32_Process.Create`.
7. `bindSrvsvc()`, `enumShares()`, and `enumSessions()` for SRVS enumeration.
8. `bindSamr()` and `enumUsers()` for SAMR local user enumeration.
9. `go-smb/dcerpc/smbtransport/`, `msscmr/`, `mssrvs/`, `mssamr/`, and `msdcom/` only when protocol-level call details matter.
