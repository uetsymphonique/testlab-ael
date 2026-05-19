# EfsPotato / CertEnrollSvc - Code Flow Summary

This document summarizes the `CertEnrollSvc.cs` variant under `resources/payloads/EfsPotato`. It is a C# wrapper based on EfsPotato, renamed to certificate-enrollment-themed namespaces/classes and padded with benign-looking helper classes to reduce static signatures. The core behavior remains local privilege escalation through MS-EFSR RPC plus named pipe impersonation.

## Source Map

| Component | Path | Role |
|---|---|---|
| Obfuscated variant | `../../resources/payloads/EfsPotato/CertEnrollSvc.cs` | Binary used in the emulation |
| Reference source | `../../resources/payloads/EfsPotato/EfsPotato.cs` | Original public source for comparison |
| Compiled binary | `../../resources/payloads/EfsPotato/CertEnrollSvc.exe` | Build output |
| Payload README | `../../resources/payloads/EfsPotato/README.md` | Technique, build, and usage notes |

## High-Level Runtime Flow

```text
CertEnrollmentAgent.Main(args)
  -> validate command and optional RPC endpoint
  -> enable SeImpersonatePrivilege on current token
  -> create random GUID
  -> CreateNamedPipe("\\.\pipe\{guid}\pipe\srvsvc")
  -> start ListenServicePipe thread
       -> ConnectNamedPipe()
       -> signal ManualResetEvent when client connects
  -> start EstablishRpcChannel thread
       -> RpcServiceClient(endpoint)
       -> InvokeEncryptionService("\\localhost/PIPE/{guid}/\\{guid}\\{guid}")
  -> wait up to 3000 ms for pipe connection
  -> ImpersonateNamedPipeClient(pipe)
  -> get current impersonated token
  -> CreateProcessAsUser(token, args[0])
  -> wait for spawned process to exit
```

The flow forces a privileged Windows service/RPC server to connect to an attacker-created named pipe. The process then impersonates the named pipe client token and spawns the requested command with that token.

## Benign-Looking Wrapper

The file uses the namespace:

```text
CertificateServices.Enrollment
```

The following classes are not on the exploit-critical path:

| Class | Role in code |
|---|---|
| `EnrollmentConstants` | Stores certificate-enrollment-themed metadata |
| `CertificateRequestBuilder` | Builds fake XML certificate request content |
| `EnrollmentLogger` | Writes logs to `%ProgramData%\Microsoft\CertificateServices\enrollment.log` |
| `RegistryHelper` | Reads registry auto-enrollment policy/configuration |

These classes create Certificate Services context, but `Main()` does not call them in the exploit path. The execution core is in `CertEnrollmentAgent` and `RpcServiceClient`.

## Argument and Endpoint Selection

`CertEnrollmentAgent.Main()` requires at least one argument:

```text
CertEnrollSvc.exe <command> [endpoint]
```

`args[0]` is the command spawned after successful impersonation. `args[1]` is the optional RPC endpoint; if omitted, it defaults to `lsarpc`.

Valid endpoints:

| Endpoint | Interface GUID used |
|---|---|
| `lsarpc` | `c681d488-d850-11d0-8c52-00c04fd90f7e` |
| `samr` | `c681d488-d850-11d0-8c52-00c04fd90f7e` |
| `lsass` | `c681d488-d850-11d0-8c52-00c04fd90f7e` |
| `netlogon` | `c681d488-d850-11d0-8c52-00c04fd90f7e` |
| `efsrpc` | `df1941c5-fe89-4e79-bf10-463657acf44d` |

In `CertEnrollSvc.cs`, both GUIDs are split into string fragments before `new Guid(...)`, preventing full contiguous GUID strings from appearing at the source call site.

## Privilege Preparation

The code uses `WindowsIdentity.GetCurrent()` to get the current token, then enables `SeImpersonatePrivilege`:

```text
LookupPrivilegeValue(null, "SeImpersonatePrivilege")
AdjustTokenPrivileges(currentToken, ...)
```

The string `SeImpersonatePrivilege` is built with `new string(new char[]{...})` instead of being used as a direct literal. If `AdjustTokenPrivileges()` fails or `Marshal.GetLastWin32Error() != 0`, the process returns immediately.

The tool does not grant itself a new privilege. It only enables the privilege if the current token already has it, which is why the payload fits service account or IIS AppPool contexts better than normal user contexts.

## Named Pipe Setup

After the privilege is ready, the code creates a random GUID:

```text
g = Guid.NewGuid().ToString("d")
pipePath = \\.\pipe\{g}\pipe\srvsvc
```

The named pipe is created with:

```text
CreateNamedPipe(pipePath, 3, 0, 10, 2048, 2048, 0, IntPtr.Zero)
```

`ListenServicePipe` then runs in a background thread:

```text
ConnectNamedPipe(pipe, IntPtr.Zero)
mre.Set()
```

The `ManualResetEvent` synchronizes the pipe-listening thread and main thread. The main thread impersonates only if `mre.WaitOne(3000)` reports a client connection within three seconds.

On timeout, the code calls `CreateFile(pipePath, GENERIC_WRITE, ...)` to force-cancel the async operation, then cleans up handles.

## RPC Coercion Flow

The second thread runs `EstablishRpcChannel()`:

```text
RpcServiceClient r = new RpcServiceClient(endpoint)
r.InvokeEncryptionService("\\localhost/PIPE/" + g + "/\" + g + "\" + g)
```

The `\\localhost/PIPE/` prefix is also built from a char array.

`RpcServiceClient` manually builds an RPC client stub:

1. Select interface GUID by endpoint.
2. Select MIDL format string by x86/x64 architecture.
3. Pin MIDL proc/type format arrays with `GCHandle`.
4. Build `RPC_CLIENT_INTERFACE`.
5. Build `MIDL_STUB_DESC`.
6. Bind to `localhost` over `ncacn_np` and endpoint `\pipe\<endpoint>`.
7. Call `NdrClientCall2` with format string offset `2`.

Bind path:

```text
RpcStringBindingCompose(interfaceId, "ncacn_np", "localhost", "\pipe\<endpoint>", null)
RpcBindingFromStringBinding(...)
RpcBindingSetAuthInfo(..., AuthnLevel=6, AuthnSvc=9)
RpcBindingSetOption(..., timeout=5000)
NdrClientCall2(...)
```

`InvokeEncryptionService()` is the renamed EFSRPC-style `EfsRpcEncryptFileSrv` call. Its `FileName` parameter points to the attacker-controlled local named pipe path, causing the RPC-side service to attempt access to that pipe.

## Impersonation and Process Creation

When the RPC server connects to the named pipe, the main thread continues:

```text
ImpersonateNamedPipeClient(hChannel)
tkn = WindowsIdentity.GetCurrent().Token
CreatePipe(out hRead, out hWrite, ...)
CreateProcessAsUser(tkn, null, args[0], ..., CREATE_NO_WINDOW, ..., STARTUPINFO)
```

`STARTUPINFO` is configured as follows:

| Field | Value |
|---|---|
| `hStdOutput` | Write side of anonymous pipe |
| `hStdError` | Write side of anonymous pipe |
| `lpDesktop` | `WinSta0\Default`, built from a char array |
| `dwFlags` | `0x101` |
| `wShowWindow` | `0` |
| creation flags | `0x08000000` (`CREATE_NO_WINDOW`) |

After the process is created, `ProcessOutputStream()` reads stdout/stderr through the anonymous pipe but does not write it to the console. This differs from the public source, where output is printed with `Console.WriteLine()`.

The code waits for the child process to exit through `ProcessWaitHandle`, then closes process, thread, token, and pipe handles.

## Obfuscation and Signature Reduction

`CertEnrollSvc.cs` does not change the main primitive, but it reduces static signatures compared with `EfsPotato.cs`.

| Area | Public source | CertEnrollSvc variant |
|---|---|---|
| Namespace/class | `Zcg.Exploits.Local.EfsPotato` | `CertificateServices.Enrollment.CertEnrollmentAgent` |
| Console banner | Attribution/exploit strings present | Removed |
| EFSRPC method name | `EfsRpcEncryptFileSrv` | `InvokeEncryptionService` |
| MIDL byte arrays | Raw bytes | XOR encoded with `0x41`, decoded by `Xd()` |
| Sensitive strings | Plain literals | Char-array construction |
| Interface GUIDs | Full contiguous strings | Split string concatenation |
| Output behavior | Writes status to console | Mostly silent |
| Benign padding | None | Certificate enrollment helper classes |

MIDL arrays are exposed through properties:

```text
MIDL_ProcFormatStringx86 => Xd(encodedBytes)
MIDL_ProcFormatStringx64 => Xd(encodedBytes)
MIDL_TypeFormatStringx86 => Xd(encodedBytes)
MIDL_TypeFormatStringx64 => Xd(encodedBytes)
```

`Xd()` XORs each byte with `0x41` at runtime. Static signatures over the original MIDL format byte sequence should therefore not match the encoded variant directly.

## Detection-Relevant Code Paths

| Behavior | Code path | Observable artifact |
|---|---|---|
| SeImpersonate enable attempt | `LookupPrivilegeValue` -> `AdjustTokenPrivileges` | Process attempts to enable `SeImpersonatePrivilege` |
| Random attacker pipe | `Guid.NewGuid()` -> `CreateNamedPipe("\\.\pipe\{guid}\pipe\srvsvc")` | Named pipe path with GUID component and `\pipe\srvsvc` suffix |
| RPC coercion | `RpcStringBindingCompose` -> `NdrClientCall2` | Local RPC over `ncacn_np` to `lsarpc`/`efsrpc`/`samr`/`lsass`/`netlogon` |
| EFSRPC-like file parameter | `InvokeEncryptionService("\\localhost/PIPE/{guid}/...")` | RPC request references attacker-controlled local pipe path |
| Named pipe impersonation | `ConnectNamedPipe` -> `ImpersonateNamedPipeClient` | Thread impersonates client connected to pipe |
| SYSTEM process creation | `CreateProcessAsUser(tkn, null, args[0], ...)` | Child process spawned with impersonated token |
| Hidden child window | `CreateProcessAsUser` with `0x08000000` | `CREATE_NO_WINDOW` process creation |
| Output pipe redirection | `CreatePipe` + `STARTUPINFO.hStdOutput/hStdError` | Child stdout/stderr redirected to anonymous pipe |
| MIDL stub obfuscation | `Xd()` on MIDL arrays | Runtime-decoded RPC format strings, raw public bytes absent at rest |
| Certificate enrollment masquerade | `CertificateServices.Enrollment` namespace and helper classes | Binary contains certificate-enrollment-themed class/string context |

## Reading Order

1. `CertEnrollmentAgent.Main()` for the privilege, pipe, impersonation, and process creation flow.
2. `EstablishRpcChannel()` and `ListenServicePipe()` to understand the two-thread race/synchronization.
3. `RpcServiceClient` constructor for endpoint-to-interface GUID selection and MIDL stub initialization.
4. `InvokeEncryptionService()` for the `NdrClientCall2` call path.
5. `Bind()` for RPC binding over `ncacn_np`.
6. `EfsPotato.cs` only as a reference to identify what changed in `CertEnrollSvc.cs`.

## ATT&CK-Relevant Behaviors

| Behavior | Likely ATT&CK mapping |
|---|---|
| Impersonating named pipe client token | `T1134.001` Access Token Manipulation: Token Impersonation/Theft |
| Spawning command with impersonated token | `T1134.002` Access Token Manipulation: Create Process with Token |
| Local RPC coercion over named pipes | Supports `T1134.001`; detection can map to named pipe/RPC activity |
| Certificate enrollment-themed masquerade | `T1036` Masquerading, if modeled as a distinct static/filename/context behavior |
| XOR-encoded MIDL arrays and string construction | `T1027` Obfuscated Files or Information |
