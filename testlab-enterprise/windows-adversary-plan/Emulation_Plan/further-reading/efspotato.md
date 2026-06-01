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
  -> X.Init()  -- resolve all Win32 API delegates at runtime
  -> determine target command:
       Mode 1 (stdin is pipe): read [4-byte LE size][PE bytes] from stdin,
                               write to GetTempFileName(), use temp path as command
       Mode 2 (args):          args[0] is the command
  -> select RPC endpoint from args[1] (default: lsarpc)
  -> enable SeImpersonatePrivilege on current token
  -> create random GUID
  -> CreateNamedPipeW("\\.\pipe\{guid}\pipe\srvsvc")
  -> start ListenServicePipe thread
       -> ConnectNamedPipe()
       -> signal ManualResetEvent when client connects
  -> start EstablishRpcChannel thread
       -> RpcServiceClient(endpoint)
       -> InvokeEncryptionService("\\localhost/PIPE/{guid}/\{guid}\{guid}")
  -> wait up to 3000 ms for pipe connection
  -> NtFsControlFile(pipe, FSCTL_PIPE_IMPERSONATE)   -- indirect syscall; no advapi32 hook
  -> NtOpenThreadToken()                              -- indirect syscall; capture SYSTEM token
  -> NtDuplicateToken()                               -- indirect syscall; duplicate to primary token
  -> CreateProcessWithTokenW(primaryToken, targetCommand)
  -> wait for spawned process to exit (WaitOne(-1))
  -> Mode 1 only: delete temp file after process exits
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

`CertEnrollmentAgent.Main()` supports two modes based on whether stdin is a pipe.

**Mode 1 — stdin pipe (primary delivery mechanism in this emulation)**

```text
<pe_sender> | CertEnrollSvc.exe [endpoint]
```

If `GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_PIPE`, the process reads a PE from stdin using the framing `[4-byte LE DWORD size][PE bytes]`, writes it to `Path.GetTempFileName()`, and uses the temp path as the target command. `args[0]` is not used. The temp file is deleted after the spawned process exits.

**Mode 2 — command-line argument**

```text
CertEnrollSvc.exe <command> [endpoint]
```

`args[0]` is the command spawned after successful impersonation. `args[1]` is the optional RPC endpoint in both modes; if omitted, it defaults to `lsarpc`.

Valid endpoints:

| Endpoint | Interface GUID used |
|---|---|
| `lsarpc` | `c681d488-d850-11d0-8c52-00c04fd90f7e` |
| `samr` | `c681d488-d850-11d0-8c52-00c04fd90f7e` |
| `lsass` | `c681d488-d850-11d0-8c52-00c04fd90f7e` |
| `netlogon` | `c681d488-d850-11d0-8c52-00c04fd90f7e` |
| `efsrpc` | `df1941c5-fe89-4e79-bf10-463657acf44d` |

In `CertEnrollSvc.cs`, both GUIDs are stored as XOR-encoded byte arrays (`_g1`, `_g2` in class `X`) and decoded at runtime via `X.S()`. No GUID substring appears in the binary at rest.

## Privilege Preparation

The code uses `WindowsIdentity.GetCurrent()` to get the current token, then enables `SeImpersonatePrivilege`:

```text
LookupPrivilegeValue(null, "SeImpersonatePrivilege")
AdjustTokenPrivileges(currentToken, ...)
```

The string `SeImpersonatePrivilege` is stored as a XOR-encoded byte array (`X._priv`) and decoded at runtime via `X.S()`. No plaintext string appears in the binary. If `AdjustTokenPrivileges()` fails or `Marshal.GetLastWin32Error() != 0`, the process returns immediately.

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

The `\\localhost/PIPE/` prefix is stored as a XOR-encoded byte array (`X._lpipe`) and decoded at runtime via `X.S()`.

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
NtFsControlFile(hChannel, FSCTL_PIPE_IMPERSONATE)     -- indirect syscall (pfNtFsControlFile)
NtOpenThreadToken(hThread, TOKEN_ALL_ACCESS, ...)      -- indirect syscall (pfNtOpenThreadToken)
NtDuplicateToken(token, ..., TokenPrimary, ...)        -- indirect syscall (pfNtDuplicateToken)
CreatePipe(out hRead, out hWrite, ...)
CreateProcessWithTokenW(primaryToken, 0, null, targetCommand, ..., CREATE_NO_WINDOW, ..., STARTUPINFO)
    -- targetCommand = args[0] in Mode 2, or temp file path in Mode 1
```

`ImpersonateNamedPipeClient` is the Win32 fallback path only — resolved when indirect syscalls are unavailable (non-x64 or SSN resolution failure).

`STARTUPINFO` is configured as follows:

| Field | Value |
|---|---|
| `hStdOutput` | Write side of anonymous pipe |
| `hStdError` | Write side of anonymous pipe |
| `lpDesktop` | `WinSta0\Default`, decoded from XOR byte array `X._desk` via `X.S()` |
| `dwFlags` | `0x101` |
| `wShowWindow` | `0` |
| creation flags | `0x08000000` (`CREATE_NO_WINDOW`) |

After the process is created, `ProcessOutputStream()` reads stdout/stderr through the anonymous pipe but does not write it to the console. This differs from the public source, where output is printed with `Console.WriteLine()`.

The code waits for the child process to exit through `ProcessWaitHandle`, then closes process, thread, token, and pipe handles.

## Dynamic API Resolution

`CertEnrollSvc.cs` resolves all sensitive Win32 APIs at runtime via `Marshal.GetDelegateForFunctionPointer`. Only `GetModuleHandleW` and `GetProcAddress` appear in the PE Import Address Table. `X.Init()` resolves 20 Win32 function pointers from `kernel32`, `advapi32`, and `Rpcrt4`, plus 3 indirect syscall trampolines (`NtFsControlFile`, `NtOpenThreadToken`, `NtDuplicateToken`) written into a dedicated `PAGE_EXECUTE_READ` page via Halo's Gate SSN resolution. Delegates for the three trampolines are bound to the trampoline page, not to the ntdll stubs — EDR hooks on the original stubs are bypassed.

All DLL names and API name strings are also stored as XOR-encoded byte arrays in class `X` and decoded only at resolution time. Verification: `dumpbin /imports CertEnrollSvc.exe` shows only `GetModuleHandleW` and `GetProcAddress`.

## Obfuscation and Signature Reduction

`CertEnrollSvc.cs` does not change the main primitive, but it reduces static signatures compared with `EfsPotato.cs`.

| Area | Public source | CertEnrollSvc variant |
|---|---|---|
| Namespace/class | `Zcg.Exploits.Local.EfsPotato` | `CertificateServices.Enrollment.CertEnrollmentAgent` |
| Console banner | Attribution/exploit strings present | Removed |
| EFSRPC method name | `EfsRpcEncryptFileSrv` | `InvokeEncryptionService` |
| MIDL byte arrays | Raw bytes in properties | XOR-encoded (`_mps86/64`, `_mts86/64`), decoded by `X.D()` |
| Sensitive strings | Plain literals | XOR byte arrays, decoded by `X.S()` |
| Interface GUIDs | Full contiguous strings | XOR byte arrays `_g1`/`_g2`, decoded by `X.S()` |
| Win32 API imports | `[DllImport]` for all APIs | All resolved dynamically — only `GetModuleHandleW`/`GetProcAddress` in IAT |
| API name strings | N/A (in imports table) | XOR-encoded byte arrays decoded at resolution time |
| Output behavior | Writes status to console | Mostly silent |
| Benign padding | None | Certificate enrollment helper classes |

MIDL arrays are stored as XOR-encoded byte fields and decoded via `X.D()` at stub initialization:

```text
X.D(X._mps86)  ->  MIDL_ProcFormatString (x86)
X.D(X._mps64)  ->  MIDL_ProcFormatString (x64)
X.D(X._mts86)  ->  MIDL_TypeFormatString (x86)
X.D(X._mts64)  ->  MIDL_TypeFormatString (x64)
```

XOR formula: `decoded[i] = encoded[i] ^ ((0xA3 + i * 0x5B) & 0xFF)`. Position-dependent — single-byte brute-force (FLOSS, CyberChef) yields nothing.

## Detection-Relevant Code Paths

| Behavior | Code path | Observable artifact |
|---|---|---|
| SeImpersonate enable attempt | `LookupPrivilegeValue` -> `AdjustTokenPrivileges` | Process attempts to enable `SeImpersonatePrivilege` |
| Random attacker pipe | `Guid.NewGuid()` -> `CreateNamedPipe("\\.\pipe\{guid}\pipe\srvsvc")` | Named pipe path with GUID component and `\pipe\srvsvc` suffix |
| RPC coercion | `RpcStringBindingCompose` -> `NdrClientCall2` | Local RPC over `ncacn_np` to `lsarpc`/`efsrpc`/`samr`/`lsass`/`netlogon` |
| EFSRPC-like file parameter | `InvokeEncryptionService("\\localhost/PIPE/{guid}/...")` | RPC request references attacker-controlled local pipe path |
| Named pipe impersonation | `ConnectNamedPipe` → `NtFsControlFile(FSCTL_PIPE_IMPERSONATE)` → `NtOpenThreadToken` → `NtDuplicateToken` | Indirect syscall path — thread context impersonated, SYSTEM token captured and duplicated to primary; `ImpersonateNamedPipeClient` is Win32 fallback only |
| SYSTEM process creation | `CreateProcessWithTokenW(primaryToken, 0, null, targetCommand, ...)` | Child process spawned with duplicated primary SYSTEM token via seclogon; temp file in Mode 1, args[0] in Mode 2 |
| Hidden child window | `CreateProcessWithTokenW` with `0x08000000` | `CREATE_NO_WINDOW` process creation |
| Output pipe redirection | `CreatePipe` + `STARTUPINFO.hStdOutput/hStdError` | Child stdout/stderr redirected to anonymous pipe |
| MIDL stub obfuscation | `X.D()` on XOR-encoded MIDL arrays | Runtime-decoded RPC format strings, raw public bytes absent at rest |
| Certificate enrollment masquerade | `CertificateServices.Enrollment` namespace and helper classes | Binary contains certificate-enrollment-themed class/string context |
| Dynamic API resolution | `X.Init()` resolves 20 Win32 delegates + 3 indirect syscall trampolines via `GetProcAddress` | IAT shows only `GetModuleHandleW` and `GetProcAddress`; all other imports absent |

## Reading Order

1. `CertEnrollmentAgent.Main()` for the privilege, pipe, impersonation, and process creation flow.
2. `EstablishRpcChannel()` and `ListenServicePipe()` to understand the two-thread race/synchronization.
3. `RpcServiceClient` constructor for endpoint-to-interface GUID selection and MIDL stub initialization.
4. `InvokeEncryptionService()` for the `NdrClientCall2` call path.
5. `Bind()` for RPC binding over `ncacn_np`.
6. `EfsPotato.cs` only as a reference to identify what changed in `CertEnrollSvc.cs`.

