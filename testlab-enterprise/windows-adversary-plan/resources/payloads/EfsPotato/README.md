# EfsPotato — Privilege Escalation via MS-EFSR Named Pipe Impersonation

**MITRE ATT&CK:** T1134.001 — Access Token Manipulation: Token Impersonation/Theft  
**Original author:** zcgonvh — [github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)

---

## Technique

EfsPotato exploits the Windows Encrypting File System RPC interface (MS-EFSR) to coerce the `LSASS` process into authenticating to an attacker-controlled named pipe, yielding a `SYSTEM`-level impersonation token. The exploit leverages `SeImpersonatePrivilege` (held by IIS AppPool identities, SQL Server, and similar service accounts) to escalate from a service account to `NT AUTHORITY\SYSTEM`.

### Exploit Flow

```mermaid
flowchart TD
    A[Service account with SeImpersonatePrivilege] --> B[Create named pipe\n\\.\pipe\{guid}\pipe\srvsvc]
    B --> C[Trigger EfsRpcEncryptFileSrv RPC call\nto \\localhost/PIPE/{guid}/...]
    C --> D[LSASS connects to attacker pipe\nwith SYSTEM token]
    D --> E[ImpersonateNamedPipeClient\nAcquire SYSTEM impersonation token]
    E --> F[CreateProcessAsUser\nSpawn target process as SYSTEM]
```

### Key APIs

All Win32 APIs are resolved at runtime via delegates — none appear in the PE Import Address Table except `GetModuleHandleW` and `GetProcAddress`.

| API | DLL | Role |
| --- | --- | ---- |
| `CreateNamedPipeW` | kernel32 | Create attacker-controlled pipe endpoint |
| `ConnectNamedPipe` | kernel32 | Block until LSASS connects |
| `EfsRpcEncryptFileSrv` (via `NdrClientCall2`) | Rpcrt4 | Coerce LSASS to connect to pipe |
| `ImpersonateNamedPipeClient` | advapi32 | Elevate thread to SYSTEM impersonation |
| `AdjustTokenPrivileges` | advapi32 | Enable `SeImpersonatePrivilege` on caller token |
| `CreateProcessAsUserW` | advapi32 | Spawn target process under SYSTEM token |

### Prerequisites

- Caller must hold `SeImpersonatePrivilege`
- Local privilege escalation only — RPC coercion targets `localhost`
- EFS service (`EFSSVC`) must be running on the target host
- Supported named pipe endpoints: `lsarpc`, `efsrpc`, `samr`, `lsass`, `netlogon`

---

## Files

| File | Description |
| ---- | ----------- |
| `EfsPotato.cs` | Original public source — unmodified reference |
| `CertEnrollSvc.cs` | **Obfuscated variant** used in this emulation (see below) |
| `CertEnrollSvc.exe` | Compiled obfuscated binary (x64) |
| `encode.py` | Position-dependent XOR encoder — generates byte array literals for `CertEnrollSvc.cs` |

---

## CertEnrollSvc — Obfuscated Variant

`CertEnrollSvc.cs` is a hardened version of `EfsPotato.cs` adapted for use in this adversary emulation. The following modifications were made to evade static detection by Windows Defender.

### Changes vs. original `EfsPotato.cs`

#### 1. Namespace and class rename

```
EfsPotato.cs  →  namespace CertificateServices.Enrollment
                   class CertEnrollmentAgent
```

All attribution strings (`"Exploit for EfsPotato"`, `"zcgonvh"`, `"xassiz"`, etc.) removed.

#### 2. Class `X` — position-dependent XOR codec

A static helper class `X` centralises all encoding/decoding and API resolution. Two decode functions are defined:

```csharp
// Decode byte[] → byte[]  (for MIDL stubs)
internal static byte[] D(byte[] b) {
    var r = new byte[b.Length];
    for (int i = 0; i < b.Length; i++) r[i] = (byte)(b[i] ^ (byte)(0xA3 + i * 0x5B));
    return r;
}

// Decode byte[] → string  (for string constants)
internal static string S(byte[] b) {
    var r = new byte[b.Length];
    for (int i = 0; i < b.Length; i++) r[i] = (byte)(b[i] ^ (byte)(0xA3 + i * 0x5B));
    return Encoding.UTF8.GetString(r);
}
```

Key formula: `encoded[i] = plaintext[i] ^ ((0xA3 + i × 0x5B) & 0xFF)`. Position-dependent — no single constant can be extracted by single-byte brute-force (e.g., FLOSS, CyberChef).

`encode.py` generates the C# byte array literals. Example:
```
python encode.py "SeImpersonatePrivilege" _priv
python encode.py --verify    # round-trip check for all registry entries
```

#### 3. MIDL RPC stub byte arrays — XOR encoded

The four MIDL format string arrays (`MIDL_ProcFormatStringx86/x64`, `MIDL_TypeFormatStringx86/x64`) carry the strongest static AV signatures. All four are stored XOR-encoded in class `X` as `_mps86`, `_mps64`, `_mts86`, `_mts64` and decoded at runtime via `X.D()` before being pinned for the RPC stub.

#### 4. All string constants — XOR byte arrays

Every string that was a static literal in the original is now stored as a XOR-encoded `byte[]` field in class `X` and decoded via `X.S()` at use site. This includes:

| Field | Plaintext |
| ----- | --------- |
| `_priv` | `SeImpersonatePrivilege` |
| `_desk` | `WinSta0\Default` |
| `_lpipe` | `\\localhost/PIPE/` |
| `_ep1`…`_ep5` | `lsarpc`, `efsrpc`, `samr`, `lsass`, `netlogon` |
| `_ncnp` | `ncacn_np` |
| `_lh` | `localhost` |

#### 5. MS-EFSR interface GUIDs — XOR byte arrays

Both interface GUIDs are stored as XOR-encoded byte arrays (`_g1`, `_g2`) and decoded via `X.S()` at construction time. No GUID substring appears in the binary.

```csharp
// _g1 decodes to: c681d488-d850-11d0-8c52-00c04fd90f7e  (lsarpc / samr / lsass / netlogon)
// _g2 decodes to: df1941c5-fe89-4e79-bf10-463657acf44d  (efsrpc)
```

#### 6. Dynamic API resolution — IAT reduction

All sensitive Win32 APIs are resolved at runtime via `Marshal.GetDelegateForFunctionPointer`. Only `GetModuleHandleW` and `GetProcAddress` appear in the PE Import Address Table.

```csharp
[DllImport("kernel32", EntryPoint = "GetModuleHandleW", CharSet = CharSet.Unicode)]
static extern IntPtr G(string m);
[DllImport("kernel32", EntryPoint = "GetProcAddress", CharSet = CharSet.Ansi, ExactSpelling = true)]
static extern IntPtr P(IntPtr h, string p);
```

`X.Init()` resolves 18 function pointers at startup. DLL names and all API name strings are themselves XOR-encoded (fields `_k32`, `_adv`, `_rpc`, `_fn_*`):

| Field | Plaintext API name | DLL |
| ----- | ------------------ | --- |
| `_fn_ll` | `LoadLibraryW` | kernel32 |
| `_fn_gsh` | `GetStdHandle` | kernel32 |
| `_fn_gft` | `GetFileType` | kernel32 |
| `_fn_cfw` | `CreateFileW` | kernel32 |
| `_fn_cnpw` | `CreateNamedPipeW` | kernel32 |
| `_fn_cnp` | `ConnectNamedPipe` | kernel32 |
| `_fn_ch` | `CloseHandle` | kernel32 |
| `_fn_cp` | `CreatePipe` | kernel32 |
| `_fn_inp` | `ImpersonateNamedPipeClient` | advapi32 |
| `_fn_atp` | `AdjustTokenPrivileges` | advapi32 |
| `_fn_lpv` | `LookupPrivilegeValueW` | advapi32 |
| `_fn_cpau` | `CreateProcessAsUserW` | advapi32 |
| `_fn_rbfsb` | `RpcBindingFromStringBindingW` | Rpcrt4 |
| `_fn_rbsai` | `RpcBindingSetAuthInfoW` | Rpcrt4 |
| `_fn_ncc2` | `NdrClientCall2` | Rpcrt4 |
| `_fn_rbf` | `RpcBindingFree` | Rpcrt4 |
| `_fn_rsbcw` | `RpcStringBindingComposeW` | Rpcrt4 |
| `_fn_rbso` | `RpcBindingSetOption` | Rpcrt4 |

Verification: `dumpbin /imports CertEnrollSvc.exe` shows only `GetModuleHandleW` and `GetProcAddress`.

#### 7. Method rename

`EfsRpcEncryptFileSrv()` → `InvokeEncryptionService()`

#### 8. Creation flags

`dwCreationFlags = 0x08000000` (`CREATE_NO_WINDOW`). `CREATE_BREAKAWAY_FROM_JOB` is **not** set — IIS Job Object escape is handled downstream by CWLHerpaderping's `GetNonJobParent()` which spoofs the ghost process parent to a Session 0 non-job process.

#### 9. Legitimate code padding

Four classes dilute the ratio of malicious to benign code:

- `EnrollmentConstants` — const strings matching real Windows Certificate Enrollment Policy Service metadata
- `CertificateRequestBuilder` — builds XML cert request, validates key size, formats Subject DN
- `EnrollmentLogger` — file-based logger writing to `%ProgramData%\Microsoft\CertificateServices\enrollment.log`
- `RegistryHelper` — reads `SOFTWARE\Microsoft\Cryptography\AutoEnrollment` and `SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment` registry keys

#### 10. Stdin PE delivery — temp file with deferred cleanup

If stdin is a pipe, `Main()` reads a PE using the framing format `[4-byte LE DWORD size][PE bytes]`, writes it to `Path.GetTempFileName()`, and passes the path to `CreateProcessAsUser(SYSTEM, ...)`. The temp file is deleted **after** the spawned process exits (`WaitOne(-1)`).

```csharp
if (X.pfGetFileType(hStdin) == FILE_TYPE_PIPE)
{
    // ReadFull(stdin, hdr, 4) → peSize
    // ReadFull(stdin, peBytes, peSize)
    tempFilePath  = Path.GetTempFileName();
    File.WriteAllBytes(tempFilePath, peBytes);
    targetCmdLine = tempFilePath;
}
// ...CreateProcessAsUser → WaitOne(-1) → then:
if (tempFilePath != null)
    try { File.Delete(tempFilePath); } catch { }
```

The temp file is on disk for the lifetime of the spawned process. If stdin is not a pipe, falls through to `args[0]` as the target command (Mode 2).

---

## Evasion Status

| Measure | Status |
| ------- | ------ |
| Namespace / class rename, attribution removal | ✅ Done |
| Position-dependent XOR codec (`X.S` / `X.D`) | ✅ Done |
| MIDL stub arrays XOR-encoded | ✅ Done |
| All string constants XOR-encoded | ✅ Done |
| Interface GUIDs XOR-encoded | ✅ Done |
| Dynamic API resolution (18 delegates) | ✅ Done |
| Legitimate code padding (4 classes) | ✅ Done |
| Stdin PE delivery | ✅ Done |
| ETW suppression (`EtwEventWrite` patch) | ⬜ Pending — see `evasion-roadmap.md` Phase 4 |

---

## Build

```cmd
# CertEnrollSvc (obfuscated variant, x64)
csc /target:exe /platform:x64 /optimize+ /out:CertEnrollSvc.exe CertEnrollSvc.cs -nowarn:1691,618

# Original EfsPotato (reference, x64)
csc /target:exe /platform:x64 /out:EfsPotato.exe EfsPotato.cs -nowarn:1691,618
```

## Usage

### Mode 1 — stdin pipe

If stdin is a pipe, reads PE from it and spawns it as SYSTEM. The endpoint defaults to `lsarpc`.

Stdin framing: `[4-byte LE DWORD size][PE bytes]`

```
<pe_sender> | CertEnrollSvc.exe
```

### Mode 2 — command-line argument

```
CertEnrollSvc.exe <target_cmd> [pipe]
    pipe -> lsarpc|efsrpc|samr|lsass|netlogon  (default: lsarpc)
```

Spawns `<target_cmd>` as `NT AUTHORITY\SYSTEM`.

