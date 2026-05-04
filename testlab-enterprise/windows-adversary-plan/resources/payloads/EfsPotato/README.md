# EfsPotato — Privilege Escalation via MS-EFSR Named Pipe Impersonation

**MITRE ATT&CK:** T1134.001 — Access Token Manipulation: Token Impersonation/Theft  
**CVE:** CVE-2021-36942 (patch bypass via `EfsRpcEncryptFileSrv`)  
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

| API | Role |
| --- | ---- |
| `CreateNamedPipe` | Create attacker-controlled pipe endpoint |
| `EfsRpcEncryptFileSrv` (via `NdrClientCall2`) | Coerce LSASS to connect to pipe |
| `ImpersonateNamedPipeClient` | Elevate thread to SYSTEM impersonation |
| `CreateProcessAsUser` | Spawn process under SYSTEM token |

### Prerequisites

- Caller must hold `SeImpersonatePrivilege`
- Target is **local privilege escalation only** (localhost RPC)
- Works on unpatched systems; CVE-2021-36942 patch bypass via `EfsRpcEncryptFileSrv` method (vs. original `EfsRpcOpenFileRaw`)
- Supported named pipe endpoints: `lsarpc`, `efsrpc`, `samr`, `lsass`, `netlogon`

---

## Files

| File | Description |
| ---- | ----------- |
| `EfsPotato.cs` | Original public source — unmodified reference |
| `CertEnrollSvc.cs` | **Obfuscated variant** used in this emulation (see below) |
| `CertEnrollSvc.exe` | Compiled obfuscated binary |

---

## CertEnrollSvc — Obfuscated Variant

`CertEnrollSvc.cs` is a hardened version of `EfsPotato.cs` adapted for use in this adversary emulation. The following modifications were made to evade static detection by Windows Defender.

### Changes vs. original `EfsPotato.cs`

#### 1. Namespace and class rename

```
EfsPotato.cs         → namespace CertificateServices.Enrollment
                         class CertEnrollmentAgent
```

Removed all attribution strings (`"Exploit for EfsPotato"`, `"zcgonvh"`, `"CVE-2021-36942"`, `"xassiz"`, etc.).

#### 2. MIDL RPC stub byte arrays — XOR encoded

The most distinctive static signature: the `MIDL_ProcFormatString` and `MIDL_TypeFormatString` byte arrays are stored verbatim in the original binary, directly matching AV signatures for the MS-EFSR RPC stub.

**Fix:** XOR-encode all four arrays with key `0x41`; add inline `Xd()` decoder called at runtime.

```csharp
private static byte[] Xd(byte[] b) {
    byte[] r = new byte[b.Length];
    for (int i = 0; i < b.Length; i++) r[i] = (byte)(b[i] ^ 0x41);
    return r;
}
private static byte[] MIDL_ProcFormatStringx64 => Xd(new byte[] { 0x41, 0x41, ... });
```

#### 3. Sensitive string literals — runtime assembly via char array

| Original string | Obfuscation method |
| --------------- | ------------------ |
| `"SeImpersonatePrivilege"` | `new string(new char[]{'S','e','I',...})` |
| `"WinSta0\Default"` | `new string(new char[]{'W','i','n',...})` |
| `"\\localhost/PIPE/"` | `new string(new char[]{'\\','\\','l',...})` |

#### 4. MS-EFSR interface GUIDs — split string concatenation

```csharp
string g1 = "c681d488-d850-11d0-" + "8c52-00c04fd90f7e";
string g2 = "df1941c5-fe89-4e79-" + "bf10-463657acf44d";
```

Prevents the full GUID from appearing as a contiguous string in the binary.

#### 5. Method rename

`EfsRpcEncryptFileSrv()` → `InvokeEncryptionService()`

#### 6. `CREATE_BREAKAWAY_FROM_JOB` flag

`dwCreationFlags` changed from `0x08000000` (`CREATE_NO_WINDOW`) to `0x09000000` (`CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB`) to allow the spawned process to escape IIS Job Object constraints.

#### 7. Legitimate code padding

Added three classes to dilute the ratio of malicious to benign code:

- `EnrollmentConstants` — const strings matching real Windows cert enrollment service metadata
- `CertificateRequestBuilder` — builds XML cert request, reads key size/template params
- `EnrollmentLogger` — file-based logger writing to `%ProgramData%\Microsoft\CertificateServices\enrollment.log`
- `RegistryHelper` — reads `SOFTWARE\Microsoft\Cryptography\AutoEnrollment` registry keys

---

## Build

```cmd
# CertEnrollSvc (obfuscated variant, x64)
csc /target:exe /platform:x64 /optimize+ /out:CertEnrollSvc.exe CertEnrollSvc.cs -nowarn:1691,618

# Original EfsPotato (reference, x64)
csc /target:exe /platform:x64 /out:EfsPotato.exe EfsPotato.cs -nowarn:1691,618
```

## Usage

```
CertEnrollSvc.exe <cmd> [pipe]
    pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)
```

**In this emulation:**
```
C:\Windows\Temp\CertEnrollSvc.exe C:\ProgramData\CertEnrollAgent.exe
```
Spawns `CertEnrollAgent.exe` (CWLHerpaderping) as `NT AUTHORITY\SYSTEM`.

