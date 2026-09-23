# FwPolicySvc — Build

**Toolchain:** C# via `csc` (Visual Studio Build Tools) — `csc` is only on `PATH` inside a Visual Studio Developer Command Prompt (`VsDevCmd.bat`).

## Build

From the `FwPolicySvc/` payload directory, inside a VS Developer Command Prompt:

```cmd
csc /target:exe /optimize+ /debug- /out:FwPolicySvc.exe FwPolicySvc.cs
```

If you prefer to open a shell and source the environment yourself:

```cmd
call "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64
csc /target:exe /optimize+ /debug- /out:FwPolicySvc.exe FwPolicySvc.cs
```

## On-target build (framework `csc`)

Windows Server 2022 ships .NET Framework 4.8 — the tool can also be built in place on the host:

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /optimize+ /debug- /out:FwPolicySvc.exe FwPolicySvc.cs
```

## Options

| Flag | Purpose |
| ---- | ------- |
| `/target:exe` | Console executable (managed PE) |
| `/optimize+` | Release code optimization |
| `/debug-` | No PDB emitted — keeps the artifact a single self-contained file |

No external references are required: the firewall API is reached through late-bound COM (`Type.GetTypeFromProgID` + `InvokeMember`), so `NetFwTypeLib` / `Microsoft.CSharp` are not referenced.

## String re-encode

`encode.py` regenerates the XOR byte-array literals for the COM ProgIDs if they are ever changed:

```cmd
python encode.py
python encode.py --verify
```

## Output

- **Artifact:** `FwPolicySvc.exe` — managed PE (anycpu), single file, ~9.5 KB (`/optimize+ /debug-`)
- **Dev-env verify:** run with no arguments — prints usage and exits `2`, no firewall change is made:

```cmd
FwPolicySvc.exe
```

## Runtime gotcha

The firewall API is reached by late-bound COM, so the binding flag per member matters: `Rules` is a `propget` (`BindingFlags.GetProperty`), while `Item` / `Add` / `Remove` are methods (`BindingFlags.InvokeMethod`). A mismatch fails with `DISP_E_MEMBERNOTFOUND (0x80020003)`. See `README.md` → *COM late-binding notes* before changing any `Get` / `Set` / `Call` usage.

## Status

Lab-verified on IIS01 (Windows Server 2022) as `NT AUTHORITY\SYSTEM` via the EfsPotato chain — see `README.md` → *Verification status*.
