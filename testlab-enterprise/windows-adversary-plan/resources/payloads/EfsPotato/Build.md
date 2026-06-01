# CertEnrollSvc — Build

**Toolchain:** C# via `csc` (Visual Studio Build Tools) — must be invoked from the Visual Studio Developer Command Prompt; see `plan-for-agent/guides/cli-execution.md`

## Build

From the `EfsPotato/` payload directory inside a VS Developer Command Prompt:

```cmd
csc /target:exe /platform:x64 /optimize+ /out:CertEnrollSvc.exe CertEnrollSvc.cs -nowarn:1691,618
```

## Options

| Flag | Purpose |
| ---- | ------- |
| `/platform:x64` | Target 64-bit only — the indirect syscall engine (Halo's Gate + `syscall;ret` trampoline) is x64-exclusive and is skipped on x86 |
| `/optimize+` | Dead-code elimination removes all `[Conditional("DEBUG")]` debug log call sites and their string literal arguments from the release binary |
| `-nowarn:1691` | Suppress CS1691 (unrecognised warning number) — emitted by some csc versions |
| `-nowarn:618` | Suppress CS0618 (obsolete API) — covers `Thread.Abort()` used in the output-relay thread |

## Output

- **Artifact:** `CertEnrollSvc.exe` — x64 PE, single self-contained binary
- **Dev-env verify:** Run the binary with no arguments from cmd — it exits silently (no args → `return` at line 544), confirming clean startup without triggering exploit behavior

```cmd
CertEnrollSvc.exe
REM exits with no output — expected
```

## Reference (original EfsPotato)

```cmd
csc /target:exe /platform:x64 /out:EfsPotato.exe EfsPotato.cs -nowarn:1691,618
```

`EfsPotato.cs` is the unmodified public reference — kept for diff purposes only, not used in the emulation.
