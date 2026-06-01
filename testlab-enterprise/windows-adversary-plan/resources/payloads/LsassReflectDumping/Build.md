# LsassReflectDumping — Build

**Toolchain:** MSVC 14.x (Visual Studio 2022, v143 toolset, Desktop development with C++ workload, Windows 10/11 SDK) — see `plan-for-agent/guides/cli-execution.md`

## Build

**Option A — x64 Native Tools Command Prompt for VS 2022:**

```cmd
cd testlab-enterprise\windows-adversary-plan\resources\payloads\LsassReflectDumping\ReflectDump
msbuild ReflectDump.sln /p:Configuration=Release /p:Platform=x64 /m
```

**Option B — PowerShell (no Developer Command Prompt required):**

```powershell
$vs  = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
           -latest -products * -requires Microsoft.Component.MSBuild `
           -property installationPath
$msb = Join-Path $vs 'MSBuild\Current\Bin\MSBuild.exe'
& $msb 'testlab-enterprise\windows-adversary-plan\resources\payloads\LsassReflectDumping\ReflectDump\ReflectDump.sln' `
       /p:Configuration=Release /p:Platform=x64 /m
```

**Option C — devenv (GUI build from CLI):**

```cmd
devenv testlab-enterprise\windows-adversary-plan\resources\payloads\LsassReflectDumping\ReflectDump\ReflectDump.sln /Build "Release|x64"
```

## Options

| Flag | Effect |
|---|---|
| `/p:Configuration=Release` | Optimized build, no debug symbols |
| `/p:Platform=x64` | 64-bit output — required for LSASS on modern Windows |

## Clean

```cmd
msbuild ReflectDump.sln /t:Clean /p:Configuration=Release /p:Platform=x64
```

## Output

- **Artifact:** `ReflectDump\x64\Release\ReflectDump.exe`

## Dev-env verify

Run after each build before deploying to the lab:

```cmd
:: 1. dbghelp.dll must NOT appear — it is resolved at runtime via LoadLibraryA
dumpbin /imports ReflectDump\x64\Release\ReflectDump.exe | findstr /i dbghelp

:: 2. VS_VERSION_INFO from ReflectDump.rc must be present
dumpbin /headers ReflectDump\x64\Release\ReflectDump.exe | findstr /i "version"

:: 3. Lab Defender scan before deployment
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File "%CD%\ReflectDump\x64\Release\ReflectDump.exe"
```

Step 1 must print nothing. If `dbghelp.dll` appears, the static `#pragma comment(lib, "Dbghelp.lib")` has been re-introduced.
