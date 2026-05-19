# WMI Antivirus Query

Lightweight native C++ application using WMI COM APIs to query installed antivirus products on Windows.

## Features

- Native WMI COM implementation
- Queries `root\SecurityCenter2` namespace
- Displays all installed antivirus products with details
- Parses product state to show enabled/disabled and update status
- **Small executable size: ~30-50 KB** (vs 60-80 MB for .NET)

## Requirements

- Windows OS
- **Visual Studio Build Tools** OR **MinGW-w64**
- Administrator privileges (recommended)

## Build

### Visual Studio (MSVC)

Open **Visual Studio Developer Command Prompt** or **x64 Native Tools Command Prompt**, then run:

```cmd
cd d:\vcs\discovery\WmiAvQuery
cl.exe /EHsc /O2 /MT /Fe:WmiAvQuery.exe main.cpp /link /SUBSYSTEM:CONSOLE
```

**Compiler flags explained:**
- `/EHsc` - Enable C++ exception handling
- `/O2` - Maximize speed optimization
- `/MT` - Statically link runtime (no DLL dependencies)
- `/Fe:` - Specify output executable name
- `/SUBSYSTEM:CONSOLE` - Console application

**Expected size:** ~40-50 KB

---

### MinGW-w64

Open Command Prompt with MinGW in PATH:

```cmd
cd d:\vcs\discovery\WmiAvQuery
g++ -O2 -s -static -std=c++11 -o WmiAvQuery.exe main.cpp -lwbemuuid -lole32 -loleaut32
```

**Compiler flags explained:**
- `-O2` - Optimize for speed
- `-s` - Strip debug symbols (smaller binary)
- `-static` - Static linking (standalone executable)
- `-std=c++11` - Use C++11 standard
- `-l` - Link libraries: wbemuuid, ole32, oleaut32

**Expected size:** ~30-40 KB

## Run

```cmd
WmiAvQuery.exe
```

## Example Output

```
[*] Querying installed Antivirus products using WMI COM API...

=== Antivirus Product #1 ===
  displayName: Windows Defender
  instanceGuid: {D68DDC3A-831F-4fae-9E44-DA132C1ACF46}
  pathToSignedProductExe: %ProgramFiles%\Windows Defender\MSASCui.exe
  pathToSignedReportingExe: %ProgramFiles%\Windows Defender\MsMpeng.exe
  productState: 0x401000
  Product State (Raw): 0x401000
  Status: ENABLED
  Definitions: UP-TO-DATE

[+] Total antivirus products found: 1

[*] Query completed.
```

## Technical Details

Uses native Windows COM APIs:
- `IWbemLocator` - WMI locator interface
- `IWbemServices` - WMI services interface  
- `IEnumWbemClassObject` - Result enumeration
- Queries `AntiVirusProduct` class from `root\SecurityCenter2`

## Advantages over .NET version

- **30-50 KB** executable (vs 60-80 MB for .NET standalone)
- No runtime dependencies
- Direct native API calls
- Faster startup time
- Smaller memory footprint

## Notes

- Some AV products may not register in SecurityCenter2
- Requires Windows Vista or later (for SecurityCenter2 namespace)
- Administrator privileges recommended for full access
