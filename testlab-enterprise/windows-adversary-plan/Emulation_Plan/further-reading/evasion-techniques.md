# Evasion Techniques — Payload Summary

This document collects and cross-references the evasion techniques used across all payloads referenced in this emulation plan. Each section covers one evasion category, listing which payload implements it and how. A per-payload quick-reference matrix appears at the end.

**Payloads covered:**

| Short name | Source | Further reading |
|---|---|---|
| `CWLHerpaderping` | `resources/payloads/CWLHerpaderping/` | `process-herpaderping.md` |
| `EfsPotato/CertEnrollSvc` | `resources/payloads/EfsPotato/` | `efspotato.md` |
| `react2shell-tool` | `resources/payloads/react2shell-tool/` | `rce-react2shell.md` |
| `go-thehash` | `resources/payloads/go-thehash/` | `go-thehash.md` |
| `dnscat2 go-client` | `resources/payloads/dnscat2/go-client/` | `dnscat2.md` |
| `LsassReflectDumping` | `resources/payloads/LsassReflectDumping/` | `LsassReflectDumping/README.md` |
| `NtdsRawDump` | `resources/payloads/NtdsRawDump/` | `NtdsRawDump/README.md` |

---

## 1. Static Signature Evasion

### 1.1 Compile-time string obfuscation

**Payload: CWLHerpaderping**

`obfstr.h` provides `OBFSTR()` / `OBFWSTR()` macros that XOR-obfuscate string literals at compile time using a position-dependent key: `key(i) = (0xA3 + i × 0x5B) & 0xFF` — single-byte brute-force (FLOSS) cannot recover the plaintext. Sensitive strings — `svchost.exe`, `wininit.exe`, `kernel32.dll`, `C:\Windows\System32\RuntimeBroker.exe`, `C:\Windows\System32` — are stored as encrypted byte arrays in the binary. Each string is decrypted into a `thread_local` buffer at the call site. In Release builds (`/p:CWLDebug` not set), `perror` is suppressed via macro (`#define perror(x) ((void)0)`) — all error-path string literals are unreferenced and omitted from `.rdata`. No plaintext sensitive string appears as a contiguous literal in the PE on disk.

**Payload: EfsPotato/CertEnrollSvc**

Sensitive strings are stored as XOR-encoded byte arrays in class `X` and decoded at runtime via `X.S()`. Key formula: `plaintext[i] = encoded[i] ^ ((0xA3 + i × 0x5B) & 0xFF)` — same position-dependent formula as CWLHerpaderping and NtdsRawDump; single-byte brute-force yields nothing. Encoded strings include `SeImpersonatePrivilege`, `\\localhost/PIPE/`, `WinSta0\Default`, the EFSRPC endpoint names, both MS-EFSR interface GUIDs, and all DLL/API name strings. The approach prevents signature matching against known EfsPotato strings at the binary level.

**Payload: NtdsRawDump**

All IOC strings are stored as XOR-encoded byte arrays with a position-dependent key: `plaintext[i] = encoded[i] ^ ((0xA3 + i * 0x5B) & 0xFF)`. Encoded strings include `Win32_ShadowCopy`, `\\.\root\cimv2`, NTDS/hive paths, output filenames, and `kernel32.dll` export names. The position-dependent key prevents single-byte brute-force recovery and defeats tools like FLOSS that assume a fixed key constant.

**ATT&CK:** `T1027` Obfuscated Files or Information; `T1027.002` Software Packing (compile-time encoding)

---

### 1.2 Runtime MIDL byte array encoding

**Payload: EfsPotato/CertEnrollSvc**

The MIDL format strings for the `EfsRpcEncryptFileSrv`-compatible RPC call are XOR-encoded with the position-dependent key `(0xA3 + i × 0x5B) & 0xFF` and stored as byte array fields (`_mps86`, `_mps64`, `_mts86`, `_mts64`) in class `X`. They are decoded at runtime via `X.D()` before being pinned for the RPC stub. Static signatures tuned to the known public EfsPotato MIDL byte sequences will not match the encoded variant.

**ATT&CK:** `T1027` Obfuscated Files or Information

---

### 1.3 Payload compression

**Payload: react2shell-tool**

`compress_payload.py` compresses tool payloads with gzip at level 9 before upload, typically achieving ~62% size reduction. An optional `--b64` flag base64-encodes the compressed output. The target-side `decompress` command uses Node.js `zlib.gunzipSync()` to restore the original binary in-process without spawning a child process. Raw PE magic bytes (`MZ`, `PE\0\0`) are not present in the uploaded `.gz.b64` artifact.

**ATT&CK:** `T1027.015` Obfuscated Files or Information: Compression

---

### 1.4 Masquerade namespace and benign padding

**Payload: EfsPotato/CertEnrollSvc**

The exploit binary uses the namespace `CertificateServices.Enrollment` and entry class `CertEnrollmentAgent` instead of the public `Zcg.Exploits.Local.EfsPotato`. Non-operational classes (`EnrollmentConstants`, `CertificateRequestBuilder`, `EnrollmentLogger`, `RegistryHelper`) provide certificate-enrollment-themed context visible in static analysis. The EFSRPC method is renamed `InvokeEncryptionService` instead of `EfsRpcEncryptFileSrv`. Console banner and attribution strings are removed. The binary runs mostly silently — child stdout/stderr are redirected to an anonymous pipe but not printed.

**ATT&CK:** `T1036` Masquerading

---

## 2. Dynamic API Resolution and Indirect Syscalls

### 2.1 PEB walk + DJB2 hash-based ntdll API resolution

**Payload: CWLHerpaderping**

`api_hash.h` resolves ntdll APIs without `GetProcAddress("ApiName")`. The code finds the `ntdll` base through a PEB walk (`GetNtdllBase()`), parses the Export Address Table, and hashes each export name with DJB2, comparing against compile-time constants in `ApiHash::`. APIs resolved this way include `EtwEventWrite`, `NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`, `NtQueryInformationProcess`, `NtSetInformationProcess`, `RtlCreateProcessParametersEx`, `RtlInitUnicodeString`, `RtlImageNtHeader`, and `NtReadVirtualMemory`. No API name string appears at call sites; the import table does not reference these symbols.

**ATT&CK:** `T1027.007` Obfuscated Files or Information: Dynamic API Resolution

---

### 2.2 IAT reduction via runtime GetProcAddress

**Payload: NtdsRawDump**

`CreateFileW`, `DeviceIoControl`, `ReadFile`, `SetFilePointerEx`, `GetFileSizeEx`, and `CloseHandle` are not present in the PE Import Address Table. The binary imports only `GetModuleHandleW` and `GetProcAddress`; all operational Win32 APIs are resolved at runtime using decoded name strings (see §1.1). This eliminates the most common IAT indicators inspected by AV/EDR import scanners.

**ATT&CK:** `T1027.007` Obfuscated Files or Information: Dynamic API Resolution

---

### 2.3 Indirect syscalls with Halo's Gate SSN resolution

**Payload: CWLHerpaderping**

`syscall.h` builds runtime stubs for five sensitive NT APIs (`NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`). Each stub is built as:

```asm
mov r10, rcx
mov eax, <SSN>
movabs r11, <gadget>
jmp r11
```

The SSN is read directly from the ntdll stub. If the stub is hooked (first bytes modified), Halo's Gate infers the SSN from adjacent unhooked stubs. The gadget is a `syscall; ret` instruction found in the `.text` section of `ntdll`. Syscalls therefore originate through the `ntdll` text section, not through the loader's own code, defeating call-stack origin checks. After the stubs are written, the page is flipped to `PAGE_EXECUTE_READ` to avoid a long-lived RWX region.

**ATT&CK:** `T1106` Native API

---

### 2.4 Stack spoofing

**Payload: CWLHerpaderping**

`StackSpoof.cpp::StackSpoofer` wraps every indirect syscall with a fake return address:

1. `_AddressOfReturnAddress()` locates the current return address on the stack.
2. `FindReturnAddressGadget("kernel32.dll")` finds a return/epilogue gadget inside `kernel32.dll`.
3. `Activate()` replaces the return address with the `kernel32.dll` gadget before the syscall.
4. `Deactivate()` restores the original return address afterward.

During the syscall, a kernel-mode stack walk or ETW provider inspecting the call chain sees `kernel32.dll` as the return target rather than the loader's own code region.

Wrapped calls: `NtCreateProcessEx` only. The other four indirect syscalls (`NtCreateSection`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`) are not stack-spoofed.

**ATT&CK:** `T1106` Native API (stack masking behavior)

---

## 3. Defense Tool Tampering

### 3.1 ETW patch in loader process

**Payload: CWLHerpaderping**

`PatchEtw()` is the first call in `main()`. It resolves `ntdll!EtwEventWrite` via API hash, changes the page protection to writable, and patches the first three bytes to `xor eax, eax; ret`. This makes the loader process return immediate success for any internal ETW write before NT API calls that would otherwise generate telemetry through ETW providers. The patch occurs in the loader's own process memory only.

**Observable artifacts:** `VirtualProtect` on an `ntdll.dll` code region; modified bytes at `ntdll!EtwEventWrite`; no ETW events from the loader process for subsequent NT operations.

**ATT&CK:** `T1562.006` Impair Defenses: Indicator Blocking

---

### 3.2 File-system minifilter bypass via raw VSS reads

**Payload: NtdsRawDump**

Security products that attach as file-system minifilters (e.g. `WdFilter.sys`) intercept `IRP_MJ_READ` callbacks on paths matching `*\ntds.dit` and registry hive paths. `NtdsRawDump` avoids triggering these callbacks through the following sequence:

1. Opens each target file via its VSS shadow path **only to call `FSCTL_GET_RETRIEVAL_POINTERS`** — retrieves the NTFS cluster map without reading file data.
2. Closes the file handle immediately after the cluster map is obtained.
3. Opens the **shadow volume device** (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`) as a raw block device. Reads go directly to the storage driver stack, below the file-system minifilter layer — no `IRP_MJ_READ` on the NTDS or hive path is ever issued.
4. Reads file clusters at raw byte offsets (`LCN × BytesPerCluster`) via `ReadFile` on the volume device handle.

**ATT&CK:** `T1003.003` OS Credential Dumping: NTDS (evasion of minifilter-based detection)

---

## 4. Memory-Only and Reflective Loading

### 4.1 Reflective payload loading via stdin pipe (no disk artifact)

**Payload: CWLHerpaderping (Mode 1)**

When `GetFileType(STD_INPUT_HANDLE) == FILE_TYPE_PIPE`, the loader detects piped input and switches to reflective mode. It reads a 4-byte size header from stdin, allocates heap memory with `VirtualAlloc`, and reads the payload bytes directly from stdin. The `PAYLOAD_PATH` file path is bypassed entirely. The PE payload never touches disk before being mapped.

**Payload: react2shell-tool (herpload)**

The `herpload` command reads a local base64 file, decodes it to a `Buffer`, prepends a 4-byte little-endian size header, then calls `child_process.spawnSync(loader_exe, [], {input: size_header + payload_bytes})`. The loader receives the PE over its stdin pipe. No binary disk artifact is written to the target beyond the base64 text file already staged.

**ATT&CK:** `T1620` Reflective Code Loading

---

### 4.2 In-memory encryption before disk write

**Payload: NtdsRawDump**

AES-256-CBC encryption (`AesCryptoServiceProvider`, delegated to Windows CNG `bcrypt.dll`) is applied to each credential buffer in memory before any disk write. A random IV is generated per call and prepended to the ciphertext. The in-memory ZIP archive is also AES-encrypted before being flushed as `certstore.tmp`. Output `.tmp` files contain no NTDS magic bytes, no hive signatures, and no ZIP `PK` header. No intermediate plaintext or zip file ever touches disk.

**ATT&CK:** `T1027` Obfuscated Files or Information (in-memory encryption before disk I/O)

---

### 4.3 Process forking for LSASS dump (clone, not live process)

**Payload: LsassReflectDumping**

Instead of calling `MiniDumpWriteDump` against the live `lsass.exe` process — a well-monitored EDR hook target — the tool uses `RtlCreateProcessReflection` to fork `lsass.exe` into a clone process. The memory dump is then generated from the clone using `MINIDUMP_CALLBACK_INFORMATION` callbacks. The cloned process is terminated after the dump. Because the dump I/O happens against a forked reflection rather than the real lsass PID, EDR hooks on `MiniDumpWriteDump` for the primary lsass handle may not fire.

**ATT&CK:** `T1003.001` OS Credential Dumping: LSASS Memory (process fork evasion path)

---

## 5. Process and Identity Spoofing

### 5.1 Parent process ID (PPID) spoofing

**Payload: CWLHerpaderping**

`GetNonJobParent()` enumerates running processes with `CreateToolhelp32Snapshot` and opens a Session 0 process (`svchost.exe` preferred, `wininit.exe` fallback) with `PROCESS_CREATE_PROCESS`. This handle is passed to `NtCreateProcessEx` as the parent, so the ghost process appears in the process tree as a child of `svchost.exe` or `wininit.exe` rather than the real loader. The token is corrected afterward (see §5.2) so the ghost process retains the caller's privileges.

**ATT&CK:** `T1134.004` Access Token Manipulation: Parent PID Spoofing

---

### 5.2 Process parameter (PEB) spoofing

**Payload: CWLHerpaderping**

After creating the ghost process, the loader calls `RtlCreateProcessParametersEx` with:

```
ImagePathName = C:\Windows\System32\RuntimeBroker.exe
DllPath       = C:\Windows\System32
```

It allocates remote memory in the ghost process with `NtAllocateVirtualMemory`, writes the spoofed parameters with `NtWriteVirtualMemory`, and patches `PEB->ProcessParameters` with `WriteProcessMemory`. Process listing tools, EDR process metadata queries, and SIEM data sources that report `ImagePathName` from the PEB will show `RuntimeBroker.exe` rather than any loader-related path. The actual memory image is the dnscat2 payload mapped from the image section.

**ATT&CK:** `T1564.010` Hide Artifacts: Process Argument Spoofing; `T1036.005` Masquerading: Match Legitimate Name or Location

---

### 5.3 Process herpaderping — disk/memory image mismatch

**Payload: CWLHerpaderping**

The core herpaderping technique:

1. The PE payload is written to a temp file (`%TEMP%\HD*.tmp`), created with `FILE_ATTRIBUTE_HIDDEN` — hidden from Explorer and basic `dir` output; MFT enumeration required to observe.
2. `NtCreateSection(..., SEC_IMAGE, hTemp)` maps the PE as an image section.
3. `NtCreateProcessEx(section, parent)` creates the ghost process from the section.
4. The temp file is then overwritten in-place with rotating IIS W3SVC log lines via the pre-held `hTemp` handle (`loop until totalWritten >= payloadSize`) — no file reopen needed. The file stays on disk after `CloseHandle(hTemp)` because the active `SEC_IMAGE` section blocks deletion (`STATUS_CANNOT_DELETE 0xC0000121`).

Because the process is created from the section before the file is overwritten, the in-memory image still contains the original PE payload while the backing file on disk contains IIS log content. Security products that scan a process by re-reading its image file from disk will not see the real payload.

**ATT&CK:** `T1055` Process Injection (process herpaderping variant)

---

### 5.4 Token manipulation (ImpersonateNamedPipeClient)

**Payload: EfsPotato/CertEnrollSvc**

The exploit creates a named pipe at `\\.\pipe\{GUID}\pipe\srvsvc` and coerces the Windows EFSRPC service to connect to it by calling the renamed `EfsRpcEncryptFileSrv`-compatible method with the attacker-controlled pipe path. When the RPC server connects, the impersonation sequence uses indirect syscalls to avoid advapi32 hooks: `NtFsControlFile(FSCTL_PIPE_IMPERSONATE)` → `NtOpenThreadToken` → `NtDuplicateToken` (impersonation → primary token). `CreateProcessWithTokenW()` then spawns the requested command with the duplicated SYSTEM token via seclogon. `ImpersonateNamedPipeClient` is only a Win32 fallback path (non-x64 or SSN resolution failure). The `SeImpersonatePrivilege` is required and is enabled via `AdjustTokenPrivileges` (it is already present on IIS AppPool accounts).

**ATT&CK:** `T1134.001` Access Token Manipulation: Token Impersonation/Theft; `T1134.002` Create Process with Token

---

## 6. Credential Access Evasion

### 6.1 Pass-the-Hash without Windows SSPI

**Payload: go-thehash**

`go-thehash` implements NTLM authentication entirely in-process using the vendored `go-smb` library. The tool accepts a raw 32-character NT hash and builds `spnego.NTLMInitiator{User, Domain, Hash}` without calling any Windows credential API, `LsaLogonUser`, or Windows SSPI. This means the authentication does not go through `lsass.exe` on the operator machine and does not require a plaintext password or a credential stored in Windows Credential Manager.

**ATT&CK:** `T1550.002` Use Alternate Authentication Material: Pass the Hash

---

### 6.2 WMI execution instead of SCM (no service artifact path)

**Payload: go-thehash**

The `exec-wmi` subcommand authenticates via DCOM/WMI with `Win32_Process.Create` rather than creating a transient Windows service. Unlike the `exec` (SCMR) path, WMI execution leaves no Event ID `7045` service-installation log entry and creates no transient service object in the SCM database.

**ATT&CK:** `T1047` Windows Management Instrumentation

---

## 7. Network and Protocol Evasion

### 7.1 DNS-tunneled C2 with encryption

**Payload: dnscat2 go-client**

Command-and-control traffic is encoded into DNS queries across TXT, CNAME, MX, A, and AAAA record types. Data is hex-encoded and split into DNS labels (≤62 chars each), then prefixed with the configured domain. The server responds inside DNS answer records. At the application layer the session is encrypted with ECDH P-256 key exchange, Salsa20 stream cipher, and SHA3 MAC. A pre-shared secret can be added for mutual authentication. All C2 traffic is therefore:

- Carried entirely over UDP port 53 (standard DNS)
- Indistinguishable at the protocol layer from legitimate recursive DNS queries
- Encrypted and MACed at the session layer — payload bytes are not visible to passive inspection

**ATT&CK:** `T1071.004` Application Layer Protocol: DNS; `T1573.001` Encrypted Channel: Symmetric Cryptography; `T1573.002` Encrypted Channel: Asymmetric Cryptography

---

### 7.2 Registry-based C2 configuration (no config file on disk)

**Payload: dnscat2 go-client (service mode)**

When running as a Windows service, `dnscat-service` reads all configuration from:

```
HKLM\SYSTEM\CurrentControlSet\Services\dnscat2\Parameters
```

No plaintext configuration file is written to disk. Domain, DNS server, port, record types, and PSK are stored in the registry under the service key — a location expected to hold service metadata, not C2 parameters.

**ATT&CK:** `T1112` Modify Registry (configuration storage evasion)

---

### 7.3 Output exfiltration via HTTP response header

**Payload: react2shell-tool**

Command output is not returned in the HTTP response body. The injected JavaScript converts output to base64 and throws a Next.js redirect-shaped error:

```
NEXT_REDIRECT;push;/login?a=<base64>;307;
```

The exploit engine reads `X-Action-Redirect`, extracts `/login?a=...`, URL-decodes, and base64-decodes. Network inspection tools that log response bodies but not response headers will miss the exfiltrated data.

**ATT&CK:** `T1041` Exfiltration Over C2 Channel; response-header side-channel behavior

---

### 7.4 In-process Node.js recon (no child process spawning)

**Payload: react2shell-tool**

Recon commands (`sysinfo`, `ipconfig`, `env`, `domain`, `ls`, `readfile`) and file operations (`upload`, `decode`, `decompress`, `copyfile`, `rename`, `download`) execute through the eval path using Node.js built-in APIs (`os`, `fs`, `dns`, `zlib`, `path`, `process.env`). No child process is spawned. EDR telemetry that correlates suspicious behavior to child process trees from the web server process will not see these activities — they appear as in-process JavaScript evaluation within `node.exe`.

**ATT&CK:** `T1059.007` Command and Scripting Interpreter: JavaScript (in-process, no child process)

---

### 7.5 Static Go binary — no interpreter dependency

**Payload: go-thehash**

`go-thehash` is compiled as a static Go binary with no external DLL dependencies. It does not require `powershell.exe`, `wscript.exe`, `cscript.exe`, or any scripting host. EDR rules targeting interpreter-based lateral movement (PowerShell Remoting, WMI via WScript) will not fire on this path.

---

## 8. Artifact Minimization

### 8.1 File deletion after payload read

**Payload: CWLHerpaderping (Mode 2)**

When stdin is not redirected, the loader reads the PE from `PAYLOAD_PATH` (e.g. `C:\ProgramData\CertCA.bin`) into heap memory, then calls `DeleteFileW(PAYLOAD_PATH)` before the herpaderping flow begins. The PE is in heap memory when it is mapped; the file no longer exists by the time the ghost process is running.

**ATT&CK:** `T1070.004` Indicator Removal: File Deletion

---

### 8.2 Transient service deletion after SCM execution

**Payload: go-thehash**

The `exec` subcommand uses `CreateService` → `StartService` → `DeleteService` in sequence. The service is deleted immediately after launch, so the SCM service object does not persist. A 12-character random lowercase service name (`randName(12)`) limits the value of name-based signature matching. Event ID `7045` may still log the creation.

---

### 8.3 Base64 encode → decode → rename staging pattern

**Payload: react2shell-tool**

Binary payloads are uploaded through the exploit channel as base64 text (`.b64`), decoded to binary on the target (`.bin`), then renamed to `.exe`. The `.b64` file contains no PE magic bytes and passes as plain text during upload. Intermediate `.b64` and `.bin` files persist briefly but are cleaned in Cleanup.

---

## 9. Payload Quick Reference Matrix

| Evasion Technique | CWLHerpaderping | EfsPotato/CertEnrollSvc | react2shell-tool | go-thehash | dnscat2 | LsassReflectDumping | NtdsRawDump |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Compile-time string obfuscation | ✓ | ✓ (XOR position-key) | — | — | — | — | ✓ (XOR position-key) |
| Runtime MIDL/byte decoding | — | ✓ (XOR 0x41) | — | — | — | — | — |
| Payload compression (gzip) | — | — | ✓ | — | — | — | — |
| IAT reduction / dynamic resolution | ✓ (DJB2 hash) | — | — | — | — | — | ✓ (GetProcAddress) |
| Indirect syscalls | ✓ (Halo's Gate, 5 NT APIs) | ✓ (3 trampolines: NtFsControlFile, NtOpenThreadToken, NtDuplicateToken) | — | — | — | — | — |
| Stack spoofing | ✓ | — | — | — | — | — | — |
| ETW patch | ✓ | — | — | — | — | — | — |
| File-system minifilter bypass | — | — | — | — | — | — | ✓ (raw VSS read) |
| Reflective loading (no disk PE) | ✓ (Mode 1) | — | ✓ (herpload) | — | — | — | — |
| In-memory encryption before disk | — | — | — | — | — | — | ✓ (AES-256-CBC) |
| Process fork / LSASS clone | — | — | — | — | — | ✓ (RtlCreateProcessReflection) | — |
| PPID spoofing | ✓ | — | — | — | — | — | — |
| PEB / process parameter spoofing | ✓ | — | — | — | — | — | — |
| Disk/memory image mismatch (herpaderping) | ✓ | — | — | — | — | — | — |
| Token impersonation (named pipe) | — | ✓ | — | — | — | — | — |
| Masquerade namespace / filename | ✓ (RuntimeBroker) | ✓ (CertEnrollSvc) | — | — | — | — | — |
| Pass-the-Hash (no SSPI / no plaintext) | — | — | — | ✓ | — | — | — |
| WMI execution (no SCM artifact) | — | — | — | ✓ | — | — | — |
| DNS-tunneled C2 | — | — | — | — | ✓ | — | — |
| Session-layer encryption (ECDH+Salsa20) | — | — | — | — | ✓ | — | — |
| Registry-based C2 config | — | — | — | — | ✓ | — | — |
| Output via HTTP response header | — | — | ✓ | — | — | — | — |
| In-process recon (no child process) | — | — | ✓ | — | — | — | — |
| File deletion after payload read | ✓ (Mode 2) | — | — | — | — | — | — |
| Hidden file attribute (`FILE_ATTRIBUTE_HIDDEN`) | ✓ (HD*.tmp) | — | — | — | — | — | — |
| Transient service deletion | — | — | — | ✓ | — | — | — |
| Base64 staging (no raw PE on wire) | — | — | ✓ | — | — | — | — |

---

## ATT&CK Technique Index

| Technique | Description | Payload(s) |
|---|---|---|
| `T1003.001` | OS Credential Dumping: LSASS Memory | LsassReflectDumping |
| `T1003.003` | OS Credential Dumping: NTDS | NtdsRawDump |
| `T1027` | Obfuscated Files or Information | CWLHerpaderping, EfsPotato, NtdsRawDump |
| `T1027.002` | Software Packing (compile-time encoding) | CWLHerpaderping |
| `T1027.007` | Dynamic API Resolution | CWLHerpaderping, NtdsRawDump |
| `T1027.015` | Compression | react2shell-tool |
| `T1036` | Masquerading | EfsPotato/CertEnrollSvc |
| `T1036.005` | Match Legitimate Name or Location | CWLHerpaderping (RuntimeBroker) |
| `T1047` | Windows Management Instrumentation | go-thehash |
| `T1055` | Process Injection (herpaderping) | CWLHerpaderping |
| `T1059.007` | Command and Scripting Interpreter: JavaScript | react2shell-tool |
| `T1071.004` | Application Layer Protocol: DNS | dnscat2 |
| `T1106` | Native API | CWLHerpaderping, EfsPotato/CertEnrollSvc |
| `T1112` | Modify Registry (C2 config) | dnscat2 |
| `T1134.001` | Token Impersonation/Theft | EfsPotato/CertEnrollSvc |
| `T1134.002` | Create Process with Token | EfsPotato/CertEnrollSvc |
| `T1134.004` | Parent PID Spoofing | CWLHerpaderping |
| `T1550.002` | Pass the Hash | go-thehash |
| `T1562.006` | Impair Defenses: Indicator Blocking (ETW) | CWLHerpaderping |
| `T1564.001` | Hide Artifacts: Hidden Files and Directories | CWLHerpaderping (HD*.tmp) |
| `T1564.010` | Process Argument Spoofing | CWLHerpaderping |
| `T1573.001` | Encrypted Channel: Symmetric Cryptography | dnscat2 |
| `T1573.002` | Encrypted Channel: Asymmetric Cryptography | dnscat2 |
| `T1620` | Reflective Code Loading | CWLHerpaderping (Mode 1), react2shell-tool (herpload) |
| `T1070.004` | Indicator Removal: File Deletion | CWLHerpaderping (Mode 2) |
