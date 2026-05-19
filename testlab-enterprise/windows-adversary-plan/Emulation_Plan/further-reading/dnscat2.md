# dnscat2 Go Client - Code Flow Summary

This document summarizes the code flow of the `dnscat2/go-client` payload, focusing on how the client creates sessions, packages data over DNS, receives commands from the server, and exposes command, shell, file, and tunnel capabilities.

## Source Map

| Component | Path | Role |
|---|---|---|
| CLI entry point | `../../resources/payloads/dnscat2/go-client/cmd/dnscat/main.go` | Parses flags, selects mode, creates session, runs DNS driver |
| Service entry point | `../../resources/payloads/dnscat2/go-client/cmd/dnscat-service/main.go` | Chooses Windows Service or interactive execution |
| Service config | `../../resources/payloads/dnscat2/go-client/cmd/dnscat-service/config.go` | Reads config from registry or build-time defaults |
| Service runtime | `../../resources/payloads/dnscat2/go-client/cmd/dnscat-service/service.go` | Creates session and DNS driver in service context |
| Controller | `../../resources/payloads/dnscat2/go-client/pkg/controller/controller.go` | Manages multiple sessions and routes inbound/outbound packets |
| Session | `../../resources/payloads/dnscat2/go-client/pkg/session/session.go` | State machine, retransmit, ACK/SEQ, encryption handshake |
| DNS tunnel | `../../resources/payloads/dnscat2/go-client/pkg/tunnel/dns/dns.go` | Encodes packets into DNS queries and decodes server answers |
| DNS wire format | `../../resources/payloads/dnscat2/go-client/pkg/tunnel/dns/protocol.go` | Builds/parses DNS queries and responses |
| Command driver | `../../resources/payloads/dnscat2/go-client/pkg/driver/command/driver.go` | Handles command-session requests: shell, exec, upload, download, tunnel |
| Exec driver | `../../resources/payloads/dnscat2/go-client/pkg/driver/exec.go` | Spawns local processes and bridges stdin/stdout through sessions |
| Crypto | `../../resources/payloads/dnscat2/go-client/pkg/crypto/encryptor.go` | ECDH P-256, Salsa20, SHA3 MAC, PSK authenticator |

## High-Level Runtime Flow

```text
cmd/dnscat/main.go
  -> parse flags / build-time defaults
  -> configure global session settings
  -> create session:
       --ping       -> NewPingSession()
       --console    -> NewConsoleSession()
       --exec <cmd> -> NewExecSession()
       default      -> command session
  -> controller.AddSession()
  -> dns.NewDriver(domain, host, port, types, server)
  -> dnsDriver.Run()
       -> controller.GetOutgoing()
       -> session.GetOutgoing()
       -> driver.GetOutgoing()
       -> DNS query to server
       -> DNS answer from server
       -> controller.DataIncoming()
       -> session.DataIncoming()
       -> driver.DataReceived()
```

Service mode uses the same core runtime with a different entry point:

```text
cmd/dnscat-service/main.go
  -> svc.IsWindowsService()
       service     -> runService()
       interactive -> runInteractive()

runService()
  -> LoadConfigFromRegistry()
  -> svc.Run("dnscat2", dnscat2Service)

dnscat2Service.Execute()
  -> runDnscat(config)
  -> same session/controller/DNS flow as CLI
```

## CLI Entry Point

`cmd/dnscat/main.go` is the main path for the console binary.

1. Parse flags: `domain`, `dns-server`, `dns-port`, `dns-type`, `secret`, `no-encryption`, `delay`, `max-retransmits`, `packet-trace`, `ping`, `console`, `exec`.
2. Assign global settings in the `session` package: `PacketTrace`, `PacketDelay`, `DoEncryption`, and `PresharedSecret`.
3. Assign `controller.MaxRetransmits`.
4. Select DNS server from `--dns-server`, system DNS via `getSystemDNS()`, or fallback `8.8.8.8`.
5. Create the session for the selected mode.
6. Add the session to the controller.
7. Create the DNS driver and call `dnsDriver.Run()`.

If `--ping`, `--console`, or `--exec` is not supplied, the client creates a command session by default. This is the control plane used by the server to request shell, exec, upload/download, or TCP tunnel operations.

## Windows Service Flow

The service binary lives under `cmd/dnscat-service`.

`main.go` checks whether the process is running under the Service Control Manager or interactively. In service mode, `runService()` reads configuration from:

```text
HKLM\SYSTEM\CurrentControlSet\Services\dnscat2\Parameters
```

Supported values:

| Registry value | Meaning |
|---|---|
| `Domain` | Domain used for tunneling |
| `DnsServer` | Destination DNS server |
| `DnsPort` | UDP port, default `53` |
| `DnsTypes` | Record types, default `TXT,CNAME,MX` |
| `Secret` | Pre-shared secret |
| `ExecCommand` | Command to run when the session opens |
| `Delay` | Delay between packets |
| `MaxRetransmit` | Retransmit threshold before killing the session |
| `NoEncryption` | Disables encryption when non-zero |
| `PacketTrace` | Enables packet trace when non-zero |

If the registry key does not exist, the code falls back to build-time defaults injected through `-ldflags`. The service runtime then calls `runDnscat(config)`, creates a session like the CLI path, and runs the blocking DNS driver loop.

## Session State Machine

`pkg/session/session.go` stores session state and converts driver-specific data into dnscat2 packets.

| State | Meaning |
|---|---|
| `StateBeforeInit` | Preparing the encryption handshake |
| `StateBeforeAuth` | Waiting for PSK authenticator when a secret is configured |
| `StateNew` | Sending `SYN` to open a dnscat2 session |
| `StateEstablished` | Sending/receiving `MSG`, `FIN`, and encryption renegotiation packets |

Outbound flow in `Session.GetOutgoing()`:

1. Poll the driver through `Driver.GetOutgoing()`.
2. Append driver data to `OutgoingBuffer`.
3. If `PacketDelay` has not elapsed, do not send yet.
4. If still in the encryption handshake, send `ENC INIT` with the public key or `ENC AUTH` when a PSK is configured.
5. If `StateNew`, send `SYN` with the session name and command-session flag.
6. If `StateEstablished`, send `MSG` from the sliding buffer or `FIN` if the session is closing.
7. If encryption is enabled, encrypt and sign the packet before returning it to the DNS driver.

Inbound flow in `Session.DataIncoming()`:

1. Verify signature and decrypt when needed.
2. Parse the packet.
3. Route by packet type: `SYN` establishes the session, `MSG` ACKs outgoing bytes and passes data to the driver, `FIN` kills the session, and `ENC` handles key exchange, PSK auth, or renegotiation.

`OutgoingBuffer` is consumed only after the server ACKs data. Lost DNS responses therefore result in retransmission rather than data loss.

## DNS Tunnel Flow

`pkg/tunnel/dns/dns.go` converts dnscat2 packets into DNS queries.

Outbound:

```text
controller.GetOutgoing(maxLength)
  -> select next active session round-robin
  -> session.GetOutgoing()
  -> dns.encodeDNSName(data)
       hex(data)
       split label <= 62 chars
       append domain or wildcard prefix "dnscat"
  -> BuildDNSQuery(name, random record type)
  -> UDP write to DNSServer:DNSPort
```

Inbound:

```text
UDP response
  -> ParseDNSResponse()
  -> decodeDNSResponse()
       TXT         -> hex decode TXT body
       CNAME / MX  -> strip domain, hex decode name
       A           -> sort answers by sequence byte, read 3 bytes per answer
       AAAA        -> sort answers by sequence byte, read 15 bytes per answer
  -> controller.DataIncoming(data)
```

`Run()` uses a 50 ms read deadline. On timeout, the driver calls `controller.Heartbeat()` and then tries to send the next packet. Heartbeat kills a session when `MissedTransmissions` exceeds `MaxRetransmits`.

## Command Session Flow

The command session uses `pkg/driver/command/driver.go`.

The server sends command packets through session `MSG`; the driver parses the stream with `ReadPacket()` and dispatches in `handlePacket()`:

| Command | Handler | Behavior |
|---|---|---|
| `CommandPing` | `handlePing` | Echoes data back to the server |
| `CommandShell` | `handleShell` | Creates a new session running `cmd.exe` on Windows or `sh` on Unix |
| `CommandExec` | `handleExec` | Creates a new session running the server-supplied command |
| `CommandDownload` | `handleDownload` | Reads a local file and sends bytes to the server |
| `CommandUpload` | `handleUpload` | Writes server-supplied bytes to a local file |
| `CommandShutdown` | `handleShutdown` | Calls the callback that kills all sessions |
| `CommandDelay` | `handleDelay` | Changes `session.PacketDelay` |
| `TunnelConnect` | `handleTunnelConnect` | Opens a TCP connection from the victim to the server-specified host:port |
| `TunnelData` | `handleTunnelData` | Writes data to the TCP tunnel |
| `TunnelClose` | `handleTunnelClose` | Closes the TCP tunnel |

The command session does not spawn a shell immediately. It is a control plane. Shell and exec requests are created as new sessions through the `CreateSession` callback, and the controller multiplexes all sessions through the same DNS channel.

## Exec Driver Flow

`pkg/driver/exec.go` bridges a local process and a dnscat2 session.

1. `NewExecDriver(process)` determines whether the command is an interactive shell.
2. If it is a shell (`cmd.exe`, `powershell.exe`, `sh`, `bash`, and similar), it runs directly.
3. If it is a command string, it wraps through `cmd.exe /c <process>` on Windows or `/bin/sh -c <process>` on Unix.
4. It obtains stdin/stdout pipes and merges stderr into stdout.
5. `readOutput()` reads stdout in a goroutine and appends it to `outgoingData`.
6. `DataReceived()` writes server-supplied data to stdin.
7. `GetOutgoing()` returns buffered stdout to the session.
8. `Close()` closes stdin and kills the process.

## Encryption Flow

`pkg/crypto/encryptor.go` implements the optional encryption layer.

1. The client creates an ECDH P-256 keypair.
2. `ENC INIT` exchanges public keys in `X || Y` form.
3. The shared secret derives keys with SHA3-256: `client_write_key`, `client_mac_key`, `server_write_key`, and `server_mac_key`.
4. If a PSK exists, client and server exchange an authenticator.
5. The packet body is encrypted with Salsa20.
6. The packet is signed with a truncated 6-byte SHA3 MAC.
7. The session renegotiates keys when the nonce is nearly exhausted.

## Detection-Relevant Code Paths

| Behavior | Code path | Observable artifact |
|---|---|---|
| DNS C2 beacon | `dns.Driver.Run()` -> `doSend()` | UDP DNS queries to the configured DNS server with long hex labels in query names |
| TXT/CNAME/MX multiplexing | `dns.NewDriver()` / `getType()` | Mixed DNS record types in the same beacon family |
| Command session | `newCommandSession()` -> `command.NewDriver()` | Server-driven shell, exec, upload, download, and tunnel capability |
| Remote shell spawn | `handleShell()` -> `session.NewExecSession()` -> `NewExecDriver("cmd.exe")` | `dnscat*.exe` spawns `cmd.exe` |
| Remote command execution | `handleExec()` -> `NewExecDriver(command)` | `dnscat*.exe` spawns `cmd.exe /c <command>` on Windows |
| File download from victim | `handleDownload()` | Local file read followed by DNS egress |
| File upload to victim | `handleUpload()` | Local file write from bytes received over DNS |
| TCP tunnel | `handleTunnelConnect()` | Victim opens outbound TCP connection to a server-specified host:port |
| Service persistence/config | `LoadConfigFromRegistry()` | Registry reads under `HKLM\SYSTEM\CurrentControlSet\Services\dnscat2\Parameters` |

## Reading Order

1. `cmd/dnscat/main.go` for normal CLI execution.
2. `cmd/dnscat-service/main.go`, `config.go`, `service.go` for Windows Service execution.
3. `pkg/session/session.go` to understand packet state and ACK/SEQ handling.
4. `pkg/tunnel/dns/dns.go` and `protocol.go` for DNS transport.
5. `pkg/driver/command/driver.go` for C2 command capability.
6. `pkg/driver/exec.go` for process execution semantics.
7. `pkg/crypto/encryptor.go` if encryption/authentication behavior matters for detection.
