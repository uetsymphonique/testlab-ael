# dnscat2 Go Client — Code Flow Reference

## Source Map

| Component | Path | Role |
|---|---|---|
| CLI entry — raw UDP | `cmd/dnscat/main.go` | Flags, session setup, DNS driver bootstrap |
| CLI entry — DnsQuery_W | `cmd/dnscat-dnsapi/main.go` | Same interface; imports `pkg/tunnel/dnsapi` |
| Service entry | `cmd/dnscat-service/main.go` | SCM or interactive dispatch |
| Service config | `cmd/dnscat-service/config.go` | Registry / build-time defaults |
| Controller | `pkg/controller/controller.go` | Multi-session routing |
| Session | `pkg/session/session.go` | State machine, ACK/SEQ, retransmit, encryption handshake |
| DNS tunnel (raw UDP) | `pkg/tunnel/dns/dns.go` | Encodes packets into DNS queries |
| DNS tunnel (DnsQuery_W) | `pkg/tunnel/dnsapi/dnsapi.go` | Same logic; calls `DnsQuery_W` via CGo |
| Command driver | `pkg/driver/command/driver.go` | Shell, exec, upload, download, tunnel commands |
| Exec driver | `pkg/driver/exec.go` | Spawns local process, bridges stdin/stdout |
| Crypto | `pkg/crypto/encryptor.go` | ECDH P-256 + Salsa20 + SHA3 MAC |

All paths are relative to `resources/payloads/rce-and-c2/dnscat2/go-client/`.

---

## Runtime Flow

```
main.go
  -> parse flags / build-time defaults
  -> create session: ping / console / exec / command (default)
  -> controller.AddSession()
  -> tunnel.Driver.Run()          # dns.go or dnsapi.go
       -> controller.GetOutgoing()
       -> encode → DNS query → server
       -> DNS answer → controller.DataIncoming()
       -> driver.DataReceived()
```

Session states: `BeforeInit` → `BeforeAuth` → `New` (SYN) → `Established` (MSG/FIN).

---

## Transport Variants

| | `cmd/dnscat` | `cmd/dnscat-dnsapi` |
|---|---|---|
| Transport | raw UDP socket | `dnsapi.dll!DnsQuery_W` |
| UDP/53 socket owner | binary process | `svchost.exe` (Dnscache) |
| `--dns-server` flag | used as resolver | informational; system resolver always used |
| Sysmon Event 22 | binary PID | binary PID |
| Cross-platform | yes | compiles on all; Windows-only at runtime |

DnsQuery_W transport is the operational choice for this plan — see `Setup.md` for build command, `BUILD.md` for full options.

---

## Evasion Passes (stealth build tag)

| Pass | Mechanism | Effect |
|---|---|---|
| C — label cap | `MaxLabelLength = 20` | Kills long-label entropy rules (threshold typically > 50 chars) |
| D — adaptive jitter | `scheduleNext(sent && hasData)` | Active: 1–3 s; idle: 5–30 s; kills fixed-interval beacon signatures |
| E — idle suppression | `HasPendingData()` chain | No keep-alive when no real application data; genuine burst-then-silence |
| F — socket attribution | DnsQuery_W transport | UDP/53 owned by Dnscache; binary not visible at network layer |

---

## Command Session Dispatch

The default session (no `--exec`, `--console`, `--ping`) is a command session — a control plane. Shell/exec are spawned as new sessions by the server:

| Command | Behavior |
|---|---|
| `CommandShell` | Spawns `cmd.exe`; new exec session |
| `CommandExec` | Spawns server-supplied command |
| `CommandDownload` | Reads local file → DNS egress |
| `CommandUpload` | Writes bytes from server → local file |
| `TunnelConnect/Data/Close` | TCP tunnel: victim opens outbound TCP to server-specified host:port |
| `CommandShutdown` | Kills all sessions |

---

## Detection-Relevant Behaviors

| Behavior | Observable |
|---|---|
| DNS C2 beacon | UDP/53 queries with hex-encoded labels; mixed A/CNAME record types |
| DnsQuery_W attribution | `svchost.exe` (Dnscache) holds UDP/53 socket; Sysmon Ev 22 logs ghost process PID |
| Shell spawn | Ghost process (RuntimeBroker.exe) → `cmd.exe` child via exec driver |
| Remote command | `RuntimeBroker.exe` → `cmd.exe /c <command>` |
| File write (upload) | Local file write from bytes received over DNS |
| Service persistence | Registry reads/writes under `HKLM\SYSTEM\CurrentControlSet\Services\dnscat2\Parameters` |
| Encryption handshake | ECDH ENC INIT / ENC AUTH packets before first MSG; observable as initial burst of short queries |
