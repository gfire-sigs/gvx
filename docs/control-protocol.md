# Control Socket Protocol (`gvx-ctrl/2`)

This document specifies the `gvx-ctrl/2` binary wire protocol, transport authentication, server-side capability policy, lockdown compatibility matrix, and RPC methods. The protocol runs over an owner-only Unix domain socket or an authenticated loopback TCP listener bound prior to `hostlockdown.Apply()`.

---

## 1. Transport and Connection Framing

A sandbox binds one control listener before sealing its host process. Authorized clients attach to inspect state, execute guest commands, transfer archives, modify limits, tunnel network traffic, attach runtime mounts, and capture checkpoints without relaxing host containment.

### 1.1 Protocol Selection and Legacy Compatibility

The server examines the initial bytes of each accepted stream to select the protocol version:

| Leading Bytes | Selected Protocol | Transport Behavior |
| :--- | :--- | :--- |
| `'{'` (`0x7B`) | Legacy v1 JSON | Reads one bounded JSON checkpoint request (64 KiB maximum) and emits one JSON status reply. |
| `"GVX2"` | `gvx-ctrl/2` binary framing | Reads a `HELLO` frame on stream `0`, verifies credentials, negotiates parameters, and begins multiplexed RPC dispatch. |

### 1.2 Binary Frame Format

Every `gvx-ctrl/2` frame starts with a 12-byte big-endian header followed by `Length` payload bytes.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type (1B)   |   Flags (1B)  |          Channel (2B)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         StreamID (4B)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Length (4B)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Payload (Length B) ...                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Specification |
| :--- | ---: | :--- |
| `Type` | 1 byte | Opcode: `HELLO` (`0x01`), `REQUEST` (`0x02`), `RESPONSE` (`0x03`), `DATA` (`0x04`), `EVENT` (`0x05`), `WINDOW_UPDATE` (`0x06`), `CANCEL` (`0x07`), `PING` (`0x08`), `PONG` (`0x09`), `GOAWAY` (`0x0A`). |
| `Flags` | 1 byte | Bitmask: `END_STREAM` (`0x01`), `COMPRESSED_ZSTD` (`0x02`), `HAS_FDS` (`0x04`). |
| `Channel` | 2 bytes | Sub-stream selector inside `DATA` frames: `0` (generic), `1` (stdin), `2` (stdout), `3` (stderr). |
| `StreamID` | 4 bytes | `0` for connection control; odd IDs (`1, 3, 5...`) for client RPCs; even IDs for server-initiated calls. |
| `Length` | 4 bytes | Payload length capped at `64 KiB` prior to `HELLO` and `control.max_frame_bytes` (default `256 KiB`, hard limit `4 MiB`) thereafter. |

Each stream maintains a credit-based flow-control window initialized to `1 MiB`; receivers transmit `WINDOW_UPDATE` once at least `256 KiB` has been consumed. Setting `COMPRESSED_ZSTD` is valid on `DATA` frames only, with both compressed and decompressed lengths bounded by `max_frame_bytes`. Setting `HAS_FDS` is valid on Unix-socket `REQUEST` frames only when `mount.volume_attach` (or bind attach) is permitted; ancillary descriptors immediately follow via `SCM_RIGHTS`.

---

## 2. Authentication, Capability Policy, and Lockdown Matrix

Control access enforces transport authentication and server-side capability enforcement inside the locked sandbox process.

### 2.1 Transport Authentication

| Transport | Host OS | Verification Mechanism |
| :--- | :--- | :--- |
| Unix domain socket | Linux, macOS | Mode `0600` socket inside an owner-only directory plus peer UID check (`SO_PEERCRED` on Linux; `LOCAL_PEERCRED` on macOS). Optional `--control-token-file`. |
| Unix domain socket | Windows | Mandatory per-run 256-bit hex token in `<socket>.token` (`0600`), verified in constant time during `HELLO`. |
| Loopback TCP (`127.0.0.1`, `[::1]`) | Linux, macOS, Windows | Loopback-only bind validation plus mandatory per-run 256-bit token in `<cache>/gvx/control/tcp-<port>.token` (`tcp6-<port>.token` for IPv6). |

### 2.2 Capability Profiles

`--control-policy` selects a baseline capability set; `--control-disable` removes individual capabilities or groups (`exec`, `fs`, `port`, `mount`, `resource`, `net.dial`, `net.policy`).

| Policy | Enabled Capabilities |
| :--- | :--- |
| `default` | All capabilities compatible with the active host lockdown and runtime flags. |
| `readonly` | `system.ping`, `sandbox.inspect`, `sandbox.stats`, `sandbox.events`, `fs.export`, `port.list`, `mount.list`, `proc.list`, `kernel.log` (excluding `kernel.log_clear`), and `net.policy.read`. |
| `checkpoint-only` | `system.ping`, `sandbox.inspect`, `checkpoint.local`, and `checkpoint.stream`. |

### 2.3 Lockdown Compatibility Matrix

Operations incompatible with active host containment fail with `LOCKDOWN_DENIED`.

| Operation | Behavior Under Default Lockdown | Required Opt-In |
| :--- | :--- | :--- |
| `exec`, `pause`, `unpause`, `stop`, `kill` | Permitted; executes wholly inside the Sentry kernel. | None. |
| `cp`, `export`, `checkpoint -o` | Permitted; the unlocked client performs all host disk I/O over tar streams. | None. |
| `update` | Permitted; adjusts per-sandbox memory, CPU, PID, LAN, NAT bandwidth, and mutable tunables. | None. |
| `net-policy` | Reads or replaces the host NAT policy in memory (client parses files outside lockdown). | NAT mode without a custom `StreamInterceptor`. |
| `port-forward` (`net.dial`) | Permitted; unlocked client binds host sockets and tunnels TCP streams into guest Netstack. | None. |
| `unix-forward` (`net.unix_forward`) | Permitted; sandbox listens on guest Unix socket and relays connections to the unlocked client. | None. |
| `port add` | Permitted on loopback or explicitly listed IP literals only; unlisted addresses and `unix:` binds return `LOCKDOWN_DENIED`. | `--dynamic-ports`, `--auto-publish`, or `--dynamic-ports-addr IP`. |
| `mount add --type tmpfs`, `mount rm` | Permitted; opens no host paths. | None. |
| `mount remount` | `rw` to `ro` always permitted; `ro` to `rw` requires host backing opened writable before lockdown. | Initial writable backing. |
| `mount add --type volume` | Permitted over POSIX `AF_UNIX` via `SCM_RIGHTS`; server validates `S_IFREG` before opening `ext4lite`. | `--allow-volume-attach` (Linux seccomp). |
| `mount serve` (`rpcfs`) | Permitted on all host OSes; unlocked client serves an `os.Root`-pinned directory or single file with paginated `readdir` and host-to-guest `inotify`. | None. |
| `mount add --type bind` | Permitted over POSIX `AF_UNIX` via `SCM_RIGHTS` directory FD (with macOS Seatbelt extension tokens; skips Linux Landlock while retaining seccomp). Unsupported under Windows lockdown. | `--allow-bind-attach` (POSIX) or `-lockdown=false`. |

---

## 3. RPC Method Reference

Each `REQUEST` payload is a JSON object `{"method": "...", "params": {...}}`; each `RESPONSE` payload is `{"ok": true, "result": {...}}` or `{"ok": false, "error": {...}}`.

| Method | Stream Pattern | Purpose |
| :--- | :--- | :--- |
| `system.ping` | Unary | Report protocol version, sandbox ID, state, uptime, and capabilities. |
| `sandbox.inspect` | Unary | Return runtime configuration, limits, ports, mounts, and security posture. |
| `sandbox.stats` | Unary or event stream | Return one-shot or periodic CPU, memory, network, block I/O, and PID metrics. |
| `sandbox.events` | Event stream | Stream filtered events (`exec`, `lifecycle`, `port`, `unix_forward`, `mount`, `resource`, `oom`), including `source=auto` port events (`add`, `remove`, `bind_failed`). |
| `lifecycle.pause` | Unary | Pause guest tasks and optionally quiesce network forwarders. |
| `lifecycle.unpause` | Unary | Resume a paused sandbox. |
| `lifecycle.stop` | Unary | Signal PID 1, await `timeout_ms`, and escalate to `SIGKILL`. |
| `lifecycle.checkpoint` | Unary | Save a checkpoint bundle into the pre-opened `-checkpoint-dir`. |
| `lifecycle.checkpoint_stream` | Server data stream | Stream a checkpoint bundle as tar on channel `0` without `-checkpoint-dir`. |
| `exec.start` | Bidirectional stream | Launch a guest process (closed stdin unless `stdin: true`) with optional PTY, resize, signal, and exit event. |
| `fs.stat` | Unary | Stat a single guest path. |
| `fs.export` | Server data stream | Stream a guest path or root overlay upper layer (`upper_only: true`) as tar on channel `0`. |
| `fs.import` | Client data stream | Extract a client tar stream from channel `0` into a guest directory. |
| `resource.update` | Unary | Update memory, CPU bandwidth, PIDs, LAN isolation, NAT rates (`net_tx_bps`, `net_rx_bps`), or mutable tunables. |
| `port.list` | Unary | List static, auto-published, and dynamic port rules. |
| `port.add` / `port.remove` | Unary | Add or remove host-to-guest NAT port rules. |
| `net.dial` | Bidirectional stream | Dial a guest TCP endpoint inside Netstack and relay bytes on channel `0`. |
| `net.policy_get` / `net.policy_set` | Unary | Read (`net.policy.read`) or atomically replace (`net.policy.write`) the active JSON host NAT policy (bounded by 64 KiB and negotiated frame size). |
| `net.unix_forward` / `net.unix_accept` | Event / bidirectional stream | Bind a guest Unix listener, emit `unix.accept` events, and claim each `conn_id` stream. |
| `mount.list` / `mount.add` / `mount.remount` / `mount.remove` | Unary (optional FD) | Inspect, attach (`tmpfs`, `SCM_RIGHTS` `ext4lite`, or bind), toggle `ro`/`rw`, or unmount targets. |
| `mount.serve` | Bidirectional event stream | Attach or reconnect an `rpcfs` proxy mount backed by client `rpcfs.req`, `rpcfs.resp`, `rpcfs.notify`, and `rpcfs.detached` events. |
| `proc.list` / `proc.signal` | Unary | Snapshot guest thread groups or deliver a POSIX signal. |
| `kernel.log` | Unary or event stream | Read or follow `/dev/kmsg` ring records. |
| `debug.log_level` | Unary | Set Sentry log verbosity (`warning`, `info`, or `debug`). |

In `HELLO`, the `net_qos` feature advertises support for optional unsigned integer fields `net_tx_bps` and `net_rx_bps` on `resource.update` (requiring `resource.network`; omitted fields remain unchanged, `0` removes the limit, and both apply atomically).

### 3.1 Structured Error Codes

Failed RPCs return a `ProtoError` carrying `code`, `message`, optional Linux `errno`, and `retryable`.

| Error Code | CLI Exit Code | Meaning |
| :--- | ---: | :--- |
| `UNAUTHORIZED` | `126` | Missing or invalid token, or peer UID mismatch. |
| `FORBIDDEN_BY_POLICY` | `126` | Capability disabled by `--control-policy` or `--control-disable`. |
| `LOCKDOWN_DENIED` | `126` | Request violates active host lockdown rules. |
| `INVALID_ARGUMENT` | `1` | Malformed argument, immutable tunable, or mismatched directory. |
| `UNSUPPORTED` | `1` | Unavailable on the active host OS, transport, or configuration (such as checkpointing an ephemeral `ext4lite` volume). |
| `ALREADY_PAUSED` / `NOT_PAUSED` | `1` | Sandbox pause state disagrees with the request (paused sandboxes also reject `exec.start`). |
| `NOT_FOUND` / `ALREADY_EXISTS` | `1` | Target PID, path, port, or mount is absent or conflicts with an existing entry. |
| `BUSY` | `1` | Resource in use, or bandwidth-shaped NAT tunnels active during checkpoint. |
| `LIMIT_EXCEEDED` | `1` | Concurrency or resource ceiling exceeded (such as shrinking memory below usage without `--force-memory`). |
| `EXEC_ACTIVE` | `1` | Active `exec` sessions block checkpointing without `--force`. |
| `SANDBOX_EXITING` | `1` | Sandbox is terminating and accepts no new streams. |

---

## 4. Operating a Controlled Sandbox

Follow these steps to launch a named sandbox and control it from a second terminal.

> [!IMPORTANT]
> Never bind a control socket on a non-loopback address or inside a world-writable directory. Keep Unix sockets inside a mode `0700` owner-only directory.

1. Start a named sandbox with `--control` (and optional `--dynamic-ports`).
2. Confirm connectivity with `rungvx ping -n <name>`.
3. Execute commands, adjust limits, forward ports, serve host paths, or stream checkpoints.
4. Terminate cleanly with `rungvx stop -n <name>`.

```sh
rungvx run --name app --control --dynamic-ports alpine:3.20 sleep 600
rungvx ping -n app
rungvx exec -n app -it -- /bin/sh
rungvx update -n app -m 512m --cpus 1.0 --pids-limit 128
rungvx port-forward -n app 18080:80
rungvx mount serve -n app "$PWD":/mnt/host
rungvx checkpoint -n app -z -o ./app-ckpt --leave-running
rungvx stop -n app
```
