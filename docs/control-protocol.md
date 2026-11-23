# `gvx` Control Socket Protocol (`gvx-ctrl/2`)

This document specifies the `gvx-ctrl/2` wire protocol, capability matrix, lockdown constraints, and CLI control model. The protocol operates over owner-only Unix domain sockets or authenticated loopback TCP connections bound before host lockdown.

---

## 1. Transport and Connection Framing (Descriptive Module)

A sandbox binds one control listener before `hostlockdown.Apply()` runs. Clients connect to that listener to inspect state, execute processes, transfer files, adjust limits, tunnel ports, and attach runtime mounts without weakening host containment.

### 1.1 Protocol Detection and Legacy Compatibility

The server inspects the first byte of each accepted connection to select the wire protocol. A leading `'{'` selects the legacy v1 single-JSON checkpoint handler for older clients. The 4-byte ASCII preface `GVX2` selects `gvx-ctrl/2` binary framing.

| Leading Bytes | Selected Protocol | Transport Behavior |
| :--- | :--- | :--- |
| `'{'` (`0x7B`) | Legacy v1 JSON | Reads one bounded JSON object (64 KiB maximum) and replies with one JSON checkpoint status object. |
| `"GVX2"` | `gvx-ctrl/2` binary framing | Reads a `HELLO` frame on stream `0`, verifies authentication, and starts multiplexed stream dispatch. |

### 1.2 Frame Layout

Every `gvx-ctrl/2` message begins with a 12-byte big-endian header followed by `Length` payload bytes.

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

| Field | Size | Meaning |
| :--- | ---: | :--- |
| `Type` | 1 byte | Frame opcode: `HELLO` (`0x01`), `REQUEST` (`0x02`), `RESPONSE` (`0x03`), `DATA` (`0x04`), `EVENT` (`0x05`), `WINDOW_UPDATE` (`0x06`), `CANCEL` (`0x07`), `PING` (`0x08`), `PONG` (`0x09`), `GOAWAY` (`0x0A`). |
| `Flags` | 1 byte | Bitmask: `END_STREAM` (`0x01`), `COMPRESSED_ZSTD` (`0x02`), `HAS_FDS` (`0x04`). |
| `Channel` | 2 bytes | Byte sub-stream inside `DATA` frames: `0` (generic payload), `1` (stdin), `2` (stdout), `3` (stderr). |
| `StreamID` | 4 bytes | Stream `0` carries connection control. Client RPCs use odd IDs (`1, 3, 5...`). Server-initiated calls use even IDs. |
| `Length` | 4 bytes | Payload byte count bounded by `64 KiB` before `HELLO` and `control.max_frame_bytes` (default `256 KiB`, hard limit `4 MiB`) after `HELLO`. |

Each stream maintains a credit-based flow-control window starting at `1 MiB`. Receivers emit `WINDOW_UPDATE` frames once a reader consumes `256 KiB` or more.

When the sender sets `COMPRESSED_ZSTD` on a `DATA` frame, it compresses the payload with `zstd`. The receiver rejects `COMPRESSED_ZSTD` on non-`DATA` frames and bounds both wire length and decompressed length by `max_frame_bytes`.

When the sender sets `HAS_FDS` on a `REQUEST` frame on a Unix domain socket, it transmits ancillary file descriptors with `SCM_RIGHTS` immediately after the frame bytes. The server rejects `HAS_FDS` unless `mount.volume_attach` is active on a Unix socket.

---

## 2. Authentication, Policy, and Lockdown Rules (Descriptive Module)

Control access enforces two layers of defense: transport authentication and server-side capability filtering. The server evaluates every capability decision inside the sandbox process after lockdown.

### 2.1 Transport Authentication

Every control endpoint restricts access to the local owner account.

| Transport | Host OS | Authentication Mechanism |
| :--- | :--- | :--- |
| Unix domain socket | Linux, macOS | Mode `0600` socket file inside an owner-only directory plus peer UID verification via `SO_PEERCRED` (Linux) or `LOCAL_PEERCRED` (macOS). Optional token file via `--control-token-file`. |
| Unix domain socket | Windows | Per-run 256-bit hexadecimal token in a `0600` token file (`<socket>.token`) verified in constant time during `HELLO`. |
| Loopback TCP (`127.0.0.1` or `[::1]`) | Linux, macOS, Windows | Loopback-only bind validation plus mandatory per-run 256-bit token in `<cache>/gvx/control/tcp-<port>.token` (IPv4) or `tcp6-<port>.token` (IPv6). |

### 2.2 Capability Policies

`--control-policy` selects a baseline set of enabled capabilities. `--control-disable` removes individual capabilities or groups (such as `exec`, `fs`, `port`, `mount`, `resource`, or `net.dial`).

| Policy | Permitted Capabilities |
| :--- | :--- |
| `default` | All capabilities compatible with the active host lockdown and runtime flags. |
| `readonly` | `system.ping`, `sandbox.inspect`, `sandbox.stats`, `sandbox.events`, `fs.export`, `port.list`, `mount.list`, `proc.list`, `kernel.log` (without `kernel.log_clear`), and `net.policy.read`. |
| `checkpoint-only` | `system.ping`, `sandbox.inspect`, `checkpoint.local`, `checkpoint.stream`. |

### 2.3 Lockdown Compatibility Matrix

Host lockdown blocks new host file opens, child process creation, and arbitrary socket binds inside the sandbox process. The control server obeys every lockdown rule and rejects forbidden operations with `LOCKDOWN_DENIED`.

| Feature | Behavior Under Default Lockdown | Required Opt-In |
| :--- | :--- | :--- |
| `exec`, `pause`, `unpause`, `stop`, `kill` | Allowed; operates purely inside the Sentry kernel. | None. |
| `cp`, `export`, `checkpoint -o` | Allowed; the unlocked client performs all host disk I/O over framed tar streams. | None. |
| `update` (`-m`, `--cpus`, `--pids-limit`, `--isolate-lan`, `--net-tx-bps`, `--net-rx-bps`, `--tune`) | Allowed; modifies per-sandbox Sentry limits, root CPU bandwidth, root cgroup2 `pids.max`, and NAT settings. | None. |
| `net-policy` | Reads or replaces the NAT policy in memory. The client reads policy files outside lockdown. | NAT without a custom stream interceptor. |
| `port-forward` (`net.dial`) | Allowed; the unlocked client binds host sockets and tunnels TCP streams into the guest stack. | None. |
| `port add` | Allowed on `127.0.0.1` or `[::1]` only when loopback binds are pre-authorized; non-loopback and `unix:` binds return `LOCKDOWN_DENIED`. | `--dynamic-ports` or `--auto-publish`. |
| `mount add --type tmpfs`, `mount rm` | Allowed; no host path opens occur. | None. |
| `mount remount` | The server always allows remounting `rw` to `ro`; remounting `ro` to `rw` succeeds only when the host backing opened writable before lockdown. | Original writable mount. |
| `mount add --type volume` | Allowed over POSIX `AF_UNIX` via `SCM_RIGHTS` FD transfer; server verifies `S_IFREG` before opening `ext4lite`. | `--allow-volume-attach` (Linux seccomp rule). |
| `mount serve` (`rpcfs`) | Allowed on all host OSes; the unlocked client serves an `os.Root`-pinned directory or single file over stream events. Supports paginated `readdir` and host-to-guest `inotify` events. | None. |
| `mount add --type bind` | Always rejected with `LOCKDOWN_DENIED` under lockdown. | `-lockdown=false` (debugging only). |

---

## 3. RPC Method Reference (Reference Module)

Every `REQUEST` frame carries `{"method": "...", "params": {...}}`. Every `RESPONSE` frame carries `{"ok": true, "result": {...}}` or `{"ok": false, "error": {...}}`.

| Method | Stream Pattern | Purpose |
| :--- | :--- | :--- |
| `system.ping` | Unary | Report protocol version, sandbox ID, state, uptime, and capabilities. |
| `sandbox.inspect` | Unary | Return full runtime configuration, limits, ports, mounts, and security posture. |
| `sandbox.stats` | Unary or event stream | Return one-shot or periodic CPU, memory, network, block I/O, and PID counters. |
| `sandbox.events` | Event stream | Stream filtered lifecycle events (`exec`, `lifecycle`, `port`, `mount`, `resource`, `oom`). |
| `lifecycle.pause` | Unary | Pause all guest tasks and optionally quiesce host network forwarders. |
| `lifecycle.unpause` | Unary | Resume a paused sandbox. |
| `lifecycle.stop` | Unary | Send a signal to PID 1, wait up to `timeout_ms`, and escalate to `SIGKILL`. |
| `lifecycle.checkpoint` | Unary | Write a checkpoint bundle to the pre-opened `-checkpoint-dir`. |
| `lifecycle.checkpoint_stream` | Server data stream | Stream a checkpoint bundle as a tar archive on channel `0` without `-checkpoint-dir`. |
| `exec.start` | Bidirectional stream | Spawn a guest process with Docker-style stdio (closed stdin unless `stdin: true`), optional PTY, resize, signal, and exit event. |
| `fs.stat` | Unary | Inspect one guest filesystem entry. |
| `fs.export` | Server data stream | Stream a guest file, directory, or root overlay upper layer (`upper_only: true`) as tar on channel `0`. |
| `fs.import` | Client data stream | Extract a client tar stream from channel `0` into a guest directory. |
| `resource.update` | Unary | Update memory, CPU bandwidth, PIDs, LAN isolation, NAT bandwidth, or mutable tunables. |
| `port.list` | Unary | List static, auto-published, and dynamic host-to-guest port rules. |
| `port.add` | Unary | Bind dynamic host-to-guest port rules on the sandbox forwarder. |
| `port.remove` | Unary | Close dynamic or specified host-to-guest port rules. |
| `net.dial` | Bidirectional stream | Dial a guest TCP endpoint inside the sandbox network stack and relay bytes on channel `0`. |
| `net.policy_get` | Unary | Read the active host NAT policy. Requires `net.policy.read`. |
| `net.policy_set` | Unary | Replace the active host NAT policy. Requires `net.policy.write`. |
| `mount.list` | Unary | List active guest mounts and mutability status. |
| `mount.add` | Unary (optional FD) | Mount a `tmpfs`, `SCM_RIGHTS` `ext4lite` volume, or `-lockdown=false` bind mount. |
| `mount.remount` | Unary | Toggle a mount between read-only and read-write. |
| `mount.remove` | Unary | Unmount one guest mount point (optional `MNT_DETACH`). |
| `mount.serve` | Bidirectional event stream | Attach an `rpcfs` directory or single-file proxy mount backed by client `rpcfs.req`, `rpcfs.resp`, and `rpcfs.notify` events. |
| `proc.list` | Unary | Return a snapshot of guest thread groups from `TaskSet`. |
| `proc.signal` | Unary | Send a POSIX signal to PID 1, a specific guest PID, or all guest processes. |
| `kernel.log` | Unary or event stream | Read or follow records from the guest kernel log ring. |
| `debug.log_level` | Unary | Change the active Sentry log level (`warning`, `info`, or `debug`). |

The `net_qos` feature in `HELLO` identifies support for the NAT bandwidth fields in `resource.update`. The client verifies that feature before sending a request with either field. Both fields require the `resource.network` capability.

| Field | Type | Meaning |
| :--- | :--- | :--- |
| `net_tx_bps` | Optional unsigned integer | Guest transmit limit in bits per second. |
| `net_rx_bps` | Optional unsigned integer | Guest receive limit in bits per second. |

An omitted field leaves that rate unchanged. A value of `0` removes the limit for that direction. The server installs both requested rates as one pair. `sandbox.inspect` and a successful `resource.update` report the effective rates in the resource snapshot.

`net.policy_get` returns an object with a `policy` field. The value is the active JSON policy or `null` before the first installation. `net.policy_set` accepts the same object with a non-null policy. The server validates the complete document before replacing the rules. It returns the installed document.

The encoded request and response must fit the negotiated frame size. Keep the default frame size to use the full 64 KiB policy limit.

The `net.policy` group disables both capabilities. The `readonly` profile permits `net.policy.read` but not `net.policy.write`. Policy changes leave `resource.update` bandwidth values unchanged.

### 3.1 Structured Error Codes

Failed RPCs return a `ProtoError` object with a stable `code`, a diagnostic `message`, an optional Linux `errno`, and a `retryable` boolean.

| Error Code | CLI Exit Code | Meaning |
| :--- | ---: | :--- |
| `UNAUTHORIZED` | `126` | Missing or invalid control token, or peer UID mismatch. |
| `FORBIDDEN_BY_POLICY` | `126` | Capability disabled by `--control-policy` or `--control-disable`. |
| `LOCKDOWN_DENIED` | `126` | Operation violates active host lockdown constraints. |
| `INVALID_ARGUMENT` | `1` | Invalid request parameter, immutable tunable, or directory mismatch. |
| `UNSUPPORTED` | `1` | Operation unavailable on the active host OS or transport. |
| `ALREADY_PAUSED` | `1` | Sandbox is already paused (also rejects `exec.start`). |
| `NOT_PAUSED` | `1` | `lifecycle.unpause` called on a running sandbox. |
| `NOT_FOUND` | `1` | Target PID, path, port rule, or mount does not exist. |
| `ALREADY_EXISTS` | `1` | Conflicting port rule or mount target already exists. |
| `BUSY` | `1` | Target mount is in use, or an active `rpcfs` mount or shaped NAT tunnel blocks checkpointing. |
| `LIMIT_EXCEEDED` | `1` | Resource limit or concurrency ceiling exceeded (for example, memory cap below usage without `--force-memory`). |
| `EXEC_ACTIVE` | `1` | Active `exec` sessions block checkpointing without `--force`. |
| `SANDBOX_EXITING` | `1` | Sandbox is shutting down and accepts no new streams. |

---

## 4. Control Operations Procedure (Procedural Module)

Run these steps to start a named sandbox with a control socket and control it from a second terminal.

> [!IMPORTANT]
> Never expose a control socket on a non-loopback address or a world-writable directory. On Linux and macOS, keep the socket inside a mode `0700` directory.

1. Start a named sandbox with `--control` and optional `--dynamic-ports`.
2. Verify socket readiness with `rungv ping -n <name>`.
3. Run commands inside the guest with `rungv exec -n <name>`.
4. Copy files or serve a host directory with `rungv cp` or `rungv mount serve`.
5. Stop the sandbox cleanly with `rungv stop -n <name>`.

```sh
rungv run --name app --control --dynamic-ports alpine:3.20 sleep 600
rungv ping -n app
rungv exec -n app -it -- /bin/sh
rungv update -n app -m 512m --cpus 1.0 --pids-limit 128
rungv port-forward -n app 18080:80
rungv mount serve -n app "$PWD":/mnt/host
rungv checkpoint -n app -z -o ./app-ckpt --leave-running
rungv stop -n app
```
