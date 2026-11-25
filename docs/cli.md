# The `rungv` Command Line

`rungv` executes an OCI image or a Linux ELF64 binary in the foreground inside a self-confined sandbox. Its subcommands, flags, and output follow Docker CLI conventions wherever the single-process model applies. This reference documents every subcommand, flag, tunable, networking rule, checkpoint operation, nested-execution detail, and Android setting. Consult [`architecture.md`](architecture.md) for system internals, [`compatibility.md`](compatibility.md) for verified workloads, and [`troubleshooting.md`](troubleshooting.md) for failure diagnosis.

---

## 1. Execution Model

`rungv` operates without a background daemon. Each `rungv run` invocation starts a sandbox, executes the guest command, and tears down all resources upon exit, matching `docker run --rm`.

By default, guest writes land in an ephemeral memory-backed `tmpfs` upper layer above read-only EROFS image layers. Data persists across invocations only in a bind mount, a named volume, a `-rootfs-volume` image, or the host image cache.

Before executing guest code, the host process enforces OS-native self-lockdown (`hostlockdown.Apply()`). Once locked down, the process cannot open unbound host paths, create child processes, or bind arbitrary sockets. Passing `--auto-publish` or `--dynamic-ports` relaxes socket lockdown strictly for host loopback (`127.0.0.1`) binds. Starting `rungv run` with `-S`, `--control-socket`, or `--control` exposes an authenticated `gvx-ctrl/2` control listener for live inspection, `exec`, file copy, pause, resource updates, port rules, mounts, signals, logs, and checkpoints. See [`control-protocol.md`](control-protocol.md) for the wire protocol and lockdown rules.

---

## 2. Subcommand Overview

Run `rungv help` to display this command table.

| Command | Purpose |
| :--- | :--- |
| `run` | Execute a command inside an OCI image or a local Linux ELF64 binary. |
| `exec` | Spawn a command inside a running sandbox over its control socket (stdin closed unless `-i`). |
| `pause` | Suspend all guest tasks in a running sandbox (`--quiesce-net=true` by default). |
| `unpause` | Resume guest tasks in a paused sandbox. |
| `cp` | Copy files or directories between the host and a running sandbox via tar streams. |
| `export` | Export a sandbox filesystem or overlay upper layer (`--upper-only`) as a tar archive. |
| `update` | Modify live memory, CPU quota, PID limit, LAN isolation, NAT bandwidth, or mutable tunables. |
| `net-policy` | Read (`get`) or replace (`replace`) the active host NAT policy over the control socket. |
| `port` | Group command for `ls`, `add`, and `rm` on published sandbox ports. |
| `port-forward` | Tunnel host TCP or Unix connections into a running sandbox via the control socket (alias: `pf`). |
| `unix-forward` | Forward guest Unix socket connections to a host Unix socket via the control socket (alias: `uf`). |
| `mount` | Group command for `ls`, `add`, `remount`, `rm`, and `serve` on runtime mounts. |
| `status` | Inspect a running sandbox over its control socket (also `rungv sandbox inspect`). |
| `stats` | Display live CPU, memory, network, block I/O, and PID counters. |
| `top` | List running processes inside a sandbox. |
| `kill` | Deliver a POSIX signal to PID 1, a specific guest PID, or all guest processes. |
| `stop` | Stop a sandbox cleanly with a timeout before escalating to `SIGKILL`. |
| `dmesg` | Read or follow records from the guest kernel log ring. |
| `events` | Stream filtered lifecycle events from a running sandbox. |
| `ping` | Verify control socket readiness and advertised capabilities. |
| `debug` | Adjust the active Sentry log level (`warning`, `info`, or `debug`). |
| `pull` | Fetch an OCI image into the local layer cache (`--platform linux/ARCH`; `-keep-blobs`). |
| `push` | Push a cached image to a registry using OCI Distribution v1.1 (`rungv push [flags] IMAGE [TARGET]`). |
| `images` | List cached images. |
| `inspect` | Print cached image metadata as JSON or through a Go template. |
| `tag` | Add a repository or tag alias to a cached image. |
| `rmi` | Remove an image tag or delete an unreferenced image. |
| `save` | Export cached images to an OCI and `docker save` tar archive. |
| `load` | Import images from a tar archive (`-keep-blobs` retains original compressed blobs). |
| `image` | Group command for `ls`, `pull`, `push`, `rm`, `inspect`, `tag`, `save`, `load`, and `prune`. |
| `volume` | Group command for `create`, `ls`, `inspect`, `compact`, `rm`, and `prune` on local volumes. |
| `system` | Group command for `info`, `df`, and `prune` on host backends and local storage. |
| `info` | Report host OS, available backends, lockdown profile, and storage paths. |
| `checkpoint` | Capture a checkpoint bundle for a running sandbox (alias: `snapshot`). |
| `restore` | Resume a sandbox from a checkpoint bundle directory (alias: `resume`). |
| `login` | Authenticate and store registry credentials in Docker config. |
| `logout` | Remove stored registry credentials. |
| `completion` | Emit shell completion scripts for `bash`, `zsh`, `fish`, or `powershell`. |
| `stub` | Probe `systrap` readiness on the active host. |
| `tune` | List host-side tunables (`rungv tune list`; Section 3.3). |
| `license` | Print embedded open-source license notices (Section 9). |
| `version` | Print binary version, commit SHA, and Go build metadata (Section 10). |

Inspect subcommand flags with `rungv COMMAND --help`. Every flag accepts single-dash (`-e`) and double-dash (`--env`) forms. On `run`, flags precede the image name, short flag clusters expand (`-itP`, `-itp 8080:80`, `-eKEY=VAL`, `-w/app`, `-m512m`), `-h` sets the hostname, and arguments after `--` or the image name pass verbatim to the guest. Non-execution commands accept flags before or after positional arguments.

---

## 3. `rungv run`

The synopsis is `rungv run [flags] IMAGE [COMMAND [ARG...]]`. The first positional argument names the OCI image; subsequent arguments replace image `Cmd` while preserving `Entrypoint`. To run a local Linux ELF64 binary directly, invoke `rungv run [flags] -bin=ELF [ARG...]`, where trailing arguments form its complete `argv`.

### Recommended Flag Spellings for Engine vs. Architecture

To avoid ambiguity between the host execution engine and the Linux image architecture, adopt these two canonical flags across scripts and documentation:

- **`--backend ENGINE`** (`auto`, `whpx`, `hvf`, or `systrap`): Selects the execution engine on the host.
- **`--platform linux/ARCH`** (`linux/amd64` or `linux/arm64`): Selects the OCI image architecture.

Legacy aliases (`-platform ENGINE` without a slash, and `-arch ARCH`) remain supported for backward compatibility, though setting conflicting values for `--backend` and `-platform ENGINE` fails with a usage error.

### 3.1 Docker-Compatible Flags

| Flag | Meaning |
| :--- | :--- |
| `-e`, `--env KEY=VALUE` | Set a guest environment variable; `KEY` alone inherits the host variable if present. |
| `--env-file FILE` | Load `KEY=VALUE` and `KEY` entries, ignoring blank lines and `#` comments. |
| `--entrypoint PROGRAM` | Override image `Entrypoint` (empty string clears it) and discard image `Cmd`. |
| `-u`, `--user USER[:GROUP]` | Execute as a guest user by name or numeric UID/GID. |
| `-h`, `--hostname NAME` | Set guest hostname (default: `gvx`). |
| `-w`, `--workdir DIR` | Set guest working directory (also accepted on `restore`). |
| `--name NAME` | Set kernel container ID and derive the default control socket path under `--control`. |
| `--rm` | Accepted for compatibility; every sandbox cleans up upon exit. |
| `-i` | Accepted for compatibility; `rungv` stdin always feeds guest stdin. |
| `-t` | Allocate a guest pseudo-terminal. |
| `-p`, `--publish [IP:][HOST:]GUEST[/PROTO]` | Publish a guest port. Omitting `HOST` or passing `0` chooses a free `127.0.0.1` port. Equal-length ranges (`8000-8009:8000-8009`) publish each port. `unix:PATH:GUEST` exposes guest TCP over a host Unix socket (Section 4.7). |
| `-P` | Publish every port declared by image `EXPOSE` to free `127.0.0.1` ports. |
| `--auto-publish` | Dynamically publish guest TCP listeners and `iptables` NAT `DNAT` ports on `127.0.0.1` (or `--auto-publish-addr`). Static `-p` rules retain precedence (Section 4.7). |
| `--auto-publish-addr IP` | Override the host bind IP literal for `--auto-publish` (requires `--auto-publish` and NAT mode). |
| `-v`, `--volume SRC:DST[:ro\|rw]` | Mount a host directory, a single host regular file, or a named volume. Creates missing host directories before lockdown. |
| `--mount type=bind\|volume\|tmpfs\|overlay,...` | Docker key-value mount syntax supporting `src`, `dst`, `readonly`, `driver=ext4lite\|hostfs`, `size`, `ephemeral`, `upper`, and `tmpfs-size`. A volume `src` with a path separator names a host `.ext4` file. |
| `--tmpfs PATH[:size=64m,ro]` | Mount an in-memory `tmpfs` directory. |
| `--read-only` | Mount the guest root filesystem read-only (incompatible with `-rootfs-volume`). |
| `-m`, `--memory SIZE` | Cap guest memory (`b`, `k`, `m`, `g`, `t`; minimum `6m`). |
| `--cpus N` | Set online guest CPU count (rounded up) and Sentry CFS CPU bandwidth quota (decimal, such as `1.5`). |
| `--pids-limit N` | Cap total guest tasks via root `cgroup2` `pids.max` (`0` means unlimited). |
| `--network NAME` | `bridge` and `nat` select NAT; `none` and `wg` select isolated or WireGuard modes; `host` is refused. |
| `--platform linux/ARCH` | Recommended flag for OCI image architecture (`linux/amd64` or `linux/arm64`). |
| `--pull POLICY` | Registry resolution policy: `missing` (default), `always`, or `never` (Section 5.1). |

The Docker detach flag `-d` is rejected with an error because `rungv` runs strictly in the foreground.

### 3.2 `gvx`-Specific Flags

| Flag | Meaning |
| :--- | :--- |
| `-image REF`, `-bin ELF` | Specify an OCI image or local ELF64 binary by flag rather than positionally. |
| `--backend BACKEND` | Recommended flag for the execution backend: `auto`, `whpx`, `hvf`, or `systrap`. |
| `-platform BACKEND` | Legacy alias for `--backend` when the argument contains no slash; arguments with a slash select the image platform. |
| `-allow-unconfined-systrap` | Permit `--backend=auto` on Windows to fall back to `systrap` when `whpx` is unavailable. Use only for trusted workloads. |
| `-arch ARCH` | Legacy alias for selecting guest architecture (defaults to host CPU architecture). |
| `-workspace DIR`, `-ro` | Mount an existing host directory at `/workspace` (optionally read-only). Unlike `-v`, `DIR` must exist beforehand. |
| `-rootfs-volume NAME\|PATH` | Mount a named `.ext4` volume or host `.ext4` file as the persistent root overlay upper layer. |
| `-net MODE`, `-wg-conf FILE`, `-isolate-lan` | Select network mode (`nat`, `wg`, `none`), WireGuard config file, or RFC1918/loopback blocking. |
| `--net-tx-bps N`, `--net-rx-bps N` | Cap NAT egress and ingress bandwidth in bits per second (`0` removes the cap). |
| `--nat-policy-file FILE` | Load a host NAT policy (`.json`, `.yaml`, or `.yml`) on `run` or `restore` (Section 4.14). |
| `--privileged` | Enabled by default; turns on `--net-raw`, `--allow-packet-socket-write`, and `--allow-suid`. `--privileged=false` disables all three; explicit flags override. |
| `--net-raw` | Permit guest raw sockets and legacy `iptables` (required by `dockerd` and `k3s`). |
| `--allow-packet-socket-write` | Permit guest writes on `AF_PACKET` sockets (requires `--net-raw`). |
| `--allow-suid` | Honor `setuid`/`setgid` bits on guest executables (`sudo`, `su`, `passwd`). |
| `--host-ca-certs` | Inject host root CA certificates into the guest upper layer (Section 4.10). |
| `-registry-url URL` | Override the registry base URL for an image reference. |
| `--host-dns IP[:PORT]` | Explicit host DNS server (repeatable; overrides `/etc/resolv.conf` discovery for DNS relay and registry pulls; also accepted by `pull`, `push`, and `save`). |
| `-cache-dir DIR` | Override the layer cache directory. |
| `-keep-blobs` | Retain original compressed layer blobs in cache (default from `GVX_KEEP_BLOBS`) for offline `save` and `push`. |
| `-checkpoint-dir DIR` | Pre-open a host directory before lockdown to hold local checkpoint bundle files. |
| `-S`, `--control-socket SPEC` | Bind an owner-only Unix socket or loopback TCP listener before lockdown for `gvx-ctrl/2`. |
| `--control` | Automatically bind an owner-only Unix control socket derived from `--name NAME`. |
| `--control-policy POLICY` | Baseline control capability profile: `default`, `readonly`, or `checkpoint-only`. |
| `--control-disable CAPS` | Comma-separated control capabilities or groups to disable (for example, `exec,net.dial`). |
| `--control-token-file PATH` | Write the per-run 256-bit token to `PATH` and require token auth even on POSIX Unix sockets. |
| `--dynamic-ports` | Allow runtime `rungv port add` loopback (`127.0.0.1`, `[::1]`) binds under host lockdown. |
| `--dynamic-ports-addr IP` | Allow runtime `rungv port add` binds on the given host IP literal (repeatable). |
| `--unix-forward SPEC` | Forward a guest Unix socket to a host Unix socket (`GUEST_PATH=HOST_SOCKET[,uid=N,gid=N,mode=0600]`, repeatable) via a pre-lockdown helper. |
| `--allow-volume-attach` | Enable Linux seccomp rules permitting runtime `ext4lite` volume attach over `SCM_RIGHTS`. |
| `--allow-bind-attach` | Enable runtime `hostfs` bind attach over `SCM_RIGHTS` (skips Linux Landlock while keeping seccomp; Windows uses `rungv mount serve`). |
| `-lockdown=false` | Disable host self-lockdown (debugging only). |
| `--tune KEY=VALUE` | Set a host-side tunable (repeatable; Section 3.3). Accepted by `run`, `restore`, image commands, `system`, and `info`. |
| `--tune-file FILE` | Load host-side tunables from a JSON object (`--tune` flags take precedence). |

### 3.3 Tunables

Tunables configure host-side ceilings and timeouts for which Linux defines no guest `sysctl`. Guest kernel settings continue to use `sysctl`, `/sys/module`, and netlink. One central registry in `pkg/gvx/tuning` drives `gvx.Config.Tuning`, `--tune`, `--tune-file`, `rungv tune list`, and the reference table below.

Durations follow Go syntax (`250ms`, `30s`); sizes accept byte counts or binary suffixes (`64MiB`). Invalid keys, malformed values, or out-of-range settings fail immediately with the valid range.

1. Run `rungv tune list` to list every key, default, and range.
2. Pass `--tune net.nat.mtu=9000` (repeatable) or `--tune-file FILE` with JSON (`{"net.nat.mtu": 9000, "net.dns.timeout": "8s"}`).
3. Supply `--tune` to image commands (`rungv pull`, `rungv load`) when adjusting `oci.*` limits.

`TestDocsMatchRegistry` in `pkg/gvx/tuning` enforces synchronization between the registry and the table below. After editing `pkg/gvx/tuning`, regenerate the table with `go test ./pkg/gvx/tuning -run TestDocsMatchRegistry -update`.

<!-- tuning:begin -->
| Key | Type | Default | Range | Unit | Description |
| :--- | :--- | ---: | :--- | :--- | :--- |
| `net.nat.mtu` | int | 1500 | 68 to 65535 | bytes | MTU of eth0 in the nat network mode at the start of the guest. |
| `net.nat.udp_sessions` | int | 512 | 1 to 1048576 | sessions | Number of guest UDP flows that the NAT relays at once; a new flow ends the oldest one. |
| `net.udp.idle_timeout` | duration | 30s | 10ms to 24h | time | Time without a datagram in either direction after which the NAT or a published UDP port ends a session. |
| `net.nat.dial_timeout` | duration | 10s | 100ms to 10m | time | Time that the NAT waits for a host TCP connection before it refuses the guest connection. |
| `net.nat.syn_backlog` | int | 1024 | 1 to 1048576 | connections | Number of guest TCP connection requests that the NAT holds while it dials the host. |
| `net.dns.timeout` | duration | 4s | 100ms to 1m | time | Time that the DNS relay at 10.0.2.3 waits for a guest query, a host lookup, and a reply. |
| `net.dns.upstream_timeout` | duration | 2s | 100ms to 1m | time | Time that one exchange of the DNS relay with one host DNS server may take. |
| `net.forward.udp_sessions` | int | 1024 | 1 to 1048576 | sessions | Number of host client sessions that one published UDP port relays at once. |
| `net.forward.guest_dial_window` | duration | 3s | 10ms to 10m | time | Time that a published TCP port waits for the guest to listen before it closes the host client. |
| `net.forward.guest_dial_interval` | duration | 15ms | 1ms to 10s | time | Pause between two attempts of a published TCP port to reach the guest listener. |
| `net.forward.max_port_range` | int | 1024 | 1 to 65535 | ports | Largest number of ports in one range of a publish specification, such as 30000-32767. |
| `net.forward.max_dynamic_ports` | int | 64 | 1 to 256 | ports | Largest number of host loopback ports that auto-publish opens at once. |
| `net.forward.dynamic_poll_interval` | duration | 200ms | 20ms to 10s | time | Pause between two scans of guest listeners and iptables NAT rules when auto-publish is on. |
| `net.wg.queue_length` | int | 512 | 1 to 1048576 | packets | Number of packets that the eth0 queue holds in the wg network mode. |
| `net.wg.resolve_timeout` | duration | 10s | 100ms to 10m | time | Time that the sandbox waits to resolve the host name of the WireGuard peer endpoint. |
| `memory.guard.poll_interval` | duration | 5ms | 1ms to 10s | time | Time between two readings of the guest memory use when the sandbox has a memory limit. |
| `memory.guard.host_poll_interval` | duration | 100ms | 1ms to 10s | time | Time between two readings of the guest memory use when the limit is the RAM of the host. |
| `memory.cgroup.poll_interval` | duration | 5ms | 1ms to 10s | time | Shortest time between two checks of memory.max while a cgroup uses half of its limit. |
| `memory.cgroup.idle_poll_interval` | duration | 25ms | 1ms to 10s | time | Time between two checks of memory.max while every limited cgroup uses less than half of its limit. |
| `memory.cgroup.scan_ratio` | int | 4 | 1 to 1000 | ratio | The checks of memory.max use at most one over this number of a CPU. |
| `kernel.log_buf_len` | size | 128KiB | 4KiB to 2GiB | bytes | Size of the guest kernel log ring that /dev/kmsg and dmesg read, rounded up to a power of two. |
| `oci.max_json_bytes` | size | 8MiB | 64KiB to 1GiB | bytes | Largest index, manifest, or config body that a pull accepts. |
| `oci.max_blob_bytes` | size | 32GiB | 1MiB to 1TiB | bytes | Largest compressed layer that a pull accepts. |
| `oci.max_layer_bytes` | size | 64GiB | 1MiB to 1TiB | bytes | Largest decompressed tar stream of one layer. |
| `oci.max_image_bytes` | size | 128GiB | 1MiB to 1TiB | bytes | Largest sum of the decompressed layers of one image. |
| `oci.max_entry_bytes` | size | 32GiB | 1KiB to 1TiB | bytes | Largest regular file in a layer. |
| `oci.max_entries` | int | 2000000 | 1 to 1099511627776 | entries | Largest number of tar entries in one layer. |
| `oci.max_archive_entries` | int | 1000000 | 1 to 1099511627776 | entries | Largest number of members in an image archive. |
| `oci.max_zstd_window_bytes` | size | 128MiB | 1MiB to 16GiB | bytes | Largest zstd window that a layer may ask for; the decoder allocates this much memory. |
| `oci.registry_idle_timeout` | duration | 1m | 1s to 24h | time | Time that a registry request may go without data before the pull fails. |
| `control.max_connections` | int | 64 | 1 to 1024 | connections | Largest number of concurrent client connections accepted on the control socket. |
| `control.max_exec_sessions` | int | 32 | 1 to 512 | sessions | Largest number of concurrent exec sessions running in one sandbox. |
| `control.handshake_timeout` | duration | 10s | 100ms to 5m | time | Time allowed for a control client to complete the initial handshake. |
| `control.max_frame_bytes` | size | 256KiB | 16KiB to 4MiB | bytes | Largest payload frame accepted on the control socket. |
<!-- tuning:end -->

`kernel.log_buf_len` rounds up to a power of two and drops oldest records when full. Guest processes adjust log policy through `/proc/sys/kernel/printk_devkmsg` (`on`, `off`, `ratelimit`), `dmesg_restrict`, and `printk`.

`net.nat.mtu` sets the initial NAT `eth0` MTU; WireGuard mode reads `MTU` from `[Interface]` (default `1420`). Dropping a link MTU below `1280` strips its IPv6 addresses and routes until raised again. Changing MTU inside the guest requires `CAP_NET_ADMIN` (`ip link set dev eth0 mtu 1400` or `ifconfig eth0 mtu 1400`).

| Guest Link | Permitted MTU Range |
| :--- | :--- |
| `eth0` (NAT mode) | `68` to `65535` |
| `eth0` (WireGuard mode, Linux and macOS) | `68` to `65503` |
| `eth0` (WireGuard mode, Windows) | `68` to `1984` |
| Guest `veth` or `bridge` | `68` to `65535` |
| `lo` | Accepts request and retains `65536` |

---

## 4. Operational Semantics of `run`

This section summarizes how `rungv run` resolves commands, users, mounts, resource limits, networking, certificates, checkpoints, and control operations.

### 4.1 Command and Environment

Guest `argv` concatenates `Entrypoint` and `Cmd`, with CLI flags overriding image defaults. Passing `--entrypoint` discards the image `Cmd`, matching Docker. Environment variables apply in order: image `Env`, `--env-file`, then `-e`. Default `PATH`, `HOME`, and `HOSTNAME` are populated when absent, and `-t` adds `TERM=xterm`.

### 4.2 User and Permissions

Guest identity resolves from `--user`, then image `User`, else `root`. Named accounts resolve against image `/etc/passwd` and `/etc/group`; numeric IDs need not exist in `/etc/passwd` (unlisted UIDs receive GID `0` and home `/`). Passing `name` alone loads supplementary groups, whereas `name:group` sets none. Non-root users start without Linux capabilities, and `/` carries mode `0755`.

### 4.3 Hostname

The runtime writes the guest hostname to `/etc/hostname` and ensures `/etc/hosts` maps both the hostname and `host.docker.internal` (pointing to the host gateway `10.0.2.2`).

### 4.4 Mounts and Volumes

`rungv` supports four mount classes:

- **Named `ext4lite` volumes (`-v NAME:DST[:ro]`, default driver)**: Stored as `<NAME>.ext4` under `<cacheDir>/volumes/` (`[a-zA-Z0-9][a-zA-Z0-9_.-]*`). Images grow in 16 MiB steps up to 64 TiB, maintain an ordered JBD2 journal, acquire `LOCK_EX` (read-write) or `LOCK_SH` (read-only), compact unused tail blocks on clean exit, and require zero post-lockdown host path rules. In `--mount type=volume`, a `src` containing a path separator targets a host `.ext4` file directly; `size=SIZE` caps growth; `ephemeral` creates a one-run scratch image in `ephemeral-volumes/` and disables checkpointing.
- **Copy-on-write volume overlays (`--mount type=overlay,src=BASE,dst=PATH[,upper=BRANCH][,tmpfs-size=SIZE]`)**: Branches a shared read-only base volume into either a persistent upper volume or an ephemeral `tmpfs` upper layer.
- **Host bind mounts (`-v HOST:DST[:ro]`, `--mount type=bind`, `-workspace DIR`)**: Backed by `hostfs` (see [`components/hostfs.md`](components/hostfs.md)). `-v` creates missing directories (never missing single files); `--mount type=bind` and `-workspace` require an existing source path. Single-file mounts expose only that regular file without writing `.gvx_meta`; Windows defaults unrecorded host files to `0755` (`0555` read-only). `-rootfs-volume NAME|PATH` mounts an `ext4lite` image as the persistent root overlay upper layer.
- **Memory mounts (`--tmpfs PATH[:size=64m,ro]`)**: Pure in-memory directories.

Guest destinations must be clean absolute paths and may not overwrite `/`, `/proc`, `/sys`, `/dev`, or subpaths other than `/dev/shm`.

| Host OS | Lockdown Enforcement for Host Bind Mounts |
| :--- | :--- |
| macOS | Seatbelt read rules (and write rules when writable) scoped to the mount path and its resolved target. |
| Windows | Pre-lockdown `winMountBroker` pins directory and single-file parent handles without altering NTFS ACLs. |
| Linux | Landlock ruleset confines path opens to mounted paths before `seccomp` restricts syscalls. |

### 4.5 Resource Limits

- **`--memory`**: Enforced by a polling guard (`memory.guard.poll_interval`, default `5 ms`; defaults to host physical RAM polled every `100 ms` when unset) sending `SIGKILL` (exit code `137`) upon overrun. `/proc/meminfo` (`MemTotal`) and `sysinfo(2)` report the lesser of `--memory` and host RAM. Nested guest cgroups enforce `memory.max` similarly (see [`recipes/docker-engine.md`](recipes/docker-engine.md#74-memory-limits-of-containers)).
- **`--cpus`**: Sets online guest CPU count (rounded up) and enforces a tamper-proof Sentry CFS bandwidth quota across all platforms (plus a Windows Job Object CPU rate cap under lockdown). Nested cgroups enforce `cpu.max`.
- **`--pids-limit`**: Sets root `cgroup2` `pids.max` so guest root cannot raise its process cap.

### 4.6 Guest Kernel Environment

Guests receive `/proc`, `/sys`, `/sys/fs/cgroup` (`cgroup2`), `/dev`, `/dev/pts`, `/dev/shm`, `/dev/mqueue`, `/dev/fuse`, `/dev/net/tun`, and network interfaces `lo` and `eth0`. Because the root filesystem mounts over a hidden read-only root, `pivot_root(2)` works for nested `runc` containers. Calling `reboot(2)` as guest root terminates `rungv` with exit code `0` (halt/poweroff) or `129` (restart).

### 4.7 Published Ports

Static `-p` ports bind before lockdown and print one stderr line each (`rungv: publishing 127.0.0.1:49493 -> 8080/tcp`). Equal-length ranges support up to `net.forward.max_port_range` (default `1,024`) ports. `-p unix:PATH:GUEST` binds an owner-only host Unix socket (expanding leading `~/`, replacing stale socket files on subsequent runs, and refusing commas in `PATH`).

With `--auto-publish`, `rungv` polls guest TCP listeners and `iptables` NAT `DNAT` rules every `net.forward.dynamic_poll_interval` (default `200 ms`) and binds matching host `127.0.0.1` ports up to `net.forward.max_dynamic_ports` (default `64`). Static `-p` bindings always keep precedence.

### 4.8 Raw Sockets, Netfilter, and `conntrack`

`--privileged` is on by default because its capabilities stay strictly inside the sandbox. The guest stack implements legacy `iptables` (`filter`, `nat`, `mangle`, `raw`; `nftables` is unavailable) with matches `addrtype`, `comment`, `conntrack` (`--ctstate`), `icmp`, `icmp6`, `limit`, `mark`, `multiport`, `owner`, `physdev`, `recent`, `set`, `statistic`, `tcp`, and `udp`, targets including `DNAT`, `LOG` (root netns to `/dev/kmsg`), `NFLOG` (accepted no-op), and `SET`, plus `conntrack` netlink and `ipset` (`hash:*`, `bitmap:port`, `list:set`). Connection tracking obeys `/proc/sys/net/netfilter/*` timeouts and `nf_conntrack_max` (default `262,144`, ~500 bytes per tracked flow).

### 4.9 Failures and Diagnostics

`--backend=auto` chooses `hvf` on macOS, `systrap` on Linux and Android, and `whpx` on Windows (failing closed if WHP is absent unless `-allow-unconfined-systrap` opts into `systrap`, which emits a stderr warning and records `Sandbox.FallbackReason`).

`rungv` distinguishes two causes of exit code `137`: exceeding `--memory` prints a memory-limit message, whereas an underlying engine failure prints `the execution engine stopped the guest` with the cause (`ErrEngineFault` in the SDK). Set `GVX_DEBUG_LOG=1` (or `2`), `GVX_STRACE=1`, or `GVX_SYSTRAP_TRACE=1..4` for detailed traces (see [`troubleshooting.md`](troubleshooting.md)).

### 4.10 Host Root Certificates

Pass `--host-ca-certs` (`Config.HostCACerts`) behind a TLS-inspecting proxy or private CA. Before lockdown, `rungv` reads host roots from `SSL_CERT_FILE`/`SSL_CERT_DIR` and system trust stores: `/etc/ssl/certs` and `/etc/pki/tls/certs` on Linux; `System.keychain`, `SystemRootCertificates.keychain`, and `login.keychain-db` on macOS (honoring denials); and the `ROOT` store on Windows. At startup, missing roots append to existing image PEM bundles in the writable upper layer (or create `/etc/ssl/certs/ca-certificates.crt`) and drop anchor files in `/usr/local/share/ca-certificates` and `/etc/pki/ca-trust/source/anchors`.

> [!WARNING]
> `--host-ca-certs` affects direct sandbox processes only. Nested containers run by `dockerd` have separate root filesystems; see [`recipes/docker-engine.md`](recipes/docker-engine.md#6-operating-behind-a-tls-inspecting-proxy).

```sh
rungv run --host-ca-certs alpine:3.20 wget -qO- https://example.com/
SSL_CERT_FILE=$PWD/corp-root.pem rungv run --host-ca-certs alpine:3.20 wget -qO- https://registry.corp.example/
```

### 4.11 Checkpoint and Restore

A checkpoint directory holds four files (`manifest.json`, `state.img`, `pages.meta`, `pages.img`). Because lockdown blocks new opens, pre-open `-checkpoint-dir` and `-control-socket` at start (or stream directly with `rungv checkpoint -o`). `rungv restore` validates host OS, architecture, backend, address holes, layer digests, mounts, `root_volume`, and network mode before re-applying lockdown.

Bundles omit NAT bandwidth limits and NAT firewall rules: pass `--net-tx-bps`/`--net-rx-bps` or `--nat-policy-file` explicitly on restore. Checkpointing a sandbox with a protected NAT policy requires supplying a policy file on restore.

> [!IMPORTANT]
> Supply the same workspace, bind mounts, named volumes, and `-rootfs-volume` on `restore`; pass `--serve HOST:GUEST[:ro|rw]` to reattach `rpcfs` mounts immediately, and close bandwidth-shaped control tunnels before checkpointing.

1. Start a sandbox with `-checkpoint-dir` and `-control-socket`.
2. Trigger a checkpoint from a second terminal.
3. Restore the bundle in a new process with matching mounts.

```sh
mkdir -p ./work ./ckpt
rungv run -checkpoint-dir=./ckpt -control-socket=./ckpt.sock -workspace=./work alpine:3.20 sh -c "sleep 30" &
sleep 1
rungv checkpoint -control-socket=./ckpt.sock -checkpoint-dir=./ckpt
rungv restore -checkpoint-dir=./ckpt -workspace=./work
```

### 4.12 Control Socket Subcommands

Control commands accept `-S`/`--control-socket SPEC` (`GVX_CONTROL_SOCKET`), `-n`/`--name NAME` (for `--control`), `--token` (`GVX_CONTROL_TOKEN`), `--token-file`, and `--timeout`. See [`control-protocol.md`](control-protocol.md) for the complete specification.

| Command | Synopsis and Notes |
| :--- | :--- |
| `exec` | `rungv exec [-i] [-t] [-d] [-e K=V] [--env-file F] [-w DIR] [-u USER] [--privileged=BOOL] [--detach-keys K] [--pid-file F] [--] CMD [ARG...]` |
| `pause` / `unpause` | `rungv pause [--quiesce-net=true\|false]` and `rungv unpause`. |
| `cp` / `export` | `rungv cp [-a] [-L] [-q] [-z] [--no-overwrite-dir] [--user U:G] SRC DST` and `rungv export [--upper-only] [-z] [-o FILE\|-] [PATH]`. Host disk I/O runs in the unlocked client. |
| `update` | `rungv update [-m SIZE] [--force-memory] [--cpus N] [--cpu-quota US] [--cpu-period US] [--pids-limit N] [--isolate-lan=BOOL] [--net-tx-bps N] [--net-rx-bps N] [--tune K=V]...` |
| `net-policy` | `rungv net-policy get` and `rungv net-policy replace --file FILE`. |
| `port` / `port-forward` | `rungv port <ls\|add\|rm>` (requires `--dynamic-ports` or `--auto-publish`) and `rungv port-forward` (`pf`, tunnels over `net.dial` without relaxing lockdown). |
| `unix-forward` | `rungv unix-forward [--replace] GUEST_PATH=HOST_SOCKET[,uid=N,gid=N,mode=0600]` (`uf`). |
| `mount` | `rungv mount <ls\|add\|remount\|rm\|serve>`. `mount serve HOST:GUEST` serves a pinned host directory or file via `rpcfs` with `inotify`. |
| `status`, `stats`, `top`, `dmesg`, `events`, `kill`, `stop`, `ping`, `debug` | Inspect state, stream counters or kernel logs, deliver signals, stop PID 1 cleanly, or set Sentry verbosity. |

### 4.13 NAT Bandwidth Limits

`--net-tx-bps` (guest egress) and `--net-rx-bps` (guest ingress) share one token bucket per direction across NAT relays, DNS, published ports, and `port-forward` tunnels (`0` is unlimited; NAT mode only; 256 KiB burst per direction). Stream relays throttle; full packet queues drop. The Go SDK does not combine bandwidth limits with `Config.StreamInterceptor`.

```sh
rungv run --net=nat --net-tx-bps 2000000 --net-rx-bps 8000000 --name app --control alpine:3.20 sleep 600
rungv update -n app --net-tx-bps 4000000
rungv update -n app --net-rx-bps 0
```

### 4.14 Host NAT Policy

`--nat-policy-file` enforces an IPv4/IPv6 firewall at the host NAT boundary, outside guest `iptables`. Policy files (`.json`, `.yaml`, or `.yml`; 64 KiB maximum; single YAML document without aliases or merge keys; quote numeric port strings such as `ports: "443"`) define `egress` and `ingress` chains, each with `default` (`allow` or `deny`) and up to 1,024 ordered rules matching optional `cidr`, `guest_cidr`, `protocol` (`tcp`, `udp`, `icmp`, `icmpv6`, or `1`..`255`), and `ports` (single port or inclusive range).

Rules are evaluated first-match; unreadable fields fail closed; `-isolate-lan` overrides `allow`; NAT dials to the sandbox's own TCP control listener are blocked; active IP policies refuse Unix socket publications. Replacing a policy via `rungv net-policy replace` cancels active relays denied by the new policy without mutating bandwidth settings.

```json
{
  "egress": {
    "default": "deny",
    "rules": [{"action": "allow", "protocol": "tcp", "ports": "443"}]
  },
  "ingress": {"default": "deny"}
}
```

---

## 5. Images, Registries, and Host DNS

Image references obey the Docker grammar (host with `.` or `:` or `localhost`; otherwise Docker Hub with `library/` for single-segment names; default tag `latest`; `@sha256:` digests; lowercase repositories only). Registries use HTTPS except loopback (`localhost`, `127.0.0.0/8`, `[::1]`). Credentials resolve from `$DOCKER_CONFIG/config.json` (`credHelpers`, `credsStore`, `auths`), with 30 s / 1 MiB helper bounds. `rungv login` verifies credentials before saving.

### 5.1 Pull Policy

| Policy | Resolution Order |
| :--- | :--- |
| `missing` | Use local cache; query the registry only when absent (default). |
| `always` | Query registry first; falls back to cache with a stderr warning if the registry is unreachable or returns HTTP 401/403/404 for locally loaded images. |
| `never` | Use local cache strictly; fail if absent. |

### 5.2 Host DNS Servers

Hosts lacking `/etc/resolv.conf` (such as Android apps) fail default Go DNS lookups against `[::1]:53`. Pass `--host-dns IP[:PORT]` (repeatable or comma-separated) to `run`, `pull`, `push`, or `save` (`Config.HostDNSServers` and `LayerCache.SetDNSServers` in Go) to supply explicit resolvers for both the guest DNS relay (`10.0.2.3`) and registry pulls without altering global process state.

```sh
rungv run --host-dns 10.0.2.3 alpine:3.20 nslookup example.com
```

---

## 6. Storage, System, and Shell Completion Commands

Docker-style noun-verb groups administer local images, named volumes, diagnostics, and completions. Top-level aliases (`images`, `pull`, `push`, `rmi`, `inspect`, `tag`, `save`, `load`, `info`) remain available.

### 6.1 Image Store (`rungv image`)

The layer cache lives under `%LOCALAPPDATA%\gvx\cache\layers` (Windows), `~/Library/Caches/gvx/layers` (macOS), or `~/.cache/gvx/layers` (Linux). Passing `-keep-blobs` (or `GVX_KEEP_BLOBS=1`) retains compressed blobs under `blobs/sha256/<hex>`.

| Command | Behavior |
| :--- | :--- |
| `rungv image ls` (`images`) | List cached images (`-a`, `-q`, `--no-trunc`, `--digests`, `--format`). |
| `rungv image pull` (`pull`) | Download an image (`--platform linux/ARCH`, `-registry-url`, `-keep-blobs`, `--host-dns`). |
| `rungv image push` (`push`) | Upload a cached image (`IMAGE [TARGET]`) with `HEAD` checks, cross-repo mounts, and stdin/FD auth flags. |
| `rungv image inspect` (`inspect`) | Print JSON metadata array or evaluate `-f`/`--format`. |
| `rungv image rm` (`rmi`) | Untag or delete unreferenced layers and kept blobs (`-f` for multi-tagged IDs). |
| `rungv image tag` (`tag`) | Add a second reference to a cached image. |
| `rungv image save` (`save`) | Write an OCI and `docker save` tar archive (offline when `-keep-blobs` retained all layers). |
| `rungv image load` (`load`) | Import images for the target architecture from a tar archive (`-keep-blobs` supported). |
| `rungv image prune [-a] [-f]` | Remove dangling (or all `-a`) images and orphan layers; report reclaimed bytes. |

### 6.2 Named Volumes (`rungv volume`)

`rungv volume` inspects `ext4lite` host file locks (`ProbeVolumeLock`) and refuses to compact or delete any mounted volume.

| Command | Behavior |
| :--- | :--- |
| `rungv volume create [-d ext4lite\|hostfs] [NAME]` | Format an `ext4lite` volume (default) or `hostfs` directory (random 64-hex name if omitted). |
| `rungv volume ls [-q] [--format SPEC]` | List local volumes sorted by name. |
| `rungv volume inspect [-f SPEC] NAME...` | Print volume metadata (`SizeBytes`, `AllocatedBytes`, `InUse`, `LockMode`, etc.). |
| `rungv volume compact NAME...` | Replay pending journals, punch freed blocks, and shrink tail groups on unlocked `ext4lite` volumes. |
| `rungv volume rm [-f] NAME...` | Delete unlocked volumes (`-f` ignores missing names; mounted volumes still fail). |
| `rungv volume prune [-f]` | Remove all unlocked local volumes and print reclaimed bytes. |

### 6.3 System Diagnostics (`rungv system`) and Templates

| Command or Format | Behavior |
| :--- | :--- |
| `rungv system info` (`info`) | Probe `whpx`, `hvf`, and `systrap`, report lockdown profile, and list cache/volume counts. |
| `rungv system df [-v] [--format SPEC]` | Report total, active, and reclaimable space for images and volumes (`-v` adds detail tables). |
| `rungv system prune [-a] [--volumes] [-f]` | Prune unused images and optionally unlocked volumes. |
| `--format json` / `'{{.Field}}'` / `'table ...'` | Emit NDJSON or evaluate Go `text/template` with helpers `json`, `lower`, `upper`, `join`, `split`, `truncate`. |

### 6.4 Shell Completion

| Shell | Activation Command |
| :--- | :--- |
| Bash | `source <(rungv completion bash)` |
| Zsh | `source <(rungv completion zsh)` (after `compinit`) |
| Fish | `rungv completion fish \| source` |
| PowerShell | `rungv completion powershell \| Out-String \| Invoke-Expression` |

---

## 7. Summary of Differences from Docker

| Docker Feature | `rungv` Behavior |
| :--- | :--- |
| `-d`, `ps`, `logs`, `rm`, `restart` | Unavailable (no daemon); live commands require `-S`/`--control-socket` or `--control`. |
| `docker build`, `compose`, `network` | Unavailable directly; run `docker:dind` inside `gvx` (see [`recipes/docker-engine.md`](recipes/docker-engine.md)). |
| Image `VOLUME`, `HEALTHCHECK`, `STOPSIGNAL`, labels | Ignored. |
| `--network host` | Refused; guest owns an isolated network stack. |
| `-p HOST-RANGE:PORT` | Refused; port ranges must share equal length. |
| `--privileged` | On by default; privileges remain strictly inside the sandbox. |
| Docker manifest schema 1 | Rejected with an error. |
| Cgroup v1 | Unavailable; `/sys/fs/cgroup` mounts `cgroup2`. |
| Foreign guest architecture | Unsupported; guest architecture must match host CPU. |
| Root filesystem writes | Ephemeral unless `-rootfs-volume` is supplied. |

---

## 8. Compact Command Examples

```sh
# Run as UID 1000 with an environment variable and read-only bind mount
rungv run -u 1000 -e MODE=test -v "$PWD":/src:ro -w /src alpine:3.20 sh -c 'ls; id'

# Publish all EXPOSE ports to ephemeral host loopback ports
rungv run -P nginx:alpine

# Create an ext4lite volume, run with memory limit, and inspect disk usage
rungv volume create appdata
rungv run -m512m -v appdata:/var/lib/app alpine:3.20 sh -c "date > /var/lib/app/stamp"
rungv run -rootfs-volume rootstate alpine:3.20 sh -c "echo saved > /etc/custom"
rungv system df -v

# Export and re-import an image archive
rungv save -o alpine.tar alpine:3.20
rungv load -i alpine.tar
```

---

## 9. `rungv license`

`rungv license [-list]` prints the embedded notice file (`cmd/rungv/licenses/THIRD_PARTY_LICENSES.txt`) covering `gvx`, upstream gVisor, the Go standard library, and every linked third-party module. Passing `-list` prints one summary line per module with version and SPDX identifier. Regenerate notices with `go run ./tools/licenses -o cmd/rungv/licenses/THIRD_PARTY_LICENSES.txt` and verify both the file and `README.md` with `go run ./tools/licenses -check`.

---

## 10. `rungv version`

`rungv version` (or `rungv --version`) prints module version, Git commit SHA and timestamp (`modified` if dirty), and Go toolchain/target architecture level (`GOAMD64` or `GOARM64`). Include its full output in every bug or security report.

---

## 11. Nested Execution

Running `rungv` inside an outer sandbox exercises `ptrace`, `seccomp`, shared memory, futexes, and architecture signal frames provided by the outer kernel.

> [!IMPORTANT]
> Place a statically linked Linux `rungv` binary inside the outer guest (`CGO_ENABLED=0 go build -o rungv-static ./cmd/rungv`), as minimal guests lack the host C library loader.

### 11.1 `rungv` Inside `rungv`

An inner `rungv --backend=systrap` executes inside an outer `rungv` running on Linux `systrap` (`amd64` and `arm64`, including KVM-less cloud VMs) or macOS `hvf` (slower). The inner sandbox prints a benign warning (`seccomp user-space notification mechanism isn't supported`) and uses its futex wake loop.

1. Compile a static Linux binary: `CGO_ENABLED=0 go build -o rungv-static ./cmd/rungv`.
2. Build the smoke ELF binary: `go run ./internal/testelf/cmd/mkelf -o smoke`.
3. Run nested execution: `rungv run --backend=systrap -v "$PWD/smoke:/smoke:ro" -bin ./rungv-static -- run --backend=systrap -bin /smoke`.
4. Confirm the output prints `gvx-smoke-ok`.

### 11.2 `rungv` Inside Docker with Upstream `runsc`

Under upstream `runsc` (`release-20261102.0`, both `--platform=kvm` and `--platform=systrap`), `linux/amd64` nested runs succeed with `--backend=systrap -net=none -lockdown=false` because inner `rungv` adapts to four `runsc` divergences (fixed-map alignment order, zero fault error codes, `ARCH_SET_GS` clearing outer patches, and per-mapping unmap around sealed outer patch tables). On `linux/arm64`, upstream `runsc` omits `fpsimd_context` from signal frames, causing stub exit code `137`.

### 11.3 Nested Limits

On `amd64`, inner stub processes inherit the outer Sentry's sealed syscall-patching table (`0x60000` to `0x65000`), preventing guest mappings in that range. Hardware backends are unavailable inside an outer guest.

---

## 12. Android Operation

On `android/arm64`, `--backend=auto` selects `systrap` because unprivileged Android apps cannot access `/dev/kvm`. See [`components/android.md`](components/android.md) for library packaging and build details.

### 12.1 Process Model and Phantom Process Ceiling

`dev.gfire.gvx.Gvx` starts `librungv.so` from the application's native library directory and passes active network resolvers via `--host-dns`. Because Android SELinux denies `linkat` hard links on app-data files (`EACCES`), use `ext4lite` volumes for workloads needing hard links.

Each live guest address space holds one stub process and at most two `sysmsg` processes on Android. Android 12+ counts all app child processes system-wide and terminates the oldest once the total exceeds 32, causing `the execution engine stopped the guest`. Android also terminates CPU-intensive background child processes.

| Android Version | Disable 32-Process Ceiling | Disable Background CPU Limit |
| :--- | :--- | :--- |
| 12 | `adb shell device_config put activity_manager max_phantom_processes 2147483647` | None |
| 12L and 13 | `adb shell settings put global settings_enable_monitor_phantom_procs false` | Same setting |
| 14 and later | Developer Options: "Disable child process restrictions" | Same setting |

### 12.2 Sustaining Long-Running Android Workloads

1. Launch `librungv.so` from an Android foreground service (as `android/sample` does).
2. Keep concurrent guest processes below 10 when operating under default system limits.
3. Disable child-process restrictions using the table above if builds require higher concurrency.
