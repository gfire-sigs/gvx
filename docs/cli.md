# The `rungvx` Command Line

`rungvx` executes an OCI container image or a Linux ELF64 binary in the foreground inside one self-confined sandbox. Its subcommands, flags, and output follow Docker CLI conventions wherever the single-process model applies.

The CLI compiles image layers into read-only EROFS files, opens all host mounts and sockets, and locks down the host process before entering the guest. This single-process design requires no root privileges, no kernel driver, and no background daemon.

Consult [`architecture.md`](architecture.md) for system internals, [`compatibility.md`](compatibility.md) for workload status, and [`troubleshooting.md`](troubleshooting.md) for failure diagnosis.

---

## 1. Execution Model

`rungvx` operates without a background daemon. Each `rungvx run` invocation starts a sandbox, executes the guest command, and tears down all resources upon exit.

By default, guest writes land in an ephemeral memory-backed `tmpfs` upper layer above read-only EROFS image layers. Data persists across runs only through a bind mount, a named volume, a `-rootfs-volume` image, or the host image cache.

Before entering the guest, `rungvx` applies OS self-lockdown (`hostlockdown.Apply()`), blocking forks, unbound opens, and sockets unless `--auto-publish`, `--dynamic-ports`, or `-S` authorizes them ([`control-protocol.md`](control-protocol.md)).

---

## 2. Subcommand Overview

Run `rungvx help` to print the CLI summary. Every flag accepts single-dash (`-e`) and double-dash (`--env`) forms. On `run`, place flags before the image name; short clusters expand (`-itP`, `-itp 8080:80`, `-eKEY=VAL`, `-w/app`, `-m512m`). Arguments after `--` or the image name pass verbatim to the guest, while non-execution commands accept flags anywhere.

### 2.1 Sandbox Lifecycle

Use these subcommands to launch, pause, signal, and stop sandboxes.

| Command | Purpose |
| :--- | :--- |
| `run` | Execute a command inside an OCI image or a local Linux ELF64 binary. |
| `exec` | Spawn a command inside a running sandbox over its control socket (stdin closed unless `-i`). |
| `pause` | Suspend all guest tasks in a running sandbox (`--quiesce-net=true` by default). |
| `unpause` | Resume guest tasks in a paused sandbox. |
| `kill` | Deliver a POSIX signal to PID 1, a specific guest PID, or all guest processes. |
| `stop` | Stop a sandbox with a grace timeout before escalating to `SIGKILL`. |

### 2.2 Live Control, Inspection, and Checkpointing

Use these subcommands over a control socket (`-S` or `--control`) to inspect, update, and checkpoint live sandboxes.

| Command | Purpose |
| :--- | :--- |
| `status` | Inspect a running sandbox over its control socket (also `rungvx sandbox inspect`). |
| `stats` | Display live CPU, memory, network, block I/O, and PID counters. |
| `top` | List running processes inside a sandbox. |
| `dmesg` | Read or follow records from the guest kernel log ring. |
| `events` | Stream filtered lifecycle events from a running sandbox. |
| `ping` | Verify control socket readiness and advertised capabilities. |
| `debug` | Adjust the active Sentry log level (`warning`, `info`, or `debug`). |
| `update` | Modify live memory, CPU quota, PID limit, LAN isolation, NAT bandwidth, or mutable tunables. |
| `checkpoint` | Capture a checkpoint bundle for a running sandbox (alias: `snapshot`). |
| `restore` | Resume a sandbox from a checkpoint bundle directory (alias: `resume`). |

### 2.3 Images and Registries

Use these subcommands to pull, push, inspect, tag, archive, and remove local OCI images.

| Command | Purpose |
| :--- | :--- |
| `pull` | Fetch an OCI image into the local layer cache (`--platform linux/ARCH`; `-keep-blobs`). |
| `push` | Push a cached image to a registry using OCI Distribution v1.1 (`rungvx push [flags] IMAGE [TARGET]`). |
| `images` | List cached images. |
| `inspect` | Print cached image metadata as JSON or through a Go template. |
| `tag` | Add a repository or tag alias to a cached image. |
| `rmi` | Remove an image tag or delete an unreferenced image. |
| `save` | Export cached images to an OCI and `docker save` tar archive. |
| `load` | Import images from a tar archive (`-keep-blobs` retains original compressed blobs). |
| `image` | Group command for `ls`, `pull`, `push`, `rm`, `inspect`, `tag`, `save`, `load`, and `prune`. |
| `login` | Authenticate and store registry credentials in Docker config. |
| `logout` | Remove stored registry credentials. |

### 2.4 Filesystems, Volumes, and Networking

Use these subcommands to copy files, attach runtime mounts, administer volumes, publish ports, and update NAT rules.

| Command | Purpose |
| :--- | :--- |
| `cp` | Copy files or directories between the host and a running sandbox via tar streams. |
| `export` | Export a sandbox filesystem or overlay upper layer (`--upper-only`) as a tar archive. |
| `mount` | Group command for `ls`, `add`, `remount`, `rm`, and `serve` on runtime mounts. |
| `volume` | Group command for `create`, `ls`, `inspect`, `compact`, `rm`, and `prune` on local volumes. |
| `net-policy` | Read (`get`) or replace (`replace`) the active host NAT policy over the control socket. |
| `port` | Group command for `ls`, `add`, and `rm` on published sandbox ports. |
| `port-forward` | Tunnel host TCP or Unix connections into a running sandbox via the control socket (alias: `pf`). |
| `unix-forward` | Forward guest Unix socket connections to a host Unix socket via the control socket (alias: `uf`). |

### 2.5 System, Diagnostics, and Licensing

Use these subcommands to inspect host capabilities, reclaim disk space, generate completions, and view build or license metadata.

| Command | Purpose |
| :--- | :--- |
| `system` | Group command for `info`, `df`, and `prune` on host backends and local storage. |
| `info` | Report host OS, available backends, lockdown profile, and storage paths. |
| `completion` | Emit shell completion scripts for `bash`, `zsh`, `fish`, or `powershell`. |
| `stub` | Probe `systrap` readiness on the active host. |
| `tune` | List host-side tunables (`rungvx tune list`; Section 3.3). |
| `license` | Print embedded open-source license notices (Section 9). |
| `version` | Print binary version, commit SHA, Go build metadata, and build options (Section 10). |

Inspect flags for any subcommand with `rungvx COMMAND --help`.

---

## 3. `rungvx run`

The synopsis is `rungvx run [flags] IMAGE [COMMAND [ARG...]]`. The first positional argument names the OCI image; trailing arguments replace `Cmd` while keeping `Entrypoint`. To run a Linux ELF64 binary directly, invoke `rungvx run [flags] -bin=ELF [ARG...]`, where trailing arguments form its `argv`.

### Recommended Flag Spellings for Engine vs. Architecture

Adopt these two canonical flags across scripts and automation to separate the host engine from the image architecture:

- **`--backend ENGINE`** (`auto`, `whpx`, `hvf`, or `systrap`): Selects the execution engine on the host.
- **`--platform linux/ARCH`** (`linux/amd64` or `linux/arm64`): Selects the OCI image architecture.

Legacy aliases (`-platform ENGINE` without a slash, and `-arch ARCH`) still work. Conflicting `--backend` and `-platform ENGINE` values fail with a usage error.

### 3.1 Docker-Compatible Flags

These flags match standard Docker CLI options where `rungvx`'s single-process model applies.

| Flag | Meaning |
| :--- | :--- |
| `-e`, `--env KEY=VALUE` | Set a guest environment variable; `KEY` alone inherits the host variable if set. |
| `--env-file FILE` | Load `KEY=VALUE` and `KEY` entries, ignoring blank lines and `#` comments. |
| `--entrypoint PROGRAM` | Override image `Entrypoint` (empty string clears it) and discard image `Cmd`. |
| `-u`, `--user USER[:GROUP]` | Execute as a guest user by name or numeric UID/GID. |
| `-h`, `--hostname NAME` | Set guest hostname (default: `gvx`). |
| `-w`, `--workdir DIR` | Set guest working directory (also accepted on `restore`). |
| `--name NAME` | Set kernel container ID and derive the default socket path under `--control`. |
| `--rm` | Accepted for compatibility; every sandbox cleans up upon exit. |
| `-i` | Accepted for compatibility; `rungvx` stdin always feeds guest stdin. |
| `-t` | Allocate a guest pseudo-terminal. |
| `-p`, `--publish [IP:][HOST:]GUEST[/PROTO]` | Publish a guest port (omitting `HOST` or `0` picks free `127.0.0.1`). Supports equal ranges (`8000-8009:8000-8009`) and `unix:PATH:GUEST` (Section 4.7). |
| `-P` | Publish every port declared by image `EXPOSE` to free `127.0.0.1` ports. |
| `--auto-publish` | Publish guest TCP listeners and NAT `DNAT` ports on `127.0.0.1` (or `--auto-publish-addr`). Static `-p` keeps precedence. |
| `--auto-publish-addr IP` | Override the host bind IP literal for `--auto-publish` (requires NAT mode). |
| `-v`, `--volume SRC:DST[:ro\|rw]` | Mount a host directory, single regular file, or named volume. Creates missing host directories before lockdown. |
| `--mount type=bind\|volume\|tmpfs\|overlay,...` | Docker mount syntax (`src`, `dst`, `readonly`, `symlinks`, `driver`, `size`, `ephemeral`, `upper`, `tmpfs-size`). A `src` with a path separator names a `.ext4` file. |
| `--tmpfs PATH[:size=64m,ro]` | Mount an in-memory `tmpfs` directory. |
| `--read-only` | Mount the guest root filesystem read-only (incompatible with `-rootfs-volume`). |
| `-m`, `--memory SIZE` | Cap guest memory (`b`, `k`, `m`, `g`, `t`; minimum `6m`). |
| `--cpus N` | Set rounded-up online guest CPUs and Sentry CFS quota (decimal, such as `1.5`). |
| `--pids-limit N` | Cap total guest tasks via root `cgroup2` `pids.max` (`0` means unlimited). |
| `--network NAME` | `bridge` and `nat` select NAT; `none` and `wg` select isolated or WireGuard; `host` is refused. |
| `--platform linux/ARCH` | Recommended flag for OCI image architecture (`linux/amd64` or `linux/arm64`). |
| `--pull POLICY` | Registry resolution policy: `missing` (default), `always`, or `never` (Section 5.1). |

`rungvx` rejects `-d` with `-d is not supported` because it runs strictly in the foreground with no background daemon.

### 3.2 `gvx`-Specific Flags

These flags configure execution backends, volumes, host lockdown, networking limits, DNS, and the control socket.

| Flag | Meaning |
| :--- | :--- |
| `-image REF`, `-bin ELF` | Specify an OCI image or local ELF64 binary by flag rather than positionally. |
| `--backend BACKEND` | Recommended flag for the execution backend: `auto`, `whpx`, `hvf`, or `systrap`. |
| `-platform BACKEND` | Legacy alias for `--backend` without a slash; values with a slash select image platform. |
| `-allow-unconfined-systrap` | Allow Windows `--backend=auto` fallback to `systrap` when `whpx` is unavailable (trusted workloads only). |
| `-gpu MODE` | Enable optional virtio-gpu (`off`, `venus`, or `virgl`; requires a `-tags ext_gpu` build on macOS 26+ `arm64`, Section 4.15). |
| `-gpu-renderer PATH` | Select the `gvx-gpu-renderer` binary for `-gpu=venus` or `-gpu=virgl` (overrides `GVX_GPU_RENDERER`). |
| `-gpu-memory-limit SIZE` | Cap imported GPU shared memory per sandbox (for example `512m` or `2g`; requires `-gpu`). |
| `-arch ARCH` | Legacy alias for selecting guest architecture (defaults to host CPU architecture). |
| `-workspace DIR`, `-ro` | Mount an existing host directory at `/workspace` (optionally read-only). Unlike `-v`, `DIR` must exist. |
| `-rootfs-volume NAME\|PATH` | Mount a named `.ext4` volume or host `.ext4` file as the persistent root overlay. |
| `-net MODE`, `-wg-conf FILE`, `-isolate-lan` | Select network mode (`nat`, `wg`, `none`), WireGuard config file, or RFC1918/loopback blocking. |
| `--net-tx-bps N`, `--net-rx-bps N` | Cap NAT egress and ingress bandwidth in bits per second (`0` removes the cap). |
| `--nat-policy-file FILE` | Load a host NAT policy (`.json`, `.yaml`, or `.yml`) on `run` or `restore` (Section 4.14). |
| `--privileged` | Enabled by default; turns on `--net-raw`, `--allow-packet-socket-write`, and `--allow-suid` (`=false` clears them). |
| `--net-raw` | Permit guest raw sockets and legacy `iptables` (required by `dockerd` and `k3s`). |
| `--allow-packet-socket-write` | Permit guest writes on `AF_PACKET` sockets (requires `--net-raw`). |
| `--allow-suid` | Honor `setuid`/`setgid` bits on guest executables (`sudo`, `su`, `passwd`). |
| `--host-ca-certs` | Inject host root CA certificates into the guest upper layer (Section 4.10). |
| `-registry-url URL` | Override the registry base URL for an image reference. |
| `--host-dns IP[:PORT]` | Explicit host DNS server (repeatable; accepted by `run`, `pull`, `push`, and `save`). |
| `-cache-dir DIR` | Override the layer cache directory. Named volumes then live in `DIR/volumes` unless `-volume-dir` is set. |
| `-volume-dir DIR` | Override the named volume directory (takes precedence over `-cache-dir` and `GVX_VOLUME_DIR`). |
| `-keep-blobs` | Retain compressed layer blobs in cache (`GVX_KEEP_BLOBS`) for offline `save` and `push`. |
| `-checkpoint-dir DIR` | Pre-open a host directory before lockdown to hold local checkpoint bundle files. |
| `-S`, `--control-socket SPEC` | Bind an owner-only Unix socket or loopback TCP listener before lockdown for `gvx-ctrl/2`. |
| `--control` | Automatically bind an owner-only Unix control socket derived from `--name NAME`. |
| `--control-policy POLICY` | Baseline control capability profile: `default`, `readonly`, or `checkpoint-only`. |
| `--control-disable CAPS` | Comma-separated control capabilities or groups to disable (for example, `exec,net.dial`). |
| `--control-token-file PATH` | Write the 256-bit token to `PATH` and require token auth on POSIX Unix sockets. |
| `--dynamic-ports` | Allow runtime `rungvx port add` loopback (`127.0.0.1`, `[::1]`) binds under host lockdown. |
| `--dynamic-ports-addr IP` | Allow runtime `rungvx port add` binds on the given host IP literal (repeatable). |
| `--unix-forward SPEC` | Forward a guest Unix socket (`GUEST_PATH=HOST_SOCKET[,uid=N,gid=N,mode=0600]`, repeatable) via pre-lockdown helper. |
| `--allow-volume-attach` | Enable Linux seccomp rules permitting runtime `ext4lite` volume attach over `SCM_RIGHTS`. |
| `--allow-bind-attach` | Enable runtime `hostfs` bind attach over `SCM_RIGHTS` (skips Landlock on Linux; Windows uses `mount serve`). |
| `-lockdown=false` | Disable host self-lockdown (debugging only). |
| `--tune KEY=VALUE` | Set a host-side tunable (repeatable; Section 3.3). Accepted by `run`, `restore`, image, `system`, and `info`. |
| `--tune-file FILE` | Load host-side tunables from a JSON object (`--tune` flags take precedence). |

### 3.3 Tunables

Tunables configure host-side ceilings and timeouts for which Linux defines no guest `sysctl`. Guest kernel settings continue to use `sysctl`, `/sys/module`, and netlink. One central registry in `pkg/gvx/tuning` drives `gvx.Config.Tuning`, `--tune`, `--tune-file`, `rungvx tune list`, and the reference table below.

Durations follow Go syntax (`250ms`, `30s`); sizes accept byte counts or binary suffixes (`64MiB`). Invalid keys, malformed values, or out-of-range settings fail immediately with the valid range.

1. Run `rungvx tune list` to list every key, default, and range.
2. Pass `--tune net.nat.mtu=9000` (repeatable) or `--tune-file FILE` with JSON.
3. Supply `--tune` to `rungvx pull` or `rungvx load` when adjusting `oci.*` limits.

`TestDocsMatchRegistry` in `pkg/gvx/tuning` checks synchronization between the registry and the table below. After editing `pkg/gvx/tuning`, regenerate the table with `go test ./pkg/gvx/tuning -run TestDocsMatchRegistry -update`.

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
| `net.link.queue_length` | int | 512 | 16 to 65536 | packets | Number of packets that the eth0 queue holds in the link network mode. |
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

This section defines how `rungvx run` resolves commands, users, mounts, resource limits, networking, certificates, checkpoints, and control operations.

### 4.1 Command and Environment

Guest `argv` concatenates `Entrypoint` and `Cmd`, with CLI flags overriding image defaults. Passing `--entrypoint` discards image `Cmd`, matching Docker. Environment variables apply in order: image `Env`, `--env-file`, then `-e`. Default `PATH`, `HOME`, and `HOSTNAME` populate when absent, and `-t` adds `TERM=xterm`.

### 4.2 User and Permissions

Guest identity resolves from `--user`, then image `User`, else `root`. Named accounts resolve against guest `/etc/passwd` and `/etc/group`; unlisted numeric UIDs receive GID `0` and home `/`. Passing `name` alone loads supplementary groups, whereas `name:group` sets none. Non-root users start without Linux capabilities, and `/` carries mode `0755`.

### 4.3 Hostname

The runtime writes the guest hostname to `/etc/hostname` and maps both the hostname and `host.docker.internal` to `10.0.2.2` in `/etc/hosts`.

### 4.4 Mounts and Volumes

`rungvx` supports four mount classes:

- **Named `ext4lite` volumes (`-v NAME:DST[:ro]`, default driver)**: Stored as `<NAME>.ext4` in the volume directory of [Section 6.2](#62-named-volumes-rungvx-volume) (`[a-zA-Z0-9][a-zA-Z0-9_.-]*`). Images grow in 16 MiB steps up to 64 TiB and keep an ordered JBD2 journal. Mounts hold `LOCK_EX` (read-write) or `LOCK_SH` (read-only), compact trailing blocks on clean exit, and need no post-lockdown path rules. In `--mount type=volume`, a `src` with a path separator targets a host `.ext4` file directly. `size=SIZE` caps growth, while `ephemeral` creates a scratch image under the cache directory (`ephemeral-volumes/`) and disables checkpointing.
- **Copy-on-write volume overlays (`--mount type=overlay,src=BASE,dst=PATH[,upper=BRANCH][,tmpfs-size=SIZE]`)**: Branches a shared read-only base volume into a persistent upper volume or an ephemeral `tmpfs` upper layer.
- **Host bind mounts (`-v HOST:DST[:ro]`, `--mount type=bind`, `-workspace DIR`)**: Backed by `hostfs` (see [`components/hostfs.md`](components/hostfs.md)). `-v` creates missing directories (never missing single files), whereas `--mount type=bind` and `-workspace` require existing paths. Single-file mounts expose only that regular file without writing `.gvx_meta`; Windows defaults unrecorded host files to `0755` (`0555` read-only). `-rootfs-volume NAME|PATH` mounts an `ext4lite` image as the persistent root overlay.
- **Memory mounts (`--tmpfs PATH[:size=64m,ro]`)**: Pure in-memory directories.

Guest destinations must be clean absolute paths and cannot overwrite `/`, `/proc`, `/sys`, `/dev`, or subpaths other than `/dev/shm`.

| Host OS | Lockdown Enforcement for Host Bind Mounts |
| :--- | :--- |
| macOS | Seatbelt read rules (and write rules when writable) scoped to the mount path and its resolved target. |
| Windows | Pre-lockdown `winMountBroker` pins directory and single-file parent handles without altering NTFS ACLs. |
| Linux | Landlock ruleset confines path opens to mounted paths before `seccomp` restricts syscalls. |

### 4.5 Resource Limits

- **`--memory`**: A polling guard (`memory.guard.poll_interval`, default `5 ms`, or `100 ms` against host RAM when unset) sends `SIGKILL` (`137`) upon overrun. `/proc/meminfo` and `sysinfo(2)` report the lesser of `--memory` and host RAM. Nested cgroups enforce `memory.max` similarly (see [`recipes/docker-engine.md`](recipes/docker-engine.md#74-memory-limits-of-containers)).
- **`--cpus`**: Sets online guest CPUs (rounded up) and enforces a Sentry CFS quota on every platform. Windows also applies a Job Object CPU rate cap under lockdown; nested cgroups enforce `cpu.max`.
- **`--pids-limit`**: Sets root `cgroup2` `pids.max` so guest root cannot raise its task limit.

### 4.6 Guest Kernel Environment

Guests receive `/proc`, `/sys`, `/sys/fs/cgroup` (`cgroup2`), `/dev`, `/dev/pts`, `/dev/shm`, `/dev/mqueue`, `/dev/fuse`, `/dev/net/tun`, `lo`, and `eth0`. Because the root filesystem mounts over a hidden read-only root, `pivot_root(2)` works for nested `runc` containers. Calling `reboot(2)` as guest root terminates `rungvx` with exit code `0` (halt) or `129` (restart).

### 4.7 Published Ports

Static `-p` ports bind before lockdown and print one stderr line each (`rungvx: publishing 127.0.0.1:49493 -> 8080/tcp`). Equal-length ranges support up to `net.forward.max_port_range` (default `1,024`) ports. `-p unix:PATH:GUEST` binds an owner-only host Unix socket, expands leading `~/`, replaces stale socket files, and refuses commas in `PATH`.

With `--auto-publish`, `rungvx` polls guest TCP listeners and `iptables` NAT `DNAT` rules every `net.forward.dynamic_poll_interval` (default `200 ms`). It binds matching host `127.0.0.1` ports up to `net.forward.max_dynamic_ports` (default `64`), while static `-p` bindings keep precedence.

### 4.8 Raw Sockets, Netfilter, and `conntrack`

`--privileged` is enabled by default because its capabilities remain strictly inside the sandbox. The guest stack implements legacy `iptables` (`filter`, `nat`, `mangle`, `raw`; `nftables` is unavailable) plus `conntrack` netlink and `ipset` (`hash:*`, `bitmap:port`, `list:set`).

Supported matches include `addrtype`, `comment`, `conntrack`, `icmp`, `icmp6`, `limit`, `mark`, `multiport`, `owner`, `physdev`, `recent`, `set`, `statistic`, `tcp`, and `udp`. Targets include `DNAT`, `LOG` (to `/dev/kmsg`), `NFLOG` (no-op), and `SET`; `conntrack` obeys `/proc/sys/net/netfilter/*` timeouts and `nf_conntrack_max` (default `262,144`).

### 4.9 Failures and Diagnostics

`--backend=auto` selects `hvf` on macOS, `systrap` on Linux and Android, and `whpx` on Windows. On Windows, `auto` fails closed when WHP is absent unless `-allow-unconfined-systrap` opts into `systrap`, emitting a warning and setting `Sandbox.FallbackReason`.

`rungvx` distinguishes two exit code `137` causes: exceeding `--memory` prints a memory-limit message, while engine failures print `the execution engine stopped the guest` (`ErrEngineFault`). Set `GVX_DEBUG_LOG=1` (or `2`), `GVX_STRACE=1`, or `GVX_SYSTRAP_TRACE=1..4` for traces (see [`troubleshooting.md`](troubleshooting.md)).

### 4.10 Host Root Certificates

Pass `--host-ca-certs` (`Config.HostCACerts`) behind a TLS-inspecting proxy or private CA. Before lockdown, `rungvx` reads `SSL_CERT_FILE`, `SSL_CERT_DIR`, and OS trust stores: `/etc/ssl/certs` and `/etc/pki/tls/certs` on Linux, macOS keychains (honoring denials), and the Windows `ROOT` store.

At startup, missing roots append to existing PEM bundles in the writable upper layer (or create `/etc/ssl/certs/ca-certificates.crt`). The injector also writes anchor files in `/usr/local/share/ca-certificates` and `/etc/pki/ca-trust/source/anchors`.

> [!WARNING]
> `--host-ca-certs` affects direct sandbox processes only. Nested containers run by `dockerd` have separate root filesystems; see [`recipes/docker-engine.md`](recipes/docker-engine.md#6-operating-behind-a-tls-inspecting-proxy).

```sh
rungvx run --host-ca-certs alpine:3.20 wget -qO- https://example.com/
SSL_CERT_FILE=$PWD/corp-root.pem rungvx run --host-ca-certs alpine:3.20 wget -qO- https://registry.corp.example/
```

### 4.11 Checkpoint and Restore

A checkpoint directory holds four files (`manifest.json`, `state.img`, `pages.meta`, `pages.img`). Pre-open `-checkpoint-dir` and `-control-socket` at startup (or stream with `rungvx checkpoint -o`), because lockdown blocks new host opens. `rungvx restore` validates host OS, architecture, backend, address holes, layer digests, mounts, `root_volume`, and network mode before re-applying lockdown.

Bundles omit NAT bandwidth caps and NAT firewall rules: pass `--net-tx-bps`/`--net-rx-bps` or `--nat-policy-file` explicitly on restore. Checkpointing a sandbox with an active NAT policy requires supplying a policy file on restore.

> [!IMPORTANT]
> Supply matching workspace, bind mounts, named volumes, and `-rootfs-volume` on `restore`. Pass `--serve HOST:GUEST[:ro|rw]` to reattach `rpcfs` mounts, and close throttled control tunnels before checkpointing.

1. Start a sandbox in Terminal 1 with pre-opened `-checkpoint-dir` and `-S`.
2. Trigger a checkpoint from Terminal 2.
3. Restore the bundle in a new process with matching mounts.

```sh
# Terminal 1
mkdir -p ./work ./ckpt
rungvx run -checkpoint-dir=./ckpt -S ./ckpt.sock -workspace=./work alpine:3.20 sh -c "sleep 300"

# Terminal 2
rungvx checkpoint -S ./ckpt.sock -checkpoint-dir=./ckpt
rungvx restore -checkpoint-dir=./ckpt -workspace=./work
```

### 4.12 Control Socket Subcommands

Control commands accept `-S`/`--control-socket SPEC` (`GVX_CONTROL_SOCKET`), `-n`/`--name NAME` (for `--control`), `--token` (`GVX_CONTROL_TOKEN`), `--token-file`, and `--timeout`. See [`control-protocol.md`](control-protocol.md) for wire framing and capabilities.

| Command | Synopsis and Notes |
| :--- | :--- |
| `exec` | `rungvx exec [-i] [-t] [-d] [-e K=V] [--env-file F] [-w DIR] [-u USER] [--privileged=BOOL] [--detach-keys K] [--pid-file F] [--] CMD [ARG...]` |
| `pause` / `unpause` | `rungvx pause [--quiesce-net=true\|false]` and `rungvx unpause`. |
| `cp` / `export` | `rungvx cp [-a] [-L] [-q] [-z] [--no-overwrite-dir] [--user U:G] SRC DST` and `rungvx export [--upper-only] [-z] [-o FILE\|-] [PATH]`. Host I/O runs in the client. |
| `update` | `rungvx update [-m SIZE] [--force-memory] [--cpus N] [--cpu-quota US] [--cpu-period US] [--pids-limit N] [--isolate-lan=BOOL] [--net-tx-bps N] [--net-rx-bps N] [--tune K=V]...` |
| `net-policy` | `rungvx net-policy get` and `rungvx net-policy replace --file FILE`. |
| `port` / `port-forward` | `rungvx port <ls\|add\|rm>` (needs `--dynamic-ports` or `--auto-publish`) and `rungvx port-forward` (`pf`, tunnels over `net.dial`). |
| `unix-forward` | `rungvx unix-forward [--replace] GUEST_PATH=HOST_SOCKET[,uid=N,gid=N,mode=0600]` (`uf`). |
| `mount` | `rungvx mount <ls\|add\|remount\|rm\|serve>`. `mount serve HOST:GUEST` serves a pinned path via `rpcfs` with `inotify`. |
| `status`, `stats`, `top`, `dmesg`, `events`, `kill`, `stop`, `ping`, `debug` | Inspect state, stream counters or logs, send signals, stop PID 1, or set verbosity. |

### 4.13 NAT Bandwidth Limits

`--net-tx-bps` (egress) and `--net-rx-bps` (ingress) share one token bucket per direction (`256 KiB` burst; `0` unlimited; NAT only). The cap covers NAT relays, DNS, published ports, and `port-forward` tunnels. Stream relays throttle while full packet queues drop; Go callers cannot combine bandwidth caps with `Config.StreamInterceptor`.

```sh
rungvx run --net=nat --net-tx-bps 2000000 --net-rx-bps 8000000 --name app --control alpine:3.20 sleep 600
rungvx update -n app --net-tx-bps 4000000
rungvx update -n app --net-rx-bps 0
```

### 4.14 Host NAT Policy

`--nat-policy-file` enforces an IPv4/IPv6 firewall at the host NAT boundary, outside guest `iptables`. Policy files (`.json`, `.yaml`, or `.yml`; `64 KiB` max; no YAML aliases or merge keys) define `egress` and `ingress` chains with `default` (`allow` or `deny`). Each chain supports up to 1,024 ordered rules matching `cidr`, `guest_cidr`, `protocol` (`tcp`, `udp`, `icmp`, `icmpv6`, or `1`..`255`), and `ports` (quote strings like `ports: "443"`).

Rules evaluate first-match, unreadable fields fail closed, and `-isolate-lan` overrides `allow`. NAT dials to the sandbox's TCP control listener fail, and active policies refuse Unix socket publications. `rungvx net-policy replace` cancels active relays denied by the updated policy without changing bandwidth caps.

```json
{
  "egress": {
    "default": "deny",
    "rules": [{"action": "allow", "protocol": "tcp", "ports": "443"}]
  },
  "ingress": {"default": "deny"}
}
```

### 4.15 GPU Extension (`-tags ext_gpu`)

Build `ext/cmd/rungvx` with `-tags ext_gpu` (or `-tags ext_all`) to include `-gpu=venus` and `-gpu=virgl`. Both active modes require Apple Silicon (`darwin/arm64`), macOS 26 or later, the `hvf` backend, and `gvx-gpu-renderer`. Confirm support with `rungvx version -V`, which prints `extension gpu: modes=venus,virgl`.

| Rule | Behavior |
| :--- | :--- |
| **Renderer search** | Checks `-gpu-renderer`, `GVX_GPU_RENDERER`, `gvx-gpu-renderer/bin/gvx-gpu-renderer` beside `rungvx`, then `../libexec/gvx-gpu-renderer/bin/gvx-gpu-renderer`. |
| **Missing renderer** | Exits with an error listing searched paths or stderr output. Never falls back silently to software rendering. |
| **Guest drivers** | `venus` requires guest `mesa-vulkan-drivers`; `virgl` requires guest `libgl1-mesa-dri` and `libegl-mesa0`. |
| **Checkpointing** | Refuses `-checkpoint-dir`, `rungvx restore`, and control-socket checkpoints. Other control subcommands stay active. |
| **Memory cap** | Defaults to the smaller of 4 GiB and 25% of host RAM; override with `-gpu-memory-limit`. |
| **Renderer exit** | Returns I/O errors to guest GPU calls without restarting the worker. |

---

## 5. Images, Registries, and Host DNS

Image references obey Docker grammar with an explicit registry host (`.` or `:` or `localhost`) or Docker Hub (`library/` for single-segment names). Repositories must be lowercase, defaulting to tag `latest` or `@sha256:` digests. Registries use HTTPS except loopback (`localhost`, `127.0.0.0/8`, `[::1]`). Credentials resolve from `$DOCKER_CONFIG/config.json` (`credHelpers`, `credsStore`, `auths`) within 30 s and 1 MiB bounds; `rungvx login` verifies credentials before saving.

### 5.1 Pull Policy

| Policy | Resolution Order |
| :--- | :--- |
| `missing` | Use local cache; query the registry only when absent (default). |
| `always` | Query registry first; falls back to cache on unreachable registry or HTTP 401/403/404 for locally loaded images. |
| `never` | Use local cache strictly; fail if absent. |

### 5.2 Host DNS Servers

Hosts lacking `/etc/resolv.conf` (such as Android apps) fail default Go lookups against `[::1]:53`. Pass `--host-dns IP[:PORT]` (repeatable or comma-separated) to `run`, `pull`, `push`, or `save`. Those explicit resolvers configure the guest DNS relay (`10.0.2.3`) and registry pulls without mutating process DNS settings.

```sh
rungvx run --host-dns 1.1.1.1 alpine:3.20 nslookup example.com
```

---

## 6. Storage, System, and Shell Completion Commands

Docker-style noun-verb groups administer local images, named volumes, diagnostics, and completions. Top-level aliases (`images`, `pull`, `push`, `rmi`, `inspect`, `tag`, `save`, `load`, `info`) remain available.

### 6.1 Image Store (`rungvx image`)

The layer cache lives under `%LOCALAPPDATA%\gvx\cache\layers` (Windows), `~/Library/Caches/gvx/layers` (macOS), or `~/.cache/gvx/layers` (Linux). Passing `-keep-blobs` (or `GVX_KEEP_BLOBS=1`) retains compressed blobs under `blobs/sha256/<hex>`.

| Command | Behavior |
| :--- | :--- |
| `rungvx image ls` (`images`) | List cached images (`-a`, `-q`, `--no-trunc`, `--digests`, `--format`). |
| `rungvx image pull` (`pull`) | Download an image (`--platform linux/ARCH`, `-registry-url`, `-keep-blobs`, `--host-dns`). |
| `rungvx image push` (`push`) | Upload a cached image (`IMAGE [TARGET]`) with `HEAD` checks, cross-repo mounts, and auth flags. |
| `rungvx image inspect` (`inspect`) | Print JSON metadata array or evaluate `-f`/`--format`. |
| `rungvx image rm` (`rmi`) | Untag or delete unreferenced layers and kept blobs (`-f` for multi-tagged IDs). |
| `rungvx image tag` (`tag`) | Add a second reference to a cached image. |
| `rungvx image save` (`save`) | Write an OCI and `docker save` tar archive (offline when `-keep-blobs` retained all layers). |
| `rungvx image load` (`load`) | Import images for the target architecture from a tar archive (`-keep-blobs` supported). |
| `rungvx image prune [-a] [-f]` | Remove dangling (or all `-a`) images and orphan layers; report reclaimed bytes. |

### 6.2 Named Volumes (`rungvx volume`)

`rungvx volume` inspects `ext4lite` host file locks (`ProbeVolumeLock`) and refuses to compact or delete any mounted volume.

On macOS, Linux, and Android, named volumes live in the user data directory, because a host can purge its cache directory. macOS deletes the content of `~/Library/Caches` when the disk runs low. `rungvx system info` prints the active directory as `Volume Dir`.

| Source | Volume directory |
| :--- | :--- |
| `-volume-dir DIR` (`Config.VolumeDir`) | The given directory. It takes precedence over `-cache-dir` and `GVX_VOLUME_DIR`. |
| `-cache-dir DIR` (`Config.OCICacheDir`) | `DIR/volumes`. It takes precedence over `GVX_VOLUME_DIR`. |
| `GVX_VOLUME_DIR` | The given directory when neither `-volume-dir` nor `-cache-dir` is set. |
| Default on macOS | `~/Library/Application Support/gvx/volumes`. |
| Default on Linux and Android | `$XDG_DATA_HOME/gvx/volumes`, or `~/.local/share/gvx/volumes` when `XDG_DATA_HOME` is unset or relative. |
| Default on Windows | `%LOCALAPPDATA%\gvx\cache\volumes`. Windows does not purge this directory. |

Earlier releases kept the default volume directory on macOS, Linux, and Android beside the layer cache, for example `~/Library/Caches/gvx/volumes`. The first command that uses the default directory renames that directory to the new location. It leaves a symbolic link at the earlier path, so an earlier release finds the same volumes. When the rename fails, `gvx` keeps the volumes at the earlier location.

| Command | Behavior |
| :--- | :--- |
| `rungvx volume create [-d ext4lite\|hostfs] [NAME]` | Format an `ext4lite` volume (default) or `hostfs` directory (random 64-hex name if omitted). |
| `rungvx volume ls [-q] [--format SPEC]` | List local volumes sorted by name. |
| `rungvx volume inspect [-f SPEC] NAME...` | Print volume metadata (`SizeBytes`, `AllocatedBytes`, `InUse`, `LockMode`, etc.). |
| `rungvx volume compact NAME...` | Replay pending journals, punch freed blocks, and shrink tail groups on unlocked `ext4lite` volumes. |
| `rungvx volume rm [-f] NAME...` | Delete unlocked volumes (`-f` ignores missing names; mounted volumes still fail). |
| `rungvx volume prune [-f]` | Remove all unlocked local volumes and print reclaimed bytes. |

### 6.3 System Diagnostics (`rungvx system`) and Templates

These commands probe host backends, inspect storage usage, reclaim unused data, and format JSON or Go template output.

| Command or Format | Behavior |
| :--- | :--- |
| `rungvx system info` (`info`) | Probe `whpx`, `hvf`, and `systrap`, report lockdown profile, and list cache/volume counts. |
| `rungvx system df [-v] [--format SPEC]` | Report total, active, and reclaimable space for images and volumes (`-v` adds detail tables). |
| `rungvx system prune [-a] [--volumes] [-f]` | Prune unused images and optionally unlocked volumes. |
| `--format json` / `'{{.Field}}'` / `'table ...'` | Emit NDJSON or evaluate Go `text/template` with `json`, `lower`, `upper`, `join`, `split`, `truncate`. |

### 6.4 Shell Completion

Activate shell completions with one of the commands below.

| Shell | Activation Command |
| :--- | :--- |
| Bash | `source <(rungvx completion bash)` |
| Zsh | `source <(rungvx completion zsh)` (after `compinit`) |
| Fish | `rungvx completion fish \| source` |
| PowerShell | `rungvx completion powershell \| Out-String \| Invoke-Expression` |

---

## 7. Summary of Differences from Docker

This table summarizes places where `rungvx`'s single-process design intentionally differs from Docker.

| Docker Feature | `rungvx` Behavior |
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

Copy and run these examples to exercise user mapping, port publishing, persistent volumes, and image archives.

```sh
# Run as UID 1000 with an environment variable and read-only bind mount
rungvx run -u 1000 -e MODE=test -v "$PWD":/src:ro -w /src alpine:3.20 sh -c 'ls; id'

# Publish all EXPOSE ports to ephemeral host loopback ports
rungvx run -P nginx:alpine

# Create an ext4lite volume, run with memory limit, and inspect disk usage
rungvx volume create appdata
rungvx run -m512m -v appdata:/var/lib/app alpine:3.20 sh -c "date > /var/lib/app/stamp"
rungvx run -rootfs-volume rootstate alpine:3.20 sh -c "echo saved > /etc/custom"
rungvx system df -v

# Export and re-import an image archive
rungvx save -o alpine.tar alpine:3.20
rungvx load -i alpine.tar
```

---

## 9. `rungvx license`

`rungvx license [-list]` prints the embedded notice file (`pkg/rungvx/licenses/THIRD_PARTY_LICENSES.txt`) covering `gvx`, upstream gVisor, Go, and third-party modules. Passing `-list` prints one summary line per module with version and SPDX identifier. Regenerate notices with `go run ./tools/licenses -o pkg/rungvx/licenses/THIRD_PARTY_LICENSES.txt` and verify both files with `go run ./tools/licenses -check`.

---

## 10. `rungvx version`

`rungvx version` (`--version`) prints the module version, Git commit SHA, Go toolchain, and architecture baseline (`GOAMD64` or `GOARM64`). It also prints nginx-style `build options:` (`cgo`, tags, and compiled extensions). Pass `-V` (`rungvx version -V` or `rungvx -V`) to append compiler, build mode, `trimpath`, `SPIVersion`, and per-extension summaries. Include the full `rungvx version -V` output in every bug or security report.

---

## 11. Nested Execution

Running `rungvx` inside an outer sandbox exercises `ptrace`, `seccomp`, shared memory, futexes, and architecture signal frames provided by the outer kernel.

> [!IMPORTANT]
> Place a statically linked Linux `rungvx` binary inside the outer guest (`CGO_ENABLED=0 go build -o rungvx-static ./cmd/rungvx`). Minimal container images lack the host dynamic linker required by cgo binaries.

### 11.1 `rungvx` Inside `rungvx`

An inner `rungvx --backend=systrap` runs inside an outer `rungvx` on Linux `systrap` (`amd64` and `arm64`, including KVM-less cloud VMs) or macOS `hvf` (slower). The inner sandbox prints one warning (`seccomp user-space notification mechanism isn't supported`) and falls back to its futex wake loop.

1. Compile a static Linux binary: `CGO_ENABLED=0 go build -o rungvx-static ./cmd/rungvx`.
2. Build the smoke ELF binary: `go run ./internal/testelf/cmd/mkelf -o smoke`.
3. Run nested execution: `rungvx run --backend=systrap -v "$PWD/smoke:/smoke:ro" -bin ./rungvx-static -- run --backend=systrap -bin /smoke`.
4. Confirm the output prints `gvx-smoke-ok`.

### 11.2 `rungvx` Inside Docker with Upstream `runsc`

Under upstream `runsc` (`release-20261102.0`, `--platform=kvm` and `--platform=systrap`), `linux/amd64` nested runs succeed with `--backend=systrap -net=none -lockdown=false`. Inner `rungvx` adapts to `runsc`'s fixed-map ordering, zero fault codes, `ARCH_SET_GS` clearing outer patches, and unmapping around sealed outer patch tables. On `linux/arm64`, upstream `runsc` omits `fpsimd_context` from signal frames, causing stub exit code `137`.

### 11.3 Nested Limits

On `amd64`, inner stub processes inherit the outer Sentry's sealed syscall-patching table (`0x60000` to `0x65000`), preventing guest mappings there. Hardware hypervisor backends are unavailable inside an outer guest.

---

## 12. Android Operation

On `android/arm64`, `--backend=auto` selects `systrap` because unprivileged Android apps lack `/dev/kvm`. Android launches `librungvx.so` via `dev.gfire.gvx.Gvx` with app-private `HOME`/`TMPDIR` and active `--host-dns` resolvers; see [`components/android.md`](components/android.md) for packaging and kernel adaptations.

Because Android SELinux denies `linkat` hard links on app-data files (`EACCES`), use `ext4lite` volumes for workloads needing hard links. Android 12+ also terminates child processes when system-wide app children exceed 32 (`the execution engine stopped the guest`) and throttles CPU-heavy background children.

| Android Version | Disable 32-Process Ceiling | Disable Background CPU Limit |
| :--- | :--- | :--- |
| 12 | `adb shell device_config put activity_manager max_phantom_processes 2147483647` | None |
| 12L and 13 | `adb shell settings put global settings_enable_monitor_phantom_procs false` | Same setting |
| 14 and later | Developer Options: "Disable child process restrictions" | Same setting |

1. Launch `librungvx.so` from an Android foreground service (as `android/sample` does).
2. Keep concurrent guest processes below 10 under default system limits.
3. Disable child-process restrictions using the table above when builds require higher concurrency.
