# The `rungv` Command Line

`rungv` runs an OCI image or a Linux ELF64 binary in the foreground. Its flags and output follow the Docker CLI wherever the single-process sandbox model matches. This document covers every subcommand, every `rungv run` flag, runtime tunables, and all differences from Docker. See [`architecture.md`](architecture.md) for the internal architecture.

## 1. Model

`rungv` has no background daemon. Each run starts a sandbox, executes the guest command, and tears down everything on exit, behaving like `docker run --rm`.

By default, guest writes go to an ephemeral memory-backed layer above the read-only image layers. Data persists after exit only in a bind mount, a named volume, a `-rootfs-volume` image, or the host image store.

The host process locks itself down before the guest starts. After lockdown, it cannot open unbound host files, spawn child processes, or bind arbitrary sockets (unless `--auto-publish` opts into host `127.0.0.1` loopback binds). Because every host resource is prepared up front and no daemon exists, `rungv` has no `exec`, `logs`, or `-d` mode.

## 2. Commands

Run `rungv help` to print this command list.

| Command | Purpose |
| :--- | :--- |
| `run` | Run a command in an OCI image or a Linux ELF64 binary. |
| `pull` | Download an image into the layer cache (`--platform linux/ARCH` selects the architecture). |
| `images` | List cached images. |
| `inspect` | Print image metadata as JSON or through a Go template. |
| `tag` | Add a second name or tag to a cached image. |
| `rmi` | Remove an image tag or delete an unreferenced image. |
| `save` | Export images to a tar archive. |
| `load` | Import images from a tar archive. |
| `image` | Group command for `ls`, `pull`, `rm`, `inspect`, `tag`, `save`, `load`, and `prune`. |
| `volume` | Group command for `create`, `ls`, `inspect`, `compact`, `rm`, and `prune` on local volumes. |
| `system` | Group command for `info`, `df`, and `prune` on host backends and local storage. |
| `info` | Print the host OS, available execution backends, lockdown profile, and storage paths. |
| `checkpoint` | Write a checkpoint bundle for a running sandbox over its control socket (alias: `snapshot`). |
| `restore` | Restore and run a sandbox from a checkpoint bundle directory (alias: `resume`). |
| `login` | Store registry credentials. |
| `logout` | Remove registry credentials. |
| `completion` | Print shell completion scripts for `bash`, `zsh`, `fish`, or `powershell`. |
| `stub` | Probe the `systrap` engine on this host. |
| `tune` | List host-side tunables (see Section 3.3). |
| `license` | Print license texts for `gvx`, upstream gVisor, and linked libraries (see Section 9). |
| `version` | Print the version, source commit, and Go toolchain of the binary (see Section 10). |

Print the flags of any subcommand with `rungv COMMAND --help`. On `run`, `-h` sets the hostname, as in Docker. Every flag accepts single-dash (`-e`) and double-dash (`--env`) forms. On `run`, flags precede the image argument, and short clusters expand boolean flags (`-itP`) and value flags (`-itp 8080:80`, `-p8080:80`, `-eKEY=VAL`, `-w/app`, `-m512m`). Arguments after `--` or after the image name pass unchanged to the guest command. Non-execution commands (`pull`, `images`, `inspect`, `rmi`, `tag`, `save`, `load`, `image`, `volume`, `system`, `info`, `checkpoint`, `restore`) accept flags before or after positional arguments.

## 3. `rungv run`

The synopsis is `rungv run [flags] IMAGE [COMMAND [ARG...]]`. The first non-flag argument names the image. Later arguments replace the image `Cmd` while keeping its `Entrypoint`. The form `rungv run [flags] -bin=ELF [ARG...]` runs a host ELF64 binary with the trailing arguments as its full `argv`.

### 3.1 Docker flags

The table below lists the `rungv run` flags that match the Docker CLI.

| Flag | Meaning |
| :--- | :--- |
| `-e`, `--env KEY=VALUE` | Set an environment variable. `KEY` alone copies the variable from the host if set. |
| `--env-file FILE` | Read `KEY=VALUE` and `KEY` lines, skipping blank lines and `#` comments. |
| `--entrypoint PROGRAM` | Replace the image entrypoint (empty string clears it) and drop the image `Cmd`. |
| `-u`, `--user USER[:GROUP]` | Run as a guest user by name or numeric ID. |
| `-h`, `--hostname NAME` | Set the guest hostname (default: `gvx`). |
| `-w`, `--workdir DIR` | Set the guest working directory (also supported on `restore`). |
| `--name NAME` | Set the kernel container ID; has no other lifecycle effect. |
| `--rm` | Accepted for compatibility; every run cleans up on exit. |
| `-i` | Accepted for compatibility; the guest always reads `rungv` stdin. |
| `-t` | Allocate a pseudo-terminal. |
| `-p`, `--publish [IP:][HOST:]GUEST[/PROTO]` | Publish a guest port. Omitting the host port or using `0` picks a free port on `127.0.0.1`. Ranges like `8000-8009:8000-8009` publish each port. `unix:PATH:GUEST` exposes a guest TCP port on a host Unix socket (see Section 4.7). |
| `-P` | Publish every port declared by image `EXPOSE` to a free `127.0.0.1` port. |
| `--auto-publish` | Automatically publish guest TCP listeners and `iptables` NAT `DNAT` ports on host `127.0.0.1` while the sandbox runs. Static `-p` rules keep precedence (see Section 4.7). |
| `-v`, `--volume SRC:DST[:ro\|rw]` | Mount a host directory, a single host file, or a named volume. |
| `--mount type=bind\|volume\|tmpfs\|overlay,src=...,dst=...,readonly[,driver=ext4lite\|hostfs][,upper=...][,tmpfs-size=...]` | Mount using Docker key-value syntax. `driver` applies to `type=volume` only; a volume `src` with a path separator names a host `.ext4` file. `type=overlay` mounts a copy-on-write branch over a read-only base volume. |
| `--tmpfs PATH[:size=64m,ro]` | Mount a memory-backed directory. |
| `--read-only` | Mount the guest root filesystem read-only (cannot combine with `-rootfs-volume`). |
| `-m`, `--memory SIZE` | Limit guest memory (`b`, `k`, `m`, `g`, `t`; minimum `6m`). |
| `--cpus N` | Set the guest CPU count and quota as a decimal value, such as `1.5`. |
| `--network NAME` | `bridge` and `nat` select NAT mode; `none` and `wg` are the other modes; `host` is refused. |
| `--platform linux/ARCH` | Select the image architecture: `linux/amd64` or `linux/arm64`. |
| `--pull POLICY` | Control registry pulls: `missing` (default), `always`, or `never` (see Section 5.1). |

The flag `-d` is refused with an error because `rungv` has no background daemon.

### 3.2 gvx flags

The table below lists the sandbox flags specific to `gvx`.

| Flag | Meaning |
| :--- | :--- |
| `-image REF`, `-bin ELF` | Specify the image or ELF binary without a positional argument. |
| `-backend`, `--backend BACKEND` | Select the execution backend: `auto`, `whpx`, `hvf`, or `systrap`. Combine with `--platform linux/ARCH` to specify both image architecture and backend. |
| `-platform BACKEND` | Legacy alias for `-backend` (`auto`, `whpx`, `hvf`, or `systrap`) when the value has no slash. Values with a slash (`linux/amd64`, `linux/arm64`) select the image platform. Setting both `-backend` and `-platform BACKEND` to different engines fails. |
| `-allow-unconfined-systrap` | Allow `-backend=auto` on Windows to fall back to `systrap` when `whpx` is unavailable. Untrusted Windows workloads require `whpx`, because Windows `systrap` has no hardware or kernel syscall trap. |
| `-gpu MODE` | Give the guest a virtual GPU: `off` (default), `venus` (Vulkan), or `virgl` (OpenGL). Both active modes need an Apple Silicon host with macOS 26 or later, the `hvf` backend, and the renderer bundle. Section 4.12 describes the rules. |
| `-gpu-renderer PATH` | Name the `gvx-gpu-renderer` executable for `-gpu=venus` and `-gpu=virgl`. Without the flag, `rungv` reads `GVX_GPU_RENDERER` and then searches beside its own executable. |
| `-arch ARCH` | Select the guest architecture (defaults to the host architecture). |
| `-workspace DIR`, `-ro` | Mount a host directory at `/workspace`, optionally read-only. |
| `-rootfs-volume NAME\|PATH` | Mount a managed `.ext4` volume or host `.ext4` file as the persistent root overlay upper layer (`upper` and `work`). |
| `-net MODE`, `-wg-conf FILE`, `-isolate-lan` | Select the network mode (`nat`, `wg`, `none`) and its options. |
| `--privileged` | On by default. Enables `--net-raw`, `--allow-packet-socket-write`, and `--allow-suid`. `--privileged=false` disables all three. Explicit per-flag values override `--privileged` (see Section 4.8). |
| `--net-raw` | Allow guest raw sockets and `iptables` (required by `dockerd`). Defaults to `--privileged`. |
| `--allow-packet-socket-write` | Allow guest writes on `AF_PACKET` sockets (requires `--net-raw`). Defaults to `--privileged` when `--net-raw` is on. |
| `--allow-suid` | Obey `setuid` and `setgid` bits on guest executables (`sudo`, `su`, `passwd` for non-root users). Defaults to `--privileged`. |
| `--host-ca-certs` | Copy host root CA certificates into the guest (off by default; see Section 4.10). |
| `-registry-url URL` | Override the registry host of the image reference. |
| `--host-dns IP[:PORT]` | Specify a host DNS server (repeatable). Replaces host resolver discovery for the guest DNS relay and registry pulls. Also accepted by `pull` and `save` (see Section 5.2). |
| `-cache-dir DIR` | Override the layer cache directory. |
| `-checkpoint-dir DIR` | Pre-open a host directory before lockdown for checkpoint bundle files. |
| `-control-socket PATH` | Bind a Unix socket or loopback TCP listener before lockdown for `rungv checkpoint`. TCP listeners and Windows Unix sockets require the per-run token written to a `0600` token file. |
| `-lockdown=false` | Skip host lockdown. Use for debugging only. |
| `--tune KEY=VALUE` | Set a host-side tunable (repeatable; see Section 3.3). Accepted by `run`, `restore`, `pull`, `load`, `save`, `images`, `inspect`, `rmi`, `tag`, `image`, `system`, and `info`. |
| `--tune-file FILE` | Load host-side tunables from a JSON object. `--tune` flags override the file. Accepted by the same commands. |

### 3.3 Tunables

A tunable controls a host-side limit or timeout that Linux has no sysctl for. Guest Linux settings still go through `sysctl`, `/sys/module`, or netlink; tunables never replace them. One registry in `pkg/gvx/tuning` defines every tunable for `gvx.Config.Tuning`, `--tune`, `--tune-file`, `rungv tune list`, and the table below.

Durations use Go syntax (`250ms`, `30s`). Sizes accept byte counts with optional binary suffixes (`64MiB`). Values in `--tune-file` can be strings or numbers, and `--tune` flags override the file. Unknown keys, malformed values, or out-of-range values fail with an error showing the valid range.

To set a tunable:

1. Run `rungv tune list` to view all keys and defaults.
2. Pick a key and a value within its range.
3. Pass `--tune net.nat.mtu=9000` (repeat for multiple keys).
4. Or pass `--tune-file FILE` with JSON such as `{"net.nat.mtu": 9000, "net.dns.timeout": "8s"}`.
5. Pass the same flags to image commands like `rungv pull` to adjust `oci.*` limits.

`TestDocsMatchRegistry` in `pkg/gvx/tuning` verifies that the table below stays synchronized with the registry.

To regenerate this table after updating the registry, run `go test ./pkg/gvx/tuning -run TestDocsMatchRegistry -update`.

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
<!-- tuning:end -->

`kernel.log_buf_len` sets the kernel log ring size read by `/dev/kmsg`, `dmesg`, and `syslog(2)`. The sandbox rounds it up to a power of two, and `syslog(SYSLOG_ACTION_SIZE_BUFFER)` returns that size. When full, the ring drops the oldest records. Guest processes control other log settings via `/proc/sys/kernel/printk_devkmsg` (`on`, `off`, or `ratelimit`), `/proc/sys/kernel/dmesg_restrict` (`0` or `1`), and `/proc/sys/kernel/printk`.

`net.nat.mtu` sets the initial `eth0` MTU in NAT mode. In WireGuard mode, `eth0` starts with the `MTU` key from `[Interface]` (default `1420`). Each link type enforces its own MTU range and returns `EINVAL` outside it, as on Linux. Callers need `CAP_NET_ADMIN`, and each end of a veth pair has an independent MTU.

A link with an MTU below `1280` drops its IPv6 addresses and routes and refuses new ones until the MTU returns to `1280` or higher, matching Linux.

| Link | MTU range |
| :--- | :--- |
| `eth0` in NAT mode | 68 to 65535 |
| `eth0` in WireGuard mode on Linux and macOS | 68 to 65503 |
| `eth0` in WireGuard mode on Windows | 68 to 1984 |
| Guest-created veth or bridge link | 68 to 65535 |
| `lo` | Accepts requests and keeps `65536` (Linux updates the value). |

To change a link MTU inside the guest:

1. Run `ip link set dev eth0 mtu 1400` (works with iproute2 and busybox `ip`).
2. Run `ifconfig eth0 mtu 1400` if the guest only has busybox `ifconfig`.
3. Inspect the result in `/sys/class/net/eth0/mtu` or with `ip link show dev eth0`.

Guest networking tools derive tunnel MTUs from `eth0`: `flannel` subtracts `50` for VXLAN and `80` for WireGuard. The NAT relay forwards datagrams up to the link MTU. On macOS, the relay raises host UDP socket send buffers so the default `net.inet.udp.maxdgram` (`9216` bytes) does not reject larger datagrams.

## 4. Rules of `run`

### 4.1 Command and environment

The guest command combines `Entrypoint` followed by `Cmd`, taking CLI overrides before image defaults. Overriding `--entrypoint` drops the image `Cmd`, matching Docker. Running with no command fails.

The guest environment starts from the image `Env`, then applies `--env-file` entries, then `-e` flags (so `-e` wins). The sandbox sets default `PATH`, `HOME`, and `HOSTNAME` when missing, and adds `TERM=xterm` when `-t` is set.

### 4.2 User

The guest user comes from `--user`, then the image `User`, and otherwise `root`. Named users resolve through the image's `/etc/passwd` and `/etc/group`; unknown names fail, while numeric IDs need not exist there.

An unlisted numeric user gets group `0` and home `/`, as in Docker. Passing `name` alone adds its supplementary groups from `/etc/group`; passing `name:group` adds none. Non-root users start with no capabilities.

The guest root directory has mode `0755`, matching standard container images, so non-root users cannot create files directly in `/`.

### 4.3 Hostname

The sandbox writes the hostname to `/etc/hostname` and adds it to `/etc/hosts` if missing. It also adds `host.docker.internal`, pointing to the host.

### 4.4 Mounts

A bind mount exposes a host directory or a single host file inside the guest. A named volume is a single image file, `<name>.ext4`, stored in the `volumes` directory inside `-cache-dir` (or next to the default layer cache). Volume names must match `[a-zA-Z0-9][a-zA-Z0-9_.-]*`. Before lockdown, the sandbox creates missing volume images and missing `-v` bind directories, but never creates missing single files. `--mount type=bind` always requires an existing source path.

The `ext4lite` driver formats and mounts each `<name>.ext4` image as an ext4 filesystem. Images grow in 16 MiB steps up to 64 TiB, and a clean exit compacts unused tail blocks. Writable mounts acquire an exclusive file lock (`LOCK_EX`), so a second writer fails at start. Read-only mounts (`:ro`) acquire a shared lock (`LOCK_SH`), allowing multiple concurrent readers while blocking writers and deletions; a read-only mount fails if the previous run ended uncleanly and still needs journal replay.

Each volume carries a `jbd2` metadata journal. After a crash or kill, the next writable run replays the journal, preserving synced files and freeing unlinked open files. Clean images pass `e2fsck -fn` and mount directly on Linux with `mount -o loop -t ext4`.

In `--mount type=volume`, a `src` containing a path separator targets an `.ext4` image file at that host path, such as `--mount type=volume,src=/disk/vols/pg.ext4,dst=/var/lib/postgresql`. Prefix relative paths with `./` so they are not treated as volume names. The sandbox creates a missing image file before lockdown (except for read-only mounts) but never creates parent directories. `-v` keeps its Docker meaning: `-v /disk/vols/pg.ext4:/data` bind-mounts the file itself.

To branch a read-only base volume without copying it, pass `--mount type=overlay,src=BASE,dst=PATH[,upper=BRANCH][,tmpfs-size=SIZE]`. With `upper=BRANCH`, mutations and whiteouts persist in the `BRANCH` volume while `BASE` stays untouched; without `upper`, writes stay in an ephemeral `tmpfs` layer.

Legacy directory volumes from older releases keep mounting through `hostfs` when no `.ext4` file exists for that name. To create a new directory volume explicitly, pass `--mount type=volume,src=NAME,dst=PATH,driver=hostfs`. The default driver is `ext4lite`.

Guest `mount -t overlay` accepts an upper directory on `tmpfs`, an `ext4lite` volume, or a `hostfs` directory (other upper filesystems return `EINVAL`). `docker:dind` relies on this for its overlay storage driver. `ext4lite` is the faster persistent choice; `hostfs` stores individual host files at higher per-syscall overhead. In a single run on macOS, `docker pull nginx:alpine` inside `docker:dind` took about `5 s` on `tmpfs`, `9 s` on `ext4lite`, and `32 to 54 s` on `hostfs`.

A source without a path separator and without an absolute path names a volume. Windows drive letters stay part of the host path, such as `C:\data:/data:ro`.

A bind mount can target a single regular file, such as `-v /host/app.conf:/etc/app.conf:ro` (sockets, devices, and pipes are refused). The guest sees only that file; the host parent directory and sibling files remain inaccessible. The sandbox creates an empty `0644` mount point file and any missing guest parent directories. `-workspace` accepts directories only.

Single-file mounts write no `.gvx_meta` file. Mode, owner, and xattr changes stay in memory for the run, while timestamp updates reach the host file. Guest `unlink` or `rename` on the mount point returns `EBUSY` (as in Docker), and `link` returns `EXDEV`.

On macOS, on Windows, and with `-lockdown=false`, an atomic host rename replaces the mounted file for future guest opens. On Windows, the pre-lockdown `winMountBroker` pins the parent directory handle and authorizes opens for the exact leaf filename without modifying any NTFS ACL or integrity label. On Linux under Landlock, the ruleset binds the original file descriptor, so atomic host replacement requires a directory mount or `-lockdown=false`. Open file descriptors always keep reading the old file.

Each mounted host directory owns one `.gvx_meta` table (shared by duplicate mounts of the same directory with the same access mode). A nested host directory gets its own table. In a non-aligned layout such as `-v $PWD:/app -v $PWD/logs:/var/log/app`, reaching the same file through two mounts can show different metadata. Aligned layouts such as `-v $PWD:/app -v $PWD/node_modules:/app/node_modules` avoid overlap because the inner mount shadows the outer path.

Guest mount destinations must be clean absolute paths and cannot be `/`, `/proc`, `/sys`, `/dev`, or paths beneath them (except under `/dev/shm`). Duplicate guest paths and conflicts with `-workspace` are rejected.

`--tmpfs` accepts `size` (with binary units), `ro`, and `rw`, rejecting unknown options.

`ext4lite` volumes need no host path lockdown rule because the sandbox opens the `.ext4` image file before lockdown. Pass `-rootfs-volume NAME` or `-rootfs-volume PATH` to back root filesystem writes with a persistent `.ext4` image instead of `tmpfs`. The runtime opens it before lockdown and rejects combinations with `--read-only`, raw `-bin` runs, or reusing the same `.ext4` file in `-v`.

| Host OS | Lockdown behavior for host bind mounts |
| :--- | :--- |
| macOS | Seatbelt adds read rules (and write rules for writable mounts) for the mount path and its resolved target. |
| Windows | `winMountBroker` pins each mounted directory or single-file parent handle before lockdown and routes opens in memory without changing NTFS security descriptors. |
| Linux | Landlock confines path opens to the mounted directories and files before seccomp restricts syscalls. |

### 4.5 Resource limits

`--memory` caps guest memory usage. A background guard polls Sentry memory accounting and sends `SIGKILL` (exit code `137`) with a diagnostic message when usage exceeds the limit. Because the guard polls, a guest can briefly overshoot between readings. Without `--memory`, the cap defaults to host physical RAM polled every `100 ms` (configurable via `memory.guard.poll_interval` and `memory.guard.host_poll_interval`).

The guest kernel reports `MemTotal` in `/proc/meminfo` and `totalram` in `sysinfo(2)` as the lesser of `--memory` and host physical RAM. Unsized `tmpfs` mounts like `/dev/shm` default to half of host RAM (matching Linux), and `size=N%` uses `N` percent of host RAM. The rootfs `tmpfs` layer has no separate cap and is bounded by the memory guard.

Inside the guest, nested cgroups also enforce `memory.max` (as `docker run -m` sets in `docker:dind`). The Sentry polls finite cgroups at least every `5 ms` above half their limit and every `25 ms` otherwise (`memory.cgroup.poll_interval`, `memory.cgroup.idle_poll_interval`). It compares subtree anonymous memory plus `tmpfs` data against the limit and kills the highest-scoring process with `SIGKILL` (skipping guest PID 1 and `oom_score_adj=-1000`, or killing the whole subtree when `memory.oom.group` is set). `memory.events` increments `oom` and `oom_kill` and notifies `inotify` watchers. Nested cgroups also enforce `cpu.max` on every engine; `memory.high`, `cpu.weight`, and `memory.swap.*` are accepted and stored without enforcement. See [`recipes/docker-engine.md`](recipes/docker-engine.md) Sections 7.4 and 7.5 for full details.

`--cpus` sets the online guest CPU count (rounded up). On Windows, it also applies a hard CPU cap to the containment Job Object (excluding Windows `systrap` stub processes). macOS and Linux have no host-process CPU cap, so `rungv` prints a warning there.

### 4.6 Guest kernel

The guest sees the mounts that Docker gives a container: `/proc`, `/sys`, `/sys/fs/cgroup` (the `cgroup2` hierarchy), `/dev`, `/dev/pts`, `/dev/shm`, and `/dev/mqueue`. The devices `/dev/fuse` and `/dev/net/tun` exist. A FUSE server and a TUN device stay inside the sandbox. The network links have the names `lo` and `eth0`. A new network namespace, as from `unshare -n` or runc, has only `lo`. The guest can create bridge and veth links and forward packets between them. With `--net-raw`, `dockerd` and its default `bridge` network work, and so do `docker exec` and healthchecks. A bridge container cannot connect to the `eth0` address `10.0.2.15`, because the guest sends the reply through `eth0`.

The root file system is a mount on top of a hidden read-only root, as in runsc. `pivot_root(2)` therefore works, and runc can start containers in the guest. A call of `reboot(2)` by root in the guest stops the run. A power off or a halt gives the exit code 0. A restart gives 129, as if SIGHUP ended the init process. `systemctl poweroff` therefore ends `rungv`.

### 4.7 Published ports

`rungv` binds each static `-p` port before the lockdown. It prints one line for each port to standard error before the guest starts, as in `rungv: publishing 127.0.0.1:49493 -> 8080/tcp`. The line shows the free port that the host chose. Published ports need the NAT network mode. Without `--auto-publish`, the guest cannot add a published port after start, so publish every port that a program in the guest uses with `-p`.

When `--auto-publish` (`Config.AutoPublishPorts`) is set, `rungv` relaxes host lockdown only for loopback binds (`127.0.0.1`). It scans guest TCP listeners and `iptables` NAT `DNAT` rules every `net.forward.dynamic_poll_interval` (default `200ms`). It opens matching `127.0.0.1` listeners up to `net.forward.max_dynamic_ports` (default `64`). When the guest closes a listener or removes a `DNAT` rule, `rungv` closes the host listener. Static `-p` rules always keep precedence, so `rungv` never exposes a guest port from `-p unix:...` on `127.0.0.1`. If a host port is busy, `rungv` prints one warning to standard error and leaves the host process untouched.

A range publishes one port for each number. The host range and the guest range must have the same length, as in `-p 8000-8009:8000-8009`. A guest range alone, as in `-p 8000-8009`, gets free host ports. One range has at most 1024 ports. A host port range and a single guest port are refused.

`-p unix:PATH:GUEST` binds a Unix socket at `PATH` on the host and forwards each connection to the TCP port `GUEST` of the guest. A leading `~/` names the home directory, because a shell does not expand `~` after `unix:`. Only the owner can open the socket. The lockdown stops `rungv` from removing the socket file at the end. The next run replaces a socket file that it finds at `PATH`, and it refuses any other file. A path cannot contain a comma, because `-p` splits its value at commas.

### 4.8 Raw sockets

`--privileged` is on by default, because its privileges stay inside the sandbox. A raw socket can send packets with any source address on the guest network, but the packets reach only the guest stack. The NAT mode still applies its destination rules, including `-isolate-lan`, to each packet that leaves `eth0`. The host network does not see the packets of a raw socket. The `iptables` tables work through the legacy interface (`iptables-legacy`). The `nftables` interface is not available.

The legacy interface has the tables `filter`, `nat`, `mangle`, and `raw`. It has these matches: `addrtype`, `comment`, `conntrack` (`--ctstate` only), `icmp`, `icmp6`, `limit`, `mark`, `multiport`, `owner`, `physdev`, `recent`, `set`, `statistic`, `tcp`, and `udp`. The `addrtype` match knows the types `UNICAST`, `LOCAL`, `BROADCAST`, `MULTICAST`, and `UNSPEC`. It accepts `--limit-iface-in` and `--limit-iface-out`. The match `--dst-type LOCAL` is true for each address of a guest link and for the whole `127.0.0.0/8` range. The `statistic` match takes `--mode random` and `--mode nth`. The `recent` match keeps each list in the network namespace of its rules, and it has no `/proc/net/xt_recent` files. The `icmp` and `icmp6` matches select packets by ICMP type and code, as `-p icmp --icmp-type echo-request` does. The `limit` match is a token bucket, and each rule has its own bucket that `iptables-restore` fills again. The `physdev` match reads the ports of a frame that a bridge switches between two ports. A packet that the IP layer routes has no bridge information. Linux knows the egress port in the FORWARD and POSTROUTING hooks only, so `--physdev-is-bridged` matches there. The target `NFLOG` accepts its rules and keeps them for `iptables-save`, but no log group receives a packet. The target `LOG` writes its line to the kernel log of the guest, which `dmesg` and `/dev/kmsg` read, when its rule is in the root network namespace. The commands `iptables -C` and `iptables -D` find rules with `! -i`, `! -o`, and `-j DNAT`. The `conntrack` tool and the Go library `github.com/vishvananda/netlink` list and delete tracked connections. The guest has IP sets, which the `ipset` tool, `kube-router`, and Calico create through `NETLINK_NETFILTER`. The set types are `hash:ip`, `hash:net`, `hash:ip,port`, `hash:net,port`, `hash:ip,port,ip`, `hash:ip,port,net`, `hash:net,net`, `bitmap:port`, and `list:set`. The match `set` and the target `SET` use them for IPv4 and IPv6. The sets belong to the network namespace, and a limit follows the Linux setting: `maxelem` defaults to 65536, and `/sys/module/ip_set/parameters/max_sets` (default 256) sets the first size of the table of sets.

The connection tracker starts with the first rule of a table. It follows the sysctl files of `/proc/sys/net/netfilter`, with the Linux defaults. A TCP connection has one timeout for each state, from `nf_conntrack_tcp_timeout_syn_sent` to `nf_conntrack_tcp_timeout_close`. A UDP flow, an ICMP flow, and an ICMPv6 flow have a timeout each. `nf_conntrack_max` is 262144 at the start and has one value for the whole guest. When the table is full, the tracker removes a connection that timed out or is not assured. Otherwise it drops the packet that needs a new connection. `conntrack -L` shows the time that is left of each timeout. Each connection takes about 500 bytes of host memory.

An unmodified `docker:dind` image starts with the default `--iptables=true`. [`recipes/docker-engine.md`](recipes/docker-engine.md) shows how to use it as the Docker Engine of the host. The `bridge` network masquerades the traffic of its containers. A published port (`docker run -p`) uses a `DNAT` rule and the `docker-proxy` process. A user-defined network resolves container names. `docker build` and `docker compose up` work. The option `--userland-proxy=false` works. A published port then uses only the `DNAT` rule, and a connection from the guest to `127.0.0.1` and the published port reaches the container. The command `iptables-legacy-save` prints the tables `filter`, `nat`, `mangle`, and `raw`. The bridge passes the IP frames that it forwards through the `iptables` hooks while `/proc/sys/net/bridge/bridge-nf-call-iptables` is 1, which is the default. A `FORWARD` rule for `-i docker0 -o docker0` therefore separates two containers of one bridge.

### 4.9 Failures and diagnostics

`-platform=auto` selects `hvf` on macOS, `systrap` on Linux, and `whpx` on Windows unless `-allow-unconfined-systrap` enables fallback to `systrap`. On Windows, a disabled "Windows Hypervisor Platform" feature makes `auto` fail closed without `-allow-unconfined-systrap`. When `-allow-unconfined-systrap` or `-platform=systrap` runs on Windows, `rungv` prints a stderr warning and the SDK records the reason in `Sandbox.FallbackReason`. macOS has no `systrap` engine, so `auto` fails when the binary lacks the hypervisor entitlement. Sign it with `codesign --sign - --entitlements entitlements.plist --force rungv`.

The exit code 137 has two causes that `rungv` tells apart. A guest that passes `--memory` gets the message about the memory limit. When the engine fails under the guest, the kernel ends the guest with SIGKILL, and `rungv` prints `the execution engine stopped the guest` with the cause. The SDK returns `ErrEngineFault` in that case. A stub process that a virus scanner ended is one example of an engine fault.

`GVX_DEBUG_LOG=1` prints Sentry kernel logs to `rungv` stderr, and `GVX_DEBUG_LOG=2` adds debug lines. Use it when a guest fails without a clear error message. `GVX_STRACE=1` logs every guest system call.

### 4.10 Host root certificates

A host behind a TLS-inspecting proxy or using a private registry trusts root certificates that container images do not include. `--host-ca-certs` (`Config.HostCACerts`) copies host root certificates into the guest. Without this flag, the guest trusts only its image's CA bundle; the sandbox never enables it automatically.

`rungv` reads host root certificates before lockdown because lockdown forbids opening new host files or spawning child processes.

| Host | Source of root certificates |
| :--- | :--- |
| Linux | `SSL_CERT_FILE` (or the default Go system bundle) plus `SSL_CERT_DIR` (or `/etc/ssl/certs` and `/etc/pki/tls/certs`). |
| macOS | `System.keychain`, `SystemRootCertificates.keychain`, and `login.keychain-db`. Certificates are included when user, admin, or system trust settings accept them for TLS servers; denials take precedence in user, admin, system order. |
| Windows | The `ROOT` system store (the `CA` store holds intermediates and is ignored). |

On macOS and Windows, `SSL_CERT_FILE` and `SSL_CERT_DIR` append extra roots outside the system store. The run fails if the host provides no roots at all, and unreadable sources print a stderr warning.

At guest startup, the sandbox writes host roots into the writable upper layer without modifying cached images or mounting over bundle files, so `update-ca-certificates` and `apk add ca-certificates` keep working.

| Write | Detail |
| :--- | :--- |
| Image bundles | Appends missing host roots to each existing bundle among `/etc/ssl/certs/ca-certificates.crt`, `/etc/ssl/cert.pem`, `/etc/pki/tls/certs/ca-bundle.crt`, `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`, and `/etc/ssl/ca-bundle.pem`. |
| Image without a bundle | Creates `/etc/ssl/certs/ca-certificates.crt` containing the host roots. |
| Anchor files | Writes each missing host root as `gvx-host-*.crt` in `/usr/local/share/ca-certificates` (Debian/Alpine) and `/etc/pki/ca-trust/source/anchors` (RHEL) when those directories exist, so later `update-ca-certificates` or `update-ca-trust` runs preserve them. |
| Mounts | Leaves mount points and mounted subtrees untouched. |

> [!WARNING]
> Only direct guest processes trust these roots. Nested containers started by `dockerd` have their own root filesystems; see [`recipes/docker-engine.md`](recipes/docker-engine.md) to pass host roots into them.

Run an image behind a TLS-inspecting proxy:

```sh
rungv run --host-ca-certs alpine:3.20 wget -qO- https://example.com/
```

Add an extra root certificate on any host OS:

```sh
SSL_CERT_FILE=$PWD/corp-root.pem rungv run --host-ca-certs alpine:3.20 wget -qO- https://registry.corp.example/
```

### 4.11 Checkpoint and restore

`rungv` can save a running sandbox to a host directory and resume it in a new process. Because host lockdown blocks new file opens and socket binds after startup, the sandbox pre-opens `-checkpoint-dir` and binds `-control-socket` before calling `hostlockdown.Apply()`.

A checkpoint bundle contains four files: `manifest.json`, `state.img`, `pages.meta`, and `pages.img`. `manifest.json` records the host OS, CPU architecture, platform backend, address holes, EROFS layer digests, mounts, and network mode. `rungv restore` (`rungv resume`) validates `manifest.json` against the current host and reopens cached layers and mounts before applying lockdown.

| Command or flag | Meaning |
| :--- | :--- |
| `rungv run -checkpoint-dir DIR -control-socket PATH` | Pre-open `DIR` and bind `PATH` (mode `0600` Unix socket or loopback TCP address) before lockdown. |
| `rungv checkpoint -control-socket PATH [-checkpoint-dir DIR] [-leave-running]` | Connect to `PATH` and trigger a checkpoint (`rungv snapshot` alias). Without `-leave-running`, the sandbox stops with exit code `0` after saving. If `-checkpoint-dir` is given, the server verifies it matches the pre-opened directory. |
| `rungv restore -checkpoint-dir DIR [flags]` | Restore a sandbox from `DIR` (alias: `rungv resume`). Pass `-w`, `-workspace`, `-v`, `--mount`, `-rootfs-volume`, `-p`, `--auto-publish`, `-net`, `-wg-conf`, `-checkpoint-dir`, and `-control-socket` to reattach mounts, networking, or a new control listener. |

> [!IMPORTANT]
> Pass the same workspace, volume mounts, and `-rootfs-volume` flag to `rungv restore` that the sandbox used when `rungv checkpoint` ran. `rungv restore` rejects the bundle when the mount paths, the `root_volume` setting, the layer digests, the platform, or the network mode do not match `manifest.json`.

1. Start a workload with `-checkpoint-dir` and `-control-socket`.
2. Run `rungv checkpoint` in another terminal to write the bundle and stop the sandbox.
3. Run `rungv restore` with `-checkpoint-dir` and the same mounts to resume the workload.

```sh
rungv run -checkpoint-dir=./ckpt -control-socket=./ckpt.sock -workspace=./work alpine:3.20 sh -c "sleep 30"
rungv checkpoint -control-socket=./ckpt.sock -checkpoint-dir=./ckpt
rungv restore -checkpoint-dir=./ckpt -workspace=./work
```

### 4.12 GPU

`-gpu=venus` and `-gpu=virgl` give the guest the render node `/dev/dri/renderD128` of a `virtio-gpu` device. In `venus` mode, `gvx-gpu-renderer` runs Vulkan commands on Metal through KosmicKrisp. In `virgl` mode, `gvx-gpu-renderer` runs OpenGL and OpenGL ES commands on Apple OpenGL 4.1 through `vrend` and CGL. `rungv` starts one renderer process before the lockdown and stops it when the guest exits.

| Rule | Behavior |
| :--- | :--- |
| Host | `darwin/arm64` with macOS 26 or later and the `hvf` backend. On another host or backend, `rungv` exits with a configuration error. |
| Renderer search | `-gpu-renderer`, then `GVX_GPU_RENDERER`, then `gvx-gpu-renderer/bin/gvx-gpu-renderer` beside `rungv`, then `../libexec/gvx-gpu-renderer/bin/gvx-gpu-renderer`. |
| Renderer missing or broken | `rungv` exits with an error that names the searched paths or the last stderr line of the renderer. It never falls back to software rendering. |
| Guest software | For `venus`, the image needs `mesa-vulkan-drivers` (tested with Mesa 25.0.7, 25.2.8, and 26.2.6) and Chromium flags `--use-angle=vulkan --ignore-gpu-blocklist --disable-vulkan-surface`. For `virgl`, the image needs `libgl1-mesa-dri` and `libegl-mesa0` (tested with Mesa 25.0.7 and 25.2.8) and Chromium flags `--use-gl=angle --use-angle=gl-egl --ignore-gpu-blocklist`. `rungv` changes nothing in the guest. |
| Checkpoint and restore | Not possible with `-gpu=venus` or `-gpu=virgl`: `-checkpoint-dir`, `-control-socket`, and `rungv restore` refuse the combination. |
| Renderer loss | When the renderer exits during a run, the guest gets I/O errors from the GPU, and the run continues. The renderer does not restart. |
| Memory | The guest can hold shared GPU memory up to the smaller of 4 GiB and 25% of host RAM. |

The renderer parses guest data in C code. A Seatbelt profile confines it: no process creation, no file write, and no network. The option is still a larger attack surface than a run without it, so it is off by default. `GVX_DEBUG_LOG=2` prints each DRM request that the device refuses.

## 5. Images and registries

An image reference follows the Docker rules. The first path component is a registry host when it contains a dot or a colon, or when it is `localhost`. Any other name belongs to Docker Hub, and a name with one component gets the prefix `library/`. A reference without a tag and without a digest means the tag `latest`. A digest form is `NAME@sha256:HEX`. An uppercase repository name is invalid.

A registry host uses `https`, except `localhost`, the `127.0.0.0/8` range, and `[::1]`, which use `http`. The flag `-registry-url` overrides the registry. The reference then supplies only the repository, the tag, and the digest.

The credentials come from the Docker configuration file. The directory is `DOCKER_CONFIG`, or else `.docker` in the home directory. The lookup order is `credHelpers`, then `credsStore`, then `auths`.

A credential helper is the program `docker-credential-NAME`. It has 30 seconds and 1 MiB of output. A missing helper means no credentials. `rungv` sends credentials only to the registry and to its token service.

`rungv login` verifies the credentials against the registry before it stores them. It stores them with the helper, or else in `auths` as base64. It keeps every other field of the file. `rungv logout` removes them.

### 5.1 Pull policy

`rungv run` resolves a reference through the layer cache and the registry. The flag `--pull` selects the order. An image archive or `-bin` ignores the flag.

| Policy | Order |
| :--- | :--- |
| `missing` | Use the cached image. Ask the registry only when the cache has no record of the reference. This is the default, as in Docker. A tag that moved in the registry keeps the cached image until `rungv pull` or `--pull=always`. |
| `always` | Ask the registry first, so a tag that moved gives the new image. |
| `never` | Use the cached image only. A reference that the cache does not hold stops the run with an error. |

With `always`, the cached image replaces a failed request in two cases. The first case is a registry that is unreachable. The second case is a registry that answers HTTP 401, 403, or 404, or demands credentials that the Docker configuration does not hold. `rungv` then prints one warning line to the standard error. Any other failure stops the run, and so does a missing cached image.

The second case lets `rungv load -i img.tar` followed by `rungv run --pull=always mylocal/app:1` work. The name `mylocal/app:1` is unknown to Docker Hub. With the default `missing`, the run uses the loaded image without a registry request. `rungv pull` always asks the registry and never uses the cache after a 401, 403, or 404.

### 5.2 Host DNS servers

A host such as an Android app has no `/etc/resolv.conf`. The Go resolver then asks `[::1]:53` and fails with `connection refused`. The flag `--host-dns` names a DNS server of the host as `IP` or `IP:PORT`. A bare IP uses port 53. The flag repeats, and one value can hold a comma-separated list. The commands `run`, `pull`, and `save` take it. `rungv login` does not take it.

The servers replace the discovery of the host resolver for two users. The first user is the DNS relay of the guest at `10.0.2.3`, in `-net=nat` and `-net=wg` modes. The second user is the registry client of an image pull. The registry client sends its queries to the servers and changes no process-wide resolver. Without the flag, both users keep the discovery of the host. A WireGuard config with its own `DNS =` servers keeps them for the guest relay.

The SDK field is `Config.HostDNSServers`. An embedder that pulls with its own layer cache calls `LayerCache.SetDNSServers`. An Android app reads the servers with `ConnectivityManager`. The Android emulator uses `10.0.2.3`.

```sh
rungv run --host-dns 10.0.2.3 alpine:3.20 nslookup example.com
rungv pull --host-dns 10.0.2.3 alpine:3.20
```

## 6. Storage, system, and completion commands

`rungv` provides Docker-style noun-verb groups for local images, named volumes, host diagnostics, and shell completion. Top-level commands (`images`, `pull`, `rmi`, `inspect`, `tag`, `save`, `load`, `info`) remain aliases of the corresponding group subcommands.

### 6.1 Image store and `rungv image`

The layer cache holds compiled EROFS layers, one record per image, and one record per tag or digest. The default directory is `%LOCALAPPDATA%\gvx\cache\layers` on Windows, `~/Library/Caches/gvx/layers` on macOS, and `~/.cache/gvx/layers` on Linux.

| Command | Behavior |
| :--- | :--- |
| `rungv image ls` (`rungv images`) | Lists cached images. `IMAGE ID` shows the first 12 hex digits of the config digest, and `SIZE` sums the EROFS layer files. Accepts `-a`, `-q`, `--no-trunc`, `--digests`, and `--format`. |
| `rungv image pull` (`rungv pull`) | Downloads an image or archive into the layer cache. Accepts `--platform linux/ARCH`, `-arch`, `-registry-url`, and `--host-dns`. |
| `rungv image inspect` (`rungv inspect`) | Prints a JSON array of image metadata, or evaluates `-f` / `--format` per image. |
| `rungv image rm` (`rungv rmi`) | Removes a tag or an image record and deletes unreferenced EROFS layers. An image ID with multiple tags requires `-f`. |
| `rungv image tag` (`rungv tag`) | Creates a second repository or tag reference for a cached image. |
| `rungv image save` (`rungv save`) | Writes an OCI layout and `docker save` tar archive by fetching verified layer blobs from the origin registry. |
| `rungv image load` (`rungv load`) | Loads images for the selected architecture from an OCI layout or `docker save` tar archive. |
| `rungv image prune [-a] [-f]` | Deletes dangling images (or all images for the architecture with `-a`), sweeps orphaned layer files, and prints reclaimed bytes. |

### 6.2 Named volumes and `rungv volume`

`rungv volume` creates, inspects, compacts, and deletes named volumes in the local `volumes` directory without starting a sandbox. Each `ext4lite` volume probes its host file lock via `ext4lite.ProbeVolumeLock` so `rungv` refuses compaction or deletion while a sandbox mounts the volume.

| Command | Behavior |
| :--- | :--- |
| `rungv volume create [-d ext4lite\|hostfs] [NAME]` | Formats an `ext4lite` image file (`<name>.ext4`, default) or creates a `hostfs` directory. Generates a 64-digit hex name when `NAME` is omitted. |
| `rungv volume ls [-q] [--format SPEC]` | Lists local volumes sorted by name, or prints only names with `-q`. |
| `rungv volume inspect [-f SPEC] NAME...` | Prints JSON metadata (`Name`, `Driver`, `Mountpoint`, `CreatedAt`, `SizeBytes`, `AllocatedBytes`, `InUse`, `LockMode`) or evaluates a Go template. |
| `rungv volume compact NAME...` | Replays any pending journal, punches freed blocks, and shrinks unused tail groups on unlocked `ext4lite` volumes. |
| `rungv volume rm [-f] NAME...` | Deletes unlocked volumes. `-f` ignores missing names, and locked volumes always fail with `in use`. |
| `rungv volume prune [-f]` | Deletes all unlocked local volumes after confirmation (or immediately with `-f`) and prints reclaimed bytes. |

### 6.3 System diagnostics, disk usage, and Go templates

`rungv system` and `rungv info` inspect the host environment and local storage without applying host lockdown. List and inspect commands share a Go `text/template` formatter through `--format` (and `-f` on `inspect`, `volume inspect`, and `info`).

| Command or format | Behavior |
| :--- | :--- |
| `rungv system info` (`rungv info`) | Probes `whpx`, `hvf`, and `systrap`, reports the host lockdown profile, and prints cache and volume counts. |
| `rungv system df [-v] [--format SPEC]` | Prints total, active, and reclaimable bytes for `Images` and `Local Volumes`. `-v` appends per-image and per-volume tables. |
| `rungv system prune [-a] [--volumes] [-f]` | Prunes unused images across cached architectures (or one `--platform`) and prunes unlocked volumes when `--volumes` is set. |
| `--format json` | Prints newline-delimited JSON objects on list commands, or an indented JSON value on `inspect` and `info`. |
| `--format '{{.Field}}'` / `'table {{.A}}\t{{.B}}'` | Evaluates a Go `text/template` with the functions `json`, `lower`, `upper`, `join`, `split`, and `truncate`. |

### 6.4 Shell completion

`rungv completion <bash|zsh|fish|powershell>` writes a completion script for subcommands, group verbs, and common `run` flags to standard output.

| Shell | Activation command |
| :--- | :--- |
| Bash | `source <(rungv completion bash)` |
| Zsh | `source <(rungv completion zsh)` (after `compinit`) |
| Fish | `rungv completion fish \| source` |
| PowerShell | `rungv completion powershell \| Out-String \| Invoke-Expression` |

## 7. Differences from Docker

The table below lists Docker CLI features that differ or do not exist in `rungv`.

| Docker | `rungv` |
| :--- | :--- |
| `-d`, `ps`, `exec`, `logs`, `stop`, `rm`, `restart` | Not available. A run executes in the foreground and keeps no container daemon state. |
| `docker build`, `compose`, `network` | Not available. Use `rungv volume` to create, inspect, compact, remove, or prune named volumes. |
| Image `VOLUME`, `HEALTHCHECK`, `STOPSIGNAL`, labels | Ignored. |
| `--network host` | Refused. The guest has its own network stack. |
| `-p HOST-RANGE:PORT` | Refused. Publish ranges of the same length. |
| `--privileged` | On by default. Its privileges stay inside the sandbox. |
| `--name` | Sets the kernel container ID and nothing else. |
| Image with Docker manifest schema 1 | Refused with an error. Docker 28 and later also refuse it; rebuild or re-push the image. |
| `docker save` of any image | Requires the origin registry to fetch verified compressed layer blobs. |
| Cgroup limits | `--memory` uses a polling guard. `--cpus` caps host process CPU time on Windows only. Inside the guest, nested cgroups enforce `memory.max` (polling) and `cpu.max` (on every engine); `memory.high` and `cpu.weight` are not enforced. |
| Linux host with an active seccomp user-notify listener | Linux allows one listener per filter chain, so `systrap` prints a warning and falls back to the slower futex loop for stub threads. |
| Cgroup v1 | Not available. `/sys/fs/cgroup` mounts `cgroup2`. |
| Guest architecture | Must match the host CPU architecture on every backend (no Rosetta 2 or cross-architecture emulation). |
| Non-PIE executables (fixed load address) | `hvf`, `whpx`, and Windows `systrap` run them natively. The removed macOS `systrap` engine could not, because macOS `arm64` processes reserve a 4 GB `PAGEZERO`. |
| Self-modifying store into an executing code page | Windows `systrap` serves the store with a single-step window (three debug stops). On `arm64`, store-exclusive instructions (`stxr`, `stlxr`, `stxp`, `stlxp`) targeting their own page raise `SIGSEGV`. |
| Root filesystem writes | Ephemeral unless `-rootfs-volume` is set. Use `-rootfs-volume` or a mount for persistent data. |

## 8. Examples

Run a command in an image, as a user, with an environment variable and a bind mount:

```sh
rungv run -u 1000 -e MODE=test -v "$PWD":/src:ro -w /src alpine:3.20 sh -c 'ls; id'
```

Publish the exposed port of an image to a free host port:

```sh
rungv run -P nginx:alpine
```

Create an `ext4lite` volume, mount it as a data volume or persistent root overlay in a memory-limited guest, and inspect disk usage:

```sh
rungv volume create appdata
rungv run -m512m -v appdata:/var/lib/app myimage:1.0
rungv run -rootfs-volume rootstate alpine:latest sh -c "echo saved >/etc/custom"
rungv system df -v
```

Move an image to another host:

```sh
rungv save -o alpine.tar alpine:3.20
rungv load -i alpine.tar
```

## 9. `rungv license`

`rungv license` prints the license notices of the binary. The binary embeds the notice file `cmd/rungv/licenses/THIRD_PARTY_LICENSES.txt`, and the command prints that file. The file covers the Go standard library, the gVisor code, and each third-party module that the binary links.

The synopsis is `rungv license [-list]`. The command takes no other argument.

| Flag | Meaning |
| :--- | :--- |
| none | Print the whole notice file. Each license text appears once, followed by the components that use it. |
| `-list` | Print one line per component: the name, the version, and the SPDX identifier. |

The command exits with 0 on success and with 2 when an argument is unexpected. The notice file is regenerated with `go run ./tools/licenses`. The command `go run ./tools/licenses -check` fails when the file or the README table is stale.

## 10. `rungv version`

`rungv version` prints the build identity that the Go toolchain records in the binary. Include its output in every bug report. The synopsis is `rungv version`, and `rungv --version` is the same command.

| Line | Content |
| :--- | :--- |
| `rungv VERSION` | The module version. A build of a clean tag checkout prints the tag, such as `v0.1.0-rc.1`. Another build prints a pseudo-version or `(devel)`. |
| `commit SHA (TIME)` | The Git commit and its commit time. The word `modified` follows when the checkout had uncommitted changes. A build without Git metadata omits this line. |
| `go VERSION OS/ARCH LEVEL` | The Go toolchain, target OS and architecture, and compiled architecture level (such as `GOAMD64=v2` or `GOARM64=v8.4`). |

The command exits with 0 on success and with 2 when an argument is unexpected.

## 11. Nested use

This section states what runs when `rungv` runs inside another sandbox. The inner `rungv` needs ptrace, seccomp filters, shared memory, futex calls, and the signal frame of the architecture from the kernel of the outer sandbox. The tables list the measured results. Each result names the flags of the run.

> [!IMPORTANT]
> Copy a static Linux binary of `rungv` into the outer guest. Build it with `CGO_ENABLED=0 go build ./cmd/rungv`. A guest has no dynamic loader for the libc of the host.

### 11.1 `rungv` inside `rungv`

The outer `rungv` uses the engine `systrap` on a Linux host, or the engine `hvf` on macOS. The inner `rungv` uses `-platform=systrap`. The outer guest kernel tells the address space when a tracer sets `GS` and reports the page fault in the signal frame, as Linux does. The inner sandbox prints `seccomp user-space notification mechanism isn't supported` and uses the futex loop. This message is a warning, not a failure.

| Outer host and flags | Inner flags | Result |
| :--- | :--- | :--- |
| Linux arm64, `-platform=systrap` | `-platform=systrap -bin /smoke` | Works. |
| Linux arm64, `-platform=systrap`, image `alpine:3.20` | `-platform=systrap alpine:3.20 uname -a` | Works. The inner guest reports `aarch64`. |
| macOS arm64, `-platform=hvf` | `-platform=systrap -bin /smoke` | Works. The run is slow. |
| Linux amd64, `-platform=systrap` | `-platform=systrap -bin /smoke` | Works. |
| Linux amd64, `-platform=systrap`, e2-micro host without KVM | `-platform=systrap -net=none -bin /smoke` | Works. The inner guest prints `gvx-smoke-ok`. |

To run the nested smoke test:

1. Run `go build -o rungv-static ./cmd/rungv` with `CGO_ENABLED=0`.
2. Run `go run ./internal/testelf/cmd/mkelf -o smoke`.
3. Run `rungv run -platform=systrap -v $PWD/smoke:/smoke:ro -bin ./rungv-static -- run -platform=systrap -bin /smoke`.
4. Verify that the output is `gvx-smoke-ok`.

The inner `rungv` has no root certificates when the outer guest comes from `-bin`. Pull an image in the inner guest only when the outer guest is an image with certificates, such as `alpine:3.20`, or when the outer run has `--host-ca-certs`.

### 11.2 `rungv` inside Docker with the gVisor runtime

The upstream runtime `runsc` is the host kernel of the inner `rungv` in this case. The release `release-20261102.0` of `runsc` gives the same results with `--platform=kvm` and with `--platform=systrap`. The flags `--privileged` and `--security-opt seccomp=unconfined` do not change the result.

| Host | Inner flags | Result |
| :--- | :--- | :--- |
| Linux amd64, `runsc-kvm` | `-platform=systrap -net=none -lockdown=false -bin /n/smoke.elf` | Works. The exit code is 0. |
| Linux amd64, `runsc-systrap` | `-platform=systrap -net=none -lockdown=false -bin /n/smoke.elf` | Works. The exit code is 0. |
| Linux arm64, `runsc` with any platform | `-platform=systrap` | Does not work. The signal frame of `runsc` has no `fpsimd_context` record. The stub stops with `FP state context magic header (0) does not match expected FPSIMD_MAGIC`. The exit code is 137. |

The amd64 results depend on four differences between `runsc` and Linux. The inner `rungv` accepts each of them:

- `runsc` checks the alignment of a fixed mapping before its range. The inner `rungv` maps the last page of the address space to measure the size.
- `runsc` gives a page fault the error code 0 in the signal frame. The inner `rungv` infers an instruction fetch from the fault address. It treats a fault as a read first, and the second fault at the same instruction and address as a write.
- `runsc` with the platform `systrap` patches the syscall instructions of the stub with jumps that use `GS`. It does not remove the patches when a tracer sets `GS`. The syscall thread of the stub calls `arch_prctl(ARCH_SET_GS)` once, so `runsc` removes the patches before the stub runs.
- `runsc` with the platform `systrap` seals its table of syscall patches in the address space of the stub. A call that unmaps the whole range fails with `EPERM`. The inner `rungv` unmaps its address space mapping by mapping.

The arm64 failure belongs in upstream gVisor: `runsc` must write `fpsimd_context`, `esr_context`, and the end marker into the arm64 signal frame, as `gvx` does. The same upstream report can request Linux-compatible page fault error codes in the amd64 signal frame.

### 11.3 Limits

The stub processes of an inner Sentry keep the sealed syscall patching table of the outer Sentry on amd64. A guest mapping at `0x60000` to `0x65000` fails there. The engine `ptrace` and the hardware engines of the inner `rungv` need devices that the outer guest does not give.

## 12. Android

`rungv` runs on `android/arm64` with the `systrap` engine. An Android app cannot start a hardware hypervisor, so `-platform=auto` selects `systrap`.

### 12.1 Process Model

The app starts `librungv.so` from its native library directory. The Android library `dev.gfire.gvx.Gvx` does this and passes the DNS servers of the active network with `--host-dns`, because Android has no `/etc/resolv.conf`. The Sentry then runs in that child process with its host lockdown. Android SELinux denies `linkat` hard links on app and shell data files with `EACCES`, so hard links in the guest work on `ext4lite` volumes and the root file system, not on a `hostfs` workspace.

Each live guest address space has one stub process and at most 2 sysmsg processes on Android. Android counts every child process of every app. Above 32 in total, it kills the oldest child processes of the app with the worst priority. A killed stub stops the sandbox, and `rungv` prints `the execution engine stopped the guest` with a note that names this limit. Android also kills a child process that uses much CPU while its app is in the background.

| Android version | Switch for the limit of 32 | Switch for the CPU limit in the background |
| :--- | :--- | :--- |
| 12 | `adb shell device_config put activity_manager max_phantom_processes 2147483647` | None |
| 12L and 13 | `adb shell settings put global settings_enable_monitor_phantom_procs false` | The same switch |
| 14 and later | Developer options, "Disable child process restrictions" | The same switch |

### 12.2 Keep a Long Guest Running

Use this procedure for a guest that runs longer than a few seconds, such as a build.

1. Start the guest from a foreground service of the app, as the sample app `android/sample` does.
2. Keep the number of concurrent guest processes below 10.
3. Turn off the limit with the switch of the table in section 12.1 when the guest needs more processes.
