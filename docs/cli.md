# The `rungv` Command Line

`rungv` runs one OCI image or one Linux ELF64 binary in the foreground. Its flags and its output follow the Docker command line where the sandbox can keep the same meaning. This document is the reference for every command, every flag of `rungv run`, and every difference from Docker. The architecture of the sandbox is in [`architecture.md`](architecture.md).

## 1. Model

`rungv` has no daemon. A run starts a sandbox, runs the guest command, and removes everything when the guest exits. Every run therefore behaves like `docker run --rm`.

The writes of the guest go to a memory-backed layer on top of the read-only image layers. The only writes that outlive the run go to a bind mount, a named volume, or the image store of the host.

The host process locks itself down before the guest starts. After that point it cannot open a new host file, start a process, or create a socket. Every host resource of a run exists before the lockdown. This rule is the reason that `rungv` has no `exec`, no `logs`, and no `-d` in this stage.

## 2. Commands

Run `rungv help` to print this list.

| Command | Purpose |
| :--- | :--- |
| `run` | Run a command in an image or in an ELF binary. |
| `pull` | Download an image into the layer cache. |
| `images` | List the images of the cache. |
| `inspect` | Print the configuration of images as JSON. |
| `tag` | Give an image a second name. |
| `rmi` | Remove a name of an image, or the image. |
| `save` | Write images to a tar archive. |
| `load` | Read images from a tar archive. |
| `login` | Store the credentials of a registry. |
| `logout` | Remove the credentials of a registry. |
| `stub` | Probe the `systrap` engine of this host. |
| `tune` | List the host-side tunables. Section 3.3 describes them. |
| `license` | Print the license texts of `gvx`, of its upstream code, and of the libraries in the binary. Section 9 describes it. |
| `version` | Print the version, the source commit, and the Go toolchain of the binary. Section 10 describes it. |

Print the flags of a command with `rungv COMMAND --help`. The flag `-h` of `run` sets the hostname, as in Docker. Flags go before the arguments. Every flag has a single-dash form, such as `-e`, and a double-dash form, such as `--env`. A cluster of one-letter flags, such as `-it`, works for `-i`, `-t`, `-d`, and `-P`.

## 3. `rungv run`

The synopsis is `rungv run [flags] IMAGE [COMMAND [ARG...]]`. The first argument that is not a flag names the image. The arguments after it replace the `Cmd` of the image and keep its `Entrypoint`. The synopsis `rungv run [flags] -bin=ELF [ARG...]` runs a host ELF binary with the arguments as the whole command vector.

### 3.1 Docker flags

| Flag | Meaning |
| :--- | :--- |
| `-e`, `--env KEY=VALUE` | Set a variable. `KEY` alone copies it from the host and sets nothing when the host has none. |
| `--env-file FILE` | Read `KEY=VALUE` and `KEY` lines. Blank lines and lines that start with `#` are skipped. |
| `--entrypoint PROGRAM` | Replace the image entrypoint. An empty value clears it. The image `Cmd` is dropped. |
| `-u`, `--user USER[:GROUP]` | Run as a user, by name or by number. |
| `-h`, `--hostname NAME` | Set the hostname. The default is `gvx`. |
| `-w`, `--workdir DIR` | Set the working directory. |
| `--name NAME` | Set the container name. It becomes the container ID of the kernel and has no other effect. |
| `--rm` | Accepted. Every run removes its container. |
| `-i` | Accepted. The guest always reads the standard input of `rungv`. |
| `-t` | Allocate a pseudo-terminal. |
| `-p`, `--publish [IP:][HOST:]GUEST[/PROTO]` | Publish a guest port. A missing host port or the host port `0` asks for a free port. The default bind address is `127.0.0.1`. A range such as `8000-8009:8000-8009` publishes each port. `unix:PATH:GUEST` publishes a guest TCP port on a host Unix socket. Section 4.7 gives the rules. |
| `-P` | Publish every port that the image declares with `EXPOSE` to a free port of `127.0.0.1`. |
| `-v`, `--volume SRC:DST[:ro\|rw]` | Mount a host directory, one host file, or a named volume. |
| `--mount type=bind\|volume\|tmpfs,src=...,dst=...,readonly[,driver=ext4lite\|hostfs]` | Mount with the Docker key syntax. The `driver` key applies to `type=volume` only. A `type=volume` source with a path separator names an image file. |
| `--tmpfs PATH[:size=64m,ro]` | Mount a memory-backed directory. |
| `--read-only` | Mount the root file system of the guest read-only. |
| `-m`, `--memory SIZE` | Limit the guest memory. The units are `b`, `k`, `m`, `g`, and `t`. The minimum is 6m. |
| `--cpus N` | Limit the CPU quota. The value is a decimal number, such as `1.5`. |
| `--network NAME` | `bridge` and `nat` select the NAT mode. `none` and `wg` are the other modes. `host` is refused. |
| `--platform linux/ARCH` | Select the architecture of the image: `linux/amd64` or `linux/arm64`. |
| `--pull POLICY` | Select when the image comes from its registry: `missing` (the default, as in Docker), `always`, or `never`. Section 5.1 describes the policies. |

The flag `-d` is refused with a message, because a run has no daemon.

### 3.2 gvx flags

| Flag | Meaning |
| :--- | :--- |
| `-image REF`, `-bin ELF` | Name the image or the binary without a positional argument. |
| `-platform BACKEND` | Select the execution backend: `auto`, `whpx`, `hvf`, or `systrap`. The `systrap` backend runs on Windows and Linux. macOS has no `systrap` engine. A value with a slash is a Docker image platform. |
| `-arch ARCH` | Select the guest architecture. The default is the host architecture. |
| `-workspace DIR`, `-ro` | Mount a host directory at `/workspace`, optionally read-only. |
| `-net MODE`, `-wg-conf FILE`, `-isolate-lan` | Select the network mode and its options. |
| `--privileged` | On by default. Turns on `--net-raw`, `--allow-packet-socket-write`, and `--allow-suid`. `--privileged=false` turns them off. A flag of the three that you set wins over `--privileged`. Section 4.8 describes the boundary. |
| `--net-raw` | Let the guest open raw sockets and use `iptables`. `dockerd` needs it. The default comes from `--privileged`. |
| `--allow-packet-socket-write` | Let the guest send on `AF_PACKET` sockets. It needs `--net-raw`. The default comes from `--privileged`, and it is off when `--net-raw` is off. |
| `--allow-suid` | Obey the set-user-ID and set-group-ID bits of guest executables. `sudo`, `su`, and `passwd` need it for a user that is not root. The default comes from `--privileged`. |
| `-registry-url URL` | Override the registry of the image reference. |
| `-cache-dir DIR` | Select the layer cache directory. |
| `-lockdown=false` | Skip the host lockdown. Use it only to debug. |
| `--tune KEY=VALUE` | Set a host-side tunable. The flag repeats. Section 3.3 lists the keys. `run`, `pull`, `load`, `save`, `images`, `inspect`, `rmi`, and `tag` take it. |
| `--tune-file FILE` | Read host-side tunables from a JSON object. A `--tune` flag wins over the file. The same eight commands take it. |

### 3.3 Tunables

A tunable is a limit or a time value of the host process that Linux has no knob for. The guest sets every Linux limit itself, through a `sysctl` file, a module parameter under `/sys/module`, or a netlink request. A tunable never replaces one of those. One registry in `pkg/gvx/tuning` holds all tunables. The SDK field `gvx.Config.Tuning`, the flags `--tune` and `--tune-file`, the command `rungv tune list`, and the table of this section come from that registry.

A duration has the form of a Go duration, such as `250ms` or `30s`. A size is a number of bytes with an optional binary suffix, such as `64MiB`. Each value in a `--tune-file` file is a string or a number. A `--tune` flag wins over the file. An unknown key, a value that does not parse, or a value outside the range is an error. The error names the key and the range.

To set a tunable:

1. Run `rungv tune list` to print the table.
2. Choose a key and a value inside its range.
3. Add `--tune net.nat.mtu=9000` to the command. Repeat the flag for each key.
4. Add `--tune-file FILE` instead to read the keys from a JSON file, such as `{"net.nat.mtu": 9000, "net.dns.timeout": "8s"}`.
5. Add the same flags to an image command, such as `rungv pull`, to set an `oci.*` key.

The test `TestDocsMatchRegistry` of `pkg/gvx/tuning` fails when this table differs from the registry.

To rewrite the table after a change of the registry, run `go test ./pkg/gvx/tuning -run TestDocsMatchRegistry -update`.

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

The key `kernel.log_buf_len` sets the size of the kernel log ring that `/dev/kmsg`, `dmesg`, and `syslog(2)` read. The sandbox rounds the value up to a power of two, and `syslog(SYSLOG_ACTION_SIZE_BUFFER)` returns the result. When the ring is full, the oldest records leave. The guest controls the other settings of the log through the files `/proc/sys/kernel/printk_devkmsg` (`on`, `off`, or `ratelimit`), `/proc/sys/kernel/dmesg_restrict` (0 or 1), and `/proc/sys/kernel/printk`.

The key `net.nat.mtu` sets the first MTU of `eth0` in the `nat` network mode. In the `wg` network mode, `eth0` starts with the `MTU` key of the `[Interface]` section of the WireGuard file, which is 1420 by default. Each link type accepts its own range of MTU values, and a value outside the range fails with `EINVAL`, as on Linux. A caller needs `CAP_NET_ADMIN`. Each end of a veth pair has its own MTU.

A link with an MTU below 1280 has no IPv6, as on Linux. The link loses its IPv6 addresses and routes. It accepts no new IPv6 address while the MTU stays below 1280. When the MTU returns to 1280 or more, the link accepts IPv6 addresses again.

| Link | MTU range |
| :--- | :--- |
| `eth0` in the `nat` network mode | 68 to 65535 |
| `eth0` in the `wg` network mode on Linux and macOS | 68 to 65503 |
| `eth0` in the `wg` network mode on Windows | 68 to 1984 |
| A veth link or a bridge that the guest creates | 68 to 65535 |
| `lo` | The link accepts a request and keeps 65536. Linux changes the value. |

To change the MTU of a link in the guest:

1. Run `ip link set dev eth0 mtu 1400`. Both `ip` of iproute2 and `ip` of busybox work.
2. Run `ifconfig eth0 mtu 1400` when the guest has only the busybox `ifconfig`.
3. Read the value in `/sys/class/net/eth0/mtu` or with `ip link show dev eth0`.

Software in the guest derives the MTU of its tunnels from `eth0`. `flannel` uses the MTU of `eth0` minus 50 for `vxlan` and minus 80 for WireGuard. The NAT relay sends datagrams of every size that the MTU allows. On macOS, the relay raises the send buffer of its host UDP sockets. The default `net.inet.udp.maxdgram` of 9216 bytes would refuse a larger datagram.

## 4. Rules of `run`

### 4.1 Command and environment

The command is the entrypoint followed by the command arguments. Each part comes from the caller, or else from the image. An override of the entrypoint drops the image `Cmd`, as in Docker. A run without any command stops with an error.

The environment starts with the `Env` of the image. Each `-e` entry and each env-file line then replaces the variable with the same name, or adds a new one. The env files are read first, and then the `-e` flags, so a `-e` flag wins. The sandbox adds `PATH`, `HOME`, and `HOSTNAME` when none sets them. It adds `TERM=xterm` for a terminal.

### 4.2 User

The user comes from `--user`, then from the `User` of the image, then it is root. The sandbox resolves a name in the `/etc/passwd` and `/etc/group` files of the image. A name that these files do not list stops the run. A number need not be listed.

A user that the passwd file does not list gets the group 0 and the home `/`, as in Docker. The user form `name` adds the supplementary groups that list the user. The form `name:group` adds none. The process of a user that is not root has no capability.

The root directory of the guest has the mode 0755, as in an image. A user that is not root cannot create a file there.

### 4.3 Hostname

The sandbox writes the hostname to `/etc/hostname`. It adds a line with the guest address to `/etc/hosts` when no line names the hostname. It also adds `host.docker.internal`, which names the host.

### 4.4 Mounts

A bind mount shows a host directory or one host file in the guest. A named volume is one image file, `<name>.ext4`, in a `volumes` directory. That directory is inside the `-cache-dir` directory, or else next to the default layer cache. The volume name matches `[a-zA-Z0-9][a-zA-Z0-9_.-]*`. The sandbox creates a missing volume image and a missing `-v` bind directory before the lockdown. The sandbox never creates a missing file. A `--mount type=bind` source must exist.

The image holds an ext4 file system that the `ext4lite` driver reads and writes. The image grows in steps of 16MiB, up to 64TiB. A clean exit returns the unused tail to the host. One sandbox at a time can use a volume, because the driver locks the image file. A second sandbox on the same volume fails at start. A read-only mount of a volume opens the image read-only and fails when the last run did not end cleanly.

The guest sees only the files that it wrote. The host sees one file. The image has a metadata journal. After a crash or a kill, the next run replays the journal. It keeps every file that the guest synced, and it frees the files that a guest unlinked and still held open. A volume of an older release gets a journal at the first run when the first 16MiB of the image has room for it, and the image never grows for that. `e2fsck -fn` accepts a clean image, and `mount -o loop -t ext4` mounts it on Linux.

A `--mount type=volume` source that contains a path separator names the image file of an `ext4lite` volume at any host path, as in `--mount type=volume,src=/disk/vols/pg.ext4,dst=/var/lib/postgresql`. A relative source starts with `./`, because a source without a separator is a volume name. The sandbox creates a missing image file before the lockdown, but not its directory. A read-only mount never creates the file. The path must not name a directory or a device. Such a volume has the same lock, journal, and growth rules as a named volume. `-v` keeps its meaning: `-v /disk/vols/pg.ext4:/data` mounts that file as one regular file.

A volume from an older release is a host directory in the same `volumes` directory. When that directory exists and the `.ext4` file does not, the sandbox keeps mounting the directory through `hostfs`. To use the `hostfs` driver for a new volume, write `--mount type=volume,src=NAME,dst=PATH,driver=hostfs`. The value `driver=ext4lite` is the default.

A guest overlay mount, as in `mount -t overlay -o lowerdir=...,upperdir=...,workdir=...`, accepts an upper directory on tmpfs, on an `ext4lite` volume, or on a `hostfs` directory. `docker:dind` needs this for the overlay storage driver, with `-v NAME:/var/lib/docker` or `-v /host/dir:/var/lib/docker`. The `ext4lite` volume is the faster persistent choice. The `hostfs` directory keeps each file as a host file, but it is slower, because it calls the host for each file operation. A measured `docker pull nginx:alpine` in `docker:dind` on macOS took about 5s on tmpfs, 9s on `ext4lite`, and 32s to 54s on `hostfs`. Another upper file system gets `EINVAL`.

A source with no path separator that is not an absolute path names a volume. A Windows drive letter stays in the source, as in `C:\data:/data:ro`.

A bind source can be one regular file, as in `-v /host/app.conf:/etc/app.conf:ro`. A socket, a device, or a pipe is not valid. The guest sees only that file. The parent directory and the sibling files of the host file are not exposed, and the guest cannot reach them by a path. The sandbox creates the guest path as an empty regular file with the mode 0644, and it creates the missing parent directories. The option `:ro` makes the file read-only. The option `-workspace` takes a directory only.

A file mount writes no `.gvx_meta` file. The mode, the owner, and the extended attributes that the guest sets stay in memory and reset at the next start. A change of the times reaches the host file. An `unlink` or a `rename` of the mounted file in the guest returns `EBUSY`, as for a file that Docker bind-mounts. A `link` to the file returns `EXDEV`. When a host editor replaces the file with an atomic rename, the next open of the guest path reaches the new file. A descriptor that was already open keeps the old file.

On Windows, the sandbox puts the Low integrity label and an access entry for the logon session on the mounted file only. It also gives the logon session the traverse right (`FILE_TRAVERSE`) on the parent directory, with no inheritance. The restricted token has no `SeChangeNotifyPrivilege`, so the system needs that right to open the file through the parent. The right gives no listing and no creation of files. The sibling files keep their own security descriptors and stay closed. The entry stays on the parent directory after the run.

Each mounted host directory has one `.gvx_meta` table. Two mounts of one directory with the same access share the table. A host directory nested inside another mounted directory gets its own table. When the guest reaches the same file through both mounts, as in a non-aligned layout such as `-v $PWD:/app -v $PWD/logs:/var/log/app`, the two views can show different mode, owner, and attributes for that file. An aligned layout, as in `-v $PWD:/app -v $PWD/node_modules:/app/node_modules`, has no such overlap, because the inner mount covers the outer copy. A bind mount of one file keeps no table, so it can sit inside a mounted directory.

The guest path of a mount is absolute and clean. It is not `/`. It is not `/proc`, `/sys`, `/dev`, or a path below them, except a path below `/dev/shm`. Two mounts cannot share a guest path. A mount at `/workspace` conflicts with `-workspace`.

The tmpfs options are `size`, `ro`, and `rw`. The option `size` takes a number with a binary unit. Any other tmpfs option stops the run with an error that names it.

A volume with the `ext4lite` driver needs no lockdown rule for a host path. The sandbox opens the image file before the lockdown, and the guest reaches it only through that open file.

| Host OS | What the lockdown does with a mount |
| :--- | :--- |
| macOS | The Seatbelt profile gets a read rule, and a write rule for a writable mount, for the path and for its resolved path. |
| Windows | The lockdown writes a Low integrity label on each object of a writable mount. It grants the logon session read and execute access, and write access for a writable mount. |
| Linux | The seccomp filter allows opens through a directory descriptor when a bind mount or a `hostfs` volume exists. |

> [!WARNING]
> On Windows, a bind mount changes the security descriptors of the host directory, or of the host file for a file mount. Mount only a path that the guest may change.

### 4.5 Resource limits

`--memory` sets a limit on the memory use of the guest. A guard reads the memory accounting of the Sentry and kills the guest with SIGKILL when the use passes the limit. The exit code is 137, and `rungv` prints a message. The guard reads the use at short intervals, so a guest can pass the limit by the amount that it allocates between two readings. Without `--memory`, the limit is the physical RAM of the host, and the guard reads the use every 100 ms. The keys `memory.guard.poll_interval` and `memory.guard.host_poll_interval` set the two intervals.

The guest kernel takes its memory size from the physical RAM of the host, as runsc does. `MemTotal` in `/proc/meminfo` and `totalram` of `sysinfo(2)` equal `--memory` when it is below that RAM, and that RAM otherwise. A tmpfs mount without a size option, such as `/dev/shm`, gets half of the host RAM, as on Linux, also with `--memory`. A guest mount with `size=N%` gets N percent of the host RAM. The tmpfs that holds the writes to the root file system has no size limit of its own. The memory guard limits it.

A program in the guest can also limit a cgroup with `memory.max`, as `docker run -m` does in `docker:dind`. The Sentry checks each cgroup with a finite limit every 5 ms or more while it uses half of its limit, and every 25 ms otherwise. The keys `memory.cgroup.poll_interval` and `memory.cgroup.idle_poll_interval` set these times. It compares the anonymous memory plus the tmpfs data of the subtree with the limit. When the use passes the limit, the Sentry ends the process with the highest score with SIGKILL, but never the init process of the guest or a process with `oom_score_adj` of -1000. With `memory.oom.group` set, it ends every other process of the subtree. The Windows `systrap` engine does not enforce the limit. The counters `oom` and `oom_kill` in `memory.events` grow, and the file reports a change through `inotify`. A process can pass the limit by what it allocates between two checks, and a process that frees its memory before the next check is not found. The limits `memory.high`, `cpu.max`, and `cpu.weight` are accepted and stored, but nothing enforces them. [`docker-engine.md`](docker-engine.md), section 6.4, lists the details.

`--cpus` sets the number of CPUs that the guest sees, rounded up. Windows also caps the CPU time of the host process with a hard cap on the containment job. The other host OSes have no such cap, and `rungv` prints a warning. On Windows with `-platform=systrap`, the guest runs in stub processes that the cap does not cover.

### 4.6 Guest kernel

The guest sees the mounts that Docker gives a container: `/proc`, `/sys`, `/sys/fs/cgroup` (the `cgroup2` hierarchy), `/dev`, `/dev/pts`, `/dev/shm`, and `/dev/mqueue`. The devices `/dev/fuse` and `/dev/net/tun` exist. A FUSE server and a TUN device stay inside the sandbox. The network links have the names `lo` and `eth0`. A new network namespace, as from `unshare -n` or runc, has only `lo`. The guest can create bridge and veth links and forward packets between them. With `--net-raw`, `dockerd` and its default `bridge` network work, and so do `docker exec` and healthchecks. A bridge container cannot connect to the `eth0` address `10.0.2.15`, because the guest sends the reply through `eth0`.

The root file system is a mount on top of a hidden read-only root, as in runsc. `pivot_root(2)` therefore works, and runc can start containers in the guest. A call of `reboot(2)` by root in the guest stops the run. A power off or a halt gives the exit code 0. A restart gives 129, as if SIGHUP ended the init process. `systemctl poweroff` therefore ends `rungv`.

### 4.7 Published ports

`rungv` binds each published port before the lockdown. It prints one line for each port to the standard error before the guest starts, as in `rungv: publishing 127.0.0.1:49493 -> 8080/tcp`. The line shows the free port that the host chose. A published port needs the NAT network mode. The guest cannot add a published port after the start, so publish every port that a program in the guest will use, such as the ports of nested containers.

A range publishes one port for each number. The host range and the guest range must have the same length, as in `-p 8000-8009:8000-8009`. A guest range alone, as in `-p 8000-8009`, gets free host ports. One range has at most 1024 ports. A host port range and a single guest port are refused.

`-p unix:PATH:GUEST` binds a Unix socket at `PATH` on the host and forwards each connection to the TCP port `GUEST` of the guest. A leading `~/` names the home directory, because a shell does not expand `~` after `unix:`. Only the owner can open the socket. The lockdown stops `rungv` from removing the socket file at the end. The next run replaces a socket file that it finds at `PATH`, and it refuses any other file. A path cannot contain a comma, because `-p` splits its value at commas.

### 4.8 Raw sockets

`--privileged` is on by default, because its privileges stay inside the sandbox. A raw socket can send packets with any source address on the guest network, but the packets reach only the guest stack. The NAT mode still applies its destination rules, including `-isolate-lan`, to each packet that leaves `eth0`. The host network does not see the packets of a raw socket. The `iptables` tables work through the legacy interface (`iptables-legacy`). The `nftables` interface is not available.

The legacy interface has the tables `filter`, `nat`, `mangle`, and `raw`. It has these matches: `addrtype`, `comment`, `conntrack` (`--ctstate` only), `icmp`, `icmp6`, `limit`, `mark`, `multiport`, `owner`, `physdev`, `recent`, `set`, `statistic`, `tcp`, and `udp`. The `addrtype` match knows the types `UNICAST`, `LOCAL`, `BROADCAST`, `MULTICAST`, and `UNSPEC`. It accepts `--limit-iface-in` and `--limit-iface-out`. The match `--dst-type LOCAL` is true for each address of a guest link and for the whole `127.0.0.0/8` range. The `statistic` match takes `--mode random` and `--mode nth`. The `recent` match keeps each list in the network namespace of its rules, and it has no `/proc/net/xt_recent` files. The `icmp` and `icmp6` matches select packets by ICMP type and code, as `-p icmp --icmp-type echo-request` does. The `limit` match is a token bucket, and each rule has its own bucket that `iptables-restore` fills again. The `physdev` match reads the ports of a frame that a bridge switches between two ports. A packet that the IP layer routes has no bridge information. Linux knows the egress port in the FORWARD and POSTROUTING hooks only, so `--physdev-is-bridged` matches there. The target `NFLOG` accepts its rules and keeps them for `iptables-save`, but no log group receives a packet. The target `LOG` writes its line to the kernel log of the guest, which `dmesg` and `/dev/kmsg` read, when its rule is in the root network namespace. The commands `iptables -C` and `iptables -D` find rules with `! -i`, `! -o`, and `-j DNAT`. The `conntrack` tool and the Go library `github.com/vishvananda/netlink` list and delete tracked connections. The guest has IP sets, which the `ipset` tool, `kube-router`, and Calico create through `NETLINK_NETFILTER`. The set types are `hash:ip`, `hash:net`, `hash:ip,port`, `hash:net,port`, `hash:ip,port,ip`, `hash:ip,port,net`, `hash:net,net`, `bitmap:port`, and `list:set`. The match `set` and the target `SET` use them for IPv4 and IPv6. The sets belong to the network namespace, and a limit follows the Linux setting: `maxelem` defaults to 65536, and `/sys/module/ip_set/parameters/max_sets` (default 256) sets the first size of the table of sets.

The connection tracker starts with the first rule of a table. It follows the sysctl files of `/proc/sys/net/netfilter`, with the Linux defaults. A TCP connection has one timeout for each state, from `nf_conntrack_tcp_timeout_syn_sent` to `nf_conntrack_tcp_timeout_close`. A UDP flow, an ICMP flow, and an ICMPv6 flow have a timeout each. `nf_conntrack_max` is 262144 at the start and has one value for the whole guest. When the table is full, the tracker removes a connection that timed out or is not assured. Otherwise it drops the packet that needs a new connection. `conntrack -L` shows the time that is left of each timeout. Each connection takes about 500 bytes of host memory.

An unmodified `docker:dind` image starts with the default `--iptables=true`. [`docker-engine.md`](docker-engine.md) shows how to use it as the Docker Engine of the host. The `bridge` network masquerades the traffic of its containers. A published port (`docker run -p`) uses a `DNAT` rule and the `docker-proxy` process. A user-defined network resolves container names. `docker build` and `docker compose up` work. The option `--userland-proxy=false` works. A published port then uses only the `DNAT` rule, and a connection from the guest to `127.0.0.1` and the published port reaches the container. The command `iptables-legacy-save` prints the tables `filter`, `nat`, `mangle`, and `raw`. The bridge passes the IP frames that it forwards through the `iptables` hooks while `/proc/sys/net/bridge/bridge-nf-call-iptables` is 1, which is the default. A `FORWARD` rule for `-i docker0 -o docker0` therefore separates two containers of one bridge.

### 4.9 Failures and diagnostics

`-platform=auto` prefers the hardware hypervisor and falls back to `systrap`. The fallback is slower. `rungv` then prints a warning that names the cause and the fix. On Windows the usual cause is a disabled "Windows Hypervisor Platform" feature. On macOS it is a binary without the hypervisor entitlement. Sign it with `codesign --sign - --entitlements entitlements.plist --force rungv`. The SDK gives the same text through `Sandbox.FallbackReason`.

The exit code 137 has two causes that `rungv` tells apart. A guest that passes `--memory` gets the message about the memory limit. When the engine fails under the guest, the kernel ends the guest with SIGKILL, and `rungv` prints `the execution engine stopped the guest` with the cause. The SDK returns `ErrEngineFault` in that case. A stub process that a virus scanner ended is one example of an engine fault.

`GVX_DEBUG_LOG=1` prints the log of the kernel to the standard error of `rungv`, and the value `2` also prints debug lines. Use it when a guest fails and no message names the cause. `GVX_STRACE=1` also prints each system call of the guest.

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

## 6. The image store

The layer cache is the image store. It holds the compiled EROFS layers, one record for each image, and one record for each name. The default directory is `%LOCALAPPDATA%\gvx\cache\layers` on Windows and `~/Library/Caches/gvx/layers` on macOS.

`rungv images` lists names and tags. The IMAGE ID is the first 12 digits of the config digest, as in Docker. The SIZE column is the size of the EROFS layer files on disk. The flags are `-a`, `-q`, `--no-trunc`, `--digests`, and `--format json`.

`rungv rmi` removes a name. When no name or digest keeps the image, it removes the image record and the layer files that no other image uses. An ID that has several names needs `-f`.

`rungv save` writes a tar archive that is an OCI image layout and also has the Docker file `manifest.json` with `RepoTags`. The cache holds compiled layers and not the original blobs. The command therefore fetches each original layer from the registry and verifies its digest. It fails for an image that came from an archive. It writes a temporary file first, so a failure leaves no partial archive.

`rungv load` reads such an archive, an OCI layout, or the output of `docker save`. It registers the names of the archive. It skips the images of other architectures.

## 7. Differences from Docker

| Docker | `rungv` |
| :--- | :--- |
| `-d`, `ps`, `exec`, `logs`, `stop`, `rm`, `restart` | Not available. A run is in the foreground and has no state. |
| `docker build`, `compose`, `network`, `volume` | Not available. Remove a named volume by deleting its image file, `<name>.ext4`. |
| Image `VOLUME`, `HEALTHCHECK`, `STOPSIGNAL`, labels | Ignored. |
| `--network host` | Refused. The guest has its own network stack. |
| `-p HOST-RANGE:PORT` | Refused. Publish ranges of the same length. |
| `--privileged` | On by default. Its privileges stay inside the sandbox. |
| `--name` | Sets the container ID of the kernel and nothing else. |
| Image with a Docker manifest schema 1 | Refused with a message. Docker 28 and later also refuse it. Rebuild or re-push the image. |
| `docker save` of any image | The command needs the registry that the image came from. |
| Cgroup limits | `--memory` is a guard with a delay. `--cpus` caps the CPU time on Windows only. In the guest, `memory.max` of a nested cgroup ends processes with a delay. The Windows `systrap` engine does not enforce it. `cpu.max` of a nested cgroup holds on every engine. `memory.high` and `cpu.weight` of a nested cgroup are not enforced. |
| Linux host with a seccomp listener in the filter chain of the process | The kernel allows one listener in a chain. The `systrap` engine then uses the futex loop for its stub threads. It writes one warning. This loop is slower than the listener. |
| Cgroup v1 | Not available. `/sys/fs/cgroup` holds the `cgroup2` hierarchy. |
| Guest architecture | Must equal the host architecture, except with `-platform=systrap`. |
| Executables that link at a fixed address (non-PIE) | `hvf`, `whpx`, and the Windows `systrap` engine run them natively. The removed macOS `systrap` engine could not run them, because every `arm64` task on macOS has a 4GB `PAGEZERO`. |
| A store into the page of the storing instruction | The Windows `systrap` engine completes the store with a single step, and the page runs the new bytes. Each such store costs three debug stops. On `arm64`, a store exclusive (`stxr`, `stlxr`, `stxp`, `stlxp`) into its own page ends with SIGSEGV. |
| Writes to the root file system | Lost at exit. Use a mount for data that must stay. |

## 8. Examples

Run a command in an image, as a user, with an environment variable and a bind mount:

```sh
rungv run -u 1000 -e MODE=test -v "$PWD":/src:ro -w /src alpine:3.20 sh -c 'ls; id'
```

Publish the exposed port of an image to a free host port:

```sh
rungv run -P nginx:alpine
```

Limit the memory and keep the data in a named volume:

```sh
rungv run -m 512m -v data:/var/lib/app myimage:1.0
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
| `go VERSION OS/ARCH` | The Go toolchain and the target of the binary. |

The command exits with 0 on success and with 2 when an argument is unexpected.
