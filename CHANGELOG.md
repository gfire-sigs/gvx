# Changelog

This file records the observable changes of each `gvx` release. The release workflow `.github/workflows/release.yml` publishes the section of a tag as its release notes. A tag with a hyphen, such as `v0.1.0-rc.1`, publishes a pre-release.

## [Unreleased]

This section records changes that no release contains yet.

### Bug Fixes

- **Directory link count on Windows `hostfs`**: `stat` of a directory reported 2 links on NTFS for every directory. It now reports 2 plus the number of subdirectories, as Linux does. Tools such as `find` use that count.
- **Large `truncate` on Windows `hostfs`**: a growth above the free disk space failed with `ENOSPC`, and a size above the NTFS file limit failed with `EIO`. The growth now leaves a hole, as on Linux, and the size above the limit fails with `EFBIG`.
- **Windows `systrap` engine errata** (`windows/amd64` and `windows/arm64`): three defects of the engine are fixed.
  - A guest that wrote code through one view of a memory file and ran it through another view kept running the old code. A write through a second view of a frame now drops the patched copies of that frame in every address space. A frame without a patched copy costs no extra fault.
  - On `windows/arm64`, a fast `svc` overwrote a live `x18` of the guest with a stale value, unless the guest set `x18` with `mov x18, xN`. The `svc` slot now saves `x18` first, so every `svc` keeps it. A guest whose stack pointer is invalid still gets its system call through the debug path. The patcher no longer rewrites `mov x18, xN`, which leaves 289 rewritten encodings instead of 320.
  - On `windows/arm64`, every `ic ivau` of a guest cost one debug stop. The engine now replaces the instruction with `nop`, and `CTR_EL0` reports `DIC` and `IDC` for the guest. Guests that obey these bits, such as V8, skip the instruction.

### Behavior Changes

- **`.gvx_meta` keys its records on file identity** (`hostfs`, journal version 4): a record belongs to a file and not to a path. The identity is the volume serial number and the 128-bit file id on Windows, and the device, the inode number, and the birth time on Linux and macOS. The birth time tells a new file from an old one with the same inode number, which ext4 reuses at the next create. APFS lowers the birth time when a process sets an earlier modification time. `hostfs` detects that case and keeps the record. Measured on an Apple M1 with APFS, with the benchmarks of `HOSTFS_BENCH=1`:

  | Operation | Table size | Before | After |
  | :--- | ---: | ---: | ---: |
  | Listing of a directory with 100 files | 10,000 records | 216 us | 165 us |
  | Listing of a directory with 100 files | 100,000 records | 789 us | 140 us |
  | Rename of a directory with 2,000 children | 10,000 records | 527 us | 87 us |
  | Rename of a directory with 2,000 children | 100,000 records | 1.8 ms | 73 us |
  | `chmod` through one name of a file with 4 names | 10,000 records | 276 ms | 4 us |
  | `chmod` through one name of a file with 4 names | 100,000 records | 2.5 s | 3 us |
  | Flush of one change | 10,000 records | 4.9 ms | 4.0 ms |
  | Flush of one change | 100,000 records | 5.0 ms | 4.0 ms |
  | Open of a workspace | 10,000 records | 59 ms | 25 ms |
  | Open of a workspace | 100,000 records | 450 ms | 165 ms |

  - A host process that renames a file or a directory keeps the mode, the owner, and the extended attributes of the guest. A guest symbolic link follows its directory. Before, the record stayed behind at the old path.
  - A host process that creates a file at the path of a file that still exists no longer gives it the record of that file. A host editor that saves by writing a temporary file and renaming it over the document keeps the record: a file with no record adopts the record that the guest last saw under the same directory and name, when the recorded file is gone, and it loses the set-user-ID and set-group-ID bits. On Linux and macOS, a host process that deletes a file and creates another one under the same name, or that moves a file to another directory and creates a new one in its place, gives the record to the new file, because only Windows can ask the host whether the recorded file still exists.
  - On macOS, `utimensat` to a time before the creation of a file lowers its APFS birth time, as `tar`, `cp -a`, and `rsync -a` cause. `hostfs` re-keys the record of the file, and the guest links of a directory, at the call.
  - The names of a hard-linked file share one record. A `chmod`, `chown`, or `setxattr` makes no scan of the table, and a `link` needs no new record. A listing and a rename of a directory scan no table either.
  - The open of a workspace no longer checks each record against the host. A background collector removes the records whose file is gone. It starts 30 s after the open and works in small steps. A record dies when two complete passes in a row miss it and a lookup by its hint path confirms the loss. A directory that the host denies access to is skipped, and a skipped directory keeps its records. A record that a conversion could not resolve because of a host error stays as a path record until the next open.
  - The cap of the table is now 128 MiB of estimated memory, about 300,000 plain records. The old cap was 262,144 records. A record with large extended attributes counts more than a plain record.
  - A volume without trustworthy file identities keeps its records by guest path, as before. The probe at the open needs a real birth time on Linux and macOS, or `FILE_ID_INFO` on Windows. On macOS the volume must be APFS or HFS+. The identity must stay the same across a write. `WorkspaceCaps.StableIDs` reports the result. A bind mount of one file keeps its records in memory only, as before.
  - The sandbox now refuses a host directory that lies inside another mounted host directory, unless both mounts are read-only or the inner mount covers the outer copy of its directory (`-v $PWD:/app -v $PWD/node_modules:/app/node_modules`). The two `.gvx_meta` tables would otherwise drift apart for the same files. The error is an invalid configuration error at the start.
  - `hostfs.ReadMeta` names each record by the path where it finds the file in the host tree, and it leaves out the record of a file that no longer exists.
  - **Upgrade note**: the first write to a workspace or a volume that has an older `.gvx_meta` converts the file to version 4. The conversion reads the host once for each recorded path, drops the records of paths that name nothing, and merges the records of hard links. A release before this one cannot open a converted workspace: it fails with an error for the unsupported version. Keep a copy of `.gvx_meta` before you convert a workspace that an older release must open again. A session that changes nothing leaves the older file as it is.

- **Faster `hostfs` and a journal for `.gvx_meta`**: `hostfs` serves `-workspace`, bind mounts, and `driver=hostfs` volumes. Measured on an Apple M1 with `hvf`, the guest creates 10,000 files in 1.2 s to 2.0 s (was 2.4 s to 2.6 s), runs `ls -lR` over them in 0.4 s (was 1.0 s), extracts a tree of 2,000 files with `tar x` in 0.7 s (was 1.6 s), and runs 300 rounds of `dd conv=fsync` plus `mv` in 3.8 s (was 10.4 s). A `docker pull nginx:alpine` on `hostfs` went from 44 s to 41 s, because the host file system dominates that workload.
  - Every lookup, mutation, and directory listing now goes through the pinned handle of the directory. A `create`, `rename`, `chmod`, `utimensat`, or `link` at depth 5 made 7 to 34 host system calls and now makes 2 to 8.
  - A directory listing reads the entry type and the inode number from the directory record, and no longer stats each entry. A `stat` of each entry after an `ls` makes no host call. Metadata that a host process changes for an existing entry shows up after 1 s, as for every other host change.
  - A write no longer drops the cached identity of a file, so an `fstat` of an open file makes no path lookup.
  - `.gvx_meta` is an append-only journal with checksummed frames and periodic compaction. A flush of one change with 100,000 records took 83 ms and now takes 7.9 ms (13.4 ms and 6.8 ms with 10,000 records). `fsync`, `fdatasync`, `sync`, and writes with `O_SYNC` keep their durability, and a table without changes costs no host call. A crash can leave a torn last frame, which the next start ignores.
  - **Upgrade note**: the first write to a workspace or a volume that has a JSON `.gvx_meta` converts the file to the journal form. A release before this one cannot open a converted workspace: it fails with a parse error for `.gvx_meta`. Keep a copy of `.gvx_meta` before you convert a workspace that an older release must open again. A session that changes nothing leaves the JSON file as it is.

## [v0.6.10002026110200] - 2026-11-03

This release updates the Sentry to gVisor `release-20261102.0` and introduces a new version format. `AGENTS.md`, section 5.2, defines the format.

### Behavior Changes

- **Upstream gVisor `release-20261102.0`**: the Sentry now comes from the `go` branch commit `1cea747e`. That commit is the first merge that contains the release commit `7a675ac6`. The guest vDSO reads a new `CLOCK_BOOTTIME` offset from the parameter page.
- **Upstream diff budget**: `tools/upstream -mode=audit` accepts a charged share of up to 2.0% of upstream files. The old limit was 1.0%.
- **Version format**: the PATCH field of a release tag joins the digit `1`, a three-digit release counter, the upstream release date, and the two-digit upstream release suffix. `v0.6.10002026110200` is the first release in `0.6` and contains gVisor `release-20261102.0`.

## [v0.5.2] - 2026-11-03

This release lets Node.js build TypeScript and JavaScript projects on the Windows `amd64` `systrap` engine. The engine runs when the host has no Windows Hypervisor Platform, or with `-platform=systrap`.

### Bug Fixes

- **Node.js on the Windows `amd64` `systrap` engine** (issue #24): `npm install`, `tsc`, `transpileModule()`, esbuild, and `vite build` ended with SIGSEGV (exit code 139), SIGTRAP (exit code 133), or SIGILL (exit code 132) in Node.js 20, 22, and 24. Three engine defects caused this:
  - The repair of a lost FS base ran the faulting `%fs` instruction again, and Windows could reset the base again first. After eight repairs, the engine reported SIGSEGV. The Sentry now runs the instruction and moves past it, so each repair makes progress.
  - The engine patched false system call and GS sites in the data that V8 keeps beside its code in writable and executable anonymous memory. V8 then read changed pointers. On `amd64`, such pages now run unpatched. A writable segment of an ELF file stays patched.
  - The scan saw only 15 bytes before a page, and it found a GS instruction inside a `lea` of Node.js 20. The scan now starts 64 bytes before the page.

## [v0.5.1] - 2026-11-02

This release lets the unmodified `docker:dind` image run as a persistent Docker Engine that the `docker` command of the host controls. `docs/docker-engine.md` describes the setup on macOS and Windows.

### Features

- **Guest overlay upper layer on `ext4lite` and `hostfs`**: a guest `mount -t overlay` with `upperdir` on a named volume, a volume image, or a bind mount no longer fails with `EINVAL`. The overlay storage driver of `dockerd` therefore works with `-v NAME:/var/lib/docker` and with `-v /host/dir:/var/lib/docker`, with the containerd snapshotter and with `overlay2`. Whiteouts, opaque directories, and copy-up data survive a restart and a SIGKILL. `ext4lite` is the faster choice. `hostfs` is slower. See `docs/cli.md`, section 4.4.
- **`iptables -m addrtype`**: the guest has the `addrtype` match in revisions 0 and 1, for IPv4 and IPv6. It knows the types `UNICAST`, `LOCAL`, `BROADCAST`, `MULTICAST`, and `UNSPEC`, and the options `--limit-iface-in` and `--limit-iface-out`. An unmodified `docker:dind` image now starts with the default `--iptables=true`. It failed with `Extension addrtype revision 0 not supported`. `docker run -p`, the default `bridge` network, user-defined networks, `docker build`, and `docker compose up` work in the guest.
- **Port ranges in `-p`**: `-p 8000-8009:8000-8009` and `-p 8000-8009` publish one port for each number, up to 1024 ports. Two ranges must have the same length.
- **Unix socket publishing**: `-p unix:PATH:GUEST` forwards a host Unix socket to a guest TCP port, for example `-p unix:~/.gvx/docker.sock:2375` for the Docker API. The SDK field is `PortForward.HostSocket`.

### Behavior Changes

- **`--privileged` on by default**: `rungv run` turns on `--net-raw`, `--allow-packet-socket-write`, and `--allow-suid` unless `--privileged=false` is given. A flag of the three that you set wins over `--privileged`. These privileges stay inside the sandbox. The SDK fields keep their zero values off.

### Bug Fixes

- **`hostfs` and `ext4lite` as overlay layers**: both drivers returned `EOPNOTSUPP` for the POSIX ACL query of the overlay, so a mount with one of them as a layer failed. They now report no ACL.
- **Failed overlay mount**: an error after the root dentry of the overlay existed made the Sentry panic. The mount now fails with the error.
- **Program starts from a `hostfs` layer of an overlay**: the second start of an executable on a `hostfs` lower or upper layer ended with SIGBUS or `Bad address`, for example `nginx` in a container on a `hostfs` Docker root. `hostfs` now opens a handle when a new mapping finds none.
- **Inverted input interface in `iptables`**: a rule such as `! -i docker0 -j DNAT` came back from the guest as `-i docker0`. `iptables -C` and `iptables -D` did not find the rule. The guest now reports the `!` of `-i`, for IPv4 and IPv6.
- **`DNAT` rule deletion**: the `DNAT` target of revision 2 reported a size of 72 bytes, but it has 80 bytes. `iptables -C` and `iptables -D` did not find a `DNAT` rule, so `dockerd` left the rule of a removed container behind. The size is now correct.

## [v0.4.1] - 2026-11-02

This release makes `docker exec` work in a guest.

### Bug Fixes

- **`docker exec` in a guest**: runc refused `docker exec`, healthchecks, and `docker compose exec` with `namespace NEWNS is not supported`. The root mount namespace of the guest had no nsfs inode, so `/proc/[pid]/ns/mnt` could not be read. The kernel now gives the namespace its inode, as in runsc. `setns(2)` into a mount namespace also works.
- **Linux `FutexWait` with a timeout**: a signal handler that ran during the wait, such as the SIGURG of Go preemption, made the wait return as if a wake had come. The Sentry synchronization code on Linux hosts now parks again for the time that is left.

## [v0.4.0] - 2026-11-02

This release closes the gaps to runsc that systemd, Docker in the guest, and desktop workloads hit. It also fixes a guest-triggered host panic and a slowdown of every system call on macOS.

### Features

- **`rungv run --pull=always|missing|never`**: the flag selects when an image comes from its registry, as in Docker. The default is `missing`, as in Docker. The SDK has `Config.PullPolicy` with `PullAlways`, `PullMissing`, and `PullNever`, and `Config.Warnings` for the warning line. `missing` uses the cache first. `never` uses only the cache.
- **ext4lite volume at any host path**: `--mount type=volume,src=/disk/vols/pg.ext4,dst=/data` stores the volume in that image file instead of the `volumes` directory of the cache. A source with a path separator names the file. The sandbox creates a missing file but not its directory. The SDK field is `Mount.ImagePath`.
- **`--net-raw` and `--allow-packet-socket-write`**: the guest can open raw sockets and use `iptables-legacy`, as with the runsc flags of the same names. `dockerd` needs them. The SDK fields are `Config.NetRaw` and `Config.AllowPacketSocketWrite`. Both are off by default.
- **`--allow-suid`**: the guest obeys the set-user-ID and set-group-ID bits, as with the runsc flag. `sudo` then works for a user that is not root. The SDK field is `Config.AllowSUID`. It is off by default.
- **Container runtimes in the guest**: the guest root file system is now a mount on a hidden read-only root, as in runsc, so `pivot_root(2)` works. A new network namespace gets a stack with `lo`; `unshare -n` hung before. The kernel has `mqueue` at `/dev/mqueue`, `cgroup2` at `/sys/fs/cgroup`, `/dev/fuse`, `/dev/net/tun`, and `NETLINK_KOBJECT_UEVENT` and netfilter netlink sockets.
- **`reboot(2)`**: a power off or a halt by root in the guest ends the run with exit code 0, and a restart ends it with 129. `systemctl poweroff` stopped no run before.
- **Task watchdog**: the kernel logs the stacks of a task that stays in the Sentry for 3 minutes. `GVX_DEBUG_LOG=1` shows the log.

### Behavior Changes

- **`rungv run` uses the cached image first**: the default pull policy is now `missing`, as in Docker. A run of a cached reference sends no registry request, so a tag that moved in the registry keeps the cached image. Use `--pull=always` or `rungv pull` to get the new image. The SDK default of `Config.PullPolicy` is `PullMissing`.
- **Host RAM as the guest memory size**: `MemTotal` and `sysinfo(2)` report the physical RAM of the host, as in runsc. Before, they reported 2 GiB. A tmpfs mount without a size option gets half of that RAM, and `size=N%` now resolves. systemd failed at boot on `size=20%` before. Without `--memory`, the memory guard stops a guest that passes the host RAM.
- **Network links**: the guest links have the names `lo` and `eth0`, so `ip addr` lists them and Docker host networking finds them. Every guest stack has ARP, local delivery, SACK, receive buffer tuning, and a default TTL of 64, as the runsc stack has.
- **NAT mode routing**: `eth0` is now a link to a second in-memory stack that stands for the host network, and not a loopback device of the guest stack. The guest stack therefore forwards and translates packets as a Linux router does. `dockerd --net-raw` with its default `bridge` network now reaches the internet, and `docker build` works. A connection from a bridge container to `10.0.2.15` still fails, because the guest stack sends the reply through `eth0`, the link of that address.

### Performance

- **Root file system lookups**: the overlay of the root file system keeps up to 4096 unused dentries. Before, it destroyed a dentry at its last reference and looked up each path component in each layer again. On `hvf` (Apple M1), `stat(2)` of a file two directories below the root fell from 8.6 us to 2.3 us, a path with 8 more components from 20.8 us to 2.4 us, and a file in the merged `/tmp` from 13.4 us to 2.0 us. A plain tmpfs takes 2.0 us.
- **`darwin` system calls**: see the `GOMAXPROCS` fix below. A 1-byte `pread` stays at about 1.9 us after the first second, where it rose to 42 us.

### Bug Fixes

- **Guest-triggered host panic on `darwin` and `windows`**: a failed `sendmsg` on a Unix socket (for example `su` or `logger` in an Alpine guest) stopped the host with `unknown host errno "errno 107"`. `syserr.Error.ToError` returned a Linux number as a host `unix.Errno`, and `syserr.FromError` then looked it up in the host table. `ToError` now returns the `linuxerr` error on those hosts, and `FromError` keeps the Linux number.
- **`darwin` host performance after lockdown**: `GOMAXPROCS` fell from the CPU count to 1 about one second after `hostlockdown.Apply`, and every guest system call became about 20 times slower. The Go runtime re-read `hw.ncpu` with `sysctl`, and Seatbelt rejected the call. `Apply` now pins `GOMAXPROCS` before it applies the profile.
- **`/proc/cpuinfo` on `darwin/arm64` and `windows/arm64`**: `CPU architecture`, `CPU implementer`, `CPU part`, and `BogoMIPS` were 0. containerd then chose the platform `linux/arm64/unknown`. The fields now show architecture 8, the fields of the `MIDR_EL1` value that the guest reads, and `BogoMIPS` of twice the `CNTFRQ_EL0` frequency in MHz (48.00 for a 24 MHz counter). `hvf` guests show implementer 0x61 (Apple). The `hvf` backend writes that `MIDR_EL1` value to every vCPU, so the guest value does not depend on the Apple chip of the host.
- **`rungv run` of a loaded image**: after `rungv load -i img.tar`, `rungv run mylocal/app:1` failed with a registry 401, because the run always asked the registry first. The default policy `missing` now uses the cached image without a registry request. With `--pull=always`, the run uses the cached image when the registry answers 401, 403, or 404, and it prints one warning line. `oci.ErrAuthRequired` names a registry that demands credentials that the Docker configuration does not hold.
- **systemd mount units**: `run-lock.mount` and other units with `KeyringMode=shared` failed with status 237/KEYRING, because `keyctl(KEYCTL_LINK)` of the user keyring returned ENOSYS. That link now succeeds. The Sentry has no user keyring, so the link adds no key.
- **Host crash when a guest init exits**: `rungv` stopped with a nil pointer panic when the guest init exited with a netlink socket open, as systemd does at power off. The sandbox held the last reference of the init file table and released it without a task.
- **Docker schema 1 images**: `rungv pull` and `rungv run` now report `image uses Docker manifest schema 1, which is not supported; rebuild or re-push it with a current Docker`. Before, a signed schema 1 manifest such as `sshipway/xclock` failed with `content digest mismatch`, because the registry reports the digest of the unsigned payload. `oci.ErrSchema1Unsupported` names the error.

## [v0.3.0] - 2026-11-02

This release makes the CPU features that a guest sees agree with the features that it can use.

### Bug Fixes

- **`whpx` on `windows/amd64`**: guests can use AVX, AVX2, FMA, F16C, and AVX-512. XCR0 was 3 (x87 and SSE), while CPUID and `/proc/cpuinfo` reported the AVX family. A program that checked only CPUID or `/proc/cpuinfo` got `SIGILL`, and x86-64-v3 images (RHEL 10 family) did not start. The backend now selects the `ProcessorXsaveFeatures` property and XCR0 together. It moves the compacted XSAVE state through `WHvGetVirtualProcessorState` and `WHvSetVirtualProcessorState`.
- **`whpx` feature set on `windows/amd64`**: `/proc/cpuinfo`, signal frames, and sigreturn checks list only the features of the partition. MPX, AMX, and protection keys no longer appear.
- **`AT_HWCAP` on `darwin/arm64` and `windows/arm64`**: the value was 0, and the `Features` line of `/proc/cpuinfo` was empty. `hvf` guests now get the bits of the `hw.optional` sysctl keys. `whpx` guests on `windows/arm64` get the host bits that `hvcommon.DefaultIDRegisters` also reports. glibc and OpenSSL then use LSE atomics, AES, SHA, and CRC32.

### Performance

Each value is the median of 3 runs. The baseline is `v0.2.0`.

| Workload | Host | Before | After |
| :--- | :--- | ---: | ---: |
| AES-128-GCM, `openssl speed` 16 KiB blocks in `alpine/openssl` on `hvf` | Apple M1 | 0.22 GB/s | 7.45 GB/s |
| SHA-256, same method | Apple M1 | 0.45 GB/s | 2.84 GB/s |
| ChaCha20-Poly1305, same method | Apple M1 | 0.68 GB/s | 2.12 GB/s |
| Vector state pull and push with one system call on `whpx` | `windows-latest` (AMD, AVX2, nested Hyper-V) | 68.9 us | 63.4 us |
| Vector state push on `whpx` | same | 16.1 us | 13.6 us |
| System call round trip on `whpx` | same | 18.4 us | 15.9 us |

The `hvf` microbenchmarks of `e2e/microbench_e2e_test.go` (`getpid`, `open_close`, `pipe_pingpong`, `futex_pingpong`, `fork_wait`, `fork_exec_true`) show no change outside the variation between runs.

### Not verified

- `TestRealZMMSurvivesTheSentryAndProcessorSharing` skips on a CI runner without AVX-512.
- The `windows/arm64` `AT_HWCAP` path has no run on a Windows host.

## [v0.2.0] - 2026-11-01

This release makes the `whpx` backend run guests on `windows/arm64`. The other backends and targets have no behavior change.

### Bug Fixes

- **`whpx` on `windows/arm64`**: the partition now starts guests. The backend configures GICv3 before partition setup, assigns one redistributor to each virtual processor, and starts every virtual processor active. With v0.1.0 on Windows 11 build 28000, partition setup failed without the GICv3 parameters, and secondary processors stayed suspended.
- **`whpx` stub exit on `windows/arm64`**: WHP consumes `HVC #0` without an exit to the host. The EL1 stub now returns to the host through a load from an unbacked guest physical page that only EL1 can read.

### Performance

- **`whpx` on `windows/arm64`**: each system call and fault stop costs one extra `WHvSetVirtualProcessorRegisters` call. The memory exit leaves the program counter at the load, so the host writes the program counter before it resumes the processor.

### Not verified

- The contributor ran the native `whpx` suites and the image gates on Windows 11 build 28000 only. The project has no native result on Windows 11 24H2 (build 26100), the documented minimum.
- CI cannot run `whpx` on `windows/arm64`, because the `windows-11-arm` runner has no Windows Hypervisor Platform.
- The extra program counter write has no latency measurement.

## [v0.1.0] - 2026-11-01

This section describes the first release. The API of `pkg/gvx`, the flags of `rungv`, and the on-disk formats of the image store and of `ext4lite` volumes can change before `v1.0.0`.

### Features

- **`rungv` CLI**: runs OCI images and Linux ELF64 binaries in the foreground with Docker-style flags. The commands are `run`, `pull`, `images`, `inspect`, `tag`, `rmi`, `save`, `load`, `login`, `logout`, `stub`, `license`, and `version`. [`docs/cli.md`](docs/cli.md) is the reference.
- **`pkg/gvx` SDK**: embeds one sandbox in a Go host program.
- **Execution backends**: `hvf` on `darwin/arm64`, `whpx` on `windows/amd64` and `windows/arm64`, the `gvx` `systrap` engine on `windows/amd64` and `windows/arm64`, and the upstream `systrap` platform on Linux.
- **OCI images**: pulls multi-arch images and compiles each layer in memory into a cached `.erofs` file. The guest architecture must equal the host architecture.
- **Storage**: `-workspace` and `-v` bind mounts through `hostfs`, and named volumes in one journaled `.ext4` file through `ext4lite`.
- **Network**: `-net=nat` with `-p` port forwarding, and `-net=wg` with an in-memory WireGuard tunnel.
- **Host lockdown**: Windows Restricted Token and Job Object, macOS Seatbelt, and Linux `seccomp`. The lockdown starts before the guest entrypoint runs.
- **Control shim**: the optional `containerd-shim-gvx-v2` command implements the control endpoints of runtime `io.containerd.gvx.v2`.
- **Release identity**: `rungv version` and `rungv --version` print the module version, the source commit, and the Go toolchain of the binary.
- **Release provenance**: each release archive has a SLSA v1 build provenance attestation (SLSA Build Level 2). `gh attestation verify` checks it. Section 2.4 of [`README.md`](README.md) gives the procedure.

### Known limitations

- The control shim rejects sandbox and workload creation with `Unimplemented`. It does not implement CRI.
- macOS has no `systrap` engine. `rungv` on macOS needs `Hypervisor.framework` and a binary signed with `entitlements.plist`.
- `darwin/amd64` is not supported.
- On Linux, a workspace, a bind mount, or a `hostfs` volume leaves `Status.UnboundFileOpenBlocked` false. Section 3.9 of [`docs/architecture.md`](docs/architecture.md) gives the reason.
- The release archive for macOS has an ad-hoc signature, not a Developer ID signature or notarization. Section 2.4 of [`README.md`](README.md) gives the install procedure.
- `whpx` on `windows/arm64` does not start a guest in this release. Use `-platform=systrap` on `windows/arm64`. v0.2.0 fixes `whpx`.

### Not verified

- CI cannot run `hvf`, because the hosted macOS runner has no hypervisor. The project verifies `hvf` on an Apple Silicon development host only.
- CI runs `whpx` on `windows/amd64` only. The `windows-11-arm` runner has no Windows Hypervisor Platform, so `whpx` on `windows/arm64` has no CI run.
- The control shim has no successful native sandbox creation and no guest workload on any platform.
