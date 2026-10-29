# `gvx`

`gvx` ports the Google gVisor user-space Linux kernel (Sentry) to 64-bit Windows (`windows/amd64`, `windows/arm64`) and macOS (`darwin/arm64`) as co-equal Priority-0 targets. It also supports Linux (`linux/amd64`, `linux/arm64`) officially. It executes unmodified Linux ELF64 binaries and multi-arch OCI container images inside one unprivileged host process via the `rungv` CLI or `pkg/gvx` SDK. Callers get isolated Linux execution on Windows, macOS, and Linux with millisecond startup, no Linux virtual machine, no kernel drivers, and no administrator or `root` privileges.

---

## 1. Architecture and Capability Overview

Running Linux binaries or container images on Windows and macOS traditionally requires a full virtual machine or software CPU emulation. WSL2, Docker Desktop, and Apple `Virtualization.framework` boot a Linux guest kernel and require background virtualization daemons. QEMU emulates an entire system board and CPU in software.

`gvx` runs the Linux kernel boundary in user space. About 65% of upstream `google/gvisor` (`pkg/sentry/kernel`, `pkg/sentry/arch`, `pkg/ring0`, `pkg/sentry/vfs`, `pkg/sentry/fsimpl/{erofs,overlay,tmpfs}`, and `pkg/tcpip`) is OS-agnostic Go code for `amd64` and `arm64`. `tools/upstream` expands those build constraints to `linux || windows || darwin` automatically. Host packages bind to Windows (`WinHvPlatform.dll`, `WaitOnAddress`, `MapViewOfFile3`), macOS (`Hypervisor.framework`, `__ulock_wait`, `mach_vm_remap`), and Linux (`systrap`, `seccomp`) primitives.

| Runtime Model | Host Targets | Cold Start | Memory Overhead | Admin or `sudo` Required | 4KB `mmap(MAP_FIXED)` | Direct OCI Image Run |
| :--- | :--- | ---: | ---: | :--- | :--- | :--- |
| **`gvx` / `rungv` (`whpx` / `hvf`)** | Windows (`amd64`, `arm64`) & macOS (`arm64`) | `~20 ms` | `~30 MiB` | No (Low Integrity / Seatbelt) | Hardware 4KB EPT / Stage-1 MMU | Yes (In-Memory Tar-to-EROFS) |
| **`gvx` / `rungv` (`systrap` Engine, M5)** | Windows (`amd64`, `arm64`), Linux (`amd64`, `arm64`) | `~25 ms` (`amd64`), `~65 ms` (`arm64`) on Windows | `~31 MiB` (Sentry only) | No (Restricted Token / `seccomp`) | 4KB | Yes (In-Memory Tar-to-EROFS) |
| **WSL2 / Docker Desktop** | Windows & macOS | `800-2500 ms` | `> 512 MiB` | Yes (VM Daemon / Services) | Guest Linux Kernel MMU | Requires VM Daemon |
| **QEMU (`tcg` Full System)** | Windows & macOS | `1500-4000 ms` | `> 256 MiB` | No | SoftMMU Emulation | Requires Disk Image Build |

The `whpx` and `hvf` row comes from `rungv run` on an Apple M1 with macOS 26 and the cached `busybox:1.36.1-musl` image. The registry remained offline during the run; a reachable registry adds about one second for tag verification. The `systrap` cold start is the median time of `gvx.New` on the GitHub-hosted runners `windows-latest` and `windows-11-arm`. These runners are virtual machines with four vCPUs. macOS has no `systrap` engine and runs on `hvf`. CI builds, vets, and tests `linux/amd64`, `linux/arm64`, `darwin/arm64`, `windows/amd64`, and `windows/arm64`.

| Architectural Layer | Owning Packages | Host Primitives and Mechanisms | Runtime Contract |
| :--- | :--- | :--- | :--- |
| **CLI & Go SDK** | `cmd/rungv`, `pkg/gvx` | Docker-style CLI parser and embeddable `gvx.Sandbox` lifecycle controller | Prepares images, volumes, sockets, and host handles before self-lockdown, then boots Sentry. |
| **OCI Image Store** | `pkg/oci` | Streaming `.tar.gz`/`.tar.zst` reader, `tar2erofs` compiler, Docker credential store | Compiles multi-arch OCI layers in memory into cached `.erofs` files without host extraction. |
| **Execution Backends** | `pkg/sentry/platform/{whpx,hvf,systrap,hvcommon}` | `WinHvPlatform.dll`, `Hypervisor.framework`, or `systrap` stub processes with trampoline islands | Executes guest Ring-3/EL0 code and intercepts syscalls and faults via shared memory pages. |
| **Application Kernel** | `pkg/sentry/kernel`, `pkg/sentry/mm`, `pkg/sentry/vfs` | Pure-Go Linux task scheduler, virtual memory manager, signal table, and VFS2 router | Services ~250 Linux system calls (`amd64` and `arm64`) in memory-safe Go. |
| **VFS2 Storage Drivers** | `pkg/sentry/fsimpl/{erofs,overlay,tmpfs,hostfs,ext4lite,chunkcache}` | Read-only EROFS layers, `os.Root` host mounts, and single-file `ext4` volumes with JBD2 journaling | Isolates rootfs writes in memory, persists volumes in one `.ext4` file, and pins `/workspace` opens. |
| **Netstack & Egress** | `pkg/tcpip`, `pkg/netbackend` | Track A: L4 Go `net` NAT and `-p` forwarders; Track B: L3 in-memory `wireguard-go` tunnel | Implements virtual `eth0` and `lo` in memory with zero kernel network drivers (`WinTun` or `/dev/tun`). |
| **Host Containment** | `pkg/hostlockdown` | Windows Restricted Token + Job Object, macOS Seatbelt `sandbox_init`, Linux `seccomp` | Blocks child process creation and unbound host file access before the guest entrypoint runs. |
| **Control Shim** | `cmd/containerd-shim-gvx-v2`, `internal/gvxshim` | JSON v3 bootstrap, local ttRPC Task v3 and Sandbox endpoints, generation-fenced lease cleanup | Provides an optional control-only `io.containerd.gvx.v2` shim adapter without guest execution. |

---

## 2. Quickstart (Procedural Module)

Run an unmodified OCI image or Linux ELF64 binary from the command line with `cmd/rungv`, or embed a sandbox inside a Go program with `pkg/gvx`.

### 2.1 CLI Execution (`cmd/rungv`)

`cmd/rungv` provides a Docker-compatible foreground runner and local OCI image store without a background daemon. See [`docs/cli.md`](docs/cli.md) for the complete command and flag reference.

| Command | Synopsis | Purpose |
| :--- | :--- | :--- |
| `run` | `rungv run [flags] IMAGE [COMMAND [ARG...]]` | Run a command inside an OCI image or a local Linux ELF64 binary (`-bin`). |
| `pull` | `rungv pull [flags] IMAGE` | Download an OCI image and compile its layers into the local EROFS cache. |
| `images` | `rungv images [-a] [-q] [--no-trunc] [--digests] [--format json]` | List cached images, tags, 12-char config IDs, and compiled EROFS sizes. |
| `inspect` | `rungv inspect IMAGE [IMAGE...]` | Print the OCI configuration and layer metadata of cached images as JSON. |
| `tag` | `rungv tag SOURCE_IMAGE[:TAG] TARGET_IMAGE[:TAG]` | Assign an additional repository name and tag to a cached image. |
| `rmi` | `rungv rmi [-f] IMAGE [IMAGE...]` | Remove an image reference and garbage-collect unreferenced EROFS layer files. |
| `save` / `load` | `rungv save -o FILE IMAGE...` / `rungv load -i FILE` | Export or import OCI/Docker tar archives across hosts. |
| `login` / `logout` | `rungv login [SERVER]` / `rungv logout [SERVER]` | Verify and store or remove registry credentials in the Docker config store. |
| `stub` | `rungv stub` | Probe the `systrap` engine on the active host and report its readiness. |

> [!IMPORTANT]
> On Windows, enable the "Windows Hypervisor Platform" feature for `whpx`, or pass `-platform=systrap` without it. On Linux, build with `CGO_ENABLED=0` because the upstream `systrap` platform hangs in a cgo build. On macOS, sign the binary with `entitlements.plist` for `hvf`. The macOS build has no `systrap` engine.

1. Build `rungv` with the Go 1.27+ toolchain.
2. Sign `rungv` with `entitlements.plist` on macOS.
3. Run an unmodified OCI image (`nginx:alpine`) with `-p 8080:80` port forwarding and `-net=nat` networking.
4. Mount a persistent named volume (`-v data:/var/lib/app`) backed by a journaled `<name>.ext4` image file.
5. Pass `-net=wg` with a WireGuard configuration file when cryptographic L3 host LAN isolation is required.
6. Run `rungv stub` on Windows or Linux to probe the `systrap` engine before running `-platform=systrap`.

```bash
# Build on macOS (Apple Silicon arm64) and apply the ad-hoc hypervisor signature
go build -o rungv ./cmd/rungv
codesign --sign - --entitlements entitlements.plist --force ./rungv

# Or build on Windows (amd64 or arm64)
go build -o rungv.exe ./cmd/rungv

# Or build on Linux (amd64 or arm64) without cgo
CGO_ENABLED=0 go build -o rungv ./cmd/rungv

# Track A: L4 NAT mode with -p port forwarding, named ext4lite volume, and bind mount
./rungv run -net=nat -p=8080:80 -v appdata:/var/lib/nginx -workspace=./my-project nginx:alpine

# Track B: Cryptographic L3 WireGuard mode (zero host LAN access, no WinTun.dll or /dev/tun)
./rungv run -net=wg -wg-conf=./sandbox-wg.conf -workspace=./my-project python:3.12-alpine \
  python3 -c "import urllib.request; print(urllib.request.urlopen('https://example.com').status)"

# Probe and run the systrap engine on Windows or Linux (no hypervisor needed)
./rungv stub
./rungv run -platform=systrap alpine:3.20 uname -m
```

### 2.2 Embeddable Go SDK (`pkg/gvx`)

`pkg/gvx` embeds the sandbox directly inside a Windows, macOS, or Linux host binary without external daemons.

| `gvx.Config` Field | Type | Description |
| :--- | :--- | :--- |
| `Platform` | `gvx.PlatformType` | `PlatformAuto` (tries `whpx`/`hvf`, then `systrap` on Windows and Linux), `PlatformWHPX`, `PlatformHVF`, or `PlatformSystrap`. |
| `OCIImage` / `BinaryPath` / `ELFBytes` | `string` / `string` / `[]byte` | OCI image reference (`alpine:3.20`), a Linux ELF64 file on the host, or the bytes of one. |
| `Argv` / `Envv` / `WorkDir` | `[]string` / `string` | Guest command vector, `KEY=VALUE` environment overrides, and working directory. |
| `WorkspacePath` / `Mounts` | `string` / `[]gvx.Mount` | Host `/workspace` directory and additional bind (`MountBind`), volume (`MountVolume`), or `MountTmpfs` entries. |
| `NetworkMode` / `PortForwards` | `gvx.NetworkMode` / `[]gvx.PortForward` | `NetModeNAT` (with inbound TCP/UDP forwards and optional `IsolateLAN`), `NetModeWireGuard`, or `NetModeNone`. |
| `Resources` | `gvx.Resources` | `MemoryBytes` is the guest memory ceiling in bytes (enforced with `SIGKILL`). `CPUMillis` is the CPU quota in thousandths of a CPU. |
| `DisableHostLockdown` | `bool` | Skips `hostlockdown.Apply()` when set to `true`. Leave `false` in production. |

> [!CAUTION]
> Always call `sb.Close()` after `sb.Run()` returns. Omitting `sb.Close()` leaks hypervisor guest physical mappings, cached EROFS handles, open volume files, the `os.Root` workspace handle, and host sandbox resources. Defer `sb.Close()` immediately after `gvx.New()` succeeds.

1. Populate a `gvx.Config` with the execution backend, OCI image, network mode, and mounts.
2. Call `gvx.New(ctx, cfg)` to open host resources and lock down the host process.
3. Call `sb.Run(ctx)` to execute the guest binary and read its Linux exit status.

```go
package main

import (
	"context"
	"fmt"
	"os"

	"z.gfire.dev/gvx/pkg/gvx"
)

func main() {
	ctx := context.Background()
	sb, err := gvx.New(ctx, gvx.Config{
		Platform:      gvx.PlatformAuto,
		NetworkMode:   gvx.NetModeNAT,
		OCIImage:      "alpine:3.20",
		WorkspacePath: "./repo",
		Argv:          []string{"/usr/bin/git", "status"},
		Stdout:        os.Stdout,
		Stderr:        os.Stderr,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "init sandbox: %v\n", err)
		os.Exit(1)
	}
	defer sb.Close()

	exitCode, err := sb.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run sandbox: %v\n", err)
		os.Exit(1)
	}
	os.Exit(exitCode)
}
```

### 2.3 Containerd Control Shim (Procedural Module)

Build the optional `containerd-shim-gvx-v2` binary separately from `rungv`. These smoke tests need no guest image, registry, or rootfs.

> [!IMPORTANT]
> Use the shim only for control-plane experiments. It rejects workload creation and does not implement CRI.

1. Build the shim with the toolchain selected by `go.mod`.
2. Run the native control tests without an external binary override.
3. Run the isolated ShimManager smoke test on Linux.
4. Run the native rejection smoke test with a containerd `2.2.4` executable.

```sh
go build -o "$PWD/containerd-shim-gvx-v2" ./cmd/containerd-shim-gvx-v2
SHIM_BINARY="$PWD/containerd-shim-gvx-v2"

go test -count=1 -skip '^TestContainerdNativeRejection$' ./internal/gvxshim

GVX_SHIM_BINARY="$SHIM_BINARY" \
  go -C tools/shiminterop test -v -count=1 -run '^TestShimManagerInterop$' ./...

GVX_SHIM_BINARY="$SHIM_BINARY" GVX_CONTAINERD_BINARY=/bin/containerd \
  go test -v -count=1 ./internal/gvxshim -run '^TestContainerdNativeRejection$'
```

The external smoke test owns private daemon paths and never modifies host-global containerd configuration. See [`docs/architecture.md`](docs/architecture.md#43-containerd-shim-verification-reference-module) for the compatibility matrix.

---

## 3. Core Mechanics and Invariants (Descriptive Module)

`gvx` resolves six architectural differences across Linux, Windows, and macOS: virtual memory page granularity, system call interception latency, POSIX storage over NTFS and APFS, user-space networking, multi-arch OCI layer execution, and unprivileged process containment.

### 3.1 Execution Backends (`whpx`, `hvf`, and `systrap`)

Hardware backends (`whpx` and `hvf`) map guest memory at 4KB granularity through hardware page tables and exchange syscall state through a shared 4KB communication page. The user-mode `systrap` backends run guest code inside isolated stub processes and rewrite syscall instructions in place on lazy execute faults. They run on Windows and Linux. macOS uses `hvf` only.

| Backend | Host Target | Guest Page Size | Syscall & Trap Mechanism | Fixed-Address (`ET_EXEC`) Support | Register & TLS Virtualization |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`platform/whpx`** | `windows/amd64`, `windows/arm64` | `4 KiB` (4KB EPT / Stage-2 over 64KB host views) | In-partition Ring-0 `SYSCALL` (`HLT`) or EL1 `SVC #0` (`HVC #0`) stub writing to shared `CommPage` | Full native support at linked virtual addresses | Hardware vCPU state; two-tier lazy sync (`PullFullState` on clone, fault, or signal) |
| **`platform/hvf`** | `darwin/arm64` | `4 KiB` (Stage-1 `TTBR0_EL1` 4KB over Stage-2 16KB IPA) | In-guest EL1 `VBAR_EL1` `bluepill` stub spilling GPRs to shared `CommPage` before `HVC #0` | Full native support at linked virtual addresses | Dedicated locked OS thread per vCPU; syncs GPRs, `V0..V31`, and `TPIDR_EL0` |
| **`platform/systrap` (`winsystrap`)** | `windows/amd64`, `windows/arm64` | `4 KiB` (`VirtualAlloc2` placeholder views) | Lazy execute fault patches `syscall` (`jmp rel32` or `CC 90`) and `svc #0` (`B` or `brk`); fast path uses `winSysmsg`, event pairs, and a time-based spin window | Full native support via pre-reserved low window `[0x10000, 0x7FFE0000)` and high window above 16TB | `amd64`: patches `RDFSBASE`, `RDGSBASE`, and `%gs:` `MOV` to island slots; `arm64`: patches `TPIDR_EL0` reads |
| **`platform/systrap` (Upstream)** | `linux/amd64`, `linux/arm64` (`CGO_ENABLED=0`) | `4 KiB` | Upstream gVisor `sysmsg` shared memory and stub threads | Full native support | Upstream Linux register context |

The Windows `systrap` fast path serves a system call without a stop in the debug object. Each side spins for a short time before it sleeps: `64 µs` in the stub and `8 µs` in the Sentry. `GVX_SYSTRAP_SPIN_US=stub,sentry` changes both values. Each stub runs a 1 KB generated executable that the host locks against writes, deletes, and renames. The table lists medians from the hosted runners. `docs/systrap-windows.md` section 3.9 has the method and the other columns.

| Operation | `hvf` (Apple Silicon) | `whpx` (`windows-latest`) | Windows `systrap` `amd64` | Windows `systrap` `arm64` |
| :--- | ---: | ---: | ---: | ---: |
| `getpid` | `1.2 µs` | `19 µs` | `0.48 µs` | `0.99 µs` |
| Pipe round trip, 64 bytes | `12.5 µs` | `174 µs` | `18 µs` | `11 µs` |
| Futex round trip | `23 µs` | `159 µs` | `13 µs` | `8.9 µs` |
| `fork` and `wait` | `0.95 ms` | `0.84 ms` | `7.1 ms` | `14 ms` |
| `gvx.New` | `10 ms` | `17 ms` | `24 to 30 ms` | `63 to 73 ms` |

Run `GVX_E2E_BENCH=1 go test -run TestE2EMicroBench ./e2e/` to measure the active host. A `systrap` stub costs one Windows process, so `fork` is the slow operation. The whpx column runs under nested virtualization and does not predict a physical host.

### 3.2 VFS2 Storage Engines (`erofs`, `ext4lite`, `hostfs`, and `chunkcache`)

`gvx` provides specialized VFS2 filesystems for read-only container layers, high-throughput persistent volumes, and live host workspace sharing. Both `hostfs` and `ext4lite` share the 64KiB page-cache and `memmap.Mappable` implementation in `pkg/sentry/fsimpl/chunkcache`.

| Storage Engine | Mount Role | Backing Host Resource | Key Capabilities and Durability Model | Post-Lockdown Host Syscalls |
| :--- | :--- | :--- | :--- | :--- |
| **`fsimpl/erofs` & `fsimpl/overlay`** | Read-only image lower layers + writable rootfs upper layer | Pre-opened `<sha256>.erofs` files + `fsimpl/tmpfs` (or persistent upper) | Zero host extraction; maps pages directly on `whpx`/`systrap` and copies into immutable slab pages on `hvf`. | `pread64` on pre-opened read-only descriptors (`0` path walks) |
| **`fsimpl/ext4lite`** | Named volumes (`-v name:/path`, default driver, VFS type `ext4`) | Single pre-opened `<name>.ext4` file locked exclusively per sandbox | 16MiB dense block-group growth (Tiers A/B/C, up to 64TiB via `meta_bg`), JBD2 ordered metadata journal (`inode 8`), orphan list cleanup, `fsckLite` fallback, depth-0..5 extent trees, inline data (`<= 128B`), shared/in-body xattrs, unmount tail compaction, and dirty-block tracking for live migration. | `pread64`, `pwrite64`, `fsync`, `ftruncate`, `fallocate` on 1 descriptor (`UnboundFileOpenBlocked = true`) |
| **`fsimpl/hostfs` (Directory Mode)** | Live host workspace (`-workspace`, `-v /host/dir:/guest/dir`) | Pinned Go 1.25+ `*os.Root` handle and bounded parent-handle cache (256 handles, 5s TTL) | Anti-TOCTOU traversal (`FILE_OPEN_REPARSE_POINT` / `O_NOFOLLOW`), Windows open-directory rename (`winHandleRegistry`), `NameCodec` (`~gvx~` escaping and APFS NFC/NFD normalization), atomic `.gvx_meta` persistence, and host-to-guest `inotify` bridge (`ReadDirectoryChangesW`, `kqueue`, or `fstatat` poll; up to 8,192 watches). | Handle-relative `NtCreateFile` or `openat`, `renameat`, `unlinkat` |
| **`fsimpl/hostfs` (Single-File Mode)** | Single-file bind mount (`-v /host/file:/guest/file[:ro]`) | Pinned parent `*os.Root` scoped to the single target filename | Exposes only the bound file (siblings remain unreachable); tracks atomic host editor file replacement on fresh opens; keeps metadata in memory without writing `.gvx_meta`. | Handle-relative open of the single pinned filename |

### 3.3 Dual-Track Netstack and Port Forwarding (`pkg/netbackend`)

Guest applications invoke socket system calls against gVisor's pure-Go `pkg/tcpip` (Netstack). `pkg/netbackend` bridges Netstack to the host network without requiring elevated privileges or kernel TAP/TUN drivers.

| Network Mode | Flag Configuration | Interception Layer | Outbound & Inbound Data Path | Host Gateway & LAN Policy | DNS Resolution |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Track A: L4 Go `net` NAT** | `-net=nat` (default), `-p`, `-P`, `-isolate-lan` | L4 Transport (`tcp.NewForwarder`, `udp.NewForwarder`) | Dials outbound via host `net.DialContext` (IOCP / `kqueue`); pre-binds `-p` / `-P` host listeners and relays inbound traffic via `gonet.DialTCP`. | Maps `10.0.2.2` (`host.docker.internal`) to host `127.0.0.1`; `-isolate-lan` blocks RFC1918 and loopback ranges. | Built-in virtual DNS relay at `10.0.2.3:53` using pre-read host resolvers |
| **Track B: L3 WireGuard** | `-net=wg -wg-conf=FILE` | L3 Network (`channel.Endpoint` MTU 1420 to `wireguard-go`) | Encrypts raw IP packets in memory with ChaCha20-Poly1305 and sends them over one pre-opened host UDP socket. | Physically blocks all host LAN access; traffic exits exclusively to the WireGuard peer. | Built-in virtual DNS relay at `10.0.2.3:53` |
| **Isolated Loopback** | `-net=none` | Internal `lo` only | Drops all external interfaces; installs Winsock / Seatbelt / `seccomp` outbound socket blocks on the host. | Zero external or host network connectivity. | None |

### 3.4 Multi-Arch OCI Image Compiler and Store (`pkg/oci`)

Extracting Linux `.tar` layers onto Windows NTFS or case-insensitive macOS APFS breaks case-sensitive filenames, fails on reserved Windows device names (`CON`, `AUX`, `NUL`, `:`), and loses POSIX ownership and special files. `pkg/oci` compiles OCI layers directly in memory into EROFS filesystem images.

| Subsystem Stage | Implementation Mechanism | Enforced Invariant and Limit |
| :--- | :--- | :--- |
| **Reference & Auth Resolution** | `oci.ParseReference` and Docker `config.json` reader (`credHelpers`, `credsStore`, `auths`) | Obeys Docker reference grammar; invokes `docker-credential-*` helpers with a 30s timeout and 1MiB output bound. |
| **Manifest & Layer Fetch** | Multi-arch OCI Index / Docker ManifestList resolver (`linux/amd64`, `linux/arm64`) | Verifies SHA-256 digests of the manifest, config blob, and every compressed layer before commit. |
| **Decompression** | Standard `gzip` and `github.com/klauspost/compress/zstd` | Caps `zstd` window size and uncompressed output streams; rejects `xz` and `bzip2` layers. |
| **In-Memory Tar-to-EROFS** | `tar2erofs.go` streaming compiler writing `<sha256>.gvx-erofs-v3-b<block>.erofs` and `.sum` | Aligns EROFS blocks to `hostarch.PageSize` (`4096` or `16384`); translates `.wh.*` and `.wh..wh..opq` into overlay whiteouts and `trusted.overlay.opaque`. |
| **Archive Import & Export** | `rungv save` (OCI layout + Docker `manifest.json`) and `rungv load` | Writes archives atomically via temporary files; skips foreign-architecture manifests on load. |

### 3.5 Unprivileged Host Self-Lockdown (`pkg/hostlockdown`)

`pkg/gvx` opens all hypervisor handles, `systrap` stubs, `.erofs` layers, `.ext4` volumes, `/workspace` roots, and sockets before guest entry. `hostlockdown.Apply()` then locks down the host process and probes each restriction. `Apply()` returns an error if any self-probe succeeds.

| Host OS | Process Creation Containment | File System Containment | Token, Privilege & Thread Hardening | Syscall & Network Filtering |
| :--- | :--- | :--- | :--- | :--- |
| **Windows** (`lockdown_windows.go`) | Anonymous Job Object with `JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 1` and UI/clipboard limits | Restricts primary token default DACL; applies Low-Integrity ACEs to writable mounts and non-inherited `FILE_TRAVERSE` to single-file mount parents | Strips privileges in place (`SE_PRIVILEGE_REMOVED`) on Sentry and stub tokens; binds `Low` integrity deny-only impersonation token to runtime and `systrap` switch threads | Sets `DisallowWin32kSystemCalls = 1`; installs Winsock outbound connect/listen hook for `-net=none` and `-net=wg` |
| **macOS** (`lockdown_darwin.go`) | `setrlimit(RLIMIT_NPROC, 0)` and Seatbelt `(deny process-fork)` / `(deny process-exec*)` | Seatbelt `(deny default)` profile allowing file access only to bound mount paths (`subpath` for directories, `literal` for single-file mounts) | Enforces kernel-level MAC containment on the Sentry process | Blocks outbound sockets in `-net=none` and pins UDP traffic to the WireGuard peer port in `-net=wg` |
| **Linux** (`lockdown_linux.go`, `syscallfilter_linux.go`) | `PR_SET_NO_NEW_PRIVS` + `seccomp` rule returning `EPERM` on `clone`, `execve`, and `execveat` | Omits `openat` from the `seccomp` allowlist when only `ext4lite` and `tmpfs` mounts exist (`UnboundFileOpenBlocked = true`); returns `EPERM` on unbound `openat` | Synchronizes the gVisor Sentry `seccomp` BPF program across all OS threads with `SECCOMP_FILTER_FLAG_TSYNC` | Kills the process on any syscall outside the allowlist; returns `EPERM` on disallowed `socket` calls |

### 3.6 Upstream Tracking and Three-Tier Isolation

`gvx` tracks the `go` branch of `https://github.com/google/gvisor.git` (`upstream/go`) and pins the synced commit SHA in `UPSTREAM_COMMIT`. `tools/upstream` enforces package import boundaries (`boundaries.go`) and audits the upstream modification ratio on every CI run.

| Isolation Tier | File Count | Repository Paths | Upstream Merge Policy |
| :--- | ---: | :--- | :--- |
| **Tier 1: Additive Packages** | `510` | `cmd/rungv`, `cmd/containerd-shim-gvx-v2`, `internal/gvxshim`, `pkg/gvx`, `pkg/oci`, `pkg/netbackend`, `pkg/hostlockdown`, `pkg/sentry/platform/{whpx,hvf,hvcommon}`, `pkg/sentry/fsimpl/{chunkcache,hostfs,ext4lite}`, `e2e`, `tools/{upstream,shiminterop,licenses}`, `docs` | Owned exclusively by `gvx` (`0.0%` conflict rate with `upstream/go`). |
| **Tier 2: Sibling Host Files** | `142` | `*_{windows,darwin,xplat}*` files in `pkg/sync`, `pkg/memutil`, `pkg/fd`, `pkg/{erofs,fdnotifier,syserr,hostarch}`, `pkg/sentry/{kernel,mm,pgalloc,time,hostcpu}`, and `pkg/sentry/platform/systrap` | Placed beside unmodified `*_linux.go` files (`0.0%` conflict rate). |
| **Tier 3: Build-Tag & Seam Patches** | `18 / 2507` (`0.72%`) | Allowlisted pure-Go files in `tools/upstream/buildtag_allowlist.txt` and minimal seam hooks (`< 1.0%` budget ceiling) | Re-applied by `go run ./tools/upstream -mode=retag`; `624` Linux-only fence tags (`25.57%` strict count) are tracked separately. |

### 3.7 Optional Containerd Control Adapter

Runtime identity `io.containerd.gvx.v2` resolves to `containerd-shim-gvx-v2`. The adapter in `internal/gvxshim` implements the control-only G3 boundary without importing `pkg/gvx`, Sentry, or `pkg/hostlockdown`.

| Boundary | Implemented Behavior | Enforced Limit |
| :--- | :--- | :--- |
| **Bootstrap** | Emits JSON version `3` (`protocol: "ttrpc"`) after probing the detached child; keeps successful stderr empty | No binary bootstrap from containerd `2.3` |
| **Task v3 Service** | `Connect` returns the real shim PID, task PID `0`, and version `gvx-control-v1`; `Shutdown` stops the daemon | No Task v2 service or guest workloads |
| **Native Sandbox** | `CreateSandbox` attaches the caller and returns wire `Unimplemented`; `ShutdownSandbox` stops the daemon | No successful sandbox creation or CRI |
| **Executable Cleanup** | `delete` uses an independent stop endpoint, verifies generation identity, and waits for lease release | Never signals a stored PID or deletes containerd-owned bundle files |

---

## 4. Documentation Index

Read the architecture specification and agent operating manual before modifying any package.

| Document | Audience | Scope Description |
| :--- | :--- | :--- |
| [`docs/architecture.md`](docs/architecture.md) | Engineers & AI Agents | Subsystem architecture, Windows/macOS/Linux specifications, upstream sync rules, M1-M5 milestones, and shim verification. |
| [`docs/cli.md`](docs/cli.md) | Users & Engineers | Complete `rungv` command reference, `rungv run` flags, mount/volume rules, and behavioral differences from Docker. |
| [`docs/systrap-windows.md`](docs/systrap-windows.md) | Systems Engineers | Design, measurements, placeholder memory layout, fast-path islands, and limits of the Windows `systrap` engine. |
| [`docs/x-sys-unix.md`](docs/x-sys-unix.md) | Systems Engineers | The embedded copy of `golang.org/x/sys/unix`: why it exists, what it changes, and how to update it. |
| [`docs/gvxip/gvxip-001-better-posix-hostfs.md`](docs/gvxip/gvxip-001-better-posix-hostfs.md) | Systems Engineers | Specification for `hostfs` v2: pinned handle caching, `NameCodec`, single-file mounts, and host-to-guest `inotify`. |
| [`docs/gvxip/gvxip-002-ext4lite-volume-engine.md`](docs/gvxip/gvxip-002-ext4lite-volume-engine.md) | Systems Engineers | Specification for `ext4lite`: 16MiB dense block groups, JBD2 ordered journaling, unmount compaction, and `fsckLite`. |
| [`docs/gvxip/gvxip-003-backend-perf-and-compat.md`](docs/gvxip/gvxip-003-backend-perf-and-compat.md) | Systems Engineers | Cross-backend performance optimizations, large-page mapping units, and `ET_EXEC` compatibility specifications. |
| [`AGENTS.md`](AGENTS.md) | AI Coding Agents & Reviewers | Mandatory startup protocol, ASD-STE100 writing gates, package import boundaries, and verification commands. |
| [`cmd/rungv/licenses/THIRD_PARTY_LICENSES.txt`](cmd/rungv/licenses/THIRD_PARTY_LICENSES.txt) | Legal Reviewers & Users | License texts and notices of every component in the `rungv` binary, as printed by `rungv license`. |

---

## 5. Build, Upstream Sync, and Verification (Procedural Module)

`gvx` builds with the standard Go 1.27+ toolchain (`go build` and `go test`) across Windows, macOS, and Linux without Bazel.

### 5.1 Build and Verification Steps

Run these steps locally before pushing changes.

> [!IMPORTANT]
> Run `go test` through `scripts/codesign-exec.sh` on macOS. An unsigned test binary lacks the hypervisor entitlement and skips network and hypervisor tests.

1. Format all source files with `go fmt ./...`.
2. Run the native test suite with `scripts/codesign-exec.sh` on macOS.
3. Cross-compile all packages across `darwin/arm64`, `windows/amd64`, `windows/arm64`, `linux/amd64`, and `linux/arm64`.
4. Run the upstream diff audit tool to verify that charged upstream modifications remain below `1.0%`.

```bash
# 1. Format and run native unit and e2e tests on macOS arm64
go fmt ./...
go test -race -exec "$PWD/scripts/codesign-exec.sh" ./...

# 2. Cross-compile across all five supported targets
GOOS=darwin  GOARCH=arm64 go build ./...
GOOS=windows GOARCH=amd64 go build ./...
GOOS=windows GOARCH=arm64 go build ./...
GOOS=linux   GOARCH=amd64 go build ./...
GOOS=linux   GOARCH=arm64 go build ./...

# 3. Verify the upstream diff budget (< 1.0% charged upstream files)
go run ./tools/upstream -mode=audit -max-ratio=0.01
```

GitHub Actions executes six verification jobs on every push in `.github/workflows/ci.yml`. The workflow `.github/workflows/pjdfstest.yml` runs the POSIX conformance suite when `ext4lite` changes. The workflow `.github/workflows/e2e-images.yml` runs live registry image gates weekly. The workflow `.github/workflows/diagnose.yml` runs a chosen test selection on a chosen runner by hand.

| CI Job (`.github/workflows/ci.yml`) | Runner | Verification Scope |
| :--- | :--- | :--- |
| `build, vet, and audit` | `ubuntu-24.04` | Verifies `gofmt`, compiles all five targets, runs `go vet` (including the `systrap` package on the three non-Linux targets), and audits the `< 1.0%` upstream diff budget. |
| `test linux/amd64` | `ubuntu-24.04` | Runs `go test -race` on owned packages and `CGO_ENABLED=0` `e2e`, `pkg/gvx`, and `pkg/hostlockdown` suites with `seccomp` lockdown enabled. |
| `test linux/arm64` | `ubuntu-24.04-arm` | Runs `go test -race` on owned packages and `CGO_ENABLED=0` `e2e`, `pkg/gvx`, and `pkg/hostlockdown` suites on ARM64 Linux. |
| `test darwin/arm64` | `macos-15` | Runs signed package tests. The hosted runner has no hypervisor, so `GVX_ALLOW_NO_HYPERVISOR=1` skips the guest and hypervisor tests. |
| `test windows/amd64` | `windows-latest` | Runs owned package tests, `winsystrap` tests, the `systrap` end-to-end gates, `hostlockdown` suites, and `whpx` guest execution gates. |
| `test windows/arm64` | `windows-11-arm` | Runs `internal/gvxshim`, `winsystrap`, and the `systrap` end-to-end gates. The runner has no hypervisor, so `systrap` runs every guest. |

### 5.2 Implementation Roadmap (`M1` to `M5`)

This table maps each completed milestone to its deliverables and verification gate across Windows, macOS, and Linux.

| Phase | Milestone | Deliverables and Verification Gate |
| :--- | :--- | :--- |
| **M1** | **Host Primitives & Pure-Go Sentry Compile** | `pkg/sync`, `pkg/memutil`, `pkg/fd`, `pgalloc`, `time`, `hostcpu`, `tools/upstream`, and `pkg/sentry/kernel` compile and pass unit tests across all five targets. |
| **M2** | **WHPX & HVF Engines & Static ELF Execution** | `platform/whpx` (`windows/amd64`, `windows/arm64`), `platform/hvf` (`darwin/arm64`), and `platform/hvcommon` boot static `busybox` (`PID 1`) and execute shell commands. |
| **M3** | **Dynamic Linking, Dual-Track Netstack & OCI Runner** | `clone`, `futex`, signals, TLS, VDSO, `pkg/netbackend` (`-net=nat` & `-net=wg`), and `pkg/oci` boot `alpine:3.20`, `nginx:alpine`, `python:3.12-alpine`, and `node:22-alpine`. |
| **M4** | **`hostfs`, `ext4lite`, `chunkcache` & Self-Lockdown** | `fsimpl/hostfs` v2, `fsimpl/ext4lite` (JBD2 journaled single-file `ext4` volumes), `fsimpl/chunkcache`, and `pkg/hostlockdown` pass POSIX durability, crash recovery, and containment gates. |
| **M5** | **`systrap` Fallback Engine (`winsystrap` and upstream Linux)** | `platform/systrap` executes static (`ET_EXEC`) and dynamic (`ET_DYN`) ELF64 workloads via trampoline islands and `winSysmsg` stubs on `windows/amd64` and `windows/arm64`, and through the upstream platform on Linux. The `darwin/arm64` engine was removed, and macOS runs on `hvf`. |

---

## License

`gvx` is licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the full license text.

### Third-party and upstream licenses

The `rungv` binary contains the components below. The generator `tools/licenses` collects their licenses, and the table comes from the same data.

- `gvx` is licensed under the Apache License, Version 2.0.
- The code derived from [google/gvisor](https://github.com/google/gvisor) is licensed under the Apache License, Version 2.0, Copyright The gVisor Authors. The pinned upstream commit is in [`UPSTREAM_COMMIT`](UPSTREAM_COMMIT).
- The Go standard library is licensed under the BSD-3-Clause license, Copyright The Go Authors.
- The module embeds a modified copy of the `unix` package of `golang.org/x/sys` in `third_party/x_sys/unix`. The copy stays under the BSD-3-Clause license of that module, whose text is in `third_party/x_sys/LICENSE`.

The third-party Go modules that `rungv` links are listed by SPDX identifier.

| SPDX identifier | Third-party modules |
| :--- | :--- |
| `Apache-2.0` | `github.com/google/btree` v1.1.2 |
| `Apache-2.0 AND BSD-3-Clause AND MIT` | `github.com/klauspost/compress` v1.18.0 |
| `BSD-3-Clause` | `golang.org/x/arch` v0.32.0, `golang.org/x/crypto` v0.57.0, `golang.org/x/exp` v0.0.0-20250711185948-6ae5c78190dc, `golang.org/x/mod` v0.41.0, `golang.org/x/net` v0.60.0, `golang.org/x/sync` v0.23.0, `golang.org/x/sys` v0.48.0, `golang.org/x/text` v0.42.0, `golang.org/x/time` v0.15.0, `google.golang.org/protobuf` v1.36.11 |
| `MIT` | `golang.zx2c4.com/wintun` v0.0.0-20230126152724-0fa3db229ce2, `golang.zx2c4.com/wireguard` v0.0.0-20261006164505-2631ce99a06f |

`rungv license` prints every license text of the binary, and `rungv license -list` prints the component list.
