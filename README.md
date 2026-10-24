# `gvx`

`gvx` ports Google's gVisor user-space Linux kernel (Sentry) to 64-bit Windows (`windows/amd64`, `windows/arm64`) and macOS (`darwin/arm64`, `darwin/amd64`) as co-equal Priority-0 targets. It also supports Linux (`linux/amd64`, `linux/arm64`) officially. It executes unmodified Linux ELF64 binaries and multi-arch OCI container images inside one unprivileged host process via the `rungv` CLI or `pkg/gvx` SDK. Callers get isolated Linux execution on Windows and Mac with millisecond startup, no Linux virtual machine, no kernel drivers, and no administrator or `root` privileges.

---

## 1. Architecture and Capability Overview

Running Linux binaries or container images on Windows and macOS usually forces a heavy compromise. WSL2, Docker Desktop, and Apple `Virtualization.framework` boot a full Linux virtual machine that consumes hundreds of megabytes of RAM and requires background virtualization daemons. QEMU emulates an entire motherboard and CPU in software.

`gvx` takes a direct user-space approach. About 65% of upstream `google/gvisor` (`pkg/sentry/kernel`, `pkg/sentry/arch`, `pkg/ring0`, `pkg/sentry/vfs`, `pkg/sentry/fsimpl/{erofs,overlay,tmpfs}`, and `pkg/tcpip`) is OS-agnostic Go code supporting both `amd64` and `arm64`. `tools/upstream` expands those build constraints to `linux || windows || darwin` automatically. Thin host packages bind to Windows (`WinHvPlatform.dll`, `WaitOnAddress`, `MapViewOfFile3`) and macOS (`Hypervisor.framework`, `__ulock_wait`, `mach_vm_remap`) primitives.

| Runtime Model | Host Targets | Cold Start | Memory Overhead | Admin / `sudo` Required | 4KB `mmap(MAP_FIXED)` | Direct OCI Image Run |
| :--- | :--- | ---: | ---: | :--- | :--- | :--- |
| **`gvx` / `rungv` (`whpx` / `hvf`)** | Windows & macOS (`amd64`, `arm64`) | `~20 ms` | `~30 MiB` | No (Low Integrity / Seatbelt) | Hardware 4KB EPT / Stage-1 MMU | Yes (In-Memory Tar-to-EROFS) |
| **`gvx` / `rungv` (`systrap` Engine, M5)** | macOS `arm64` (`pagesize_16k` build); unavailable on Windows and macOS `amd64` | `~180 ms` | `~31 MiB` (Sentry only) | No (Seatbelt) | 16KB host pages, native stub tasks | Yes (In-Memory Tar-to-EROFS) |
| **WSL2 / Docker Desktop** | Windows & macOS | `800-2500 ms` | `> 512 MiB` | Yes (VM Daemon / Services) | Guest Linux Kernel MMU | Requires VM Daemon |
| **QEMU (`tcg` Full System)** | Windows & macOS | `1500-4000 ms` | `> 256 MiB` | No | SoftMMU Emulation | Requires Disk Image Build |

The `gvx` rows come from `rungv run` on an Apple M1 with macOS 26 and the cached `busybox:1.36.1-musl` image. The registry was offline. A reachable registry adds about one second for the tag check. Only `hvf` and `systrap` on `darwin/arm64` are executed in this repository.

```mermaid
flowchart LR
    OCI["Unmodified OCI Image (amd64 / arm64)"] --> Platform["Execution Backend (whpx, hvf, or systrap)"]
    Platform -->|"Shared 4KB Comm Page or sysmsg Stub"| Sentry["gVisor Sentry Kernel (Pure Go on Windows & macOS)"]
    Sentry --> VFS["VFS2: overlay (tmpfs + EROFS Layers) & hostfs (/workspace)"]
    Sentry --> Netstack["Netstack (pkg/tcpip eth0 & lo)"]
    Netstack <-->|"Track A (-net=nat -p)"| NAT["L4 Go net NAT & Port Forwarder"]
    Netstack <-->|"Track B (-net=wg)"| WG["L3 In-Memory wireguard-go Tunnel"]
```

---

## 2. Quickstart (Procedural Module)

Run an unmodified OCI image or ELF binary from the CLI via `cmd/rungv`, or embed a sandbox in Go via `pkg/gvx`.

### 2.1 CLI Execution on Windows and macOS (`cmd/rungv`)

Use these steps to compile `rungv` and run an unmodified OCI image on Windows or macOS:

> [!IMPORTANT]
> On Windows, enable the "Windows Hypervisor Platform" feature for `whpx`. On Linux, build with `CGO_ENABLED=0`. The upstream systrap platform hangs in a cgo build. On macOS, sign the binary with the `com.apple.security.hypervisor` entitlement (`entitlements.plist`) for `hvf`. The `systrap` backend on macOS `arm64` needs the build tag `pagesize_16k`.

1. Build `rungv` with the standard Go 1.25+ toolchain (and apply ad-hoc signing on macOS for `hvf`).
2. Run an unmodified OCI image (`nginx:alpine`) with `-p 8080:80` port forwarding and `-net=nat` networking.
3. Pass `-net=wg` with a WireGuard configuration file when strict L3 host LAN isolation is required.
4. Select the guest architecture with `-arch`. The hardware backends accept only the host architecture.
5. Run `rungv stub` to probe the `systrap` engine. The command exits with status 1 and prints the typed error when the engine is unavailable.
6. Use the Docker flags `-e`, `-u`, `-v`, `-m`, `--cpus`, `-P`, `--read-only`, and `--tmpfs`, and the image commands `pull`, `images`, `inspect`, `tag`, `rmi`, `save`, `load`, `login`, and `logout`. The reference [`docs/cli.md`](docs/cli.md) lists every flag and every difference from Docker.

```bash
# Build on macOS (Apple Silicon arm64 or Intel amd64) and apply free ad-hoc hypervisor signature
go build -o rungv ./cmd/rungv
codesign --sign - --entitlements entitlements.plist --force ./rungv

# Or build on Windows (amd64 or arm64)
go build -o rungv.exe ./cmd/rungv

# Or build on Linux (amd64 or arm64); the guest runs on the upstream systrap platform
CGO_ENABLED=0 go build -o rungv ./cmd/rungv

# Track A: Zero-config L4 NAT mode with -p port forwarding and OCI Tar-to-EROFS caching
./rungv run -net=nat -p=8080:80 -image=nginx:alpine -workspace=./my-project

# Track B: Cryptographic L3 WireGuard mode (zero host LAN access, no WinTun.dll or /dev/tun required)
./rungv run -net=wg -wg-conf=./sandbox-wg.conf -image=python:3.12-alpine -workspace=./my-project \
  -- python3 -c "import urllib.request; print(urllib.request.urlopen('https://example.com').status)"

# systrap engine on macOS arm64 (needs the pagesize_16k build tag)
go build -tags pagesize_16k -o rungv ./cmd/rungv
codesign --sign - --entitlements entitlements.plist --force ./rungv
./rungv stub
./rungv run -platform=systrap -image=alpine:3.20 -- uname -m
```

`rungv run` locks down the host process before guest entry. Pass `-lockdown=false` only for debugging. The command then prints a warning.

### 2.2 Embeddable Go SDK (`pkg/gvx`)

Embed `gvx` inside a Windows or macOS host binary to run sandboxed Linux toolchains without external daemons:

> [!CAUTION]
> Always call `sb.Close()` after `sb.Run()` returns. Omitting `sb.Close()` leaks hypervisor guest physical mappings, cached EROFS handles, the `os.Root` workspace handle, and host sandbox resources. Defer `sb.Close()` immediately after `gvx.New()` succeeds.

1. Construct a `gvx.Config` specifying the execution backend, OCI image or rootfs path, network mode, and workspace path.
2. Call `gvx.New(ctx, cfg)` to compile or open EROFS layers, initialize networking, and apply self-lockdown (`pkg/hostlockdown`). Set `Config.DisableHostLockdown` only for debugging.
3. Call `sb.Run(ctx)` to execute the guest binary and read its Linux exit code.

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
		Platform:      gvx.PlatformAuto, // Tries whpx or hvf first, then systrap; reports both errors if all fail
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

Build the optional `containerd-shim-gvx-v2` command separately from `rungv`. These smoke tests need no guest image, registry, or rootfs.

> [!IMPORTANT]
> Use the shim only for control-plane experiments. It rejects workload creation and does not implement CRI.

1. Build the shim with the toolchain selected by `go.mod`.
2. Run the native control tests without an external binary override.
3. Run the isolated ShimManager smoke on Linux.
4. Run the native rejection smoke with a containerd `2.2.4` executable.

```sh
go build -o "$PWD/containerd-shim-gvx-v2" ./cmd/containerd-shim-gvx-v2
SHIM_BINARY="$PWD/containerd-shim-gvx-v2"

go test -count=1 -skip '^TestContainerdNativeRejection$' ./internal/gvxshim

GVX_SHIM_BINARY="$SHIM_BINARY" \
  go -C tools/shiminterop test -v -count=1 -run '^TestShimManagerInterop$' ./...

GVX_SHIM_BINARY="$SHIM_BINARY" GVX_CONTAINERD_BINARY=/bin/containerd \
  go test -v -count=1 ./internal/gvxshim -run '^TestContainerdNativeRejection$'
```

The external smoke owns private daemon paths and never changes host-global containerd configuration. The architecture guide records the [compatibility evidence](docs/architecture.md#43-containerd-shim-verification-reference-module).

---

## 3. Core Mechanics and Invariants (Descriptive Module)

`gvx` resolves six architectural differences between Linux, Windows, and macOS: 4KB vs. 64KB/16KB virtual memory alignment, system call interception latency, dual-track user-space networking, NTFS/APFS-safe OCI image execution, POSIX filesystem semantics, and unprivileged process lockdown.

### 3.1 Hardware and `systrap` Execution Backends (`whpx`, `hvf`, and `systrap`)

Windows enforces a 64KB alignment granularity on `VirtualAlloc(..., MEM_RESERVE, ...)`, while Apple Silicon macOS enforces a 16KB host page size (`vm_page_size = 16384`). Linux ELF loaders require 4KB alignment for `mmap(MAP_FIXED)`. The hardware backends keep 4KB guest pages. The `systrap` backend on macOS `arm64` cannot, so it needs 16KB guest pages.

`pkg/sentry/platform/whpx` (Windows `amd64`/`arm64`) and `pkg/sentry/platform/hvf` (macOS `arm64`/`amd64`) map guest pages from `pgalloc.MemoryFile` through `WHvMapGpaRange` and `hv_vm_map`. The EROFS image uses a read-only file descriptor, and `hv_vm_map` rejects it. `hvf` copies those pages into immutable slab pages. Stage-1 4KB translation granules (`arm64`) and Extended Page Tables (`amd64`) enforce `R/W/X` at 4KB boundaries.

Go generators emit the guest stubs for the Ring-0/EL1 vector and the fast-path syscall exit (`bluepill_*.go` in `hvf`, `stubgen_*.go` in `whpx`). `arch.Context64` holds the general and FP registers, and every `Switch` loads and stores them. `Hypervisor.framework` ties a vCPU to its host thread, so `hvf` runs each vCPU on a dedicated locked worker thread. `hvf` on `darwin/arm64` is the only hardware backend that this repository executes. `whpx` and `hvf` on `darwin/amd64` are compile-checked only.

`pkg/sentry/platform/systrap` (Fallback, Milestone M5) runs guest code natively in forked stub tasks. The Sentry shares `sysmsg` memory with each stub through `mach_vm_remap` and hands control over with `__ulock_wait`. A lazy page-trap patcher rewrites `svc #0` to a branch into a trampoline slot. It also rewrites `TPIDR_EL0`, `CTR_EL0`, and `x18` accesses inside ELF code sections. The Seatbelt profile of each stub denies every host system call that the stub does not need, so an unpatched `svc` kills the stub.

`systrap` runs on macOS `arm64` and on Windows. The macOS engine needs `-tags pagesize_16k`. Without the tag, `systrap.New()` returns `*ErrUnsupportedPageSize`. Guest addresses start above the permanent host reservations that the Sentry reads from the template stub (448GB on the test host). The macOS engine cannot load an `ET_EXEC` image, because every `arm64` task has a 4GB `PAGEZERO`. Run such an image with `-platform=hvf`. The Windows engine runs on `amd64` and `arm64`, needs no hypervisor, and puts the guest above 16TB. It also holds the range from `0x10000` to `0x7FFE0000`, so an `ET_EXEC` image runs at the address that it links to. [`docs/systrap-windows.md`](docs/systrap-windows.md) records its measurements, design, and limits. The engine is not a syscall sandbox on Windows. On macOS `amd64`, the project dropped the Rosetta 2 engine. A syscall-number Seatbelt filter on a translated process panicked the host kernel. A stub without the filter would weaken isolation. `-platform=auto` never falls back to a software backend. `gvx` contains no instruction interpreter and no JIT.

### 3.2 Dual-Track Netstack and Port Forwarding (`pkg/netbackend`)

Guest applications (`nginx`, `postgres`, `git`, `curl`, `omp`, `herdr`) invoke `socket()`, `connect()`, `bind()`, and `epoll_wait()` against gVisor's pure-Go `pkg/tcpip` (Netstack). Netstack implements a complete Linux `eth0` and `lo` TCP/UDP stack in memory. `pkg/netbackend` runs identically on Windows and macOS using two selectable modes.

In Track A (`-net=nat`, default), `tcp.NewForwarder` and `udp.NewForwarder` dial outbound streams through Go's `net.DialContext` (backed by Windows IOCP and macOS `kqueue`). Outbound connections to `10.0.2.2` (`host.docker.internal`) route to the host's `127.0.0.1`, while inbound `-p hostPort:guestPort` listeners forward host traffic into Netstack via `gonet.DialTCP`. Callers can attach host-side L4/L7 proxies for LLM API key injection or pass `-isolate-lan` when untrusted workloads require RFC1918 blocking.

In Track B (`-net=wg`), a Netstack `channel.Endpoint` pipes raw L3 IP packets directly in memory into `golang.zx2c4.com/wireguard/device` without `WinTun.dll` or `/dev/tun`. `wireguard-go` encrypts every packet in memory and transmits it through one pre-opened host UDP socket, physically blocking all access to the host LAN.

### 3.3 Unmodified Multi-Arch OCI Image Runner (`pkg/oci`)

Extracting Linux `.tar.gz` layers onto NTFS or APFS breaks case-sensitive files, fails on reserved names (`CON`, `AUX`, `NUL`, `:`), and loses POSIX modes and symlinks. `pkg/oci` resolves the `linux/amd64` or `linux/arm64` manifest and streams image layers in memory through `tar2erofs.go`. It writes content-addressed `<layer-sha256>.gvx-erofs-v3-b<block>.erofs` files into the host cache directory. `<block>` is the EROFS block size, which equals `hostarch.PageSize` (4096 by default, 16384 with `pagesize_16k`).

The runner verifies every layer digest and manifest digest. `github.com/klauspost/compress/zstd` decodes zstd layers under bounded window and output limits. Whiteouts become overlay whiteout nodes, and opaque directories carry the `trusted.overlay.opaque` xattr. At boot, Sentry's pure-Go `fsimpl/overlay` mounts those read-only `.erofs` files as lower layers and mounts `fsimpl/tmpfs` as the writable upper layer. Docker credential helpers and `xz` or `bzip2` layers are not supported.

### 3.4 Anti-TOCTOU Host Mounts (`pkg/sentry/fsimpl/hostfs`)

Instead of running an external file-server process (`lisafs`), `fsimpl/hostfs` mounts the host `/workspace` directory directly inside Sentry VFS2. `hostfs` anchors `/workspace` using Go 1.25+ `os.OpenRoot(hostWorkspacePath)` backed by `NtCreateFile` (`FILE_OPEN_REPARSE_POINT` on Windows) and `openat` (`O_NOFOLLOW | O_SYMLINK` on macOS).

On Windows, every open call sets `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE` and executes atomic renames on open files via `SetFileInformationByHandle(FileRenameInfoEx)` with `FILE_RENAME_FLAG_POSIX_SEMANTICS`. On macOS, `hostfs` uses native `renameat` and `unlinkat`. On both platforms, an in-memory xattr table stores POSIX mode bits (`0755`), `uid/gid`, and intra-workspace symlinks, persisting them atomically to `.gvx_meta`.

### 3.5 Unprivileged Self-Lockdown (`pkg/hostlockdown`)

After opening the hypervisor handle, cached `.erofs` layers, `-p` / `-net=wg` sockets, and `/workspace` `os.Root`, `pkg/hostlockdown` locks down the host process before guest entry. `rungv` and `pkg/gvx` enable the lockdown by default. `hostlockdown.Apply` returns an error when a self-probe shows that the lockdown did not take effect.

On Windows (`lockdown_windows.go`), it removes privileges in place via `AdjustTokenPrivileges(SE_PRIVILEGE_REMOVED)` and lowers the primary token to `Low Integrity`. It also binds a `SE_GROUP_USE_FOR_DENY_ONLY` token to vCPU threads, enforces `JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 1`, and sets `DisallowWin32kSystemCalls = 1`. These Windows steps are compile-checked only.

On macOS (`lockdown_darwin.go`), it sets `RLIMIT_NPROC = 0` and activates a `(deny default)` Seatbelt profile through `sandbox_init`. The profile denies process creation and new host file opens. After `Apply`, `getaddrinfo` and reads of `/etc/resolv.conf` fail, so `pkg/netbackend` reads the DNS resolvers before the lockdown.

On Linux (`lockdown_linux.go` and `pkg/gvx/syscallfilter_linux.go`), it installs the seccomp allowlist of the gVisor Sentry on every thread. A call outside the allowlist kills the process. The calls `execve`, `clone`, `openat`, and `socket` return `EPERM` instead, so that code in the embedding process sees an error. Seccomp reads no path. With a workspace, an `openat` relative to a directory descriptor can still open an absolute path, and `UnboundFileOpenBlocked` reports false. gVisor closes this gap with a mount namespace and `chroot`, which a library cannot create without privilege. Build with `CGO_ENABLED=0`. The upstream `systrap` platform hangs at startup in a cgo build, and `New` returns `ErrPlatformUnavailable`.

### 3.6 Upstream Tracking and Three-Tier Isolation

`gvx` tracks the `go` branch of `https://github.com/google/gvisor.git` (`upstream/go`) and pins the synced commit SHA in `UPSTREAM_COMMIT`. All Windows and macOS packages live either in dedicated directories (`cmd/rungv`, `pkg/gvx`, `pkg/oci`, `pkg/netbackend`, `pkg/sentry/platform/{whpx,hvf}`, `pkg/sentry/fsimpl/hostfs`, `pkg/hostlockdown`) or in `*_{windows,darwin,xplat}*` sibling files (`pkg/sentry/platform/systrap`).

`tools/upstream` widens `//go:build linux` tags on allowlisted Sentry files after each `git merge upstream/go`, and it fences Linux-only files from the new targets. `-mode=audit` compares the tree with the pinned upstream archive and checks the SPEC import boundaries.

The merged-tree audit at `0d0ef55` charged 16 of 2485 files (0.64%) against the `< 0.7%` ceiling. The charged share excludes Linux fences; the audit also reports a strict count that includes them.

### 3.7 Optional Containerd Control Adapter

Runtime identity `io.containerd.gvx.v2` resolves to `containerd-shim-gvx-v2`. The adapter implements control-only G3 without changing the M1 through M5 guest runtime.

| Boundary | Implemented behavior | Limit |
| :--- | :--- | :--- |
| Bootstrap | JSON version `3`, protocol `ttrpc`, separate serving child, empty successful stderr | No binary bootstrap from containerd `2.3` |
| Task v3 | `Connect` returns the real shim PID, task PID `0`, and version `gvx-control-v1`; `Shutdown` stops the daemon | No Task v2 service or workloads |
| Native Sandbox | `CreateSandbox` attaches the caller, then returns `Unimplemented`; `ShutdownSandbox` stops the daemon | No successful sandbox creation or CRI |
| Executable cleanup | `delete` uses an independent stop endpoint and waits for lease release | No termination from a stored PID |

Every instance belongs to one owner, containerd address, namespace, ID, and canonical bundle. Delete validates that identity and the admitted generation before removing owned resources.

The caller supplies `-namespace`, `-id`, and a local `-address` to `start`. The bundle defaults to the current directory; `delete` requires an explicit `-bundle`.
The positive `-timeout` defaults to five seconds and bounds startup, handoff, cleanup, and shutdown drain. An unattached child exits when handoff expires.
Nonempty runtime options remain unsupported. The standalone SDK needs no daemon and retains its existing lockdown behavior.

Delete preserves containerd-owned bundle entries and stable lock files. Conflicting ownership or an unresponsive child produces an error rather than destructive cleanup.
The isolated `tools/shiminterop` module retains the SDK's compatible telemetry dependencies. It does not downgrade root dependencies or fork SDK code.
The audit charges 24 of 2485 upstream files (0.97%) against the `< 1.0%` ceiling. It reports 596 Linux fences separately. Counted together with the fences, the modified share is 25%, so the strict reading of the ceiling is not met.

---

## 4. Documentation Index

Read the architecture plan and agent operating manual before modifying any package.

| Document | Audience | Scope Description |
| :--- | :--- | :--- |
| [`docs/architecture.md`](docs/architecture.md) | Engineers & AI Agents | Subsystem design, Windows/macOS `amd64`/`arm64` specs, upstream sync, M1-M5 milestones, and the optional containerd control adapter. |
| [`docs/cli.md`](docs/cli.md) | Users & Engineers | Every `rungv` command, every flag of `rungv run`, the run rules, and the differences from Docker. |
| [`AGENTS.md`](AGENTS.md) | AI Coding Agents & Reviewers | Mandatory startup protocol, ASD-STE100 rules, package import boundaries, and verification gates. |

---

## 5. Build, Upstream Sync, and Verification (Procedural Module)

`gvx` builds with the standard Go 1.25+ toolchain (`go build` and `go test`) across Windows and macOS without requiring Bazel.

### 5.1 Build and Verification Steps

1. Cross-compile all packages across the four Priority-0 targets (`windows/amd64`, `windows/arm64`, `darwin/arm64`, `darwin/amd64`).
2. Run the unit test suite with the signing wrapper. The wrapper gives test binaries the `hvf` entitlement.
3. Audit the upstream diff against `UPSTREAM_COMMIT` to verify the `< 1.0%` modification ceiling.

```bash
# Compile across all four Priority-0 targets
GOOS=windows GOARCH=amd64 go build ./...
GOOS=windows GOARCH=arm64 go build ./...
GOOS=darwin  GOARCH=arm64 go build ./...
GOOS=darwin  GOARCH=amd64 go build ./...

# Run the tests and the upstream diff audit
go test -race -exec "$PWD/scripts/codesign-exec.sh" ./...
go run ./tools/upstream -mode=audit -max-ratio=0.01

# Run the systrap engine tests on macOS arm64
go test -race -tags pagesize_16k -exec "$PWD/scripts/codesign-exec.sh" ./pkg/sentry/platform/systrap/...
```

GitHub Actions verifies every change. The workflow `ci.yml` builds and vets all six targets, audits the upstream diff, and tests `linux/amd64`, `linux/arm64`, `darwin/arm64`, and `windows/amd64`. A hosted macOS runner has no hypervisor, so it runs the `systrap` suites with `-tags pagesize_16k`. The workflow `e2e-images.yml` pulls real images once a week.

### 5.2 Implementation Roadmap (`M1` to `M5`)

This table maps each implementation milestone to its deliverables and verification gate across Windows and macOS.

| Phase | Milestone | Target Workload and Verification Gate |
| :--- | :--- | :--- |
| **M1** | **Host Primitives & Pure-Go Sentry Compile** | `pkg/sync`, `pkg/memutil`, `pkg/fd`, `pgalloc`, `time`, `hostcpu`, `tools/upstream`, and `pkg/sentry/kernel` compile on `windows/{amd64,arm64}` and `darwin/{arm64,amd64}`. |
| **M2** | **WHPX & HVF Engines & Static ELF Execution** | Boot static `busybox` (`PID 1`) via `platform/whpx` (Windows) and `platform/hvf` (macOS) on `amd64` and `arm64` and reach an interactive `busybox ash` prompt. |
| **M3** | **Dynamic Linking, Dual-Track Netstack & OCI Runner** | Implement `clone`, `futex`, signals, TLS (`ARCH_SET_FS` & `TPIDR_EL0`), VDSO, `pkg/netbackend` (`-net=nat -p` & `-net=wg`), and `pkg/oci`. Boot `alpine:3.20` and `nginx:alpine`. |
| **M4** | **`hostfs` VFS2 Driver & Self-Lockdown** | Pass POSIX rename and unlink tests (`git rebase`, `bun install`) on `/workspace` and verify `pkg/hostlockdown` blocks child process spawning on Windows and macOS. |
| **M5** | **Unified `systrap` Fallback Engine (`darwinsystrap` and `winsystrap`)** | macOS: lazy page-trap `arm64asm` syscall patcher, trampoline islands, and `sysmsg` stub subprocesses. Windows: stub host, debug object, placeholder window, and the `x86asm` and `brk` patchers. Status: macOS `arm64` runs real guests and needs `pagesize_16k`. Windows `amd64` and `arm64` run real guests. The Rosetta 2 and Prism cross-arch engines are dropped. |

---

## License

`gvx` is licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the full license text.
