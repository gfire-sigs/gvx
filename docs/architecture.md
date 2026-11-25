# System Architecture of `gvx`

`gvx` ports Google's `gvisor` user-space Linux kernel (`Sentry` and `Netstack`) to Windows, macOS, Linux, and Android while tracking upstream continuously. Without booting a Linux VM, `rungvx` and `pkg/gvx` run unmodified ELF64 binaries and OCI containers inside one unprivileged process.

Host-specific code sits in isolated packages and OS-suffixed sibling files rather than inside core gVisor trees. Hardware virtualization (`whpx`, `hvf`), `systrap` stubs, EROFS layer compilation, pinned host mounts, and OS lockdown keep upstream overlap below 5.0%.

This document defines the supported targets, package import boundaries, cross-cutting kernel contracts, and verification tooling across `main`.

---

## 1. Executive Summary and System Scope

This section states the architectural contracts, supported host matrix, and deliverable boundaries that govern the system.

| Architectural Property | Design Contract | Verification Boundary |
| :--- | :--- | :--- |
| **Multi-OS, Multi-Arch Hosts** | Supports `windows/{amd64,arm64}`, `darwin/arm64`, `linux/{amd64,arm64}`, and `android/arm64`. | Executes matching-architecture `linux/amd64` and `linux/arm64` ELF64 workloads across hosts. |
| **Zero Runtime Elevation** | Runs under a standard user account and confines its host process before guest entry. | Needs no `sudo`, no UAC prompt, no kernel driver, and no daemon. |
| **Hardware 4 KiB Paging** | Runs guest code via `WinHvPlatform.dll` and `Hypervisor.framework` with 4 KiB guest pages. | Bypasses Windows 64 KiB `VirtualAlloc` alignment and Apple Silicon 16 KiB host pages. |
| **Stub Execution (`systrap`)** | Runs `seccomp`-trapped `systrap` on Linux/Android, and opt-in binary rewriting (`winsystrap`) on Windows. | Executes ELF64 binaries and JIT runtimes (V8, HotSpot) without hypervisor APIs. |
| **Driverless Networking** | Connects Netstack to Go `net` NAT (`-net=nat`) or an in-memory `wireguard-go` tunnel (`-net=wg`). | Runs `docker:dind`, single-node and multi-node `k3s`, Flannel, and Calico VXLAN. |
| **Direct OCI Compilation** | Compiles `.tar.gz`/`.tar.zst` layers into cached read-only EROFS files under `tmpfs` or `ext4lite`. | Runs unmodified images without unpacking Linux metadata onto NTFS or APFS. |
| **Lockdown-Safe C/R** | Pre-opens bundles and `gvx-ctrl/2` listeners before `hostlockdown.Apply()`, validating untrusted manifests. | Restores tasks, memory, `hostfs`, `ext4lite`, and netns under containment. |
| **Upstream Isolation** | Separates host logic into Tier 1 packages, Tier 2 siblings, and isolated `ext/`. | Enforces a `< 4.5%` CI diff gate; builds pure Go with Go 1.27.4+ without Bazel. |

![gvx Subsystem Architecture Overview](assets/arch-overview.svg)

### 1.1 Supported Host Targets

Hardware virtualization (`whpx` and `hvf`) is the default backend on Windows and macOS. On Windows, `--backend=auto` fails closed without `whpx` unless `-allow-unconfined-systrap` opts into `systrap`. Untrusted Windows guests require `whpx`; Linux and Android select `systrap`, and guest architectures must match the host CPU.

`darwinsystrap` was removed because macOS forces 16 KiB user mappings and reserves a 4 GiB `PAGEZERO`, blocking 4 KiB segments and non-PIE binaries. Intel Macs (`darwin/amd64`) and Rosetta 2 are unsupported.

| Host Target | Primary Backend | Fallback Backend | Host Page Granularity | Platform Requirements |
| :--- | :--- | :--- | :--- | :--- |
| `windows/amd64` | `whpx` (`WinHvPlatform.dll`, 4 KiB EPT) | `systrap` (opt-in; trusted only) | 4 KiB page / 64 KiB reserve | Windows 10 (2004+) or Windows 11 with WHP enabled. |
| `windows/arm64` | `whpx` (`Arm64Support`, 4 KiB Stage-2) | `systrap` (opt-in; trusted only) | 4 KiB page / 64 KiB reserve | Windows 11 24H2 (`Build 26100.3915+`) for `whpx`. |
| `darwin/arm64` | `hvf` (`Hypervisor.framework`, Stage-1 4 KiB) | None (`ErrUnavailable`) | 16 KiB page | Apple Silicon with `com.apple.security.hypervisor`. |
| `darwin/amd64` | None | None | None | Unsupported. |
| `linux/amd64` | Upstream `systrap` | None | 4 KiB page | Official target; full CI `e2e/` and POSIX suites. |
| `linux/arm64` | Upstream `systrap` (4 KiB or 16 KiB sub-blocks) | None | 4 KiB or 16 KiB page | Official target; 4 KiB native and 16 KiB QEMU CI. |
| `android/arm64` | None (lacks `/dev/kvm`) | Upstream `systrap` (`MFD_EXEC`) | 4 KiB or 16 KiB page | Packaged as `librungvx.so` in `gvx-android.aar` (`minSdkVersion 31`). |

### 1.2 Deliverables and Feature Map

The repository builds four deliverables backed by core subsystems and an isolated extension submodule.

| Deliverable or Subsystem | Owning Packages | Component Specification |
| :--- | :--- | :--- |
| Standalone CLI (`rungvx`) | `cmd/rungvx`, `pkg/rungvx` | [`cli.md`](cli.md) |
| Embeddable Go SDK & Control | `pkg/gvx`, `pkg/gvx/{control,shm,tuning,exttest}` | Section 3.13; [`control-protocol.md`](control-protocol.md) |
| Extension Submodule (`ext/`) | `ext/cmd/rungvx`, `ext/extensions/gpu` | [`extensions-plan.md`](extensions-plan.md) |
| Optional Containerd Control Shim | `cmd/containerd-shim-gvx-v2`, `internal/gvxshim` | Section 3.10 |
| Android Library (`gvx-android.aar`) | `android/`, `tools/androidprobe` | [`components/android.md`](components/android.md) |
| Hardware Hypervisor Backends | `pkg/sentry/platform/{whpx,hvf,hvcommon}` | [`components/hypervisors.md`](components/hypervisors.md) |
| Windows and Linux `systrap` | `pkg/sentry/platform/systrap` | Section 3.3; [`systrap-windows.md`](systrap-windows.md) |
| Single-File Ext4 Volumes | `pkg/sentry/fsimpl/ext4lite`, `pkg/sentry/blockdev` | [`components/ext4lite.md`](components/ext4lite.md) |
| Pinned Host Filesystem & Proxy VFS | `pkg/sentry/fsimpl/{hostfs,rpcfs,chunkcache,fsutilx}` | [`components/hostfs.md`](components/hostfs.md) |
| Driverless Networking & Overlays | `pkg/netbackend`, `pkg/ipset`, `pkg/tcpip/link/{vxlan,wgtun}`, `genetlink` | [`components/netbackend.md`](components/netbackend.md) |
| OCI Image Compiler & Host CAs | `pkg/oci`, `pkg/gvx/hostcerts` | [`components/oci.md`](components/oci.md) |
| Pre-Execution Host Self-Lockdown | `pkg/hostlockdown` | [`components/hostlockdown.md`](components/hostlockdown.md) |

---

## 2. Repository Layout and Upstream Synchronization

`gvx` tracks the pre-generated `go` branch of `https://github.com/google/gvisor.git` (`upstream/go`), where upstream publishes `go_stateify` and `go_marshal` output for `amd64` and `arm64`. Consequently, `gvx` compiles with `go build` without Bazel, while `tools/gostateify` generates `*_state_autogen.go` for `gvx`-owned and Tier 2 packages.

```text
gvx/ (Tracks google/gvisor@go)
 ├── AGENTS.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, README.md, SECURITY.md, CHANGELOG.md
 ├── UPSTREAM_COMMIT                        # Pinned google/gvisor go-branch commit SHA
 ├── entitlements.plist                     # com.apple.security.hypervisor entitlement for macOS
 ├── android/                               # Android AAR library (dev.gfire.gvx.Gvx) and sample service
 ├── cmd/
 │   ├── rungvx/                            # Pure-Go CLI entrypoint (imports only pkg/rungvx)
 │   └── containerd-shim-gvx-v2/            # Optional containerd v3 control shim
 ├── ext/                                   # Nested Go submodule (z.gfire.dev/gvx/ext)
 │   ├── cmd/rungvx/                        # Extended CLI selected via -tags ext_gpu or ext_all
 │   └── extensions/gpu/                    # Optional GPU Extension SPI plugin
 ├── docs/
 │   ├── architecture.md, cli.md, compatibility.md, control-protocol.md, glossary.md, troubleshooting.md
 │   ├── extensions-plan.md, systrap-windows.md, moonshots.md
 │   ├── components/                        # Standalone specifications per major subsystem
 │   ├── recipes/                           # Docker Engine and Kubernetes user recipes
 │   └── assets/                            # D2 diagram sources and compiled SVGs
 ├── internal/                              # gvxshim, acceptprog probes, weakmap, embedded xsys/unix
 ├── pkg/
 │   ├── rungvx/                            # Standalone CLI implementation and CLIPlugin interface
 │   ├── gvx/                               # Embeddable SDK, control/, hostcerts/, tuning/, shm/, exttest/
 │   ├── oci/                               # Multi-arch OCI client, cache, Tar-to-EROFS compiler
 │   ├── netbackend/                        # NAT forwarder, DNS relay, bandwidth/policy, WireGuard
 │   ├── ipset/, tcpip/link/{vxlan,wgtun}/  # Guest IP sets, VXLAN, and shared WireGuard TUN endpoint
 │   ├── hostlockdown/                      # Windows, macOS, Linux, and Android host self-confinement
 │   ├── sync/, memutil/, fd/, fdnotifier/  # Cross-platform host OS primitives (Tier 2 siblings)
 │   └── sentry/
 │       ├── blockdev/                      # Lock-free 17-field disk statistics
 │       ├── socket/netlink/genetlink/      # Generic Netlink router and in-guest WireGuard family
 │       ├── platform/{whpx,hvf,hvcommon,systrap}/
 │       └── fsimpl/{chunkcache,fsutilx,hostfs,ext4lite,rpcfs}/
 ├── e2e/                                   # OS-agnostic black-box end-to-end suite
 ├── scripts/                               # Build, signing, sync, lint, repro, pjdfstest, android, linux16k
 └── tools/                                 # upstream, gostateify, gvisorlint, licenses, androidprobe, shiminterop
```

### 2.1 Layered Subsystem Map and Import Directionality

Strict top-down import directionality keeps host OS bindings out of the pure-Go Sentry kernel. `tools/upstream` (`boundaries.go`, `VerifyBoundaries`) verifies this table in CI. Foundational types (`pkg/context`, `pkg/hostarch`, `pkg/usermem`, `pkg/sentry/memmap`) are permitted across platform and VFS interfaces; exceptions require registration in `boundaries.go`.

| Package | Single Responsibility | Permitted Internal Imports | Forbidden Imports |
| :--- | :--- | :--- | :--- |
| `cmd/containerd-shim-gvx-v2` | Entrypoint for the optional containerd shim. | `internal/gvxshim` | `pkg/*`, `runsc/*`, `shim/*` |
| `internal/gvxshim` | Shim bootstrap, ttRPC serving, leases, and teardown. | Containerd types, ttRPC, protobuf, OS APIs | `pkg/*`, `runsc/*`, `shim/*`, `cmd/*` |
| `tools/shiminterop` | Isolated containerd `2.1.5` SDK interoperability tests. | None | Root runtime, `cmd/*`, `internal/*` |
| `tools/gostateify` | Reflection-free `pkg/state` generator and drift checker. | `golang.org/x/tools/*` | Production `pkg/*`, `cmd/*`, `internal/*` |
| `cmd/rungvx` | Thin pure-Go CLI entrypoint. | `pkg/rungvx` | `pkg/gvx/*`, `pkg/sentry/*`, `ext/*`, `WinHvPlatform.dll` |
| `pkg/rungvx` | CLI subcommands and `CLIPlugin` runner. | `pkg/gvx`, `pkg/gvx/control`, `pkg/oci`, `gopkg.in/yaml.v3` | `pkg/sentry/*`, `pkg/gvx/exttest`, `pkg/hostlockdown/*`, `cmd/*`, `ext/*` |
| `ext/` | Optional compile-time extension submodule. | `ext/*`, `pkg/gvx`, `pkg/gvx/shm`, `pkg/rungvx`, `pkg/sentry/fsimpl/sys`, `pkg/sentry/vfs`, `pkg/sentry/memmap` | `internal/*`, `pkg/hostlockdown/*`, `pkg/netbackend/*`, `pkg/sentry/kernel`, `pkg/sentry/platform/*`, `cmd/*` |
| `pkg/gvx` | Orchestrates OCI, mounts, networking, lockdown, Sentry, and C/R. | `pkg/gvx/{control,shm}`, `pkg/oci`, `pkg/netbackend`, `pkg/hostlockdown`, `pkg/sentry/*`, `pkg/fd`, `pkg/state`, `pkg/tcpip/*` | `cmd/*`, `ext/*`, `pkg/rungvx/*`, `pkg/gvx/exttest`, `internal/gvxshim/*` |
| `pkg/gvx/shm` | Cross-OS imported shared-memory regions and byte quotas. | `pkg/context`, `pkg/errors/linuxerr`, `pkg/hostarch`, `pkg/safemem`, `pkg/sentry/memmap`, OS syscalls | `pkg/gvx`, `pkg/sentry/{kernel,vfs,platform}/*`, `cmd/*`, `ext/*` |
| `pkg/gvx/exttest` | Narrow shared test helpers for `ext/e2e`. | `pkg/gvx`, `internal/{hvtest,systraptest,testimage}` | Production packages (`cmd/*`, `pkg/gvx`, `ext/*` production files) |
| `pkg/gvx/control` | `gvx-ctrl/2` wire framing, auth, and capability policy. | `pkg/gvx/tuning`, `internal/xsys/unix`, `windows`, `zstd` | `pkg/gvx`, `pkg/sentry/*`, `cmd/*`, `pkg/hostlockdown` |
| `pkg/oci` | Multi-arch OCI registry client, cache, and Tar-to-EROFS compiler. | `pkg/abi/linux`, `pkg/erofs`, `pkg/gvx/tuning` | `pkg/sentry/*`, `pkg/gvx/*`, `pkg/hostlockdown` |
| `pkg/netbackend` | Bridges Netstack to NAT forwarders or `wireguard-go`. | `pkg/state`, `pkg/tcpip/*`, `pkg/gvx/tuning` | `pkg/sentry/*`, `pkg/hostlockdown`, `WinHvPlatform.dll` |
| `pkg/hostlockdown` | Host self-lockdown across Windows, macOS, Linux, and Android. | `golang.org/x/sys/windows`, `internal/xsys/unix` | `pkg/sentry/*`, `pkg/tcpip/*`, `pkg/gvx/*` |
| `pkg/sentry/kernel` | OS-agnostic Linux tasks, signals, and syscalls (`amd64`, `arm64`). | `pkg/abi/linux`, `pkg/sentry/platform`, `pkg/sentry/vfs`, `pkg/sync`, `internal/weakmap` | `golang.org/x/sys/windows`, `pkg/hostlockdown` |
| `pkg/sentry/platform/hvcommon` | Shared Stage-2 GPA mapper, `CommHeader`, Stage-1 pool, encoders. | `pkg/hostarch`, `pkg/sentry/memmap` | `pkg/sentry/kernel`, `pkg/sentry/vfs` |
| `pkg/sentry/platform/whpx` | Windows Hypervisor Platform backend (`amd64`, `arm64`). | `pkg/sentry/platform`, `hvcommon`, `pkg/memutil`, `pkg/abi/linux`, `windows` | `pkg/sentry/kernel`, `pkg/sentry/vfs` |
| `pkg/sentry/platform/hvf` | macOS `Hypervisor.framework` backend (`arm64`). | `pkg/sentry/platform`, `hvcommon`, `pkg/memutil`, `pkg/abi/linux`, `internal/xsys/unix` | `pkg/sentry/kernel`, `pkg/sentry/vfs` |
| `pkg/sentry/platform/systrap` | Linux (4 KiB/16 KiB) and Windows stub execution engine. | `pkg/sentry/platform`, `hvcommon`, `pkg/memutil`, `pkg/abi/linux`, `golang.org/x/arch/*` | `pkg/sentry/kernel`, `whpx`, `hvf` |
| `pkg/sentry/fsimpl/hostfs` | Pinned host directory/file VFS2 driver and `.gvx_meta` journal. | `pkg/sentry/vfs`, `chunkcache`, `fsutilx`, `pkg/abi/linux`, `pkg/fd`, `pkg/hostlockdown` | `pkg/sentry/platform/*` |
| `pkg/sentry/fsimpl/ext4lite` | Single-file JBD2-journaled ext4 volume driver. | `pkg/sentry/vfs`, `pkg/sentry/blockdev`, `chunkcache`, `fsutilx`, `pkg/abi/linux`, `pkg/fd` | `pkg/sentry/platform/*`, `cmd/*` |
| `pkg/sentry/fsimpl/rpcfs` | Client-served proxy VFS2 driver for `rungvx mount serve`. | `pkg/sentry/vfs`, `pkg/abi/linux`, `pkg/errors/linuxerr`, `pkg/usermem` | `pkg/gvx/*`, `pkg/sentry/platform/*`, `pkg/hostlockdown` |
| `pkg/sync`, `pkg/memutil`, `pkg/fd` | Host futexes, shared memory views, and handle wrappers. | `golang.org/x/sys/windows`, `internal/xsys/unix` | `pkg/sentry/*` |

### 2.2 Three-Tier Upstream Isolation Model

Repository files fall into three isolation tiers so upstream synchronization remains mechanical:

| Isolation Tier | File Paths | Upstream Overlap | Maintenance Rule |
| :--- | :--- | ---: | :--- |
| **Tier 1: Additive Packages** | `cmd/{rungvx,containerd-shim-gvx-v2}/`, `pkg/rungvx/`, `pkg/gvx/`, `pkg/oci/`, `pkg/netbackend/`, `pkg/ipset/`, `pkg/tcpip/link/{vxlan,wgtun}/`, `pkg/hostlockdown/`, `pkg/sentry/socket/netlink/genetlink/`, `pkg/sentry/platform/{whpx,hvf,hvcommon}/`, `pkg/sentry/blockdev/`, `pkg/sentry/fsimpl/{chunkcache,fsutilx,hostfs,ext4lite,rpcfs}/`, `ext/`, `e2e/`, `internal/`, `scripts/`, `.github/`, `tools/`, `android/`, `docs/` | `0.0%` | Owned wholly by `gvx`; protected by `tools/upstream/file_mask.txt`. |
| **Tier 2: Sibling Files** | `*_windows*`, `*_darwin*`, and `*_xplat*` files placed inside upstream packages | `0.0%` | Selected by Go build tags beside unmodified `*_linux.go` files; zero diff budget. |
| **Tier 3: Build-Tag and Seam Patches** | Allowlisted pure-Go upstream files (`tools/upstream/buildtag_allowlist.txt`) | `< 5.0%` (`< 4.5%` CI gate) | Re-applied by `tools/upstream -mode=retag`; `runsc`/`shim`/`gofer` fences stay separate. |

![Upstream Synchronization Pipeline](assets/upstream-sync.svg)

### 2.3 Upstream Diff and Synchronization Procedure

Run `scripts/sync-upstream.sh` or the steps below to merge new commits from `google/gvisor`.

> [!WARNING]
> Do not hand-edit `*_linux.go` or unrecorded Tier 3 files. Unregistered edits cause merge conflicts and fail the CI audit gate. Register every Tier 3 rule in `tools/upstream/buildtag_allowlist.txt`.

1. Verify the `upstream` remote targets `https://github.com/google/gvisor.git` and fetch `upstream go`.
2. Merge `upstream/go` with `--no-commit` (or run `tools/upstream -mode=gitsync`).
3. Regenerate state files with `./scripts/gostateify.sh`.
4. Re-apply Tier 3 tags with `go run ./tools/upstream -mode=retag`.
5. Run `./scripts/gostateify.sh -check` and `tools/upstream -mode=audit` to verify compliance.
6. Update `UPSTREAM_COMMIT` and `tools/upstream/sync_manifest.json`, then compile all targets.

```bash
git remote add upstream https://github.com/google/gvisor.git 2>/dev/null || true
git fetch upstream go
git merge --no-commit upstream/go
./scripts/gostateify.sh
go run ./tools/upstream -mode=retag
./scripts/gostateify.sh -check
go run ./tools/upstream -mode=audit -max-ratio=0.045
git rev-parse upstream/go > UPSTREAM_COMMIT
for t in windows/amd64 windows/arm64 darwin/arm64 linux/amd64 linux/arm64; do
  GOOS=${t%/*} GOARCH=${t#*/} go build ./...
done
```

---

## 3. Subsystems and Cross-Cutting Contracts

Each major subsystem has a dedicated specification under [`components/`](components/hypervisors.md) or [`systrap-windows.md`](systrap-windows.md). This section defines the contracts spanning subsystems.

### 3.1 Host OS Primitives and Build-Tag Decoupling

Roughly 65% of upstream gVisor (`kernel`, `arch`, `ring0`, `vfs`, `fsimpl/{tmpfs,erofs,overlay}`, `pkg/tcpip`) is OS-agnostic Go code. `tools/upstream` widens build tags on allowlisted files to `linux || windows || darwin`, while Tier 2 siblings implement host primitives:

| Package | Linux Primitive | Windows Sibling (`_windows.go`) | macOS Sibling (`_darwin.go`) |
| :--- | :--- | :--- | :--- |
| `pkg/sync` | `SYS_FUTEX` | 64-shard table over `WaitOnAddress` / `WakeByAddress*` | `__ulock_wait` / `__ulock_wake` via `syscall6` |
| `pkg/memutil` & `pgalloc` | `memfd_create`, `mmap`, `MADV_DONTNEED`, `FALLOC_FL_PUNCH_HOLE`, `mincore` | `VirtualAlloc` (`whpx`); `CreateFileMappingW`, `MEM_RESET`, `DiscardVirtualMemory`, `K32QueryWorkingSetEx` (`systrap`) | `mmap(MAP_ANON)`, `mach_vm_remap`, 16 KiB `F_PUNCHHOLE`, 4 KiB `darwinMincore` |
| `pkg/sentry/time` & `hostcpu` | `CLOCK_MONOTONIC`, `getcpu` | `QueryPerformanceCounter`, `GetCurrentProcessorNumberEx` | `mach_continuous_time`, `pthread_cpu_number_np` |
| `pkg/fd` | Raw FD, `dup3`, `SCM_RIGHTS` | `HostHandle` wrapping `syscall.Handle` | `HostHandle` wrapping FD (`F_DUPFD_CLOEXEC`) |
| `pkg/fdnotifier` | Edge-triggered `epoll` | Passive table (`fdnotifier_portable_xplat.go`) | Passive table with non-blocking `SYS_POLL` |
| `internal/xsys/unix` | Linux syscalls and structs | Translates `SYS_MMAP`/`PREAD64` to Win32 | Bridges 48-byte `darwinMsghdr`, `Stat_t`, `Dirent`, `Fallocate` |
| `pkg/sentry/syscalls` | Host `io_uring` passthrough | Returns `-ENOSYS` on `io_uring_*` | Returns `-ENOSYS` on `io_uring_*` |

On 16 KiB hosts (macOS, Android 16, Debian `arm64-16k`), `pgalloc` aligns allocations `>= 16 KiB` to 16 KiB boundaries. It punches whole 16 KiB host holes, zeroes reclaimed 4 KiB sub-pages, and expands `mincore(2)` four-to-one (`mincoreExpandHostPages`). Each `MemoryFile` owns a per-sandbox `usage.Memory` ledger (`MemoryFileOpts.Accounting`) and notifies registered write observers (`ObserveHostWrites`).

### 3.2 Hardware Hypervisor Backends: `whpx` and `hvf`

`platform/whpx` (`windows/{amd64,arm64}`) and `platform/hvf` (`darwin/arm64`) share `platform/hvcommon` (`RegionTable`, `PageTablePool`, 304-byte `CommHeader`, and encoders). Both map `pgalloc.MemoryFile` chunks into Stage-2 once and resolve subsequent faults in 4 KiB guest page tables without hypervisor calls. Consult [`components/hypervisors.md`](components/hypervisors.md) for paging invariants, CPUID masking, `membarrier`, measurements, and files.

![Hypervisor Fast-Path Syscall and Fault Sequence](assets/hypervisor-trap.svg)

### 3.3 Stub-Process Execution Engine: `platform/systrap`

`platform/systrap` runs guest instructions natively inside isolated stub processes on Linux (4 KiB and 16 KiB pages), Android, and opt-in Windows (`winsystrap`). Consult [`systrap-windows.md`](systrap-windows.md) for Windows binary patching, fast paths, measurements, island reclamation, and security limits.

![Windows systrap Lazy Page-Trap and Fast-Path Syscall Sequence](assets/winsystrap-flow.svg)

#### 4 KiB Guest Pages on 16 KiB Linux and Android Hosts (`subblock_xplat.go`)

When the host enforces 16 KiB mappings, `subblock_xplat.go` groups 4 KiB guest pages into 16 KiB host blocks (`hostpage_xplat.go` aligns internal regions):

| 16 KiB Host Block State | Stub Mapping Strategy |
| :--- | :--- |
| Four contiguous 4 KiB pages in one file, 16 KiB aligned, uniform write permission | Direct host file mapping. |
| Heterogeneous four-page block | Non-writable composite page; guest stores trap to `substore_xplat_arm64.go`. |
| Private writable pages beside unmapped or `PROT_NONE` pages | Single block releasing spare pages via `HostBlockOwner` on `mmap`/`mprotect`. |
| Partially unpopulated block | Populated on switch; missing pages zero-fill, raising `SEGV_MAPERR` on store or `SIGILL`. |

Sentry write notifications refresh composite copies selectively. Executable composite pages flush via `pwrite(2)` and remap to clean stub instruction caches; set `GVX_SYSTRAP_SUBBLOCKS=1` on 4 KiB hosts to test this path.

#### Linux Stub Wake-Up, Idle Pool, and `membarrier`

- **Seccomp listener fallback**: Linux permits one `seccomp` user-notify listener per filter chain. On `EBUSY`, `systrap` logs one warning and switches new stubs to the futex wake loop.
- **Process-wide idle stub pool (`globalPool`)**: Retains idle stubs up to compile-time caps (`2` on Android; `GOMAXPROCS` clamped to `4..32` elsewhere). Excess stubs kill, stop readers, `wait4`, close listeners, and release memory.
- **Windows `systrap` `membarrier`**: `GlobalMemoryBarrier` suspends running stub threads under per-thread locks and calls `GetThreadContext`. After resuming them, it calls `FlushProcessWriteBuffers` for Sentry threads.

### 3.4 Register Preservation and Two-Tier Synchronization

Linux `syscall` and `svc #0` traps preserve all general-purpose registers (except return values and `RCX`/`R11` on `amd64` `syscall`) and vector state. Because Go clobbers SIMD registers (`XMM`/`YMM`, `V0..V31`), each backend isolates guest register state across transitions:

| Architecture and Class | Registers | Preservation Requirement |
| :--- | :--- | :--- |
| `amd64` GPRs | `RAX`, `RDI`, `RSI`, `RDX`, `R10`, `R8`, `R9`, `RBX`, `RBP`, `R12..R15`, `RIP`, `RSP`, `RFLAGS` | Sync syscall args/return; preserve callee-saved registers across transitions. |
| `amd64` trap-clobbered | `RCX`, `R11` | Preserve intact across `#PF`, async signals, and `int 0x80` (Wine/WoW64). |
| `amd64` TLS and segments | `FSBase`, `GSBase`, `CS`, `SS`, `DS`, `ES`, `FS`, `GS` | Preserve Linux TLS (`FSBase`), TEB (`GSBase`), and WoW64 `CS=0x23`/`0x33`. |
| `amd64` vector and debug | `XMM/YMM0..15`, AVX-512, `x87`, `MXCSR`, `FCW`, `FSW`, `DR0..DR7` | Shield from Go runtime; expose `DR0..DR7` for `ptrace` and thread contexts. |
| `arm64` GPRs and `X18` | `X0..X30`, `SP_EL0`, `PC`, `PSTATE`, `OrigR0` | Preserve `X1..X30` across traps; isolate guest `X18` from host TEB. |
| `arm64` TLS, vector, debug | `TPIDR_EL0`, `TPIDRRO_EL0`, `V0..V31`, `FPCR`, `FPSR`, debug regs | Preserve NEON state; mask `HWCAP_PACA`/`PACG` when keys are unvirtualized. |

> [!CAUTION]
> Always execute hypervisor run loops and `systrap` trampolines on OS-locked threads (`runtime.LockOSThread`). Entering Go with guest `FSBase`, `GSBase`, `X18`, or `MXCSR` corrupts the Go runtime.

`whpx` syncs syscall GPRs on fast paths and full XSAVE/segment/debug state via `PullFullState` and `FullStateChanged`. `hvf` loads and stores GPR and FP state from `arch.Context64` on every `Switch`. `systrap` trampolines spill all GPRs, TLS pointers, and vector state into `sysmsg` before waking Sentry.

### 3.5 Dual-Track Networking Backend: `pkg/netbackend`

`pkg/netbackend` bridges Netstack to Track A (`-net=nat`: L2 pipe, Go dialers, `-p`, `--auto-publish`, DNS relay, token buckets, NAT policy). Track B (`-net=wg`) attaches `wireguard-go` over `wgtun.Endpoint`. Consult [`components/netbackend.md`](components/netbackend.md) for session caps, MTU bounds, TCP error synthesis, and files.

![Dual-Track Netstack Backend](assets/netbackend.svg)

### 3.6 OCI Image Compilation and Host CA Injection

`pkg/oci` resolves multi-arch manifests, verifies digests, and compiles `.tar.gz`/`.tar.zst` streams directly into cached 4 KiB EROFS images under `tmpfs` or `ext4lite`. `pkg/gvx/hostcerts` optionally collects host root CAs before lockdown and merges them into guest upper layers. Consult [`components/oci.md`](components/oci.md) for details.

![OCI Tar-to-EROFS Layer Compilation Pipeline](assets/oci-erofs.svg)

### 3.7 Host Filesystem Driver: `pkg/sentry/fsimpl/hostfs`

`hostfs` mounts host directories and regular files through pinned `os.Root` handles (`NtCreateFile`, `openat`, `openat2`) and uses `chunkcache` for 64 KiB `mmap` chunks. It encodes incompatible names with `NameCodec`, forwards host events to `inotify`, and stores POSIX metadata in a CRC-32C-framed `.gvx_meta` v4 journal. Consult [`components/hostfs.md`](components/hostfs.md) for full invariants.

### 3.8 Volume Filesystem Driver: `pkg/sentry/fsimpl/ext4lite`

`ext4lite` stores volumes, overlays, and `-rootfs-volume` mounts inside single pre-opened `.ext4` files with 16 MiB `meta_bg` groups up to 64 TiB. Each image supports extent trees, ordered JBD2 journaling, hole punching, tail compaction, file locks, untrusted-image checks, and `blockdev` counters. Consult [`components/ext4lite.md`](components/ext4lite.md) for layout and recovery rules.

### 3.9 Host Self-Lockdown and Security Model

`pkg/hostlockdown` seals the host process before guest entry across three concentric rings. Ring 1 isolates code in hardware page tables or Linux `seccomp` stubs, while Ring 2 confines syscalls and VFS I/O in Go. Ring 3 strips OS tokens, forks, unbound paths, and sockets. Consult [`components/hostlockdown.md`](components/hostlockdown.md) for OS-specific steps.

![Host Self-Lockdown State Transition](assets/host-lockdown.svg)

### 3.10 Optional Containerd Control Adapter

`cmd/containerd-shim-gvx-v2` (`internal/gvxshim`) implements runtime identity `io.containerd.gvx.v2` for containerd Task v3 bootstrap and shutdown without importing `pkg/gvx` or launching guest workloads. It spawns a detached provisional child, emits JSON bootstrap version `3`, and bounds startup, handoff, drain, and cleanup to 5 seconds.

| RPC | Response | State Transition |
| :--- | :--- | :--- |
| Task v3 `Connect` | Shim PID, task PID `0`, version `gvx-control-v1` | Attaches external caller. |
| Task v3 `Shutdown` / `ShutdownSandbox` | Empty success after response barrier | Drains gracefully (retaining sockets up to `1 s` for ttRPC `1.2.7`). |
| Sandbox `CreateSandbox` | Wire `Unimplemented` after namespace/ID check | Attaches caller; creates no sandbox. |
| Other Task/Sandbox RPCs | Wire `Unimplemented` | None. |

Endpoint paths hash owner, normalized containerd address, namespace, ID, and bundle (`/tmp/gvx-shim-<euid>/<digest>/{task,stop}` on Unix; `\\.\pipe\gvx-shim-<digest>-{task,stop}` on Windows). `.gvx-shim` metadata coordinates locks and leases; `delete` emits Task v2 `DeleteResponse` without signaling stored PIDs. Root dependencies use containerd `2.1.5`, API `1.10.0`, and ttRPC `1.2.7`, tested in `tools/shiminterop`.

### 3.11 Guest Kernel Interfaces for Docker Engine and Kubernetes

`dockerd`, `containerd`, `runc`, `kubelet`, Flannel, and Calico rely on Linux kernel interfaces omitted by upstream gVisor. Each addition resides in Tier 1 packages or Tier 2 `*_xplat.go` siblings:

| Kernel Interface | Owning Package(s) | Core Contract |
| :--- | :--- | :--- |
| `/proc/sys/net/ipv4/conf/<link>/route_localnet`, `ipv6/conf/<link>/accept_ra`, `rp_filter` | `fsimpl/proc/*_xplat.go`, `tcpip/network/ipv4/martian_xplat.go`, `socket/netstack/rpfilter_xplat.go` | Per-link dynamic `/proc/sys` directories keyed by link index; per-endpoint `route_localnet` and `EffectiveRPFilter`. |
| `bridge-nf-call-iptables` / `ip6tables`, bridge forwarding, hairpin | `socket/netstack/{bridge_netfilter,bridgeport,hostfilter}_xplat.go`, `tcpip/stack/bridge_*_xplat.go` | Per-netns default `1`; routes bridged frames through netfilter chains and drops `PACKET_OTHERHOST`. |
| Netfilter matches/targets (`statistic`, `recent`, `set`/`SET`, `limit`, `physdev`, `CONNMARK`, `rpfilter`, `LOG`) | `socket/netfilter/*_xplat.go`, `pkg/ipset`, `socket/netlink/netfilter/ipset_xplat.go` | Legacy `iptables` (`filter`, `nat`, `mangle`, `raw`); full `ipset` types and chunked dumps. |
| `CTNETLINK` & `nf_conntrack_*` sysctls | `socket/netlink/netfilter/ctnetlink_xplat.go`, `tcpip/stack/conntrack*_xplat.go` | Resumable conntrack dumps/deletes; per-netns timeouts; `nf_conntrack_max` (default `262,144`). |
| Policy routing, proxy ARP, `SIOCETHTOOL`, `IFLA_STATS64`, `/sys/class/net/<link>` | `tcpip/stack/{fib,rpfilter,proxyarp}_xplat.go`, `socket/netlink/route/*_xplat.go`, `ethtool_xplat.go` | Priority-ordered FIB rule walks, special route types, ethtool flags, and link counters. |
| `NETLINK_GENERIC`, in-guest `wireguard`, `vxlan`, neighbor/FDB netlink | `genetlink` (Tier 1), `tcpip/link/vxlan` (Tier 1), `neigh_xplat.go`, `neighbor_gc_xplat.go` | Chunked `genetlink.Dumper`; `wireguard` link lifecycle; RFC 7348 `vxlan`; per-netns `gc_thresh1..3`. |
| `cgroup2` `memory.max`, `cpu.max`, `io.stat`, `pids.max` | `fsimpl/cgroup2fs/{memory,cpu,io}_xplat.go`, `kernel/*cpu_bandwidth*_xplat.go` | Polling OOM guard; CFS quota enforcement; `io.stat` accounting for `ext4lite`/overlay (`io.max`/`io.weight` store without throttling). |
| `/dev/kmsg`, `syslog(2)`, node sysctls, `MemTotal`, online CPUs | `devices/memdev/kmsg_xplat.go`, `kernel/{kmsg,total_memory}_xplat.go`, `fsimpl/proc/tasks_sys*_xplat.go` | Power-of-two log ring (`kernel.log_buf_len`); per-netns port/keepalive sysctls; per-sandbox RAM/CPUs. |
| Block statistics & `/sys/fs/bpf` | `pkg/sentry/blockdev`, `fsimpl/{proc/diskstats,sys/blockclass,sys/bpffs}_xplat.go` | 17-field atomic counters exposed via `/proc/diskstats`, `/sys/block/vd*`, and `rungvx stats`; stub `bpf` mountpoint (`0xcafe4a11`). |

### 3.12 State Shared Across Sandboxes in One Process

Because `pkg/gvx`, `e2e/`, and shims run multiple sandboxes inside one process, guest-visible limits and counters belong strictly to one sandbox. `internal/weakmap.Map` attaches per-sandbox state (`kernelExtState`, `stackExtState`) to upstream structs via a 16-shard `weak.Pointer` table evicted by `runtime.AddCleanup` and serialized via `saveExt`/`loadExt`.

| Intentional Process-Wide State | Owner | Justification |
| :--- | :--- | :--- |
| Host RAM bounds (`usage.Minimum/MaximumTotalMemoryBytes`, `tmpfs.totalHostMem`) | `usage`, `tmpfs`, `pkg/gvx` | Physical host RAM is constant; sandboxes override reported RAM via `SetReportedMemory`. |
| Global `usage.MemoryAccounting` / `DirtyMemoryAccounting` | `usage` | `gvx` charges per-sandbox `MemoryFile.Accounting`; globals cover unused `gofer` paths only. |
| `systrap` `sealedHoles`, dispatcher, thread budgets, `globalPool`, `sharedSystrap` | `platform/systrap`, `pkg/gvx` | Host address holes and stub pool capped at compile time (`2` Android; `4..32` Linux). |
| `hvf` shared VM (`vmGlobal`) | `platform/hvf` | XNU permits one VM per process; platforms reference-count it with separate page tables. |
| `hostfs` watch budget (`processWatches`) | `fsimpl/hostfs` | Host descriptor limits are process-wide; all workspaces share one cap. |
| Capability probes, `memutil` arena index, `lastPIDNSID`, `hostlockdown` state, `extLockdownRecvMsgFD`, `tuning` registry, `log.SetLevel` | Respective packages | Host facts, monotonic counters, one-way lockdown (`ErrLockdownActive` on incompatible spawns), or `CapDebug` logging. |
| Unused `runsc`-only globals (`seccheck.Global`, `nftables`, `gofer.globalDentryCache`, `time.tscOffset`) | Upstream Sentry | Never initialized by `gvx`. |

| Per-Sandbox Owned State | Owning Key |
| :--- | :--- |
| Memory usage accounting, `/proc/meminfo`, `memory.current`/`memory.stat`, OOM enforcer, WireGuard memory charge | `pgalloc.MemoryFile.Accounting` |
| Engine fault cause, reported total memory, `/dev/kmsg` ring (`kernelExtState`), node sysctls, `shm_rmid_forced`, cgroup registry | `kernel.Kernel` or namespace |
| Policy-routing FIB, `rp_filter`, proxy ARP, bridge netfilter switches, `xt_recent`, `ipset`, `vxlan`, WireGuard links, `stackExtState`, disk registry | Network stack or VFS |

> [!IMPORTANT]
> Never add a package variable for guest-visible state. Any change to accounting, limits, or IDs requires a concurrent two-sandbox test (modeled on `TestE2EMemoryAccountingIsPerSandbox`).

### 3.13 Pre-Lockdown Checkpoint and Restore

`Sandbox.Checkpoint` (`pkg/gvx/checkpoint.go`) and `gvx.Restore` (`pkg/gvx/restore.go`) save and resume sandboxes on identical host OS, architecture, and backend without relaxing `hostlockdown`.

![Pre-Lockdown Checkpoint and Restore Pipeline](assets/checkpoint-restore.svg)

| Bundle File | Producer / Consumer | Wire Format and Bounds |
| :--- | :--- | :--- |
| `manifest.json` | `pkg/gvx` (`CheckpointManifest` v1..v3) | JSON recording version (`1`..`3`), targets, `layer_digests`, `mounts`, `net_mode`, `eth0`, `memory_limit_bytes` (`1 MiB` max). |
| `state.img` | `pkg/state/statefile`, `pkg/sentry/state` | 8-byte `"gVisorSF"` magic, `uint64` metadata length, and `compressio` stream holding `cpuid.FeatureSet` and `kernel.Kernel`. |
| `pages.meta` | `pkg/sentry/pgalloc` | `uint64` length + `MemoryFileMetadataProto` + private metadata keyed by `ResourceID` (`256 MiB` or `131,072` chunks max). |
| `pages.img` | `pkg/sentry/pgalloc`, `stateio` | Non-zero 4 KiB ranges scanned with `SEEK_DATA`/`SEEK_HOLE` via `AsyncMFLoader` (`2 * memoryLimit + 1 GiB` max). |

During save, `Sandbox.Checkpoint` pauses guest tasks, quiesces NAT relays and WireGuard workers, captures `stackExtState`, stages unlinked `hostfs` files (`.gvx_tmp_*`), and commits `ext4lite` JBD2 journals. Post-pause failures resume the guest (except post-NIC-teardown `LeaveRunning: false`, exiting `137`). During restore, `gvx.Restore` checks manifest equality, opens backing handles before `hostlockdown.Apply()`, and rebinds mounts, stdio, and Netstack inside lockdown.

### 3.14 Android Host Runtime and Packaging

`scripts/android/build-sdk.sh` compiles `cmd/rungvx` (`GOOS=android`, `CGO_ENABLED=1`) into `jni/arm64-v8a/librungvx.so` inside `gvx-android.aar` (`minSdkVersion 31`) so PackageManager extracts it under `apk_data_file`. `dev.gfire.gvx.Gvx` passes app-private `HOME`/`TMPDIR` and active `--host-dns` servers, while `android/sample` runs inside a `specialUse` foreground service. Consult [`components/android.md`](components/android.md) for `MFD_EXEC`, 16 KiB sub-blocks, and the 32-process ceiling.

---

## 4. Implementation History, Verification, and Tooling

`gvx` was built across five milestones (`M1` Host Primitives, `M2` WHPX/HVF Static ELF, `M3` Dynamic Linking/Netstack/OCI, `M4` `hostfs`/Lockdown, `M5` `winsystrap`), all continuously verified in CI.

### 4.1 Test Architecture and Native-First Verification

Verification spans three test layers from single-package invariants to full OS-agnostic guest workloads:

| Layer | Scope | Purpose |
| :--- | :--- | :--- |
| Host primitive & contract unit tests | `pkg/sync`, `memutil`, `fd`, `hostlockdown`, `platform/*`, `fsimpl/*`, `oci`, `ipset` | Verifies OS syscalls, binary patchers, crash recovery, and layout invariants. |
| Zero-dependency guest probes | `internal/acceptprog` (`acceptprog`, `lockdownprobe`, `checkpointprobe`, `cpumaxprobe`, `nodeprobe`, `microbench`) | Static `GOOS=linux` probes exercising syscalls, signals, cgroups, and C/R offline. |
| Black-box E2E & POSIX suites | `e2e/` (`TestE2E*`), `scripts/pjdfstest` | Identical assertions across Windows, macOS, Linux (4/16 KiB), and Android, plus POSIX conformance. |

### 4.2 Continuous Integration Matrix

These workflows verify pure-Go builds, nested extensions, cross-OS unit and E2E suites, reproducible builds, and releases.

| Workflow / Job | Runner | Verified Scope |
| :--- | :--- | :--- |
| `ci.yml` (`audit`, `build, vet, and lint`) | `ubuntu-24.04` | `gofmt`, 5-target + `android/arm64` builds, `go vet`, `gostateify -check`, `tools/licenses -check`, `gvisorlint`, `tools/upstream -max-ratio=0.045`, consumer module check. |
| `ci.yml` (`test linux/*`, `repro`, `dind-build`) | `ubuntu-24.04`, `ubuntu-24.04-arm` | `-race` owned tests, `GVX_SYSTRAP_SUBBLOCKS=1`, offline `e2e/`, SHA-256 reproducible build, local-registry `docker:dind` build. |
| `ci.yml` (`test darwin/arm64`, `windows/*`) | `macos-26`, `windows-latest`, `windows-11-arm` | Signed owned tests (`codesign-exec.sh`), real `whpx` + `winsystrap` (`windows/amd64`), `winsystrap` + shim (`windows/arm64`). |
| `ext.yml` (`build`, `test-*`) | `ubuntu-24.04`, `ubuntu-24.04-arm`, `macos-26`, `windows-latest` | Cross-compiles, vets, tests (`-race` and `CGO_ENABLED=0`), and repro-verifies `ext/` with `-tags ext_gpu` and `-tags ext_all`. |
| `android.yml`, `linux16k.yml` | `ubuntu-24.04` (KVM), `ubuntu-24.04-arm` (QEMU) | Android 16 emulator smoke + APK launch; Debian trixie `arm64-16k` QEMU suite. |
| `pjdfstest.yml`, `e2e-images.yml` | Linux & Windows runners | POSIX `pjdfstest` against `known-failures.txt`; weekly real-registry Docker and K3s gates. |
| `benchmark.yml`, `release.yml` | Multi-OS runners | Longitudinal `TestE2EMicroBench` (`bench-results` branch); 7-archive SLSA-attested releases. |

Hosted macOS runners cannot execute nested VMs (`GVX_ALLOW_NO_HYPERVISOR=1`), so physical Apple Silicon hosts verify `hvf` and macOS `pjdfstest`.

### 4.3 Containerd Shim Verification

Integration evidence covers commit `f3b7ef4` (post-upstream `90a2f3f7`) across focused native runs (`internal/gvxshim`, `cmd/containerd-shim-gvx-v2`, `tools/upstream`, `hvcommon`, `fdnotifier`) without claiming guest execution or CRI support:

| Boundary | Observed Result | Scope Limit |
| :--- | :--- | :--- |
| Linux command & real SDK `2.1.5` | JSON v3/ttRPC bootstrap, repeated `delete`, lease cleanup, and `ShimManager` disconnect passed. | Control-plane lifecycle only; no guest workload. |
| External containerd `2.2.4` (`193637f7`, Linux `amd64`) | Native creation returned expected `Unimplemented`; teardown removed owned state. | No created sandbox. |
| Five targets (build + focused native tests) | Passed across `linux/{amd64,arm64}`, `darwin/arm64`, `windows/{amd64,arm64}`. | Reproduce via `tools/shiminterop` with `GVX_SHIM_BINARY` and `GVX_CONTAINERD_BINARY`. |

### 4.4 Embedded `internal/xsys/unix` Package

`gvx` embeds a tailored copy of `golang.org/x/sys/unix` inside `internal/xsys/unix` so pure-Go Sentry builds on Windows and macOS need no `replace` directive (`scripts/check-consumer.sh`). When upgrading `golang.org/x/sys`, preserve every `gvx_*` file and the Darwin `Stat_t`, `Dirent`, `darwinMsghdr`, and `SYS_POLL`/`SYS_PPOLL` adaptations.

### 4.5 The gVisor Static Analyzers (`tools/gvisorlint`)

`scripts/gvisorlint.sh` runs `checklocks`, `checkconst`, and `checklinkname` via `go vet` across all five targets. Fix real lock-order or field-guard bugs first. Add `// +checklocksforce:` or `// +checklocksignore:` only with justification when SSA cannot prove a valid lock path. `tools/gvisorlint/baseline.txt` records accepted upstream findings only.

### 4.6 Native State Code Generator (`tools/gostateify`)

`tools/gostateify` generates reflection-free `pkg/state` methods from `// +stateify savable` annotations without Bazel for packages listed in `tools/gostateify/packages.txt`. `tier2` entries emit `*_xplat_state_autogen.go` siblings so upstream autogen files remain untouched; run `./scripts/gostateify.sh` after editing savable structs and verify with `./scripts/gostateify.sh -check`.

### 4.7 Third-Party License Collector (`tools/licenses`)

`tools/licenses` walks the transitive Go module graph across shipped targets and generates `pkg/rungvx/licenses/THIRD_PARTY_LICENSES.txt`. Run `go run ./tools/licenses -check` to verify both that embedded file and the license table in `README.md`.

### 4.8 Reproducible Builds

`scripts/repro-build.sh` compiles deterministic binaries using `-trimpath`, stripped build IDs, a scrubbed environment, `CGO_ENABLED=0`, and pinned `GOAMD64`/`GOARM64` baselines. `scripts/verify-repro-gvx.sh` builds `rungvx` on the host and inside a `golang` container running on `gvx`, asserting identical SHA-256 hashes.
