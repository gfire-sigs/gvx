# `gvx` Architecture and Implementation Plan

`gvx` is an upstream-trackable fork of `google/gvisor` that ports the Sentry kernel to Windows (`windows/amd64`, `windows/arm64`) and macOS (`darwin/arm64`, `darwin/amd64`) as Priority-0 targets. Without booting a virtual machine, `gvx` runs Linux ELF64 binaries and OCI images inside an unprivileged sandbox via `cmd/rungv` or `pkg/gvx`. The runtime intercepts Linux system calls in Go and translates them into native Windows NT, macOS XNU, Go `net`, and user-mode hypervisor or `systrap` calls.

---

## 1. Executive Summary and Architectural Scope

This section defines the Priority-0 target matrix, execution backends, networking modes, OCI image pipeline, and upstream isolation rules for `gvx`. Every subsystem implementation must satisfy these baseline contracts before merging.

| Design Objective | Engineering Contract | Verification Boundary |
| :--- | :--- | :--- |
| **Priority-0 Dual-OS & Dual-Arch** | Targets `windows/amd64`, `windows/arm64`, `darwin/arm64`, and `darwin/amd64` from one codebase. | Compiles and runs native `linux/amd64` and `linux/arm64` ELF64 workloads on Windows and macOS. |
| **Zero Runtime Elevation** | Runs under a standard user account and locks down the host process before guest entry. | Requires no UAC prompts, no `sudo`/`root`, no kernel drivers/kexts, and no background daemons. |
| **Hardware 4KB Paging (`whpx` & `hvf`)** | Uses `WinHvPlatform.dll` (Windows) and `Hypervisor.framework` (macOS) with 4KB EPT and Stage-1/Stage-2 tables. | Bypasses the Windows 64KB `VirtualAlloc` limit and the Apple Silicon 16KB host page limit. |
| **Unified `systrap` Fallback (`systrap`)** | Exposes `pkg/sentry/platform/systrap` on Linux (upstream) and macOS `arm64` (`darwinsystrap`) using lazy in-place syscall patching and pre-spawned stub subprocesses. Windows returns `ErrUnavailable`. | Executes ELF64 binaries and JIT runtimes (V8) when hardware virtualization is disabled. The guest architecture must equal the host architecture. |
| **Dual-Track Netstack (`pkg/netbackend`)** | Connects `pkg/tcpip` to an L4 Go `net` NAT and port forwarder (`-net=nat -p`) or an L3 `wireguard-go` tunnel (`-net=wg`). | Supports inbound/outbound port forwarding (`-p`) and `host.docker.internal`, or cryptographic L3 isolation. |
| **Direct OCI Image Execution (`pkg/oci`)** | Streams OCI `.tar.gz`/`.tar.zst` layers in memory into cached `<sha256>.erofs` images mounted via `fsimpl/overlay`. | Runs unmodified multi-arch Docker/OCI images without extracting Linux files onto NTFS or APFS. |
| **Clean Upstream Boundary** | Isolates host logic behind `_windows.go` and `_darwin.go` files and platform interfaces. | Modifies less than 5% of upstream gVisor and builds via `go build` on Go 1.25+. |

```mermaid
flowchart TD
    HostApp["Host Caller (cmd/rungv or pkg/gvx)"] --> OCI["pkg/oci (Multi-Arch OCI Pull & In-Memory Tar-to-EROFS Cache)"]
    OCI --> Lockdown["pkg/hostlockdown (Windows RestrictedToken/JobObject or macOS Seatbelt)"]
    Lockdown --> Sentry["pkg/sentry/kernel (Pure-Go Linux Syscall & Task Engine: amd64 & arm64)"]
    Sentry --> VFS["pkg/sentry/vfs (VFS2 Layer)"]
    Sentry --> Net["pkg/tcpip (Pure-Go Netstack TCP/IP)"]
    Sentry --> Platform["pkg/sentry/platform (Execution Backend Interface)"]
    VFS --> Overlay["fsimpl/overlay (tmpfs Upper + Multi-Layer EROFS Lower)"]
    VFS --> HostFS["fsimpl/hostfs (os.Root + NtCreateFile / openat + .gvx_meta)"]
    Net --> NetNAT["pkg/netbackend: Track A (-net=nat L4 Go net NAT & -p Port Forwarder)"]
    Net --> NetWG["pkg/netbackend: Track B (-net=wg L3 channel.Endpoint + wireguard-go)"]
    Platform --> WHPX["platform/whpx (Windows WinHvPlatform.dll: amd64 & arm64)"]
    Platform --> HVF["platform/hvf (macOS Hypervisor.framework: arm64 & amd64)"]
    Platform --> Systrap["platform/systrap (Unified In-Place Syscall Patcher & Stub Subprocess: Linux, macOS, Windows)"]
```

### 1.1 Compatibility Matrix and Cross-Architecture Execution (Descriptive Module)

`gvx` pairs hardware virtualization (`whpx` and `hvf`) as the default Tier-1 engine with the `systrap` backend as the user-mode fallback. Linux uses the upstream gVisor platforms.

The `systrap` fallback runs on macOS `arm64` only, and it needs 16KB guest pages (`-tags pagesize_16k`). Windows `systrap` needs a C toolchain with a COFF linker for the stub. The project dropped the Rosetta 2 engine for `darwin/amd64`. A syscall-number Seatbelt filter on a translated process panicked the host kernel. A stub without that filter would let a guest issue host system calls. The guest architecture must equal the host architecture on every backend.

| Host Target | Primary Engine (`whpx` / `hvf`) | Fallback Engine (`systrap`) | Host Page & Allocation Granularity | Platform Requirements & Status |
| :--- | :--- | :--- | :--- | :--- |
| **`windows/amd64`** (Intel / AMD) | `platform/whpx` (`WinHvPlatform.dll` 4KB EPT) | Not implemented (`ErrUnavailable`). | 4KB Page / 64KB `VirtualAlloc` Reserve | Windows 10 (2004+) and Windows 11 with the Windows Hypervisor Platform feature. Runs `linux/amd64` images. |
| **`windows/arm64`** (Snapdragon X) | `platform/whpx` (`Arm64Support` 4KB Stage-2) | Not implemented (`ErrUnavailable`). | 4KB Page / 64KB `VirtualAlloc` Reserve | Windows 11 24H2 (Build `26100.3915+`) required for ARM64 WHPX. Runs `linux/arm64` images. |
| **`darwin/arm64`** (Apple Silicon M1-M5) | `platform/hvf` (`Hypervisor.framework` Stage-1 4KB + Stage-2 16KB) | `platform/systrap` (`darwinsystrap`: 4B `B` Island Patch + `sys_icache_invalidate`), built with `-tags pagesize_16k`. | 16KB Host Page / 16KB Map Granularity | Entitlement `com.apple.security.hypervisor` for `hvf`. Runs `linux/arm64` images. |
| **`darwin/amd64`** (Intel Mac) | `platform/hvf` (`Hypervisor.framework` VT-x 4KB EPT) | Dropped. | 4KB Page / 4KB Map Granularity | Runs `linux/amd64` images on `hvf`. |
| **`linux/amd64`** | Upstream platforms (`kvm`, `systrap`). | Upstream `systrap`. | 4KB Page | CI builds and tests the packages that `gvx` owns. |
| **`linux/arm64`** | Upstream platforms (`kvm`, `systrap`). | Upstream `systrap`. | 4KB Page (host dependent) | CI builds and tests the packages that `gvx` owns. |

---

## 2. Repository Layout and Upstream Synchronization Architecture

`gvx` tracks the pre-generated `go` branch of `https://github.com/google/gvisor.git` (`upstream/go`). Upstream publishes `go_stateify` and `go_marshal` output for both `amd64` and `arm64` directly to `upstream/go`, so `gvx` compiles with `go build` without Bazel.

```text
gvx/ (Fork of google/gvisor@go)
 ├── AGENTS.md                              # [NEW] Mandatory agent instructions and ASD-STE100 gates
 ├── README.md                              # [NEW] Project overview, quickstart, and build guide
 ├── UPSTREAM_COMMIT                        # [NEW] Pinned commit SHA from google/gvisor (go branch)
 ├── entitlements.plist                     # [NEW] com.apple.security.hypervisor entitlement for hvf
 ├── .github/workflows/                     # [NEW] ci.yml (every push) and e2e-images.yml (weekly registry gates)
 ├── docs/
 │   └── architecture.md                    # [NEW] Authoritative architecture and milestone plan
 ├── scripts/                               # [NEW] codesign-exec.sh (signs test binaries) and sync-upstream.sh
 ├── third_party/
 │   └── x_sys/                             # [NEW] golang.org/x/sys with Darwin and Windows additions (go.mod replace)
 ├── tools/
 │   └── upstream/                          # [NEW] Upstream sync, diff audit, import boundaries, and build-tag rewriter
 │       ├── main.go
 │       ├── patches.go
 │       ├── buildtag_allowlist.txt
 │       ├── boundaries.go
 │       ├── compare.go
 │       ├── sync.go
 │       └── diff_audit.go
 ├── cmd/
 │   └── rungv/                             # [NEW] Standalone CLI runner (run, pull, stub)
 │       └── main.go
 ├── internal/                              # [NEW] Test fixtures: testelf, testimage, systraptest, lockdownprobe
 ├── pkg/
 │   ├── gvx/                               # [NEW] Embeddable Go library API for host tools
 │   │   ├── sandbox.go
 │   │   ├── config.go
 │   │   ├── image.go
 │   │   ├── kernel_runner.go
 │   │   ├── stdio_device.go
 │   │   └── platform_systrap_{native,other}.go
 │   ├── oci/                               # [NEW] Multi-arch OCI puller and Tar-to-EROFS compiler
 │   │   ├── pull.go
 │   │   ├── tar2erofs.go
 │   │   ├── erofs_layout.go
 │   │   └── cache.go
 │   ├── netbackend/                        # [NEW] Dual-track Netstack egress & port forwarder
 │   │   ├── nat_forwarder.go
 │   │   ├── port_forwarder.go
 │   │   ├── dns_relay.go
 │   │   ├── wireguard_endpoint.go
 │   │   ├── wireguard_tun.go
 │   │   └── wireguard_bind.go
 │   ├── hostarch/
 │   │   └── hostarch_arm64_16k.go          # [NEW] Opt-in 16KB page size (-tags pagesize_16k) for the macOS systrap engine
 │   ├── sync/
 │   │   ├── futex_linux.go                 # [NEW] Linux SYS_FUTEX implementation
 │   │   ├── futex_windows.go               # [NEW] WaitOnAddress / WakeByAddressSingle bindings
 │   │   └── futex_darwin.go                # [NEW] XNU __ulock_wait / __ulock_wake bindings
 │   ├── memutil/
 │   │   ├── memfd_linux_unsafe.go          # Unmodified upstream memfd_create / mmap wrappers
 │   │   ├── memutil_windows.go             # [NEW] CreateFileMappingW + MapViewOfFile3 wrappers
 │   │   └── memutil_darwin.go              # [NEW] mmap(MAP_ANON) + mach_vm_remap wrappers
 │   ├── fd/
 │   │   ├── fd_windows.go                  # [NEW] Unified HostHandle wrapping Win32 HANDLE
 │   │   └── fd_darwin.go                   # [NEW] Unified HostHandle wrapping Darwin FD
 │   ├── hostlockdown/
 │   │   ├── lockdown_windows.go            # [NEW] RestrictedToken, Low Integrity, JobObject, Win32k block
 │   │   ├── lockdown_darwin.go             # [NEW] Seatbelt sandbox_init SBPL profile & RLIMIT_NPROC=0
 │   │   └── lockdown_other.go              # [NEW] Returns ErrUnsupported on other hosts
 │   └── sentry/
 │       ├── hostcpu/
 │       │   ├── hostcpu_windows.go         # [NEW] GetCurrentProcessorNumber binding
 │       │   └── hostcpu_darwin.go          # [NEW] Darwin CPU number binding
 │       ├── time/
 │       │   ├── calibrated_clock_windows.go # [NEW] QueryPerformanceCounter clock calibration
 │       │   └── calibrated_clock_darwin.go  # [NEW] mach_continuous_time clock calibration
 │       ├── pgalloc/
 │       │   ├── memory_file_windows.go     # [NEW] DiscardVirtualMemory / MEM_RESET page reclaim
 │       │   └── memory_file_darwin.go      # [NEW] madvise(MADV_FREE) page reclaim
 │       ├── platform/
 │       │   ├── whpx/                      # [NEW] Windows Hypervisor Platform backend (amd64 & arm64)
 │       │   │   ├── whpx.go
 │       │   │   ├── address_space.go
 │       │   │   ├── vcpu_amd64.go
 │       │   │   ├── vcpu_arm64.go
 │       │   │   ├── stubgen_x86.go         # Go generator for the in-partition amd64 stub
 │       │   │   └── stubgen_a64.go         # Go generator for the in-partition arm64 stub
 │       │   ├── hvf/                       # [NEW] macOS Hypervisor.framework backend (arm64 & amd64)
 │       │   │   ├── hvf.go
 │       │   │   ├── address_space.go
 │       │   │   ├── vcpu_darwin_arm64.go
 │       │   │   ├── vcpu_darwin_amd64.go
 │       │   │   ├── bluepill_arm64.go      # Go generator for the in-guest EL1 stub
 │       │   │   └── bluepill_x86.go        # Go generator for the in-guest Ring-0 stub
 │       │   └── systrap/                   # Unified systrap backend (Linux upstream + macOS/Windows siblings)
 │       │       ├── systrap.go             # Unmodified upstream Linux systrap implementation
 │       │       ├── systrap_xplat.go       # [NEW] Shared types: ProbeInfo, ErrUnavailable
 │       │       ├── platform_darwin.go     # [NEW] macOS arm64 platform, stub pool, and guest address range
 │       │       ├── address_space_darwin.go # [NEW] mach_vm_remap mappings, page-trap patcher, trampoline islands
 │       │       ├── patcher_arm64_xplat.go # [NEW] Lazy page-trap arm64asm 4B B trampoline island patcher
 │       │       ├── trampoline_darwin_arm64.s
 │       │       ├── systrap_windows.go     # [NEW] Returns ErrUnavailable
 │       │       ├── systrap_darwin_amd64.go # [NEW] Returns ErrUnavailable
 │       │       └── stub/                  # [NEW] C and assembly sources and the signed arm64 stub binary
 │       └── fsimpl/
 │           └── hostfs/                    # [NEW] Secure os.Root + .gvx_meta host mount (Windows, macOS, and Linux)
 │               ├── hostfs.go
 │               ├── inode_windows.go
 │               ├── inode_darwin.go
 │               └── posix_rename_windows.go
 └── e2e/                                   # [NEW] Unified OS-agnostic end-to-end test suite
     ├── sandbox_e2e_test.go
     └── gate_*_test.go                     # Milestone gates M2, M3, and M4
```

### 2.1 Layered Subsystem Map and Import Directionality

Each package owns one architectural boundary. Enforce top-down import directionality to keep Windows and macOS host APIs out of the pure-Go Sentry kernel.

| Package | Single Responsibility | Allowed Internal Imports | Forbidden Imports |
| :--- | :--- | :--- | :--- |
| `cmd/rungv` | Parses CLI flags (`run`, `pull`, `stub`) and starts a sandbox instance. | `pkg/gvx` | `pkg/sentry/*`, `WinHvPlatform.dll` |
| `pkg/gvx` | Coordinates `pkg/oci`, `pkg/netbackend`, `pkg/hostlockdown`, and Sentry boot. | `pkg/oci`, `pkg/netbackend`, `pkg/hostlockdown`, `pkg/sentry/*`, `pkg/fd`, `pkg/tcpip` | `cmd/*` |
| `pkg/oci` | Resolves `amd64`/`arm64` OCI manifests and compiles `.tar` layers into `.erofs` files. | `pkg/abi/linux` | `pkg/sentry/kernel`, `pkg/hostlockdown` |
| `pkg/netbackend` | Bridges `pkg/tcpip` to L4 Go `net` forwarders (`nat`) or L3 `wireguard-go` (`wg`). | `pkg/tcpip` | `pkg/sentry/kernel`, `WinHvPlatform.dll` |
| `pkg/hostlockdown` | Locks down the host process via Windows Tokens/JobObjects or macOS Seatbelt. | `golang.org/x/sys/windows`, `golang.org/x/sys/unix` | `pkg/sentry/*`, `pkg/tcpip` |
| `pkg/sentry/kernel` | Dispatches the OS-agnostic Linux task, signal, and syscall table (`amd64` & `arm64`). | `pkg/abi/linux`, `pkg/sentry/platform`, `pkg/sentry/vfs`, `pkg/sync` | `golang.org/x/sys/windows`, `pkg/hostlockdown` |
| `pkg/sentry/platform/whpx` | Executes guest Ring-3/EL0 code on Windows via `WinHvPlatform.dll` and 4KB EPT/Stage-2. | `pkg/sentry/platform`, `pkg/memutil`, `pkg/abi/linux`, `golang.org/x/sys/windows` | `pkg/sentry/kernel`, `pkg/sentry/vfs` |
| `pkg/sentry/platform/hvf` | Executes guest EL0/Ring-3 code on macOS via `Hypervisor.framework` and 4KB Stage-1/Stage-2. | `pkg/sentry/platform`, `pkg/memutil`, `pkg/abi/linux`, `golang.org/x/sys/unix` | `pkg/sentry/kernel`, `pkg/sentry/vfs` |
| `pkg/sentry/platform/systrap` | Executes guest code via in-place syscall patching, `sysmsg` shared memory, and isolated stub subprocesses across Linux, macOS, and Windows. | `pkg/sentry/platform`, `pkg/memutil`, `pkg/abi/linux`, `golang.org/x/arch/*` | `pkg/sentry/kernel`, `pkg/sentry/platform/whpx`, `pkg/sentry/platform/hvf` |
| `pkg/sentry/fsimpl/hostfs` | Mounts host `/workspace` via `os.Root`, `NtCreateFile`/`openat`, and `.gvx_meta`. | `pkg/sentry/vfs`, `pkg/abi/linux`, `pkg/fd`, `golang.org/x/sys/*` | `pkg/sentry/platform/*` |
| `pkg/sync`, `pkg/memutil`, `pkg/fd` | Provide host futexes, shared memory views, and host handles on Windows and macOS. | `golang.org/x/sys/windows`, `golang.org/x/sys/unix` | `pkg/sentry/*` |

`tools/upstream` enforces this table with `boundaries.go`. Sentry foundation packages such as `pkg/context`, `pkg/hostarch`, `pkg/usermem`, and `pkg/sentry/memmap` appear in every platform and VFS interface, so those packages import them. Each other import needs a reason-annotated exception in `boundaries.go`.

### 2.2 Three-Tier Upstream Isolation Model (Descriptive Module)

To prevent merge conflicts during continuous upstream pulls, `gvx` partitions all repository files into three strict isolation tiers.

| Isolation Tier | File Paths | Upstream Conflict Rate | Maintenance Mechanism |
| :--- | :--- | ---: | :--- |
| **Tier 1: Additive Directories** | `cmd/rungv/`, `pkg/gvx/`, `pkg/oci/`, `pkg/netbackend/`, `pkg/hostlockdown/`, `pkg/sentry/platform/whpx/`, `pkg/sentry/platform/hvf/`, `pkg/sentry/fsimpl/hostfs/`, `e2e/`, `internal/`, `scripts/`, `.github/`, `tools/upstream/`, `docs/` | `0.0%` | Owned exclusively by `gvx`; `upstream/go` never touches these paths. |
| **Tier 2: Sibling `_windows`, `_darwin`, & `_xplat` Files** | `pkg/sync/*_{windows,darwin}.go`, `pkg/memutil/*_{windows,darwin}.go`, `pkg/fd/*_{windows,darwin}.go`, `pkg/sentry/{pgalloc,time,hostcpu}/*_{windows,darwin}.go`, `pkg/sentry/platform/systrap/*_{windows,darwin,xplat}*` | `0.0%` | Placed alongside unmodified `*_linux.go` files; Go selects the target file by `GOOS` and `GOARCH`. |
| **Tier 3: Build-Tag & Seam Patches** | Pure-Go files listed in `tools/upstream/buildtag_allowlist.txt` and `io_uring` `-ENOSYS` stubs | `< 5.0%` | Re-applied automatically by `tools/upstream` (`//go:build linux \|\| windows \|\| darwin`) after every `git merge upstream/go`. |

The audit charges a file against the 5% ceiling only when its content differs from upstream. It reports files that `gvx` adds inside upstream directories separately. It also reports build-tag fences on Linux-only trees (`runsc`, `shim`, `pkg/sentry/fsimpl/gofer`) as a third number. A strict count that includes the fences is larger than the charged share, and the audit prints both.

```mermaid
flowchart LR
    Upstream["google/gvisor (go branch)"] -->|"1. git fetch upstream go"| Merge["2. git merge --no-commit upstream/go"]
    Merge -->|"3. go run ./tools/upstream -mode=retag"| Retag["Rewrite //go:build linux || windows || darwin"]
    Retag -->|"4. go run ./tools/upstream -mode=audit"| Audit["Assert touched upstream files < 5.0%"]
    Audit -->|"5. Update UPSTREAM_COMMIT"| Verify["Build & test on Windows and macOS (amd64 & arm64)"]
```

### 2.3 Upstream Diff and Synchronization Procedure (Procedural Module)

Run this procedure to audit the current upstream diff or merge new commits from `google/gvisor`.

> [!WARNING]
> Do not hand-edit `*_linux.go` files or scatter ad-hoc changes across pure-Go Sentry files. Unrecorded edits in Tier 3 files cause merge conflicts during upstream synchronization and violate the 5% diff ceiling. Register every build-tag change in `tools/upstream/buildtag_allowlist.txt`.

1. Register the upstream gVisor repository as the `upstream` Git remote.
2. Fetch the latest `go` branch from `upstream`.
3. Inspect the modified upstream file count and verify the `< 5.0%` budget against `UPSTREAM_COMMIT`.
4. Merge `upstream/go` without committing.
5. Run `tools/upstream` in `retag` mode to apply `//go:build linux || windows || darwin` to allowlisted files.
6. Run `tools/upstream` in `audit` mode to assert zero unauthorized edits in `*_linux.go` files.
7. Record the merged `upstream/go` SHA in `UPSTREAM_COMMIT` and verify all four Priority-0 targets and both Linux targets.

```bash
git remote add upstream https://github.com/google/gvisor.git 2>/dev/null || true
git fetch upstream go

# Merge new upstream commits and re-apply build tags
git merge --no-commit upstream/go
go run ./tools/upstream -mode=retag
go run ./tools/upstream -mode=audit -max-ratio=0.05   # add -offline to reuse the cached upstream archive
git rev-parse upstream/go > UPSTREAM_COMMIT

# Verify all four Priority-0 host targets and both Linux targets compile cleanly
GOOS=windows GOARCH=amd64 go build ./...
GOOS=windows GOARCH=arm64 go build ./...
GOOS=darwin  GOARCH=arm64 go build ./...
GOOS=darwin  GOARCH=amd64 go build ./...
GOOS=linux   GOARCH=amd64 go build ./...
GOOS=linux   GOARCH=arm64 go build ./...
```

---

## 3. Subsystem Porting Specifications

This section specifies the Windows and macOS APIs, `amd64` and `arm64` transitions, 4KB memory mapping decouplers, `systrap` in-place binary patchers, register preservation rules, network backends, OCI loaders, and security invariants.

### 3.1 Host OS Primitives and Build-Tag Decoupling (Descriptive Module)

Approximately 65% of gVisor (`pkg/sentry/kernel`, `pkg/sentry/arch`, `pkg/ring0`, `pkg/sentry/vfs`, `pkg/sentry/fsimpl/tmpfs`, `pkg/sentry/fsimpl/erofs`, `pkg/sentry/fsimpl/overlay`, and `pkg/tcpip`) contains OS-agnostic Go code supporting both `amd64` and `arm64`. `tools/upstream` expands the build tags on these pure-Go files to `//go:build linux || windows || darwin`, while `_windows.go` and `_darwin.go` files implement the host primitives.

| gVisor Package | Current Linux Dependency | Windows Implementation (`_windows.go`) | macOS Implementation (`_darwin.go`) |
| :--- | :--- | :--- | :--- |
| **`pkg/sync`** | `SYS_FUTEX` (`FUTEX_WAIT`, `FUTEX_WAKE`) | `WaitOnAddress`, `WakeByAddressSingle`, `WakeByAddressAll` (`api-ms-win-core-synch-l1-2-0.dll`). | `__ulock_wait` and `__ulock_wake` (`UL_COMPARE_AND_WAIT` in `libSystem.B.dylib`). |
| **`pkg/memutil` & `pgalloc`** | `memfd_create`, `SYS_MMAP`, `MADV_DONTNEED`, `FALLOC_FL_PUNCH_HOLE` | `CreateFileMappingW(INVALID_HANDLE_VALUE, ...)`, `MapViewOfFile3`, and `DiscardVirtualMemory` (`MEM_RESET`). | `mmap(MAP_ANON)`, `mach_vm_remap` (multi-view shared aliasing), and `madvise(MADV_FREE)`. |
| **`pkg/sentry/time` & `hostcpu`** | `clock_gettime(CLOCK_MONOTONIC)`, `getcpu` VDSO | `QueryPerformanceCounter` / `QueryPerformanceFrequency` and `GetCurrentProcessorNumber`. | `mach_continuous_time` / `clock_gettime_nsec_np` and `pthread_cpu_number_np`. |
| **`pkg/fd`** | Raw `int` FDs, `dup3`, `SCM_RIGHTS` | `HostHandle` wrapping `syscall.Handle` with explicit `Close()` ownership. | `HostHandle` wrapping Darwin file descriptors with `fcntl(F_DUPFD_CLOEXEC)`. |
| **`pkg/tcpip`** | `af_packet` / `tun` host links | Pure-Go Netstack routed via `pkg/netbackend` (`-net=nat` or `-net=wg`). | Pure-Go Netstack routed via `pkg/netbackend` (`-net=nat` or `-net=wg`). |
| **`pkg/abi/linux` & `sentry/arch`** | Pure Go (`amd64` & `arm64`) | Retain 100% unchanged; supports Linux `x86_64` and `aarch64` ABIs natively. | Retain 100% unchanged; supports Linux `aarch64` and `x86_64` ABIs natively. |
| **`pkg/sentry/syscalls`** | `io_uring` host passthrough | Return `-ENOSYS` on `io_uring_setup` and `io_uring_enter` to select Sentry `epoll`. | Return `-ENOSYS` on `io_uring_setup` and `io_uring_enter` to select Sentry `epoll`. |

### 3.2 Primary Hardware Hypervisor Engines: `platform/whpx` (Windows) and `platform/hvf` (macOS)

`platform/whpx` (Windows `WinHvPlatform.dll`) and `platform/hvf` (macOS `Hypervisor.framework`) share one architectural design across `amd64` and `arm64`. Both backends decouple Linux 4KB `mmap(MAP_FIXED)` mappings from the Windows 64KB allocation granularity and the Apple Silicon 16KB host page granularity. Both also use an in-partition Ring-0 (`amd64`) or EL1 (`arm64`) shared communication page to avoid per-syscall register API calls.

| Hypervisor Operation | Windows (`platform/whpx` on `amd64` & `arm64`) | macOS (`platform/hvf` on `arm64` & `amd64`) |
| :--- | :--- | :--- |
| **Privilege / OS Requirement** | Standard user token; `windows/arm64` verifies Windows 11 24H2 (`Build >= 26100.3915`) and `WHvCapabilityCodeFeatures.Arm64Support`. | Standard user token with ad-hoc `com.apple.security.hypervisor` signature (`codesign -s -`). |
| **Partition Creation** | `WHvCreatePartition` + `WHvSetupPartition` | `hv_vm_create(NULL)` |
| **4KB Page Granularity Mapping** | Allocates 64KB-aligned host arenas in `pgalloc.MemoryFile` and maps 4KB slices into hardware EPT via `WHvMapGpaRange`. | Maps 16KB host arenas into Stage-2 IPA with `HV_MEMORY_READ \| WRITE \| EXEC` via `hv_vm_map`, then enforces 4KB mappings and `R/W/X` permissions in Stage-1 (`TTBR0_EL1` with `TCR_EL1.TG0 = 0b00` 4KB granule). |
| **vCPU Execution Call** | `WHvRunVirtualProcessor(partition, vpIndex, ...)` | `hv_vcpu_run(vcpu)` on a dedicated worker thread per vCPU. The worker calls `runtime.LockOSThread()`, because a vCPU belongs to the thread that created it. |
| **Async Signal Preemption** | `WHvCancelRunVirtualProcessor(partition, vpIndex, 0)` | `hv_vcpus_exit(&vcpu, 1)` |
| **`amd64` Syscall Trap (`bluepill_x86.go`, `stubgen_x86.go`)** | Ring-3 `SYSCALL` enters Ring-0 `MSR_LSTAR`, spills syscall GPRs to `CommPage`, executes `HLT`. | Ring-3 `SYSCALL` enters Ring-0 `MSR_LSTAR`, spills syscall GPRs to `CommPage`, executes `HLT` / `VMCALL`. |
| **`arm64` Syscall Trap (`bluepill_arm64.go`, `stubgen_a64.go`)** | EL0 `SVC #0` enters EL1 `VBAR_EL1`, spills `X0..X8, SP_EL0, ELR_EL1, PSTATE` to `CommPage`, executes `HVC #1`. | EL0 `SVC #0` enters EL1 `VBAR_EL1`, spills `X0..X8, SP_EL0, ELR_EL1, PSTATE` to `CommPage`, executes `HVC #0`. |
| **Read-only File Mappings** | Maps read-only host views directly into the partition. | `hv_vm_map` rejects the read-only descriptor of an EROFS image. `hvf` copies those pages into immutable slab pages, and pgalloc memory files map directly. |
| **Unknown Exit Reason** | Not applicable. | `HV_EXIT_REASON_UNKNOWN` carries no information. The worker resumes the vCPU as it does after a cancellation, and `Switch` fails after 4096 consecutive unknown exits. |

```mermaid
sequenceDiagram
    participant Guest as Guest Ring-3 / EL0 ELF (amd64 or arm64)
    participant Stub as In-Partition Ring-0 LSTAR / EL1 VBAR Stub (bluepill_*.go, stubgen_*.go)
    participant Comm as Shared 4KB Comm Page (Host/Guest Mapped)
    participant HV as WinHvPlatform.dll (whpx) or Hypervisor.framework (hvf)
    participant Sentry as Go Sentry Kernel

    Guest->>Stub: Execute SYSCALL (amd64) / SVC #0 (arm64) or trigger Page Fault
    Stub->>Comm: Spill Fast-Path syscall GPRs (or full state on fault), RIP/ELR_EL1, RSP/SP_EL0
    Stub->>HV: Execute HLT (amd64) or HVC (arm64)
    HV-->>Sentry: Return from WHvRunVirtualProcessor / hv_vcpu_run
    Sentry->>Comm: Read spilled registers directly from shared page slice
    Sentry->>Sentry: Dispatch Linux syscall or resolve VMA page fault (PullFullState on clone/signal)
    Sentry->>Comm: Write updated return registers and PC/SP to Comm Page
    Sentry->>HV: Resume virtual processor
    HV->>Stub: Resume after HLT / HVC #0
    Stub->>Comm: Reload registers (and FSBase/GSBase/TPIDR_EL0/VRegs when FullStateChanged)
    Stub->>Guest: Return to user mode via SYSRETQ / IRETQ (amd64) or ERET (arm64)
```

#### Two-Stage 4KB Paging on Apple Silicon (`platform/hvf`) and 64KB-to-4KB Slicing on Windows (`platform/whpx`) (Descriptive Module)

Linux ELF64 binaries map `.text` (`R-X`) and `.data` (`RW-`) segments at 4KB (`0x1000`) file offsets and virtual address boundaries. On Windows, `VirtualAlloc(MEM_RESERVE)` and `MapViewOfFile3` require 64KB (`0x10000`) alignment. `platform/whpx` resolves this by allocating large 64KB-aligned backing arenas in `pgalloc.MemoryFile` and invoking `WHvMapGpaRange(partition, hostVA, guestPA, 4096, flags)` to inject 4KB mappings and permissions directly into the hardware EPT/Stage-2 tables.

On Apple Silicon macOS (`darwin/arm64`), the host XNU kernel and `hv_vm_map()` operate on 16KB (`0x4000`) pages. `platform/hvf` resolves this using the two-stage ARM64 MMU (`GVA` to Stage-1 `TTBR0_EL1` 4KB, then `IPA` to Stage-2 `hv_vm_map` 16KB, then `HPA`). Stage-2 maps 16KB host arena blocks into IPA space with permissive `HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC` rights. Inside the vCPU, the `bluepill` stub configures `TCR_EL1.TG0 = 0b00` (4KB granule) and populates 4KB Stage-1 page table entries in `TTBR0_EL1` with exact `R-X` or `RW-` (`UXN=1`) permissions. Because the ARM64 MMU enforces the intersection of Stage-1 and Stage-2 permissions, the hardware traps permission violations at exact 4KB boundaries.

### 3.3 Unified User-Mode Fallback Engine: `pkg/sentry/platform/systrap` (`winsystrap` & `darwinsystrap`) (M5)

`pkg/sentry/platform/systrap` registers the `"systrap"` backend. Linux uses the upstream implementation. macOS `arm64` uses the `darwinsystrap` engine of `gvx`. Windows (`winsystrap`) is not implemented. The engine executes guest ELF64 code and in-guest JIT code (V8) directly on the host CPU at native speed without basic-block translation or instruction emulation.

#### Multi-Process Hardware Page-Table (`CR3` / `TTBR0_EL1`) Isolation and `sysmsg` IPC (Descriptive Module)

Running untrusted guest instructions inside the Sentry process without SFI masking would expose the Go runtime heap to arbitrary pointer writes. To preserve hardware MMU isolation (`CR3` on `amd64`, `TTBR0_EL1` on `arm64`) without a hypervisor, `platform/systrap` spawns an untrusted stub template process (`gvx-stub-darwin-arm64`) before `hostlockdown.Apply()` executes. The template forks one stub task for each address space.

The stub subprocess contains no Go runtime, zero file descriptors, and zero network sockets, and is locked inside a Windows Job Object or macOS Seatbelt profile. Sentry and the stub subprocess share a `sysmsg` shared-memory region (`CreateFileMappingW` + `MapViewOfFile3` on Windows; `mmap` + `mach_vm_remap` on macOS). When guest code reaches a patched syscall site, the stub spills guest registers into its per-thread `Sysmsg` slot, wakes the Sentry thread via `WakeByAddressSingle` (Windows) or `__ulock_wake` (macOS), and waits on `WaitOnAddress` or `__ulock_wait` with zero kernel socket or pipe IPC.

| `systrap` Subsystem | Windows (`winsystrap`: `amd64` & `arm64`), not implemented | macOS (`darwinsystrap`): `arm64` implemented, `amd64` dropped |
| :--- | :--- | :--- |
| **Page Granularity** | Reserves 64KB regions with `VirtualAlloc(MEM_RESERVE, PAGE_NOACCESS)` and commits 4KB slices via `VirtualAlloc(addr, 4096, MEM_COMMIT, PAGE_READWRITE)`. | Needs `hostarch.PageSize` equal to the 16KB host page, so it requires `-tags pagesize_16k`. A build without the tag returns `*ErrUnsupportedPageSize`. The guest sees 16KB pages, and `mach_vm_remap` maps memory-file ranges into the stub task. |
| **Guest Address Range** | Not specified. | The range starts above the permanent `PROT_NONE` reservations of the host, which the Sentry reads from the template task. It ends below the `sysmsg` blocks. A Linux `ET_EXEC` image at `0x400000` does not load. |
| **Lazy Execute Page-Trap** | Maps `PROT_EXEC` pages initially as `PAGE_READONLY`; on `EXCEPTION_ACCESS_VIOLATION` (`EXCEPTION_EXECUTE_FAULT`), disassembles from verified `RIP`/`PC` and `.eh_frame` CFG boundaries, patches syscalls, and promotes to `PAGE_EXECUTE_READ`. | Maps `PROT_EXEC` pages read-only. On an instruction abort, the Sentry patches a private copy, flushes the instruction cache with `sys_icache_invalidate`, and promotes the page to `PROT_READ \| PROT_EXEC`. It rewrites only words inside ELF executable sections, because a data word can look like an instruction. |
| **`amd64` Zero-Exception Syscall Patching** | Pattern A (95%): 5-byte `E9 <rel32>` (`jmp stub`) over `mov eax, imm32; syscall` (7B) or `syscall; cmp rax, -4095` (8B). Pattern B (4.9%): 2-byte `EB <rel8>` springboard to function-end `NOP` padding (`±127B`) chained to `E9 <rel32>`. Pattern C (<0.1%): `CC 90` (`int3`). | Not applicable. |
| **`arm64` Trampoline Island & I-Cache Flush** | Allocates a 4KB Trampoline Island within `±128 MB` of each executable VMA, atomically replaces 4-byte `svc #0` (`0xD4000001`) with `B <island_slot>` (`0x14000000 \| imm26`) without clobbering `X30 (LR)`, and calls `FlushInstructionCache`. | Reserves an island through `mm.MMap` within `±120 MB` of the patched page. It replaces `svc #0` with `B <island_slot>` without clobbering `X30 (LR)`. The same patcher rewrites `mrs` and `msr` of `TPIDR_EL0`, reads of `CTR_EL0`, and every instruction that names `X18`. |
| **Register Virtualization** | Not specified. | The kernel clobbers `TPIDR_EL0` on preemption and zeroes `X18` on every return from an exception. The `sysmsg` block holds both guest values, and patched slots read and write them there. |
| **Unpatched Syscall Safety Net** | Registers `ProcessInstrumentationCallback` (`NtSetInformationProcess` Class 40 Nirvana Hook) to intercept any unpatched `0F 05` (`*(uint16*)(R10 - 2) == 0x050F`), patch it in-place, and replay the Linux syscall. | Each stub task applies a strict Seatbelt profile that allows only the host system calls that the stub needs. The kernel kills the stub on any other call, and the Sentry reports a dead stub. A Mach exception port cannot replay an unpatched `svc #0`, because XNU runs it as a host system call. |
| **Cross-Arch Container Execution** | Running `GOARCH=amd64` `rungv` (`-platform=systrap`) on `windows/arm64` would invoke Windows 11 24H2 Prism. Not implemented. | Dropped. Rosetta 2 would run a translated stub, and a syscall-number Seatbelt filter on a translated process panicked the host kernel. |

```mermaid
sequenceDiagram
    participant Guest as Guest ELF / V8 JIT Page (Stub Process)
    participant Island as 4KB Trampoline Island / Springboard Stub
    participant Sysmsg as Shared Sysmsg Context Page (MapViewOfFile3 / mach_vm_remap)
    participant Sentry as Go Sentry Kernel Process

    Note over Guest,Sentry: First Execution of a PROT_EXEC Page (Lazy Page-Trap)
    Guest->>Sentry: Execute-Fault on PAGE_READONLY / PROT_READ Page (Verified RIP/PC)
    Sentry->>Guest: Disassemble via x86asm/arm64asm (.eh_frame CFG) & Patch 0F 05 / svc #0 in-place
    Sentry->>Guest: Flush I-Cache (arm64) & Promote Page to EXECUTE_READ

    Note over Guest,Sentry: Subsequent Syscalls (Zero-Exception Fast Path)
    Guest->>Island: In-Place 5B JMP / 2B Springboard (amd64) or 4B B <island_slot> (arm64, X30 intact)
    Island->>Sysmsg: Spill GPRs (incl. RCX, R11, X18), Flags, TLS, and XSAVEOPT / V0..V31
    Island->>Sentry: Wake Sentry via WakeByAddressSingle / __ulock_wake & Wait
    Sentry->>Sysmsg: Read Syscall Args, Dispatch Linux Syscall, Write Return Value
    Sentry->>Island: Wake Stub Thread via WakeByAddressSingle / __ulock_wake
    Island->>Sysmsg: Reload Guest Registers & TLS
    Island->>Guest: Jump to Return Address (PC + 2 on amd64 / PC + 4 on arm64)
```

### 3.4 Register Preservation and Two-Tier Synchronization Contract (Linux ELF & Wine / WoW64 / ARM64EC) (Descriptive Module)

A Linux `syscall` (`amd64`) or `svc #0` (`arm64`) is a kernel trap, not a C function call. Guest compilers, `glibc`/`musl`, and Wine assume that every general-purpose register (except the return register and hardware-clobbered `RCX`/`R11` on `amd64` `syscall`) and every 128-bit/256-bit SIMD/FP vector register (`XMM`/`YMM`, `V0..V31`) remain 100% intact across system calls and page faults. Because the host Go runtime overwrites SIMD registers (`XMM`/`YMM` and `V0..V31`) during `copy`, `memmove`, and string operations, entering Go without isolating guest vector and TLS state causes silent memory corruption.

#### Mandatory Preserved Register Sets for `amd64` and `arm64` (Reference Module)

Every execution backend (`whpx`, `hvf`, and `systrap`) must preserve these architectural registers across transitions to support standard Linux ELF64 workloads, Ubuntu 24.04+ PAC binaries, and Wine (`wine64`, WoW64, and `arm64ec`).

| Architecture & Category | Register Set | Linux ELF & Wine / WoW64 / ARM64EC Preservation Rule |
| :--- | :--- | :--- |
| **`amd64` Syscall & Callee GPRs** | `RAX`, `RDI`, `RSI`, `RDX`, `R10`, `R8`, `R9`, `RBX`, `RBP`, `R12..R15`, `RIP`, `RSP`, `RFLAGS` | Sync syscall arguments/return on every syscall; preserve `RBX`, `RBP`, and `R12..R15` without modification across all transitions. |
| **`amd64` Trap-Clobbered GPRs** | `RCX`, `R11` | Hardware `syscall` clobbers `RCX` (`RIP`) and `R11` (`RFLAGS`), but page faults (`#PF`), asynchronous signals, and Wine `int 0x80` traps must preserve the original `RCX` and `R11` values. |
| **`amd64` Dual TLS & Segments** | `FSBase`, `GSBase` (`KernelGsBase`), `CS`, `SS`, `DS`, `ES`, `FS`, `GS` | `wine64` uses `FSBase` for Linux TLS and `GSBase` for the 64-bit Windows TEB; WoW64 switches between `CS=0x23` (32-bit compatibility mode) and `CS=0x33` (64-bit mode). Preserve both TLS bases and all segment selectors. |
| **`amd64` Vector, FP Control & Debug** | `XMM0..15`, `YMM0..15`, `x87 ST0..7`, `MXCSR`, `FCW`, `FSW`, `DR0..DR7` | Protect guest SIMD/x87 state and rounding/denormal control words (`MXCSR`, `FCW`) from the Go runtime; expose `DR0..DR7` for `ptrace` and Wine `GetThreadContext` / `SetThreadContext`. |
| **`arm64` General & Syscall GPRs** | `X0..X8`, `X9..X17`, `X19..X30 (LR)`, `SP (SP_EL0)`, `PC`, `PSTATE (NZCV)` | Although AAPCS64 treats `X9..X17` as caller-saved in C calls, `svc #0` and page faults must preserve all of `X1..X30` (`OrigR0` saved separately for syscall restart). |
| **`arm64` Platform Register `X18`** | `X18` | macOS and Windows ARM64 reserve `X18` on the host, while Windows ARM64 / Wine `arm64ec` stores the guest TEB pointer in `X18`. Isolate guest `X18` from host `X18` on every transition. |
| **`arm64` Dual TLS & PAC Keys** | `TPIDR_EL0`, `TPIDRRO_EL0`, `APIAKeyLo/Hi_EL1` (`HWCAP_PACA`) | Preserve both `TPIDR_EL0` (Linux TLS) and `TPIDRRO_EL0` (Wine/auxiliary thread ID). Mask `HWCAP_PACA`/`HWCAP_PACG` in `AT_HWCAP` or preserve PAC key registers so Ubuntu 24.04+ `paciasp`/`autiasp` instructions never fault with `SIGILL`. |
| **`arm64` Full 128-bit NEON/FP & Debug** | `V0..V31` (full 128-bit `Q0..Q31`), `FPCR`, `FPSR`, `DBGBVR/BCR0..15`, `DBGWVR/WCR` | Preserve all 32 128-bit vector registers (`512B`) plus `FPCR`/`FPSR` across syscalls and signals, and map hardware debug registers for `ptrace` and Wine thread contexts. |

#### Two-Tier Lazy Synchronization in `whpx` and `hvf` vs. Full Trampoline Save in `systrap` (Procedural Module)

Follow these synchronization rules in `platform/whpx`, `platform/hvf`, and `platform/systrap`:

> [!CAUTION]
> Always call `runtime.LockOSThread()` at the start of `Context.Switch()` before invoking `hv_vcpu_run`, `WHvRunVirtualProcessor`, or entering a `systrap` trampoline. Calling `hv_vcpu_run` from a migrated OS thread returns `HV_ERROR` immediately, and entering Go with guest `FSBase`, `GSBase`, `X18`, or `MXCSR` crashes the Go runtime.

1. In `platform/whpx` and `platform/hvf` Fast-Path transitions (standard system calls), read and write only the syscall argument/return GPRs, `PC`, `SP`, and `PSTATE`/`RFLAGS` in `CommPage` while leaving `XSAVE`/`V0..V31`, `FSBase`/`GSBase`, and `DR0..DR7` inside the hardware vCPU.
2. In `platform/whpx` and `platform/hvf` Medium/Cold-Path transitions (`PullFullState` and `FullStateChanged` on `clone`, signal delivery, page faults, `arch_prctl`, and `ptrace` / Wine context queries), synchronize all GPRs (`RCX`, `R11`, `X18`), dual TLS bases, segment selectors, full 512-byte `V0..V31` / `XSAVE` state (`ac.FloatingPointData()`), `FPCR`/`FPSR`/`MXCSR`/`FCW`, and debug registers.
3. In `platform/systrap` trampolines, spill all GPRs (`RAX..R15` including `RCX` and `R11` on `amd64`; `X0..X30` including `X18` on `arm64`), flags, dual TLS pointers, and vector state (`XSAVEOPT` on `amd64` or `STP Q0..Q31` on `arm64`) into the `Sysmsg` context before restoring host `FSBase`/`GSBase`/`X18`/`MXCSR` and waking the Sentry thread.

Two implementations deviate from this contract for stated reasons. `hvf` loads and stores the general and FP registers from `arch.Context64` on every `Switch`, because `Hypervisor.framework` ties a vCPU to its host thread. `systrap` on macOS keeps guest `X18` in the `sysmsg` block and rewrites each instruction that names it, because XNU zeroes `X18` on every return from an exception. `hvf` does not synchronize `TPIDRRO_EL0`, the PAC keys, or the debug registers.

### 3.5 Dual-Track Netstack Backend and Port Forwarding: `pkg/netbackend`

Guest applications (`nginx`, `postgres`, `git`, `curl`, `omp`, `herdr`) invoke `socket()`, `connect()`, `bind()`, and `epoll_wait()` against gVisor's pure-Go `pkg/tcpip` (Netstack). Netstack implements the virtual Linux network interface (`eth0`), loopback (`lo`), TCP 3-way handshakes, sliding windows, and packet retransmission in memory. `pkg/netbackend` is 100% OS-agnostic Go code and runs identically on Windows and macOS.

| Egress Attribute | Track A: Go `net` NAT & Port Forwarder (`-net=nat`, Default) | Track B: In-Memory WireGuard (`-net=wg`) |
| :--- | :--- | :--- |
| **Interception Layer** | L4 Transport Layer (`tcp.NewForwarder`, `udp.NewForwarder`, `gonet.DialTCP`) | L3 Network Layer (`channel.Endpoint` to `wireguard-go`) |
| **Packet / Stream Path** | Dials outbound via host `net.DialContext` and forwards inbound `-p host:guest` listeners via `gonet.DialTCP`. | Encrypts raw IP packets in memory and transmits via one pre-bound host UDP socket. |
| **Admin / Driver Needed** | None (Standard unprivileged host sockets on Windows IOCP and macOS `kqueue`) | None (Pure in-memory link; no `WinTun.dll` or `/dev/tun`) |
| **Local / LAN Access** | Permitted by default (maps `10.0.2.2` / `host.docker.internal` to host `127.0.0.1`; optional `-isolate-lan` flag). | Enforced cryptographically; packets exit only through the WireGuard tunnel. |
| **Primary Workload** | Unmodified OCI containers (`-p 8080:80`), local dev tools (`git`, `omp`), and L4/L7 API key proxies. | Enterprise LAN isolation, multi-sandbox mesh, and remote `herdr` cluster links. |

```mermaid
flowchart LR
    HostPort["Host Listener (-p 8080:80)"] -->|"gonet.DialTCP (Inbound)"| Netstack["pkg/tcpip (Pure-Go Netstack eth0 & lo)"]
    Guest["Guest App (nginx, git, omp, herdr)"] -->|"socket / bind / connect"| Netstack
    Netstack -->|"Track A (-net=nat): L4 tcp.NewForwarder"| NAT["nat_forwarder.go (Outbound Dial + 10.0.2.2 Host Gateway)"]
    NAT -->|"net.DialContext"| GoNet["Go Runtime Poller (Windows IOCP / macOS kqueue)"]
    Netstack -->|"Track B (-net=wg): L3 channel.Endpoint"| WG["wireguard-go (In-Memory ChaCha20-Poly1305)"]
    WG -->|"Single Pre-Opened UDP Socket"| UDP["Encrypted WireGuard / Tailscale Peer"]
```

#### Track A: L4 Go `net` Forwarder and Bidirectional Port Forwarding (`nat_forwarder.go`, `port_forwarder.go`) (Descriptive Module)

In `-net=nat` mode, `nat_forwarder.go` registers `tcp.NewForwarder` and `udp.NewForwarder` handlers on the Netstack instance. When a guest process connects to an external address or local LAN host, Netstack completes the virtual TCP handshake and invokes the forwarder callback. Outbound connections to `10.0.2.2` (`host.docker.internal`) route to the host loopback (`127.0.0.1`). Guest `127.0.0.1` traffic remains isolated on the container's internal `lo` interface. Callers can pass the optional `-isolate-lan` flag when they wish to block RFC1918 and host loopback ranges.

For inbound port forwarding (`-p hostPort:guestPort`), `port_forwarder.go` binds host `net.Listener` and `net.PacketConn` sockets before `hostlockdown.Apply()` executes. When a host client connects to a published port (`127.0.0.1:8080`), `port_forwarder.go` calls `gonet.DialTCP` into Netstack (`10.0.2.15:80`) and relays both streams. Go's `internal/poll` runtime multiplexes host sockets over Windows IOCP and macOS `kqueue` without custom C socket loops. Optional L4/L7 stream interceptors attach at the outbound forwarder boundary to inject host-held LLM API keys without exposing secrets inside the guest environment.

A DNS relay (`dns_relay.go`) answers guest queries to `10.0.2.3` through the host resolvers. The relay reads the resolver addresses before `hostlockdown.Apply()` executes, because the macOS profile denies `getaddrinfo` and reads of `/etc/resolv.conf` afterwards. The relay has no fixed public resolver address.

#### Track B: L3 In-Memory WireGuard Tunnel (`wireguard_endpoint.go`) (Descriptive Module)

In `-net=wg` mode, `wireguard_endpoint.go` attaches a Netstack `channel.Endpoint` (MTU 1420) directly to `golang.zx2c4.com/wireguard/device` in Go memory. `wireguard_tun.go` adapts the endpoint to a `tun.Device`, and `wireguard_bind.go` adapts the pre-bound socket to a `conn.Bind`. Before `hostlockdown.Apply()` locks down the process, `wireguard_endpoint.go` opens one host UDP socket (`net.ListenPacket("udp", ":0")`) and passes it to the WireGuard bind interface. Outbound guest IP packets enter `wireguard-go` in memory for ChaCha20-Poly1305 encryption. Encrypted packets exit exclusively through that pre-bound UDP socket to the configured WireGuard or Tailscale peer.

### 3.6 Unmodified Multi-Arch OCI Image Runner: `pkg/oci`

Extracting Linux container layers (`.tar.gz`) directly onto Windows NTFS or case-insensitive macOS APFS breaks case-sensitive filenames (`xt_CONNMARK.h` vs. `xt_connmark.h`), fails on reserved Windows names (`CON`, `AUX`, `NUL`, `:`), discards POSIX `uid/gid` ownership, and requires elevated privileges for device nodes or symbolic links. `pkg/oci` runs unmodified OCI and Docker images on both Windows and macOS by compiling layer tarballs in memory into cached EROFS images.

```mermaid
flowchart LR
    Source["OCI Registry (linux/amd64 or linux/arm64) or .tar"] -->|"1. Select Host GOARCH Manifest"| Tar2Erofs["pkg/oci/tar2erofs.go (In-Memory Stream Compiler)"]
    Tar2Erofs -->|"2. Write Single Binary File"| Cache["Host Cache Dir (<sha256>.gvx-erofs-v3-b<block>.erofs)"]
    Cache -->|"3. Pre-Lockdown os.Open"| Overlay["Sentry VFS2 fsimpl/overlay (tmpfs Upper + EROFS Lower Layers)"]
```

#### Tar-to-EROFS Layer Compilation and Overlay Mount (Procedural Module)

Execute these steps in `pkg/oci` before calling `hostlockdown.Apply()`:

1. Resolve the OCI Image Index and select the manifest matching `linux/amd64` or `linux/arm64` for the target guest architecture. Verify the manifest digest and every layer digest.
2. Parse `Entrypoint`, `Cmd`, `Env`, `WorkingDir`, and `User` from the OCI image configuration JSON.
3. Stream each `.tar.gz` or `.tar.zst` layer in memory through `tar2erofs.go` without extracting files onto NTFS or APFS. Decode zstd with `github.com/klauspost/compress/zstd` under bounded window and output limits.
4. Convert OverlayFS whiteout markers (`.wh.<name>` and `.wh..wh..opq`) into native EROFS whiteout nodes and the `trusted.overlay.opaque` attribute on opaque directories.
5. Write each compiled layer to the non-TCC cache directory (`%LOCALAPPDATA%\gvx\cache\layers\` on Windows; `~/Library/Caches/gvx/layers/` on macOS). Name the file `<sha256>.gvx-erofs-v3-b<block>.erofs`. The block size equals `hostarch.PageSize`, which is 4096 by default and 16384 with `-tags pagesize_16k`. A `.sum` record next to the file proves its integrity.
6. Open read-only `os.File` handles for all cached `.erofs` layers before calling `hostlockdown.Apply()`.
7. Mount the `.erofs` handles as ordered read-only lower layers under Sentry's `fsimpl/overlay` with `fsimpl/tmpfs` as the writable upper layer.

### 3.7 Secure Host File System Driver: `pkg/sentry/fsimpl/hostfs`

`fsimpl/hostfs` replaces `pkg/sentry/fsimpl/gofer` (`lisafs`) to mount the host `/workspace` directory on Windows and macOS without spawning an external file-server process. It also runs on Linux, where it uses `os.Root` and `openat` in the same way.

#### Handle-Scoped Traversal and POSIX Adaptation (Descriptive Module)

`hostfs` anchors the workspace mount using Go 1.25+ `os.OpenRoot(hostWorkspacePath)` before sandbox lockdown. On Windows (`inode_windows.go`), every file open invokes `NtCreateFile` with `OBJECT_ATTRIBUTES.RootDirectory` pinned to the `os.Root` handle and enforces `FILE_OPEN_REPARSE_POINT`. On macOS (`inode_darwin.go`), `os.OpenRoot` uses `openat(dirfd, ..., O_NOFOLLOW | O_SYMLINK)` so the XNU kernel never traverses symbolic links or firmlinks pointing outside `/workspace`.

On Windows, `hostfs` sets `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE` on every open. It implements `rename(2)` on open files via `NtSetInformationFile(FileRenameInformationEx)` with `FILE_RENAME_POSIX_SEMANTICS`, and `unlink(2)` via `FileDispositionInfoEx`. NTFS refuses to rename a directory that has an open descendant, and the guest then sees `EACCES`. On macOS, `hostfs` uses native `renameat` and `unlinkat` scoped to directory file descriptors. On both platforms, an in-memory xattr table stores virtual POSIX mode bits (`0755`), `uid/gid`, and intra-workspace symlinks. It persists this table atomically to `.gvx_meta`.

A guest `mmap` of a workspace file reads the file in 64KiB chunks. The hardware backends and the macOS `systrap` engine map a guest page by host pointer, so `hostfs` keeps each chunk on the Go heap. The upstream Linux `systrap` platform runs guest code in stub processes and maps a guest page by the descriptor of a memory file. On Linux, `pkg/gvx` therefore passes the kernel memory file to `Workspace.SetChunkMemory`, and `hostfs` allocates each chunk there. `hostfs` invalidates the mappings of a truncated file before it drops its reference to a chunk.

### 3.8 Host Self-Lockdown and Security Model: `pkg/hostlockdown`

`gvx` enforces a three-ring defense-in-depth security model against untrusted guest code.

| Security Ring | Boundary Owner | Enforced Invariant |
| :--- | :--- | :--- |
| **Ring 1: Execution Boundary** | `platform/whpx`, `platform/hvf`, `platform/systrap` | Isolates guest execution inside hardware 4KB EPT/Stage-1 tables or an untrusted `systrap` stub process (`CR3`/`TTBR0_EL1`) with zero direct host syscall access. |
| **Ring 2: Application Kernel** | `pkg/sentry/kernel`, `fsimpl/hostfs`, `pkg/netbackend` | Services ~250 Linux syscalls in memory-safe Go and scopes all `/workspace` opens to the `os.Root` handle. |
| **Ring 3: Host OS Containment** | `pkg/hostlockdown` (Windows NT, macOS XNU, and Linux seccomp) | Applies host containment before guest entry. Windows restricts file access on bound vCPU threads. Linux retains path limitations with a workspace. |

```mermaid
stateDiagram-v2
    [*] --> PreInit: Launch rungv or pkg/gvx (Unprivileged User Account)
    PreInit --> HandlesOpen: Open Hypervisor (WHPX/HVF) or Pre-Spawn systrap Stub, .erofs Layers, Sockets, and /workspace os.Root
    HandlesOpen --> WinLockdown: Windows: In-Place SE_PRIVILEGE_REMOVED + Low Integrity + Deny-Only SID + JobObject + NoWin32k
    HandlesOpen --> MacLockdown: macOS: sandbox_init Seatbelt Profile (deny process-fork/exec/file-*) + RLIMIT_NPROC=0
    HandlesOpen --> LinuxLockdown: Linux: PR_SET_NO_NEW_PRIVS + seccomp allowlist of the runsc Sentry on every thread (other calls kill the process)
    WinLockdown --> GuestRunning: Enter Guest ELF Entrypoint (amd64 or arm64)
    MacLockdown --> GuestRunning: Enter Guest ELF Entrypoint (arm64 or amd64)
    LinuxLockdown --> GuestRunning: Enter Guest ELF Entrypoint (amd64 or arm64)
```

#### Windows Lockdown Sequence (`lockdown_windows.go`) (Procedural Module)

Execute these steps in `lockdown_windows.go` before starting virtual processor or `systrap` execution:

> [!IMPORTANT]
> Open the WHPX partition, cached layers, network sockets, and workspace before calling `hostlockdown.Apply()`.
> The Job Object blocks child creation.
> Only threads that call `BindThread` receive the restricted token.

1. Apply an inheritable Low-Integrity ACE (`S-1-16-4096`) to writable `/workspace` directories so Windows MIC permits guest writes after token downgrade.
2. Open the live primary process token (`OpenProcessToken`) and call `AdjustTokenPrivileges` with `SE_PRIVILEGE_REMOVED` to delete all privileges in-place.
3. Call `SetTokenInformation(hPrimaryToken, TokenIntegrityLevel, ...)` to lower the live primary token integrity level to `Low` (`S-1-16-4096`) in-place.
4. Create a `DISABLE_MAX_PRIVILEGE` restricted token with `SE_GROUP_USE_FOR_DENY_ONLY` and bind it to each vCPU thread via `SetThreadToken`.
5. Create an anonymous Job Object with `CreateJobObjectW` and assign the current process via `AssignProcessToJobObject`.
6. Set `JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 1` and `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION` on the Job Object to block child process creation (`cmd.exe`, `powershell.exe`).
7. Set `JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_READCLIPBOARD | JOB_OBJECT_UILIMIT_WRITECLIPBOARD` to isolate host UI handles and the clipboard.
8. Call `SetProcessMitigationPolicy(ProcessSystemCallDisablePolicy, ...)` with `DisallowWin32kSystemCalls = 1` to block `win32kfull.sys` system calls.

#### Windows Lockdown Limits (Descriptive Module)

The restricted token applies only to threads that call `BindThread`. Other Go threads can still read outside the workspace. Windows does not enforce the network options at the host boundary.

#### macOS Lockdown Sequence (`lockdown_darwin.go`) (Procedural Module)

Execute these steps in `lockdown_darwin.go` after opening the `Hypervisor.framework` VM (or pre-spawning the `systrap` stub subprocess and Mach exception ports), cached `.erofs` layer descriptors, network sockets, and `/workspace` `os.Root` descriptor:

1. Call `setrlimit(RLIMIT_NPROC, &rlimit{Cur: 0, Max: 0})` to block `fork()` at the XNU kernel boundary.
2. Call `sandbox_init_with_parameters` with the Seatbelt `deny default` profile to block `process-fork`, `process-exec*`, and new host file opens.
3. Probe that each denial holds. `Apply` returns an error when a probe succeeds.

`rungv` and `pkg/gvx` enable the lockdown by default. The option `-lockdown=false` opts out and prints a warning. The `systrap` stub applies its own, stricter profile in each forked task. The profile allows the MIG routine `mach_exception_raise`, because macOS 15 counts the delivery of a guest fault to a signal handler as that routine.

#### Linux Lockdown Sequence (`lockdown_linux.go` and `syscallfilter_linux.go`) (Procedural Module)

Execute these steps after the `systrap` platform, the cached `.erofs` layer descriptors, the network sockets, and the `/workspace` directory exist. The lockdown reuses the seccomp allowlist of the gVisor Sentry in `runsc/boot/filter`. `pkg/hostlockdown` must not import the Sentry. Therefore `pkg/gvx` builds the program and passes it in `Options.InstallSyscallFilter`.

1. Build the rules with `config.Rules`. Pass the `SeccompInfo` of the `systrap` platform. Enable the host network rules for `-net=nat`. Enable the host filesystem rules when a workspace exists.
2. Merge the embedder rules of `gvx`. They allow `fcntl` with close-on-exec, `renameat`, and `sched_getaffinity`. NAT adds sockets with protocol 0. WireGuard adds `sendto` and `recvfrom`.
3. Add a last rule set that returns `EPERM` for `execve`, `execveat`, `clone`, `openat`, and `socket`. It applies only when no allow rule matched. Every other call outside the allowlist kills the process.
4. Install the program on every thread with `seccomp(SECCOMP_FILTER_FLAG_TSYNC)`. The call sets `PR_SET_NO_NEW_PRIVS` first.
5. Probe the result. `execve` and `clone` must fail with `EPERM`. An `openat` relative to the working directory must fail with `EPERM`. A TCP `socket` must fail unless the options allow outbound traffic.

#### Linux Lockdown Limits (Descriptive Module)

Seccomp reads no path. A workspace needs `openat` relative to a directory descriptor, and that call can open an absolute path. gVisor closes this gap with a mount namespace and `chroot`. A library cannot create them without privilege, because the Go runtime runs many threads. `Status.UnboundFileOpenBlocked` is therefore false on Linux when a workspace exists.

Seccomp cannot read a socket address. The filter cannot pin the WireGuard peer port the way the Seatbelt profile does. The `EPERM` rule set keeps the process alive where `runsc` kills it. Code in the embedding process then sees an error from `os/exec`, `os.Open`, or `net.Dial`. The Go runtime also opens cgroup files once a second to adjust `GOMAXPROCS`, and it accepts a failure.

The upstream `systrap` platform hangs while it starts in a cgo build. `New` returns `ErrPlatformUnavailable` there, and race builds use cgo. Build with `CGO_ENABLED=0`. A missing rule kills the process. Run `scripts/seccomp-audit.sh` to list the calls that the allowlist lacks. It builds with the tag `gvx_seccomp_log`, which logs those calls and allows them.

---

## 4. Milestone Roadmap and Verification Criteria

Implementation proceeds across five sequential milestones (`M1` through `M5`) targeting both Windows (`amd64`, `arm64`) and macOS (`arm64`, `amd64`) as Priority-0 platforms. Linux (`amd64`, `arm64`) is an official platform that CI verifies on every push.

| Phase | Milestone | Key Deliverables | Verification Gate |
| :--- | :--- | :--- | :--- |
| **M1** | **Host Primitives & Pure-Go Sentry Compile** | `pkg/sync` (`WaitOnAddress` & `__ulock_wait`), `pkg/memutil` (`MapViewOfFile3` & `mach_vm_remap`), `pkg/fd`, `pgalloc`, `time`, `hostcpu`, `tools/upstream`, and Sentry build-tag expansion (`linux \|\| windows \|\| darwin`). | `go build ./pkg/sentry/kernel/...` and primitive unit tests pass on `windows/{amd64,arm64}` and `darwin/{arm64,amd64}`. |
| **M2** | **WHPX & HVF Engines & Static ELF Execution** | `pkg/sentry/platform/whpx` (Windows `amd64`/`arm64`), `pkg/sentry/platform/hvf` (macOS `arm64`/`amd64`), shared-page stubs generated in Go (`bluepill_*.go`, `stubgen_*.go`), `cmd/rungv`, and `pkg/gvx`. | Boot static `busybox` (`PID 1`) via `platform/whpx` on Windows and `platform/hvf` on macOS and execute commands at a `busybox ash` prompt. |
| **M3** | **Dynamic Linking, Dual-Track Netstack & OCI Runner** | `clone`, `futex`, signals, TLS (`ARCH_SET_FS` & `TPIDR_EL0`), VDSO, `pkg/netbackend` (`-net=nat -p` & `-net=wg`), and `pkg/oci` (multi-arch Tar-to-EROFS + `fsimpl/overlay`). | Run unmodified `alpine:3.20`, `nginx:alpine`, `python:3.12-alpine`, and `node:22-alpine` OCI images (`amd64` & `arm64`) on Windows and macOS. |
| **M4** | **`hostfs` VFS2 Driver & Self-Lockdown** | `pkg/sentry/fsimpl/hostfs` (`os.OpenRoot`, `NtCreateFile`/`openat`, `.gvx_meta`) and `pkg/hostlockdown` (Windows RestrictedToken/JobObject & macOS Seatbelt `sandbox_init`). | Pass POSIX rename/unlink torture tests (`git rebase`, `bun install`) on `/workspace`; verify subprocess creation fails on both Windows and macOS. |
| **M5** | **Unified `systrap` Fallback Engine (`darwinsystrap`; `winsystrap` is not implemented)** | `pkg/sentry/platform/systrap`: `commit_mm_darwin.go`, the lazy page-trap `arm64asm` syscall patcher (`patcher_arm64_xplat.go`), trampoline islands, `sysmsg` shared-memory stub tasks, and a strict Seatbelt profile for each stub. The `x86asm` patcher, `winsystrap`, and Rosetta 2 / Prism support stay out of scope. | Execute static, dynamic, and JIT (`node`, `python3`) `arm64` ELF64 workloads via `-platform=systrap` on macOS `arm64` with `-tags pagesize_16k`. Windows and macOS `amd64` return `ErrUnavailable`. |

### 4.1 Host-Native-First Execution Order and Unified E2E Suite (Descriptive Module)

Within each milestone (`M1` through `M5`), engineers implement and verify `darwin/arm64` code paths (`*_darwin.go`, `*_arm64.s`, `platform/hvf`, `platform/systrap`) first on the Apple Silicon development host. Running `go test -race -exec "$PWD/scripts/codesign-exec.sh" ./...` natively on `darwin/arm64` validates the Sentry integration, VFS semantics, and OCI/Netstack pipelines immediately. Once `darwin/arm64` passes all tests, engineers implement the sibling `windows/{amd64,arm64}` (`*_windows.go`, `platform/whpx`, `platform/systrap`) and `darwin/amd64` bindings and verify cross-compilation across all four targets.

`gvx` enforces the Barbell Testing Model across two test layers:

| Test Layer | Package Scope | Build Constraints | Behavioral Contract Verified |
| :--- | :--- | :--- | :--- |
| **Bottom of Barbell: Host Primitive Unit Tests** | `pkg/sync`, `pkg/memutil`, `pkg/fd`, `pkg/hostlockdown`, `platform/{whpx,hvf,systrap}` | OS-specific (`*_darwin_test.go`, `*_windows_test.go`) | Verifies low-level OS syscalls (`__ulock_wait`, `WaitOnAddress`, `mach_vm_remap`, `MapViewOfFile3`, Seatbelt, JobObjects, in-place syscall patching, and 4KB Trampoline Islands) in isolation. |
| **Top of Barbell: Unified Black-Box E2E Suite** | `e2e/` (`sandbox_e2e_test.go`) | 100% OS-agnostic (`//go:build darwin \|\| windows \|\| linux`) | Invokes `pkg/gvx` and `cmd/rungv` with identical assertions across Windows, macOS, and Linux (`amd64` & `arm64`) and all backends (`hvf`, `whpx`, `systrap`). `-platform=auto` selects `systrap` on Linux. |

### 4.2 Continuous Integration and Verification Status (Procedural Module)

GitHub Actions runs the verification that the local host cannot run. The workflows live in `.github/workflows/`. Keep CI usage small: a new push cancels the older run, documentation-only changes skip it, and tests that pull images run once a week.

| Workflow and Job | Runner | What It Verifies |
| :--- | :--- | :--- |
| `ci.yml` build, vet, and audit | `ubuntu-24.04` | Formatting of the packages that `gvx` owns, a build of every package for six targets and for `-tags pagesize_16k`, `go vet` of the packages that `gvx` wrote, and the upstream audit. |
| `ci.yml` test linux | `ubuntu-24.04`, `ubuntu-24.04-arm` | `go test -race` of the owned packages. Without cgo: `pkg/hostlockdown`, `pkg/gvx`, and the whole `e2e` suite with the seccomp lockdown on. Guest runs on the upstream `systrap` platform with and without the lockdown. |
| `ci.yml` test darwin/arm64 | `macos-15` | The owned packages through `scripts/codesign-exec.sh`, then the `systrap` engine, the SDK, and the CLI with `-tags pagesize_16k`. |
| `ci.yml` test windows/amd64 | `windows-latest` | The owned packages, a report of the hypervisor state, and an attempt to boot a guest on `whpx`. |
| `e2e-images.yml` | `macos-15`, `ubuntu-24.04`, `ubuntu-24.04-arm` | The registry gates on the `systrap` engine, once a week. The Linux jobs run every gate with the seccomp lockdown. |
| `diagnose.yml` | A chosen runner | A chosen test selection or script, started by hand. |

A hosted runner is a virtual machine. The macOS runner cannot create a nested VM, so it skips the `hvf` tests when `GVX_ALLOW_NO_HYPERVISOR=1`. The tests that pull images skip when `GVX_E2E_OFFLINE=1`. Windows runners expose the Windows Hypervisor Platform, so CI runs the real `whpx` tests.

| Platform | Verified By |
| :--- | :--- |
| `darwin/arm64` `hvf` | The Apple Silicon development host. A hosted runner has no hypervisor. |
| `darwin/arm64` `systrap` | The development host and CI. |
| `windows/amd64` | CI builds and tests the target. WHPX tests run only where the runner has the Windows Hypervisor Platform. |
| `windows/arm64` | Native WHPX tests verify static and dynamic ELF execution, interactive BusyBox, Alpine, nginx, Python, and Node. CI cross-compiles the target. |
| `darwin/amd64` | Compile-checked only. |
| `linux/amd64` and `linux/arm64` | CI builds, vets, and tests both. |
