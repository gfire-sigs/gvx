# Sandbox Extension SPI, Nested Submodule, and `rungvx` Plan

This document specifies the architecture and phased rollout for hardware extensions in `gvx`. The plan keeps default builds pure Go (`CGO_ENABLED=0`) inside the `gfire-sigs/gvx` monorepo. It places extensions in a nested Go submodule (`ext/go.mod`) and selects them through Go build tags. It also renames `rungv` to `rungvx` and reports compiled build options in `rungvx version`.

| Field | Value |
| :--- | :--- |
| **Status** | Approved Plan (Stage 0) |
| **Tracking Issue** | [#250](https://github.com/gfire-sigs/gvx/issues/250) |
| **GPU Reference Baseline** | PR #239 (`42f8c9f1`, split across PRs #252 to #255; `1,004` of `1,009` WebGL CTS pages) |
| **Primary Build Objective** | Default pure-Go compilation (`CGO_ENABLED=0`) with zero C toolchains and zero extension entries in root `go.mod` |
| **CLI Identity** | Single binary name `rungvx` (renamed from `rungv`) extended through build tags |
| **Upstream Audit Policy** | `0.045` CI gate inside the `0.05` architectural ceiling (`main` is `108/2550`, `4.24%`) |
| **Companion Docs** | [`architecture.md`](architecture.md), [`moonshots.md`](moonshots.md), [`cli.md`](cli.md) |

---

## 1. Architectural Decision and Rationale (Descriptive Module)

This section explains why `gvx` uses a monorepo, a nested Go submodule, and Go build tags instead of a separate repository. It also records the updated baseline from PR #239.

### 1.1 Why Monorepo, Nested Submodule, and Build Tags

The primary objective is default pure-Go compilation (`CGO_ENABLED=0`) for `z.gfire.dev/gvx` and `rungvx`. Callers build the runtime and embed `pkg/gvx` with only the Go toolchain. Native C toolchains and driver SDKs apply only when builders compile isolated host workers under `ext/workers/`.

Separating hardware extensions into a second repository introduces high maintenance friction today. The GPU device (`virtgpu`) imports 17 exported `gvx` packages, including 6 packages under `pkg/sentry/`. Weekly `upstream/go` merges can break those Sentry types and force synchronized cross-repository fixes and duplicated lint tooling.

Root-only Go build tags also fail to isolate module graphs. Running `go mod tidy` inspects every build tag inside one module, so root-only tags pull extension dependencies into `z.gfire.dev/gvx` consumers. Root-only tags also leave optional extension packages outside default `go vet` and `gvisorlint` runs unless every tool adds tag loops.

Placing extensions in a nested Go submodule (`ext/go.mod`, module `z.gfire.dev/gvx/ext`) resolves both defects. This layout reuses the existing `tools/shiminterop/go.mod` pattern in this repository. Inside `ext/cmd/rungvx`, Go build tags (`ext_gpu`, `ext_all`, and future `ext_*`) select compiled extensions while keeping the single `rungvx` binary name.

| Criterion | Root-Only Build Tags | Monorepo + `ext/go.mod` + Build Tags (Selected) | Separate Repository (`gvx-ext`) |
| :--- | :--- | :--- | :--- |
| **Root `go.mod` Purity** | Polluted (`go mod tidy` scans all tags) | Clean (`ext/go.mod` isolates extension deps) | Clean |
| **Default Pure-Go Build** | Yes (`CGO_ENABLED=0`) | Yes (`CGO_ENABLED=0` via `./cmd/rungvx`) | Yes (`CGO_ENABLED=0`) |
| **Weekly `upstream/go` Sync** | Atomic in one PR; bitrot risk without tag CI | Atomic in one PR; path-filtered `ext` CI runs `-tags ext_all` | Cross-repo breakage and pinned release churn |
| **Shared Tooling (`gostateify`, `gvisorlint`, `licenses`)** | Shared | Shared in one repository | Duplicated across two repositories |
| **Android & `arm64-16k` `e2e.test`** | Requires tag guards in `e2e/` | Isolated in `ext/e2e` automatically | Isolated |
| **Future Extraction Option** | Difficult | Clean extraction along `ext/go.mod` boundary if needed | Immediate |

### 1.2 Baseline Evidence from PR #239

PR #239 (`feat/gpu-macos`, head `42f8c9f1`, split into PRs #252 to #255) proved headless WebGL rendering on `darwin/arm64` (`hvf`, macOS 26+). The table records the fixed baseline commits that govern the Extension SPI design.

| Commit or Artifact | Scope | Relevance to This Plan |
| :--- | :--- | :--- |
| `6140054a` | Paused `Close()` unpause, retryable `Close()` on timeout, `-S ctl.sock` support | Reference behavior for the Seam 1 lifecycle runner in `pkg/gvx`. |
| `f2bb06bf` | Reply deadline starts when the renderer can serve the oldest request | Reduces head-of-line kills on the stream socket; measure contention before any IPC rewrite. |
| `606c76e4` & `f1a8babc` | Texture memory budgets, `FENCE_FD_OUT` ordering, `EPERM` self-test, toolchain pins | Already complete in the reference tree; preserve during Stage 5 migration. |
| PRs #252 to #255 | 211 files, `+50,726` lines (renderer, `virtgpu`, sandbox wiring, browser/CTS gates) | Stay open as the reference tree until Stage 5 migrates them into `ext/`. |

---

## 2. Repository Layout, Module Boundaries, and Build Matrix (Reference Module)

This section defines the directory trees, Go module boundaries, upstream isolation tiers, and build-tag compilation modes across the root module and the nested `ext/` submodule.

```text
gvx/ (module z.gfire.dev/gvx, pure Go default)
 ├── go.mod                                     # Pure-Go core; zero extension dependencies
 ├── cmd/
 │   └── rungvx/                                # [RENAMED from cmd/rungv] Pure-Go entrypoint
 │       └── main.go                            # Calls pkg/rungvx.Main() with zero plugins
 ├── pkg/
 │   ├── rungvx/                                # [NEW, Tier 1] Minimal exported runner and plugin API
 │   │   ├── plugin.go                          # Main, MainWithPlugins, CLIPlugin, BuildOption
 │   │   ├── version.go                         # Nginx-style version and build-option formatter
 │   │   └── ...                                # Unexported CLI subcommands moved from cmd/rungv
 │   ├── gvx/
 │   │   ├── extension.go                       # [NEW, Tier 1] SPIVersion, Extension, BoundExtension, KernelEnv
 │   │   ├── extension_runner.go                # [NEW, Tier 1] Lockdown check, attach, 3-outcome Close()
 │   │   ├── helper_proc_*.go                   # [NEW, Tier 1] PreLockdownEnv helper spawn + Win32 confinement
 │   │   ├── syscallfilter_linux.go             # [MODIFIED, Tier 1] FD-pinned receive-only SYS_RECVMSG
 │   │   ├── shm/                               # [NEW, Tier 1] Cross-OS ImportedRegion (zero pkg/gvx imports)
 │   │   │   ├── import.go                      # Importer, Quota, TrustContract
 │   │   │   ├── import_hvf_darwin.go           # Stage 2: hvf backend
 │   │   │   └── ...                            # Future backends added with their first real producer
 │   │   └── exttest/                           # [NEW, Tier 1] Narrow shared test helpers for ext/e2e
 │   └── sentry/
 │       ├── memmap/
 │       │   └── section_windows_xplat.go       # [Deferred to Windows producer] Exported WindowsSectionFile
 │       └── fsimpl/sys/
 │           ├── sys.go                         # [MODIFIED, existing Tier 3 seam] Mount Topologies
 │           └── ext_xplat.go                   # [NEW, Tier 2] NodeSpec, merge rules, PCI/virtio allocator
 └── ext/ (module z.gfire.dev/gvx/ext, nested Go submodule, Tier 1 prefix)
     ├── go.mod                                 # Requires z.gfire.dev/gvx and extension-only Go deps
     ├── cmd/
     │   └── rungvx/                            # Extended rungvx binary selected by build tags
     │       ├── main.go                        # Calls pkg/rungvx.MainWithPlugins(registeredPlugins()...)
     │       ├── plugins.go                     # Registry for compile-time enabled plugins
     │       ├── register_gpu.go                # //go:build ext_gpu || ext_all
     │       └── ...                            # Future register_{display,audio,npu,camera}.go
     ├── extensions/
     │   └── gpu/                               # Migrated from PRs #252 to #255
     │       ├── plugin.go                      # Implements gvx.Extension and rungvx.CLIPlugin
     │       ├── virtgpu/                       # Pure-Go DRM render node (226:128)
     │       └── client/                        # Host renderer wire client
     ├── workers/
     │   └── gpu-renderer/                      # C11 gvx-gpu-renderer, Meson build, 19 patches, third_party.lock
     └── e2e/                                   # Browser (Chromium, Playwright, Electron) and WebGL CTS gates
```

### 2.1 Root Module Additions and Upstream Isolation

All new root packages belong to Tier 1 or Tier 2. The only Tier 3 edit resides in `pkg/sentry/fsimpl/sys/sys.go`, which already carries a registered `seam` entry in `tools/upstream/buildtag_allowlist.txt`.

| Path | Isolation Tier | Import Boundary Rule (`tools/upstream/boundaries.go`) |
| :--- | :--- | :--- |
| `cmd/rungvx` | Tier 1 | Imports only `pkg/rungvx`. |
| `pkg/rungvx` | Tier 1 | Same bounds as former `cmd/rungv`; forbids `pkg/sentry/*`, `pkg/hostlockdown/*`, and `ext/*`. |
| `pkg/gvx/shm` | Tier 1 | Imports `pkg/sentry/memmap`, `pkg/hostarch`, and OS bindings; forbids `pkg/gvx` and `pkg/sentry/kernel`. |
| `pkg/gvx/exttest` | Tier 1 | Test-support helpers only; production packages forbid importing it. |
| `pkg/sentry/fsimpl/sys/ext_xplat.go` | Tier 2 | Uses existing `pkg/sentry/fsimpl/sys` Tier 2 rule; zero new Tier 3 budget. |
| `ext/` | Tier 1 prefix | Registered in `Tier1Prefixes()` (`tools/gostateify/stateify/tier.go`) and pruned from `scripts/check-ci-owned.sh` root walk. |

### 2.2 Extension Submodule (`ext/go.mod`) Mechanics

Go stops recursive package walks (`./...`) at nested `go.mod` files. Root `go build ./...`, `go test ./...`, `scripts/check-consumer.sh`, and `scripts/verify-repro-gvx.sh` therefore skip `ext/` without special flags.

Inside the monorepo, development scripts and CI workflows bind `z.gfire.dev/gvx` to `..` via a temporary `GOWORK` workspace file. Keeping `replace` directives out of `ext/go.mod` preserves external module compatibility when tagging `ext/v*` releases. External Go consumers import `z.gfire.dev/gvx` without downloading any `ext/` dependency.

### 2.3 Build Tag Matrix and Compilation Modes

Every Go build of `rungvx` compiles with `CGO_ENABLED=0`. Builders pass Go build tags to include extensions in `ext/cmd/rungvx`, and they build native C workers separately only when enabling host-backed workers.

| Build Mode | Command | `CGO_ENABLED` | Compiled Extensions | Native C Toolchain Required |
| :--- | :--- | :--- | :--- | :--- |
| **Default Pure Go** | `go build -o rungvx ./cmd/rungvx` | `0` | `none` | No |
| **GPU Extension (CLI)** | `go build -C ext -tags ext_gpu -o ../rungvx ./cmd/rungvx` | `0` | `gpu` | No (Go client and `virtgpu` only) |
| **All Extensions (CLI)** | `go build -C ext -tags ext_all -o ../rungvx ./cmd/rungvx` | `0` | All registered `ext_*` | No |
| **GPU Host Worker** | Meson build in `ext/workers/gpu-renderer` | N/A (C11) | `gvx-gpu-renderer` binary | Yes (C11, Meson, Ninja, pinned patches) |

---

## 3. Unified CLI Identity (`rungvx`) and Nginx-Style Version Output (Descriptive Module)

This section specifies the rename of `rungv` to `rungvx`, the minimal public surface of `pkg/rungvx`, and the nginx-style build-option format of `rungvx version`.

### 3.1 Rename Scope and Minimal Exported Surface

The project keeps one CLI binary name, `rungvx`, instead of splitting users across `rungv` and `rungvx`. Stage 4a renames `cmd/rungv` to `cmd/rungvx` and moves the implementation into `pkg/rungvx`. Moving `cmd/rungv` (69 files, 17,421 lines) must not expose CLI internals as a public Go API.

`pkg/rungvx` exports only four symbols: `Main(args []string) int`, `MainWithPlugins(args []string, plugins ...CLIPlugin) int`, `CLIPlugin`, and `BuildInfoOptions`. All subcommand handlers remain unexported inside `pkg/rungvx`. Stage 4a updates `scripts/repro-build.sh`, `scripts/verify-repro-gvx.sh`, `tools/licenses`, `tools/upstream/boundaries.go`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `android/`, and documentation in one behavior-preserving step.

### 3.2 Nginx-Style Build Options in `rungvx version`

Operators and bug reports must identify which extensions and compiler flags produced a `rungvx` binary. Modeled after `nginx -V`, `rungvx version` (`--version`) reads Go's embedded `debug.BuildInfo` settings together with the sorted list of compile-time registered plugins.

| Line or Flag | Source | Purpose |
| :--- | :--- | :--- |
| `rungvx <version>` | `debug.BuildInfo.Main.Version` | Reports the module version or `(devel)`. |
| `commit <rev> (<time>) [modified]` | `vcs.revision`, `vcs.time`, `vcs.modified` | Identifies the exact source commit. |
| `go <ver> <goos>/<goarch> [<level>]` | `GoVersion`, `GOOS`, `GOARCH`, `GOAMD64`/`GOARM64` | Reports the Go toolchain and ISA baseline. |
| `build options: cgo=<0\|1> tags=<list\|none> extensions=<list\|none>` | `CGO_ENABLED`, `-tags`, sorted `CLIPlugin.Name()` | Shows compiled extensions and Go build tags on every `version` call. |
| `rungvx version -V` (verbose) | Full `debug.BuildInfo.Settings` + `gvx.SPIVersion` + plugin metadata | Prints compiler, `buildmode`, `-trimpath`, `spi`, and each compiled extension's version and capabilities. |

Default pure-Go root build output (`go build ./cmd/rungvx`):

```text
rungvx v0.23.10002026111600
commit a90476e0 (2026-11-24T12:14:00Z)
go go1.27.4 darwin/arm64 GOARM64=v8.4
build options: cgo=0 tags=none extensions=none
```

Extended build output (`go build -C ext -tags ext_gpu -o ../rungvx ./cmd/rungvx`):

```text
rungvx v0.23.10002026111600
commit a90476e0 (2026-11-24T12:14:00Z)
go go1.27.4 darwin/arm64 GOARM64=v8.4
build options: cgo=0 tags=ext_gpu extensions=gpu
```

Verbose output (`rungvx version -V`) appends deterministic key-value lines:

```text
compiler: gc
buildmode: exe
trimpath: true
spi: 1
extension gpu: modes=venus,virgl
```

---

## 4. Core Extension SPI Specification (Descriptive Module)

`gvx` core defines five narrow seams. None of these packages import GPU, display, audio, NPU, or external IPC libraries. Every extension runs Go code inside the Sentry process before lockdown and therefore belongs to the Sentry trusted computing base (TCB).

### 4.1 Seam 1: Lifecycle, Process-Wide Lockdown, and Deterministic Teardown

Host lockdown (`hostlockdown.Apply`) is process-wide and irreversible. On every call after the first, `hostlockdown.Apply` returns `lastStatus, nil` and ignores new options (`pkg/hostlockdown/lockdown.go`). `Sandbox.Close` also requires guest execution and the hypervisor or stub platform to stop before imported host views unmap.

> [!CAUTION]
> Do not unmap imported shared-memory views while a guest address space or platform mapping still references them. Premature unmapping causes host virtual-address reuse hazards and hypervisor memory faults. Drop importer claims only after `Platform.Close` succeeds, and release host mappings when the last page reference drops.

```go
package gvx

// SPIVersion increments when an exported Extension SPI contract changes.
const SPIVersion = 1

// Extension configures an optional host-backed capability for one Sandbox.
// Implementations must be immutable and safe to reuse across Sandboxes.
type Extension interface {
	Name() string
	Validate(env ValidationEnv) error
	OpenPreLockdown(ctx context.Context, env PreLockdownEnv) (BoundExtension, error)
}

type ValidationEnv struct {
	GOOS          string
	GOARCH        string
	Platform      PlatformType
	NetworkMode   NetworkMode
	HasCheckpoint bool // True when CheckpointDir != ""; ignores ControlListener.
	IsRestore     bool
}

type PreLockdownEnv struct {
	PlatformName     string // "hvf", "whpx", or "systrap"
	HostMappingAlign uint64 // 16384 on hvf and 16K Linux; 4096 on whpx, 4K Linux, winsystrap
	HostRAMBytes     uint64
	SharedMemory     *shm.Importer
	SpawnHelper      func(ctx context.Context, spec HelperSpec) (*HelperProcess, error)
	Logf             func(format string, args ...any)
}

type KernelEnv struct {
	VFS          *vfs.VirtualFilesystem
	SharedMemory *shm.Importer
	Logf         func(format string, args ...any)
}

type BoundExtension interface {
	NeedsHelperSpawn() bool
	LockdownRequirements() ExtensionLockdown
	CheckpointPolicy() CheckpointPolicy
	SysfsTopologies() []sys.TopologyAddition
	AttachKernel(ctx context.Context, kenv *KernelEnv) error
	AbortPending()
	Close(guestUnmapped bool) error
	Inspect() (json.RawMessage, error)
	Stats() (json.RawMessage, error)
}
```

Seam 1 enforces these mandatory contracts:

- **Process-wide lockdown guard**: Before calling `OpenPreLockdown`, the runner reads `hostlockdown.IsLockedDown()`. When the process is locked down, `gvx.New` returns a typed `ErrLockdownActive` error if an extension needs helper spawning. It also returns that error if a requested grant is absent from the recorded status. Non-spawning extensions whose grants already hold remain allowed. Record this rule in `docs/architecture.md` Section 3.12.
- **No global registry**: Callers pass extensions per sandbox via `Config.Extensions`. Core defines no `init()` extension registry.
- **Kernel attachment order**: The runner calls `AttachKernel` once per kernel immediately before mounting `devtmpfs` so character render nodes register on time. `KernelEnv` never exposes `*kernel.Kernel`.
- **Immutable checkpoint policy**: Core computes checkpoint eligibility once from the bound extensions and importer usage. Both `Sandbox.Checkpoint` and `CheckpointStream` (over `-S ctl.sock` without `CheckpointDir`) enforce that cached policy, and `gvx.Restore` rejects unsupported extensions.
- **Helper ownership**: Extensions spawn host workers exclusively through `PreLockdownEnv.SpawnHelper`, never through package-level functions. The runner tracks every helper, reports it in status, and terminates leftovers during teardown.
- **Non-blocking telemetry**: `Inspect()` and `Stats()` return `json.RawMessage` snapshots under the extension name and never block on worker RPCs.
- **Core shutdown state**: The runner preserves the commit `6140054a` state (`runningKernel`, `runStarted`, and the closing guard). The closing guard rejects new `Run`, `Pause`, and `ServeControl` calls, and `Close` releases `ckptMu` before `k.WaitExited`.
- **Zero-extension regression gate**: A sandbox with `len(Config.Extensions) == 0` executes the existing `Sandbox.Close` path unchanged.

When `Sandbox.Close()` runs with active extensions, it first calls `unpauseForShutdown(k, dog)` to resume any paused kernel. It then calls `AbortPending()` on each extension and sends `SIGKILL` to all guest thread groups and `exec` sessions within a 30 s wait bound. The runner executes three teardown outcomes:

| Teardown Outcome | Runner Action |
| :--- | :--- |
| **Kernel and platform stop cleanly** | Drop importer claims (`ReleaseAll`), then call `Close(true)` on extensions in reverse open order, joining all errors. |
| **Kernel does not stop within 30 s** | Call `Close(false)` on extensions in reverse open order, close control endpoints, retain platform, memory, and mounts, return an error, and keep `Sandbox` open for a retryable second `Close()`. |
| **`Platform.Close` returns an error** | Call `Close(false)` on extensions in reverse open order, retain memory and mounts, and return joined errors. |

Extensions must satisfy four cleanup invariants:

1. `AbortPending` is sticky, idempotent, and non-blocking; calls started after it fail at once.
2. Blocking extension operations wake through task kill (`ctx.Block`); `AbortPending` is the backstop.
3. `Close` is idempotent, and `Close(false)` followed by `Close(true)` is valid.
4. `shm.Importer.ReleaseAll()` drops sandbox claims only; host views unmap when the last page reference drops after `AddressSpace.Unmap` returns.

### 4.2 Seam 2: Zero-Copy Shared-Memory Importer (`pkg/gvx/shm`)

`pkg/gvx/shm` wraps host descriptors or Win32 sections into `ImportedRegion` values that implement `memmap.Mappable` and `memmap.File`. `pkg/gvx/shm` must never import `pkg/gvx`, because device packages consume it directly.

Stage 2 ships the `Importer` interface, the trust contract, and the `hvf` backend (`darwin/arm64`), which is the only backend with a real producer today. Each remaining backend lands in a dedicated pull request alongside its first real producer.

| Backend | Rollout Stage | Guest Mapping Mechanism |
| :--- | :--- | :--- |
| **`hvf` (`darwin/arm64`)** | Stage 2 | Maps one `MAP_SHARED` view in Sentry; `MapInternal` feeds `hvcommon.RegionMap` (`hv_vm_map`). |
| **`whpx` (`windows/{amd64,arm64}`)** | With Windows GPU producer | Maps one `MapViewOfFile` view in Sentry; `MapInternal` feeds `whpx` `resolvePinnedBlocks` (`WHvMapGpaRange`). |
| **`winsystrap` (`windows/{amd64,arm64}`)** | With Windows GPU producer | Exports `memmap.WindowsSectionFile` (`ChunkSection`) and connects it in `address_space_windows.go`. |
| **Linux `systrap` (4K and 16K)** | With Linux producer | Retains a duplicated `FD_CLOEXEC` descriptor and returns it from `DataFD()`. |

Because an untrusted host worker owns the backing memory, `pkg/gvx/shm` enforces five trust invariants on every import:

| Invariant | Enforcement Rule |
| :--- | :--- |
| **Alignment** | Reject any size or offset that is not an exact multiple of `HostMappingAlign`. |
| **Backing immutability** | Require `F_SEAL_SHRINK` on Linux `memfd` objects and verify committed pagefile sections on Windows. |
| **No guest code execution** | Refuse `PROT_EXEC` mappings on every imported region so `winsystrap` code-patching and `ObserveHostWrites` invariants hold. |
| **Per-sandbox byte quota** | Enforce a byte quota inside `Importer` (`min(4 GiB, 25% of host RAM)` default), because imported regions bypass `pgalloc` accounting. |
| **Import direction** | Forbid `pkg/gvx/shm` from importing `pkg/gvx` in `tools/upstream/boundaries.go`. |

### 4.3 Seam 3: Declarative `sysfs` Topology Additions (`pkg/sentry/fsimpl/sys`)

Guest libraries (`libdrm`, `libudev`, Mesa) discover devices through `/sys/dev/char/<major>:<minor>`, `/sys/class/<class>`, and `/sys/bus/pci/devices`. `pkg/sentry/fsimpl/sys/ext_xplat.go` (Tier 2) defines declarative `NodeSpec` and `TopologyAddition` structs. A narrow loop in `sys.go` mounts `InternalData.Topologies`.

Seam 3 implements four concrete rules:

1. **Binary and text payloads**: `NodeSpec` supports UTF-8 text files, raw binary files (for the 64-byte PCI configuration space), static directories, and validated relative symlinks.
2. **Shared directory merge rules**: `sys.go` merges extension children into `class`, `bus/pci/devices`, and `dev/char` instead of overwriting sealed maps.
3. **Core slot and index allocation**: Core assigns PCI slots and `virtio` device indices dynamically instead of hardcoding `0000:00:01.0` and `virtio0`. Multiple extensions never collide.
4. **Early collision validation and stateify hygiene**: `gvx.New` validates all `TopologyAddition` paths before boot rather than failing during mount. Mark the `Topologies` field `state:"nosave"` and pass `./scripts/gostateify.sh -check`.

### 4.4 Seam 4: Pre-Lockdown Grants, Helper Supervision, and Trust Boundary

Extensions never supply raw BPF programs or raw Seatbelt SBPL text. Core owns every OS confinement boundary and documents explicitly that extensions run inside the Sentry TCB before lockdown; core cannot verify worker self-confinement.

| Host OS | Core Mechanism | Security Constraint |
| :--- | :--- | :--- |
| **Linux (`pkg/gvx/syscallfilter_linux.go`)** | `ExtensionLockdown.RecvMsgFDs` registers pre-opened socketpair descriptor numbers before lockdown. | Allow `SYS_RECVMSG` pinned to each reserved FD with `seccomp.EqualTo`. Do not allow `SYS_SENDMSG`, because seccomp cannot inspect `SCM_RIGHTS` payloads and a compromised Sentry could leak `os.Root` or layer FDs. Defer `AllowSharedFutex`, because `runsc/boot/filter/config/config_main.go` already allows non-private `FUTEX_WAIT` and `FUTEX_WAKE`. |
| **macOS (`pkg/hostlockdown/lockdown_darwin.go`)** | Zero Seatbelt profile edits required. | `OpenPreLockdown` opens descriptors and `mmap` rings before `sandbox_init_with_parameters`; `(allow signal (target children))` already allows worker termination. |
| **Windows (`pkg/gvx/helper_proc_windows.go`)** | `PreLockdownEnv.SpawnHelper` launches workers before Sentry enters its single-process job. | Core confines every worker with a restricted token and a dedicated job carrying UI limits and `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Sentry retains `PROCESS_DUP_HANDLE` toward the worker; the worker receives no duplication right into Sentry. |

### 4.5 Seam 5: CLI Plugin Registry and Shared Test Support

`pkg/rungvx/plugin.go` defines `CLIPlugin` with four hooks: `Name() string`, `BuildSummary() string`, `RegisterFlags(fs *flag.FlagSet)`, and `ApplyConfig(cfg *gvx.Config) error` (plus optional subcommand registration). `ext/cmd/rungvx` registers compiled plugins through build-tagged files (`//go:build ext_gpu || ext_all`) and invokes `pkg/rungvx.MainWithPlugins(os.Args[1:], plugins...)`.

To let `ext/e2e` run guest probes without importing root `internal/*` packages or copy-pasting harnesses, Stage 4b exports a minimal test-only package `pkg/gvx/exttest`. That package wraps the required `internal/hvtest`, `internal/acceptprog`, and `e2e` sandbox helpers behind a narrow test API. `tools/upstream/boundaries.go` forbids every production package from importing `pkg/gvx/exttest`.

---

## 5. Verification, Compatibility, and CI Integration (Descriptive Module)

This section specifies how `gvx` verifies the Extension SPI against real producers, enforces upstream diff limits, and runs path-filtered CI for `ext/`.

`AGENTS.md` Section 6 requires real producers in boundary tests. Stages 1 through 4 verify the SPI through two layers:

1. **Pure-Go conformance extension (`pkg/gvx/extension_conformance_test.go`)**: Runs inside root `gvx` tests with `CGO_ENABLED=0`. It spawns a helper subprocess, imports a POSIX shared-memory object, and blocks a guest VFS operation. It then verifies all three teardown outcomes and the two-sandbox lockdown error.
2. **Real GPU acceptance consumer (`ext/extensions/gpu` and `ext/e2e`)**: Stage 5 migrates the PR #252 to #255 GPU stack onto `gvx.Extension`, `pkg/gvx/shm`, `sys.TopologyAddition`, and `-tags ext_gpu`. The SPI reaches stability when both `venus` and `virgl` match the `1,004` of `1,009` Khronos WebGL CTS baseline on `darwin/arm64`.

Compatibility and CI hygiene obey three rules:

- **Unified upstream audit gate**: Align `AGENTS.md`, `.github/workflows/ci.yml`, `scripts/sync-upstream.sh`, and `docs/architecture.md` to one **`0.045`** CI gate inside the `0.05` ceiling. Current `main` stands at `108/2550` (`4.24%`).
- **Path-filtered extension CI (`.github/workflows/ext.yml`)**: Trigger automatically on pull requests touching `ext/**`, `pkg/gvx/**`, `pkg/rungvx/**`, `pkg/sentry/fsimpl/sys/**`, `pkg/sentry/vfs/**`, `pkg/sentry/memmap/**`, or `UPSTREAM_COMMIT`. The workflow runs `go build`, `go vet`, `scripts/gvisorlint.sh`, `./scripts/gostateify.sh -check`, unit tests, and license audits for `ext/` with `-tags ext_all`.
- **Reproducible builds and licenses**: `scripts/verify-repro-gvx.sh` verifies deterministic SHA-256 builds of pure-Go `./cmd/rungvx`. A matching `ext` job verifies deterministic Go builds of `ext/cmd/rungvx` (`-tags ext_gpu`) and validates extension license notices.

---

## 6. Phased Execution Plan (Procedural Module)

Execute Stages 0 through 5 in order. Each stage lands as one focused pull request that passes CI before the next stage starts.

> [!IMPORTANT]
> Keep every pull request that modifies Tier 3 files focused on one behavior and below 400 changed production lines. Record an independent review on every pull request that changes Tier 3 files, lockdown rules, or teardown paths.

### Stage 0: Plan Commit and Audit Threshold Unification

1. Commit `docs/extensions-plan.md` on `main`.
2. Update `scripts/sync-upstream.sh`, `docs/architecture.md`, and `AGENTS.md` to use `-max-ratio=0.045` as the unified CI gate.
3. Verify `go run ./tools/upstream -mode=audit -max-ratio=0.045` passes on `main`.

### Stage 1: Declarative `sysfs` Topology Seam

1. Add `NodeSpec`, `TopologyAddition`, directory merge logic, and PCI/virtio allocators in `pkg/sentry/fsimpl/sys/ext_xplat.go`.
2. Wire `InternalData.Topologies` with `state:"nosave"` in `pkg/sentry/fsimpl/sys/sys.go`.
3. Add guest tests verifying binary files, merged `dev/char` and `class` directories, and collision errors in `gvx.New`.
4. Run `./scripts/gostateify.sh -check` and `scripts/gvisorlint.sh` across all five targets.

### Stage 2: Shared-Memory Importer and `hvf` Backend

1. Create `pkg/gvx/shm` with `Importer`, `ImportedRegion`, alignment validation, `PROT_EXEC` refusal, and byte quotas.
2. Implement the `hvf` backend (`import_hvf_darwin.go`) and register `pkg/gvx/shm` in `tools/upstream/boundaries.go`.
3. Verify guest reads and writes to a test-created POSIX shared-memory object on `hvf` and assert `PROT_EXEC` rejection.

### Stage 3a: Lifecycle SPI, Lockdown Guard, and Conformance Extension

1. Add `SPIVersion`, `Extension`, `BoundExtension`, `KernelEnv`, `ValidationEnv`, `PreLockdownEnv`, and `CheckpointPolicy` in `pkg/gvx/extension.go`.
2. Implement `extension_runner.go` with `hostlockdown.IsLockedDown()` enforcement, the three teardown outcomes, and commit `6140054a` shutdown state.
3. Add the pure-Go conformance extension tests covering paused `Close()`, retryable `Close()`, and two-sandbox lockdown assertions.
4. Update `docs/architecture.md` Section 3.12 with the process-wide extension lockdown invariant.

### Stage 3b: Helper Supervision and Lockdown Grants

1. Implement `PreLockdownEnv.SpawnHelper` in `pkg/gvx/helper_proc_*.go` with Windows restricted-token and job-object confinement.
2. Add FD-pinned receive-only `SYS_RECVMSG` rules (`seccomp.EqualTo`) in `pkg/gvx/syscallfilter_linux.go`.
3. Run `scripts/seccomp-audit.sh` on Linux and verify that an ungranted descriptor transfer fails.

### Stage 3c: Control Protocol Extension Telemetry

1. Expose non-blocking `Inspect()` and `Stats()` extension JSON snapshots through `pkg/gvx/control`.
2. Add protocol unit tests verifying snapshot serialization and timeout-free behavior when an extension aborts.

### Stage 4a: Rename `rungv` to `rungvx` and Extract `pkg/rungvx`

1. Rename `cmd/rungv` to `cmd/rungvx` and move subcommand files into `pkg/rungvx` with zero behavior change.
2. Export only `Main` from `pkg/rungvx` in this stage.
3. Update `scripts/repro-build.sh`, `scripts/verify-repro-gvx.sh`, `tools/licenses`, `tools/upstream/boundaries.go`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `android/`, and docs.
4. Verify reproducible SHA-256 builds and record the new `rungvx` baseline hash.

### Stage 4b: Plugin API, Nginx-Style `version`, and `ext/` Submodule Bootstrap

1. Export `MainWithPlugins`, `CLIPlugin`, and `BuildInfoOptions` in `pkg/rungvx/plugin.go`.
2. Update `pkg/rungvx/version.go` to emit nginx-style `build options:` lines and verbose `-V` output.
3. Add `pkg/gvx/exttest`, `ext/go.mod`, `ext/cmd/rungvx`, `Tier1Prefixes` registration for `ext/`, and `.github/workflows/ext.yml`.
4. Verify pure-Go `./cmd/rungvx` prints `build options: cgo=0 tags=none extensions=none` and tagged `ext/cmd/rungvx` prints enabled tags and extensions.

### Stage 5: Migrate GPU Stack into `ext/`

1. Migrate `virtgpu`, the renderer client, `ext/workers/gpu-renderer`, the 19 patches, and browser/CTS gates from PRs #252 to #255 into `ext/`.
2. Register `gpu.Plugin()` under `//go:build ext_gpu || ext_all` in `ext/cmd/rungvx/register_gpu.go`.
3. Verify `venus` and `virgl` match the `1,004` of `1,009` WebGL CTS baseline on `darwin/arm64` and verify root `go.mod` stays unchanged.
4. Close PRs #252 to #255 and PR #239 with links to the migrated commits.

### Verification Commands

Run these commands after each stage to verify pure-Go default compilation, upstream diff limits, and extension builds:

```bash
# 1. Verify default pure-Go compilation across all five targets and Android
for target in darwin/arm64 windows/amd64 windows/arm64 linux/amd64 linux/arm64; do
  GOOS=${target%/*} GOARCH=${target#*/} CGO_ENABLED=0 go build ./...
done
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build ./...

# 2. Verify upstream diff budget, stateify, gVisor analyzers, and external SDK consumer build
go run ./tools/upstream -mode=audit -max-ratio=0.045
./scripts/gostateify.sh -check
./scripts/gvisorlint.sh
./scripts/check-consumer.sh

# 3. Verify extended rungvx build and nginx-style version output (Stage 4b onward)
GOWORK=auto go build -C ext -tags ext_gpu -o ../rungvx-gpu ./cmd/rungvx
./rungvx-gpu version -V
```

---

## 7. Deferred Scope and Follow-Up Issues (Reference Module)

The items in this table stay outside Stages 0 through 5 and require dedicated issues and measurements before implementation.

| Deferred Item | Prerequisite Before Starting |
| :--- | :--- |
| **`gosuda.org/hqq` IPC migration** | Measure remaining queue contention after commit `f2bb06bf`, then prove cross-process wake, worker death recovery, and fence completion under real confinement with a pinned revision. |
| **Windows GPU worker (`whpx` & `winsystrap`)** | Complete Stage 5, add `whpx` and `winsystrap` backends to `pkg/gvx/shm`, and add WARP functional CI gates. |
| **Future hardware extensions (`display`, `audio`, `npu`, `camera`)** | Stabilize SPI v1 on `gpu` first, then add each extension under `ext/extensions/` behind its own `ext_<name>` build tag. |
| **Ed25519 worker binary verification** | Define key ownership, signing infrastructure, and key rotation rules. |
| **LAN Mac GPU pooling (`remote` `virgl`)** | Keep out of `gvx` core; evaluate as an experimental `ext/extensions/gpu/remote` backend only if low-rate WebGL fingerprint workloads require it. |
