# Agent Operating Manual (`AGENTS.md`)

This manual governs engineering sessions in the `gvx` repository. It establishes the startup protocol, package and upstream isolation boundaries, ownership invariants, prose discipline, verification procedures, and release rules. `gvx` treats Windows (`windows/amd64`, `windows/arm64`) and macOS (`darwin/arm64`) as co-equal Priority-0 hosts alongside official Linux (`linux/amd64`, `linux/arm64`) and Android (`android/arm64`) support.

> [!IMPORTANT]
> Read [`docs/architecture.md`](docs/architecture.md) at the outset of every session before planning, writing code, or reviewing changes. Identify the owning subsystem and verify its package boundaries before editing any file.

---

## 1. Mandatory Startup Protocol

Execute these steps before editing repository files.

1. Read [`docs/architecture.md`](docs/architecture.md) to verify subsystem boundaries, system-call contracts, and upstream isolation rules.
2. Inspect the target package and its Go build constraints (`windows`, `darwin`, `linux`, `amd64`, `arm64`).
3. Activate the applicable engineering skills under `.agents/skills/` from the routing table below.
4. Implement and verify `darwin/arm64` paths natively first when working on cross-platform features, then add `windows/{amd64,arm64}` bindings and verify them in CI.
5. Verify that modified upstream files stay below the 5.0% architectural ceiling (4.5% CI audit gate).

| Task Category | Required Skill (`.agents/skills/`) | Scope of Enforcement |
| :--- | :--- | :--- |
| **Umbrella Engineering** | [`just-good-practices`](.agents/skills/just-good-practices/SKILL.md) | Incremental implementation, guard clauses, and boundary error translation. |
| **Go Implementation** | [`go-practices`](.agents/skills/go-practices/SKILL.md) | Go 1.27+ standard library usage, context ordering, and `%w` / `errors.Join` (`gojgp` lint disabled). |
| **API and Signatures** | [`api-design`](.agents/skills/api-design/SKILL.md) | Explicit resource ownership, typed options, and constructor dependency injection. |
| **Code Health** | [`code-health`](.agents/skills/code-health/SKILL.md) | Shallow control flow, domain naming, and separation of pure logic from I/O. |
| **Testing** | [`testing-practices`](.agents/skills/testing-practices/SKILL.md) | Hermetic fixtures, `testing/synctest`, and behavioral boundary assertions. |
| **Writing and Anti-Slop** | [`deslop`](.agents/skills/deslop/SKILL.md) & [`zero-slop`](.agents/skills/zero-slop/SKILL.md) | Controlled concise prose, zero em-dashes, zero buzzwords, and behavioral tests. |
| **Diff and PR Review** | [`code-review`](.agents/skills/code-review/SKILL.md) | Atomic commits, risk classification, and evidence-backed verification reports. |

---

## 2. Layered Subsystem Map and Upstream Sync Rules

`gvx` tracks the `go` branch of `https://github.com/google/gvisor.git` (`upstream/go`) and records the synced commit SHA in `UPSTREAM_COMMIT`. Host bindings remain segregated from the pure-Go Sentry kernel across three isolation tiers.

| Isolation Tier | Packages and Files | Architectural Rule |
| :--- | :--- | :--- |
| **Tier 1: Additive Packages** | `cmd/rungvx`, `cmd/containerd-shim-gvx-v2`, `internal/gvxshim`, `pkg/rungvx`, `pkg/gvx`, `pkg/gvx/control`, `pkg/gvx/shm`, `pkg/gvx/exttest`, `pkg/oci`, `pkg/netbackend`, `pkg/hostlockdown`, `pkg/sentry/blockdev`, `pkg/sentry/platform/whpx`, `pkg/sentry/platform/hvf`, `pkg/sentry/platform/hvcommon`, `pkg/sentry/fsimpl/chunkcache`, `pkg/sentry/fsimpl/fsutilx`, `pkg/sentry/socket/netlink/genetlink`, `pkg/ipset`, `pkg/tcpip/link/vxlan`, `pkg/tcpip/link/wgtun`, `pkg/sentry/fsimpl/hostfs`, `pkg/sentry/fsimpl/ext4lite`, `pkg/sentry/fsimpl/rpcfs`, `ext/`, `e2e`, `tools/upstream`, `tools/shiminterop`, `tools/licenses`, `tools/gvisorlint`, `tools/androidprobe`, `tools/gostateify`, `tools/slimlink`, `android`, `docs/` | Owned exclusively by `gvx`; absent from `upstream/go` (0.0% merge conflict rate). |
| **Tier 2: Sibling `_windows`, `_darwin`, and `_xplat` Files** | `pkg/sync/*_{windows,darwin,xplat}*`, `pkg/memutil/*_{windows,darwin,xplat}*`, `pkg/fd/*_{windows,darwin,xplat}*`, `pkg/{erofs,fdnotifier,syserr}/*_{windows,darwin,xplat}*`, `pkg/hostarch/*_darwin*`, `pkg/sentry/{kernel,mm}/*_xplat*`, `pkg/sentry/{pgalloc,time,hostcpu}/*_{windows,darwin}.go`, `pkg/sentry/platform/*_{windows,darwin,xplat}*`, `pkg/sentry/platform/systrap/*_{windows,darwin,xplat}*` | Placed beside unmodified `*_linux.go` files so `git merge upstream/go` never conflicts. |
| **Tier 3: Build-Tag and Seam Patches** | Pure-Go files in `pkg/sentry/kernel`, `pkg/sentry/arch`, `pkg/ring0`, `pkg/sentry/vfs`, `pkg/sentry/fsimpl/{erofs,tmpfs,overlay}`, `pkg/tcpip`, `pkg/sentry/platform/systrap/{usertrap,sysmsg}` (`amd64` files) | Register every build-tag change (`linux \|\| windows \|\| darwin`) in `tools/upstream/buildtag_allowlist.txt`; keep modified upstream files below 5.0%. Name additive helpers in shared packages `*_xplat.go` or `*_darwin*.go` so the audit counts them as Tier 2 siblings. |

The optional containerd shim (`internal/gvxshim`) owns the G3 control boundary beside M2. It must never import `pkg/gvx`, Sentry, `pkg/hostlockdown`, or the upstream `runsc` shim. The standalone SDK never imports the shim adapter, and a live control daemon does not represent a running sandbox. The isolated `tools/shiminterop` module exercises real containerd SDK `2.1.5` without importing the root module or altering root telemetry dependencies.

---

## 3. Resource Ownership and Concurrency Invariants

Every subsystem that allocates host kernel handles, virtual memory arenas, or CPU register state obeys the ownership rules below.

### 3.1 Memory and Address Space Ownership

`pgalloc.MemoryFile` owns backing shared memory created via `CreateFileMappingW` and `MapViewOfFile3` on Windows or `mmap(MAP_ANON)` and `mach_vm_remap` on macOS. `platform/whpx` (`WHvMapGpaRange`) and `platform/hvf` (`hv_vm_map`) map 4 KiB slices into guest physical memory; `AddressSpace.Unmap()` unmaps GPA ranges before `MemoryFile` releases backing pages.

On Windows, `platform/systrap` (`winsystrap`) owns one stub process per address space and one shared debug object. A stub host started prior to `hostlockdown.Apply()` creates the stubs from a generated 1 KiB PE image held open with read-only sharing until exit. macOS has no `systrap` engine because `darwinsystrap` could not accommodate non-PIE executables or 4 KiB-aligned segments. `winsystrap` patches `syscall` with `jmp rel32` or `CC 90` on `amd64` and `svc #0` with `B` or `brk` on `arm64`, serving fast traps through `winSysmsg` pages and faults through the debug object. Read [`docs/systrap-windows.md`](docs/systrap-windows.md) before modifying it; set `GVX_SYSTRAP_TRACE=1` to inspect traps.

### 3.2 Host Handle and Lockdown Ordering

> [!CAUTION]
> Do not spawn child processes, open unbound host paths, or invoke `win32k` APIs after `hostlockdown.Apply()` returns. Windows Job Objects (`JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 1`) and macOS Seatbelt (`deny process-fork`, `deny file-*`) reject or terminate violating calls immediately. Open all host handles (`whpx`/`hvf` VM, pre-spawned `systrap` stub host and `sysmsg` memory, cached `.erofs` layers, `ext4lite` volume images, `/workspace` `os.Root`, `-p` listeners, and the `-net=wg` UDP socket) before calling `hostlockdown.Apply()`.

`pkg/fd.HostHandle` wraps every Windows `syscall.Handle` and POSIX file descriptor with explicit `Close()` ownership. `pkg/oci` compiles multi-arch (`amd64`/`arm64`) OCI layers in memory into cached `<sha256>.erofs` files without extracting files onto NTFS or APFS. `pkg/netbackend` routes `pkg/tcpip` traffic through either L4 Go `net` NAT and port forwarders (`-net=nat`) or an L3 in-memory `wireguard-go` tunnel (`-net=wg`). `pkg/sentry/fsimpl/hostfs` opens workspace paths relative to a pinned `os.Root` handle (`NtCreateFile` on Windows; `openat`/`openat2` on Unix), enforces `FILE_OPEN_REPARSE_POINT` or `O_NOFOLLOW`, and persists POSIX metadata in `.gvx_meta`.

---

## 4. Documentation and Zero-Slop Standard

All documentation (`README.md`, `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/**/*.md`), code comments, and commit messages are written in plain, concise English adhering to the rules below and [`.agents/skills/deslop/SKILL.md`](.agents/skills/deslop/SKILL.md).

| Writing Rule | Mandatory Constraint |
| :--- | :--- |
| **Procedural Sentence Length** | At most 20 words per sentence; one instruction per sentence; begin with an imperative verb (`Run`, `Call`, `Open`, `Set`, `Verify`). |
| **Descriptive Sentence Length** | At most 25 words per sentence; at most 6 sentences per paragraph; prefer active voice and clear agency. |
| **Compound Noun Clusters** | At most 3 consecutive nouns; unpack longer chains with prepositions (`of`, `for`, `in`, `on`) or hyphenated modifiers. |
| **Exact Verbs** | Use concrete mechanical verbs (`parse`, `validate`, `dispatch`, `allocate`, `verify`, `obey`) rather than vague `handle`, `manage`, `process`, or `check`. |
| **Zero Em-Dashes and Arrows** | Never emit `U+2014`, spaced `U+2013`, prose double hyphens, or prose arrows (`U+2192`). Use `:`, `;`, `()`, `.`, or `,`. |
| **Zero AI-Slop Vocabulary** | Never emit marketing buzzwords or throat-clearing prefaces listed in Section 4 of [`.agents/skills/deslop/SKILL.md`](.agents/skills/deslop/SKILL.md). |
| **Modular Separation** | Keep conceptual prose, numbered procedures, and fault or reference tables in distinct sections. |
| **Pre-Procedure Alerts** | Place `> [!CAUTION]`, `> [!WARNING]`, and `> [!IMPORTANT]` immediately before the procedure or code block they govern (at most 3 sentences). |
| **Heading Lead Rule** | Never place two headings back-to-back without a brief scope lead or summary table. |
| **English Only** | Write all repository documentation, comments, and commit messages in English. |

---

## 5. Build, Audit, and Verification Procedure

Keep `e2e/` black-box tests OS-agnostic across Windows, macOS, and Linux, isolating host-specific unit tests in `*_darwin_test.go` and `*_windows_test.go`. Do not run `gojgp` lint; it is disabled owing to upstream gVisor conventions.

> [!IMPORTANT]
> Run `go test` through `scripts/codesign-exec.sh` on macOS. Unsigned test binaries cannot verify TLS certificates and skip network image tests silently.

1. Format source files and run native unit and `e2e/` tests on `darwin/arm64` via `scripts/codesign-exec.sh`.
2. Cross-compile all packages across `darwin/arm64`, `windows/amd64`, `windows/arm64`, `linux/amd64`, and `linux/arm64`.
3. Run the upstream diff audit to confirm modified upstream files remain below 5.0%.
4. Run `./scripts/gostateify.sh -check` to verify generated state files match source annotations.
5. Run `scripts/gvisorlint.sh` (`checklocks`, `checkconst`, `checklinkname`) across all five targets. Consult [`docs/architecture.md`](docs/architecture.md#45-the-gvisor-static-analyzers-toolsgvisorlint) to resolve findings.
6. Run the typographic check against all Markdown documentation files.
7. Push the branch and inspect CI results for platforms the local host cannot execute.

```bash
# 1. Format and test natively on the active host (gojgp lint is disabled)
go fmt ./...
go test -race -exec "$PWD/scripts/codesign-exec.sh" ./...

# 2. Cross-compile all five production targets
GOOS=darwin  GOARCH=arm64 go build ./...
GOOS=windows GOARCH=amd64 go build ./...
GOOS=windows GOARCH=arm64 go build ./...
GOOS=linux   GOARCH=amd64 go build ./...
GOOS=linux   GOARCH=arm64 go build ./...

# 3. Audit upstream diff budget (< 5.0% ceiling; 4.5% CI gate)
go run ./tools/upstream -mode=audit -max-ratio=0.045

# 4. Verify generated state files match source annotations
./scripts/gostateify.sh -check

# 5. Run gVisor static analyzers across all five targets (must produce no output)
scripts/gvisorlint.sh

# 6. Verify zero em-dashes, spaced en-dashes, or prose arrows in documentation
rg -n "\x{2014}| \x{2013} |\x{2192}" README.md AGENTS.md CONTRIBUTING.md SECURITY.md docs/ 2>/dev/null
```

### 5.1 Continuous Integration

`.github/workflows/ci.yml` builds and vets all five targets, runs `gvisorlint`, audits the upstream diff, verifies third-party licenses, and tests `linux/amd64`, `linux/arm64`, `darwin/arm64`, `windows/amd64`, and `windows/arm64`. Its `repro` job executes `scripts/verify-repro-gvx.sh` to confirm identical SHA-256 hashes between host and in-`gvx` builds. Its `dind-build` job runs `TestE2EDockerBuildDindLocalRegistry` against cached `docker:dind` layers. Hosted macOS and `windows-11-arm` runners lack nested hypervisors and therefore skip hypervisor-only tests.

Additional workflows serve specialized verification: `ext.yml` builds, vets, and tests the nested `ext/` submodule with `-tags ext_gpu` and `-tags ext_all`; `e2e-images.yml` pulls registry images weekly; `diagnose.yml` runs targeted diagnostics on demand; `pjdfstest.yml` runs the POSIX suite on `ext4lite` and `hostfs` (recording unavoidable host limits in `scripts/pjdfstest/known-failures.txt`); `android.yml` runs `scripts/android/emulator-smoke.sh` on an x86-64 Android 16 KVM emulator; `linux16k.yml` boots a Debian trixie `arm64-16k` kernel in QEMU; and `release.yml` builds, attests, and publishes tagged releases. On Linux, run `scripts/seccomp-audit.sh` whenever adding a host system call.

Native shim tests re-execute production `Main` without `GVX_SHIM_BINARY`. Explicit interoperability tests set `GVX_SHIM_BINARY` (and `GVX_CONTAINERD_BINARY` for the external-daemon smoke test), documented in [`docs/architecture.md`](docs/architecture.md#43-containerd-shim-verification).

Keep CI consumption modest. Avoid redundant jobs and reserve the following variables for CI or targeted diagnostics:

| Variable | Effect |
| :--- | :--- |
| `GVX_ALLOW_NO_HYPERVISOR=1` | Skips hypervisor tests when `hv_vm_create` or `WHvCreatePartition` fails. |
| `GVX_E2E_OFFLINE=1` | Skips tests that pull images from external registries. |
| `GVX_E2E_REQUIRE_NETWORK=1` | Fails rather than skipping when a registry is unreachable. |
| `GVX_E2E_DIND_CACHE_DIR` | Layer cache directory for `TestE2EDockerBuildDindLocalRegistry`. |
| `GVX_PREBUILT_DIR` | Directory holding prebuilt guest binaries for `e2e.test` on VMs without a Go toolchain. |
| `GVX_E2E_CPUMAX_CHECKS` | Comma-separated `cpumaxprobe` subtest list for `TestE2ECPUMaxEnforcement`. |
| `GVX_E2E_BROWSER=1` | Runs the SwiftShader browser gates in `ext/e2e/gate_browser_test.go` (pulls a ~1 GB Playwright image). |
| `GVX_E2E_BROWSER_BENCH=1` | Runs `TestE2EBrowserBench` alongside `GVX_E2E_BROWSER=1`. |
| `GVX_E2E_GPU=1` | Runs the GPU gates in `ext/e2e/gate_gpu*_test.go` on `darwin/arm64` with `hvf` (requires `GVX_GPU_RENDERER`). |
| `GVX_E2E_ARTIFACT_DIR` | Output directory for GPU gate records (`g1`, `g1-kill`, `g2`, `g3`, `webgl-cts`, `venus-guard`). |
| `GVX_GPU_RENDERER` | Path to `gvx-gpu-renderer` for `-gpu=venus` and `-gpu=virgl` (`scripts/gpu/build-renderer.sh` outputs to `build/gpu/gvx-gpu-renderer/bin/`). |
| `GVX_E2E_GPU_MODES` | Comma-separated GPU modes (`venus`, `virgl`) for `ext/e2e` GPU gates (unset runs both). |
| `GVX_E2E_GPU_CHROMIUM_FLAGS` | Overrides `venus` Chromium flags in `TestE2EGateGPUChromium` and `TestE2EGateGPUWebGLCTS`. |
| `GVX_E2E_GPU_CHROMIUM_VIRGL_FLAGS` | Overrides `virgl` Chromium flags in `TestE2EGateGPUChromium` and `TestE2EGateGPUWebGLCTS`. |
| `GVX_E2E_WEBGL_CTS` | Selects `TestE2EGateGPUWebGLCTS` scope (`subset`, `full`, or `full-deqp`) when `GVX_E2E_GPU=1`. |
| `GVX_E2E_WEBGL_CTS_PAGES` | Comma-separated subset selectors overriding `webgl-cts-subset.txt` during diagnosis runs. |
| `GVX_DEBUG_LOG=1` | Prints Sentry kernel logs (`2` adds debug lines including unresolved guest faults). |
| `GVX_SYSTRAP_SUBBLOCKS=1` | Exercises the 16 KiB sub-block layer of Linux `systrap` on a 4 KiB host. |
| `GVX_SYSTRAP_TRACE=1` | Prints Windows `systrap` guest exception signals (`2` logs every stop; `3` prints stop counts and patch summaries; `4` samples hot PCs). |

### 5.2 Release Version Rule

Every release tag takes the form `vMAJOR.MINOR.PATCH` obeying SemVer 2.0 with no leading zeros. `release.yml` rejects any tag that disagrees with the Go module version. The `PATCH` field encodes both the `gvx` release counter and the synced upstream gVisor release date.

| Field | Example (`v0.22.10002026111600`) | Rule |
| :--- | :--- | :--- |
| `MAJOR` | `0` | Retain `0`. |
| `MINOR` | `22` | Increment by 1 when a release adds a feature or alters behavior; an upstream sync alone does not increment `MINOR`. |
| `PATCH` | `10002026111600` | Concatenate the four decimal segments below in table order. |

| PATCH Segment | Digits | Example Value | Rule |
| :--- | ---: | :--- | :--- |
| Fixed prefix | 1 | `1` | Always `1`, preventing a leading zero when the counter is `000`. |
| Release counter | 3 | `000` | Reset to `000` when `MINOR` increments; increment by 1 for every other release, including upstream syncs. |
| Upstream date | 8 | `20261116` | The `YYYYMMDD` portion of `release_tag` (`release-YYYYMMDD.N`) in `tools/upstream/sync_manifest.json`. |
| Upstream suffix | 2 | `00` | The `N` suffix of `release_tag`, zero-padded to two digits. |

Because the counter precedes the upstream date, successive releases within one `MINOR` series sort monotonically (up to 1,000 releases per `MINOR`). Appending a hyphenated suffix such as `-rc.1` publishes a pre-release.

### 5.3 Release Procedure

Execute this procedure on `main` after CI passes on the release commit. `release.yml` extracts release notes from `CHANGELOG.md`.

1. Compute the next version tag using Section 5.2.
2. Rename `## [Unreleased]` in `CHANGELOG.md` to `## [<tag>] - <YYYY-MM-DD>`.
3. Commit as `docs(changelog): release <tag>` and push `main`.
4. Create an annotated Git tag `<tag>` on that commit and push the tag.
5. Verify that `release.yml` publishes all archives, checksums, and SLSA attestations.

### 5.4 Slim Linker and Dead-Method Elimination Rules

Release binaries build through `scripts/slim-build.sh` and `tools/slimlink`. The wrapper patches `cmd/link/internal/ld/deadcode.go` from the active `GOROOT` via `-overlay` and preserves stock `pclntab`, stack traces, `runtime.Caller`, GC maps, and `pprof`.

> [!CAUTION]
> Never strip `pclntab` (`funcnametab`, `filetab`, or `InlTree`) in production releases. Go runtime internals (`isSystemGoroutine`, `panicwrap`, `gorecover`, `isAsyncSafePoint`, and `reflect.makeFuncStub`) depend on undocumented `pclntab` invariants across Go versions.

1. Run `go test -race ./tools/slimlink/...` after every `go.mod` Go upgrade to verify `deadcode.go` patch anchors.
2. Keep `cmd/rungvx` free of `<ReflectMethod>` symbols, enforced in CI via `-ldflags=-dumpdep`.
3. Avoid adding `reflect.Type.Method`, `reflect.Value.Method`, or non-constant `MethodByName` calls under `cmd/rungvx` dependencies.
4. Never call `reflect.Type.Methods` or `reflect.Value.Methods` solely through a generic interface constraint or `MethodByName("Methods")`.
5. Keep `pkg/rungvx/template_eval.go` free of reflection method dispatch; expose new `--format` values as struct fields or explicit builtins.

---

## 6. Change Size, Review, and Test Source Rules

Past regressions that escaped CI (an assumed floating-point layout fixed in PR #84, a reused lookup across two safety checks in PR #81, and a process-wide limit counter in PR #80) motivate the six mandatory rules below.

| Rule | Mandatory Constraint | Verification Before Merge |
| :--- | :--- | :--- |
| **One behavior per Tier 3 PR** | A PR modifying Tier 3 files changes one behavior and stays under roughly 400 changed lines excluding tests and generated files. | `gh pr diff <N> --name-only` and the PR description confirm one behavior. |
| **Independent review** | Any PR modifying Tier 3 files, a platform engine, or signal, memory, or locking paths receives a review from a person or reviewer agent who did not author it. | A review comment records findings or "no blocker". |
| **Real producers in tests** | Tests checking cross-boundary data (registers, signal frames, shared memory, wire formats) obtain data from the real platform, kernel, or guest probe rather than synthetic fixtures built with the same assumption. | The test fails before the fix when producer and consumer disagree. |
| **One contract per shared format** | Define any data layout shared between packages once with named constants and reference those constants on both sides. | `rg` finds no duplicated literal offsets outside the definition. |
| **Invariant for each race fix** | Every concurrency fix states the restored invariant and audits every caller of modified helpers. | The PR body lists the invariant and all callers. |
| **Per-sandbox state** | Never store per-sandbox limits, accounting, or guest-visible IDs in process-wide upstream globals. Document intentional host-wide globals in [`docs/architecture.md`](docs/architecture.md#312-state-shared-across-sandboxes-in-one-process). | Changes to accounting, limits, or IDs include a test running two sandboxes concurrently in one host process. |
