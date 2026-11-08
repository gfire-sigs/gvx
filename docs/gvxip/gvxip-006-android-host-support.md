# GVXIP-006: Android Host Support

This specification defines how `gvx` runs Linux workloads inside an Android app on `android/arm64` devices. It selects the execution engine, lists the Android limits that apply to it, and splits the work into phases with exit criteria. Each phase ends in pull requests that pass CI on their own.

| Field | Value |
| :--- | :--- |
| **Document ID** | `GVXIP-006` |
| **Title** | Android Host Support |
| **Status** | Proposed |
| **Isolation Tier** | Tier 2 (`_xplat.go` siblings with `android` build tags), Tier 3 seams in `pkg/sentry/platform/systrap`, and Tier 1 (`pkg/gvx`, `cmd/rungv`, new tool directories) |
| **Target Platforms** | `android/arm64` (devices), `android/amd64` (emulator only); `linux/amd64` and `linux/arm64` for phase P0 |
| **Companion Specs** | [`../architecture.md`](../architecture.md), [`../systrap-windows.md`](../systrap-windows.md) |

The phases below have a fixed order. A phase ends when every test of its exit criterion in section 5 passes.

| Phase | Content | Release effect |
| :--- | :--- | :--- |
| P0 | Bound the idle stub pool of the Linux `systrap` engine | Changes Linux behavior; increases `MINOR` |
| P1 | Android build target and device probe | No user change |
| P2 | Host adaptations that the probe requires | No user change until P3 |
| P3 | Android SDK package and sample app | First Android release |
| P4 | Diagnostics for process limits | User-visible messages |
| P5 | Devices with 16 KB pages | Extends the device set |

---

## 1. Facts (Reference Module)

The facts below come from the `gvx` source tree, its Git history, and Android documentation. A fact without a source in this table is an inference, and phase P1 verifies it.

### 1.1 Android Limits

| ID | Limit | Effect on `gvx` | Source |
| :--- | :--- | :--- | :--- |
| F1 | The Android kernel is Linux. Go selects `*_linux.go` files for `GOOS=android`. | The upstream Linux `systrap` engine and the Linux host code compile for Android. | Go build constraints |
| F2 | AVF APIs are `@SystemApi`. `MANAGE_VIRTUAL_MACHINE` is for privileged apps on Android 14 and preinstalled apps on Android 15. `adb shell pm grant` grants it for development. | A store app cannot start a VM. | AOSP `libs/framework-virtualization/README.md` |
| F3 | AVF starts a whole `crosvm` VM. It has no API for vCPU exits, guest registers, or guest physical memory. | AVF cannot be a backend in the form of `hvf` or `whpx`. | AOSP AVF documentation |
| F4 | Android kills phantom processes (processes that an app forks) above 32. The limit counts all apps together. Inside one app, older processes die first. | A `systrap` sandbox with more than about 31 live stubs loses its oldest stub and stops. | `agnostic-apollo/Android-Docs`, `PhantomProcessList` |
| F5 | Android also kills a phantom process that uses excessive CPU while its app is in the background. Android 12 has no switch for this. | A build in a background app can die. A foreground service avoids it. | Same as F4 |
| F6 | Switches for F4 and F5: `max_phantom_processes` with `device_config` (Android 12), `settings_enable_monitor_phantom_procs` (Android 12L and 13), and "Disable child process restrictions" (Android 14 and later). | Each switch needs `adb` or developer options. | Same as F4 |
| F7 | Android 15 adds kernels with 16 KB pages. | The Linux `systrap` engine maps memory in host pages, so 4 KB-aligned segments fail on such a device. | Android 15 release notes |

### 1.2 Engine Facts

| ID | Fact | Source |
| :--- | :--- | :--- |
| F8 | Each guest address space has one stub process. The pool keeps every released stub, and nothing bounds the pool. | `pkg/sentry/platform/systrap/subprocess.go` (`release`), `subprocess_pool.go` |
| F9 | A pooled stub keeps its sysmsg threads. Their count grows to `min(GOMAXPROCS, guest threads)` and never drops in the normal path. | `subprocess.go` (`kickSysmsgThread`) |
| F10 | Stubs start with `CLONE_PARENT`, so the Sentry process reaps them. No path destroys a live stub. | `subprocess_linux.go`, `subprocess.go` (`kill`, `release`) |
| F11 | The lowest guest address of the Linux engine is `/proc/sys/vm/mmap_min_addr`. The package `init` panics when it cannot read that file. | `pkg/sentry/platform/mmap_min_addr.go`, `systrap.go` (`MinUserAddress`) |
| F12 | The zone mode of the removed macOS engine rewrote fixed-address code only because macOS reserves a 4 GB `PAGEZERO`. Linux has no such range. | Commits `95454d98`, `38b62d16` |
| F13 | The removed macOS engine had a 4 KB sub-block engine for 16 KB host pages. It reported `SIGSEGV` for a store into the block of the storing instruction. The Windows engine completes that store with a single step. | Commits `132d9fe9`, `47ab2a62`, `95cda8e4` |
| F14 | The commit that removed the macOS engine states no reason. The architecture document names the 16 KB pages and `PAGEZERO`. | Commit `54b7ad53`, `docs/architecture.md` section 3.3 |

---

## 2. Method (Descriptive Module)

This section states the design decisions and their reasons. Section 3 turns each decision into work items.

### 2.1 Execution Engine

Android runs the upstream Linux `systrap` engine, the engine that CI tests on `linux/arm64`. Android gives a store app no hypervisor (F2), and AVF exposes no vCPU interface (F3). This specification therefore uses no AVF mode. A rooted device with `/dev/kvm` could use the upstream KVM platform, but `gvx` does not connect it on Linux, and this specification leaves it out.

The Sentry runs inside the app process through a Go library binding. This choice removes one phantom process (F4). It also removes the oldest phantom process, which Android kills first.

### 2.2 Fixed-Address Executables

A non-PIE executable needs no rewrite on Android (F12). Go links `arm64` programs at `0x10000`, and GNU `ld` links at `0x400000`. Both addresses lie above the expected `mmap_min_addr` of 32768. Phase P1 verifies this value and the readability of the file on real devices (F11).

### 2.3 Process Limit

The idle stub pool gets a bound (F8). The bound applies to every Linux build, so Linux CI runs the destroy path in every end-to-end test. Each OS gets its own bound `K`:

| Build | `K` | Reason |
| :--- | :--- | :--- |
| `android` | 2 | F4 counts every live stub. |
| `linux && !android` | `GOMAXPROCS`, clamped to 8 through 32 | A pooled stub holds up to `GOMAXPROCS + 1` host threads (F9). The bound keeps reuse for parallel builds and caps `pids.max` use. |

The pool is process-wide upstream state, because one stub pool serves every sandbox of the process. A per-sandbox tunable would conflict between two sandboxes, so `K` is a constant for each OS. Section 6 of [`../architecture.md`](../architecture.md) records this process-wide state.

The bound limits the stubs that wait in the pool. It does not limit the live stubs of a workload with more than about 31 concurrent guest processes. Phase P4 reports that case and names the switch of F6.

### 2.4 Devices with 16 KB Pages

Phase P5 ports the sub-block engine of the macOS engine (F13) to Android as a sibling engine. Linux lets the Sentry single-step a stub thread with `ptrace`. The port therefore completes a store into the block of the storing instruction, as the Windows engine does. P5 starts only after the reason for the removal of the macOS engine is known (F14).

---

## 3. Work Breakdown (Reference Module)

Each work item lists its change, its files, its tier, and the check that proves it. A row with a PR number is one pull request. The independent review rule of `AGENTS.md` section 6 applies to every PR that changes `pkg/sentry/platform/systrap`.

### 3.1 P0: Idle Stub Pool Bound

| Item | Change | Files | Tier | Proof |
| :--- | :--- | :--- | :--- | :--- |
| P0-1 (PR 1) | `markAvailable` returns false when the pool holds `K` stubs. `release` destroys a refused stub after it unlocks the pool. The request loop of a stub returns on a stop request. | `subprocess_pool.go`, `subprocess.go` | Tier 3 seams | T0-1, T0-2, T0-3 |
| P0-2 (PR 1) | `destroyIdle` kills the stub, stops its request loop, reaps it with `wait4`, closes the seccomp listener, and unmaps and releases its memory-file ranges. | new `subprocess_destroy_xplat.go` (`linux`) | Tier 2 | T0-2 |
| P0-3 (PR 1) | Constant `K` for each build. | new `idle_stubs_xplat.go` (`linux && !android`), `idle_stubs_android_xplat.go` (`android`) | Tier 2 | T0-4 |
| P0-4 (PR 1) | Record the process-wide pool in the architecture document and the change in `CHANGELOG.md`. | `docs/architecture.md`, `CHANGELOG.md` | Tier 1 | Review |
| P0-5 (PR 2) | Measure `K` on `linux/arm64` and set the final values. | `idle_stubs_*_xplat.go` | Tier 2 | B0-1 |

The memory-file ranges of a stub are its context queue, its thread context region, its syscall thread message area, and one stack for each sysmsg thread.

### 3.2 P1: Build Target and Device Probe

| Item | Change | Files | Tier | Proof |
| :--- | :--- | :--- | :--- | :--- |
| P1-1 (PR 3) | Build `GOOS=android GOARCH=arm64` and `amd64` in the job `build, vet, and audit`. Fix compile errors in owned packages. | `.github/workflows/ci.yml`, owned packages | Tier 1 | CI |
| P1-2 (PR 3) | Accept the token `android` as a Tier 2 sibling in the upstream audit. | `tools/upstream` | Tier 1 | `go test ./tools/upstream` |
| P1-3 (PR 4) | Add a probe that runs inside an app as `untrusted_app`. It reports each item of section 3.2.1. | new `tools/androidprobe` (Go library and test APK) | Tier 1 | T1-1 |
| P1-4 (PR 5) | Add a manual workflow that runs the probe and the `systrap` smoke tests on an Android emulator. | new `.github/workflows/android.yml` (`workflow_dispatch` only) | Tier 1 | T1-2 |

#### 3.2.1 Probe Items

The probe must run as an app, because the `adb shell` domain has other SELinux and seccomp rules than `untrusted_app`. Each item reports a value or the exact error.

| Probe | Question |
| :--- | :--- |
| `mmap_min_addr` | Can the app read the file, and what is the value (F11)? |
| Page size and address bits | What do `getpagesize` and the `TaskSize` search return? |
| `ptrace` | Can the app attach to a child and single-step it? |
| `seccomp` | Do `SECCOMP_RET_TRAP` and a user notification listener work under the filter of the app? |
| `memfd` | Can the app map a `memfd` with `PROT_EXEC` in itself and in a child? |
| Stub start | Does the upstream stub start, unmap its address space, and run one guest system call? |
| Host system calls | Does any system call of the Sentry hit the seccomp filter of the app? |
| Phantom count | How many `PhantomProcessRecord` entries does a burst of 40 guest processes create? |

### 3.3 P2: Host Adaptations

The items below are candidates. Phase P1 decides which items stay.

| Item | Change | Files | Tier | Proof |
| :--- | :--- | :--- | :--- | :--- |
| P2-1 | Read `mmap_min_addr` through an Android sibling that falls back to 32768 when SELinux denies the read. Register the build-tag change. | `pkg/sentry/platform/mmap_min_addr*.go`, `tools/upstream/buildtag_allowlist.txt` | Tier 2 and Tier 3 tag | T2-1 |
| P2-2 | Pass DNS servers from the app to the sandbox, because Android has no `/etc/resolv.conf`. | `pkg/gvx` (`Config`), `pkg/netbackend` | Tier 1 | T2-2 |
| P2-3 | Compare the host system calls of the Sentry with the app filter of Android, and remove or replace each call that the filter kills. | `scripts/seccomp-audit.sh`, affected packages | Tier 1 or Tier 2 | T1-1 (host system calls) |
| P2-4 | Verify the file identity probe of `hostfs` on `f2fs` and `ext4` app storage. | `pkg/sentry/fsimpl/hostfs` | Tier 1 | T2-3 |

### 3.4 P3: SDK Package

| Item | Change | Files | Tier | Proof |
| :--- | :--- | :--- | :--- | :--- |
| P3-1 | Export a binding API over `pkg/gvx`: run, stop, standard I/O streams, mounts, and volumes. The Sentry runs in the app process. | new `pkg/gvx/mobile` | Tier 1 | T3-1 |
| P3-2 | Add a sample app with a foreground service (F5) and app storage paths for the OCI cache and volumes. | new `examples/android` | Tier 1 | T3-2 |
| P3-3 | Build and attest the Android archive in the release workflow. | `.github/workflows/release.yml` | Tier 1 | Release run |

### 3.5 P4: Diagnostics

| Item | Change | Files | Tier | Proof |
| :--- | :--- | :--- | :--- | :--- |
| P4-1 | A stub can die by a `SIGKILL` that the Sentry did not send. The engine fault then names the phantom process limit and the switch for the Android version (F6). | `pkg/gvx`, `pkg/sentry/platform/systrap` (Tier 2 file) | Tier 1 and Tier 2 | T4-1 |
| P4-2 | Write one warning when the live stubs reach 24. | Same | Tier 2 | T4-2 |
| P4-3 | Document the limits, the switches, and the foreground service. | `README.md`, `docs/cli.md` | Tier 1 | Review |

### 3.6 P5: Devices with 16 KB Pages

| Item | Change | Files | Tier | Proof |
| :--- | :--- | :--- | :--- | :--- |
| P5-1 | Find the reason for the removal of the macOS engine in the session history (F14). Stop P5 if the reason applies to Linux. | None | None | Written finding |
| P5-2 | Restore the sub-block engine from commit `54b7ad53^` as an Android sibling. Remove the zone mode and the macOS code. | `pkg/sentry/platform/systrap/*_android_xplat.go`, `pkg/sentry/mm` (Tier 2 files) | Tier 2 | T5-1 |
| P5-3 | Complete a store into the block of the storing instruction with `PTRACE_SINGLESTEP`. | Same | Tier 2 | T5-2 |
| P5-4 | Enable the write reports of the memory file on Android, so private copies stay coherent with Sentry writes. | `pkg/sentry/pgalloc` (Tier 2 file) | Tier 2 | T5-3 |

---

## 4. Tests (Reference Module)

Each test uses the real producer of the data that it checks, as section 6 of `AGENTS.md` requires. Tests T0 run in Linux CI. Tests T1 to T5 run on the emulator workflow or on a device.

| ID | Test | Producer | Failure it catches |
| :--- | :--- | :--- | :--- |
| T0-1 | Create 8 address spaces, release them, and count the child processes of the Sentry in `/proc/self/task/*/children`. The count must be `K + 1`. A second round of 8 must work. | Host kernel | Unbounded pool; zombie stubs |
| T0-2 | With `K = 0`, create and release 500 address spaces. The counts of `/proc/self/fd`, `/proc/self/maps`, and child processes, and the memory-file usage, must return to their first values. | Host kernel, `pgalloc` | A leaked range, descriptor, mapping, or stub |
| T0-3 | Release and create address spaces while other address spaces call `MapFile`, under `-race`. | Engine | Lock order errors |
| T0-4 | With the default `K`, the child process count stays at or below live address spaces plus `K + 1`. | Host kernel | A wrong default |
| B0-1 | Run `sh -c 'for i in $(seq 2000); do /bin/true; done'` and a `make -j4` build. Repeat with `K` = 0, 1, 2, 4, 8, 16, `GOMAXPROCS`, and no bound. | Engine | Choose the smallest `K` within 5% of no bound |
| T1-1 | Probe report of section 3.2.1 on a 4 KB emulator image and on one device. | Android | Unknown limits |
| T1-2 | `TestE2EGateETExec` and `TestE2ESystrapCodeWrites` run in the sample app on the emulator. | Guest programs | Engine gaps on Android |
| T2-1 | A guest maps `0x10000` after the fallback read of `mmap_min_addr`. | Guest program | Wrong lowest address |
| T2-2 | A guest resolves a registry name and pulls an image. | Network | Missing DNS servers |
| T2-3 | The `hostfs` metadata tests pass on app storage. | Host file system | Wrong file identity |
| T3-1 | The binding runs a guest command and returns its exit code and output. | Guest program | Broken binding |
| T3-2 | The sample app runs a guest for 10 minutes in the background with its foreground service. | Android | F5 kills |
| T4-1 | Kill a stub with `SIGKILL` from outside. The fault message names the phantom process limit. | Host kernel | Silent "subprocess died" |
| T4-2 | Start 24 concurrent guest processes. The log has one warning. | Engine | Missing warning |
| T5-1 | `TestE2EGateETExec` passes on a 16 KB emulator image. | Guest programs | Sub-block mapping gaps |
| T5-2 | A guest stores into the 4 KB page of its own code inside one 16 KB host page. | Guest program | The fault loop of F13 |
| T5-3 | A guest maps a file shared, and a `write` system call changes it. The mapping shows the new bytes. | Guest program | Stale private copies |

---

## 5. Exit Criteria of the Phases (Reference Module)

A phase ends when the tests below pass and the listed release step is complete.

| Phase | Tests | Release step |
| :--- | :--- | :--- |
| P0 | T0-1 to T0-4 pass on `linux/amd64` and `linux/arm64`; B0-1 results are in PR 2 | Release with an increased `MINOR` |
| P1 | T1-1 report is in this document; T1-2 passes on the 4 KB emulator image | None |
| P2 | T2-1 to T2-3 pass on the emulator | None |
| P3 | T3-1 and T3-2 pass on the emulator and one device | First Android archive |
| P4 | T4-1 and T4-2 pass | Next release |
| P5 | P5-1 finding is in this document; T5-1 to T5-3 pass on the 16 KB emulator image | Next release |

---

## 6. Risks and Open Questions (Reference Module)

| ID | Risk or question | Phase that answers it |
| :--- | :--- | :--- |
| R1 | SELinux can deny `ptrace`, `memfd` execution, or the read of `mmap_min_addr` for `untrusted_app`. | P1 |
| R2 | The seccomp filter of the app can kill a host system call of the Sentry with `SIGSYS`. | P1, P2 |
| R3 | Workloads with more than about 31 concurrent guest processes exceed F4 even with the pool bound. | P4 |
| R4 | Google Play rules on downloaded executable code can block store distribution of an app that pulls OCI images. | P3 |
| R5 | The reason for the removal of the macOS engine can apply to Linux. | P5 |
| R6 | A 39-bit address space can break guests that expect 47 bits, such as programs built with ThreadSanitizer. | P1 |

---

## 7. Sources (Reference Module)

The sources below support the facts of section 1. The commits refer to this repository.

- AOSP Virtualization module, `libs/framework-virtualization/README.md`: <https://android.googlesource.com/platform/packages/modules/Virtualization/+/refs/heads/main/libs/framework-virtualization/README.md>
- AVF stubs and permission grants: <https://github.com/freundTech/android-avf-stubs>
- Phantom, cached, and empty processes: <https://github.com/agnostic-apollo/Android-Docs/blob/master/en/docs/apps/processes/phantom-cached-and-empty-processes.md>
- Commits `95454d98` (zone mode), `132d9fe9` (sub-block engine), `47ab2a62` (store into the storing block), `95cda8e4` (Windows single step), `54b7ad53` (engine removal), `38b62d16` (removal note)
