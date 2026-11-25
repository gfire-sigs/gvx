# Workload Compatibility and Limitations

This document answers a direct practical question: which Linux workloads are verified to run on `gvx`, which remain unverified, and which are unsupported by design. Every compatibility claim below traces directly to automated end-to-end tests in `e2e/` (180 `TestE2E*` functions) or to documented host-platform constraints.

---

## 1. Verified Workloads (`e2e/`)

The `e2e/` test suite exercises `pkg/gvx` and `cmd/rungv` as black-box binaries across Linux (`amd64`, `arm64`, 4 KiB and 16 KiB host pages), Windows (`amd64` `whpx` and `systrap`; `arm64` `systrap`), macOS (`arm64` `hvf`), and Android (`arm64` emulator smoke).

| Workload Category | Verified Images or Binaries | Representative `e2e/` Tests |
| :--- | :--- | :--- |
| **Shell and core utilities** | `alpine:3.20`, `busybox:1.36.1-musl`, static `busybox` | `TestE2EGateM2BusyboxAshInteractive`, `TestE2EGateM3Alpine`, `TestE2ESystrapBusyboxPipeline` |
| **HTTP servers and port forwarding** | `nginx:alpine` with `-p`, `-P`, `--auto-publish`, Unix socket publish | `TestE2EGateM3NginxPortForward`, `TestE2EDockerRunPublishAllBindsTheExposedPorts`, `TestE2EAutoPublishUnderHostLockdown` |
| **Python runtime** | `python:3.12-alpine` (hashlib, JSON, HTTP server on loopback, TLS) | `TestE2EGateM3PythonAlpine`, `TestE2ESystrapPythonAlpine` |
| **Node.js and V8 JIT** | `node:22-alpine` (crypto, zlib, V8 dynamic JIT, loopback HTTP, `node_modules` tree torture) | `TestE2EGateM3NodeAlpine`, `TestE2EGateM4NodeModulesTorture` |
| **Java / HotSpot JVM** | `eclipse-temurin:21-jdk-alpine` (C2 JIT, 8-thread concurrency, GC, parallel streams, `membarrier`) | `TestE2EGateJVM` |
| **Git and POSIX workspace torture** | `alpine/git:latest` (commits, rebases, packfiles, hard links, atomic renames, crash recovery) | `TestE2EGateM4GitWorkloads`, `TestE2EGateM4PosixTortureBusybox`, `TestE2EGateM4MetaSurvivesSigkill` |
| **Static and non-PIE ELF64 (`ET_EXEC`)** | Static Go, static C, fixed-address `herdr` binary and server | `TestE2EGateETExecGoStatic`, `TestE2EGateETExecCStatic`, `TestE2EGateETExecHerdrServer` |
| **Docker Engine (`docker:dind`)** | Unmodified `docker:dind` with `overlayfs`, `docker build` (local and upstream), `iptables`, container isolation | `TestE2EDockerRunDindEngine`, `TestE2EDockerBuildDindLocalRegistry`, `TestE2EDockerIccSeparatesContainers` |
| **Kubernetes (`rancher/k3s`)** | `rancher/k3s:v1.31.4-k3s1` single-node, two-node (`flannel` WireGuard), 3-node HA `etcd`, `kube-router` and Calico `v3.28.2` VXLAN `NetworkPolicy`, Sonobuoy `Quick` and `[sig-network] Services` | `TestE2EK3sSingleNode`, `TestE2EK3sNetworkPolicy`, `TestE2EK3sCalico`, `TestE2EK3sMultiNodeT1Join`, `TestE2EK3sMultiNodeControlPlaneFailover`, `TestE2EK3sConformanceQuick`, `TestE2EK3sConformanceServices` |
| **Networking, netfilter, and overlays** | `iptables-legacy`, `conntrack`, `ipset`, policy routing, `rp_filter`, proxy ARP, VXLAN, WireGuard (`wg0` and `-net=wg`), NAT throughput, MTU changes | `TestE2EIPSetNetfilter`, `TestE2EPolicyRouting`, `TestE2EVxlanA13TwoSandboxesOverWireGuard`, `TestE2EWireGuardFullTunnel`, `TestE2ENATThroughput` |
| **Persistent volumes and overlays** | `ext4lite` named, capped, ephemeral, shared read-only, and copy-on-write overlay mounts; `-rootfs-volume`; single-file bind mounts | `TestE2EVolumePersistsAcrossSandboxes`, `TestE2EEphemeralAndCappedVolumeUnderLockdown`, `TestE2EOverlayUpperPersistsAcrossSandboxes`, `TestE2ERootfsVolumePersistenceAndCLI`, `TestE2EFileBindMountExposesOnlyTheFile` |
| **Resource controls (`cgroup2`)** | `memory.max` OOM killer, `cpu.max` CFS quota enforcement, per-sandbox accounting, `pids.max` | `TestE2ECPUMaxEnforcement`, `TestE2EMemoryCgroupLimits`, `TestE2EMemoryAccountingIsPerSandbox` |
| **Checkpoint and restore** | Live and stop-mode save/restore of memory, `hostfs`, `ext4lite`, `-rootfs-volume`, `rpcfs`, network namespaces, `ipset`, port forwards | `TestE2ECheckpointRestoreMemoryState`, `TestE2ECheckpointRestoreExt4liteState`, `TestE2ECheckpointRestoreNetnsIPSetPortForwarding`, `TestE2ECheckpointRestoreRungvCLIRoundTrip` |
| **Control protocol (`gvx-ctrl/2`)** | `exec`, `cp`, `export`, `update`, dynamic ports, `unix-forward`, `mount serve` (`rpcfs`), `net-policy` under host lockdown | `TestE2EControlProtocolUnderLockdown`, `TestE2EDynamicPortsUnderLockdown`, `TestE2EReverseUnixForwardUnderLockdown` |
| **Nested sandboxing** | Linux `rungv` inside `rungv` (`systrap` in `systrap` or `hvf`) | `TestE2ENestedRungvInRungv` |

In addition to `e2e/`, the POSIX filesystem conformance suite `pjdfstest` runs continuously in CI against both `ext4lite` and `hostfs`, with unavoidable host-filesystem exceptions recorded in `scripts/pjdfstest/known-failures.txt`.

---

## 2. Unverified Workloads

Absence of an automated test means runtime behavior is not established by CI. Do not assume support for these workloads without testing on your target host and backend:

| Workload | Current Evidence State |
| :--- | :--- |
| **Relational and embedded databases (PostgreSQL, SQLite, MySQL, Redis)** | No test under `e2e/` runs a database engine. Although `ext4lite` implements ordered JBD2 journaling, `fsync`, and POSIX file locking, database durability and concurrency behavior remain unverified in CI. |
| **Browsers and GUI automation (Chromium, Playwright, Puppeteer, Electron)** | No test under `e2e/` starts a browser or Electron process. Both software rendering and multi-process Chromium sandboxing are unverified, and hardware GPU acceleration is unimplemented (see [`moonshots.md`](moonshots.md)). |
| **Calico eBPF and BIRD BGP modes** | Calico is verified only in VXLAN mode with legacy iptables (`FELIX_IPTABLESBACKEND=Legacy`). BGP and eBPF datapaths are untested. |
| **Additional JVM implementations and versions** | `TestE2EGateJVM` verifies Eclipse Temurin 21 (and manual probes tested Temurin 25 on `windows-11-arm`). Other JVMs and `javac` releases are untested. |

---

## 3. Unsupported Features and Consolidated Platform Limits

All known architectural omissions and platform restrictions are gathered here so evaluators need not consult multiple design documents.

| Area | Limitation | Scope and Practical Consequence |
| :--- | :--- | :--- |
| **Host OS: Intel macOS** | `darwin/amd64` is not supported. | Only Apple Silicon (`darwin/arm64`) Macs are supported. |
| **Cross-architecture execution** | Guest CPU architecture must match the host CPU architecture on every backend. | No QEMU user-mode emulation, Rosetta 2, or Prism translation. Run `linux/arm64` on ARM64 hosts and `linux/amd64` on x86-64 hosts. |
| **Kernel modules and eBPF** | Loadable kernel modules (`insmod`), eBPF programs, and `bpf(2)` are unsupported. | eBPF-based CNIs such as Cilium cannot run. `/sys/fs/bpf` exists only as a stub directory mountpoint for tools that probe its presence. |
| **`nftables` and IPVS** | `nftables` and IPVS are unavailable. | Configure `dockerd`, `k3s`, `kube-proxy`, and Calico to use legacy iptables (`IPTABLES_MODE=legacy`). |
| **`io_uring`** | `io_uring_setup` and `io_uring_enter` return `ENOSYS`. | Runtimes fall back to standard `epoll` automatically. |
| **Cgroup v1** | Only `cgroup2` is mounted at `/sys/fs/cgroup`. | Legacy tools requiring cgroup v1 hierarchies are unsupported. `memory.high`, `cpu.weight`, and `memory.swap.*` are accepted and stored without enforcement. |
| **Memory limit polling** | `--memory` and guest `memory.max` are enforced by periodic polling rather than synchronous page-fault accounting. | Short allocation spikes lasting less than one poll interval (for example, under 30 ms) may escape OOM detection. See [`recipes/docker-engine.md`](recipes/docker-engine.md#74-memory-limits-of-containers). |
| **Windows `systrap` security boundary** | Windows provides no unprivileged kernel system-call filter comparable to Linux `seccomp`. | Hostile code inside a Windows `systrap` stub can branch to `ntdll` stubs or invoke NT services from anonymous `amd64` RWX pages under the stub's Low-integrity restricted token. Always use `whpx` for untrusted workloads on Windows. |
| **Windows `systrap` fixed virtual ranges** | AddressSanitizer (`amd64` and `arm64`) and 64-bit Wine fail at startup on Windows `systrap`. | Their fixed virtual address reservations cross reserved address-space holes (such as `KUSER_SHARED_DATA` at `0x7ffe0000`). Run them under `whpx` instead. |
| **Windows `systrap` and Microsoft Defender** | The stub host, debug object, and patched executable views are untested under default Microsoft Defender settings. | Endpoint protection software may terminate stub processes, causing guest exit code 137 (`ErrEngineFault`). |
| **Windows `systrap` code-page reads and `arm64` store-exclusives** | A guest reading its own executing code page observes patched bytes; `arm64` `stxr`/`stlxr`/`stxp`/`stlxp` storing into their own executing page raise `SIGSEGV`. | Ordinary ELF binaries and JIT compilers are unaffected; self-inspecting binaries differ from Linux. |
| **macOS `membarrier` scope** | macOS offers no host API to issue a memory barrier across all threads of a process. | `membarrier` orders guest vCPU threads only and does not serialize Sentry goroutines performing concurrent system calls. |
| **Host GPU acceleration** | No `/dev/dri/*` DRM device or host GPU renderer exists in the repository. | Guests have CPU rendering only. See [`moonshots.md`](moonshots.md) for the unimplemented proposal. |
| **Android 32-process ceiling and SELinux** | Android 12+ limits total child processes across all apps to 32; SELinux denies `linkat` hard links on app-data files. | Long Android guests require a foreground service and fewer than 10 concurrent guest processes unless phantom process monitoring is disabled. Use `ext4lite` volumes for POSIX hard links on Android. |
| **Containerd shim scope** | `containerd-shim-gvx-v2` implements only the Task v3 control-plane bootstrap and shutdown adapter. | It rejects `CreateSandbox` with `Unimplemented` and does not launch guest workloads through containerd yet. |
