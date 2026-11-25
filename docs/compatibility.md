# Workload Compatibility and Limitations

This reference defines which Linux workloads run on `gvx`, which remain untested, and which kernel or host limits apply by design. Every compatibility claim traces directly to automated end-to-end tests in `e2e/` or documented platform constraints.

Black-box integration suites exercise `pkg/gvx` and `rungvx` across Windows, macOS, Linux (4 KiB and 16 KiB pages), and Android. Separate `pjdfstest` runs validate POSIX filesystem semantics on both `ext4lite` and `hostfs` across Linux and Windows.

Review the verified workloads, unverified targets, and canonical platform limits below before deploying specialized software.

---

## 1. Verified Workloads (`e2e/`)

The `e2e/` suite tests `pkg/gvx` and `rungvx` end-to-end across `linux/{amd64,arm64}`, `windows/{amd64,arm64}`, `darwin/arm64`, and `android/arm64` smoke environments.

| Workload Category | Verified Images and Binaries | Outcome and `e2e/` Source |
| :--- | :--- | :--- |
| **Shell and core utilities** | `alpine:3.20`, `busybox:1.36.1-musl`, static `busybox` | Interactive ash, pipes, signals, and stdio (`gate_m2_test.go`, `gate_m3_test.go`). |
| **HTTP servers and ports** | `nginx:alpine` (`-p`, `-P`, `--auto-publish`, `unix:`) | Static, exposed, dynamic, and Unix socket forwarding under lockdown (`gate_m3_test.go`, `auto_publish_e2e_test.go`). |
| **Python runtime** | `python:3.12-alpine` | `hashlib`, JSON, TLS clients, and loopback HTTP servers (`gate_m3_test.go`). |
| **Node.js and V8 JIT** | `node:22-alpine` | Dynamic V8 JIT, crypto, zlib, HTTP, and `node_modules` workloads (`gate_m3_test.go`, `gate_m4_test.go`). |
| **Java / HotSpot JVM** | `eclipse-temurin:21-jdk-alpine` | C2 JIT, 8-thread GC, parallel streams, and `membarrier` (`gate_jvm_test.go`). |
| **Git and POSIX workspaces** | `alpine/git:latest` | Commits, rebases, packfiles, hard links, atomic renames, and crash recovery (`gate_m4_test.go`). |
| **Static and non-PIE ELF64** | Static Go, static C, `herdr` (`ET_EXEC`) | Fixed-address non-PIE executables and servers (`gate_etexec_test.go`). |
| **Docker Engine (`docker:dind`)** | Unmodified `docker:dind` | `overlayfs` driver, `docker build`, legacy `iptables`, and container isolation (`gate_dockerd_test.go`, `docker_build_e2e_test.go`). |
| **Kubernetes (`rancher/k3s`)** | `rancher/k3s:v1.31.4-k3s1`, Calico `v3.28.2` | Single-node, two-node Flannel WireGuard, 3-node HA `etcd`, Calico `NetworkPolicy`, Sonobuoy `Quick` (`k3s_*_test.go`). |
| **Networking and overlays** | `iptables-legacy`, `conntrack`, `ipset`, VXLAN, WireGuard | Policy routing, `rp_filter`, proxy ARP, VXLAN, `-net=wg`, and bandwidth shaping (`ipset_e2e_test.go`, `vxlan_e2e_test.go`, `wireguard_*.go`). |
| **Volumes and overlays** | `ext4lite`, copy-on-write overlays, `-rootfs-volume`, single files | Persistent, capped, ephemeral, and shared read-only volumes (`volume_e2e_test.go`, `root_volume_e2e_test.go`, `filemount_e2e_test.go`). |
| **Resource controls (`cgroup2`)** | `memory.max`, `cpu.max`, `pids.max`, `io.stat` | Polling OOM killer, CFS quota throttling, and per-sandbox accounting (`cpumax_e2e_test.go`, `memory_accounting_e2e_test.go`). |
| **Checkpoint and restore** | Live and stop-mode bundles | Restores memory, `hostfs`, `ext4lite`, `rpcfs`, netns, `ipset`, and port forwards (`checkpoint_*_test.go`). |
| **Control protocol (`gvx-ctrl/2`)** | `exec`, `cp`, `export`, `update`, `mount serve`, `net-policy` | Authenticated live control and reverse Unix forwards under lockdown (`control_e2e_test.go`, `unix_forward_e2e_test.go`). |
| **Nested sandboxing** | Linux `rungvx` inside `rungvx` | `systrap` inside `systrap` or `hvf` (`nested_gvx_linux_test.go`). |

`pjdfstest` also runs in CI on Linux and Windows for `ext4lite` and `hostfs`. Unavoidable host filesystem exceptions appear in `scripts/pjdfstest/known-failures.txt`.

---

## 2. Unverified Workloads

Absence of an automated test means runtime behavior is not established by CI. Validate any workload below on your target host and backend before relying on it.

| Workload | Current Evidence State |
| :--- | :--- |
| **Relational and embedded databases (PostgreSQL, SQLite, MySQL, Redis)** | No `e2e/` test runs a database engine. `ext4lite` implements ordered JBD2 journaling and `fsync`, yet database durability remains untested in CI. |
| **Browsers and GUI automation (Chromium, Playwright, Puppeteer, Electron)** | No `e2e/` test runs a browser or Electron process. Software rendering and browser sandboxing remain untested, and host GPU acceleration is unimplemented (see [`moonshots.md`](moonshots.md)). |
| **Calico eBPF and BIRD BGP modes** | Calico is verified only in VXLAN mode with legacy iptables (`FELIX_IPTABLESBACKEND=Legacy`). BGP and eBPF datapaths are untested. |
| **Additional JVM releases** | Automated tests verify Eclipse Temurin 21 only. Other JVM builds and versions are untested. |

---

## 3. Unsupported Features and Platform Limits

This table is the canonical reference for omitted Linux interfaces, architecture restrictions, and host-specific boundaries.

| Area | Limitation | Scope and Practical Consequence |
| :--- | :--- | :--- |
| **Host OS: Intel macOS** | `darwin/amd64` is unsupported. | Run `gvx` only on Apple Silicon (`darwin/arm64`) Macs. |
| **Cross-architecture execution** | Guest CPU architecture must match the host CPU architecture. | No QEMU user-mode emulation, Rosetta 2, or Prism translation exists. |
| **Kernel modules and eBPF** | Loadable kernel modules (`insmod`), eBPF programs, and `bpf(2)` are unsupported. | eBPF CNIs such as Cilium fail; `/sys/fs/bpf` is a directory stub only. |
| **`nftables` and IPVS** | `nftables` and IPVS are unavailable. | Configure `dockerd`, `k3s`, `kube-proxy`, and Calico with legacy iptables (`IPTABLES_MODE=legacy`). |
| **`io_uring`** | `io_uring_setup` and `io_uring_enter` return `ENOSYS`. | Runtimes fall back to standard `epoll` automatically. |
| **Cgroup v1 and passive v2 knobs** | Only `cgroup2` mounts at `/sys/fs/cgroup`; several cgroup v2 controls do not throttle. | `io.stat` accounts block I/O, while `memory.high`, `cpu.weight`, `io.max`, `io.weight`, and `memory.swap.*` are stored without enforcement. |
| **Memory limit polling** | Periodic scans enforce `--memory` and `memory.max` rather than synchronous page-fault checks. | Sub-interval allocation spikes (such as under 30 ms) can escape detection; see [`recipes/docker-engine.md`](recipes/docker-engine.md#74-memory-limits-of-containers). |
| **Windows `systrap` security boundary** | Windows offers no kernel system-call trap comparable to Linux `seccomp`. | Code inside Windows `systrap` stubs can invoke NT services; use `whpx` for untrusted guests. |
| **Windows `systrap` fixed virtual ranges** | AddressSanitizer and 64-bit Wine fail at startup on Windows `systrap`. | Their fixed mappings cross host address holes (`0x7ffe0000`); run them under `whpx` instead. |
| **Windows `systrap` and Defender** | Stub hosts, debug objects, and patched views remain untested under Microsoft Defender. | Antivirus software can kill stub processes, causing guest exit code 137 (`ErrEngineFault`). |
| **Windows `systrap` self-reads and `arm64` exclusives** | Self-reading code pages observe patched bytes; `arm64` `stxr`/`stlxr` on executing pages raise `SIGSEGV`. | Ordinary ELF binaries and JITs run normally; self-modifying code differs from Linux. |
| **macOS `membarrier` scope** | macOS provides no process-wide cross-thread memory barrier primitive. | `membarrier` orders guest vCPU threads only and not concurrent Sentry syscalls. |
| **Host GPU acceleration** | No `/dev/dri/*` render device or host GPU worker ships in default builds. | Guests use CPU rendering; see [`moonshots.md`](moonshots.md) and [`extensions-plan.md`](extensions-plan.md). |
| **Android 32-process ceiling and SELinux** | Android 12+ caps total app children at 32; SELinux blocks app-data hard links. | Keep guest concurrency under 10 in a foreground service, and use `ext4lite` for hard links. |
| **Containerd shim scope** | `containerd-shim-gvx-v2` implements only Task v3 bootstrap and shutdown. | It returns `Unimplemented` on `CreateSandbox` and launches no guest workloads yet. |
