# Glossary

This glossary defines the technical terms, subsystems, execution backends, and deliverables used across `gvx` documentation.

| Term | Definition |
| :--- | :--- |
| **Address space hole** | A guest virtual address range reserved by the host OS (such as `KUSER_SHARED_DATA` on Windows `systrap`). Sentry never maps guest pages there. |
| **Chunk cache (`chunkcache`)** | The shared 64 KiB page-chunk cache (`pkg/sentry/fsimpl/chunkcache`) backing guest `mmap` mappings across hardware and stub backends. |
| **Containerd shim (`containerd-shim-gvx-v2`)** | The optional control-plane binary (`cmd/containerd-shim-gvx-v2`, `internal/gvxshim`) implementing containerd Task v3 bootstrap and shutdown without launching guest workloads. |
| **Control protocol (`gvx-ctrl/2`)** | The framed binary RPC protocol (`pkg/gvx/control`) served over an owner-only Unix socket or loopback TCP listener bound before lockdown. See [`control-protocol.md`](control-protocol.md). |
| **EROFS** | Enhanced Read-Only File System. `pkg/oci` compiles container `.tar` layers into 4 KiB EROFS images so Linux metadata never touches NTFS or APFS. |
| **`ext/` submodule** | The nested Go module (`ext/go.mod`) isolating optional hardware extensions (`-tags ext_gpu`, `-tags ext_all`) from root `go.mod`. See [`extensions-plan.md`](extensions-plan.md). |
| **`ext4lite`** | Single-file ext4 filesystem driver (`pkg/sentry/fsimpl/ext4lite`) storing each volume in one `<name>.ext4` image with an ordered JBD2 journal. See [`components/ext4lite.md`](components/ext4lite.md). |
| **Extension SPI** | The typed plugin contracts (`gvx.Extension`, `gvx.BoundExtension`, `rungvx.CLIPlugin`) enabling optional host extensions without pulling native dependencies into pure-Go builds. |
| **Guest / Host** | The *host* is the physical OS running `rungvx` or a Go embedder. The *guest* is the isolated Linux user space inside the sandbox. |
| **`gvx-android.aar`** | The Android archive built by `scripts/android/build-sdk.sh`, bundling `dev.gfire.gvx.Gvx` and `librungvx.so` for `android/arm64`. See [`components/android.md`](components/android.md). |
| **`hostfs`** | Pinned host VFS2 driver (`pkg/sentry/fsimpl/hostfs`) anchoring mounts to `os.Root`, encoding incompatible names, and storing POSIX metadata in `.gvx_meta`. See [`components/hostfs.md`](components/hostfs.md). |
| **`hostlockdown`** | Pre-execution confinement package (`pkg/hostlockdown`) blocking child spawns, unbound file opens, and unauthorized sockets before guest entry. See [`components/hostlockdown.md`](components/hostlockdown.md). |
| **`hvf`** | The Apple Silicon backend (`pkg/sentry/platform/hvf`), running guest EL0 code via `Hypervisor.framework` with 4 KiB Stage-1 paging. See [`components/hypervisors.md`](components/hypervisors.md). |
| **Isolation Tiers (1, 2, 3)** | Repository layout separating `gvx` packages (Tier 1), `_windows`/`_darwin`/`_xplat` siblings (Tier 2), and allowlisted upstream patches (Tier 3, `< 5.0%`). |
| **Netstack (`pkg/tcpip`)** | gVisor's pure-Go TCP/IP stack providing guest `lo`, `eth0`, bridges, `veth`, legacy `iptables`, `conntrack`, VXLAN, and WireGuard links. |
| **`netbackend`** | Host networking adapter (`pkg/netbackend`) linking Netstack to unprivileged host sockets (`-net=nat`) or an in-memory `wireguard-go` tunnel (`-net=wg`). See [`components/netbackend.md`](components/netbackend.md). |
| **OCI Layer Cache** | Host directory storing compiled `.erofs` image layers, manifests, and optional compressed blobs (`-keep-blobs`), administered through `pkg/oci` and `rungvx image`. |
| **`rpcfs`** | Client-served proxy VFS2 driver (`pkg/sentry/fsimpl/rpcfs`) backing `rungvx mount serve` to expose pinned host directories over `gvx-ctrl/2`. |
| **`rungvx`** | The standalone foreground CLI (`cmd/rungvx`, `pkg/rungvx`) executing OCI images and ELF64 binaries and controlling live sandboxes. See [`cli.md`](cli.md). |
| **Sandbox** | One isolated execution instance (`gvx.Sandbox`) owning a Sentry kernel, backing memory file, execution platform, mounts, network stack, and optional control listener. |
| **Sentry** | gVisor's pure-Go Linux kernel (`pkg/sentry/kernel`) implementing system calls, signals, virtual memory, filesystems, and cgroups in user space. |
| **Stub process** | An unprivileged child process used by `systrap` to execute guest instructions in a separate address space away from the Go heap. |
| **`systrap`** | Stub-process backend (`pkg/sentry/platform/systrap`). Linux and Android use `seccomp` traps; Windows (`winsystrap`) uses opt-in binary rewriting. See [`systrap-windows.md`](systrap-windows.md). |
| **Tunable** | A typed host-side limit or timeout registered in `pkg/gvx/tuning` and configured via `--tune KEY=VALUE` or `--tune-file`. |
| **`whpx`** | The Windows hypervisor backend (`pkg/sentry/platform/whpx`), running guest code via `WinHvPlatform.dll` with 4 KiB guest paging. See [`components/hypervisors.md`](components/hypervisors.md). |
| **`winsystrap`** | Shorthand for the Windows `platform/systrap` engine, serving trusted workloads on Windows hosts without WHP. See [`systrap-windows.md`](systrap-windows.md). |
