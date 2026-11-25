# Glossary

This glossary defines the technical terms, subsystems, execution backends, and deliverables used throughout the `gvx` documentation.

| Term | Definition |
| :--- | :--- |
| **Address space hole** | A range of guest virtual addresses reserved by the host operating system (for example, `KUSER_SHARED_DATA` on Windows `systrap`) that the Sentry memory manager never allocates to guest mappings. |
| **Chunk cache (`chunkcache`)** | The shared 64 KiB page-chunk cache (`pkg/sentry/fsimpl/chunkcache`) used by `hostfs` and `ext4lite` to back guest `mmap` mappings cleanly across hardware and stub backends. |
| **Containerd shim (`containerd-shim-gvx-v2`)** | The optional control-plane binary (`cmd/containerd-shim-gvx-v2`, `internal/gvxshim`) implementing containerd Task v3 bootstrap, lease management, and shutdown without launching guest workloads. |
| **Control protocol (`gvx-ctrl/2`)** | The framed, multiplexed binary RPC protocol (`pkg/gvx/control`) served over an owner-only Unix socket or authenticated loopback TCP listener bound before host lockdown. See [`control-protocol.md`](control-protocol.md). |
| **EROFS** | Enhanced Read-Only File System. `pkg/oci` compiles container `.tar` layers directly into cached 4 KiB-block EROFS images so Linux filenames, permissions, and whiteouts never touch host NTFS or APFS. |
| **`ext4lite`** | Pure-Go single-file ext4 filesystem driver (`pkg/sentry/fsimpl/ext4lite`) storing each named volume or persistent root overlay in one `<name>.ext4` image file with an ordered JBD2 metadata journal. See [`components/ext4lite.md`](components/ext4lite.md). |
| **Guest / Host** | The *host* is the physical machine and OS running `rungvx` or a Go embedder (macOS, Windows, Linux, or Android). The *guest* is the isolated Linux user-space environment executing inside the sandbox. |
| **`gvx-android.aar`** | The Android archive built by `scripts/android/build-sdk.sh`, bundling `dev.gfire.gvx.Gvx` and `librungvx.so` (`cmd/rungvx` compiled as a native library for `android/arm64`). See [`components/android.md`](components/android.md). |
| **`hostfs`** | Secure host directory and single-file VFS2 driver (`pkg/sentry/fsimpl/hostfs`) that anchors mounts to a pinned `os.Root` handle, prevents symlink escape, translates host-incompatible names, and persists POSIX metadata in `.gvx_meta`. See [`components/hostfs.md`](components/hostfs.md). |
| **`hostlockdown`** | Pre-execution self-confinement package (`pkg/hostlockdown`) that strips privileges and blocks new process creation, unbound file opens, and unauthorized sockets before the first guest instruction runs. See [`components/hostlockdown.md`](components/hostlockdown.md). |
| **`hvf`** | The macOS Apple Silicon execution backend (`pkg/sentry/platform/hvf`), running guest EL0 code via `Hypervisor.framework` with 4 KiB Stage-1 page tables over 16 KiB host pages. See [`components/hypervisors.md`](components/hypervisors.md). |
| **Isolation Tiers (1, 2, 3)** | The three-tier repository layout separating `gvx`-owned packages (Tier 1), OS-suffixed sibling files (`_windows`, `_darwin`, `_xplat`, Tier 2), and minimal build-tag or seam patches in upstream gVisor files (Tier 3, kept below 5.0%). |
| **Netstack (`pkg/tcpip`)** | gVisor's pure-Go user-space TCP/IP stack providing guest `lo`, `eth0`, bridges, `veth`, iptables-legacy netfilter, `conntrack`, VXLAN, and WireGuard links inside the Sentry. |
| **`netbackend`** | The host networking adapter (`pkg/netbackend`) bridging guest Netstack to either unprivileged host TCP/UDP sockets (`-net=nat`, port forwarders, DNS relay, bandwidth limits, host NAT policy) or an in-memory `wireguard-go` tunnel (`-net=wg`). See [`components/netbackend.md`](components/netbackend.md). |
| **OCI Layer Cache** | Host directory holding compiled `.erofs` image layers, manifest metadata, and optional original blobs (`-keep-blobs`), managed by `pkg/oci` and `rungvx image`. |
| **`rpcfs`** | Client-served proxy VFS2 driver (`pkg/sentry/fsimpl/rpcfs`) backing `rungvx mount serve`, enabling an unlocked host client to expose an `os.Root`-pinned directory or file to a locked sandbox over `gvx-ctrl/2`. |
| **`rungvx`** | The standalone foreground CLI binary (`cmd/rungvx`) for executing OCI images and Linux ELF64 binaries, administering local images and volumes, and controlling live sandboxes. See [`cli.md`](cli.md). |
| **Sandbox** | One isolated execution instance (`gvx.Sandbox`) owning its Sentry kernel, backing memory file, execution platform, mounted filesystems, network stack, and optional control server. |
| **Sentry** | gVisor's pure-Go Linux application kernel (`pkg/sentry/kernel`) implementing Linux system calls, signals, virtual memory, filesystems, and cgroups in user space. |
| **Stub process** | A minimal, unprivileged child process used by `systrap` to execute guest instructions in a separate hardware page table (`CR3` or `TTBR0_EL1`) away from the Sentry Go heap. |
| **`systrap`** | The stub-process execution backend (`pkg/sentry/platform/systrap`). On Linux and Android it uses upstream `seccomp` traps (plus 16 KiB sub-block paging). On Windows (`winsystrap`) it uses binary rewriting, shared `winSysmsg` pages, and a debug object under explicit opt-in. See [`systrap-windows.md`](systrap-windows.md). |
| **Tunable** | A typed host-side limit or timeout registered in `pkg/gvx/tuning` and set via `--tune KEY=VALUE` or `--tune-file` for parameters that Linux has no guest `sysctl` for. |
| **`whpx`** | The Windows hardware virtualization backend (`pkg/sentry/platform/whpx`), running guest Ring-3 (`amd64`) or EL0 (`arm64`) code inside a Windows Hypervisor Platform (`WinHvPlatform.dll`) partition with 4 KiB guest paging. See [`components/hypervisors.md`](components/hypervisors.md). |
| **`winsystrap`** | Shorthand for the Windows implementation of `platform/systrap`, intended for trusted workloads on Windows hosts without WHP. See [`systrap-windows.md`](systrap-windows.md). |
