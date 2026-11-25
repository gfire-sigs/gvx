# gvx

`gvx` executes unmodified Linux containers (OCI images) and Linux ELF64 programs inside a single unprivileged process on Windows, macOS, Linux, and Android. The runtime boots no Linux virtual machine, installs no kernel driver, and requires no background daemon.

The implementation derives from Google's [gVisor](https://github.com/google/gvisor) user-space application kernel and tracks upstream releases directly. Because the port avoids a diverging fork, upstream Linux compatibility improvements and security fixes reach `gvx` without manual backporting. Guest instructions execute directly on the host processor, while a memory-safe Go kernel intercepts Linux system calls in user space.

---

## 1. Intended Users and Deliverables

Different classes of users adopt `gvx` for different operational settings. The repository produces four deliverables, each with a distinct entry point.

| Deliverable | Audience | Entry Point |
| :--- | :--- | :--- |
| `rungvx` | Developers running Linux containers, Docker Engine, or local Kubernetes without a virtual machine. | Section 2 below; [`docs/cli.md`](docs/cli.md) |
| `pkg/gvx` | Go programmers embedding isolated Linux execution inside a host application. | Section 2.4 below; `go get z.gfire.dev/gvx` |
| `gvx-android.aar` | Android developers packaging Linux execution inside an application (`android/arm64`). | [`docs/components/android.md`](docs/components/android.md) |
| `containerd-shim-gvx-v2` | Runtime integrators testing the optional containerd v3 control-plane adapter. | [`docs/architecture.md`](docs/architecture.md#310-optional-containerd-control-adapter) |

---

## 2. Installation and First Run

This section brings a new user from an empty workstation to a verified container run. Every example below succeeds from an empty directory.

### 2.1 Host Prerequisites

Each supported host operating system imposes a small set of prerequisites. Consult the subsection for your host before installing the binary.

#### macOS (Apple Silicon `arm64`)

1. Verify that the machine uses an Apple Silicon processor (`arm64`); Intel Macs (`darwin/amd64`) are not supported.
2. Prebuilt release binaries carry an ad-hoc `com.apple.security.hypervisor` signature rather than Apple notarization.
3. If Gatekeeper blocks a downloaded binary, clear its quarantine attribute with `xattr -d com.apple.quarantine ./rungvx`.
4. If you build from source or run `go install`, sign the binary with `entitlements.plist` (Section 2.3).

#### Windows (`amd64` and `arm64`)

Hardware-assisted execution (`whpx`) requires Windows 10 (version 2004 or later) or Windows 11 on `amd64`, and Windows 11 24H2 (Build 26100.3915 or later) on `arm64`.

1. Open an elevated PowerShell prompt and enable the Windows Hypervisor Platform optional feature.
2. Restart the machine when the command completes.

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All
```

Release binaries for Windows are not Authenticode-signed. Windows SmartScreen may present a warning on first execution; remove the download mark with `Unblock-File .\rungvx.exe` or choose "More info" and "Run anyway". On hosts without hardware virtualization, trusted workloads may opt into the user-mode fallback with `--backend=systrap` or `-allow-unconfined-systrap`.

#### Linux (`amd64` and `arm64`)

Linux hosts require no administrator privileges, no kernel module, and no hypervisor device. Both 4 KiB and 16 KiB host page kernels are supported. Build from source with `CGO_ENABLED=0` so the binary requires no host C library.

### 2.2 Prebuilt Release Archives

Each tagged release on the [Releases](https://github.com/gfire-sigs/gvx/releases) page publishes seven archives, a `SHA256SUMS` file, and a Sigstore SLSA build provenance bundle. Replace `VERSION` below with the desired tag (for example, `v0.22.10002026111600`).

| Host Target | Release Archive Name |
| :--- | :--- |
| macOS Apple Silicon (`arm64`) | `rungvx-VERSION-darwin-arm64.tar.gz` |
| Windows x86-64 (`amd64`) | `rungvx-VERSION-windows-amd64.zip` |
| Windows ARM64 (`arm64`) | `rungvx-VERSION-windows-arm64.zip` |
| Linux x86-64 (`amd64`) | `rungvx-VERSION-linux-amd64.tar.gz` |
| Linux ARM64 (`arm64`, v8.0) | `rungvx-VERSION-linux-arm64.tar.gz` |
| Linux ARM64 (`arm64`, v8.2 LSE) | `rungvx-VERSION-linux-arm64v8.2.tar.gz` |
| Android ARM64 (`gvx-android.aar`) | `rungvx-VERSION-android-arm64.tar.gz` |

#### Install on macOS or Linux

1. Set `VERSION` and `TARGET` (for example, `darwin-arm64` or `linux-amd64`).
2. Download the archive, `SHA256SUMS`, and the provenance bundle from GitHub Releases.
3. Verify the SHA-256 digest before extracting the archive.
4. Optionally verify the SLSA build provenance with the GitHub CLI (`gh`).
5. Extract the archive and place `rungvx` on your `PATH`.

```sh
VERSION=v0.22.10002026111600
TARGET=darwin-arm64
ARCHIVE="rungvx-${VERSION}-${TARGET}.tar.gz"
BASE="https://github.com/gfire-sigs/gvx/releases/download/${VERSION}"

curl -fsSLO "${BASE}/${ARCHIVE}"
curl -fsSLO "${BASE}/SHA256SUMS"
curl -fsSLO "${BASE}/rungvx-${VERSION}.sigstore.json"

# Verify SHA-256 checksum (use sha256sum -c on Linux)
grep " ${ARCHIVE}\$" SHA256SUMS | shasum -a 256 -c -

# Verify SLSA v1 build provenance
gh attestation verify "${ARCHIVE}" \
  --bundle "rungvx-${VERSION}.sigstore.json" \
  --repo gfire-sigs/gvx \
  --signer-workflow gfire-sigs/gvx/.github/workflows/release.yml \
  --source-ref "refs/tags/${VERSION}" \
  --deny-self-hosted-runners

tar -xzf "${ARCHIVE}"
mv "rungvx-${VERSION}-${TARGET}/rungvx" /usr/local/bin/rungvx
# On macOS, clear Gatekeeper quarantine if prompted:
xattr -d com.apple.quarantine /usr/local/bin/rungvx 2>/dev/null || true
rungvx version
```

#### Install on Windows (PowerShell)

1. Set `$Version` and `$Target` (`windows-amd64` or `windows-arm64`).
2. Download the archive and `SHA256SUMS`.
3. Compare the computed SHA-256 hash against the entry in `SHA256SUMS`.
4. Extract `rungvx.exe`, unblock the file, and add its directory to `PATH`.

```powershell
$Version = "v0.22.10002026111600"
$Target = "windows-amd64"
$Archive = "rungvx-$Version-$Target.zip"
$Base = "https://github.com/gfire-sigs/gvx/releases/download/$Version"

Invoke-WebRequest "$Base/$Archive" -OutFile $Archive
Invoke-WebRequest "$Base/SHA256SUMS" -OutFile SHA256SUMS

$Expected = (Select-String -Path SHA256SUMS -Pattern " $Archive$").Line.Split(" ")[0]
$Actual = (Get-FileHash $Archive -Algorithm SHA256).Hash.ToLower()
if ($Actual -ne $Expected) { throw "SHA-256 mismatch: $Actual != $Expected" }

Expand-Archive -Path $Archive -DestinationPath . -Force
Unblock-File ".\rungvx-$Version-$Target\rungvx.exe"
.\rungvx-$Version-$Target\rungvx.exe version
```

### 2.3 Install with Go or Build from Source

The project does not yet publish packages for Homebrew, Winget, APT, or similar system package managers. Users with Go 1.27.4 or newer may install directly from the Go module proxy or compile from a source checkout.

> [!IMPORTANT]
> On macOS, sign any binary produced by `go install` or `repro-build.sh` with `entitlements.plist`. Without the `com.apple.security.hypervisor` entitlement, `Hypervisor.framework` refuses to create a virtual machine.

1. Install with `go install` (set `CGO_ENABLED=0` on Linux).
2. Or clone the repository and run `scripts/repro-build.sh` for a deterministic binary.
3. On macOS, apply the ad-hoc hypervisor entitlement signature.

```sh
# Option A: install from the Go module proxy (Linux and Windows; sign on macOS below)
CGO_ENABLED=0 go install z.gfire.dev/gvx/cmd/rungvx@latest

# Option B: reproducible build from a source checkout
./scripts/repro-build.sh ./rungvx ./cmd/rungvx

# Required on macOS after either Option A or Option B
codesign --sign - --entitlements entitlements.plist --force ./rungvx
```

### 2.4 First Examples

The commands below verify container execution, port forwarding, volumes, checkpointing, and Go embedding. Copy any block into a fresh directory.

#### Command-Line Examples (`rungvx`)

1. Run a command inside an unmodified Alpine Linux image.
2. Create a local web directory and serve it through nginx on host port `8080`.
3. Checkpoint a running sandbox to disk and restore it in a new process.

```sh
# 1. Execute a one-shot Linux container (no daemon, no sudo)
rungvx run alpine:3.20 uname -a

# 2. Serve a local host directory with nginx and a persistent ext4lite volume
mkdir -p ./my-site
printf '<h1>Served from gvx</h1>\n' > ./my-site/index.html
rungvx run -p 8080:80 -v appdata:/var/lib/nginx -v "$PWD/my-site:/usr/share/nginx/html:ro" nginx:alpine

# 3. Checkpoint a running container to disk and restore it later
rungvx run -control-socket ./ctrl.sock -checkpoint-dir ./snap alpine:3.20 sh -c "sleep 300" &
sleep 1
rungvx checkpoint -control-socket ./ctrl.sock -checkpoint-dir ./snap
rungvx restore -checkpoint-dir ./snap
```

Notice that `-v SRC:DST` creates a missing host directory before lockdown, whereas `-workspace DIR` requires that `DIR` already exist. See [`docs/cli.md`](docs/cli.md) for the complete command reference.

#### Embeddable Go SDK (`pkg/gvx`)

Embedders invoke `pkg/gvx` directly from Go without spawning a separate CLI binary.

> [!CAUTION]
> Always call `defer sb.Close()` immediately after `gvx.New` or `gvx.Restore` succeeds. Omitting `Close` leaks hypervisor partitions, shared memory mappings, and host file descriptors.

1. Initialize a Go module and fetch `z.gfire.dev/gvx`.
2. Save the program below as `main.go` and run `go run .` (on macOS, compile and sign with `entitlements.plist` first).

```sh
mkdir gvx-demo && cd gvx-demo
go mod init example.com/gvx-demo
go get z.gfire.dev/gvx
```

```go
package main

import (
	"context"
	"fmt"
	"os"

	"z.gfire.dev/gvx/pkg/gvx"
)

func main() {
	if err := os.MkdirAll("./work", 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create workspace: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	sb, err := gvx.New(ctx, gvx.Config{
		Platform:      gvx.PlatformAuto,
		NetworkMode:   gvx.NetModeNAT,
		OCIImage:      "alpine:3.20",
		WorkspacePath: "./work",
		Argv:          []string{"/bin/sh", "-c", "uname -a && ls -ld /workspace"},
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

---

## 3. Execution Backends and Comparison with Virtual-Machine Runtimes

Traditional container tools on Windows and macOS (Docker Desktop, WSL2, Lima, and Podman Desktop) boot a persistent Linux virtual machine in the background. `gvx` takes the opposite architecture: each sandbox runs a user-space Linux kernel inside one ordinary host process.

Before comparing approaches, we define the three execution backends that run guest machine code:

- **`hvf` (macOS Apple Silicon)**: Executes guest code inside Apple's `Hypervisor.framework` using hardware two-stage paging (4 KiB guest pages over 16 KiB host pages).
- **`whpx` (Windows `amd64` and `arm64`)**: Runs guest instructions inside a Windows Hypervisor Platform (`WinHvPlatform.dll`) partition with 4 KiB Extended Page Tables or Stage-2 mappings.
- **`systrap` (Linux, Android, and opt-in Windows)**: Executes guest instructions in isolated stub processes using system-call interception. On Linux and Android, the host kernel traps system calls with `seccomp`. On Windows, no kernel system-call filter exists, so `systrap` uses binary rewriting and requires explicit opt-in for trusted workloads only.

Use `--backend` (`auto`, `whpx`, `hvf`, or `systrap`) to choose the execution engine, and `--platform linux/ARCH` (`linux/amd64` or `linux/arm64`) to select the image architecture.

| Property | `gvx` (`hvf` / `whpx`) | `gvx` (`systrap`) | WSL2 / Lima / Docker Desktop |
| :--- | :--- | :--- | :--- |
| **Host OS** | macOS (`arm64`), Windows (`amd64`, `arm64`) | Linux (`amd64`, `arm64`), Android (`arm64`), Windows (`amd64`, `arm64` opt-in) | Windows, macOS |
| **Background VM or Daemon** | None (one process per sandbox) | None (one process per sandbox plus stub processes) | Persistent Linux virtual machine and daemon |
| **Administrator / `root` Privilege** | Not required at runtime (Windows feature enablement is one-time) | Not required | Required for initial virtual-machine or driver setup |
| **Linux Kernel Model** | User-space Go kernel (gVisor Sentry) | User-space Go kernel (gVisor Sentry) | Full Linux kernel inside the guest VM |
| **Guest Architecture** | Must match host CPU (`amd64` or `arm64`) | Must match host CPU (`amd64` or `arm64`) | Cross-architecture via QEMU `binfmt_misc` or Rosetta |
| **Untrusted Code Isolation** | Hardware page tables plus host process lockdown | Linux/Android: `seccomp` plus lockdown; Windows: trusted workloads only | Hardware virtual machine boundary |

### Measured Micro-Benchmarks

Automated micro-benchmarks run via `TestE2EMicroBench` (`GVX_E2E_BENCH=1 go test -count=1 -v -run TestE2EMicroBench ./e2e/`) and publish longitudinal results on the [`bench-results`](https://github.com/gfire-sigs/gvx/tree/bench-results) branch. The table below summarizes the latest recorded medians from that branch (GitHub-hosted runners at commit `d77169d3`, 2026-11-24; Apple Silicon development host at commit `ce792c97`, 2026-11-10). Note that `windows/amd64` `whpx` runs under nested virtualization on hosted runners, so its latency does not represent bare-metal hardware.

| Target | Backend | `host_new` | `getpid` | `open_close` | `fork_wait` | `fork_exec_true` |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: |
| `darwin/arm64` | `hvf` | 11.39 ms | 1.3 us | 5.2 us | 0.94 ms | 0.23 ms |
| `linux/amd64` | `systrap` | 47.75 ms | 2.8 us | 8.9 us | 1.80 ms | 0.41 ms |
| `linux/arm64` | `systrap` | 1.77 ms | 3.2 us | 10.7 us | 1.89 ms | 0.70 ms |
| `windows/amd64` | `whpx` (nested VM) | 12.24 ms | 12.4 us | 29.0 us | 0.99 ms | 1.12 ms |
| `windows/amd64` | `systrap` | 42.43 ms | 0.43 us | 3.1 us | 6.72 ms | 4.66 ms |
| `windows/arm64` | `systrap` | 104.34 ms | 0.96 us | 6.0 us | 17.63 ms | 12.62 ms |

No benchmark in this repository measures WSL2, Lima, or Docker Desktop; therefore no numeric comparison against those systems is claimed here.

---

## 4. Capabilities, Compatibility, and Limitations

When a sandbox starts, `gvx` compiles OCI layers into read-only EROFS files and opens all required host handles. It then seals its own process privileges (`hostlockdown`) before entering the guest.

![Overview of the gvx Sandbox Architecture](docs/assets/overview.svg)

### Verified Workloads

The black-box end-to-end suite (`e2e/`) contains 180 `TestE2E*` functions executed across supported host platforms. Verified workloads include Alpine, BusyBox, nginx, Python 3.12, Node.js 22 (V8), OpenJDK 21 (HotSpot), and Git. They also cover unmodified `docker:dind`, single-node and multi-node `rancher/k3s` with Flannel and Calico, checkpoint/restore, and host NAT policies. See [`docs/compatibility.md`](docs/compatibility.md) for the complete compatibility matrix.

### Core Subsystems

1. **In-memory OCI compilation (`pkg/oci`)**: Streams `.tar.gz` and `.tar.zst` layers into cached EROFS images without extracting Linux files onto host NTFS or APFS.
2. **Single-file ext4 volumes (`ext4lite`)**: Stores each volume (`-v`) or root overlay (`-rootfs-volume`) in one `.ext4` image with a JBD2 journal and 16 MiB groups.
3. **Pinned host directories (`hostfs`)**: Anchors bind mounts to a pinned `os.Root` handle, prevents symlink escape, encodes host-incompatible names, and forwards host changes to `inotify`.
4. **Driverless networking (`pkg/netbackend`)**: Connects gVisor's TCP/IP stack to unprivileged host sockets (`-net=nat`, `-p`, `--auto-publish`) or an in-memory WireGuard tunnel (`-net=wg`) without TUN drivers.
5. **Pre-execution lockdown (`pkg/hostlockdown`)**: Confines the host process prior to guest entry via Windows Restricted Tokens and Job Objects, macOS Seatbelt, or Linux Landlock and `seccomp-bpf`.

### Scope and Limitations

Evaluating `gvx` requires understanding what the user-space kernel and host platforms omit. All known limitations appear in [`docs/compatibility.md`](docs/compatibility.md); the principal constraints follow:

- **User-space kernel omissions**: Loadable kernel modules (`insmod`), eBPF programs (including Cilium), `io_uring`, and `nftables` are unsupported. `dockerd`, `k3s`, and Calico run using legacy iptables (`IPTABLES_MODE=legacy`).
- **Same-architecture execution only**: Guest binaries must match the host CPU architecture (`linux/arm64` on Apple Silicon and Windows ARM64; `linux/amd64` on x86-64 Windows and Linux).
- **Intel Macs unsupported**: `darwin/amd64` is not supported.
- **Windows `systrap` trust boundary**: Because Windows offers no unprivileged kernel system-call filter, `--backend=systrap` and `-allow-unconfined-systrap` serve trusted workloads only. Always use `whpx` for untrusted code on Windows.
- **Fixed-address guests and Defender on Windows `systrap`**: AddressSanitizer and 64-bit Wine fail at startup on Windows `systrap` because their fixed reservations cross reserved address holes. Run them under `whpx` instead. The Windows `systrap` stub host, debug object, and executable views remain untested under default Microsoft Defender settings.
- **Unverified workloads**: Relational databases (PostgreSQL, SQLite) and browsers or GUI tools (Chromium, Playwright, Puppeteer, Electron) have no automated tests in `e2e/`. Hardware GPU acceleration is unimplemented (see [`docs/moonshots.md`](docs/moonshots.md)).

---

## 5. Documentation Index

Documentation is organized by audience so new users can evaluate and operate `gvx` without wading through internal design specifications.

### 5.1 Guides for Users

| Document | Contents |
| :--- | :--- |
| [`docs/cli.md`](docs/cli.md) | Complete `rungvx` command reference, flags, tunables, mounts, checkpointing, nested use, and Android operation. |
| [`docs/compatibility.md`](docs/compatibility.md) | Verified workloads from `e2e/`, unverified workloads, and consolidated platform limitations. |
| [`docs/troubleshooting.md`](docs/troubleshooting.md) | Symptom-to-remedy guide covering installation, signing, exit code 137, Docker, Kubernetes, DNS, and tracing. |
| [`docs/glossary.md`](docs/glossary.md) | Concise definitions of subsystems, backends, filesystems, and deliverables. |
| [`docs/recipes/docker-engine.md`](docs/recipes/docker-engine.md) | Step-by-step recipe to run Docker Engine (`docker:dind`) inside `gvx` from the host `docker` CLI. |
| [`docs/recipes/kubernetes.md`](docs/recipes/kubernetes.md) | Step-by-step recipe for single-node and multi-node `k3s` clusters with Flannel or Calico CNI. |
| [`SECURITY.md`](SECURITY.md) | Security boundaries, documented non-vulnerabilities, provenance verification, and reporting procedure. |
| [`CHANGELOG.md`](CHANGELOG.md) | Chronological release notes for each version. |

### 5.2 Technical Documentation for Contributors

| Document | Contents |
| :--- | :--- |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | First-contribution workflow, deliverables map, local build and test commands, and review standards. |
| [`docs/architecture.md`](docs/architecture.md) | System architecture, package boundaries, upstream isolation tiers, guest kernel interfaces, and CI matrix. |
| [`docs/control-protocol.md`](docs/control-protocol.md) | Wire framing, authentication, capability policy, and RPC reference for `gvx-ctrl/2`. |
| [`docs/components/hypervisors.md`](docs/components/hypervisors.md) | Component specification for `platform/whpx`, `platform/hvf`, and `platform/hvcommon`. |
| [`docs/systrap-windows.md`](docs/systrap-windows.md) | Measured behavior, binary patching design, fast path, limits, and evidence for Windows `systrap`. |
| [`docs/components/ext4lite.md`](docs/components/ext4lite.md) | Component specification for the single-file journaled ext4 volume driver. |
| [`docs/components/hostfs.md`](docs/components/hostfs.md) | Component specification for the pinned host directory filesystem and `.gvx_meta` journal. |
| [`docs/components/netbackend.md`](docs/components/netbackend.md) | Component specification for the NAT forwarder, DNS relay, policy filter, and WireGuard backend. |
| [`docs/components/oci.md`](docs/components/oci.md) | Component specification for OCI registry access, Tar-to-EROFS compilation, and host CA injection. |
| [`docs/components/hostlockdown.md`](docs/components/hostlockdown.md) | Component specification for pre-execution process containment on Windows, macOS, Linux, and Android. |
| [`docs/components/android.md`](docs/components/android.md) | Component specification for the Android library (`gvx-android.aar`) and packaging model. |
| [`docs/moonshots.md`](docs/moonshots.md) | Unimplemented research proposal for confined host GPU acceleration in browser and GUI guests. |
| [`docs/extensions-plan.md`](docs/extensions-plan.md) | Approved rollout plan for the extension SPI, nested `ext/` submodule, and `rungvx` build-tag model. |
| [`AGENTS.md`](AGENTS.md) | Repository operating rules, upstream sync discipline, writing standards, and release versioning rules. |
| [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Standards of conduct for project discussions and contributions. |

---

## 6. Upstream Tracking and Licensing

`gvx` is licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the complete text.

The repository tracks the pre-generated `go` branch of [google/gvisor](https://github.com/google/gvisor) (Apache License 2.0, Copyright The gVisor Authors) and pins the synced commit in [`UPSTREAM_COMMIT`](UPSTREAM_COMMIT). To prevent merge conflicts across upstream releases, host bindings live in standalone Tier 1 packages and OS-suffixed Tier 2 sibling files (`*_windows.go`, `*_darwin.go`, `*_xplat.go`). Fewer than 5.0% of upstream gVisor files carry Tier 3 build-tag expansions or seams. Every CI run audits this ceiling with `go run ./tools/upstream -mode=audit`.

Run `rungvx license` to print embedded notices for `gvx`, upstream gVisor, Go, and linked third-party modules. Pass `-list` for a summary table.

| SPDX identifier | Third-party modules |
| :--- | :--- |
| `Apache-2.0` | `github.com/distribution/reference` v0.6.0, `github.com/google/btree` v1.1.2, `github.com/opencontainers/image-spec` v1.1.1 |
| `Apache-2.0 AND BSD-3-Clause AND MIT` | `github.com/klauspost/compress` v1.20.5 |
| `BSD-3-Clause` | `golang.org/x/arch` v0.32.0, `golang.org/x/crypto` v0.57.0, `golang.org/x/exp` v0.0.0-20250711185948-6ae5c78190dc, `golang.org/x/mod` v0.41.0, `golang.org/x/net` v0.60.0, `golang.org/x/sync` v0.23.0, `golang.org/x/sys` v0.48.0, `golang.org/x/text` v0.42.0, `golang.org/x/time` v0.15.0, `google.golang.org/protobuf` v1.36.11 |
| `MIT` | `golang.zx2c4.com/wintun` v0.0.0-20230126152724-0fa3db229ce2, `golang.zx2c4.com/wireguard` v0.0.0-20261006164505-2631ce99a06f, `gopkg.in/yaml.v3` v3.0.1 |
| `NOASSERTION` | `github.com/opencontainers/go-digest` v1.0.0 |
