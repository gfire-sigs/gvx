# gvx

Run unmodified Linux containers and ELF64 binaries inside one unprivileged process on macOS, Windows, Linux, and Android.

[![CI](https://github.com/gfire-sigs/gvx/actions/workflows/ci.yml/badge.svg)](https://github.com/gfire-sigs/gvx/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/gfire-sigs/gvx?style=flat)](https://github.com/gfire-sigs/gvx/releases)
[![Go Reference](https://pkg.go.dev/badge/z.gfire.dev/gvx/pkg/gvx.svg)](https://pkg.go.dev/z.gfire.dev/gvx/pkg/gvx)
[![License](https://img.shields.io/github/license/gfire-sigs/gvx?style=flat)](LICENSE)

`gvx` executes guest code directly on the host CPU while a memory-safe Go kernel derived from [gVisor](https://github.com/google/gvisor) serves Linux system calls. Unlike Docker Desktop, Lima, or WSL2, it boots no persistent Linux virtual machine, installs no kernel driver, and runs no background daemon.

- **Standalone CLI (`rungvx`)**: Run OCI containers, unmodified `docker:dind`, and local `k3s` clusters on Apple Silicon macOS, Windows, Linux, and Android.
- **Embeddable Go SDK (`pkg/gvx`)**: Execute untrusted Linux code in process with pure Go (`CGO_ENABLED=0`) and zero C dependencies in the root module.
- **Pre-execution host lockdown**: Confines each sandbox process before guest entry via macOS Seatbelt, Windows Restricted Tokens and Job Objects, or Linux Landlock and `seccomp`.
- **Continuous upstream tracking**: Syncs with weekly gVisor releases (`< 5.0%` audited diff) so Linux compatibility and security fixes arrive without a hard fork.

```sh
rungvx run alpine:3.20 uname -a
# Linux gvx 4.19.0-gvisor #1 SMP Sun Jan 10 15:06:54 PST 2016 aarch64 Linux
```

## Install

### Prebuilt Binary (macOS and Linux)

Download the latest release from [GitHub Releases](https://github.com/gfire-sigs/gvx/releases). Replace `darwin-arm64` with `darwin-arm64-ext` (for compiled extensions such as macOS GPU support), `linux-amd64`, `linux-arm64`, or `linux-arm64v8.2`.

```sh
VERSION=$(curl -fsSL https://api.github.com/repos/gfire-sigs/gvx/releases/latest | sed -n 's/.*"tag_name": "\([^"]*\)".*/\1/p')
TARGET=darwin-arm64
ARCHIVE="rungvx-${VERSION}-${TARGET}.tar.gz"
curl -fsSLO "https://github.com/gfire-sigs/gvx/releases/download/${VERSION}/${ARCHIVE}"
tar -xzf "${ARCHIVE}"
mv "rungvx-${VERSION}-${TARGET}/rungvx" ./rungvx
xattr -d com.apple.quarantine ./rungvx 2>/dev/null || true
./rungvx version
```

### Prebuilt Binary (Windows PowerShell)

Replace `windows-amd64` with `windows-arm64` on ARM64 Windows.

```powershell
$Version = (Invoke-RestMethod https://api.github.com/repos/gfire-sigs/gvx/releases/latest).tag_name
$Target = "windows-amd64"
$Archive = "rungvx-$Version-$Target.zip"
Invoke-WebRequest "https://github.com/gfire-sigs/gvx/releases/download/$Version/$Archive" -OutFile $Archive
Expand-Archive -Path $Archive -DestinationPath . -Force
Unblock-File ".\rungvx-$Version-$Target\rungvx.exe"
.\rungvx-$Version-$Target\rungvx.exe version
```

### Install with Go

Requires Go 1.27.4 or newer.

```sh
CGO_ENABLED=0 go install z.gfire.dev/gvx/cmd/rungvx@latest
```

> [!IMPORTANT]
> On macOS, sign any binary built with `go install` or `go build` using `entitlements.plist` so `Hypervisor.framework` can create a VM:
> `curl -fsSLO https://raw.githubusercontent.com/gfire-sigs/gvx/main/entitlements.plist && codesign --sign - --entitlements entitlements.plist --force "$(go env GOPATH)/bin/rungvx"`

### Platform Requirements

| Host OS | Requirements |
| :--- | :--- |
| **macOS** (`darwin/arm64`) | Apple Silicon required (Intel Macs unsupported). Clear quarantine with `xattr -d com.apple.quarantine ./rungvx` on downloads. |
| **Windows** (`windows/amd64`, `windows/arm64`) | Windows 10 2004+ (`amd64`) or Windows 11 24H2 Build `26100.3915+` (`arm64`). Enable WHP (`Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All`), restart, then run `Unblock-File`. |
| **Linux** (`linux/amd64`, `linux/arm64`) | No root privileges, kernel modules, or hypervisor devices required. Supports 4 KiB and 16 KiB host pages. |

<details>
<summary>Verify checksums and SLSA provenance</summary>

Each release publishes nine archives (seven core `rungvx` targets, `rungvx-<VERSION>-darwin-arm64-ext.tar.gz` with compiled extensions, plus `gvx-gpu-renderer` for macOS), `SHA256SUMS`, and a Sigstore attestation bundle (`rungvx-<VERSION>.sigstore.json`).

```sh
BASE="https://github.com/gfire-sigs/gvx/releases/download/${VERSION}"
curl -fsSLO "${BASE}/SHA256SUMS" "${BASE}/rungvx-${VERSION}.sigstore.json"
grep " ${ARCHIVE}\$" SHA256SUMS | shasum -a 256 -c -   # use sha256sum -c on Linux

gh attestation verify "${ARCHIVE}" \
  --bundle "rungvx-${VERSION}.sigstore.json" \
  --repo gfire-sigs/gvx \
  --signer-workflow gfire-sigs/gvx/.github/workflows/release.yml \
  --source-ref "refs/tags/${VERSION}" --deny-self-hosted-runners
```

</details>

### Desktop GUI (Community)

For a graphical interface on macOS or Windows, see [GVX Desktop](https://github.com/ironpark/gvx-desktop), an independently maintained community desktop app built on `gvx`.

## Quick Start

Run any example below from an empty directory (`-v SRC:DST` creates missing host directories before lockdown; `-workspace DIR` requires `DIR` to exist beforehand).

```sh
# 1. Run an unmodified Alpine Linux container
rungvx run alpine:3.20 uname -a

# 2. Serve a local directory with nginx, a persistent ext4lite volume, and port forwarding
mkdir -p ./my-site && printf '<h1>Served from gvx</h1>\n' > ./my-site/index.html
rungvx run -p 8080:80 -v appdata:/var/lib/nginx -v "$PWD/my-site:/usr/share/nginx/html:ro" nginx:alpine
# In a second terminal: curl http://127.0.0.1:8080/

# 3. Checkpoint a running sandbox and restore it in a new process
mkdir -p ./snap
rungvx run -S ./ctrl.sock -checkpoint-dir ./snap alpine:3.20 sh -c "sleep 300"
# In a second terminal:
# rungvx checkpoint -S ./ctrl.sock -checkpoint-dir ./snap
# rungvx restore -checkpoint-dir ./snap
```

For full container orchestration workflows, see the [Docker Engine (`docker:dind`)](docs/recipes/docker-engine.md) and [Kubernetes (`k3s`)](docs/recipes/kubernetes.md) recipes.

## Features

- **In-memory OCI layer compiler**: Streams `.tar.gz` and `.tar.zst` layers into cached EROFS images without extracting Linux metadata onto host APFS or NTFS.
- **Single-file volumes and safe bind mounts**: Persists container state in journaled `.ext4` files (`ext4lite`) and anchors bind mounts (`hostfs`) to a pinned `os.Root` handle that blocks symlink escape.
- **Driverless networking**: Provides outbound NAT (`-net=nat`), static and dynamic loopback port forwarding (`-p`, `--auto-publish`), NAT firewall policies, and an in-memory WireGuard tunnel (`-net=wg`) without TUN drivers.
- **Live control and checkpointing**: Supports `exec`, `cp`, `export`, `stats`, live resource updates, and stop/live checkpoint and restore over `gvx-ctrl/2`.
- **Verified real-world workloads**: Automated CI gates verify Alpine, `nginx`, Python 3.12, Node.js 22 (V8), OpenJDK 21 (HotSpot), Git, `docker:dind`, and single-node or multi-node `k3s` with Flannel or Calico.
- **Mobile and optional extensions**: Ships `gvx-android.aar` for `android/arm64` apps and isolates optional extensions such as macOS headless GPU rendering (`-tags ext_gpu`, `-gpu=venus` and `-gpu=virgl`) in the nested `ext/` submodule.

### How It Works

Three execution backends run guest machine code directly on the host CPU: `hvf` (`Hypervisor.framework` on Apple Silicon macOS), `whpx` (Windows Hypervisor Platform), and `systrap` (isolated stub processes on Linux, Android, and opt-in Windows). Select an engine with `--backend` and an image architecture with `--platform linux/ARCH`.

![Overview of the gvx Sandbox Architecture](docs/assets/overview.svg)

| Property | `gvx` (`hvf` / `whpx`) | `gvx` (`systrap`) | WSL2 / Lima / Docker Desktop |
| :--- | :--- | :--- | :--- |
| **Host OS** | macOS (`arm64`), Windows (`amd64`, `arm64`) | Linux (`amd64`, `arm64`), Android (`arm64`), Windows (opt-in) | Windows, macOS |
| **Background VM / Daemon** | None (one process per sandbox) | None (one process plus stub processes) | Persistent Linux VM and daemon |
| **Runtime Privileges** | Standard user account | Standard user account | Initial VM or driver setup |
| **Guest Architecture** | Matches host CPU only | Matches host CPU only | Cross-arch via QEMU or Rosetta |
| **Untrusted Code Isolation** | Hardware page tables + lockdown | Linux/Android: `seccomp` + lockdown; Windows: trusted only | Hardware VM boundary |

### Known Limits and Benchmarks

- **Same-architecture only**: Guest binaries must match the host CPU (`linux/arm64` or `linux/amd64`); Intel Macs (`darwin/amd64`) are unsupported.
- **Omitted kernel interfaces**: Loadable kernel modules (`insmod`), eBPF, `io_uring`, and `nftables` are unsupported (use `IPTABLES_MODE=legacy`).
- **Windows `systrap` scope**: `--backend=systrap` serves trusted workloads only; AddressSanitizer and 64-bit Wine require `whpx`.
- **Databases and default GPU scope**: Relational databases (PostgreSQL, SQLite) lack CI coverage; default pure-Go builds omit host GPU acceleration (macOS `-gpu=venus`/`-gpu=virgl` requires `-tags ext_gpu` and `gvx-gpu-renderer`).

Consult [`docs/compatibility.md`](docs/compatibility.md) for the complete workload matrix and [`bench-results`](https://github.com/gfire-sigs/gvx/tree/bench-results) for continuously measured micro-benchmarks across all CI targets.

## Usage: Embed in Go

Initialize a module in an empty directory to run Linux containers directly from Go:

```sh
mkdir gvx-demo && cd gvx-demo
go mod init example.com/gvx-demo
go get z.gfire.dev/gvx
mkdir -p repo
```

> [!CAUTION]
> Always call `defer sb.Close()` immediately after `gvx.New` or `gvx.Restore` succeeds. Omitting `Close` leaks hypervisor partitions, memory mappings, and host file descriptors.

Save as `main.go`:

```go
package main

import (
	"context"
	"fmt"
	"os"

	"z.gfire.dev/gvx/pkg/gvx"
)

func main() {
	ctx := context.Background()
	sb, err := gvx.New(ctx, gvx.Config{
		Platform:      gvx.PlatformAuto,
		NetworkMode:   gvx.NetModeNAT,
		OCIImage:      "alpine/git:latest",
		WorkspacePath: "./repo",
		Argv:          []string{"sh", "-c", "git init /workspace && git -C /workspace status"},
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

Build and run:

```sh
go build -o gvx-demo .
# macOS only: sign with Hypervisor.framework entitlement
curl -fsSLO https://raw.githubusercontent.com/gfire-sigs/gvx/main/entitlements.plist
codesign --sign - --entitlements entitlements.plist --force ./gvx-demo
./gvx-demo
```

## Documentation

| User Guides | Architecture and Internals |
| :--- | :--- |
| [`docs/cli.md`](docs/cli.md): CLI flags, tunables, mounts, checkpointing, Android | [`docs/architecture.md`](docs/architecture.md): Subsystems, upstream tiers, CI matrix |
| [`docs/compatibility.md`](docs/compatibility.md): Verified workloads and platform limits | [`docs/control-protocol.md`](docs/control-protocol.md): `gvx-ctrl/2` wire framing and RPCs |
| [`docs/troubleshooting.md`](docs/troubleshooting.md): Symptom-to-remedy runtime fixes | [`docs/systrap-windows.md`](docs/systrap-windows.md): Windows `systrap` patching design |
| [`docs/glossary.md`](docs/glossary.md): Terms, backends, and deliverables | [`docs/extensions-plan.md`](docs/extensions-plan.md): Extension SPI and `ext/` submodule |
| [`docs/recipes/docker-engine.md`](docs/recipes/docker-engine.md): Run `docker:dind` inside `gvx` | [`docs/moonshots.md`](docs/moonshots.md): Host GPU acceleration architecture |
| [`docs/recipes/kubernetes.md`](docs/recipes/kubernetes.md): Single- and multi-node `k3s` clusters | Component specs under `docs/components/` (`hypervisors`, `ext4lite`, `hostfs`, `netbackend`, `oci`, `hostlockdown`, `android`) |
| [`SECURITY.md`](SECURITY.md): Security boundaries and disclosure | [`CHANGELOG.md`](CHANGELOG.md): Release notes and breaking changes |

## Development and Contributing

Build deterministically from a checkout with Go 1.27.4+ and run tests with the macOS codesign wrapper (omit `-exec` on Linux and Windows):

```sh
./scripts/repro-build.sh ./rungvx ./cmd/rungvx
go test -race -exec "$PWD/scripts/codesign-exec.sh" ./pkg/gvx/...
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for deliverables, cross-compilation, static analyzers, and pull request guidelines. Maintainer procedures live in [`AGENTS.md`](AGENTS.md), and community standards live in [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## License

`gvx` is licensed under the Apache License, Version 2.0 ([`LICENSE`](LICENSE)) and tracks the `go` branch of [google/gvisor](https://github.com/google/gvisor) pinned in [`UPSTREAM_COMMIT`](UPSTREAM_COMMIT). Run `rungvx license` or inspect [`pkg/rungvx/licenses/THIRD_PARTY_LICENSES.txt`](pkg/rungvx/licenses/THIRD_PARTY_LICENSES.txt) for complete third-party notices.

<details>
<summary>Third-party licenses</summary>

| SPDX identifier | Third-party modules |
| :--- | :--- |
| `Apache-2.0` | `github.com/distribution/reference` v0.6.0, `github.com/google/btree` v1.1.2, `github.com/opencontainers/image-spec` v1.1.1 |
| `Apache-2.0 AND BSD-3-Clause AND MIT` | `github.com/klauspost/compress` v1.20.5 |
| `BSD-3-Clause` | `golang.org/x/arch` v0.32.0, `golang.org/x/crypto` v0.57.0, `golang.org/x/exp` v0.0.0-20250711185948-6ae5c78190dc, `golang.org/x/mod` v0.41.0, `golang.org/x/net` v0.60.0, `golang.org/x/sync` v0.23.0, `golang.org/x/sys` v0.48.0, `golang.org/x/text` v0.42.0, `golang.org/x/time` v0.15.0, `google.golang.org/protobuf` v1.36.11 |
| `MIT` | `golang.zx2c4.com/wintun` v0.0.0-20230126152724-0fa3db229ce2, `golang.zx2c4.com/wireguard` v0.0.0-20261006164505-2631ce99a06f, `gopkg.in/yaml.v3` v3.0.1 |
| `NOASSERTION` | `github.com/opencontainers/go-digest` v1.0.0 |

</details>
