# Troubleshooting

This guide maps common failure symptoms in `gvx` to their root causes and concrete remedies. Begin with Section 1 to gather diagnostic evidence, then locate your symptom in the tables below.

---

## 1. Collecting Diagnostic Information

Before filing an issue or diagnosing an opaque guest failure, collect host backend status and Sentry diagnostics.

1. Run `rungvx version` and `rungvx system info` to record the binary build, detected backends, and storage paths.
2. Re-run the failing command with `GVX_DEBUG_LOG=1` (or `2` for unresolved faults) to print Sentry kernel logs to standard error.
3. Set `GVX_STRACE=1` to log guest system calls when a Linux binary exits unexpectedly.
4. On Windows `systrap`, set `GVX_SYSTRAP_TRACE=1` to inspect guest exceptions and faulting instruction bytes.

```sh
rungvx version
rungvx system info
GVX_DEBUG_LOG=1 rungvx run alpine:3.20 uname -a
```

| Environment Variable | Effect |
| :--- | :--- |
| `GVX_DEBUG_LOG=1` | Prints Sentry kernel log lines to `rungvx` standard error. |
| `GVX_DEBUG_LOG=2` | Adds verbose Sentry debug lines, including unresolved guest page faults. |
| `GVX_STRACE=1` | Logs guest Linux system calls and return values to standard error. |
| `GVX_SYSTRAP_TRACE=1` | Prints each Windows `systrap` guest exception (`2` logs every stop; `3` prints stop counts and patch summaries; `4` samples hot PCs). |

---

## 2. Installation, Signing, and Backend Startup

| Symptom | Cause | Remedy |
| :--- | :--- | :--- |
| macOS Gatekeeper refuses to open downloaded `rungvx` | Prebuilt macOS binaries carry an ad-hoc signature rather than Apple notarization. | Clear the quarantine attribute: `xattr -d com.apple.quarantine ./rungvx`. |
| `hv_vm_create` fails or `hvf` reports missing entitlement on macOS | The binary was built with `go install` or `go build` without the hypervisor entitlement. | Sign the binary with `codesign --sign - --entitlements entitlements.plist --force ./rungvx`. |
| `hvf` fails inside a macOS virtual machine or cloud runner | Apple Silicon hosts do not expose nested virtualization to macOS VMs, and macOS has no `systrap` fallback. | Run `gvx` directly on a physical Apple Silicon Mac. |
| Windows SmartScreen warns on `rungvx.exe` | Prebuilt Windows archives are not Authenticode-signed. | Verify `SHA256SUMS` and SLSA provenance, then run `Unblock-File .\rungvx.exe` in PowerShell. |
| `--backend=auto` fails on Windows with WHP unavailable | The Windows Hypervisor Platform feature is disabled, and `auto` fails closed for security. | Enable WHP in elevated PowerShell (`Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All`) and restart. For trusted workloads on a host without WHP, pass `-allow-unconfined-systrap` or `--backend=systrap`. |
| `whpx` fails on Windows ARM64 | Windows 11 24H2 (Build 26100.3915 or later) is required for ARM64 WHPX. | Update Windows or use `--backend=systrap` for trusted workloads only. |
| Guest architecture error when running an image | The requested `--platform linux/ARCH` does not match the host CPU architecture. | Pull and run the architecture matching your host (`linux/arm64` on ARM64; `linux/amd64` on x86-64). |

---

## 3. Mounts, Ports, and Exit Code 137

| Symptom | Cause | Remedy |
| :--- | :--- | :--- |
| `-workspace=./dir` fails with "no such file or directory" | Unlike `-v`, `-workspace` does not create a missing host directory before lockdown. | Create the directory first (`mkdir -p ./dir`), or use `-v ./dir:/workspace`. |
| `address already in use` before the guest starts | A host port named by static `-p` (or a port inside a `-p` range) is already bound by another process. | Pick an unused host port or range, or omit the host port (for example, `-p 80`) to let `rungvx` select a free loopback port. |
| `--auto-publish` prints a bind warning for a port | Another host process already listens on that `127.0.0.1` port. | Stop the conflicting host listener or map the container port manually with `-p HOST:GUEST`. |
| Guest exits with code `137` and a memory limit message | Guest memory exceeded `--memory` (or a nested `memory.max` cgroup cap) and the memory guard sent `SIGKILL`. | Increase `-m` / `--memory` (for example, `-m 2g`) or inspect live usage with `rungvx stats`. |
| Guest exits with code `137` and `the execution engine stopped the guest` (`ErrEngineFault`) | The underlying execution engine failed (for example, an antivirus scanner killed a Windows `systrap` stub, or Android killed a child process past its 32-process limit). | Re-run with `GVX_DEBUG_LOG=1`. On Windows, prefer `--backend=whpx` or inspect endpoint protection logs. On Android, consult Section 6 below. |
| `ext4lite` mount fails with `in use` or journal replay required | Another sandbox holds an exclusive lock (`LOCK_EX`), or a read-only (`:ro`) mount encountered an unrecovered journal after an unclean stop. | Wait for the active writer to exit, or run `rungvx volume compact NAME` (or a brief read-write mount) before mounting `:ro`. |
| `rungvx` exits with `lockdown` error or `LOCKDOWN_DENIED` on a control command | The requested host path or bind address violates pre-execution host containment. | Pre-open directories with `-v`, enable `--dynamic-ports` or `--auto-publish` for loopback binds, or use `rungvx mount serve` (`rpcfs`) for post-start host directory access. |

---

## 4. Docker Engine (`docker:dind`) Failures

See [`recipes/docker-engine.md`](recipes/docker-engine.md) for the setup procedure.

| Symptom | Cause | Remedy |
| :--- | :--- | :--- |
| `docker info` fails with connection refused or socket not found | Either `dockerd` has not finished booting (`API listen on /var/run/docker.sock`), or the host `docker` context points to the wrong socket path. | Wait for the `API listen` log line, verify `docker context ls`, and run `docker context use gvx`. |
| `docker` CLI on Windows rejects `unix://` context URL | Windows `unix://` Docker contexts require Docker CLI 29 or newer. | Upgrade the Docker CLI, or publish `-p 127.0.0.1:2375:2375` on `rungvx` and configure `host=tcp://127.0.0.1:2375`. |
| `docker pull` fails inside `docker:dind` with x509 certificate error | The host sits behind a corporate TLS-inspecting proxy or private CA not present in the image. | Add `--host-ca-certs` to `rungvx run`. For containers built or run inside `dockerd`, mount `/etc/ssl/certs/ca-certificates.crt` as shown in [`recipes/docker-engine.md`](recipes/docker-engine.md#6-operating-behind-a-tls-inspecting-proxy). |
| Container on Docker `bridge` cannot reach `10.0.2.15` | A container behind the guest bridge routes replies through `eth0` and cannot connect directly to the sandbox's own `eth0` address. | Connect via the container's bridge IP or place collaborating containers on a user-defined Docker bridge network. |
| `docker run -v /host/path:/data` mounts an empty directory | Paths passed to `docker run -v` resolve inside the `gvx` sandbox filesystem, not on the host OS. | Bind-mount the host directory into `rungvx` first (`-v ~/src:/src`), then pass `-v /src:/data` to `docker run`. |

---

## 5. Kubernetes (`k3s`) Failures

See [`recipes/kubernetes.md`](recipes/kubernetes.md) for the single-node, two-node, and Calico procedures.

| Symptom | Cause | Remedy |
| :--- | :--- | :--- |
| `k3s` fails at startup with `nftables` or `iptables-nft` errors | The guest user-space kernel supports legacy `iptables` only. | Pass `-e IPTABLES_MODE=legacy` to `rungvx run`. |
| Node remains `NotReady` or `kubectl get nodes` times out | The server has not finished initialization (typically 30 to 120 seconds), or `KUBECONFIG` points to a stale file or wrong port. | Wait for `k3s is up and running` in the `rungvx` terminal, confirm `-p 127.0.0.1:6443:6443`, and verify `export KUBECONFIG=$HOME/.gvx/k3s/kubeconfig.yaml`. |
| `calico-node` fails to start or stays `CrashLoopBackOff` | Either `/` was not marked recursively shared (`mount --make-rshared /`), or Felix attempted to use `nftables` or the wrong pod CIDR. | Verify the startup wrapper runs `mount --make-rshared /` and that `calico.yaml` sets `CALICO_IPV4POOL_CIDR=10.42.0.0/16` and `FELIX_IPTABLESBACKEND=Legacy`. |
| `kubectl` shows `Skipping network policy controller start` | Legacy iptables or `ipset` support was disabled (`--net-raw=false`). | Keep default `--privileged` (which enables `--net-raw`) and `-e IPTABLES_MODE=legacy`. |
| Agent node fails to join server on the same host | Both sandboxes tried to bind host port `6443`, or the agent used `127.0.0.1` instead of the host gateway `10.0.2.2`. | Publish `6443` and `51820/udp` on the server only, and pass `--server https://10.0.2.2:6443` to the agent. |

---

## 6. Networking, DNS, and Android Issues

| Symptom | Cause | Remedy |
| :--- | :--- | :--- |
| DNS resolution fails with `connection refused` to `[::1]:53` | The host environment (such as an Android app or minimal container) has no `/etc/resolv.conf`. | Supply an explicit resolver with `--host-dns IP` (repeatable, for example `--host-dns 10.0.2.3`). |
| Pull or HTTPS request inside guest fails behind a proxy | Guest images do not contain host-installed root CA certificates by default. | Pass `--host-ca-certs` (and optionally `SSL_CERT_FILE=/path/to/root.pem`) to `rungvx run`. |
| Android guest stops abruptly during builds or multi-process runs | Android 12+ terminates child processes once total child processes across all apps exceed 32, or throttles background apps. | Launch from a foreground service (`android/sample`), keep concurrent guest processes under 10, or disable phantom process limits via Developer Options or `adb` (see [`cli.md`](cli.md#12-android-operation)). |
| Hard link (`ln`) fails with `EACCES` on an Android host mount | Android SELinux denies `linkat` on app-data files. | Store workloads requiring hard links inside an `ext4lite` volume (`-v work:/work`) rather than a `hostfs` directory. |
