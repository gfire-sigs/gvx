# Troubleshooting

This guide maps common `gvx` runtime failures to their root causes and recovery commands. Every entry pairs an observable symptom with a verifiable diagnostic check or flag fix.

Most failures stem from four boundaries: missing host signing, pre-lockdown mount or port constraints, guest memory limits, or legacy-iptables rules. Isolating those layers before changing container flags saves debugging time.

Start with Section 1 to capture environment metadata and traces, then locate your symptom in the sections below.

---

## 1. Collecting Diagnostic Information

Collect backend capabilities, build options, and Sentry logs before filing an issue or debugging a guest crash.

1. Run `rungvx version -V` and `rungvx system info` to record build options, backends, and paths.
2. Re-run the failing command with `GVX_DEBUG_LOG=1` (or `2`) to print Sentry logs.
3. Set `GVX_STRACE=1` to print guest Linux system calls when a binary exits unexpectedly.
4. Set `GVX_SYSTRAP_TRACE=1` on Windows `systrap` to inspect faulting instruction bytes.

```sh
rungvx version -V
rungvx system info
GVX_DEBUG_LOG=1 rungvx run alpine:3.20 uname -a
```

| Environment Variable | Effect |
| :--- | :--- |
| `GVX_DEBUG_LOG=1` | Prints Sentry kernel log lines to `rungvx` standard error. |
| `GVX_DEBUG_LOG=2` | Adds verbose Sentry debug lines, including unresolved guest page faults. |
| `GVX_STRACE=1` | Logs guest Linux system calls and return values to standard error. |
| `GVX_SYSTRAP_TRACE=1` | Prints Windows `systrap` exceptions (`2` every stop; `3` counts and patches; `4` hot PCs). |

---

## 2. Installation, Signing, and Backend Startup

Consult this table when `rungvx` fails Gatekeeper, SmartScreen, entitlement checks, or hypervisor creation at startup.

| Symptom | Cause | Remedy |
| :--- | :--- | :--- |
| macOS Gatekeeper blocks downloaded `rungvx` | Prebuilt macOS binaries carry an ad-hoc signature rather than Apple notarization. | Clear quarantine: `xattr -d com.apple.quarantine ./rungvx`. |
| `hv_vm_create` fails or reports missing entitlement | The binary was built with `go install` or `go build` without signing. | Sign with `codesign --sign - --entitlements entitlements.plist --force ./rungvx`. |
| `hvf` fails inside a macOS VM or CI runner | Apple Silicon VMs lack nested virtualization, and macOS offers no `systrap` backend. | Run `gvx` directly on a physical Apple Silicon Mac. |
| Windows SmartScreen warns on `rungvx.exe` | Prebuilt Windows binaries are not Authenticode-signed. | Verify `SHA256SUMS` and provenance, then run `Unblock-File .\rungvx.exe`. |
| `--backend=auto` fails on Windows with WHP unavailable | Windows Hypervisor Platform is disabled, and `auto` fails closed. | Enable `HypervisorPlatform` in elevated PowerShell and restart. For trusted guests without WHP, pass `-allow-unconfined-systrap`. |
| `whpx` fails on Windows ARM64 | ARM64 `whpx` requires Windows 11 24H2 (Build 26100.3915 or later). | Update Windows or pass `--backend=systrap` for trusted workloads only. |
| Guest architecture mismatch error | Requested `--platform linux/ARCH` differs from the host CPU architecture. | Pull and run the matching architecture (`linux/arm64` or `linux/amd64`). |

---

## 3. Mounts, Ports, Flags, and Exit Code 137

Consult this table when CLI flags are rejected, host binds fail under lockdown, or a guest exits with status `137`.

| Symptom | Cause | Remedy |
| :--- | :--- | :--- |
| `rungvx run -d` fails with `-d is not supported` | `rungvx` executes strictly in the foreground with no background daemon. | Run `rungvx` in the foreground, or run `rungvx exec -d` inside a control-enabled sandbox. |
| `-workspace=./dir` fails with no such file or directory | Unlike `-v`, `-workspace` requires the host directory to exist beforehand. | Create the directory first (`mkdir -p ./dir`), or use `-v ./dir:/workspace`. |
| `address already in use` before the guest starts | Another host process already binds a static `-p` port. | Choose an unused host port, or omit the host port (`-p 80`). |
| `--auto-publish` logs a bind warning for a port | Another host listener already occupies that `127.0.0.1` port. | Stop the conflicting listener or map the port manually with `-p HOST:GUEST`. |
| Guest exits `137` with a memory limit message | Guest memory exceeded `--memory` (or `memory.max`), triggering the polling OOM guard. | Raise `-m` / `--memory` (such as `-m 2g`) or inspect `rungvx stats`. |
| Guest exits `137` with `the execution engine stopped the guest` | The execution engine aborted (for example, Defender killed a stub or Android hit 32 children). | Re-run with `GVX_DEBUG_LOG=1`. On Windows, prefer `--backend=whpx`; on Android, see Section 6. |
| `ext4lite` mount fails with `in use` or dirty journal | Another sandbox holds `LOCK_EX`, or a `:ro` mount found an unrecovered journal. | Wait for the writer to exit, or run `rungvx volume compact NAME` first. |
| `rungvx` reports `lockdown` error or `LOCKDOWN_DENIED` | The requested host path or bind address violates pre-execution lockdown. | Pre-open directories with `-v`, enable `--dynamic-ports`, or use `rungvx mount serve`. |

---

## 4. Docker Engine (`docker:dind`) Failures

See [`recipes/docker-engine.md`](recipes/docker-engine.md) for the setup procedure.

| Symptom | Cause | Remedy |
| :--- | :--- | :--- |
| `docker info` fails with connection refused or missing socket | `dockerd` is still booting, or the host context targets the wrong socket. | Wait for `API listen on /var/run/docker.sock`, then run `docker context use gvx`. |
| `docker` CLI on Windows rejects `unix://` context | Windows `unix://` Docker contexts require Docker CLI 29 or newer. | Upgrade Docker CLI, or publish `-p 127.0.0.1:2375:2375` with `host=tcp://127.0.0.1:2375`. |
| `docker pull` fails inside `docker:dind` with x509 error | The host runs behind a corporate TLS proxy or private root CA. | Pass `--host-ca-certs` to `rungvx run`. Mount `/etc/ssl/certs/ca-certificates.crt` for nested containers. |
| Container on Docker `bridge` cannot reach `10.0.2.15` | Guest bridge containers route replies via `eth0` and cannot connect to `eth0` directly. | Connect via the container bridge IP or a user-defined Docker bridge network. |
| `docker run -v /host/path:/data` mounts an empty directory | Docker `-v` paths resolve inside the `gvx` sandbox filesystem, not the host OS. | Bind-mount into `rungvx` first (`-v ~/src:/src`), then pass `-v /src:/data`. |

---

## 5. Kubernetes (`k3s`) Failures

See [`recipes/kubernetes.md`](recipes/kubernetes.md) for the single-node, two-node, and Calico procedures.

| Symptom | Cause | Remedy |
| :--- | :--- | :--- |
| `k3s` fails at startup with `nftables` or `iptables-nft` errors | The guest user-space kernel implements legacy `iptables` only. | Pass `-e IPTABLES_MODE=legacy` to `rungvx run`. |
| Node stays `NotReady` or `kubectl get nodes` times out | The server is still initializing (30 to 120 s), or `KUBECONFIG` is stale. | Wait for `k3s is up and running`, confirm `-p 127.0.0.1:6443:6443`, and export `KUBECONFIG`. |
| `calico-node` stays `CrashLoopBackOff` | `/` was not marked shared (`mount --make-rshared /`), or Felix used `nftables` or wrong CIDR. | Run `mount --make-rshared /` at startup, and set `CALICO_IPV4POOL_CIDR=10.42.0.0/16` plus `FELIX_IPTABLESBACKEND=Legacy`. |
| `kubectl` logs `Skipping network policy controller start` | Legacy iptables or `ipset` support was turned off (`--net-raw=false`). | Keep default `--privileged` (enables `--net-raw`) and `-e IPTABLES_MODE=legacy`. |
| Agent node fails to join server on the same host | Both sandboxes bound port `6443`, or the agent dialed `127.0.0.1`. | Publish `6443` and `51820/udp` on the server only; dial `--server https://10.0.2.2:6443`. |

---

## 6. Networking, DNS, and Android Issues

Consult this table when guest DNS fails, proxies reject HTTPS, or Android limits terminate child processes.

| Symptom | Cause | Remedy |
| :--- | :--- | :--- |
| DNS fails with `connection refused` to `[::1]:53` | Hosts without `/etc/resolv.conf` (such as Android apps) fail default Go DNS lookups. | Supply an explicit resolver via `--host-dns` (for example, `--host-dns 1.1.1.1`). |
| Pull or HTTPS inside guest fails behind a proxy | Guest images omit host-installed root CA certificates by default. | Pass `--host-ca-certs` (and `SSL_CERT_FILE=/path/to/root.pem` if needed) to `rungvx run`. |
| Android guest stops abruptly during builds | Android 12+ kills apps exceeding 32 system-wide children or background CPU caps. | Run from a foreground service, keep processes below 10, or disable restrictions (see [`cli.md`](cli.md#12-android-operation)). |
| Hard link (`ln`) fails with `EACCES` on Android | Android SELinux denies `linkat` on app-data files under `hostfs`. | Store hard-link workloads in an `ext4lite` volume (`-v work:/work`). |
