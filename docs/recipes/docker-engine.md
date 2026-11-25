# Running Docker Engine Inside gvx

This guide shows how to run Docker Engine (`dockerd`) inside a `gvx` sandbox and control it from the host `docker` CLI. Images, layers, and container state persist across restarts inside one `ext4lite` volume while the host CLI talks over a forwarded socket.

The Sentry guest kernel implements legacy `iptables`, Linux bridges, network namespaces, `pivot_root`, `cgroup2`, and overlay mounts without VM drivers. Passing `--auto-publish` binds container ports onto host loopback `127.0.0.1` while keeping the daemon Unix socket owner-only.

Follow the steps below to start `docker:dind`, or consult [`../cli.md`](../cli.md) and [`../troubleshooting.md`](../troubleshooting.md#4-docker-engine-dockerdind-failures) for reference and recovery.

## 1. Architecture of the Setup

`rungvx` launches the unmodified `docker:dind` image, whose entrypoint starts `dockerd` inside the sandbox using the host options below.

| Component | Role |
| :--- | :--- |
| `--privileged` | Enabled by default; permits raw sockets, packet writes, and setuid binaries inside the sandbox only. |
| `-v gvx-docker:/var/lib/docker` | Stores `dockerd` state inside `gvx-docker.ext4`, where Docker's `overlayfs` storage driver runs natively. |
| `-p unix:~/.gvx/docker.sock:2375` | Binds an owner-only (`0600`) host Unix socket and forwards connections to `dockerd` TCP port `2375`. |
| `--auto-publish` | Dynamically binds each `docker run -p` and `docker compose` port on `127.0.0.1:<port>` while keeping port `2375` private. |
| `-p 127.0.0.1:9000-9019:9000-9019` | Optional static alternative to `--auto-publish` when strict lockdown with zero post-boot loopback binds is preferred. |
| `-e DOCKER_TLS_CERTDIR=` | Instructs the image entrypoint to listen on plain TCP `2375`, reachable only through the owner-only socket. |
| `--tls=false` | Tells `dockerd` that plain TCP is intentional, skipping its 15-second startup delay. |
| Docker context `gvx` | Points the host `docker` CLI at the forwarded Unix socket. |

By default, host self-lockdown blocks new socket binds after startup. `--auto-publish` permits post-boot loopback (`127.0.0.1`) binds only; omitting it requires static `-p` port ranges.

## 2. Starting Docker Engine

This procedure starts `dockerd` inside `gvx` and attaches the host `docker` CLI without a local Docker daemon. It requires `rungvx` (see [`../../README.md`](../../README.md#install)) and the `docker` CLI on macOS, Linux, or Windows.

**Windows PowerShell notes**: Create the socket directory with `mkdir $HOME\.gvx -Force`. Create the context with `docker context create gvx --docker "host=unix://$($HOME -replace '\\','/')/.gvx/docker.sock"`. Using `unix://` on Windows requires Docker CLI 29 or newer; earlier releases require `-p 127.0.0.1:2375:2375` and `host=tcp://127.0.0.1:2375`.

> [!IMPORTANT]
> Choose unused host ports when passing static `-p` ranges. `rungvx` exits immediately with `address already in use` if any port in the range is occupied.

1. Create the directory for the forwarded Unix socket.

   ```sh
   mkdir -p ~/.gvx
   ```

2. Start `docker:dind` in the foreground.

   ```sh
   rungvx run \
     --auto-publish \
     -p unix:~/.gvx/docker.sock:2375 \
     -v gvx-docker:/var/lib/docker \
     -e DOCKER_TLS_CERTDIR= \
     docker:dind --tls=false
   ```

3. Wait for `API listen on /var/run/docker.sock` in the terminal output.

4. Create the `gvx` Docker context once in a second terminal.

   ```sh
   docker context create gvx --docker host=unix://$HOME/.gvx/docker.sock
   ```

5. Activate the `gvx` context.

   ```sh
   docker context use gvx
   ```

6. Verify that the host CLI reaches the sandboxed daemon.

   ```sh
   docker info --format '{{.Driver}} {{.OperatingSystem}}'
   ```

   Expected output: `overlayfs Alpine Linux ... (containerized)`.

## 3. Running Workloads

Once the `gvx` context is active, standard `docker` commands run against `dockerd` inside the sandbox.

1. Run a container with outbound network access on the default `bridge`.

   ```sh
   docker run --rm alpine wget -qO- http://example.com
   ```

2. Publish a container port on host loopback (`--auto-publish` binds `127.0.0.1:9000` automatically).

   ```sh
   docker run -d --name web -p 9000:80 nginx:alpine
   curl http://127.0.0.1:9000/
   ```

3. Open an interactive shell inside the running container.

   ```sh
   docker exec -it web sh
   ```

4. Build an image from a local directory (the CLI streams context over the socket).

   ```sh
   docker build -t app ./app
   ```

5. Start a Compose stack.

   ```sh
   docker compose up -d
   ```

## 4. Stopping and Restarting the Engine

Stopping `rungvx` flushes `gvx-docker.ext4` and compacts unused tail groups while preserving images, volumes, and stopped containers.

1. Press `Ctrl-C` in the `rungvx` terminal to stop `dockerd`.
2. Re-run the `rungvx run` command from Section 2 to resume existing state.
3. Restore your default Docker context when finished.

   ```sh
   docker context use default
   ```

## 5. Sharing Host Directories with Nested Containers

Paths supplied to `docker run -v` resolve inside the `gvx` sandbox rather than directly on the host machine. Expose the host directory to `rungvx` first, then mount that sandbox path into the container.

1. Add a host bind mount (for example, `-v ~/src:/src`) to the `rungvx run` command.
2. Mount that sandbox path into the nested container.

   ```sh
   docker run --rm -v /src/data:/data alpine ls /data
   ```

## 6. Operating Behind a TLS-Inspecting Proxy

Add `--host-ca-certs` to the `rungvx run` command in Section 2 behind a corporate TLS-inspecting proxy or private registry CA. `dockerd` then trusts host root certificates for `docker pull` and `docker build` (see [`../cli.md`](../cli.md#410-host-root-certificates)).

> [!IMPORTANT]
> `--host-ca-certs` injects roots into the `dockerd` root filesystem only. Nested containers carry separate root filesystems and do not inherit host roots automatically.

1. Add `--host-ca-certs` to the `rungvx run` command in Section 2.
2. Mount the sandbox certificate bundle read-only into nested containers that make HTTPS requests.

   ```sh
   docker run --rm -v /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro alpine wget -qO- https://example.com/
   ```

3. Place your root CA PEM file (`host-ca.crt`) beside `Dockerfile` when building images.

   ```dockerfile
   FROM alpine:3.20
   COPY host-ca.crt /tmp/host-ca.crt
   RUN cat /tmp/host-ca.crt >> /etc/ssl/certs/ca-certificates.crt && rm /tmp/host-ca.crt
   ```

4. Run `docker build -t app .` so subsequent `RUN` stages trust the root certificate.

If only `dockerd` pulls from a private registry, steps 2 through 4 are unnecessary.

## 7. Reference and Known Limits

This section documents storage options, known limits, security properties, and measured container resource controls.

### 7.1 Storage Options

`dockerd` supports three backing stores under `gvx`, all compatible with Docker's `overlayfs` driver. Times below reflect single runs on an Apple M1 host using `hvf`.

| Storage Backend | `rungvx` Flag | Persists Across Restarts | `docker pull nginx:alpine` |
| :--- | :--- | :--- | ---: |
| Named `ext4lite` volume | `-v gvx-docker:/var/lib/docker` | Yes | 9 s |
| Host-path `ext4lite` image | `--mount type=volume,src=/disk/gvx-docker.ext4,dst=/var/lib/docker` | Yes | 9 s |
| Host directory (`hostfs`) | `-v /disk/gvx-docker:/var/lib/docker` | Yes, as host files | 32 to 54 s |
| Memory (`tmpfs`) | `--tmpfs /var/lib/docker:size=6g` | No | 5 s |

Prefer an `ext4lite` volume unless you need direct inspection of host files. Reset engine state completely with `rungvx volume rm gvx-docker`.

### 7.2 Known Limits

This table summarizes practical Docker Engine boundaries inside `gvx`; see [`../compatibility.md`](../compatibility.md) for host-wide limits.

| Limit | Observed Effect |
| :--- | :--- |
| Published host ports | Without `--auto-publish`, static `-p` rules fix ports at startup. With `--auto-publish`, dynamic ports bind `127.0.0.1` only (`net.forward.max_dynamic_ports`, default 64). |
| Guest architecture | Matches the host CPU architecture (`linux/arm64` on Apple Silicon and Windows ARM64; `linux/amd64` on x86-64). |
| Reaching `10.0.2.15` from a container | Bridge containers cannot dial the sandbox's `eth0` IP. Use the container IP or a user-defined Docker bridge network. |
| `docker stats` and `cgroup2` `io` | Reports memory (`memory.current`), CPU, network, and `io.stat` counters for `ext4lite` I/O (also in `rungvx stats`). `io.max` and `io.weight` throttling are not enforced. |
| Measured memory reporting | A container holding 64 MiB reported 64 MiB on `hvf` and 101 MiB on Linux `systrap`. |
| `docker run -m` and `--cpus` | Enforced via Sentry `memory.max` polling (Section 7.4) and `cpu.max` quotas (Section 7.5). |
| Passive knobs | `--memory-reservation`, `--memory-swap`, and `--cpu-shares` store without enforcement; `docker run` warns on missing swap accounting. |

### 7.3 Security Notes

`--privileged` grants capabilities solely inside the sandbox, including for nested `docker run --privileged` containers. Raw packets remain inside the guest network stack; the host NAT forwarder relays TCP and UDP through unprivileged sockets. The forwarded host Unix socket uses mode `0600`, matching local-owner access on a native Docker daemon.

### 7.4 Memory Limits of Containers

Setting `docker run -m SIZE` writes `memory.max` in the container's cgroup. The Sentry accounts pages by scanning its memory file rather than synchronously on each page fault. A background goroutine polls every finite-limit cgroup, starting on the first finite limit and stopping once none remains.

| Property | Behavior |
| :--- | :--- |
| Poll interval | At least 5 ms (`memory.cgroup.poll_interval`) and 4x prior scan time when any cgroup exceeds half its cap. Otherwise 25 ms (~40 idle wakeups/s). |
| Transient overshoot | Containers can allocate unchecked between scans (up to 25 ms below half limit). On macOS, scan cost scales with newly committed pages. |
| Victim selection | Kills the highest OOM-score task (RSS plus `oom_score_adj`; lower PID breaks ties). PID 1 and `-1000` are immune; `memory.oom.group` kills the cgroup. |
| Observable outcome | Exit code `137`, `OOMKilled: true`, `oom_kill` in `memory.events`, and `/dev/kmsg` OOM lines. Other containers and `dockerd` continue running. |
| Short-lived spikes | Allocations freed between polls escape detection (128 MiB over ~30 ms read 2 MiB in 4 of 6 macOS runs). Memory held over 100 ms is caught. |
| Retained `tmpfs` data | `tmpfs` files stay charged after victim death. If usage remains above `memory.max`, the enforcer kills the next candidate after two checks. |
| Counted memory | Anonymous memory and `tmpfs` count against `memory.max`; page cache and mapped files do not (`docker stats` counts all). Idle Go uses 1.5 to 2.7 MiB; Alpine `sleep` uses 40 to 60 KiB. |
| Windows `systrap` | Supported; stub residency observers query `K32QueryWorkingSetEx` during scans, unmaps, and exits to update `memory.stat`, `memory.current`, and `memory.max`. |
| Unenforced knobs | `memory.high`, `cpu.weight`, `io.weight`, `io.max`, and `memory.swap.*`. |

### 7.5 CPU Limits of Containers

Setting `docker run --cpus N` writes `N * 100000` microseconds of quota per 100,000-microsecond period to `cpu.max`. Tasks in a cgroup and its descendants share the quota across all CPUs and obey every ancestor's limit. A task exhausting its quota blocks on its next return to guest code and resumes when the next period opens.

| Property | Behavior |
| :--- | :--- |
| Accounting | Per-task wall-clock execution across guest and Sentry code, charged every 10 ms to `usage_usec` in `cpu.stat`. |
| Counters | `nr_periods` counts active periods; `nr_throttled` counts periods ending throttled or with debt above 10 ms. |
| `throttled_usec` | Records one wall-clock interval for the cgroup (Linux sums per-CPU intervals and reports higher values on multi-CPU cgroups). |
| Usage split | `user_usec` and `system_usec` derive from task tick clocks and sum to `usage_usec`. |
| System calls and debt | Running syscalls bill until guest return. Up to one tick carries into the next period; throttling engages above 10 ms debt. |
| Late charges | After a host or Sentry stall, runtime spreads evenly across elapsed periods (up to 1,024) to preserve duty cycles. |
| Bounds and updates | Periods span 1 ms to 1 s and quotas start at 1 ms (`EINVAL` outside). Writing `cpu.max` starts a fresh period; migrating unthrottles within 110 ms. |
| Syscall-free loops | The execution engine preempts pure compute loops. A jump loop used 0.50 CPU at `50000 100000` across `hvf`, `whpx`, and `systrap` (`amd64`/`arm64`). |
| Measuring inside containers | Because `exec` shares the cgroup quota, compute utilization as delta `usage_usec` divided by delta `/proc/uptime` in the same process. |
| Unlimited overhead | Writing `max` removes throttling at a cost of one atomic load per guest return. `cpu.weight` and Linux burst limits are unenforced. |

Measured results from `TestE2ECPUMaxEnforcement` appear below. The `max` and `130000 100000` cases run a static compute loop; others run a Go loop whose background monitor demands 1.01 to 1.03 CPU.

| Case | `hvf` | Linux `systrap` | Windows `systrap` and `whpx` |
| :--- | :--- | :--- | :--- |
| `50000 100000`, 5 s | 0.50 CPU | 0.50 CPU | 0.50 CPU |
| `max`, 3 s, static loop | 1.00 CPU | not measured | 1.00 CPU |
| `10000 100000`, billed time | 0.10 CPU | 0.10 CPU | 0.10 CPU |
| `10000 100000`, running share of billed time (clock loop) | 0.86 to 0.96 | not measured | 0.89 to 0.98 |
| `130000 100000`, `nr_throttled`, static loop | 0 | not measured | 0 |
| `100000 100000`, `nr_throttled` | 14 in 3 s | 18 in 3 s | not measured |

Because a Go program demands slightly above 1.0 CPU, a 1-CPU quota throttles it as on Linux. Clock-loop checks measure running gaps of 2 ms or more rather than iteration counts, which vary with CPU frequency scaling.

## 8. Troubleshooting

If `docker info` fails, ports collide, or builds fail behind a proxy, consult [`../troubleshooting.md`](../troubleshooting.md#4-docker-engine-dockerdind-failures). Re-run `rungvx` with `GVX_DEBUG_LOG=1` to inspect Sentry kernel diagnostics for opaque crashes.
