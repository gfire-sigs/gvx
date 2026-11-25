# Running Docker Engine Inside gvx

This guide explains how to operate Docker Engine (`dockerd`) inside a `gvx` sandbox and drive it from the host `docker` CLI. Images, layers, and container state persist across restarts inside a single `ext4lite` volume image, while the host `docker` CLI communicates over a local Docker context. Consult [`../cli.md`](../cli.md) for the complete flag reference and [`../troubleshooting.md`](../troubleshooting.md#4-docker-engine-dockerdind-failures) if a step fails.

---

## 1. Architecture of the Setup

`rungv` runs the unmodified `docker:dind` image, whose entrypoint launches `dockerd` inside the sandbox. The Sentry guest kernel provides legacy `iptables` (including `addrtype`), Linux bridges, network namespaces, `pivot_root`, `cgroup2`, and overlay mounts.

| Component | Role |
| :--- | :--- |
| `--privileged` | Enabled by default; permits raw sockets, packet writes, and setuid binaries inside the sandbox only. |
| `-v gvx-docker:/var/lib/docker` | Stores `dockerd` state inside `gvx-docker.ext4`, where Docker's `overlayfs` storage driver operates natively. |
| `-p unix:~/.gvx/docker.sock:2375` | Binds an owner-only (`0600`) host Unix socket and forwards connections to `dockerd` TCP port `2375`. |
| `--auto-publish` | Dynamically binds each `docker run -p` and `docker compose` port on host `127.0.0.1:<port>` while keeping port `2375` restricted to the Unix socket. |
| `-p 127.0.0.1:9000-9019:9000-9019` | Optional static alternative to `--auto-publish` when strict lockdown with zero post-boot loopback binds is preferred. |
| `-e DOCKER_TLS_CERTDIR=` | Instructs the image entrypoint to listen on TCP `2375` without TLS (reachable only through the owner-only Unix socket). |
| `--tls=false` | Confirms to `dockerd` that plain TCP is intentional, avoiding its 15-second startup delay. |
| Docker context `gvx` | Directs the host `docker` CLI to the forwarded Unix socket. |

By default, host self-lockdown prevents new host socket binds after startup. Passing `--auto-publish` relaxes socket lockdown solely for host loopback (`127.0.0.1`) binds; omitting it requires pre-binding a static `-p` port range.

---

## 2. Starting Docker Engine

This procedure starts `dockerd` inside `gvx` and attaches the host `docker` CLI without any local Docker daemon. It requires `rungv` (see [`../../README.md`](../../README.md#2-installation-and-first-run)) and the `docker` CLI. The commands work on macOS, Linux, and Windows.

**Windows PowerShell notes**: Create the socket directory with `mkdir $HOME\.gvx -Force`, and create the context with `docker context create gvx --docker "host=unix://$($HOME -replace '\\','/')/.gvx/docker.sock"`. Using `unix://` on Windows requires Docker CLI 29 or newer; with an earlier CLI, publish `-p 127.0.0.1:2375:2375` and configure `host=tcp://127.0.0.1:2375`.

> [!IMPORTANT]
> Choose unused host ports when using static `-p` ranges. `rungv` exits immediately with `address already in use` if any port in the range is occupied.

1. Create the directory for the forwarded Unix socket.

   ```sh
   mkdir -p ~/.gvx
   ```

2. Start `docker:dind` in the foreground.

   ```sh
   rungv run \
     --auto-publish \
     -p unix:~/.gvx/docker.sock:2375 \
     -v gvx-docker:/var/lib/docker \
     -e DOCKER_TLS_CERTDIR= \
     docker:dind --tls=false
   ```

3. Wait for `API listen on /var/run/docker.sock` in the terminal output.

4. In a second terminal, create the `gvx` Docker context once.

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

---

## 3. Running Workloads

Once the `gvx` context is active, standard `docker` commands execute against `dockerd` inside the sandbox.

1. Run a container with outbound connectivity on the default `bridge` network.

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

4. Build an image from a local directory (the `docker` CLI streams the build context to `dockerd`).

   ```sh
   docker build -t app ./app
   ```

5. Start a Compose stack.

   ```sh
   docker compose up -d
   ```

---

## 4. Stopping and Restarting the Engine

Stopping `rungv` cleanly flushes `gvx-docker.ext4` and compacts unused tail groups while preserving images, volumes, and stopped containers.

1. Press `Ctrl-C` in the `rungv` terminal to stop `dockerd`.
2. Re-run the `rungv run` command from Section 2 whenever you wish to resume with existing state.
3. Restore your default Docker context when finished.

   ```sh
   docker context use default
   ```

---

## 5. Sharing Host Directories with Nested Containers

Paths supplied to `docker run -v` refer to paths inside the `gvx` sandbox rather than directly on the host machine. Expose the host directory to `rungv` first, then mount that sandbox path into the container.

1. Add a host bind mount (for example, `-v ~/src:/src`) to the `rungv run` command in Section 2.
2. Mount the sandbox path into the nested container.

   ```sh
   docker run --rm -v /src/data:/data alpine ls /data
   ```

---

## 6. Operating Behind a TLS-Inspecting Proxy

When the host operates behind a corporate TLS-inspecting proxy or private registry CA, add `--host-ca-certs` to the `rungv run` command in Section 2. `dockerd` then trusts host root certificates for `docker pull` and `docker build`. See [`../cli.md`](../cli.md#410-host-root-certificates) for platform certificate sources.

> [!IMPORTANT]
> `--host-ca-certs` injects roots into the sandbox root filesystem used by `dockerd` only. Nested containers launched by `dockerd` carry their own root filesystems and do not inherit host roots automatically.

1. Add `--host-ca-certs` to the `rungv run` invocation in Section 2.
2. For nested containers that need the host roots, mount the sandbox bundle read-only.

   ```sh
   docker run --rm -v /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro alpine wget -qO- https://example.com/
   ```

3. For `docker build`, place your root CA PEM file (`host-ca.crt`) beside the `Dockerfile` and append it to the image bundle.

   ```dockerfile
   FROM alpine:3.20
   COPY host-ca.crt /tmp/host-ca.crt
   RUN cat /tmp/host-ca.crt >> /etc/ssl/certs/ca-certificates.crt && rm /tmp/host-ca.crt
   ```

4. Run `docker build -t app .`. Subsequent `RUN` stages trust the appended root certificate.

If only `dockerd` itself pulls from a private registry, steps 2 through 4 are unnecessary.

---

## 7. Reference and Known Limits

This section documents storage options, known limits, security properties, and measured container resource controls.

### 7.1 Storage Options

`dockerd` supports three backing stores under `gvx`, all compatible with Docker's `overlayfs` driver. Times below reflect single runs on an Apple M1 host using `hvf`.

| Storage Backend | `rungv` Flag | Persists Across Restarts | `docker pull nginx:alpine` |
| :--- | :--- | :--- | ---: |
| Named `ext4lite` volume | `-v gvx-docker:/var/lib/docker` | Yes | 9 s |
| Host-path `ext4lite` image | `--mount type=volume,src=/disk/gvx-docker.ext4,dst=/var/lib/docker` | Yes | 9 s |
| Host directory (`hostfs`) | `-v /disk/gvx-docker:/var/lib/docker` | Yes, as host files | 32 to 54 s |
| Memory (`tmpfs`) | `--tmpfs /var/lib/docker:size=6g` | No | 5 s |

Prefer an `ext4lite` volume unless direct inspection of individual files on the host is needed. To reset engine state completely, run `rungv volume rm gvx-docker`.

### 7.2 Known Limits

| Limit | Observed Effect |
| :--- | :--- |
| Published host ports | Without `--auto-publish`, static `-p` rules fix exposed ports at startup. With `--auto-publish`, `rungv` binds dynamic ports on `127.0.0.1` only (up to `net.forward.max_dynamic_ports`, default 64). |
| Guest architecture | Matches the host CPU architecture (`linux/arm64` on Apple Silicon and Windows ARM64; `linux/amd64` on x86-64). |
| Reaching `10.0.2.15` from a container | A container on the `bridge` network cannot connect to the sandbox's `eth0` IP. Use the container IP or a user-defined bridge network. |
| `docker stats` | Reports memory (`memory.current`, including page cache and mapped pages), CPU usage, and network counters. A container writing 64 MiB reported 64 MiB on `hvf` and 101 MiB on Linux `systrap`. `BLOCK I/O` remains `0B / 0B` because no `cgroup2` `io` controller exists. |
| `docker run -m` | Enforced via periodic Sentry polling of `memory.max` (Section 7.4). |
| `docker run --cpus` | Enforced via Sentry `cpu.max` bandwidth quotas on every backend (Section 7.5). |
| `--memory-reservation`, `--memory-swap`, `--cpu-shares` | Accepted and stored without enforcement; `docker run` warns about missing swap accounting. |

### 7.3 Security Notes

`--privileged` grants capabilities solely inside the sandbox, including for nested `docker run --privileged` containers. Raw packets remain confined to the guest network stack; the host NAT forwarder relays only TCP and UDP flows through unprivileged host sockets. The forwarded host Unix socket carries mode `0600`, matching the local-owner access model of a native Docker daemon.

### 7.4 Memory Limits of Containers

Setting `docker run -m SIZE` writes `memory.max` in the container's cgroup. Because the Sentry accounts pages by scanning its memory file rather than synchronously on each page fault, a background goroutine polls all cgroups with finite limits. Polling starts upon the first finite limit and stops once none remains.

| Property | Behavior |
| :--- | :--- |
| Poll interval | At least 5 ms (`memory.cgroup.poll_interval`) and 4 times the prior scan duration (`memory.cgroup.scan_ratio`) when any limited cgroup exceeds half its cap; otherwise 25 ms (`memory.cgroup.idle_poll_interval`, also bounded by 4 times scan duration). An idle limited sandbox performs roughly 40 wakeups per second. |
| Transient overshoot | A container may exceed its cap by whatever it allocates between scans (up to 25 ms below the half-limit threshold). On macOS, scan latency scales with newly committed pages, so one check may observe hundreds of MiB of new usage. |
| Victim selection | Kills the process with the highest OOM score (resident set plus `oom_score_adj` per mille of the limit; ties break toward lower PID). Guest PID 1 and `oom_score_adj=-1000` are immune. Setting `memory.oom.group` kills every process in the cgroup. |
| Observable outcome | Exit code `137`, `OOMKilled: true` in `docker inspect`, `oom_kill` in `memory.events`, and Linux-format OOM lines in `/dev/kmsg`. Other containers and `dockerd` continue running. |
| Short-lived spikes | Allocations created and freed between polls escape detection (for example, `dd if=/dev/zero bs=128M count=1` lasting roughly 30 ms showed 2 MiB in 4 of 6 macOS runs). Memory held longer than 100 ms is reliably caught; untouched mappings are not charged. |
| Retained `tmpfs` data | `tmpfs` files stay charged after a victim dies; if usage stays above the limit, the enforcer kills the next candidate after two additional checks. |
| Counted memory | Anonymous memory plus `tmpfs` data count against `memory.max`; reclaimable page cache, mapped files, and un-decommitted freed pages do not. `memory.current` and `docker stats` report all categories and therefore read higher. Measured idle usage: 1.8 MiB (`linux/amd64` `systrap`), 1.5 MiB (`linux/arm64` `systrap`), and 2.7 MiB (`hvf`) for an idle Go process; 40 to 60 KiB for Alpine `sleep` (`whpx` unmeasured). |
| Windows `systrap` | Supported; stub residency observers query `K32QueryWorkingSetEx` during scans, unmaps, and exits so `memory.stat`, `memory.current`, and `memory.max` reflect guest pages. |
| Unenforced knobs | `memory.high`, `cpu.weight`, and `memory.swap.*`. |

### 7.5 CPU Limits of Containers

Setting `docker run --cpus N` writes `N * 100000` microseconds of quota per 100,000-microsecond period to `cpu.max`. Tasks in a cgroup and its descendants share the quota across all CPUs and obey every ancestor's limit. A task exhausting its quota blocks upon its next return to guest code and resumes when the next period opens.

| Property | Behavior |
| :--- | :--- |
| Accounting | Per-task wall-clock execution across guest and Sentry code, charged every 10 ms and reported as `usage_usec` in `cpu.stat`. |
| Counters | `nr_periods` counts completed active periods; `nr_throttled` counts periods ending throttled or in debt exceeding 10 ms. |
| `throttled_usec` | Records one wall-clock interval for the cgroup (Linux sums per-CPU intervals and therefore reports larger values for multi-CPU cgroups). |
| Usage split | `user_usec` and `system_usec` derive from task tick clocks and sum to `usage_usec`. |
| System calls and debt | In-flight system calls continue until return to guest code and bill toward the quota. Up to one tick of overrun becomes debt repaid in the next period; throttling engages above 10 ms of debt. |
| Late charges | After a host or Sentry stall, accumulated runtime spreads evenly over elapsed periods (up to 1,024 periods) so paused workloads preserve their duty cycle. |
| Bounds and updates | Periods span 1 ms to 1 s and quotas start at 1 ms (`EINVAL` outside). Writing `cpu.max` starts a fresh period immediately; migrating a throttled task to an unlimited cgroup resumes it within 110 ms. |
| Syscall-free loops | Pure compute loops without system calls are preempted by the execution engine; a tight jump loop consumed 0.50 CPU at `50000 100000` across `hvf`, `whpx`, Linux `systrap`, and Windows `systrap` (`amd64` and `arm64`). |
| Measuring inside containers | Because `kubectl exec` or `docker exec` shares the cgroup quota, compute utilization as delta `usage_usec` divided by delta `/proc/uptime` read in the same process. |
| Unlimited overhead | Writing `max` removes throttling at the cost of one atomic load per return to guest code. `cpu.weight` and Linux burst limits are not enforced. |

Measured results from `TestE2ECPUMaxEnforcement` (test A14 and companions) appear below. The `max` and `130000 100000` rows execute a single-threaded static loop; other rows execute a Go loop whose runtime monitor raises average demand to 1.01 to 1.03 CPU (and higher on loaded hosts, where Go's monitor wakeups bill host scheduling time).

| Case | `hvf` | Linux `systrap` | Windows `systrap` and `whpx` |
| :--- | :--- | :--- | :--- |
| `50000 100000`, 5 s | 0.50 CPU | 0.50 CPU | 0.50 CPU |
| `max`, 3 s, static loop | 1.00 CPU | not measured | 1.00 CPU |
| `10000 100000`, billed time | 0.10 CPU | 0.10 CPU | 0.10 CPU |
| `10000 100000`, running share of billed time (clock loop) | 0.86 to 0.96 | not measured | 0.89 to 0.98 |
| `130000 100000`, `nr_throttled`, static loop | 0 | not measured | 0 |
| `100000 100000`, `nr_throttled` | 14 in 3 s | 18 in 3 s | not measured |

Because a Go program demands slightly over 1.0 CPU, a quota of exactly one CPU throttles it, matching Linux behavior. The clock-loop check measures elapsed running time using guest clock gaps of 2 ms or more rather than raw iteration counts, which vary with host CPU frequency scaling.

---

## 8. Troubleshooting

If `docker info` fails, ports collide, or builds fail behind a corporate TLS proxy, consult [`../troubleshooting.md`](../troubleshooting.md#4-docker-engine-dockerdind-failures). For opaque daemon crashes, re-run `rungv` with `GVX_DEBUG_LOG=1` to inspect Sentry kernel diagnostics.
