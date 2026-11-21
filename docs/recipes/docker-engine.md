# Use `gvx` as a Docker Engine

This guide shows how to run Docker Engine inside a `gvx` sandbox and control it with your host `docker` CLI. `dockerd` stores its images and containers in an `ext4lite` volume so they survive restarts. The host `docker` CLI connects through a Docker context. See [`../cli.md`](../cli.md) for the full flag reference.

## 1. How It Works

`rungv` runs the unmodified `docker:dind` image, whose entrypoint starts `dockerd` inside the sandbox. The guest kernel provides `iptables` (with `addrtype`), the `bridge` network, network namespaces, `pivot_root`, cgroup v2, and overlay mounts.

| Part | What it does |
| :--- | :--- |
| `--privileged` | On by default. Enables raw sockets, packet writes, and setuid binaries inside the sandbox only. |
| `-v gvx-docker:/var/lib/docker` | Stores `dockerd` data in the `ext4lite` image `gvx-docker.ext4`, where Docker's overlay storage driver works natively. |
| `-p unix:~/.gvx/docker.sock:2375` | Binds a host Unix socket (`0600`, owner-only) and forwards it to `dockerd` port 2375. |
| `--auto-publish` | Publishes each `docker run -p` and `docker compose` port automatically on host `127.0.0.1:<port>`, keeping port 2375 on the Unix socket only. |
| `-p 127.0.0.1:9000-9019:9000-9019` | Optional static alternative to `--auto-publish` when you want strict lockdown with zero post-boot loopback binds. |
| `-e DOCKER_TLS_CERTDIR=` | Tells the entrypoint to listen on TCP port 2375 without TLS (reachable only through the Unix socket forward above). |
| `--tls=false` | Tells `dockerd` that missing TLS is intentional, skipping its 15-second startup delay. |
| Docker context `gvx` | Points your host `docker` CLI at the Unix socket. |

By default, the sandbox locks itself down before the guest starts and rejects new host binds later. Pass `--auto-publish` to publish container ports dynamically on host `127.0.0.1` as containers start and stop. If you prefer strict lockdown without dynamic binds, omit `--auto-publish` and pre-bind a static `-p` port range instead.

## 2. Start the Engine

These steps start `dockerd` in `gvx` and connect your host `docker` CLI (no local Docker daemon needed). You need `rungv` (see the [README](../../README.md#3-quickstart)) and the `docker` CLI. The steps work on macOS, Linux, and Windows. On Windows PowerShell, create the socket directory with `mkdir $HOME\.gvx -Force` and create the context with `docker context create gvx --docker "host=unix://$($HOME -replace '\\','/')/.gvx/docker.sock"`. Using `unix://` on Windows requires Docker CLI 29 or later; with an older CLI, publish `-p 127.0.0.1:2375:2375` and use `host=tcp://127.0.0.1:2375`.

> [!IMPORTANT]
> Pick unused host ports when using static `-p` ranges. `rungv` exits with `address already in use` if any port in the range is busy.

1. Create the socket directory.

   ```sh
   mkdir -p ~/.gvx
   ```

2. Start the engine in the foreground.

   ```sh
   rungv run \
     --auto-publish \
     -p unix:~/.gvx/docker.sock:2375 \
     -v gvx-docker:/var/lib/docker \
     -e DOCKER_TLS_CERTDIR= \
     docker:dind --tls=false
   ```

3. Wait for `API listen on /var/run/docker.sock`.

4. Create the Docker context once in a second terminal.

   ```sh
   docker context create gvx --docker host=unix://$HOME/.gvx/docker.sock
   ```

5. Switch to the `gvx` context.

   ```sh
   docker context use gvx
   ```

6. Verify the connection.

   ```sh
   docker info --format '{{.Driver}} {{.OperatingSystem}}'
   ```

   Expected output: `overlayfs Alpine Linux ... (containerized)`.

## 3. Use the Engine

Run normal `docker` commands from your host terminal; each request talks to `dockerd` inside the sandbox.

1. Run a container on the default `bridge` network.

   ```sh
   docker run --rm alpine wget -qO- http://example.com
   ```

2. Publish a container port on host loopback.

   ```sh
   docker run -d --name web -p 9000:80 nginx:alpine
   curl http://127.0.0.1:9000/
   ```

3. Open an interactive shell in the container.

   ```sh
   docker exec -it web sh
   ```

4. Build an image from a host directory (the `docker` CLI uploads the build context to `dockerd`).

   ```sh
   docker build -t app ./app
   ```

5. Start a Compose stack. With `--auto-publish`, `rungv` binds each published port on `127.0.0.1` automatically.

   ```sh
   docker compose up -d
   ```

## 4. Stop and Restart the Engine

These steps stop `dockerd` and bring it back with your persisted images and volumes intact.

1. Press `Ctrl-C` in the `rungv` terminal.

2. Restart the engine with the `rungv run` command from Section 2. Your images, volumes, and stopped containers remain in `gvx-docker.ext4`.

3. Switch back to your default Docker context when finished.

   ```sh
   docker context use default
   ```

## 5. Share Host Directories

A path in `docker run -v` refers to a path inside the `gvx` sandbox, not on the host. Bind-mount the host directory into `rungv` first, then mount that sandbox path into the container.

1. Add a host bind mount to the `rungv run` command in Section 2.

   ```sh
   -v ~/src:/src
   ```

2. Mount the sandbox path into your container.

   ```sh
   docker run --rm -v /src/data:/data alpine ls /data
   ```

## 6. Trust a TLS-Inspecting Proxy

If your host sits behind a TLS-inspecting proxy or pulls from a private registry with an internal CA, add `--host-ca-certs` to the `rungv run` command in Section 2. `dockerd` then trusts host root certificates so `docker pull` and `docker build` succeed through the proxy. See [`../cli.md`](../cli.md#410-host-root-certificates) for certificate sources.

> [!IMPORTANT]
> `--host-ca-certs` applies only to `dockerd` and direct sandbox processes. Containers started by `dockerd` have their own root filesystems and do not inherit host roots automatically.

1. Add `--host-ca-certs` to the `rungv run` command in Section 2.

   ```sh
   --host-ca-certs
   ```

2. Mount the sandbox CA bundle into a container when it needs the host roots.

   ```sh
   docker run --rm -v /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro alpine wget -qO- https://example.com/
   ```

3. For `docker build`, place the root CA PEM file (here `host-ca.crt`) next to your `Dockerfile`.

   ```dockerfile
   FROM alpine:3.20
   COPY host-ca.crt /tmp/host-ca.crt
   RUN cat /tmp/host-ca.crt >> /etc/ssl/certs/ca-certificates.crt && rm /tmp/host-ca.crt
   ```

4. Build the image. Every step after the `RUN` line trusts the root certificate.

   ```sh
   docker build -t app .
   ```

If only `dockerd` pulls from a private registry, skip steps 2 and 3 and run `docker pull REGISTRY/IMAGE` directly.

## 7. Reference

### 7.1 Storage Choices

`dockerd` can store its data in three ways, all compatible with the overlay storage driver. Measured times are single runs on an Apple M1 with `hvf`.

| Storage | `rungv` flag | Persists across restarts | `docker pull nginx:alpine` |
| :--- | :--- | :--- | ---: |
| `ext4lite` volume | `-v gvx-docker:/var/lib/docker` | Yes | 9 s |
| `ext4lite` image at a host path | `--mount type=volume,src=/disk/gvx-docker.ext4,dst=/var/lib/docker` | Yes | 9 s |
| Host directory (`hostfs`) | `-v /disk/gvx-docker:/var/lib/docker` | Yes, as host files | 32 to 54 s |
| Memory (`tmpfs`) | `--tmpfs /var/lib/docker:size=6g` | No | 5 s |

Prefer an `ext4lite` volume unless you need direct host file access. The image grows on demand and compacts its unused tail on clean exit. To wipe all engine state, run `rungv volume rm gvx-docker` (or delete `gvx-docker.ext4` in the `volumes` directory).

### 7.2 Known Limits

| Limit | Effect |
| :--- | :--- |
| Published host ports | Without `--auto-publish`, static `-p` rules fix published ports at start. With `--auto-publish`, `rungv` binds dynamic ports on `127.0.0.1` only (up to `net.forward.max_dynamic_ports`, default 64). |
| Guest architecture | Matches the host CPU architecture (`linux/arm64` on Apple Silicon and ARM64 Windows; `linux/amd64` on x86_64). |
| `10.0.2.15` from a container | A `bridge` container cannot reach the sandbox's `eth0` address. Use the container IP or a user-defined bridge network. |
| `docker stats` | Reports memory (`memory.current`, including page cache and mapped pages), CPU time, and network counters. A container writing 64 MiB reported 64 MiB on `hvf` and 101 MiB on Linux `systrap`. `BLOCK I/O` stays `0B / 0B` because the guest has no `io` controller. |
| `docker run -m` | The Sentry polls each limited container's memory usage and kills the highest-scoring process above the limit (see Section 7.4). |
| `docker run --cpus` | Translates to `cpu.max`, enforced by the Sentry on every engine (see Section 7.5). |
| `--memory-reservation`, `--memory-swap`, `--cpu-shares` | Accepted and stored without enforcement. `docker run` warns about the missing swap limit. |

### 7.3 Security

`--privileged` grants privileges only inside the sandbox, including for nested `docker run --privileged` containers. Raw packets never leave the guest network stack; the NAT forwarder only relays TCP and UDP through host sockets. The host API socket uses mode `0600`, so only your user account can access it, matching a local Docker daemon.

### 7.4 Memory Limits of Containers

A container with `docker run -m SIZE` gets `memory.max` in its cgroup. The Sentry cannot count a page at the moment of its allocation. It counts a page after a scan of the memory file, so it polls. The poll starts with the first finite limit and ends when no cgroup has a limit.

| Property | Value |
| :--- | :--- |
| Poll interval | 5 ms at least (tunable `memory.cgroup.poll_interval`), and 4 times the duration of the last check (tunable `memory.cgroup.scan_ratio`), while a limited container uses half of its limit or more. Otherwise 25 ms (tunable `memory.cgroup.idle_poll_interval`), and also at least 4 times the duration of the last check, so a slow scan of untouched memory cannot repeat without bound. An idle sandbox with a limit makes 40 wakeups a second. |
| Overshoot | A container can pass its limit by what it allocates between two checks. A container that uses less than half of its limit is checked every 25 ms, so it can pass the limit by 25 ms of allocation. The scan of the memory file on macOS costs time in proportion to the new pages, so one check can see hundreds of MiB more than the check before. |
| Victim | The process with the highest score: its resident set plus `oom_score_adj` per mille of the limit, as in Linux. Equal scores go to the lower PID. A process with `oom_score_adj` of -1000 and the init process of the guest are never ended. With `memory.oom.group` set, every other process of the container. |
| Result | Exit code 137, `OOMKilled: true` in `docker inspect`, and `oom_kill` in `memory.events`. Other containers and `dockerd` keep running. |
| Not caught | A process that allocates and frees more than the limit between two checks. A one-shot `dd if=/dev/zero bs=128M count=1` is an example: its buffer lives about 30 ms. On macOS, a test that held 128 MiB for 30 ms showed only 2 MiB in `memory.current` in 4 of 6 runs, so the scan of the memory file missed most of the pages. Linux counts each page at its first write and kills such a process. A process that holds its memory for longer than 100 ms is found. Memory that a process maps but never writes is not charged, as on Linux. |
| Held after the kill | Data in `tmpfs` files stays charged to the container. The enforcer waits for the usage to drop to the limit after a kill. When tmpfs data keeps the usage above the limit, it kills the next process after two more checks. |
| Counted memory | The enforcer compares anonymous memory plus tmpfs data with the limit. Page cache, mapped file pages, and freed pages that the Sentry has not decommitted yet do not count, as they are reclaimable or free in Linux. `memory.current` and `docker stats` still show every kind, so they read higher than the enforced value. Measured idle values: an idle Go process holds 1.8 MiB (`linux/amd64` systrap), 1.5 MiB (`linux/arm64` systrap), and 2.7 MiB (`hvf`) of this memory. An `alpine` container that runs `sleep` holds 40 KiB to 60 KiB. `whpx` is not measured. |
| Windows `systrap` | Enabled. The engine tracks stub views and queries `K32QueryWorkingSetEx` in stub processes during scans, unmaps, and address-space exits. Both `memory.stat` and `memory.current` count guest pages, and the enforcer enforces `memory.max`. |
| Not enforced | `memory.high`, `cpu.weight`, and `memory.swap.*`. |

### 7.5 CPU Limits of Containers

A container with `docker run --cpus N` gets `cpu.max` in its cgroup. The value is `N * 100000` microseconds of quota for each period of 100000 microseconds. The tasks of the container, and of its child cgroups, use the quota together on all CPUs. A task that spends the quota stops at its next return to guest code. It runs again when the next period starts. A child cgroup obeys the quota of every ancestor.

| Property | Value |
| :--- | :--- |
| Accounting | A meter measures the wall time that each task runs in guest and Sentry code. The Sentry charges that time every 10 ms. `usage_usec` of `cpu.stat` is the same measured time. |
| Counters | `nr_periods` counts the periods that end while the cgroup is active. `nr_throttled` counts the periods that end while it throttles, and the periods of a late charge that end in debt of more than 10 ms. Both follow Linux. |
| `throttled_usec` | One wall-clock interval for the whole cgroup. Linux sums the time of each CPU, so it reports more for a cgroup with tasks on several CPUs. A late charge adds the estimated stop time of each period that ends in debt. |
| Split of usage | `user_usec` and `system_usec` still come from the tick clocks of the tasks. Their sum is the measured time. |
| System time | A task in a system call keeps running, as in Linux. The call counts toward the quota, and the task stops when it returns to guest code. |
| Debt | A task can run up to one tick past the quota before it stops. The next period repays that time. A cgroup throttles only after a debt of more than 10 ms. |
| Late charge | A stall of the Sentry can delay the charge of a task by many periods. The charge spreads the running time of the task evenly over the time since its last charge, so a task that paused keeps its duty cycle. Each period takes its part and gives the quota again. A task that stayed below its quota in each period makes no debt. A task that stayed above it pays the debt later. A charge covers at most 1024 periods. |
| Period and quota | A period is 1 ms to 1 s, and a quota is 1 ms or more. Other values give `EINVAL`. |
| Write to `cpu.max` | A new value starts a new period with a full quota. It releases a throttled task at once. |
| Move to another cgroup | A throttled task reads the budget of its new cgroup at once. Without a limit there, it runs within 110 ms on every backend. |
| Loop without system calls | A task that makes no system call is interrupted by the engine, not by the Sentry. A static program that only jumps to itself used 0.50 CPU at `50000 100000` on `hvf`, `whpx`, Linux `systrap`, and Windows `systrap` (`amd64` and `arm64`). |
| Measuring from a container | `kubectl exec` starts a process in the cgroup of the container, and that process shares the quota. On Windows `systrap`, an exec takes seconds. Divide the change of `usage_usec` by the change of `/proc/uptime`, read in the same exec, and not by the sleep time. |
| Unlimited | `max` removes the limit. A sandbox without a finite `cpu.max` pays one atomic load for each return to guest code. |
| Not enforced | `cpu.weight` and the burst limit of Linux. |

The next table lists the measured results of the test A14 and its companions. The rows `max` and `130000 100000` run a static program with one thread and no runtime. The other rows run a busy Go loop. A Go loop has other threads, such as the runtime monitor. Its demand is 1.01 to 1.03 CPU on average.

The Sentry bills each run of a thread for its wall time. Each wake-up of the monitor thread therefore bills the time that the host needs to run it. On a loaded host that sum is large. A Go loop read 1.17 CPU on a Windows runner and 1.5 CPU on a macOS host with busy processes. A static loop reads 1.00 CPU on the same hosts, so the tests use it for every claim about one thread.

| Case | `hvf` | Linux `systrap` | Windows `systrap` and `whpx` |
| :--- | :--- | :--- | :--- |
| `50000 100000`, 5 s | 0.50 CPU | 0.50 CPU | 0.50 CPU |
| `max`, 3 s, static loop | 1.00 CPU | not measured | 1.00 CPU |
| `10000 100000`, billed time | 0.10 CPU | 0.10 CPU | 0.10 CPU |
| `10000 100000`, running time of a clock loop, as a share of the billed time | 0.86 to 0.96 | not measured | 0.89 to 0.98 |
| `130000 100000`, `nr_throttled`, static loop | 0 | not measured | 0 |
| `100000 100000`, `nr_throttled` | 14 in 3 s | 18 in 3 s | not measured |

A quota of exactly one CPU throttles a Go program, because its demand is above 1.0 CPU. Linux does the same.

The clock loop reads the clock of the guest after every 65536 turns. A gap of 2 ms or more between two readings is time in which the loop did not run. The test therefore measures running time in seconds, and not loop counts. A loop count depends on the speed of the host CPU. On an Apple CPU, a native loop that runs 10 ms and sleeps 90 ms makes 0.02 of the iterations of a loop without sleep. The ideal is 0.1. On `windows/amd64` runners, a reference loop with the same duty cycle made about half of the expected progress in two runs.
