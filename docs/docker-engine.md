# Use `gvx` as a Docker Engine

This guide shows how to run a Docker Engine inside a `gvx` sandbox and control it with the `docker` command of the host. The engine keeps its images and containers in an `ext4lite` volume, so they stay after a restart. The `docker` command reaches the engine through a Docker context. The flag reference is in [`cli.md`](cli.md).

## 1. How It Works (Descriptive Module)

`rungv` runs the unmodified `docker:dind` image. Its entrypoint starts `dockerd` inside the sandbox. The guest kernel gives `dockerd` what it needs: `iptables` with the `addrtype` match, the `bridge` network, network namespaces, `pivot_root`, cgroup v2, and overlay mounts. The table below lists the parts of the setup.

| Part | What it does |
| :--- | :--- |
| `--privileged` | On by default. It turns on raw sockets, packet writes, and set-user-ID programs. These privileges stay inside the sandbox. |
| `-v gvx-docker:/var/lib/docker` | Stores the data of `dockerd` in the `ext4lite` image `gvx-docker.ext4`. The overlay storage driver of `dockerd` works on it. |
| `-p unix:~/.gvx/docker.sock:2375` | Binds a Unix socket on the host and forwards it to the API port 2375 of `dockerd`. Only your user can open the socket. |
| `-p 127.0.0.1:9000-9019:9000-9019` | Publishes a range of host ports. A container that `docker run -p 9000:80` publishes in the guest is then reachable at `127.0.0.1:9000` on the host. |
| `-e DOCKER_TLS_CERTDIR=` | Makes the entrypoint listen on TCP port 2375 without TLS. The port is reachable only through the forwards above. |
| `--tls=false` | Tells `dockerd` that the missing TLS is intended. Without it, `dockerd` waits 15 seconds before it starts. |
| Docker context `gvx` | Points the `docker` command of the host at the Unix socket. |

The sandbox locks itself down before the guest starts. The guest therefore cannot publish a new host port later. Publish every host port that your containers will use when you start the engine.

## 2. Start the Engine (Procedural Module)

These steps start the engine and connect the `docker` command of the host to it. You need `rungv` (see the [README](../README.md#3-quickstart)) and a `docker` command on the host. The `docker` command needs no local engine. The steps work on macOS and Windows. On Windows, use PowerShell, create the directory with `mkdir $HOME\.gvx -Force`, and create the context with `docker context create gvx --docker "host=unix://$($HOME -replace '\\','/')/.gvx/docker.sock"`. A `unix://` host on Windows needs Docker CLI 29 or later. With an older CLI, publish `-p 127.0.0.1:2375:2375` and use `host=tcp://127.0.0.1:2375`.

> [!IMPORTANT]
> Use host ports that no other program uses. `rungv` stops with `address already in use` when one port of a range is busy.

1. Create the directory of the socket.

   ```sh
   mkdir -p ~/.gvx
   ```

2. Start the engine in a terminal. It runs in the foreground.

   ```sh
   rungv run \
     -p unix:~/.gvx/docker.sock:2375 \
     -p 127.0.0.1:9000-9019:9000-9019 \
     -v gvx-docker:/var/lib/docker \
     -e DOCKER_TLS_CERTDIR= \
     docker:dind --tls=false
   ```

3. Wait for the line `API listen on /var/run/docker.sock`.

4. Create the Docker context in a second terminal. Do this one time.

   ```sh
   docker context create gvx --docker host=unix://$HOME/.gvx/docker.sock
   ```

5. Select the context.

   ```sh
   docker context use gvx
   ```

6. Verify the connection.

   ```sh
   docker info --format '{{.Driver}} {{.OperatingSystem}}'
   ```

   The output is `overlayfs Alpine Linux ... (containerized)`.

## 3. Use the Engine (Procedural Module)

These commands work as with a local Docker Engine. Each `docker` command runs on the host and talks to `dockerd` in the sandbox.

1. Run a container on the default `bridge` network.

   ```sh
   docker run --rm alpine wget -qO- http://example.com
   ```

2. Publish a container port inside the published range.

   ```sh
   docker run -d --name web -p 9000:80 nginx:alpine
   curl http://127.0.0.1:9000/
   ```

3. Open a shell in the running container.

   ```sh
   docker exec -it web sh
   ```

4. Build an image from a directory of the host. The `docker` command sends the build context to the engine.

   ```sh
   docker build -t app ./app
   ```

5. Start a Compose project. Use host ports inside the published range.

   ```sh
   docker compose up -d
   ```

## 4. Stop and Restart the Engine (Procedural Module)

These steps stop the engine and start it again with the same data.

1. Press Ctrl-C in the terminal of `rungv`.

2. Start the engine again with the command of step 2 in section 2. The images, the volumes, and the stopped containers are still there.

3. Select the default engine of the host when you no longer need `gvx`.

   ```sh
   docker context use default
   ```

## 5. Share Host Directories (Procedural Module)

A path in `docker run -v` names a path in the sandbox, not on the host. Mount a host directory into the sandbox first, and then mount its sandbox path into the container.

1. Add a bind mount to the `rungv run` command of section 2.

   ```sh
   -v ~/src:/src
   ```

2. Use the sandbox path in the container.

   ```sh
   docker run --rm -v /src/data:/data alpine ls /data
   ```

## 6. Trust a TLS-Inspecting Proxy (Procedural Module)

A host behind a proxy that inspects TLS, or a host with a private registry, trusts a root certificate that the images do not hold. Add `--host-ca-certs` to the `rungv run` command of section 2. `dockerd` then trusts the roots of the host, and `docker pull` and `docker build` can reach the registries through the proxy. [`cli.md`](cli.md#410-host-root-certificates) lists the sources of the roots.

> [!IMPORTANT]
> Only the `dockerd` process and the other sandbox processes trust the roots. A container that `dockerd` starts has its own file system and does not trust them.

1. Add the flag to the `rungv run` command of section 2.

   ```sh
   --host-ca-certs
   ```

2. Give a container the bundle of the sandbox. The path in `-v` names a path in the sandbox, as in section 5.

   ```sh
   docker run --rm -v /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro alpine wget -qO- https://example.com/
   ```

3. Give a build the root. Put the PEM file of the root, here `host-ca.crt`, next to the `Dockerfile`.

   ```dockerfile
   FROM alpine:3.20
   COPY host-ca.crt /tmp/host-ca.crt
   RUN cat /tmp/host-ca.crt >> /etc/ssl/certs/ca-certificates.crt && rm /tmp/host-ca.crt
   ```

4. Build the image. The build steps after the `RUN` line trust the root.

   ```sh
   docker build -t app .
   ```

A private registry needs no step 2 or 3 when only `dockerd` pulls from it. Use `docker pull REGISTRY/IMAGE`.

## 7. Reference

### 7.1 Storage Choices

The data of `dockerd` can stay in three places. The overlay storage driver works on each of them. The times are single runs on an Apple M1 with `hvf`.

| Storage | `rungv` flag | Kept after a restart | `docker pull nginx:alpine` |
| :--- | :--- | :--- | ---: |
| `ext4lite` volume | `-v gvx-docker:/var/lib/docker` | Yes | 9 s |
| `ext4lite` image at a path | `--mount type=volume,src=/disk/gvx-docker.ext4,dst=/var/lib/docker` | Yes | 9 s |
| Host directory (`hostfs`) | `-v /disk/gvx-docker:/var/lib/docker` | Yes, as host files | 32 to 54 s |
| Memory | `--tmpfs /var/lib/docker:size=6g` | No | 5 s |

Use the `ext4lite` volume unless you need the files as host files. The volume image grows as `dockerd` writes, and a clean exit returns the unused tail to the host. Delete `gvx-docker.ext4` in the `volumes` directory next to the layer cache to remove all data of the engine.

### 7.2 Known Limits

| Limit | Effect |
| :--- | :--- |
| Published host ports | Fixed at the start. A container port outside the published range is reachable only inside the sandbox. |
| Guest architecture | The engine runs images for the host architecture. On Apple Silicon, it runs `linux/arm64` images. |
| `10.0.2.15` from a container | A `bridge` container cannot connect to the `eth0` address of the sandbox. Use the container address or a user-defined network. |
| `docker stats` | Shows the memory, the CPU time, and the network counters of a container. The memory is `memory.current`, which counts page cache and mapped pages too. A container that wrote 64 MiB showed 64 MiB on `hvf` and 101 MiB on Linux systrap. `BLOCK I/O` stays at `0B / 0B`, because the guest has no `io` controller. |
| `docker run -m` | The Sentry polls the memory use of each limited container and ends the process with the highest score when the use passes the limit. Section 7.4 gives the details. |
| `docker run --cpus` | `--cpus` becomes `cpu.max`, and the Sentry enforces it. Section 7.5 gives the details. |
| `--memory-reservation`, `--memory-swap`, `--cpu-shares` | Accepted and stored. The engine does not enforce them. `docker run` prints a warning about the missing swap limit. |

### 7.3 Security

The privileges of `--privileged` stay inside the sandbox. A container with `docker run --privileged` gets them only inside the sandbox too. A raw packet reaches only the network stack of the sandbox. The NAT forwarder relays only TCP and UDP connections, through host sockets. The API socket on the host has the mode `0600`, so only your user can open it. Any program of your user can therefore control the engine, as with a local Docker Engine.

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
| Windows `systrap` | The enforcer stays off. The engine runs guest code in stub processes, and the Sentry counts a page through the working set of its own process, so a page that only a stub wrote can stay uncounted. `memory.stat` and `memory.current` can show too little. `memory.max` is stored and not enforced. |
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

The next table lists the measured results of the test A14 and its companions. Each row is one busy Go loop. The loop has other threads, such as the runtime monitor, so its demand is 1.01 to 1.03 CPU on average. On a Windows host, the wake-ups of those threads cost up to 1.5 CPU in one period.

| Case | `hvf` | Linux `systrap` | Windows `systrap` and `whpx` |
| :--- | :--- | :--- | :--- |
| `50000 100000`, 5 s | 0.50 CPU | 0.50 CPU | 0.50 CPU |
| `max`, 3 s | 1.01 CPU | 1.00 to 1.03 CPU | 1.00 to 1.01 CPU |
| `10000 100000`, billed time | 0.10 CPU | 0.10 CPU | 0.10 CPU |
| `10000 100000`, progress of the loop | 0.03 to 0.08 of full speed | 0.09 to 0.10 of full speed | 0.09 to 0.10 of full speed |
| `200000 100000`, `nr_throttled` | 0 | 0 | 0 |
| `100000 100000`, `nr_throttled` | 14 in 3 s | 18 in 3 s | not measured |

A quota of exactly one CPU throttles a Go program, because its demand is above 1.0 CPU. Linux does the same. On `hvf`, resuming a throttled task costs several milliseconds inside the platform. A loop at a tenth of a CPU therefore keeps 0.03 to 0.08 of its speed.
