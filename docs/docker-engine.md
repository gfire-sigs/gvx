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

## 6. Reference

### 6.1 Storage Choices

The data of `dockerd` can stay in three places. The overlay storage driver works on each of them. The times are single runs on an Apple M1 with `hvf`.

| Storage | `rungv` flag | Kept after a restart | `docker pull nginx:alpine` |
| :--- | :--- | :--- | ---: |
| `ext4lite` volume | `-v gvx-docker:/var/lib/docker` | Yes | 9 s |
| `ext4lite` image at a path | `--mount type=volume,src=/disk/gvx-docker.ext4,dst=/var/lib/docker` | Yes | 9 s |
| Host directory (`hostfs`) | `-v /disk/gvx-docker:/var/lib/docker` | Yes, as host files | 32 to 54 s |
| Memory | `--tmpfs /var/lib/docker:size=6g` | No | 5 s |

Use the `ext4lite` volume unless you need the files as host files. The volume image grows as `dockerd` writes, and a clean exit returns the unused tail to the host. Delete `gvx-docker.ext4` in the `volumes` directory next to the layer cache to remove all data of the engine.

### 6.2 Known Limits

| Limit | Effect |
| :--- | :--- |
| Published host ports | Fixed at the start. A container port outside the published range is reachable only inside the sandbox. |
| Guest architecture | The engine runs images for the host architecture. On Apple Silicon, it runs `linux/arm64` images. |
| `10.0.2.15` from a container | A `bridge` container cannot connect to the `eth0` address of the sandbox. Use the container address or a user-defined network. |
| `docker stats` | Shows the memory, the CPU time, and the network counters of a container. `BLOCK I/O` stays at `0B / 0B`, because the guest has no `io` controller. |
| `docker run -m` | The Sentry polls the memory use of each limited container and ends the process with the largest resident set when the use passes the limit. Section 6.4 gives the details. |
| `--memory-reservation`, `--memory-swap`, `--cpus`, `--cpu-shares` | Accepted and stored. The engine does not enforce them. `docker run` prints a warning about the missing swap limit. |
| `--icc=false` | `dockerd` starts with it, but the bridge does not pass frames through `iptables`. Two containers of one bridge can still reach each other. |

### 6.3 Security

The privileges of `--privileged` stay inside the sandbox. A container with `docker run --privileged` gets them only inside the sandbox too. A raw packet reaches only the network stack of the sandbox. The NAT forwarder relays only TCP and UDP connections, through host sockets. The API socket on the host has the mode `0600`, so only your user can open it. Any program of your user can therefore control the engine, as with a local Docker Engine.

### 6.4 Memory Limits of Containers

A container with `docker run -m SIZE` gets `memory.max` in its cgroup. The Sentry cannot count a page at the moment of its allocation. It counts a page after a scan of the memory file, so it polls. The poll starts with the first finite limit and ends when no cgroup has a limit.

| Property | Value |
| :--- | :--- |
| Poll interval | At least 5 ms, and at least 4 times the duration of the last check. |
| Overshoot | A container can pass its limit by what it allocates between two checks. At 1 GB/s of fresh writes, 5 ms is about 5 MB. |
| Victim | The process with the largest resident set. With `memory.oom.group` set, every process of the container. |
| Result | Exit code 137, `OOMKilled: true` in `docker inspect`, and `oom_kill` in `memory.events`. Other containers and `dockerd` keep running. |
| Not caught | A process that allocates and frees more than the limit between two checks. A one-shot `dd if=/dev/zero bs=128M count=1` is an example: its buffer lives about 30 ms. On macOS, a test that held 128 MiB for 30 ms showed only 2 MiB in `memory.current` in 4 of 6 runs, so the scan of the memory file missed most of the pages. Linux counts each page at its first write and kills such a process. A process that holds its memory for longer than 100 ms is found. Memory that a process maps but never writes is not charged, as on Linux. |
| Held after the kill | Data in `tmpfs` files stays charged to the container. A new process in that container is ended at the next check while the data still counts. |
| Not enforced | `memory.high`, `cpu.max`, `cpu.weight`, and `memory.swap.*`. |
