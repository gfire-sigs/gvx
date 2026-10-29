# The `rungv` Command Line

`rungv` runs one OCI image or one Linux ELF64 binary in the foreground. Its flags and its output follow the Docker command line where the sandbox can keep the same meaning. This document is the reference for every command, every flag of `rungv run`, and every difference from Docker. The architecture of the sandbox is in [`architecture.md`](architecture.md).

## 1. Model

`rungv` has no daemon. A run starts a sandbox, runs the guest command, and removes everything when the guest exits. Every run therefore behaves like `docker run --rm`.

The writes of the guest go to a memory-backed layer on top of the read-only image layers. The only writes that outlive the run go to a bind mount, a named volume, or the image store of the host.

The host process locks itself down before the guest starts. After that point it cannot open a new host file, start a process, or create a socket. Every host resource of a run exists before the lockdown. This rule is the reason that `rungv` has no `exec`, no `logs`, and no `-d` in this stage.

## 2. Commands

Run `rungv help` to print this list.

| Command | Purpose |
| :--- | :--- |
| `run` | Run a command in an image or in an ELF binary. |
| `pull` | Download an image into the layer cache. |
| `images` | List the images of the cache. |
| `inspect` | Print the configuration of images as JSON. |
| `tag` | Give an image a second name. |
| `rmi` | Remove a name of an image, or the image. |
| `save` | Write images to a tar archive. |
| `load` | Read images from a tar archive. |
| `login` | Store the credentials of a registry. |
| `logout` | Remove the credentials of a registry. |
| `stub` | Probe the `systrap` engine of this host. |

Print the flags of a command with `rungv COMMAND --help`. The flag `-h` of `run` sets the hostname, as in Docker. Flags go before the arguments. Every flag has a single-dash form, such as `-e`, and a double-dash form, such as `--env`. A cluster of one-letter flags, such as `-it`, works for `-i`, `-t`, `-d`, and `-P`.

## 3. `rungv run`

The synopsis is `rungv run [flags] IMAGE [COMMAND [ARG...]]`. The first argument that is not a flag names the image. The arguments after it replace the `Cmd` of the image and keep its `Entrypoint`. The synopsis `rungv run [flags] -bin=ELF [ARG...]` runs a host ELF binary with the arguments as the whole command vector.

### 3.1 Docker flags

| Flag | Meaning |
| :--- | :--- |
| `-e`, `--env KEY=VALUE` | Set a variable. `KEY` alone copies it from the host and sets nothing when the host has none. |
| `--env-file FILE` | Read `KEY=VALUE` and `KEY` lines. Blank lines and lines that start with `#` are skipped. |
| `--entrypoint PROGRAM` | Replace the image entrypoint. An empty value clears it. The image `Cmd` is dropped. |
| `-u`, `--user USER[:GROUP]` | Run as a user, by name or by number. |
| `-h`, `--hostname NAME` | Set the hostname. The default is `gvx`. |
| `-w`, `--workdir DIR` | Set the working directory. |
| `--name NAME` | Set the container name. It becomes the container ID of the kernel and has no other effect. |
| `--rm` | Accepted. Every run removes its container. |
| `-i` | Accepted. The guest always reads the standard input of `rungv`. |
| `-t` | Allocate a pseudo-terminal. |
| `-p`, `--publish [IP:][HOST:]GUEST[/PROTO]` | Publish a guest port. A missing host port or the host port `0` asks for a free port. The default bind address is `127.0.0.1`. |
| `-P` | Publish every port that the image declares with `EXPOSE` to a free port of `127.0.0.1`. |
| `-v`, `--volume SRC:DST[:ro\|rw]` | Mount a host directory, one host file, or a named volume. |
| `--mount type=bind\|volume\|tmpfs,src=...,dst=...,readonly[,driver=ext4lite\|hostfs]` | Mount with the Docker key syntax. The `driver` key applies to `type=volume` only. |
| `--tmpfs PATH[:size=64m,ro]` | Mount a memory-backed directory. |
| `--read-only` | Mount the root file system of the guest read-only. |
| `-m`, `--memory SIZE` | Limit the guest memory. The units are `b`, `k`, `m`, `g`, and `t`. The minimum is 6m. |
| `--cpus N` | Limit the CPU quota. The value is a decimal number, such as `1.5`. |
| `--network NAME` | `bridge` and `nat` select the NAT mode. `none` and `wg` are the other modes. `host` is refused. |
| `--platform linux/ARCH` | Select the architecture of the image: `linux/amd64` or `linux/arm64`. |

The flag `-d` is refused with a message, because a run has no daemon.

### 3.2 gvx flags

| Flag | Meaning |
| :--- | :--- |
| `-image REF`, `-bin ELF` | Name the image or the binary without a positional argument. |
| `-platform BACKEND` | Select the execution backend: `auto`, `whpx`, `hvf`, or `systrap`. The `systrap` backend runs on Windows and Linux. macOS has no `systrap` engine. A value with a slash is a Docker image platform. |
| `-arch ARCH` | Select the guest architecture. The default is the host architecture. |
| `-workspace DIR`, `-ro` | Mount a host directory at `/workspace`, optionally read-only. |
| `-net MODE`, `-wg-conf FILE`, `-isolate-lan` | Select the network mode and its options. |
| `-registry-url URL` | Override the registry of the image reference. |
| `-cache-dir DIR` | Select the layer cache directory. |
| `-lockdown=false` | Skip the host lockdown. Use it only to debug. |

## 4. Rules of `run`

### 4.1 Command and environment

The command is the entrypoint followed by the command arguments. Each part comes from the caller, or else from the image. An override of the entrypoint drops the image `Cmd`, as in Docker. A run without any command stops with an error.

The environment starts with the `Env` of the image. Each `-e` entry and each env-file line then replaces the variable with the same name, or adds a new one. The env files are read first, and then the `-e` flags, so a `-e` flag wins. The sandbox adds `PATH`, `HOME`, and `HOSTNAME` when none sets them. It adds `TERM=xterm` for a terminal.

### 4.2 User

The user comes from `--user`, then from the `User` of the image, then it is root. The sandbox resolves a name in the `/etc/passwd` and `/etc/group` files of the image. A name that these files do not list stops the run. A number need not be listed.

A user that the passwd file does not list gets the group 0 and the home `/`, as in Docker. The user form `name` adds the supplementary groups that list the user. The form `name:group` adds none. The process of a user that is not root has no capability.

The root directory of the guest has the mode 0755, as in an image. A user that is not root cannot create a file there.

### 4.3 Hostname

The sandbox writes the hostname to `/etc/hostname`. It adds a line with the guest address to `/etc/hosts` when no line names the hostname. It also adds `host.docker.internal`, which names the host.

### 4.4 Mounts

A bind mount shows a host directory or one host file in the guest. A named volume is one image file, `<name>.ext4`, in a `volumes` directory. That directory is inside the `-cache-dir` directory, or else next to the default layer cache. The volume name matches `[a-zA-Z0-9][a-zA-Z0-9_.-]*`. The sandbox creates a missing volume image and a missing `-v` bind directory before the lockdown. The sandbox never creates a missing file. A `--mount type=bind` source must exist.

The image holds an ext4 file system that the `ext4lite` driver reads and writes. The image grows in steps of 16MiB, up to 64TiB. A clean exit returns the unused tail to the host. One sandbox at a time can use a volume, because the driver locks the image file. A second sandbox on the same volume fails at start. A read-only mount of a volume opens the image read-only and fails when the last run did not end cleanly.

The guest sees only the files that it wrote. The host sees one file. The image has a metadata journal. After a crash or a kill, the next run replays the journal. It keeps every file that the guest synced, and it frees the files that a guest unlinked and still held open. A volume of an older release gets a journal at the first run when the first 16MiB of the image has room for it, and the image never grows for that. `e2fsck -fn` accepts a clean image, and `mount -o loop -t ext4` mounts it on Linux.

A volume from an older release is a host directory in the same `volumes` directory. When that directory exists and the `.ext4` file does not, the sandbox keeps mounting the directory through `hostfs`. To use the `hostfs` driver for a new volume, write `--mount type=volume,src=NAME,dst=PATH,driver=hostfs`. The value `driver=ext4lite` is the default.

A source with no path separator that is not an absolute path names a volume. A Windows drive letter stays in the source, as in `C:\data:/data:ro`.

A bind source can be one regular file, as in `-v /host/app.conf:/etc/app.conf:ro`. A socket, a device, or a pipe is not valid. The guest sees only that file. The parent directory and the sibling files of the host file are not exposed, and the guest cannot reach them by a path. The sandbox creates the guest path as an empty regular file with the mode 0644, and it creates the missing parent directories. The option `:ro` makes the file read-only. The option `-workspace` takes a directory only.

A file mount writes no `.gvx_meta` file. The mode, the owner, and the extended attributes that the guest sets stay in memory and reset at the next start. A change of the times reaches the host file. An `unlink` or a `rename` of the mounted file in the guest returns `EBUSY`, as for a file that Docker bind-mounts. A `link` to the file returns `EXDEV`. When a host editor replaces the file with an atomic rename, the next open of the guest path reaches the new file. A descriptor that was already open keeps the old file.

On Windows, the sandbox puts the Low integrity label and an access entry for the logon session on the mounted file only. It also gives the logon session the traverse right (`FILE_TRAVERSE`) on the parent directory, with no inheritance. The restricted token has no `SeChangeNotifyPrivilege`, so the system needs that right to open the file through the parent. The right gives no listing and no creation of files. The sibling files keep their own security descriptors and stay closed. The entry stays on the parent directory after the run.

The guest path of a mount is absolute and clean. It is not `/`. It is not `/proc`, `/sys`, `/dev`, or a path below them, except a path below `/dev/shm`. Two mounts cannot share a guest path. A mount at `/workspace` conflicts with `-workspace`.

The tmpfs options are `size`, `ro`, and `rw`. The option `size` takes a number with a binary unit. Any other tmpfs option stops the run with an error that names it.

A volume with the `ext4lite` driver needs no lockdown rule for a host path. The sandbox opens the image file before the lockdown, and the guest reaches it only through that open file.

| Host OS | What the lockdown does with a mount |
| :--- | :--- |
| macOS | The Seatbelt profile gets a read rule, and a write rule for a writable mount, for the path and for its resolved path. |
| Windows | The lockdown writes a Low integrity label on each object of a writable mount. It grants the logon session read and execute access, and write access for a writable mount. |
| Linux | The seccomp filter allows opens through a directory descriptor when a bind mount or a `hostfs` volume exists. |

> [!WARNING]
> On Windows, a bind mount changes the security descriptors of the host directory, or of the host file for a file mount. Mount only a path that the guest may change.

### 4.5 Resource limits

`--memory` sets a limit on the memory use of the guest. A guard reads the memory accounting of the Sentry and kills the guest with SIGKILL when the use passes the limit. The exit code is 137, and `rungv` prints a message. The guard reads the use at short intervals, so a guest can pass the limit by the amount that it allocates between two readings.

`--cpus` sets the number of CPUs that the guest sees, rounded up. Windows also caps the CPU time of the host process with a hard cap on the containment job. The other host OSes have no such cap, and `rungv` prints a warning. On Windows with `-platform=systrap`, the guest runs in stub processes that the cap does not cover.

### 4.6 Published ports

`rungv` binds each published port before the lockdown. It prints one line for each port to the standard error before the guest starts, as in `rungv: publishing 127.0.0.1:49493 -> 8080/tcp`. The line shows the free port that the host chose. A published port needs the NAT network mode.

### 4.7 Failures and diagnostics

`-platform=auto` prefers the hardware hypervisor and falls back to `systrap`. The fallback is slower. `rungv` then prints a warning that names the cause and the fix. On Windows the usual cause is a disabled "Windows Hypervisor Platform" feature. On macOS it is a binary without the hypervisor entitlement. Sign it with `codesign --sign - --entitlements entitlements.plist --force rungv`. The SDK gives the same text through `Sandbox.FallbackReason`.

The exit code 137 has two causes that `rungv` tells apart. A guest that passes `--memory` gets the message about the memory limit. When the engine fails under the guest, the kernel ends the guest with SIGKILL, and `rungv` prints `the execution engine stopped the guest` with the cause. The SDK returns `ErrEngineFault` in that case. A stub process that a virus scanner ended is one example of an engine fault.

`GVX_DEBUG_LOG=1` prints the log of the kernel to the standard error of `rungv`, and the value `2` also prints debug lines. Use it when a guest fails and no message names the cause. `GVX_STRACE=1` also prints each system call of the guest.

## 5. Images and registries

An image reference follows the Docker rules. The first path component is a registry host when it contains a dot or a colon, or when it is `localhost`. Any other name belongs to Docker Hub, and a name with one component gets the prefix `library/`. A reference without a tag and without a digest means the tag `latest`. A digest form is `NAME@sha256:HEX`. An uppercase repository name is invalid.

A registry host uses `https`, except `localhost`, the `127.0.0.0/8` range, and `[::1]`, which use `http`. The flag `-registry-url` overrides the registry. The reference then supplies only the repository, the tag, and the digest.

The credentials come from the Docker configuration file. The directory is `DOCKER_CONFIG`, or else `.docker` in the home directory. The lookup order is `credHelpers`, then `credsStore`, then `auths`.

A credential helper is the program `docker-credential-NAME`. It has 30 seconds and 1 MiB of output. A missing helper means no credentials. `rungv` sends credentials only to the registry and to its token service.

`rungv login` verifies the credentials against the registry before it stores them. It stores them with the helper, or else in `auths` as base64. It keeps every other field of the file. `rungv logout` removes them.

## 6. The image store

The layer cache is the image store. It holds the compiled EROFS layers, one record for each image, and one record for each name. The default directory is `%LOCALAPPDATA%\gvx\cache\layers` on Windows and `~/Library/Caches/gvx/layers` on macOS.

`rungv images` lists names and tags. The IMAGE ID is the first 12 digits of the config digest, as in Docker. The SIZE column is the size of the EROFS layer files on disk. The flags are `-a`, `-q`, `--no-trunc`, `--digests`, and `--format json`.

`rungv rmi` removes a name. When no name or digest keeps the image, it removes the image record and the layer files that no other image uses. An ID that has several names needs `-f`.

`rungv save` writes a tar archive that is an OCI image layout and also has the Docker file `manifest.json` with `RepoTags`. The cache holds compiled layers and not the original blobs. The command therefore fetches each original layer from the registry and verifies its digest. It fails for an image that came from an archive. It writes a temporary file first, so a failure leaves no partial archive.

`rungv load` reads such an archive, an OCI layout, or the output of `docker save`. It registers the names of the archive. It skips the images of other architectures.

## 7. Differences from Docker

| Docker | `rungv` |
| :--- | :--- |
| `-d`, `ps`, `exec`, `logs`, `stop`, `rm`, `restart` | Not available. A run is in the foreground and has no state. |
| `docker build`, `compose`, `network`, `volume` | Not available. Remove a named volume by deleting its image file, `<name>.ext4`. |
| Image `VOLUME`, `HEALTHCHECK`, `STOPSIGNAL`, labels | Ignored. |
| `--network host` | Refused. The guest has its own network stack. |
| A port range in `-p` | Refused. |
| `--name` | Sets the container ID of the kernel and nothing else. |
| `docker save` of any image | The command needs the registry that the image came from. |
| Cgroup limits | `--memory` is a guard with a delay. `--cpus` caps the CPU time on Windows only. |
| Guest architecture | Must equal the host architecture, except with `-platform=systrap`. |
| Executables that link at a fixed address (non-PIE) | `hvf`, `whpx`, and the Windows `systrap` engine run them natively. The removed macOS `systrap` engine could not run them, because every `arm64` task on macOS has a 4GB `PAGEZERO`. |
| A store into the page of the storing instruction | A `systrap` engine gives a page write access or execute access, never both. The Sentry runs a store from a writable and executable page into the same page. It writes both copies of the page. The Sentry decodes the single and pair stores of general and vector registers. Exclusive and atomic stores, a store across the page edge, and a store over an instruction that the patcher changed end with SIGSEGV. The Sentry log names the instruction. |
| Writes to the root file system | Lost at exit. Use a mount for data that must stay. |

## 8. Examples

Run a command in an image, as a user, with an environment variable and a bind mount:

```sh
rungv run -u 1000 -e MODE=test -v "$PWD":/src:ro -w /src alpine:3.20 sh -c 'ls; id'
```

Publish the exposed port of an image to a free host port:

```sh
rungv run -P nginx:alpine
```

Limit the memory and keep the data in a named volume:

```sh
rungv run -m 512m -v data:/var/lib/app myimage:1.0
```

Move an image to another host:

```sh
rungv save -o alpine.tar alpine:3.20
rungv load -i alpine.tar
```

## 9. `rungv license`

`rungv license` prints the license notices of the binary. The binary embeds the notice file `cmd/rungv/licenses/THIRD_PARTY_LICENSES.txt`, and the command prints that file. The file covers the Go standard library, the gVisor code, and each third-party module that the binary links.

The synopsis is `rungv license [-list]`. The command takes no other argument.

| Flag | Meaning |
| :--- | :--- |
| none | Print the whole notice file. Each license text appears once, followed by the components that use it. |
| `-list` | Print one line per component: the name, the version, and the SPDX identifier. |

The command exits with 0 on success and with 2 when an argument is unexpected. The notice file is regenerated with `go run ./tools/licenses`. The command `go run ./tools/licenses -check` fails when the file or the README table is stale.
