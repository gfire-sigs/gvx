# OCI Image Compiler, Registry Client, and Host CA Injector: `pkg/oci` and `pkg/gvx/hostcerts`

This specification describes `pkg/oci` and `pkg/gvx/hostcerts`. `pkg/oci` resolves, pulls, pushes, saves, loads, caches, and compiles multi-arch OCI images into EROFS files in memory. `pkg/gvx/hostcerts` collects host root CAs before lockdown.

---

## 1. Purpose and Scope

Extracting Linux container `.tar` layers onto Windows NTFS or case-insensitive APFS breaks case-sensitive filenames (`Makefile` vs. `makefile`) and Windows reserved names (`CON`, `AUX`, `NUL`). Unpacking onto host filesystems also discards POSIX ownership bits and requires elevation for special device nodes.

`pkg/oci` bypasses host filesystem extraction by streaming compressed layers into cached read-only 4 KiB EROFS images. `gvx` opens those EROFS files as read-only descriptors before `hostlockdown.Apply()` seals the process.

The diagram and sections below detail reference parsing, Tar-to-EROFS compilation, blob caching, host CA injection, and component limits.

---

## 2. Design and Invariants

![OCI Tar-to-EROFS Layer Compilation Pipeline](../assets/oci-erofs.svg)

### 2.1 Reference Grammar, Registry Transport, and Credentials

`oci.ParseReference` implements Docker image grammar, resolving registry host, `library/` defaults, `latest` tags, and `@sha256:` digests while rejecting uppercase repositories. Registries default to HTTPS except `localhost`, `127.0.0.0/8`, and `[::1]`, which allow HTTP.

Credentials load from `$DOCKER_CONFIG/config.json` in order: `credHelpers`, `credsStore`, then `auths` (helper timeout `30 s`, output cap `1 MiB`). `rungvx login` verifies credentials before saving them. `LayerCache.SetDNSServers` routes registry queries through `--host-dns` servers without modifying process-wide Go DNS settings.

### 2.2 In-Memory Tar-to-EROFS Compilation

For every resolved manifest matching the target architecture (`linux/amd64` or `linux/arm64`), `pkg/oci` executes these steps before host lockdown:

1. Verify the manifest digest and compressed blob SHA-256 digests (rejecting Docker manifest schema 1).
2. Parse `Entrypoint`, `Cmd`, `Env`, `WorkingDir`, `User`, and `ExposedPorts` from image config JSON.
3. Stream `.tar`, `.tar.gz`, or `.tar.zst` layers through `tar2erofs.go` without extracting onto host disks.
4. Deduplicate 4 KiB blocks with `InodeDataLayoutChunkBased`, and inline short symlinks and tails with `InodeDataLayoutFlatInline`.
5. Convert `.wh.<name>` and `.wh..wh..opq` whiteouts into `0:0` character nodes and `trusted.overlay.opaque` xattrs.
6. Write `<sha256>.gvx-erofs-v3-b4096.erofs` and `.sum` sidecars to the platform cache (`%LOCALAPPDATA%\gvx\cache\layers`, `~/Library/Caches/gvx/layers`, `~/.cache/gvx/layers`).
7. Enforce all `oci.*` ceilings from `pkg/gvx/tuning` (`max_json_bytes`, `max_blob_bytes`, `max_layer_bytes`, `max_zstd_window_bytes`, `registry_idle_timeout`).

At runtime, `pkg/gvx` opens read-only `HostHandle` descriptors for all lower `.erofs` layers before lockdown. It mounts them under `fsimpl/overlay` beneath either an ephemeral `tmpfs` upper layer or a persistent `ext4lite` `-rootfs-volume`.

### 2.3 Cache Operations, Blob Retention, Push, Save, and Load

- **Pull policies**: `missing` (default), `always` (falling back to cache on unreachable registry or HTTP 401/403/404 for locally loaded images), and `never` (strictly offline).
- **Blob retention (`-keep-blobs` / `GVX_KEEP_BLOBS=1`)**: Retains compressed blobs under `blobs/sha256/<hex>` so `rungvx save` and `rungvx push` run offline.
- **OCI Distribution v1.1 push (`push.go`)**: Probes existing blobs via `HEAD`, attempts cross-repository mounts, and uploads exact manifest bytes.
- **Archives (`save.go`, `load.go`)**: Read and write dual OCI-layout and `docker save` tar archives.

### 2.4 Host Root CA Injection (`pkg/gvx/hostcerts`)

With `--host-ca-certs` (`Config.HostCACerts`), `hostcerts` gathers trusted X.509 roots prior to `hostlockdown.Apply()`. Sources cover Windows `ROOT`, macOS Keychains (`System.keychain`, `SystemRootCertificates.keychain`, `login.keychain-db`, honoring denials), Linux `/etc/ssl/certs` and `/etc/pki/tls/certs`, plus `SSL_CERT_FILE` and `SSL_CERT_DIR`. Missing roots append to existing guest PEM bundles in the writable upper layer and write `/usr/local/share/ca-certificates` or `/etc/pki/ca-trust/source/anchors` files.

---

## 3. Component Limits

Consult [`../compatibility.md`](../compatibility.md) for host-wide limits; the invariants below apply specifically to `pkg/oci` and `hostcerts`:

- **Docker manifest schema 1**: Rejected with an error (matching Docker 28+).
- **Offline `save` / `push` without `-keep-blobs`**: Requires registry network access unless original compressed blobs were retained when pulling or loading.
- **Ignored image directives**: `VOLUME`, `HEALTHCHECK`, `STOPSIGNAL`, and image labels are ignored by `rungvx run`.
- **Nested container CA roots**: `--host-ca-certs` modifies the direct guest rootfs only; nested `dockerd` containers require mounting `/etc/ssl/certs/ca-certificates.crt` explicitly.

---

## 4. Implementation Map

This table maps the OCI compiler, cache, and host certificate package files.

| Files | Role |
| :--- | :--- |
| `pkg/oci/reference.go`, `registry.go`, `credentials.go`, `resolver.go`, `pull.go`, `push.go` | Reference parser, OCI Distribution v1.1 client, Docker credential helpers, pull/push. |
| `pkg/oci/tar2erofs.go`, `erofs_layout.go`, `compress.go`, `limits.go` | Streaming Tar-to-EROFS compiler, 4 KiB deduplication, whiteouts, decompression caps. |
| `pkg/oci/cache.go`, `store.go`, `blobs.go`, `archive.go`, `save.go`, `load.go`, `prune.go` | Layer cache index, blob store, OCI/Docker tar save and load, pruning. |
| `pkg/gvx/hostcerts/` & `pkg/gvx/hostcacerts.go` | Cross-platform trust-store reader and upper-layer PEM injector. |
| Tests | `pkg/oci/*_test.go`, `pkg/gvx/hostcerts/*_test.go`, `e2e/gate_m3_test.go`, `e2e/hostcacerts_e2e_test.go`. |
