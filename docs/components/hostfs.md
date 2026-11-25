# Pinned Host Filesystem Driver: `hostfs`

This specification describes `pkg/sentry/fsimpl/hostfs`, the in-process VFS2 driver that mounts host directories and single regular files (`-workspace`, `-v HOST:GUEST`, `--mount type=bind`) without spawning an external `gofer` file server.

---

## 1. Purpose and Scope

Upstream gVisor shares host directories through an out-of-process 9P/`lisafs` file server (`gofer`). Because `gvx` runs inside a single self-locked host process across Windows, macOS, Linux, and Android, `hostfs` accesses mounted host trees directly through handles pinned prior to `hostlockdown.Apply()`. It prevents symbolic-link escape outside the mounted root, preserves POSIX permissions, ownership, symlinks, special files, and extended attributes on Windows NTFS and macOS APFS, and delivers host edits to guest `inotify` watchers.

---

## 2. Design and Invariants

`hostfs` enforces host boundary confinement through pinned handles, name encoding, an identity-keyed metadata journal, and a bounded host event bridge.

### 2.1 Pinned Handle Traversal and Caching

Before lockdown, `OpenWorkspace` anchors each host directory via `os.OpenRoot`. Subsequent lookups, mutations, and listings operate strictly on one path component relative to a pinned parent directory handle (rejecting embedded separators):

- **Windows**: `NtCreateFile` with `OBJECT_ATTRIBUTES.RootDirectory`, `FILE_OPEN_REPARSE_POINT`, and full sharing (`FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`). Open-file `rename` uses `FileRenameInformationEx` (`FILE_RENAME_POSIX_SEMANTICS`); `unlink` uses `FileDispositionInfoEx`. Because NTFS refuses to rename a directory containing open descendants, `winHandleRegistry` flushes mapped pages, acquires handle locks in path order, closes descendants, renames the directory, reopens handles, and verifies host file identity (rolling back on failure).
- **macOS**: `openat` with `O_NOFOLLOW | O_SYMLINK`, native `renameat` and `unlinkat`.
- **Linux and Android**: `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`, falling back to single-component `O_NOFOLLOW` `openat` on `ENOSYS` or Android.

Each `Workspace` caches up to 256 pinned directory handles (retiring idle handles after 5 seconds) and closes subtree handles before directory rename or removal. Positive and negative lookup entries remain valid for 1 second without a host call; guest mutations invalidate affected entries immediately, and pinned directory handles revalidate their parent `lstat` after 1 second to detect host directory swaps.

### 2.2 Mapped Files (`chunkcache`), Name Translation, and Clutter Filtering

Guest `mmap` reads files in 64 KiB chunks via `pkg/sentry/fsimpl/chunkcache`. On macOS hardware virtualization, chunks reside on the Go heap; on Linux and Windows `systrap`, `pkg/gvx` binds the kernel memory file (`Workspace.SetChunkMemory`) so stub processes can map chunks cleanly (skipping ranges that cross 1 GiB slice boundaries). `ConfigureMMap` reserves the backing host handle against concurrent `munmap` races (`AddMapping` re-attaches it if dropped). `pread` flushes only dirty overlapping chunks.

`OpenWorkspace` probes host volume capabilities (`WorkspaceCaps`) before lockdown:

- **Name translation (`NameCodec`)**: Identity on Linux (zero allocation). On Windows and case-folding volumes, ordinary names stay untouched while reserved names (`CON`, `AUX`, `NUL`), illegal characters, and case collisions encode under a stateless `~gvx~` prefix with `%XX` hex escapes. On APFS, lookups fall back to NFC and listings normalize NFD unless `.gvx_meta` records a guest-created NFD name.
- **Host clutter**: Hides `.DS_Store`, `._*`, `Thumbs.db`, `.gvx_meta*`, and internal `~gvx~tmp.*`/`~gvx~swap.*` files. `rmdir` sweeps verified clutter from otherwise empty directories; `OpenWorkspace` removes stale internal temporaries.

### 2.3 Single-File Bind Mounts

`OpenWorkspace` also accepts a single regular file (rejecting sockets, devices, and pipes). It pins the parent directory, records the leaf name, and exposes only that file as the mount root without writing `.gvx_meta`. Mode, ownership, and xattr updates stay in memory while timestamp changes reach the host file. On Windows, unrecorded files default to mode `0755` (`0555` read-only) so mounted scripts execute cleanly. Atomic host renames become visible to fresh opens on macOS and Windows (`winMountBroker`), whereas Linux Landlock pins the original inode descriptor.

### 2.4 Host Event Bridge (`inotify`) and Watch Caps

When a guest attaches an `inotify` watch to a `hostfs` dentry, `AdmitInotifyWatch` installs a lockdown-safe host watcher: 200 ms pinned polling via `fstatat`/`getdents64` on Linux, `kqueue` `EVFILT_VNODE` on macOS (up to 4,096 registrations plus poll fallback), and overlapped `ReadDirectoryChangesW` on Windows. Diffing pairs same-inode vanished and new names into `IN_MOVED_FROM`/`IN_MOVED_TO`, suppresses guest-originated echoes via generation counters, and evicts clean page-cache chunks before delivering events. Poll loops throttle to `max(200 ms, 3 * passDuration)` to cap CPU use below one quarter of a core.

All workspaces in one host process draw from a shared watch budget (`processWatches`) computed before lockdown:

| Host | Cost per Watched Object | Process Watch Cap |
| :--- | :--- | :--- |
| Linux | One pinned directory descriptor | `soft RLIMIT_NOFILE - 1,024`, clamped to `[2,048, 65,536]` |
| macOS | One directory descriptor (plus up to 4,096 `kqueue` FDs) | `soft RLIMIT_NOFILE - 5,120`, clamped to `[2,048, 65,536]` (5,120 at default 10,240) |
| Windows | One directory handle and one 4 KiB buffer | `32,768` objects (at most 128 MiB of buffers) |

Exceeding the budget returns `ENOSPC` to `inotify_add_watch(2)`.

### 2.5 Identity-Keyed `.gvx_meta` Journal and Multi-Sandbox Locking

`.gvx_meta` (format v4, magic `GVXMETA`) is a CRC-32C-framed append-only binary journal persisting virtual modes, `uid`/`gid`, guest symlinks, special nodes, and xattrs. Records key on stable host file identity rather than path (`FILE_ID_INFO` + volume serial on Windows; device + inode + `statx` birth time on Linux; APFS device + inode on macOS without birth time, because `utimensat` lowers APFS birth times). Hard links share one record; atomic editor temp-file renames adopt the orphaned record (dropping SUID/SGID) via directory-identity + leaf hints. Volumes failing the 64-round `StableIDs` probe fall back to path keys.

Flushes batch after 250 ms (or immediately on `fsync`/`O_SYNC`), compact via atomic temp-file rename when torn, over 64 MiB, or exceeding `2 * live + 1,024` operations, and cap table memory at 512 MiB (roughly 1,100,000 records, returning `ENOSPC` above). A background collector sweeps deleted files after two confirming passes. Multiple concurrent sandboxes sharing one host directory coordinate reads and flushes through `.gvx_meta.lock` opened before lockdown.

### 2.6 Special Files, Extended Attributes, and Overlay Support

Sockets, FIFOs, and device nodes create empty host placeholders with `.gvx_meta` type records; bound socket endpoints and pipes live in Sentry memory (socket inodes never evict from the dentry cache). On Linux, `user.*` xattrs live on host files while `trusted.*`, `security.*`, and all macOS/Windows xattrs live in `.gvx_meta` (capped at 4 KiB per inode; single values <= 64 KiB). Both `hostfs` and `ext4lite` serve as overlayfs upper and lower layers (whiteouts stored as `0:0` placeholders plus `trusted.overlay.opaque`). `fallocate` supports mode `0`, `KEEP_SIZE`, and `PUNCH_HOLE` (using `FSCTL_SET_ZERO_DATA` on NTFS with automatic zero-fill fallback when `$ATTRIBUTE_LIST` fills).

---

## 3. Known Limits

- **Slower than `ext4lite` for metadata-heavy workloads**: Individual host syscalls cost more than single-file block I/O (`docker pull nginx:alpine` took 32 to 54 s on `hostfs` vs. 9 s on `ext4lite` on Apple M1).
- **Non-aligned nested mounts**: Mounting a host subdirectory at an unshadowed guest path (`-v $PWD:/app -v $PWD/logs:/var/log/app`) creates two separate `.gvx_meta` tables; aligned mounts (`-v $PWD/node_modules:/app/node_modules`) avoid overlap.
- **Host-held open descendants on Windows**: An external Windows process holding a descendant open still blocks guest directory rename with `EACCES`.
- **Android hard links**: Android SELinux denies `linkat` on app-data files (`EACCES`); use `ext4lite` volumes for workloads needing hard links on Android.
- **Single-file mounts on Linux under Landlock**: Landlock binds the original inode descriptor, so host atomic rename replacement requires a directory mount or `-lockdown=false`.
- **Single-file metadata volatility**: Single-file mounts write no `.gvx_meta`; mode, owner, and xattr edits reset on next run.

---

## 4. Implementation Map

| Files in `pkg/sentry/fsimpl/hostfs/` | Role |
| :--- | :--- |
| `hostfs.go`, `workspace_*.go`, `vfs*.go`, `dirpin.go`, `handle_open.go`, `handle_registry.go` | VFS2 filesystem, pinned directory handle cache, lookup cache, Windows open-handle rename registry. |
| `inode_*.go`, `openat_*.go`, `openfd_*.go`, `posix_rename_windows.go`, `rename_flags*.go`, `allocate*.go`, `punch_windows.go` | OS-specific handle-scoped open, rename (`RENAME_EXCHANGE`, `RENAME_WHITEOUT`), `fallocate`, hole punch. |
| `codec.go`, `clutter.go`, `names.go`, `caps*.go`, `single_file*.go` | Volume probing, `~gvx~` name codec, clutter hiding, single-file bind mount mode. |
| `meta_*.go`, `metastore*.go`, `durability.go`, `orphans.go`, `unlinked.go` | Format v4 identity-keyed `.gvx_meta` journal, legacy v3/JSON upgrade, multi-sandbox locking, collector. |
| `watcher*.go`, `watchlimit*.go`, `special_node.go`, `xattr*.go`, `regular_file.go`, `save_restore.go` | Lockdown-safe `inotify` host bridge, process watch budget, special nodes, xattrs, `chunkcache` `mmap`, checkpointing. |
| Tests | `pkg/sentry/fsimpl/hostfs/*_test.go`, `e2e/gate_m4_test.go`, `e2e/filemount_e2e_test.go`, `e2e/mounts_e2e_test.go`, and `scripts/pjdfstest`. |
