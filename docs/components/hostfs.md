# Pinned Host Filesystem Driver: `hostfs`

This specification describes `pkg/sentry/fsimpl/hostfs`, the in-process VFS2 driver backing host directory and single-file mounts (`-workspace`, `-v HOST:GUEST`, `--mount type=bind`) without spawning an external `gofer` server.

---

## 1. Purpose and Scope

Upstream gVisor shares host directories through an out-of-process 9P/`lisafs` server (`gofer`). Because `gvx` locks its host process before guest entry across Windows, macOS, Linux, and Android, an external server cannot run inside the same sandbox boundary.

`hostfs` pins mounted host directories and files through `os.OpenRoot` handles opened before `hostlockdown.Apply()`. It blocks symlink escapes, encodes host-incompatible filenames, stores POSIX attributes in `.gvx_meta`, and relays host changes to guest `inotify`.

The sections below define handle traversal, caching, single-file mounts, watch budgets, `.gvx_meta` journaling, and component limits.

---

## 2. Design and Invariants

`hostfs` enforces host boundary confinement through pinned handles, name encoding, an identity-keyed metadata journal, and a bounded host event bridge.

### 2.1 Pinned Handle Traversal and Caching

Before lockdown, `OpenWorkspace` anchors each host directory via `os.OpenRoot`. Subsequent lookups, mutations, and listings resolve one path component at a time relative to a pinned directory handle:

- **Windows**: Calls `NtCreateFile` with `OBJECT_ATTRIBUTES.RootDirectory`, `FILE_OPEN_REPARSE_POINT`, and full file sharing. Renames use `FILE_RENAME_POSIX_SEMANTICS`; unlinks use `FileDispositionInfoEx`. Because NTFS rejects directory renames with open descendants, `winHandleRegistry` flushes mapped pages, closes descendants under path-ordered locks, renames, reopens, and verifies identity.
- **macOS**: Uses `openat` with `O_NOFOLLOW | O_SYMLINK`, `renameat`, and `unlinkat`.
- **Linux and Android**: Uses `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`, falling back to single-component `O_NOFOLLOW` `openat` on `ENOSYS` or Android.

Each `Workspace` caches up to 256 pinned directory handles (retiring after 5 seconds idle) and closes subtree handles before directory renames or removals. Positive and negative lookup entries expire after 1 second unless invalidated by guest writes. Pinned directory handles revalidate their parent `lstat` after 1 second to detect host swaps.

### 2.2 Mapped Files (`chunkcache`), Name Translation, and Clutter Filtering

Guest `mmap` reads files in 64 KiB chunks via `pkg/sentry/fsimpl/chunkcache`. On macOS `hvf`, chunks live on the Go heap; on `systrap`, `Workspace.SetChunkMemory` backs chunks in the kernel memory file while skipping 1 GiB boundary crossings. `ConfigureMMap` pins the backing handle against concurrent `munmap` races, and `pread` flushes only dirty overlapping chunks.

`OpenWorkspace` probes host volume capabilities (`WorkspaceCaps`) before lockdown:

- **Name translation (`NameCodec`)**: Identity on Linux with zero allocation. On Windows and case-folding volumes, reserved names (`CON`, `AUX`, `NUL`), illegal characters, and case collisions encode via `~gvx~` hex escapes. On APFS, lookups try NFC fallback and listings normalize NFD unless `.gvx_meta` records NFD.
- **Host clutter**: Hides `.DS_Store`, `._*`, `Thumbs.db`, `.gvx_meta*`, and `~gvx~tmp.*` or `~gvx~swap.*` files. `rmdir` sweeps verified clutter from empty directories, and `OpenWorkspace` removes stale temporaries.

### 2.3 Single-File Bind Mounts

`OpenWorkspace` accepts a single regular file while rejecting sockets, devices, and pipes. It pins the parent directory, tracks the leaf name, and exposes only that file without writing `.gvx_meta`. Mode, owner, and xattr updates stay in memory, while timestamps propagate to the host. Unrecorded Windows files default to `0755` (`0555` read-only); macOS and Windows (`winMountBroker`) observe atomic host renames, whereas Linux Landlock pins the original inode.

### 2.4 Host Event Bridge (`inotify`) and Watch Caps

When a guest adds an `inotify` watch, `AdmitInotifyWatch` installs a lockdown-safe watcher. Linux polls every 200 ms via `fstatat`/`getdents64`, macOS uses `kqueue` `EVFILT_VNODE` (up to 4,096 descriptors plus poll fallback), and Windows uses overlapped `ReadDirectoryChangesW`. Event diffing pairs vanished and created inodes into `IN_MOVED_FROM`/`IN_MOVED_TO`, suppresses guest echoes, evicts clean cache chunks, and throttles polling to `max(200 ms, 3 * passDuration)`.

All workspaces in one host process draw from a shared watch budget (`processWatches`) computed before lockdown:

| Host | Cost per Watched Object | Process Watch Cap |
| :--- | :--- | :--- |
| Linux | One pinned directory descriptor | `soft RLIMIT_NOFILE - 1,024`, clamped to `[2,048, 65,536]` |
| macOS | One directory descriptor (plus up to 4,096 `kqueue` FDs) | `soft RLIMIT_NOFILE - 5,120`, clamped to `[2,048, 65,536]` (`5,120` at default `10,240`) |
| Windows | One directory handle and one 4 KiB buffer | `32,768` objects (`128 MiB` buffer cap) |

Exceeding the process budget returns `ENOSPC` to `inotify_add_watch(2)`.

### 2.5 Identity-Keyed `.gvx_meta` Journal and Multi-Sandbox Locking

`.gvx_meta` (format v4, magic `GVXMETA`) is a CRC-32C-framed journal storing modes, `uid`/`gid`, virtual symlinks, special nodes, and xattrs. Records key on host file identity (`FILE_ID_INFO` + serial on Windows, device + inode + `statx` birth on Linux, or device + inode on macOS). Hard links share one record, and atomic temp-file renames adopt orphaned records (clearing SUID/SGID) via directory-identity hints; volumes failing `StableIDs` use path keys.

Flushes batch every 250 ms (or immediately on `fsync`/`O_SYNC`), compacting above 64 MiB or `2 * live + 1,024` operations. Table memory caps at 512 MiB (~1,100,000 records, returning `ENOSPC` above), and a sweeper reaps deleted entries after two passes. Concurrent sandboxes sharing a host directory synchronize reads and flushes via `.gvx_meta.lock` opened before lockdown.

Callers can isolate `.gvx_meta`, `.gvx_meta.lock`, and staging files outside the workspace directory via `OpenOptions.MetaDir` (`Mount.MetaDir` or `Config.WorkspaceMetaDir`). `MetaDir` must already exist as a non-root directory disjoint from every mounted host path, and `hostlockdown` authorizes it before lockdown. When `MetaDir` is external, `.gvx_meta*` names stay ordinary workspace files, and `ReadMetaAt(metaPath, workspaceDir)` resolves identity-keyed records against the workspace tree.

### 2.6 Special Files, Symbolic Links, Extended Attributes, and Overlay Support

Sockets, FIFOs, and device nodes create empty host placeholders with `.gvx_meta` records; active socket endpoints stay in Sentry memory. On Linux, `user.*` xattrs write to host files while `trusted.*`, `security.*`, and macOS/Windows xattrs stay in `.gvx_meta` (`4 KiB`/inode, `64 KiB`/value max). Both `hostfs` and `ext4lite` act as overlay upper/lower layers, and `fallocate` supports `0`, `KEEP_SIZE`, and `PUNCH_HOLE` (`FSCTL_SET_ZERO_DATA` with zero-fill fallback).

`OpenOptions.SymlinkMode` (`Mount.SymlinkMode`, `Config.WorkspaceSymlinkMode`, or `--mount ...,symlinks=virtual|contained`) controls how guest-created symbolic links are persisted:

- **`SymlinkVirtual` (default)**: Stores every guest-created symbolic link only in `.gvx_meta`. The host filesystem receives no link entry.
- **`SymlinkContained` (opt-in)**: Materializes relative guest symbolic links on Linux and macOS via `symlinkat(2)` on a verified parent directory handle. Eligible targets must be non-empty, avoid NUL, backslashes, and colons, and place every `..` before ordinary components. Ordinary components must strictly outnumber leading `..` segments and stay within parent depth. Targets must avoid reserved metadata or internal names, uncontained host symlinks, and `NameCodec` escapes or case-folding collisions. Non-eligible targets and Windows hosts fall back transparently to `.gvx_meta`.
- **Containment across `rename` and `RENAME_EXCHANGE`**: `hostfs` verifies host symlinks and directories under `.gvx_meta.lock` before moving them. Directories holding unsafe hidden or shadowed host symlinks fail with `EACCES`. Visible host symlinks that cannot stay contained at the destination demote durably to `.gvx_meta` before unlinking the host link.
- **Metadata and inspection**: Host symlinks store optional `uid`, `gid`, and extended attributes in identity-keyed `.gvx_meta` records while reading target strings from the host OS. `Workspace.VirtualSymlinks()` and `VirtualSymlinksAt(metaPath, workspaceDir)` return the sorted virtual symbolic links in `.gvx_meta`.

---

## 3. Component Limits

Consult [`../compatibility.md`](../compatibility.md) for host-wide limits; the invariants below apply specifically to `hostfs`:

- **Slower than `ext4lite` for metadata-heavy workloads**: Host syscalls add overhead (`docker pull nginx:alpine` took 32 to 54 s on `hostfs` vs. 9 s on `ext4lite`).
- **Non-aligned nested mounts**: Unshadowed nested mounts (`-v $PWD:/app -v $PWD/logs:/var/log/app`) create separate `.gvx_meta` tables; aligned mounts (`-v $PWD/node_modules:/app/node_modules`) avoid overlap.
- **Host-held open descendants on Windows**: An external Windows process holding a descendant open blocks guest directory rename with `EACCES`.
- **Single-file mounts under Landlock and volatile metadata**: Linux Landlock pins the original inode descriptor across host atomic renames. Single-file mounts write no `.gvx_meta`, resetting mode, owner, and xattrs across restarts.

---

## 4. Implementation Map

This table maps the `hostfs` package files and test suites.

| Files in `pkg/sentry/fsimpl/hostfs/` | Role |
| :--- | :--- |
| `hostfs.go`, `workspace_*.go`, `vfs*.go`, `dirpin.go`, `handle_open.go`, `handle_registry.go` | VFS2 filesystem, pinned directory handle cache, lookup cache, Windows handle registry. |
| `inode_*.go`, `openat_*.go`, `openfd_*.go`, `posix_rename_windows.go`, `rename_flags*.go`, `allocate*.go`, `punch_windows.go` | OS-specific handle-scoped open, rename (`RENAME_EXCHANGE`, `RENAME_WHITEOUT`), `fallocate`, hole punch. |
| `codec.go`, `clutter.go`, `names.go`, `caps*.go`, `single_file*.go`, `symlink_rules.go`, `symlink_demote.go` | Volume probing, `~gvx~` name codec, clutter hiding, single-file bind mode, symlink containment and demotion. |
| `meta_*.go`, `metastore*.go`, `durability.go`, `orphans.go`, `unlinked.go` | Format v4 identity-keyed `.gvx_meta` journal, v3/JSON upgrade, multi-sandbox locking, collector. |
| `watcher*.go`, `watchlimit*.go`, `special_node.go`, `xattr*.go`, `regular_file.go`, `save_restore.go` | Lockdown-safe `inotify` bridge, watch budget, special nodes, xattrs, `chunkcache` `mmap`, C/R. |
| Tests | `pkg/sentry/fsimpl/hostfs/*_test.go`, `e2e/gate_m4_test.go`, `e2e/filemount_e2e_test.go`, `e2e/mounts_e2e_test.go`, `scripts/pjdfstest`. |
