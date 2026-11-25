# Single-File Journaled Volume Driver: `ext4lite`

This specification describes `pkg/sentry/fsimpl/ext4lite`, the pure-Go VFS2 driver backing named volumes (`-v name:/path`), `-rootfs-volume`, and copy-on-write overlays (`--mount type=overlay`). Each volume resides in a single host `.ext4` file opened prior to `hostlockdown.Apply()`.

---

## 1. Purpose and Scope

Workloads such as `dockerd`, `containerd`, `k3s`, Git, and package managers depend on strict POSIX filesystem semantics. Host NTFS and case-insensitive APFS break case-sensitive names, special `0:0` whiteouts, arbitrary extended attributes, and atomic cross-directory renames.

`ext4lite` formats and mounts a Linux ext4 filesystem inside one pre-opened host `.ext4` image file across Windows, macOS, Linux, and Android. That single-file model satisfies POSIX invariants identically across all hosts without requiring post-lockdown host path opens.

Clean volume images pass `e2fsck -fn` and mount directly on Linux with `mount -o loop -t ext4`.

---

## 2. Design and Invariants

`ext4lite` implements standard Linux ext4 disk geometry, tiered host allocation, ordered JBD2 crash recovery, and file-lock concurrency inside one pre-opened host file.

### 2.1 On-Disk Layout and Storage Forms

`ext4lite` formats 4 KiB blocks in 16 MiB block groups (`4,096` blocks and `4,096` 256-byte inodes per group). The superblock sits at byte `1024` of block `0`, with backups in groups `0`, `1`, and powers of `3`, `5`, and `7`.

- **Enabled ext4 features**: `ext_attr`, `filetype`, `meta_bg`, `extents`, `64bit`, `inline_data`, `sparse_super`, `large_file`, `extra_isize`, and `has_journal`. Directory hash trees and metadata checksums are omitted.
- **Dynamic growth via `meta_bg`**: Each 64-group meta-group stores descriptor blocks in its first, second, and last groups, growing online up to 64 TiB. Groups past the 32-bit inode ceiling hold data blocks only.
- **Inode storage forms**: Files up to 128 bytes store data inline (60 bytes in `i_block` plus 68 bytes in `system.data`). Symlinks under 60 bytes sit in `i_block`; larger files use depth-2 extent trees (462,400 extents max), including uninitialized extents.
- **Extended attributes**: Non-`system.data` attributes live in extra inode space or one 4 KiB xattr block (`ENOSPC` above 4 KiB). Imported shared xattr blocks are reference-counted and copied on write.

### 2.2 Growth, Compaction, Hole Punching, and Storage Tiers

Volumes grow one 16 MiB group at a time when blocks or inodes fill. `VolumeOptions.MaxBytes` (`size=`) caps growth at a 16 MiB multiple up to 64 TiB without preallocation. `ephemeral` creates a scratch image in `ephemeral-volumes/` and forbids checkpointing.

To avoid sparse-write fragmentation during growth, `ext4lite` probes three allocation tiers at open and falls back automatically:

| Storage Tier | Allocation Mechanism |
| :--- | :--- |
| Tier A | `fallocate` (Linux) or `fcntl(F_PREALLOCATE)` (macOS). |
| Tier B | `FileAllocationInfo` on Windows without `FSCTL_SET_SPARSE`. |
| Tier C | `ftruncate` fallback growing on demand. |

Space reclamation operates in two modes:

- **Online hole punching**: After commits and guest `FITRIM`, `ext4lite` punches free runs outside `heldBlocks` (`fallocate`, 16 KiB-aligned `F_PUNCHHOLE`, or `FSCTL_SET_ZERO_DATA`). Unsupported filesystems treat punching as a no-op.
- **Clean-unmount and offline compaction**: On unmount or `rungvx volume compact`, `ext4lite` moves trailing blocks into lower holes while preserving inode numbers. It then drops empty trailing groups, clears the journal, and truncates the file.

### 2.3 Ordered JBD2 Journaling and Crash Safety

Inode `8` reserves a 1,024-block (4 MiB) big-endian JBD2 journal in group `0` running in ordered mode:

1. Flush newly allocated data blocks before committing metadata so stale blocks never appear after crashes.
2. Pause guest mutations briefly at the operation gate to snapshot dirty metadata blocks.
3. Write revoke, descriptor, metadata, and CRC-32 commit blocks to the journal, then sync the host file.
4. Write home blocks asynchronously; the next sync or journal wrap makes them durable.
5. Keep freed blocks in `heldBlocks` until the freeing commit is durable, and link unlinked open inodes into `s_last_orphan`.

`fsync`, `fdatasync`, `sync`, and `O_SYNC`/`O_DSYNC` flush immediately; a background worker commits every 5 seconds or 96 dirty nodes. Legacy unjournaled images upgrade at writable mount when group `0` has 1,024 free blocks, or else use ordered writes and `fsckLite`.

### 2.4 Shared Locks, Overlays, Block Statistics, and Validation

- **File locking**: Writable mounts hold non-blocking `LOCK_EX`; read-only mounts hold `LOCK_SH`, permitting concurrent readers across sandboxes. Read-only mounts fail if a dirty journal needs replay.
- **Overlay branching**: `--mount type=overlay,src=base,upper=branch,dst=/path` stacks a read-only base volume beneath a persistent `branch` or ephemeral `tmpfs` upper layer.
- **Untrusted image checks**: `isValidDataBlock` rejects blocks overlapping superblocks, descriptors, bitmaps, or inode tables. Directory `rec_len`, extent bounds, inode sizes, and journal checksums validate before use, returning `EUCLEAN` on corruption.
- **Block statistics and migration**: `countedFile` records 17-field atomic counters for `/proc/diskstats`, `/proc/partitions`, `/sys/block/vd*`, `cgroup2` `io.stat`, and `rungvx stats`. `EnableMigrationTracking` and `DrainDirtyBlocks` track dirty blocks for pre-copy migration.
- **Extended I/O**: Supports `fallocate` (`0`, `KEEP_SIZE`, `PUNCH_HOLE`, `ZERO_RANGE`, `COLLAPSE_RANGE`, `INSERT_RANGE`) and `preadv2`/`pwritev2` flags (`RWF_HIPRI`, `RWF_DSYNC`, `RWF_SYNC`, `RWF_NOWAIT`, `RWF_APPEND`, `RWF_NOAPPEND`).

---

## 3. Verified Measurements

On Apple M1 (`hvf`), `docker pull nginx:alpine` took 9 s on `ext4lite`, versus 5 s on `tmpfs` and 32 to 54 s on `hostfs` ([`../recipes/docker-engine.md`](../recipes/docker-engine.md#71-storage-options)). POSIX conformance runs continuously on Linux and Windows in `pjdfstest.yml`.

---

## 4. Component Limits

Consult [`../compatibility.md`](../compatibility.md) for host-wide limits; the invariants below apply specifically to `ext4lite`:

- **No directory hash tree (`dir_index`) or metadata checksums**: Lookups read directories into an in-memory map rather than walking an HTree index.
- **Extended attribute ceiling**: One 4 KiB xattr block per inode; sets exceeding 4 KiB return `ENOSPC`.
- **Unmovable inodes during shrink**: Compaction relocates data extents only; trailing groups holding allocated inodes cannot truncate until freed.
- **Ephemeral volumes and checkpointing**: Sandboxes mounting an `ephemeral` volume forbid `rungvx checkpoint`.

---

## 5. Implementation Map

This table maps the `ext4lite` package files and test suites.

| Files in `pkg/sentry/fsimpl/ext4lite/` | Role |
| :--- | :--- |
| `mkfs.go`, `ondisk.go`, `geometry.go`, `open.go`, `volume.go`, `volume_api.go` | Image creation, superblock and `meta_bg` geometry, lock probing, mount API. |
| `alloc.go`, `bitmap.go`, `extent.go`, `data.go`, `regular_file.go`, `mmap.go`, `fallocate.go`, `rwf.go` | Block/inode allocator, extent tree, `chunkcache` `mmap`, `fallocate`, `RWF_*` I/O. |
| `dir.go`, `directory.go`, `dentry.go`, `node.go`, `symlink.go`, `special.go`, `tmpfile.go`, `orphan.go`, `xattr*.go` | VFS2 directory and inode operations, `O_TMPFILE`, orphan list, xattrs. |
| `jbd2.go`, `journal.go`, `flush.go`, `flusher.go`, `gate.go`, `fsck.go` | Ordered JBD2 journal, atomic flush gate, replay, and `fsckLite` repair. |
| `storage*.go`, `compact.go`, `trim.go`, `hostfile.go`, `blockstats.go`, `save_restore.go` | OS storage tiers, tail compaction, hole punching, block counters, checkpointing. |
| Tests | `pkg/sentry/fsimpl/ext4lite/*_test.go`, `e2e/volume*_e2e_test.go`, `e2e/root_volume_e2e_test.go`, `e2e/overlay_upper_e2e_test.go`, `scripts/pjdfstest`. |
