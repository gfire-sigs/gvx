# Single-File Journaled Volume Driver: `ext4lite`

This specification describes `pkg/sentry/fsimpl/ext4lite`, the pure-Go VFS2 filesystem driver that backs named volumes (`-v name:/path`), persistent root overlays (`-rootfs-volume`), and copy-on-write volume branches (`--mount type=overlay`). Each volume resides in a single host `.ext4` image file opened prior to `hostlockdown.Apply()`.

---

## 1. Purpose and Scope

Workloads such as `dockerd`, `containerd`, `k3s`, Git, and package managers depend on strict POSIX semantics: case-sensitive filenames, arbitrary extended attributes (`trusted.overlay.*`, `security.*`), whiteout device nodes (`0:0`), hard links, atomic cross-directory renames, and durable crash recovery. Host NTFS and case-insensitive APFS violate several of these invariants. By formatting and mounting a genuine Linux ext4 filesystem inside one pre-opened host file, `ext4lite` satisfies POSIX semantics uniformly across Windows, macOS, Linux, and Android while requiring zero post-lockdown host path opens. Clean images pass `e2fsck -fn` and mount directly on Linux with `mount -o loop -t ext4`.

---

## 2. Design and Invariants

`ext4lite` implements standard Linux ext4 disk geometry, tiered host allocation, ordered JBD2 crash recovery, and file-lock concurrency inside one pre-opened host file.

### 2.1 On-Disk Layout and Storage Forms

`ext4lite` formats 4 KiB blocks organized into 16 MiB block groups (`4,096` blocks and `4,096` 256-byte inodes per group). The superblock resides at byte offset `1024` of block `0`, with backups in groups `0`, `1`, and powers of `3`, `5`, and `7`.

- **Enabled ext4 features**: `ext_attr`, `filetype`, `meta_bg`, `extents`, `64bit`, `inline_data`, `sparse_super`, `large_file`, `extra_isize`, and `has_journal`. Directory hash trees and metadata checksums are omitted.
- **Dynamic growth via `meta_bg`**: Each meta-group of 64 block groups stores its descriptor block in its first, second, and last groups, allowing online growth up to 64 TiB without relocating existing blocks. Groups beyond the 32-bit inode ceiling hold data blocks only.
- **Inode storage forms**: Files up to 128 bytes store data inline (60 bytes in `i_block` plus 68 bytes in the `system.data` extended attribute); symlinks shorter than 60 bytes are fast symlinks in `i_block`; larger files use extent trees up to depth 2 (at most 462,400 extents per file), including uninitialized extents (length > 32,768) that read as zero until written.
- **Extended attributes**: Attributes other than `system.data` reside behind extra inode fields or in a single 4 KiB xattr block (returning `ENOSPC` above 4 KiB). Shared xattr blocks imported from Linux images are reference-counted and copied on write.

### 2.2 Growth, Compaction, Hole Punching, and Storage Tiers

Volumes grow one 16 MiB group at a time when free blocks or inodes run out. `VolumeOptions.MaxBytes` (`size=`) caps growth at a 16 MiB multiple up to 64 TiB without preallocating disk space. Passing `ephemeral` creates a private scratch image in `ephemeral-volumes/` and forbids checkpointing for that run.

To avoid host sparse-write fragmentation during group growth, `ext4lite` probes three allocation tiers at open and degrades cleanly upon failure:

| Storage Tier | Allocation Mechanism |
| :--- | :--- |
| Tier A | `fallocate` (Linux) or `fcntl(F_PREALLOCATE)` (macOS). |
| Tier B | `FileAllocationInfo` on Windows without `FSCTL_SET_SPARSE`. |
| Tier C | `ftruncate` fallback growing on demand. |

Space reclamation operates in two modes:

1. **Online hole punching**: After each journal commit and home-block flush (and on guest `FITRIM` / `fstrim`), `ext4lite` punches free runs outside `heldBlocks` using `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)` on Linux and Android, 16 KiB-aligned `fcntl(F_PUNCHHOLE)` on macOS, or `FSCTL_SET_ZERO_DATA` on Windows. Unsupported host filesystems treat hole punching as a clean no-op.
2. **Clean-unmount and offline compaction**: On clean unmount or `rungvx volume compact`, `ext4lite` relocates data blocks from trailing groups into free holes in lower groups (keeping inode numbers invariant), removes empty trailing groups, empties the journal, and truncates the host file.

### 2.3 Ordered JBD2 Journaling and Crash Safety

Inode `8` reserves a fixed 1,024-block (4 MiB) big-endian JBD2 journal in group `0` operating in ordered mode:

1. Data writes for newly allocated blocks flush before the metadata transaction commits, preventing stale deleted-file data from appearing after power loss.
2. Each flush pauses guest mutations briefly at the operation gate to snapshot dirty metadata blocks, writes revoke, descriptor, metadata, and CRC-32 commit blocks to the journal, and calls `Sync` on the host file.
3. Home blocks are then written without a second sync; the next sync or journal wrap makes them durable.
4. `fsync`, `fdatasync`, `sync`, and `O_SYNC`/`O_DSYNC` writes flush immediately; a background flusher commits every 5 seconds or once 96 dirty nodes accumulate.
5. Freed blocks remain in `heldBlocks` until the freeing transaction is durable, preventing reuse before commit. Unlinked open files and `O_TMPFILE` inodes link into `s_last_orphan` so replay frees them after a crash.

Legacy volumes lacking a journal upgrade automatically at the first writable mount if group `0` holds 1,024 contiguous free blocks; otherwise they fall back to ordered metadata writes and `fsckLite` repair on unclean mount.

### 2.4 Shared Locks, Copy-on-Write Overlays, Block Statistics, and Untrusted Checks

- **File locking**: Writable mounts hold non-blocking `LOCK_EX`; read-only mounts hold `LOCK_SH`, permitting concurrent readers across sandboxes while rejecting writers and deletions. Read-only mounts fail if a dirty journal requires replay.
- **Overlay branching**: `--mount type=overlay,src=base,upper=branch,dst=/path` mounts a read-only base volume beneath a persistent `branch` volume (or an ephemeral `tmpfs` upper layer) using `/upper` and `/work`.
- **Untrusted image validation**: `isValidDataBlock` rejects any block overlapping superblocks, descriptors, bitmaps, or inode tables. Directory `rec_len`, extent coverage, inode sizes (directories <= 2^20 blocks, symlinks <= 4,095 bytes, files <= 2^32 - 1 blocks), and journal checksums are verified before allocation, returning `EUCLEAN` on corruption.
- **Block statistics and live migration**: `countedFile` records lock-free 17-field Linux block counters exposed under `/proc/diskstats`, `/proc/partitions`, and `/sys/block/vd*`. `Volume.AllocatedBlocks`, `EnableMigrationTracking`, and `DrainDirtyBlocks` expose incremental block bitmaps for pre-copy migration.
- **Extended I/O**: Supports `fallocate` (`0`, `KEEP_SIZE`, `PUNCH_HOLE`, `ZERO_RANGE`, `COLLAPSE_RANGE`, `INSERT_RANGE`) and `preadv2`/`pwritev2` flags (`RWF_HIPRI`, `RWF_DSYNC`, `RWF_SYNC`, `RWF_NOWAIT`, `RWF_APPEND`, `RWF_NOAPPEND`).

---

## 3. Verified Measurements

Single-run overlay pulls inside `docker:dind` on an Apple M1 host (`hvf`) showed `docker pull nginx:alpine` completing in 9 s on `ext4lite`, compared with 5 s on memory-backed `tmpfs` and 32 to 54 s on host-directory `hostfs` ([`../recipes/docker-engine.md`](../recipes/docker-engine.md#71-storage-options)). POSIX conformance is verified continuously on Linux and Windows by `pjdfstest.yml`.

---

## 4. Known Limits

- **No directory hash tree (`dir_index`) or metadata checksums**: Directory lookups read the directory once into an in-memory map rather than walking an HTree index.
- **Extended attribute ceiling**: One 4 KiB xattr block per inode; sets exceeding 4 KiB return `ENOSPC`.
- **Unmovable inodes during shrink**: Compaction relocates data extents only; trailing groups containing allocated inodes cannot be truncated away until those inodes are freed.
- **Ephemeral volumes and checkpointing**: Sandboxes mounting an `ephemeral` volume forbid `rungvx checkpoint`.
- **Database suites unverified in `e2e/`**: Although JBD2 ordering and `fsync` are implemented and unit-tested, no automated test under `e2e/` executes PostgreSQL or SQLite.

---

## 5. Implementation Map

| Files in `pkg/sentry/fsimpl/ext4lite/` | Role |
| :--- | :--- |
| `mkfs.go`, `ondisk.go`, `geometry.go`, `open.go`, `volume.go`, `volume_api.go` | Image creation, superblock and `meta_bg` geometry, lock probing, mount API. |
| `alloc.go`, `bitmap.go`, `extent.go`, `data.go`, `regular_file.go`, `mmap.go`, `fallocate.go`, `rwf.go` | Block/inode allocator, extent tree, `chunkcache` `mmap`, `fallocate`, `RWF_*` I/O. |
| `dir.go`, `directory.go`, `dentry.go`, `node.go`, `symlink.go`, `special.go`, `tmpfile.go`, `orphan.go`, `xattr*.go` | VFS2 directory and inode operations, `O_TMPFILE`, orphan list, xattrs. |
| `jbd2.go`, `journal.go`, `flush.go`, `flusher.go`, `gate.go`, `fsck.go` | Ordered JBD2 journal, atomic flush gate, replay, and `fsckLite` repair. |
| `storage*.go`, `compact.go`, `trim.go`, `hostfile.go`, `blockstats.go`, `save_restore.go` | OS storage tiers, tail compaction, hole punching, block counters, checkpointing. |
| Tests | `pkg/sentry/fsimpl/ext4lite/*_test.go`, `e2e/volume*_e2e_test.go`, `e2e/root_volume_e2e_test.go`, `e2e/overlay_upper_e2e_test.go`, and `scripts/pjdfstest`. |
