// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package hostfs implements a handle-scoped workspace filesystem driver. Every
// host access goes through a directory handle pinned by os.OpenRoot before
// sandbox lockdown. Windows uses NtCreateFile relative to that handle and
// macOS uses openat with O_NOFOLLOW relative to its descriptor. POSIX
// permissions, ownership, and symbolic links live in the .gvx_meta journal.
//
// Crash consistency of .gvx_meta: a flush appends one checksummed frame with
// the changed records and flushes the file, and a compaction writes a snapshot
// to .gvx_meta.tmp, flushes it, and renames it over .gvx_meta. A crash at any
// point leaves every flush that completed, and a torn last frame drops out at
// the next load. See metastore.go. Mutations reach disk within a short
// coalescing window. Workspace.Sync and Workspace.Close flush before they
// return, so a successful Sync guarantees durability of every earlier
// mutation.
package hostfs

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/chunkcache"
)

const (
	// Name is the VFS2 filesystem type name for hostfs.
	Name = "hostfs"

	// MetaFileName is the hidden metadata file persisted inside the workspace root.
	MetaFileName = ".gvx_meta"
	// MetaLockFileName is the hidden advisory lock and commit-sequence file
	// persisted inside the workspace root for multi-sandbox synchronization.
	MetaLockFileName = ".gvx_meta.lock"
	metaTempName     = ".gvx_meta.tmp"
	metaTempPrefix   = ".gvx_meta.tmp."

	// defaultCoalesceWindow is the delay between the first unflushed
	// metadata mutation and the background flush. Later mutations in the
	// window share one flush. Sync bypasses the window. See section 6 of
	// GVXIP-001.
	defaultCoalesceWindow = 250 * time.Millisecond

	// maxFilenameLen is the longest name hostfs reports. It matches the
	// NAME_MAX of Linux, APFS, and NTFS.
	maxFilenameLen = 255

	// maxNameCacheDirs bounds the case-insensitive name index.
	maxNameCacheDirs = 4096
)

var (
	// ErrPathTraversal indicates that a path or symlink target attempted to
	// escape the pinned workspace os.Root boundary.
	ErrPathTraversal = errors.New("hostfs: path escapes workspace root")

	// ErrReadOnly indicates a write attempt against a read-only workspace mount.
	ErrReadOnly = errors.New("hostfs: workspace is mounted read-only")

	// errReservedName indicates an attempt to create or modify the hidden
	// metadata files.
	errReservedName = errors.New("hostfs: name is reserved for workspace metadata")

	// errNotEmpty indicates a directory that still holds entries.
	errNotEmpty = errors.New("hostfs: directory not empty")

	// errNotDir indicates that a directory operation met a non-directory.
	errNotDir = errors.New("hostfs: not a directory")

	// errIsDir indicates that a file operation met a directory.
	errIsDir = errors.New("hostfs: is a directory")

	// errNotPermitted indicates an operation that POSIX reports as EPERM, such
	// as a hard link to a directory.
	errNotPermitted = errors.New("hostfs: operation not permitted")

	// errInvalidMove indicates a rename of a directory into itself.
	errInvalidMove = errors.New("hostfs: cannot move a directory into itself")
)

// POSIXAttr stores virtual POSIX permissions, ownership, symlink target, and
// extended attributes in .gvx_meta for one host file or virtual symlink. The
// JSON tags describe the records of earlier releases, which ReadMeta and the
// loader still read.
//
// Atime, Mtime, and Ctime hold Unix nanoseconds. They apply to virtual
// symlinks, which have no host file to carry timestamps. A regular file or a
// directory keeps the change time of its last metadata mutation. Xattrs holds
// the extended attributes that the host cannot store. A record whose Mode names a
// socket, a FIFO, or a device stands for an empty placeholder file on the
// host. Rdev holds the device number of a device record: the major number in
// the high 32 bits and the minor number in the low 32 bits.
// +stateify savable
type POSIXAttr struct {
	Mode    uint32            `json:"mode"`
	UID     uint32            `json:"uid"`
	GID     uint32            `json:"gid"`
	Symlink string            `json:"symlink,omitempty"`
	Xattrs  map[string][]byte `json:"xattrs,omitempty"`
	Atime   int64             `json:"atime,omitempty"`
	Mtime   int64             `json:"mtime,omitempty"`
	Ctime   int64             `json:"ctime,omitempty"`
	Rdev    uint64            `json:"rdev,omitempty"`
}

// entry is the effective state of one workspace path: the virtual attributes
// layered over the host metadata.
//
// +stateify savable
type entry struct {
	attr POSIXAttr
	info hostInfo
	// virtual marks a symlink that exists only in .gvx_meta.
	virtual bool
	// key is the metadata key under which a record of the entry lives, whether
	// or not one exists. Host symlinks use their identity or path key so
	// UID, GID, and xattrs persist while targets come from the host OS.
	key recKey
}

func (e *entry) isDir() bool {
	return e.attr.Mode&linux.S_IFMT == linux.S_IFDIR
}

func (e *entry) isSymlink() bool {
	return e.attr.Mode&linux.S_IFMT == linux.S_IFLNK
}

// dirNames is a snapshot of one directory listing. It holds the host names as
// the host stores them, and it verifies that a name exists with exactly the
// requested case, form, and escape. The snapshot follows mutations through
// Workspace.addDirNameLocked and Workspace.removeDirNameLocked. The snapshot
// belongs to the guest directory path that keys Workspace.nameCache.
type dirNames struct {
	id    hostID
	mtime int64
	// until is the time up to which the snapshot is trusted without a stat
	// of the directory.
	until int64
	names map[string]struct{}
	// aux holds the secondary indexes. Workspace.nameMu protects it, and a
	// change of names resets it.
	aux *dirAux
}

// Workspace wraps a pre-opened Go 1.25+ *os.Root directory handle and enforces
// symlink-safe traversal and POSIX metadata persistence.
type Workspace struct {
	// mu protects closed and orders the guest calls. Lock order:
	// filesystem.mu, then Workspace.mu, then Workspace.flushMu, then
	// .gvx_meta.lock, then pinMu, then nameMu. The metaTable has its own lock,
	// which is a leaf.
	mu            sync.RWMutex
	rootPath      string
	root          *os.Root
	host          hostBackend
	metaRoot      *os.Root
	metaHost      hostBackend
	metaLockHost  hostBackend
	metaDirPath   string
	metaDev       uint64
	metaStableIDs bool
	externalMeta  bool
	readOnly      bool
	closed        bool
	closing       bool
	closingAtomic atomic.Bool

	// meta holds the records of .gvx_meta. See meta_table.go.
	meta *metaTable
	// metaLock holds the pre-opened .gvx_meta.lock file for directory
	// workspaces, or nil in single-file mode and on read-only workspaces before
	// any writer creates the lock file.
	metaLock          atomic.Pointer[os.File]
	metaEpoch         atomic.Uint64
	lastLockCommit    atomic.Uint64
	lastLockCompact   atomic.Uint64
	lastMetaCheckNano atomic.Int64
	// pathKeys selects the key kind of the records: guest paths on a volume
	// without trustworthy file identities and in single-file mode, file
	// identities everywhere else. It never changes after openWorkspace
	// returns. See recKind.
	pathKeys bool
	// rootDev is the device number of the workspace root. storedID replaces
	// it with zero. rootKey is the key of the root directory.
	rootDev uint64
	rootKey recKey

	// flushMu serialises table writes so a slow disk never blocks mutations.
	// It also protects journal.
	flushMu sync.Mutex
	journal metaJournal

	// inos holds the inode sets of directories for adoption. It has its own
	// leaf lock. See dirinos.go.
	inos inoCache

	nameMu    sync.Mutex
	nameCache map[string]*dirNames
	// altNames holds the stored host names that differ from the plain
	// encoding of the guest name. nameMu protects it. See names.go.
	altNames map[altKey]string

	// pinMu protects pins, the sweep state, and the fields of every pin but
	// h, id, and root. pins holds the pinned directory handles by
	// workspace-relative path.
	pinMu      sync.Mutex
	pins       map[string]*dirPin
	rootPin    dirPin
	pinsClosed bool
	sweepArmed bool
	sweepTimer *time.Timer

	// clock returns monotonic nanoseconds for cache expiry.
	clock func() int64

	coalesce time.Duration
	kick     chan struct{}
	stop     chan struct{}
	done     chan struct{}

	// chunkMem holds the shared memory for the chunks of mapped files, or nil
	// when chunks live on the Go heap.
	chunkMem chunkcache.ChunkMemoryHolder

	// watch bridges changes that host processes make to the guest. See
	// watcher.go.
	watch hostWatcher

	// beforeMetaRename lets tests stop a compaction between the temporary
	// file write and the rename, which models a crash.
	beforeMetaRename func() error
	// appendFault lets tests model a crash in the append of a journal frame.
	// It receives the frame and returns how many bytes reach the file and
	// the error that ends the flush.
	appendFault func(frame []byte) (int, error)

	// caps records the capabilities of the host volume. The fields below it
	// follow from caps and never change after openWorkspace returns.
	caps WorkspaceCaps
	// codec translates between guest names and host names.
	codec NameCodec
	// stateful reports that the stored name of an entry can differ from the
	// plain encoding of its guest name: the volume folds case or normalizes
	// Unicode.
	stateful bool
	// countsDirLinks reports that hostfs counts the subdirectories of a
	// directory for its link count, because the host does not. See
	// dirlinks.go.
	countsDirLinks bool
	// clutter selects the host shell files that guest listings hide.
	clutter clutterRules
	// handles tracks the open regular-file handles when the host locks an
	// open directory against a move. It is nil on every other host. See
	// handle_registry.go.
	handles *winHandleRegistry

	// maxMetaBytes is the memory that meta may use. See checkMetaRoom.
	maxMetaBytes int64
	// dirTimes records the last virtual symlink mutation time in a directory
	// that has no .gvx_meta record of its own. mu protects it.
	dirTimes map[recKey]int64
	// orphans collects the records whose host file is gone. See orphans.go.
	orphans orphanCollector
	// single is the host name of the bound file in single-file mode, or empty
	// for a directory workspace. It never changes after openWorkspace
	// returns. See single_file.go.
	single string
	// symlinkMode selects whether eligible guest symlinks materialize on the
	// host filesystem. Never changes after initWorkspace returns.
	symlinkMode SymlinkMode
}

type workspaceOptions struct {
	coalesce         time.Duration
	beforeMetaRename func() error
	// appendFault is Workspace.appendFault.
	appendFault func(frame []byte) (int, error)
	// wrapHost replaces the host backend with a wrapper. Tests use it to
	// count host calls.
	wrapHost func(hostBackend) hostBackend
	// clock replaces the monotonic clock of the cache expiry.
	clock func() int64
	// caps replaces the probe of the host volume. Tests use it to model
	// another volume.
	caps *WorkspaceCaps
	// hostOS replaces runtime.GOOS where hostfs picks the host clutter rules.
	hostOS string
	// maxMetaBytes replaces the memory cap of the .gvx_meta table. Tests use
	// it to reach the cap with few files.
	maxMetaBytes int64
	// noOrphanGC stops the background collector of orphan records. Tests
	// drive the collector by hand.
	noOrphanGC bool
	// orphanDirsPerStep replaces orphanStepDirs. Tests use it to stop a walk
	// between two directories.
	orphanDirsPerStep int
	// pathKeys keys the records on guest paths, as on a volume without
	// trustworthy file identities. Tests use it to model such a volume.
	pathKeys bool
	// journalSlack replaces the slack of the journal bound. Tests use it to
	// reach a compaction with few records.
	journalSlack int
	// countDirLinks makes hostfs count directory links on every host, as it
	// does on NTFS.
	countDirLinks bool
	// restoreMode skips ephemeral file sweeping during OpenWorkspaceForRestore
	// so CompleteRestore can reattach unlinked backing files first.
	restoreMode bool
	// metaDir overrides the host directory storing .gvx_meta and .gvx_meta.lock.
	metaDir string
	// metaDirResolved reports that metaDir was already validated by openWorkspace.
	metaDirResolved bool
	// symlinkMode configures how guest-created symbolic links are stored.
	symlinkMode SymlinkMode
}

// OpenOptions configures OpenWorkspaceWithOptions.
type OpenOptions struct {
	// ReadOnly mounts the workspace read-only without writing metadata.
	ReadOnly bool

	// MetaDir overrides the host directory storing .gvx_meta, .gvx_meta.lock,
	// and .gvx_meta.tmp.* staging files. When empty or resolving to the
	// workspace root itself, metadata lives in the workspace root directory.
	// MetaDir must already exist as a directory and cannot be a filesystem root
	// or strictly contain or lie inside the workspace directory.
	// When MetaDir resolves to an external directory, .gvx_meta* names are not
	// hidden inside the workspace namespace.
	MetaDir string

	// SymlinkMode selects how guest-created symbolic links are stored. Empty
	// defaults to SymlinkVirtual. SymlinkContained materializes eligible
	// relative symlinks on Unix hosts and falls back to virtual records for
	// non-eligible targets and on Windows. Unsupported for single-file mounts.
	SymlinkMode SymlinkMode

	// RestoreMode preserves unlinked ephemeral backing files during startup so
	// CompleteRestore can reattach open unlinked inodes.
	RestoreMode bool
}

// ChunkMemory supplies the memory for the chunks of mapped files.
type ChunkMemory = chunkcache.ChunkMemory

// SetChunkMemory makes mem back the chunks that files create from now on. Call
// it once before the first mapping, and only with memory that outlives every
// mapping.
func (w *Workspace) SetChunkMemory(mem ChunkMemory) {
	w.chunkMem.Set(mem)
}

// chunkMemory returns the shared chunk memory, or nil.
func (w *Workspace) chunkMemory() ChunkMemory {
	return w.chunkMem.Get()
}

// WarmWatchLimit caches the host watch descriptor budget before host lockdown
// runs so runtime OpenWorkspaceFromDirFD calls on Linux never invoke getrlimit.
func WarmWatchLimit() {
	if processWatches.limit.Load() <= 0 {
		processWatches.limit.Store(int64(hostWatchLimit()))
	}
}

// OpenWorkspace opens hostPath via os.OpenRoot prior to hostlockdown.Apply()
// and loads any persisted .gvx_meta table.
func OpenWorkspace(hostPath string, readOnly bool) (*Workspace, error) {
	return openWorkspace(hostPath, readOnly, workspaceOptions{coalesce: defaultCoalesceWindow})
}

// OpenWorkspaceWithOptions opens hostPath with explicit options prior to
// hostlockdown.Apply().
func OpenWorkspaceWithOptions(hostPath string, opts OpenOptions) (*Workspace, error) {
	return openWorkspace(hostPath, opts.ReadOnly, workspaceOptions{
		coalesce:    defaultCoalesceWindow,
		restoreMode: opts.RestoreMode,
		metaDir:     opts.MetaDir,
		symlinkMode: opts.SymlinkMode,
	})
}

func stripWindowsExtendedPrefix(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	if rest, ok := strings.CutPrefix(p, `\\?\UNC\`); ok {
		return `\\` + rest
	}
	if rest, ok := strings.CutPrefix(p, `\\?\`); ok {
		return rest
	}
	return p
}

func evalSymlinksOrClean(p string) string {
	cur := filepath.Clean(p)
	var tail []string
	for {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			for i := len(tail) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, tail[i])
			}
			return filepath.Clean(resolved)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return filepath.Clean(p)
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
	}
}

func canonicalPathForCompare(p string) string {
	cleaned := filepath.Clean(stripWindowsExtendedPrefix(p))
	if runtime.GOOS == "windows" {
		return strings.ToLower(cleaned)
	}
	return cleaned
}

func sameHostPath(a, b string) bool {
	if ai, errA := os.Stat(a); errA == nil {
		if bi, errB := os.Stat(b); errB == nil {
			return os.SameFile(ai, bi)
		}
	}
	return canonicalPathForCompare(evalSymlinksOrClean(a)) == canonicalPathForCompare(evalSymlinksOrClean(b))
}

// pathContainsStrict reports whether child lies strictly beneath parent using
// both physical filesystem identity (catching case-insensitive volumes,
// symlinks, and Windows extended-length prefixes) and lexical checks.
func pathContainsStrict(parent, child string) bool {
	if sameHostPath(parent, child) {
		return false
	}
	resolvedParent := evalSymlinksOrClean(parent)
	resolvedChild := evalSymlinksOrClean(child)
	if parentInfo, err := os.Stat(resolvedParent); err == nil {
		cur := resolvedChild
		for {
			next := filepath.Dir(cur)
			if next == cur {
				break
			}
			cur = next
			if curInfo, serr := os.Stat(cur); serr == nil && os.SameFile(parentInfo, curInfo) {
				return true
			}
		}
	}
	p := canonicalPathForCompare(resolvedParent)
	c := canonicalPathForCompare(resolvedChild)
	if p == c {
		return false
	}
	rel, err := filepath.Rel(p, c)
	if err != nil || rel == "." || rel == ".." {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// resolveExternalMetaDir validates metaDir relative to hostAbs and returns the
// symlink-resolved path of metaDir, or "" when metaDir resolves to hostAbs.
func resolveExternalMetaDir(hostAbs, metaDir string) (string, error) {
	absMeta, err := filepath.Abs(metaDir)
	if err != nil {
		return "", fmt.Errorf("hostfs: resolve MetaDir %q: %w", metaDir, err)
	}
	metaFI, err := os.Stat(absMeta)
	if err != nil {
		return "", fmt.Errorf("hostfs: stat MetaDir %q: %w", metaDir, err)
	}
	if !metaFI.IsDir() {
		return "", fmt.Errorf("hostfs: MetaDir %q must be a directory", metaDir)
	}
	realMeta, err := filepath.EvalSymlinks(absMeta)
	if err != nil {
		return "", fmt.Errorf("hostfs: resolve symlinks for MetaDir %q: %w", metaDir, err)
	}
	realMeta = filepath.Clean(realMeta)
	if filepath.Dir(realMeta) == realMeta {
		return "", fmt.Errorf("hostfs: MetaDir %q must not be a filesystem root", metaDir)
	}
	realHost := evalSymlinksOrClean(hostAbs)
	if sameHostPath(realHost, realMeta) {
		return "", nil
	}
	if pathContainsStrict(realHost, realMeta) {
		return "", fmt.Errorf("hostfs: MetaDir %q must not lie inside workspace %q", metaDir, hostAbs)
	}
	if pathContainsStrict(realMeta, realHost) {
		return "", fmt.Errorf("hostfs: MetaDir %q must not be an ancestor of workspace %q", metaDir, hostAbs)
	}
	return realMeta, nil
}

func openWorkspace(hostPath string, readOnly bool, opts workspaceOptions) (*Workspace, error) {
	if _, err := parseSymlinkMode(opts.symlinkMode); err != nil {
		return nil, err
	}
	absPath, err := filepath.Abs(hostPath)
	if err != nil {
		return nil, fmt.Errorf("hostfs: resolve workspace path %q: %w", hostPath, err)
	}
	// A regular file selects the single-file mode: the pinned directory is the
	// parent of the file, and the stored name of the file is remembered.
	pinDir, single := absPath, ""
	if fi, serr := os.Stat(absPath); serr == nil && fi.Mode().IsRegular() {
		if opts.metaDir != "" {
			return nil, fmt.Errorf("hostfs: MetaDir is unsupported for single-file mount %q", hostPath)
		}
		if opts.symlinkMode != "" {
			return nil, fmt.Errorf("hostfs: SymlinkMode is unsupported for single-file mount %q", hostPath)
		}
		if pinDir, single, err = splitSingleFile(absPath); err != nil {
			return nil, err
		}
	}
	if opts.metaDir != "" {
		realMeta, err := resolveExternalMetaDir(absPath, opts.metaDir)
		if err != nil {
			return nil, err
		}
		opts.metaDir = realMeta
		opts.metaDirResolved = true
	}
	root, err := os.OpenRoot(pinDir)
	if err != nil {
		return nil, fmt.Errorf("hostfs: os.OpenRoot(%q): %w", pinDir, err)
	}
	backend, err := newHostRoot(root)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	return initWorkspace(absPath, root, backend, single, readOnly, opts)
}

func initWorkspace(absPath string, root *os.Root, backend *hostRoot, single string, readOnly bool, opts workspaceOptions) (*Workspace, error) {
	var host hostBackend = backend
	if single != "" {
		host = &singleHost{hostBackend: host, bound: backend, name: single}
	}
	if opts.wrapHost != nil {
		host = opts.wrapHost(host)
	}
	var (
		metaRoot    *os.Root
		metaBackend *hostRoot
		metaLockRef *Workspace
		committed   bool
	)
	defer func() {
		if committed {
			return
		}
		if metaLockRef != nil {
			_ = metaLockRef.closeMetaLock()
		}
		if metaBackend != nil {
			_ = metaBackend.close()
		}
		if metaRoot != nil {
			_ = metaRoot.Close()
		}
		_ = host.close()
		if root != nil {
			_ = root.Close()
		}
	}()
	clock := opts.clock
	if clock == nil {
		start := time.Now()
		clock = func() int64 { return int64(time.Since(start)) }
	}
	rootInfo, err := host.lstat(".")
	if err != nil {
		return nil, fmt.Errorf("hostfs: stat workspace root %q: %w", absPath, err)
	}
	var caps WorkspaceCaps
	if opts.caps != nil {
		caps = *opts.caps
	} else {
		// The probe of a writable workspace creates files. A single-file
		// workspace must not write into the directory of the user.
		caps = platformCaps(host, readOnly || single != "")
		probeFileIDs(host, rootInfo, readOnly || single != "", &caps)
	}
	if single != "" {
		// The attributes of the guest stay in memory.
		caps.NativeXattr = false
	}
	hostOS := opts.hostOS
	if hostOS == "" {
		hostOS = runtime.GOOS
	}
	symlinkMode, err := parseSymlinkMode(opts.symlinkMode)
	if err != nil {
		return nil, err
	}
	if single != "" && opts.symlinkMode != "" {
		return nil, fmt.Errorf("hostfs: SymlinkMode is unsupported for single-file mount %q", absPath)
	}
	w := &Workspace{
		rootPath:         absPath,
		root:             root,
		host:             host,
		metaHost:         host,
		metaLockHost:     backend,
		metaDev:          rootInfo.fid.dev,
		metaStableIDs:    caps.StableIDs,
		readOnly:         readOnly,
		meta:             newMetaTable(),
		pathKeys:         opts.pathKeys || !caps.StableIDs || single != "",
		rootDev:          rootInfo.fid.dev,
		nameCache:        make(map[string]*dirNames),
		pins:             make(map[string]*dirPin),
		rootPin:          dirPin{h: host.rootDir(), root: true},
		clock:            clock,
		coalesce:         opts.coalesce,
		beforeMetaRename: opts.beforeMetaRename,
		appendFault:      opts.appendFault,
		caps:             caps,
		codec:            newNameCodec(caps),
		stateful:         !caps.CaseSensitive || caps.UnicodeNormalized,
		countsDirLinks:   !hostCountsDirLinks || opts.countDirLinks,
		clutter:          clutterRulesFor(hostOS),
		maxMetaBytes:     metaLimit(opts.maxMetaBytes),
		journal:          metaJournal{slack: opts.journalSlack, tempName: newMetaTempName()},
		dirTimes:         make(map[recKey]int64),
		single:           single,
		symlinkMode:      symlinkMode,
		orphans:          orphanCollector{dirsPerStep: opts.orphanDirsPerStep},
	}
	if opts.metaDir != "" {
		if single != "" {
			return nil, fmt.Errorf("hostfs: MetaDir is unsupported for single-file mount %q", absPath)
		}
		realMeta := opts.metaDir
		if !opts.metaDirResolved {
			realMeta, err = resolveExternalMetaDir(absPath, opts.metaDir)
			if err != nil {
				return nil, err
			}
		}
		if realMeta != "" {
			metaRoot, err = os.OpenRoot(realMeta)
			if err != nil {
				return nil, fmt.Errorf("hostfs: os.OpenRoot(MetaDir %q): %w", realMeta, err)
			}
			metaBackend, err = newHostRoot(metaRoot)
			if err != nil {
				return nil, fmt.Errorf("hostfs: open MetaDir backend %q: %w", realMeta, err)
			}
			metaInfo, err := metaBackend.lstat(".")
			if err != nil {
				return nil, fmt.Errorf("hostfs: stat MetaDir %q: %w", realMeta, err)
			}
			sameDir := (metaInfo.fidOK && rootInfo.fidOK && metaInfo.fid == rootInfo.fid) ||
				(metaInfo.id != (hostID{}) && metaInfo.id == rootInfo.id)
			if sameDir {
				_ = metaBackend.close()
				_ = metaRoot.Close()
				metaBackend = nil
				metaRoot = nil
			} else {
				var metaCaps WorkspaceCaps
				probeFileIDs(metaBackend, metaInfo, readOnly, &metaCaps)
				w.externalMeta = true
				w.metaDirPath = realMeta
				w.metaRoot = metaRoot
				w.metaHost = metaBackend
				w.metaLockHost = metaBackend
				w.metaDev = metaInfo.fid.dev
				w.metaStableIDs = metaCaps.StableIDs
			}
		}
	}
	// Reuse the pre-lockdown cached watch limit when set because the Linux
	// seccomp filter forbids getrlimit after lockdown.
	if cached := processWatches.limit.Load(); cached > 0 {
		w.watch.limit = int(cached)
	} else {
		w.watch.limit = hostWatchLimit()
		processWatches.limit.Store(int64(w.watch.limit))
	}
	if w.pathKeys {
		w.rootKey = recKey{kind: kindPath, path: "."}
	} else {
		w.rootKey = recKey{kind: kindInode, id: w.storedID(rootInfo.fid)}
		w.rootPin.key = w.rootKey.id
	}
	if caps.LocksOpenDirMove {
		w.handles = newWinHandleRegistry(workspaceHandleOps{w})
	}
	if single != "" {
		// Every host change reaches the guest through the poll backend, which
		// reads the one file by name.
		w.watch.factory = func(hw *hostWatcher) (watchBackend, error) { return newPollBackend(hw), nil }
		committed = true
		return w, nil
	}
	metaLockRef = w
	if err := w.openMetaLock(); err != nil {
		return nil, err
	}
	if err := w.loadMeta(); err != nil {
		return nil, err
	}
	if !readOnly && !opts.restoreMode {
		w.sweepEphemeral()
	}
	if !readOnly && w.coalesce > 0 {
		w.kick = make(chan struct{}, 1)
		w.meta.kick = w.kick
		w.stop = make(chan struct{})
		w.done = make(chan struct{})
		go w.flushLoop()
	}
	if !readOnly && !opts.noOrphanGC {
		w.startOrphanGC()
	}
	committed = true
	return w, nil
}

// Root returns the underlying pinned *os.Root handle.
func (w *Workspace) Root() *os.Root {
	return w.root
}

// HostPath returns the absolute host directory path of the workspace.
func (w *Workspace) HostPath() string {
	return w.rootPath
}

// MetaDir returns the resolved external metadata directory path, or empty when
// metadata lives in the workspace root directory.
func (w *Workspace) MetaDir() string {
	return w.metaDirPath
}

// SymlinkMode returns the effective symbolic link storage mode of the workspace.
func (w *Workspace) SymlinkMode() SymlinkMode {
	return w.symlinkMode
}

// ReadOnly reports whether the workspace mount disallows mutations.
func (w *Workspace) ReadOnly() bool {
	return w.readOnly
}

// Close flushes dirty metadata (when writable), closes every pinned directory
// handle, and closes the pinned root handles.
func (w *Workspace) Close() error {
	w.mu.Lock()
	if w.closing {
		w.mu.Unlock()
		return nil
	}
	w.closing = true
	w.mu.Unlock()

	w.watchShutdown()
	w.stopOrphanGC()
	if w.stop != nil {
		close(w.stop)
		<-w.done
	}
	flushErr := w.flushMeta()
	w.closingAtomic.Store(true)
	w.flushMu.Lock()
	journalErr := w.closeJournal()
	lockErr := w.closeMetaLock()
	w.flushMu.Unlock()

	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	pinErr := w.closePins()
	hostErr := w.host.close()
	var rootErr, metaHostErr, metaRootErr error
	if w.root != nil {
		rootErr = w.root.Close()
	}
	if w.externalMeta {
		if w.metaHost != nil {
			metaHostErr = w.metaHost.close()
		}
		if w.metaRoot != nil {
			metaRootErr = w.metaRoot.Close()
		}
	}
	return errors.Join(flushErr, journalErr, lockErr, pinErr, hostErr, rootErr, metaHostErr, metaRootErr)
}

// Sync writes every pending metadata mutation to stable storage. After Sync
// returns nil, a crash cannot lose any mutation that completed before the call.
func (w *Workspace) Sync() error {
	return w.flushMeta()
}

// CleanRelativePath validates and normalizes a workspace-relative path,
// rejecting any ".." component or escape outside the workspace root.
func CleanRelativePath(rel string) (string, error) {
	if hostSeparatorIsBackslash {
		rel = strings.ReplaceAll(rel, "\\", "/")
	}
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" || rel == "." {
		return ".", nil
	}
	for _, part := range strings.Split(rel, "/") {
		if part == ".." {
			return "", ErrPathTraversal
		}
	}
	cleaned := path.Clean(rel)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") || path.IsAbs(cleaned) {
		return "", ErrPathTraversal
	}
	return cleaned, nil
}

func splitParent(rel string) (parent, name string) {
	i := strings.LastIndexByte(rel, '/')
	if i < 0 {
		return ".", rel
	}
	return rel[:i], rel[i+1:]
}

func joinRelPath(parentRel, comp string) string {
	if parentRel == "" || parentRel == "." {
		return comp
	}
	return parentRel + "/" + comp
}

// isMetaTempName reports whether rel names a root-level metadata snapshot
// staging file, either ".gvx_meta.tmp" or ".gvx_meta.tmp.<suffix>".
func isMetaTempName(rel string) bool {
	if strings.ContainsRune(rel, '/') {
		return false
	}
	if strings.EqualFold(rel, metaTempName) {
		return true
	}
	return len(rel) >= len(metaTempPrefix) && strings.EqualFold(rel[:len(metaTempPrefix)], metaTempPrefix)
}

// isReservedPath reports whether rel names a hidden metadata or lock file. The
// match ignores case because a case-insensitive host volume would alias such a
// name.
func isReservedPath(rel string) bool {
	return strings.EqualFold(rel, MetaFileName) ||
		strings.EqualFold(rel, MetaLockFileName) ||
		isMetaTempName(rel)
}

// isReservedPath reports whether rel is hidden as a metadata file inside this
// workspace. External MetaDir workspaces store no metadata inside the workspace
// root, so no metadata names are reserved there.
func (w *Workspace) isReservedPath(rel string) bool {
	return !w.externalMeta && isReservedPath(rel)
}

// nowNano returns monotonic nanoseconds for cache expiry.
func (w *Workspace) nowNano() int64 {
	return w.clock()
}
