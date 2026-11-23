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

	"z.gfire.dev/gvx/internal/hoststorage"
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
	// key is the key under which a record of the entry lives, whether or not
	// one exists. It is zero for a host symbolic link, which has no record.
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
// Keep backing descriptor state on hostRoot: the checkpoint fingerprint
// includes the size of Workspace even though it is not saved.
type Workspace struct {
	// mu protects closed and orders the guest calls. Lock order:
	// Workspace.mu, then pinMu, then nameMu. filesystem.mu is always taken
	// before Workspace.mu. The metaTable has its own lock, which is a leaf.
	mu            sync.RWMutex
	rootPath      string
	root          *os.Root
	host          hostBackend
	rawHost       hostBackend
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
	restoreMode  bool
	isolate      func(dir, file *os.File) error
	validateFile func(hoststorage.StorageIdentity) error
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

// OpenWorkspace opens hostPath via os.OpenRoot prior to hostlockdown.Apply()
// and loads any persisted .gvx_meta table.
func OpenWorkspace(hostPath string, readOnly bool) (*Workspace, error) {
	return openWorkspace(hostPath, readOnly, workspaceOptions{coalesce: defaultCoalesceWindow})
}

// OpenIsolatedWorkspace validates the opened root and optional binding before
// it probes the filesystem, opens metadata, or starts workers.
func OpenIsolatedWorkspace(hostPath string, readOnly, restore bool, validate func(dir, file *os.File) error, validateFile func(hoststorage.StorageIdentity) error) (*Workspace, error) {
	if validate == nil || validateFile == nil {
		return nil, os.ErrInvalid
	}
	return openWorkspace(hostPath, readOnly, workspaceOptions{
		coalesce: defaultCoalesceWindow, restoreMode: restore, isolate: validate, validateFile: validateFile,
	})
}

func openWorkspace(hostPath string, readOnly bool, opts workspaceOptions) (*Workspace, error) {
	absPath, err := filepath.Abs(hostPath)
	if err != nil {
		return nil, fmt.Errorf("hostfs: resolve workspace path %q: %w", hostPath, err)
	}
	// A regular file selects the single-file mode: the pinned directory is the
	// parent of the file, and the stored name of the file is remembered.
	pinDir, single := absPath, ""
	if fi, serr := os.Stat(absPath); serr == nil && fi.Mode().IsRegular() {
		if pinDir, single, err = splitSingleFile(absPath); err != nil {
			return nil, err
		}
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
	var pinnedFile *os.File
	if opts.isolate != nil {
		if err := backend.isolate(); err != nil {
			return nil, errors.Join(err, backend.close(), root.Close())
		}
		if single != "" {
			pinnedFile, err = backend.open(single, os.O_RDONLY, 0)
			if err != nil {
				return nil, errors.Join(err, backend.close(), root.Close())
			}
			if _, err = hoststorage.VerifyStorageFile(pinnedFile); err != nil {
				return nil, errors.Join(err, pinnedFile.Close(), backend.close(), root.Close())
			}
		}
		if err := opts.isolate(backend.dir, pinnedFile); err != nil {
			if pinnedFile != nil {
				err = errors.Join(err, pinnedFile.Close())
			}
			return nil, errors.Join(err, backend.close(), root.Close())
		}
	}
	var host hostBackend = backend
	if single != "" {
		host = &singleHost{hostBackend: host, bound: backend, name: single, validate: opts.validateFile}
	}
	if opts.wrapHost != nil {
		host = opts.wrapHost(host)
	}
	clock := opts.clock
	if clock == nil {
		start := time.Now()
		clock = func() int64 { return int64(time.Since(start)) }
	}
	rootInfo, err := host.lstat(".")
	if err != nil {
		if pinnedFile != nil {
			_ = pinnedFile.Close()
		}
		_ = host.close()
		_ = root.Close()
		return nil, fmt.Errorf("hostfs: stat workspace root %q: %w", pinDir, err)
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
	backend.pinnedFile = pinnedFile
	w := &Workspace{
		rootPath:         absPath,
		root:             root,
		host:             host,
		rawHost:          backend,
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
		orphans:          orphanCollector{dirsPerStep: opts.orphanDirsPerStep},
	}
	// The query runs here because the Linux filter after the lockdown does not
	// allow getrlimit.
	w.watch.limit = hostWatchLimit()
	processWatches.limit.Store(int64(w.watch.limit))
	if w.pathKeys {
		w.rootKey = recKey{kind: kindPath, path: "."}
	} else {
		w.rootKey = recKey{kind: kindInode, id: w.storedID(rootInfo.fid)}
		w.rootPin.key = w.rootKey.id
	}
	if caps.LocksOpenDirMove {
		w.handles = newWinHandleRegistry(workspaceHandleOps{w})
	}
	if single != "" || (backend.isolated && runtime.GOOS == "darwin") {
		w.watch.factory = func(hw *hostWatcher) (watchBackend, error) { return newPollBackend(hw), nil }
	}
	if single != "" {
		return w, nil
	}
	if err := w.openMetaLock(); err != nil {
		_ = host.close()
		_ = root.Close()
		return nil, err
	}
	if err := w.loadMeta(); err != nil {
		_ = w.closeMetaLock()
		_ = host.close()
		_ = root.Close()
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
	return w, nil
}

// Root returns the underlying pinned *os.Root handle.
func (w *Workspace) Root() *os.Root {
	return w.root
}

// IsolatedStorage returns the borrowed directory and optional bound file of
// a protected workspace. The workspace owns the descriptors until Close.
func (w *Workspace) IsolatedStorage() (dir, file *os.File, leaf string) {
	backend := w.rawHost.(*hostRoot)
	if !backend.isolated {
		return nil, nil, ""
	}
	return backend.dir, backend.pinnedFile, w.single
}

// ValidateRestoreBinding verifies the protected file's current open target.
func (w *Workspace) ValidateRestoreBinding() error {
	if _, file, _ := w.IsolatedStorage(); file == nil {
		return nil
	}
	f, err := w.host.open(".", os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	return f.Close()
}

// HostPath returns the absolute host directory path of the workspace.
func (w *Workspace) HostPath() string {
	return w.rootPath
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
	rootErr := w.root.Close()
	var fileErr error
	if _, file, _ := w.IsolatedStorage(); file != nil {
		fileErr = file.Close()
	}
	return errors.Join(flushErr, journalErr, lockErr, pinErr, hostErr, rootErr, fileErr)
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

// nowNano returns monotonic nanoseconds for cache expiry.
func (w *Workspace) nowNano() int64 {
	return w.clock()
}
