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
// permissions, ownership, and symbolic links live in an atomically replaced
// .gvx_meta table.
//
// Crash consistency of .gvx_meta: the table is written to .gvx_meta.tmp,
// flushed to stable storage, and renamed over .gvx_meta. A crash at any point
// leaves either the previous complete table or the new complete table.
// Mutations reach disk within a short coalescing window. Workspace.Sync and
// Workspace.Close flush before they return, so a successful Sync guarantees
// durability of every earlier mutation.
package hostfs

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

const (
	// Name is the VFS2 filesystem type name for hostfs.
	Name = "hostfs"

	// MetaFileName is the hidden metadata file persisted inside the workspace root.
	MetaFileName = ".gvx_meta"
	metaTempName = ".gvx_meta.tmp"

	// metaVersion is the schema version that hostfs writes. metaVersionV1 is
	// the schema before the xattr field. The reader accepts both.
	metaVersion   = 2
	metaVersionV1 = 1

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
// extended attributes in .gvx_meta for a workspace-relative path. It is the
// record of schema version 2.
//
// Atime, Mtime, and Ctime hold Unix nanoseconds. They apply to virtual
// symlinks only, which have no host file to carry timestamps. Xattrs holds the
// extended attributes that the host cannot store. A record whose Mode names a
// socket, a FIFO, or a device stands for an empty placeholder file on the
// host. Rdev holds the device number of a device record: the major number in
// the high 32 bits and the minor number in the low 32 bits.
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

type metaStoreFile struct {
	Version int                  `json:"version"`
	Entries map[string]POSIXAttr `json:"entries"`
}

// entry is the effective state of one workspace path: the virtual attributes
// layered over the host metadata.
type entry struct {
	attr POSIXAttr
	info hostInfo
	// virtual marks a symlink that exists only in .gvx_meta.
	virtual bool
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
	// mu protects meta, metaGen, and closed. Lock order: Workspace.mu, then
	// pinMu, then nameMu. filesystem.mu is always taken before Workspace.mu.
	mu       sync.RWMutex
	rootPath string
	root     *os.Root
	host     hostBackend
	readOnly bool
	meta     map[string]POSIXAttr
	closed   bool
	closing  bool

	// metaGen counts mutations. metaFlushedGen is the metaGen of the table
	// last written to disk. Both are protected by mu.
	metaGen        uint64
	metaFlushedGen uint64

	// flushMu serialises table writes so a slow disk never blocks mutations.
	flushMu sync.Mutex

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
	chunkMem atomic.Pointer[chunkMemoryHolder]

	// watch bridges changes that host processes make to the guest. See
	// watcher.go.
	watch hostWatcher

	// beforeMetaRename lets tests stop a flush between the temporary file
	// write and the rename, which models a crash.
	beforeMetaRename func() error

	// caps records the capabilities of the host volume. The fields below it
	// follow from caps and never change after openWorkspace returns.
	caps WorkspaceCaps
	// codec translates between guest names and host names.
	codec NameCodec
	// stateful reports that the stored name of an entry can differ from the
	// plain encoding of its guest name: the volume folds case or normalizes
	// Unicode.
	stateful bool
	// clutter selects the host shell files that guest listings hide.
	clutter clutterRules
	// handles tracks the open regular-file handles when the host locks an
	// open directory against a move. It is nil on every other host. See
	// handle_registry.go.
	handles *winHandleRegistry

	// pruneKeys and pruneCursor drive the incremental check of the .gvx_meta
	// records against the host. mu protects them.
	pruneKeys   []string
	pruneCursor int
	// maxMeta is the most entries that meta may hold. See checkMetaRoomLocked.
	maxMeta int
}

type workspaceOptions struct {
	coalesce         time.Duration
	beforeMetaRename func() error
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
	// maxMeta replaces the limit of .gvx_meta entries. Tests use it to reach
	// the limit with few files.
	maxMeta int
}

// ChunkMemory supplies the memory for the chunks of mapped files. A platform
// that runs guest code in another process maps guest pages by file descriptor,
// so it cannot use Go heap memory. The Linux systrap platform is one.
type ChunkMemory interface {
	memmap.File

	// AllocateChunk returns a zeroed range of length bytes. The caller holds
	// one reference, which it drops with DecRef.
	AllocateChunk(length uint64) (memmap.FileRange, error)
}

type chunkMemoryHolder struct{ m ChunkMemory }

// SetChunkMemory makes mem back the chunks that files create from now on. Call
// it once before the first mapping, and only with memory that outlives every
// mapping.
func (w *Workspace) SetChunkMemory(mem ChunkMemory) {
	w.chunkMem.Store(&chunkMemoryHolder{m: mem})
}

// chunkMemory returns the shared chunk memory, or nil.
func (w *Workspace) chunkMemory() ChunkMemory {
	if h := w.chunkMem.Load(); h != nil {
		return h.m
	}
	return nil
}

// OpenWorkspace opens hostPath via os.OpenRoot prior to hostlockdown.Apply()
// and loads any persisted .gvx_meta table.
func OpenWorkspace(hostPath string, readOnly bool) (*Workspace, error) {
	return openWorkspace(hostPath, readOnly, workspaceOptions{coalesce: defaultCoalesceWindow})
}

func openWorkspace(hostPath string, readOnly bool, opts workspaceOptions) (*Workspace, error) {
	absPath, err := filepath.Abs(hostPath)
	if err != nil {
		return nil, fmt.Errorf("hostfs: resolve workspace path %q: %w", hostPath, err)
	}
	root, err := os.OpenRoot(absPath)
	if err != nil {
		return nil, fmt.Errorf("hostfs: os.OpenRoot(%q): %w", absPath, err)
	}
	backend, err := newHostRoot(root)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	var host hostBackend = backend
	if opts.wrapHost != nil {
		host = opts.wrapHost(host)
	}
	clock := opts.clock
	if clock == nil {
		start := time.Now()
		clock = func() int64 { return int64(time.Since(start)) }
	}
	var caps WorkspaceCaps
	if opts.caps != nil {
		caps = *opts.caps
	} else {
		caps = platformCaps(host, readOnly)
	}
	hostOS := opts.hostOS
	if hostOS == "" {
		hostOS = runtime.GOOS
	}
	w := &Workspace{
		rootPath:         absPath,
		root:             root,
		host:             host,
		readOnly:         readOnly,
		meta:             make(map[string]POSIXAttr),
		nameCache:        make(map[string]*dirNames),
		pins:             make(map[string]*dirPin),
		rootPin:          dirPin{h: host.rootDir(), root: true},
		clock:            clock,
		coalesce:         opts.coalesce,
		beforeMetaRename: opts.beforeMetaRename,
		caps:             caps,
		codec:            newNameCodec(caps),
		stateful:         !caps.CaseSensitive || caps.UnicodeNormalized,
		clutter:          clutterRulesFor(hostOS),
		maxMeta:          metaLimit(opts.maxMeta),
	}
	if caps.LocksOpenDirMove {
		w.handles = newWinHandleRegistry(workspaceHandleOps{w})
	}
	if err := w.loadMeta(); err != nil {
		_ = host.close()
		_ = root.Close()
		return nil, err
	}
	if !readOnly {
		w.sweepEphemeral()
	}
	if !readOnly && w.coalesce > 0 {
		w.kick = make(chan struct{}, 1)
		w.stop = make(chan struct{})
		w.done = make(chan struct{})
		go w.flushLoop()
	}
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
	if w.stop != nil {
		close(w.stop)
		<-w.done
	}
	flushErr := w.flushMeta()

	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	pinErr := w.closePins()
	hostErr := w.host.close()
	rootErr := w.root.Close()
	return errors.Join(flushErr, pinErr, hostErr, rootErr)
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

// isReservedPath reports whether rel names a hidden metadata file. The match
// ignores case because a case-insensitive host volume would alias such a name.
func isReservedPath(rel string) bool {
	return strings.EqualFold(rel, MetaFileName) || strings.EqualFold(rel, metaTempName)
}

func (w *Workspace) loadMeta() error {
	f, err := w.host.open(MetaFileName, os.O_RDONLY, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("hostfs: open %s: %w", MetaFileName, err)
	}
	defer func() {
		_ = f.Close()
	}()
	raw, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("hostfs: read %s: %w", MetaFileName, err)
	}
	if len(raw) == 0 {
		return nil
	}
	var parsed metaStoreFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("hostfs: parse %s: %w", MetaFileName, err)
	}
	if parsed.Version != metaVersion && parsed.Version != metaVersionV1 {
		return fmt.Errorf("hostfs: %s has unsupported version %d", MetaFileName, parsed.Version)
	}
	for k, v := range parsed.Entries {
		cleanKey, kErr := CleanRelativePath(k)
		if kErr != nil || cleanKey == "." || isReservedPath(cleanKey) {
			continue
		}
		w.meta[cleanKey] = v
	}
	// Records of host files that vanished while no guest ran are dead state.
	w.pruneOrphansLocked(len(w.meta))
	w.pruneKeys, w.pruneCursor = nil, 0
	return nil
}

// markDirtyLocked records a metadata mutation and wakes the background
// flusher. Callers hold w.mu for writing.
func (w *Workspace) markDirtyLocked() {
	w.metaGen++
	if w.kick != nil {
		select {
		case w.kick <- struct{}{}:
		default:
		}
	}
}

// flushLoop coalesces bursts of mutations into one table write. It runs until
// Close stops it. A failed write stays pending: the next mutation, Sync, or
// Close retries and reports the error.
func (w *Workspace) flushLoop() {
	defer close(w.done)
	for {
		select {
		case <-w.stop:
			return
		case <-w.kick:
		}
		timer := time.NewTimer(w.coalesce)
		select {
		case <-w.stop:
			timer.Stop()
			return
		case <-timer.C:
		}
		_ = w.flushMeta()
	}
}

// flushMeta writes the table if it changed since the last write. The payload
// is built under the read lock and written without it.
func (w *Workspace) flushMeta() error {
	if w.readOnly {
		return nil
	}
	w.flushMu.Lock()
	defer w.flushMu.Unlock()

	w.mu.RLock()
	dirty := w.metaGen != w.metaFlushedGen
	w.mu.RUnlock()
	if !dirty {
		return nil
	}
	// Drop the records whose host object vanished before the table goes to
	// disk. One batch per flush keeps the pause short.
	w.mu.Lock()
	if !w.closed {
		w.pruneOrphansLocked(pruneBatch)
	}
	w.mu.Unlock()

	w.mu.RLock()
	gen := w.metaGen
	payload, err := json.Marshal(metaStoreFile{Version: metaVersion, Entries: w.meta})
	w.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("hostfs: encode %s: %w", MetaFileName, err)
	}

	if err := w.writeMetaFile(payload); err != nil {
		return err
	}
	w.mu.Lock()
	w.metaFlushedGen = gen
	w.mu.Unlock()
	return nil
}

// writeMetaFile replaces .gvx_meta atomically. The temporary file lives in the
// same directory so the final rename never crosses a volume.
func (w *Workspace) writeMetaFile(payload []byte) (err error) {
	f, err := w.host.open(metaTempName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("hostfs: create %s: %w", metaTempName, err)
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = w.host.unlink(metaTempName)
		}
	}()
	if _, werr := f.Write(payload); werr != nil {
		_ = f.Close()
		return fmt.Errorf("hostfs: write %s: %w", metaTempName, werr)
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return fmt.Errorf("hostfs: sync %s: %w", metaTempName, serr)
	}
	if cerr := f.Close(); cerr != nil {
		return fmt.Errorf("hostfs: close %s: %w", metaTempName, cerr)
	}
	if w.beforeMetaRename != nil {
		if herr := w.beforeMetaRename(); herr != nil {
			return herr
		}
	}
	if rerr := w.host.rename(metaTempName, MetaFileName); rerr != nil {
		return fmt.Errorf("hostfs: replace %s: %w", MetaFileName, rerr)
	}
	renamed = true
	if derr := w.host.syncDir("."); derr != nil {
		return fmt.Errorf("hostfs: sync workspace directory: %w", derr)
	}
	return nil
}

// nowNano returns monotonic nanoseconds for cache expiry.
func (w *Workspace) nowNano() int64 {
	return w.clock()
}

// exactNameIn reports whether the host stores the entry leaf of the guest
// directory parent under exactly that name. On a case-insensitive volume the
// host resolves "A" to a file stored as "a". Guest code expects case-sensitive
// names, so hostfs compares the requested name with the stored directory
// entry. A non-nil pin is the pinned handle of the directory parent.
func (w *Workspace) exactNameIn(parent, leaf string, pin *dirPin) (bool, error) {
	if !w.host.caseInsensitive() {
		return true, nil
	}
	for attempt := range 2 {
		snap, fresh, err := w.snapshotDir(parent, pin, attempt == 1)
		if err != nil {
			return false, err
		}
		w.nameMu.Lock()
		_, ok := snap.names[leaf]
		w.nameMu.Unlock()
		if ok || fresh {
			return ok, nil
		}
		// A cached snapshot may predate an external creation: re-read once.
	}
	return false, nil
}

// snapshotDir returns the listing snapshot of the guest directory parent. The
// snapshot stays valid for cacheTTL without a host call, and a stat of the
// directory proves it afterwards. A non-nil pin is the pinned handle of the
// directory. forceRead skips the cache. The second result reports that the
// call read the directory from the host.
func (w *Workspace) snapshotDir(parent string, pin *dirPin, forceRead bool) (*dirNames, bool, error) {
	now := w.nowNano()
	w.nameMu.Lock()
	cached := w.nameCache[parent]
	if !forceRead && cached != nil && now < cached.until {
		w.nameMu.Unlock()
		return cached, false, nil
	}
	w.nameMu.Unlock()
	pinfo, err := w.dirInfo(parent, pin)
	if err != nil {
		return nil, false, err
	}
	if !forceRead {
		w.nameMu.Lock()
		cached = w.nameCache[parent]
		if cached != nil && cached.id == pinfo.id && cached.mtime == pinfo.mtime.UnixNano() {
			cached.until = now + int64(cacheTTL)
			w.nameMu.Unlock()
			return cached, false, nil
		}
		w.nameMu.Unlock()
	}
	hostDir, err := w.hostPath(parent)
	if err != nil {
		return nil, false, err
	}
	entries, err := w.host.readDir(hostDir)
	if err != nil {
		return nil, false, err
	}
	snap := &dirNames{id: pinfo.id, mtime: pinfo.mtime.UnixNano(), until: now + int64(cacheTTL), names: make(map[string]struct{}, len(entries))}
	for _, e := range entries {
		snap.names[e.name] = struct{}{}
	}
	w.nameMu.Lock()
	if len(w.nameCache) >= maxNameCacheDirs {
		w.nameCache = make(map[string]*dirNames)
	}
	w.nameCache[parent] = snap
	w.nameMu.Unlock()
	return snap, true, nil
}

// dirInfo reads the metadata of the guest directory rel. It uses the pin when
// one is given and a path walk otherwise.
func (w *Workspace) dirInfo(rel string, pin *dirPin) (hostInfo, error) {
	if pin != nil {
		return w.host.fstatDir(pin.h)
	}
	hostDir, err := w.hostPath(rel)
	if err != nil {
		return hostInfo{}, err
	}
	return w.host.lstat(hostDir)
}

// needsExactCheck reports whether the backend resolves a name that differs in
// case from the stored name and leaves the comparison to hostfs.
func (w *Workspace) needsExactCheck() bool {
	return w.host.caseInsensitive() && !w.host.caseVerified()
}

// tracksDirNames reports whether the listing snapshots need updates when the
// guest mutates a directory.
func (w *Workspace) tracksDirNames() bool {
	return w.stateful || w.needsExactCheck()
}

// addDirNameLocked records that the host directory dir now holds the entry
// hostName for the guest name name. It updates the snapshot of dir in place, so
// the next lookup does not list dir again. A directory without a snapshot stays
// without one. Callers hold w.mu for writing.
func (w *Workspace) addDirNameLocked(dir, name, hostName string) {
	w.updateDirName(dir, name, hostName, true)
}

// removeDirNameLocked records that the host directory dir no longer holds the
// entry hostName. Callers hold w.mu for writing.
func (w *Workspace) removeDirNameLocked(dir, name, hostName string) {
	w.updateDirName(dir, name, hostName, false)
}

func (w *Workspace) updateDirName(dir, name, hostName string, present bool) {
	w.watchNoteName(dir, name)
	if !w.tracksDirNames() {
		return
	}
	w.nameMu.Lock()
	cached := w.nameCache[dir]
	if cached == nil {
		w.nameMu.Unlock()
		return
	}
	if present {
		cached.names[hostName] = struct{}{}
	} else {
		delete(cached.names, hostName)
	}
	cached.aux = nil
	w.nameMu.Unlock()

	// The mutation changed the modification time of the directory. Stamp the
	// snapshot with the new time, or the next stat would reject it.
	pin := w.holdPin(dir)
	info, err := w.dirInfo(dir, pin)
	if pin != nil {
		w.releasePin(pin)
	}
	now := w.nowNano()
	w.nameMu.Lock()
	defer w.nameMu.Unlock()
	if w.nameCache[dir] != cached {
		return
	}
	if err != nil {
		delete(w.nameCache, dir)
		return
	}
	cached.id = info.id
	cached.mtime = info.mtime.UnixNano()
	cached.until = now + int64(cacheTTL)
}

// dropDirNamesLocked drops the snapshots of the directory rel and of every
// directory below it. A directory rename or removal changes whole subtrees,
// which the in-place updates cannot express. Callers hold w.mu for writing.
func (w *Workspace) dropDirNamesLocked(rel string) {
	if !w.tracksDirNames() {
		return
	}
	prefix := rel + "/"
	w.nameMu.Lock()
	defer w.nameMu.Unlock()
	for k := range w.nameCache {
		if rel == "." || k == rel || strings.HasPrefix(k, prefix) {
			delete(w.nameCache, k)
		}
	}
}

func defaultPerm(info hostInfo) uint32 {
	return info.perm & 0o7777
}

// effectiveAttr layers the .gvx_meta record over the host metadata. The file
// type always comes from the host so a stale record cannot change the type.
func (w *Workspace) effectiveAttr(rel string, info hostInfo) POSIXAttr {
	var typ uint32
	switch info.kind {
	case hostKindDir:
		typ = linux.S_IFDIR
	default:
		typ = linux.S_IFREG
	}
	if m, ok := w.meta[rel]; ok {
		a := POSIXAttr{Mode: typ | m.Mode&0o7777, UID: m.UID, GID: m.GID, Xattrs: m.Xattrs}
		if st := placeholderType(info, m); st != 0 {
			a.Mode, a.Rdev = st|m.Mode&0o7777, m.Rdev
		}
		return a
	}
	return POSIXAttr{Mode: typ | defaultPerm(info)}
}

// lookupLocked resolves rel to its effective state without following links.
// It walks the path from the workspace root on every call, so the result
// never depends on a pinned handle. Callers hold w.mu.
func (w *Workspace) lookupLocked(rel string) (entry, error) {
	e, _, err := w.lookupProbeLocked(rel)
	return e, err
}

// lookupProbeLocked is lookupLocked that also returns where the host holds the
// entry, or the name that a new entry at rel would get. Callers hold w.mu.
func (w *Workspace) lookupProbeLocked(rel string) (entry, hostProbe, error) {
	if w.closed {
		return entry{}, hostProbe{}, os.ErrClosed
	}
	if isReservedPath(rel) {
		return entry{}, hostProbe{}, fs.ErrNotExist
	}
	if m, ok := w.meta[rel]; ok && m.Symlink != "" {
		parent, _ := splitParent(rel)
		hostDir, err := w.hostPath(parent)
		if err != nil {
			return entry{}, hostProbe{}, err
		}
		pinfo, err := w.host.lstat(hostDir)
		if err != nil {
			return entry{}, hostProbe{}, err
		}
		if pinfo.kind != hostKindDir {
			return entry{}, hostProbe{}, errNotDir
		}
		return virtualEntry(m), hostProbe{}, nil
	}
	if rel == "." {
		info, err := w.host.lstat(rel)
		if err != nil {
			return entry{}, hostProbe{}, err
		}
		e, err := w.entryFromInfo(rel, info)
		return e, hostProbe{found: true, info: info}, err
	}
	p, err := w.locateLocked(rel)
	if err != nil {
		return entry{}, hostProbe{}, err
	}
	if !p.found || p.hidden {
		return entry{}, p, p.missingError(rel)
	}
	e, err := w.entryFromInfo(rel, p.info)
	return e, p, err
}

// entryFromInfo builds the effective state of rel from its host metadata.
// Callers hold w.mu.
func (w *Workspace) entryFromInfo(rel string, info hostInfo) (entry, error) {
	switch info.kind {
	case hostKindDir, hostKindRegular:
		attr := w.effectiveAttr(rel, info)
		if specialFileType(attr.Mode) != 0 {
			info.kind, info.size, info.blocks = hostKindSpecial, 0, 0
		}
		return entry{attr: attr, info: info}, nil
	case hostKindSymlink:
		hostRel, err := w.hostPath(rel)
		if err != nil {
			return entry{}, err
		}
		target, err := w.host.readlink(hostRel)
		if err != nil {
			return entry{}, err
		}
		if validateSymlinkTarget(rel, target) != nil {
			return entry{}, ErrPathTraversal
		}
		return entry{attr: POSIXAttr{Mode: linux.S_IFLNK | 0o777, Symlink: target}, info: info}, nil
	default:
		return entry{}, ErrPathTraversal
	}
}

// nameMismatch builds the error for a name that exists on the host only under
// another case.
func nameMismatch(rel string) error {
	return fmt.Errorf("hostfs: lookup %q: %w: %w", rel, errNameMismatch, fs.ErrNotExist)
}

func virtualEntry(m POSIXAttr) entry {
	ts := time.Unix(0, m.Ctime)
	return entry{
		attr:    m,
		virtual: true,
		info: hostInfo{
			kind:  hostKindSymlink,
			size:  int64(len(m.Symlink)),
			nlink: 1,
			perm:  0o777,
			atime: time.Unix(0, m.Atime),
			mtime: time.Unix(0, m.Mtime),
			ctime: ts,
			btime: ts,
		},
	}
}

func (w *Workspace) lookup(rel string) (entry, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.lookupLocked(rel)
}

// checkWritableLocked rejects mutations of read-only workspaces and of the
// hidden metadata names.
func (w *Workspace) checkWritableLocked(rels ...string) error {
	if w.readOnly {
		return ErrReadOnly
	}
	if w.closed {
		return os.ErrClosed
	}
	for _, rel := range rels {
		if isReservedPath(rel) {
			return errReservedName
		}
	}
	return nil
}

// checkParentDirLocked verifies that the parent of rel is a host directory.
func (w *Workspace) checkParentDirLocked(rel string) error {
	parent, _ := splitParent(rel)
	hostDir, err := w.hostPath(parent)
	if err != nil {
		return err
	}
	pinfo, err := w.host.lstat(hostDir)
	if err != nil {
		return err
	}
	if pinfo.kind != hostKindDir {
		return errNotDir
	}
	return nil
}

// createTargetLocked returns the host path and the stored name for a new entry
// at rel. It fails with fs.ErrExist when an entry that the guest can see, or a
// virtual symlink, holds the name. A hidden host clutter file at the name goes
// away first. Callers hold w.mu for writing.
func (w *Workspace) createTargetLocked(rel string) (hostRel, leaf string, err error) {
	if m, ok := w.meta[rel]; ok && m.Symlink != "" {
		return "", "", fs.ErrExist
	}
	p, err := w.locateLocked(rel)
	if err != nil {
		return "", "", err
	}
	if p.found {
		if !p.clutter {
			return "", "", fs.ErrExist
		}
		hostRel, err = w.hostPath(rel)
		if err != nil {
			return "", "", err
		}
		if err := w.host.unlink(hostRel); err != nil && !isNotExist(err) {
			return "", "", err
		}
		return hostRel, leafOf(hostRel), nil
	}
	if p.collided && !w.stateful {
		// The host holds the name under another case, and hostfs cannot tell
		// it apart.
		return "", "", fs.ErrExist
	}
	parent, _ := splitParent(rel)
	hostDir, err := w.hostPath(parent)
	if err != nil {
		return "", "", err
	}
	return hostChild(hostDir, p.create), p.create, nil
}

func hostOpenFlags(flags int) (int, error) {
	const allowed = os.O_RDONLY | os.O_WRONLY | os.O_RDWR | os.O_CREATE | os.O_EXCL | os.O_TRUNC
	if flags&^allowed != 0 {
		return 0, fmt.Errorf("hostfs: unsupported open flags %#x: %w", flags&^allowed, fs.ErrInvalid)
	}
	return flags, nil
}

// OpenFile opens a regular file inside the pinned workspace. Unlike os.OpenFile
// it never follows links. A created file gets the virtual mode mode and owner
// 0:0.
func (w *Workspace) OpenFile(relPath string, flags int, mode uint32) (*os.File, error) {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return nil, err
	}
	if _, err := hostOpenFlags(flags); err != nil {
		return nil, err
	}
	if flags&os.O_CREATE != 0 {
		f, _, err := w.createFile(cleanRel, mode&0o7777, 0, 0)
		if err == nil || flags&os.O_EXCL != 0 || !errors.Is(err, fs.ErrExist) {
			return f, err
		}
	}
	if w.readOnly && flags&(os.O_WRONLY|os.O_RDWR|os.O_TRUNC) != 0 {
		return nil, ErrReadOnly
	}
	f, _, err := w.openRegular(cleanRel, flags)
	return f, err
}

// openRegular opens an existing regular file.
func (w *Workspace) openRegular(rel string, flags int) (*os.File, entry, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.openRegularLocked(rel, flags)
}

// openRegularLocked is openRegular for a caller that holds w.mu.
func (w *Workspace) openRegularLocked(rel string, flags int) (*os.File, entry, error) {
	e, err := w.lookupLocked(rel)
	if err != nil {
		return nil, entry{}, err
	}
	if e.isDir() {
		return nil, entry{}, errIsDir
	}
	if e.isSymlink() {
		return nil, entry{}, ErrPathTraversal
	}
	hostRel, err := w.hostPath(rel)
	if err != nil {
		return nil, entry{}, err
	}
	f, err := w.host.open(hostRel, flags&^(os.O_CREATE|os.O_EXCL), 0)
	if err != nil {
		return nil, entry{}, err
	}
	return f, e, nil
}

// createFile creates a regular file that must not exist and returns it open for
// reading and writing. Host files stay owner-only: guest permissions are
// virtual, and the sentry process must always be able to reopen them.
func (w *Workspace) createFile(rel string, perm, uid, gid uint32) (*os.File, entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.createFileLocked(rel, perm, uid, gid)
}

// createFileLocked is createFile for a caller that holds w.mu for writing.
func (w *Workspace) createFileLocked(rel string, perm, uid, gid uint32) (*os.File, entry, error) {
	if err := w.checkWritableLocked(rel); err != nil {
		return nil, entry{}, err
	}
	if rel == "." {
		return nil, entry{}, errIsDir
	}
	if err := w.checkMetaRoomLocked(rel); err != nil {
		return nil, entry{}, err
	}
	hostRel, leaf, err := w.createTargetLocked(rel)
	if err != nil {
		return nil, entry{}, err
	}
	f, err := w.host.open(hostRel, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, entry{}, err
	}
	info, err := w.host.fstat(f)
	if err != nil {
		_ = f.Close()
		_ = w.host.unlink(hostRel)
		return nil, entry{}, err
	}
	attr := POSIXAttr{Mode: linux.S_IFREG | perm&0o7777, UID: uid, GID: gid}
	w.meta[rel] = attr
	w.markDirtyLocked()
	parent, name := splitParent(rel)
	w.setAlt(parent, name, leaf)
	w.addDirNameLocked(parent, name, leaf)
	return f, entry{attr: attr, info: info}, nil
}

// WriteFile writes data to relPath inside the workspace root and records mode
// in .gvx_meta.
func (w *Workspace) WriteFile(relPath string, data []byte, mode uint32) error {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return err
	}
	f, _, err := w.createFile(cleanRel, mode, 0, 0)
	created := err == nil
	if errors.Is(err, fs.ErrExist) {
		if w.readOnly {
			return ErrReadOnly
		}
		f, _, err = w.openRegular(cleanRel, os.O_WRONLY|os.O_TRUNC)
	}
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if !created {
		return w.Chmod(cleanRel, mode)
	}
	return nil
}

// ReadFile reads the contents of relPath inside the workspace root.
func (w *Workspace) ReadFile(relPath string) ([]byte, error) {
	f, err := w.OpenFile(relPath, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()
	return io.ReadAll(f)
}

// MkdirAll creates a directory hierarchy inside the pinned workspace.
func (w *Workspace) MkdirAll(relPath string, mode uint32) error {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return err
	}
	if w.readOnly {
		return ErrReadOnly
	}
	if cleanRel == "." {
		return nil
	}
	cur := ""
	for _, part := range strings.Split(cleanRel, "/") {
		cur = joinRelPath(cur, part)
		err := w.mkdir(cur, mode, 0, 0)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		if errors.Is(err, fs.ErrExist) {
			e, lerr := w.lookup(cur)
			if lerr != nil {
				return lerr
			}
			if !e.isDir() {
				return errNotDir
			}
		}
	}
	return nil
}

// mkdir creates one directory with the virtual mode, owner, and group.
func (w *Workspace) mkdir(rel string, mode, uid, gid uint32) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkWritableLocked(rel); err != nil {
		return err
	}
	if rel == "." {
		return fs.ErrExist
	}
	if err := w.checkMetaRoomLocked(rel); err != nil {
		return err
	}
	hostRel, leaf, err := w.createTargetLocked(rel)
	if err != nil {
		return err
	}
	if err := w.host.mkdir(hostRel); err != nil {
		return err
	}
	w.meta[rel] = POSIXAttr{Mode: linux.S_IFDIR | mode&0o7777, UID: uid, GID: gid}
	w.markDirtyLocked()
	parent, name := splitParent(rel)
	w.setAlt(parent, name, leaf)
	w.addDirNameLocked(parent, name, leaf)
	return nil
}

// Mkdir creates a single directory at relPath inside the pinned workspace.
func (w *Workspace) Mkdir(relPath string, mode uint32) error {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return err
	}
	return w.mkdir(cleanRel, mode, 0, 0)
}

// Chmod updates the virtual POSIX mode bits for relPath. The host file mode
// never changes: the sentry process must keep access to the file.
func (w *Workspace) Chmod(relPath string, mode uint32) error {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return err
	}
	m := mode & 0o7777
	return w.setAttr(cleanRel, &m, nil, nil)
}

// Chown updates the virtual POSIX UID and GID for relPath.
func (w *Workspace) Chown(relPath string, uid, gid uint32) error {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return err
	}
	return w.setAttr(cleanRel, nil, &uid, &gid)
}

// setAttr changes virtual attributes. A hard-linked file keeps one set of
// attributes: setAttr copies the change to every other recorded path of the
// same host file.
func (w *Workspace) setAttr(rel string, mode, uid, gid *uint32) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkWritableLocked(rel); err != nil {
		return err
	}
	e, err := w.lookupLocked(rel)
	if err != nil {
		return err
	}
	now := time.Now().UnixNano()
	cur := e.attr
	if e.virtual {
		if uid != nil {
			cur.UID = *uid
		}
		if gid != nil {
			cur.GID = *gid
		}
		cur.Ctime = now
		w.meta[rel] = cur
		w.markDirtyLocked()
		return nil
	}
	if e.isSymlink() {
		// A host symlink has no record to hold ownership.
		return errNotPermitted
	}
	if mode != nil {
		cur.Mode = cur.Mode&linux.S_IFMT | *mode&0o7777
	}
	if uid != nil {
		cur.UID = *uid
	}
	if gid != nil {
		cur.GID = *gid
	}
	if err := w.checkMetaRoomLocked(rel); err != nil {
		return err
	}
	w.meta[rel] = cur
	if e.info.nlink > 1 && !e.isDir() {
		if err := w.propagateLinkAttrLocked(rel, e.info.id, cur); err != nil {
			return err
		}
	}
	w.markDirtyLocked()
	return nil
}

// propagateLinkAttrLocked copies attr to every other recorded path that names
// the same host file.
func (w *Workspace) propagateLinkAttrLocked(skip string, id hostID, attr POSIXAttr) error {
	for k, m := range w.meta {
		if k == skip || m.Symlink != "" {
			continue
		}
		hostRel, err := w.hostPath(k)
		if err != nil {
			continue
		}
		info, err := w.host.lstat(hostRel)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, errNotDir) {
				continue
			}
			return err
		}
		if info.id == id && info.kind == hostKindRegular {
			w.meta[k] = attr
		}
	}
	return nil
}

// Symlink records a guest symbolic link in .gvx_meta. The host never receives
// a link. The target may be absolute or climb above the workspace, because the
// Sentry VFS resolves it in the guest namespace. Only an empty target and a
// target with a NUL byte fail.
func (w *Workspace) Symlink(target, linkRelPath string) error {
	cleanLink, err := CleanRelativePath(linkRelPath)
	if err != nil {
		return err
	}
	return w.symlink(target, cleanLink, 0, 0)
}

func (w *Workspace) symlink(target, rel string, uid, gid uint32) error {
	if err := validateGuestSymlinkTarget(target); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkWritableLocked(rel); err != nil {
		return err
	}
	if rel == "." {
		return fs.ErrExist
	}
	if err := w.checkParentDirLocked(rel); err != nil {
		return err
	}
	if err := w.checkMetaRoomLocked(rel); err != nil {
		return err
	}
	if _, _, err := w.createTargetLocked(rel); err != nil {
		return err
	}
	now := time.Now().UnixNano()
	w.meta[rel] = POSIXAttr{
		Mode:    linux.S_IFLNK | 0o777,
		UID:     uid,
		GID:     gid,
		Symlink: target,
		Atime:   now,
		Mtime:   now,
		Ctime:   now,
	}
	w.markDirtyLocked()
	return nil
}

func validateSymlinkTarget(linkRelPath, target string) error {
	targetSlash := target
	if hostSeparatorIsBackslash {
		targetSlash = strings.ReplaceAll(target, "\\", "/")
	}
	if strings.HasPrefix(targetSlash, "/") {
		return ErrPathTraversal
	}
	linkDir := path.Dir(linkRelPath)
	joined := path.Clean(path.Join(linkDir, targetSlash))
	if joined == ".." || strings.HasPrefix(joined, "../") || path.IsAbs(joined) {
		return ErrPathTraversal
	}
	return nil
}

// Readlink returns the symlink target for relPath from .gvx_meta or the host OS.
func (w *Workspace) Readlink(relPath string) (string, error) {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return "", err
	}
	e, err := w.lookup(cleanRel)
	if err != nil {
		return "", err
	}
	if !e.isSymlink() {
		return "", fs.ErrInvalid
	}
	return e.attr.Symlink, nil
}

// Stat returns the combined host FileInfo and virtual POSIXAttr for relPath.
func (w *Workspace) Stat(relPath string) (POSIXAttr, int64, error) {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return POSIXAttr{}, 0, err
	}
	e, err := w.lookup(cleanRel)
	if err != nil {
		return POSIXAttr{}, 0, err
	}
	return e.attr, e.info.size, nil
}

// Rename atomically renames oldRel to newRel inside the workspace using POSIX
// rename semantics (even when oldRel or newRel has open file descriptors) and
// updates .gvx_meta.
func (w *Workspace) Rename(oldRel, newRel string) error {
	cleanOld, err := CleanRelativePath(oldRel)
	if err != nil {
		return err
	}
	cleanNew, err := CleanRelativePath(newRel)
	if err != nil {
		return err
	}
	return w.rename(cleanOld, cleanNew)
}

// rename moves oldRel to newRel with POSIX semantics. It checks the type rules
// before touching the host, so the result is the same on every platform.
func (w *Workspace) rename(oldRel, newRel string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.renameLocked(oldRel, newRel)
}

// renameLocked is rename for a caller that holds w.mu for writing.
func (w *Workspace) renameLocked(oldRel, newRel string) error {
	if err := w.checkWritableLocked(oldRel, newRel); err != nil {
		return err
	}
	if oldRel == "." || newRel == "." {
		return fs.ErrInvalid
	}
	src, err := w.lookupLocked(oldRel)
	if err != nil {
		return err
	}
	if oldRel == newRel {
		return nil
	}
	if src.isDir() && strings.HasPrefix(newRel, oldRel+"/") {
		return errInvalidMove
	}
	if err := w.checkParentDirLocked(newRel); err != nil {
		return err
	}
	dst, dstProbe, dstErr := w.lookupProbeLocked(newRel)
	dstExists := dstErr == nil
	if dstErr != nil && !errors.Is(dstErr, fs.ErrNotExist) {
		return dstErr
	}

	oldParent, oldName := splitParent(oldRel)
	newParent, newName := splitParent(newRel)
	var srcPath string
	if !src.virtual {
		if srcPath, err = w.hostPath(oldRel); err != nil {
			return err
		}
	}
	dstLeaf := dstProbe.create
	if !dstExists && dstProbe.collided {
		switch {
		case dstProbe.occupant != "" && !src.virtual && strings.EqualFold(oldParent, newParent) && dstProbe.occupant == leafOf(srcPath):
			// Only the case of the name changes: the entry keeps the plain
			// form of the new name.
			if dstLeaf, err = w.codec.leafForm(newName); err != nil {
				return err
			}
		case dstProbe.occupant == "" && !strings.EqualFold(oldRel, newRel):
			// The host would replace the file that holds the other-case name,
			// which the guest sees as a different file.
			return fs.ErrExist
		}
	}
	if dstExists || dstLeaf == "" {
		if dstLeaf, err = w.hostLeaf(newParent, newName); err != nil {
			return err
		}
	}
	newHostDir, err := w.hostPath(newParent)
	if err != nil {
		return err
	}
	dstPath := hostChild(newHostDir, dstLeaf)

	if dstExists {
		if !src.virtual && !dst.virtual && src.info.id == dst.info.id && !src.isDir() {
			// Two names of one file: POSIX rename succeeds and changes nothing.
			return nil
		}
		switch {
		case src.isDir() && !dst.isDir():
			return errNotDir
		case !src.isDir() && dst.isDir():
			return errIsDir
		case src.isDir():
			if err := w.purgeEmptyDirLocked(newRel, dstPath); err != nil {
				return err
			}
		}
	}

	var quiesced *quiescedTree
	if src.virtual {
		if dstExists && !dst.virtual {
			if err := w.host.unlink(dstPath); err != nil {
				return err
			}
			w.removeDirNameLocked(newParent, newName, dstLeaf)
		}
	} else {
		// Windows refuses to rename a directory with an open handle below it,
		// and to replace one. The next lookup reopens the handles.
		if src.isDir() {
			w.closeSubtreeHandlesLocked(oldRel)
		}
		if dstExists && dst.isDir() && !dst.virtual {
			w.closeSubtreeHandlesLocked(newRel)
		}
		if dstExists && dst.isDir() && !dst.virtual && !hostRenameReplacesDir {
			if err := w.host.rmdir(dstPath); err != nil {
				return err
			}
		}
		// A host that locks an open directory against a move needs the files
		// below the directory closed during the rename. They reopen after the
		// stored names moved.
		if src.isDir() {
			quiesced = w.handles.quiesce(oldRel)
		}
		if err := w.host.rename(srcPath, dstPath); err != nil {
			_ = quiesced.finish(false, "")
			return err
		}
		w.removeDirNameLocked(oldParent, oldName, leafOf(srcPath))
		w.addDirNameLocked(newParent, newName, dstLeaf)
		if src.isDir() {
			w.dropDirNamesLocked(oldRel)
		}
		if dstExists && dst.isDir() {
			w.dropDirNamesLocked(newRel)
		}
	}

	// The stored names move with the entries. The destination entry and its
	// subtree die, the subtree of the source moves, and the moved entry gets
	// the stored name of its new name.
	w.dropAltTree(newRel)
	w.moveAltTree(oldRel, newRel)
	w.dropAlt(oldParent, oldName)
	if !src.virtual {
		w.setAlt(newParent, newName, dstLeaf)
		// Open handles follow their files to the new names. A replaced file
		// keeps its open handles, which no longer name any path.
		if src.isDir() {
			_ = quiesced.finish(true, newRel)
		} else {
			if dstExists {
				w.handles.detach(newRel)
			}
			w.handles.moveFile(oldRel, newRel)
		}
	}

	// Table update: the destination record dies, the source record and every
	// record below it move.
	delete(w.meta, newRel)
	if m, ok := w.meta[oldRel]; ok {
		delete(w.meta, oldRel)
		w.meta[newRel] = m
	}
	prefix := oldRel + "/"
	var moved []string
	for k := range w.meta {
		if strings.HasPrefix(k, prefix) {
			moved = append(moved, k)
		}
	}
	for _, k := range moved {
		w.meta[newRel+"/"+strings.TrimPrefix(k, prefix)] = w.meta[k]
		delete(w.meta, k)
	}
	w.markDirtyLocked()
	return nil
}

// link creates a hard link. The new path shares the host file and its
// attributes with oldRel.
func (w *Workspace) link(oldRel, newRel string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkWritableLocked(oldRel, newRel); err != nil {
		return err
	}
	src, err := w.lookupLocked(oldRel)
	if err != nil {
		return err
	}
	if src.isDir() || src.virtual || src.isSymlink() {
		return errNotPermitted
	}
	if err := w.checkParentDirLocked(newRel); err != nil {
		return err
	}
	srcPath, err := w.hostPath(oldRel)
	if err != nil {
		return err
	}
	if err := w.checkMetaRoomLocked(newRel); err != nil {
		return err
	}
	dstPath, leaf, err := w.createTargetLocked(newRel)
	if err != nil {
		return err
	}
	if err := w.host.link(srcPath, dstPath); err != nil {
		return err
	}
	w.meta[newRel] = src.attr
	w.markDirtyLocked()
	parent, name := splitParent(newRel)
	w.setAlt(parent, name, leaf)
	w.addDirNameLocked(parent, name, leaf)
	return nil
}

// Unlink removes a non-directory from the workspace using POSIX delete
// semantics (even when relPath has open handles) and updates .gvx_meta.
func (w *Workspace) Unlink(relPath string) error {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return err
	}
	return w.unlink(cleanRel)
}

func (w *Workspace) unlink(rel string) error {
	_, err := w.unlinkLast(rel)
	return err
}

// unlinkLast is unlink that also reports whether the call removed the last
// name of the file. A file with another hard link, and a virtual symbolic
// link, report false.
func (w *Workspace) unlinkLast(rel string) (last bool, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkWritableLocked(rel); err != nil {
		return false, err
	}
	if rel == "." {
		return false, errIsDir
	}
	e, err := w.lookupLocked(rel)
	if err != nil {
		return false, err
	}
	if e.isDir() {
		return false, errIsDir
	}
	if !e.virtual {
		hostRel, err := w.hostPath(rel)
		if err != nil {
			return false, err
		}
		if err := w.host.unlink(hostRel); err != nil {
			return false, err
		}
		last = e.info.nlink <= 1
		w.handles.detach(rel)
		parent, name := splitParent(rel)
		w.removeDirNameLocked(parent, name, leafOf(hostRel))
		w.dropAlt(parent, name)
	}
	delete(w.meta, rel)
	w.markDirtyLocked()
	return last, nil
}

// Rmdir removes an empty directory at relPath inside the pinned workspace.
func (w *Workspace) Rmdir(relPath string) error {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return err
	}
	return w.rmdir(cleanRel)
}

func (w *Workspace) rmdir(rel string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkWritableLocked(rel); err != nil {
		return err
	}
	if rel == "." {
		return fs.ErrInvalid
	}
	e, err := w.lookupLocked(rel)
	if err != nil {
		return err
	}
	if !e.isDir() {
		return errNotDir
	}
	hostRel, err := w.hostPath(rel)
	if err != nil {
		return err
	}
	if err := w.purgeEmptyDirLocked(rel, hostRel); err != nil {
		return err
	}
	// Windows refuses to remove a directory that has an open handle.
	w.closeSubtreeHandlesLocked(rel)
	if err := w.host.rmdir(hostRel); err != nil {
		return err
	}
	delete(w.meta, rel)
	w.markDirtyLocked()
	parent, name := splitParent(rel)
	w.removeDirNameLocked(parent, name, leafOf(hostRel))
	w.dropDirNamesLocked(rel)
	w.dropAltTree(rel)
	return nil
}

// Truncate changes the size of the regular file at relPath.
func (w *Workspace) Truncate(relPath string, size int64) error {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return err
	}
	if w.readOnly {
		return ErrReadOnly
	}
	f, _, err := w.openRegular(cleanRel, os.O_WRONLY)
	if err != nil {
		return err
	}
	truncErr := f.Truncate(size)
	closeErr := f.Close()
	return errors.Join(truncErr, closeErr)
}

// syncDir flushes the host directory that holds rel's children, so a
// completed create, rename, or unlink survives a host crash.
func (w *Workspace) syncDir(rel string) error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return os.ErrClosed
	}
	hostRel, err := w.hostPath(rel)
	if err != nil {
		return err
	}
	return w.host.syncDir(hostRel)
}

// chtimes sets host timestamps of a host file, or the recorded timestamps of
// a virtual symlink. A nil time stays unchanged.
func (w *Workspace) chtimes(rel string, atime, mtime *time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkWritableLocked(rel); err != nil {
		return err
	}
	e, err := w.lookupLocked(rel)
	if err != nil {
		return err
	}
	if e.virtual {
		m := e.attr
		if atime != nil {
			m.Atime = atime.UnixNano()
		}
		if mtime != nil {
			m.Mtime = mtime.UnixNano()
		}
		m.Ctime = time.Now().UnixNano()
		w.meta[rel] = m
		w.markDirtyLocked()
		return nil
	}
	hostRel, err := w.hostPath(rel)
	if err != nil {
		return err
	}
	return w.host.chtimes(hostRel, atime, mtime)
}

// dirListing is one directory entry with its type and the host inode number
// when the host layer reports it.
type dirListing struct {
	name    string
	kind    hostKind
	ino     uint64
	virtual bool
	// leaf is the stored host name. It is empty for a virtual symlink.
	leaf string
	// special is the file type of a socket, FIFO, or device record, or zero.
	special uint32
}

// listDir returns the visible children of the directory at rel, host entries
// and virtual symlinks, sorted by name.
func (w *Workspace) listDir(rel string) ([]dirListing, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out, _, err := w.listDirLocked(rel)
	return out, err
}

// listDirLocked is listDir for a caller that holds w.mu. It also returns the
// stored names of the host clutter files that the listing hides. The listing
// teaches the alternate-name table the stored name of every entry whose guest
// name differs from it.
func (w *Workspace) listDirLocked(rel string) ([]dirListing, []string, error) {
	if w.closed {
		return nil, nil, os.ErrClosed
	}
	hostDir, err := w.hostPath(rel)
	if err != nil {
		return nil, nil, err
	}
	entries, err := w.host.readDir(hostDir)
	if err != nil {
		return nil, nil, err
	}
	var clutter []string
	byName := make(map[string]dirListing, len(entries))
	for _, e := range entries {
		if rel == "." && isReservedPath(e.name) {
			continue
		}
		if e.kind == hostKindOther || w.hiddenByName(e.name) {
			// An internal file has no owner while the guest sees an empty
			// directory, so the removal of the directory unlinks it. A guest
			// that holds an unnamed temporary file open keeps its inode.
			if e.kind == hostKindRegular && isEphemeralName(e.name) {
				clutter = append(clutter, e.name)
			}
			continue
		}
		if w.clutter.candidate(e.name) {
			info := hostInfo{kind: e.kind}
			if e.kind == hostKindRegular && w.clutter.needsContent(e.name) {
				fi, err := w.host.lstat(hostChild(hostDir, e.name))
				if err != nil {
					continue
				}
				info = fi
			}
			if w.isClutterLocked(rel, e.name, info) {
				clutter = append(clutter, e.name)
				continue
			}
		}
		guest := w.listName(rel, e.name)
		if e.kind == hostKindSymlink {
			full := joinRelPath(rel, guest)
			if _, ok := w.meta[full]; ok {
				continue
			}
			target, err := w.host.readlink(hostChild(hostDir, e.name))
			if err != nil || validateSymlinkTarget(full, target) != nil {
				continue
			}
		}
		if old, dup := byName[guest]; dup && old.leaf == guest {
			// Two host names show as one guest name. The plain name wins.
			continue
		}
		if guest != e.name {
			w.setAlt(rel, guest, e.name)
		}
		l := dirListing{name: guest, kind: e.kind, ino: e.ino, leaf: e.name}
		if e.kind == hostKindRegular {
			l.special = specialFileType(w.meta[joinRelPath(rel, guest)].Mode)
		}
		byName[guest] = l
	}
	prefix := rel + "/"
	if rel == "." {
		prefix = ""
	}
	for k, m := range w.meta {
		if m.Symlink == "" || !strings.HasPrefix(k, prefix) {
			continue
		}
		rest := k[len(prefix):]
		if rest == "" || strings.Contains(rest, "/") {
			continue
		}
		byName[rest] = dirListing{name: rest, kind: hostKindSymlink, virtual: true}
	}
	out := make([]dirListing, 0, len(byName))
	for _, l := range byName {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, clutter, nil
}

// ListEntries returns the sorted workspace-relative paths of all files,
// directories, and .gvx_meta symlinks inside the workspace (excluding .gvx_meta).
func (w *Workspace) ListEntries() ([]string, error) {
	var out []string
	var walk func(rel string) error
	walk = func(rel string) error {
		children, err := w.listDir(rel)
		if err != nil {
			return err
		}
		for _, c := range children {
			full := joinRelPath(rel, c.name)
			out = append(out, full)
			if c.kind == hostKindDir {
				if err := walk(full); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk("."); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// DirChild describes a direct child entry of a workspace directory.
type DirChild struct {
	Name string
	Attr POSIXAttr
	Size int64
}

// ReadDirChildren returns the sorted direct children of the directory at relPath.
func (w *Workspace) ReadDirChildren(relPath string) ([]DirChild, error) {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return nil, err
	}
	children, err := w.listDir(cleanRel)
	if err != nil {
		return nil, err
	}
	out := make([]DirChild, 0, len(children))
	for _, c := range children {
		e, err := w.lookup(joinRelPath(cleanRel, c.name))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		out = append(out, DirChild{Name: c.name, Attr: e.attr, Size: e.info.size})
	}
	return out, nil
}
