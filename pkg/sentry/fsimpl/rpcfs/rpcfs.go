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

// Package rpcfs implements a VFS2 filesystem backed by a remote client over the
// gvx-ctrl/2 control socket. It lets an unlocked client expose a host directory
// to a locked-down sandbox without relaxing host lockdown policies.
package rpcfs

import (
	goContext "context"
	"errors"
	"hash/fnv"
	"io"
	"path"
	"strings"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/socket/unix/transport"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/sync"
	"z.gfire.dev/gvx/pkg/usermem"
)

// Name is the VFS filesystem type name reported in /proc/mounts.
const Name = "rpcfs"

const (
	rpcfsMagic       = 0x72706366 // "rpcf"
	defaultChunkSize = 64 << 10
)

// Options configures an rpcfs filesystem instance.
type Options struct {
	Label      string
	ReadOnly   bool
	SingleFile bool
}

// Entry describes one file or directory returned by the remote client.
type Entry struct {
	Name       string
	Ino        uint64
	Mode       uint32
	Size       int64
	Nlink      uint32
	UID        uint32
	GID        uint32
	AtimeNS    int64
	MtimeNS    int64
	CtimeNS    int64
	LinkTarget string
}

// NotifyEvent describes one host-side change reported by a WatchClient.
type NotifyEvent struct {
	Path   string
	Name   string
	Mask   uint32
	Cookie uint32
}

// ChunkSizer is an optional extension of Client that reports the maximum raw
// payload bytes per Read or Write RPC supported by the transport.
type ChunkSizer interface {
	MaxChunkBytes() int64
}

// WatchClient is an optional extension of Client that relays host filesystem
// change notifications to guest inotify watchers.
type WatchClient interface {
	Watch(ctx goContext.Context, relPath string) error
	Unwatch(ctx goContext.Context, relPath string) error
	SetNotifyHandler(fn func(NotifyEvent))
}

// Client executes filesystem RPCs against an unlocked host peer. Returned
// errors must already be linuxerr values (such as ENOENT, EEXIST, EACCES, EIO).
type Client interface {
	Stat(ctx goContext.Context, relPath string) (Entry, error)
	Readdir(ctx goContext.Context, relPath string) ([]Entry, error)
	Read(ctx goContext.Context, relPath string, offset, length int64) ([]byte, error)
	Write(ctx goContext.Context, relPath string, offset int64, data []byte) (int64, error)
	Create(ctx goContext.Context, relPath string, mode, flags uint32) (Entry, error)
	Mkdir(ctx goContext.Context, relPath string, mode uint32) error
	Unlink(ctx goContext.Context, relPath string) error
	Rmdir(ctx goContext.Context, relPath string) error
	Rename(ctx goContext.Context, oldRel, newRel string) error
	Truncate(ctx goContext.Context, relPath string, size int64) error
	Chmod(ctx goContext.Context, relPath string, mode uint32) error
	Utimens(ctx goContext.Context, relPath string, atimeNS, mtimeNS int64, setAtime, setMtime bool) error
	Readlink(ctx goContext.Context, relPath string) (string, error)
	Symlink(ctx goContext.Context, target, linkRel string) error
	Close() error
}

// callRPC bridges Sentry task interruption (signals, SIGKILL, Pause) to a
// cancelable Go context for remote filesystem RPCs.
func callRPC[T any](ctx context.Context, fn func(goContext.Context) (T, error)) (T, error) {
	rpcCtx, cancel := goContext.WithCancel(goContext.Background())
	done := make(chan struct{})
	var (
		val     T
		callErr error
	)
	go func() {
		val, callErr = fn(rpcCtx)
		close(done)
	}()
	if err := ctx.Block(done); err != nil {
		cancel()
		var zero T
		if errors.Is(err, linuxerr.ErrInterrupted) {
			return zero, linuxerr.ERESTARTSYS
		}
		return zero, linuxerr.EINTR
	}
	cancel()
	return val, callErr
}

func callRPCErr(ctx context.Context, fn func(goContext.Context) error) error {
	_, err := callRPC(ctx, func(c goContext.Context) (struct{}, error) {
		return struct{}{}, fn(c)
	})
	return err
}

// FilesystemType implements vfs.FilesystemType for rpcfs.
type FilesystemType struct{}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string { return Name }

// Release implements vfs.FilesystemType.Release.
func (FilesystemType) Release(context.Context) {}

// GetFilesystem rejects guest mount(2) attempts; rpcfs mounts are created only
// internally via NewFilesystem.
func (FilesystemType) GetFilesystem(context.Context, *vfs.VirtualFilesystem, *auth.Credentials, string, vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	return nil, nil, linuxerr.EPERM
}

// NewFilesystem constructs a directory-rooted rpcfs filesystem backed by
// client. When readOnly is true, all mutating operations fail with EROFS
// regardless of VFS mount flags. The caller owns one reference on both the
// returned Filesystem and root Dentry.
func NewFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, client Client, label string, readOnly bool) (*vfs.Filesystem, *vfs.Dentry, error) {
	return NewFilesystemWithOptions(ctx, vfsObj, client, Options{
		Label:    label,
		ReadOnly: readOnly,
	})
}

// NewFilesystemWithOptions constructs an rpcfs filesystem backed by client with
// explicit directory or single-file mount options.
func NewFilesystemWithOptions(ctx context.Context, vfsObj *vfs.VirtualFilesystem, client Client, opts Options) (*vfs.Filesystem, *vfs.Dentry, error) {
	if client == nil {
		return nil, nil, linuxerr.EINVAL
	}
	rootEntry := Entry{
		Ino:   1,
		Mode:  linux.S_IFDIR | 0o755,
		Nlink: 2,
	}
	if opts.SingleFile {
		rootEntry = Entry{
			Ino:   1,
			Mode:  linux.S_IFREG | 0o644,
			Nlink: 1,
		}
	}
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, nil, err
	}
	maxChunk := int64(defaultChunkSize)
	if cs, ok := client.(ChunkSizer); ok {
		if n := cs.MaxChunkBytes(); n >= 512 {
			maxChunk = n
		}
	}
	watchCtx, watchCancel := goContext.WithCancel(goContext.Background())
	fs := &filesystem{
		client:      client,
		label:       opts.Label,
		readOnly:    opts.ReadOnly,
		singleFile:  opts.SingleFile,
		devMinor:    devMinor,
		maxChunk:    maxChunk,
		watchCtx:    watchCtx,
		watchCancel: watchCancel,
		watched:     make(map[*dentry]string),
		watchSynced: make(map[string]struct{}),
	}
	if wc, ok := client.(WatchClient); ok {
		fs.watcher = wc
		fs.watchNotify = make(chan struct{}, 1)
		fs.watchDone = make(chan struct{})
		wc.SetNotifyHandler(fs.deliverNotify)
		go fs.watchLoop()
	}
	fs.vfsfs.Init(vfsObj, FilesystemType{}, fs)
	fs.root = fs.newDentry(nil, "", rootEntry)
	// One ref for fs.root, one ref returned to the caller for the mount.
	fs.root.refs.Store(2)
	return &fs.vfsfs, &fs.root.vfsd, nil
}

type filesystem struct {
	vfsfs      vfs.Filesystem
	client     Client
	watcher    WatchClient
	label      string
	readOnly   bool
	singleFile bool
	devMinor   uint32
	maxChunk   int64

	// mu protects the dentry child maps. Lock order: fs.mu before fs.ancestryMu.
	mu sync.Mutex
	// ancestryMu is a leaf lock protecting parent/name/dead for VFS callbacks
	// (PrependPath, IsDescendant, InotifyWithParent) and dynamic path() walks.
	ancestryMu sync.RWMutex
	root       *dentry

	// watchOpMu serializes host Watch/Unwatch RPCs across AdmitInotifyWatch and
	// watchLoop. Never hold watchOpMu inside VFS/Inotify callbacks (Watches,
	// OnZeroWatches). Lock order: watchOpMu before watchMu.
	watchOpMu sync.Mutex
	// watchMu is a leaf lock protecting watched, watchSynced, and watchClosed.
	// Never acquire fs.mu, fs.ancestryMu, watchOpMu, or Watches locks while
	// holding watchMu.
	watchMu     sync.Mutex
	watched     map[*dentry]string
	watchSynced map[string]struct{}
	watchClosed bool
	watchCtx    goContext.Context
	watchCancel goContext.CancelFunc
	watchNotify chan struct{}
	watchDone   chan struct{}
}

func (fs *filesystem) maxChunkSize() int64 {
	if fs.maxChunk > 0 {
		return fs.maxChunk
	}
	return defaultChunkSize
}

func (fs *filesystem) signalWatchReconcile() {
	if fs.watcher == nil {
		return
	}
	select {
	case fs.watchNotify <- struct{}{}:
	default:
	}
}

func (fs *filesystem) watchLoop() {
	defer close(fs.watchDone)
	for {
		select {
		case <-fs.watchCtx.Done():
			return
		case <-fs.watchNotify:
			fs.reconcileWatches()
		}
	}
}

func (fs *filesystem) reconcileWatches() {
	fs.watchOpMu.Lock()
	defer fs.watchOpMu.Unlock()

	for {
		if fs.watchCtx.Err() != nil {
			return
		}
		var (
			toUnwatch []string
			toWatch   []string
		)
		fs.watchMu.Lock()
		if fs.watchClosed {
			fs.watchMu.Unlock()
			return
		}
		desired := make(map[string]struct{}, len(fs.watched))
		for _, rel := range fs.watched {
			desired[rel] = struct{}{}
		}
		for rel := range fs.watchSynced {
			if _, want := desired[rel]; !want {
				toUnwatch = append(toUnwatch, rel)
			}
		}
		for rel := range desired {
			if _, have := fs.watchSynced[rel]; !have {
				toWatch = append(toWatch, rel)
			}
		}
		fs.watchMu.Unlock()

		if len(toUnwatch) == 0 && len(toWatch) == 0 {
			return
		}
		for _, rel := range toUnwatch {
			if fs.watchCtx.Err() != nil {
				return
			}
			callCtx, cancel := goContext.WithTimeout(fs.watchCtx, 5*time.Second)
			_ = fs.watcher.Unwatch(callCtx, rel)
			cancel()
			fs.watchMu.Lock()
			delete(fs.watchSynced, rel)
			fs.watchMu.Unlock()
		}
		for _, rel := range toWatch {
			if fs.watchCtx.Err() != nil {
				return
			}
			callCtx, cancel := goContext.WithTimeout(fs.watchCtx, 5*time.Second)
			err := fs.watcher.Watch(callCtx, rel)
			cancel()
			fs.watchMu.Lock()
			if err == nil {
				fs.watchSynced[rel] = struct{}{}
			} else {
				// Avoid spinning on a permanently rejected/missing watch path.
				for d, wRel := range fs.watched {
					if wRel == rel {
						delete(fs.watched, d)
					}
				}
			}
			fs.watchMu.Unlock()
		}
	}
}

func (fs *filesystem) unwatchDentry(d *dentry) {
	if fs.watcher == nil {
		return
	}
	fs.watchMu.Lock()
	_, ok := fs.watched[d]
	if ok {
		delete(fs.watched, d)
	}
	closed := fs.watchClosed
	fs.watchMu.Unlock()
	if ok && !closed {
		fs.signalWatchReconcile()
	}
}

func (fs *filesystem) unwatchDentries(list []*dentry) {
	if fs.watcher == nil || len(list) == 0 {
		return
	}
	changed := false
	fs.watchMu.Lock()
	closed := fs.watchClosed
	for _, d := range list {
		if _, ok := fs.watched[d]; ok {
			delete(fs.watched, d)
			changed = true
		}
	}
	fs.watchMu.Unlock()
	if changed && !closed {
		fs.signalWatchReconcile()
	}
}

func (fs *filesystem) rebaseWatchedPaths(oldRel, newRel string) {
	if fs.watcher == nil || oldRel == newRel {
		return
	}
	prefix := oldRel + "/"
	changed := false
	fs.watchMu.Lock()
	closed := fs.watchClosed
	if !closed && len(fs.watched) > 0 {
		for d, rel := range fs.watched {
			switch {
			case rel == oldRel:
				fs.watched[d] = newRel
				changed = true
			case strings.HasPrefix(rel, prefix):
				fs.watched[d] = newRel + rel[len(oldRel):]
				changed = true
			}
		}
	}
	fs.watchMu.Unlock()
	if changed && !closed {
		fs.signalWatchReconcile()
	}
}

func cleanNotifyPath(raw string) string {
	p := path.Clean("/" + strings.TrimPrefix(raw, "/"))
	rel := strings.TrimPrefix(p, "/")
	if rel == "" {
		return "."
	}
	return rel
}

func (fs *filesystem) deliverNotify(ev NotifyEvent) {
	rel := cleanNotifyPath(ev.Path)
	var targets []*dentry
	fs.watchMu.Lock()
	if !fs.watchClosed {
		for d, wRel := range fs.watched {
			if wRel == rel && d.TryIncRef() {
				targets = append(targets, d)
			}
		}
	}
	fs.watchMu.Unlock()
	if len(targets) == 0 {
		return
	}
	ctx := context.Background()
	unlinked := ev.Name == "" && ev.Mask&linux.IN_DELETE_SELF != 0
	for _, d := range targets {
		fs.ancestryMu.RLock()
		dead := d.dead
		fs.ancestryMu.RUnlock()
		if !dead {
			d.watches.Notify(ctx, ev.Name, ev.Mask, ev.Cookie, vfs.InodeEvent, unlinked)
		}
		d.DecRef(ctx)
	}
}

func (fs *filesystem) isReadOnly(mnt *vfs.Mount) bool {
	return fs.readOnly || (mnt != nil && mnt.ReadOnly())
}

// MountSource implements vfs.MountSourceProvider.
func (fs *filesystem) MountSource() string {
	if fs.label != "" {
		return "rpcfs:" + fs.label
	}
	return "rpcfs"
}

// detachSubtreeLocked detaches d and all of its cached descendants from their
// child maps, marks them dead under ancestryMu, and appends them to out for
// post-unlock DecRef.
//
// Preconditions: fs.mu must be held; fs.ancestryMu must not be held.
func (fs *filesystem) detachSubtreeLocked(d *dentry, out *[]*dentry) {
	if d == nil {
		return
	}
	var collect func(cur *dentry)
	collect = func(cur *dentry) {
		for name, child := range cur.children {
			delete(cur.children, name)
			collect(child)
			*out = append(*out, child)
		}
		cur.children = nil
	}
	start := len(*out)
	collect(d)
	*out = append(*out, d)
	fs.ancestryMu.Lock()
	for _, node := range (*out)[start:] {
		node.dead = true
	}
	fs.ancestryMu.Unlock()
}

// isAncestorLocked reports whether anc is equal to or an ancestor of desc.
//
// Preconditions: fs.ancestryMu must be held for reading or writing.
func isAncestorLocked(anc, desc *dentry) bool {
	for cur := desc; cur != nil; cur = cur.parent {
		if cur == anc {
			return true
		}
	}
	return false
}

func (fs *filesystem) Release(ctx context.Context) {
	fs.watchMu.Lock()
	fs.watchClosed = true
	clear(fs.watched)
	fs.watchMu.Unlock()
	if fs.watcher != nil {
		fs.watcher.SetNotifyHandler(nil)
	}
	if fs.watchCancel != nil {
		fs.watchCancel()
	}
	if fs.watchDone != nil {
		<-fs.watchDone
	}

	var toDecRef []*dentry
	fs.mu.Lock()
	root := fs.root
	fs.root = nil
	if root != nil {
		for name, child := range root.children {
			delete(root.children, name)
			fs.detachSubtreeLocked(child, &toDecRef)
		}
		root.children = nil
	}
	fs.mu.Unlock()

	for _, child := range toDecRef {
		child.DecRef(ctx)
	}
	if root != nil {
		root.DecRef(ctx)
	}
	_ = fs.client.Close()
	fs.vfsfs.VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
}

func (fs *filesystem) Sync(context.Context) error             { return nil }
func (fs *filesystem) DrainDentryCache(context.Context) error { return nil }
func (fs *filesystem) MountOptions() string                   { return "" }

type dentry struct {
	vfsd vfs.Dentry

	refs atomicbitops.Int64
	fs   *filesystem

	// Protected by fs.ancestryMu (writers hold both fs.mu and fs.ancestryMu).
	parent *dentry
	name   string
	dead   bool

	// Protected by fs.mu.
	children map[string]*dentry

	mode    atomicbitops.Uint32
	uid     atomicbitops.Uint32
	gid     atomicbitops.Uint32
	ino     atomicbitops.Uint64
	watches vfs.Watches
	locks   vfs.FileLocks
}

func synthIno(rel string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(rel))
	v := h.Sum64()
	if v == 0 {
		return 1
	}
	return v
}

func (fs *filesystem) newDentry(parent *dentry, name string, e Entry) *dentry {
	rel := "."
	if parent != nil {
		rel = joinRel(parent.path(), name)
	}
	ino := e.Ino
	if ino == 0 {
		ino = synthIno(rel)
	}
	d := &dentry{
		fs:     fs,
		parent: parent,
		name:   name,
	}
	d.mode.Store(e.Mode)
	d.uid.Store(e.UID)
	d.gid.Store(e.GID)
	d.ino.Store(ino)
	d.vfsd.Init(d)
	return d
}

func (d *dentry) updateAttr(e Entry) {
	d.mode.Store(e.Mode)
	d.uid.Store(e.UID)
	d.gid.Store(e.GID)
	if e.Ino != 0 {
		d.ino.Store(e.Ino)
	}
}

func (d *dentry) checkPermissions(creds *auth.Credentials, ats vfs.AccessTypes) error {
	return vfs.GenericCheckPermissions(creds, ats, linux.FileMode(d.mode.Load()), nil, auth.KUID(d.uid.Load()), auth.KGID(d.gid.Load()))
}

func (d *dentry) IncRef() {
	d.refs.Add(1)
}

func (d *dentry) TryIncRef() bool {
	for {
		r := d.refs.Load()
		if r <= 0 {
			return false
		}
		if d.refs.CompareAndSwap(r, r+1) {
			return true
		}
	}
}

func (d *dentry) DecRef(ctx context.Context) {
	if d.refs.Add(-1) == 0 {
		d.fs.unwatchDentry(d)
		d.watches.HandleDeletion(ctx)
	}
}

func (d *dentry) InotifyWithParent(ctx context.Context, events, cookie uint32, et vfs.EventType) {
	if d.isDir() {
		events |= linux.IN_ISDIR
	}
	d.fs.ancestryMu.RLock()
	parent := d.parent
	name := d.name
	dead := d.dead
	d.fs.ancestryMu.RUnlock()
	if parent != nil && name != "" {
		parent.watches.Notify(ctx, name, events, cookie, et, dead)
	}
	d.watches.Notify(ctx, "", events, cookie, et, dead)
}

// AdmitInotifyWatch registers a host watch synchronously before inotify_add_watch(2)
// returns so the host peer captures its baseline before guest callers proceed.
func (d *dentry) AdmitInotifyWatch() error {
	fs := d.fs
	if fs.watcher == nil {
		return nil
	}
	rel := d.path()
	fs.watchOpMu.Lock()
	defer fs.watchOpMu.Unlock()

	fs.watchMu.Lock()
	if fs.watchClosed {
		fs.watchMu.Unlock()
		return nil
	}
	if _, synced := fs.watchSynced[rel]; synced {
		fs.watched[d] = rel
		fs.watchMu.Unlock()
		return nil
	}
	fs.watchMu.Unlock()

	callCtx, cancel := goContext.WithTimeout(fs.watchCtx, 5*time.Second)
	err := fs.watcher.Watch(callCtx, rel)
	cancel()
	if err != nil {
		if linuxerr.Equals(linuxerr.ENOSPC, err) {
			return linuxerr.ENOSPC
		}
		return nil
	}

	fs.watchMu.Lock()
	if !fs.watchClosed {
		fs.watchSynced[rel] = struct{}{}
		fs.watched[d] = rel
	}
	fs.watchMu.Unlock()
	return nil
}

func (d *dentry) Watches() *vfs.Watches {
	fs := d.fs
	if fs.watcher != nil && d.refs.Load() > 0 {
		rel := d.path()
		fs.watchMu.Lock()
		_, tracked := fs.watched[d]
		closed := fs.watchClosed
		if !tracked && !closed {
			fs.watched[d] = rel
		}
		fs.watchMu.Unlock()
		if !tracked && !closed {
			fs.signalWatchReconcile()
		}
	}
	return &d.watches
}

func (d *dentry) OnZeroWatches(context.Context) {
	if d.watches.Size() != 0 {
		return
	}
	d.fs.unwatchDentry(d)
}

func (d *dentry) isDir() bool {
	return d.mode.Load()&linux.S_IFMT == linux.S_IFDIR
}

func (d *dentry) isSymlink() bool {
	return d.mode.Load()&linux.S_IFMT == linux.S_IFLNK
}

func (d *dentry) path() string {
	d.fs.ancestryMu.RLock()
	defer d.fs.ancestryMu.RUnlock()
	if d.parent == nil {
		return "."
	}
	var parts []string
	for cur := d; cur != nil && cur.parent != nil; cur = cur.parent {
		parts = append(parts, cur.name)
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, "/")
}

func joinRel(parentRel, name string) string {
	if parentRel == "" || parentRel == "." {
		return name
	}
	return path.Join(parentRel, name)
}

func (fs *filesystem) statxFor(e Entry, rel string) linux.Statx {
	ino := e.Ino
	if ino == 0 {
		ino = synthIno(rel)
	}
	nlink := e.Nlink
	if nlink == 0 {
		if e.Mode&linux.S_IFMT == linux.S_IFDIR {
			nlink = 2
		} else {
			nlink = 1
		}
	}
	return linux.Statx{
		Mask:     linux.STATX_BASIC_STATS,
		Blksize:  4096,
		Nlink:    nlink,
		UID:      e.UID,
		GID:      e.GID,
		Mode:     uint16(e.Mode),
		Ino:      ino,
		Size:     uint64(max(e.Size, 0)),
		Blocks:   uint64((max(e.Size, 0) + 511) / 512),
		Atime:    linux.NsecToStatxTimestamp(e.AtimeNS),
		Mtime:    linux.NsecToStatxTimestamp(e.MtimeNS),
		Ctime:    linux.NsecToStatxTimestamp(e.CtimeNS),
		DevMajor: linux.UNNAMED_MAJOR,
		DevMinor: fs.devMinor,
	}
}

func (fs *filesystem) lookupChild(ctx context.Context, parent *dentry, name string) (*dentry, Entry, error) {
	rel := joinRel(parent.path(), name)
	e, err := callRPC(ctx, func(c goContext.Context) (Entry, error) {
		return fs.client.Stat(c, rel)
	})
	if err != nil {
		if err == linuxerr.ENOENT {
			var evicted []*dentry
			fs.mu.Lock()
			if parent.children != nil {
				if old := parent.children[name]; old != nil {
					delete(parent.children, name)
					fs.detachSubtreeLocked(old, &evicted)
				}
			}
			fs.mu.Unlock()
			fs.unwatchDentries(evicted)
			for _, d := range evicted {
				d.DecRef(ctx)
			}
		}
		return nil, Entry{}, err
	}

	var evicted []*dentry
	fs.mu.Lock()
	if parent.children == nil {
		parent.children = make(map[string]*dentry)
	}
	if existing, ok := parent.children[name]; ok {
		fs.ancestryMu.RLock()
		isDead := existing.dead
		fs.ancestryMu.RUnlock()
		if !isDead && existing.mode.Load()&linux.S_IFMT == e.Mode&linux.S_IFMT {
			existing.updateAttr(e)
			existing.IncRef()
			fs.mu.Unlock()
			return existing, e, nil
		}
		delete(parent.children, name)
		fs.detachSubtreeLocked(existing, &evicted)
	}
	child := fs.newDentry(parent, name, e)
	child.refs.Store(2) // 1 for cache, 1 for caller
	parent.children[name] = child
	fs.mu.Unlock()

	fs.unwatchDentries(evicted)
	for _, d := range evicted {
		d.DecRef(ctx)
	}
	return child, e, nil
}

func (fs *filesystem) step(ctx context.Context, rp *vfs.ResolvingPath, cur *dentry) (*dentry, Entry, bool, error) {
	if !cur.isDir() {
		return nil, Entry{}, false, linuxerr.ENOTDIR
	}
	if err := cur.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, Entry{}, false, err
	}
	name := rp.Component()
	if name == "." {
		rp.Advance()
		cur.IncRef()
		return cur, Entry{Mode: cur.mode.Load(), UID: cur.uid.Load(), GID: cur.gid.Load(), Ino: cur.ino.Load()}, false, nil
	}
	if name == ".." {
		if isRoot, err := rp.CheckRoot(ctx, &cur.vfsd); err != nil {
			return nil, Entry{}, false, err
		} else if isRoot {
			rp.Advance()
			cur.IncRef()
			return cur, Entry{Mode: cur.mode.Load(), UID: cur.uid.Load(), GID: cur.gid.Load(), Ino: cur.ino.Load()}, false, nil
		}
		fs.ancestryMu.RLock()
		parent := cur.parent
		gotParent := parent != nil && parent.TryIncRef()
		fs.ancestryMu.RUnlock()
		if !gotParent {
			rp.Advance()
			cur.IncRef()
			return cur, Entry{Mode: cur.mode.Load(), UID: cur.uid.Load(), GID: cur.gid.Load(), Ino: cur.ino.Load()}, false, nil
		}
		if err := rp.CheckMount(ctx, &parent.vfsd); err != nil {
			parent.DecRef(ctx)
			return nil, Entry{}, false, err
		}
		rp.Advance()
		return parent, Entry{Mode: parent.mode.Load(), UID: parent.uid.Load(), GID: parent.gid.Load(), Ino: parent.ino.Load()}, false, nil
	}
	child, e, err := fs.lookupChild(ctx, cur, name)
	if err != nil {
		return nil, Entry{}, false, err
	}
	if err := rp.CheckMount(ctx, &child.vfsd); err != nil {
		child.DecRef(ctx)
		return nil, Entry{}, false, err
	}
	if e.Mode&linux.S_IFMT == linux.S_IFLNK && rp.ShouldFollowSymlink() {
		target := e.LinkTarget
		if target == "" {
			var rlErr error
			target, rlErr = callRPC(ctx, func(c goContext.Context) (string, error) {
				return fs.client.Readlink(c, child.path())
			})
			if rlErr != nil {
				child.DecRef(ctx)
				return nil, Entry{}, false, rlErr
			}
		}
		followed, sErr := rp.HandleSymlink(target)
		if sErr != nil {
			child.DecRef(ctx)
			return nil, Entry{}, false, sErr
		}
		if followed {
			child.DecRef(ctx)
			cur.IncRef()
			return cur, Entry{}, true, nil
		}
	}
	rp.Advance()
	return child, e, false, nil
}

func (fs *filesystem) resolve(ctx context.Context, rp *vfs.ResolvingPath) (*dentry, Entry, error) {
	cur := rp.Start().Impl().(*dentry)
	cur.IncRef()
	var lastEntry Entry
	haveEntry := false
	for !rp.Done() {
		next, e, followed, err := fs.step(ctx, rp, cur)
		cur.DecRef(ctx)
		if err != nil {
			return nil, Entry{}, err
		}
		cur = next
		if !followed {
			lastEntry = e
			haveEntry = true
		}
	}
	if rp.MustBeDir() && !cur.isDir() {
		cur.DecRef(ctx)
		return nil, Entry{}, linuxerr.ENOTDIR
	}
	if !haveEntry {
		e, err := callRPC(ctx, func(c goContext.Context) (Entry, error) {
			return fs.client.Stat(c, cur.path())
		})
		if err != nil {
			cur.DecRef(ctx)
			return nil, Entry{}, err
		}
		cur.updateAttr(e)
		lastEntry = e
	}
	return cur, lastEntry, nil
}

func (fs *filesystem) resolveParent(ctx context.Context, rp *vfs.ResolvingPath) (*dentry, error) {
	cur := rp.Start().Impl().(*dentry)
	cur.IncRef()
	for !rp.Final() {
		next, _, _, err := fs.step(ctx, rp, cur)
		cur.DecRef(ctx)
		if err != nil {
			return nil, err
		}
		cur = next
	}
	if !cur.isDir() {
		cur.DecRef(ctx)
		return nil, linuxerr.ENOTDIR
	}
	if err := cur.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		cur.DecRef(ctx)
		return nil, err
	}
	return cur, nil
}

func (fs *filesystem) AccessAt(ctx context.Context, rp *vfs.ResolvingPath, creds *auth.Credentials, ats vfs.AccessTypes) error {
	d, e, err := fs.resolve(ctx, rp)
	if err != nil {
		return err
	}
	defer d.DecRef(ctx)
	if ats.MayWrite() && fs.isReadOnly(rp.Mount()) {
		return linuxerr.EROFS
	}
	return vfs.GenericCheckPermissions(creds, ats, linux.FileMode(e.Mode), nil, auth.KUID(e.UID), auth.KGID(e.GID))
}

func (fs *filesystem) GetDentryAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetDentryOptions) (*vfs.Dentry, error) {
	// Resolve the mount root (or already-reached start dentry) without an RPC
	// round-trip so UmountAt can detach a mount even after the client disconnects.
	if rp.Done() {
		d := rp.Start().Impl().(*dentry)
		if opts.CheckSearchable {
			if !d.isDir() {
				return nil, linuxerr.ENOTDIR
			}
			if err := d.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
				return nil, err
			}
		}
		d.IncRef()
		return &d.vfsd, nil
	}
	d, e, err := fs.resolve(ctx, rp)
	if err != nil {
		return nil, err
	}
	if opts.CheckSearchable {
		if !d.isDir() {
			d.DecRef(ctx)
			return nil, linuxerr.ENOTDIR
		}
		if err := vfs.GenericCheckPermissions(rp.Credentials(), vfs.MayExec, linux.FileMode(e.Mode), nil, auth.KUID(e.UID), auth.KGID(e.GID)); err != nil {
			d.DecRef(ctx)
			return nil, err
		}
	}
	return &d.vfsd, nil
}

func (fs *filesystem) GetParentDentryAt(ctx context.Context, rp *vfs.ResolvingPath) (*vfs.Dentry, error) {
	parent, err := fs.resolveParent(ctx, rp)
	if err != nil {
		return nil, err
	}
	return &parent.vfsd, nil
}

func (fs *filesystem) LinkAt(context.Context, *vfs.ResolvingPath, vfs.VirtualDentry) error {
	return linuxerr.EOPNOTSUPP
}

func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	if fs.isReadOnly(rp.Mount()) {
		return linuxerr.EROFS
	}
	parent, err := fs.resolveParent(ctx, rp)
	if err != nil {
		return err
	}
	defer parent.DecRef(ctx)
	if err := parent.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return linuxerr.EEXIST
	}
	rel := joinRel(parent.path(), name)
	if err := callRPCErr(ctx, func(c goContext.Context) error {
		return fs.client.Mkdir(c, rel, uint32(opts.Mode.Permissions()))
	}); err != nil {
		return err
	}
	parent.watches.Notify(ctx, name, linux.IN_CREATE|linux.IN_ISDIR, 0, vfs.InodeEvent, false)
	return nil
}

func (fs *filesystem) MknodAt(context.Context, *vfs.ResolvingPath, vfs.MknodOptions) error {
	return linuxerr.EOPNOTSUPP
}

func (fs *filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	if opts.Flags&linux.O_TMPFILE != 0 {
		return nil, linuxerr.EOPNOTSUPP
	}
	mustCreate := opts.Flags&(linux.O_CREAT|linux.O_EXCL) == (linux.O_CREAT | linux.O_EXCL)
	mayCreate := opts.Flags&linux.O_CREAT != 0
	writable := vfs.MayWriteFileWithOpenFlags(opts.Flags)

	var (
		d           *dentry
		e           Entry
		err         error
		createdHere bool
	)
	if mayCreate && !rp.Done() {
		cur := rp.Start().Impl().(*dentry)
		cur.IncRef()
		for {
			for !rp.Final() {
				next, _, _, sErr := fs.step(ctx, rp, cur)
				cur.DecRef(ctx)
				if sErr != nil {
					return nil, sErr
				}
				cur = next
			}
			if !cur.isDir() {
				cur.DecRef(ctx)
				return nil, linuxerr.ENOTDIR
			}
			if err := cur.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
				cur.DecRef(ctx)
				return nil, err
			}
			name := rp.Component()
			if name == "." || name == ".." {
				if mustCreate {
					cur.DecRef(ctx)
					return nil, linuxerr.EEXIST
				}
				next, ne, _, sErr := fs.step(ctx, rp, cur)
				cur.DecRef(ctx)
				if sErr != nil {
					return nil, sErr
				}
				d, e = next, ne
				break
			}
			child, ce, lErr := fs.lookupChild(ctx, cur, name)
			if lErr == nil {
				if mustCreate {
					child.DecRef(ctx)
					cur.DecRef(ctx)
					return nil, linuxerr.EEXIST
				}
				if err := rp.CheckMount(ctx, &child.vfsd); err != nil {
					child.DecRef(ctx)
					cur.DecRef(ctx)
					return nil, err
				}
				if ce.Mode&linux.S_IFMT == linux.S_IFLNK && rp.ShouldFollowSymlink() {
					target := ce.LinkTarget
					if target == "" {
						var rlErr error
						target, rlErr = callRPC(ctx, func(c goContext.Context) (string, error) {
							return fs.client.Readlink(c, child.path())
						})
						if rlErr != nil {
							child.DecRef(ctx)
							cur.DecRef(ctx)
							return nil, rlErr
						}
					}
					followed, sErr := rp.HandleSymlink(target)
					if sErr != nil {
						child.DecRef(ctx)
						cur.DecRef(ctx)
						return nil, sErr
					}
					if followed {
						child.DecRef(ctx)
						if rp.Done() {
							se, stErr := callRPC(ctx, func(c goContext.Context) (Entry, error) {
								return fs.client.Stat(c, cur.path())
							})
							if stErr != nil {
								cur.DecRef(ctx)
								return nil, stErr
							}
							cur.updateAttr(se)
							d, e = cur, se
							break
						}
						continue
					}
				}
				cur.DecRef(ctx)
				d, e = child, ce
				break
			} else if lErr == linuxerr.ENOENT {
				if fs.isReadOnly(rp.Mount()) {
					cur.DecRef(ctx)
					return nil, linuxerr.EROFS
				}
				if err := cur.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
					cur.DecRef(ctx)
					return nil, err
				}
				rel := joinRel(cur.path(), name)
				created, cErr := callRPC(ctx, func(c goContext.Context) (Entry, error) {
					return fs.client.Create(c, rel, uint32(opts.Mode.Permissions()), opts.Flags)
				})
				if cErr != nil {
					cur.DecRef(ctx)
					return nil, cErr
				}
				if created.Mode&linux.S_IFMT == 0 {
					created.Mode |= linux.S_IFREG | uint32(opts.Mode.Permissions())
				}
				nd := fs.newDentry(cur, name, created)
				nd.refs.Store(2)
				var evicted []*dentry
				fs.mu.Lock()
				if cur.children == nil {
					cur.children = make(map[string]*dentry)
				}
				if old := cur.children[name]; old != nil {
					delete(cur.children, name)
					fs.detachSubtreeLocked(old, &evicted)
				}
				cur.children[name] = nd
				fs.mu.Unlock()
				fs.unwatchDentries(evicted)
				for _, oldD := range evicted {
					oldD.DecRef(ctx)
				}
				cur.watches.Notify(ctx, name, linux.IN_CREATE, 0, vfs.InodeEvent, false)
				cur.DecRef(ctx)
				d, e = nd, created
				createdHere = true
				break
			} else {
				cur.DecRef(ctx)
				return nil, lErr
			}
		}
	} else {
		if mustCreate {
			return nil, linuxerr.EEXIST
		}
		d, e, err = fs.resolve(ctx, rp)
		if err != nil {
			return nil, err
		}
	}
	defer d.DecRef(ctx)

	if e.Mode&linux.S_IFMT == linux.S_IFDIR {
		if writable {
			return nil, linuxerr.EISDIR
		}
		if !createdHere {
			ats := vfs.AccessTypesForOpenFlags(&opts)
			if err := vfs.GenericCheckPermissions(rp.Credentials(), ats, linux.FileMode(e.Mode), nil, auth.KUID(e.UID), auth.KGID(e.GID)); err != nil {
				return nil, err
			}
		}
		fd := &dirFD{fileDescription: fileDescription{dentry: d}}
		fd.LockFD.Init(&d.locks)
		if err := fd.vfsfd.Init(fd, opts.Flags, rp.Credentials(), rp.Mount(), &d.vfsd, &vfs.FileDescriptionOptions{}); err != nil {
			return nil, err
		}
		return &fd.vfsfd, nil
	}
	if opts.Flags&linux.O_DIRECTORY != 0 || rp.MustBeDir() {
		return nil, linuxerr.ENOTDIR
	}
	// Reject non-regular files (symlinks under O_NOFOLLOW must return ELOOP;
	// FIFOs/sockets/devices must never open on the synchronous host RPC peer).
	if e.Mode&linux.S_IFMT == linux.S_IFLNK {
		return nil, linuxerr.ELOOP
	}
	if e.Mode&linux.S_IFMT != linux.S_IFREG {
		return nil, linuxerr.ENXIO
	}
	if writable && fs.isReadOnly(rp.Mount()) {
		return nil, linuxerr.EROFS
	}
	if !createdHere {
		ats := vfs.AccessTypesForOpenFlags(&opts)
		if err := vfs.GenericCheckPermissions(rp.Credentials(), ats, linux.FileMode(e.Mode), nil, auth.KUID(e.UID), auth.KGID(e.GID)); err != nil {
			return nil, err
		}
	}
	if opts.Flags&linux.O_TRUNC != 0 && writable {
		rel := d.path()
		if err := callRPCErr(ctx, func(c goContext.Context) error {
			return fs.client.Truncate(c, rel, 0)
		}); err != nil {
			return nil, err
		}
	}
	fd := &regularFD{fileDescription: fileDescription{dentry: d}}
	fd.LockFD.Init(&d.locks)
	if err := fd.vfsfd.Init(fd, opts.Flags, rp.Credentials(), rp.Mount(), &d.vfsd, &vfs.FileDescriptionOptions{}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

func (fs *filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	d, e, err := fs.resolve(ctx, rp)
	if err != nil {
		return "", err
	}
	defer d.DecRef(ctx)
	if e.Mode&linux.S_IFMT != linux.S_IFLNK {
		return "", linuxerr.EINVAL
	}
	if e.LinkTarget != "" {
		return e.LinkTarget, nil
	}
	rel := d.path()
	return callRPC(ctx, func(c goContext.Context) (string, error) {
		return fs.client.Readlink(c, rel)
	})
}

func (fs *filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, oldParentVD vfs.VirtualDentry, oldName string, opts vfs.RenameOptions) error {
	if opts.Flags != 0 {
		return linuxerr.EINVAL
	}
	if fs.isReadOnly(rp.Mount()) {
		return linuxerr.EROFS
	}
	if rp.Mount() != oldParentVD.Mount() {
		return linuxerr.EXDEV
	}
	newParent, err := fs.resolveParent(ctx, rp)
	if err != nil {
		return err
	}
	defer newParent.DecRef(ctx)
	if err := newParent.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	newName := rp.Component()
	if newName == "." || newName == ".." {
		return linuxerr.EBUSY
	}
	oldParent := oldParentVD.Dentry().Impl().(*dentry)
	if err := oldParent.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	oldRel := joinRel(oldParent.path(), oldName)
	newRel := joinRel(newParent.path(), newName)
	if oldRel == newRel {
		return nil
	}
	if oldRel == "." || strings.HasPrefix(newRel, oldRel+"/") {
		return linuxerr.EINVAL
	}
	fs.mu.Lock()
	var cycleBefore bool
	if oldParent.children != nil {
		if moved := oldParent.children[oldName]; moved != nil {
			fs.ancestryMu.RLock()
			cycleBefore = isAncestorLocked(moved, newParent)
			fs.ancestryMu.RUnlock()
		}
	}
	fs.mu.Unlock()
	if cycleBefore {
		return linuxerr.EINVAL
	}

	if err := callRPCErr(ctx, func(c goContext.Context) error {
		return fs.client.Rename(c, oldRel, newRel)
	}); err != nil {
		return err
	}
	var evicted []*dentry
	var cycleAfter bool
	var movedDentry *dentry
	var movedIsDir bool
	fs.mu.Lock()
	if newParent.children != nil {
		if existing, ok := newParent.children[newName]; ok {
			if oldParent.children == nil || oldParent.children[oldName] != existing {
				delete(newParent.children, newName)
				fs.detachSubtreeLocked(existing, &evicted)
			}
		}
	}
	if oldParent.children != nil {
		if moved, ok := oldParent.children[oldName]; ok {
			delete(oldParent.children, oldName)
			fs.ancestryMu.Lock()
			if isAncestorLocked(moved, newParent) {
				fs.ancestryMu.Unlock()
				fs.detachSubtreeLocked(moved, &evicted)
				cycleAfter = true
			} else {
				if newParent.children == nil {
					newParent.children = make(map[string]*dentry)
				}
				moved.parent = newParent
				moved.name = newName
				newParent.children[newName] = moved
				moved.IncRef()
				movedDentry = moved
				movedIsDir = moved.isDir()
				fs.ancestryMu.Unlock()
			}
		}
	}
	fs.mu.Unlock()
	fs.unwatchDentries(evicted)
	for _, d := range evicted {
		d.DecRef(ctx)
	}
	if cycleAfter {
		return linuxerr.EINVAL
	}
	fs.rebaseWatchedPaths(oldRel, newRel)
	if movedDentry != nil {
		if movedDentry.watches.Size() > 0 || oldParent.watches.Size() > 0 || newParent.watches.Size() > 0 {
			vfs.InotifyRename(ctx, &movedDentry.watches, &oldParent.watches, &newParent.watches, oldName, newName, movedIsDir)
		}
		movedDentry.DecRef(ctx)
	} else if oldParent.watches.Size() > 0 || newParent.watches.Size() > 0 {
		vfs.InotifyRename(ctx, nil, &oldParent.watches, &newParent.watches, oldName, newName, false)
	}
	return nil
}

func (fs *filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	if fs.isReadOnly(rp.Mount()) {
		return linuxerr.EROFS
	}
	parent, err := fs.resolveParent(ctx, rp)
	if err != nil {
		return err
	}
	defer parent.DecRef(ctx)
	if err := parent.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." {
		return linuxerr.EINVAL
	}
	if name == ".." {
		return linuxerr.ENOTEMPTY
	}
	rel := joinRel(parent.path(), name)
	e, stErr := callRPC(ctx, func(c goContext.Context) (Entry, error) {
		return fs.client.Stat(c, rel)
	})
	if stErr != nil {
		return stErr
	}
	if e.Mode&linux.S_IFMT != linux.S_IFDIR {
		return linuxerr.ENOTDIR
	}
	if err := callRPCErr(ctx, func(c goContext.Context) error {
		return fs.client.Rmdir(c, rel)
	}); err != nil {
		return err
	}
	fs.dropChild(ctx, parent, name)
	parent.watches.Notify(ctx, name, linux.IN_DELETE|linux.IN_ISDIR, 0, vfs.InodeEvent, true)
	return nil
}

func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	if fs.isReadOnly(rp.Mount()) {
		return linuxerr.EROFS
	}
	parent, err := fs.resolveParent(ctx, rp)
	if err != nil {
		return err
	}
	defer parent.DecRef(ctx)
	if err := parent.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return linuxerr.EISDIR
	}
	rel := joinRel(parent.path(), name)
	e, stErr := callRPC(ctx, func(c goContext.Context) (Entry, error) {
		return fs.client.Stat(c, rel)
	})
	if stErr != nil {
		return stErr
	}
	if e.Mode&linux.S_IFMT == linux.S_IFDIR {
		return linuxerr.EISDIR
	}
	if err := callRPCErr(ctx, func(c goContext.Context) error {
		return fs.client.Unlink(c, rel)
	}); err != nil {
		return err
	}
	removed := fs.takeChild(parent, name)
	var selfWatches *vfs.Watches
	if removed != nil {
		selfWatches = &removed.watches
	}
	vfs.InotifyRemoveChild(ctx, selfWatches, &parent.watches, name)
	if removed != nil {
		fs.evictDetached(ctx, removed)
	}
	return nil
}

func (fs *filesystem) takeChild(parent *dentry, name string) *dentry {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if parent.children == nil {
		return nil
	}
	old := parent.children[name]
	if old != nil {
		delete(parent.children, name)
	}
	return old
}

func (fs *filesystem) evictDetached(ctx context.Context, d *dentry) {
	var evicted []*dentry
	fs.mu.Lock()
	fs.detachSubtreeLocked(d, &evicted)
	fs.mu.Unlock()
	fs.unwatchDentries(evicted)
	for _, n := range evicted {
		n.DecRef(ctx)
	}
}

func (fs *filesystem) dropChild(ctx context.Context, parent *dentry, name string) {
	var evicted []*dentry
	fs.mu.Lock()
	if parent.children != nil {
		if old := parent.children[name]; old != nil {
			delete(parent.children, name)
			fs.detachSubtreeLocked(old, &evicted)
		}
	}
	fs.mu.Unlock()
	fs.unwatchDentries(evicted)
	for _, d := range evicted {
		d.DecRef(ctx)
	}
}

func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	if fs.isReadOnly(rp.Mount()) {
		return linuxerr.EROFS
	}
	parent, err := fs.resolveParent(ctx, rp)
	if err != nil {
		return err
	}
	defer parent.DecRef(ctx)
	if err := parent.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return linuxerr.EEXIST
	}
	rel := joinRel(parent.path(), name)
	if err := callRPCErr(ctx, func(c goContext.Context) error {
		return fs.client.Symlink(c, target, rel)
	}); err != nil {
		return err
	}
	parent.watches.Notify(ctx, name, linux.IN_CREATE, 0, vfs.InodeEvent, false)
	return nil
}

func (fs *filesystem) setStatDentry(ctx context.Context, creds *auth.Credentials, d *dentry, mnt *vfs.Mount, opts vfs.SetStatOptions) error {
	if fs.isReadOnly(mnt) {
		return linuxerr.EROFS
	}
	if creds != nil {
		owner := auth.KUID(d.uid.Load())
		isOwner := creds.EffectiveKUID == owner || creds.HasCapabilityIn(linux.CAP_FOWNER, creds.UserNamespace)
		if opts.Stat.Mask&linux.STATX_SIZE != 0 {
			if err := d.checkPermissions(creds, vfs.MayWrite); err != nil {
				return err
			}
		}
		if opts.Stat.Mask&linux.STATX_MODE != 0 && !isOwner {
			return linuxerr.EPERM
		}
		if opts.Stat.Mask&(linux.STATX_ATIME|linux.STATX_MTIME) != 0 && !isOwner {
			if err := d.checkPermissions(creds, vfs.MayWrite); err != nil {
				return linuxerr.EPERM
			}
		}
	}
	rel := d.path()
	if opts.Stat.Mask&linux.STATX_SIZE != 0 {
		if err := callRPCErr(ctx, func(c goContext.Context) error {
			return fs.client.Truncate(c, rel, int64(opts.Stat.Size))
		}); err != nil {
			return err
		}
	}
	if opts.Stat.Mask&linux.STATX_MODE != 0 {
		newPerm := uint32(opts.Stat.Mode) & 0o7777
		if err := callRPCErr(ctx, func(c goContext.Context) error {
			return fs.client.Chmod(c, rel, newPerm)
		}); err != nil {
			return err
		}
		d.mode.Store((d.mode.Load() & linux.S_IFMT) | newPerm)
	}
	setA := opts.Stat.Mask&linux.STATX_ATIME != 0
	setM := opts.Stat.Mask&linux.STATX_MTIME != 0
	if setA || setM {
		if err := callRPCErr(ctx, func(c goContext.Context) error {
			return fs.client.Utimens(c, rel, opts.Stat.Atime.ToNsec(), opts.Stat.Mtime.ToNsec(), setA, setM)
		}); err != nil {
			return err
		}
	}
	return nil
}

func (fs *filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	d, _, err := fs.resolve(ctx, rp)
	if err != nil {
		return err
	}
	defer d.DecRef(ctx)
	if err := fs.setStatDentry(ctx, rp.Credentials(), d, rp.Mount(), opts); err != nil {
		return err
	}
	if ev := vfs.InotifyEventFromStatMask(opts.Stat.Mask); ev != 0 {
		d.InotifyWithParent(ctx, ev, 0, vfs.InodeEvent)
	}
	return nil
}

func (fs *filesystem) StatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.StatOptions) (linux.Statx, error) {
	d, e, err := fs.resolve(ctx, rp)
	if err != nil {
		return linux.Statx{}, err
	}
	defer d.DecRef(ctx)
	st := fs.statxFor(e, d.path())
	rp.AddMountRootAttr(&d.vfsd, &st)
	return st, nil
}

func (fs *filesystem) StatFSAt(context.Context, *vfs.ResolvingPath) (linux.Statfs, error) {
	return linux.Statfs{
		Type:            rpcfsMagic,
		BlockSize:       4096,
		FragmentSize:    4096,
		NameLength:      255,
		Blocks:          1 << 20,
		BlocksFree:      1 << 19,
		BlocksAvailable: 1 << 19,
	}, nil
}

func (fs *filesystem) ListXattrAt(context.Context, *vfs.ResolvingPath, uint64) ([]string, error) {
	return nil, linuxerr.ENOTSUP
}
func (fs *filesystem) GetXattrAt(context.Context, *vfs.ResolvingPath, vfs.GetXattrOptions) (string, error) {
	return "", linuxerr.ENOTSUP
}
func (fs *filesystem) SetXattrAt(context.Context, *vfs.ResolvingPath, vfs.SetXattrOptions) error {
	return linuxerr.ENOTSUP
}
func (fs *filesystem) RemoveXattrAt(context.Context, *vfs.ResolvingPath, string) error {
	return linuxerr.ENOTSUP
}
func (fs *filesystem) GetPosixACLAt(context.Context, *vfs.ResolvingPath, vfs.ACLType) (*vfs.PosixACL, error) {
	return nil, linuxerr.ENOTSUP
}
func (fs *filesystem) SetPosixACLAt(context.Context, *vfs.ResolvingPath, vfs.ACLType, *vfs.PosixACL, bool) (*vfs.PosixACL, linux.FileMode, error) {
	return nil, 0, linuxerr.ENOTSUP
}
func (fs *filesystem) BoundEndpointAt(context.Context, *vfs.ResolvingPath, vfs.BoundEndpointOptions) (transport.BoundEndpoint, error) {
	return nil, linuxerr.ECONNREFUSED
}

func (fs *filesystem) PrependPath(_ context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	fs.ancestryMu.RLock()
	defer fs.ancestryMu.RUnlock()
	mnt := vd.Mount()
	d := vd.Dentry().Impl().(*dentry)
	for {
		if mnt == vfsroot.Mount() && &d.vfsd == vfsroot.Dentry() {
			return vfs.PrependPathAtVFSRootError{}
		}
		if mnt != nil && &d.vfsd == mnt.Root() {
			return nil
		}
		if d.dead {
			return vfs.PrependPathSyntheticError{}
		}
		if d.parent == nil {
			return vfs.PrependPathAtNonMountRootError{}
		}
		b.PrependComponent(d.name)
		d = d.parent
	}
}

func (fs *filesystem) IsDescendant(vfsroot, vd vfs.VirtualDentry) bool {
	if vfsroot.Mount() != vd.Mount() {
		return false
	}
	fs.ancestryMu.RLock()
	defer fs.ancestryMu.RUnlock()
	target := vfsroot.Dentry().Impl().(*dentry)
	for d := vd.Dentry().Impl().(*dentry); d != nil; d = d.parent {
		if d == target {
			return true
		}
	}
	return false
}

type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD
	dentry *dentry
}

func (fd *fileDescription) Release(context.Context) {}

func (fd *fileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	rel := fd.dentry.path()
	e, err := callRPC(ctx, func(c goContext.Context) (Entry, error) {
		return fd.dentry.fs.client.Stat(c, rel)
	})
	if err != nil {
		return linux.Statx{}, err
	}
	fd.dentry.updateAttr(e)
	return fd.dentry.fs.statxFor(e, rel), nil
}

func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	return fd.dentry.fs.setStatDentry(ctx, auth.CredentialsFromContext(ctx), fd.dentry, fd.vfsfd.Mount(), opts)
}

func (fd *fileDescription) StatFS(ctx context.Context) (linux.Statfs, error) {
	return fd.dentry.fs.StatFSAt(ctx, nil)
}

type regularFD struct {
	fileDescription
	mu  sync.Mutex
	off int64
}

func (fd *regularFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	want := dst.NumBytes()
	if want == 0 {
		return 0, nil
	}
	rel := fd.dentry.path()
	maxChunk := fd.dentry.fs.maxChunkSize()
	var total int64
	for total < want {
		chunkLen := min(want-total, maxChunk)
		data, err := callRPC(ctx, func(c goContext.Context) ([]byte, error) {
			return fd.dentry.fs.client.Read(c, rel, offset+total, chunkLen)
		})
		if len(data) > 0 {
			if int64(len(data)) > chunkLen {
				data = data[:chunkLen]
			}
			n, copyErr := dst.DropFirst64(total).CopyOut(ctx, data)
			total += int64(n)
			if copyErr != nil {
				return total, copyErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if total > 0 {
					return total, nil
				}
				return 0, io.EOF
			}
			if total > 0 {
				return total, nil
			}
			return 0, err
		}
		if len(data) == 0 {
			if total > 0 {
				return total, nil
			}
			return 0, io.EOF
		}
		if int64(len(data)) < chunkLen {
			return total, nil
		}
	}
	return total, nil
}

func (fd *regularFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	n, err := fd.PRead(ctx, dst, fd.off, opts)
	fd.off += n
	return n, err
}

func (fd *regularFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	if fd.dentry.fs.isReadOnly(fd.vfsfd.Mount()) {
		return 0, linuxerr.EROFS
	}
	want := src.NumBytes()
	if want == 0 {
		return 0, nil
	}
	rel := fd.dentry.path()
	maxChunk := fd.dentry.fs.maxChunkSize()
	var total int64
	buf := make([]byte, min(want, maxChunk))
	for total < want {
		step := int(min(want-total, int64(len(buf))))
		copied, copyErr := src.DropFirst64(total).CopyIn(ctx, buf[:step])
		if copied == 0 {
			return total, copyErr
		}
		written, wErr := callRPC(ctx, func(c goContext.Context) (int64, error) {
			return fd.dentry.fs.client.Write(c, rel, offset+total, buf[:copied])
		})
		if written < 0 || written > int64(copied) {
			if total > 0 {
				return total, nil
			}
			return 0, linuxerr.EIO
		}
		total += written
		if wErr != nil {
			if total > 0 {
				return total, nil
			}
			return 0, wErr
		}
		if copyErr != nil {
			return total, copyErr
		}
		if written < int64(copied) {
			break
		}
	}
	return total, nil
}

func (fd *regularFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	off := fd.off
	if fd.vfsfd.StatusFlags()&linux.O_APPEND != 0 {
		rel := fd.dentry.path()
		e, err := callRPC(ctx, func(c goContext.Context) (Entry, error) {
			return fd.dentry.fs.client.Stat(c, rel)
		})
		if err != nil {
			return 0, err
		}
		off = e.Size
	}
	n, err := fd.PWrite(ctx, src, off, opts)
	fd.off = off + n
	return n, err
}

func (fd *regularFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	var next int64
	switch whence {
	case linux.SEEK_SET:
		next = offset
	case linux.SEEK_CUR:
		next = fd.off + offset
	case linux.SEEK_END:
		rel := fd.dentry.path()
		e, err := callRPC(ctx, func(c goContext.Context) (Entry, error) {
			return fd.dentry.fs.client.Stat(c, rel)
		})
		if err != nil {
			return 0, err
		}
		next = e.Size + offset
	default:
		return 0, linuxerr.EINVAL
	}
	if next < 0 {
		return 0, linuxerr.EINVAL
	}
	fd.off = next
	return next, nil
}

type dirFD struct {
	fileDescription
	vfs.DirectoryFileDescriptionDefaultImpl
	mu      sync.Mutex
	off     int64
	entries []vfs.Dirent
	loaded  bool
}

func direntTypeFromMode(mode uint32) uint8 {
	switch mode & linux.S_IFMT {
	case linux.S_IFDIR:
		return linux.DT_DIR
	case linux.S_IFLNK:
		return linux.DT_LNK
	case linux.S_IFREG:
		return linux.DT_REG
	case linux.S_IFIFO:
		return linux.DT_FIFO
	case linux.S_IFSOCK:
		return linux.DT_SOCK
	case linux.S_IFCHR:
		return linux.DT_CHR
	case linux.S_IFBLK:
		return linux.DT_BLK
	default:
		return linux.DT_UNKNOWN
	}
}

func (fd *dirFD) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback) error {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.loaded {
		rel := fd.dentry.path()
		raw, err := callRPC(ctx, func(c goContext.Context) ([]Entry, error) {
			return fd.dentry.fs.client.Readdir(c, rel)
		})
		if err != nil {
			return err
		}
		parentIno := fd.dentry.ino.Load()
		fd.dentry.fs.ancestryMu.RLock()
		if fd.dentry.parent != nil {
			parentIno = fd.dentry.parent.ino.Load()
		}
		fd.dentry.fs.ancestryMu.RUnlock()
		list := make([]vfs.Dirent, 0, len(raw)+2)
		list = append(list,
			vfs.Dirent{Name: ".", Type: linux.DT_DIR, Ino: fd.dentry.ino.Load(), NextOff: 1},
			vfs.Dirent{Name: "..", Type: linux.DT_DIR, Ino: parentIno, NextOff: 2},
		)
		for _, e := range raw {
			if e.Name == "" || e.Name == "." || e.Name == ".." || strings.Contains(e.Name, "/") {
				continue
			}
			ino := e.Ino
			if ino == 0 {
				ino = synthIno(joinRel(rel, e.Name))
			}
			list = append(list, vfs.Dirent{
				Name:    e.Name,
				Type:    direntTypeFromMode(e.Mode),
				Ino:     ino,
				NextOff: int64(len(list) + 1),
			})
		}
		fd.entries = list
		fd.loaded = true
	}
	for fd.off < int64(len(fd.entries)) {
		if err := cb.Handle(fd.entries[fd.off]); err != nil {
			return err
		}
		fd.off++
	}
	return nil
}

func (fd *dirFD) Seek(_ context.Context, offset int64, whence int32) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	switch whence {
	case linux.SEEK_SET:
		if offset < 0 {
			return 0, linuxerr.EINVAL
		}
		fd.off = offset
		if offset == 0 {
			fd.loaded = false
			fd.entries = nil
		}
		return fd.off, nil
	case linux.SEEK_CUR:
		next := fd.off + offset
		if next < 0 {
			return 0, linuxerr.EINVAL
		}
		fd.off = next
		return fd.off, nil
	default:
		return 0, linuxerr.EINVAL
	}
}
