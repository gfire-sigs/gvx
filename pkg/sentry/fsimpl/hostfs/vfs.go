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

package hostfs

import (
	"errors"
	"hash/fnv"
	iofs "io/fs"
	"sync"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/chunkcache"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

const (
	// pruneThreshold is the dentry count above which the cache drops
	// unreferenced leaves. Dentries are cheap to rebuild from the host.
	pruneThreshold = 1 << 16

	// virtualInoBit marks inode numbers of virtual symlinks. Host inode
	// numbers never use the top bit on APFS, NTFS, or ext4.
	virtualInoBit = uint64(1) << 63
)

// InternalFilesystemOptions may be passed as vfs.GetFilesystemOptions.InternalData
// to mount an already-opened *Workspace prior to hostlockdown.Apply().
type InternalFilesystemOptions struct {
	Workspace *Workspace
}

// FilesystemType implements vfs.FilesystemType for hostfs.
type FilesystemType struct{}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// Release implements vfs.FilesystemType.Release.
func (FilesystemType) Release(ctx context.Context) {}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fsType FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	var ws *Workspace
	ownsWS := false
	if internalOpts, ok := opts.InternalData.(InternalFilesystemOptions); ok && internalOpts.Workspace != nil {
		ws = internalOpts.Workspace
	} else if source != "" {
		var err error
		ws, err = OpenWorkspace(source, false)
		if err != nil {
			return nil, nil, translateHostError(err)
		}
		ownsWS = true
	} else {
		return nil, nil, linuxerr.EINVAL
	}
	fail := func(err error) (*vfs.Filesystem, *vfs.Dentry, error) {
		if ownsWS {
			_ = ws.Close()
		}
		return nil, nil, err
	}

	rootEntry, err := ws.lookup(".")
	if err != nil {
		return fail(translateHostError(err))
	}
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return fail(err)
	}
	hfs := &filesystem{
		ws:       ws,
		ownsWS:   ownsWS,
		devMinor: devMinor,
		inodes:   make(map[hostID]*inode),
		pruneAt:  pruneThreshold,
	}
	hfs.vfsfs.Init(vfsObj, fsType, hfs)
	hfs.mu.Lock()
	hfs.root = hfs.newDentryLocked(nil, "", ".", hfs.inodeForLocked(rootEntry, "."))
	// One reference for the filesystem and one for the mount.
	hfs.root.refs.Add(1)
	hfs.mu.Unlock()
	return &hfs.vfsfs, &hfs.root.vfsd, nil
}

// filesystem implements vfs.FilesystemImpl. The host is the source of truth.
// A path step revalidates against the workspace when its cached result has
// expired or a mutation dropped it. The dentry tree also keeps object identity
// stable for open files, mounts, and watches. The consistency contract is in
// lookupChildLocked.
type filesystem struct {
	vfsfs    vfs.Filesystem
	ws       *Workspace
	ownsWS   bool
	devMinor uint32

	// mu protects the dentry tree, dentry names and paths, the inode map, and
	// pending. Lock order: filesystem.mu, then Workspace.mu, then inode locks.
	mu     sync.Mutex
	root   *dentry
	inodes map[hostID]*inode
	// pending holds references returned by the VFS that must be dropped after
	// mu is released, because dropping them can release this filesystem.
	pending []decRefer

	dentryCount int
	pruneAt     int
}

// decRefer is the part of refs.RefCounter that hostfs needs. The VFS returns
// reference lists in that type.
type decRefer interface {
	DecRef(ctx context.Context)
}

// deferDecRef queues references that the VFS handed back, to drop after mu is
// released.
func deferDecRef[T decRefer](fs *filesystem, list []T) {
	for _, r := range list {
		fs.pending = append(fs.pending, r)
	}
}

func (fs *filesystem) lock() {
	fs.mu.Lock()
}

func (fs *filesystem) unlock(ctx context.Context) {
	pending := fs.pending
	fs.pending = nil
	fs.mu.Unlock()
	for _, r := range pending {
		r.DecRef(ctx)
	}
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	fs.mu.Lock()
	inodes := make([]*inode, 0, len(fs.inodes))
	for _, ino := range fs.inodes {
		inodes = append(inodes, ino)
	}
	fs.mu.Unlock()
	for _, ino := range inodes {
		// Release has no error result, so a failure is logged. An earlier
		// Sync call already reported the failures that it saw.
		if err := ino.syncData(); err != nil {
			ctx.Warningf("hostfs: write back mapped data at unmount: %v", err)
		}
	}
	if err := fs.ws.Sync(); err != nil {
		ctx.Warningf("hostfs: flush metadata at unmount: %v", err)
	}
	fs.mu.Lock()
	fs.root.decRefLocked()
	fs.mu.Unlock()
	fs.vfsfs.VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	if fs.ownsWS {
		_ = fs.ws.Close()
	}
}

// Sync implements vfs.FilesystemImpl.Sync. It writes back mapped file data and
// flushes the metadata table, and it reports every failure.
func (fs *filesystem) Sync(ctx context.Context) error {
	fs.mu.Lock()
	inodes := make([]*inode, 0, len(fs.inodes))
	for _, ino := range fs.inodes {
		inodes = append(inodes, ino)
	}
	fs.mu.Unlock()
	var errs []error
	for _, ino := range inodes {
		if err := ino.syncFile(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := fs.ws.Sync(); err != nil {
		errs = append(errs, err)
	}
	return translateHostError(errors.Join(errs...))
}

// inode is the identity of a host file. Hard links share one inode through the
// filesystem inode map, so they share locks, watches, and the mapped-page
// cache. A virtual symlink has an inode of its own.
type inode struct {
	fs      *filesystem
	id      hostID
	virtual bool
	kind    hostKind
	ino     uint64

	// refs counts the dentries that name this inode. Protected by fs.mu.
	refs int

	locks   vfs.FileLocks
	watches vfs.Watches

	// attrMu protects cur, the last entry observed for this inode, and the
	// validity of cur. Unlinked files keep serving their last attributes to
	// open file descriptors.
	//
	// metaValid marks cur as current until metaUntil, so a lookup that finds
	// the dentry of this inode makes no host call. Every mutation that
	// changes the inode calls invalidateMeta, which also advances metaSeq.
	// A lookup that started before the mutation then cannot mark the older
	// entry valid again, because commitMeta compares metaSeq.
	attrMu    sync.Mutex
	cur       entry
	metaValid bool
	metaUntil int64
	metaSeq   uint64

	// negChildren holds the names that a lookup in this directory did not
	// find, so a repeated lookup makes no host call. negUntil ends the life of
	// the whole set. Protected by fs.mu. See lookupChildLocked for the
	// consistency contract.
	negChildren map[string]struct{}
	negUntil    int64

	// wmu serialises writes so that O_APPEND is atomic.
	wmu sync.Mutex

	data fileData

	// writeCount tracks the processes that execute this file, which blocks
	// every write to it. Hard links share the count. See exec_busy.go.
	writeCount vfs.WriteCount

	// unlinked reports that no name in the namespace reaches the inode any
	// more: the guest removed the last link, or the guest created the file
	// with O_TMPFILE and has not linked it. The link count that stat reports
	// is zero then.
	unlinked atomicbitops.Bool

	// tmp holds the host state of a file that the guest created with
	// O_TMPFILE, or nil. Protected by fs.mu. See tmpfile.go.
	tmp *tmpFile

	// special holds the in-memory state of a socket, a FIFO, or a device
	// node. See special_node.go.
	special specialState

	// guest records the host state that the last guest write produced. The
	// host watcher uses it to tell a guest write from a host write. See
	// watcher.go.
	guest guestState
}

func (i *inode) snapshot() entry {
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	return i.cur
}

func (i *inode) update(e entry) {
	i.attrMu.Lock()
	i.cur = e
	i.attrMu.Unlock()
}

// metaFresh reports whether cur is valid at time now.
func (i *inode) metaFresh(now int64) bool {
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	return i.metaValid && now < i.metaUntil
}

// invalidateMeta marks cur as stale. Callers invoke it after every host
// change of the inode: writes, truncation, attribute changes, link count
// changes, and changes of the directory contents.
func (i *inode) invalidateMeta() {
	i.attrMu.Lock()
	i.metaValid = false
	i.metaSeq++
	i.attrMu.Unlock()
}

// beginMeta returns the token that commitMeta needs. Call it before the host
// lookup that produces the entry.
func (i *inode) beginMeta() uint64 {
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	return i.metaSeq
}

// commitMeta stores e and marks it valid until the given time, unless a
// mutation invalidated the inode after beginMeta returned seq. In that case it
// stores e and leaves the inode invalid.
func (i *inode) commitMeta(e entry, seq uint64, until int64) {
	i.attrMu.Lock()
	i.cur = e
	if i.metaSeq == seq {
		i.metaValid = true
		i.metaUntil = until
	}
	i.attrMu.Unlock()
}

// markValid marks cur of a new inode as valid until the given time.
func (i *inode) markValid(until int64) {
	i.attrMu.Lock()
	i.metaValid = true
	i.metaUntil = until
	i.attrMu.Unlock()
}

// maxNegChildren bounds the negative entries of one directory.
const maxNegChildren = 1024

// negHit reports whether a lookup of name in this directory failed recently.
// Callers hold fs.mu.
func (i *inode) negHit(name string, now int64) bool {
	if len(i.negChildren) == 0 {
		return false
	}
	if now >= i.negUntil {
		i.negChildren = nil
		return false
	}
	_, ok := i.negChildren[name]
	return ok
}

// negAdd records that name does not exist in this directory. Callers hold
// fs.mu.
func (i *inode) negAdd(name string, now int64) {
	if len(i.negChildren) == 0 || now >= i.negUntil {
		i.negChildren = make(map[string]struct{})
		i.negUntil = now + int64(cacheTTL)
	} else if len(i.negChildren) >= maxNegChildren {
		clear(i.negChildren)
	}
	i.negChildren[name] = struct{}{}
}

// negDel forgets the negative entry of name. Callers hold fs.mu.
func (i *inode) negDel(name string) {
	delete(i.negChildren, name)
}

func (i *inode) mode() linux.FileMode {
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	return linux.FileMode(i.cur.attr.Mode)
}

func (i *inode) isDir() bool {
	return i.kind == hostKindDir
}

func (i *inode) isSymlink() bool {
	return i.kind == hostKindSymlink
}

func (i *inode) isRegular() bool {
	return i.kind == hostKindRegular
}

func (i *inode) checkPermissions(creds *auth.Credentials, ats vfs.AccessTypes) error {
	e := i.snapshot()
	return vfs.GenericCheckPermissions(creds, ats, linux.FileMode(e.attr.Mode), nil, auth.KUID(e.attr.UID), auth.KGID(e.attr.GID))
}

func (i *inode) matches(e entry) bool {
	if i.fs.ws.single != "" {
		// The only inode is the root, which stands for the name of the bound
		// file. A host editor can replace the file under that name.
		return !e.virtual && e.info.kind == i.kind
	}
	if i.virtual != e.virtual {
		return false
	}
	return i.virtual || (i.id == e.info.id && i.kind == e.info.kind)
}

// syncData writes back mapped file data and reports any earlier write-back
// failure that no caller observed.
func (i *inode) syncData() error {
	return i.data.syncData()
}

// destroy releases the resources of an inode with no dentries left.
func (i *inode) destroy() {
	i.fs.ws.watchForget(i)
	i.data.release()
	i.releaseTmp()
}

// virtualInoFor derives the inode number of a virtual symlink from its path.
func virtualInoFor(rel string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(rel))
	return h.Sum64() | virtualInoBit
}

// inodeForLocked returns the inode for e, creating it when no dentry names
// the host file yet.
func (fs *filesystem) inodeForLocked(e entry, rel string) *inode {
	if !e.virtual {
		// An unlinked inode never names a file of the host again. The host
		// can reuse its inode number once nothing holds the file open.
		if ino, ok := fs.inodes[e.info.id]; ok && ino.kind == e.info.kind && !ino.unlinked.Load() {
			ino.update(e)
			return ino
		}
	}
	ino := &inode{
		fs:      fs,
		id:      e.info.id,
		virtual: e.virtual,
		kind:    e.info.kind,
		ino:     e.info.id.ino,
		cur:     e,
	}
	if e.virtual {
		ino.ino = virtualInoFor(rel)
	} else {
		fs.inodes[e.info.id] = ino
	}
	ino.data.init(ino)
	ino.initSpecial(e)
	return ino
}

// dentry implements vfs.DentryImpl.
type dentry struct {
	vfsd vfs.Dentry
	// refs counts the VFS and file description references, plus one for the
	// parent's child map and one for every cached child.
	refs atomicbitops.Int64
	fs   *filesystem

	// nameMu protects parent, name, and relPath for readers that do not hold
	// fs.mu. Writers hold both.
	nameMu  sync.RWMutex
	parent  *dentry
	name    string
	relPath string

	// inode, children, and dead are protected by fs.mu.
	inode    *inode
	children map[string]*dentry
	dead     bool
}

func (fs *filesystem) newDentryLocked(parent *dentry, name, rel string, ino *inode) *dentry {
	d := &dentry{
		fs:      fs,
		parent:  parent,
		name:    name,
		relPath: rel,
		inode:   ino,
	}
	d.vfsd.Init(d)
	d.refs.Store(1)
	ino.refs++
	fs.dentryCount++
	if parent != nil {
		parent.refs.Add(1)
		if parent.children == nil {
			parent.children = make(map[string]*dentry)
		}
		parent.children[name] = d
	}
	return d
}

func (d *dentry) path() string {
	d.nameMu.RLock()
	defer d.nameMu.RUnlock()
	return d.relPath
}

func (d *dentry) names() (parent *dentry, name string) {
	d.nameMu.RLock()
	defer d.nameMu.RUnlock()
	return d.parent, d.name
}

// IncRef implements vfs.DentryImpl.IncRef.
func (d *dentry) IncRef() {
	d.refs.Add(1)
}

// TryIncRef implements vfs.DentryImpl.TryIncRef.
func (d *dentry) TryIncRef() bool {
	return chunkcache.TryIncRef(&d.refs)
}

// DecRef implements vfs.DentryImpl.DecRef.
func (d *dentry) DecRef(ctx context.Context) {
	if d.refs.Add(-1) == 0 {
		d.fs.lock()
		d.fs.destroyLocked(d)
		d.fs.unlock(ctx)
	}
}

func (d *dentry) decRefLocked() {
	if d.refs.Add(-1) == 0 {
		d.fs.destroyLocked(d)
	}
}

// destroyLocked frees a dentry that no reference reaches any more.
func (fs *filesystem) destroyLocked(d *dentry) {
	fs.dentryCount--
	ino := d.inode
	ino.refs--
	if ino.refs == 0 {
		if !ino.virtual && fs.inodes[ino.id] == ino {
			delete(fs.inodes, ino.id)
		}
		ino.destroy()
	}
	if d.parent != nil {
		d.parent.decRefLocked()
	}
}

// InotifyWithParent implements vfs.DentryImpl.InotifyWithParent.
func (d *dentry) InotifyWithParent(ctx context.Context, events, cookie uint32, et vfs.EventType) {
	if parent, name := d.names(); parent != nil {
		parent.inode.watches.Notify(ctx, name, events, cookie, et, false)
	}
	d.inode.watches.Notify(ctx, "", events, cookie, et, false)
}

// AdmitInotifyWatch is called by inotify_add_watch(2) before a new guest watch
// joins d. It attaches the host watch and returns ENOSPC when the workspace
// already watches maxWatchedDentries other objects. A dentry that has a host
// watch always passes, so a mask update never fails. Any other host error
// leaves the guest watch without host events and only logs the reason.
func (d *dentry) AdmitInotifyWatch() error {
	err := d.fs.ws.watchDentry(d)
	if err == nil {
		return nil
	}
	if linuxerr.Equals(linuxerr.ENOSPC, err) {
		return linuxerr.ENOSPC
	}
	d.fs.ws.logWatchRefusal(d, err)
	return nil
}

// Watches implements vfs.DentryImpl.Watches.
func (d *dentry) Watches() *vfs.Watches {
	// A guest inotify watch is about to join this set, or it is leaving. The
	// VFS offers no hook that can fail the add, so a refusal of the cap leaves
	// the guest watch without host events and only logs the reason.
	if err := d.fs.ws.watchDentry(d); err != nil {
		d.fs.ws.logWatchRefusal(d, err)
	}
	return &d.inode.watches
}

// OnZeroWatches implements vfs.DentryImpl.OnZeroWatches.
func (d *dentry) OnZeroWatches(ctx context.Context) {
	d.fs.ws.unwatchDentry(d)
}

// dropLocked removes d and its cached children from the tree after the host
// object they described changed or vanished.
func (fs *filesystem) dropLocked(d *dentry) {
	for _, c := range d.children {
		fs.dropLocked(c)
	}
	fs.detachLocked(d)
	deferDecRef(fs, fs.vfsfs.VirtualFilesystem().InvalidateDentry(context.Background(), &d.vfsd))
}

// detachLocked removes d from its parent's child map and drops the cache
// reference. Open files and mounts keep the dentry alive.
func (fs *filesystem) detachLocked(d *dentry) {
	if d.dead {
		return
	}
	d.dead = true
	if d.parent != nil && d.parent.children[d.name] == d {
		delete(d.parent.children, d.name)
	}
	d.decRefLocked()
}

// pruneLocked drops dentries that only the cache references.
func (fs *filesystem) pruneLocked(d *dentry) {
	for _, c := range d.children {
		fs.pruneLocked(c)
	}
	if d != fs.root && len(d.children) == 0 && d.refs.Load() == 1 && !d.inode.pinnedLocked() {
		fs.detachLocked(d)
	}
}

func (fs *filesystem) maybePruneLocked() {
	if fs.dentryCount < fs.pruneAt {
		return
	}
	fs.pruneLocked(fs.root)
	if fs.dentryCount > fs.pruneAt/2 {
		fs.pruneAt *= 2
	}
}

// attachChildLocked creates the dentry for entry e below parent. A non-zero
// until marks the metadata of a new inode as valid up to that time.
func (fs *filesystem) attachChildLocked(parent *dentry, name, rel string, e entry, until int64) *dentry {
	fs.maybePruneLocked()
	ino := fs.inodeForLocked(e, rel)
	// An inode without dentries is new, so no other path can change it yet.
	fresh := ino.refs == 0
	d := fs.newDentryLocked(parent, name, rel, ino)
	if fresh && until != 0 {
		ino.markValid(until)
	}
	return d
}

// lookupChildLocked finds name in parent. The returned error is a Linux errno.
//
// Consistency contract: a result that this filesystem produced or confirmed
// stays valid for cacheTTL without a host call. A guest mutation of the entry,
// of a hard link to it, or of its parent drops the result at once, and so
// does a listing of the parent. A change by a host process, or through another
// mount of the same host directory, shows up after cacheTTL at the latest.
func (fs *filesystem) lookupChildLocked(parent *dentry, name string) (*dentry, error) {
	now := fs.ws.nowNano()
	child := parent.children[name]
	if child != nil {
		if child.inode.metaFresh(now) {
			return child, nil
		}
	} else if parent.inode.negHit(name, now) {
		return nil, linuxerr.ENOENT
	}
	var seq uint64
	if child != nil {
		seq = child.inode.beginMeta()
	}
	e, err := fs.ws.lookupIn(parent.relPath, name)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			if child != nil {
				fs.dropLocked(child)
			}
			parent.inode.negAdd(name, now)
		}
		return nil, translateLookupError(err)
	}
	until := now + int64(cacheTTL)
	if child != nil {
		if child.inode.matches(e) {
			child.inode.commitMeta(e, seq, until)
			return child, nil
		}
		fs.dropLocked(child)
	}
	return fs.attachChildLocked(parent, name, joinRelPath(parent.relPath, name), e, until), nil
}

// refreshLocked revalidates d against the host. It makes no host call while
// the cached metadata of d is valid.
func (fs *filesystem) refreshLocked(d *dentry) error {
	if d.dead {
		return nil
	}
	now := fs.ws.nowNano()
	if d.inode.metaFresh(now) {
		return nil
	}
	seq := d.inode.beginMeta()
	e, err := fs.ws.lookupPath(d.relPath)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) && d != fs.root {
			fs.dropLocked(d)
		}
		return translateLookupError(err)
	}
	if !d.inode.matches(e) {
		if d != fs.root {
			fs.dropLocked(d)
		}
		return linuxerr.ENOENT
	}
	d.inode.commitMeta(e, seq, now+int64(cacheTTL))
	return nil
}

// stepLocked resolves rp.Component() below d. The Boolean result reports that
// a symbolic link was followed.
//
// Preconditions: fs.mu is held and !rp.Done().
func (fs *filesystem) stepLocked(ctx context.Context, rp *vfs.ResolvingPath, d *dentry) (*dentry, bool, error) {
	if !d.inode.isDir() {
		return nil, false, linuxerr.ENOTDIR
	}
	if err := d.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, false, err
	}
	name := rp.Component()
	if name == "." {
		rp.Advance()
		return d, false, nil
	}
	if name == ".." {
		if isRoot, err := rp.CheckRoot(ctx, &d.vfsd); err != nil {
			return nil, false, err
		} else if isRoot || d.parent == nil {
			rp.Advance()
			return d, false, nil
		}
		parent := d.parent
		if err := rp.CheckMount(ctx, &parent.vfsd); err != nil {
			return nil, false, err
		}
		rp.Advance()
		return parent, false, nil
	}
	if len(name) > maxFilenameLen {
		return nil, false, linuxerr.ENAMETOOLONG
	}
	child, err := fs.lookupChildLocked(d, name)
	if err != nil {
		return nil, false, err
	}
	if err := rp.CheckMount(ctx, &child.vfsd); err != nil {
		return nil, false, err
	}
	if child.inode.isSymlink() && rp.ShouldFollowSymlink() {
		followed, err := rp.HandleSymlink(child.inode.snapshot().attr.Symlink)
		return d, followed, err
	}
	rp.Advance()
	return child, false, nil
}

// walkParentDirLocked resolves all but the last component of rp to a
// directory. It does not check that the caller may search the result.
//
// Preconditions: fs.mu is held and !rp.Done().
func (fs *filesystem) walkParentDirLocked(ctx context.Context, rp *vfs.ResolvingPath, d *dentry) (*dentry, error) {
	for !rp.Final() {
		next, _, err := fs.stepLocked(ctx, rp, d)
		if err != nil {
			return nil, err
		}
		d = next
	}
	if !d.inode.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	return d, nil
}

// resolveLocked resolves rp to an existing file.
//
// Preconditions: fs.mu is held.
func (fs *filesystem) resolveLocked(ctx context.Context, rp *vfs.ResolvingPath) (*dentry, error) {
	start := rp.Start().Impl().(*dentry)
	d := start
	if d.inode.isSymlink() && rp.Done() && rp.ShouldFollowSymlink() {
		if _, err := rp.HandleSymlink(d.inode.snapshot().attr.Symlink); err != nil {
			return nil, err
		}
	} else {
		for !rp.Done() {
			next, _, err := fs.stepLocked(ctx, rp, d)
			if err != nil {
				return nil, err
			}
			d = next
		}
		if d == start {
			if err := fs.refreshLocked(d); err != nil {
				return nil, err
			}
		}
	}
	if rp.MustBeDir() && !d.inode.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	return d, nil
}

// newOwnerLocked returns the owner of a new child: the caller's credentials,
// with the group inherited from a set-group-ID parent directory.
func newOwner(parent *inode, creds *auth.Credentials) (auth.KUID, auth.KGID, bool) {
	e := parent.snapshot()
	if linux.FileMode(e.attr.Mode)&linux.ModeSetGID != 0 {
		return creds.EffectiveKUID, auth.KGID(e.attr.GID), true
	}
	return creds.EffectiveKUID, creds.EffectiveKGID, false
}

// doCreateAt checks that creating a file at rp is permitted, then calls create.
//
// Preconditions: !rp.Done() and rp.ShouldFollowSymlink() is false for the last
// component.
func (fs *filesystem) doCreateAt(ctx context.Context, rp *vfs.ResolvingPath, dir bool, create func(parent *dentry, name, rel string) error) error {
	fs.lock()
	defer fs.unlock(ctx)
	parent, err := fs.walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	if err := parent.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return linuxerr.EEXIST
	}
	if len(name) > maxFilenameLen {
		return linuxerr.ENAMETOOLONG
	}
	if _, err := fs.lookupChildLocked(parent, name); err == nil {
		return linuxerr.EEXIST
	} else if !linuxerr.Equals(linuxerr.ENOENT, err) {
		return err
	}
	if !dir && rp.MustBeDir() {
		return linuxerr.ENOENT
	}
	if parent.dead {
		return linuxerr.ENOENT
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	if err := parent.inode.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
		return err
	}
	if err := create(parent, name, joinRelPath(parent.relPath, name)); err != nil {
		if linuxerr.Equals(linuxerr.EEXIST, err) {
			// The name exists on the host, so a negative entry is stale.
			parent.inode.negDel(name)
		}
		return err
	}
	parent.inode.negDel(name)
	parent.inode.invalidateMeta()
	ev := linux.IN_CREATE
	if dir {
		ev |= linux.IN_ISDIR
	}
	parent.inode.watches.Notify(ctx, name, uint32(ev), 0, vfs.InodeEvent, false)
	return nil
}

// AccessAt implements vfs.FilesystemImpl.AccessAt.
func (fs *filesystem) AccessAt(ctx context.Context, rp *vfs.ResolvingPath, creds *auth.Credentials, ats vfs.AccessTypes) error {
	fs.lock()
	defer fs.unlock(ctx)
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		return err
	}
	if err := d.inode.checkPermissions(creds, ats); err != nil {
		return err
	}
	if ats.MayWrite() && fs.ws.ReadOnly() {
		return linuxerr.EROFS
	}
	return vfs.CheckMountAccess(rp, ats, d.inode.mode())
}

// GetDentryAt implements vfs.FilesystemImpl.GetDentryAt.
func (fs *filesystem) GetDentryAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetDentryOptions) (*vfs.Dentry, error) {
	fs.lock()
	defer fs.unlock(ctx)
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		return nil, err
	}
	if opts.CheckSearchable {
		if !d.inode.isDir() {
			return nil, linuxerr.ENOTDIR
		}
		if err := d.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
			return nil, err
		}
	}
	d.IncRef()
	return &d.vfsd, nil
}

// GetParentDentryAt implements vfs.FilesystemImpl.GetParentDentryAt.
func (fs *filesystem) GetParentDentryAt(ctx context.Context, rp *vfs.ResolvingPath) (*vfs.Dentry, error) {
	fs.lock()
	defer fs.unlock(ctx)
	d, err := fs.walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return nil, err
	}
	d.IncRef()
	return &d.vfsd, nil
}

// LinkAt implements vfs.FilesystemImpl.LinkAt. It creates a real host hard
// link: both names share one host file, one inode number, and one link count.
func (fs *filesystem) LinkAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry) error {
	return fs.doCreateAt(ctx, rp, false, func(parent *dentry, name, rel string) error {
		if rp.Mount() != vd.Mount() {
			return linuxerr.EXDEV
		}
		src := vd.Dentry().Impl().(*dentry)
		if src.dead {
			// An unnamed file from O_TMPFILE is the only dead file that can
			// gain a name.
			return fs.linkTmpLocked(rp.Credentials(), src, parent, name, rel)
		}
		if src.inode.isDir() {
			return linuxerr.EPERM
		}
		e := src.inode.snapshot()
		if err := vfs.MayLink(rp.Credentials(), linux.FileMode(e.attr.Mode), nil, auth.KUID(e.attr.UID), auth.KGID(e.attr.GID)); err != nil {
			return err
		}
		if err := fs.ws.link(src.relPath, rel); err != nil {
			return translateHostError(err)
		}
		// The link count of the shared inode changed.
		src.inode.invalidateMeta()
		src.inode.fs.ws.watchNoteInode(src.inode)
		src.inode.watches.Notify(ctx, "", linux.IN_ATTRIB, 0, vfs.InodeEvent, false)
		return nil
	})
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	return fs.doCreateAt(ctx, rp, true, func(parent *dentry, name, rel string) error {
		uid, gid, inherit := newOwner(parent.inode, rp.Credentials())
		mode := uint32(opts.Mode) & 0o7777
		if inherit {
			mode |= linux.S_ISGID
		}
		if err := fs.ws.mkdir(rel, mode, uint32(uid), uint32(gid)); err != nil {
			return translateHostError(err)
		}
		return nil
	})
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt. Symbolic links live in
// .gvx_meta: the host never receives a link, so no host link can leave the
// workspace.
func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	return fs.doCreateAt(ctx, rp, false, func(parent *dentry, name, rel string) error {
		uid, gid, _ := newOwner(parent.inode, rp.Credentials())
		if err := fs.ws.symlink(target, rel, uint32(uid), uint32(gid)); err != nil {
			return translateHostError(err)
		}
		return nil
	})
}

// OpenAt implements vfs.FilesystemImpl.OpenAt.
func (fs *filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	if opts.Flags&linux.O_TMPFILE != 0 {
		return fs.openTmpfile(ctx, rp, opts)
	}

	if opts.Flags&linux.O_CREAT == 0 {
		fs.lock()
		d, err := fs.resolveLocked(ctx, rp)
		if err != nil {
			fs.unlock(ctx)
			return nil, err
		}
		d.IncRef()
		fs.unlock(ctx)
		defer d.DecRef(ctx)
		return d.open(ctx, rp, &opts, nil)
	}

	mustCreate := opts.Flags&linux.O_EXCL != 0
	start := rp.Start().Impl().(*dentry)
	fs.lock()
	unlocked := false
	unlock := func() {
		if !unlocked {
			fs.unlock(ctx)
			unlocked = true
		}
	}
	defer unlock()
	if rp.Done() {
		if rp.MustBeDir() {
			return nil, linuxerr.EISDIR
		}
		if mustCreate {
			return nil, linuxerr.EEXIST
		}
		if err := fs.refreshLocked(start); err != nil {
			return nil, err
		}
		start.IncRef()
		defer start.DecRef(ctx)
		unlock()
		return start.open(ctx, rp, &opts, nil)
	}
	retriedExist := false
afterTrailingSymlink:
	parent, err := fs.walkParentDirLocked(ctx, rp, start)
	if err != nil {
		return nil, err
	}
	if err := parent.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, err
	}
	if rp.MustBeDir() {
		return nil, linuxerr.EISDIR
	}
	name := rp.Component()
	child, followed, err := fs.stepLocked(ctx, rp, parent)
	if followed {
		if mustCreate {
			return nil, linuxerr.EEXIST
		}
		if err != nil {
			return nil, err
		}
		start = parent
		goto afterTrailingSymlink
	}
	if linuxerr.Equals(linuxerr.ENOENT, err) {
		if name == "." || name == ".." {
			return nil, linuxerr.EISDIR
		}
		if err := parent.inode.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
			return nil, err
		}
		if err := rp.Mount().CheckBeginWrite(); err != nil {
			return nil, err
		}
		defer rp.Mount().EndWrite()
		rel := joinRelPath(parent.relPath, name)
		uid, gid, _ := newOwner(parent.inode, rp.Credentials())
		f, e, err := fs.ws.createHandle(rel, uint32(opts.Mode)&0o7777, uint32(uid), uint32(gid))
		if errors.Is(err, iofs.ErrExist) && !mustCreate && !retriedExist {
			// A host process created the name after the negative entry. Drop
			// the entry and resolve the name again, once.
			retriedExist = true
			parent.inode.negDel(name)
			start = parent
			goto afterTrailingSymlink
		}
		if err != nil {
			return nil, translateHostError(err)
		}
		parent.inode.negDel(name)
		parent.inode.invalidateMeta()
		child = fs.attachChildLocked(parent, name, rel, e, fs.ws.nowNano()+int64(cacheTTL))
		child.IncRef()
		defer child.DecRef(ctx)
		unlock()
		fd, err := child.open(ctx, rp, &opts, f)
		if err != nil {
			return nil, err
		}
		fd.SetCreated()
		parent.inode.watches.Notify(ctx, name, linux.IN_CREATE, 0, vfs.PathEvent, false)
		return fd, nil
	}
	if err != nil {
		return nil, err
	}
	if mustCreate {
		return nil, linuxerr.EEXIST
	}
	if rp.MustBeDir() && !child.inode.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	child.IncRef()
	defer child.DecRef(ctx)
	unlock()
	return child.open(ctx, rp, &opts, nil)
}

// open creates the file description for d. created is the host handle of a
// file that OpenAt just created, or nil.
//
// Preconditions: fs.mu is not held.
func (d *dentry) open(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions, created *hostHandle) (*vfs.FileDescription, error) {
	closeCreated := func() {
		if created != nil {
			_ = created.decRef()
		}
	}
	ats := vfs.AccessTypesForOpenFlags(opts)
	if opts.FileExec && !d.inode.isRegular() && !d.inode.isSymlink() {
		closeCreated()
		return nil, linuxerr.EACCES
	}
	if created == nil {
		if err := d.inode.checkPermissions(rp.Credentials(), ats); err != nil {
			return nil, err
		}
		// Linux rejects a write open of a running program. The check covers
		// O_TRUNC, which AccessTypesForOpenFlags folds into the write access.
		if ats.MayWrite() {
			if err := d.inode.checkWritable(); err != nil {
				return nil, err
			}
		}
	}
	switch {
	case d.inode.isRegular():
		return d.openRegular(ctx, rp, opts, created)
	case d.inode.isDir():
		closeCreated()
		if opts.Flags&linux.O_CREAT != 0 || ats&vfs.MayWrite != 0 {
			return nil, linuxerr.EISDIR
		}
		if opts.Flags&linux.O_DIRECT != 0 {
			return nil, linuxerr.EINVAL
		}
		fd := &dirFD{}
		fd.dentry = d
		fd.LockFD.Init(&d.inode.locks)
		if err := fd.vfsfd.Init(fd, opts.Flags, rp.Credentials(), rp.Mount(), &d.vfsd, &vfs.FileDescriptionOptions{AllowDirectIO: true}); err != nil {
			return nil, err
		}
		return &fd.vfsfd, nil
	case d.inode.isSpecial():
		closeCreated()
		return d.openSpecial(ctx, rp, opts)
	default:
		closeCreated()
		// Symlinks open only with O_PATH, which the VFS layer handles.
		return nil, linuxerr.ELOOP
	}
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	fs.lock()
	defer fs.unlock(ctx)
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		return "", err
	}
	if !d.inode.isSymlink() {
		return "", linuxerr.EINVAL
	}
	return d.inode.snapshot().attr.Symlink, nil
}

// mayDelete reports whether creds may remove child from parent.
func mayDelete(creds *auth.Credentials, parent, child *inode) error {
	if err := parent.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	pe, ce := parent.snapshot(), child.snapshot()
	return vfs.CheckDeleteSticky(creds, linux.FileMode(pe.attr.Mode), auth.KUID(pe.attr.UID), auth.KUID(ce.attr.UID), auth.KGID(ce.attr.GID))
}

// isAncestorLocked reports whether anc is d or an ancestor of d.
func isAncestorLocked(anc, d *dentry) bool {
	for ; d != nil; d = d.parent {
		if d == anc {
			return true
		}
	}
	return false
}

// RenameAt implements vfs.FilesystemImpl.RenameAt.
func (fs *filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, oldParentVD vfs.VirtualDentry, oldName string, opts vfs.RenameOptions) error {
	fs.lock()
	defer fs.unlock(ctx)
	newParent, err := fs.walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	if err := checkRenameFlags(opts.Flags); err != nil {
		return err
	}
	if opts.Flags&linux.RENAME_WHITEOUT != 0 {
		// Linux asks for CAP_MKNOD in the initial user namespace, because
		// the whiteout is a device node.
		creds := rp.Credentials()
		if !creds.HasCapabilityIn(linux.CAP_MKNOD, creds.UserNamespace.Root()) {
			return linuxerr.EPERM
		}
	}
	newName := rp.Component()
	if newName == "." || newName == ".." {
		if opts.Flags&linux.RENAME_NOREPLACE != 0 {
			return linuxerr.EEXIST
		}
		return linuxerr.EBUSY
	}
	if len(newName) > maxFilenameLen {
		return linuxerr.ENAMETOOLONG
	}
	mnt := rp.Mount()
	if mnt != oldParentVD.Mount() {
		return linuxerr.EXDEV
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	if opts.Flags&linux.RENAME_EXCHANGE != 0 {
		return fs.exchangeAt(ctx, rp, newParent, newName, oldParentVD.Dentry().Impl().(*dentry), oldName, opts)
	}

	creds := rp.Credentials()
	oldParent := oldParentVD.Dentry().Impl().(*dentry)
	if err := oldParent.inode.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	renamed, err := fs.lookupChildLocked(oldParent, oldName)
	if err != nil {
		return err
	}
	if err := mayDelete(creds, oldParent.inode, renamed.inode); err != nil {
		return err
	}
	if renamed.inode.isDir() {
		if isAncestorLocked(renamed, newParent) {
			return linuxerr.EINVAL
		}
		if oldParent != newParent {
			if err := renamed.inode.checkPermissions(creds, vfs.MayWrite); err != nil {
				return err
			}
		}
	} else if opts.MustBeDir || rp.MustBeDir() {
		return linuxerr.ENOTDIR
	}
	if err := newParent.inode.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	replaced, err := fs.lookupChildLocked(newParent, newName)
	if err != nil && !linuxerr.Equals(linuxerr.ENOENT, err) {
		return err
	}
	if err != nil {
		replaced = nil
	}
	if replaced != nil {
		if opts.Flags&linux.RENAME_NOREPLACE != 0 {
			return linuxerr.EEXIST
		}
		if err := mayDelete(creds, newParent.inode, replaced.inode); err != nil {
			return err
		}
		if replaced.inode.isDir() {
			if !renamed.inode.isDir() {
				return linuxerr.EISDIR
			}
		} else if rp.MustBeDir() || renamed.inode.isDir() {
			return linuxerr.ENOTDIR
		}
		if renamed == replaced || (renamed.inode == replaced.inode && !renamed.inode.isDir()) {
			// POSIX: renaming a name onto another name of the same file does
			// nothing.
			return nil
		}
	}
	if newParent.dead {
		return linuxerr.ENOENT
	}

	oldRel := joinRelPath(oldParent.relPath, oldName)
	newRel := joinRelPath(newParent.relPath, newName)
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	var replacedVFSD *vfs.Dentry
	if replaced != nil {
		replacedVFSD = &replaced.vfsd
	}
	handle, err := vfsObj.PrepareRenameDentry(mntns, &renamed.vfsd, replacedVFSD)
	if err != nil {
		return err
	}
	vfsObj.RenameBegin(&handle)
	var replacedLinks uint32
	if replaced != nil {
		replacedLinks = fs.specialLinksLocked(replaced)
	}
	whiteout := opts.Flags&linux.RENAME_WHITEOUT != 0
	var renameErr error
	if whiteout {
		renameErr = fs.ws.renameWhiteout(oldRel, newRel)
	} else {
		renameErr = fs.ws.rename(oldRel, newRel)
	}
	if renameErr != nil {
		vfsObj.AbortRenameDentry(&handle, &renamed.vfsd, replacedVFSD)
		return translateHostError(renameErr)
	}
	// The moved inode, the replaced inode, and both parents change times or
	// link counts. The old name is gone, and the new name is taken.
	now := fs.ws.nowNano()
	renamed.inode.invalidateMeta()
	oldParent.inode.invalidateMeta()
	newParent.inode.invalidateMeta()
	if whiteout {
		// The whiteout holds the old name now.
		oldParent.inode.negDel(oldName)
	} else {
		oldParent.inode.negAdd(oldName, now)
	}
	newParent.inode.negDel(newName)
	if replaced != nil {
		replaced.inode.invalidateMeta()
		replaced.inode.noteReplaced()
		fs.retireSpecialLocked(replaced.inode, replacedLinks)
		fs.detachLocked(replaced)
	}
	fs.moveLocked(renamed, newParent, newName, newRel)
	fs.ws.watchNoteInode(renamed.inode)
	deferDecRef(fs, vfsObj.CommitRenameReplaceDentry(ctx, &handle, &renamed.vfsd, replacedVFSD))
	vfs.InotifyRename(ctx, &renamed.inode.watches, &oldParent.inode.watches, &newParent.inode.watches, oldName, newName, renamed.inode.isDir())
	return nil
}

// moveLocked re-parents d and rewrites the cached path of d and of every
// cached descendant. Open files and later lookups then agree on the new names.
func (fs *filesystem) moveLocked(d, newParent *dentry, newName, newRel string) {
	oldParent := d.parent
	if oldParent.children[d.name] == d {
		delete(oldParent.children, d.name)
	}
	if newParent.children == nil {
		newParent.children = make(map[string]*dentry)
	}
	newParent.children[newName] = d
	newParent.refs.Add(1)
	d.nameMu.Lock()
	d.parent = newParent
	d.name = newName
	d.nameMu.Unlock()
	fs.rewritePathLocked(d, newRel)
	oldParent.decRefLocked()
}

func (fs *filesystem) rewritePathLocked(d *dentry, rel string) {
	d.nameMu.Lock()
	d.relPath = rel
	d.nameMu.Unlock()
	for name, c := range d.children {
		fs.rewritePathLocked(c, joinRelPath(rel, name))
	}
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.lock()
	defer fs.unlock(ctx)
	parent, err := fs.walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	creds := rp.Credentials()
	if err := parent.inode.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." {
		return linuxerr.EINVAL
	}
	if name == ".." {
		return linuxerr.ENOTEMPTY
	}
	child, err := fs.lookupChildLocked(parent, name)
	if err != nil {
		return err
	}
	if err := mayDelete(creds, parent.inode, child.inode); err != nil {
		return err
	}
	if !child.inode.isDir() {
		return linuxerr.ENOTDIR
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	if err := vfsObj.PrepareDeleteDentry(mntns, &child.vfsd); err != nil {
		return err
	}
	if err := fs.ws.rmdir(child.relPath); err != nil {
		vfsObj.AbortDeleteDentry(&child.vfsd)
		return translateHostError(err)
	}
	parent.inode.invalidateMeta()
	parent.inode.negAdd(name, fs.ws.nowNano())
	for _, c := range child.children {
		fs.dropLocked(c)
	}
	fs.detachLocked(child)
	parent.inode.watches.Notify(ctx, name, linux.IN_DELETE|linux.IN_ISDIR, 0, vfs.InodeEvent, true)
	deferDecRef(fs, vfsObj.CommitDeleteDentry(ctx, &child.vfsd))
	return nil
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt. The host removes the name
// at once, even while file descriptions keep the file open.
func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.lock()
	defer fs.unlock(ctx)
	parent, err := fs.walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	creds := rp.Credentials()
	if err := parent.inode.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return linuxerr.EISDIR
	}
	child, err := fs.lookupChildLocked(parent, name)
	if err != nil {
		return err
	}
	if err := mayDelete(creds, parent.inode, child.inode); err != nil {
		return err
	}
	if child.inode.isDir() {
		return linuxerr.EISDIR
	}
	if rp.MustBeDir() {
		return linuxerr.ENOTDIR
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	if err := vfsObj.PrepareDeleteDentry(mntns, &child.vfsd); err != nil {
		return err
	}
	links := fs.specialLinksLocked(child)
	last, err := fs.ws.unlinkLast(child.relPath)
	if err != nil {
		vfsObj.AbortDeleteDentry(&child.vfsd)
		return translateHostError(err)
	}
	fs.retireSpecialLocked(child.inode, links)
	if last {
		child.inode.noteUnlinked()
	}
	// The link count of the shared inode and the times of the parent change.
	child.inode.invalidateMeta()
	parent.inode.invalidateMeta()
	parent.inode.negAdd(name, fs.ws.nowNano())
	// Notify before the dentry dies, or the watches would be dropped first.
	fs.ws.watchNoteInode(child.inode)
	vfs.InotifyRemoveChild(ctx, &child.inode.watches, &parent.inode.watches, name)
	fs.detachLocked(child)
	deferDecRef(fs, vfsObj.CommitDeleteDentry(ctx, &child.vfsd))
	return nil
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	fs.lock()
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		fs.unlock(ctx)
		return err
	}
	d.IncRef()
	fs.unlock(ctx)
	defer d.DecRef(ctx)
	if err := d.setStat(ctx, rp.Credentials(), rp.Mount(), &opts, nil); err != nil {
		return err
	}
	if ev := vfs.InotifyEventFromStatMask(opts.Stat.Mask); ev != 0 {
		d.InotifyWithParent(ctx, ev, 0, vfs.InodeEvent)
	}
	return nil
}

// setStat applies opts to d. h is the open host handle when the caller is a
// file description, which lets truncation work on an unlinked file.
//
// Preconditions: fs.mu is not held.
func (d *dentry) setStat(ctx context.Context, creds *auth.Credentials, mnt *vfs.Mount, opts *vfs.SetStatOptions, h *hostHandle) error {
	e := d.inode.snapshot()
	if err := vfs.CheckSetStat(ctx, creds, opts, linux.FileMode(e.attr.Mode), nil, auth.KUID(e.attr.UID), auth.KGID(e.attr.GID)); err != nil {
		return err
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	if d.fs.ws.ReadOnly() {
		return linuxerr.EROFS
	}
	stat := &opts.Stat
	if stat.Mask&linux.STATX_SIZE != 0 {
		if d.inode.isDir() {
			return linuxerr.EISDIR
		}
		if !d.inode.isRegular() {
			return linuxerr.EINVAL
		}
		if opts.NeedWritePerm {
			// truncate(2), unlike ftruncate(2), needs write access to the
			// file and so fails while a process executes it.
			if err := d.inode.checkWritable(); err != nil {
				return err
			}
		}
		if err := d.inode.truncate(d, h, int64(stat.Size)); err != nil {
			return err
		}
	}

	var mode, uid, gid *uint32
	if stat.Mask&linux.STATX_MODE != 0 {
		m := uint32(stat.Mode) & 0o7777
		mode = &m
	}
	if stat.Mask&linux.STATX_UID != 0 {
		uid = &stat.UID
	}
	if stat.Mask&linux.STATX_GID != 0 {
		gid = &stat.GID
	}
	if opts.ClearPrivs && !d.inode.isDir() {
		m := vfs.ClearSUIDAndSGID(uint32(e.attr.Mode)) & 0o7777
		if mode != nil {
			m = vfs.ClearSUIDAndSGID(*mode|e.attr.Mode&linux.S_IFMT) & 0o7777
		}
		mode = &m
	}
	if mode != nil || uid != nil || gid != nil {
		if err := d.setAttr(mode, uid, gid); err != nil {
			return err
		}
	}

	if stat.Mask&(linux.STATX_ATIME|linux.STATX_MTIME) != 0 {
		now := time.Now()
		var at, mt *time.Time
		if stat.Mask&linux.STATX_ATIME != 0 {
			t := statxTime(stat.Atime, now)
			at = &t
		}
		if stat.Mask&linux.STATX_MTIME != 0 {
			t := statxTime(stat.Mtime, now)
			mt = &t
		}
		if d.isDead() {
			return linuxerr.ENOENT
		}
		d.inode.guestBegin()
		err := d.fs.ws.chtimes(d.path(), at, mt)
		d.inode.guestEndPath(d.path())
		if err != nil {
			return translateHostError(err)
		}
	}
	d.inode.invalidateMeta()
	return d.refresh()
}

func statxTime(ts linux.StatxTimestamp, now time.Time) time.Time {
	if ts.Nsec == linux.UTIME_NOW {
		return now
	}
	return time.Unix(ts.Sec, int64(ts.Nsec))
}

func (d *dentry) isDead() bool {
	d.fs.mu.Lock()
	defer d.fs.mu.Unlock()
	return d.dead
}

// setAttr changes virtual attributes. A dentry that no longer has a name
// updates only the inode snapshot that open files see.
func (d *dentry) setAttr(mode, uid, gid *uint32) error {
	if !d.isDead() {
		if err := d.fs.ws.setAttr(d.path(), mode, uid, gid); err != nil {
			return translateHostError(err)
		}
		d.inode.invalidateMeta()
		return nil
	}
	d.inode.attrMu.Lock()
	defer d.inode.attrMu.Unlock()
	a := &d.inode.cur.attr
	if mode != nil {
		a.Mode = a.Mode&linux.S_IFMT | *mode&0o7777
	}
	if uid != nil {
		a.UID = *uid
	}
	if gid != nil {
		a.GID = *gid
	}
	return nil
}

// refresh updates the inode snapshot from the host after a change. It makes
// no host call while the cached snapshot is valid.
func (d *dentry) refresh() error {
	if d.isDead() {
		return nil
	}
	now := d.fs.ws.nowNano()
	if d.inode.metaFresh(now) {
		return nil
	}
	seq := d.inode.beginMeta()
	e, err := d.fs.ws.lookupPath(d.path())
	if err != nil {
		return translateHostError(err)
	}
	if d.inode.matches(e) {
		d.inode.commitMeta(e, seq, now+int64(cacheTTL))
	}
	return nil
}

// StatAt implements vfs.FilesystemImpl.StatAt.
func (fs *filesystem) StatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.StatOptions) (linux.Statx, error) {
	fs.lock()
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		fs.unlock(ctx)
		return linux.Statx{}, err
	}
	stat := d.inode.statx(fs.devMinor)
	fs.unlock(ctx)
	rp.AddMountRootAttr(&d.vfsd, &stat)
	return stat, nil
}

func statxTimestamp(t time.Time) linux.StatxTimestamp {
	return linux.StatxTimestamp{Sec: t.Unix(), Nsec: uint32(t.Nanosecond())}
}

// statx builds the stat result from the last observed state.
func (i *inode) statx(devMinor uint32) linux.Statx {
	return i.statxFor(i.snapshot(), devMinor)
}

// statxFor builds the stat result for entry e of this inode.
func (i *inode) statxFor(e entry, devMinor uint32) linux.Statx {
	info := e.info
	nlink := info.nlink
	switch {
	case i.unlinked.Load():
		// No name reaches the file. Linux and macOS report this through
		// fstat. A Windows file keeps a link count while a handle stays
		// open, and a named temporary file keeps its host name.
		nlink = 0
	case e.isDir() && nlink < 2:
		nlink = 2
	}
	btime := info.btime
	if btime.IsZero() {
		btime = info.mtime
	}
	blocks := uint64(info.blocks)
	if blocks == 0 && info.size > 0 {
		blocks = (uint64(info.size) + 511) / 512
	}
	st := linux.Statx{
		Mask:     linux.STATX_BASIC_STATS | linux.STATX_BTIME,
		Blksize:  4096,
		Nlink:    nlink,
		UID:      e.attr.UID,
		GID:      e.attr.GID,
		Mode:     uint16(e.attr.Mode),
		Ino:      i.ino,
		Size:     uint64(info.size),
		Blocks:   blocks,
		Atime:    statxTimestamp(info.atime),
		Mtime:    statxTimestamp(info.mtime),
		Ctime:    statxTimestamp(info.ctime),
		Btime:    statxTimestamp(btime),
		DevMajor: 0,
		DevMinor: devMinor,
	}
	st.RdevMajor, st.RdevMinor = unpackRdev(e.attr.Rdev)
	return st
}

// StatFSAt implements vfs.FilesystemImpl.StatFSAt. It reports the capacity of
// the host volume.
func (fs *filesystem) StatFSAt(ctx context.Context, rp *vfs.ResolvingPath) (linux.Statfs, error) {
	fs.lock()
	_, err := fs.resolveLocked(ctx, rp)
	fs.unlock(ctx)
	if err != nil {
		return linux.Statfs{}, err
	}
	return fs.statFS()
}

// GetPosixACLAt implements vfs.FilesystemImpl.GetPosixACLAt.
func (fs *filesystem) GetPosixACLAt(ctx context.Context, rp *vfs.ResolvingPath, t vfs.ACLType) (*vfs.PosixACL, error) {
	return nil, linuxerr.EOPNOTSUPP
}

// SetPosixACLAt implements vfs.FilesystemImpl.SetPosixACLAt.
func (fs *filesystem) SetPosixACLAt(ctx context.Context, rp *vfs.ResolvingPath, t vfs.ACLType, acl *vfs.PosixACL, clearSGID bool) (*vfs.PosixACL, linux.FileMode, error) {
	return nil, 0, linuxerr.EOPNOTSUPP
}

// PrependPath implements vfs.FilesystemImpl.PrependPath.
func (fs *filesystem) PrependPath(ctx context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
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

// IsDescendant implements vfs.FilesystemImpl.IsDescendant.
func (fs *filesystem) IsDescendant(vfsroot, vd vfs.VirtualDentry) bool {
	if vfsroot.Mount() != vd.Mount() {
		return false
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return isAncestorLocked(vfsroot.Dentry().Impl().(*dentry), vd.Dentry().Impl().(*dentry))
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	return ""
}
