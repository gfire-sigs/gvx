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
	"sync"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/checkpoint"
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
//
// +stateify savable
type InternalFilesystemOptions struct {
	Workspace   *Workspace `state:"nosave"`
	UniqueID    checkpoint.ResourceID
	RestoreMode bool
}

// FilesystemType implements vfs.FilesystemType for hostfs.
//
// +stateify savable
type FilesystemType struct{}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// Release implements vfs.FilesystemType.Release.
func (FilesystemType) Release(ctx context.Context) {}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fsType FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	ws, uniqueID, ownsWS, err := resolveWorkspaceForMount(source, opts)
	if err != nil {
		return nil, nil, err
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
		ws:         ws,
		ownsWS:     ownsWS,
		devMinor:   devMinor,
		uniqueID:   uniqueID,
		singleFile: ws.SingleFile(),
		inodes:     make(map[hostID]*inode),
		liveInodes: make(map[*inode]struct{}),
		pruneAt:    pruneThreshold,
		openFDs:    make(map[*regularFD]struct{}),
	}
	hfs.vfsfs.Init(vfsObj, fsType, hfs)
	hfs.mu.Lock()
	hfs.root = hfs.newDentryLocked(nil, "", ".", hfs.inodeForLocked(rootEntry, "."))
	// One reference for the filesystem and one for the mount.
	hfs.root.refs.Add(1)
	hfs.mu.Unlock()
	return &hfs.vfsfs, &hfs.root.vfsd, nil
}

func resolveWorkspaceForMount(source string, opts vfs.GetFilesystemOptions) (*Workspace, checkpoint.ResourceID, bool, error) {
	var (
		ws          *Workspace
		uniqueID    checkpoint.ResourceID
		restoreMode bool
	)
	if internalOpts, ok := opts.InternalData.(InternalFilesystemOptions); ok {
		uniqueID = internalOpts.UniqueID
		restoreMode = internalOpts.RestoreMode
		ws = internalOpts.Workspace
	}
	if ws != nil {
		return ws, uniqueID, false, nil
	}
	if source == "" {
		return nil, checkpoint.ResourceID{}, false, linuxerr.EINVAL
	}
	var err error
	if restoreMode {
		ws, err = OpenWorkspaceForRestore(source, false)
	} else {
		ws, err = OpenWorkspace(source, false)
	}
	if err != nil {
		return nil, checkpoint.ResourceID{}, false, translateHostError(err)
	}
	return ws, uniqueID, true, nil
}

// filesystem implements vfs.FilesystemImpl. The host is the source of truth.
// A path step revalidates against the workspace when its cached result has
// expired or a mutation dropped it. The dentry tree also keeps object identity
// stable for open files, mounts, and watches. The consistency contract is in
// lookupChildLocked.
// +stateify savable
type filesystem struct {
	vfsfs            vfs.Filesystem
	ws               *Workspace `state:"nosave"`
	ownsWS           bool
	devMinor         uint32
	uniqueID         checkpoint.ResourceID
	singleFile       bool
	preserveSavedTmp bool `state:"nosave"`

	// mu protects the dentry tree, dentry names and paths, the inode map, and
	// pending. Lock order: filesystem.mu, then Workspace.mu, then inode locks.
	mu         sync.Mutex `state:"nosave"`
	root       *dentry
	inodes     map[hostID]*inode
	liveInodes map[*inode]struct{}
	// pending holds references returned by the VFS that must be dropped after
	// mu is released, because dropping them can release this filesystem.
	pending []decRefer `state:"nosave"`

	dentryCount int
	pruneAt     int

	// openFDsMu is a leaf lock protecting openFDs.
	openFDsMu sync.Mutex `state:"nosave"`
	openFDs   map[*regularFD]struct{}
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

// lock takes fs.mu.
//
// +checklocksacquire:fs.mu
func (fs *filesystem) lock() {
	fs.mu.Lock()
}

// unlock releases fs.mu and drops the references that deferDecRef collected.
//
// +checklocksrelease:fs.mu
func (fs *filesystem) unlock(ctx context.Context) {
	pending := fs.pending
	fs.pending = nil
	fs.mu.Unlock()
	for _, r := range pending {
		r.DecRef(ctx)
	}
}

// snapshotInodes returns all unique live and mapped inodes in the filesystem.
func (fs *filesystem) snapshotInodes() []*inode {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	capHint := max(len(fs.inodes), len(fs.liveInodes))
	inodes := make([]*inode, 0, capHint)
	seen := make(map[*inode]struct{}, capHint)
	for _, ino := range fs.inodes {
		seen[ino] = struct{}{}
		inodes = append(inodes, ino)
	}
	for ino := range fs.liveInodes {
		if _, ok := seen[ino]; !ok {
			seen[ino] = struct{}{}
			inodes = append(inodes, ino)
		}
	}
	return inodes
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	if fs.ws != nil {
		for _, ino := range fs.snapshotInodes() {
			if err := ino.syncData(); err != nil {
				ctx.Warningf("hostfs: write back mapped data at unmount: %v", err)
			}
		}
		if err := fs.ws.Sync(); err != nil {
			ctx.Warningf("hostfs: flush metadata at unmount: %v", err)
		}
	}
	fs.mu.Lock()
	if fs.root != nil {
		fs.root.decRefLocked()
	}
	fs.mu.Unlock()
	fs.vfsfs.VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	if fs.ownsWS && fs.ws != nil {
		_ = fs.ws.Close()
	}
}

// Sync implements vfs.FilesystemImpl.Sync. It writes back mapped file data and
// flushes the metadata table, and it reports every failure.
func (fs *filesystem) Sync(ctx context.Context) error {
	var errs []error
	for _, ino := range fs.snapshotInodes() {
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
// +stateify savable
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
	attrMu     sync.Mutex `state:"nosave"`
	cur        entry
	metaValid  bool   `state:"nosave"`
	timesStale bool   `state:"nosave"`
	metaUntil  int64  `state:"nosave"`
	metaSeq    uint64 `state:"nosave"`

	// negChildren holds the names that a lookup in this directory did not
	// find, so a repeated lookup makes no host call. negUntil ends the life of
	// the whole set. Protected by fs.mu.
	negChildren map[string]struct{} `state:"nosave"`
	negUntil    int64               `state:"nosave"`

	// wmu serialises writes so that O_APPEND is atomic.
	wmu sync.Mutex `state:"nosave"`

	data fileData

	// writeCount tracks the processes that execute this file, which blocks
	// every write to it. Hard links share the count. See exec_busy.go.
	writeCount vfs.WriteCount

	// unlinked reports that no name in the namespace reaches the inode any
	// more.
	unlinked atomicbitops.Bool

	// tmp holds the host state of a file that the guest created with
	// O_TMPFILE, or nil. Protected by fs.mu. See tmpfile.go.
	tmp *tmpFile

	savedRel    string
	savedTmpRel string

	// special holds the in-memory state of a socket, a FIFO, or a device
	// node. See special_node.go.
	special specialState

	// guest records the host state that the last guest write produced.
	guest guestState `state:"nosave"`

	// dirLinks caches the counted link count of a directory on a host that
	// does not count directory links. See dirlinks.go.
	dirLinks dirLinkCache `state:"nosave"`
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

// metaFresh reports whether cur is valid at time now, with current size and
// times.
func (i *inode) metaFresh(now int64) bool {
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	return i.metaValid && !i.timesStale && now < i.metaUntil
}

// identityFresh reports whether cur names the right host object, with the
// right mode and owner, at time now. The size and the times can be stale.
func (i *inode) identityFresh(now int64) bool {
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	return i.metaValid && now < i.metaUntil
}

// markDataChanged records that a write changed the size and the times of the
// host file.
func (i *inode) markDataChanged() {
	i.attrMu.Lock()
	i.timesStale = true
	i.metaSeq++
	i.attrMu.Unlock()
}

// invalidateMeta marks cur as stale.
func (i *inode) invalidateMeta() {
	i.attrMu.Lock()
	i.metaValid = false
	i.metaSeq++
	i.attrMu.Unlock()
}

// beginMeta returns the token that commitMeta needs.
func (i *inode) beginMeta() uint64 {
	i.attrMu.Lock()
	defer i.attrMu.Unlock()
	return i.metaSeq
}

// commitMeta stores e and marks it valid until the given time, unless a
// mutation invalidated the inode after beginMeta returned seq.
func (i *inode) commitMeta(e entry, seq uint64, until int64) {
	i.attrMu.Lock()
	i.cur = e
	if i.metaSeq == seq {
		i.metaValid = true
		i.timesStale = false
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
	return i.data.SyncData()
}

// destroy releases the resources of an inode with no dentries left.
func (i *inode) destroy() {
	if i.fs.ws != nil {
		i.fs.ws.watchForget(i)
		if !i.fs.preserveSavedTmp && i.savedTmpRel != "" && (i.tmp == nil || !i.tmp.named()) {
			i.fs.ws.removeEphemeral(i.savedTmpRel)
		}
	}
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
	if fs.liveInodes == nil {
		fs.liveInodes = make(map[*inode]struct{})
	}
	fs.liveInodes[ino] = struct{}{}
	ino.data.init(ino)
	ino.initSpecial(e)
	return ino
}

// dentry implements vfs.DentryImpl.
//
// +stateify savable
type dentry struct {
	vfsd vfs.Dentry
	// refs counts the VFS and file description references, plus one for the
	// parent's child map and one for every cached child.
	refs atomicbitops.Int64
	fs   *filesystem

	// nameMu protects parent, name, and relPath for readers that do not hold
	// fs.mu. Writers hold both.
	nameMu  sync.RWMutex `state:"nosave"`
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
		delete(fs.liveInodes, ino)
		if !ino.virtual && fs.inodes[ino.id] == ino {
			delete(fs.inodes, ino.id)
		}
		ino.destroy()
	}
	if d.parent != nil {
		d.parent.decRefLocked()
	}
}
