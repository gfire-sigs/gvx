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

package ext4lite

import (
	"sync"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/chunkcache"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/kernel/pipe"
	"z.gfire.dev/gvx/pkg/sentry/socket/unix/transport"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// attr is a consistent copy of the attributes of one node.
type attr struct {
	mode    uint16
	uid     uint32
	gid     uint32
	links   uint32
	size    uint64
	atime   tstamp
	mtime   tstamp
	ctime   tstamp
	crtime  tstamp
	rdev    uint32
	nblocks uint64
}

// inode is the identity of one engine node in the VFS. Hard links share one
// inode, so they share locks, watches, and the page cache of mapped pages. The
// inode owns one reference on the engine node.
type inode struct {
	fs   *filesystem
	n    *node
	ino  uint32
	kind uint16 // node type bits, constant for the life of the inode

	// refs counts the dentries that name this inode. fs.mu protects it.
	refs int

	locks      vfs.FileLocks
	watches    vfs.Watches
	writeCount vfs.WriteCount

	// wmu serializes writes and truncation, so that O_APPEND is atomic.
	wmu sync.Mutex

	// data is the page cache of mapped pages. Only regular files use it.
	data fileData

	// pipe is the pipe of a FIFO.
	pipe *pipe.VFSPipe

	// ep is the endpoint that a bind(2) stored in a socket inode. It is lost
	// when the inode leaves the cache, so the cache pins such an inode. fs.mu
	// protects it.
	ep transport.BoundEndpoint

	// targetOnce guards target, the immutable content of a symlink.
	targetOnce sync.Once
	target     string
	targetErr  error
}

func (i *inode) isDir() bool     { return i.kind == modeDir }
func (i *inode) isRegular() bool { return i.kind == modeRegular }
func (i *inode) isSymlink() bool { return i.kind == modeSymlink }

// attr returns the attributes of the node.
func (i *inode) attr() attr {
	n := i.n
	n.mu.RLock()
	defer n.mu.RUnlock()
	return attr{
		mode: n.mode, uid: n.uid, gid: n.gid, links: n.links, size: n.size,
		atime: n.atime, mtime: n.mtime, ctime: n.ctime, crtime: n.crtime,
		rdev: n.rdev, nblocks: n.nblocks,
	}
}

// owner returns the mode and owner of the node.
func (i *inode) owner() (linux.FileMode, auth.KUID, auth.KGID) {
	n := i.n
	n.mu.RLock()
	defer n.mu.RUnlock()
	return linux.FileMode(n.mode), auth.KUID(n.uid), auth.KGID(n.gid)
}

func (i *inode) checkPermissions(creds *auth.Credentials, ats vfs.AccessTypes) error {
	mode, uid, gid := i.owner()
	return vfs.GenericCheckPermissions(creds, ats, mode, nil, uid, gid)
}

// mutate changes the node under its lock and registers it for the next flush.
func (i *inode) mutate(f func(n *node)) {
	n := i.n
	n.mu.Lock()
	f(n)
	n.markDirtyLocked()
	n.mu.Unlock()
}

// touchMCtime sets the modification and change times to now.
func (i *inode) touchMCtime() {
	now := i.fs.now()
	i.mutate(func(n *node) { n.mtime, n.ctime = now, now })
}

// touchCtime sets the change time to now.
func (i *inode) touchCtime() {
	now := i.fs.now()
	i.mutate(func(n *node) { n.ctime = now })
}

// addLinks adds delta to the link count and sets the change time.
func (i *inode) addLinks(delta int) {
	now := i.fs.now()
	i.mutate(func(n *node) {
		if delta < 0 && n.links < uint32(-delta) {
			n.links = 0
		} else {
			n.links = uint32(int64(n.links) + int64(delta))
		}
		n.ctime = now
	})
}

// destroy releases the inode after its last dentry died. The mapped-page cache
// goes first, and the engine frees the storage when no name remains.
func (i *inode) destroy(ctx context.Context) {
	i.n.mu.RLock()
	unlinked := i.n.links == 0
	i.n.mu.RUnlock()
	if err := i.data.release(!unlinked); err != nil {
		ctx.Warningf("ext4lite: write back mapped data of inode %d: %v", i.ino, err)
	}
	i.fs.v.putNode(i.n)
}

// dentry implements vfs.DentryImpl.
type dentry struct {
	vfsd vfs.Dentry

	// refs counts the VFS and file description references, one reference of
	// the parent's child map, and one reference for every cached child.
	refs atomicbitops.Int64
	fs   *filesystem

	// nameMu protects parent and name for readers that do not hold fs.mu.
	// Writers hold both.
	nameMu sync.RWMutex
	parent *dentry
	name   string

	// inode, children, and dead are protected by fs.mu.
	inode    *inode
	children map[string]*dentry
	dead     bool
}

// newDentryLocked creates the dentry of name below parent and adds it to the
// child map. The caller owns the one reference that the map holds.
func (fs *filesystem) newDentryLocked(parent *dentry, name string, ino *inode) *dentry {
	d := &dentry{fs: fs, parent: parent, name: name, inode: ino}
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
		d.fs.mu.Lock()
		d.fs.destroyLocked(ctx, d)
		d.fs.unlock(ctx)
	}
}

func (d *dentry) decRefLocked(ctx context.Context) {
	if d.refs.Add(-1) == 0 {
		d.fs.destroyLocked(ctx, d)
	}
}

// destroyLocked frees a dentry that no reference reaches any more.
func (fs *filesystem) destroyLocked(ctx context.Context, d *dentry) {
	fs.dentryCount--
	ino := d.inode
	ino.refs--
	if ino.refs == 0 {
		delete(fs.inodes, ino.ino)
		ino.destroy(ctx)
	}
	if d.parent != nil {
		d.parent.decRefLocked(ctx)
	}
}

// InotifyWithParent implements vfs.DentryImpl.InotifyWithParent.
func (d *dentry) InotifyWithParent(ctx context.Context, events, cookie uint32, et vfs.EventType) {
	if d.inode.isDir() {
		events |= linux.IN_ISDIR
	}
	deleted := d.vfsd.IsDead()
	if parent, name := d.names(); parent != nil {
		parent.inode.watches.Notify(ctx, name, events, cookie, et, deleted)
	}
	d.inode.watches.Notify(ctx, "", events, cookie, et, deleted)
}

// Watches implements vfs.DentryImpl.Watches.
func (d *dentry) Watches() *vfs.Watches {
	return &d.inode.watches
}

// OnZeroWatches implements vfs.DentryImpl.OnZeroWatches.
func (d *dentry) OnZeroWatches(ctx context.Context) {}

// WriteCount implements vfs.WriteCounter.
func (d *dentry) WriteCount() *vfs.WriteCount {
	return &d.inode.writeCount
}

// detachLocked removes d from its parent's child map and drops the cache
// reference. Open files and mounts keep the dentry alive.
func (fs *filesystem) detachLocked(ctx context.Context, d *dentry) {
	if d.dead {
		return
	}
	d.dead = true
	if d.parent != nil && d.parent.children[d.name] == d {
		delete(d.parent.children, d.name)
	}
	d.decRefLocked(ctx)
}

// pruneLocked drops the dentries that only the cache references. A socket
// inode stays, because the endpoint of a bound socket lives in the inode.
func (fs *filesystem) pruneLocked(ctx context.Context, d *dentry) {
	for _, c := range d.children {
		fs.pruneLocked(ctx, c)
	}
	if d != fs.root && len(d.children) == 0 && d.refs.Load() == 1 && d.inode.ep == nil {
		fs.detachLocked(ctx, d)
	}
}

// maybePruneLocked bounds the dentry cache. It runs when an operation starts,
// while the operation holds a reference on its start dentry, so it never drops
// a dentry that the operation walks.
func (fs *filesystem) maybePruneLocked(ctx context.Context) {
	if fs.dentryCount < fs.pruneAt {
		return
	}
	fs.pruneLocked(ctx, fs.root)
	if fs.dentryCount > fs.pruneAt/2 {
		fs.pruneAt *= 2
	}
}

// moveLocked moves d below newParent under newName.
func (fs *filesystem) moveLocked(ctx context.Context, d, newParent *dentry, newName string) {
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
	oldParent.decRefLocked(ctx)
}

// inodeForNodeLocked returns the inode of n and takes over the engine
// reference of the caller. When the filesystem already holds an inode for the
// node, it drops the extra reference.
func (fs *filesystem) inodeForNodeLocked(n *node) *inode {
	if ino, ok := fs.inodes[n.ino]; ok {
		fs.v.putNode(n)
		return ino
	}
	n.mu.RLock()
	kind := n.mode & modeTypeMask
	n.mu.RUnlock()
	ino := &inode{fs: fs, n: n, ino: n.ino, kind: kind}
	ino.data.init(ino)
	if kind == modeFIFO {
		ino.pipe = pipe.NewVFSPipe(true /* isNamed */, pipe.DefaultPipeSize)
	}
	fs.inodes[n.ino] = ino
	return ino
}

// lookupChildLocked finds name in parent and creates its dentry when the cache
// has none. Every change of the volume goes through this filesystem, so a
// cached dentry is always current.
func (fs *filesystem) lookupChildLocked(parent *dentry, name string) (*dentry, error) {
	if c := parent.children[name]; c != nil {
		return c, nil
	}
	ino, ft, err := parent.inode.n.lookup(name)
	if err != nil {
		return nil, toLinuxErr(err)
	}
	ci, ok := fs.inodes[ino]
	if !ok {
		n, err := fs.v.getNode(ino)
		if err != nil {
			return nil, toLinuxErr(err)
		}
		n.mu.RLock()
		mode := n.mode
		n.mu.RUnlock()
		if fileTypeOfMode(mode) != ft {
			fs.v.putNode(n)
			return nil, linuxerr.EUCLEAN
		}
		ci = fs.inodeForNodeLocked(n)
	} else if fileTypeOfMode(ci.kind) != ft {
		return nil, linuxerr.EUCLEAN
	}
	return fs.newDentryLocked(parent, name, ci), nil
}
