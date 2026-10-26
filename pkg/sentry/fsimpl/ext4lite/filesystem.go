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

// Package ext4lite implements a read-write VFS2 filesystem inside one host
// file. The file holds an ext4 image that the engine in this package reads and
// writes. The engine is in volume.go and the files that it uses. The files
// filesystem.go, namespace.go, regular_file.go, directory.go, special.go, and
// mmap.go connect the engine to the Sentry VFS.
package ext4lite

import (
	"errors"
	"sync"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/refs"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/chunkcache"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/socket/unix/transport"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// Name is the name of the filesystem type.
const Name = "ext4lite"

const (
	// pruneThreshold is the dentry count above which the cache drops the
	// dentries that nothing references. The engine rebuilds them on demand.
	pruneThreshold = 1 << 16

	// maxLinks is the largest link count of an inode. The on-disk field has
	// 16 bits, and ext4 stops at this number without the dir_nlink feature.
	maxLinks = 65000
)

// ChunkMemory supplies the memory for the chunks of mapped files.
type ChunkMemory = chunkcache.ChunkMemory

// SetChunkMemory makes mem back the chunks that files create from now on. Call
// it once before the first mapping, and only with memory that outlives every
// mapping.
func (vol *Volume) SetChunkMemory(mem ChunkMemory) {
	vol.chunkMem.Set(mem)
}

// chunkMemory returns the shared chunk memory, or nil.
func (vol *Volume) chunkMemory() ChunkMemory {
	return vol.chunkMem.Get()
}

// InternalFilesystemOptions is the vfs.GetFilesystemOptions.InternalData of a
// mount. The sandbox opens the volume before the host lockdown and passes it
// here. The ReadOnly option of the volume, not the read-only flag of the mount,
// decides whether the volume accepts writes.
type InternalFilesystemOptions struct {
	Volume *Volume
}

// FilesystemType implements vfs.FilesystemType for ext4lite.
type FilesystemType struct{}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// Release implements vfs.FilesystemType.Release.
func (FilesystemType) Release(ctx context.Context) {}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem. A volume serves
// one filesystem, and the filesystem closes the volume when the VFS releases
// it.
func (fsType FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	iopts, ok := opts.InternalData.(InternalFilesystemOptions)
	if !ok || iopts.Volume == nil {
		return nil, nil, linuxerr.EINVAL
	}
	vol := iopts.Volume
	if !vol.mounted.CompareAndSwap(false, true) {
		return nil, nil, linuxerr.EBUSY
	}
	// fsckLite dropped what it could not keep. The notes tell the user why a
	// file is missing.
	for _, note := range vol.v.repairNotes {
		ctx.Warningf("ext4lite: repaired the volume: %s", note)
	}
	fail := func(err error) (*vfs.Filesystem, *vfs.Dentry, error) {
		vol.mounted.Store(false)
		return nil, nil, err
	}
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return fail(err)
	}
	rootNode, err := vol.v.getNode(rootIno)
	if err != nil {
		vfsObj.PutAnonBlockDevMinor(devMinor)
		return fail(toLinuxErr(err))
	}
	fs := &filesystem{
		vol:      vol,
		v:        vol.v,
		readOnly: vol.v.readOnly,
		devMinor: devMinor,
		inodes:   make(map[uint32]*inode),
		pruneAt:  pruneThreshold,
	}
	fs.vfsfs.Init(vfsObj, fsType, fs)
	fs.mu.Lock()
	fs.root = fs.newDentryLocked(nil, "", fs.inodeForNodeLocked(rootNode))
	// One reference for the filesystem and one for the mount.
	fs.root.refs.Add(1)
	fs.mu.Unlock()
	vol.dataSync.Store(&dataSyncHook{fn: fs.syncMapped})
	if !fs.readOnly {
		fs.startFlusher()
	}
	return &fs.vfsfs, &fs.root.vfsd, nil
}

// filesystem implements vfs.FilesystemImpl. The engine is the only writer of
// the volume, so the dentry tree is a cache that is always current. A change
// of the namespace goes through filesystem.mu.
type filesystem struct {
	vfsfs    vfs.Filesystem
	vol      *Volume
	v        *volume
	readOnly bool
	devMinor uint32

	// mu protects the dentry tree, the names of dentries, the inode map, and
	// pending. Lock order: mu, then the locks of the engine nodes, then the
	// lock of the volume.
	mu     sync.Mutex
	root   *dentry
	inodes map[uint32]*inode
	// pending holds references that the VFS returned and that must drop after
	// mu is released, because dropping them can release this filesystem.
	pending []refs.RefCounter

	dentryCount int
	pruneAt     int

	// flusher is the background flush of a writable filesystem.
	flusher *flusher
}

func (fs *filesystem) lock(ctx context.Context) {
	fs.mu.Lock()
	fs.maybePruneLocked(ctx)
}

func (fs *filesystem) unlock(ctx context.Context) {
	pending := fs.pending
	fs.pending = nil
	fs.mu.Unlock()
	for _, r := range pending {
		r.DecRef(ctx)
	}
}

// deferDecRef queues references to drop after mu is released.
func (fs *filesystem) deferDecRef(list []refs.RefCounter) {
	fs.pending = append(fs.pending, list...)
}

// now returns the current time as an inode time.
func (fs *filesystem) now() tstamp {
	t := fs.v.now()
	return tstamp{sec: t.Unix(), nsec: uint32(t.Nanosecond())}
}

// beginWrite checks that the volume and the mount accept a write, and it enters
// the operation gate. On success the caller calls endWrite once.
//
// The call first throttles the guest while too many nodes wait for a flush, so
// that one transaction never outgrows the journal. The throttle runs before the
// gate, because a flush needs the gate closed.
func (fs *filesystem) beginWrite(mnt *vfs.Mount) error {
	if fs.readOnly {
		return linuxerr.EROFS
	}
	if err := fs.v.throttle(); err != nil {
		return toLinuxErr(err)
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	fs.v.gate.enterOp()
	return nil
}

// endWrite ends the operation that beginWrite started.
func (fs *filesystem) endWrite(mnt *vfs.Mount) {
	fs.v.gate.exit()
	mnt.EndWrite()
}

// retryHeld runs op. An operation that fails with ENOSPC while freed space waits
// for a flush gets one more try after the flush. op must return with the gate
// open and with no node lock. It can run under fs.mu, because a flush takes no
// filesystem lock. The retry depends on the volume state and not on a flag that
// the failed call set, because parallel operations would overwrite such a flag.
func (fs *filesystem) retryHeld(op func() error) error {
	err := op()
	if err == nil || !linuxerr.Equals(linuxerr.ENOSPC, err) || !fs.v.hasHeld() {
		return err
	}
	if serr := fs.v.sync(); serr != nil {
		return toLinuxErr(serr)
	}
	return op()
}

// writeOp runs op as one guest operation that changes the volume. op runs in the
// gate, and the wrapper retries it once after a flush when the volume ran out of
// space that a flush frees.
func (fs *filesystem) writeOp(mnt *vfs.Mount, op func() error) error {
	return fs.retryHeld(func() error {
		if err := fs.beginWrite(mnt); err != nil {
			return err
		}
		defer fs.endWrite(mnt)
		return op()
	})
}

// Release implements vfs.FilesystemImpl.Release. It writes back mapped data,
// drops the nodes, and runs the clean unmount of the volume. The unmount
// compacts the trailing groups, truncates the host file, and sets the valid bit.
func (fs *filesystem) Release(ctx context.Context) {
	fs.stopFlusher()
	fs.mu.Lock()
	inodes := fs.inodes
	fs.inodes = make(map[uint32]*inode)
	for _, ino := range inodes {
		ino.destroy(ctx)
	}
	fs.mu.Unlock()
	fs.vol.dataSync.Store(nil)
	// Release has no error result, so a failure is logged. An earlier Sync
	// call already reported the failures that it saw.
	if err := fs.vol.Close(); err != nil {
		ctx.Warningf("ext4lite: unmount the volume: %v", err)
	}
	fs.vfsfs.VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
}

// Sync implements vfs.FilesystemImpl.Sync.
//
// The sync protocol of the specification keeps a dirty tracker. Here the
// tracker is the union of two parts. The chunks of mapped pages track the dirty
// file data, and the engine tracks its dirty nodes, directory blocks,
// bitmaps, and flags. Sync first writes the dirty chunks to the host file
// through node.writeAt. Then it calls volume.sync, which writes the metadata
// in the strict order and flushes the host file.
func (fs *filesystem) Sync(ctx context.Context) error {
	return fs.syncAll()
}

// syncAll writes the dirty mapped data of every inode and then flushes the
// volume. It reports every failure as a Linux error.
func (fs *filesystem) syncAll() error {
	err := fs.syncMapped()
	if serr := fs.v.sync(); serr != nil {
		err = errors.Join(err, serr)
	}
	return toLinuxErr(err)
}

// syncMapped writes the dirty mapped data of every inode to the host file. The
// volume drain of a live migration calls it before the flush of the volume.
func (fs *filesystem) syncMapped() error {
	fs.mu.Lock()
	list := make([]*inode, 0, len(fs.inodes))
	for _, ino := range fs.inodes {
		if ino.isRegular() {
			list = append(list, ino)
		}
	}
	fs.mu.Unlock()
	var errs []error
	for _, ino := range list {
		err := ino.data.SyncData()
		if errors.Is(err, errSpaceHeld) && fs.v.hasHeld() {
			// The write-back found no free block while freed blocks wait for a
			// flush. The flush runs with the gate open.
			if serr := fs.v.sync(); serr == nil {
				err = ino.data.SyncData()
			}
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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
	if len(name) > maxNameLen {
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
		target, err := child.inode.symlinkTarget()
		if err != nil {
			return nil, false, err
		}
		followed, err := rp.HandleSymlink(target)
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
	d := rp.Start().Impl().(*dentry)
	if d.inode.isSymlink() && rp.Done() && rp.ShouldFollowSymlink() {
		target, err := d.inode.symlinkTarget()
		if err != nil {
			return nil, err
		}
		if _, err := rp.HandleSymlink(target); err != nil {
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
	}
	if rp.MustBeDir() && !d.inode.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	return d, nil
}

// AccessAt implements vfs.FilesystemImpl.AccessAt.
func (fs *filesystem) AccessAt(ctx context.Context, rp *vfs.ResolvingPath, creds *auth.Credentials, ats vfs.AccessTypes) error {
	fs.lock(ctx)
	defer fs.unlock(ctx)
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		return err
	}
	if err := d.inode.checkPermissions(creds, ats); err != nil {
		return err
	}
	if ats.MayWrite() && fs.readOnly {
		return linuxerr.EROFS
	}
	mode, _, _ := d.inode.owner()
	return vfs.CheckMountAccess(rp, ats, mode)
}

// GetDentryAt implements vfs.FilesystemImpl.GetDentryAt.
func (fs *filesystem) GetDentryAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetDentryOptions) (*vfs.Dentry, error) {
	fs.lock(ctx)
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
	fs.lock(ctx)
	defer fs.unlock(ctx)
	d, err := fs.walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return nil, err
	}
	d.IncRef()
	return &d.vfsd, nil
}

// StatAt implements vfs.FilesystemImpl.StatAt.
func (fs *filesystem) StatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.StatOptions) (linux.Statx, error) {
	fs.lock(ctx)
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		fs.unlock(ctx)
		return linux.Statx{}, err
	}
	stat := d.inode.statx()
	fs.unlock(ctx)
	rp.AddMountRootAttr(&d.vfsd, &stat)
	return stat, nil
}

// StatFSAt implements vfs.FilesystemImpl.StatFSAt.
func (fs *filesystem) StatFSAt(ctx context.Context, rp *vfs.ResolvingPath) (linux.Statfs, error) {
	fs.lock(ctx)
	defer fs.unlock(ctx)
	if _, err := fs.resolveLocked(ctx, rp); err != nil {
		return linux.Statfs{}, err
	}
	return fs.statfs(), nil
}

// statfs reports the space of the volume. The numbers come from the engine,
// which counts the room for new groups up to the size limit and up to the free
// space of the host volume.
func (fs *filesystem) statfs() linux.Statfs {
	info := fs.v.statfs()
	return linux.Statfs{
		Type:            linux.EXT_SUPER_MAGIC,
		BlockSize:       blockSize,
		FragmentSize:    blockSize,
		Blocks:          info.blocks,
		BlocksFree:      info.bfree,
		BlocksAvailable: info.bfree,
		Files:           info.files,
		FilesFree:       info.ffree,
		NameLength:      maxNameLen,
	}
}

// GetPosixACLAt implements vfs.FilesystemImpl.GetPosixACLAt.
func (fs *filesystem) GetPosixACLAt(ctx context.Context, rp *vfs.ResolvingPath, t vfs.ACLType) (*vfs.PosixACL, error) {
	return nil, linuxerr.EOPNOTSUPP
}

// SetPosixACLAt implements vfs.FilesystemImpl.SetPosixACLAt.
func (fs *filesystem) SetPosixACLAt(ctx context.Context, rp *vfs.ResolvingPath, t vfs.ACLType, acl *vfs.PosixACL, clearSGID bool) (*vfs.PosixACL, linux.FileMode, error) {
	return nil, 0, linuxerr.EOPNOTSUPP
}

// BoundEndpointAt implements vfs.FilesystemImpl.BoundEndpointAt. It returns the
// endpoint that bind(2) stored in a socket file. A socket file from an earlier
// mount has no endpoint, and a connect to it fails with ECONNREFUSED.
func (fs *filesystem) BoundEndpointAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.BoundEndpointOptions) (transport.BoundEndpoint, error) {
	fs.lock(ctx)
	defer fs.unlock(ctx)
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		return nil, err
	}
	if err := d.inode.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
		return nil, err
	}
	if d.inode.kind != modeSocket || d.inode.ep == nil {
		return nil, linuxerr.ECONNREFUSED
	}
	return d.inode.ep, nil
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

// isAncestorLocked reports whether anc is d or an ancestor of d.
func isAncestorLocked(anc, d *dentry) bool {
	for ; d != nil; d = d.parent {
		if d == anc {
			return true
		}
	}
	return false
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	return ""
}
