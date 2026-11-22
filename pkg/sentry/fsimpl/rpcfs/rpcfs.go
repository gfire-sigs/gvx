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
	"hash/fnv"
	"io"
	"path"
	"strings"

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
	rpcfsMagic   = 0x72706366 // "rpcf"
	maxChunkSize = 64 << 10
)

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

// NewFilesystem constructs an rpcfs filesystem backed by client. The caller
// owns one reference on both the returned Filesystem and root Dentry.
func NewFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, client Client, label string) (*vfs.Filesystem, *vfs.Dentry, error) {
	if client == nil {
		return nil, nil, linuxerr.EINVAL
	}
	rootEntry := Entry{
		Ino:   1,
		Mode:  linux.S_IFDIR | 0o755,
		Nlink: 2,
	}
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, nil, err
	}
	fs := &filesystem{
		client:   client,
		label:    label,
		devMinor: devMinor,
	}
	fs.vfsfs.Init(vfsObj, FilesystemType{}, fs)
	fs.root = fs.newDentry(nil, "", ".", rootEntry)
	// One ref for fs.root, one ref returned to the caller for the mount.
	fs.root.refs.Store(2)
	return &fs.vfsfs, &fs.root.vfsd, nil
}

type filesystem struct {
	vfsfs    vfs.Filesystem
	client   Client
	label    string
	devMinor uint32

	// mu protects the dentry child map. Lock order: fs.mu before fs.ancestryMu.
	mu sync.Mutex
	// ancestryMu is a leaf lock protecting parent/name/relPath/dead for VFS
	// callbacks (PrependPath, IsDescendant, InotifyWithParent).
	ancestryMu sync.RWMutex
	root       *dentry
}

// MountSource implements vfs.MountSourceProvider.
func (fs *filesystem) MountSource() string {
	if fs.label != "" {
		return "rpcfs:" + fs.label
	}
	return "rpcfs"
}

func (fs *filesystem) Release(ctx context.Context) {
	if fs.root != nil {
		fs.root.DecRef(ctx)
		fs.root = nil
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
	parent  *dentry
	name    string
	relPath string
	dead    bool

	// Protected by fs.mu.
	children map[string]*dentry

	mode    atomicbitops.Uint32
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

func (fs *filesystem) newDentry(parent *dentry, name, rel string, e Entry) *dentry {
	ino := e.Ino
	if ino == 0 {
		ino = synthIno(rel)
	}
	d := &dentry{
		fs:      fs,
		parent:  parent,
		name:    name,
		relPath: rel,
	}
	d.mode.Store(e.Mode)
	d.ino.Store(ino)
	d.vfsd.Init(d)
	return d
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
	d.fs.ancestryMu.RUnlock()
	if parent != nil && name != "" {
		parent.watches.Notify(ctx, name, events, cookie, et, d.vfsd.IsDead())
	}
	d.watches.Notify(ctx, "", events, cookie, et, d.vfsd.IsDead())
}

func (d *dentry) Watches() *vfs.Watches         { return &d.watches }
func (d *dentry) OnZeroWatches(context.Context) {}

func (d *dentry) isDir() bool {
	return d.mode.Load()&linux.S_IFMT == linux.S_IFDIR
}

func (d *dentry) isSymlink() bool {
	return d.mode.Load()&linux.S_IFMT == linux.S_IFLNK
}

func (d *dentry) path() string {
	d.fs.ancestryMu.RLock()
	p := d.relPath
	d.fs.ancestryMu.RUnlock()
	return p
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

func (fs *filesystem) lookupChild(parent *dentry, name string) (*dentry, Entry, error) {
	rel := joinRel(parent.path(), name)
	e, err := fs.client.Stat(goContext.Background(), rel)
	if err != nil {
		if err == linuxerr.ENOENT {
			fs.mu.Lock()
			if parent.children != nil {
				delete(parent.children, name)
			}
			fs.mu.Unlock()
		}
		return nil, Entry{}, err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if parent.children == nil {
		parent.children = make(map[string]*dentry)
	}
	if existing, ok := parent.children[name]; ok && !existing.dead {
		if existing.mode.Load()&linux.S_IFMT == e.Mode&linux.S_IFMT {
			existing.mode.Store(e.Mode)
			if e.Ino != 0 {
				existing.ino.Store(e.Ino)
			}
			existing.IncRef()
			return existing, e, nil
		}
		delete(parent.children, name)
	}
	child := fs.newDentry(parent, name, rel, e)
	child.refs.Store(2) // 1 for cache, 1 for caller
	parent.children[name] = child
	return child, e, nil
}

func (fs *filesystem) step(ctx context.Context, rp *vfs.ResolvingPath, cur *dentry) (*dentry, Entry, bool, error) {
	if !cur.isDir() {
		return nil, Entry{}, false, linuxerr.ENOTDIR
	}
	name := rp.Component()
	if name == "." {
		rp.Advance()
		cur.IncRef()
		return cur, Entry{Mode: cur.mode.Load(), Ino: cur.ino.Load()}, false, nil
	}
	if name == ".." {
		if isRoot, err := rp.CheckRoot(ctx, &cur.vfsd); err != nil {
			return nil, Entry{}, false, err
		} else if isRoot {
			rp.Advance()
			cur.IncRef()
			return cur, Entry{Mode: cur.mode.Load(), Ino: cur.ino.Load()}, false, nil
		}
		fs.ancestryMu.RLock()
		parent := cur.parent
		fs.ancestryMu.RUnlock()
		if parent == nil {
			rp.Advance()
			cur.IncRef()
			return cur, Entry{Mode: cur.mode.Load(), Ino: cur.ino.Load()}, false, nil
		}
		if err := rp.CheckMount(ctx, &parent.vfsd); err != nil {
			return nil, Entry{}, false, err
		}
		rp.Advance()
		parent.IncRef()
		return parent, Entry{Mode: parent.mode.Load(), Ino: parent.ino.Load()}, false, nil
	}
	child, e, err := fs.lookupChild(cur, name)
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
			target, rlErr = fs.client.Readlink(goContext.Background(), child.path())
			if rlErr != nil {
				child.DecRef(ctx)
				return nil, Entry{}, false, rlErr
			}
		}
		child.DecRef(ctx)
		followed, err := rp.HandleSymlink(target)
		if err != nil {
			return nil, Entry{}, false, err
		}
		if followed {
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
		e, err := fs.client.Stat(goContext.Background(), cur.path())
		if err != nil {
			cur.DecRef(ctx)
			return nil, Entry{}, err
		}
		cur.mode.Store(e.Mode)
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
	return cur, nil
}

func (fs *filesystem) AccessAt(ctx context.Context, rp *vfs.ResolvingPath, creds *auth.Credentials, ats vfs.AccessTypes) error {
	d, e, err := fs.resolve(ctx, rp)
	if err != nil {
		return err
	}
	defer d.DecRef(ctx)
	if ats.MayWrite() && rp.Mount().ReadOnly() {
		return linuxerr.EROFS
	}
	return vfs.GenericCheckPermissions(creds, ats, linux.FileMode(e.Mode), nil, auth.KUID(e.UID), auth.KGID(e.GID))
}

func (fs *filesystem) GetDentryAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetDentryOptions) (*vfs.Dentry, error) {
	// Resolve the mount root (or already-reached start dentry) without an RPC
	// round-trip so UmountAt can detach a mount even after the client disconnects.
	if rp.Done() {
		d := rp.Start().Impl().(*dentry)
		if opts.CheckSearchable && !d.isDir() {
			return nil, linuxerr.ENOTDIR
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
	if rp.Mount().ReadOnly() {
		return linuxerr.EROFS
	}
	parent, err := fs.resolveParent(ctx, rp)
	if err != nil {
		return err
	}
	defer parent.DecRef(ctx)
	name := rp.Component()
	if name == "." || name == ".." {
		return linuxerr.EEXIST
	}
	rel := joinRel(parent.path(), name)
	if err := fs.client.Mkdir(goContext.Background(), rel, uint32(opts.Mode.Permissions())); err != nil {
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
		d   *dentry
		e   Entry
		err error
	)
	if mayCreate && !rp.Done() {
		parent, pErr := fs.resolveParent(ctx, rp)
		if pErr != nil {
			return nil, pErr
		}
		defer parent.DecRef(ctx)
		name := rp.Component()
		if name == "." || name == ".." {
			if mustCreate {
				return nil, linuxerr.EEXIST
			}
			d = parent
			d.IncRef()
			e, err = fs.client.Stat(goContext.Background(), d.path())
			if err != nil {
				d.DecRef(ctx)
				return nil, err
			}
		} else {
			child, ce, lErr := fs.lookupChild(parent, name)
			if lErr == nil {
				if mustCreate {
					child.DecRef(ctx)
					return nil, linuxerr.EEXIST
				}
				if ce.Mode&linux.S_IFMT == linux.S_IFLNK && rp.ShouldFollowSymlink() {
					target := ce.LinkTarget
					if target == "" {
						target, _ = fs.client.Readlink(goContext.Background(), child.path())
					}
					child.DecRef(ctx)
					if _, sErr := rp.HandleSymlink(target); sErr != nil {
						return nil, sErr
					}
					return nil, linuxerr.ELOOP
				}
				d, e = child, ce
			} else if lErr == linuxerr.ENOENT {
				if rp.Mount().ReadOnly() {
					return nil, linuxerr.EROFS
				}
				rel := joinRel(parent.path(), name)
				created, cErr := fs.client.Create(goContext.Background(), rel, uint32(opts.Mode.Permissions()), opts.Flags)
				if cErr != nil {
					return nil, cErr
				}
				if created.Mode&linux.S_IFMT == 0 {
					created.Mode |= linux.S_IFREG | uint32(opts.Mode.Permissions())
				}
				fs.mu.Lock()
				if parent.children == nil {
					parent.children = make(map[string]*dentry)
				}
				nd := fs.newDentry(parent, name, rel, created)
				nd.refs.Store(2)
				parent.children[name] = nd
				fs.mu.Unlock()
				parent.watches.Notify(ctx, name, linux.IN_CREATE, 0, vfs.InodeEvent, false)
				d, e = nd, created
			} else {
				return nil, lErr
			}
		}
	} else {
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
	if writable && rp.Mount().ReadOnly() {
		return nil, linuxerr.EROFS
	}
	if opts.Flags&linux.O_TRUNC != 0 && writable {
		if err := fs.client.Truncate(goContext.Background(), d.path(), 0); err != nil {
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
	return fs.client.Readlink(goContext.Background(), d.path())
}

func (fs *filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, oldParentVD vfs.VirtualDentry, oldName string, opts vfs.RenameOptions) error {
	if opts.Flags != 0 {
		return linuxerr.EINVAL
	}
	if rp.Mount().ReadOnly() {
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
	newName := rp.Component()
	if newName == "." || newName == ".." {
		return linuxerr.EBUSY
	}
	oldParent := oldParentVD.Dentry().Impl().(*dentry)
	oldRel := joinRel(oldParent.path(), oldName)
	newRel := joinRel(newParent.path(), newName)
	if oldRel == newRel {
		return nil
	}
	if err := fs.client.Rename(goContext.Background(), oldRel, newRel); err != nil {
		return err
	}
	fs.mu.Lock()
	fs.ancestryMu.Lock()
	if oldParent.children != nil {
		if moved, ok := oldParent.children[oldName]; ok {
			delete(oldParent.children, oldName)
			if newParent.children == nil {
				newParent.children = make(map[string]*dentry)
			}
			moved.parent = newParent
			moved.name = newName
			moved.relPath = newRel
			newParent.children[newName] = moved
		}
	}
	fs.ancestryMu.Unlock()
	fs.mu.Unlock()
	return nil
}

func (fs *filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	if rp.Mount().ReadOnly() {
		return linuxerr.EROFS
	}
	parent, err := fs.resolveParent(ctx, rp)
	if err != nil {
		return err
	}
	defer parent.DecRef(ctx)
	name := rp.Component()
	if name == "." {
		return linuxerr.EINVAL
	}
	if name == ".." {
		return linuxerr.ENOTEMPTY
	}
	rel := joinRel(parent.path(), name)
	if err := fs.client.Rmdir(goContext.Background(), rel); err != nil {
		return err
	}
	fs.dropChild(parent, name)
	return nil
}

func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	if rp.Mount().ReadOnly() {
		return linuxerr.EROFS
	}
	parent, err := fs.resolveParent(ctx, rp)
	if err != nil {
		return err
	}
	defer parent.DecRef(ctx)
	name := rp.Component()
	if name == "." || name == ".." {
		return linuxerr.EISDIR
	}
	rel := joinRel(parent.path(), name)
	if err := fs.client.Unlink(goContext.Background(), rel); err != nil {
		return err
	}
	fs.dropChild(parent, name)
	return nil
}

func (fs *filesystem) dropChild(parent *dentry, name string) {
	fs.mu.Lock()
	var old *dentry
	if parent.children != nil {
		old = parent.children[name]
		delete(parent.children, name)
	}
	if old != nil {
		fs.ancestryMu.Lock()
		old.dead = true
		fs.ancestryMu.Unlock()
	}
	fs.mu.Unlock()
	if old != nil {
		old.DecRef(context.Background())
	}
}

func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	if rp.Mount().ReadOnly() {
		return linuxerr.EROFS
	}
	parent, err := fs.resolveParent(ctx, rp)
	if err != nil {
		return err
	}
	defer parent.DecRef(ctx)
	name := rp.Component()
	if name == "." || name == ".." {
		return linuxerr.EEXIST
	}
	return fs.client.Symlink(goContext.Background(), target, joinRel(parent.path(), name))
}

func (fs *filesystem) setStatDentry(d *dentry, mnt *vfs.Mount, opts vfs.SetStatOptions) error {
	if mnt.ReadOnly() {
		return linuxerr.EROFS
	}
	rel := d.path()
	if opts.Stat.Mask&linux.STATX_SIZE != 0 {
		if err := fs.client.Truncate(goContext.Background(), rel, int64(opts.Stat.Size)); err != nil {
			return err
		}
	}
	if opts.Stat.Mask&linux.STATX_MODE != 0 {
		if err := fs.client.Chmod(goContext.Background(), rel, uint32(opts.Stat.Mode)&0o7777); err != nil {
			return err
		}
	}
	setA := opts.Stat.Mask&linux.STATX_ATIME != 0
	setM := opts.Stat.Mask&linux.STATX_MTIME != 0
	if setA || setM {
		if err := fs.client.Utimens(goContext.Background(), rel, opts.Stat.Atime.ToNsec(), opts.Stat.Mtime.ToNsec(), setA, setM); err != nil {
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
	return fs.setStatDentry(d, rp.Mount(), opts)
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
		if &d.vfsd == mnt.Root() {
			return nil
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
	e, err := fd.dentry.fs.client.Stat(goContext.Background(), rel)
	if err != nil {
		return linux.Statx{}, err
	}
	return fd.dentry.fs.statxFor(e, rel), nil
}

func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	return fd.dentry.fs.setStatDentry(fd.dentry, fd.vfsfd.Mount(), opts)
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
	var total int64
	for total < want {
		chunkLen := min(want-total, int64(maxChunkSize))
		data, err := fd.dentry.fs.client.Read(goContext.Background(), rel, offset+total, chunkLen)
		if len(data) > 0 {
			n, copyErr := dst.DropFirst64(total).CopyOut(ctx, data)
			total += int64(n)
			if copyErr != nil {
				return total, copyErr
			}
		}
		if err == io.EOF || int64(len(data)) < chunkLen {
			if total == 0 && err != nil {
				return 0, err
			}
			return total, nil
		}
		if err != nil {
			if total > 0 {
				return total, nil
			}
			return 0, err
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
	want := src.NumBytes()
	if want == 0 {
		return 0, nil
	}
	rel := fd.dentry.path()
	var total int64
	buf := make([]byte, min(want, int64(maxChunkSize)))
	for total < want {
		step := int(min(want-total, int64(len(buf))))
		copied, copyErr := src.DropFirst64(total).CopyIn(ctx, buf[:step])
		if copied == 0 {
			return total, copyErr
		}
		written, wErr := fd.dentry.fs.client.Write(goContext.Background(), rel, offset+total, buf[:copied])
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
		e, err := fd.dentry.fs.client.Stat(goContext.Background(), fd.dentry.path())
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
		e, err := fd.dentry.fs.client.Stat(goContext.Background(), fd.dentry.path())
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
		raw, err := fd.dentry.fs.client.Readdir(goContext.Background(), rel)
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
