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
	iofs "io/fs"
	"os"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel/pipe"
	"z.gfire.dev/gvx/pkg/sentry/socket/unix/transport"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// Sockets, FIFOs, and device nodes live in Sentry memory. The host volume may
// lack them, or the sandbox may forbid them, so hostfs never creates a host
// object of these types. Each node has two parts:
//
//   - An empty regular file on the host, the placeholder. It makes listings,
//     name checks, and host tools agree with the guest view.
//   - A .gvx_meta record whose Mode holds the file type, and whose Rdev holds
//     the device number of a device node.
//
// The in-memory state of a node lives in specialState on the inode. A socket
// keeps its bound endpoint there, and a FIFO keeps its pipe. The state does
// not survive a remount. A socket file from an earlier run refuses
// connections, as a Linux socket file does when no process listens. A FIFO
// from an earlier run starts with an empty pipe.

const (
	// rdevMajorMax and rdevMinorMax bound the device numbers that a record
	// holds. They are the limits of the Linux device number encoding.
	rdevMajorMax = 0xfff
	rdevMinorMax = 0xfffff
)

// packRdev joins a device number into the form that POSIXAttr.Rdev holds.
func packRdev(major, minor uint32) uint64 {
	return uint64(major)<<32 | uint64(minor)
}

// unpackRdev splits a POSIXAttr.Rdev value into the major and minor numbers.
func unpackRdev(rdev uint64) (major, minor uint32) {
	return uint32(rdev >> 32), uint32(rdev)
}

// specialFileType returns the file type bits of mode when they name a
// socket, a FIFO, or a device. It returns zero for every other type.
func specialFileType(mode uint32) uint32 {
	switch t := mode & linux.S_IFMT; t {
	case linux.S_IFSOCK, linux.S_IFIFO, linux.S_IFCHR, linux.S_IFBLK:
		return t
	}
	return 0
}

// placeholderType returns the special file type that the record m gives to
// the host file described by info. A placeholder is an empty regular file. A
// host file with content is a regular file, even when an old record names a
// special type, because a host tool replaced the placeholder.
func placeholderType(info hostInfo, m POSIXAttr) uint32 {
	if info.kind != hostKindRegular || info.size != 0 {
		return 0
	}
	return specialFileType(m.Mode)
}

// specialState is the in-memory state of a socket, a FIFO, or a device node.
type specialState struct {
	// pipe is the pipe of a FIFO. It is set when the inode is created and
	// never changes.
	pipe *pipe.VFSPipe
	// ep is the endpoint that bind(2) stored in a socket file. filesystem.mu
	// protects it. A dentry that names an inode with an endpoint stays in the
	// cache, because a new inode would lose the endpoint.
	ep transport.BoundEndpoint
}

func (i *inode) isSpecial() bool {
	return i.kind == hostKindSpecial
}

// initSpecial creates the in-memory state that a new inode needs for entry e.
func (i *inode) initSpecial(e entry) {
	if e.attr.Mode&linux.S_IFMT == linux.S_IFIFO {
		i.special.pipe = pipe.NewVFSPipe(true /* isNamed */, pipe.DefaultPipeSize)
	}
}

// pinnedLocked reports that the inode holds state that a new inode cannot
// rebuild, so the dentry cache must keep it. Callers hold filesystem.mu.
func (i *inode) pinnedLocked() bool {
	return i.special.ep != nil
}

// mknod creates the placeholder and the record of a special node.
func (w *Workspace) mknod(rel string, mode, uid, gid uint32, rdev uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.mknodLocked(rel, mode, uid, gid, rdev)
}

// mknodLocked creates an empty host file at rel and records mode, owner, and
// device number for it in .gvx_meta. The file type of mode must be a socket,
// a FIFO, or a device. It fails with fs.ErrExist when a guest entry holds the
// name. Callers hold w.mu for writing.
func (w *Workspace) mknodLocked(rel string, mode, uid, gid uint32, rdev uint64) error {
	if err := w.checkWritableLocked(rel); err != nil {
		return err
	}
	if specialFileType(mode) == 0 {
		return iofs.ErrInvalid
	}
	if rel == "." {
		return iofs.ErrExist
	}
	if err := w.checkMetaRoomLocked(rel); err != nil {
		return err
	}
	hostRel, leaf, err := w.createTargetLocked(rel)
	if err != nil {
		return err
	}
	f, err := w.host.open(hostRel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		_ = w.host.unlink(hostRel)
		return err
	}
	w.meta[rel] = POSIXAttr{Mode: mode&linux.S_IFMT | mode&0o7777, UID: uid, GID: gid, Rdev: rdev}
	w.markDirtyLocked()
	parent, name := splitParent(rel)
	w.setAlt(parent, name, leaf)
	w.addDirNameLocked(parent, name, leaf)
	return nil
}

// createWhiteoutLocked creates a whiteout at rel: a character device node
// with the device number 0:0 and no permission bits. An overlay uses it to
// hide an entry of a lower layer. It fails with fs.ErrExist when a guest entry
// holds the name. Callers hold w.mu for writing.
func (w *Workspace) createWhiteoutLocked(rel string) error {
	return w.mknodLocked(rel, linux.S_IFCHR, 0, 0, 0)
}

// MknodAt implements vfs.FilesystemImpl.MknodAt. A regular file is an ordinary
// host file. A socket, a FIFO, or a device node is a placeholder with a
// record, and the new inode carries the endpoint of a socket at once.
func (fs *filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	return fs.doCreateAt(ctx, rp, false, func(parent *dentry, name, rel string) error {
		uid, gid, _ := newOwner(parent.inode, rp.Credentials())
		perm := uint32(opts.Mode) & 0o7777
		ftype := uint32(opts.Mode.FileType())
		switch ftype {
		case 0, linux.S_IFREG:
			f, _, err := fs.ws.createFile(rel, perm, uint32(uid), uint32(gid))
			if err != nil {
				return translateHostError(err)
			}
			return translateHostError(f.Close())
		case linux.S_IFSOCK, linux.S_IFIFO:
			return fs.mknodLocked(parent, name, rel, ftype|perm, uint32(uid), uint32(gid), 0, opts.Endpoint)
		case linux.S_IFCHR, linux.S_IFBLK:
			if opts.DevMajor > rdevMajorMax || opts.DevMinor > rdevMinorMax {
				return linuxerr.EINVAL
			}
			return fs.mknodLocked(parent, name, rel, ftype|perm, uint32(uid), uint32(gid), packRdev(opts.DevMajor, opts.DevMinor), nil)
		default:
			return linuxerr.EINVAL
		}
	})
}

// mknodLocked creates a special node and attaches its dentry to parent, so
// the inode that holds ep stays the one that later lookups find.
//
// Preconditions: fs.mu is held.
func (fs *filesystem) mknodLocked(parent *dentry, name, rel string, mode, uid, gid uint32, rdev uint64, ep transport.BoundEndpoint) error {
	if err := fs.ws.mknod(rel, mode, uid, gid, rdev); err != nil {
		return translateHostError(err)
	}
	e, err := fs.ws.lookupIn(parent.relPath, name)
	if err != nil {
		// The node exists but the dentry cannot attach. Remove the node, so a
		// retry starts clean.
		_ = fs.ws.unlink(rel)
		return translateHostError(err)
	}
	d := fs.attachChildLocked(parent, name, rel, e, fs.ws.nowNano()+int64(cacheTTL))
	d.inode.special.ep = ep
	return nil
}

// BoundEndpointAt implements vfs.FilesystemImpl.BoundEndpointAt. It returns the
// endpoint that bind(2) stored in a socket file. A socket file from an earlier
// mount has no endpoint, and a connect to it fails with ECONNREFUSED.
func (fs *filesystem) BoundEndpointAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.BoundEndpointOptions) (transport.BoundEndpoint, error) {
	fs.lock()
	defer fs.unlock(ctx)
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		return nil, err
	}
	if err := d.inode.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
		return nil, err
	}
	if d.inode.special.ep == nil {
		return nil, linuxerr.ECONNREFUSED
	}
	return d.inode.special.ep, nil
}

// openSpecial opens a FIFO, a device node, or a socket node.
//
// A FIFO uses the pipe of its inode, which the VFS pipe implementation drives.
// A device node opens through the device registry of the VFS, and it fails
// with ENXIO when no device has that number. A socket node never opens, and a
// connect to it goes through BoundEndpointAt.
//
// Preconditions: fs.mu is not held, because opening a FIFO can block until
// another process opens the other end.
func (d *dentry) openSpecial(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	ino := d.inode
	attr := ino.snapshot().attr
	switch attr.Mode & linux.S_IFMT {
	case linux.S_IFIFO:
		return ino.special.pipe.Open(ctx, rp.Mount(), &d.vfsd, opts.Flags, &ino.locks)
	case linux.S_IFCHR, linux.S_IFBLK:
		kind := vfs.CharDevice
		if attr.Mode&linux.S_IFMT == linux.S_IFBLK {
			kind = vfs.BlockDevice
		}
		major, minor := unpackRdev(attr.Rdev)
		return rp.VirtualFilesystem().OpenDeviceSpecialFile(ctx, rp.Mount(), &d.vfsd, kind, major, minor, opts)
	default:
		return nil, linuxerr.ENXIO
	}
}

// specialLinksLocked returns the host link count of the special inode of d
// before a removal. It returns zero for every other inode, and when the host
// no longer holds the entry.
//
// Preconditions: fs.mu is held.
func (fs *filesystem) specialLinksLocked(d *dentry) uint32 {
	if !d.inode.isSpecial() {
		return 0
	}
	e, err := fs.ws.lookupPath(d.relPath)
	if err != nil {
		return 0
	}
	return e.info.nlink
}

// retireSpecialLocked ends the lookup of a special inode by host identity
// after a removal of one name. A host inode number can come back for a new
// file while open file descriptions keep the old inode alive, and the new file
// must not share the pipe of the old one. links is the link count that
// specialLinksLocked returned before the removal. Another name keeps the inode
// in the map.
//
// Preconditions: fs.mu is held.
func (fs *filesystem) retireSpecialLocked(ino *inode, links uint32) {
	if !ino.isSpecial() || links > 1 {
		return
	}
	if fs.inodes[ino.id] == ino {
		delete(fs.inodes, ino.id)
	}
}
