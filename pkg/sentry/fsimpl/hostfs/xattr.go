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
	"maps"
	"slices"
	"strings"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// Extended attributes use two stores.
//
// The native store is the host file system. A Linux host with
// WorkspaceCaps.NativeXattr keeps the user.* attributes of regular files and
// directories there, through the descriptor of the object. A host tool then
// sees the attributes that the guest sets. hostfs never writes the trusted.*
// and security.* namespaces to the host, because the host kernel would honor
// attributes such as security.capability on the real file.
//
// The meta store is POSIXAttr.Xattrs in .gvx_meta. It holds every other
// attribute: all attributes on macOS and Windows, the namespaces that the
// native store excludes, the attributes of sockets, FIFOs, devices, and
// virtual symlinks, and the attributes that the host refuses with EPERM or
// EOPNOTSUPP. The meta store caps the attributes of one inode at
// maxXattrBytes, because .gvx_meta lives in memory. The native store follows
// the limits of the host file system.
//
// A name that exists in the meta store stays there. Reads look in the meta
// store first and in the native store second. A hard-linked file keeps one set
// of attributes: a change of the meta store copies to every recorded name of
// the file.
//
// The maps in POSIXAttr.Xattrs are immutable. A change builds a new map, so
// records that share a map by a hard link or a copy never see a partial
// change.

const (
	// maxXattrBytes is the most bytes that the meta store holds for one inode:
	// the sum of the lengths of all names and all values.
	maxXattrBytes = 4096
)

// checkXattrPrefix accepts the namespaces that this filesystem stores: user,
// trusted, and security. A POSIX ACL is not supported, so the system namespace
// is rejected.
func checkXattrPrefix(name string) error {
	for _, prefix := range []string{linux.XATTR_USER_PREFIX, linux.XATTR_TRUSTED_PREFIX, linux.XATTR_SECURITY_PREFIX} {
		if strings.HasPrefix(name, prefix) {
			return nil
		}
	}
	return linuxerr.EOPNOTSUPP
}

// xattrBytes returns the size that the meta store charges for m.
func xattrBytes(m map[string][]byte) int {
	total := 0
	for name, value := range m {
		total += len(name) + len(value)
	}
	return total
}

// setXattrMap returns a copy of cur with name set to value. It applies the
// create and replace flags and the size limit of the meta store, and it
// returns a Linux errno on failure.
func setXattrMap(cur map[string][]byte, name string, value []byte, flags uint32) (map[string][]byte, error) {
	if len(value) > linux.XATTR_SIZE_MAX {
		return nil, linuxerr.E2BIG
	}
	_, exists := cur[name]
	if flags&linux.XATTR_CREATE != 0 && exists {
		return nil, linuxerr.EEXIST
	}
	if flags&linux.XATTR_REPLACE != 0 && !exists {
		return nil, linuxerr.ENODATA
	}
	next := make(map[string][]byte, len(cur)+1)
	maps.Copy(next, cur)
	next[name] = slices.Clone(value)
	if xattrBytes(next) > maxXattrBytes {
		return nil, linuxerr.ENOSPC
	}
	return next, nil
}

// removeXattrMap returns a copy of cur without name. It returns ENODATA when
// cur has no such name. An empty result is nil.
func removeXattrMap(cur map[string][]byte, name string) (map[string][]byte, error) {
	if _, ok := cur[name]; !ok {
		return nil, linuxerr.ENODATA
	}
	if len(cur) == 1 {
		return nil, nil
	}
	next := maps.Clone(cur)
	delete(next, name)
	return next, nil
}

// xattrTarget names the object that an extended attribute call reaches.
type xattrTarget struct {
	ino *inode
	// rel is the guest path of the object. It is empty when the dentry has no
	// name any more, which happens to an unlinked file with an open descriptor.
	rel string
	// h is the open host handle of a file description, or nil.
	h *hostHandle
}

// xattrRefused reports that the host refuses the native call and that the
// meta store must take the attribute. The Linux lockdown filter answers a
// refused call with EPERM, so a lockdown looks like a refusal.
func xattrRefused(err error) bool {
	return errors.Is(err, errHostUnsupported) || nativeXattrRefused(err)
}

// nativeXattrFor reports whether the native store holds the attribute name of
// the object of ino.
func (w *Workspace) nativeXattrFor(ino *inode, name string) bool {
	return w.nativeXattrKind(ino) && strings.HasPrefix(name, linux.XATTR_USER_PREFIX)
}

// nativeXattrKind reports whether the native store can hold the attributes of
// ino: a regular file or a directory of a host that supports them.
func (w *Workspace) nativeXattrKind(ino *inode) bool {
	return w.caps.NativeXattr && !ino.virtual && (ino.kind == hostKindRegular || ino.kind == hostKindDir)
}

// metaXattrsLocked returns the attributes that the meta store holds for t.
// Callers hold w.mu.
func (w *Workspace) metaXattrsLocked(t xattrTarget) map[string][]byte {
	if t.rel == "" {
		return t.ino.snapshot().attr.Xattrs
	}
	return w.meta[t.rel].Xattrs
}

// storeXattrsLocked replaces the attributes that the meta store holds for t.
// A named object gets its record updated and persisted. An unlinked object
// has no record, so only the snapshot of its inode changes. Callers hold w.mu
// for writing.
func (w *Workspace) storeXattrsLocked(t xattrTarget, next map[string][]byte) error {
	if t.rel == "" {
		t.ino.attrMu.Lock()
		t.ino.cur.attr.Xattrs = next
		t.ino.attrMu.Unlock()
		return nil
	}
	e, err := w.lookupLocked(t.rel)
	if err != nil {
		return translateLookupError(err)
	}
	if e.isSymlink() && !e.virtual {
		// A host symbolic link has no record, and a record would hide it.
		return linuxerr.EOPNOTSUPP
	}
	if err := w.checkMetaRoomLocked(t.rel); err != nil {
		return translateHostError(err)
	}
	rec := e.attr
	rec.Xattrs = next
	w.meta[t.rel] = rec
	// The snapshot of the inode follows the record, so an open descriptor of
	// a file that the guest unlinks later still sees the attributes.
	t.ino.attrMu.Lock()
	t.ino.cur.attr.Xattrs = next
	t.ino.attrMu.Unlock()
	if e.info.nlink > 1 && !e.isDir() && !e.virtual {
		if err := w.propagateLinkAttrLocked(t.rel, e.info.id, rec); err != nil {
			return translateHostError(err)
		}
	}
	w.markDirtyLocked()
	return nil
}

// checkXattrWritableLocked fails when the workspace refuses mutations.
func (w *Workspace) checkXattrWritableLocked() error {
	if w.readOnly {
		return linuxerr.EROFS
	}
	if w.closed {
		return linuxerr.EIO
	}
	return nil
}

// xattrGet returns the value of the attribute name of t. It returns a Linux
// errno on failure.
func (w *Workspace) xattrGet(t xattrTarget, name string) ([]byte, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return nil, linuxerr.EIO
	}
	if v, ok := w.metaXattrsLocked(t)[name]; ok {
		return slices.Clone(v), nil
	}
	if w.nativeXattrFor(t.ino, name) {
		v, err := w.nativeGetXattr(t, name)
		switch {
		case err == nil:
			return v, nil
		case nativeXattrNoData(err), xattrRefused(err):
		default:
			return nil, nativeXattrError(err)
		}
	}
	return nil, linuxerr.ENODATA
}

// xattrList returns the sorted names of the attributes of t. It returns a
// Linux errno on failure.
func (w *Workspace) xattrList(t xattrTarget) ([]string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return nil, linuxerr.EIO
	}
	set := make(map[string]struct{})
	for name := range w.metaXattrsLocked(t) {
		set[name] = struct{}{}
	}
	if w.nativeXattrKind(t.ino) {
		names, err := w.nativeListXattr(t)
		switch {
		case err == nil:
			for _, name := range names {
				if strings.HasPrefix(name, linux.XATTR_USER_PREFIX) {
					set[name] = struct{}{}
				}
			}
		case xattrRefused(err):
		default:
			return nil, nativeXattrError(err)
		}
	}
	return slices.Sorted(maps.Keys(set)), nil
}

// xattrSet creates or replaces the attribute name of t. It returns a Linux
// errno on failure.
func (w *Workspace) xattrSet(t xattrTarget, name string, value []byte, flags uint32) error {
	if len(value) > linux.XATTR_SIZE_MAX {
		return linuxerr.E2BIG
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkXattrWritableLocked(); err != nil {
		return err
	}
	cur := w.metaXattrsLocked(t)
	if _, inMeta := cur[name]; !inMeta && w.nativeXattrFor(t.ino, name) {
		err := w.nativeSetXattr(t, name, value, flags)
		if err == nil {
			return nil
		}
		if !xattrRefused(err) {
			return nativeXattrError(err)
		}
	}
	next, err := setXattrMap(cur, name, value, flags)
	if err != nil {
		return err
	}
	return w.storeXattrsLocked(t, next)
}

// xattrRemove removes the attribute name of t. It returns ENODATA when no
// store holds the name, and another Linux errno on failure.
func (w *Workspace) xattrRemove(t xattrTarget, name string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkXattrWritableLocked(); err != nil {
		return err
	}
	removed := false
	if next, err := removeXattrMap(w.metaXattrsLocked(t), name); err == nil {
		if err := w.storeXattrsLocked(t, next); err != nil {
			return err
		}
		removed = true
	}
	if w.nativeXattrFor(t.ino, name) {
		err := w.nativeRemoveXattr(t, name)
		switch {
		case err == nil:
			removed = true
		case nativeXattrNoData(err), xattrRefused(err):
		default:
			return nativeXattrError(err)
		}
	}
	if !removed {
		return linuxerr.ENODATA
	}
	return nil
}

// xattrTarget returns the target of an extended attribute call on d. h is the
// open host handle of a file description, or nil.
func (d *dentry) xattrTarget(h *hostHandle) xattrTarget {
	t := xattrTarget{ino: d.inode, h: h}
	if !d.isDead() {
		t.rel = d.path()
	}
	return t
}

// listXattr returns the names of the attributes that the caller may see. The
// trusted namespace stays hidden from a caller without CAP_SYS_ADMIN, as in
// fs/xattr.c:simple_xattr_list().
func (d *dentry) listXattr(creds *auth.Credentials, size uint64, h *hostHandle) ([]string, error) {
	all, err := d.fs.ws.xattrList(d.xattrTarget(h))
	if err != nil {
		return nil, err
	}
	haveCap := creds.HasRootCapability(linux.CAP_SYS_ADMIN)
	names := make([]string, 0, len(all))
	listSize := 0
	for _, name := range all {
		if checkXattrPrefix(name) != nil {
			continue
		}
		if !haveCap && strings.HasPrefix(name, linux.XATTR_TRUSTED_PREFIX) {
			continue
		}
		names = append(names, name)
		// One more byte for the null terminator.
		listSize += len(name) + 1
	}
	if size != 0 && uint64(listSize) > size {
		return nil, linuxerr.ERANGE
	}
	return names, nil
}

func (d *dentry) getXattr(creds *auth.Credentials, opts *vfs.GetXattrOptions, h *hostHandle) (string, error) {
	e := d.inode.snapshot()
	mode, uid, gid := linux.FileMode(e.attr.Mode), auth.KUID(e.attr.UID), auth.KGID(e.attr.GID)
	// Linux requires read permission for the namespaces that are not security,
	// system, or trusted, and it checks before any handler rejects the name.
	if vfs.XattrReadNeedsFilePermission(opts.Name) {
		if err := vfs.GenericCheckPermissions(creds, vfs.MayRead, mode, nil, uid, gid); err != nil {
			return "", err
		}
	}
	if err := checkXattrPrefix(opts.Name); err != nil {
		return "", err
	}
	if err := vfs.CheckXattrPermissions(creds, vfs.MayRead, mode, uid, opts.Name); err != nil {
		return "", err
	}
	raw, err := d.fs.ws.xattrGet(d.xattrTarget(h), opts.Name)
	if err != nil {
		return "", err
	}
	value := string(raw)
	// The size is a hint of the caller. A larger value gets ERANGE.
	if opts.Size != 0 && uint64(len(value)) > opts.Size {
		return "", linuxerr.ERANGE
	}
	if opts.Name == linux.XATTR_SECURITY_CAPABILITY {
		return auth.FixupVfsCapDataOnGet(creds, value)
	}
	return value, nil
}

func (d *dentry) setXattr(creds *auth.Credentials, mnt *vfs.Mount, opts *vfs.SetXattrOptions, h *hostHandle) error {
	if err := checkXattrPrefix(opts.Name); err != nil {
		return err
	}
	e := d.inode.snapshot()
	mode, uid, gid := linux.FileMode(e.attr.Mode), auth.KUID(e.attr.UID), auth.KGID(e.attr.GID)
	if err := vfs.GenericCheckPermissions(creds, vfs.MayWrite, mode, nil, uid, gid); err != nil {
		return err
	}
	if err := vfs.CheckXattrPermissions(creds, vfs.MayWrite, mode, uid, opts.Name); err != nil {
		return err
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	value := opts.Value
	if opts.Name == linux.XATTR_SECURITY_CAPABILITY {
		var err error
		value, err = auth.FixupVfsCapDataOnSet(creds, value, uid, gid)
		if err != nil {
			return err
		}
	}
	return d.mutateXattr(opts.Name, h, func(t xattrTarget) error {
		return d.fs.ws.xattrSet(t, opts.Name, []byte(value), opts.Flags)
	})
}

func (d *dentry) removeXattr(creds *auth.Credentials, mnt *vfs.Mount, name string, h *hostHandle) error {
	if err := checkXattrPrefix(name); err != nil {
		return err
	}
	e := d.inode.snapshot()
	mode, uid, gid := linux.FileMode(e.attr.Mode), auth.KUID(e.attr.UID), auth.KGID(e.attr.GID)
	if err := vfs.GenericCheckPermissions(creds, vfs.MayWrite, mode, nil, uid, gid); err != nil {
		return err
	}
	if err := vfs.CheckXattrPermissions(creds, vfs.MayWrite, mode, uid, name); err != nil {
		return err
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	return d.mutateXattr(name, h, func(t xattrTarget) error {
		return d.fs.ws.xattrRemove(t, name)
	})
}

// mutateXattr runs a change of the attribute name. A change in the native
// store changes the host object, so the host watcher must take the new host
// state as the result of a guest action and send no second event.
//
// A file records the host state of the change in its guest state. A directory
// has no such record. The scan of a watched directory takes filesystem.mu, so
// the change and the mark of the inode run in one step under that lock.
func (d *dentry) mutateXattr(name string, h *hostHandle, change func(xattrTarget) error) error {
	t := d.xattrTarget(h)
	native := d.fs.ws.nativeXattrFor(d.inode, name)
	var err error
	switch {
	case native && d.inode.isDir():
		d.fs.mu.Lock()
		err = change(t)
		if err == nil {
			d.fs.ws.watchNoteInode(d.inode)
			if t.rel != "" && t.rel != "." {
				parent, leaf := splitParent(t.rel)
				d.fs.ws.watchNoteName(parent, leaf)
			}
		}
		d.fs.mu.Unlock()
	case native:
		d.inode.guestBegin()
		err = change(t)
		if h != nil {
			h.guestEnd(d.inode)
		} else {
			d.inode.guestEndPath(t.rel)
		}
	default:
		err = change(t)
	}
	d.inode.invalidateMeta()
	return err
}

// resolveXattrDentry resolves rp and returns the dentry with one reference.
// The caller drops it with DecRef.
func (fs *filesystem) resolveXattrDentry(ctx context.Context, rp *vfs.ResolvingPath) (*dentry, error) {
	fs.lock()
	defer fs.unlock(ctx)
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		return nil, err
	}
	d.IncRef()
	return d, nil
}

// ListXattrAt implements vfs.FilesystemImpl.ListXattrAt.
func (fs *filesystem) ListXattrAt(ctx context.Context, rp *vfs.ResolvingPath, size uint64) ([]string, error) {
	d, err := fs.resolveXattrDentry(ctx, rp)
	if err != nil {
		return nil, err
	}
	defer d.DecRef(ctx)
	return d.listXattr(rp.Credentials(), size, nil)
}

// GetXattrAt implements vfs.FilesystemImpl.GetXattrAt.
func (fs *filesystem) GetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetXattrOptions) (string, error) {
	d, err := fs.resolveXattrDentry(ctx, rp)
	if err != nil {
		return "", err
	}
	defer d.DecRef(ctx)
	return d.getXattr(rp.Credentials(), &opts, nil)
}

// SetXattrAt implements vfs.FilesystemImpl.SetXattrAt.
func (fs *filesystem) SetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetXattrOptions) error {
	d, err := fs.resolveXattrDentry(ctx, rp)
	if err != nil {
		return err
	}
	defer d.DecRef(ctx)
	if err := d.setXattr(rp.Credentials(), rp.Mount(), &opts, nil); err != nil {
		return err
	}
	d.InotifyWithParent(ctx, linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}

// RemoveXattrAt implements vfs.FilesystemImpl.RemoveXattrAt.
func (fs *filesystem) RemoveXattrAt(ctx context.Context, rp *vfs.ResolvingPath, name string) error {
	d, err := fs.resolveXattrDentry(ctx, rp)
	if err != nil {
		return err
	}
	defer d.DecRef(ctx)
	if err := d.removeXattr(rp.Credentials(), rp.Mount(), name, nil); err != nil {
		return err
	}
	d.InotifyWithParent(ctx, linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}

// ListXattr implements vfs.FileDescriptionImpl.ListXattr.
func (fd *regularFD) ListXattr(ctx context.Context, size uint64) ([]string, error) {
	return fd.dentry.listXattr(auth.CredentialsFromContext(ctx), size, fd.h)
}

// GetXattr implements vfs.FileDescriptionImpl.GetXattr.
func (fd *regularFD) GetXattr(ctx context.Context, opts vfs.GetXattrOptions) (string, error) {
	return fd.dentry.getXattr(auth.CredentialsFromContext(ctx), &opts, fd.h)
}

// SetXattr implements vfs.FileDescriptionImpl.SetXattr.
func (fd *regularFD) SetXattr(ctx context.Context, opts vfs.SetXattrOptions) error {
	if err := fd.dentry.setXattr(auth.CredentialsFromContext(ctx), fd.vfsfd.Mount(), &opts, fd.h); err != nil {
		return err
	}
	fd.dentry.InotifyWithParent(ctx, linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}

// RemoveXattr implements vfs.FileDescriptionImpl.RemoveXattr.
func (fd *regularFD) RemoveXattr(ctx context.Context, name string) error {
	if err := fd.dentry.removeXattr(auth.CredentialsFromContext(ctx), fd.vfsfd.Mount(), name, fd.h); err != nil {
		return err
	}
	fd.dentry.InotifyWithParent(ctx, linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}

// ListXattr implements vfs.FileDescriptionImpl.ListXattr.
func (fd *dirFD) ListXattr(ctx context.Context, size uint64) ([]string, error) {
	return fd.dentry.listXattr(auth.CredentialsFromContext(ctx), size, nil)
}

// GetXattr implements vfs.FileDescriptionImpl.GetXattr.
func (fd *dirFD) GetXattr(ctx context.Context, opts vfs.GetXattrOptions) (string, error) {
	return fd.dentry.getXattr(auth.CredentialsFromContext(ctx), &opts, nil)
}

// SetXattr implements vfs.FileDescriptionImpl.SetXattr.
func (fd *dirFD) SetXattr(ctx context.Context, opts vfs.SetXattrOptions) error {
	if err := fd.dentry.setXattr(auth.CredentialsFromContext(ctx), fd.vfsfd.Mount(), &opts, nil); err != nil {
		return err
	}
	fd.dentry.InotifyWithParent(ctx, linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}

// RemoveXattr implements vfs.FileDescriptionImpl.RemoveXattr.
func (fd *dirFD) RemoveXattr(ctx context.Context, name string) error {
	if err := fd.dentry.removeXattr(auth.CredentialsFromContext(ctx), fd.vfsfd.Mount(), name, nil); err != nil {
		return err
	}
	fd.dentry.InotifyWithParent(ctx, linux.IN_ATTRIB, 0, vfs.InodeEvent)
	return nil
}
