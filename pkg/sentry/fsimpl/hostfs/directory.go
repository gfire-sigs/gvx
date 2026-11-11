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
	goContext "context"
	"errors"
	"slices"
	"strings"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/chunkcache"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// fileDescription holds the members shared by the file description types. The
// nesting lets dirFD embed both default implementations without ambiguity.
//
// +stateify savable
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD

	dentry *dentry
	h      *hostHandle `state:"nosave"`
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	d := fd.dentry
	if err := d.setStat(ctx, auth.CredentialsFromContext(ctx), fd.vfsfd.Mount(), &opts, fd.h); err != nil {
		return err
	}
	if ev := vfs.InotifyEventFromStatMask(opts.Stat.Mask); ev != 0 {
		d.InotifyWithParent(ctx, ev, 0, vfs.InodeEvent)
	}
	return nil
}

// StatFS implements vfs.FileDescriptionImpl.StatFS.
func (fd *fileDescription) StatFS(ctx context.Context) (linux.Statfs, error) {
	return fd.dentry.fs.statFS()
}

// dirFD implements vfs.FileDescriptionImpl for directories.
//
// A directory description lists the directory once, when the guest first reads
// it or rewinds it. Every later read comes from that snapshot. POSIX leaves
// the visibility of entries that change during iteration unspecified. The
// snapshot keeps offsets stable while the guest deletes entries it already
// read, as rm -rf does.
// +stateify savable
type dirFD struct {
	fileDescription
	vfs.DirectoryFileDescriptionDefaultImpl
	cursor         chunkcache.DirCursor `state:"nosave"`
	savedCursorOff int64
}

func (fd *dirFD) beforeSave() {
	off, _ := fd.cursor.SeekDir(0, linux.SEEK_CUR)
	fd.savedCursorOff = off
}

func (fd *dirFD) afterLoad(goContext.Context) {
	if fd.savedCursorOff > 0 {
		_, _ = fd.cursor.SeekDir(fd.savedCursorOff, linux.SEEK_SET)
	}
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *dirFD) Release(ctx context.Context) {}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *dirFD) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	d := fd.dentry
	if err := d.refresh(); err != nil {
		return linux.Statx{}, err
	}
	e := d.inode.snapshot()
	stat := d.inode.statxFor(e, d.fs.devMinor)
	stat.Nlink = d.dirLinks(e, stat.Nlink)
	return stat, nil
}

func direntType(kind hostKind) uint8 {
	switch kind {
	case hostKindDir:
		return linux.DT_DIR
	case hostKindSymlink:
		return linux.DT_LNK
	default:
		return linux.DT_REG
	}
}

// direntTypeOf returns the dirent type of a listing entry. A placeholder
// reports the type that its .gvx_meta record names.
func direntTypeOf(l dirListing) uint8 {
	switch l.special {
	case linux.S_IFSOCK:
		return linux.DT_SOCK
	case linux.S_IFIFO:
		return linux.DT_FIFO
	case linux.S_IFCHR:
		return linux.DT_CHR
	case linux.S_IFBLK:
		return linux.DT_BLK
	}
	return direntType(l.kind)
}

// load lists the directory into a snapshot. The entries "." and ".." come
// first, then the children by name.
func (fd *dirFD) load() ([]vfs.Dirent, error) {
	d := fd.dentry
	fs := d.fs
	// A listing is a revalidation point for the names: drop the names that
	// the guest found missing, so the next lookup asks the host again. See
	// lookupChildLocked for the consistency contract.
	fs.mu.Lock()
	d.inode.negChildren = nil
	fs.mu.Unlock()
	children, err := fs.ws.listDir(d.path())
	if err != nil {
		return nil, translateHostError(err)
	}
	fs.mu.Lock()
	parentIno := d.inode.ino
	if d.parent != nil {
		parentIno = d.parent.inode.ino
	}
	// A cached entry that the listing shows with the same identity keeps its
	// metadata until the cache lifetime ends. Any other entry is stale now.
	for name, c := range d.children {
		i, found := slices.BinarySearchFunc(children, name, func(l dirListing, name string) int {
			return strings.Compare(l.name, name)
		})
		if !found || !c.inode.matchesListing(children[i]) {
			c.inode.invalidateMeta()
		}
	}
	fs.mu.Unlock()
	snap := make([]vfs.Dirent, 0, len(children)+2)
	snap = append(snap,
		vfs.Dirent{Name: ".", Type: linux.DT_DIR, Ino: d.inode.ino},
		vfs.Dirent{Name: "..", Type: linux.DT_DIR, Ino: parentIno},
	)
	rel := d.path()
	for _, c := range children {
		ino := c.ino
		switch {
		case c.virtual:
			ino = virtualInoFor(joinRelPath(rel, c.name))
		case ino == 0:
			// The platform layer did not report an inode number while
			// listing, so ask for it. A miss means the entry vanished.
			e, err := fs.ws.lookupIn(rel, c.name)
			if err != nil {
				continue
			}
			ino = e.info.id.ino
		}
		snap = append(snap, vfs.Dirent{Name: c.name, Type: direntTypeOf(c), Ino: ino})
	}
	for i := range snap {
		snap[i].NextOff = int64(i + 1)
	}
	return snap, nil
}

// IterDirents implements vfs.FileDescriptionImpl.IterDirents.
func (fd *dirFD) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback) error {
	return fd.cursor.IterDirents(cb, fd.load)
}

// Seek implements vfs.FileDescriptionImpl.Seek. Seeking to the start discards
// the snapshot, so rewinddir observes the current directory.
func (fd *dirFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return fd.cursor.SeekDir(offset, whence)
}

// Sync implements vfs.FileDescriptionImpl.Sync. It bypasses the coalesce
// window of the metadata table. It flushes the directory, the entry of the
// directory in its parent, the mapped pages of the filesystem, and .gvx_meta.
func (fd *dirFD) Sync(ctx context.Context, opts vfs.SyncOptions) error {
	var errs []error
	if err := fd.dentry.fs.ws.syncDir(fd.dentry.path()); err != nil {
		errs = append(errs, err)
	}
	if err := fd.dentry.syncParentDir(); err != nil {
		errs = append(errs, err)
	}
	if err := fd.dentry.fs.Sync(ctx); err != nil {
		errs = append(errs, err)
	}
	return translateHostError(errors.Join(errs...))
}

// matchesListing reports whether the listing entry l names the same host
// object as i: the same kind and the same inode number. A listing that carries
// no inode number matches on the kind alone.
func (i *inode) matchesListing(l dirListing) bool {
	if i.virtual || l.virtual {
		return i.virtual == l.virtual
	}
	kind := l.kind
	if l.special != 0 {
		kind = hostKindSpecial
	}
	return i.kind == kind && (l.ino == 0 || l.ino == i.id.ino)
}
