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
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/chunkcache"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// dirFD implements vfs.FileDescriptionImpl for directories.
//
// A directory description lists the directory once, when the guest first reads
// it or rewinds it. Every later read comes from that snapshot. POSIX leaves the
// visibility of entries that change during iteration unspecified. The snapshot
// keeps offsets stable while the guest deletes entries it already read, as
// rm -rf does.
type dirFD struct {
	fileDescription
	vfs.DirectoryFileDescriptionDefaultImpl
	cursor chunkcache.DirCursor
}

// openDir creates the file description of a directory.
func (d *dentry) openDir(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions, ats vfs.AccessTypes) (*vfs.FileDescription, error) {
	// A directory opens neither for writing nor with O_CREAT.
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
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *dirFD) Release(ctx context.Context) {}

// direntType returns the DT_* constant of a directory entry type.
func direntType(ft uint8) uint8 {
	switch ft {
	case ftRegular:
		return linux.DT_REG
	case ftDir:
		return linux.DT_DIR
	case ftChar:
		return linux.DT_CHR
	case ftBlock:
		return linux.DT_BLK
	case ftFIFO:
		return linux.DT_FIFO
	case ftSocket:
		return linux.DT_SOCK
	case ftSymlink:
		return linux.DT_LNK
	}
	return linux.DT_UNKNOWN
}

// load lists the directory into a snapshot. The entries "." and ".." come
// first, then the other entries in the order of the directory blocks.
func (fd *dirFD) load() ([]vfs.Dirent, error) {
	ents, err := fd.dentry.inode.n.entries()
	if err != nil {
		return nil, toLinuxErr(err)
	}
	snap := make([]vfs.Dirent, len(ents))
	for i, e := range ents {
		snap[i] = vfs.Dirent{Name: e.name, Type: direntType(e.ft), Ino: uint64(e.ino), NextOff: int64(i + 1)}
	}
	fd.dentry.inode.touchAtime(fd.vfsfd.Mount())
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

// Sync implements vfs.FileDescriptionImpl.Sync. The volume flush writes the
// directory blocks after the inode table.
func (fd *dirFD) Sync(ctx context.Context, opts vfs.SyncOptions) error {
	return fd.dentry.fs.syncInode(fd.dentry.inode)
}
