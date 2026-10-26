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
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// dirFD implements vfs.FileDescriptionImpl for directories.
//
// The position of a description is a cookie: the byte offset in the directory
// of the next entry to return. An entry keeps its offset while it lives,
// because unlinking another entry never moves it. So a read that interleaves
// with unlinks neither repeats nor skips a surviving entry, as rm -rf needs.
// A cookie that names no entry resumes at the next entry.
type dirFD struct {
	fileDescription
	vfs.DirectoryFileDescriptionDefaultImpl

	mu  sync.Mutex
	pos int64
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

// IterDirents implements vfs.FileDescriptionImpl.IterDirents. It returns the
// entries at or after the position, in directory order. The position moves past
// each entry that the callback accepts, so a callback that fails leaves the
// failed entry for the next call.
func (fd *dirFD) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback) error {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	inode := fd.dentry.inode
	ents, err := inode.n.entriesFrom(uint64(fd.pos))
	if err != nil {
		return toLinuxErr(err)
	}
	inode.touchAtime(fd.vfsfd.Mount())
	for _, e := range ents {
		d := vfs.Dirent{Name: e.name, Type: direntType(e.ft), Ino: uint64(e.ino), NextOff: int64(e.next)}
		if err := cb.Handle(d); err != nil {
			return err
		}
		fd.pos = int64(e.next)
	}
	return nil
}

// Seek implements vfs.FileDescriptionImpl.Seek. The offset is a cookie. Seeking
// to zero rewinds the directory. SEEK_END names the size of the directory, as
// ext4 does.
func (fd *dirFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	var newOff int64
	switch whence {
	case linux.SEEK_SET:
		newOff = offset
	case linux.SEEK_CUR:
		newOff = fd.pos + offset
	case linux.SEEK_END:
		n := fd.dentry.inode.n
		n.mu.RLock()
		size := n.size
		n.mu.RUnlock()
		newOff = int64(size) + offset
	default:
		return 0, linuxerr.EINVAL
	}
	if newOff < 0 {
		return 0, linuxerr.EINVAL
	}
	fd.pos = newOff
	return newOff, nil
}

// Sync implements vfs.FileDescriptionImpl.Sync. The volume flush writes the
// directory blocks after the inode table.
func (fd *dirFD) Sync(ctx context.Context, opts vfs.SyncOptions) error {
	return fd.dentry.fs.syncInode(fd.dentry.inode)
}
