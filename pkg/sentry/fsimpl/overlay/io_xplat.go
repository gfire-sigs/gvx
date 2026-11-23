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

package overlay

import (
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/blockdev"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// shouldAccountUpperTmpfsIO reports whether this overlay represents a block
// device (such as the rootfs overlay on vda) whose upper layer is tmpfs rather
// than a self-accounting block filesystem such as ext4lite.
func (fs *filesystem) shouldAccountUpperTmpfsIO() bool {
	if fs.dirDevMajor == linux.UNNAMED_MAJOR || !fs.opts.UpperRoot.Ok() {
		return false
	}
	return fs.opts.UpperRoot.Mount().Filesystem().FilesystemType().Name() == "tmpfs"
}

// initRegularFileFD constructs and initializes either an ioRegularFileFD (when
// the overlay accounts tmpfs upper layer I/O against its block device) or a
// standard regularFileFD.
func (fs *filesystem) initRegularFileFD(
	ctx context.Context,
	rp *vfs.ResolvingPath,
	mnt *vfs.Mount,
	d *dentry,
	copiedUp bool,
	layerFD *vfs.FileDescription,
	layerFlags uint32,
	layerFDOpts *vfs.FileDescriptionOptions,
) (*vfs.FileDescription, error) {
	if fs.shouldAccountUpperTmpfsIO() {
		fd := &ioRegularFileFD{
			regularFileFD: regularFileFD{
				copiedUp:    copiedUp,
				cachedFD:    layerFD,
				cachedFlags: layerFlags,
			},
		}
		fd.LockFD.Init(&d.locks)
		if err := fd.vfsfd.Init(fd, layerFlags, rp.Credentials(), mnt, &d.vfsd, layerFDOpts); err != nil {
			layerFD.DecRef(ctx)
			return nil, err
		}
		return &fd.vfsfd, nil
	}
	fd := &regularFileFD{
		copiedUp:    copiedUp,
		cachedFD:    layerFD,
		cachedFlags: layerFlags,
	}
	fd.LockFD.Init(&d.locks)
	if err := fd.vfsfd.Init(fd, layerFlags, rp.Credentials(), mnt, &d.vfsd, layerFDOpts); err != nil {
		layerFD.DecRef(ctx)
		return nil, err
	}
	return &fd.vfsfd, nil
}

// ioRegularFileFD wraps regularFileFD to attribute reads and writes on the
// tmpfs upper layer of a block-backed rootfs overlay to the overlay's block
// device in the cgroup v2 io controller. Lower-layer reads are not charged
// here because EROFS accounts them directly.
//
// +stateify savable
type ioRegularFileFD struct {
	regularFileFD
}

func (fd *ioRegularFileFD) accountIO(ctx context.Context, op blockdev.Op, n uint64) {
	fs := fd.filesystem()
	blockdev.AccountIO(ctx, fs.vfsfs.VirtualFilesystem(), fs.dirDevMajor, fs.dirDevMinor, op, n, 1)
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *ioRegularFileFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	fdIdx := fd.lockIndex()
	fd.mu.NestedLock(fdIdx)
	wrappedFD, err := fd.currentFDLocked(ctx)
	if err != nil {
		fd.mu.NestedUnlock(fdIdx)
		return 0, err
	}
	fromUpper := fd.copiedUp
	wrappedFD.IncRef()
	fd.mu.NestedUnlock(fdIdx)
	defer wrappedFD.DecRef(ctx)

	n, err := wrappedFD.PRead(ctx, dst, offset, opts)
	if n > 0 && fromUpper {
		fd.accountIO(ctx, blockdev.Read, uint64(n))
	}
	return n, err
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *ioRegularFileFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	fdIdx := fd.lockIndex()
	fd.mu.NestedLock(fdIdx)
	defer fd.mu.NestedUnlock(fdIdx)
	wrappedFD, err := fd.currentFDLocked(ctx)
	if err != nil {
		return 0, err
	}
	fromUpper := fd.copiedUp
	n, err := wrappedFD.Read(ctx, dst, opts)
	if n > 0 && fromUpper {
		fd.accountIO(ctx, blockdev.Read, uint64(n))
	}
	return n, err
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *ioRegularFileFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	n, err := fd.regularFileFD.PWrite(ctx, src, offset, opts)
	if n > 0 {
		fd.accountIO(ctx, blockdev.Write, uint64(n))
	}
	return n, err
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *ioRegularFileFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	n, err := fd.regularFileFD.Write(ctx, src, opts)
	if n > 0 {
		fd.accountIO(ctx, blockdev.Write, uint64(n))
	}
	return n, err
}
