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
	"math"
	"os"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// This file implements fallocate(2) for regular files. hostfs supports three
// modes: 0, FALLOC_FL_KEEP_SIZE, and FALLOC_FL_PUNCH_HOLE with
// FALLOC_FL_KEEP_SIZE. Every other mode returns EOPNOTSUPP.
//
// The host does the work through the platform function allocateNative: Linux
// calls fallocate, macOS calls fcntl with F_PREALLOCATE and F_PUNCHHOLE, and
// Windows sets the allocation size and the end of file of the handle. A
// volume or a range that the host call cannot serve takes the emulation of
// emulateAllocate. The emulation extends the file, or it writes zeros, and it
// reserves no space.
//
// The mapped-page cache stays correct in both cases. A punch writes back the
// dirty chunks of the range first, so the host call removes them as well. The
// punch then zeroes the loaded chunks of the range in place. A mapping sees
// the zeros without an invalidation, because the mapping translates to the
// same chunk memory. A growth raises the cached size of the file.

// zeroChunk is the write size of the zero-fill emulation.
const zeroChunk = 64 << 10

// Allocate implements vfs.FileDescriptionImpl.Allocate.
func (fd *regularFD) Allocate(ctx context.Context, mode, offset, length uint64) error {
	const supported = linux.FALLOC_FL_KEEP_SIZE | linux.FALLOC_FL_PUNCH_HOLE
	if mode&^uint64(supported) != 0 {
		return linuxerr.EOPNOTSUPP
	}
	punch := mode&linux.FALLOC_FL_PUNCH_HOLE != 0
	keepSize := mode&linux.FALLOC_FL_KEEP_SIZE != 0
	if punch && !keepSize {
		return linuxerr.EOPNOTSUPP
	}
	if length == 0 || offset > math.MaxInt64 || length > math.MaxInt64 {
		return linuxerr.EINVAL
	}
	end := offset + length
	if end < offset || end > math.MaxInt64 {
		return linuxerr.EFBIG
	}
	d := fd.dentry
	ino := d.inode
	mnt := fd.vfsfd.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	if d.fs.ws.ReadOnly() {
		return linuxerr.EROFS
	}
	ino.wmu.Lock()
	defer ino.wmu.Unlock()
	if punch {
		// The host call must see the bytes that a mapping wrote.
		if err := ino.data.FlushRange(offset, end); err != nil {
			return translateHostError(err)
		}
	}
	// The host watcher must not mistake this change for a host change.
	ino.guestBegin()
	f, err := fd.h.acquire()
	if err != nil {
		ino.guestEnd(hostInfo{}, false)
		return translateHostError(err)
	}
	err = allocateFile(f, d.fs.ws.caps.NativeFallocate, mode, int64(offset), int64(length))
	ino.guestEndFile(f)
	fd.h.release()
	if err != nil {
		return translateHostError(err)
	}
	ino.invalidateMeta()
	switch {
	case punch:
		ino.data.Punched(offset, length)
	case !keepSize:
		if info, err := fd.h.fstat(d.fs.ws.host); err == nil {
			ino.data.extended(info.size)
		}
	}
	return nil
}

// allocateFile runs one fallocate request on the host file f. The mode has
// been validated. A host without native support, and a native call that the
// host refuses as unsupported, take the emulation.
func allocateFile(f *os.File, native bool, mode uint64, off, length int64) error {
	if native {
		err := allocateNative(f, mode, off, length)
		if !unsupportedByHost(err) {
			return err
		}
	}
	return emulateAllocate(f, mode, off, length)
}

// unsupportedByHost reports whether err means that the host cannot do the
// call. A nil error is not such a failure.
func unsupportedByHost(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errHostUnsupported) {
		return true
	}
	mapped, ok := hostErrno(err)
	return ok && linuxerr.Equals(linuxerr.EOPNOTSUPP, mapped)
}

// emulateAllocate serves a fallocate request without a native call. Mode 0
// extends the file. The mode KEEP_SIZE changes nothing, because it only
// reserves space. A punch writes zeros over the part of the range that the file
// holds.
func emulateAllocate(f *os.File, mode uint64, off, length int64) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	size := st.Size()
	switch {
	case mode&linux.FALLOC_FL_PUNCH_HOLE != 0:
		return zeroRange(f, off, min(length, size-off))
	case mode&linux.FALLOC_FL_KEEP_SIZE != 0:
		return nil
	case off+length > size:
		return f.Truncate(off + length)
	}
	return nil
}

// zeroRange writes n zero bytes at offset off. A range at or below zero bytes
// does nothing.
func zeroRange(f *os.File, off, n int64) error {
	if n <= 0 {
		return nil
	}
	zeros := make([]byte, min(n, zeroChunk))
	for n > 0 {
		chunk := zeros[:min(n, int64(len(zeros)))]
		if _, err := f.WriteAt(chunk, off); err != nil {
			return err
		}
		off += int64(len(chunk))
		n -= int64(len(chunk))
	}
	return nil
}

// extended raises the cached size after the host file grew. A loaded chunk
// holds zeros beyond the old size, so no chunk changes.
func (c *fileData) extended(size int64) {
	if !c.Active.Load() {
		return
	}
	c.DataMu.Lock()
	defer c.DataMu.Unlock()
	if size > c.size {
		c.size = size
	}
}
