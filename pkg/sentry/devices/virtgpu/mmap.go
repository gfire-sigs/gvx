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

package virtgpu

import (
	"encoding/binary"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/usermem"
)

const (
	// mapSlotShift shifts a fake mmap slot into the high 32 bits of the offset.
	// Slots start at 1, so the first offset is 4 GiB, matching Linux
	// DRM_FILE_PAGE_OFFSET_START. Blobs are at most 1 GiB, so the low 32 bits
	// hold the byte offset inside the blob.
	mapSlotShift = 32

	// maxMapSlot is the last slot whose shifted offset stays below math.MaxInt64.
	maxMapSlot = 1<<31 - 1
)

// mapBlob serves DRM_IOCTL_VIRTGPU_MAP.
func (fd *renderFD) mapBlob(ctx context.Context, uio usermem.IO, arg []byte) error {
	var req virtgpuMap
	if _, err := binary.Decode(arg, binary.LittleEndian, &req); err != nil {
		return linuxerr.EINVAL
	}

	fd.gemMu.Lock()
	o, ok := fd.gem.lookup(req.Handle)
	if !ok {
		fd.gemMu.Unlock()
		return linuxerr.ENOENT
	}
	if o.blob == nil {
		fd.gemMu.Unlock()
		return linuxerr.EINVAL
	}
	slot, ok := fd.gem.assignSlot(o)
	fd.gemMu.Unlock()
	if !ok {
		return linuxerr.ENOMEM
	}

	req.Offset = slot << mapSlotShift
	_, _ = binary.Encode(arg, binary.LittleEndian, &req)
	return nil
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap. The offset
// selects a blob by its MAP slot; the mapping then translates straight to the
// blob view.
func (fd *renderFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	if opts.Private {
		return linuxerr.EINVAL
	}
	slot := opts.Offset >> mapSlotShift
	within := opts.Offset & (1<<mapSlotShift - 1)

	fd.gemMu.Lock()
	o := fd.gem.lookupSlot(slot)
	if o == nil {
		fd.gemMu.Unlock()
		return linuxerr.EINVAL
	}
	end := within + opts.Length
	if end < within || end > o.blob.guestSize {
		fd.gemMu.Unlock()
		return linuxerr.EINVAL
	}
	// Take the blob owner and file reference through blobMapping while gemMu
	// is held so a concurrent GEM_CLOSE cannot drop the last owner first
	// (I-6b.2).
	bm := newBlobMapping(o.blob, &fd.vfsfd)
	fd.gemMu.Unlock()

	opts.MappingIdentity = bm
	opts.Mappable = o.blob
	opts.Offset = within
	return nil
}
