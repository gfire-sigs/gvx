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

package mm

import (
	"errors"
	"io"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

var _ platform.ExecImageProvider = (*MemoryManager)(nil)

// ExecImageAt implements platform.ExecImageProvider.ExecImageAt.
//
// +checklocksexclude:mm.mappingMu
func (mm *MemoryManager) ExecImageAt(ctx context.Context, addr hostarch.Addr) platform.ExecImage {
	mm.mappingMu.RLock()
	vseg := mm.vmas.FindSegment(addr)
	if !vseg.Ok() {
		mm.mappingMu.RUnlock()
		return platform.ExecImage{Kind: platform.MappingUnmapped}
	}
	vma := vseg.ValuePtr()
	if vma.mappable == nil {
		mm.mappingMu.RUnlock()
		return platform.ExecImage{Kind: platform.MappingAnonymous}
	}
	fd, ok := vma.id.(*vfs.FileDescription)
	if !ok {
		mm.mappingMu.RUnlock()
		return platform.ExecImage{Kind: platform.MappingSpecial}
	}
	// The reference keeps the description alive after the lock goes away.
	fd.IncRef()
	offset := vma.off + uint64(addr-vseg.Start())
	mm.mappingMu.RUnlock()
	return platform.ExecImage{
		Kind:    platform.MappingFile,
		Device:  fd.DeviceID(),
		Inode:   fd.InodeID(),
		Offset:  offset,
		File:    &fileReaderAt{ctx: ctx, fd: fd},
		Release: func() { fd.DecRef(ctx) },
	}
}

// HasMappingIn reports whether any virtual memory area overlaps ar.
//
// +checklocksexclude:mm.mappingMu
func (mm *MemoryManager) HasMappingIn(ar hostarch.AddrRange) bool {
	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
	seg := mm.vmas.LowerBoundSegment(ar.Start)
	return seg.Ok() && seg.Start() < ar.End
}

// fileReaderAt reads a file description at absolute offsets.
type fileReaderAt struct {
	ctx context.Context
	fd  *vfs.FileDescription
}

// ReadAt implements io.ReaderAt.
func (r *fileReaderAt) ReadAt(p []byte, off int64) (int, error) {
	total := 0
	for total < len(p) {
		n, err := r.fd.PRead(r.ctx, usermem.BytesIOSequence(p[total:]), off+int64(total), vfs.ReadOptions{})
		total += int(n)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, io.EOF
			}
			return total, err
		}
		if n == 0 {
			return total, io.EOF
		}
	}
	return total, nil
}
