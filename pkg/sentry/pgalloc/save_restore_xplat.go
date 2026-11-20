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

package pgalloc

import (
	"errors"
	"fmt"
	"io"
	"math"

	"z.gfire.dev/gvx/internal/xsys/unix"
	pgallocpb "z.gfire.dev/gvx/pkg/sentry/pgalloc/pgalloc_metadata_go_proto"
)

// saveRestoreXplat stores per-file save, restore, and destruction state.
type saveRestoreXplat struct {
	// seekFn overrides unix.Seek in hostFileDataSeeker during unit tests.
	seekFn func(fd int, offset int64, whence int) (int64, error)

	// destroyDone reports whether releaserDestroyLocked finished.
	// MemoryFile.mu protects destroyDone.
	destroyDone bool

	// destroyUnmapErr joins chunk unmap errors from releaserDestroyLocked.
	// MemoryFile.mu protects destroyUnmapErr.
	destroyUnmapErr error

	// winBacking holds Windows-only chunk backing state.
	winBacking windowsBacking
}

// isSeekDataUnsupported reports whether err indicates that the host kernel or
// backing filesystem rejects SEEK_DATA or SEEK_HOLE.
func isSeekDataUnsupported(err error) bool {
	return errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.ENOTSUP) ||
		errors.Is(err, unix.EOPNOTSUPP)
}

func (f *MemoryFile) seekFileData(fd int, offset int64, whence int) (int64, error) {
	if f.saveRestore.seekFn != nil {
		return f.saveRestore.seekFn(fd, offset, whence)
	}
	return unix.Seek(fd, offset, whence)
}

// commitLoadedRanges commits every allocated memAcct range after LoadFrom maps
// the backing chunks. Non-Windows hosts treat this as a no-op because mmap
// commits pages on demand.
func (f *MemoryFile) commitLoadedRanges() error {
	for maseg := f.memAcct.FirstSegment(); maseg.Ok(); maseg = maseg.NextSegment() {
		if err := f.commitRange(maseg.Range()); err != nil {
			return err
		}
	}
	return nil
}

// unmapChunksLocked unmaps every chunk during destruction and wakes waiters on
// f.releaseCond.
//
// Preconditions: caller holds f.mu.
func (f *MemoryFile) unmapChunksLocked(chunks []chunkInfo) {
	f.saveRestore.destroyUnmapErr = f.unmapBackingChunks(chunks)
	f.saveRestore.destroyDone = true
	f.releaseCond.Broadcast()
}

const (
	// maxLoadMetadataBytes bounds the length of the serialized
	// MemoryFileMetadataProto that LoadFrom reads. A checkpoint that records
	// one range for each 4 KiB page of a 1 TiB file stays below it.
	maxLoadMetadataBytes = 256 << 20

	// maxLoadChunks bounds the chunk count in loaded metadata. It equals the
	// 47-bit user address space divided by chunkSize.
	maxLoadChunks = 1 << 17
)

// readBoundedBytes reads exactly n bytes from r. It grows the buffer as data
// arrives, so a corrupt length cannot allocate more than twice the number of
// bytes that r holds. It returns io.ErrUnexpectedEOF or io.EOF when r ends
// before n bytes.
func readBoundedBytes(r io.Reader, n uint64) ([]byte, error) {
	const firstChunk = 64 << 10
	if n <= firstChunk {
		buf := make([]byte, n)
		_, err := io.ReadFull(r, buf)
		return buf, err
	}
	buf := make([]byte, 0, firstChunk)
	for uint64(len(buf)) < n {
		if len(buf) == cap(buf) {
			grown := make([]byte, len(buf), min(uint64(cap(buf))*2, n))
			copy(grown, buf)
			buf = grown
		}
		end := min(uint64(cap(buf)), n)
		got, err := io.ReadFull(r, buf[len(buf):end])
		buf = buf[:len(buf)+got]
		if err != nil {
			return nil, err
		}
	}
	return buf, nil
}

// rangeProto is implemented by every generated range message of
// MemoryFileMetadataProto.
type rangeProto interface {
	GetStart() uint64
	GetEnd() uint64
}

// validateRangeProtos verifies that segs are non-empty, ordered, and disjoint.
// The segment sets of MemoryFile panic on other input. If limit is not
// math.MaxUint64, it also verifies that every range ends at or below limit.
// The free and waste sets that SaveTo writes end at math.MaxUint64, so only
// the accounting ranges have a limit.
func validateRangeProtos[T rangeProto](name string, segs []T, limit uint64) error {
	var prevEnd uint64
	for i, s := range segs {
		start, end := s.GetStart(), s.GetEnd()
		switch {
		case start >= end:
			return fmt.Errorf("%s[%d] has the empty or inverted range [%#x, %#x)", name, i, start, end)
		case end > limit:
			return fmt.Errorf("%s[%d] range [%#x, %#x) exceeds the backing file size %#x", name, i, start, end, limit)
		case start < prevEnd:
			return fmt.Errorf("%s[%d] range [%#x, %#x) overlaps or precedes the previous range", name, i, start, end)
		}
		prevEnd = end
	}
	return nil
}

// validateMetadataProto verifies saved metadata before importMetadataProto
// applies it: the chunk count must fit the host and the limit of the file, and
// accounting range must lie inside the chunks.
func (f *MemoryFile) validateMetadataProto(pb *pgallocpb.MemoryFileMetadataProto) error {
	nrChunks := uint64(len(pb.Chunks))
	if nrChunks > maxLoadChunks || nrChunks > maxChunks {
		return fmt.Errorf("%d chunks exceed the limit of %d", nrChunks, uint64(maxLoadChunks))
	}
	fileSize := nrChunks * chunkSize
	if limit := f.opts.MaxLoadBytes; limit != 0 && fileSize > limit {
		return fmt.Errorf("%d chunks need a %d byte file, above the limit of %d bytes", nrChunks, fileSize, limit)
	}
	return errors.Join(
		validateRangeProtos("mem_acct", pb.MemAcct, fileSize),
		validateRangeProtos("unfree_small", pb.UnfreeSmall, math.MaxUint64),
		validateRangeProtos("unfree_huge", pb.UnfreeHuge, math.MaxUint64),
		validateRangeProtos("unwaste_small", pb.UnwasteSmall, math.MaxUint64),
		validateRangeProtos("unwaste_huge", pb.UnwasteHuge, math.MaxUint64),
	)
}
