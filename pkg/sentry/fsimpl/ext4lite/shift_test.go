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
	"bytes"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

// view returns the memory of the file range [start, end) as the guest sees it
// through the mapping at this moment. A guest keeps such a pointer until the
// memory manager invalidates the mapping, so a test can store through it later.
func (mp *mapping) view(start, end uint64) []byte {
	mp.e.t.Helper()
	r := memmap.MappableRange{Start: start, End: end}
	ts, err := mp.m.Translate(mp.e.ctx, r, r, hostarch.ReadWrite)
	if err != nil {
		mp.e.t.Fatalf("Translate: %v", err)
	}
	bs, err := ts[0].File.MapInternal(memmap.FileRange{Start: ts[0].Offset, End: ts[0].Offset + (end - start)}, hostarch.ReadWrite)
	if err != nil {
		mp.e.t.Fatalf("MapInternal: %v", err)
	}
	if bs.Head().Len() < int(end-start) {
		mp.e.t.Fatalf("the mapped range [%d, %d) is not contiguous", start, end)
	}
	return bs.Head().ToSlice()[:end-start]
}

// TestRangeShiftKeepsStoresThroughALongLivedMapping stores into page 0 through a
// mapping that outlives a collapse and an insert at the offset 4096. The page
// lies below the offset, so the shift does not invalidate its mapping, and the
// store after the shift must reach the file.
func TestRangeShiftKeepsStoresThroughALongLivedMapping(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode uint64
	}{{"collapse", collapse}, {"insert", insert}} {
		t.Run(tc.name, func(t *testing.T) {
			forEachChunkMode(t, func(t *testing.T, e *env) {
				content := blocksPattern(1, 8)
				fd := e.fileWith("f", content)
				mp := e.mapFile(fd, 8*blockSize, true)
				defer mp.remove()
				page0 := mp.view(0, blockSize)
				copy(page0[:5], "first")

				if err := e.allocate(fd, tc.mode, blockSize, blockSize); err != nil {
					t.Fatal(err)
				}
				copy(page0[100:], "second")
				want := bytes.Clone(content)
				copy(want, "first")
				copy(want[100:], "second")
				if tc.mode == collapse {
					want = append(want[:blockSize], want[2*blockSize:]...)
				} else {
					want = append(append(want[:blockSize:blockSize], make([]byte, blockSize)...), want[blockSize:]...)
				}
				if err := fd.Sync(e.ctx); err != nil {
					t.Fatal(err)
				}
				wantBytes(t, "file after the shift and the late store", e.readAll(fd), want)
				wantBytes(t, "mapped pages after the shift", mp.view(0, uint64(len(want))), want)
			})
		})
	}
}

// TestKeepSizeReservationLeavesACleanImage reserves blocks behind the end of the
// file, as fallocate with FALLOC_FL_KEEP_SIZE does. e2fsck rejects an
// initialized extent behind the end, so the blocks must be unwritten. The test
// then shifts the file, because the unwritten blocks move with it.
func TestKeepSizeReservationLeavesACleanImage(t *testing.T) {
	e := newEnv(t)
	content := blocksPattern(1, 2)
	fd := e.fileWith("f", content)
	before := e.sectors("f")
	if err := e.allocate(fd, uint64(linux.FALLOC_FL_KEEP_SIZE), 0, 8*blockSize); err != nil {
		t.Fatal(err)
	}
	if st := e.mustStat("f"); st.Size != 2*blockSize || st.Blocks != before+6*blockSize/512 {
		t.Fatalf("size %d and %d sectors after the reservation, want size %d and %d sectors", st.Size, st.Blocks, 2*blockSize, before+6*blockSize/512)
	}
	wantBytes(t, "content", e.readAll(fd), content)
	e = requireCleanImage(t, e)
	fd = e.own(e.mustOpen("f", linux.O_RDWR))
	if err := e.allocate(fd, insert, blockSize, blockSize); err != nil {
		t.Fatal(err)
	}
	if err := e.allocate(fd, 0, 0, 12*blockSize); err != nil {
		t.Fatal(err)
	}
	want := append(append(bytes.Clone(content[:blockSize]), make([]byte, blockSize)...), content[blockSize:]...)
	want = append(want, make([]byte, 12*blockSize-len(want))...)
	e = requireCleanImage(t, e)
	wantBytes(t, "content after a remount", e.readFile("f"), want)
}

// TestFsckLiteRebuildsTheLinkCountOfANamedInodeWithNoLink gives an inode on the
// disk link count zero and a deletion time while a directory entry still names
// it. The mount must keep the file and give it one link.
func TestFsckLiteRebuildsTheLinkCountOfANamedInodeWithNoLink(t *testing.T) {
	img, res := auFsckImage(t)
	off := auInodeAt(res.Tree["/one"].ino)
	var raw [auISize]byte
	img.readAt(raw[:], off)
	auLE.PutUint16(raw[0x1A:], 0)
	auLE.PutUint32(raw[0x14:], 1_700_000_000)
	img.writeAt(raw[:], off)

	got, notes := auMountLegacy(t, img)
	one := got.Tree["/one"]
	if one == nil || len(one.data) != 200_000 {
		t.Fatalf("/one after the repair = %v, want the file of 200000 bytes (notes %v)", one, notes)
	}
}
