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
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gverrors "z.gfire.dev/gvx/pkg/errors"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

const (
	zeroKeep = uint64(linux.FALLOC_FL_ZERO_RANGE | linux.FALLOC_FL_KEEP_SIZE)
	zeroGrow = uint64(linux.FALLOC_FL_ZERO_RANGE)
	collapse = uint64(linux.FALLOC_FL_COLLAPSE_RANGE)
	insert   = uint64(linux.FALLOC_FL_INSERT_RANGE)
	punchKS  = uint64(linux.FALLOC_FL_PUNCH_HOLE | linux.FALLOC_FL_KEEP_SIZE)
)

// blocksPattern returns n blocks, and every block holds bytes that no other
// block holds, so a block that moved to the wrong place shows at once.
func blocksPattern(seed byte, n int) []byte {
	out := make([]byte, 0, n*blockSize)
	for i := range n {
		out = append(out, bytes.Repeat([]byte{seed + byte(i)}, blockSize)...)
	}
	return out
}

// fileWith creates the file p with content and returns an open description.
func (e *env) fileWith(p string, content []byte) *vfs.FileDescription {
	e.t.Helper()
	e.writeFile(p, content)
	return e.own(e.mustOpen(p, linux.O_RDWR))
}

// own registers fd, so that closeOwned or the end of the test closes it.
func (e *env) own(fd *vfs.FileDescription) *vfs.FileDescription {
	if slices.Contains(e.owned, fd) {
		return fd
	}
	if len(e.owned) == 0 {
		e.t.Cleanup(e.closeOwned)
	}
	e.owned = append(e.owned, fd)
	return fd
}

// closeOwned closes the descriptions that own registered.
func (e *env) closeOwned() {
	for _, fd := range e.owned {
		fd.DecRef(e.ctx)
	}
	e.owned = nil
}

func (e *env) allocate(fd *vfs.FileDescription, mode, off, length uint64) error {
	return fd.Allocate(e.ctx, mode, off, length)
}

// sectors returns the number of 512-byte units that the file owns.
func (e *env) sectors(p string) uint64 { return e.mustStat(p).Blocks }

// requireCleanImage unmounts the volume, lets e2fsck check the image, and
// mounts the image again, so the caller sees what the image persists.
func requireCleanImage(t *testing.T, e *env) *env {
	t.Helper()
	e.closeOwned()
	e = e.remount()
	e.unmount()
	runE2fsck(t, e.path)
	return openEnv(t, e.path, VolumeOptions{}, vfs.MountOptions{})
}

// requireRecoverableImage runs e2fsck on a crash image the way an operator
// does. The first run replays the journal and clears the orphan list, and the
// second run must find no problem.
func requireRecoverableImage(t *testing.T, path string) {
	t.Helper()
	bin, err := exec.LookPath("e2fsck")
	if err != nil {
		if os.Getenv("EXT4LITE_REQUIRE_E2FSCK") != "" {
			t.Fatal("e2fsck is not installed, and EXT4LITE_REQUIRE_E2FSCK is set")
		}
		t.Skip("e2fsck is not installed")
	}
	out, err := exec.Command(bin, "-p", path).CombinedOutput()
	if code := auExitCode(err); code != 0 && code != 1 {
		t.Fatalf("e2fsck -p of the crash image exits with %d:\n%s", code, bytes.TrimSpace(out))
	}
	runE2fsck(t, path)
}

func TestFallocateRejectsModesAsLinuxDoes(t *testing.T) {
	e := newEnv(t)
	fd := e.fileWith("f", blocksPattern(1, 4))
	const keep = linux.FALLOC_FL_KEEP_SIZE
	tests := []struct {
		name         string
		mode         uint64
		offset, size uint64
		want         *gverrors.Error
	}{
		{"hide stale", linux.FALLOC_FL_NO_HIDE_STALE, 0, blockSize, linuxerr.EOPNOTSUPP},
		{"unshare", linux.FALLOC_FL_UNSHARE_RANGE, 0, blockSize, linuxerr.EOPNOTSUPP},
		{"unknown bit", 0x80, 0, blockSize, linuxerr.EOPNOTSUPP},
		{"punch without keep size", linux.FALLOC_FL_PUNCH_HOLE, 0, blockSize, linuxerr.EOPNOTSUPP},
		{"punch with zero", linux.FALLOC_FL_PUNCH_HOLE | linux.FALLOC_FL_ZERO_RANGE | keep, 0, blockSize, linuxerr.EOPNOTSUPP},
		{"collapse with keep size", collapse | keep, 0, blockSize, linuxerr.EOPNOTSUPP},
		{"insert with keep size", insert | keep, 0, blockSize, linuxerr.EOPNOTSUPP},
		{"collapse with insert", collapse | insert, 0, blockSize, linuxerr.EOPNOTSUPP},
		{"collapse with zero", collapse | zeroGrow, 0, blockSize, linuxerr.EOPNOTSUPP},
		{"zero length", zeroGrow, 0, 0, linuxerr.EINVAL},
		{"offset above int64", zeroGrow, math.MaxUint64 - 5, 1, linuxerr.EINVAL},
		{"zero past the size limit", zeroGrow, maxFileSize, blockSize, linuxerr.EFBIG},
		{"collapse unaligned offset", collapse, 100, blockSize, linuxerr.EINVAL},
		{"collapse unaligned length", collapse, 0, blockSize + 1, linuxerr.EINVAL},
		{"collapse to the end", collapse, blockSize, 3 * blockSize, linuxerr.EINVAL},
		{"collapse past the end", collapse, 2 * blockSize, 8 * blockSize, linuxerr.EINVAL},
		{"insert unaligned offset", insert, 100, blockSize, linuxerr.EINVAL},
		{"insert unaligned length", insert, 0, 100, linuxerr.EINVAL},
		{"insert at the end", insert, 4 * blockSize, blockSize, linuxerr.EINVAL},
		{"insert past the end", insert, 6 * blockSize, blockSize, linuxerr.EINVAL},
		{"insert past the size limit", insert, 0, maxFileSize - 3*blockSize, linuxerr.EFBIG},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wantErrno(t, tc.name, e.allocate(fd, tc.mode, tc.offset, tc.size), tc.want)
		})
	}
	wantBytes(t, "content after the rejected calls", e.readAll(fd), blocksPattern(1, 4))
}

func TestZeroRangeClearsBytesAndKeepsTheBlocks(t *testing.T) {
	e := newEnv(t)
	content := blocksPattern(1, 8)
	fd := e.fileWith("f", content)
	before := e.sectors("f")

	off, length := uint64(blockSize+blockSize/2), uint64(4*blockSize)
	if err := e.allocate(fd, zeroKeep, off, length); err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(content)
	clear(want[off : off+length])
	wantBytes(t, "content after the zero range", e.readAll(fd), want)
	if st := e.mustStat("f"); st.Size != 8*blockSize || st.Blocks != before {
		t.Fatalf("size %d and %d sectors after the zero range, want size %d and %d sectors", st.Size, st.Blocks, 8*blockSize, before)
	}
	// The whole blocks 2 to 4 are unwritten, as ext4 leaves them. The partial
	// blocks 1 and 5 still hold data.
	if pos, err := fd.Seek(e.ctx, 0, linux.SEEK_HOLE); err != nil || pos != 2*blockSize {
		t.Fatalf("SEEK_HOLE = (%d, %v), want %d", pos, err, 2*blockSize)
	}
	if pos, err := fd.Seek(e.ctx, 2*blockSize, linux.SEEK_DATA); err != nil || pos != 5*blockSize {
		t.Fatalf("SEEK_DATA = (%d, %v), want %d", pos, err, 5*blockSize)
	}

	e = requireCleanImage(t, e)
	wantBytes(t, "content after a remount", e.readFile("f"), want)
}

func TestZeroRangeInsideOneBlock(t *testing.T) {
	e := newEnv(t)
	content := blocksPattern(1, 2)
	fd := e.fileWith("f", content)
	if err := e.allocate(fd, zeroKeep, 100, 200); err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(content)
	clear(want[100:300])
	wantBytes(t, "content", e.readAll(fd), want)
}

func TestZeroRangeAllocatesAHole(t *testing.T) {
	e := newEnv(t)
	fd := e.own(e.mustOpen("f", linux.O_CREAT|linux.O_RDWR))
	e.pwrite(fd, blocksPattern(1, 1), 0)
	e.pwrite(fd, blocksPattern(9, 1), 9*blockSize)
	before := e.sectors("f")

	if err := e.allocate(fd, zeroKeep, 2*blockSize, 4*blockSize); err != nil {
		t.Fatal(err)
	}
	if got, want := e.sectors("f"), before+4*blockSize/512; got != want {
		t.Fatalf("%d sectors after a zero range over a hole, want %d: the range needs its own blocks", got, want)
	}
	if st := e.mustStat("f"); st.Size != 10*blockSize {
		t.Fatalf("size %d, want %d", st.Size, 10*blockSize)
	}
	want := append(append(blocksPattern(1, 1), make([]byte, 8*blockSize)...), blocksPattern(9, 1)...)
	wantBytes(t, "content", e.readAll(fd), want)
	if pos, err := fd.Seek(e.ctx, blockSize, linux.SEEK_DATA); err != nil || pos != 9*blockSize {
		t.Fatalf("SEEK_DATA from the first hole = (%d, %v), want %d: unwritten blocks are holes", pos, err, 9*blockSize)
	}
	requireCleanImage(t, e)
}

func TestZeroRangeBeyondTheEndOfFile(t *testing.T) {
	t.Run("grows the size", func(t *testing.T) {
		e := newEnv(t)
		fd := e.fileWith("f", blocksPattern(1, 2)[:2*blockSize-500])
		if err := e.allocate(fd, zeroGrow, blockSize, 8*blockSize+7); err != nil {
			t.Fatal(err)
		}
		if st := e.mustStat("f"); st.Size != 9*blockSize+7 {
			t.Fatalf("size %d, want %d", st.Size, 9*blockSize+7)
		}
		want := make([]byte, 9*blockSize+7)
		copy(want, blocksPattern(1, 1))
		wantBytes(t, "content", e.readAll(fd), want)
		e = requireCleanImage(t, e)
		wantBytes(t, "content after a remount", e.readFile("f"), want)
	})
	t.Run("keeps the size", func(t *testing.T) {
		e := newEnv(t)
		fd := e.fileWith("f", blocksPattern(1, 1))
		before := e.sectors("f")
		if err := e.allocate(fd, zeroKeep, blockSize, 4*blockSize); err != nil {
			t.Fatal(err)
		}
		if st := e.mustStat("f"); st.Size != blockSize || st.Blocks != before+4*blockSize/512 {
			t.Fatalf("size %d and %d sectors, want size %d and %d sectors: KEEP_SIZE maps the blocks and keeps the size", st.Size, st.Blocks, blockSize, before+4*blockSize/512)
		}
		wantBytes(t, "content", e.readAll(fd), blocksPattern(1, 1))
		requireCleanImage(t, e)
	})
}

func TestZeroRangeOfInlineFile(t *testing.T) {
	e := newEnv(t)
	fd := e.fileWith("f", pattern(3, 100))
	if err := e.allocate(fd, zeroKeep, 10, 20); err != nil {
		t.Fatal(err)
	}
	want := pattern(3, 100)
	clear(want[10:30])
	wantBytes(t, "content after a zero range inside the file", e.readAll(fd), want)
	if err := e.allocate(fd, zeroGrow, 90, 110); err != nil {
		t.Fatal(err)
	}
	want = append(want[:90], make([]byte, 110)...)
	wantBytes(t, "content after a zero range past the end", e.readAll(fd), want)
	if st := e.mustStat("f"); st.Size != 200 {
		t.Fatalf("size %d, want 200", st.Size)
	}
	e = requireCleanImage(t, e)
	wantBytes(t, "content after a remount", e.readFile("f"), want)
}

// TestWriteToZeroedBlockShowsNoStaleBytes writes into a block that a zero range
// left unwritten. The block still holds the old bytes on the host, and the
// write must not bring them back.
func TestWriteToZeroedBlockShowsNoStaleBytes(t *testing.T) {
	e := newEnv(t)
	fd := e.fileWith("f", blocksPattern(1, 4))
	if err := e.allocate(fd, zeroKeep, 0, 4*blockSize); err != nil {
		t.Fatal(err)
	}
	e.pwrite(fd, []byte("fresh"), blockSize+100)
	want := make([]byte, 4*blockSize)
	copy(want[blockSize+100:], "fresh")
	wantBytes(t, "content", e.readAll(fd), want)
	e = requireCleanImage(t, e)
	wantBytes(t, "content after a remount", e.readFile("f"), want)
}

func TestZeroRangeSplitsLongExtents(t *testing.T) {
	if testing.Short() {
		t.Skip("the test writes 130 MB")
	}
	e := newEnv(t)
	fd := e.own(e.mustOpen("f", linux.O_CREAT|linux.O_RDWR))
	const blocks = 33_000
	if err := e.allocate(fd, 0, 0, blocks*blockSize); err != nil {
		t.Fatal(err)
	}
	before := e.sectors("f")
	// An initialized extent holds up to 32768 blocks, and an unwritten extent
	// holds up to 32767.
	if err := e.allocate(fd, zeroKeep, 0, blocks*blockSize); err != nil {
		t.Fatal(err)
	}
	if got := e.sectors("f"); got != before {
		t.Fatalf("%d sectors after the zero range, want %d", got, before)
	}
	e.pwrite(fd, []byte("tail"), (blocks-1)*blockSize)
	e = requireCleanImage(t, e)
	got := e.readFile("f")
	if len(got) != blocks*blockSize || string(got[(blocks-1)*blockSize:(blocks-1)*blockSize+4]) != "tail" || !isZero(got[:(blocks-1)*blockSize]) {
		t.Fatalf("content after the zero range and a write at the end is wrong (size %d)", len(got))
	}
}

func TestCollapseRangeRemovesBlocksAndShiftsTheRest(t *testing.T) {
	e := newEnv(t)
	content := blocksPattern(1, 10)
	fd := e.fileWith("f", content)
	before := e.sectors("f")

	if err := e.allocate(fd, collapse, 2*blockSize, 3*blockSize); err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Clone(content[:2*blockSize]), content[5*blockSize:]...)
	wantBytes(t, "content after the collapse", e.readAll(fd), want)
	if st := e.mustStat("f"); st.Size != 7*blockSize || st.Blocks != before-3*blockSize/512 {
		t.Fatalf("size %d and %d sectors after the collapse, want size %d and %d sectors", st.Size, st.Blocks, 7*blockSize, before-3*blockSize/512)
	}
	e = requireCleanImage(t, e)
	wantBytes(t, "content after a remount", e.readFile("f"), want)
}

func TestCollapseRangeKeepsAPartialLastBlock(t *testing.T) {
	e := newEnv(t)
	content := blocksPattern(1, 6)[:5*blockSize+1234]
	fd := e.fileWith("f", content)
	if err := e.allocate(fd, collapse, blockSize, 2*blockSize); err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Clone(content[:blockSize]), content[3*blockSize:]...)
	wantBytes(t, "content", e.readAll(fd), want)
	if st := e.mustStat("f"); st.Size != uint64(len(want)) {
		t.Fatalf("size %d, want %d", st.Size, len(want))
	}
	requireCleanImage(t, e)
}

func TestCollapseRangeOfSparseFile(t *testing.T) {
	e := newEnv(t)
	fd := e.own(e.mustOpen("f", linux.O_CREAT|linux.O_RDWR))
	e.pwrite(fd, blocksPattern(1, 1), 0)
	e.pwrite(fd, blocksPattern(2, 1), 5*blockSize)
	e.pwrite(fd, blocksPattern(3, 1), 9*blockSize)
	if err := e.allocate(fd, collapse, 2*blockSize, 5*blockSize); err != nil {
		t.Fatal(err)
	}
	// The range 2..6 held the block 5, so only the blocks 0 and 9 remain.
	want := append(append(blocksPattern(1, 1), make([]byte, blockSize)...), make([]byte, 2*blockSize)...)
	want = append(want, blocksPattern(3, 1)...)
	wantBytes(t, "content", e.readAll(fd), want)
	requireCleanImage(t, e)
}

func TestInsertRangeOpensAHole(t *testing.T) {
	e := newEnv(t)
	content := blocksPattern(1, 6)
	fd := e.fileWith("f", content)
	before := e.sectors("f")

	if err := e.allocate(fd, insert, 2*blockSize, 3*blockSize); err != nil {
		t.Fatal(err)
	}
	want := append(append(bytes.Clone(content[:2*blockSize]), make([]byte, 3*blockSize)...), content[2*blockSize:]...)
	wantBytes(t, "content after the insert", e.readAll(fd), want)
	if st := e.mustStat("f"); st.Size != 9*blockSize || st.Blocks != before {
		t.Fatalf("size %d and %d sectors after the insert, want size %d and %d sectors: the new range is a hole", st.Size, st.Blocks, 9*blockSize, before)
	}
	if pos, err := fd.Seek(e.ctx, 0, linux.SEEK_HOLE); err != nil || pos != 2*blockSize {
		t.Fatalf("SEEK_HOLE = (%d, %v), want %d", pos, err, 2*blockSize)
	}
	if pos, err := fd.Seek(e.ctx, 2*blockSize, linux.SEEK_DATA); err != nil || pos != 5*blockSize {
		t.Fatalf("SEEK_DATA = (%d, %v), want %d", pos, err, 5*blockSize)
	}
	e = requireCleanImage(t, e)
	wantBytes(t, "content after a remount", e.readFile("f"), want)
}

func TestInsertRangeInsideAnExtentSplitsIt(t *testing.T) {
	e := newEnv(t)
	content := blocksPattern(1, 4)
	fd := e.fileWith("f", content)
	if err := e.allocate(fd, insert, blockSize, blockSize); err != nil {
		t.Fatal(err)
	}
	want := append(append(bytes.Clone(content[:blockSize]), make([]byte, blockSize)...), content[blockSize:]...)
	wantBytes(t, "content", e.readAll(fd), want)
	requireCleanImage(t, e)
}

func TestInsertRangeBeforeInlineContent(t *testing.T) {
	e := newEnv(t)
	content := pattern(5, 100)
	fd := e.fileWith("f", content)
	if err := e.allocate(fd, insert, 0, blockSize); err != nil {
		t.Fatal(err)
	}
	want := append(make([]byte, blockSize), content...)
	wantBytes(t, "content", e.readAll(fd), want)
	e = requireCleanImage(t, e)
	wantBytes(t, "content after a remount", e.readFile("f"), want)
}

// TestRangeChangesKeepMappedPagesCoherent maps a file, moves its blocks with a
// collapse and with an insert, and reads the file through the mapping. The
// mapped pages must show the new place of every byte.
func TestRangeChangesKeepMappedPagesCoherent(t *testing.T) {
	forEachChunkMode(t, func(t *testing.T, e *env) {
		content := blocksPattern(1, 8)
		fd := e.fileWith("f", content)
		mp := e.mapFile(fd, 8*blockSize, true)
		defer mp.remove()
		wantBytes(t, "mapped content", mp.read(0, 8*blockSize), content)

		if err := e.allocate(fd, collapse, blockSize, 2*blockSize); err != nil {
			t.Fatal(err)
		}
		want := append(bytes.Clone(content[:blockSize]), content[3*blockSize:]...)
		wantBytes(t, "mapped content after the collapse", mp.read(0, uint64(len(want))), want)

		if err := e.allocate(fd, insert, blockSize, blockSize); err != nil {
			t.Fatal(err)
		}
		want = append(append(bytes.Clone(want[:blockSize]), make([]byte, blockSize)...), want[blockSize:]...)
		wantBytes(t, "mapped content after the insert", mp.read(0, uint64(len(want))), want)

		mp.store(100, []byte("MAPPED"))
		copy(want[100:], "MAPPED")
		wantBytes(t, "read after a store into the shifted mapping", e.readAll(fd), want)
	})
}

// TestRangeChangesMatchAByteModel applies random zero, collapse, insert, punch,
// and write calls to a file and to a byte slice. The file must equal the slice
// after every call, and e2fsck must accept the image at the end. The file has
// many extents, so the extent tree grows and shrinks.
func TestRangeChangesMatchAByteModel(t *testing.T) {
	for _, seed := range []uint64{1, 2, 3} {
		t.Run(fmt.Sprintf("seed %d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(seed, 0xFA11))
			e := newEnv(t)
			fd := e.own(e.mustOpen("f", linux.O_CREAT|linux.O_RDWR))
			model := blocksPattern(1, 1200)
			e.pwrite(fd, model, 0)
			// Alternate blocks become holes, which leaves 600 extents.
			for b := 1; b < 1200; b += 2 {
				if err := e.allocate(fd, punchKS, uint64(b)*blockSize, blockSize); err != nil {
					t.Fatal(err)
				}
				clear(model[b*blockSize : (b+1)*blockSize])
			}
			var log []string
			for step := range 60 {
				blocks := len(model) / blockSize
				off := rng.IntN(blocks) * blockSize
				length := (1 + rng.IntN(max(1, min(300, blocks-off/blockSize)))) * blockSize
				var desc string
				var err error
				switch rng.IntN(4) {
				case 0:
					desc = fmt.Sprintf("zero %d+%d", off, length)
					err = e.allocate(fd, zeroKeep, uint64(off), uint64(length))
					clear(model[off:min(len(model), off+length)])
				case 1:
					desc = fmt.Sprintf("collapse %d+%d", off, length)
					err = e.allocate(fd, collapse, uint64(off), uint64(length))
					if off+length < len(model) {
						model = append(model[:off], model[off+length:]...)
					} else if linuxerr.Equals(linuxerr.EINVAL, err) {
						// A range that reaches the end of the file is a truncate.
						err = nil
					}
				case 2:
					desc = fmt.Sprintf("insert %d+%d", off, length)
					err = e.allocate(fd, insert, uint64(off), uint64(length))
					model = append(model[:off], append(make([]byte, length), model[off:]...)...)
				default:
					desc = fmt.Sprintf("write %d+%d", off, length)
					data := pattern(byte(step), length)
					e.pwrite(fd, data, int64(off))
					copy(model[off:], data)
				}
				log = append(log, desc)
				if err != nil {
					t.Fatalf("step %d (%s): %v\nsteps: %s", step, desc, err, strings.Join(log, "; "))
				}
				if got := e.readAll(fd); !bytes.Equal(got, model) {
					t.Fatalf("after step %d (%s): got %d bytes, want %d, first difference at %d\nsteps: %s", step, desc, len(got), len(model), firstDiff(got, model), strings.Join(log, "; "))
				}
			}
			e = requireCleanImage(t, e)
			wantBytes(t, "content after a remount", e.readFile("f"), model)
		})
	}
}
