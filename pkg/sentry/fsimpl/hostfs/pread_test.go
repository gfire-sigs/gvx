package hostfs

import (
	"bytes"
	"io"
	"math"
	"os"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

func TestPReadAllocatesLessThanTheSectionReaderPath(t *testing.T) {
	e := newEnv(t)
	e.writeFile("f", bytes.Repeat([]byte("x"), 4096))
	fd := e.mustOpen("f", linux.O_RDONLY)
	defer fd.DecRef(e.ctx)
	regular := fd.Impl().(*regularFD)
	buf := make([]byte, 1024)
	dst := usermem.BytesIOSequence(buf)

	now := testing.AllocsPerRun(200, func() {
		if _, err := fd.PRead(e.ctx, dst, 0, vfs.ReadOptions{}); err != nil {
			t.Fatal(err)
		}
	})
	// The path that PRead used before copies through a section reader and an
	// adapter, and each boxes a value.
	before := testing.AllocsPerRun(200, func() {
		r := io.NewSectionReader(regular.h.f, 0, math.MaxInt64)
		if _, err := dst.CopyOutFrom(e.ctx, safemem.FromIOReader{Reader: r}); err != nil {
			t.Fatal(err)
		}
	})
	t.Logf("allocations per call: PRead %v, section reader path %v", now, before)
	if now >= before {
		t.Errorf("PRead makes %v allocations per call, want fewer than the %v of the section reader path", now, before)
	}
}

func TestPReadFlushesOnlyTheChunksItOverlaps(t *testing.T) {
	e := newEnv(t)
	content := bytes.Repeat([]byte("a"), 2*chunkSize)
	e.writeFile("m", content)
	fd := e.mustOpen("m", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	m, ms, ar := e.mapFile(fd, uint64(len(content)), true)

	rw := hostarch.ReadWrite
	write := func(off uint64, s string) {
		t.Helper()
		required := memmap.MappableRange{Start: off, End: off + uint64(hostarch.PageSize)}
		ts, err := m.Translate(e.ctx, required, required, rw)
		if err != nil || len(ts) == 0 {
			t.Fatalf("Translate(%v) = (%v, %v)", required, ts, err)
		}
		tr := ts[0]
		start := tr.Offset + off - tr.Source.Start
		bs, err := tr.File.MapInternal(memmap.FileRange{Start: start, End: start + uint64(len(s))}, rw)
		if err != nil || bs.NumBlocks() != 1 {
			t.Fatalf("MapInternal = (%v blocks, %v)", bs.NumBlocks(), err)
		}
		copy(bs.Head().ToSlice(), s)
	}
	write(0, "first!!!")
	write(chunkSize, "second!!")

	buf := make([]byte, 8)
	if n, err := fd.PRead(e.ctx, usermem.BytesIOSequence(buf), 0, vfs.ReadOptions{}); err != nil || n != 8 || string(buf) != "first!!!" {
		t.Fatalf("pread of the first chunk = (%q, %d, %v)", buf, n, err)
	}
	raw, err := os.ReadFile(e.host("m"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw[:8]) != "first!!!" {
		t.Errorf("host bytes of the first chunk = %q, want the mapped write", raw[:8])
	}
	if got := string(raw[chunkSize : chunkSize+8]); got != "aaaaaaaa" {
		t.Errorf("host bytes of the second chunk = %q, want them untouched by a read of the first chunk", got)
	}

	m.RemoveMapping(e.ctx, ms, ar, 0, true)
	if raw, err = os.ReadFile(e.host("m")); err != nil || string(raw[chunkSize:chunkSize+8]) != "second!!" {
		t.Errorf("host bytes of the second chunk after unmap = (%q, %v), want the mapped write", raw[chunkSize:chunkSize+8], err)
	}
}
