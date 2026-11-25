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

//go:build linux

package systrap

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

// These tests start real stub processes. The host kernel is the producer of
// the process tree, the descriptor table, and the mappings that they count.

// sharedPlatform is the one platform of the test binary. The source stub of
// globalPool keeps the memory file of the first platform, so all tests use it.
var sharedPlatform = sync.OnceValues(func() (*Systrap, error) {
	// New reads the CPU features of the host on amd64.
	cpuid.Initialize()
	return New(platform.Options{})
})

// mapAddr is the guest address where the tests map one page. It lies far
// below the stub region, which sits at the top of the address space.
const mapAddr = hostarch.Addr(1 << 28)

func requirePlatform(t *testing.T) *Systrap {
	t.Helper()
	p, err := sharedPlatform()
	if err != nil {
		t.Skipf("systrap engine unavailable: %v", err)
	}
	drainIdleStubs()
	return p
}

// useIdleLimit replaces the bound of the idle pool for one test.
func useIdleLimit(t *testing.T, k int) {
	t.Helper()
	old := idleStubLimit
	idleStubLimit = func() int { return k }
	t.Cleanup(func() {
		drainIdleStubs()
		idleStubLimit = old
	})
}

// drainIdleStubs destroys every stub in the idle pool.
func drainIdleStubs() {
	for sp := globalPool.fetchAvailable(); sp != nil; sp = globalPool.fetchAvailable() {
		sp.destroyIdle()
	}
}

// childPIDs returns the child processes of the test process. A zombie that
// the test process did not reap counts as a child.
func childPIDs(t testing.TB) map[int]struct{} {
	t.Helper()
	files, err := filepath.Glob("/proc/self/task/*/children")
	if err != nil {
		t.Fatalf("glob /proc/self/task/*/children: %v", err)
	}
	pids := make(map[int]struct{})
	if len(files) > 0 {
		for _, f := range files {
			b, err := os.ReadFile(f)
			if os.IsNotExist(err) {
				continue // The Go runtime ended this thread.
			}
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			for _, field := range strings.Fields(string(b)) {
				pid, err := strconv.Atoi(field)
				if err != nil {
					t.Fatalf("parse child pid %q in %s: %v", field, f, err)
				}
				pids[pid] = struct{}{}
			}
		}
		return pids
	}

	selfPID := os.Getpid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatalf("read /proc: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == selfPID {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err != nil {
			continue
		}
		closeParen := strings.LastIndexByte(string(b), ')')
		if closeParen < 0 {
			continue
		}
		fields := strings.Fields(string(b[closeParen+1:]))
		if len(fields) < 2 {
			continue
		}
		ppid, err := strconv.Atoi(fields[1])
		if err == nil && ppid == selfPID {
			pids[pid] = struct{}{}
		}
	}
	return pids
}

func countChildren(t testing.TB) int {
	t.Helper()
	return len(childPIDs(t))
}

func newTestAddressSpace(p *Systrap) (*subprocess, error) {
	as, err := p.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		return nil, err
	}
	return as.(*subprocess), nil
}

// mapAndUnmapPage maps one page of the platform memory file into the address
// space and unmaps it. The call goes through the syscall thread of the stub.
func mapAndUnmapPage(p *Systrap, as platform.AddressSpace) error {
	fr, err := p.memoryFile.Allocate(uint64(hostarch.PageSize), pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		return fmt.Errorf("allocate: %w", err)
	}
	defer p.memoryFile.DecRef(fr)
	if err := as.MapFile(mapAddr, p.memoryFile, fr, hostarch.ReadWrite, false); err != nil {
		return fmt.Errorf("MapFile: %w", err)
	}
	as.Unmap(mapAddr, uint64(hostarch.PageSize))
	return nil
}

// spaceSet holds the live address spaces of one test. The cleanup of the test
// releases the address spaces that the test did not release, so a failed test
// does not leave live stubs for the next test.
type spaceSet struct {
	spaces   []*subprocess
	released map[*subprocess]bool
}

// useAddressSpaces creates n address spaces and uses each one.
func useAddressSpaces(t *testing.T, p *Systrap, n int) *spaceSet {
	t.Helper()
	set := &spaceSet{released: make(map[*subprocess]bool)}
	t.Cleanup(func() { set.release(set.spaces...) })
	for i := range n {
		sp, err := newTestAddressSpace(p)
		if err != nil {
			t.Fatalf("NewAddressSpace %d of %d: %v", i, n, err)
		}
		set.spaces = append(set.spaces, sp)
		if err := mapAndUnmapPage(p, sp); err != nil {
			t.Fatalf("address space %d of %d: %v", i, n, err)
		}
	}
	return set
}

// release releases each address space that is still live.
func (g *spaceSet) release(spaces ...*subprocess) {
	for _, sp := range spaces {
		if !g.released[sp] {
			g.released[sp] = true
			sp.Release()
		}
	}
}

func TestReleasedStubsStayWithinTheIdleBound(t *testing.T) {
	p := requirePlatform(t)
	const k = 2
	useIdleLimit(t, k)

	for round := 1; round <= 2; round++ {
		set := useAddressSpaces(t, p, 8)
		if got, want := countChildren(t), 8+1; got != want {
			t.Fatalf("round %d: %d live address spaces: %d child processes, want %d (live stubs plus the source stub)", round, len(set.spaces), got, want)
		}
		set.release(set.spaces...)
		if got, want := countChildren(t), k+1; got != want {
			t.Fatalf("round %d: after releasing 8 address spaces with bound %d: %d child processes, want %d (pooled stubs plus the source stub)", round, k, got, want)
		}
	}
}

func TestStubOutlivesAddressSpaceUntilTheLastContextReleases(t *testing.T) {
	p := requirePlatform(t)
	useIdleLimit(t, 0)

	sp, err := newTestAddressSpace(p)
	if err != nil {
		t.Fatalf("NewAddressSpace: %v", err)
	}
	sc, err := sp.getSharedContext()
	if err != nil {
		t.Fatalf("getSharedContext: %v", err)
	}
	sp.Release()
	if got, want := countChildren(t), 2; got != want {
		t.Fatalf("a shared context still uses the stub: %d child processes, want %d", got, want)
	}
	sc.release()
	if got, want := countChildren(t), 1; got != want {
		t.Fatalf("the last shared context released the stub: %d child processes, want %d (the source stub)", got, want)
	}
}

// memfdMappings parses /proc/self/maps and returns VMA counts and mapped byte totals.
// It reports totals for inode ino, totals across all memfds, and total VMA lines.
func memfdMappings(t testing.TB, ino uint64) (lines int, bytes uint64, allMemfdLines int, allMemfdBytes uint64, all int) {
	t.Helper()
	b, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatalf("read /proc/self/maps: %v", err)
	}
	wantIno := strconv.FormatUint(ino, 10)
	for line := range strings.Lines(string(b)) {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		all++
		if !strings.Contains(line, "memfd:") {
			continue
		}
		var start, end uint64
		if _, err := fmt.Sscanf(fields[0], "%x-%x", &start, &end); err != nil {
			t.Fatalf("parse maps line %q: %v", line, err)
		}
		span := end - start
		allMemfdLines++
		allMemfdBytes += span
		if fields[4] == wantIno {
			lines++
			bytes += span
		}
	}
	return lines, bytes, allMemfdLines, allMemfdBytes, all
}

func openFDs(t testing.TB) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(entries)
}

// waitMemoryFileIdle waits until the asynchronous releaser of mf drains all
// waste pages and returns to idle.
func waitMemoryFileIdle(t testing.TB, mf *pgalloc.MemoryFile) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	if err := mf.WaitReleaserIdle(ctx); err != nil {
		t.Fatalf("WaitReleaserIdle: %v", err)
	}
}

// stubMemoryRanges returns every memory-file range owned by sp.
func stubMemoryRanges(sp *subprocess) []memmap.FileRange {
	ranges := []memmap.FileRange{
		sp.syscallThread.stackRange,
		sp.contextQueueRange,
		sp.threadContextRange,
	}
	sp.sysmsgThreadsMu.Lock()
	for _, st := range sp.sysmsgThreads {
		ranges = append(ranges, st.stackRange)
	}
	sp.sysmsgThreadsMu.Unlock()
	return ranges
}

// alignRangesOutward expands each non-empty range to align-byte boundaries.
func alignRangesOutward(ranges []memmap.FileRange, align uint64) []memmap.FileRange {
	mask := align - 1
	out := make([]memmap.FileRange, 0, len(ranges))
	for _, r := range ranges {
		if r.Length() == 0 {
			continue
		}
		start := r.Start &^ mask
		end := (r.End + mask) &^ mask
		out = append(out, memmap.FileRange{Start: start, End: end})
	}
	return out
}

// mergeFileRanges returns a sorted slice of disjoint non-empty ranges covering
// the same offsets as ranges.
func mergeFileRanges(ranges []memmap.FileRange) []memmap.FileRange {
	filtered := make([]memmap.FileRange, 0, len(ranges))
	for _, r := range ranges {
		if r.Length() > 0 {
			filtered = append(filtered, r)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	slices.SortFunc(filtered, func(a, b memmap.FileRange) int {
		if c := cmp.Compare(a.Start, b.Start); c != 0 {
			return c
		}
		return cmp.Compare(a.End, b.End)
	})
	merged := filtered[:1]
	for _, r := range filtered[1:] {
		last := &merged[len(merged)-1]
		if r.Start <= last.End {
			last.End = max(last.End, r.End)
			continue
		}
		merged = append(merged, r)
	}
	return merged
}

// subtractFileRanges removes every offset in exclude from base. Both inputs
// must be sorted and disjoint, as returned by mergeFileRanges.
func subtractFileRanges(base, exclude []memmap.FileRange) []memmap.FileRange {
	if len(base) == 0 {
		return nil
	}
	if len(exclude) == 0 {
		return slices.Clone(base)
	}
	out := make([]memmap.FileRange, 0, len(base))
	j := 0
	for _, cur := range base {
		for j < len(exclude) && exclude[j].End <= cur.Start {
			j++
		}
		for k := j; k < len(exclude) && exclude[k].Start < cur.End; k++ {
			if exclude[k].Start > cur.Start {
				out = append(out, memmap.FileRange{Start: cur.Start, End: exclude[k].Start})
			}
			if exclude[k].End >= cur.End {
				cur.Start = cur.End
				break
			}
			cur.Start = exclude[k].End
		}
		if cur.Start < cur.End {
			out = append(out, cur)
		}
	}
	return out
}

// residentBytesInRanges queries the host kernel with SEEK_DATA and SEEK_HOLE
// and returns the total committed bytes inside the sorted, disjoint ranges.
//
// Querying owned ranges instead of whole-file st_blocks isolates the test from
// external host scanners that read-fault free memfd offsets on shared runners.
// Those read faults charge Linux shmem i_blocks without any leak in pgalloc.
func residentBytesInRanges(t testing.TB, f *os.File, ranges []memmap.FileRange) uint64 {
	t.Helper()
	defer runtime.KeepAlive(f)
	fd := int(f.Fd())
	origOff, err := unix.Seek(fd, 0, io.SeekCurrent)
	if err != nil {
		t.Fatalf("seek current offset on memory file: %v", err)
	}
	defer func() {
		if _, err := unix.Seek(fd, origOff, io.SeekStart); err != nil {
			t.Errorf("restore memory file offset to %d: %v", origOff, err)
		}
	}()

	var total uint64
	for _, r := range ranges {
		pos := int64(r.Start)
		end := int64(r.End)
		for pos < end {
			dataOff, err := unix.Seek(fd, pos, unix.SEEK_DATA)
			if errors.Is(err, unix.ENXIO) {
				break
			}
			if err != nil {
				t.Fatalf("seek SEEK_DATA at %#x on memory file: %v", pos, err)
			}
			if dataOff >= end {
				break
			}
			holeOff, err := unix.Seek(fd, dataOff, unix.SEEK_HOLE)
			if err != nil {
				t.Fatalf("seek SEEK_HOLE at %#x on memory file: %v", dataOff, err)
			}
			if holeOff <= dataOff {
				t.Fatalf("SEEK_HOLE at %#x returned non-advancing offset %#x", dataOff, holeOff)
			}
			segEnd := min(holeOff, end)
			total += uint64(segEnd - dataOff)
			pos = segEnd
		}
	}
	return total
}

type hostCounts struct {
	fds, children, memfdLines, totalMemfdLines, allLines int
	memfdBytes, totalMemfdBytes                          uint64
	allocatedBytes, pendingBytes, totalSize              uint64
	sourceResidentBytes, stubResidentBytes               uint64
}

func (c hostCounts) String() string {
	return fmt.Sprintf(
		"fds=%d children=%d memfd mapping lines=%d memfd mapped bytes=%d all memfd lines=%d all memfd bytes=%d all mapping lines=%d allocated=%d pending=%d totalSize=%d sourceResident=%d stubResident=%d",
		c.fds, c.children, c.memfdLines, c.memfdBytes, c.totalMemfdLines, c.totalMemfdBytes, c.allLines,
		c.allocatedBytes, c.pendingBytes, c.totalSize, c.sourceResidentBytes, c.stubResidentBytes,
	)
}

func measureHost(t testing.TB, mf *pgalloc.MemoryFile, ino uint64, sourceRanges, stubRanges []memmap.FileRange) hostCounts {
	t.Helper()
	waitMemoryFileIdle(t, mf)
	lines, bytes, allMemfdLines, allMemfdBytes, all := memfdMappings(t, ino)
	stats := mf.AllocationStats()
	return hostCounts{
		fds:                 openFDs(t),
		children:            countChildren(t),
		memfdLines:          lines,
		memfdBytes:          bytes,
		totalMemfdLines:     allMemfdLines,
		totalMemfdBytes:     allMemfdBytes,
		allLines:            all,
		allocatedBytes:      stats.AllocatedBytes,
		pendingBytes:        stats.PendingReleaseBytes,
		totalSize:           mf.TotalSize(),
		sourceResidentBytes: residentBytesInRanges(t, mf.File(), sourceRanges),
		stubResidentBytes:   residentBytesInRanges(t, mf.File(), stubRanges),
	}
}

func TestDestroyingEveryReleasedStubLeaksNothing(t *testing.T) {
	p := requirePlatform(t)
	useIdleLimit(t, 0)

	st, err := p.memoryFile.File().Stat()
	if err != nil {
		t.Fatalf("stat memory file: %v", err)
	}
	ino := st.Sys().(*syscall.Stat_t).Ino

	// Expand source ranges to host pages so sub-pages sharing a host page with
	// globalPool.source on 16 KiB hosts stay in sourceHostRanges.
	if globalPool.source == nil {
		t.Fatal("source stub not initialized")
	}
	waitMemoryFileIdle(t, p.memoryFile)
	sourceRanges := mergeFileRanges(stubMemoryRanges(globalPool.source))
	var sourceAllocatedBytes uint64
	for _, r := range sourceRanges {
		sourceAllocatedBytes += r.Length()
	}
	hostPage := uint64(unix.Getpagesize())
	sourceHostRanges := mergeFileRanges(alignRangesOutward(sourceRanges, hostPage))
	var rawStubRanges []memmap.FileRange

	oneRound := func() {
		sp, err := newTestAddressSpace(p)
		if err != nil {
			t.Fatalf("NewAddressSpace: %v", err)
		}
		if err := mapAndUnmapPage(p, sp); err != nil {
			t.Fatalf("use address space: %v", err)
		}
		rawStubRanges = append(rawStubRanges, stubMemoryRanges(sp)...)
		sp.Release()
	}

	// Run several warm-up rounds and a GC cycle so the Go runtime opens its
	// background threads, descriptors, and heap arenas before baseline capture.
	const warmupRounds = 16
	for range warmupRounds {
		oneRound()
	}
	runtime.GC()
	warmupStubRanges := subtractFileRanges(mergeFileRanges(rawStubRanges), sourceHostRanges)
	if len(warmupStubRanges) == 0 {
		t.Fatal("expected non-empty destroyed stub ranges after warm-up")
	}
	first := measureHost(t, p.memoryFile, ino, sourceHostRanges, warmupStubRanges)
	t.Logf("after %d warm-up rounds: %v", warmupRounds, first)
	if first.allocatedBytes != sourceAllocatedBytes || first.pendingBytes != 0 || first.stubResidentBytes != 0 {
		t.Fatalf("after %d warm-up rounds, destroyed stub memory remained allocated, pending, or resident (want allocated=%d, stubRanges=%v): %v",
			warmupRounds, sourceAllocatedBytes, warmupStubRanges, first)
	}

	const rounds = 500
	for range rounds {
		oneRound()
	}
	runtime.GC()
	allStubRanges := subtractFileRanges(mergeFileRanges(rawStubRanges), sourceHostRanges)
	last := measureHost(t, p.memoryFile, ino, sourceHostRanges, allStubRanges)
	t.Logf("after %d rounds: %v", rounds, last)

	// Every systrap shared mapping backs a memfd, so totalMemfdLines and
	// totalMemfdBytes require exact equality. Go GC madvise calls can split
	// anonymous heap and stack VMAs, while a per-round anonymous VMA leak across
	// 500 rounds adds at least 500 lines.
	const runtimeSlack = 128
	if last.fds != first.fds || last.children != first.children ||
		last.memfdLines != first.memfdLines || last.memfdBytes != first.memfdBytes ||
		last.totalMemfdLines != first.totalMemfdLines || last.totalMemfdBytes != first.totalMemfdBytes ||
		last.allocatedBytes != first.allocatedBytes || last.pendingBytes != 0 ||
		last.totalSize != first.totalSize ||
		last.sourceResidentBytes > first.sourceResidentBytes || last.stubResidentBytes != 0 ||
		last.allLines > first.allLines+runtimeSlack {
		t.Fatalf("after %d create and release rounds with bound 0, the host counts differ from the baseline\nfirst: %v\nlast:  %v\nsourceHostRanges: %v\nstubRanges:       %v",
			rounds, first, last, sourceHostRanges, allStubRanges)
	}
}

func TestResidentBytesInRangesDetectsLeaksAndIgnoresFreeSpaceFaults(t *testing.T) {
	const (
		fileSize      = 16 << 20
		scanLength    = 8 << 20
		stubOffset    = 12 << 20
		untouchedBase = 14 << 20
	)
	page := uint64(unix.Getpagesize())
	fd, err := memutil.CreateMemFD("systrap-seek-data-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	f := os.NewFile(uintptr(fd), "systrap-seek-data-test")
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close memfd: %v", err)
		}
	}()
	if err := f.Truncate(fileSize); err != nil {
		t.Fatalf("truncate memfd: %v", err)
	}

	// Simulate an external scanner read-faulting free offsets at [0, 8 MiB) via
	// MAP_SHARED, which charges Linux shmem st_blocks across the scanned span.
	mapped, err := unix.Mmap(fd, 0, scanLength, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		t.Fatalf("mmap free-space window: %v", err)
	}
	defer func() {
		if err := unix.Munmap(mapped); err != nil {
			t.Errorf("munmap free-space window: %v", err)
		}
	}()
	var sink byte
	for off := 0; off < len(mapped); off += int(page) {
		sink ^= mapped[off]
	}
	runtime.KeepAlive(sink)

	// Commit one host page inside the simulated stub range. On hosts with
	// shmem THP enabled, the write may commit up to all four pages. Clamping to
	// the single written page always returns exactly one page.
	stubRanges := []memmap.FileRange{{Start: stubOffset, End: stubOffset + 4*page}}
	writtenPage := []memmap.FileRange{{Start: stubOffset + page, End: stubOffset + 2*page}}
	untouchedRange := []memmap.FileRange{{Start: untouchedBase, End: untouchedBase + 4*page}}
	if _, err := f.WriteAt([]byte{1}, stubOffset+int64(page)); err != nil {
		t.Fatalf("write stub page: %v", err)
	}
	if got := residentBytesInRanges(t, f, stubRanges); got < page || got > 4*page {
		t.Fatalf("residentBytesInRanges before punch = %d, want [%d, %d]", got, page, 4*page)
	}
	if got := residentBytesInRanges(t, f, writtenPage); got != page {
		t.Fatalf("residentBytesInRanges on written page = %d, want %d", got, page)
	}
	if got := residentBytesInRanges(t, f, untouchedRange); got != 0 {
		t.Fatalf("residentBytesInRanges on untouched range = %d, want 0", got)
	}

	// Punch the committed stub page and verify only stubRanges drops to zero
	// while whole-file st_blocks still reflects the external free-space scan.
	if err := unix.Fallocate(fd, unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, stubOffset, int64(4*page)); err != nil {
		t.Fatalf("fallocate punch hole: %v", err)
	}
	if got := residentBytesInRanges(t, f, stubRanges); got != 0 {
		t.Fatalf("residentBytesInRanges after punch = %d, want 0", got)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		t.Fatalf("fstat memfd: %v", err)
	}
	if got := uint64(stat.Blocks * 512); got < scanLength {
		t.Fatalf("whole-file st_blocks usage = %d, want at least %d from MAP_SHARED read faults", got, scanLength)
	}
}

func TestSubtractFileRangesWithHostPageAlignment(t *testing.T) {
	const hostPage = 16 << 10
	// Source owns [0x3fffc000, 0x3fffe000), which expands to [0x3fffc000, 0x40000000).
	source := mergeFileRanges(alignRangesOutward([]memmap.FileRange{
		{Start: 0x3fffc000, End: 0x3fffe000},
	}, hostPage))
	// Child stub allocated a sub-page in the same 16 KiB host page plus two
	// adjacent ranges below it.
	raw := []memmap.FileRange{
		{Start: 0x3fffe000, End: 0x40000000},
		{Start: 0x3eff0000, End: 0x3fff0000},
		{Start: 0x3fff0000, End: 0x3fffc000},
	}
	got := subtractFileRanges(mergeFileRanges(raw), source)
	want := []memmap.FileRange{
		{Start: 0x3eff0000, End: 0x3fffc000},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("subtractFileRanges = %v, want %v", got, want)
	}

	// Verify splitting a base range around an interior excluded range.
	splitGot := subtractFileRanges(
		[]memmap.FileRange{{Start: 0x1000, End: 0x9000}},
		[]memmap.FileRange{{Start: 0x3000, End: 0x5000}, {Start: 0x6000, End: 0x7000}},
	)
	splitWant := []memmap.FileRange{
		{Start: 0x1000, End: 0x3000},
		{Start: 0x5000, End: 0x6000},
		{Start: 0x7000, End: 0x9000},
	}
	if !slices.Equal(splitGot, splitWant) {
		t.Fatalf("subtractFileRanges interior split = %v, want %v", splitGot, splitWant)
	}
}

func TestIdleBoundHoldsUnderConcurrentReleaseAndMapFile(t *testing.T) {
	p := requirePlatform(t)
	const k = 2
	useIdleLimit(t, k)

	const (
		churners = 4
		rounds   = 15
		steady   = 3
	)
	steadySet := useAddressSpaces(t, p, steady)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		failures []error
	)
	fail := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		failures = append(failures, err)
	}
	stop := make(chan struct{})

	// Steady address spaces call MapFile while churners destroy other stubs.
	var steadyWG sync.WaitGroup
	for i, sp := range steadySet.spaces {
		steadyWG.Add(1)
		go func() {
			defer steadyWG.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := mapAndUnmapPage(p, sp); err != nil {
					fail(fmt.Errorf("steady address space %d: %w", i, err))
					return
				}
			}
		}()
	}

	for i := range churners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range rounds {
				sp, err := newTestAddressSpace(p)
				if err != nil {
					fail(fmt.Errorf("churner %d round %d: NewAddressSpace: %w", i, r, err))
					return
				}
				if err := mapAndUnmapPage(p, sp); err != nil {
					fail(fmt.Errorf("churner %d round %d: %w", i, r, err))
				}
				sp.Release()
			}
		}()
	}
	wg.Wait()
	close(stop)
	steadyWG.Wait()
	steadySet.release(steadySet.spaces...)

	for _, err := range failures {
		t.Error(err)
	}
	if got, limit := countChildren(t), k+1; got > limit {
		t.Errorf("after the churn and releasing all address spaces: %d child processes, want at most %d", got, limit)
	}
}

func TestDefaultIdleBoundLimitsStubsToLivePlusBound(t *testing.T) {
	p := requirePlatform(t)
	k := idleStubLimit()

	atMost := func(stage string, live int) {
		t.Helper()
		if got, limit := countChildren(t), live+k+1; got > limit {
			t.Fatalf("%s: %d live address spaces and bound %d: %d child processes, want at most %d", stage, live, k, got, limit)
		}
	}

	set := useAddressSpaces(t, p, k+4)
	atMost("all live", len(set.spaces))
	half := len(set.spaces) / 2
	set.release(set.spaces[:half]...)
	atMost("half released", len(set.spaces)-half)
	set.release(set.spaces...)
	atMost("all released", 0)
	if got, want := countChildren(t), k+1; got != want {
		t.Fatalf("after releasing %d address spaces with bound %d: %d child processes, want %d (the bound plus the source stub)", len(set.spaces), k, got, want)
	}

	// A new round reuses the pooled stubs and stays within the bound.
	set = useAddressSpaces(t, p, k+4)
	atMost("second round, all live", len(set.spaces))
	set.release(set.spaces...)
	atMost("second round, all released", 0)
}
