//go:build darwin

package pgalloc

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/internal/xsys/unix"
)

func TestSharedPagesAliasAndDecommit(t *testing.T) {
	t.Parallel()
	pages, err := AllocateSharedPages(16384)
	if err != nil {
		t.Fatalf("AllocateSharedPages: %v", err)
	}
	defer func() {
		if err := ReleaseSharedPages(pages); err != nil {
			t.Errorf("ReleaseSharedPages: %v", err)
		}
	}()
	for i := range pages {
		pages[i] = 0x5A
	}
	alias, err := RemapSharedPages(pages)
	if err != nil {
		t.Fatalf("RemapSharedPages: %v", err)
	}
	if alias[0] != 0x5A || alias[len(alias)-1] != 0x5A {
		t.Fatalf("alias bytes = %#x..%#x, want 0x5A", alias[0], alias[len(alias)-1])
	}
	if err := DecommitSharedPages(pages); err != nil {
		t.Fatalf("DecommitSharedPages: %v", err)
	}
	for i, b := range pages {
		if b != 0 {
			t.Fatalf("pages[%d] = %#x after DecommitSharedPages, want 0", i, b)
		}
	}
	for i, b := range alias {
		if b != 0 {
			t.Fatalf("alias[%d] = %#x after DecommitSharedPages, want 0", i, b)
		}
	}
}

// TestDecommitSharedPagesKeepsNeighbours verifies that a region smaller than the
// 16KB host page clears only its own bytes. MADV_FREE works on whole host pages,
// so reclaiming the neighbouring bytes would lose live data.
func TestDecommitSharedPagesKeepsNeighbours(t *testing.T) {
	t.Parallel()
	hostPage := unix.Getpagesize()
	pages, err := AllocateSharedPages(uint64(2 * hostPage))
	if err != nil {
		t.Fatalf("AllocateSharedPages: %v", err)
	}
	defer ReleaseSharedPages(pages)
	for i := range pages {
		pages[i] = 0xC3
	}
	// Decommit one 4KB page in the middle of the first host page.
	const sub = 4096
	region := pages[sub : 2*sub]
	if err := DecommitSharedPages(region); err != nil {
		t.Fatalf("DecommitSharedPages(sub-host-page): %v", err)
	}
	for i, b := range pages {
		want := byte(0xC3)
		if i >= sub && i < 2*sub {
			want = 0
		}
		if b != want {
			t.Fatalf("pages[%d] = %#x, want %#x", i, b, want)
		}
	}
}

func TestDecommitSharedPagesRejectsEmptyRegion(t *testing.T) {
	t.Parallel()
	if err := DecommitSharedPages(nil); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("DecommitSharedPages(nil) = %v, want EINVAL", err)
	}
}

func TestDefaultMemoryFileDecommitPunchesHole(t *testing.T) {
	t.Parallel()
	mf, err := NewDefaultMemoryFile(MemoryFileOpts{DisableMemoryAccounting: true})
	if err != nil {
		t.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	defer mf.Destroy()

	fr, err := mf.Allocate(4*uint64(hostarch.PageSize), AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	slice := bs.Head().ToSlice()
	for i := range slice {
		slice[i] = 0x7F
	}

	// decommitFile is the native reclaim. Decommit hides its failure behind a manual zero.
	if err := mf.decommitFile(fr); errors.Is(err, unix.ENOTSUP) {
		t.Skipf("temporary directory file system lacks F_PUNCHHOLE: %v", err)
	} else if err != nil {
		t.Fatalf("decommitFile: %v", err)
	}
	for i, b := range slice {
		if b != 0 {
			t.Fatalf("slice[%d] = %#x after hole punch, want 0", i, b)
		}
	}

	for i := range slice {
		slice[i] = 0x7F
	}
	mf.Decommit(fr)
	for i, b := range slice {
		if b != 0 {
			t.Fatalf("slice[%d] = %#x after Decommit, want 0", i, b)
		}
	}
	mf.DecRef(fr)
}

// TestDecommitKeepsLiveNeighboursInHostPage is a regression test for reclaim
// that zeroed live 4KB pages sharing a 16KB host page with the freed range.
// Every iteration writes fresh patterns right before the reclaim, so the
// neighbours are dirty and unwritten to the file when the reclaim runs.
func TestDecommitKeepsLiveNeighboursInHostPage(t *testing.T) {
	t.Parallel()
	mf, err := NewDefaultMemoryFile(MemoryFileOpts{DisableMemoryAccounting: true})
	if err != nil {
		t.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	defer mf.Destroy()

	page := uint64(hostarch.PageSize)
	hostPage := uint64(unix.Getpagesize())
	pagesPerHost := hostPage / page
	const hostPages = 3
	total := hostPages * pagesPerHost
	fr, err := mf.Allocate(total*page, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	mem := bs.Head().ToSlice()

	fill := func(iter int) {
		for p := uint64(0); p < total; p++ {
			pat := byte(1 + (uint64(iter)+p)%250)
			for i := p * page; i < (p+1)*page; i++ {
				mem[i] = pat
			}
		}
	}
	// Free one 4KB page in the middle of the first host page, one whole host
	// page in the middle, and the last 4KB page of the final host page.
	freed := []uint64{1, pagesPerHost, pagesPerHost + 1, pagesPerHost + 2, pagesPerHost + 3, total - 1}
	if pagesPerHost == 1 {
		freed = []uint64{1}
	}
	for iter := 0; iter < 300; iter++ {
		fill(iter)
		isFreed := map[uint64]bool{}
		for _, p := range freed {
			isFreed[p] = true
			sub := memmap.FileRange{Start: fr.Start + p*page, End: fr.Start + (p+1)*page}
			mf.Decommit(sub)
		}
		for p := uint64(0); p < total; p++ {
			want := byte(1 + (uint64(iter)+p)%250)
			if isFreed[p] {
				want = 0
			}
			for i := p * page; i < (p+1)*page; i++ {
				if mem[i] != want {
					t.Fatalf("iteration %d: page %d byte %d = %#x, want %#x", iter, p, i-p*page, mem[i], want)
				}
			}
		}
	}
	mf.DecRef(fr)
}

// TestConcurrentDecommitKeepsWritesToNeighbours reproduces the guest corruption
// that partial-host-page hole punching caused. One goroutine reclaims a 4KB
// page while another writes the 4KB pages next to it in the same host page.
// A reclaim that touches the neighbours loses or zeroes the fresh writes.
func TestConcurrentDecommitKeepsWritesToNeighbours(t *testing.T) {
	t.Parallel()
	mf, err := NewDefaultMemoryFile(MemoryFileOpts{DisableMemoryAccounting: true})
	if err != nil {
		t.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	defer mf.Destroy()

	page := uint64(hostarch.PageSize)
	hostPage := uint64(unix.Getpagesize())
	if hostPage == page {
		t.Skip("the host page equals the 4KB page, so no neighbour shares a host page")
	}
	pagesPerHost := hostPage / page
	fr, err := mf.Allocate(hostPage, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	mem := bs.Head().ToSlice()
	victim := memmap.FileRange{Start: fr.Start + page, End: fr.Start + 2*page}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				mf.Decommit(victim)
			}
		}
	}()

	var failure string
	for iter := 0; iter < 20000 && failure == ""; iter++ {
		pat := byte(1 + iter%250)
		for p := uint64(0); p < pagesPerHost; p++ {
			if p == 1 {
				continue
			}
			for i := p * page; i < (p+1)*page; i += 512 {
				mem[i] = pat
			}
		}
		for p := uint64(0); p < pagesPerHost; p++ {
			if p == 1 {
				continue
			}
			for i := p * page; i < (p+1)*page; i += 512 {
				if mem[i] != pat {
					failure = fmt.Sprintf("iteration %d: page %d byte %d = %#x, want %#x", iter, p, i-p*page, mem[i], pat)
				}
			}
		}
	}
	close(stop)
	<-done
	if failure != "" {
		t.Fatal(failure)
	}
	mf.DecRef(fr)
}

// TestMincoreHelperFillsOneEntryPerHostarchPage is a regression test for a Go
// heap overflow in builds with 16KB pages. The mincore overlay wrote one byte per
// 4KB page while the usage scan sized its vector with one byte per 16KB page,
// so every scan of a chunk wrote past the end of the vector into the heap.
func TestMincoreHelperFillsOneEntryPerHostarchPage(t *testing.T) {
	t.Parallel()
	if unix.MincorePageSize != hostarch.PageSize {
		t.Fatalf("unix.MincorePageSize = %d, want hostarch.PageSize = %d", unix.MincorePageSize, hostarch.PageSize)
	}
	hostPage := unix.Getpagesize()
	size := 8 * max(hostPage, hostarch.PageSize)
	mapping, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	defer unix.Munmap(mapping)
	for i := 0; i < len(mapping); i += hostPage {
		mapping[i] = 1
	}

	entries := size >> hostarch.PageShift
	const guard = 8192
	const poison = 0xEE
	vec := make([]byte, entries+guard)
	for i := range vec {
		vec[i] = poison
	}
	if err := mincore(mapping, vec[:entries]); err != nil {
		t.Fatalf("mincore: %v", err)
	}
	for i := range entries {
		if vec[i]&1 == 0 {
			t.Errorf("vec[%d] = %#x for a touched page, want resident", i, vec[i])
		}
	}
	for i := entries; i < len(vec); i++ {
		if vec[i] != poison {
			t.Fatalf("vec[%d] = %#x past the %d entries of the vector, want the untouched %#x", i, vec[i], entries, poison)
		}
	}
}

// TestUsageScanCommitsTheTouchedPagesOnly checks that the usage scan maps each
// mincore entry to the page it describes. A scan that reads entries of another
// page size would commit the wrong ranges.
func TestUsageScanCommitsTheTouchedPagesOnly(t *testing.T) {
	t.Parallel()
	mf, err := NewDefaultMemoryFile(MemoryFileOpts{DisableMemoryAccounting: true})
	if err != nil {
		t.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	defer mf.Destroy()

	page := uint64(hostarch.PageSize)
	hostPage := uint64(unix.Getpagesize())
	const pages = 12
	fr, err := mf.Allocate(pages*page, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer mf.DecRef(fr)
	bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	mem := bs.Head().ToSlice()
	touched := []uint64{2, 9}
	want := uint64(0)
	var lastHost uint64 = ^uint64(0)
	for _, p := range touched {
		mem[p*page] = 1
		hostStart := (fr.Start + p*page) &^ (hostPage - 1)
		if hostStart == lastHost {
			continue
		}
		lastHost = hostStart
		want += memmap.FileRange{Start: hostStart, End: hostStart + hostPage}.Intersect(fr).Length()
	}

	mf.mu.Lock()
	err = mf.updateUsageLocked(nil)
	got := mf.knownCommittedBytes
	mf.mu.Unlock()
	if err != nil {
		t.Fatalf("updateUsageLocked: %v", err)
	}
	if got != want {
		t.Fatalf("knownCommittedBytes = %d after touching pages %v of %d, want %d", got, touched, pages, want)
	}
}

// TestDecommitUnalignedRangePunchesInteriorHostPages verifies that Decommit on
// a range with 4KB-aligned ends zeroes the partial head and tail in memory and
// punches holes in the interior whole host pages.
func TestDecommitUnalignedRangePunchesInteriorHostPages(t *testing.T) {
	t.Parallel()
	mf, err := NewDefaultMemoryFile(MemoryFileOpts{DisableMemoryAccounting: true})
	if err != nil {
		t.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	defer mf.Destroy()

	page := uint64(hostarch.PageSize)
	hostPage := uint64(unix.Getpagesize())
	const hostPages = 4
	total := hostPages * hostPage
	fr, err := mf.Allocate(total, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer mf.DecRef(fr)

	bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	mem := bs.Head().ToSlice()
	for i := range mem {
		mem[i] = 0xA5
	}
	if err := mf.file.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	before, err := mf.TotalUsage()
	if err != nil {
		t.Fatalf("TotalUsage before Decommit: %v", err)
	}
	if before < total {
		t.Skipf("backing file reports %d bytes before Decommit, want at least %d", before, total)
	}

	sub := memmap.FileRange{Start: fr.Start + page, End: fr.End - page}
	mf.Decommit(sub)

	for i, b := range mem {
		off := fr.Start + uint64(i)
		want := byte(0xA5)
		if off >= sub.Start && off < sub.End {
			want = 0
		}
		if b != want {
			t.Fatalf("mem[%d] = %#x, want %#x", i, b, want)
		}
	}
	after, err := mf.TotalUsage()
	if err != nil {
		t.Fatalf("TotalUsage after Decommit: %v", err)
	}
	reclaimed := before - after
	wantReclaimed := 2 * hostPage
	if reclaimed < wantReclaimed {
		t.Fatalf("reclaimed %d bytes from backing file, want at least %d", reclaimed, wantReclaimed)
	}
}

// TestReleaseSubPagesCoalescesIntoWholeHostPageHolePunch verifies that
// releasing all 4KB sub-pages of a 16KB host page one by one punches a hole in
// the backing file once the final sub-page is released.
func TestReleaseSubPagesCoalescesIntoWholeHostPageHolePunch(t *testing.T) {
	t.Parallel()
	mf, err := NewDefaultMemoryFile(MemoryFileOpts{DisableMemoryAccounting: true})
	if err != nil {
		t.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	defer mf.Destroy()

	page := uint64(hostarch.PageSize)
	hostPage := uint64(unix.Getpagesize())
	pagesPerHost := hostPage / page
	var subRanges []memmap.FileRange
	for range pagesPerHost {
		fr, err := mf.Allocate(page, AllocOpts{Kind: usage.Anonymous})
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
		if err != nil {
			t.Fatalf("MapInternal: %v", err)
		}
		slice := bs.Head().ToSlice()
		for i := range slice {
			slice[i] = 0x5C
		}
		subRanges = append(subRanges, fr)
	}
	if err := mf.file.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	before, err := mf.TotalUsage()
	if err != nil {
		t.Fatalf("TotalUsage before release: %v", err)
	}
	if before == 0 {
		t.Skip("backing file reports 0 bytes before release")
	}

	// Release one sub-page at a time in non-sequential order so releaserMain
	// handles each sub-page individually before the final sub-page completes the host page.
	order := []int{0, int(pagesPerHost) - 1}
	for i := 1; i < int(pagesPerHost)-1; i++ {
		order = append(order, i)
	}
	if pagesPerHost == 1 {
		order = []int{0}
	}
	for _, idx := range order {
		mf.DecRef(subRanges[idx])
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			mf.mu.Lock()
			busy := mf.haveWaste
			mf.mu.Unlock()
			if !busy {
				break
			}
			time.Sleep(time.Millisecond)
		}
	}

	after, err := mf.TotalUsage()
	if err != nil {
		t.Fatalf("TotalUsage after release: %v", err)
	}
	if after >= before {
		t.Fatalf("TotalUsage after releasing all sub-pages = %d, want less than %d", after, before)
	}
}
